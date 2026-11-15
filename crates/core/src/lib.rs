use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateStatus {
    UpToDate,
    UpdateAvailable,
    SecurityFixAvailable,
    Testing,
    Approved,
    Deployed,
    Outdated,
    Unknown,
}
#[derive(Debug, Serialize)]
pub struct Recommendation {
    pub status: UpdateStatus,
    pub major_warning: bool,
    pub reason: String,
}

pub fn recommend(
    current: &str,
    candidate: &str,
    digest: Option<&str>,
    candidate_digest: Option<&str>,
    stable_only: bool,
    security_fix: bool,
) -> Recommendation {
    let result = |status, major_warning, reason: &str| Recommendation {
        status,
        major_warning,
        reason: reason.into(),
    };
    if digest.is_some() && digest == candidate_digest {
        return result(UpdateStatus::UpToDate, false, "Digest совпадает");
    }
    if current == candidate && (digest.is_none() || candidate_digest.is_none()) {
        return result(
            UpdateStatus::Unknown,
            false,
            "Для mutable tag требуется digest",
        );
    }
    let parse = |s: &str| semver::Version::parse(s.trim_start_matches('v'));
    match (parse(current), parse(candidate)) {
        (Ok(a), Ok(b)) => {
            if stable_only && !b.pre.is_empty() {
                return result(
                    UpdateStatus::Unknown,
                    false,
                    "Предварительные релизы запрещены политикой",
                );
            }
            if b <= a {
                return result(
                    UpdateStatus::UpToDate,
                    false,
                    "Подходящая версия уже установлена",
                );
            }
            result(
                if security_fix {
                    UpdateStatus::SecurityFixAvailable
                } else {
                    UpdateStatus::UpdateAvailable
                },
                b.major > a.major,
                "Доступна новая версия",
            )
        }
        _ if current == candidate => result(
            UpdateStatus::UpdateAvailable,
            false,
            "Содержимое mutable tag изменилось",
        ),
        _ => result(
            UpdateStatus::Unknown,
            false,
            "Схема тегов требует явной политики сравнения",
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageReference {
    pub registry: String,
    pub repository: String,
    pub reference: String,
}
impl ImageReference {
    pub fn parse(input: &str) -> Result<Self> {
        if input.len() > 512
            || input.is_empty()
            || input.starts_with('-')
            || input.contains("://")
            || input
                .chars()
                .any(|c| c.is_whitespace() || !(c.is_ascii_alphanumeric() || "./:_@-".contains(c)))
        {
            bail!("Некорректная ссылка на OCI image");
        }
        let (name, reference) = if let Some((n, d)) = input.split_once('@') {
            if !d.starts_with("sha256:")
                || d.len() != 71
                || !d[7..].bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!("Некорректный digest");
            }
            (n, d)
        } else {
            let last_slash = input.rfind('/').map(|i| i + 1).unwrap_or(0);
            match input[last_slash..].rfind(':') {
                Some(i) => (&input[..last_slash + i], &input[last_slash + i + 1..]),
                None => (input, "latest"),
            }
        };
        if !reference.starts_with("sha256:")
            && (reference.len() > 128
                || !reference
                    .as_bytes()
                    .first()
                    .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
                || !reference
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b)))
        {
            bail!("Некорректный OCI tag");
        }
        if name.is_empty() || reference.is_empty() {
            bail!("Пустое имя или тег");
        }
        let first = name.split('/').next().unwrap_or_default();
        let (registry, repository) = if name.contains('/')
            && (first.contains('.') || first.contains(':') || first == "localhost")
        {
            let (r, p) = name.split_once('/').unwrap();
            (r.to_owned(), p.to_owned())
        } else {
            (
                "registry-1.docker.io".into(),
                if name.contains('/') {
                    name.into()
                } else {
                    format!("library/{name}")
                },
            )
        };
        if repository
            .split('/')
            .any(|p| p.is_empty() || p == "." || p == "..")
        {
            bail!("Некорректный путь repository");
        }
        let registry = if registry == "docker.io" || registry == "index.docker.io" {
            "registry-1.docker.io".into()
        } else {
            registry
        };
        Ok(Self {
            registry,
            repository,
            reference: reference.into(),
        })
    }
    pub fn canonical(&self) -> String {
        format!(
            "{}/{}{}{}",
            self.registry,
            self.repository,
            if self.reference.starts_with("sha256:") {
                "@"
            } else {
                ":"
            },
            self.reference
        )
    }
}

pub fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            !(a.is_private()
                || a.is_loopback()
                || a.is_link_local()
                || a.is_multicast()
                || a.is_unspecified()
                || a.is_broadcast()
                || o[0] == 0
                || o[0] >= 224
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 192 && o[1] == 0)
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19 || o[1] == 51))
                || (o[0] == 203 && o[1] == 0 && o[2] == 113))
        }
        IpAddr::V6(a) => a
            .to_ipv4_mapped()
            .map(|a| public_ip(IpAddr::V4(a)))
            .unwrap_or_else(|| {
                let s = a.segments();
                (s[0] & 0xe000) == 0x2000
                    && !(s[0] == 0x2001 && (s[1] == 0 || s[1] == 0xdb8))
                    && s[0] != 0x2002
            }),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub cve: String,
    pub package: String,
    pub installed: String,
    pub fixed: String,
    pub severity: String,
    pub title: String,
    pub target: String,
}
pub fn trivy_findings(report: &serde_json::Value) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for result in report["Results"].as_array().into_iter().flatten() {
        for v in result["Vulnerabilities"].as_array().into_iter().flatten() {
            let s = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
            let f = Finding {
                cve: s("VulnerabilityID"),
                package: s("PkgName"),
                installed: s("InstalledVersion"),
                fixed: s("FixedVersion"),
                severity: s("Severity").to_uppercase(),
                title: s("Title"),
                target: result["Target"].as_str().unwrap_or_default().into(),
            };
            if !f.cve.is_empty()
                && !f.package.is_empty()
                && seen.insert((
                    f.cve.clone(),
                    f.package.clone(),
                    f.installed.clone(),
                    f.target.clone(),
                ))
            {
                out.push(f)
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn digest_wins() {
        assert_eq!(
            recommend("1.0.0", "2.0.0", Some("a"), Some("a"), true, false).status,
            UpdateStatus::UpToDate
        );
    }
    #[test]
    fn semantic_versions() {
        let r = recommend("1.9.0", "1.10.0", None, None, true, false);
        assert_eq!(r.status, UpdateStatus::UpdateAvailable);
        assert!(!r.major_warning);
        assert!(recommend("1.0.0", "2.0.0", None, None, true, false).major_warning);
    }
    #[test]
    fn prerelease_rejected() {
        assert_eq!(
            recommend("1.0.0", "2.0.0-rc.1", None, None, true, false).status,
            UpdateStatus::Unknown
        );
    }
    #[test]
    fn mutable() {
        assert_eq!(
            recommend("latest", "latest", Some("a"), Some("b"), true, false).status,
            UpdateStatus::UpdateAvailable
        );
    }
    #[test]
    fn reference_validation() {
        assert_eq!(
            ImageReference::parse("nginx:stable-alpine")
                .unwrap()
                .canonical(),
            "registry-1.docker.io/library/nginx:stable-alpine"
        );
        assert!(ImageReference::parse("--config /etc/passwd").is_err());
        assert!(ImageReference::parse("ghcr.io/../image").is_err());
    }
    #[test]
    fn ssrf_ranges() {
        for s in [
            "127.0.0.1",
            "169.254.169.254",
            "10.0.0.1",
            "100.64.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "fd00::1",
            "2002:7f00::",
        ] {
            assert!(!public_ip(s.parse().unwrap()), "{s}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
    }
    #[test]
    fn findings_deduplicated() {
        let v = serde_json::json!({"Results":[{"Target":"a","Vulnerabilities":[{"VulnerabilityID":"CVE-2025-1","PkgName":"openssl"},{"VulnerabilityID":"CVE-2025-1","PkgName":"openssl"},{"VulnerabilityID":"CVE-2025-1","PkgName":"libssl"}]}]});
        assert_eq!(trivy_findings(&v).len(), 2);
    }
}

/// Unknown/custom tag schemes are deliberately left to an explicit policy.
pub fn latest_stable<'a>(current: &str, tags: impl IntoIterator<Item = &'a str>) -> Option<String> {
    let current_version = semver::Version::parse(current.trim_start_matches('v')).ok()?;
    tags.into_iter()
        .filter_map(|tag| {
            semver::Version::parse(tag.trim_start_matches('v'))
                .ok()
                .map(|v| (v, tag))
        })
        .filter(|(v, _)| v.pre.is_empty() && v > &current_version)
        .max_by(|(a, _), (b, _)| a.cmp(b))
        .map(|(_, tag)| tag.to_owned())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Package {
    pub name: String,
    pub version: String,
    pub license: String,
    pub purl: String,
}
pub fn sbom_packages(document: &serde_json::Value) -> Result<Vec<Package>> {
    let mut packages = Vec::new();
    if let Some(items) = document["components"].as_array() {
        for item in items {
            let license = item["licenses"]
                .as_array()
                .into_iter()
                .flatten()
                .filter_map(|l| {
                    l["license"]["id"]
                        .as_str()
                        .or_else(|| l["license"]["name"].as_str())
                        .or_else(|| l["expression"].as_str())
                })
                .collect::<Vec<_>>()
                .join(", ");
            packages.push(Package {
                name: item["name"].as_str().unwrap_or_default().into(),
                version: item["version"].as_str().unwrap_or_default().into(),
                license,
                purl: item["purl"].as_str().unwrap_or_default().into(),
            });
        }
    } else if let Some(items) = document["packages"].as_array() {
        for item in items {
            packages.push(Package {
                name: item["name"].as_str().unwrap_or_default().into(),
                version: item["versionInfo"].as_str().unwrap_or_default().into(),
                license: item["licenseConcluded"]
                    .as_str()
                    .unwrap_or("NOASSERTION")
                    .into(),
                purl: item["externalRefs"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .find(|r| r["referenceType"] == "purl")
                    .and_then(|r| r["referenceLocator"].as_str())
                    .unwrap_or_default()
                    .into(),
            });
        }
    } else {
        bail!("Документ не содержит CycloneDX components или SPDX packages");
    }
    Ok(packages)
}
#[cfg(test)]
mod sbom_tests {
    use super::*;
    #[test]
    fn cdx_and_spdx() {
        let cdx = serde_json::json!({"components":[{"name":"openssl","version":"3.0","licenses":[{"license":{"id":"Apache-2.0"}}]}]});
        assert_eq!(sbom_packages(&cdx).unwrap()[0].license, "Apache-2.0");
        let spdx = serde_json::json!({"packages":[{"name":"openssl","versionInfo":"3.1"}]});
        assert_eq!(sbom_packages(&spdx).unwrap()[0].version, "3.1");
        assert!(sbom_packages(&serde_json::json!({})).is_err());
    }
    #[test]
    fn stable_selection() {
        assert_eq!(
            latest_stable("1.9.0", ["1.10.0", "2.0.0-rc.1", "latest"]),
            Some("1.10.0".into())
        );
        assert_eq!(latest_stable("latest", ["1.10.0"]), None);
    }
}
