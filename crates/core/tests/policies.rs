use rizenvuln_core::*;
use serde_json::json;
#[test]
fn image_reference_roundtrips_and_rejects_argument_injection() {
    let digest = format!("sha256:{}", "a".repeat(64));
    for reference in [
        "nginx".to_string(),
        "docker.io/library/nginx:stable".into(),
        "registry.example.test:5000/team/app:v1".into(),
        format!("ghcr.io/team/app@{digest}"),
    ] {
        let canonical = ImageReference::parse(&reference).unwrap().canonical();
        assert_eq!(
            ImageReference::parse(&canonical).unwrap().canonical(),
            canonical
        );
    }
    for reference in [
        "",
        "-v",
        "nginx;id",
        "nginx\n--help",
        "https://example.test/image",
        "a/../b",
        "a//b",
        "nginx:",
        "nginx@sha256:bad",
        "nginx:$(id)",
    ] {
        assert!(ImageReference::parse(reference).is_err(), "{reference}");
    }
}
#[test]
fn recommendation_matrix() {
    for (current, candidate, stable, security, status, major) in [
        (
            "1.0.0",
            "1.0.1",
            true,
            false,
            UpdateStatus::UpdateAvailable,
            false,
        ),
        (
            "1.0.0",
            "2.0.0",
            true,
            true,
            UpdateStatus::SecurityFixAvailable,
            true,
        ),
        ("2.0.0", "1.0.0", true, false, UpdateStatus::UpToDate, false),
        (
            "1.0.0",
            "1.1.0-rc.1",
            true,
            false,
            UpdateStatus::Unknown,
            false,
        ),
        (
            "1.0.0",
            "1.1.0-rc.1",
            false,
            false,
            UpdateStatus::UpdateAvailable,
            false,
        ),
        (
            "latest",
            "stable",
            true,
            false,
            UpdateStatus::Unknown,
            false,
        ),
        (
            "latest",
            "latest",
            true,
            false,
            UpdateStatus::Unknown,
            false,
        ),
    ] {
        let r = recommend(current, candidate, None, None, stable, security);
        assert_eq!(r.status, status, "{current} -> {candidate}");
        assert_eq!(r.major_warning, major);
    }
    assert_eq!(
        latest_stable("v1.0.0", ["latest", "v1.2.0", "v2.0.0-rc.1", "v1.10.0"]),
        Some("v1.10.0".into())
    );
}
#[test]
fn findings_are_scoped_by_target_and_skip_incomplete_entries() {
    let vuln = json!({"VulnerabilityID":"CVE-TEST","PkgName":"openssl","InstalledVersion":"1","Severity":"high"});
    let report = json!({"Results":[{"Target":"a","Vulnerabilities":[vuln,vuln,{"VulnerabilityID":"missing-package"}]},{"Target":"b","Vulnerabilities":[vuln]},{}]});
    let findings = trivy_findings(&report);
    assert_eq!(findings.len(), 2);
    assert!(findings
        .iter()
        .all(|f| f.severity == "HIGH" && f.fixed.is_empty()));
    for invalid in [json!(null), json!({}), json!({"Results":[]})] {
        assert!(trivy_findings(&invalid).is_empty());
    }
}
#[test]
fn sbom_supports_license_expressions_purls_and_empty_documents() {
    let cdx = json!({"components":[{"name":"lib","version":"1","purl":"pkg:generic/lib@1","licenses":[{"license":{"name":"Custom"}},{"expression":"MIT OR Apache-2.0"}]}]});
    let p = sbom_packages(&cdx).unwrap();
    assert_eq!(p[0].license, "Custom, MIT OR Apache-2.0");
    assert_eq!(p[0].purl, "pkg:generic/lib@1");
    let spdx = json!({"packages":[{"name":"lib","externalRefs":[{"referenceType":"purl","referenceLocator":"pkg:generic/lib"}]}]});
    let p = sbom_packages(&spdx).unwrap();
    assert_eq!(p[0].purl, "pkg:generic/lib");
    assert_eq!(p[0].license, "NOASSERTION");
    assert!(sbom_packages(&json!({"components":[]})).unwrap().is_empty());
    assert!(sbom_packages(&json!({"packages":[]})).unwrap().is_empty());
}
