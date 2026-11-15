use super::http::{bytes_limited, json, Http};
use anyhow::{bail, Context, Result};
use reqwest::{Method, StatusCode};
use rizenvuln_core::ImageReference;
use serde_json::Value;
use sha2::{Digest, Sha256};
const ACCEPT:&str="application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json";
#[derive(Clone)]
pub struct Registry {
    http: Http,
    reference: ImageReference,
    credentials: Option<(String, String)>,
}
impl Registry {
    pub fn new(reference: ImageReference, credentials: Option<(String, String)>) -> Result<Self> {
        Ok(Self {
            http: Http::new(&format!("https://{}/", reference.registry), false, None)?,
            reference,
            credentials,
        })
    }
    async fn get(&self, path: &str) -> Result<reqwest::Response> {
        let url = self.http.url(path)?;
        let mut req = self
            .http
            .request(Method::GET, url.clone())
            .await?
            .header("Accept", ACCEPT);
        if let Some((u, p)) = &self.credentials {
            req = req.basic_auth(u, Some(p));
        }
        let r = req.send().await?;
        if r.status() != StatusCode::UNAUTHORIZED {
            return Ok(r);
        }
        let challenge = r
            .headers()
            .get("www-authenticate")
            .and_then(|h| h.to_str().ok())
            .context("Missing registry authentication challenge")?;
        let challenge = challenge
            .strip_prefix("Bearer ")
            .context("Unsupported registry authentication")?;
        let fields: std::collections::HashMap<_, _> = challenge
            .split(',')
            .filter_map(|p| p.trim().split_once('='))
            .map(|(k, v)| (k, v.trim_matches('"')))
            .collect();
        let realm = *fields.get("realm").context("Missing token realm")?;
        let realm_url = url::Url::parse(realm)?;
        let same_origin = realm_url.origin() == self.http.base.origin();
        let token_http = Http::new(
            realm,
            self.http.trusted && same_origin,
            if same_origin {
                self.http.ca.clone()
            } else {
                None
            },
        )?;
        let mut token_url = token_http.base.clone();
        {
            let mut q = token_url.query_pairs_mut();
            if let Some(s) = fields.get("service") {
                q.append_pair("service", s);
            }
            q.append_pair(
                "scope",
                &format!("repository:{}:pull", self.reference.repository),
            );
        }
        let mut auth = token_http.request(Method::GET, token_url).await?;
        // Never forward registry credentials to a challenge-controlled foreign host.
        if token_http.base.host_str() == self.http.base.host_str()
            || (self.reference.registry == "registry-1.docker.io"
                && token_http.base.host_str() == Some("auth.docker.io"))
        {
            if let Some((u, p)) = &self.credentials {
                auth = auth.basic_auth(u, Some(p));
            }
        }
        let v = json(auth.send().await?).await?;
        let token = v["token"]
            .as_str()
            .or_else(|| v["access_token"].as_str())
            .context("Missing registry bearer token")?;
        Ok(self
            .http
            .request(Method::GET, url)
            .await?
            .header("Accept", ACCEPT)
            .bearer_auth(token)
            .send()
            .await?)
    }
    pub async fn manifest(&self) -> Result<(String, Value)> {
        let r = self
            .get(&format!(
                "v2/{}/manifests/{}",
                self.reference.repository, self.reference.reference
            ))
            .await?;
        let claimed = r
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let raw = bytes_limited(r, 8 * 1024 * 1024).await?;
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&raw)));
        if claimed.as_ref().is_some_and(|d| d != &digest) {
            bail!("Registry manifest digest mismatch");
        }
        if self.reference.reference.starts_with("sha256:") && self.reference.reference != digest {
            bail!("Requested digest mismatch");
        }
        Ok((digest, serde_json::from_slice(&raw)?))
    }

    pub fn configured(
        reference: ImageReference,
        credentials: Option<(String, String)>,
        ca: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            http: Http::new(&format!("https://{}/", reference.registry), true, ca)?,
            reference,
            credentials,
        })
    }
    pub async fn tags(&self) -> Result<Value> {
        let mut path = format!("v2/{}/tags/list?n=100", self.reference.repository);
        let mut tags = Vec::new();
        for _ in 0..100 {
            let response = self.get(&path).await?;
            let next = response
                .headers()
                .get("link")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.split(',').find(|s| s.contains("rel=\"next\"")))
                .and_then(|h| h.split('<').nth(1))
                .and_then(|h| h.split('>').next())
                .map(str::to_owned);
            let data = json(response).await?;
            tags.extend(data["tags"].as_array().cloned().unwrap_or_default());
            if let Some(next) = next {
                let next = self.http.url(&next)?;
                if !next
                    .path()
                    .starts_with(&format!("/v2/{}/tags/list", self.reference.repository))
                {
                    bail!("Unexpected registry pagination URL");
                }
                path = next.to_string();
            } else {
                return Ok(serde_json::json!({"tags":tags}));
            }
        }
        bail!("Registry tag pagination limit reached")
    }
    pub async fn manifest_for(&self, reference: &str) -> Result<(String, Value)> {
        let mut registry = self.clone();
        registry.reference.reference = reference.into();
        registry.manifest().await
    }
    pub async fn sbom(&self) -> Result<Value> {
        let data = json(
            self.get(&format!(
                "v2/{}/referrers/{}",
                self.reference.repository, self.reference.reference
            ))
            .await?,
        )
        .await?;
        for item in data["manifests"].as_array().into_iter().flatten().take(50) {
            let typ = item["artifactType"].as_str().unwrap_or_default();
            if !typ.contains("cyclonedx") && !typ.contains("spdx") {
                continue;
            }
            let digest = item["digest"].as_str().context("Invalid SBOM descriptor")?;
            valid_digest(digest)?;
            let (_, manifest) = self.manifest_for(digest).await?;
            let descriptor = manifest["layers"]
                .as_array()
                .and_then(|v| v.first())
                .context("SBOM layer absent")?;
            let blob = descriptor["digest"]
                .as_str()
                .context("SBOM digest absent")?;
            valid_digest(blob)?;
            let bytes = bytes_limited(self.blob(blob).await?, 32 * 1024 * 1024).await?;
            if format!("sha256:{}", hex::encode(Sha256::digest(&bytes))) != blob {
                bail!("SBOM integrity mismatch");
            }
            return Ok(serde_json::from_slice(&bytes)?);
        }
        bail!("SBOM OCI referrer not available")
    }
    async fn blob(&self, digest: &str) -> Result<reqwest::Response> {
        valid_digest(digest)?;
        let mut response = self
            .get(&format!("v2/{}/blobs/{digest}", self.reference.repository))
            .await?;
        for _ in 0..3 {
            if !response.status().is_redirection() {
                return Ok(response);
            }
            let location = response
                .headers()
                .get("location")
                .and_then(|s| s.to_str().ok())
                .context("Registry redirect without location")?;
            let target = response.url().join(location)?;
            let mut origin = target.clone();
            origin.set_query(None);
            origin.set_fragment(None);
            let same_origin = target.origin() == self.http.base.origin();
            let h = Http::new(
                origin.as_str(),
                self.http.trusted && same_origin,
                if same_origin {
                    self.http.ca.clone()
                } else {
                    None
                },
            )?;
            // CDN redirects are individually DNS-pinned and never receive registry credentials.
            response = h.request(Method::GET, target).await?.send().await?;
        }
        bail!("Registry blob redirect limit reached")
    }
    pub async fn pull_layout(
        &self,
        dir: &std::path::Path,
        architecture: &str,
        max_bytes: u64,
    ) -> Result<std::path::PathBuf> {
        use tokio::io::AsyncWriteExt;
        if !self.reference.reference.starts_with("sha256:") {
            bail!("OCI archive requires pinned digest");
        }
        tokio::fs::create_dir_all(dir.join("layout/blobs/sha256")).await?;
        let mut selected = self.reference.reference.clone();
        let mut media = String::new();
        let mut total = 0_u64;
        let mut document = Value::Null;
        for _ in 0..3 {
            let mut pinned = self.clone();
            pinned.reference.reference = selected.clone();
            let response = pinned
                .get(&format!(
                    "v2/{}/manifests/{selected}",
                    self.reference.repository
                ))
                .await?;
            let raw = bytes_limited(response, 8 * 1024 * 1024).await?;
            if format!("sha256:{}", hex::encode(Sha256::digest(&raw))) != selected {
                bail!("OCI manifest integrity mismatch");
            }
            document = serde_json::from_slice(&raw)?;
            if let Some(manifests) = document["manifests"].as_array() {
                selected = manifests
                    .iter()
                    .find(|m| {
                        m["platform"]["os"] == "linux"
                            && m["platform"]["architecture"] == architecture
                    })
                    .and_then(|m| m["digest"].as_str())
                    .context("Requested image architecture unavailable")?
                    .into();
                valid_digest(&selected)?;
            } else {
                media = document["mediaType"]
                    .as_str()
                    .unwrap_or("application/vnd.oci.image.manifest.v1+json")
                    .into();
                valid_digest(&selected)?;
                tokio::fs::write(dir.join("layout/blobs/sha256").join(&selected[7..]), &raw)
                    .await?;
                total += raw.len() as u64;
                break;
            }
        }
        if media.is_empty() {
            bail!("OCI manifest nesting limit exceeded");
        }
        if total > max_bytes {
            bail!("OCI manifest exceeds disk budget");
        }
        let mut descriptors = vec![document["config"].clone()];
        descriptors.extend(
            document["layers"]
                .as_array()
                .context("OCI image layers absent")?
                .clone(),
        );
        if descriptors.len() > 256 {
            bail!("Too many OCI image layers");
        }
        for descriptor in descriptors {
            let digest = descriptor["digest"]
                .as_str()
                .context("OCI blob digest absent")?;
            valid_digest(digest)?;
            let path = dir.join("layout/blobs/sha256").join(&digest[7..]);
            if tokio::fs::try_exists(&path).await? {
                continue;
            }
            let mut response = self.blob(digest).await?;
            if !response.status().is_success() {
                bail!("OCI blob download HTTP {}", response.status().as_u16());
            }
            let mut file = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await?;
            let mut hasher = Sha256::new();
            let mut size = 0_u64;
            while let Some(chunk) = response.chunk().await? {
                size += chunk.len() as u64;
                total += chunk.len() as u64;
                if total > max_bytes {
                    bail!("OCI image exceeds disk budget");
                }
                hasher.update(&chunk);
                file.write_all(&chunk).await?;
            }
            file.flush().await?;
            if format!("sha256:{}", hex::encode(hasher.finalize())) != digest
                || descriptor["size"].as_u64() != Some(size)
            {
                bail!("OCI blob integrity mismatch");
            }
        }
        let manifest_size =
            tokio::fs::metadata(dir.join("layout/blobs/sha256").join(&selected[7..]))
                .await?
                .len();
        tokio::fs::write(
            dir.join("layout/oci-layout"),
            b"{\"imageLayoutVersion\":\"1.0.0\"}",
        )
        .await?;
        tokio::fs::write(dir.join("layout/index.json"),serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"manifests":[{"mediaType":media,"digest":selected,"size":manifest_size,"annotations":{"org.opencontainers.image.ref.name":"scan"}}]}))?).await?;
        Ok(dir.join("layout"))
    }
}
fn valid_digest(digest: &str) -> Result<()> {
    if !digest.starts_with("sha256:")
        || digest.len() != 71
        || !digest[7..].bytes().all(|b| b.is_ascii_hexdigit())
    {
        bail!("Unsupported or invalid OCI digest");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };
    #[tokio::test]
    async fn manifest_digest_integrity() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("docker-content-digest", "sha256:wrong")
                    .set_body_json(serde_json::json!({"schemaVersion":2})),
            )
            .mount(&server)
            .await;
        let registry = Registry {
            http: Http::mock(&server.uri()),
            reference: ImageReference::parse("nginx:latest").unwrap(),
            credentials: None,
        };
        assert!(registry.manifest().await.is_err());
    }
    #[tokio::test]
    async fn downloads_verified_oci_layout() {
        let server = MockServer::start().await;
        let config = b"{\"architecture\":\"amd64\",\"os\":\"linux\"}";
        let config_digest = format!("sha256:{}", hex::encode(Sha256::digest(config)));
        let manifest=serde_json::to_vec(&serde_json::json!({"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":config_digest,"size":config.len()},"layers":[]})).unwrap();
        let digest = format!("sha256:{}", hex::encode(Sha256::digest(&manifest)));
        Mock::given(path(format!("/v2/library/nginx/manifests/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(manifest))
            .mount(&server)
            .await;
        Mock::given(path(format!("/v2/library/nginx/blobs/{config_digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_bytes(config.to_vec()))
            .mount(&server)
            .await;
        let registry = Registry {
            http: Http::mock(&server.uri()),
            reference: ImageReference::parse(&format!("nginx@{digest}")).unwrap(),
            credentials: None,
        };
        let dir = std::env::temp_dir().join(format!("rizenvuln-oci-test-{}", std::process::id()));
        let output = registry
            .pull_layout(&dir, "amd64", 1024 * 1024)
            .await
            .unwrap();
        let index: Value =
            serde_json::from_slice(&tokio::fs::read(output.join("index.json")).await.unwrap())
                .unwrap();
        assert_eq!(index["manifests"][0]["digest"], digest);
        assert_eq!(
            tokio::fs::read(output.join("blobs/sha256").join(&config_digest[7..]))
                .await
                .unwrap(),
            config
        );
        tokio::fs::remove_dir_all(dir).await.unwrap();
    }
}
