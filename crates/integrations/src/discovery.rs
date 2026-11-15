use super::http::{json, Http};
use anyhow::{bail, Result};
use reqwest::Method;
use serde::{Deserialize, Serialize};
#[derive(Debug, Serialize, Deserialize)]
pub struct Deployment {
    pub source: String,
    pub server: String,
    pub namespace: String,
    pub container: String,
    pub image: String,
    pub digest: Option<String>,
    pub running: bool,
}
pub async fn docker(endpoint: &str, ca: Vec<u8>, identity_pem: Vec<u8>) -> Result<Vec<Deployment>> {
    // Read-only GET using TLS with client authentication. No socket, exec or mutation API.
    let mut http = Http::new(endpoint, true, Some(ca))?;
    http.identity = Some(identity_pem);
    let data = json(
        http.request(Method::GET, http.url("v1.45/containers/json?all=true")?)
            .await?
            .send()
            .await?,
    )
    .await?;
    let mut out = Vec::new();
    let mut inspected = std::collections::HashMap::<String, Vec<String>>::new();
    for c in data.as_array().into_iter().flatten() {
        let image_id = c["ImageID"].as_str().unwrap_or_default();
        let image_name = c["Image"].as_str().unwrap_or_default();
        if !inspected.contains_key(image_id)
            && image_id.starts_with("sha256:")
            && image_id.len() == 71
            && image_id[7..].bytes().all(|b| b.is_ascii_hexdigit())
        {
            let data = json(
                http.request(
                    Method::GET,
                    http.url(&format!("v1.45/images/{image_id}/json"))?,
                )
                .await?
                .send()
                .await?,
            )
            .await?;
            inspected.insert(
                image_id.into(),
                data["RepoDigests"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|s| s.as_str().map(str::to_owned))
                    .collect(),
            );
        }
        let image_ref = rizenvuln_core::ImageReference::parse(image_name).ok();
        let digest = inspected.get(image_id).into_iter().flatten().find_map(|d| {
            let candidate = rizenvuln_core::ImageReference::parse(d).ok()?;
            image_ref
                .as_ref()
                .filter(|r| {
                    r.registry == candidate.registry && r.repository == candidate.repository
                })
                .map(|_| candidate.reference)
        });
        out.push(Deployment {
            source: "docker".into(),
            server: endpoint.into(),
            namespace: String::new(),
            container: c["Id"].as_str().unwrap_or_default().into(),
            image: c["Image"].as_str().unwrap_or_default().into(),
            digest,
            running: c["State"] == "running",
        });
    }
    Ok(out)
}
pub async fn kubernetes(endpoint: &str, token: &str, ca: Vec<u8>) -> Result<Vec<Deployment>> {
    let h = Http::new(endpoint, true, Some(ca))?;
    let mut result = Vec::new();
    let mut continuation = String::new();
    for _ in 0..100 {
        let mut u = h.url("api/v1/pods")?;
        u.query_pairs_mut()
            .append_pair("limit", "500")
            .append_pair("continue", &continuation);
        let data = json(
            h.request(Method::GET, u)
                .await?
                .bearer_auth(token)
                .send()
                .await?,
        )
        .await?;
        for pod in data["items"].as_array().into_iter().flatten() {
            for c in pod["status"]["containerStatuses"]
                .as_array()
                .into_iter()
                .flatten()
            {
                result.push(Deployment {
                    source: "kubernetes".into(),
                    server: pod["spec"]["nodeName"].as_str().unwrap_or_default().into(),
                    namespace: pod["metadata"]["namespace"]
                        .as_str()
                        .unwrap_or_default()
                        .into(),
                    container: format!(
                        "{}/{}",
                        pod["metadata"]["name"].as_str().unwrap_or_default(),
                        c["name"].as_str().unwrap_or_default()
                    ),
                    image: c["image"].as_str().unwrap_or_default().into(),
                    digest: c["imageID"].as_str().and_then(|s| {
                        s.split_once("@sha256:")
                            .map(|(_, hash)| format!("sha256:{hash}"))
                    }),
                    running: c["state"]["running"].is_object(),
                });
            }
        }
        continuation = data["metadata"]["continue"]
            .as_str()
            .unwrap_or_default()
            .into();
        if continuation.is_empty() {
            return Ok(result);
        }
    }
    bail!("Kubernetes pagination limit reached")
}
