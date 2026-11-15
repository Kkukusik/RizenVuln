use super::http::{json, Http};
use anyhow::Result;
use reqwest::Method;
use serde_json::Value;
pub async fn kev() -> Result<Value> {
    let h = Http::new("https://www.cisa.gov/", false, None)?;
    json(
        h.request(
            Method::GET,
            h.url("sites/default/files/feeds/known_exploited_vulnerabilities.json")?,
        )
        .await?
        .send()
        .await?,
    )
    .await
}
pub async fn epss(cves: &[String]) -> Result<Value> {
    let h = Http::new("https://api.first.org/", false, None)?;
    let mut u = h.url("data/v1/epss")?;
    u.query_pairs_mut().append_pair("cve", &cves.join(","));
    json(h.request(Method::GET, u).await?.send().await?).await
}
