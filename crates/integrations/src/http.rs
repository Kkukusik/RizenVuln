use anyhow::{bail, Context, Result};
use reqwest::{Client, Method, RequestBuilder, Response};
use std::{net::SocketAddr, time::Duration};
use url::Url;
#[derive(Clone)]
pub struct Http {
    pub base: Url,
    pub trusted: bool,
    pub ca: Option<Vec<u8>>,
    pub identity: Option<Vec<u8>>,
    #[cfg(test)]
    test_http: bool,
}
impl Http {
    pub fn new(base: &str, trusted: bool, ca: Option<Vec<u8>>) -> Result<Self> {
        let base = Url::parse(base).context("Invalid integration URL")?;
        if base.scheme() != "https"
            || base.host_str().is_none()
            || !base.username().is_empty()
            || base.password().is_some()
            || base.query().is_some()
        {
            bail!("Integration requires an HTTPS URL without credentials/query");
        }
        Ok(Self {
            base,
            trusted,
            ca,
            identity: None,
            #[cfg(test)]
            test_http: false,
        })
    }
    pub async fn request(&self, method: Method, url: Url) -> Result<RequestBuilder> {
        if url.origin() != self.base.origin() {
            bail!("Cross-origin request denied");
        }
        #[cfg(test)]
        if self.test_http {
            return Ok(Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()?
                .request(method, url));
        }
        let host = url.host_str().context("Missing hostname")?;
        let port = url.port_or_known_default().context("Missing port")?;
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
            .await
            .context("Integration DNS resolution failed")?
            .collect();
        if addresses.is_empty() || addresses.iter().any(|a| forbidden_ip(a.ip())) {
            bail!("Forbidden integration address");
        }
        if !self.trusted && addresses.iter().any(|a| !rizenvuln_core::public_ip(a.ip())) {
            bail!("Non-public integration address denied");
        }
        let mut builder = Client::builder()
            .timeout(Duration::from_secs(45))
            .connect_timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .resolve_to_addrs(host, &addresses)
            .https_only(true)
            .no_proxy();
        if let Some(ca) = &self.ca {
            builder = builder.add_root_certificate(
                reqwest::Certificate::from_pem(ca).context("Invalid integration CA")?,
            );
        }
        if let Some(identity) = &self.identity {
            builder = builder.identity(reqwest::Identity::from_pem(identity)?);
        }
        Ok(builder.build()?.request(method, url))
    }
    #[cfg(test)]
    pub(crate) fn mock(base: &str) -> Self {
        Self {
            base: Url::parse(base).unwrap(),
            trusted: false,
            ca: None,
            identity: None,
            test_http: true,
        }
    }
    pub fn url(&self, path: &str) -> Result<Url> {
        let u = self.base.join(path)?;
        if u.origin() != self.base.origin() {
            bail!("Cross-origin URL denied");
        }
        Ok(u)
    }
}
fn forbidden_ip(ip: std::net::IpAddr) -> bool {
    if let std::net::IpAddr::V6(a) = ip {
        if let Some(v4) = a.to_ipv4_mapped() {
            return forbidden_ip(std::net::IpAddr::V4(v4));
        }
    }
    ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || is_metadata(ip)
}
fn is_metadata(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(a) => a.is_link_local() || a.octets() == [100, 100, 100, 200],
        std::net::IpAddr::V6(a) => a.is_unicast_link_local() || a.to_string() == "fd00:ec2::254",
    }
}
pub async fn bytes_limited(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if !response.status().is_success() {
        bail!("External API HTTP {}", response.status().as_u16());
    }
    if response.content_length().is_some_and(|s| s > limit as u64) {
        bail!("External response too large");
    }
    let mut data = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        if data.len() + chunk.len() > limit {
            bail!("External response too large");
        }
        data.extend_from_slice(&chunk);
    }
    Ok(data)
}
pub async fn json(response: Response) -> Result<serde_json::Value> {
    Ok(serde_json::from_slice(
        &bytes_limited(response, 32 * 1024 * 1024).await?,
    )?)
}
pub async fn retry_get(
    http: &Http,
    url: Url,
    user: Option<(&str, &str)>,
    accept: Option<&str>,
) -> Result<serde_json::Value> {
    for attempt in 0..3 {
        let mut req = http.request(Method::GET, url.clone()).await?;
        if let Some((u, p)) = user {
            req = req.basic_auth(u, Some(p));
        }
        if let Some(a) = accept {
            req = req.header("Accept", a);
        }
        let r = req.send().await.context("External request failed")?;
        if (r.status().is_server_error() || r.status().as_u16() == 429) && attempt < 2 {
            tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
            continue;
        }
        return json(r).await;
    }
    bail!("Retry limit reached")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_insecure_config() {
        for s in [
            "http://example.org",
            "https://user:password@example.org",
            "file:///etc/passwd",
        ] {
            assert!(Http::new(s, false, None).is_err());
        }
    }
    #[tokio::test]
    async fn rejects_metadata_and_cross_origin() {
        let h = Http::new("https://169.254.169.254/", true, None).unwrap();
        assert!(h.request(Method::GET, h.base.clone()).await.is_err());
        let h = Http::new("https://example.org/", false, None).unwrap();
        assert!(h
            .request(Method::GET, Url::parse("https://evil.invalid/").unwrap())
            .await
            .is_err());
    }
}
