use super::http::Http;
use anyhow::{bail, Result};
use chrono::Utc;
use hmac::{Hmac, Mac};
use reqwest::Method;
use sha2::{Digest, Sha256};
type HmacSha256 = Hmac<Sha256>;
pub struct S3 {
    http: Http,
    region: String,
    bucket: String,
    access: String,
    secret: String,
    path_style: bool,
}
fn hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}
fn hmac(key: &[u8], data: &str) -> Vec<u8> {
    let mut m = HmacSha256::new_from_slice(key).expect("HMAC accepts arbitrary length keys");
    m.update(data.as_bytes());
    m.finalize().into_bytes().to_vec()
}
impl S3 {
    pub fn new(
        endpoint: &str,
        region: String,
        bucket: String,
        access: String,
        secret: String,
        path_style: bool,
        ca: Option<Vec<u8>>,
    ) -> Result<Self> {
        if bucket.is_empty()
            || !bucket
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b".-".contains(&b))
        {
            bail!("Invalid S3 bucket");
        }
        Ok(Self {
            http: Http::new(endpoint, true, ca)?,
            region,
            bucket,
            access,
            secret,
            path_style,
        })
    }
    pub async fn put(&self, key: &str, bytes: Vec<u8>, content_type: &str) -> Result<()> {
        if key
            .split('/')
            .any(|p| p.is_empty() || p == ".." || p == ".")
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/-_.".contains(&b))
        {
            bail!("Invalid object key");
        }
        let mut url = self.http.base.clone();
        if self.path_style {
            url.set_path(&format!("/{}/{key}", self.bucket));
        } else {
            let host = format!(
                "{}.{}",
                self.bucket,
                url.host_str()
                    .ok_or_else(|| anyhow::anyhow!("Missing S3 host"))?
            );
            url.set_host(Some(&host))?;
            url.set_path(&format!("/{key}"));
        }
        let now = Utc::now();
        let timestamp = now.format("%Y%m%dT%H%M%SZ").to_string();
        let date = now.format("%Y%m%d").to_string();
        let host = match url.port() {
            Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
            None => url.host_str().unwrap_or_default().into(),
        };
        let payload_hash = hash(&bytes);
        let signed_headers = "host;x-amz-content-sha256;x-amz-date";
        let canonical = format!(
            "PUT\n{}\n\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\n{}\n{}",
            url.path(),
            host,
            payload_hash,
            timestamp,
            signed_headers,
            payload_hash
        );
        let scope = format!("{date}/{}/s3/aws4_request", self.region);
        let sign_string = format!(
            "AWS4-HMAC-SHA256\n{timestamp}\n{scope}\n{}",
            hash(canonical.as_bytes())
        );
        let kdate = hmac(format!("AWS4{}", self.secret).as_bytes(), &date);
        let kr = hmac(&kdate, &self.region);
        let ks = hmac(&kr, "s3");
        let signing = hmac(&ks, "aws4_request");
        let signature = hex::encode(hmac(&signing, &sign_string));
        let authorization=format!("AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",self.access);
        // Virtual hosting changes the origin, so construct the pinned transport for this exact configured bucket host.
        let mut transport = self.http.clone();
        transport.base = url.clone();
        let response = transport
            .request(Method::PUT, url)
            .await?
            .header("Host", host)
            .header("x-amz-content-sha256", payload_hash)
            .header("x-amz-date", timestamp)
            .header("Authorization", authorization)
            .header("Content-Type", content_type)
            .body(bytes)
            .send()
            .await?;
        super::http::bytes_limited(response, 1024 * 1024).await?;
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_vector() {
        assert_eq!(
            hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
    #[test]
    fn hmac_vector() {
        assert_eq!(
            hex::encode(hmac(b"key", "The quick brown fox jumps over the lazy dog")),
            "f7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8"
        );
    }
}

#[cfg(test)]
mod mock_tests {
    use super::*;
    use wiremock::{
        matchers::{body_bytes, header_exists, method, path},
        Mock, MockServer, ResponseTemplate,
    };
    #[tokio::test]
    async fn signed_put() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/reports/reports/test/data.json"))
            .and(header_exists("authorization"))
            .and(header_exists("x-amz-content-sha256"))
            .and(body_bytes(b"{}".to_vec()))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;
        let s = S3 {
            http: Http::mock(&server.uri()),
            region: "test-region".into(),
            bucket: "reports".into(),
            access: "mock-access".into(),
            secret: "mock-secret".into(),
            path_style: true,
        };
        s.put("reports/test/data.json", b"{}".to_vec(), "application/json")
            .await
            .unwrap();
    }
    #[tokio::test]
    async fn upload_error() {
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(403))
            .mount(&server)
            .await;
        let s = S3 {
            http: Http::mock(&server.uri()),
            region: "test-region".into(),
            bucket: "reports".into(),
            access: "mock-access".into(),
            secret: "mock-secret".into(),
            path_style: true,
        };
        assert!(s.put("x.json", vec![], "application/json").await.is_err());
    }
}
