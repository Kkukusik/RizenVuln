use super::http::{retry_get, Http};
use anyhow::{bail, Result};
use serde_json::Value;
pub struct Harbor {
    http: Http,
    user: String,
    password: String,
}
impl Harbor {
    pub fn new(
        endpoint: &str,
        user: String,
        password: String,
        ca: Option<Vec<u8>>,
    ) -> Result<Self> {
        Ok(Self {
            http: Http::new(endpoint, true, ca)?,
            user,
            password,
        })
    }
    fn path(parts: &[&str]) -> String {
        let mut u = url::Url::parse("https://placeholder.invalid/api/v2.0/").expect("static URL");
        {
            let mut p = u.path_segments_mut().expect("hierarchical URL");
            p.pop_if_empty();
            for s in parts {
                p.push(s);
            }
        }
        u.path().into()
    }
    async fn pages(&self, parts: &[&str]) -> Result<Vec<Value>> {
        let mut all = Vec::new();
        for page in 1..=1000 {
            let mut u = self.http.url(&Self::path(parts))?;
            u.query_pairs_mut()
                .append_pair("page", &page.to_string())
                .append_pair("page_size", "100")
                .append_pair("with_tag", "true");
            let v = retry_get(&self.http, u, Some((&self.user, &self.password)), None).await?;
            let items = v
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("Unexpected Harbor response"))?;
            let end = items.len() < 100;
            all.extend(items.clone());
            if end {
                return Ok(all);
            }
        }
        bail!("Harbor pagination limit reached")
    }
    pub async fn projects(&self) -> Result<Vec<Value>> {
        self.pages(&["projects"]).await
    }
    pub async fn repositories(&self, project: &str) -> Result<Vec<Value>> {
        self.pages(&["projects", project, "repositories"]).await
    }
    pub async fn artifacts(&self, project: &str, repository: &str) -> Result<Vec<Value>> {
        // Harbor requires repository slashes encoded twice.
        let encoded = repository.replace('/', "%2F");
        self.pages(&["projects", project, "repositories", &encoded, "artifacts"])
            .await
    }
    pub async fn scan_report(
        &self,
        project: &str,
        repository: &str,
        digest: &str,
    ) -> Result<Value> {
        let encoded = repository.replace('/', "%2F");
        let path = Self::path(&[
            "projects",
            project,
            "repositories",
            &encoded,
            "artifacts",
            digest,
            "additions",
            "vulnerabilities",
        ]);
        retry_get(
            &self.http,
            self.http.url(&path)?,
            Some((&self.user, &self.password)),
            Some("application/vnd.scanner.adapter.vuln.report.harbor+json; version=1.0"),
        )
        .await
    }
    pub async fn sbom(&self, project: &str, repository: &str, digest: &str) -> Result<Value> {
        let encoded = repository.replace('/', "%2F");
        let path = Self::path(&[
            "projects",
            project,
            "repositories",
            &encoded,
            "artifacts",
            digest,
            "additions",
            "sbom",
        ]);
        retry_get(
            &self.http,
            self.http.url(&path)?,
            Some((&self.user, &self.password)),
            Some("application/vnd.cyclonedx+json"),
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wiremock::{
        matchers::{method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };
    #[tokio::test]
    async fn project_pagination() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v2.0/projects"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!([{"name":"prod"}])),
            )
            .expect(1)
            .mount(&server)
            .await;
        let h = Harbor {
            http: Http::mock(&server.uri()),
            user: "robot".into(),
            password: "mock-only".into(),
        };
        assert_eq!(h.projects().await.unwrap()[0]["name"], "prod");
    }
    #[tokio::test]
    async fn unauthorized_is_error() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .respond_with(ResponseTemplate::new(401))
            .mount(&server)
            .await;
        let h = Harbor {
            http: Http::mock(&server.uri()),
            user: String::new(),
            password: String::new(),
        };
        assert!(h.projects().await.is_err());
    }
    #[test]
    fn double_encoding() {
        assert!(Harbor::path(&["repositories", "a%2Fb"]).contains("a%252Fb"));
    }
}
