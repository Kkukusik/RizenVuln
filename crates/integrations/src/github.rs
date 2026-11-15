use super::http::{json, Http};
use anyhow::{bail, Result};
use reqwest::Method;
use serde_json::{json, Value};
#[derive(Debug)]
pub struct RateLimited {
    pub retry_after_seconds: i64,
}
impl std::fmt::Display for RateLimited {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "GitHub rate limited; retry in {} seconds",
            self.retry_after_seconds
        )
    }
}
impl std::error::Error for RateLimited {}
pub struct Github {
    http: Http,
    token: Option<String>,
}
pub enum Conditional {
    NotModified,
    Modified { data: Value, etag: Option<String> },
}
impl Github {
    pub fn new(token: Option<String>) -> Result<Self> {
        Ok(Self {
            http: Http::new("https://api.github.com/", false, None)?,
            token,
        })
    }
    pub fn repository(input: &str) -> Result<String> {
        let path = if input.starts_with("https://github.com/") {
            input
                .trim_start_matches("https://github.com/")
                .trim_end_matches('/')
        } else {
            input
        };
        let parts: Vec<_> = path.split('/').collect();
        if parts.len() != 2
            || parts.iter().any(|p| {
                p.is_empty()
                    || *p == "."
                    || *p == ".."
                    || !p
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
            })
        {
            bail!("Expected GitHub owner/repository");
        }
        Ok(path.into())
    }
    async fn get(&self, path: &str, etag: Option<&str>) -> Result<Conditional> {
        let mut req = self
            .http
            .request(Method::GET, self.http.url(path)?)
            .await?
            .header("User-Agent", "RizenVuln")
            .header("Accept", "application/vnd.github+json")
            .header("X-GitHub-Api-Version", "2022-11-28");
        if let Some(t) = &self.token {
            req = req.bearer_auth(t);
        }
        if let Some(e) = etag {
            req = req.header("If-None-Match", e);
        }
        let res = req.send().await?;
        if res.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(Conditional::NotModified);
        }
        let exhausted = res
            .headers()
            .get("x-ratelimit-remaining")
            .and_then(|h| h.to_str().ok())
            == Some("0");
        if res.status().as_u16() == 429 || (res.status().as_u16() == 403 && exhausted) {
            let retry = res
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<i64>().ok())
                .or_else(|| {
                    res.headers()
                        .get("x-ratelimit-reset")
                        .and_then(|h| h.to_str().ok())
                        .and_then(|s| s.parse::<i64>().ok())
                        .map(|t| t - chrono::Utc::now().timestamp())
                })
                .unwrap_or(60)
                .clamp(1, 86400);
            return Err(RateLimited {
                retry_after_seconds: retry,
            }
            .into());
        }
        let etag = res
            .headers()
            .get("etag")
            .and_then(|h| h.to_str().ok())
            .map(str::to_owned);
        Ok(Conditional::Modified {
            data: json(res).await?,
            etag,
        })
    }
    async fn pages(&self, path: &str) -> Result<Value> {
        let mut items = Vec::new();
        for page in 1..=100 {
            match self
                .get(
                    &format!(
                        "{path}{}per_page=100&page={page}",
                        if path.contains('?') { "&" } else { "?" }
                    ),
                    None,
                )
                .await?
            {
                Conditional::Modified { data, .. } => {
                    let a = data
                        .as_array()
                        .ok_or_else(|| anyhow::anyhow!("Unexpected GitHub response"))?;
                    let last = a.len() < 100;
                    items.extend(a.clone());
                    if last {
                        return Ok(Value::Array(items));
                    }
                }
                Conditional::NotModified => bail!("Unexpected 304"),
            }
        }
        bail!("GitHub pagination exceeds 10000 results")
    }
    pub async fn sync(
        &self,
        repo: &str,
        branch: &str,
        track_commits: bool,
        etag: Option<&str>,
    ) -> Result<Conditional> {
        let repo = Self::repository(repo)?;
        // Releases are conditionally fetched, but tags/advisories/commits are still refreshed.
        let releases = self
            .get(&format!("repos/{repo}/releases?per_page=100"), etag)
            .await?;
        let (release_data, new_etag) = match releases {
            Conditional::NotModified => (Value::Null, etag.map(str::to_owned)),
            Conditional::Modified { data, etag } => (data, etag),
        };
        let tags = self.pages(&format!("repos/{repo}/tags")).await?;
        let advisories = self
            .pages(&format!("repos/{repo}/security-advisories"))
            .await?;
        let commits = if track_commits {
            let encoded: String = url::form_urlencoded::byte_serialize(branch.as_bytes()).collect();
            match self
                .get(
                    &format!("repos/{repo}/commits?sha={encoded}&per_page=30"),
                    None,
                )
                .await?
            {
                Conditional::Modified { data, .. } => data,
                _ => Value::Null,
            }
        } else {
            Value::Null
        };
        Ok(Conditional::Modified {
            data: json!({"releases":release_data,"tags":tags,"advisories":advisories,"commits":commits}),
            etag: new_etag,
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repo_validation() {
        assert_eq!(
            Github::repository("https://github.com/goharbor/harbor").unwrap(),
            "goharbor/harbor"
        );
        assert!(Github::repository("https://evil.invalid/a/b").is_err());
        assert!(Github::repository("../test").is_err());
    }
}

#[cfg(test)]
mod mock_tests {
    use super::*;
    use wiremock::{matchers::path, Mock, MockServer, ResponseTemplate};
    #[tokio::test]
    async fn conditional_not_modified() {
        let s = MockServer::start().await;
        Mock::given(path("/repos/a/b/releases"))
            .respond_with(ResponseTemplate::new(304))
            .mount(&s)
            .await;
        let g = Github {
            http: Http::mock(&s.uri()),
            token: None,
        };
        assert!(matches!(
            g.get("repos/a/b/releases", Some("etag")).await.unwrap(),
            Conditional::NotModified
        ));
    }
    #[tokio::test]
    async fn rate_limit() {
        let s = MockServer::start().await;
        Mock::given(path("/repos/a/b/tags"))
            .respond_with(ResponseTemplate::new(429).insert_header("x-ratelimit-reset", "1234"))
            .mount(&s)
            .await;
        let g = Github {
            http: Http::mock(&s.uri()),
            token: None,
        };
        assert!(g.get("repos/a/b/tags", None).await.is_err());
    }
}
