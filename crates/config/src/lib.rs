use anyhow::{bail, Context, Result};
use std::env;

pub trait SecretProvider {
    fn get(&self, key: &str) -> Result<String>;
}
pub struct EnvironmentSecretProvider;
impl SecretProvider for EnvironmentSecretProvider {
    fn get(&self, key: &str) -> Result<String> {
        let value = env::var(key).with_context(|| format!("Не задан {key}"))?;
        if value.is_empty() || value == "CHANGE_ME" {
            bail!("Не настроен {key}");
        }
        Ok(value)
    }
}
#[derive(Clone)]
pub struct Config {
    pub database_url: String,
    pub bind: String,
    pub public_url: String,
    pub secure_cookie: bool,
    pub admin_email: String,
    pub admin_password: String,
    pub session_secret: String,
    pub scan_enabled: bool,
    pub scan_interval: u64,
    pub concurrency: usize,
    pub trivy_cache: String,
}
pub fn value(key: &str, default: &str) -> String {
    env::var(key)
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.into())
}
pub fn enabled(key: &str, default: bool) -> bool {
    value(key, if default { "true" } else { "false" }) == "true"
}
impl Config {
    pub fn load() -> Result<Self> {
        let secrets = EnvironmentSecretProvider;
        let session_secret = secrets.get("SESSION_SECRET")?;
        if session_secret.len() < 32 {
            bail!("SESSION_SECRET должен содержать не менее 32 символов");
        }
        let admin_email = secrets.get("ADMIN_EMAIL")?;
        let admin_password = secrets.get("ADMIN_PASSWORD")?;
        if !admin_email.contains('@') || admin_password.len() < 16 {
            bail!("ADMIN_EMAIL или ADMIN_PASSWORD не соответствует политике");
        }
        let public_url = value("PUBLIC_BASE_URL", "http://localhost:8080");
        let url = url::Url::parse(&public_url).context("Некорректный PUBLIC_BASE_URL")?;
        if !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
        {
            bail!("Некорректный PUBLIC_BASE_URL");
        }
        if value("APP_ENV", "development") == "production" && url.scheme() != "https" {
            bail!("В production требуется PUBLIC_BASE_URL с HTTPS");
        }
        for (flag, keys) in [
            (
                "HARBOR_ENABLED",
                &["HARBOR_URL", "HARBOR_USERNAME", "HARBOR_PASSWORD"][..],
            ),
            (
                "S3_ENABLED",
                &[
                    "S3_ENDPOINT",
                    "S3_REGION",
                    "S3_BUCKET",
                    "S3_ACCESS_KEY",
                    "S3_SECRET_KEY",
                ][..],
            ),
            (
                "TELEGRAM_ENABLED",
                &["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"][..],
            ),
            (
                "DOCKER_DISCOVERY_ENABLED",
                &["DOCKER_HOST", "DOCKER_CA_FILE", "DOCKER_IDENTITY_FILE"][..],
            ),
            (
                "KUBERNETES_ENABLED",
                &["KUBERNETES_URL", "KUBERNETES_TOKEN", "KUBERNETES_CA_FILE"][..],
            ),
        ] {
            if enabled(flag, false) {
                for key in keys {
                    secrets.get(key)?;
                }
            }
        }
        let scan_interval = value("SCAN_INTERVAL_HOURS", "24")
            .parse::<u64>()
            .context("SCAN_INTERVAL_HOURS")?
            .clamp(1, 8760)
            * 3600;
        Ok(Self {
            database_url: secrets.get("DATABASE_URL")?,
            bind: format!(
                "{}:{}",
                value("APP_HOST", "0.0.0.0"),
                value("APP_PORT", "8080")
            ),
            secure_cookie: url.scheme() == "https",
            public_url: url.origin().ascii_serialization(),
            admin_email,
            admin_password,
            session_secret,
            scan_enabled: enabled("SCAN_ENABLED", true),
            scan_interval,
            concurrency: value("MAX_CONCURRENT_SCANS", "1")
                .parse::<usize>()
                .context("MAX_CONCURRENT_SCANS")?
                .clamp(1, 8),
            trivy_cache: value("TRIVY_CACHE_DIR", "/var/cache/trivy"),
        })
    }
}
