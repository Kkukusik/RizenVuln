use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::process::Command;
use uuid::Uuid;
pub struct ScanOutput {
    pub report: Value,
    pub cyclonedx: Value,
    pub spdx: Value,
    pub version: String,
}
pub struct Scanner {
    pub cache: PathBuf,
    pub temporary: PathBuf,
    pub timeout: Duration,
}
impl Scanner {
    async fn run(&self, args: &[&str]) -> Result<()> {
        let mut command = Command::new("trivy");
        command
            .env_clear()
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .env("HOME", "/tmp")
            .env("TRIVY_CACHE_DIR", &self.cache)
            .env("TMPDIR", &self.temporary)
            .args(args)
            .kill_on_drop(true)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        let status = tokio::time::timeout(self.timeout, command.status())
            .await
            .context("Trivy timeout")??;
        if !status.success() {
            bail!("Trivy execution failed: {status}");
        }
        Ok(())
    }
    async fn document(path: &Path) -> Result<Value> {
        if tokio::fs::metadata(path).await?.len() > 64 * 1024 * 1024 {
            bail!("Trivy document exceeds 64 MiB");
        }
        Ok(serde_json::from_slice(&tokio::fs::read(path).await?)?)
    }
    pub async fn scan(&self, archive: &Path) -> Result<ScanOutput> {
        if !archive.is_absolute() || !archive.is_dir() {
            bail!("Scanner requires local OCI layout");
        }
        tokio::fs::create_dir_all(&self.temporary).await?;
        let directory = self.temporary.join(Uuid::new_v4().to_string());
        tokio::fs::create_dir(&directory).await?;
        let result = self.scan_in(&directory, archive).await;
        let _ = tokio::fs::remove_dir_all(&directory).await;
        result
    }
    async fn scan_in(&self, dir: &Path, archive: &Path) -> Result<ScanOutput> {
        let input = archive.to_str().context("Invalid OCI archive path")?;
        for format in ["json", "cyclonedx", "spdx-json"] {
            let output = dir.join(format!("{format}.json"));
            let mut args = vec![
                "image",
                "--offline-scan",
                "--input",
                input,
                "--format",
                format,
                "--timeout",
                "20m",
                "--output",
                output.to_str().context("Invalid output path")?,
            ];
            if format == "json" {
                args.extend(["--scanners", "vuln"]);
            }
            self.run(&args).await?;
        }
        let mut version_command = Command::new("trivy");
        version_command
            .env_clear()
            .env("TRIVY_CACHE_DIR", &self.cache)
            .env("PATH", "/usr/local/bin:/usr/bin:/bin")
            .args(["version", "--format", "json"])
            .kill_on_drop(true);
        let output =
            tokio::time::timeout(Duration::from_secs(10), version_command.output()).await??;
        if !output.status.success() || output.stdout.len() > 65536 {
            bail!("Trivy version query failed");
        }
        let version = String::from_utf8(output.stdout)?;
        let report = Self::document(&dir.join("json.json")).await?;
        if report["SchemaVersion"].is_null() || !report["Results"].is_array() {
            bail!("Incomplete Trivy vulnerability report");
        }
        Ok(ScanOutput {
            report,
            cyclonedx: Self::document(&dir.join("cyclonedx.json")).await?,
            spdx: Self::document(&dir.join("spdx-json.json")).await?,
            version,
        })
    }
}
