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
    async fn run(&self, executable: &Path, args: &[&str]) -> Result<()> {
        let mut command = Command::new(executable);
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
        self.scan_with(archive, Path::new("trivy")).await
    }
    async fn scan_with(&self, archive: &Path, executable: &Path) -> Result<ScanOutput> {
        if !archive.is_absolute() || !archive.is_dir() {
            bail!("Scanner requires local OCI layout");
        }
        tokio::fs::create_dir_all(&self.temporary).await?;
        let directory = self.temporary.join(Uuid::new_v4().to_string());
        tokio::fs::create_dir(&directory).await?;
        let result = self.scan_in(&directory, archive, executable).await;
        let _ = tokio::fs::remove_dir_all(&directory).await;
        result
    }
    async fn scan_in(&self, dir: &Path, archive: &Path, executable: &Path) -> Result<ScanOutput> {
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
            self.run(executable, &args).await?;
        }
        let mut version_command = Command::new(executable);
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

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn rejects_non_local_input_before_invoking_trivy() {
        let root = std::env::temp_dir().join(format!("scanner-test-{}", Uuid::new_v4()));
        let scanner = Scanner {
            cache: root.join("cache"),
            temporary: root.join("temp"),
            timeout: Duration::from_millis(100),
        };
        for path in [
            Path::new("relative"),
            Path::new("https://example.test/image"),
            Path::new("/does-not-exist-rizenvuln"),
        ] {
            assert!(scanner.scan(path).await.is_err());
        }
        assert!(!root.exists());
    }
    #[tokio::test]
    async fn documents_are_valid_json_and_bounded() {
        let root = std::env::temp_dir().join(format!("scanner-test-{}", Uuid::new_v4()));
        tokio::fs::create_dir(&root).await.unwrap();
        let path = root.join("document");
        tokio::fs::write(&path, b"{\"Results\":[]}").await.unwrap();
        assert!(Scanner::document(&path).await.unwrap()["Results"].is_array());
        tokio::fs::write(&path, b"invalid json").await.unwrap();
        assert!(Scanner::document(&path).await.is_err());
        let file = tokio::fs::File::create(&path).await.unwrap();
        file.set_len(64 * 1024 * 1024 + 1).await.unwrap();
        assert!(Scanner::document(&path)
            .await
            .unwrap_err()
            .to_string()
            .contains("64 MiB"));
        tokio::fs::remove_dir_all(&root).await.unwrap();
    }
}

#[cfg(all(test, unix))]
mod process_tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[tokio::test]
    async fn trivy_protocol_timeout_failure_and_cleanup() {
        let root = std::env::temp_dir().join(format!("trivy-protocol-{}", Uuid::new_v4()));
        tokio::fs::create_dir(&root).await.unwrap();
        let executable = root.join("fake-trivy");
        tokio::fs::write(
            &executable,
            br#"#!/bin/sh
set -eu
if [ "$1" = version ]; then
  echo '{"Version":"fixture"}'
  exit 0
fi
[ "$1" = image ]
shift
input= format= output=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --input) input=$2; shift 2;;
    --format) format=$2; shift 2;;
    --output) output=$2; shift 2;;
    --offline-scan) shift;;
    --timeout|--scanners) shift 2;;
    *) exit 9;;
  esac
done
case "$input" in
  *timeout) exec sleep 5;;
  *failure) exit 4;;
  *malformed) echo invalid > "$output"; exit 0;;
  *incomplete) echo '{}' > "$output"; exit 0;;
esac
case "$format" in
  json) echo '{"SchemaVersion":2,"Results":[]}' > "$output";;
  cyclonedx) echo '{"bomFormat":"CycloneDX","components":[]}' > "$output";;
  spdx-json) echo '{"spdxVersion":"SPDX-2.3","packages":[]}' > "$output";;
  *) exit 8;;
esac
"#,
        )
        .await
        .unwrap();
        tokio::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700))
            .await
            .unwrap();
        let scanner = Scanner {
            cache: root.join("cache"),
            temporary: root.join("tmp"),
            timeout: Duration::from_millis(250),
        };
        for mode in ["success", "failure", "malformed", "incomplete", "timeout"] {
            let input = root.join(mode);
            tokio::fs::create_dir(&input).await.unwrap();
            let result = scanner.scan_with(&input, &executable).await;
            if mode == "success" {
                let output = result.unwrap();
                assert_eq!(output.report["SchemaVersion"], 2);
                assert_eq!(output.cyclonedx["bomFormat"], "CycloneDX");
                assert_eq!(output.spdx["spdxVersion"], "SPDX-2.3");
                assert!(output.version.contains("fixture"));
            } else {
                assert!(result.is_err(), "{mode}");
            }
            assert!(
                tokio::fs::read_dir(&scanner.temporary)
                    .await
                    .unwrap()
                    .next_entry()
                    .await
                    .unwrap()
                    .is_none(),
                "temporary output leaked after {mode}"
            );
        }
        tokio::fs::remove_dir_all(root).await.unwrap();
    }
}
