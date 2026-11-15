use anyhow::{bail, Context, Result};
use rizenvuln_config::{enabled, value, Config, EnvironmentSecretProvider, SecretProvider};
use rizenvuln_database::Job;
use rizenvuln_integrations::{
    github::{Conditional, Github},
    harbor::Harbor,
    registry::Registry,
    s3::S3,
};
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};
use uuid::Uuid;
pub async fn process(pool: &PgPool, c: &Config, job: &Job) -> Result<()> {
    let integration = match job.kind.as_str() {
        "github" => Some("github"),
        "harbor" => Some("harbor"),
        "telegram" => Some("telegram"),
        "upload" => Some("s3"),
        "docker" => Some("docker"),
        "kubernetes" => Some("kubernetes"),
        _ => None,
    };
    let result = match job.kind.as_str() {
        "image" => image(pool, c, job).await,
        "github" => github(pool, job).await,
        "harbor" => harbor(pool, job).await,
        "telegram" => telegram(pool, job).await,
        "upload" => upload(pool, job).await,
        "intelligence" => intelligence(pool).await,
        "docker" | "kubernetes" => discover(pool, &job.kind).await,
        _ => Err(anyhow::anyhow!("Unknown job type")),
    };
    if let Some(kind) = integration {
        sqlx::query("UPDATE integrations SET status=$2,error=$3,last_checked=now(),errors_total=errors_total+CASE WHEN $2='ERROR' THEN 1 ELSE 0 END WHERE kind=$1")
            .bind(kind)
            .bind(if result.is_ok() { "CONNECTED" } else { "ERROR" })
            .bind(if result.is_ok() {
                None
            } else {
                Some("API request failed; check configuration and credentials")
            })
            .execute(pool)
            .await?;
    }
    if result.is_err() && job.kind != "telegram" && enabled("TELEGRAM_ENABLED", false) {
        rizenvuln_database::notification(
            pool,
            &format!("job-failed:{}", job.id),
            "scan_or_integration_failed",
            &format!("RizenVuln: не выполнено задание {} ({})", job.kind, job.id),
        )
        .await?;
    }
    result
}
fn id(job: &Job, key: &str) -> Result<Uuid> {
    Ok(job.payload[key]
        .as_str()
        .context("Missing job entity ID")?
        .parse()?)
}
fn secret(key: &str) -> Result<String> {
    EnvironmentSecretProvider.get(key)
}
fn ca(key: &str) -> Result<Option<Vec<u8>>> {
    std::env::var(key)
        .ok()
        .filter(|p| !p.is_empty())
        .map(std::fs::read)
        .transpose()
        .map_err(Into::into)
}
async fn github(pool: &PgPool, job: &Job) -> Result<()> {
    if !enabled("GITHUB_ENABLED", true) {
        bail!("GitHub disabled");
    }
    let id = id(job, "repository_id")?;
    let r = sqlx::query(
        "SELECT full_name,branch,track_commits,etag,data FROM repositories WHERE id=$1",
    )
    .bind(id)
    .fetch_one(pool)
    .await?;
    let client = Github::new(std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()))?;
    let name: String = r.get("full_name");
    let branch: String = r.get("branch");
    let etag: Option<String> = r.get("etag");
    let result = client
        .sync(&name, &branch, r.get("track_commits"), etag.as_deref())
        .await;
    let result = match result {
        Ok(v) => v,
        Err(e) => {
            sqlx::query("UPDATE repositories SET status='ERROR',last_checked=now() WHERE id=$1")
                .bind(id)
                .execute(pool)
                .await?;
            return Err(e);
        }
    };
    if let Conditional::Modified { mut data, etag } = result {
        let old: Value = r.get("data");
        if data["releases"].is_null() {
            data["releases"] = old["releases"].clone();
        }
        if enabled("TELEGRAM_ENABLED", false) {
            for release in data["releases"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["prerelease"] == false && r["draft"] == false)
                .take(1)
            {
                let tag = release["tag_name"].as_str().unwrap_or_default();
                rizenvuln_database::notification(
                    pool,
                    &format!("release:{id}:{tag}"),
                    "stable_release",
                    &format!("RizenVuln: {name}, стабильный релиз {tag}"),
                )
                .await?;
            }
        }
        sqlx::query("UPDATE repositories SET data=$2,etag=$3,status='SYNCED',last_checked=now() WHERE id=$1").bind(id).bind(data).bind(etag).execute(pool).await?;
    }
    Ok(())
}
async fn image(pool: &PgPool, c: &Config, job: &Job) -> Result<()> {
    let image_id = id(job, "image_id")?;
    let row = sqlx::query("SELECT reference,digest FROM images WHERE id=$1")
        .bind(image_id)
        .fetch_one(pool)
        .await?;
    let reference: String = row.get("reference");
    let parsed = rizenvuln_core::ImageReference::parse(&reference)?;
    let credentials = match parsed.registry.as_str() {
        "registry-1.docker.io" => {
            if let (Ok(u), Ok(p)) = (secret("DOCKERHUB_USERNAME"), secret("DOCKERHUB_TOKEN")) {
                Some((u, p))
            } else {
                None
            }
        }
        "ghcr.io" => {
            if let (Ok(u), Ok(p)) = (secret("GHCR_USERNAME"), secret("GITHUB_TOKEN")) {
                Some((u, p))
            } else {
                None
            }
        }
        _ => None,
    };
    let registry = Registry::new(parsed.clone(), credentials.clone())?;
    let (digest, manifest) = match registry.manifest().await {
        Ok(r) => r,
        Err(e) => {
            sqlx::query("UPDATE images SET status='ERROR',last_checked=now() WHERE id=$1")
                .bind(image_id)
                .execute(pool)
                .await?;
            return Err(e);
        }
    };
    let old_digest: Option<String> = row.get("digest");
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE images SET digest=$2,metadata=$3,status='DISCOVERED',last_checked=now() WHERE id=$1").bind(image_id).bind(&digest).bind(json!({"manifest":manifest,"previous_digest":old_digest})).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO image_versions(id,image_id,tag,digest,architecture) VALUES($1,$2,$3,$4,$5) ON CONFLICT(image_id,tag,digest) DO NOTHING").bind(Uuid::new_v4()).bind(image_id).bind(&parsed.reference).bind(&digest).bind(manifest["manifests"].clone()).execute(&mut *tx).await?;
    tx.commit().await?;
    let deployed:Option<String>=sqlx::query_scalar("SELECT digest FROM deployments WHERE image=$1 AND environment='production' AND running=true ORDER BY last_seen DESC LIMIT 1").bind(&reference).fetch_optional(pool).await?.flatten();
    let tags = registry.tags().await.unwrap_or_else(|_| json!({"tags":[]}));
    let candidate = rizenvuln_core::latest_stable(
        &parsed.reference,
        tags["tags"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str),
    )
    .unwrap_or_else(|| parsed.reference.clone());
    let candidate_digest = if candidate == parsed.reference {
        digest.clone()
    } else {
        registry.manifest_for(&candidate).await?.0
    };
    let mut recommendation = rizenvuln_core::recommend(
        &parsed.reference,
        &candidate,
        deployed.as_deref().or(old_digest.as_deref()),
        Some(&candidate_digest),
        true,
        false,
    );
    let approved:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM version_approvals WHERE image_id=$1 AND digest=$2 AND environment='production')").bind(image_id).bind(&candidate_digest).fetch_one(pool).await?;
    let testing:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM deployments WHERE digest=$1 AND environment='test' AND running=true)").bind(&candidate_digest).fetch_one(pool).await?;
    if deployed.as_deref() == Some(&candidate_digest) {
        recommendation.status = rizenvuln_core::UpdateStatus::Deployed;
    } else if approved {
        recommendation.status = rizenvuln_core::UpdateStatus::Approved;
    } else if testing {
        recommendation.status = rizenvuln_core::UpdateStatus::Testing;
    }
    let status = serde_json::to_value(&recommendation.status)?
        .as_str()
        .context("Invalid update status")?
        .to_owned();
    let duplicate:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM (SELECT digest,status FROM update_recommendations WHERE image_id=$1 ORDER BY created_at DESC LIMIT 1) r WHERE r.digest=$2 AND r.status=$3)").bind(image_id).bind(&candidate_digest).bind(&status).fetch_one(pool).await?;
    if !duplicate {
        sqlx::query("INSERT INTO update_recommendations(id,image_id,candidate,digest,status,major_warning,reason) VALUES($1,$2,$3,$4,$5,$6,$7)").bind(Uuid::new_v4()).bind(image_id).bind(&candidate).bind(&candidate_digest).bind(status).bind(recommendation.major_warning).bind(recommendation.reason).execute(pool).await?;
    }
    if !duplicate
        && enabled("TELEGRAM_ENABLED", false)
        && matches!(
            recommendation.status,
            rizenvuln_core::UpdateStatus::UpdateAvailable
                | rizenvuln_core::UpdateStatus::Outdated
                | rizenvuln_core::UpdateStatus::SecurityFixAvailable
        )
    {
        rizenvuln_database::notification(pool,&format!("update:{image_id}:{candidate_digest}"),"image_outdated",&format!("RizenVuln: для {reference} доступно обновление {candidate}; digest {candidate_digest}")).await?;
    }
    if !c.scan_enabled {
        return Ok(());
    }
    let run = Uuid::new_v4();
    sqlx::query("INSERT INTO scan_runs(id,image_id,digest,status) VALUES($1,$2,$3,'RUNNING')")
        .bind(run)
        .bind(image_id)
        .bind(&digest)
        .execute(pool)
        .await?;
    let start = Instant::now();
    let allowed = value("SCAN_REGISTRY_ALLOWLIST", "registry-1.docker.io,ghcr.io");
    if !allowed.split(',').any(|s| s.trim() == parsed.registry) {
        sqlx::query("UPDATE scan_runs SET status='FAILED',completed_at=now(),error='Registry not permitted by SCAN_REGISTRY_ALLOWLIST' WHERE id=$1").bind(run).execute(pool).await?;
        bail!("Registry not allowed for scanning");
    }
    let scanner = rizenvuln_scanner::Scanner {
        cache: PathBuf::from(&c.trivy_cache),
        temporary: PathBuf::from(value("SCAN_TMP_DIR", "/tmp/rizenvuln")),
        timeout: Duration::from_secs(1500),
    };
    let pull_dir =
        PathBuf::from(value("SCAN_TMP_DIR", "/tmp/rizenvuln")).join(format!("pull-{run}"));
    let mut pinned = parsed.clone();
    pinned.reference = digest.clone();
    let pull = Registry::new(pinned, credentials)?;
    let limit = value("MAX_IMAGE_BYTES", "1073741824")
        .parse::<u64>()?
        .clamp(1024 * 1024, 1073741824);
    let downloaded = pull
        .pull_layout(&pull_dir, &value("SCAN_ARCHITECTURE", "amd64"), limit)
        .await;
    let outcome = match downloaded {
        Ok(path) => scanner.scan(&path).await,
        Err(e) => Err(e),
    };
    let _ = tokio::fs::remove_dir_all(&pull_dir).await;
    match outcome {
        Ok(output) => {
            let findings = rizenvuln_core::trivy_findings(&output.report);
            persist(
                pool,
                run,
                image_id,
                &findings,
                serde_json::from_str::<Value>(&output.version).ok().and_then(|v|v["Version"].as_str().map(str::to_owned)).as_deref().unwrap_or("unknown"),
                json!({"image":output.report["Metadata"],"scanner":serde_json::from_str::<Value>(&output.version).unwrap_or(Value::Null)}),
                start.elapsed().as_secs_f64(),
            )
            .await?;
            for (format, document) in [
                ("trivy-json", output.report),
                ("cyclonedx-json", output.cyclonedx),
                ("spdx-json", output.spdx),
            ] {
                artifact(pool, run, format, document).await?;
            }
            sqlx::query("UPDATE images SET status='SCANNED' WHERE id=$1")
                .bind(image_id)
                .execute(pool)
                .await?;
        }
        Err(e) => {
            sqlx::query("UPDATE scan_runs SET status='FAILED',completed_at=now(),error='Trivy execution failed',duration_seconds=$2 WHERE id=$1").bind(run).bind(start.elapsed().as_secs_f64()).execute(pool).await?;
            sqlx::query("UPDATE images SET status='SCAN_FAILED' WHERE id=$1")
                .bind(image_id)
                .execute(pool)
                .await?;
            return Err(e);
        }
    }
    Ok(())
}
async fn persist(
    pool: &PgPool,
    run: Uuid,
    image: Uuid,
    findings: &[rizenvuln_core::Finding],
    version: &str,
    metadata: Value,
    duration: f64,
) -> Result<()> {
    let mut tx = pool.begin().await?;
    for f in findings {
        sqlx::query("INSERT INTO vulnerabilities(id,title,severity) VALUES($1,$2,$3) ON CONFLICT(id) DO UPDATE SET title=EXCLUDED.title,severity=EXCLUDED.severity,updated_at=now()").bind(&f.cve).bind(&f.title).bind(&f.severity).execute(&mut *tx).await?;
        let previous_status:Option<String>=sqlx::query_scalar("SELECT f.status FROM vulnerability_findings f JOIN scan_runs s ON s.id=f.scan_run_id WHERE f.image_id=$1 AND f.vulnerability_id=$2 AND f.package=$3 AND f.installed_version=$4 AND f.target=$5 AND s.status='COMPLETED' ORDER BY s.started_at DESC LIMIT 1").bind(image).bind(&f.cve).bind(&f.package).bind(&f.installed).bind(&f.target).fetch_optional(&mut *tx).await?;
        // A fresh finding is never automatically FIXED based on a prior manual decision.
        let status = previous_status
            .filter(|s| s != "FIXED" && s != "PENDING_VERIFICATION")
            .unwrap_or("NEW".into());
        sqlx::query("INSERT INTO vulnerability_findings(id,vulnerability_id,scan_run_id,image_id,package,installed_version,fixed_version,target,severity,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) ON CONFLICT(scan_run_id,vulnerability_id,package,installed_version,target) DO NOTHING").bind(Uuid::new_v4()).bind(&f.cve).bind(run).bind(image).bind(&f.package).bind(&f.installed).bind(&f.fixed).bind(&f.target).bind(&f.severity).bind(status).execute(&mut *tx).await?;
    }
    sqlx::query("UPDATE scan_runs SET status='COMPLETED',completed_at=now(),scanner_version=$2,database_metadata=$3,duration_seconds=$4 WHERE id=$1").bind(run).bind(version).bind(metadata).bind(duration).execute(&mut *tx).await?;
    tx.commit().await?;
    if enabled("TELEGRAM_ENABLED", false) {
        for f in findings {
            if ["CRITICAL", "HIGH"].contains(&f.severity.as_str()) || !f.fixed.is_empty() {
                let key = format!(
                    "finding:{image}:{}:{}:{}:{}:{}",
                    f.cve, f.package, f.installed, f.severity, f.fixed
                );
                rizenvuln_database::notification(
                    pool,
                    &key,
                    if f.fixed.is_empty() {
                        "vulnerability"
                    } else {
                        "fix_available"
                    },
                    &format!(
                        "RizenVuln: {} {} / {} {}; исправление: {}",
                        f.severity,
                        f.cve,
                        f.package,
                        f.installed,
                        if f.fixed.is_empty() {
                            "неизвестно"
                        } else {
                            &f.fixed
                        }
                    ),
                )
                .await?;
            }
        }
    }
    Ok(())
}
async fn artifact(pool: &PgPool, run: Uuid, format: &str, document: Value) -> Result<()> {
    artifact_with_upload(pool, run, format, document, enabled("S3_ENABLED", false)).await
}
async fn artifact_with_upload(
    pool: &PgPool,
    run: Uuid,
    format: &str,
    document: Value,
    upload_enabled: bool,
) -> Result<()> {
    use sha2::{Digest, Sha256};
    let bytes = serde_json::to_vec(&document)?;
    let id = Uuid::new_v4();
    let key = format!("reports/{run}/{format}.json");
    let mut tx = pool.begin().await?;
    let inserted: Option<Uuid> = sqlx::query_scalar("INSERT INTO sbom_artifacts(id,scan_run_id,format,object_key,sha256,document,storage_status) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(scan_run_id,format) DO NOTHING RETURNING id").bind(id).bind(run).bind(format).bind(&key).bind(hex::encode(Sha256::digest(&bytes))).bind(document).bind(if upload_enabled{"PENDING"}else{"LOCAL_ONLY"}).fetch_optional(&mut *tx).await?;
    // A retry must not queue an upload for the fresh UUID rejected by ON CONFLICT.
    if upload_enabled && inserted.is_some() {
        sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,'upload',$2,$3) ON CONFLICT(dedup_key) WHERE status IN ('PENDING','RUNNING') DO NOTHING").bind(Uuid::new_v4()).bind(json!({"artifact_id":id})).bind(format!("upload:{id}")).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn upload(pool: &PgPool, job: &Job) -> Result<()> {
    let id = id(job, "artifact_id")?;
    let r = sqlx::query("SELECT object_key,document FROM sbom_artifacts WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    let key: String = r.get("object_key");
    let document: Value = r.get("document");
    let s3 = S3::new(
        &secret("S3_ENDPOINT")?,
        secret("S3_REGION")?,
        secret("S3_BUCKET")?,
        secret("S3_ACCESS_KEY")?,
        secret("S3_SECRET_KEY")?,
        enabled("S3_FORCE_PATH_STYLE", true),
        ca("S3_CA_FILE")?,
    )?;
    let result = s3
        .put(&key, serde_json::to_vec(&document)?, "application/json")
        .await;
    sqlx::query("UPDATE sbom_artifacts SET storage_status=$2 WHERE id=$1")
        .bind(id)
        .bind(if result.is_ok() { "STORED" } else { "ERROR" })
        .execute(pool)
        .await?;
    result
}
async fn telegram(pool: &PgPool, job: &Job) -> Result<()> {
    if !enabled("TELEGRAM_ENABLED", false) {
        bail!("Telegram disabled");
    }
    let id = id(job, "notification_id")?;
    let r = sqlx::query("SELECT message,status FROM notifications WHERE id=$1")
        .bind(id)
        .fetch_one(pool)
        .await?;
    if r.get::<String, _>("status") == "SENT" {
        return Ok(());
    }
    let message: String = r.get("message");
    let result = rizenvuln_integrations::telegram::send(
        &secret("TELEGRAM_BOT_TOKEN")?,
        &secret("TELEGRAM_CHAT_ID")?,
        &message,
    )
    .await;
    sqlx::query("UPDATE notifications SET attempts=attempts+1,status=$2,error=$3,sent_at=CASE WHEN $2='SENT' THEN now() ELSE NULL END WHERE id=$1").bind(id).bind(if result.is_ok(){"SENT"}else{"ERROR"}).bind(if result.is_ok(){None}else{Some("Telegram request failed")}).execute(pool).await?;
    result
}
async fn harbor(pool: &PgPool, job: &Job) -> Result<()> {
    if !enabled("HARBOR_ENABLED", false) {
        bail!("Harbor disabled");
    }
    let project_id = id(job, "project_id")?;
    let name = job.payload["name"]
        .as_str()
        .context("Missing Harbor project")?;
    let client = Harbor::new(
        &secret("HARBOR_URL")?,
        secret("HARBOR_USERNAME")?,
        secret("HARBOR_PASSWORD")?,
        ca("HARBOR_CA_FILE")?,
    )?;
    let endpoint = url::Url::parse(&secret("HARBOR_URL")?)?;
    let registry = &endpoint[url::Position::BeforeHost..url::Position::AfterPort];
    for repo in client.repositories(name).await? {
        let full_name = repo["name"]
            .as_str()
            .context("Missing Harbor repository name")?;
        let repository = full_name
            .strip_prefix(&format!("{name}/"))
            .unwrap_or(full_name);
        for art in client.artifacts(name, repository).await? {
            let digest = art["digest"].as_str().context("Missing Harbor digest")?;
            let reference = format!("{registry}/{full_name}@{digest}");
            let image:Uuid=sqlx::query_scalar("INSERT INTO images(id,project_id,reference,registry,digest,metadata,status,last_checked) VALUES($1,$2,$3,$4,$5,$6,'HARBOR_IMPORTED',now()) ON CONFLICT(project_id,reference) DO UPDATE SET metadata=EXCLUDED.metadata,last_checked=now() RETURNING id").bind(Uuid::new_v4()).bind(project_id).bind(&reference).bind(registry).bind(digest).bind(json!({"source":"harbor","artifact":art})).fetch_one(pool).await?;
            let run = Uuid::new_v4();
            sqlx::query("INSERT INTO scan_runs(id,image_id,digest,source,status) VALUES($1,$2,$3,'harbor','RUNNING')").bind(run).bind(image).bind(digest).execute(pool).await?;
            match client.scan_report(name, repository, digest).await {
                Ok(report) => {
                    let mut findings = Vec::new();
                    for r in report.as_object().into_iter().flat_map(|m| m.values()) {
                        for v in r["vulnerabilities"].as_array().into_iter().flatten() {
                            let s = |k: &str| v[k].as_str().unwrap_or_default().to_owned();
                            findings.push(rizenvuln_core::Finding {
                                cve: s("id"),
                                package: s("package"),
                                installed: s("version"),
                                fixed: s("fix_version"),
                                severity: s("severity").to_uppercase(),
                                title: s("description"),
                                target: full_name.into(),
                            });
                        }
                    }
                    if !report
                        .as_object()
                        .is_some_and(|m| m.values().any(|r| r["vulnerabilities"].is_array()))
                    {
                        bail!("Harbor report incomplete");
                    }
                    persist(pool, run, image, &findings, "harbor", report.clone(), 0.0).await?;
                    artifact(pool, run, "harbor-json", report).await?;
                }
                Err(_) => {
                    sqlx::query("UPDATE scan_runs SET status='FAILED',completed_at=now(),error='Harbor scan report unavailable' WHERE id=$1").bind(run).execute(pool).await?;
                }
            }
            let harbor_sbom = match client.sbom(name, repository, digest).await {
                Ok(v) => Ok(v),
                Err(_) => {
                    let image_ref = rizenvuln_core::ImageReference::parse(&reference)?;
                    Registry::configured(
                        image_ref,
                        Some((secret("HARBOR_USERNAME")?, secret("HARBOR_PASSWORD")?)),
                        ca("HARBOR_CA_FILE")?,
                    )?
                    .sbom()
                    .await
                }
            };
            match harbor_sbom {
                Ok(sbom) => {
                    artifact(pool, run, "cyclonedx-json", sbom).await?;
                }
                Err(_) => {
                    sqlx::query("UPDATE images SET metadata=metadata||'{\"sbom_status\":\"UNAVAILABLE\"}'::jsonb WHERE id=$1").bind(image).execute(pool).await?;
                }
            }
        }
    }
    Ok(())
}
async fn discover(pool: &PgPool, kind: &str) -> Result<()> {
    let deployments = if kind == "docker" {
        rizenvuln_integrations::discovery::docker(
            &secret("DOCKER_HOST")?,
            std::fs::read(secret("DOCKER_CA_FILE")?)?,
            std::fs::read(secret("DOCKER_IDENTITY_FILE")?)?,
        )
        .await?
    } else {
        rizenvuln_integrations::discovery::kubernetes(
            &secret("KUBERNETES_URL")?,
            &secret("KUBERNETES_TOKEN")?,
            std::fs::read(secret("KUBERNETES_CA_FILE")?)?,
        )
        .await?
    };
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE deployments SET running=false WHERE source=$1")
        .bind(kind)
        .execute(&mut *tx)
        .await?;
    for d in deployments {
        sqlx::query("INSERT INTO deployments(id,source,server,namespace,container,image,digest,running,environment) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT(source,server,namespace,container) DO UPDATE SET image=EXCLUDED.image,digest=EXCLUDED.digest,running=EXCLUDED.running,last_seen=now()").bind(Uuid::new_v4()).bind(d.source).bind(d.server).bind(d.namespace).bind(d.container).bind(d.image).bind(d.digest).bind(d.running).bind(value("DISCOVERY_ENVIRONMENT","unknown")).execute(&mut *tx).await?;
    }
    tx.commit().await?;
    Ok(())
}
async fn intelligence(pool: &PgPool) -> Result<()> {
    let kev = rizenvuln_integrations::intelligence::kev().await?;
    for cve in kev["vulnerabilities"].as_array().into_iter().flatten() {
        if let Some(id) = cve["cveID"].as_str() {
            let changed = sqlx::query(
                "UPDATE vulnerabilities SET kev=true,enriched_at=now() WHERE id=$1 AND kev=false",
            )
            .bind(id)
            .execute(pool)
            .await?
            .rows_affected();
            if changed > 0 && enabled("TELEGRAM_ENABLED", false) {
                rizenvuln_database::notification(
                    pool,
                    &format!("kev:{id}"),
                    "kev",
                    &format!("RizenVuln: {id} добавлена в CISA KEV"),
                )
                .await?;
            }
        }
    }
    let cves:Vec<String>=sqlx::query_scalar("SELECT id FROM vulnerabilities WHERE id LIKE 'CVE-%' ORDER BY enriched_at NULLS FIRST LIMIT 1000").fetch_all(pool).await?;
    for batch in cves.chunks(100) {
        let data = rizenvuln_integrations::intelligence::epss(batch).await?;
        for item in data["data"].as_array().into_iter().flatten() {
            if let (Some(cve), Some(epss)) = (
                item["cve"].as_str(),
                item["epss"].as_str().and_then(|s| s.parse::<f64>().ok()),
            ) {
                sqlx::query("UPDATE vulnerabilities SET epss=$2,enriched_at=now() WHERE id=$1")
                    .bind(cve)
                    .bind(epss)
                    .execute(pool)
                    .await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    mod support {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../tests/support.rs"
        ));
    }
    #[tokio::test]
    #[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
    async fn rescans_preserve_decisions_but_reopen_unverified_fixes() {
        let db = support::TestDatabase::new().await;
        let project = Uuid::new_v4();
        let image = Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,name) VALUES($1,'worker fixture')")
            .bind(project)
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO images(id,project_id,reference,registry) VALUES($1,$2,'nginx:1','registry-1.docker.io')").bind(image).bind(project).execute(&db.pool).await.unwrap();
        let statuses = [
            "NEW",
            "IN_PROGRESS",
            "RISK_ACCEPTED",
            "FALSE_POSITIVE",
            "FIXED",
            "PENDING_VERIFICATION",
        ];
        let findings: Vec<_> = statuses
            .iter()
            .enumerate()
            .map(|(i, _)| rizenvuln_core::Finding {
                cve: format!("CVE-TEST-{i}"),
                package: format!("package-{i}"),
                installed: "1".into(),
                fixed: "2".into(),
                severity: "HIGH".into(),
                title: "test".into(),
                target: "os".into(),
            })
            .collect();
        let first = Uuid::new_v4();
        sqlx::query("INSERT INTO scan_runs(id,image_id,status,started_at) VALUES($1,$2,'RUNNING',now()-interval '1 hour')").bind(first).bind(image).execute(&db.pool).await.unwrap();
        persist(&db.pool, first, image, &findings, "test", json!({}), 0.1)
            .await
            .unwrap();
        for (f, status) in findings.iter().zip(statuses) {
            sqlx::query("UPDATE vulnerability_findings SET status=$1 WHERE scan_run_id=$2 AND vulnerability_id=$3").bind(status).bind(first).bind(&f.cve).execute(&db.pool).await.unwrap();
        }
        let second = Uuid::new_v4();
        sqlx::query("INSERT INTO scan_runs(id,image_id,status) VALUES($1,$2,'RUNNING')")
            .bind(second)
            .bind(image)
            .execute(&db.pool)
            .await
            .unwrap();
        let mut duplicates = findings.clone();
        duplicates.push(findings[0].clone());
        persist(
            &db.pool,
            second,
            image,
            &duplicates,
            "test",
            json!({"db":"fixture"}),
            0.2,
        )
        .await
        .unwrap();
        let actual:Vec<String>=sqlx::query_scalar("SELECT status FROM vulnerability_findings WHERE scan_run_id=$1 ORDER BY vulnerability_id").bind(second).fetch_all(&db.pool).await.unwrap();
        assert_eq!(
            actual,
            [
                "NEW",
                "IN_PROGRESS",
                "RISK_ACCEPTED",
                "FALSE_POSITIVE",
                "NEW",
                "NEW"
            ]
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>(
                "SELECT count(*) FROM vulnerability_findings WHERE scan_run_id=$1"
            )
            .bind(first)
            .fetch_one(&db.pool)
            .await
            .unwrap(),
            6
        );
        let row: (String, String) =
            sqlx::query_as("SELECT status,scanner_version FROM scan_runs WHERE id=$1")
                .bind(second)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(row, ("COMPLETED".into(), "test".into()));
        let document = json!({"components":[{"name":"fixture","version":"1"}]});
        artifact_with_upload(&db.pool, second, "cyclonedx-json", document.clone(), true)
            .await
            .unwrap();
        artifact_with_upload(&db.pool, second, "cyclonedx-json", document, true)
            .await
            .unwrap();
        let jobs: Vec<Uuid> = sqlx::query_scalar(
            "SELECT (payload->>'artifact_id')::uuid FROM jobs WHERE kind='upload'",
        )
        .fetch_all(&db.pool)
        .await
        .unwrap();
        let artifact_id: Uuid =
            sqlx::query_scalar("SELECT id FROM sbom_artifacts WHERE scan_run_id=$1")
                .bind(second)
                .fetch_one(&db.pool)
                .await
                .unwrap();
        assert_eq!(
            jobs,
            vec![artifact_id],
            "artifact retry must not enqueue nonexistent artifacts"
        );
        db.close().await;
    }
    #[test]
    fn invalid_job_payload_is_rejected() {
        for payload in [
            json!({}),
            json!({"image_id":42}),
            json!({"image_id":"not-a-uuid"}),
        ] {
            let job = Job {
                id: Uuid::new_v4(),
                kind: "image".into(),
                payload,
                attempts: 1,
                max_attempts: 5,
                lease_token: None,
            };
            assert!(id(&job, "image_id").is_err());
        }
    }
}
