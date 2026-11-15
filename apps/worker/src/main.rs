mod processor;
use anyhow::Result;
use rizenvuln_config::Config;
use rizenvuln_database::Job;
use serde_json::json;
use sqlx::{PgPool, Row};
use std::{sync::Arc, time::Duration};
use tokio::sync::watch;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Arc::new(Config::load()?);
    let pool = rizenvuln_database::connect(&config.database_url).await?;
    rizenvuln_database::migrate(&pool).await?;
    let (stop_tx, stop) = watch::channel(false);
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(run_scheduler(pool.clone(), config.clone(), stop.clone()));
    for _ in 0..config.concurrency {
        tasks.spawn(run_worker(pool.clone(), config.clone(), stop.clone()));
    }
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c().await?;
    }
    let _ = stop_tx.send(true);
    tracing::info!("Worker draining jobs");
    if tokio::time::timeout(Duration::from_secs(50), async {
        while let Some(result) = tasks.join_next().await {
            if let Err(error) = result {
                tracing::error!(%error,"Worker task failed");
            }
        }
    })
    .await
    .is_err()
    {
        tasks.abort_all();
    }
    pool.close().await;
    Ok(())
}

async fn run_scheduler(pool: PgPool, config: Arc<Config>, mut stop: watch::Receiver<bool>) {
    let mut tick = tokio::time::interval(Duration::from_secs(30));
    loop {
        tokio::select! {
            _ = tick.tick() => {
                if let Err(error)=schedule(&pool,&config).await {tracing::error!(%error,"Scheduler error");}
            },
            _ = stop.changed() => break,
        }
    }
}

async fn run_worker(pool: PgPool, config: Arc<Config>, mut stop: watch::Receiver<bool>) {
    loop {
        if *stop.borrow() {
            break;
        }
        match rizenvuln_database::claim(&pool).await {
            Ok(Some(job)) => execute(&pool, &config, &job).await,
            Ok(None) => {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(2)) => {},
                    _ = stop.changed() => break,
                }
            }
            Err(error) => {
                tracing::error!(%error,"Queue error");
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(3)) => {},
                    _ = stop.changed() => break,
                }
            }
        }
    }
}

async fn execute(pool: &PgPool, config: &Config, job: &Job) {
    let mut execution = Box::pin(processor::process(pool, config, job));
    let mut heartbeat = tokio::time::interval(Duration::from_secs(25));
    heartbeat.tick().await;
    let result = loop {
        tokio::select! {
            result = &mut execution => break result,
            _ = heartbeat.tick() => {
                if !matches!(rizenvuln_database::heartbeat(pool,job).await,Ok(true)) {
                    break Err(anyhow::anyhow!("Job lease lost"));
                }
            },
        }
    };
    drop(execution);
    let retry_after = result
        .as_ref()
        .err()
        .and_then(|e| e.downcast_ref::<rizenvuln_integrations::github::RateLimited>())
        .map(|e| e.retry_after_seconds);
    // Reqwest errors may contain URLs with credentials. Persist sanitized errors only.
    let error = result
        .err()
        .map(|_| format!("{} job failed; attempt {}", job.kind, job.attempts));
    if let Err(error) =
        rizenvuln_database::finish_after(pool, job, error.as_deref(), retry_after).await
    {
        tracing::error!(%error,"Job completion failed");
    }
    if error.is_some() {
        tracing::warn!(kind=%job.kind,id=%job.id,"Job failed; retry scheduled");
    }
}

async fn schedule(pool: &PgPool, c: &Config) -> Result<()> {
    sqlx::query("SELECT 1").execute(pool).await?;
    sqlx::query("UPDATE scan_runs SET status='FAILED',completed_at=now(),error='Interrupted scan exceeded maximum duration' WHERE status='RUNNING' AND started_at<now()-interval '2 hours'").execute(pool).await?;
    tokio::fs::write(
        "/tmp/worker-ready",
        chrono::Utc::now().timestamp().to_string(),
    )
    .await?;
    for row in sqlx::query("SELECT id FROM images WHERE COALESCE(metadata->>'source','')<>'harbor' AND (last_checked IS NULL OR last_checked<now()-make_interval(secs=>$1::float8))").bind(c.scan_interval as f64).fetch_all(pool).await? {let id:uuid::Uuid=row.get("id");rizenvuln_database::enqueue(pool,"image",json!({"image_id":id}),&format!("image:{id}")).await?;}
    if rizenvuln_config::enabled("GITHUB_ENABLED", true) {
        let interval = rizenvuln_config::value("UPDATE_CHECK_INTERVAL_MINUTES", "30")
            .parse::<f64>()
            .unwrap_or(30.0)
            .max(1.0)
            * 60.0;
        for row in sqlx::query("SELECT id FROM repositories WHERE last_checked IS NULL OR last_checked<now()-make_interval(secs=>$1::float8)").bind(interval).fetch_all(pool).await?{let id:uuid::Uuid=row.get("id");rizenvuln_database::enqueue(pool,"github",json!({"repository_id":id}),&format!("github:{id}")).await?;}
    }
    if rizenvuln_config::enabled("HARBOR_ENABLED", false) {
        for row in sqlx::query("SELECT project_id,name FROM sources WHERE kind='harbor'")
            .fetch_all(pool)
            .await?
        {
            let id: uuid::Uuid = row.get("project_id");
            let name: String = row.get("name");
            periodic(
                pool,
                "harbor",
                json!({"project_id":id,"name":name}),
                &format!("harbor:{id}:{name}"),
                c.scan_interval as f64,
            )
            .await?;
        }
    }
    for (flag, kind) in [
        ("DOCKER_DISCOVERY_ENABLED", "docker"),
        ("KUBERNETES_ENABLED", "kubernetes"),
    ] {
        if rizenvuln_config::enabled(flag, false) {
            periodic(pool, kind, json!({}), kind, 300.0).await?;
        }
    }
    if rizenvuln_config::enabled("INTELLIGENCE_ENABLED", true) {
        periodic(pool, "intelligence", json!({}), "intelligence", 3600.0).await?;
    }
    Ok(())
}
async fn periodic(
    pool: &PgPool,
    kind: &str,
    payload: serde_json::Value,
    key: &str,
    seconds: f64,
) -> Result<()> {
    let recent:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM jobs WHERE dedup_key=$1 AND (status IN ('PENDING','RUNNING') OR created_at>now()-make_interval(secs=>$2::float8)))").bind(key).bind(seconds).fetch_one(pool).await?;
    if !recent {
        rizenvuln_database::enqueue(pool, kind, payload, key).await?;
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
    async fn scheduler_deduplicates_due_sources_and_fails_stale_scans() {
        let db = support::TestDatabase::new().await;
        let project = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO projects(id,name) VALUES($1,'schedule')")
            .bind(project)
            .execute(&db.pool)
            .await
            .unwrap();
        let mut ids = Vec::new();
        for (reference, recent, harbor) in [
            ("due", false, false),
            ("fresh", true, false),
            ("imported", false, true),
        ] {
            let id = uuid::Uuid::new_v4();
            ids.push(id);
            sqlx::query("INSERT INTO images(id,project_id,reference,registry,last_checked,metadata) VALUES($1,$2,$3,'fixture',CASE WHEN $4 THEN now() ELSE NULL END,$5)").bind(id).bind(project).bind(reference).bind(recent).bind(if harbor {json!({"source":"harbor"})} else {json!({})}).execute(&db.pool).await.unwrap();
        }
        sqlx::query("INSERT INTO repositories(id,project_id,full_name) VALUES($1,$2,'owner/repo')")
            .bind(uuid::Uuid::new_v4())
            .bind(project)
            .execute(&db.pool)
            .await
            .unwrap();
        sqlx::query("INSERT INTO scan_runs(id,image_id,status,started_at) VALUES($1,$2,'RUNNING',now()-interval '3 hours')").bind(uuid::Uuid::new_v4()).bind(ids[0]).execute(&db.pool).await.unwrap();
        let config = Config {
            database_url: String::new(),
            bind: String::new(),
            public_url: String::new(),
            secure_cookie: false,
            admin_email: String::new(),
            admin_password: String::new(),
            session_secret: String::new(),
            scan_enabled: true,
            scan_interval: 86400,
            concurrency: 1,
            trivy_cache: String::new(),
        };
        schedule(&db.pool, &config).await.unwrap();
        schedule(&db.pool, &config).await.unwrap();
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs WHERE kind='image'")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs WHERE kind='github'")
                .fetch_one(&db.pool)
                .await
                .unwrap(),
            1
        );
        let status: String = sqlx::query_scalar("SELECT status FROM scan_runs")
            .fetch_one(&db.pool)
            .await
            .unwrap();
        assert_eq!(status, "FAILED");
        db.close().await;
    }
}
