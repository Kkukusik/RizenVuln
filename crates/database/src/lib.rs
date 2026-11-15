use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{postgres::PgPoolOptions, PgPool};
use uuid::Uuid;
pub async fn connect(url: &str) -> Result<PgPool> {
    Ok(PgPoolOptions::new()
        .max_connections(12)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .connect(url)
        .await?)
}
pub async fn migrate(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("../../migrations").run(pool).await?;
    Ok(())
}
#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct Job {
    pub id: Uuid,
    pub kind: String,
    pub payload: Value,
    pub attempts: i32,
    pub max_attempts: i32,
    pub lease_token: Option<Uuid>,
}
pub async fn enqueue(pool: &PgPool, kind: &str, payload: Value, key: &str) -> Result<()> {
    sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,$2,$3,$4) ON CONFLICT (dedup_key) WHERE status IN ('PENDING','RUNNING') DO NOTHING").bind(Uuid::new_v4()).bind(kind).bind(payload).bind(key).execute(pool).await?;
    Ok(())
}
pub async fn claim(pool: &PgPool) -> Result<Option<Job>> {
    // Expired leases can be reclaimed; exhausted jobs never stay RUNNING forever.
    sqlx::query("UPDATE jobs SET status='FAILED',last_error='Lease expired after final attempt',lease_until=NULL WHERE status='RUNNING' AND lease_until<now() AND attempts>=max_attempts").execute(pool).await?;
    Ok(sqlx::query_as::<_,Job>("WITH candidate AS (SELECT id FROM jobs WHERE ((status='PENDING' AND run_at<=now()) OR (status='RUNNING' AND lease_until<now())) AND attempts<max_attempts ORDER BY run_at FOR UPDATE SKIP LOCKED LIMIT 1) UPDATE jobs SET status='RUNNING',attempts=attempts+1,lease_until=now()+interval '90 seconds',lease_token=$1 FROM candidate WHERE jobs.id=candidate.id RETURNING jobs.id,kind,payload,attempts,max_attempts,lease_token").bind(Uuid::new_v4()).fetch_optional(pool).await?)
}
pub async fn heartbeat(pool: &PgPool, job: &Job) -> Result<bool> {
    Ok(sqlx::query("UPDATE jobs SET lease_until=now()+interval '90 seconds' WHERE id=$1 AND lease_token=$2 AND status='RUNNING'").bind(job.id).bind(job.lease_token).execute(pool).await?.rows_affected()==1)
}
pub fn retry_delay(attempts: i32) -> i64 {
    (5_i64 * 2_i64.pow(attempts.clamp(0, 9) as u32)).min(3600)
}
pub async fn finish(pool: &PgPool, job: &Job, error: Option<&str>) -> Result<()> {
    finish_after(pool, job, error, None).await
}
pub async fn finish_after(
    pool: &PgPool,
    job: &Job,
    error: Option<&str>,
    retry_after: Option<i64>,
) -> Result<()> {
    sqlx::query("UPDATE jobs SET status=$3,last_error=$4,lease_until=NULL,run_at=now()+make_interval(secs=>$5::double precision),completed_at=CASE WHEN $3 IN ('COMPLETED','FAILED') THEN now() ELSE NULL END WHERE id=$1 AND lease_token=$2 AND status='RUNNING'").bind(job.id).bind(job.lease_token).bind(if error.is_none(){"COMPLETED"}else if job.attempts>=job.max_attempts{"FAILED"}else{"PENDING"}).bind(error).bind(retry_after.unwrap_or_else(||retry_delay(job.attempts)).clamp(1,86400) as f64).execute(pool).await?;
    Ok(())
}
pub async fn notification(pool: &PgPool, key: &str, event: &str, message: &str) -> Result<()> {
    let mut tx = pool.begin().await?;
    let enabled: Option<bool> =
        sqlx::query_scalar("SELECT enabled FROM notification_rules WHERE event=$1")
            .bind(event)
            .fetch_optional(&mut *tx)
            .await?;
    if enabled == Some(false) {
        tx.commit().await?;
        return Ok(());
    }
    let id = Uuid::new_v4();
    let inserted=sqlx::query("INSERT INTO notifications(id,event_key,event,message) VALUES($1,$2,$3,$4) ON CONFLICT(event_key) DO NOTHING").bind(id).bind(key).bind(event).bind(message).execute(&mut *tx).await?.rows_affected();
    if inserted == 1 {
        sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,'telegram',$2,$3)")
            .bind(Uuid::new_v4())
            .bind(serde_json::json!({"notification_id":id}))
            .bind(format!("telegram:{id}"))
            .execute(&mut *tx)
            .await?;
    }
    tx.commit().await?;
    Ok(())
}
#[derive(Serialize, sqlx::FromRow)]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub description: String,
    pub created_at: DateTime<Utc>,
}
#[cfg(test)]
mod test_support {
    use crate as rizenvuln_database;
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/support.rs"
    ));
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_retry() {
        assert_eq!(retry_delay(1), 10);
        assert_eq!(retry_delay(99), 2560);
        assert!(retry_delay(-2) > 0);
    }
    #[tokio::test]
    #[ignore = "requires TEST_DATABASE_URL pointing to a dedicated empty PostgreSQL database"]
    async fn queue_and_dedup() {
        let db = test_support::TestDatabase::new().await;
        let pool = db.pool.clone();
        let key = Uuid::new_v4().to_string();
        enqueue(&pool, "test", serde_json::json!({}), &key)
            .await
            .unwrap();
        enqueue(&pool, "test", serde_json::json!({}), &key)
            .await
            .unwrap();
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE dedup_key=$1")
            .bind(&key)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
        let a = claim(&pool).await.unwrap().unwrap();
        assert!(heartbeat(&pool, &a).await.unwrap());
        finish(&pool, &a, Some("retry")).await.unwrap();
        let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id=$1")
            .bind(a.id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(status, "PENDING");
        notification(&pool, &key, "test", "test").await.unwrap();
        notification(&pool, &key, "test", "test").await.unwrap();
        let n: i64 = sqlx::query_scalar("SELECT count(*) FROM notifications WHERE event_key=$1")
            .bind(&key)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(n, 1);
        db.close().await;
    }
}
