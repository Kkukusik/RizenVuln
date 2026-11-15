#[path = "../../../tests/support.rs"]
mod support;
use rizenvuln_database::*;
use serde_json::json;
use support::TestDatabase;

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn concurrent_claims_and_enqueue_are_exclusive() {
    let db = TestDatabase::new().await;
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let p = db.pool.clone();
        tasks.spawn(async move { enqueue(&p, "test", json!({}), "same").await.unwrap() });
    }
    while let Some(r) = tasks.join_next().await {
        r.unwrap();
    }
    let n: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(n, 1);
    for i in 0..9 {
        enqueue(&db.pool, "test", json!({}), &format!("job-{i}"))
            .await
            .unwrap();
    }
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..24 {
        let p = db.pool.clone();
        tasks.spawn(async move { claim(&p).await.unwrap() });
    }
    let mut ids = std::collections::HashSet::new();
    while let Some(r) = tasks.join_next().await {
        if let Some(job) = r.unwrap() {
            assert!(ids.insert(job.id));
            assert_eq!(job.attempts, 1);
        }
    }
    assert_eq!(ids.len(), 10);
    db.close().await;
}
#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn expired_leases_cannot_be_completed_by_previous_worker() {
    let db = TestDatabase::new().await;
    enqueue(&db.pool, "test", json!({}), "lease").await.unwrap();
    let first = claim(&db.pool).await.unwrap().unwrap();
    sqlx::query("UPDATE jobs SET lease_until=now()-interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    let second = claim(&db.pool).await.unwrap().unwrap();
    assert_eq!(first.id, second.id);
    assert_ne!(first.lease_token, second.lease_token);
    assert_eq!(second.attempts, 2);
    assert!(!heartbeat(&db.pool, &first).await.unwrap());
    finish(&db.pool, &first, None).await.unwrap();
    assert!(heartbeat(&db.pool, &second).await.unwrap());
    finish(&db.pool, &second, None).await.unwrap();
    let row: (String, bool) =
        sqlx::query_as("SELECT status,completed_at IS NOT NULL FROM jobs WHERE id=$1")
            .bind(first.id)
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(row, ("COMPLETED".into(), true));
    enqueue(&db.pool, "test", json!({}), "lease").await.unwrap();
    assert!(claim(&db.pool).await.unwrap().is_some());
    db.close().await;
}
#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn retries_are_delayed_bounded_and_terminal() {
    let db = TestDatabase::new().await;
    enqueue(&db.pool, "test", json!({}), "retry").await.unwrap();
    sqlx::query("UPDATE jobs SET max_attempts=2")
        .execute(&db.pool)
        .await
        .unwrap();
    let first = claim(&db.pool).await.unwrap().unwrap();
    finish_after(&db.pool, &first, Some("temporary"), Some(120))
        .await
        .unwrap();
    assert!(claim(&db.pool).await.unwrap().is_none());
    let row: (String, bool) =
        sqlx::query_as("SELECT status,run_at>now()+interval '110 seconds' FROM jobs")
            .fetch_one(&db.pool)
            .await
            .unwrap();
    assert_eq!(row, ("PENDING".into(), true));
    sqlx::query("UPDATE jobs SET run_at=now()-interval '1 second'")
        .execute(&db.pool)
        .await
        .unwrap();
    let second = claim(&db.pool).await.unwrap().unwrap();
    finish(&db.pool, &second, Some("permanent")).await.unwrap();
    let status: String = sqlx::query_scalar("SELECT status FROM jobs")
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(status, "FAILED");
    assert!(claim(&db.pool).await.unwrap().is_none());
    enqueue(&db.pool, "test", json!({}), "exhausted-lease")
        .await
        .unwrap();
    sqlx::query("UPDATE jobs SET max_attempts=1 WHERE status='PENDING'")
        .execute(&db.pool)
        .await
        .unwrap();
    let job = claim(&db.pool).await.unwrap().unwrap();
    sqlx::query("UPDATE jobs SET lease_until=now()-interval '1 second' WHERE id=$1")
        .bind(job.id)
        .execute(&db.pool)
        .await
        .unwrap();
    assert!(claim(&db.pool).await.unwrap().is_none());
    let status: String = sqlx::query_scalar("SELECT status FROM jobs WHERE id=$1")
        .bind(job.id)
        .fetch_one(&db.pool)
        .await
        .unwrap();
    assert_eq!(status, "FAILED");
    db.close().await;
}
#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn notifications_respect_rules_and_concurrent_deduplication() {
    let db = TestDatabase::new().await;
    sqlx::query("INSERT INTO notification_rules(id,event,enabled) VALUES($1,'kev',false)")
        .bind(uuid::Uuid::new_v4())
        .execute(&db.pool)
        .await
        .unwrap();
    notification(&db.pool, "disabled", "kev", "test")
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notifications")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        0
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let p = db.pool.clone();
        tasks.spawn(async move {
            notification(&p, "dedup", "vulnerability", "test")
                .await
                .unwrap()
        });
    }
    while let Some(r) = tasks.join_next().await {
        r.unwrap();
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM notifications")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs WHERE kind='telegram'")
            .fetch_one(&db.pool)
            .await
            .unwrap(),
        1
    );
    db.close().await;
}
