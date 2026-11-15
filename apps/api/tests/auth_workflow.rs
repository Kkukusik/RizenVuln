#[path = "../../../tests/support.rs"]
mod support;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use rizenvuln_api::app::{router, State};
use rizenvuln_config::Config;
use serde_json::{json, Value};
use tower::ServiceExt;
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires dedicated TEST_DATABASE_URL; creates and removes only its own test records"]
async fn cookie_csrf_rbac_logout_workflow() {
    let db = support::TestDatabase::new().await;
    let pool = db.pool.clone();
    let password = rizenvuln_auth::token();
    let hash = rizenvuln_auth::hash_password(&password).unwrap();
    let admin = Uuid::new_v4();
    let viewer = Uuid::new_v4();
    let email = format!("{admin}@example.test");
    let viewer_email = format!("{viewer}@example.test");
    for (id, email, role) in [(admin, &email, "admin"), (viewer, &viewer_email, "viewer")] {
        sqlx::query("INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4)")
            .bind(id)
            .bind(email)
            .bind(&hash)
            .bind(role)
            .execute(&pool)
            .await
            .unwrap();
    }
    let config = Config {
        database_url: String::new(),
        bind: String::new(),
        public_url: "https://monitor.example.test".into(),
        secure_cookie: true,
        admin_email: email.clone(),
        admin_password: password.clone(),
        session_secret: rizenvuln_auth::token(),
        scan_enabled: false,
        scan_interval: 86400,
        concurrency: 1,
        trivy_cache: String::new(),
    };
    let app = router(State::new(pool.clone(), config));
    let login = |email: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/auth/login")
            .header("content-type", "application/json")
            .header("origin", "https://monitor.example.test")
            .body(Body::from(
                json!({"email":email,"password":password}).to_string(),
            ))
            .unwrap()
    };
    let res = app.clone().oneshot(login(&email)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let set_cookie = res.headers()["set-cookie"].to_str().unwrap().to_owned();
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("Secure"));
    assert!(set_cookie.contains("SameSite=Strict"));
    let cookie = set_cookie.split(';').next().unwrap().to_owned();
    let data: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 8192).await.unwrap()).unwrap();
    let csrf = data["csrf_token"].as_str().unwrap();
    let name = format!("auth-test-{admin}");
    let request = |csrf: &str| {
        Request::builder()
            .method("POST")
            .uri("/api/v1/projects")
            .header("content-type", "application/json")
            .header("origin", "https://monitor.example.test")
            .header("cookie", &cookie)
            .header("x-csrf-token", csrf)
            .body(Body::from(json!({"name":name}).to_string()))
            .unwrap()
    };
    assert_eq!(
        app.clone()
            .oneshot(request("wrong"))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let res = app.clone().oneshot(request(csrf)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created: Value =
        serde_json::from_slice(&to_bytes(res.into_body(), 8192).await.unwrap()).unwrap();
    let project: Uuid = created["id"].as_str().unwrap().parse().unwrap();
    let viewer_res = app.clone().oneshot(login(&viewer_email)).await.unwrap();
    let viewer_cookie = viewer_res.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let viewer_data: Value =
        serde_json::from_slice(&to_bytes(viewer_res.into_body(), 8192).await.unwrap()).unwrap();
    let forbidden = Request::builder()
        .method("POST")
        .uri("/api/v1/projects")
        .header("content-type", "application/json")
        .header("origin", "https://monitor.example.test")
        .header("cookie", &viewer_cookie)
        .header("x-csrf-token", viewer_data["csrf_token"].as_str().unwrap())
        .body(Body::from(json!({"name":"must-not-create"}).to_string()))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(forbidden).await.unwrap().status(),
        StatusCode::FORBIDDEN
    );
    let viewer_logout = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("origin", "https://monitor.example.test")
        .header("cookie", viewer_cookie)
        .header("x-csrf-token", viewer_data["csrf_token"].as_str().unwrap())
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(viewer_logout).await.unwrap().status(),
        StatusCode::OK
    );
    let logout = Request::builder()
        .method("POST")
        .uri("/api/v1/auth/logout")
        .header("origin", "https://monitor.example.test")
        .header("cookie", &cookie)
        .header("x-csrf-token", csrf)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.clone().oneshot(logout).await.unwrap().status(),
        StatusCode::OK
    );
    let me = Request::builder()
        .uri("/api/v1/auth/me")
        .header("cookie", cookie)
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(me).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    sqlx::query("DELETE FROM audit_logs WHERE user_id IN ($1,$2)")
        .bind(admin)
        .bind(viewer)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM projects WHERE id=$1")
        .bind(project)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query("DELETE FROM users WHERE id IN ($1,$2)")
        .bind(admin)
        .bind(viewer)
        .execute(&pool)
        .await
        .unwrap();
    db.close().await;
}
