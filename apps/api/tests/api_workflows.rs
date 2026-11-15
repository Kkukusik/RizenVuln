mod common;
use axum::http::StatusCode;
use common::*;
use serde_json::{json, Value};
use uuid::Uuid;

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn authentication_validation_and_password_rotation() {
    let a = Api::new().await;
    for body in [
        json!({"email":a.config.admin_email,"password":"wrong"}),
        json!({"email":"missing@example.test","password":"wrong"}),
    ] {
        let (status, _, value) = a.send("POST", "/auth/login", Some(body), false, &[]).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(value["error"]["message"], "Неверный email или пароль");
    }
    assert_eq!(
        a.send(
            "POST",
            "/auth/login",
            Some(json!({"email":a.config.admin_email,"password":a.config.admin_password})),
            false,
            &[("origin", "https://evil.example")]
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    for path in [
        "/projects",
        "/settings",
        "/settings/users",
        "/dashboard",
        "/jobs",
        "/openapi.json",
    ] {
        assert_eq!(
            a.send("GET", path, None, false, &[]).await.0,
            StatusCode::UNAUTHORIZED
        );
    }
    for headers in [
        vec![("x-csrf-token", "wrong")],
        vec![("origin", "https://evil.example")],
    ] {
        assert_eq!(
            a.send(
                "POST",
                "/projects",
                Some(json!({"name":"denied"})),
                true,
                &headers
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let me = a.ok("GET", "/auth/me", None).await;
    let password = rizenvuln_auth::token();
    let user = a
        .ok(
            "POST",
            "/settings/users",
            Some(json!({"email":"VIEWER@example.test","password":password,"role":"viewer"})),
        )
        .await;
    let users = a.ok("GET", "/settings/users", None).await;
    assert!(users["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|u| u.get("password_hash").is_none()));
    let (status, headers, body) = a
        .send(
            "POST",
            "/auth/login",
            Some(json!({"email":"viewer@example.test","password":password})),
            false,
            &[],
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    let cookie = headers["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap();
    let csrf = body["csrf_token"].as_str().unwrap();
    let viewer = [("cookie", cookie), ("x-csrf-token", csrf)];
    assert_eq!(
        a.send("GET", "/settings/users", None, true, &viewer)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        a.send(
            "POST",
            "/projects",
            Some(json!({"name":"forbidden"})),
            true,
            &viewer
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        a.send("POST", "/auth/logout", None, true, &viewer).await.0,
        StatusCode::OK
    );
    assert_eq!(
        a.send("GET", "/auth/me", None, true, &viewer).await.0,
        StatusCode::UNAUTHORIZED
    );
    let new_password = rizenvuln_auth::token();
    a.ok(
        "POST",
        &format!("/settings/users/{}/password", me["id"].as_str().unwrap()),
        Some(json!({"password":new_password})),
    )
    .await;
    assert_eq!(
        a.send("GET", "/auth/me", None, true, &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        a.send(
            "POST",
            "/auth/login",
            Some(json!({"email":a.config.admin_email,"password":a.config.admin_password})),
            false,
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        a.send(
            "POST",
            "/auth/login",
            Some(json!({"email":a.config.admin_email,"password":new_password})),
            false,
            &[]
        )
        .await
        .0,
        StatusCode::OK
    );
    let audit: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_logs WHERE action='user.password_reset'")
            .fetch_one(&a.db.pool)
            .await
            .unwrap();
    assert_eq!(audit, 1);
    assert!(user["id"].is_string());
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn sources_listing_validation_and_scan_deduplication() {
    let a = Api::new().await;
    let project = a.project().await;
    let image = a
        .ok(
            "POST",
            "/images",
            Some(json!({"project_id":project,"reference":"nginx:1.27"})),
        )
        .await;
    let image_id = image["id"].as_str().unwrap();
    let repo=a.ok("POST","/repositories",Some(json!({"project_id":project,"reference":"https://github.com/Kkukusik/RizenVuln","branch":"main","track_commits":true}))).await;
    assert!(repo["id"].is_string());
    for _ in 0..3 {
        a.ok("POST", &format!("/images/{image_id}/scan"), None)
            .await;
    }
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM jobs WHERE kind='image'")
        .fetch_one(&a.db.pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
    let images = a
        .ok("GET", &format!("/images?project_id={project}"), None)
        .await;
    assert_eq!(
        images["items"][0]["reference"],
        "registry-1.docker.io/library/nginx:1.27"
    );
    for path in [
        "/projects",
        "/images",
        "/repositories",
        "/sbom",
        "/deployments",
        "/updates",
        "/reports",
        "/notifications",
        "/integrations",
        "/jobs",
    ] {
        let list = a.ok("GET", path, None).await;
        assert!(list["items"].is_array(), "{path}");
        assert!(list["total"].is_number());
    }
    let page = a.ok("GET", "/projects?page=0&per_page=999", None).await;
    assert_eq!(page["page"], 1);
    assert_eq!(page["per_page"], 100);
    let search = a
        .ok(
            "GET",
            "/projects?q=%27%3B%20DROP%20TABLE%20projects%3B--",
            None,
        )
        .await;
    assert_eq!(search["total"], 0);
    assert_eq!(a.ok("GET", "/projects", None).await["total"], 1);
    for (path, body) in [
        ("/projects", json!({"name":"  "})),
        ("/projects", json!({"name":"x".repeat(121)})),
        (
            "/images",
            json!({"project_id":project,"reference":"--help"}),
        ),
        (
            "/repositories",
            json!({"project_id":project,"reference":"https://evil.example/a/b"}),
        ),
        (
            "/repositories",
            json!({"project_id":project,"reference":"owner/repo","branch":""}),
        ),
        (
            "/settings/users",
            json!({"email":"a@example.test","password":"short","role":"admin"}),
        ),
        (
            "/settings/users",
            json!({"email":"a@example.test","password":"x".repeat(20),"role":"root"}),
        ),
        (
            "/notifications/rules",
            json!({"event":"unknown","enabled":true}),
        ),
    ] {
        assert_eq!(
            a.send("POST", path, Some(body), true, &[]).await.0,
            StatusCode::BAD_REQUEST,
            "{path}"
        );
    }
    assert_eq!(
        a.send(
            "POST",
            "/projects",
            Some(json!({"name":"Production"})),
            true,
            &[]
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        a.send(
            "POST",
            &format!("/images/{}/scan", Uuid::new_v4()),
            None,
            true,
            &[]
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        a.send("GET", "/images?project_id=bad", None, true, &[])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        a.send("GET", "/does-not-exist", None, true, &[]).await.0,
        StatusCode::NOT_FOUND
    );
    a.ok(
        "POST",
        "/notifications/rules",
        Some(json!({"event":"kev","enabled":false})),
    )
    .await;
    a.ok(
        "POST",
        "/notifications/rules",
        Some(json!({"event":"kev","enabled":true})),
    )
    .await;
    assert_eq!(
        a.ok("GET", "/notifications/rules", None).await["items"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let settings = a.ok("GET", "/settings", None).await;
    assert_eq!(settings["read_only_infrastructure"], true);
    assert!(settings.get("session_secret").is_none());
    let dashboard = a.ok("GET", "/dashboard", None).await;
    assert_eq!(dashboard["counts"]["projects"], 1);
    assert_eq!(dashboard["counts"]["stale_images"], 1);
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn findings_history_sbom_and_version_approval() {
    let a = Api::new().await;
    let project = a.project().await;
    let image = a
        .ok(
            "POST",
            "/images",
            Some(json!({"project_id":project,"reference":"nginx:1.27"})),
        )
        .await;
    let image = Uuid::parse_str(image["id"].as_str().unwrap()).unwrap();
    let old = Uuid::new_v4();
    let run = Uuid::new_v4();
    let failed = Uuid::new_v4();
    for (id, status, age) in [
        (old, "COMPLETED", 3),
        (run, "COMPLETED", 2),
        (failed, "FAILED", 1),
    ] {
        sqlx::query("INSERT INTO scan_runs(id,image_id,status,started_at,completed_at,digest) VALUES($1,$2,$3,now()-make_interval(hours=>$4),now(),'sha256:test')").bind(id).bind(image).bind(status).bind(age).execute(&a.db.pool).await.unwrap();
    }
    sqlx::query(
        "INSERT INTO vulnerabilities(id,severity,epss,kev) VALUES('CVE-TEST-1','HIGH',0.9,true)",
    )
    .execute(&a.db.pool)
    .await
    .unwrap();
    let finding = Uuid::new_v4();
    for (id, scan) in [
        (Uuid::new_v4(), old),
        (finding, run),
        (Uuid::new_v4(), failed),
    ] {
        sqlx::query("INSERT INTO vulnerability_findings(id,vulnerability_id,scan_run_id,image_id,package,installed_version,fixed_version,severity) VALUES($1,'CVE-TEST-1',$2,$3,'openssl','1','2','HIGH')").bind(id).bind(scan).bind(image).execute(&a.db.pool).await.unwrap();
    }
    for query in [
        "",
        "?severity=HIGH&kev=true&fix_available=true&min_epss=0.8",
        &format!("?image_id={image}&project_id={project}"),
    ] {
        assert_eq!(
            a.ok("GET", &format!("/vulnerabilities{query}"), None).await["total"],
            1
        );
    }
    for query in [
        "?severity=LOW",
        "?kev=false",
        "?fix_available=false",
        "?min_epss=0.99",
        "?environment=production",
    ] {
        assert_eq!(
            a.ok("GET", &format!("/vulnerabilities{query}"), None).await["total"],
            0
        );
    }
    assert_eq!(
        a.send("GET", "/vulnerabilities?min_epss=2", None, true, &[])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    a.ok(
        "PATCH",
        &format!("/remediation/{finding}"),
        Some(json!({"status":"IN_PROGRESS","note":"triaged"})),
    )
    .await;
    let history: (String, String, String) = sqlx::query_as(
        "SELECT old_status,new_status,note FROM vulnerability_status_history WHERE finding_id=$1",
    )
    .bind(finding)
    .fetch_one(&a.db.pool)
    .await
    .unwrap();
    assert_eq!(
        history,
        ("NEW".into(), "IN_PROGRESS".into(), "triaged".into())
    );
    assert_eq!(
        a.ok("GET", "/remediation?status=IN_PROGRESS", None).await["total"],
        1
    );
    assert_eq!(
        a.send(
            "PATCH",
            &format!("/remediation/{finding}"),
            Some(json!({"status":"INVALID"})),
            true,
            &[]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    let left = Uuid::new_v4();
    let right = Uuid::new_v4();
    for (id, scan, doc) in [
        (
            left,
            old,
            json!({"components":[{"name":"openssl","version":"1","licenses":[{"license":{"id":"MIT"}}]}]}),
        ),
        (
            right,
            run,
            json!({"packages":[{"name":"openssl","versionInfo":"2","licenseConcluded":"Apache-2.0"}]}),
        ),
    ] {
        sqlx::query("INSERT INTO sbom_artifacts(id,scan_run_id,format,sha256,document,storage_status) VALUES($1,$2,'cyclonedx-json','fixture',$3,'LOCAL')").bind(id).bind(scan).bind(doc).execute(&a.db.pool).await.unwrap();
    }
    let docs = a.ok("GET", "/sbom", None).await;
    assert!(docs["items"]
        .as_array()
        .unwrap()
        .iter()
        .all(|d| d.get("document").is_none()));
    assert!(a.ok("GET", &format!("/sbom/{left}"), None).await["components"].is_array());
    assert_eq!(
        a.ok("GET", &format!("/sbom/{left}/packages?q=mit"), None)
            .await["total"],
        1
    );
    assert_eq!(
        a.ok("GET", &format!("/sbom/{left}/packages?q=missing"), None)
            .await["total"],
        0
    );
    let diff = a
        .ok(
            "GET",
            &format!("/sbom/compare?left={left}&right={right}"),
            None,
        )
        .await;
    assert_eq!(diff["added"].as_array().unwrap().len(), 1);
    assert_eq!(diff["removed"].as_array().unwrap().len(), 1);
    assert_eq!(
        a.send("GET", &format!("/sbom/{}", Uuid::new_v4()), None, true, &[])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let update = Uuid::new_v4();
    sqlx::query("INSERT INTO update_recommendations(id,image_id,candidate,digest,status,reason) VALUES($1,$2,'2.0','sha256:new','UPDATE_AVAILABLE','fixture')").bind(update).bind(image).execute(&a.db.pool).await.unwrap();
    for _ in 0..2 {
        a.ok(
            "POST",
            &format!("/updates/{update}/approve"),
            Some(json!({"environment":"test"})),
        )
        .await;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM version_approvals")
            .fetch_one(&a.db.pool)
            .await
            .unwrap(),
        1
    );
    let status: String =
        sqlx::query_scalar("SELECT status FROM update_recommendations WHERE id=$1")
            .bind(update)
            .fetch_one(&a.db.pool)
            .await
            .unwrap();
    assert_eq!(status, "APPROVED");
    let dashboard = a.ok("GET", "/dashboard", None).await;
    assert_eq!(dashboard["severity"][0]["count"], 1);
    assert_eq!(a.ok("GET", "/reports", None).await["total"], 3);
    let _: Value = a.ok("GET", "/openapi.json", None).await;
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn bootstrap_expired_sessions_rate_limit_and_security_headers() {
    let a = Api::new().await;
    let mut changed = a.config.clone();
    changed.admin_password = rizenvuln_auth::token();
    rizenvuln_api::app::bootstrap(&a.db.pool, &changed)
        .await
        .unwrap();
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM users WHERE role='admin'")
            .fetch_one(&a.db.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        a.send(
            "POST",
            "/auth/login",
            Some(json!({"email":changed.admin_email,"password":changed.admin_password})),
            false,
            &[]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, headers, _) = a.send("GET", "/auth/me", None, true, &[]).await;
    assert_eq!(status, StatusCode::OK);
    for (key, value) in [
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(headers[key], value);
    }
    assert!(headers["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    sqlx::query("UPDATE sessions SET expires_at=now()-interval '1 second'")
        .execute(&a.db.pool)
        .await
        .unwrap();
    assert_eq!(
        a.send("GET", "/auth/me", None, true, &[]).await.0,
        StatusCode::UNAUTHORIZED
    );
    let mut limited = false;
    for _ in 0..16 {
        let (status, _, _) = a
            .send(
                "POST",
                "/auth/login",
                Some(json!({"email":"missing@example.test","password":"wrong"})),
                false,
                &[],
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            limited = true;
            break;
        }
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(limited, "login attempts should be rate limited");
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn every_documented_protected_route_requires_authentication() {
    let a = Api::new().await;
    let spec: Value = serde_json::from_str(include_str!("../../../docs/openapi.json")).unwrap();
    for (path, methods) in spec["paths"].as_object().unwrap() {
        let Some(path) = path.strip_prefix("/api/v1") else {
            continue;
        };
        if path == "/auth/login" {
            continue;
        }
        let path = path.replace("{id}", &Uuid::new_v4().to_string());
        for method in methods
            .as_object()
            .unwrap()
            .keys()
            .filter(|m| ["get", "post", "patch", "put", "delete"].contains(&m.as_str()))
        {
            assert_eq!(
                a.send(&method.to_uppercase(), &path, None, false, &[])
                    .await
                    .0,
                StatusCode::UNAUTHORIZED,
                "{method} {path}"
            );
        }
    }
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn health_metrics_and_integration_controls() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let a = Api::new().await;
    let project = a.project().await;
    for _ in 0..2 {
        a.ok(
            "POST",
            "/integrations/harbor/monitor",
            Some(json!({"project_id":project,"harbor_project":"selected"})),
        )
        .await;
    }
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM sources WHERE kind='harbor'")
            .fetch_one(&a.db.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM jobs WHERE kind='harbor'")
            .fetch_one(&a.db.pool)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        a.send("POST", "/notifications/test", None, true, &[])
            .await
            .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        a.send("GET", "/integrations/harbor/projects", None, true, &[])
            .await
            .0,
        StatusCode::BAD_GATEWAY
    );
    for path in ["/health/live", "/health/ready"] {
        let res = a
            .router
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }
    let res = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
    let token =
        std::env::var("METRICS_TOKEN").expect("test runner supplies ephemeral metrics token");
    let res = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = to_bytes(res.into_body(), 65536).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(text.contains("rizenvuln_jobs_pending 1"));
    assert!(!text.contains(&token));
    a.db.pool.close().await;
    let res = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let res = a
        .router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    a.db.close().await;
}

#[tokio::test]
#[ignore = "requires isolated rvtest_* PostgreSQL; scripts/test-integration.py"]
async fn malformed_and_oversized_requests_do_not_leak_secrets() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use tower::ServiceExt;
    let a = Api::new().await;
    for (body, expected) in [
        ("{".to_string(), StatusCode::BAD_REQUEST),
        (
            json!({"name":"x".repeat(1024*1024+1)}).to_string(),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ] {
        let res = a
            .router
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/projects")
                    .header("content-type", "application/json")
                    .header("origin", ORIGIN)
                    .header("cookie", &a.cookie)
                    .header("x-csrf-token", &a.csrf)
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), expected);
        let bytes = to_bytes(res.into_body(), 8192).await.unwrap();
        let error: Value = serde_json::from_slice(&bytes).unwrap();
        assert!(error["error"]["message"].is_string());
        let text = String::from_utf8(bytes.to_vec()).unwrap();
        assert!(!text.contains(&a.config.admin_password));
        assert!(!text.contains(&a.config.session_secret));
    }
    assert_eq!(a.ok("GET", "/projects", None).await["total"], 0);
    let audit: Vec<Value> = sqlx::query_scalar("SELECT to_jsonb(a) FROM audit_logs a")
        .fetch_all(&a.db.pool)
        .await
        .unwrap();
    let text = serde_json::to_string(&audit).unwrap();
    assert!(!text.contains(&a.config.admin_password));
    assert!(!text.contains(&a.config.session_secret));
    a.db.close().await;
}
