#[path = "../../../../tests/support.rs"]
mod support;
use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use rizenvuln_api::app::{bootstrap, router, State};
use rizenvuln_config::Config;
use serde_json::{json, Value};
pub use support::TestDatabase;
use tower::ServiceExt;
pub const ORIGIN: &str = "https://monitor.example.test";
pub struct Api {
    pub db: TestDatabase,
    pub router: Router,
    pub config: Config,
    pub cookie: String,
    pub csrf: String,
}
impl Api {
    pub async fn new() -> Self {
        let db = TestDatabase::new().await;
        let config = Config {
            database_url: String::new(),
            bind: String::new(),
            public_url: ORIGIN.into(),
            secure_cookie: true,
            admin_email: "admin@example.test".into(),
            admin_password: rizenvuln_auth::token(),
            session_secret: rizenvuln_auth::token(),
            scan_enabled: true,
            scan_interval: 86400,
            concurrency: 1,
            trivy_cache: String::new(),
        };
        bootstrap(&db.pool, &config).await.unwrap();
        let router = router(State::new(db.pool.clone(), config.clone()));
        let mut api = Self {
            db,
            router,
            config,
            cookie: String::new(),
            csrf: String::new(),
        };
        let (status, headers, body) = api
            .send(
                "POST",
                "/auth/login",
                Some(json!({"email":api.config.admin_email,"password":api.config.admin_password})),
                false,
                &[],
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        api.cookie = headers["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .into();
        api.csrf = body["csrf_token"].as_str().unwrap().into();
        api
    }
    pub async fn send(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
        authenticated: bool,
        extra: &[(&str, &str)],
    ) -> (StatusCode, axum::http::HeaderMap, Value) {
        let mut request = Request::builder()
            .method(method)
            .uri(format!("/api/v1{path}"))
            .header("origin", ORIGIN)
            .header("content-type", "application/json");
        if authenticated {
            request = request
                .header("cookie", &self.cookie)
                .header("x-csrf-token", &self.csrf);
        }
        let mut request = request
            .body(
                body.map(|v| Body::from(v.to_string()))
                    .unwrap_or_else(Body::empty),
            )
            .unwrap();
        for (k, v) in extra {
            request.headers_mut().insert(
                axum::http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                v.parse().unwrap(),
            );
        }
        let response = self.router.clone().oneshot(request).await.unwrap();
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
            .await
            .unwrap();
        let body = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| panic!("non-JSON response: {status}"));
        (status, headers, body)
    }
    pub async fn ok(&self, method: &str, path: &str, body: Option<Value>) -> Value {
        let (status, _, body) = self.send(method, path, body, true, &[]).await;
        assert_eq!(status, StatusCode::OK, "{method} {path}: {body}");
        body
    }
    pub async fn project(&self) -> String {
        self.ok(
            "POST",
            "/projects",
            Some(json!({"name":"Production","description":"integration fixture"})),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .into()
    }
}
