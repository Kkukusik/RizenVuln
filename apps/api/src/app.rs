use axum::{
    extract::{DefaultBodyLimit, OriginalUri, Path, Query, Request, State as AxState},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, patch, post},
    Extension, Json, Router,
};
use chrono::{Duration, Utc};
use rizenvuln_config::Config;
use serde::Deserialize;
use serde_json::{json, Value};
use sqlx::{PgPool, Row};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};
use tower_http::{
    services::{ServeDir, ServeFile},
    trace::TraceLayer,
};
use uuid::Uuid;
#[derive(Clone)]
pub struct State {
    pub pool: PgPool,
    pub config: Arc<Config>,
    limits: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
}
impl State {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            config: Arc::new(config),
            limits: Arc::new(Mutex::new(HashMap::new())),
        }
    }
}
#[derive(Clone)]
struct User {
    id: Uuid,
    email: String,
    role: String,
}
#[derive(Debug)]
pub struct ApiError(StatusCode, &'static str);
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.0,
            Json(json!({"error":{"code":self.0.as_u16(),"message":self.1}})),
        )
            .into_response()
    }
}
impl From<sqlx::Error> for ApiError {
    fn from(e: sqlx::Error) -> Self {
        if let sqlx::Error::Database(d) = &e {
            if d.is_unique_violation() {
                return Self(StatusCode::CONFLICT, "Запись уже существует");
            }
            if d.is_foreign_key_violation() {
                return Self(StatusCode::BAD_REQUEST, "Связанная запись не найдена");
            }
        }
        tracing::error!(error=%e,"Database operation failed");
        Self(StatusCode::INTERNAL_SERVER_ERROR, "Ошибка базы данных")
    }
}
impl From<anyhow::Error> for ApiError {
    fn from(_: anyhow::Error) -> Self {
        Self(
            StatusCode::BAD_GATEWAY,
            "Операция интеграции не выполнена; проверьте настройки",
        )
    }
}
type ApiResult<T> = Result<T, ApiError>;
fn bad(message: &'static str) -> ApiError {
    ApiError(StatusCode::BAD_REQUEST, message)
}
fn cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("cookie")?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|s| s.trim().strip_prefix("rv_session="))
}
fn allow(state: &State, key: &str, max: u32) -> bool {
    let Ok(mut limits) = state.limits.lock() else {
        return false;
    };
    let e = limits.entry(key.into()).or_insert((Instant::now(), 0));
    if e.0.elapsed().as_secs() >= 60 {
        *e = (Instant::now(), 0)
    }
    e.1 += 1;
    e.1 <= max
}
async fn guard(
    AxState(state): AxState<State>,
    OriginalUri(original_uri): OriginalUri,
    mut request: Request,
    next: Next,
) -> Response {
    if !allow(&state, "api", 600) {
        return ApiError(StatusCode::TOO_MANY_REQUESTS, "Слишком много запросов").into_response();
    }
    // Nested routers strip /api/v1 from request.uri(); access rules use the full path.
    let path = original_uri.path();
    if path == "/api/v1/auth/login" {
        return next.run(request).await;
    }
    let Some(token) = cookie(request.headers()) else {
        return ApiError(StatusCode::UNAUTHORIZED, "Требуется вход").into_response();
    };
    let hash = rizenvuln_auth::digest(&state.config.session_secret, token);
    let row=sqlx::query("SELECT u.id,u.email,u.role,s.csrf_hash FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.id=$1 AND s.expires_at>now()").bind(&hash).fetch_optional(&state.pool).await;
    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return ApiError(StatusCode::UNAUTHORIZED, "Сессия истекла").into_response(),
        Err(e) => return ApiError::from(e).into_response(),
    };
    let user = User {
        id: row.get("id"),
        email: row.get("email"),
        role: row.get("role"),
    };
    if !matches!(
        *request.method(),
        Method::GET | Method::HEAD | Method::OPTIONS
    ) {
        if user.role != "admin" && path != "/api/v1/auth/logout" {
            return ApiError(StatusCode::FORBIDDEN, "Требуется роль admin").into_response();
        }
        let origin = request
            .headers()
            .get("origin")
            .and_then(|h| h.to_str().ok());
        let csrf = request
            .headers()
            .get("x-csrf-token")
            .and_then(|h| h.to_str().ok())
            .unwrap_or_default();
        if origin != Some(state.config.public_url.as_str())
            || rizenvuln_auth::digest(&state.config.session_secret, csrf)
                != row.get::<String, _>("csrf_hash")
        {
            return ApiError(StatusCode::FORBIDDEN, "Проверка CSRF не пройдена").into_response();
        }
    }
    request.extensions_mut().insert(user);
    next.run(request).await
}
async fn security(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    if response.status().is_client_error()
        && !response
            .headers()
            .get("content-type")
            .and_then(|h| h.to_str().ok())
            .is_some_and(|s| s.starts_with("application/json"))
    {
        response = ApiError(response.status(), "Некорректный запрос").into_response();
    }
    let h = response.headers_mut();
    for (name,value) in [("x-content-type-options","nosniff"),("referrer-policy","same-origin"),("x-frame-options","DENY"),("cache-control","no-store"),("content-security-policy","default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")] {h.insert(axum::http::HeaderName::from_static(name),HeaderValue::from_static(value));}
    response
}
pub fn router(state: State) -> Router {
    let api = Router::new()
        .route("/auth/login", post(login))
        .route("/auth/logout", post(logout))
        .route("/auth/me", get(me))
        .route("/dashboard", get(dashboard))
        .route("/projects", get(projects).post(create_project))
        .route("/images", get(images).post(create_image))
        .route("/images/{id}/scan", post(scan))
        .route("/repositories", get(repositories).post(create_repository))
        .route("/vulnerabilities", get(vulnerabilities))
        .route("/remediation", get(vulnerabilities))
        .route("/remediation/{id}", patch(remediate))
        .route("/sbom", get(sboms))
        .route("/sbom/{id}", get(sbom_document))
        .route("/sbom/{id}/packages", get(sbom_packages))
        .route("/sbom/compare", get(sbom_compare))
        .route("/deployments", get(deployments))
        .route("/updates", get(updates))
        .route("/updates/{id}/approve", post(approve))
        .route("/reports", get(reports))
        .route("/notifications", get(notifications))
        .route("/notifications/test", post(test_notification))
        .route("/integrations", get(integrations))
        .route("/integrations/harbor/projects", get(harbor_projects))
        .route("/integrations/harbor/monitor", post(harbor_monitor))
        .route("/settings", get(settings))
        .route("/settings/users", get(users).post(create_user))
        .route("/settings/users/{id}/password", post(reset_password))
        .route(
            "/notifications/rules",
            get(notification_rules).post(set_rule),
        )
        .route("/jobs", get(jobs))
        .route("/openapi.json", get(openapi))
        .fallback(|| async { ApiError(StatusCode::NOT_FOUND, "Маршрут не найден") })
        .layer(middleware::from_fn_with_state(state.clone(), guard));
    Router::new()
        .nest("/api/v1", api)
        .route(
            "/health/live",
            get(|| async { Json(json!({"status":"live"})) }),
        )
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .fallback_service(
            ServeDir::new(rizenvuln_config::value("FRONTEND_DIR", "frontend/dist"))
                .not_found_service(ServeFile::new(format!(
                    "{}/index.html",
                    rizenvuln_config::value("FRONTEND_DIR", "frontend/dist")
                ))),
        )
        .layer(DefaultBodyLimit::max(1024 * 1024))
        .layer(middleware::from_fn(security))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
pub async fn bootstrap(pool: &PgPool, c: &Config) -> anyhow::Result<()> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM users WHERE role='admin')")
        .fetch_one(pool)
        .await?;
    if !exists {
        let password = c.admin_password.clone();
        let hash =
            tokio::task::spawn_blocking(move || rizenvuln_auth::hash_password(&password)).await??;
        sqlx::query("INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,'admin') ON CONFLICT(email) DO NOTHING").bind(Uuid::new_v4()).bind(c.admin_email.to_lowercase()).bind(hash).execute(pool).await?;
    }
    for (kind, enabled) in [
        ("harbor", rizenvuln_config::enabled("HARBOR_ENABLED", false)),
        ("github", rizenvuln_config::enabled("GITHUB_ENABLED", true)),
        ("s3", rizenvuln_config::enabled("S3_ENABLED", false)),
        (
            "telegram",
            rizenvuln_config::enabled("TELEGRAM_ENABLED", false),
        ),
        (
            "docker",
            rizenvuln_config::enabled("DOCKER_DISCOVERY_ENABLED", false),
        ),
        (
            "kubernetes",
            rizenvuln_config::enabled("KUBERNETES_ENABLED", false),
        ),
    ] {
        sqlx::query("INSERT INTO integrations(id,kind,enabled,status) VALUES($1,$2,$3,$4) ON CONFLICT(kind) DO UPDATE SET enabled=EXCLUDED.enabled").bind(Uuid::new_v4()).bind(kind).bind(enabled).bind(if enabled{"PENDING"}else{"DISABLED"}).execute(pool).await?;
    }
    Ok(())
}
#[derive(Deserialize)]
struct Login {
    email: String,
    password: String,
}
async fn login(
    AxState(s): AxState<State>,
    headers: HeaderMap,
    Json(input): Json<Login>,
) -> ApiResult<Response> {
    if !allow(&s, "login", 15) {
        return Err(ApiError(
            StatusCode::TOO_MANY_REQUESTS,
            "Повторите вход через минуту",
        ));
    }
    if headers.get("origin").and_then(|v| v.to_str().ok()) != Some(s.config.public_url.as_str()) {
        return Err(ApiError(StatusCode::FORBIDDEN, "Недопустимый Origin"));
    }
    if input.email.len() > 254 || input.password.len() > 256 {
        return Err(bad("Некорректные данные входа"));
    }
    let row = sqlx::query("SELECT id,password_hash,role FROM users WHERE email=$1")
        .bind(input.email.to_lowercase())
        .fetch_optional(&s.pool)
        .await?;
    let fallback="$argon2id$v=19$m=19456,t=2,p=1$MTIzNDU2Nzg5MDEyMzQ1Ng$M4bdQRO1GY4vSOxQvWl4E6Xvrm5OOIeFM8q7VAMl4Hw";
    let hash = row
        .as_ref()
        .map(|r| r.get::<String, _>("password_hash"))
        .unwrap_or(fallback.into());
    let password = input.password;
    let valid = tokio::task::spawn_blocking(move || rizenvuln_auth::verify(&password, &hash))
        .await
        .unwrap_or(false);
    let Some(row) = row.filter(|_| valid) else {
        return Err(ApiError(
            StatusCode::UNAUTHORIZED,
            "Неверный email или пароль",
        ));
    };
    let id: Uuid = row.get("id");
    let token = rizenvuln_auth::token();
    let csrf = rizenvuln_auth::token();
    let mut tx = s.pool.begin().await?;
    sqlx::query("DELETE FROM sessions WHERE expires_at<now()")
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO sessions(id,user_id,csrf_hash,expires_at) VALUES($1,$2,$3,$4)")
        .bind(rizenvuln_auth::digest(&s.config.session_secret, &token))
        .bind(id)
        .bind(rizenvuln_auth::digest(&s.config.session_secret, &csrf))
        .bind(Utc::now() + Duration::hours(12))
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, id, "login", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    let cookie = format!(
        "rv_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200{}",
        if s.config.secure_cookie {
            "; Secure"
        } else {
            ""
        }
    );
    Ok((
        [("set-cookie", cookie)],
        Json(json!({"csrf_token":csrf,"role":row.get::<String,_>("role")})),
    )
        .into_response())
}
async fn logout(AxState(s): AxState<State>, headers: HeaderMap) -> ApiResult<Response> {
    if let Some(t) = cookie(&headers) {
        sqlx::query("DELETE FROM sessions WHERE id=$1")
            .bind(rizenvuln_auth::digest(&s.config.session_secret, t))
            .execute(&s.pool)
            .await?;
    }
    Ok((
        [(
            "set-cookie",
            "rv_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"ok":true})),
    )
        .into_response())
}
async fn me(Extension(u): Extension<User>) -> Json<Value> {
    Json(json!({"id":u.id,"email":u.email,"role":u.role}))
}
async fn audit(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    user: Uuid,
    action: &str,
    resource: &str,
    details: Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO audit_logs(id,user_id,action,resource,details) VALUES($1,$2,$3,$4,$5)",
    )
    .bind(Uuid::new_v4())
    .bind(user)
    .bind(action)
    .bind(resource)
    .bind(details)
    .execute(&mut **tx)
    .await?;
    Ok(())
}
#[derive(Deserialize, Default)]
struct Paging {
    page: Option<i64>,
    per_page: Option<i64>,
    q: Option<String>,
    severity: Option<String>,
    status: Option<String>,
    project_id: Option<Uuid>,
    image_id: Option<Uuid>,
    environment: Option<String>,
    fix_available: Option<bool>,
    kev: Option<bool>,
    min_epss: Option<f64>,
    sort: Option<String>,
    order: Option<String>,
}
async fn listing(s: &State, table: &str, p: Paging) -> ApiResult<Json<Value>> {
    let page = p.page.unwrap_or(1).clamp(1, 100000);
    let size = p.per_page.unwrap_or(25).clamp(1, 100);
    let search = format!(
        "%{}%",
        p.q.unwrap_or_default()
            .chars()
            .take(200)
            .collect::<String>()
    );
    let sort = p.sort.as_deref().unwrap_or("id");
    let order = if p.order.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };
    let filter="to_jsonb(t)::text ILIKE $1 AND ($2::text IS NULL OR to_jsonb(t)->>'severity'=$2) AND ($3::text IS NULL OR to_jsonb(t)->>'status'=$3) AND ($4::text IS NULL OR to_jsonb(t)->>'project_id'=$4)";
    let sql=format!("SELECT to_jsonb(t) - 'document' FROM {table} t WHERE {filter} ORDER BY to_jsonb(t)->>$7 {order},id LIMIT $5 OFFSET $6");
    let project = p.project_id.map(|v| v.to_string());
    let rows: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(&search)
        .bind(&p.severity)
        .bind(&p.status)
        .bind(&project)
        .bind(size)
        .bind((page - 1) * size)
        .bind(sort)
        .fetch_all(&s.pool)
        .await?;
    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) FROM {table} t WHERE {filter}"))
        .bind(search)
        .bind(p.severity)
        .bind(p.status)
        .bind(project)
        .fetch_one(&s.pool)
        .await?;
    Ok(Json(
        json!({"items":rows,"total":count,"page":page,"per_page":size}),
    ))
}
macro_rules! list_handler {
    ($name:ident,$table:literal) => {
        async fn $name(
            AxState(s): AxState<State>,
            Query(p): Query<Paging>,
        ) -> ApiResult<Json<Value>> {
            listing(&s, $table, p).await
        }
    };
}
list_handler!(projects, "projects");
list_handler!(images, "images");
list_handler!(repositories, "repositories");
list_handler!(sboms, "sbom_artifacts");
list_handler!(deployments, "deployments");
list_handler!(updates, "update_recommendations");
list_handler!(reports, "scan_runs");
list_handler!(notifications, "notifications");
list_handler!(integrations, "integrations");
list_handler!(jobs, "jobs");
#[derive(Deserialize)]
struct ProjectInput {
    name: String,
    #[serde(default)]
    description: String,
}
async fn create_project(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<ProjectInput>,
) -> ApiResult<Json<Value>> {
    if i.name.trim().is_empty() || i.name.len() > 120 || i.description.len() > 4000 {
        return Err(bad("Некорректное имя или описание"));
    }
    let id = Uuid::new_v4();
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO projects(id,name,description) VALUES($1,$2,$3)")
        .bind(id)
        .bind(i.name.trim())
        .bind(i.description)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, u.id, "project.create", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id})))
}
#[derive(Deserialize)]
struct SourceInput {
    project_id: Uuid,
    reference: String,
    branch: Option<String>,
    track_commits: Option<bool>,
}
async fn create_image(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<SourceInput>,
) -> ApiResult<Json<Value>> {
    let r = rizenvuln_core::ImageReference::parse(&i.reference)
        .map_err(|_| bad("Некорректный образ"))?;
    let id = Uuid::new_v4();
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO images(id,project_id,reference,registry) VALUES($1,$2,$3,$4)")
        .bind(id)
        .bind(i.project_id)
        .bind(r.canonical())
        .bind(r.registry)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,'image',$2,$3)")
        .bind(Uuid::new_v4())
        .bind(json!({"image_id":id}))
        .bind(format!("image:{id}"))
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, u.id, "image.create", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id})))
}
async fn create_repository(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<SourceInput>,
) -> ApiResult<Json<Value>> {
    let name = rizenvuln_integrations::github::Github::repository(&i.reference)
        .map_err(|_| bad("Некорректный GitHub repository"))?;
    let branch = i.branch.unwrap_or("main".into());
    if branch.len() > 200 || branch.is_empty() {
        return Err(bad("Некорректная ветка"));
    }
    let id = Uuid::new_v4();
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO repositories(id,project_id,full_name,branch,track_commits) VALUES($1,$2,$3,$4,$5)").bind(id).bind(i.project_id).bind(name).bind(branch).bind(i.track_commits.unwrap_or(false)).execute(&mut *tx).await?;
    sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,'github',$2,$3)")
        .bind(Uuid::new_v4())
        .bind(json!({"repository_id":id}))
        .bind(format!("github:{id}"))
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        u.id,
        "repository.create",
        &id.to_string(),
        json!({}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id})))
}
async fn scan(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Path(id): Path<Uuid>,
) -> ApiResult<Json<Value>> {
    let exists: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM images WHERE id=$1)")
        .bind(id)
        .fetch_one(&s.pool)
        .await?;
    if !exists {
        return Err(ApiError(StatusCode::NOT_FOUND, "Образ не найден"));
    }
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO jobs(id,kind,payload,dedup_key) VALUES($1,'image',$2,$3) ON CONFLICT(dedup_key) WHERE status IN ('PENDING','RUNNING') DO NOTHING").bind(Uuid::new_v4()).bind(json!({"image_id":id})).bind(format!("image:{id}")).execute(&mut *tx).await?;
    audit(&mut tx, u.id, "scan.enqueue", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"queued":true})))
}
async fn vulnerabilities(
    AxState(s): AxState<State>,
    Query(p): Query<Paging>,
) -> ApiResult<Json<Value>> {
    let size = p.per_page.unwrap_or(25).clamp(1, 100);
    let page = p.page.unwrap_or(1).clamp(1, 100000);
    let filter="s.status='COMPLETED' AND s.id=(SELECT id FROM scan_runs WHERE image_id=f.image_id AND status='COMPLETED' ORDER BY started_at DESC LIMIT 1) AND ($1::text IS NULL OR f.severity=$1) AND ($2::text IS NULL OR f.status=$2) AND ($3::uuid IS NULL OR i.project_id=$3) AND ($4::bool IS NULL OR (f.fixed_version<>'')=$4) AND ($5::bool IS NULL OR v.kev=$5) AND ($6::float8 IS NULL OR v.epss >= $6) AND (f.vulnerability_id ILIKE $7 OR f.package ILIKE $7) AND ($8::uuid IS NULL OR f.image_id=$8) AND ($9::text IS NULL OR EXISTS(SELECT 1 FROM deployments d WHERE d.environment=$9 AND d.running=true AND (d.image=i.reference OR d.digest=s.digest)))";
    let base="FROM vulnerability_findings f JOIN vulnerabilities v ON v.id=f.vulnerability_id JOIN images i ON i.id=f.image_id JOIN scan_runs s ON s.id=f.scan_run_id";
    let q = format!("%{}%", p.q.unwrap_or_default());
    if p.min_epss.is_some_and(|v| !(0.0..=1.0).contains(&v)) {
        return Err(bad("EPSS должен быть от 0 до 1"));
    }
    let sorting=match p.sort.as_deref(){Some("severity")=>"CASE f.severity WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END",Some("epss")=>"v.epss",Some("kev")=>"v.kev",Some("package")=>"f.package",Some("vulnerability_id")=>"f.vulnerability_id",Some("status")=>"f.status",_=>"f.created_at"};
    let direction = if p.order.as_deref() == Some("asc") {
        "ASC"
    } else {
        "DESC"
    };
    let sql=format!("SELECT to_jsonb(f)||jsonb_build_object('kev',v.kev,'epss',v.epss,'title',v.title,'reference',i.reference,'project_id',i.project_id) {base} WHERE {filter} ORDER BY {sorting} {direction} NULLS LAST,f.id LIMIT $10 OFFSET $11");
    let items: Vec<Value> = sqlx::query_scalar(&sql)
        .bind(&p.severity)
        .bind(&p.status)
        .bind(p.project_id)
        .bind(p.fix_available)
        .bind(p.kev)
        .bind(p.min_epss)
        .bind(&q)
        .bind(p.image_id)
        .bind(&p.environment)
        .bind(size)
        .bind((page - 1) * size)
        .fetch_all(&s.pool)
        .await?;
    let count: i64 = sqlx::query_scalar(&format!("SELECT count(*) {base} WHERE {filter}"))
        .bind(p.severity)
        .bind(p.status)
        .bind(p.project_id)
        .bind(p.fix_available)
        .bind(p.kev)
        .bind(p.min_epss)
        .bind(q)
        .bind(p.image_id)
        .bind(p.environment)
        .fetch_one(&s.pool)
        .await?;
    Ok(Json(
        json!({"items":items,"total":count,"page":page,"per_page":size}),
    ))
}
#[derive(Deserialize)]
struct Remediation {
    status: String,
    #[serde(default)]
    note: String,
}
async fn remediate(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Path(id): Path<Uuid>,
    Json(i): Json<Remediation>,
) -> ApiResult<Json<Value>> {
    if ![
        "NEW",
        "IN_PROGRESS",
        "PENDING_VERIFICATION",
        "FIXED",
        "RISK_ACCEPTED",
        "FALSE_POSITIVE",
    ]
    .contains(&i.status.as_str())
        || i.note.len() > 4000
    {
        return Err(bad("Некорректный статус или примечание"));
    }
    let mut tx = s.pool.begin().await?;
    let old: Option<String> =
        sqlx::query_scalar("SELECT status FROM vulnerability_findings WHERE id=$1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await?;
    let old = old.ok_or(ApiError(StatusCode::NOT_FOUND, "Уязвимость не найдена"))?;
    sqlx::query("UPDATE vulnerability_findings SET status=$2 WHERE id=$1")
        .bind(id)
        .bind(&i.status)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO vulnerability_status_history(id,finding_id,old_status,new_status,user_id,note) VALUES($1,$2,$3,$4,$5,$6)").bind(Uuid::new_v4()).bind(id).bind(old).bind(&i.status).bind(u.id).bind(i.note).execute(&mut *tx).await?;
    audit(
        &mut tx,
        u.id,
        "remediation.change",
        &id.to_string(),
        json!({"status":i.status}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
async fn sbom_document(AxState(s): AxState<State>, Path(id): Path<Uuid>) -> ApiResult<Json<Value>> {
    let d = sqlx::query_scalar("SELECT document FROM sbom_artifacts WHERE id=$1")
        .bind(id)
        .fetch_optional(&s.pool)
        .await?;
    Ok(Json(d.ok_or(ApiError(
        StatusCode::NOT_FOUND,
        "SBOM не найден",
    ))?))
}
#[derive(Deserialize)]
struct Approval {
    environment: String,
}
async fn approve(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Path(id): Path<Uuid>,
    Json(i): Json<Approval>,
) -> ApiResult<Json<Value>> {
    if !["test", "production", "staging"].contains(&i.environment.as_str()) {
        return Err(bad("Неизвестное окружение"));
    }
    let mut tx = s.pool.begin().await?;
    let row = sqlx::query(
        "SELECT image_id,candidate,digest FROM update_recommendations WHERE id=$1 FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await?
    .ok_or(ApiError(StatusCode::NOT_FOUND, "Рекомендация не найдена"))?;
    let digest: Option<String> = row.get("digest");
    let digest = digest.ok_or(bad("Для одобрения требуется digest"))?;
    sqlx::query("INSERT INTO version_approvals(id,image_id,version,digest,user_id,environment) VALUES($1,$2,$3,$4,$5,$6) ON CONFLICT(image_id,digest,environment) DO NOTHING").bind(Uuid::new_v4()).bind(row.get::<Uuid,_>("image_id")).bind(row.get::<String,_>("candidate")).bind(digest).bind(u.id).bind(i.environment).execute(&mut *tx).await?;
    sqlx::query("UPDATE update_recommendations SET status='APPROVED' WHERE id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, u.id, "version.approve", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    Ok(Json(
        json!({"ok":true,"warning":"Одобрение не гарантирует безопасность"}),
    ))
}
async fn test_notification(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
) -> ApiResult<Json<Value>> {
    if !rizenvuln_config::enabled("TELEGRAM_ENABLED", false) {
        return Err(bad("Telegram выключен"));
    }
    rizenvuln_database::notification(
        &s.pool,
        &format!("test:{}", Uuid::new_v4()),
        "test",
        "RizenVuln: тестовое уведомление",
    )
    .await?;
    let mut tx = s.pool.begin().await?;
    audit(&mut tx, u.id, "telegram.test", "telegram", json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"queued":true})))
}
fn harbor() -> anyhow::Result<rizenvuln_integrations::harbor::Harbor> {
    if !rizenvuln_config::enabled("HARBOR_ENABLED", false) {
        anyhow::bail!("Harbor disabled");
    }
    use rizenvuln_config::{EnvironmentSecretProvider, SecretProvider};
    let e = EnvironmentSecretProvider;
    rizenvuln_integrations::harbor::Harbor::new(
        &e.get("HARBOR_URL")?,
        e.get("HARBOR_USERNAME")?,
        e.get("HARBOR_PASSWORD")?,
        std::env::var("HARBOR_CA_FILE")
            .ok()
            .filter(|p| !p.is_empty())
            .map(std::fs::read)
            .transpose()?,
    )
}
async fn harbor_projects() -> ApiResult<Json<Value>> {
    Ok(Json(json!({"items":harbor()?.projects().await?})))
}
#[derive(Deserialize)]
struct Monitor {
    project_id: Uuid,
    harbor_project: String,
}
async fn harbor_monitor(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<Monitor>,
) -> ApiResult<Json<Value>> {
    if i.harbor_project.is_empty() || i.harbor_project.len() > 200 {
        return Err(bad("Некорректный проект Harbor"));
    }
    let mut tx = s.pool.begin().await?;
    let id = Uuid::new_v4();
    sqlx::query("INSERT INTO sources(id,project_id,kind,name) VALUES($1,$2,'harbor',$3) ON CONFLICT(project_id,kind,name) DO NOTHING").bind(id).bind(i.project_id).bind(&i.harbor_project).execute(&mut *tx).await?;
    audit(
        &mut tx,
        u.id,
        "harbor.monitor",
        &i.harbor_project,
        json!({}),
    )
    .await?;
    tx.commit().await?;
    rizenvuln_database::enqueue(
        &s.pool,
        "harbor",
        json!({"project_id":i.project_id,"name":i.harbor_project}),
        &format!("harbor:{}:{}", i.project_id, i.harbor_project),
    )
    .await?;
    Ok(Json(json!({"queued":true})))
}
async fn settings(AxState(s): AxState<State>, Extension(u): Extension<User>) -> Json<Value> {
    Json(
        json!({"app":"RizenVuln","role":u.role,"scan_enabled":s.config.scan_enabled,"scan_interval_seconds":s.config.scan_interval,"max_concurrent_scans":s.config.concurrency,"read_only_infrastructure":true}),
    )
}
async fn dashboard(AxState(s): AxState<State>) -> ApiResult<Json<Value>> {
    let counts:Value=sqlx::query_scalar("SELECT jsonb_build_object('projects',(SELECT count(*) FROM projects),'images',(SELECT count(*) FROM images),'updates',(SELECT count(*) FROM images i WHERE (SELECT status FROM update_recommendations WHERE image_id=i.id ORDER BY created_at DESC LIMIT 1) IN ('UPDATE_AVAILABLE','OUTDATED','SECURITY_FIX_AVAILABLE')),'last_scan',(SELECT max(completed_at) FROM scan_runs WHERE status='COMPLETED'),'stale_images',(SELECT count(*) FROM images i WHERE NOT EXISTS(SELECT 1 FROM scan_runs s WHERE s.image_id=i.id AND s.status='COMPLETED' AND s.completed_at>now()-make_interval(secs=>$1::float8))),'fixes',(SELECT count(*) FROM vulnerability_findings f JOIN scan_runs s ON s.id=f.scan_run_id WHERE f.fixed_version<>'' AND s.id=(SELECT id FROM scan_runs WHERE image_id=f.image_id AND status='COMPLETED' ORDER BY started_at DESC LIMIT 1)))").bind(s.config.scan_interval as f64*1.5).fetch_one(&s.pool).await?;
    let severity:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('severity',f.severity,'count',count(*)) FROM vulnerability_findings f WHERE f.scan_run_id=(SELECT id FROM scan_runs WHERE image_id=f.image_id AND status='COMPLETED' ORDER BY started_at DESC LIMIT 1) GROUP BY f.severity").fetch_all(&s.pool).await?;
    let trend:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('date',date_trunc('day',s.started_at),'count',count(f.id),'scans',count(DISTINCT s.id)) FROM scan_runs s LEFT JOIN vulnerability_findings f ON f.scan_run_id=s.id WHERE s.started_at>now()-interval '30 days' GROUP BY date_trunc('day',s.started_at) ORDER BY date_trunc('day',s.started_at)").fetch_all(&s.pool).await?;
    let integrations: Vec<Value> =
        sqlx::query_scalar("SELECT to_jsonb(i) FROM integrations i ORDER BY kind")
            .fetch_all(&s.pool)
            .await?;
    let by_project:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('name',p.name,'count',count(f.id)) FROM projects p LEFT JOIN images i ON i.project_id=p.id LEFT JOIN vulnerability_findings f ON f.image_id=i.id AND f.scan_run_id=(SELECT id FROM scan_runs WHERE image_id=i.id AND status='COMPLETED' ORDER BY started_at DESC LIMIT 1) GROUP BY p.id,p.name ORDER BY count(f.id) DESC LIMIT 30").fetch_all(&s.pool).await?;
    let fixes:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('date',date_trunc('day',created_at),'count',count(*)) FROM vulnerability_status_history WHERE new_status='FIXED' AND created_at>now()-interval '30 days' GROUP BY date_trunc('day',created_at) ORDER BY date_trunc('day',created_at)").fetch_all(&s.pool).await?;
    Ok(Json(
        json!({"counts":counts,"severity":severity,"trend":trend,"integrations":integrations,"by_project":by_project,"fixes":fixes}),
    ))
}
async fn ready(AxState(s): AxState<State>) -> Response {
    match sqlx::query("SELECT 1").execute(&s.pool).await {
        Ok(_) => Json(json!({"status":"ready"})).into_response(),
        Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status":"unready"})),
        )
            .into_response(),
    }
}
async fn metrics(AxState(s): AxState<State>, headers: HeaderMap) -> Response {
    let configured = std::env::var("METRICS_TOKEN").unwrap_or_default();
    if configured.is_empty()
        || headers.get("authorization").and_then(|v| v.to_str().ok())
            != Some(format!("Bearer {configured}").as_str())
    {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let queries = [
        (
            "rizenvuln_scans_total",
            "SELECT count(*)::float8 FROM scan_runs",
        ),
        (
            "rizenvuln_scans_failed_total",
            "SELECT count(*)::float8 FROM scan_runs WHERE status='FAILED'",
        ),
        (
            "rizenvuln_scan_duration_seconds_sum",
            "SELECT COALESCE(sum(duration_seconds),0)::float8 FROM scan_runs",
        ),
        (
            "rizenvuln_scan_duration_seconds_count",
            "SELECT count(duration_seconds)::float8 FROM scan_runs",
        ),
        (
            "rizenvuln_vulnerabilities_total",
            "SELECT count(*)::float8 FROM vulnerabilities",
        ),
        (
            "rizenvuln_images_monitored",
            "SELECT count(*)::float8 FROM images",
        ),
        (
            "rizenvuln_integrations_errors_total",
            "SELECT COALESCE(sum(errors_total),0)::float8 FROM integrations",
        ),
        (
            "rizenvuln_notifications_total",
            "SELECT count(*)::float8 FROM notifications WHERE status='SENT'",
        ),
        (
            "rizenvuln_jobs_pending",
            "SELECT count(*)::float8 FROM jobs WHERE status='PENDING'",
        ),
    ];
    let mut out = String::new();
    for (name, query) in queries {
        match sqlx::query_scalar::<_, f64>(query).fetch_one(&s.pool).await {
            Ok(v) => out.push_str(&format!("{name} {v}\n")),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        }
    }
    ([("content-type", "text/plain; version=0.0.4")], out).into_response()
}
async fn openapi() -> Json<Value> {
    Json(
        serde_json::from_str(include_str!("../../../docs/openapi.json")).expect("embedded OpenAPI"),
    )
}
pub async fn shutdown() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {_=tokio::signal::ctrl_c()=>{},_=term.recv()=>{}}
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    tracing::info!("Graceful shutdown");
}
#[cfg(test)]
mod tests {
    use super::*;
    use tower::ServiceExt;
    #[tokio::test]
    async fn live_and_auth() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://test:test@localhost/test")
            .unwrap();
        let config = Config {
            database_url: String::new(),
            bind: String::new(),
            public_url: "http://localhost:8080".into(),
            secure_cookie: false,
            admin_email: String::new(),
            admin_password: String::new(),
            session_secret: "x".repeat(32),
            scan_enabled: false,
            scan_interval: 86400,
            concurrency: 1,
            trivy_cache: String::new(),
        };
        let r = router(State::new(pool, config));
        let response = r
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health/live")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        // Login must reach its Origin check without requiring an existing session.
        let response = r
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .header("origin", "https://untrusted.example")
                    .body(axum::body::Body::from(
                        r#"{"email":"admin@example.test","password":"test"}"#,
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let body = axum::body::to_bytes(response.into_body(), 8192)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body["error"]["message"], "Недопустимый Origin");
        let response = r
            .oneshot(
                axum::http::Request::builder()
                    .uri("/api/v1/projects")
                    .body(axum::body::Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

async fn sbom_packages(
    AxState(s): AxState<State>,
    Path(id): Path<Uuid>,
    Query(p): Query<Paging>,
) -> ApiResult<Json<Value>> {
    let document: Value = sqlx::query_scalar("SELECT document FROM sbom_artifacts WHERE id=$1")
        .bind(id)
        .fetch_optional(&s.pool)
        .await?
        .ok_or(ApiError(StatusCode::NOT_FOUND, "SBOM не найден"))?;
    let packages = rizenvuln_core::sbom_packages(&document)
        .map_err(|_| bad("Этот документ не содержит перечень пакетов SBOM"))?;
    let search = p.q.unwrap_or_default().to_lowercase();
    let filtered: Vec<_> = packages
        .into_iter()
        .filter(|p| {
            p.name.to_lowercase().contains(&search) || p.license.to_lowercase().contains(&search)
        })
        .collect();
    let total = filtered.len();
    let page = p.page.unwrap_or(1).clamp(1, 100000);
    let size = p.per_page.unwrap_or(25).clamp(1, 100);
    let items: Vec<_> = filtered
        .into_iter()
        .skip(((page - 1) * size) as usize)
        .take(size as usize)
        .collect();
    Ok(Json(
        json!({"items":items,"total":total,"page":page,"per_page":size}),
    ))
}
#[derive(Deserialize)]
struct Compare {
    left: Uuid,
    right: Uuid,
}
async fn sbom_compare(
    AxState(s): AxState<State>,
    Query(p): Query<Compare>,
) -> ApiResult<Json<Value>> {
    let mut sides = Vec::new();
    for id in [p.left, p.right] {
        let d: Value = sqlx::query_scalar("SELECT document FROM sbom_artifacts WHERE id=$1")
            .bind(id)
            .fetch_optional(&s.pool)
            .await?
            .ok_or(ApiError(StatusCode::NOT_FOUND, "SBOM не найден"))?;
        sides.push(
            rizenvuln_core::sbom_packages(&d).map_err(|_| bad("Неподдерживаемый формат SBOM"))?,
        );
    }
    let keys = |packages: &Vec<rizenvuln_core::Package>| {
        packages
            .iter()
            .map(|p| (p.name.clone(), p.version.clone(), p.purl.clone()))
            .collect::<std::collections::BTreeSet<_>>()
    };
    let a = keys(&sides[0]);
    let b = keys(&sides[1]);
    Ok(Json(
        json!({"added":b.difference(&a).collect::<Vec<_>>(),"removed":a.difference(&b).collect::<Vec<_>>(),"warning":"Сравнение состава SBOM не подтверждает отсутствие уязвимостей"}),
    ))
}

async fn users(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
) -> ApiResult<Json<Value>> {
    if u.role != "admin" {
        return Err(ApiError(StatusCode::FORBIDDEN, "Требуется роль admin"));
    }
    let items:Vec<Value>=sqlx::query_scalar("SELECT jsonb_build_object('id',id,'email',email,'role',role,'created_at',created_at) FROM users ORDER BY created_at LIMIT 100").fetch_all(&s.pool).await?;
    Ok(Json(json!({"items":items})))
}
#[derive(Deserialize)]
struct NewUser {
    email: String,
    password: String,
    role: String,
}
async fn create_user(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<NewUser>,
) -> ApiResult<Json<Value>> {
    if i.email.len() > 254
        || !i.email.contains('@')
        || i.email.chars().any(char::is_control)
        || !(16..=256).contains(&i.password.len())
        || !["admin", "viewer"].contains(&i.role.as_str())
    {
        return Err(bad("Некорректный email, пароль или роль"));
    }
    let hash = tokio::task::spawn_blocking(move || rizenvuln_auth::hash_password(&i.password))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Ошибка хеширования"))??;
    let id = Uuid::new_v4();
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO users(id,email,password_hash,role) VALUES($1,$2,$3,$4)")
        .bind(id)
        .bind(i.email.to_lowercase())
        .bind(hash)
        .bind(i.role)
        .execute(&mut *tx)
        .await?;
    audit(&mut tx, u.id, "user.create", &id.to_string(), json!({})).await?;
    tx.commit().await?;
    Ok(Json(json!({"id":id})))
}
#[derive(Deserialize)]
struct NewPassword {
    password: String,
}
async fn reset_password(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Path(id): Path<Uuid>,
    Json(i): Json<NewPassword>,
) -> ApiResult<Json<Value>> {
    if !(16..=256).contains(&i.password.len()) {
        return Err(bad("Пароль должен содержать 16–256 символов"));
    }
    let hash = tokio::task::spawn_blocking(move || rizenvuln_auth::hash_password(&i.password))
        .await
        .map_err(|_| ApiError(StatusCode::INTERNAL_SERVER_ERROR, "Ошибка хеширования"))??;
    let mut tx = s.pool.begin().await?;
    if sqlx::query("UPDATE users SET password_hash=$2 WHERE id=$1")
        .bind(id)
        .bind(hash)
        .execute(&mut *tx)
        .await?
        .rows_affected()
        == 0
    {
        return Err(ApiError(StatusCode::NOT_FOUND, "Пользователь не найден"));
    }
    sqlx::query("DELETE FROM sessions WHERE user_id=$1")
        .bind(id)
        .execute(&mut *tx)
        .await?;
    audit(
        &mut tx,
        u.id,
        "user.password_reset",
        &id.to_string(),
        json!({"sessions_revoked":true}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
async fn notification_rules(AxState(s): AxState<State>) -> ApiResult<Json<Value>> {
    let items: Vec<Value> =
        sqlx::query_scalar("SELECT to_jsonb(r) FROM notification_rules r ORDER BY event")
            .fetch_all(&s.pool)
            .await?;
    Ok(Json(json!({"items":items})))
}
#[derive(Deserialize)]
struct Rule {
    event: String,
    enabled: bool,
}
async fn set_rule(
    AxState(s): AxState<State>,
    Extension(u): Extension<User>,
    Json(i): Json<Rule>,
) -> ApiResult<Json<Value>> {
    if ![
        "vulnerability",
        "fix_available",
        "kev",
        "stable_release",
        "scan_or_integration_failed",
        "image_outdated",
        "test",
    ]
    .contains(&i.event.as_str())
    {
        return Err(bad("Неизвестное событие"));
    }
    let mut tx = s.pool.begin().await?;
    sqlx::query("INSERT INTO notification_rules(id,event,enabled) VALUES($1,$2,$3) ON CONFLICT(event) DO UPDATE SET enabled=EXCLUDED.enabled").bind(Uuid::new_v4()).bind(&i.event).bind(i.enabled).execute(&mut *tx).await?;
    audit(
        &mut tx,
        u.id,
        "notification_rule.change",
        &i.event,
        json!({"enabled":i.enabled}),
    )
    .await?;
    tx.commit().await?;
    Ok(Json(json!({"ok":true})))
}
