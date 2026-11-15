use anyhow::Result;
use rizenvuln_api::app;
use rizenvuln_config::Config;
#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let config = Config::load()?;
    let pool = rizenvuln_database::connect(&config.database_url).await?;
    rizenvuln_database::migrate(&pool).await?;
    app::bootstrap(&pool, &config).await?;
    let listener = tokio::net::TcpListener::bind(&config.bind).await?;
    let state = app::State::new(pool, config);
    tracing::info!("RizenVuln API started");
    axum::serve(listener, app::router(state))
        .with_graceful_shutdown(app::shutdown())
        .await?;
    Ok(())
}
