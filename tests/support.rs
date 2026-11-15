// Shared by integration tests; never connects to the application's database.
use sqlx::{
    postgres::{PgConnectOptions, PgPoolOptions},
    PgPool,
};
use uuid::Uuid;

pub struct TestDatabase {
    pub pool: PgPool,
    admin: PgPool,
    schema: String,
}
impl TestDatabase {
    pub async fn new() -> Self {
        let url = std::env::var("TEST_DATABASE_URL").expect("run scripts/test-integration.py");
        let options: PgConnectOptions = url.parse().expect("valid test database URL");
        assert!(
            options
                .get_database()
                .is_some_and(|name| name.starts_with("rvtest_")),
            "TEST_DATABASE_URL must point to a dedicated rvtest_* database"
        );
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options.clone())
            .await
            .unwrap();
        let schema = format!("test_{}", Uuid::new_v4().simple());
        sqlx::query(&format!("CREATE SCHEMA {schema}"))
            .execute(&admin)
            .await
            .unwrap();
        let search_path = schema.clone();
        let pool = PgPoolOptions::new()
            .max_connections(8)
            .after_connect(move |connection, _| {
                let statement = format!("SET search_path TO {search_path}");
                Box::pin(async move {
                    sqlx::query(&statement).execute(connection).await?;
                    Ok(())
                })
            })
            .connect_with(options)
            .await
            .unwrap();
        rizenvuln_database::migrate(&pool).await.unwrap();
        Self {
            pool,
            admin,
            schema,
        }
    }
    pub async fn close(self) {
        self.pool.close().await;
        sqlx::query(&format!("DROP SCHEMA {} CASCADE", self.schema))
            .execute(&self.admin)
            .await
            .unwrap();
        self.admin.close().await;
    }
}
