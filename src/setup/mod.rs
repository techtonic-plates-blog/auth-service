use crate::config;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};


pub async fn db_init(database_url: &str) -> anyhow::Result<DatabaseConnection> {
    let opt = ConnectOptions::new(database_url.to_string());
    let db = Database::connect(opt).await?;
    Ok(db)
}

pub struct SetupResult {
    pub db: DatabaseConnection,
}

pub async fn setup_all() -> anyhow::Result<SetupResult> {
    let db = db_init(&config::CONFIG.database_url).await?;
    Ok(SetupResult { db })
}
