use crate::config;
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use redis::Client as RedisClient;


pub async fn db_init(database_url: &str) -> anyhow::Result<DatabaseConnection> {
    let opt = ConnectOptions::new(database_url.to_string());
    let db = Database::connect(opt).await?;
    Ok(db)
}

pub async fn redis_init(redis_url: &str) -> anyhow::Result<RedisClient> {
    let client = RedisClient::open(redis_url)?;
    // Test the connection
    let mut conn = client.get_connection()?;
    redis::cmd("PING").exec(&mut conn)?;
    Ok(client)
}

pub struct SetupResult {
    pub db: DatabaseConnection,
    pub redis: RedisClient,
}

pub async fn setup_all() -> anyhow::Result<SetupResult> {
    let db = db_init(&config::CONFIG.database_url).await?;
    let redis = redis_init(&config::CONFIG.redis_url).await?;
    Ok(SetupResult { db, redis })
}
