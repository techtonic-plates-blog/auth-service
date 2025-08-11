use argon2::{
    password_hash::{rand_core::OsRng, SaltString},
    Argon2, PasswordHasher,
};
use entities::{
    sea_orm_active_enums::UserStatusEnum,
    users::{self, Entity as User},
};
use poem::{listener::TcpListener, EndpointExt, Route};
use poem_openapi::OpenApiService;
use rand::Rng;
use routes::api;
use sea_orm::*;
use tracing::info;
use uuid::Uuid;

use crate::middleware::LoggingMiddleware;

use crate::setup::SetupResult;

mod auth;
mod config;
mod middleware;
mod routes;
mod setup;

const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                            abcdefghijklmnopqrstuvwxyz\
                            0123456789)(*&^%$#@!~";

fn generate_password(length: usize) -> String {
    let mut rng = rand::thread_rng();
    let password: String = (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect();
    password
}

async fn create_admin_user(db: &DbConn) -> anyhow::Result<()> {
    let admin_user = User::find()
        .filter(users::Column::Name.eq("admin"))
        .one(db)
        .await?;

    if admin_user.is_some() {
        info!("Admin user already exists.");
        return Ok(());
    }

    info!("Admin user not found, creating one.");
    let password = generate_password(16);
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Password hashing failed")
        .to_string();

    let user_id = Uuid::new_v4();
    let new_user = users::ActiveModel {
        id: Set(user_id),
        name: Set("admin".to_owned()),
        password_hash: Set(password_hash),
        creation_time: Set(chrono::Utc::now().naive_utc()),
        last_login_time: Set(chrono::Utc::now().naive_utc()),
        last_edit_time: Set(chrono::Utc::now().naive_utc()),
        status: Set(UserStatusEnum::Active),
    };

    let permissions = entities::permissions::Entity::find()
        .all(db)
        .await?;

 

    User::insert(new_user).exec(db).await?;

       entities::user_permissions::Entity::insert_many(permissions.iter().map(|permission| {
        entities::user_permissions::ActiveModel {
            user_id: Set(user_id.clone()),
            permission_id: Set(permission.id.clone()),
        }
    })).exec(db).await?;

    info!("Admin user created with password: {}", password);

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    // Initialize tracing with INFO level to capture request/response logs
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();
    
    let SetupResult { db } = setup::setup_all().await.expect("setup failed");

    create_admin_user(&db)
        .await
        .expect("failed to create admin user");

    let api_service =
        OpenApiService::new(api(), "Auth service", "1.0").server("http://localhost:5000");

    let spec_endpoint = api_service.spec_endpoint();
    let spec_yaml_endpoint = api_service.spec_endpoint_yaml();

    let swagger = api_service.swagger_ui();
    let scalar = api_service.scalar();

    let app = Route::new()
        .nest("/", api_service)
        .nest("/docs/swagger", swagger)
        .nest("/docs/", scalar)
        .nest("/docs/api.json", spec_endpoint)
        .nest("/docs/api.yaml", spec_yaml_endpoint)
        .with(LoggingMiddleware)  // Custom detailed logging middleware
        // Alternative: use built-in Tracing middleware instead
        // .with(Tracing)
        .data(db);

    info!("listening at: http://0.0.0.0:5000");
    poem::Server::new(TcpListener::bind("0.0.0.0:5000"))
        .run(app)
        .await
}
