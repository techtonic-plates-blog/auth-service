use crate::auth::{Permission, MinimalClaims, SessionData};
use crate::config::CONFIG;
use crate::routes::ApiTags;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc};
use entities::permissions::Entity as Permissions;
use entities::sea_orm_active_enums::UserStatusEnum;
use entities::user_permissions::Entity as UserPermissions;
use entities::user_role::Entity as UserRole;
use entities::role_permissions::Entity as RolePermissions;
use entities::roles::Entity as RolesEntity;
use entities::users::Entity as User;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use poem::http::StatusCode;
use poem::{Result, error::InternalServerError, web::Data};
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};
use std::collections::HashSet;
use redis::Client as RedisClient;

pub struct AuthApi;

// Helper function to create tokens with Redis session storage
async fn create_tokens_with_session(
    redis: &RedisClient,
    user_id: uuid::Uuid,
    permissions: Vec<Permission>,
) -> Result<Tokens> {
    let mut conn = redis.get_connection().map_err(InternalServerError)?;
    
    // Create session ID
    let session_id = uuid::Uuid::new_v4().to_string();
    
    // Create session data
    let session_data = SessionData {
        user_id: user_id.to_string(),
        company: "techtonic-plate".to_string(),
        permissions,
        created_at: Utc::now().timestamp(),
        last_accessed: Utc::now().timestamp(),
    };
    
    // Store session in Redis with 30-day expiration
    let session_key = format!("session:{}", session_id);
    let session_json = serde_json::to_string(&session_data).map_err(InternalServerError)?;
    let _: () = redis::cmd("SET")
        .arg(&session_key)
        .arg(&session_json)
        .arg("EX")
        .arg(30 * 24 * 60 * 60) // 30 days
        .query(&mut conn)
        .map_err(InternalServerError)?;
    
    // Create JWT and refresher tokens with minimal claims
    let jwt_exp = Utc::now() + Duration::minutes(15);
    let refresher_exp = Utc::now() + Duration::days(30);
    
    let jwt_claims = MinimalClaims {
        sub: user_id.to_string(),
        session_id: session_id.clone(),
        exp: jwt_exp.timestamp() as usize,
    };
    
    let refresher_claims = MinimalClaims {
        sub: user_id.to_string(),
        session_id,
        exp: refresher_exp.timestamp() as usize,
    };
    
    let jwt = encode(
        &Header::new(Algorithm::RS256),
        &jwt_claims,
        &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes())
            .map_err(InternalServerError)?,
    )
    .map_err(InternalServerError)?;
    
    let refresher = encode(
        &Header::new(Algorithm::RS256),
        &refresher_claims,
        &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes())
            .map_err(InternalServerError)?,
    )
    .map_err(InternalServerError)?;
    
    Ok(Tokens {
        jwt: Token {
            token: jwt,
            exp: jwt_claims.exp,
        },
        refresher: Token {
            token: refresher,
            exp: refresher_claims.exp,
        },
    })
}

#[derive(Object)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Object)]
struct Token {
    token: String,
    exp: usize,
}
#[derive(Object)]
struct Tokens {
    jwt: Token,
    refresher: Token,
}

#[derive(ApiResponse)]
enum LoginResponse {
    #[oai(status = 200)]
    Ok(Json<Tokens>),
    #[oai(status = 401)]
    Unauthorized,
    #[oai(status = 403)]
    Forbidden,
}
#[derive(Object)]
struct RefreshRequest {
    refresher: String,
}
#[derive(ApiResponse)]
enum RefreshResponse {
    #[oai(status = 200)]
    Ok(Json<Tokens>),
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(Object)]
struct RegisterRequest {
    username: String,
    password: String,
    permissions: Vec<uuid::Uuid>,
}

#[derive(Object)]
struct ValidateTokenRequest {
    token: String,
}

#[derive(Object)]
struct TokenValidationResult {
    user_id: String,
    company: String,
    permissions: Vec<String>,
    expires_at: usize,
}

#[derive(ApiResponse)]
enum ValidateTokenResponse {
    #[oai(status = 200)]
    Valid(Json<TokenValidationResult>),
    #[oai(status = 401)]
    Invalid,
}

#[OpenApi(prefix_path = "/auth", tag = "ApiTags::Auth")]
impl AuthApi {
    #[oai(method = "post", path = "/login")]
    async fn login(
        &self,
        db: Data<&DatabaseConnection>,
        redis: Data<&RedisClient>,
        request: Json<LoginRequest>,
    ) -> Result<LoginResponse> {
        let argon2 = Argon2::default();

        let users = User::find()
            .filter(entities::users::Column::Name.eq(request.username.clone()))
            .one(*db)
            .await
            .map_err(InternalServerError)?;

        let Some(users) = users else {
            return Ok(LoginResponse::Unauthorized);
        };

        if users.status == UserStatusEnum::Banned {
            return Ok(LoginResponse::Forbidden);
        }

        let password_hash = PasswordHash::new(&users.password_hash).map_err(|e| {
            poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
        })?;
        let verify_result = argon2.verify_password(request.password.as_bytes(), &password_hash);
        if verify_result.is_err() {
            return Ok(LoginResponse::Unauthorized);
        }

        // Update last login time
        let mut user_model: entities::users::ActiveModel = users.clone().into();
        user_model.last_login_time = Set(Utc::now().naive_utc());
        user_model.update(*db).await.map_err(InternalServerError)?;

        let permissions = UserPermissions::find()
            .filter(entities::user_permissions::Column::UserId.eq(users.id.clone()))
            .find_also_related(Permissions)
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        let mut permissions = permissions
            .into_iter()
            .filter_map(|x| x.1)
            .filter_map(|x| {
                x.permission_name.and_then(|name| Permission::from_string(&name))
            })
            .collect::<Vec<Permission>>();

        // Also collect permissions granted via roles
        let user_roles = UserRole::find()
            .filter(entities::user_role::Column::UserId.eq(users.id.clone()))
            .find_also_related(RolesEntity)
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        let role_ids: Vec<uuid::Uuid> = user_roles
            .into_iter()
            .filter_map(|(_, role)| role.map(|r| r.id))
            .collect();

        if !role_ids.is_empty() {
            let role_perms = RolePermissions::find()
                .filter(entities::role_permissions::Column::RoleId.is_in(role_ids.clone()))
                .find_also_related(Permissions)
                .all(*db)
                .await
                .map_err(InternalServerError)?;

            let role_permissions_parsed = role_perms
                .into_iter()
                .filter_map(|x| x.1)
                .filter_map(|p| p.permission_name.and_then(|name| Permission::from_string(&name)))
                .collect::<Vec<Permission>>();

            // Merge and deduplicate permissions by string form
            let mut seen = HashSet::new();
            let mut merged = Vec::new();
            for perm in permissions.iter().chain(role_permissions_parsed.iter()) {
                let key = perm.to_string();
                if seen.insert(key.clone()) {
                    merged.push(perm.clone());
                }
            }
            permissions = merged;
        }

        let tokens = create_tokens_with_session(*redis, users.id, permissions).await?;
        Ok(LoginResponse::Ok(Json(tokens)))
    }
    #[oai(method = "post", path = "/refresh")]
    async fn refresh(
        &self,
        db: Data<&DatabaseConnection>,
        redis: Data<&RedisClient>,
        request: Json<RefreshRequest>,
    ) -> Result<RefreshResponse> {
        // Decode the refresher token
        let decoding_key =
            &jsonwebtoken::DecodingKey::from_rsa_pem(CONFIG.jwt_public_key.as_bytes())
                .map_err(InternalServerError)?;
        let validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        let token_data =
            match jsonwebtoken::decode::<MinimalClaims>(&request.refresher, decoding_key, &validation) {
                Ok(data) => data,
                Err(_) => return Ok(RefreshResponse::Unauthorized),
            };
        let claims = token_data.claims;

        // Get session from Redis
        let mut conn = (*redis).get_connection().map_err(InternalServerError)?;
        let session_key = format!("session:{}", claims.session_id);
        let _session_json: String = match redis::cmd("GET")
            .arg(&session_key)
            .query(&mut conn) {
            Ok(json) => json,
            Err(_) => return Ok(RefreshResponse::Unauthorized),
        };
        
        // Verify session exists (we don't need to parse it, just check it exists)
        match serde_json::from_str::<SessionData>(&_session_json) {
            Ok(_) => {},
            Err(_) => return Ok(RefreshResponse::Unauthorized),
        };

        // Parse user ID as Uuid
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(uuid) => uuid,
            Err(_) => return Ok(RefreshResponse::Unauthorized),
        };
        
        // Verify user still exists and is active
        let users = User::find_by_id(user_id)
            .one(*db)
            .await
            .map_err(InternalServerError)?;
        let Some(users) = users else {
            return Ok(RefreshResponse::Unauthorized);
        };

        if users.status == UserStatusEnum::Banned {
            return Ok(RefreshResponse::Unauthorized);
        }

        // Get fresh permissions from database (in case they changed)
        let permissions = UserPermissions::find()
            .filter(entities::user_permissions::Column::UserId.eq(users.id.clone()))
            .find_also_related(Permissions)
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        let mut permissions = permissions
            .into_iter()
            .filter_map(|x| x.1)
            .filter_map(|x| {
                x.permission_name.and_then(|name| Permission::from_string(&name))
            })
            .collect::<Vec<Permission>>();

        // Also collect permissions granted via roles
        let user_roles = UserRole::find()
            .filter(entities::user_role::Column::UserId.eq(users.id.clone()))
            .find_also_related(RolesEntity)
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        let role_ids: Vec<uuid::Uuid> = user_roles
            .into_iter()
            .filter_map(|(_, role)| role.map(|r| r.id))
            .collect();

        if !role_ids.is_empty() {
            let role_perms = RolePermissions::find()
                .filter(entities::role_permissions::Column::RoleId.is_in(role_ids.clone()))
                .find_also_related(Permissions)
                .all(*db)
                .await
                .map_err(InternalServerError)?;

            let role_permissions_parsed = role_perms
                .into_iter()
                .filter_map(|x| x.1)
                .filter_map(|p| p.permission_name.and_then(|name| Permission::from_string(&name)))
                .collect::<Vec<Permission>>();

            // Merge and deduplicate permissions by string form
            let mut seen = HashSet::new();
            let mut merged = Vec::new();
            for perm in permissions.iter().chain(role_permissions_parsed.iter()) {
                let key = perm.to_string();
                if seen.insert(key.clone()) {
                    merged.push(perm.clone());
                }
            }
            permissions = merged;
        }

        let tokens = create_tokens_with_session(*redis, users.id, permissions).await?;
        Ok(RefreshResponse::Ok(Json(tokens)))
    }

    /// Validate a JWT token and return session information for other services
    #[oai(method = "post", path = "/validate")]
    async fn validate_token(
        &self,
        redis: Data<&RedisClient>,
        request: Json<ValidateTokenRequest>,
    ) -> Result<ValidateTokenResponse> {
        // Decode the token
        let decoding_key =
            &jsonwebtoken::DecodingKey::from_rsa_pem(CONFIG.jwt_public_key.as_bytes())
                .map_err(InternalServerError)?;
        let validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        let token_data =
            match jsonwebtoken::decode::<MinimalClaims>(&request.token, decoding_key, &validation) {
                Ok(data) => data,
                Err(_) => return Ok(ValidateTokenResponse::Invalid),
            };
        let claims = token_data.claims;

        // Get session from Redis
        let mut conn = (*redis).get_connection().map_err(InternalServerError)?;
        let session_key = format!("session:{}", claims.session_id);
        let session_json: String = match redis::cmd("GET")
            .arg(&session_key)
            .query(&mut conn) {
            Ok(json) => json,
            Err(_) => return Ok(ValidateTokenResponse::Invalid),
        };
        
        let session_data: SessionData = match serde_json::from_str(&session_json) {
            Ok(data) => data,
            Err(_) => return Ok(ValidateTokenResponse::Invalid),
        };

        // Update last accessed time
        let mut updated_session = session_data.clone();
        updated_session.last_accessed = Utc::now().timestamp();
        let updated_json = serde_json::to_string(&updated_session).map_err(InternalServerError)?;
        let _: () = redis::cmd("SET")
            .arg(&session_key)
            .arg(&updated_json)
            .arg("EX")
            .arg(30 * 24 * 60 * 60) // 30 days expiration
            .query(&mut conn)
            .map_err(InternalServerError)?;

        Ok(ValidateTokenResponse::Valid(Json(TokenValidationResult {
            user_id: session_data.user_id,
            company: session_data.company,
            permissions: session_data.permissions.into_iter().map(|p| p.to_string()).collect(),
            expires_at: claims.exp,
        })))
    }
}
