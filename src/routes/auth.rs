use crate::auth::Claims;
use crate::config::CONFIG;
use crate::routes::ApiTags;
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use chrono::{Duration, Utc};
use entities::permissions::Entity as Permissions;
use entities::users::Entity as User;
use entities::user_permissions::Entity as UserPermissions;
use entities::sea_orm_active_enums::UserStatusEnum;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use poem::http::StatusCode;
use poem::{Result, error::InternalServerError, web::Data};
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

pub struct AuthApi;

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
    permissions: Vec<uuid::Uuid>
}

#[OpenApi(prefix_path = "/auth", tag = "ApiTags::Auth")]
impl AuthApi {
    #[oai(method = "post", path = "/login")]
    async fn login(
        &self,
        db: Data<&DatabaseConnection>,
        request: Json<LoginRequest>,
    ) -> Result<LoginResponse> {
        //let salt = SaltString::generate(&mut OsRng);
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
            return Ok(LoginResponse::Unauthorized);
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
        let permissions = permissions
            .into_iter()
            .filter_map(|x| x.1)
            .map(|x| x.permission_name)
            .collect::<Vec<String>>();

        let jwt_exp = Utc::now() + Duration::minutes(15);
        let refresher_exp = Utc::now() + Duration::days(30);

        let jwt_claims = Claims {
            sub: users.id.to_string(),
            company: "techtonic-plate".to_string(),
            exp: jwt_exp.timestamp() as usize,
            permissions: permissions.clone(),
        };

        let refresher_claims = Claims {
            sub: users.id.to_string(),
            company: "techtonic-plate".to_string(),
            exp: refresher_exp.timestamp() as usize,
            permissions: permissions,
        };

        let jwt = encode(
            &Header::new(Algorithm::RS256),
            &jwt_claims,
            &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes()).map_err(InternalServerError)?,
        )
        .map_err(InternalServerError)?;
        let refresher = encode(
            &Header::new(Algorithm::RS256),
            &refresher_claims,
            &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes()).map_err(InternalServerError)?,
        )
        .map_err(InternalServerError)?;

        Ok(LoginResponse::Ok(Json(Tokens {
            jwt: Token {
                token: jwt,
                exp: jwt_claims.exp,
            },
            refresher: Token {
                token: refresher,
                exp: refresher_claims.exp,
            },
        })))
    }
    #[oai(method = "post", path = "/refresh")]
    async fn refresh(
        &self,
        db: Data<&DatabaseConnection>,
        request: Json<RefreshRequest>,
    ) -> Result<RefreshResponse> {
        // Decode the refresher token
        let decoding_key =
            &jsonwebtoken::DecodingKey::from_rsa_pem(CONFIG.jwt_public_key.as_bytes()).map_err(InternalServerError)?;
        let validation = jsonwebtoken::Validation::new(Algorithm::RS256);
        let token_data =
            match jsonwebtoken::decode::<Claims>(&request.refresher, decoding_key, &validation) {
                Ok(data) => data,
                Err(_) => return Ok(RefreshResponse::Unauthorized),
            };
        let claims = token_data.claims;

        // Parse users id as Uuid
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(uuid) => uuid,
            Err(_) => return Ok(RefreshResponse::Unauthorized),
        };
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

        // Get permissions
        let permissions = UserPermissions::find()
            .filter(entities::user_permissions::Column::UserId.eq(users.id.clone()))
            .find_also_related(Permissions)
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        let permissions = permissions
            .into_iter()
            .filter_map(|x| x.1)
            .map(|x| x.permission_name)
            .collect::<Vec<String>>();

        let jwt_exp = Utc::now() + Duration::minutes(15);
        let refresher_exp = Utc::now() + Duration::days(30);

        let jwt_claims = Claims {
            sub: users.id.to_string(),
            company: "techtonic-plate".to_string(),
            exp: jwt_exp.timestamp() as usize,
            permissions: permissions.clone(),
        };
        let refresher_claims = Claims {
            sub: users.id.to_string(),
            company: "techtonic-plate".to_string(),
            exp: refresher_exp.timestamp() as usize,
            permissions,
        };

        let jwt = encode(
            &Header::new(Algorithm::RS256),
            &jwt_claims,
            &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes()).map_err(InternalServerError)?,
        )
        .map_err(InternalServerError)?;
        let refresher = encode(
            &Header::new(Algorithm::RS256),
            &refresher_claims,
            &EncodingKey::from_rsa_pem(CONFIG.jwt_secret_key.as_bytes()).map_err(InternalServerError)?,
        )
        .map_err(InternalServerError)?;

        Ok(RefreshResponse::Ok(Json(Tokens {
            jwt: Token {
                token: jwt,
                exp: jwt_claims.exp,
            },
            refresher: Token {
                token: refresher,
                exp: refresher_claims.exp,
            },
        })))
    }

 
}
