use super::ApiTags;
use crate::auth::BearerAuthorization;
use argon2::{PasswordHasher, PasswordVerifier};
use poem::{Result, http::StatusCode, web::Data};
use poem_openapi::payload::PlainText;
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

pub struct MeApi;

#[derive(Object, Debug)]
pub struct UpdateMyPasswordRequest {
    #[oai(validator(min_length = 8))]
    pub old_password: String,
    #[oai(validator(min_length = 8))]
    pub new_password: String,
}

#[derive(Object, Debug)]
pub struct UpdateUsernameRequest {
    pub new_username: String,
}

#[derive(Object, Debug)]
pub struct MeInfo {
    pub id: uuid::Uuid,
    pub username: String,
    pub permissions: Vec<String>,
}

#[derive(poem_openapi::Enum, Debug, Clone)]
pub enum AllowedUserStatus {
    #[oai(rename = "active")]
    Active,
    #[oai(rename = "inactive")]
    Inactive,
}

impl From<AllowedUserStatus> for entities::sea_orm_active_enums::UserStatusEnum {
    fn from(status: AllowedUserStatus) -> Self {
        match status {
            AllowedUserStatus::Active => entities::sea_orm_active_enums::UserStatusEnum::Active,
            AllowedUserStatus::Inactive => entities::sea_orm_active_enums::UserStatusEnum::Inactive,
        }
    }
}

#[derive(Object, Debug)]
pub struct UpdateStatusRequest {
    pub status: AllowedUserStatus,
}

#[derive(ApiResponse)]
enum MeGetResponse {
    #[oai(status = 200)]
    Ok(Json<MeInfo>),
    #[oai(status = 404)]
    NotFound,
    #[oai(status = 401)]
    Unauthorized,
}

#[derive(ApiResponse)]
enum MeUpdateResponse {
    #[oai(status = 200)]
    Ok(PlainText<String>),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
    #[oai(status = 404)]
    NotFound(PlainText<String>),
}

#[OpenApi(prefix_path = "/me", tag = "ApiTags::Me")]
impl MeApi {
    /// Get current user's info
    #[oai(path = "/", method = "get")]
    async fn get_me(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
    ) -> Result<MeGetResponse> {
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return Ok(MeGetResponse::Unauthorized),
        };
        let user = entities::users::Entity::find_by_id(user_id)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(user) = user else {
            return Ok(MeGetResponse::NotFound);
        };
        // Fetch permissions for the user
        let user_permissions = entities::user_permissions::Entity::find()
            .filter(entities::user_permissions::Column::UserId.eq(user.id))
            .find_also_related(entities::permissions::Entity)
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let permissions = user_permissions
            .into_iter()
            .filter_map(|(_, perm)| perm.and_then(|p| p.permission_name))
            .collect::<Vec<String>>();
        let info = MeInfo {
            id: user.id,
            username: user.name,
            permissions,
        };
        Ok(MeGetResponse::Ok(Json(info)))
    }

    /// Update current user's password
    #[oai(path = "/password", method = "patch")]
    async fn update_password(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<UpdateMyPasswordRequest>,
    ) -> Result<MeUpdateResponse> {
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return Ok(MeUpdateResponse::Unauthorized(PlainText("Invalid user id".to_string()))),
        };
        let user = entities::users::Entity::find_by_id(user_id)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(user) = user else {
            return Ok(MeUpdateResponse::NotFound(PlainText("User not found".to_string())));
        };
        // Verify old password
        let parsed_hash = argon2::PasswordHash::new(&user.password_hash)
            .map_err(|_| poem::Error::from_string("Invalid password hash", StatusCode::INTERNAL_SERVER_ERROR))?;
        if argon2::Argon2::default()
            .verify_password(req.old_password.as_bytes(), &parsed_hash)
            .is_err()
        {
            return Ok(MeUpdateResponse::Unauthorized(PlainText("Old password incorrect".to_string())));
        }
        // Hash new password
        let salt = argon2::password_hash::SaltString::generate(&mut argon2::password_hash::rand_core::OsRng);
        let new_hash = argon2::Argon2::default()
            .hash_password(req.new_password.as_bytes(), &salt)
            .map_err(|e| poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR))?
            .to_string();
        let mut active: entities::users::ActiveModel = user.into();
        active.password_hash = Set(new_hash);
        active.last_edit_time = Set(chrono::Utc::now().naive_utc());
        active.update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(MeUpdateResponse::Ok(PlainText("Password updated".to_string())))
    }

    /// Update current user's username
    #[oai(path = "/username", method = "patch")]
    async fn update_username(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<UpdateUsernameRequest>,
    ) -> Result<MeUpdateResponse> {
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return Ok(MeUpdateResponse::Unauthorized(PlainText("Invalid user id".to_string()))),
        };
        let user = entities::users::Entity::find_by_id(user_id)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(user) = user else {
            return Ok(MeUpdateResponse::NotFound(PlainText("User not found".to_string())));
        };
        // Check if new username already exists
        let exists = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(req.new_username.clone()))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if exists.is_some() {
            return Ok(MeUpdateResponse::BadRequest(PlainText("Username already taken".to_string())));
        }
        let mut active: entities::users::ActiveModel = user.into();
        active.name = Set(req.new_username.clone());
        active.last_edit_time = Set(chrono::Utc::now().naive_utc());
        active.update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(MeUpdateResponse::Ok(PlainText("Username updated".to_string())))
    }

    /// Update current user's status
    #[oai(path = "/status", method = "patch")]
    async fn update_status(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<UpdateStatusRequest>,
    ) -> Result<MeUpdateResponse> {
        let user_id = match uuid::Uuid::parse_str(&claims.sub) {
            Ok(id) => id,
            Err(_) => return Ok(MeUpdateResponse::Unauthorized(PlainText("Invalid user id".to_string()))),
        };

        let user = entities::users::Entity::find_by_id(user_id)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        let Some(user) = user else {
            return Ok(MeUpdateResponse::NotFound(PlainText("User not found".to_string())));
        };

        let mut active: entities::users::ActiveModel = user.into();
        active.status = Set(req.status.clone().into());
        active.last_edit_time = Set(chrono::Utc::now().naive_utc());
        
        active.update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        Ok(MeUpdateResponse::Ok(PlainText(format!("Status updated to {:?}", req.status))))
    }
}
