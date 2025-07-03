use super::ApiTags;
use crate::auth::BearerAuthorization;
use argon2::PasswordHasher;
use poem::{Error, Result, http::StatusCode, web::Data};
use poem_openapi::payload::PlainText;
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

pub struct UsersApi;

#[derive(Object, Debug)]
pub struct UserRequest {
    pub name: String,
    pub password_hash: String,
    // Add other fields as needed
}

#[derive(Object, Debug)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub password_hash: Option<String>,
    // Add other fields as needed
}

#[derive(Object, Debug)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(ApiResponse)]
enum RegisterResponse {
    #[oai(status = 201)]
    Created(PlainText<String>),
    #[oai(status = 400)]
    PermissionDoesNotExists(PlainText<String>),
    #[oai(status = 409)]
    UserAlreadyExists(PlainText<String>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
}

#[derive(ApiResponse)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<entities::user::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<uuid::Uuid>>),
}

#[derive(Object, Debug)]
pub struct AddPermissionsRequest {
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct RemovePermissionsRequest {
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct BatchUsersRequest {
    pub uuids: Vec<uuid::Uuid>,
}

#[derive(ApiResponse)]
enum BatchUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::user::Model>>),
}

#[OpenApi(prefix_path = "/users", tag = "ApiTags::Users")]
impl UsersApi {
    #[oai(path = "/:uuid", method = "get")]
    async fn get_user(
        &self,
        db: Data<&DatabaseConnection>,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
    ) -> Result<GetUserResponse> {
        let user = entities::user::Entity::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match user {
            Some(model) => Ok(GetUserResponse::Ok(Json(model))),
            None => Ok(GetUserResponse::NotFound),
        }
    }

    #[oai(path = "/", method = "post")]
    async fn register(
        &self,
        claims: BearerAuthorization,
        db: Data<&DatabaseConnection>,
        request: Json<RegisterRequest>,
    ) -> Result<RegisterResponse> {
        if !claims.permissions.contains(&"create user".to_string()) {
            return Ok(RegisterResponse::Unauthorized(PlainText(
                "User does not have enough permissions".to_string(),
            )));
        }
        let existing = entities::user::Entity::find()
            .filter(entities::user::Column::Name.eq(request.username.clone()))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if existing.is_some() {
            return Ok(RegisterResponse::UserAlreadyExists(PlainText(
                "User already exists".to_string(),
            )));
        }
        let found_permissions: Vec<uuid::Uuid> = entities::permission::Entity::find()
            .filter(entities::permission::Column::Id.is_in(request.permissions.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?
            .into_iter()
            .map(|perm| perm.id)
            .collect();
        let missing_permissions: Vec<uuid::Uuid> = request
            .permissions
            .iter()
            .filter(|id| !found_permissions.contains(id))
            .cloned()
            .collect();
        if !missing_permissions.is_empty() {
            return Ok(RegisterResponse::PermissionDoesNotExists(PlainText(
                format!("Permissions do not exist: {:?}", missing_permissions),
            )));
        }
        let salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng,
        );
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(request.password.as_bytes(), &salt)
            .map_err(|e| {
                poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
            })?
            .to_string();
        let new_user = entities::user::ActiveModel {
            name: Set(request.username.clone()),
            password_hash: Set(password_hash),
            // Set other fields as needed
            ..Default::default()
        };
        let user = entities::user::Entity::insert(new_user)
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        for perm_id in &request.permissions {
            let user_perm = entities::user_permission::ActiveModel {
                user_id: Set(user.last_insert_id),
                permission_id: Set(*perm_id),
                ..Default::default()
            };
            entities::user_permission::Entity::insert(user_perm)
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }
        Ok(RegisterResponse::Created(PlainText(format!(
            "/users/{}",
            user.last_insert_id
        ))))
    }

    #[oai(path = "/:uuid", method = "delete")]
    async fn delete_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
    ) -> Result<PlainText<String>> {
        if !claims.permissions.contains(&"delete user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let res = entities::user::Entity::delete_by_id(uuid.0)
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        }
        Ok(PlainText(uuid.0.to_string()))
    }

    #[oai(path = "/:uuid", method = "patch")]
    async fn update_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
        req: Json<UpdateUserRequest>,
    ) -> Result<PlainText<String>> {
        if !claims.permissions.contains(&"update user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let user = entities::user::Entity::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(mut user) = user else {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        };
        if let Some(name) = &req.0.name {
            user.name = name.clone();
        }
        if let Some(password_hash) = &req.0.password_hash {
            user.password_hash = password_hash.clone();
        }
        // Update other fields as needed
        let active: entities::user::ActiveModel = user.into();
        let updated = active
            .update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(PlainText(updated.id.to_string()))
    }

    #[oai(path = "/:uuid/permissions", method = "post")]
    async fn add_permissions_to_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
        req: Json<AddPermissionsRequest>,
    ) -> Result<PlainText<String>> {
        if !claims
            .permissions
            .contains(&"assign permission".to_string())
        {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        // Check if user exists
        let user = entities::user::Entity::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if user.is_none() {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        }
        // Check if all permissions exist
        let found_permissions: Vec<uuid::Uuid> = entities::permission::Entity::find()
            .filter(entities::permission::Column::Id.is_in(req.0.permissions.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?
            .into_iter()
            .map(|perm| perm.id)
            .collect();
        let missing_permissions: Vec<uuid::Uuid> = req
            .0
            .permissions
            .iter()
            .filter(|id| !found_permissions.contains(id))
            .cloned()
            .collect();
        if !missing_permissions.is_empty() {
            return Err(Error::from_string(
                format!("Permissions do not exist: {:?}", missing_permissions),
                StatusCode::BAD_REQUEST,
            ));
        }
        // Assign permissions
        for perm_id in &req.0.permissions {
            let user_perm = entities::user_permission::ActiveModel {
                user_id: Set(uuid.0),
                permission_id: Set(*perm_id),
                ..Default::default()
            };
            entities::user_permission::Entity::insert(user_perm)
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }
        Ok(PlainText("Permissions assigned".to_string()))
    }

    #[oai(path = "/:uuid/permissions", method = "delete")]
    async fn remove_permissions_from_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
        req: Json<RemovePermissionsRequest>,
    ) -> Result<PlainText<String>> {
        if !claims.permissions.contains(&"assign permission".to_string()) {
            return Err(Error::from_string("Not enough permissions", StatusCode::UNAUTHORIZED));
        }
        // Check if user exists
        let user = entities::user::Entity::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if user.is_none() {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        }
        // Remove permissions
        for perm_id in &req.0.permissions {
            let res = entities::user_permission::Entity::delete_many()
                .filter(entities::user_permission::Column::UserId.eq(uuid.0))
                .filter(entities::user_permission::Column::PermissionId.eq(*perm_id))
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
            if res.rows_affected == 0 {
                // Optionally, you can return an error if a permission was not found for this user
            }
        }
        Ok(PlainText("Permissions removed".to_string()))
    }

    #[oai(path = "/", method = "get")]
    async fn get_users(
        &self,
        claims: BearerAuthorization,
        db: Data<&DatabaseConnection>,
    ) -> Result<GetUsersResponse> {
        if !claims.permissions.contains(&"get user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let users = entities::user::Entity::find()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let uuids = users.into_iter().map(|u| u.id).collect();
        Ok(GetUsersResponse::Ok(Json(uuids)))
    }

    #[oai(path = "/batch", method = "post")]
    async fn batch_get_users(
        &self,
        claims: BearerAuthorization,
        db: Data<&DatabaseConnection>,
        req: Json<BatchUsersRequest>,
    ) -> Result<BatchUsersResponse> {
        if !claims.permissions.contains(&"get user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let users = entities::user::Entity::find()
            .filter(entities::user::Column::Id.is_in(req.0.uuids.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchUsersResponse::Ok(Json(users)))
    }
}
