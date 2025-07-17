use super::ApiTags;
use crate::auth::BearerAuthorization;
use argon2::PasswordHasher;
use poem::{Error, Result, http::StatusCode, web::Data};
use poem_openapi::payload::PlainText;
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, Set};

pub struct UsersApi;

#[derive(Object, Debug)]
pub struct UserWithPermissions {
    pub id: uuid::Uuid,
    pub name: String,
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
}

#[derive(Object, Debug)]
pub struct UpdatePasswordRequest {
    pub new_password: String,
}

#[derive(Object, Debug)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct ComprehensiveUpdateUserRequest {
    pub name: Option<String>,
    pub password: Option<String>,
    pub permissions: Option<Vec<uuid::Uuid>>,
}

#[derive(ApiResponse)]
enum RegisterResponse {
    #[oai(status = 201)]
    Created(PlainText<String>),
    #[oai(status = 400)]
    PermissionsDoesNotExists(PlainText<String>),
    #[oai(status = 409)]
    UserAlreadyExists(PlainText<String>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
}

#[derive(ApiResponse)]
enum GetUserResponse {
    #[oai(status = 200)]
    Ok(Json<UserWithPermissions>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(ApiResponse)]
enum GetUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<String>>),
}

#[derive(Object, Debug)]
pub struct AddpermissionssRequest {
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct RemovepermissionssRequest {
    pub permissions: Vec<uuid::Uuid>,
}

#[derive(Object, Debug)]
pub struct BatchUsersRequest {
    pub usernames: Vec<String>,
}

#[derive(ApiResponse)]
enum BatchUsersResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<UserWithPermissions>>),
}

#[derive(ApiResponse)]
enum UpdatePasswordResponse {
    #[oai(status = 200)]
    Ok(PlainText<String>),
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
}

#[derive(ApiResponse)]
enum ComprehensiveUpdateUserResponse {
    #[oai(status = 200)]
    Ok(PlainText<String>),
    #[oai(status = 404)]
    NotFound(PlainText<String>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
    #[oai(status = 400)]
    PermissionsDoNotExist(PlainText<String>),
}

#[OpenApi(prefix_path = "/users", tag = "ApiTags::Users")]
impl UsersApi {
    #[oai(path = "/:username", method = "get")]
    async fn get_user(
        &self,
        claims: BearerAuthorization,
        db: Data<&DatabaseConnection>,
        username: poem_openapi::param::Path<String>,
    ) -> Result<GetUserResponse> {
        if !claims.permissions.contains(&"get user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let user = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(username.0))
            .find_with_related(entities::permissions::Entity)
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let user = user.into_iter().next();

        match user {
            Some(user) => {
                let (user, permissions) = user;
            
                let user_with_permissions = UserWithPermissions {
                    id: user.id.clone(),
                    name: user.name.clone(),
                    permissions: permissions.clone().into_iter().map(|p| p.id).collect(),
                };

                Ok(GetUserResponse::Ok(Json(user_with_permissions)))
            }
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
        let existing = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(request.username.clone()))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if existing.is_some() {
            return Ok(RegisterResponse::UserAlreadyExists(PlainText(
                "User already exists".to_string(),
            )));
        }
        let found_permissionss: Vec<uuid::Uuid> = entities::permissions::Entity::find()
            .filter(entities::permissions::Column::Id.is_in(request.permissions.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?
            .into_iter()
            .map(|perm| perm.id)
            .collect();
        let missing_permissionss: Vec<uuid::Uuid> = request
            .permissions
            .iter()
            .filter(|id| !found_permissionss.contains(id))
            .cloned()
            .collect();
        if !missing_permissionss.is_empty() {
            return Ok(RegisterResponse::PermissionsDoesNotExists(PlainText(
                format!("permissions do not exist: {:?}", missing_permissionss),
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
        let new_user = entities::users::ActiveModel {
            name: Set(request.username.clone()),
            password_hash: Set(password_hash),
            id: Set(uuid::Uuid::new_v4()),
        };
        let users = entities::users::Entity::insert(new_user)
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        for perm_id in &request.permissions {
            let user_perm = entities::user_permissions::ActiveModel {
                user_id: Set(users.last_insert_id),
                permission_id: Set(*perm_id),
            };
            entities::user_permissions::Entity::insert(user_perm)
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }
        Ok(RegisterResponse::Created(PlainText(format!(
            "/users/{}",
            users.last_insert_id
        ))))
    }

    #[oai(path = "/:username", method = "delete")]
    async fn delete_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
    ) -> Result<PlainText<String>> {
        if !claims.permissions.contains(&"delete user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let res = entities::users::Entity::delete_many()
            .filter(entities::users::Column::Name.eq(&username.0))
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        }
        Ok(PlainText(username.0.to_string()))
    }

    #[oai(path = "/:username", method = "patch")]
    async fn update_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
        req: Json<UpdateUserRequest>,
    ) -> Result<PlainText<String>> {
        if !claims.permissions.contains(&"update user".to_string()) {
            return Err(Error::from_string(
                "Not enough permissions",
                StatusCode::UNAUTHORIZED,
            ));
        }
        let users = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(&username.0))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(mut users) = users else {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        };
        if let Some(name) = &req.0.name {
            users.name = name.clone();
        }
        let active: entities::users::ActiveModel = users.into();
        let updated = active
            .update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(PlainText(updated.id.to_string()))
    }

    #[oai(path = "/:username/password", method = "patch")]
    async fn update_password(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
        req: Json<UpdatePasswordRequest>,
    ) -> Result<UpdatePasswordResponse> {
        if !claims.permissions.contains(&"update user".to_string()) {
            return Ok(UpdatePasswordResponse::Unauthorized(PlainText(
                "Not enough permissions".to_string(),
            )));
        }
        let users = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(&username.0))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(mut users) = users else {
            return Ok(UpdatePasswordResponse::NotFound(PlainText(
                "User not found".to_string(),
            )));
        };
        let salt = argon2::password_hash::SaltString::generate(
            &mut argon2::password_hash::rand_core::OsRng,
        );
        let argon2 = argon2::Argon2::default();
        let password_hash = argon2
            .hash_password(req.0.new_password.as_bytes(), &salt)
            .map_err(|e| {
                poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
            })?
            .to_string();
        users.password_hash = password_hash;
        let active: entities::users::ActiveModel = users.into();
        active
            .update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(UpdatePasswordResponse::Ok(PlainText(
            "Password updated successfully".to_string(),
        )))
    }

    #[oai(path = "/:username", method = "patch")]
    async fn comprehensive_update_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
        req: Json<ComprehensiveUpdateUserRequest>,
    ) -> Result<ComprehensiveUpdateUserResponse> {
        if !claims.permissions.contains(&"update user".to_string()) {
            return Ok(ComprehensiveUpdateUserResponse::Unauthorized(PlainText(
                "Not enough permissions".to_string(),
            )));
        }

        // Find the user
        let user = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(&username.0))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(mut user) = user else {
            return Ok(ComprehensiveUpdateUserResponse::NotFound(PlainText(
                "User not found".to_string(),
            )));
        };

        // Update name if provided
        if let Some(new_name) = &req.0.name {
            user.name = new_name.clone();
        }

        // Update password if provided
        if let Some(new_password) = &req.0.password {
            let salt = argon2::password_hash::SaltString::generate(
                &mut argon2::password_hash::rand_core::OsRng,
            );
            let argon2 = argon2::Argon2::default();
            let password_hash = argon2
                .hash_password(new_password.as_bytes(), &salt)
                .map_err(|e| {
                    poem::Error::from_string(e.to_string(), StatusCode::INTERNAL_SERVER_ERROR)
                })?
                .to_string();
            user.password_hash = password_hash;
        }

        // Update the user in the database
        let active: entities::users::ActiveModel = user.clone().into();
        let updated_user = active
            .update(*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        // Update permissions if provided
        if let Some(new_permissions) = &req.0.permissions {
            // Check if all permissions exist
            let found_permissions: Vec<uuid::Uuid> = entities::permissions::Entity::find()
                .filter(entities::permissions::Column::Id.is_in(new_permissions.clone()))
                .all(*db)
                .await
                .map_err(poem::error::InternalServerError)?
                .into_iter()
                .map(|perm| perm.id)
                .collect();
            
            let missing_permissions: Vec<uuid::Uuid> = new_permissions
                .iter()
                .filter(|id| !found_permissions.contains(id))
                .cloned()
                .collect();
            
            if !missing_permissions.is_empty() {
                return Ok(ComprehensiveUpdateUserResponse::PermissionsDoNotExist(PlainText(
                    format!("Permissions do not exist: {:?}", missing_permissions),
                )));
            }

            // Remove all existing permissions for this user
            entities::user_permissions::Entity::delete_many()
                .filter(entities::user_permissions::Column::UserId.eq(user.id))
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;

            // Add new permissions
            for perm_id in new_permissions {
                let user_perm = entities::user_permissions::ActiveModel {
                    user_id: Set(user.id),
                    permission_id: Set(*perm_id),
                    ..Default::default()
                };
                entities::user_permissions::Entity::insert(user_perm)
                    .exec(*db)
                    .await
                    .map_err(poem::error::InternalServerError)?;
            }
        }

        Ok(ComprehensiveUpdateUserResponse::Ok(PlainText(format!(
            "User {} updated successfully", updated_user.name
        ))))
    }

    #[oai(path = "/:username/permissions", method = "post")]
    async fn add_permissionss_to_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
        req: Json<AddpermissionssRequest>,
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
        // Check if users exists
        let user = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(&username.0))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(user) = user else {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        };
        // Check if all permissions exist
        let found_permissionss: Vec<uuid::Uuid> = entities::permissions::Entity::find()
            .filter(entities::permissions::Column::Id.is_in(req.0.permissions.clone()))
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
            .filter(|id| !found_permissionss.contains(id))
            .cloned()
            .collect();
        if !missing_permissions.is_empty() {
            return Err(Error::from_string(
                format!("permissions do not exist: {:?}", missing_permissions),
                StatusCode::BAD_REQUEST,
            ));
        }
        // Assign permissions
        for perm_id in &req.0.permissions {
            let user_perm = entities::user_permissions::ActiveModel {
                user_id: Set(user.id),
                permission_id: Set(*perm_id),
                ..Default::default()
            };
            entities::user_permissions::Entity::insert(user_perm)
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }
        Ok(PlainText("permissions assigned".to_string()))
    }

    #[oai(path = "/:username/permissions", method = "delete")]
    async fn remove_permissionss_from_user(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        username: poem_openapi::param::Path<String>,
        req: Json<RemovepermissionssRequest>,
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
        // Check if users exists
        let user = entities::users::Entity::find()
            .filter(entities::users::Column::Name.eq(&username.0))
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let Some(user) = user else {
            return Err(Error::from_string("User not found", StatusCode::NOT_FOUND));
        };
        // Remove permissions
        for perm_id in &req.0.permissions {
            let res = entities::user_permissions::Entity::delete_many()
                .filter(entities::user_permissions::Column::UserId.eq(user.id))
                .filter(entities::user_permissions::Column::PermissionId.eq(*perm_id))
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
            if res.rows_affected == 0 {
                // Optionally, you can return an error if a permissions was not found for this users
            }
        }
        Ok(PlainText("permissions removed".to_string()))
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
        let users = entities::users::Entity::find()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        let usernames = users.into_iter().map(|u| u.name).collect();
        Ok(GetUsersResponse::Ok(Json(usernames)))
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
        let users_with_permissions = entities::users::Entity::find()
            .filter(entities::users::Column::Name.is_in(req.0.usernames.clone()))
            .find_with_related(entities::permissions::Entity)
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;

        let result: Vec<UserWithPermissions> = users_with_permissions
            .into_iter()
            .map(|(user, permissions)| UserWithPermissions {
                id: user.id,
                name: user.name,
                permissions: permissions.into_iter().map(|p| p.id).collect(),
            })
            .collect();

        Ok(BatchUsersResponse::Ok(Json(result)))
    }
}
