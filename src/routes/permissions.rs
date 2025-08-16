use poem::{http::StatusCode, web::Data, Error};
use poem_openapi::{payload::Json, ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, QueryFilter, ColumnTrait};
use entities::permissions::Entity as Permissions;
use entities::permission_action::Entity as PermissionActions;
use entities::permission_resource::Entity as PermissionResources;
use entities::permission_scope::Entity as PermissionScopes;
use entities::roles::Entity as RolesEntity;
use crate::auth::BearerAuthorization;

use super::ApiTags;
use poem::Result;
use sea_orm::{EntityTrait, QuerySelect};
use poem_openapi::payload::PlainText;
use sea_orm::{ActiveModelTrait, Set};

pub struct PermissionsApi;

#[derive(ApiResponse)]
enum GetPermissionResponse {
    #[oai(status = 200)]
    Ok(Json<entities::permissions::Model>),
    #[oai(status = 404)]
    NotFound
}

#[derive(poem_openapi::Object, Debug)]
pub struct AddPermissionRequest {
    pub action_id: String,
    pub resource_id: String,
    pub scope_id: String,
    pub permission_name: Option<String>,
}

#[derive(poem_openapi::Object, Debug)]
pub struct AddActionRequest {
    pub action: String,
}

#[derive(poem_openapi::Object, Debug)]
pub struct AddResourceRequest {
    pub resource: String,
}

#[derive(poem_openapi::Object, Debug)]
pub struct AddScopeRequest {
    pub scope: String,
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchPermissionsRequest {
    pub uuids: Vec<uuid::Uuid>,
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchActionsRequest {
    pub actions: Vec<String>,
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchResourcesRequest {
    pub resources: Vec<String>,
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchScopesRequest {
    pub scopes: Vec<String>,
}

#[derive(ApiResponse)]
enum BatchPermissionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::permissions::Model>>),
}

#[derive(ApiResponse)]
enum GetActionResponse {
    #[oai(status = 200)]
    Ok(Json<entities::permission_action::Model>),
    #[oai(status = 404)]
    NotFound
}

#[derive(ApiResponse)]
enum GetResourceResponse {
    #[oai(status = 200)]
    Ok(Json<entities::permission_resource::Model>),
    #[oai(status = 404)]
    NotFound
}

#[derive(ApiResponse)]
enum GetScopeResponse {
    #[oai(status = 200)]
    Ok(Json<entities::permission_scope::Model>),
    #[oai(status = 404)]
    NotFound
}

#[derive(ApiResponse)]
enum BatchActionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::permission_action::Model>>),
}

#[derive(ApiResponse)]
enum BatchResourcesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::permission_resource::Model>>),
}

#[derive(ApiResponse)]
enum BatchScopesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::permission_scope::Model>>),
}

#[derive(ApiResponse)]
enum RolePermissionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::role_permissions::Model>>),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(poem_openapi::Object, Debug)]
pub struct RolePermissionsRequest {
    pub permissions: Vec<uuid::Uuid>,
}

#[OpenApi(prefix_path = "/permissions", tag = "ApiTags::Permissions")]
impl PermissionsApi {

    #[oai(path = "/", method = "get")]
    async fn get_permissions(&self, db: Data<&DatabaseConnection>) -> Result<Json<Vec<uuid::Uuid>>> {
        let uuids: Vec<uuid::Uuid> = Permissions::find()
            .select_only()
            .column(entities::permissions::Column::Id)
            .into_tuple()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(Json(uuids))
    }

    #[oai(path = "/:uuid", method = "get")]
    async fn get_permission(&self, db: Data<&DatabaseConnection>, uuid: poem_openapi::param::Path<uuid::Uuid>) -> Result<GetPermissionResponse> {
        let permissions = Permissions::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match permissions {
            Some(model) => Ok(GetPermissionResponse::Ok(Json(model))),
            None => Ok(GetPermissionResponse::NotFound),
        }
    }

    #[oai(path = "/", method = "post")]
    async fn add_permission(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<AddPermissionRequest>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("create", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }

        // Generate permission_name if not provided
        let permission_name = req.0.permission_name.unwrap_or_else(|| {
            format!("{}:{}:{}", req.0.action_id, req.0.resource_id, req.0.scope_id)
        });

        let active = entities::permissions::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            action_id: Set(req.0.action_id),
            resource_id: Set(req.0.resource_id),
            scope_id: Set(req.0.scope_id),
            permission_name: Set(Some(permission_name)),
            ..Default::default()
        };
        let model = active.insert(*db).await.map_err(poem::error::InternalServerError)?;
        Ok(PlainText(model.id.to_string()))
    }

    #[oai(path = "/:uuid", method = "delete")]
    async fn delete_permission(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        uuid: poem_openapi::param::Path<uuid::Uuid>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("delete", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }
        let res = entities::permissions::Entity::delete_by_id(uuid.0)
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Permissions not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(uuid.0.to_string()))
    }

    #[oai(path = "/batch", method = "post")]
    async fn batch_get_permissions(
        &self,
        db: Data<&DatabaseConnection>,
        req: Json<BatchPermissionsRequest>,
    ) -> Result<BatchPermissionsResponse> {
        let permissions = Permissions::find()
            .filter(entities::permissions::Column::Id.is_in(req.0.uuids.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchPermissionsResponse::Ok(Json(permissions)))
    }

    // Actions CRUD operations
    #[oai(path = "/actions", method = "get")]
    async fn get_actions(&self, db: Data<&DatabaseConnection>) -> Result<Json<Vec<String>>> {
        let actions: Vec<String> = PermissionActions::find()
            .select_only()
            .column(entities::permission_action::Column::Action)
            .into_tuple()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(Json(actions))
    }

    #[oai(path = "/actions/:action", method = "get")]
    async fn get_action(&self, db: Data<&DatabaseConnection>, action: poem_openapi::param::Path<String>) -> Result<GetActionResponse> {
        let action_model = PermissionActions::find_by_id(action.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match action_model {
            Some(model) => Ok(GetActionResponse::Ok(Json(model))),
            None => Ok(GetActionResponse::NotFound),
        }
    }

    #[oai(path = "/actions", method = "post")]
    async fn add_action(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<AddActionRequest>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("create", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }

        let active = entities::permission_action::ActiveModel {
            action: Set(req.0.action.clone()),
            ..Default::default()
        };
        let model = active.insert(*db).await.map_err(poem::error::InternalServerError)?;
        Ok(PlainText(model.action))
    }

    #[oai(path = "/actions/:action", method = "delete")]
    async fn delete_action(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        action: poem_openapi::param::Path<String>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("delete", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }
        let res = PermissionActions::delete_by_id(action.0.clone())
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Action not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(action.0))
    }

    #[oai(path = "/actions/batch", method = "post")]
    async fn batch_get_actions(
        &self,
        db: Data<&DatabaseConnection>,
        req: Json<BatchActionsRequest>,
    ) -> Result<BatchActionsResponse> {
        let actions = PermissionActions::find()
            .filter(entities::permission_action::Column::Action.is_in(req.0.actions.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchActionsResponse::Ok(Json(actions)))
    }

    // Resources CRUD operations
    #[oai(path = "/resources", method = "get")]
    async fn get_resources(&self, db: Data<&DatabaseConnection>) -> Result<Json<Vec<String>>> {
        let resources: Vec<String> = PermissionResources::find()
            .select_only()
            .column(entities::permission_resource::Column::Resource)
            .into_tuple()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(Json(resources))
    }

    #[oai(path = "/resources/:resource", method = "get")]
    async fn get_resource(&self, db: Data<&DatabaseConnection>, resource: poem_openapi::param::Path<String>) -> Result<GetResourceResponse> {
        let resource_model = PermissionResources::find_by_id(resource.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match resource_model {
            Some(model) => Ok(GetResourceResponse::Ok(Json(model))),
            None => Ok(GetResourceResponse::NotFound),
        }
    }

    #[oai(path = "/resources", method = "post")]
    async fn add_resource(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<AddResourceRequest>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("create", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }

        let active = entities::permission_resource::ActiveModel {
            resource: Set(req.0.resource.clone()),
            ..Default::default()
        };
        let model = active.insert(*db).await.map_err(poem::error::InternalServerError)?;
        Ok(PlainText(model.resource))
    }

    #[oai(path = "/resources/:resource", method = "delete")]
    async fn delete_resource(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        resource: poem_openapi::param::Path<String>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("delete", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }
        let res = PermissionResources::delete_by_id(resource.0.clone())
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Resource not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(resource.0))
    }

    #[oai(path = "/resources/batch", method = "post")]
    async fn batch_get_resources(
        &self,
        db: Data<&DatabaseConnection>,
        req: Json<BatchResourcesRequest>,
    ) -> Result<BatchResourcesResponse> {
        let resources = PermissionResources::find()
            .filter(entities::permission_resource::Column::Resource.is_in(req.0.resources.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchResourcesResponse::Ok(Json(resources)))
    }

    // Scopes CRUD operations
    #[oai(path = "/scopes", method = "get")]
    async fn get_scopes(&self, db: Data<&DatabaseConnection>) -> Result<Json<Vec<String>>> {
        let scopes: Vec<String> = PermissionScopes::find()
            .select_only()
            .column(entities::permission_scope::Column::Scope)
            .into_tuple()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(Json(scopes))
    }

    #[oai(path = "/scopes/:scope", method = "get")]
    async fn get_scope(&self, db: Data<&DatabaseConnection>, scope: poem_openapi::param::Path<String>) -> Result<GetScopeResponse> {
        let scope_model = PermissionScopes::find_by_id(scope.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match scope_model {
            Some(model) => Ok(GetScopeResponse::Ok(Json(model))),
            None => Ok(GetScopeResponse::NotFound),
        }
    }

    #[oai(path = "/scopes", method = "post")]
    async fn add_scope(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        req: Json<AddScopeRequest>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("create", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }

        let active = entities::permission_scope::ActiveModel {
            scope: Set(req.0.scope.clone()),
            ..Default::default()
        };
        let model = active.insert(*db).await.map_err(poem::error::InternalServerError)?;
        Ok(PlainText(model.scope))
    }

    #[oai(path = "/scopes/:scope", method = "delete")]
    async fn delete_scope(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        scope: poem_openapi::param::Path<String>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("delete", "permission") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }
        let res = PermissionScopes::delete_by_id(scope.0.clone())
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Scope not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(scope.0))
    }

    #[oai(path = "/scopes/batch", method = "post")]
    async fn batch_get_scopes(
        &self,
        db: Data<&DatabaseConnection>,
        req: Json<BatchScopesRequest>,
    ) -> Result<BatchScopesResponse> {
        let scopes = PermissionScopes::find()
            .filter(entities::permission_scope::Column::Scope.is_in(req.0.scopes.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchScopesResponse::Ok(Json(scopes)))
    }

    #[oai(path = "/roles/:role_id/permissions", method = "post")]
    async fn add_permissions_to_role(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        role_id: poem_openapi::param::Path<uuid::Uuid>,
        req: Json<RolePermissionsRequest>,
    ) -> Result<RolePermissionsResponse> {
        if !claims.has_permission("update", "role") {
            return Err(poem::Error::from_string("Not enough permissions", poem::http::StatusCode::FORBIDDEN))
        }
        // Check role exists
        let role = RolesEntity::find_by_id(role_id.0).one(*db).await.map_err(poem::error::InternalServerError)?;
        if role.is_none() {
            return Ok(RolePermissionsResponse::NotFound);
        }
        // Validate permissions exist
        let found_permissions: Vec<uuid::Uuid> = Permissions::find()
            .filter(entities::permissions::Column::Id.is_in(req.0.permissions.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?
            .into_iter()
            .map(|p| p.id)
            .collect();
        let missing: Vec<uuid::Uuid> = req
            .0
            .permissions
            .iter()
            .filter(|id| !found_permissions.contains(id))
            .cloned()
            .collect();
        if !missing.is_empty() {
            return Ok(RolePermissionsResponse::BadRequest(PlainText(format!("permissions do not exist: {:?}", missing))));
        }

        // Insert role_permissions
        let mut inserted = Vec::new();
        for perm_id in req.0.permissions {
            let rp = entities::role_permissions::ActiveModel {
                role_id: Set(role_id.0),
                permission_id: Set(perm_id),
                ..Default::default()
            };
            let model = rp.insert(*db).await.map_err(poem::error::InternalServerError)?;
            inserted.push(model);
        }

        Ok(RolePermissionsResponse::Ok(Json(inserted)))
    }

    #[oai(path = "/roles/:role_id/permissions", method = "delete")]
    async fn remove_permissions_from_role(
        &self,
        db: Data<&DatabaseConnection>,
        claims: BearerAuthorization,
        role_id: poem_openapi::param::Path<uuid::Uuid>,
        req: Json<RolePermissionsRequest>,
    ) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("update", "role") {
            return Err(poem::Error::from_string("Not enough permissions", poem::http::StatusCode::FORBIDDEN))
        }
        // Check role exists
        let role = RolesEntity::find_by_id(role_id.0).one(*db).await.map_err(poem::error::InternalServerError)?;
        if role.is_none() {
            return Err(poem::Error::from_string("Role not found", poem::http::StatusCode::NOT_FOUND))
        }

        for perm_id in req.0.permissions {
            entities::role_permissions::Entity::delete_many()
                .filter(entities::role_permissions::Column::RoleId.eq(role_id.0))
                .filter(entities::role_permissions::Column::PermissionId.eq(perm_id))
                .exec(*db)
                .await
                .map_err(poem::error::InternalServerError)?;
        }

        Ok(poem_openapi::payload::PlainText("permissions removed from role".to_string()))
    }

}