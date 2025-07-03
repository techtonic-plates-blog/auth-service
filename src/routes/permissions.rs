use poem::{http::StatusCode, web::Data, Error};
use poem_openapi::{payload::Json, ApiResponse, OpenApi};
use sea_orm::{DatabaseConnection, QueryFilter, ColumnTrait};
use entities::permission::Entity as Permission;
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
    Ok(Json<entities::permission::Model>),
    #[oai(status = 404)]
    NotFound
}

#[derive(poem_openapi::Object, Debug)]
pub struct AddPermissionRequest {
    pub permission_name: String,
    // Add other fields as needed
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchPermissionsRequest {
    pub uuids: Vec<uuid::Uuid>,
}

#[derive(ApiResponse)]
enum BatchPermissionsResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::permission::Model>>),
}

#[OpenApi(prefix_path = "/permissions", tag = "ApiTags::Permissions")]
impl PermissionsApi {

    #[oai(path = "/", method = "get")]
    async fn get_permissions(&self, db: Data<&DatabaseConnection>) -> Result<Json<Vec<uuid::Uuid>>> {
        let uuids: Vec<uuid::Uuid> = Permission::find()
            .select_only()
            .column(entities::permission::Column::Id)
            .into_tuple()
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(Json(uuids))
    }

    #[oai(path = "/:uuid", method = "get")]
    async fn get_permission(&self, db: Data<&DatabaseConnection>, uuid: poem_openapi::param::Path<uuid::Uuid>) -> Result<GetPermissionResponse> {
        let permission = Permission::find_by_id(uuid.0)
            .one(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        match permission {
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
        if !claims.permissions.contains(&"create permission".to_string()) {
            return Err(Error::from_string("Not enough permissions", StatusCode::UNAUTHORIZED))
        }

        let active = entities::permission::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            permission_name: Set(req.0.permission_name.clone()),
            // Set other fields as needed
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
        if !claims.permissions.contains(&"delete permission".to_string()) {
            return Err(Error::from_string("Not enough permissions", StatusCode::UNAUTHORIZED))
        }
        let res = entities::permission::Entity::delete_by_id(uuid.0)
            .exec(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Permission not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(uuid.0.to_string()))
    }

    #[oai(path = "/batch", method = "post")]
    async fn batch_get_permissions(
        &self,
        db: Data<&DatabaseConnection>,
        req: Json<BatchPermissionsRequest>,
    ) -> Result<BatchPermissionsResponse> {
        let permissions = Permission::find()
            .filter(entities::permission::Column::Id.is_in(req.0.uuids.clone()))
            .all(*db)
            .await
            .map_err(poem::error::InternalServerError)?;
        Ok(BatchPermissionsResponse::Ok(Json(permissions)))
    }

}