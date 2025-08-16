use poem::{Result, error::InternalServerError, web::Data, http::StatusCode, Error};
use poem_openapi::{ApiResponse, Object, OpenApi, payload::Json, payload::PlainText};
use sea_orm::{DatabaseConnection, EntityTrait, QueryFilter, ColumnTrait, ActiveModelTrait, Set, QuerySelect};
use crate::routes::ApiTags;
use crate::auth::BearerAuthorization;
use entities::roles::Entity as Roles;
use entities::permissions::Entity as Permissions;
use poem_openapi::param::Query;

pub struct RolesApi;

#[derive(ApiResponse)]
enum GetRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<uuid::Uuid>>),
}

#[derive(ApiResponse)]
enum GetRoleResponse {
    #[oai(status = 200)]
    Ok(Json<entities::roles::Model>),
    #[oai(status = 404)]
    NotFound,
}

#[derive(poem_openapi::Object, Debug)]
pub struct BatchRolesRequest {
    pub uuids: Vec<uuid::Uuid>,
}

#[derive(ApiResponse)]
enum BatchRolesResponse {
    #[oai(status = 200)]
    Ok(Json<Vec<entities::roles::Model>>),
}

#[derive(Object)]
struct AddRoleRequest {
    name: String,
    description: Option<String>,
    permissions: Option<Vec<uuid::Uuid>>, 
}

#[derive(ApiResponse)]
enum AddRoleResponse {
    #[oai(status = 200)]
    Ok(Json<entities::roles::Model>),
    #[oai(status = 400)]
    BadRequest(PlainText<String>),
}

#[OpenApi(prefix_path = "/roles", tag = "ApiTags::Roles")]
impl RolesApi {
    #[oai(path = "/", method = "get")]
    async fn list(&self, db: Data<&DatabaseConnection>, name: Query<Option<String>>) -> Result<GetRolesResponse> {
        let mut finder = Roles::find();
        if let Some(n) = name.0.clone() {
            // Filter by exact name match; change to LIKE for partial matches if desired
            finder = finder.filter(entities::roles::Column::Name.eq(n));
        }
        let ids: Vec<uuid::Uuid> = finder
            .select_only()
            .column(entities::roles::Column::Id)
            .into_tuple()
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        Ok(GetRolesResponse::Ok(Json(ids)))
    }

    #[oai(path = "/batch", method = "post")]
    async fn batch_get_roles(&self, db: Data<&DatabaseConnection>, req: Json<BatchRolesRequest>) -> Result<BatchRolesResponse> {
        let roles = Roles::find()
            .filter(entities::roles::Column::Id.is_in(req.0.uuids.clone()))
            .all(*db)
            .await
            .map_err(InternalServerError)?;
        Ok(BatchRolesResponse::Ok(Json(roles)))
    }

    #[oai(path = "/", method = "post")]
    async fn add_role(&self, db: Data<&DatabaseConnection>, claims: BearerAuthorization, req: Json<AddRoleRequest>) -> Result<AddRoleResponse> {
        if !claims.has_permission("create", "role") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }

        // If permissions provided, validate they exist before creating the role
        if let Some(perms) = req.0.permissions.clone() {
            let found_permissions: Vec<uuid::Uuid> = Permissions::find()
                .filter(entities::permissions::Column::Id.is_in(perms.clone()))
                .all(*db)
                .await
                .map_err(InternalServerError)?
                .into_iter()
                .map(|p| p.id)
                .collect();
            let missing: Vec<uuid::Uuid> = perms.iter().filter(|id| !found_permissions.contains(id)).cloned().collect();
            if !missing.is_empty() {
                return Ok(AddRoleResponse::BadRequest(PlainText(format!("permissions do not exist: {:?}", missing))));
            }
        }

        let active = entities::roles::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            name: Set(req.0.name.clone()),
            description: Set(req.0.description.clone()),
            ..Default::default()
        };
        let model = active.insert(*db).await.map_err(InternalServerError)?;

        if let Some(perms) = req.0.permissions {
            for p in perms {
                let rp = entities::role_permissions::ActiveModel {
                    role_id: Set(model.id.clone()),
                    permission_id: Set(p),
                    ..Default::default()
                };
                rp.insert(*db).await.map_err(InternalServerError)?;
            }
        }

        Ok(AddRoleResponse::Ok(Json(model)))
    }

    #[oai(path = "/:id", method = "get")]
    async fn get_role(&self, db: Data<&DatabaseConnection>, id: poem_openapi::param::Path<uuid::Uuid>) -> Result<GetRoleResponse> {
        let role = Roles::find_by_id(id.0).one(*db).await.map_err(InternalServerError)?;
        match role {
            Some(r) => Ok(GetRoleResponse::Ok(Json(r))),
            None => Ok(GetRoleResponse::NotFound),
        }
    }

    #[oai(path = "/:id", method = "delete")]
    async fn delete_role(&self, db: Data<&DatabaseConnection>, claims: BearerAuthorization, id: poem_openapi::param::Path<uuid::Uuid>) -> Result<poem_openapi::payload::PlainText<String>> {
        if !claims.has_permission("delete", "role") {
            return Err(Error::from_string("Not enough permissions", StatusCode::FORBIDDEN))
        }
        let res = entities::roles::Entity::delete_by_id(id.0).exec(*db).await.map_err(InternalServerError)?;
        if res.rows_affected == 0 {
            return Err(Error::from_string("Role not found", StatusCode::NOT_FOUND));
        }
        Ok(poem_openapi::payload::PlainText(id.0.to_string()))
    }
}
