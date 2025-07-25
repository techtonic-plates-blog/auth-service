use poem_openapi::{OpenApi, Tags};

mod auth;
mod permissions;
mod users;
mod me;

#[derive(Debug, Tags)]
#[allow(dead_code)]
pub enum ApiTags {
    Auth,
    Permissions,
    Users,
    Me,
}

pub struct RootApi;

#[OpenApi]
impl RootApi {
      #[oai(method = "get", path = "/healthcheck")]
      async fn healthcheck(&self) {

      }
}

pub fn api() -> impl OpenApi {
    (RootApi, auth::AuthApi, permissions::PermissionsApi, users::UsersApi, me::MeApi)
}