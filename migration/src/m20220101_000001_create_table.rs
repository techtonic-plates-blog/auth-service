use sea_orm_migration::{
    prelude::{extension::postgres::Type, *},
    schema::*,
    sea_orm::{EnumIter, Iterable},
};
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_type(
                Type::create()
                    .as_enum(UserStatusEnum)
                    .values(UserStatusVariants::iter())
                    .to_owned(),
            )
            .await?;

        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(uuid(Users::Id).primary_key().not_null())
                    .col(string(Users::Name).not_null().unique_key())
                    .col(string(Users::PasswordHash))
                    .col(date_time(Users::CreationTime).default(Expr::current_timestamp()))
                    .col(date_time(Users::LastLoginTime).default(Expr::current_timestamp()))
                    .col(date_time(Users::LastEditTime).default(Expr::current_timestamp()))
                    .col(
                        enumeration(Users::Status, UserStatusEnum, UserStatusVariants::iter())
                            .default(Expr::value(UserStatusVariants::Active.to_string())),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PermissionAction::Table)
                    .if_not_exists()
                    .col(string(PermissionAction::Action).primary_key().not_null())
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PermissionResource::Table)
                    .if_not_exists()
                    .col(
                        string(PermissionResource::Resource)
                            .primary_key()
                            .not_null(),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .create_table(
                Table::create()
                    .table(PermissionScope::Table)
                    .if_not_exists()
                    .col(string(PermissionScope::Scope).primary_key().not_null())
                    .to_owned(),
            )
            .await?;

        // Create permissions table
        manager
            .create_table(
                Table::create()
                    .table(Permissions::Table)
                    .if_not_exists()
                    .col(uuid(Permissions::Id).primary_key().not_null())
                    .col(string_null(Permissions::PermissionName))
                    .col(string(Permissions::ActionId).not_null())
                    .col(string(Permissions::ResourceId).not_null())
                    .col(string(Permissions::ScopeId).not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .from(Permissions::Table, Permissions::ActionId)
                            .to(PermissionAction::Table, PermissionAction::Action)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Permissions::Table, Permissions::ResourceId)
                            .to(PermissionResource::Table, PermissionResource::Resource)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(Permissions::Table, Permissions::ScopeId)
                            .to(PermissionScope::Table, PermissionScope::Scope)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await?;

        // Create user_permissions join table
        manager
            .create_table(
                Table::create()
                    .table(UserPermissions::Table)
                    .if_not_exists()
                    .col(uuid(UserPermissions::UserId).not_null())
                    .col(uuid(UserPermissions::PermissionId).not_null())
                    .primary_key(
                        Index::create()
                            .col(UserPermissions::UserId)
                            .col(UserPermissions::PermissionId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserPermissions::Table, UserPermissions::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserPermissions::Table, UserPermissions::PermissionId)
                            .to(Permissions::Table, Permissions::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create roles table
        manager
            .create_table(
                Table::create()
                    .table(Roles::Table)
                    .if_not_exists()
                    .col(uuid(Roles::Id).primary_key().not_null())
                    .col(string(Roles::Name).not_null().unique_key())
                    .col(string_null(Roles::Description))
                    .to_owned(),
            )
            .await?;

        // Create role_permissions join table
        manager
            .create_table(
                Table::create()
                    .table(RolePermissions::Table)
                    .if_not_exists()
                    .col(uuid(RolePermissions::RoleId).not_null())
                    .col(uuid(RolePermissions::PermissionId).not_null())
                    .primary_key(
                        Index::create()
                            .col(RolePermissions::RoleId)
                            .col(RolePermissions::PermissionId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(RolePermissions::Table, RolePermissions::RoleId)
                            .to(Roles::Table, Roles::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(RolePermissions::Table, RolePermissions::PermissionId)
                            .to(Permissions::Table, Permissions::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // Create user_role join table
        manager
            .create_table(
                Table::create()
                    .table(UserRole::Table)
                    .if_not_exists()
                    .col(uuid(UserRole::UserId).not_null())
                    .col(uuid(UserRole::RoleId).not_null())
                    .primary_key(
                        Index::create().col(UserRole::UserId).col(UserRole::RoleId),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserRole::Table, UserRole::UserId)
                            .to(Users::Table, Users::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserRole::Table, UserRole::RoleId)
                            .to(Roles::Table, Roles::Id)
                            .on_delete(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        let actions = vec!["create", "read", "update", "delete"];
        // collect generated permission ids so we can grant them to the admin role
        let mut permission_ids: Vec<Uuid> = Vec::new();

        for action in actions.iter() {
            let insert = Query::insert()
                .into_table(PermissionAction::Table)
                .columns([PermissionAction::Action])
                .values_panic([action.to_owned().into()])
                .to_owned();
            manager.exec_stmt(insert).await?;
        }

        let scopes = vec!["any", "owned"];

        for scope in scopes.iter() {
            let insert = Query::insert()
                .into_table(PermissionScope::Table)
                .columns([PermissionScope::Scope])
                .values_panic([scope.to_owned().into()])
                .to_owned();
            manager.exec_stmt(insert).await?;
        }

        let resources = vec![
            "permission",
            "user",
            "post",
            "asset",
            "resource",
            "action",
            "collection",
            "entry",
        ];

        for resource in resources {
            let insert = Query::insert()
                .into_table(PermissionResource::Table)
                .columns([PermissionResource::Resource])
                .values_panic([resource.into()])
                .to_owned();
            manager.exec_stmt(insert).await?;

            for action in actions.iter() {
                for scope in scopes.iter() {
                    let permission_name = format!("{}:{}:{}", action, resource, scope);
                    // generate and record the permission id so we can reference it later
                    let perm_id = Uuid::new_v4();
                    permission_ids.push(perm_id);

                    let insert = Query::insert()
                        .into_table(Permissions::Table)
                        .columns([
                            Permissions::Id,
                            Permissions::ActionId,
                            Permissions::ResourceId,
                            Permissions::ScopeId,
                            Permissions::PermissionName,
                        ])
                        .values_panic([
                            perm_id.into(),
                            (*action).into(),
                            (*resource).into(),
                            (*scope).into(),
                            permission_name.into(),
                        ])
                        .to_owned();
                    manager.exec_stmt(insert).await?;
                }
            }
        }

        // Create admin role
        let admin_role_id = Uuid::new_v4();
        let insert = Query::insert()
            .into_table(Roles::Table)
            .columns([Roles::Id, Roles::Name])
            .values_panic([admin_role_id.into(), "admin".into()])
            .to_owned();
        manager.exec_stmt(insert).await?;

        // Grant all permissions to admin role
        for perm_id in &permission_ids {
            let insert = Query::insert()
                .into_table(RolePermissions::Table)
                .columns([RolePermissions::RoleId, RolePermissions::PermissionId])
                .values_panic([admin_role_id.into(), perm_id.to_owned().into()])
                .to_owned();
            manager.exec_stmt(insert).await?;
        }

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop join tables and roles in order to avoid FK constraint errors
        manager
            .drop_table(Table::drop().table(UserRole::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(RolePermissions::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(Roles::Table).to_owned())
            .await?;

        // Drop user_permissions join table first (to avoid FK constraint errors)
        manager
            .drop_table(Table::drop().table(UserPermissions::Table).to_owned())
            .await?;
        // Drop permissions table
        manager
            .drop_table(Table::drop().table(Permissions::Table).to_owned())
            .await?;
        // Drop users table
        manager
            .drop_table(Table::drop().table(Users::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
struct UserStatusEnum;

#[derive(DeriveIden, EnumIter)]
enum UserStatusVariants {
    Active,
    Inactive,
    Banned,
}

#[derive(DeriveIden)]
enum Users {
    Id,
    Table,
    Name,
    PasswordHash,
    CreationTime,
    LastLoginTime,
    LastEditTime,
    Status,
}

#[derive(DeriveIden)]
enum Permissions {
    Id,
    Table,
    ActionId,
    ResourceId,
    PermissionName,
    ScopeId
}

#[derive(DeriveIden)]
enum UserPermissions {
    Table,
    UserId,
    PermissionId,
}

#[derive(DeriveIden)]
enum PermissionAction {
    Table,
    Action,
}

#[derive(DeriveIden)]
enum PermissionResource {
    Table,
    Resource,
}

#[derive(DeriveIden)]
enum PermissionScope {
    Table,
    Scope,
}

#[derive(DeriveIden)]
enum Roles {
    Table,
    Id,
    Name,
    Description,
}

#[derive(DeriveIden)]
enum RolePermissions {
    Table,
    RoleId,
    PermissionId,
}

#[derive(DeriveIden)]
enum UserRole {
    Table,
    UserId,
    RoleId,
}