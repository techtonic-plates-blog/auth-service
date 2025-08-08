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
        manager.create_type(Type::create()
            .as_enum(UserStatusEnum)
            .values(UserStatusVariants::iter())
            .to_owned()
        ).await?;

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

        manager.create_table(
            Table::create()
                .table(PermissionAction::Table)
                .if_not_exists()
                .col(string(PermissionAction::Action).primary_key().not_null())
                .to_owned(),
        ).await?;

        manager.create_table(
            Table::create()
                .table(PermissionResource::Table)
                .if_not_exists()
                .col(string(PermissionResource::Resource).primary_key().not_null())
                .to_owned(),
        ).await?;  

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

        let actions = vec![
            "create",
            "read",
            "update",
            "delete",
            
        ];

        for action in actions.iter() {
            let insert = Query::insert()
                .into_table(PermissionAction::Table)
                .columns([PermissionAction::Action])
                .values_panic([action.to_owned().into()])
                .to_owned();
            manager.exec_stmt(insert).await?;
        }

        let resources = vec![
            "permission",
            "user",
            "post",
            "asset",
            "resource", 
            "action"
        ];

        for resource in resources {
            let insert = Query::insert()
                .into_table(PermissionResource::Table)
                .columns([PermissionResource::Resource])
                .values_panic([resource.into()])
                .to_owned();
            manager.exec_stmt(insert).await?;

            for action in &actions {
                let permission_name = format!("{}:{}", action, resource);
                let insert = Query::insert()
                    .into_table(Permissions::Table)
                    .columns([
                        Permissions::Id,
                        Permissions::ActionId,
                        Permissions::ResourceId,
                        Permissions::PermissionName,
                    ])
                    .values_panic([
                        Uuid::new_v4().into(),
                        (*action).into(),
                        (*resource).into(),
                        permission_name.into(),
                    ])
                    .to_owned();
                manager.exec_stmt(insert).await?;
            }
        }

       
       

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
    Action
} 

#[derive(DeriveIden)]
enum PermissionResource {
    Table,
    Resource
}