use sea_orm_migration::{
    prelude::*,
    schema::*,
    sea_orm::{entity},
};
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(Users::Table)
                    .if_not_exists()
                    .col(uuid(Users::Id).primary_key().not_null())
                    .col(string(Users::Name).not_null().unique_key())
                    .col(string(Users::PasswordHash))
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
                    .col(string(Permissions::PermissionName).not_null().unique_key())
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

        // Insert all permissions used in the routes
        let permissions = vec![
            "create permission",
            "delete permission",
            "create user",
            "delete user",
            "update user",
            "get user",
            "assign permission",
            "create post",
            "delete post",
            "update post"
        ];
        for perm in permissions {
            let insert = Query::insert()
                .into_table(Permissions::Table)
                .columns([Permissions::Id, Permissions::PermissionName])
                .values_panic([Uuid::new_v4().into(), perm.into()])
                .to_owned();
            manager.exec_stmt(insert).await?;
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
enum Users {
    Id,
    Table,
    Name,
    PasswordHash,
}

#[derive(DeriveIden)]
enum Permissions {
    Id,
    Table,
    PermissionName,
}

#[derive(DeriveIden)]
enum UserPermissions {
    Table,
    UserId,
    PermissionId,
}
