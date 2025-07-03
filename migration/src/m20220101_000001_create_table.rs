use sea_orm_migration::{prelude::*, schema::*};

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Create users table
        manager
            .create_table(
                Table::create()
                    .table(User::Table)
                    .if_not_exists()
                    .col(uuid(User::Id).primary_key().not_null())
                    .col(string(User::Name).not_null().unique_key())
                    .col(string(User::PasswordHash))
                    .to_owned(),
            )
            .await?;

        // Create permissions table
        manager
            .create_table(
                Table::create()
                    .table(Permission::Table)
                    .if_not_exists()
                    .col(uuid(Permission::Id).primary_key().not_null())
                    .col(string(Permission::PermissionName).not_null().unique_key())
                    .to_owned(),
            )
            .await?;

        // Create user_permissions join table
        manager
            .create_table(
                Table::create()
                    .table(UserPermission::Table)
                    .if_not_exists()
                    .col(uuid(UserPermission::UserId).not_null())
                    .col(uuid(UserPermission::PermissionId).not_null())
                    .primary_key(
                        Index::create()
                            .col(UserPermission::UserId)
                            .col(UserPermission::PermissionId)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserPermission::Table, UserPermission::UserId)
                            .to(User::Table, User::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .from(UserPermission::Table, UserPermission::PermissionId)
                            .to(Permission::Table, Permission::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                    )
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Drop user_permissions join table first (to avoid FK constraint errors)
        manager
            .drop_table(Table::drop().table(UserPermission::Table).to_owned())
            .await?;
        // Drop permissions table
        manager
            .drop_table(Table::drop().table(Permission::Table).to_owned())
            .await?;
        // Drop users table
        manager
            .drop_table(Table::drop().table(User::Table).to_owned())
            .await
    }
}

#[derive(DeriveIden)]
enum User {
    Id,
    Table,
    Name,
    PasswordHash,
    
}

#[derive(DeriveIden)]
enum Permission {
    Id,
    Table,
    PermissionName
}

#[derive(DeriveIden)]
enum UserPermission {
    Table,
    UserId,
    PermissionId,
}