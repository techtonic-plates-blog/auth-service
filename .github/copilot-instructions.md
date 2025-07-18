# AI Coding Agent Instructions for Auth Service

## Architecture Overview

This is a Rust microservice for authentication in the Techtonic Plates blog system, built with:
- **Web Framework**: [`poem`](https://docs.rs/poem/) + [`poem-openapi`](https://docs.rs/poem-openapi/) for REST API with auto-generated OpenAPI docs
- **ORM**: [SeaORM](https://www.sea-ql.org/SeaORM/) with PostgreSQL database
- **Auth**: RS256 JWT tokens with [`jsonwebtoken`](https://docs.rs/jsonwebtoken/) and [`argon2`](https://docs.rs/argon2/) password hashing
- **Structure**: Cargo workspace with separate crates for entities, migrations, and password hashing

## Key Components

### 1. Workspace Structure
- Root crate: Main auth service (`src/`)
- `entities/`: Generated SeaORM models (Users, Permissions, UserPermissions)
- `migration/`: Database migrations using SeaORM migrations
- `hasher/`: CLI utility for Argon2 password hashing

### 2. Authentication Flow
- JWT uses RS256 with public/private key pair from environment variables
- Claims include `sub`, `company`, `exp`, and `permissions` array
- Bearer token authorization via `BearerAuthorization` wrapper struct
- Permission checking pattern: `claims.permissions.contains(&"permission name".to_string())`

### 3. API Patterns

#### Route Structure
```rust
// In routes/mod.rs - all APIs combined into single service
pub fn api() -> impl OpenApi {
    (RootApi, auth::AuthApi, permissions::PermissionsApi, users::UsersApi, me::MeApi)
}
```

#### Authorization Pattern
```rust
async fn endpoint(
    &self,
    claims: BearerAuthorization,  // JWT auth required
    db: Data<&DatabaseConnection>,
    // other params...
) -> ResponseType {
    if !claims.permissions.contains(&"required permission".to_string()) {
        return ResponseType::Unauthorized(PlainText("Insufficient permissions".to_string()));
    }
    // implementation...
}
```

#### Response Enum Pattern
```rust
#[derive(ApiResponse)]
enum CustomResponse {
    #[oai(status = 200)]
    Ok(Json<DataType>),
    #[oai(status = 401)]
    Unauthorized(PlainText<String>),
    #[oai(status = 404)]
    NotFound,
}
```

## Development Workflows

### Environment Setup
- Use `.dev.env` for development (contains test RSA keys - NOT for production)
- Required vars: `DATABASE_URL`, `JWT_SECRET_KEY`, `JWT_PUBLIC_KEY`, `RUST_LOG`
- JWT keys use `\\n` escaped newlines in env vars, converted to `\n` in config

### Database Operations
```bash
# Generate entities after schema changes
cargo run -p entities

# Run migrations
cargo run --bin migration
```

**Key Documentation**: [SeaORM Migrations](https://www.sea-ql.org/SeaORM/docs/migration/setting-up-migration/) | [Entity Generation](https://www.sea-ql.org/SeaORM/docs/generate-entity/sea-orm-cli/)

### Container Development
```bash
# Development with hot reload
docker compose -f compose.dev.yaml up dev

# Host networking mode available
docker compose -f compose.dev.yaml up host-mode
```

### Password Hashing
```bash
# Generate Argon2 hash for testing
cargo run --bin hasher -- "password123"
```

## Code Conventions

**Key Documentation**: [poem-openapi Guide](https://docs.rs/poem-openapi/latest/poem_openapi/) | [SeaORM Entity Relations](https://www.sea-ql.org/SeaORM/docs/relation/one-to-many/)

### Entity Relationships
- Users ↔ Permissions via UserPermissions junction table
- All primary keys are UUIDs
- SeaORM relations properly defined with `Related` implementations
- Use `#[oai(rename = "EntityName")]` for consistent API naming

### Error Handling
- Use `anyhow::Result` for setup/initialization
- Return appropriate HTTP status codes via response enums
- Database errors bubble up as 500 Internal Server Error
- Authorization failures return 401 with descriptive messages

### Configuration
- Global config via `once_cell::sync::Lazy` static in `config.rs`
- Environment variables read once at startup
- JWT key newline replacement: `.replace("\\n", "\n")`

### Testing Approach
- Hasher utility for generating test password hashes
- Development keys provided in `.dev.env` (clearly marked as test-only)
- Use external Docker network `techtonic_plates_network` for integration

## Common Pitfalls
- JWT public/private keys must have proper PEM formatting with newlines
- Permission strings are hardcoded - ensure consistency across routes
- SeaORM entities are auto-generated - don't manually edit them
- Database connection is passed as `Data<&DatabaseConnection>` in handlers
- Use `Set()` wrapper for SeaORM ActiveModel field updates

## External Dependencies
- PostgreSQL database (containerized)
- Kafka Connect for event streaming (configured but usage not evident in current codebase)
- External Docker network for microservice communication
