# Auth Service

This is the microservice for handling authentication in the Techtonic Plates blog system.

## Container Images

Pre-built container images are available from GitHub Container Registry:

- **Main Service**: `ghcr.io/techtonic-plates-blog/auth-service:latest`
- **Entities Generator**: `ghcr.io/techtonic-plates-blog/auth-service-entities:latest`
- **Database Migrations**: `ghcr.io/techtonic-plates-blog/auth-service-migration:latest`

### Quick Start with Docker

```bash
# Pull and run the main auth service
docker pull ghcr.io/techtonic-plates-blog/auth-service:latest
docker run -d --name auth-service \
  --env-file .env \
  -p 8080:8080 \
  ghcr.io/techtonic-plates-blog/auth-service:latest
```

## Development

### Local Development

To run the microservice locally:

```bash
# Compile the application
cargo build --release

# Run the binary
./target/release/auth-service
```

### Container Development

Build containers locally using the provided Dockerfiles:

```bash
# Main auth service
docker build -f container/Containerfile -t auth-service .

# Database migrations
docker build -f container/Containerfile.migration -t auth-service-migration .

# Entities generator
docker build -f container/Containerfile.entities -t auth-service-entities .

# Terraform operations
docker build -f container/Containerfile.terraform -t auth-service-terraform .
```

Or use the development docker-compose setup:

```bash
# Start development environment with hot reload
docker compose -f compose.dev.yaml up dev

# Run in host networking mode
docker compose -f compose.dev.yaml up host-mode
```

## Configuration

### Environment Variables

The application requires several environment variables to function properly. See [.dev.env](.dev.env) for development configuration:

- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET_KEY`: RSA private key for JWT signing
- `JWT_PUBLIC_KEY`: RSA public key for JWT verification
- `RUST_LOG`: Log level configuration
- `KAFKA_CONNECT_URL`: Kafka Connect endpoint (optional)

**⚠️ Note**: The keys in `.dev.env` are for development/testing only and should never be used in production.

### Database Setup

Run database migrations:

```bash
# Using the migration binary
cargo run --bin migration

# Or using the container
docker run --rm \
  --env-file .env \
  --network techtonic_plates_network \
  ghcr.io/techtonic-plates-blog/auth-service-migration:latest
```

Generate entities after schema changes:

```bash
# Using the entities binary
cargo run -p entities

# Or using the container
docker run --rm \
  --env-file .env \
  --network techtonic_plates_network \
  -v $(pwd)/entities/src:/app/output \
  ghcr.io/techtonic-plates-blog/auth-service-entities:latest
```