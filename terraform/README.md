# Auth Service Terraform Configuration

This directory contains Terraform configuration for managing Kafka Connect connectors for the auth service.

## Overview

The main component is the `auth-service-users-source` connector, which uses Debezium to stream user data changes from the PostgreSQL database to Kafka topics.

## Components

### auth-service-users-source

A Debezium PostgreSQL source connector that:
- Monitors the `users` table in the `auth_service` database
- Streams changes to Kafka topics with prefix `users`
- Uses PostgreSQL logical replication with `pgoutput` plugin
- Transforms records to extract new record state without schema

## Prerequisites

1. **PostgreSQL Configuration**: The database must be configured for logical replication:
   ```sql
   -- Create replication slot
   SELECT pg_create_logical_replication_slot('debezium_users_slot', 'pgoutput');
   
   -- Create publication
   CREATE PUBLICATION debezium_users_pub FOR TABLE users;
   
   -- Grant permissions to debezium user
   GRANT SELECT ON users TO debezium;
   GRANT USAGE ON SCHEMA public TO debezium;
   ```

2. **Kafka Connect**: A running Kafka Connect cluster with Debezium PostgreSQL connector plugin installed.

3. **Database User**: A dedicated database user with replication privileges:
   ```sql
   CREATE USER debezium WITH REPLICATION PASSWORD 'debezium_password';
   GRANT CONNECT ON DATABASE auth_service TO debezium;
   ```

## Usage

1. **Initialize Terraform**:
   ```bash
   # Run the initialization script directly
   ./init.sh
   
   # Or use the containerized version
   docker compose -f compose.dev.yaml run --rm terraform ./init.sh
   ```

2. **Configure Variables**:
   Copy `terraform.tfvars.example` to `terraform.tfvars` and update with your values:
   ```bash
   cp terraform.tfvars.example terraform.tfvars
   # Edit terraform.tfvars with your configuration
   ```

3. **Plan and Apply**:
   ```bash
   # Direct execution
   terraform plan
   terraform apply
   
   # Or using containers
   docker compose -f compose.dev.yaml run --rm terraform terraform plan
   docker compose -f compose.dev.yaml run --rm terraform terraform apply
   ```

## S3 Backend Configuration

The init script automatically configures the S3 backend if the following environment variables are set:
- `TF_VAR_minio_url`: MinIO/S3 endpoint URL (e.g., "http://minio:9000")
- `TF_VAR_minio_access_key`: Access key for S3 backend
- `TF_VAR_minio_secret_key`: Secret key for S3 backend

If these variables are not set, Terraform will use local state storage.

## Configuration

### Required Variables

- `debezium_user`: Database user for Debezium (sensitive)
- `debezium_pass`: Database password for Debezium (sensitive)

### Optional Variables

- `postgres_host`: PostgreSQL hostname (default: "postgres")
- `kafka_connect_url`: Kafka Connect REST API URL (default: "http://kafka-connect:8083")
- `environment`: Environment name (default: "dev")
- `auth_service_database`: Database name (default: "auth_service")

## Kafka Topics

The connector will create the following topics:
- `users.public.users`: User table changes
- `users.public.users.schema-changes`: Schema changes (if enabled)

## Monitoring

Monitor the connector status using Kafka Connect REST API:

```bash
# Check connector status
curl http://localhost:8083/connectors/auth-service-users-source/status

# Check connector configuration
curl http://localhost:8083/connectors/auth-service-users-source/config
```

## Troubleshooting

1. **Replication Slot Issues**: If the slot already exists, drop and recreate it:
   ```sql
   SELECT pg_drop_replication_slot('debezium_users_slot');
   ```

2. **Permission Issues**: Ensure the debezium user has proper permissions on the database and table.

3. **Connection Issues**: Verify that Kafka Connect can reach the PostgreSQL database and that the hostname is correct.

## Security Notes

- Database credentials are marked as sensitive in Terraform
- Use proper secret management in production (AWS Secrets Manager, HashiCorp Vault, etc.)
- Consider using IAM authentication for cloud deployments
