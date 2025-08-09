terraform {
  backend "s3" {
    # S3 backend configuration will be provided via backend config file
    # during initialization in the container entrypoint
    # Required variables: TF_VAR_minio_url, TF_VAR_minio_access_key, TF_VAR_minio_secret_key
  }
}

# Auth Service Users Source Connector
# Streams user data from auth service PostgreSQL to Kafka
resource "kafka-connect_connector" "auth-service-users-source" {
  name = "auth-service-users-source"
  
  config = {
    "name"                = "auth-service-users-source"
    "connector.class"     = "io.debezium.connector.postgresql.PostgresConnector"
    "database.hostname"   = var.postgres_host
    "database.port"       = "5432"
    "database.user"       = var.debezium_user
    "database.password"   = var.debezium_pass
    "database.dbname"     = "auth_service"
    "topic.prefix"        = "users"
    "plugin.name"         = "pgoutput"
    "slot.name"          = "debezium_users_slot"
    "publication.name"   = "debezium_users_pub"
    "table.include.list" = "public.users"
    
    # Additional Debezium configuration for better reliability
    "database.server.id"           = "1"
    "database.server.name"         = "auth-service-db"
    "decimal.handling.mode"        = "string"
    "include.schema.changes"       = "false"
    "transforms"                   = "unwrap"
    "transforms.unwrap.type"       = "io.debezium.transforms.ExtractNewRecordState"
    "transforms.unwrap.drop.tombstones" = "false"
    "key.converter"                = "org.apache.kafka.connect.json.JsonConverter"
    "value.converter"              = "org.apache.kafka.connect.json.JsonConverter"
    "key.converter.schemas.enable" = "false"
    "value.converter.schemas.enable" = "false"
  }
}
