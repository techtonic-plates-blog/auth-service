output "connector_name" {
  description = "Name of the created Kafka Connect connector"
  value       = kafka-connect_connector.auth-service-users-source.name
}

output "connector_config" {
  description = "Configuration of the Kafka Connect connector"
  value       = kafka-connect_connector.auth-service-users-source.config
  sensitive   = true
}

output "topic_prefix" {
  description = "Kafka topic prefix for auth service users"
  value       = "users"
}

output "database_slot_name" {
  description = "PostgreSQL replication slot name"
  value       = "debezium_users_slot"
}

output "publication_name" {
  description = "PostgreSQL publication name"
  value       = "debezium_users_pub"
}
