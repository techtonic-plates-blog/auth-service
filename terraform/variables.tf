# PostgreSQL Database Configuration
variable "postgres_host" {
  description = "PostgreSQL database hostname"
  type        = string
  default     = "postgres"
}

variable "debezium_user" {
  description = "Database user for Debezium connector"
  type        = string
  sensitive   = true
}

variable "debezium_pass" {
  description = "Database password for Debezium connector"
  type        = string
  sensitive   = true
}

# Kafka Connect Configuration
variable "kafka_connect_url" {
  description = "Kafka Connect REST API URL"
  type        = string
  default     = "http://kafka-connect:8083"
}

# Auth Service Configuration
variable "auth_service_database" {
  description = "Auth service database name"
  type        = string
  default     = "auth_service"
}
