# Development Backend Configuration
# Use local state for development
terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}
