.PHONY: init plan apply destroy validate fmt check clean help

# Default environment
ENV ?= dev

# Terraform commands
init:
	@echo "Initializing Terraform..."
	terraform init

plan:
	@echo "Planning Terraform changes for $(ENV) environment..."
	terraform plan -var-file="terraform.tfvars"

apply:
	@echo "Applying Terraform changes for $(ENV) environment..."
	terraform apply -var-file="terraform.tfvars"

destroy:
	@echo "Destroying Terraform resources for $(ENV) environment..."
	terraform destroy -var-file="terraform.tfvars"

validate:
	@echo "Validating Terraform configuration..."
	terraform validate

fmt:
	@echo "Formatting Terraform files..."
	terraform fmt -recursive

check: validate fmt
	@echo "Running Terraform checks..."
	terraform plan -detailed-exitcode -var-file="terraform.tfvars" > /dev/null

clean:
	@echo "Cleaning Terraform state and cache..."
	rm -rf .terraform/
	rm -f .terraform.lock.hcl
	rm -f terraform.tfstate*
	rm -f *.tfplan

# Setup development environment
setup-dev:
	@echo "Setting up development environment..."
	@if [ ! -f terraform.tfvars ]; then \
		cp terraform.tfvars.example terraform.tfvars; \
		echo "Created terraform.tfvars from example. Please update with your values."; \
	fi
	make init

# Check connector status (requires jq)
status:
	@echo "Checking auth-service-users-source connector status..."
	@curl -s http://localhost:8083/connectors/auth-service-users-source/status | jq '.'

# View connector config
config:
	@echo "Viewing auth-service-users-source connector configuration..."
	@curl -s http://localhost:8083/connectors/auth-service-users-source/config | jq '.'

help:
	@echo "Available commands:"
	@echo "  init        - Initialize Terraform"
	@echo "  plan        - Plan Terraform changes"
	@echo "  apply       - Apply Terraform changes"
	@echo "  destroy     - Destroy Terraform resources"
	@echo "  validate    - Validate Terraform configuration"
	@echo "  fmt         - Format Terraform files"
	@echo "  check       - Run validation and formatting checks"
	@echo "  clean       - Clean Terraform state and cache"
	@echo "  setup-dev   - Setup development environment"
	@echo "  status      - Check connector status"
	@echo "  config      - View connector configuration"
	@echo "  help        - Show this help message"
	@echo ""
	@echo "Environment variables:"
	@echo "  ENV         - Environment name (default: dev)"
