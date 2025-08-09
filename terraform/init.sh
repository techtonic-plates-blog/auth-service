#!/bin/bash

# Terraform initialization script for auth-service
set -e

echo "Starting Terraform initialization for auth-service..."

# Load environment variables from .dev.env if present
if [ -f .dev.env ]; then
  echo "Loading environment variables from .dev.env..."
  set -o allexport
  source ./.dev.env
  set +o allexport
fi

# Check if S3 backend variables are set for remote state
if [ -n "${TF_VAR_minio_url}" ] && [ -n "${TF_VAR_minio_access_key}" ] && [ -n "${TF_VAR_minio_secret_key}" ]; then
  echo "Configuring S3 backend for remote state..."
  echo "S3 endpoint: ${TF_VAR_minio_url}"
  
  # Create backend configuration file
  cat > backend.hcl <<EOF
bucket = "tf-remote-state"
endpoints = { s3 = "${TF_VAR_minio_url}" }
access_key = "${TF_VAR_minio_access_key}"
secret_key = "${TF_VAR_minio_secret_key}"
key = "auth-service/terraform.tfstate"
region = "main"
skip_requesting_account_id = true
skip_credentials_validation = true
skip_metadata_api_check = true
skip_region_validation = true
use_path_style = true
EOF

  # Initialize with S3 backend
  terraform init -backend-config=backend.hcl
  
  # Clean up backend config file
  rm -f backend.hcl
  
  echo "Terraform initialized with S3 remote backend."
else
  echo "S3 backend variables not set, using local backend..."
  echo "Set TF_VAR_minio_url, TF_VAR_minio_access_key, and TF_VAR_minio_secret_key for remote state."
  
  # Initialize with local backend
  terraform init
  
  echo "Terraform initialized with local backend."
fi

echo "Terraform initialization completed successfully!"
