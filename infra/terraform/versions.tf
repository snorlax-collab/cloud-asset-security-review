terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }

  # For production: copy backend.tf.example → backend.tf (S3 + SSE + DynamoDB lock).
  # Local state is fine for a single-operator deploy; never commit *.tfstate.
}

provider "aws" {
  region = var.aws_region
}

data "aws_caller_identity" "current" {}

locals {
  name = var.project_name
  tags = merge(var.tags, {
    Project = local.name
    Managed = "terraform"
  })
}
