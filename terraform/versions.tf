terraform {
  required_version = ">= 1.6.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }

    # Zips the Lambda source directories at plan time (Stage 3).
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }

    # Generates a unique suffix for the AWS Config S3 bucket (Stage 1b).
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}