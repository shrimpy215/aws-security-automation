provider "aws" {
  region = var.aws_region

  # Applied automatically to every resource that supports tagging.
  # Cheaper than repeating a tags block on 40 resources, and it means
  # nothing can be created without attribution.
  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "terraform"
      Repository  = "aws-security-automation"
    }
  }
}

# Data sources: read-only lookups against the credentials Terraform is using.
# These create nothing. We use them to build ARNs and scope IAM policies to
# THIS account rather than hardcoding an account number into the repo.
data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}
