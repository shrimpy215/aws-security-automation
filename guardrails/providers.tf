# AWS Budgets is a global service whose API lives in us-east-1.
# This is hardcoded rather than variable-driven on purpose — it is not a
# choice, it is a fact about the service.
provider "aws" {
  region = "us-east-1"

  default_tags {
    tags = {
      Project    = "secops"
      ManagedBy  = "terraform"
      Lifecycle  = "permanent"
      Repository = "aws-security-automation"
    }
  }
}
