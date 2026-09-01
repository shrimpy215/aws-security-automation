variable "aws_region" {
  description = "AWS region for all resources. GuardDuty and Security Hub are regional services."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short prefix for all resource names. Keep it under 12 characters."
  type        = string
  default     = "secops"

  validation {
    condition     = can(regex("^[a-z0-9-]{3,12}$", var.project_name))
    error_message = "project_name must be 3-12 chars, lowercase letters, digits, and hyphens only."
  }
}

variable "environment" {
  description = "Environment tag value."
  type        = string
  default     = "portfolio"
}

variable "enable_aws_config" {
  description = <<-EOT
    Whether to deploy an AWS Config recorder.

    Most Security Hub CIS and FSBP controls evaluate AWS Config configuration
    items. Without Config, the standards enable successfully but the majority
    of controls report "No data" and the compliance score is meaningless.

    Config bills per configuration item recorded and per evaluation. On a
    near-empty account for a few days this is well under a dollar, but it is
    not free tier.
  EOT
  type        = bool
  default     = true
}