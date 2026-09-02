variable "aws_region" {
  description = "AWS region. Must match the region the detection stack deployed into, because GuardDuty and Security Hub findings are regional events."
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Short prefix for all resource names."
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

variable "alert_email" {
  description = <<-EOT
    Email address subscribed to the security alert SNS topic.

    AWS sends a confirmation request on first subscribe. An unconfirmed
    subscription accepts messages and silently discards them, which looks
    identical to a broken pipeline. Confirm it before testing.
  EOT
  type        = string
}
