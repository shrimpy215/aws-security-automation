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
variable "min_severity" {
  description = <<-EOT
    Minimum normalized severity (0-100) that triggers an alert.

    ASFF scale: 0 INFORMATIONAL, 1-39 LOW, 40-69 MEDIUM,
    70-89 HIGH, 90-100 CRITICAL.

    Default 40 alerts on MEDIUM and above. Anything below is recorded in
    the logs but not emailed.
  EOT
  type        = number
  default     = 40

  validation {
    condition     = var.min_severity >= 0 && var.min_severity <= 100
    error_message = "min_severity must be between 0 and 100."
  }
}

variable "dedupe_ttl_hours" {
  description = "Hours a finding fingerprint suppresses repeat alerts before the window reopens."
  type        = number
  default     = 24
}

variable "log_retention_days" {
  description = "CloudWatch Logs retention. Without this, log groups keep data forever and bill forever."
  type        = number
  default     = 14
}

variable "log_level" {
  description = "Python logging level for the Lambda functions."
  type        = string
  default     = "INFO"
}
variable "enable_securityhub_rule" {
  description = <<-EOT
    Whether the Security Hub EventBridge rule is enabled.

    Defaults to false. When Security Hub standards finish enabling they
    import several hundred control findings at once. Each is a distinct
    fingerprint, so deduplication does not suppress them, and every
    HIGH/CRITICAL one would produce an email.

    Turn this on deliberately during Stage 5 verification, once you are
    watching for the results.
  EOT
  type        = bool
  default     = false
}
