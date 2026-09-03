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
variable "deploy_demo_targets" {
  description = <<-EOT
    Whether to create throwaway resources for demonstrating containment:
    one t3.micro EC2 instance and one IAM user, both tagged into scope.

    These exist only to be isolated and re-enabled. They have no data, no
    permissions, and no key pair. Destroyed with the rest of the stack.
  EOT
  type        = bool
  default     = false
}

variable "remediation_dry_run" {
  description = <<-EOT
    When true, the remediation function logs what it WOULD do and takes no
    action. Defaults to true.

    A missing or misspelled environment variable must result in no action
    rather than unintended action.
  EOT
  type        = bool
  default     = true
}

variable "remediation_min_severity" {
  description = "Minimum normalized severity (0-100) for automated containment. 70 = HIGH."
  type        = number
  default     = 70

  validation {
    condition     = var.remediation_min_severity >= 40
    error_message = "Refusing a containment threshold below MEDIUM. Automated action on low-severity findings is how you take production down over a port scan."
  }
}

variable "required_tag_key" {
  description = "Tag key a resource must carry to be eligible for automated containment."
  type        = string
  default     = "SecurityAutomation"
}

variable "required_tag_value" {
  description = "Tag value a resource must carry to be eligible for automated containment."
  type        = string
  default     = "enabled"
}

variable "protected_resources" {
  description = <<-EOT
    Resource IDs that must NEVER be acted on, regardless of tags or
    severity. Checked first, before every other guardrail.

    In a real deployment this is where domain controllers, bastions, and
    anything whose isolation would cause an outage worse than the incident
    would be listed.
  EOT
  type        = list(string)
  default     = []
}