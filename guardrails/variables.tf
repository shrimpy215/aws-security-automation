variable "alert_email" {
  description = "Email address that receives budget alerts. Must be confirmed once by clicking the link AWS sends."
  type        = string
}

variable "monthly_budget_limit" {
  description = "Monthly account spend ceiling in USD that alert thresholds are measured against."
  type        = string
  default     = "10"
}