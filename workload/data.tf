# Lookups into the long-lived detection stack.
#
# These are data sources, not remote state. The workload stack finds the key
# and topic by NAME, so the two stacks share no state file and no hardcoded
# ARNs. If the detection stack is not deployed, these fail immediately with
# a clear error rather than producing something half-built.

data "aws_kms_alias" "main" {
  name = "alias/${var.project_name}-security-automation"
}

data "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"
}
