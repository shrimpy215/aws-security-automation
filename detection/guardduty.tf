resource "aws_guardduty_detector" "main" {
  enable = true

  # Governs how often updates to EXISTING findings are published to
  # EventBridge. First occurrence of a finding is always immediate.
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

locals {
  # Optional GuardDuty data sources, each with its own per-GB or per-scan
  # charge. Core analysis (CloudTrail, VPC Flow Logs, DNS) is always on and
  # cannot be disabled. None of these are needed to exercise this pipeline.
  guardduty_optional_features = {
    S3_DATA_EVENTS         = "DISABLED"
    EKS_AUDIT_LOGS         = "DISABLED"
    EBS_MALWARE_PROTECTION = "DISABLED"
    RDS_LOGIN_EVENTS       = "DISABLED"
    LAMBDA_NETWORK_LOGS    = "DISABLED"
  }
}

resource "aws_guardduty_detector_feature" "optional" {
  for_each = local.guardduty_optional_features

  detector_id = aws_guardduty_detector.main.id
  name        = each.key
  status      = each.value
}

# RUNTIME_MONITORING is declared separately, NOT via the for_each map above.
#
# AWS returns three additional_configuration sub-settings for this feature.
# A for_each map holds only name/status pairs and cannot express nested
# blocks, so the provider treats those sub-settings as unmanaged drift and
# plans to remove them on every run. AWS restores them, and the diff never
# converges to zero.
#
# Declaring them explicitly makes the plan clean.
resource "aws_guardduty_detector_feature" "runtime_monitoring" {
  detector_id = aws_guardduty_detector.main.id
  name        = "RUNTIME_MONITORING"
  status      = "DISABLED"

  additional_configuration {
    name   = "EC2_AGENT_MANAGEMENT"
    status = "DISABLED"
  }

  additional_configuration {
    name   = "ECS_FARGATE_AGENT_MANAGEMENT"
    status = "DISABLED"
  }

  additional_configuration {
    name   = "EKS_ADDON_MANAGEMENT"
    status = "DISABLED"
  }
}
