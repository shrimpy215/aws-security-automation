resource "aws_guardduty_detector" "main" {
  enable = true

  # How often GuardDuty exports updates to EventBridge for findings it has
  # already raised. FIFTEEN_MINUTES is the tightest available and directly
  # improves MTTD for repeat activity on an existing finding.
  #
  # Note: the FIRST occurrence of a finding is published to EventBridge
  # immediately regardless of this setting. This only governs updates.
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

locals {
  # GuardDuty's core analysis — CloudTrail management events, VPC Flow Logs,
  # and DNS query logs — is always on and cannot be turned off. Everything
  # below is an OPTIONAL data source with its own per-GB or per-scan charge.
  #
  # New detectors enable several of these by default. None are needed to
  # exercise this pipeline, so we turn them off explicitly rather than
  # relying on a default. Explicit beats implicit in a cost-sensitive account,
  # and a reviewer can see the decision was deliberate.
  guardduty_optional_features = {
    S3_DATA_EVENTS         = "DISABLED"
    EKS_AUDIT_LOGS         = "DISABLED"
    EBS_MALWARE_PROTECTION = "DISABLED"
    RDS_LOGIN_EVENTS       = "DISABLED"
    LAMBDA_NETWORK_LOGS    = "DISABLED"
    RUNTIME_MONITORING     = "DISABLED"
  }
}

resource "aws_guardduty_detector_feature" "optional" {
  for_each = local.guardduty_optional_features

  detector_id = aws_guardduty_detector.main.id
  name        = each.key
  status      = each.value
}