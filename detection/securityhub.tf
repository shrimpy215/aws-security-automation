resource "aws_securityhub_account" "main" {
  # Security Hub will happily enable its own default standards on activation.
  # We subscribe explicitly below, so turn the defaults off — otherwise
  # Terraform and Security Hub disagree about what should be enabled and
  # every plan shows spurious drift.
  enable_default_standards = false

  # When AWS adds a new control to a standard we've enabled, turn it on
  # automatically. A compliance baseline that silently stops covering new
  # controls is worse than no baseline.
  auto_enable_controls = true

  # Consolidates findings so one control produces ONE finding even when
  # several standards reference that same control. CIS and FSBP overlap
  # heavily, so this removes a large amount of duplicate noise before it
  # ever reaches our EventBridge rules.
  control_finding_generator = "SECURITY_CONTROL"
}

locals {
  # Standards ARNs are region-qualified with an EMPTY account field —
  # note the double colon. These are AWS-owned resources, not yours.
  security_hub_standards = {
    cis_v3 = "arn:${data.aws_partition.current.partition}:securityhub:${var.aws_region}::standards/cis-aws-foundations-benchmark/v/3.0.0"
    fsbp   = "arn:${data.aws_partition.current.partition}:securityhub:${var.aws_region}::standards/aws-foundational-security-best-practices/v/1.0.0"
  }
}

resource "aws_securityhub_standards_subscription" "this" {
  for_each = local.security_hub_standards

  standards_arn = each.value

  # The provider's default 3-minute create wait is shorter than first-time
  # standards enablement in a fresh account. CIS v3.0.0 and FSBP together
  # activate several hundred controls, which routinely exceeds it. The
  # subscription is created successfully either way — only the readiness
  # poll times out — but Terraform taints the resource, so every subsequent
  # apply plans a needless replacement.
  timeouts {
    create = "30m"
  }

  depends_on = [aws_securityhub_account.main]
}
