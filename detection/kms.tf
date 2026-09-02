# Customer-managed key encrypting the SNS alert topic and the DynamoDB
# tables in the workload stack.
#
# This lives in the detection stack, not the workload stack, because KMS
# keys cannot be deleted on demand — destroy only SCHEDULES deletion, 7 days
# minimum, and the key bills the whole time. A key created and destroyed
# every session would accumulate billable pending-deletion keys.

data "aws_iam_policy_document" "cmk" {
  # Delegates key access control to IAM. Without this statement the key
  # becomes unmanageable: no principal, including you, can administer it,
  # and there is no way to recover it.
  statement {
    sid       = "EnableIAMUserPermissions"
    effect    = "Allow"
    actions   = ["kms:*"]
    resources = ["*"]

    principals {
      type        = "AWS"
      identifiers = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
  }
}

resource "aws_kms_key" "main" {
  description = "CMK for ${var.project_name} security automation (SNS alerts, DynamoDB findings)"

  # Minimum permitted. Only matters at teardown.
  deletion_window_in_days = 7

  # Annual automatic rotation. A CIS control checks for this, so leaving it
  # off would have our own pipeline raise a finding about our own key.
  enable_key_rotation = true

  policy = data.aws_iam_policy_document.cmk.json
}

# A friendly name. The workload stack looks the key up by this alias rather
# than by key ID, so the two stacks share no hardcoded identifiers.
resource "aws_kms_alias" "main" {
  name          = "alias/${var.project_name}-security-automation"
  target_key_id = aws_kms_key.main.key_id
}
