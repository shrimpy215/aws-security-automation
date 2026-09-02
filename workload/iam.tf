# ---------------------------------------------------------------------------
# Triage Lambda execution role
#
# Deliberately NOT using the AWSLambdaBasicExecutionRole managed policy.
# That grants logs:* across every log group in the account. This role can
# write to exactly one log group and nothing else.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "lambda_assume_role" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "triage" {
  name               = "${var.project_name}-triage-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "triage" {
  # Note: no logs:CreateLogGroup. Terraform creates the group, so the
  # function never needs permission to make one.
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.triage.arn}:*"]
  }

  # PutItem and UpdateItem only. The triage function never READS these
  # tables — the conditional write does the checking — so it has no
  # GetItem, Query, or Scan.
  statement {
    sid    = "WriteDedupeAndAudit"
    effect = "Allow"
    actions = [
      "dynamodb:PutItem",
      "dynamodb:UpdateItem",
    ]
    resources = [
      aws_dynamodb_table.dedupe.arn,
      aws_dynamodb_table.audit.arn,
    ]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerts.arn]
  }

  # Required because the SNS topic and both DynamoDB tables are encrypted
  # with the customer-managed key. Without this, every write fails with
  # AccessDenied on KMS rather than on the resource itself — a confusing
  # error the first time you meet it.
  statement {
    sid    = "UseCustomerManagedKey"
    effect = "Allow"
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = [data.aws_kms_alias.main.target_key_arn]
  }

  statement {
    sid       = "SendToDeadLetterQueue"
    effect    = "Allow"
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.triage_dlq.arn]
  }
}

resource "aws_iam_role_policy" "triage" {
  name   = "${var.project_name}-triage-policy"
  role   = aws_iam_role.triage.id
  policy = data.aws_iam_policy_document.triage.json
}