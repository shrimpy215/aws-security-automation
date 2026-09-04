# ---------------------------------------------------------------------------
# Remediation Lambda
#
# Separate function and separate IAM role from triage — deliberately.
# This role holds ec2:ModifyInstanceAttribute and iam:UpdateAccessKey.
# A parsing bug in the triage code must not be able to reach those calls.
# ---------------------------------------------------------------------------

data "archive_file" "remediation" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/remediation"
  output_path = "${path.module}/build/remediation.zip"
}

resource "aws_cloudwatch_log_group" "remediation" {
  name              = "/aws/lambda/${var.project_name}-remediation"
  retention_in_days = var.log_retention_days
}

resource "aws_sqs_queue" "remediation_dlq" {
  name                      = "${var.project_name}-remediation-dlq"
  message_retention_seconds = 1209600
  sqs_managed_sse_enabled   = true
}

resource "aws_iam_role" "remediation" {
  name = "${var.project_name}-remediation-role"

  # Reuses the assume-role document from iam.tf. Both functions are
  # assumed by the same service; only their permissions differ.
  assume_role_policy = data.aws_iam_policy_document.lambda_assume_role.json
}

data "aws_iam_policy_document" "remediation" {
  statement {
    sid    = "WriteOwnLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.remediation.arn}:*"]
  }

  # PutItem only. This function appends to the audit trail and can neither
  # read nor modify what is already there.
  statement {
    sid       = "AppendToAuditTrail"
    effect    = "Allow"
    actions   = ["dynamodb:PutItem"]
    resources = [aws_dynamodb_table.audit.arn]
  }

  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [data.aws_sns_topic.alerts.arn]
  }

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
    resources = [aws_sqs_queue.remediation_dlq.arn]
  }

  # Read-only inspection, needed to evaluate the tag guardrail.
  #
  # These three APIs do not support resource-level permissions — AWS
  # requires "*" — so this is as tight as it goes. Note it is strictly
  # read: nothing here changes anything.
  statement {
    sid    = "InspectResourcesForGuardrails"
    effect = "Allow"
    actions = [
      "ec2:DescribeInstances",
      "iam:ListUserTags",
      "iam:ListAccessKeys",
    ]
    resources = ["*"]
  }

  # -------------------------------------------------------------------------
  # The dangerous permission, and the control that makes it safe.
  #
  # AWS itself refuses this call unless the instance carries the required
  # tag. The Lambda checks the same tag in Python, so the guardrail is
  # enforced twice — once by code that can have bugs, once by IAM that
  # cannot be bypassed by one.
  # -------------------------------------------------------------------------
  statement {
    sid       = "IsolateTaggedInstancesOnly"
    effect    = "Allow"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = ["arn:${data.aws_partition.current.partition}:ec2:${var.aws_region}:${data.aws_caller_identity.current.account_id}:instance/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/${var.required_tag_key}"
      values   = [var.required_tag_value]
    }
  }

  # ModifyInstanceAttribute touches TWO resources: the instance and the
  # security group being applied. The tag condition above would deny the
  # group, which carries no such tag — so the group is granted separately
  # and by exact ARN. Only the quarantine group can ever be applied.
  statement {
    sid       = "ApplyQuarantineGroupOnly"
    effect    = "Allow"
    actions   = ["ec2:ModifyInstanceAttribute"]
    resources = [aws_security_group.quarantine.arn]
  }

  # IAM does not support tag conditions on UpdateAccessKey, so scope by
  # user-name prefix instead. This role cannot deactivate keys belonging
  # to any user outside this project.
  statement {
    sid       = "RevokeProjectUserKeysOnly"
    effect    = "Allow"
    actions   = ["iam:UpdateAccessKey"]
    resources = ["arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:user/${var.project_name}-*"]
  }

  # X-Ray write APIs do not support resource-level permissions.
  statement {
    sid    = "WriteXRayTraces"
    effect = "Allow"
    actions = [
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
    ]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "remediation" {
  name   = "${var.project_name}-remediation-policy"
  role   = aws_iam_role.remediation.id
  policy = data.aws_iam_policy_document.remediation.json
}

resource "aws_lambda_function" "remediation" {
  function_name = "${var.project_name}-remediation"
  role          = aws_iam_role.remediation.arn

  handler = "handler.lambda_handler"
  runtime = "python3.12"

  filename         = data.archive_file.remediation.output_path
  source_code_hash = data.archive_file.remediation.output_base64sha256

  timeout     = 60
  memory_size = 256

  # Lower than triage. Containment should never run wide.
  reserved_concurrent_executions = 5

  environment {
    variables = {
      AUDIT_TABLE         = aws_dynamodb_table.audit.name
      SNS_TOPIC_ARN       = data.aws_sns_topic.alerts.arn
      QUARANTINE_SG_ID    = aws_security_group.quarantine.id
      MIN_SEVERITY        = tostring(var.remediation_min_severity)
      REQUIRED_TAG_KEY    = var.required_tag_key
      REQUIRED_TAG_VALUE  = var.required_tag_value
      DRY_RUN             = tostring(var.remediation_dry_run)
      PROTECTED_RESOURCES = join(",", var.protected_resources)
      LOG_LEVEL           = var.log_level
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.remediation_dlq.arn
  }

  # Active tracing. For a project that reports latency figures, being able to
  # see where the time actually goes is the point.
  tracing_config {
    mode = "Active"
  }


  depends_on = [aws_cloudwatch_log_group.remediation]
}

# ---------------------------------------------------------------------------
# Event routing
#
# Unlike the triage rule, this one DOES filter severity in the pattern.
# Triage wants to see everything so below-threshold findings are counted;
# remediation should never be invoked at all for a finding it could not
# act on. Fewer invocations of a dangerous function is the safer default.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "remediation" {
  name        = "${var.project_name}-high-severity-containment"
  description = "Route GuardDuty findings at severity 7.0 and above to containment"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
    detail = {
      # EventBridge numeric matching, on GuardDuty's native 1-10 scale.
      # 7.0 is HIGH, equivalent to normalized 70.
      severity = [{ numeric = [">=", 7] }]
    }
  })
}

resource "aws_cloudwatch_event_target" "remediation" {
  rule      = aws_cloudwatch_event_rule.remediation.name
  target_id = "remediation-lambda"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "remediation" {
  statement_id  = "AllowExecutionFromEventBridgeRemediation"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation.arn
}