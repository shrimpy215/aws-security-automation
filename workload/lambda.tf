# ---------------------------------------------------------------------------
# Triage Lambda
# ---------------------------------------------------------------------------

# Zips the source directory at PLAN time, not apply time. The resulting
# hash is what tells Terraform the code changed, so editing handler.py
# produces a plan showing an update without you doing anything else.
data "archive_file" "triage" {
  type        = "zip"
  source_dir  = "${path.module}/../lambda/triage"
  output_path = "${path.module}/build/triage.zip"
}

# Created explicitly rather than letting Lambda auto-create it on first
# invocation. Two reasons: an auto-created group has NO retention policy
# and keeps logs forever, and the function would need logs:CreateLogGroup
# permission across the account to make one.
resource "aws_cloudwatch_log_group" "triage" {
  name              = "/aws/lambda/${var.project_name}-triage"
  retention_in_days = var.log_retention_days
}

# Events that fail all retries land here instead of vanishing. A security
# pipeline that silently drops findings is worse than no pipeline, because
# you believe you have coverage that you do not.
resource "aws_sqs_queue" "triage_dlq" {
  name                      = "${var.project_name}-triage-dlq"
  message_retention_seconds = 1209600 # 14 days, the maximum
  sqs_managed_sse_enabled   = true
}

resource "aws_lambda_function" "triage" {
  function_name = "${var.project_name}-triage"
  role          = aws_iam_role.triage.arn

  # "file.function" — handler.py, function lambda_handler.
  handler = "handler.lambda_handler"
  runtime = "python3.12"

  filename = data.archive_file.triage.output_path

  # Without this, Terraform compares only the filename and never notices
  # that the code inside changed. A very common cause of "I deployed but
  # my change isn't live".
  source_code_hash = data.archive_file.triage.output_base64sha256

  timeout     = 30
  memory_size = 256

  # Caps blast radius and cost. A malformed event storm cannot spin up
  # hundreds of concurrent executions.
  reserved_concurrent_executions = 10

  environment {
    variables = {
      DEDUPE_TABLE     = aws_dynamodb_table.dedupe.name
      AUDIT_TABLE      = aws_dynamodb_table.audit.name
      SNS_TOPIC_ARN    = data.aws_sns_topic.alerts.arn
      MIN_SEVERITY     = tostring(var.min_severity)
      DEDUPE_TTL_HOURS = tostring(var.dedupe_ttl_hours)
      LOG_LEVEL        = var.log_level
    }
  }

  dead_letter_config {
    target_arn = aws_sqs_queue.triage_dlq.arn
  }

  # Active tracing. For a project that reports latency figures, being able to
  # see where the time actually goes is the point.
  tracing_config {
    mode = "Active"
  }


  # The log group must exist before the function runs, and nothing in the
  # function config references it.
  depends_on = [aws_cloudwatch_log_group.triage]
}