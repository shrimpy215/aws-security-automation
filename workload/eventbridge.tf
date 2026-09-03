# ---------------------------------------------------------------------------
# GuardDuty findings
#
# No severity filter in the pattern. Severity filtering happens in the
# Lambda, for two reasons: EventBridge patterns cannot convert GuardDuty's
# 1-10 scale to the ASFF 0-100 scale, and findings rejected as below
# threshold are evidence the pipeline is working — we want them counted in
# the logs, not silently dropped at the router.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "guardduty" {
  name        = "${var.project_name}-guardduty-findings"
  description = "Route all GuardDuty findings to the triage function"

  event_pattern = jsonencode({
    source        = ["aws.guardduty"]
    "detail-type" = ["GuardDuty Finding"]
  })
}

resource "aws_cloudwatch_event_target" "guardduty" {
  rule      = aws_cloudwatch_event_rule.guardduty.name
  target_id = "triage-lambda"
  arn       = aws_lambda_function.triage.arn
}

# EventBridge cannot invoke a function just because a rule points at it.
# The function needs a resource-based policy granting the events service
# permission. Without this the rule matches, fires, and fails silently.
resource "aws_lambda_permission" "guardduty" {
  statement_id  = "AllowExecutionFromEventBridgeGuardDuty"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"

  # Scopes the grant to THIS rule. Without source_arn, any EventBridge rule
  # in the account could invoke this function.
  source_arn = aws_cloudwatch_event_rule.guardduty.arn
}

# ---------------------------------------------------------------------------
# Security Hub findings
#
# Filtered hard at the pattern level, and disabled by default. See the
# enable_securityhub_rule variable for why.
# ---------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "securityhub" {
  name        = "${var.project_name}-securityhub-findings"
  description = "Route HIGH and CRITICAL Security Hub findings to the triage function"

  state = var.enable_securityhub_rule ? "ENABLED" : "DISABLED"

  event_pattern = jsonencode({
    source        = ["aws.securityhub"]
    "detail-type" = ["Security Hub Findings - Imported"]
    detail = {
      findings = {
        Severity = {
          Label = ["HIGH", "CRITICAL"]
        }
        # ACTIVE excludes findings already archived. NEW excludes ones an
        # analyst has moved to NOTIFIED, SUPPRESSED, or RESOLVED — we do not
        # want to re-alert on something a human has already handled.
        RecordState = ["ACTIVE"]
        Workflow = {
          Status = ["NEW"]
        }
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "securityhub" {
  rule      = aws_cloudwatch_event_rule.securityhub.name
  target_id = "triage-lambda"
  arn       = aws_lambda_function.triage.arn
}

resource "aws_lambda_permission" "securityhub" {
  statement_id  = "AllowExecutionFromEventBridgeSecurityHub"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.triage.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub.arn
}