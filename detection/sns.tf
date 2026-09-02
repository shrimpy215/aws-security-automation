# Alert topic. Lives in the detection stack because an email subscription
# requires manual confirmation — recreating it every session would mean
# clicking a new confirmation link every session, and an unconfirmed
# subscription discards messages silently.

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-security-alerts"

  # Encrypt messages at rest. Security findings name compromised resources
  # and account IDs; that is not data to leave unencrypted.
  kms_master_key_id = aws_kms_key.main.id
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}
