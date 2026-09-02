# ---------------------------------------------------------------------------
# Table 1: deduplication state
#
# One row per finding fingerprint. The triage Lambda attempts a conditional
# write; if the row already exists, this finding is a repeat and no alert is
# sent. TTL expires the row, which reopens the alert window — so activity
# that resumes after the window is treated as new, not silently swallowed.
#
# This data is DESIGNED to expire. That is the mechanism, not a compromise.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "dedupe" {
  name = "${var.project_name}-finding-dedupe"

  # No capacity planning, no idle cost. At this volume it is effectively
  # free, and it means the table costs nothing while sitting unused.
  billing_mode = "PAY_PER_REQUEST"

  hash_key = "fingerprint"

  attribute {
    name = "fingerprint"
    type = "S"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = data.aws_kms_alias.main.target_key_arn
  }

  # Suppression state is disposable by definition. Paying to recover it
  # point-in-time would be paying to recover something we delete on purpose.
  point_in_time_recovery {
    enabled = false
  }

  # Must stay false: this stack is destroyed at the end of every session.
  deletion_protection_enabled = false
}

# ---------------------------------------------------------------------------
# Table 2: audit trail
#
# Append-only record of every finding processed and every remediation action
# attempted. Composite key: many events can relate to one finding, ordered
# by time.
#
# NO TTL. An audit record that deletes itself is not an audit record.
# ---------------------------------------------------------------------------

resource "aws_dynamodb_table" "audit" {
  name         = "${var.project_name}-audit-log"
  billing_mode = "PAY_PER_REQUEST"

  # Partition key: which finding this is about.
  hash_key = "finding_id"

  # Sort key: when it happened. Together they are unique, and querying by
  # finding_id returns that finding's full history in chronological order.
  range_key = "event_time"

  attribute {
    name = "finding_id"
    type = "S"
  }

  attribute {
    name = "event_time"
    type = "S"
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = data.aws_kms_alias.main.target_key_arn
  }

  # Unlike the dedupe table, this one is worth being able to restore.
  point_in_time_recovery {
    enabled = true
  }

  deletion_protection_enabled = false
}
