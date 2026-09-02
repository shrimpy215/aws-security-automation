# ---------------------------------------------------------------------------
# AWS Config
#
# Security Hub's CIS and FSBP controls evaluate AWS Config configuration
# items. Without a recorder, the standards enable but most controls report
# "No data" and the compliance score is meaningless.
#
# Everything here is gated on var.enable_aws_config.
# ---------------------------------------------------------------------------

# --- Section 1: the S3 bucket Config writes to -----------------------------

# S3 bucket names are globally unique across ALL AWS accounts, so
# "secops-config" is almost certainly taken by a stranger. Account ID plus a
# random suffix makes collision effectively impossible.
resource "random_id" "config_bucket_suffix" {
  count       = var.enable_aws_config ? 1 : 0
  byte_length = 4
}

resource "aws_s3_bucket" "config" {
  count = var.enable_aws_config ? 1 : 0

  bucket = "${var.project_name}-config-${data.aws_caller_identity.current.account_id}-${random_id.config_bucket_suffix[0].hex}"

  # Project 1 lesson: destroy fails on a bucket that still has objects in it.
  # Config will have written history files by then.
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id

  versioning_configuration {
    status = "Enabled"
  }
}

# --- Section 2: bucket policy granting AWS Config write access -------------

data "aws_iam_policy_document" "config_bucket" {
  count = var.enable_aws_config ? 1 : 0

  # Config checks the bucket exists and it can see it, before writing.
  statement {
    sid       = "AWSConfigBucketPermissionsCheck"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl", "s3:ListBucket"]
    resources = [aws_s3_bucket.config[0].arn]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    # Confused-deputy protection: the Config SERVICE is the principal, and
    # the service exists in every AWS account. Without this condition,
    # Config acting on behalf of a DIFFERENT account could write here.
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # The actual delivery of configuration snapshots.
  statement {
    sid       = "AWSConfigBucketDelivery"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.config[0].arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Refuse any request that arrives over plain HTTP. Checkov and FSBP both
  # look for this; it is also just correct.
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.config[0].arn,
      "${aws_s3_bucket.config[0].arn}/*",
    ]

    principals {
      type        = "*"
      identifiers = ["*"]
    }

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  count  = var.enable_aws_config ? 1 : 0
  bucket = aws_s3_bucket.config[0].id
  policy = data.aws_iam_policy_document.config_bucket[0].json
}

# --- Section 3: the IAM role AWS Config assumes ----------------------------

data "aws_iam_policy_document" "config_assume_role" {
  count = var.enable_aws_config ? 1 : 0

  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_iam_role" "config" {
  count              = var.enable_aws_config ? 1 : 0
  name               = "${var.project_name}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume_role[0].json
}

# AWS-managed policy. Config needs broad read access to describe every
# resource type it records; writing that by hand would be thousands of lines
# and would break every time AWS ships a new service.
resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_aws_config ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWS_ConfigRole"
}

# --- Section 4: the recorder itself ----------------------------------------

resource "aws_config_configuration_recorder" "main" {
  count    = var.enable_aws_config ? 1 : 0
  name     = "${var.project_name}-recorder"
  role_arn = aws_iam_role.config[0].arn

  recording_group {
    all_supported = true

    # IAM users, roles, and policies are GLOBAL, not regional. Several CIS
    # controls check them. Without this, those controls have no data.
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "main" {
  count          = var.enable_aws_config ? 1 : 0
  name           = "${var.project_name}-delivery-channel"
  s3_bucket_name = aws_s3_bucket.config[0].bucket

  # Both of these are dependencies Terraform cannot infer.
  # The recorder must exist first, and the bucket POLICY must be in place
  # or AWS rejects the channel with InsufficientDeliveryPolicyException.
  depends_on = [
    aws_config_configuration_recorder.main,
    aws_s3_bucket_policy.config,
  ]
}

# Creating a recorder does not start it. This resource is the on switch.
resource "aws_config_configuration_recorder_status" "main" {
  count      = var.enable_aws_config ? 1 : 0
  name       = aws_config_configuration_recorder.main[0].name
  is_enabled = true

  # Starting before the delivery channel exists fails with
  # NoAvailableDeliveryChannelException.
  depends_on = [
    aws_config_delivery_channel.main,
    aws_iam_role_policy_attachment.config,
  ]
}
