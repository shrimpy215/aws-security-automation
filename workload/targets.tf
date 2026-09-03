# ---------------------------------------------------------------------------
# Quarantine security group
#
# Created unconditionally — the remediation function needs its ID whether or
# not demo targets exist.
#
# A Terraform-managed security group with NO ingress or egress blocks is
# fully closed. Terraform explicitly revokes the allow-all egress rule that
# AWS adds to every new group, so this permits nothing in either direction.
# ---------------------------------------------------------------------------

data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "quarantine" {
  name        = "${var.project_name}-quarantine"
  description = "Deny all traffic. Applied to isolate a compromised instance."
  vpc_id      = data.aws_vpc.default.id

  tags = {
    Name    = "${var.project_name}-quarantine"
    Purpose = "incident containment"
  }
}

# ---------------------------------------------------------------------------
# Demo targets
#
# Throwaway resources that exist only to be contained and restored.
# Everything below is gated on var.deploy_demo_targets.
# ---------------------------------------------------------------------------

data "aws_subnets" "default" {
  count = var.deploy_demo_targets ? 1 : 0

  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# Resolves the current Amazon Linux 2023 AMI. Hardcoding an AMI ID would
# break in another region and rot as AWS publishes new images.
data "aws_ssm_parameter" "al2023" {
  count = var.deploy_demo_targets ? 1 : 0
  name  = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
}

# Baseline group with outbound access — so that isolation is observably
# different from the starting state.
resource "aws_security_group" "demo_target" {
  count = var.deploy_demo_targets ? 1 : 0

  name        = "${var.project_name}-demo-target"
  description = "Baseline group for the demo target, replaced on containment"
  vpc_id      = data.aws_vpc.default.id

  egress {
    description = "Outbound to anywhere. This is the access containment removes."
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.project_name}-demo-target"
  }
}

resource "aws_instance" "demo_target" {
  count = var.deploy_demo_targets ? 1 : 0

  ami           = data.aws_ssm_parameter.al2023[0].value
  instance_type = "t3.micro"
  subnet_id     = data.aws_subnets.default[0].ids[0]

  vpc_security_group_ids = [aws_security_group.demo_target[0].id]

  # No public IP, no key pair. Nothing can reach it and nobody logs in.
  associate_public_ip_address = false

  # IMDSv2 required. A CIS control checks this, so leaving it at the default
  # would have our own pipeline raise a finding about our own demo box.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  root_block_device {
    encrypted   = true
    volume_size = 8
    volume_type = "gp3"
  }

  tags = {
    Name    = "${var.project_name}-demo-target"
    Purpose = "remediation demonstration only"

    # THIS TAG is what makes the instance eligible for containment.
    # Without it, both the Lambda and the IAM policy refuse to act.
    (var.required_tag_key) = var.required_tag_value
  }
}

# IAM user representing compromised credentials.
#
# Deliberately created with NO access key. aws_iam_access_key would write
# the secret into terraform.tfstate in plaintext — the exact problem
# manage_master_user_password solved in Project 2. The verification script
# creates a key via the CLI when a test needs one, and force_destroy
# cleans up keys Terraform did not create.
resource "aws_iam_user" "demo_target" {
  count = var.deploy_demo_targets ? 1 : 0

  name          = "${var.project_name}-demo-compromised-user"
  force_destroy = true

  tags = {
    Purpose = "remediation demonstration only"

    (var.required_tag_key) = var.required_tag_value
  }
}