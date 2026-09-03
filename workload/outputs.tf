output "quarantine_security_group_id" {
  description = "Security group applied to isolate a compromised instance."
  value       = aws_security_group.quarantine.id
}

output "demo_instance_id" {
  description = "Demo target instance, or null when demo targets are disabled."
  value       = var.deploy_demo_targets ? aws_instance.demo_target[0].id : null
}

output "demo_instance_security_groups" {
  description = "Baseline security groups on the demo target, for before/after comparison."
  value       = var.deploy_demo_targets ? aws_instance.demo_target[0].vpc_security_group_ids : null
}

output "demo_user_name" {
  description = "Demo IAM user, or null when demo targets are disabled."
  value       = var.deploy_demo_targets ? aws_iam_user.demo_target[0].name : null
}

output "remediation_dry_run" {
  description = "Whether containment actions are simulated. Printed on every apply so the mode is never a surprise."
  value       = var.remediation_dry_run
}
