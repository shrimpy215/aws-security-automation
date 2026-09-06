# Design decisions

Each entry records a choice, the reasoning behind it, and what it cost.
Alternatives were available in every case.

## Structure

### 1. Three Terraform stacks, split by lifetime rather than by service

**Decision.** `guardrails/` (permanent), `detection/` (project duration),
`workload/` (destroyed every session).

**Why.** Grouping by service would have put a KMS key that takes seven days to
delete in the same state file as a Lambda function that redeploys in seconds.
Lifetime is the property that actually governs how a resource is operated.

**Cost.** Three `terraform init` directories instead of one. The workload stack
finds the KMS key and SNS topic by name via data sources, so no remote state
plumbing was needed and the stacks stay genuinely independent.

### 2. The cost guardrail lives in its own state file

**Decision.** The account budget is deployed separately and never destroyed.

**Why.** A budget defined inside the workload stack would be destroyed with it.
The moment you most need a spending alarm is the moment you *thought* you had
torn everything down.

**Cost.** One more directory. AWS Budgets is free for the first two budgets.

### 3. AWS Config enabled, behind a variable

**Decision.** `enable_aws_config` defaults to true.

**Why.** Most Security Hub CIS and FSBP controls evaluate Config configuration
items. Without a recorder the standards enable but the compliance score is
meaningless.

**Cost.** Config has no free tier and bills per configuration item.

Estimated at roughly thirty cents. **Actual: $2.23**, which was 76% of the
project's entire AWS spend. Recording all supported resource types including
global, across several apply and destroy cycles, generates far more
configuration items than the estimate assumed — every resource created and
destroyed is itself a recorded change.

Corrected here rather than left as the original guess. Made a variable so the
tradeoff is visible and reversible; on a longer-running project, narrowing
`recording_group` to the resource types the enabled controls actually evaluate
would be the obvious optimisation.

### 4. SSM Incident Manager excluded from scope

**Decision.** Not implemented, despite appearing in the project blueprint.

**Why.** It requires contact records, response plans, and escalation chains
that add cost and surface area without demonstrating anything the audit trail
and SNS alerting do not already show.

**Cost.** One blueprint item unaddressed. Recorded here rather than omitted
silently.

## Detection

### 5. GuardDuty optional data sources explicitly disabled

**Decision.** S3 Data Events, EKS Audit Logs, EBS Malware Protection, RDS Login
Events and Lambda Network Logs are all set to `DISABLED` in code.

**Why.** New detectors enable several by default, and each carries a per-GB or
per-scan charge. None are needed to exercise this pipeline. Writing the
decision down beats inheriting a default.

**Cost.** Five resources that exist only to turn things off. A reviewer can see
the choice was deliberate.

### 6. Consolidated control findings

**Decision.** `control_finding_generator = "SECURITY_CONTROL"`.

**Why.** CIS and FSBP overlap heavily. Under the older behaviour, root MFA
being disabled produces two findings for one problem. This produces one finding
listing both standards.

**Cost.** None. Removes a class of duplicates before the pipeline sees them.

### 7. Thirty-minute create timeout on standards subscriptions

**Decision.** `timeouts { create = "30m" }` on
`aws_securityhub_standards_subscription`.

**Why.** The provider's three-minute default is shorter than first-time
enablement in a fresh account. The subscription is created successfully; only
the readiness poll times out — but Terraform then taints the resource and every
later apply plans a needless replacement.

**Cost.** A slow first apply. Discovered the hard way; see troubleshooting.

### 8. RUNTIME_MONITORING declared outside the feature map

**Decision.** Its own resource block rather than an entry in the `for_each` map.

**Why.** AWS returns three `additional_configuration` sub-settings for that
feature. A map holds name/status pairs and cannot express nested blocks, so the
provider treated them as unmanaged drift and planned to remove them on every
run — a diff that never converges.

**Cost.** Duplicated block. Buys a plan that reaches zero changes, which is what
makes "no changes" meaningful.

## Data model

### 9. Two DynamoDB tables, not one

**Decision.** A dedupe table with TTL and no point-in-time recovery, and an
audit table with recovery and no TTL.

**Why.** Suppression state is supposed to expire — that expiry is the mechanism
that reopens the alert window. An audit record must never expire. Two
requirements in direct opposition cannot share a retention policy.

**Cost.** Two tables to manage. Both on-demand billing, effectively free at
this volume.

### 10. Deduplication keys on meaning, not identity

**Decision.** The fingerprint is `sha256(source | finding_type | resource_id)`,
not the finding ID.

**Why.** Two separate findings describing the same problem on the same instance
are the same problem. The finding ID would keep them apart, and the fiftieth
occurrence overnight would produce a fiftieth email.

**Cost.** Genuinely distinct problems that share a type and a resource collapse
into one alert. Acceptable: an analyst investigating the first will find the
second.

### 11. Conditional write rather than read-then-write

**Decision.** `ConditionExpression="attribute_not_exists(fingerprint)"`, catching
`ConditionalCheckFailedException`.

**Why.** Two Lambda containers can process the same finding simultaneously. A
read followed by a write lets both see "not present" and both alert. DynamoDB
performs the check and the write as one atomic operation.

**Cost.** Exception handling instead of an `if`. Removes a race that would only
appear under load, which is the worst time to find it.

### 12. Below-threshold findings are recorded, not just logged

**Decision.** A finding rejected as too low still gets a `BELOW_THRESHOLD` row
in the audit table.

**Why.** "We saw this and decided not to escalate" is a decision an investigator
or auditor would want proof of. CloudWatch Logs expire after fourteen days; the
audit table does not.

**Cost.** More rows. Changed late, after the gap was noticed reviewing test
output.

## Containment

### 13. Two Lambda functions with separate IAM roles

**Decision.** Triage and remediation are separate functions, not one function
with a branch.

**Why.** The remediation role holds `ec2:ModifyInstanceAttribute` and
`iam:UpdateAccessKey`. Sharing a role would mean a parsing bug in the triage
path could reach a destructive API call.

**Cost.** Duplicated boilerplate — two roles, two log groups, two dead letter
queues. The blast radius of a bug is bounded by which function contains it.

### 14. The tag guardrail is enforced twice

**Decision.** The Python checks for `SecurityAutomation=enabled`, and the IAM
policy attaches an `aws:ResourceTag` condition to the same effect.

**Why.** Code can have bugs. An IAM condition is evaluated by AWS and cannot be
bypassed by one. The quarantine security group is granted separately by exact
ARN, so no other group can ever be applied.

**Cost.** The check exists in two places and both must be kept in step. Worth
it: this is the control that stands between an automation bug and an outage.

### 15. Dry run defaults to on

**Decision.** `DRY_RUN` is true unless explicitly set to the string `false`.

**Why.** A missing or misspelled environment variable must produce no action
rather than unintended action. Fail safe, not fail open.

**Cost.** Live containment requires a deliberate config change and a redeploy.
That friction is the feature.

### 16. Isolation swaps security groups; it does not stop the instance

**Decision.** Containment replaces the instance's groups with a deny-all
quarantine group.

**Why.** Stopping the instance destroys memory and running process state —
exactly the volatile evidence a forensic investigator needs. Network isolation
achieves containment without destroying the artefact.

**Cost.** A compromised process keeps running locally. It can no longer reach
anything, and it can still be examined.

### 17. Access keys are deactivated, never deleted

**Decision.** `iam:UpdateAccessKey` to `Inactive`, not `DeleteAccessKey`.

**Why.** Reversible if the finding is a false positive, and the key remains
available for working out what it was used for.

**Cost.** The key still exists and must be cleaned up deliberately later.

## Operations

### 18. Severity is filtered in different places for the two functions

**Decision.** The triage rule forwards every finding and filters in Python. The
remediation rule filters at the router.

**Why.** A finding rejected as too low is evidence the pipeline is working and
belongs in the audit trail, so triage must see it. Remediation holds destructive
permissions, so the fewer times it is invoked at all, the better.

**Cost.** The two rules look inconsistent until the reasoning is stated. Stated
here.

### 19. The Security Hub event rule ships disabled

**Decision.** `enable_securityhub_rule` defaults to false; the rule is created
in the `DISABLED` state.

**Why.** When standards finish enabling, Security Hub imports several hundred
control findings at once. Each is a distinct fingerprint, so deduplication does
not suppress them, and every HIGH or CRITICAL one would produce an email.

**Cost.** One more variable to remember. Turning it on is a deliberate act
performed while watching.

### 20. No queue between EventBridge and Lambda

**Decision.** EventBridge invokes the functions directly.

**Why.** Simplicity, for a stack destroyed nightly.

**Cost.** EventBridge is fire-and-forget. A finding raised while the workload
stack is down is discarded, not buffered. A production deployment that could
not tolerate that would put SQS in the path. Accepted knowingly, not overlooked.

### 21. No access key is created by Terraform

**Decision.** The demo IAM user is created with `force_destroy = true` and no
`aws_iam_access_key` resource. The verification script creates a key via the CLI
when a test needs one.

**Why.** Terraform state stores every attribute in plaintext, including secrets.
Project 2 went to some trouble to keep a database password out of state;
putting an access key back in for a demo would undo that principle for no
reason.

**Cost.** One manual step in the credential-revocation test.

### 22. The provider lock file is gitignored

**Decision.** `.terraform.lock.hcl` is not committed.

**Why.** In a team repository it should be, so everyone resolves identical
provider versions. For a solo portfolio repository with versions pinned
explicitly in `versions.tf`, committing it mainly produces platform-specific
hash churn on Apple Silicon.

**Cost.** A clone may resolve a different patch version. Acceptable given the
explicit pins; the reasoning is recorded because the default advice is the
opposite.
