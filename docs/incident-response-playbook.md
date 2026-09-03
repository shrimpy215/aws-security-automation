# Incident Response Playbook

Aligned to **NIST SP 800-61r2**, *Computer Security Incident Handling Guide*.

This playbook documents how automated detection and containment in this account
fit into a defensible incident response process — including, explicitly, where
the automation stops and a human is required.

**Scope.** One AWS account, us-east-1. Findings from Amazon GuardDuty and AWS
Security Hub. Automated containment is limited to EC2 instances and IAM access
keys carrying the tag `SecurityAutomation=enabled`.

**Out of scope.** Multi-account aggregation, on-premises systems, application
layer logging, and any resource not carrying the opt-in tag.

## Roles

| Role | Responsibility |
|---|---|
| Automated pipeline | Detect, triage, deduplicate, alert, record. Contain within its guardrails. |
| Responder (human) | Validate the finding, decide on eradication, authorise anything outside the guardrails, own recovery. |
| Account owner | Approve changes to the guardrails themselves — the tag scheme, thresholds, and protected allow-list. |

In a single-operator portfolio account, all three are the same person. They are
separated here because the boundaries matter more than the headcount: the
account owner approving a threshold change is a different act from a responder
handling an alert, and conflating them is how automation scope creeps.

## Severity classification

Severity is normalized to the ASFF 0-100 scale throughout, so GuardDuty's 1-10
scale and Security Hub's labels can be compared directly.

| Label | Normalized | Alert | Automated containment | Human response |
|---|---|---|---|---|
| CRITICAL | 90-100 | Yes | Yes, if tagged in scope | Immediate |
| HIGH | 70-89 | Yes | Yes, if tagged in scope | Within the hour |
| MEDIUM | 40-69 | Yes | No | Next business day |
| LOW | 1-39 | No | No | Reviewed in aggregate |
| INFORMATIONAL | 0 | No | No | Not reviewed individually |

**Containment threshold is deliberately higher than the alert threshold.**
MEDIUM findings wake a person; only HIGH and above permit the system to act on
its own. The gap between those two lines is where the judgement lives.

## Phase 1 — Preparation

*NIST 800-61 §3.1*

Controls established before any incident occurs.

| Control | Implementation |
|---|---|
| Continuous detection | GuardDuty analysing CloudTrail management events, VPC Flow Logs and DNS queries |
| Compliance baseline | Security Hub with CIS AWS Foundations v3.0.0 and AWS Foundational Security Best Practices |
| Configuration record | AWS Config recorder with global resource types, providing the evidence those controls evaluate |
| Alert channel | KMS-encrypted SNS topic with a confirmed subscription |
| Evidence store | DynamoDB audit table, append-only, point-in-time recovery enabled, no expiry |
| Containment capability | Pre-provisioned deny-all quarantine security group |
| Scope definition | Resource tag `SecurityAutomation=enabled`, enforced in code and by IAM condition |
| Protected assets | Allow-list of resources never eligible for automated action |
| Safe default | Containment ships in dry-run mode; live action requires a deliberate configuration change |

**Preparation gap worth naming.** The quarantine security group is pre-created
rather than built on demand. This is deliberate: creating a security group
during an incident adds an API call that can fail at the worst moment, and
grants the automation `ec2:CreateSecurityGroup`, which is a far broader
permission than applying one that already exists.

## Phase 2 — Detection and Analysis

*NIST 800-61 §3.2*

### Automated

1. GuardDuty or Security Hub publishes a finding to EventBridge.
2. The triage rule forwards it; the function normalizes both source formats into
   one internal shape.
3. Severity is evaluated against the alert threshold. Below it, the finding is
   recorded as `BELOW_THRESHOLD` and no alert is sent.
4. A fingerprint of finding type plus affected resource is claimed by conditional
   write. If already held, the finding is recorded as `SUPPRESSED_DUPLICATE` and
   the occurrence counter is incremented.
5. Otherwise the finding is recorded as `TRIAGED`, enriched with a console deep
   link, and published to the alert topic.

### Human

6. Validate the finding. GuardDuty produces false positives; the alert is a
   prompt to investigate, not a verdict.
7. Determine scope. Query the audit table by `finding_id` for the full
   chronological history of what the system saw and did.
8. Classify: true positive, false positive, or duplicate of an incident already
   open.

## Phase 3 — Containment, Eradication and Recovery

*NIST 800-61 §3.3*

### Containment strategy

NIST requires containment decisions to weigh potential damage, evidence
preservation, service availability, and the duration of the solution. Those
criteria produced these choices:

| Criterion | Decision |
|---|---|
| Evidence preservation | Isolate the network; do **not** stop the instance. Stopping destroys memory and process state a forensic investigator needs. |
| Service availability | Only tagged resources are eligible. Anything whose isolation would cause an outage worse than the incident is either untagged or on the protected allow-list. |
| Duration | Containment is reversible. The original security groups are written to the audit trail at the moment of action. |
| Damage potential | Threshold set at HIGH. Automated action on MEDIUM findings risks taking production down over a port scan. |

### Playbook A — Compromised EC2 instance

**Trigger.** GuardDuty finding at severity 7.0+ with `resourceType: Instance`.

**Automated.**
1. Guardrails evaluated in order: protected allow-list, severity, required tag,
   dry-run flag. Any failure produces `REMEDIATION_REFUSED` naming the gate.
2. Current security groups read and recorded.
3. Groups replaced with the quarantine group. Ingress and egress both denied.
4. `CONTAINED_INSTANCE` written to the audit trail with the original group IDs.
5. Alert published stating what was done and to which resource.

**Human.**
6. Confirm isolation took effect with `aws ec2 describe-instances`.
7. Preserve evidence before any further change — snapshot the EBS volumes.
8. Investigate: CloudTrail for the instance role's API activity, VPC Flow Logs
   for attempted egress after containment.
9. Eradicate: terminate and rebuild from a known-good AMI. **Do not** attempt to
   clean a compromised instance in place.
10. Recover: restore service from the rebuilt instance.

**Rollback.** The original group IDs are in the audit row's
`remediation_context`. Reversal is one `modify-instance-attribute` call.

### Playbook B — Compromised IAM credentials

**Trigger.** GuardDuty finding at severity 7.0+ with `resourceType: AccessKey`.

**Automated.**
1. Same four guardrails; the tag is checked against the IAM user.
2. All active access keys for the user set to `Inactive`.
3. `REVOKED_CREDENTIALS` written to the audit trail with the affected key IDs.
4. Alert published.

**Human.**
5. Review CloudTrail for every action taken with that key, from first use.
6. Assess blast radius: what the key's policies permitted, and what it did.
7. Eradicate: delete the key, rotate any credential it could have exposed, and
   review the user's policies for standing permissions that should not exist.
8. Recover: issue replacement credentials, or preferably replace the long-lived
   key with a role.

**Why deactivate rather than delete.** Deactivation stops the key immediately and
is reversible if the finding proves false. The key record remains available for
attribution during investigation. Deletion is an eradication step, taken by a
human after analysis.

## Phase 4 — Post-Incident Activity

*NIST 800-61 §3.4*

### Evidence available for review

Every finding that entered the system left a record, including those
deliberately not acted on. Querying the audit table by `finding_id` returns the
complete chronology:

    aws dynamodb query --table-name secops-audit-log \
      --key-condition-expression "finding_id = :f" \
      --expression-attribute-values '{":f":{"S":"<finding-id>"}}'

Recorded actions: `TRIAGED`, `SUPPRESSED_DUPLICATE`, `BELOW_THRESHOLD`,
`REMEDIATION_REFUSED`, `CONTAINED_INSTANCE`, `REVOKED_CREDENTIALS`,
`REMEDIATION_FAILED`.

A refusal is recorded with the specific guardrail that stopped it. That matters
for review: "the system declined to act, and here is why" is a defensible
position; "nothing happened" is not.

### Lessons-learned questions

NIST §3.4.1 prescribes a review meeting. For this system the questions that
matter are:

1. Was the severity threshold correct for this finding? A true positive that
   fell below the alert threshold is a threshold problem, not a detection one.
2. Did deduplication suppress something that should have alerted again? Check
   `occurrence_count` against the TTL window.
3. Was the affected resource correctly tagged? An untagged resource that should
   have been contained is a tagging failure, not an automation failure.
4. Did any guardrail refuse an action that should have proceeded? Repeated
   refusals of the same kind indicate a scope that no longer matches reality.
5. How much of the response time was AWS-side, and how much was ours?

### Metrics

Response times are computed from the audit trail by
`scripts/measure_response_times.py`. Current figures and their caveats are in
`docs/verification.md`.

**A deliberate omission.** MTTD in the NIST sense — compromise to detection — is
not reported. Sample findings describe events that never occurred, so there is
no compromise time to measure from. Reporting pipeline latency as MTTD would be
the easy claim and the wrong one. What is reported is the interval this system
controls, split between the part AWS owns and the part this code owns.

## Known limitations

1. **Single account, single region.** Cross-account aggregation would require
   Security Hub as a delegated administrator and a different IAM model.
2. **No queue between detection and response.** EventBridge is fire-and-forget;
   a finding raised while the workload stack is down is lost. Accepted for a
   stack destroyed nightly, and documented rather than overlooked.
3. **Containment scope is narrow.** EC2 network isolation and IAM key
   deactivation only. No S3 bucket policy remediation, no security group rule
   revocation, no Lambda disablement.
4. **Tag-based scoping depends on tag hygiene.** A resource that should be in
   scope but is untagged will never be contained. This is a governance
   dependency, not a technical one, and it is the most likely real-world failure
   mode of the whole design.
