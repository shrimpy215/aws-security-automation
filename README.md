# aws-security-automation

Event-driven security monitoring and automated incident response on AWS.

GuardDuty and Security Hub findings are triaged, deduplicated, recorded, and —
behind four independent guardrails — acted on automatically. Built with
Terraform and Python 3.12, verified by a committed test harness, and documented
against NIST SP 800-61.

**Project 3 of 6** in an AWS solutions architecture and cloud security
portfolio.

**Status:** complete. Built, verified against live GuardDuty findings, and
destroyed. Teardown confirmed by querying AWS directly rather than trusting
`terraform destroy` output — see [docs/verification.md](docs/verification.md).
Redeploys from this repository in about three minutes.

- [Architecture brief](docs/architecture.html) — visual walkthrough
- [Executive summary](docs/executive-summary.md) — plain-English version
- [Incident response playbook](docs/incident-response-playbook.md) — NIST 800-61
- [Design decisions](docs/decisions.md) — 22 entries, with the tradeoffs
- [Verification](docs/verification.md) — evidence and known limitations
- [Troubleshooting](docs/troubleshooting.md) — what went wrong and why

## The problem

A threat is detected, an alert lands in an inbox, and a human eventually reads
it. That takes hours, works only during business hours, and stops working
altogether once the volume of alerts exceeds the attention available — which is
how most detection programs quietly fail.

This system performs the first several steps in seconds, around the clock, and
keeps a permanent record of every decision it made.

## Flow

    GuardDuty ─┐
               ├─→ EventBridge ─┬─→ Triage Lambda ─┬─→ SNS (email)
    Security ──┘                │                  ├─→ DynamoDB (dedupe, TTL 24h)
    Hub                         │                  └─→ DynamoDB (audit, no TTL)
                                │
                                └─→ Remediation Lambda ─┬─→ quarantine SG
                                    (severity >= 7.0)   ├─→ IAM key deactivation
                                                        └─→ DynamoDB (audit)

Two functions with two IAM roles. Only the remediation role holds
`ec2:ModifyInstanceAttribute` and `iam:UpdateAccessKey`, so a parsing bug in
triage cannot reach a destructive API call.

## Repository layout

    detection/    GuardDuty, Security Hub, Config, KMS, SNS   (project lifetime)
    workload/     Lambda, DynamoDB, EventBridge, IAM          (destroyed nightly)
    guardrails/   account budget and forecast alerting        (permanent)
    lambda/       Python source for both functions
    scripts/      verification harness, latency tool, fixtures
    docs/         decisions, playbook, verification, troubleshooting

Three Terraform stacks, split by **how long each piece should live** rather than
by service. The workload stack reads nothing from the others' state — it finds
the KMS key and SNS topic by name — so it can be torn down and rebuilt in about
thirty seconds without touching anything slow.

## Quick start

Requires Terraform >= 1.6, AWS CLI v2, and credentials for an account you are
willing to enable GuardDuty on.

    # 1. Cost guardrail first, before anything billable exists
    cd guardrails
    cp terraform.tfvars.example terraform.tfvars   # set alert_email
    terraform init && terraform apply

    # 2. Detection layer. Slow: standards take hours to reach READY.
    cd ../detection
    cp terraform.tfvars.example terraform.tfvars   # set alert_email
    terraform init && terraform apply
    # then confirm the SNS subscription email

    # 3. Workload. Fast, and safe to destroy between sessions.
    cd ../workload
    cp terraform.tfvars.example terraform.tfvars
    terraform init && terraform apply

    # 4. Prove it works
    cd ..
    ./scripts/verify.sh

Teardown is `terraform destroy` in `workload/`, then `detection/`. Leave
`guardrails/` alone — that is the point of it.

**Cost.** GuardDuty and Security Hub are free for 30 days. AWS Config bills from
the first minute and has no free tier, which is why it sits behind
`enable_aws_config`. Total for this build was under a dollar.

## Security posture

| Control | Implementation |
|---|---|
| Least-privilege IAM | No managed policies. Each role grants specific actions on specific ARNs. |
| Privilege separation | Destructive permissions isolated in a second function with its own role. |
| Tag-scoped containment | `aws:ResourceTag` condition on `ec2:ModifyInstanceAttribute`, enforced by AWS independently of the code. |
| Fail-safe default | Containment ships in dry-run mode; live action requires a deliberate config change. |
| Encryption at rest | Customer-managed KMS key with rotation, on both DynamoDB tables and the SNS topic. |
| No secrets in state | No `aws_iam_access_key` resource. Terraform state stores every attribute in plaintext. |
| Confused-deputy protection | `AWS:SourceAccount` conditions on every service principal grant. |
| Immutable audit trail | Append-only table, point-in-time recovery, no TTL, `PutItem` only. |
| Dead letter queues | Both functions. A security pipeline that silently drops findings is worse than none. |
| Reversible actions | Original security groups recorded before replacement; keys deactivated, not deleted. |
| Distributed tracing | Active X-Ray tracing on both functions, with `xray:Put*` scoped to the execution roles. |

## Verification

    ./scripts/verify.sh

Eighteen assertions across triage, guardrails, and audit completeness. Exits
non-zero, so CI can gate on it. It resets deduplication state first, which makes
it repeatable — a test you can only run once is not a test.

The harness earned its place immediately: it caught a live defect where a
Python indentation error had made the MEDIUM severity path unreachable. Manual
testing had exercised LOW after the change and MEDIUM before it, so neither run
saw the fault.

Full results and evidence in [docs/verification.md](docs/verification.md).

## Response time

Measured from live GuardDuty findings by
`scripts/measure_response_times.py`, reading the audit trail.

| Stage | Duration | Owned by |
|---|---|---|
| GuardDuty publish + EventBridge delivery | 1.2 – 4.8 min | AWS |
| Triage execution, cold | ~280 ms | this code |
| Triage execution, warm | ~38 ms | this code |
| Containment, once invoked | < 1 s | this code |

Median detection-to-decision was 3.0 minutes, nearly all of it AWS-side
publishing delay. **This is not MTTD in the NIST sense** — sample findings
describe events that never occurred, so there is no compromise time to measure
from. Reporting pipeline latency as MTTD would be the easy claim and the wrong
one.

## Limitations

1. Single account, single region. Cross-account aggregation is Project 5.
2. EventBridge is fire-and-forget — a finding raised while the workload stack is
   down is lost, not queued. Accepted deliberately for a stack destroyed nightly.
3. Containment covers EC2 network isolation and IAM key deactivation only.
4. Tag-based scoping depends on tag hygiene. An untagged resource that should be
   in scope will never be contained — a governance dependency, and the most
   likely real-world failure mode of the design.

## What this demonstrates

Projects 1 and 2 demonstrate building secure infrastructure. This one
demonstrates operating it — what happens after a control fires, who finds out,
how quickly, and what the system is permitted to do without asking.

Each project in the portfolio is a standalone deployment. This one shares no
resources with the earlier two; what carries forward is the conventions —
lifecycle-split stacks, a decisions log, committed verification, and CI with
justified exceptions rather than suppressed findings.

The deduplication and audit design are the substance for a security operations
audience. The IAM is the substance for an architecture audience — a function
holding genuinely destructive permissions, constrained by a resource-tag
condition AWS evaluates independently of the code that also checks it.
