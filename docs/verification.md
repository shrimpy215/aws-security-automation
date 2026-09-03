# Verification

Evidence that this system does what the README claims. Every result below is
reproducible from a clean deploy with the commands given.

**Last run:** 2026-09-03
**Region:** us-east-1

## Reproducing

    cd detection  && terraform apply    # leave running; standards take hours
    cd guardrails && terraform apply    # permanent, deployed once
    cd workload   && terraform apply    # destroyed and recreated freely

    ./scripts/verify.sh

    python3 -m venv .venv && ./.venv/bin/pip install boto3
    ./.venv/bin/python scripts/measure_response_times.py

## Automated assertions

`./scripts/verify.sh` — **18 passed, 0 failed.**

| Check | Result |
|---|---|
| Triage function deployed | PASS |
| Remediation function deployed | PASS |
| GuardDuty detector exists | PASS |
| Deduplication state cleared for a repeatable run | PASS |
| MEDIUM finding produces an alert | PASS |
| Identical finding suppressed as duplicate | PASS |
| No second alert sent for the duplicate | PASS |
| LOW finding filtered below threshold | PASS |
| No alert sent below threshold | PASS |
| MEDIUM finding refused for containment | PASS |
| Refusal reason names the severity threshold | PASS |
| Unverifiable resource refused | PASS |
| Refusal reason names the failed tag check | PASS |
| Tagged instance passes all guardrails (dry run, no action) | PASS |
| Audit trail contains TRIAGED | PASS |
| Audit trail contains SUPPRESSED_DUPLICATE | PASS |
| Audit trail contains BELOW_THRESHOLD | PASS |
| Audit trail contains REMEDIATION_REFUSED | PASS |

Every finding entering the system leaves a record of the decision made about
it, including findings deliberately not acted on.

## Containment, demonstrated live

Executed against a tagged throwaway EC2 instance with `remediation_dry_run`
set to `false`.

Before:

    GroupId                 GroupName
    sg-01a4088adb87e7cdb    secops-demo-target

Invocation response:

    {"action": "CONTAINED_INSTANCE",
     "detail": "security groups replaced with quarantine group"}

After:

    GroupId                 GroupName
    sg-069ca8449127026db    secops-quarantine

Audit record, including the rollback path:

    {"performed": true,
     "detail": "security groups replaced with quarantine group",
     "original_security_groups": ["sg-01a4088adb87e7cdb"]}

The original security group is recorded so containment can be reversed from
the audit trail alone.

### Credential revocation

    BEFORE   AKIA...   Active
    AFTER    AKIA...   Inactive

Keys are deactivated rather than deleted: reversible if the finding proves to
be a false positive, and still available for investigation.

## Response latency

Measured from live GuardDuty sample findings, whose createdAt timestamps are
set by AWS. Synthetic test fixtures are excluded: their timestamps are
hardcoded, so any interval measured from them is meaningless.

| Finding type | Detection to triage |
|---|---|
| Trojan:EC2/BlackholeTraffic | 1.2 min |
| Backdoor:EC2/Spambot | 4.8 min |

**Median 3.0 min. Range 1.2 - 4.8 min.**

### What this does and does not measure

MTTD in the NIST SP 800-61 sense is the interval between compromise and
detection. That is not measurable here: sample findings describe events that
never occurred, so there is no compromise time to measure from.

What is measured is the interval this system controls - from GuardDuty
publishing a finding to a decision being recorded in the audit trail.

That interval is dominated by AWS-side publishing and EventBridge delivery,
which this system does not control. The pipeline's own contribution:

| Stage | Duration |
|---|---|
| GuardDuty publish + EventBridge delivery | 1.2 - 4.8 min |
| Lambda cold start (init) | ~415 ms |
| Lambda execution, cold | ~280 ms |
| Lambda execution, warm | ~38 ms |

Containment adds under one second once a finding arrives. Any improvement to
end-to-end response time would have to come from the detection source, not
from this code. Reporting a single blended figure would obscure that.

## Known limitations

1. Sample findings reference non-existent instances. Every GuardDuty sample
   uses i-99999999, so live findings always hit the "cannot verify tags"
   guardrail. Containment was demonstrated separately against a real tagged
   instance via direct invocation.

2. EventBridge is fire-and-forget. A finding raised while the workload stack
   is destroyed is discarded, not queued. Accepted deliberately for a stack
   torn down between sessions; a production deployment would place a queue
   between the rule and the consumer.

3. Single-account, single-region. Multi-account aggregation is Project 5.

4. Latency sample size is small - two to four findings per run. The figures
   above are indicative, not statistically robust.
