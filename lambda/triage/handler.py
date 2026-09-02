"""
Security finding triage.

Receives GuardDuty and Security Hub findings from EventBridge, normalizes
them into a single internal shape, filters by severity, suppresses repeats
within a TTL window, records an audit entry, and publishes an alert.

Severity is normalized to the ASFF 0-100 scale throughout:
    0       INFORMATIONAL
    1-39    LOW
    40-69   MEDIUM
    70-89   HIGH
    90-100  CRITICAL
"""

import hashlib
import json
import logging
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

# Clients are created at MODULE level, not inside the handler. Lambda reuses
# a warm container across invocations, so this runs once per container rather
# than once per event. Creating a boto3 client costs ~100ms; doing it inside
# the handler would pay that on every single finding.
dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

# os.environ[...] with square brackets raises KeyError if the variable is
# missing, failing loudly at container start. os.environ.get() would return
# None and fail later with a confusing error. Fail early, fail obviously.
DEDUPE_TABLE = os.environ["DEDUPE_TABLE"]
AUDIT_TABLE = os.environ["AUDIT_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]

MIN_SEVERITY = int(os.environ.get("MIN_SEVERITY", "40"))
DEDUPE_TTL_HOURS = int(os.environ.get("DEDUPE_TTL_HOURS", "24"))

dedupe_table = dynamodb.Table(DEDUPE_TABLE)
audit_table = dynamodb.Table(AUDIT_TABLE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def severity_label(normalized):
    """Convert a 0-100 severity score to its ASFF label."""
    if normalized >= 90:
        return "CRITICAL"
    if normalized >= 70:
        return "HIGH"
    if normalized >= 40:
        return "MEDIUM"
    if normalized >= 1:
        return "LOW"
    return "INFORMATIONAL"


def now_iso():
    """Current UTC time as an ISO 8601 string."""
    return datetime.now(timezone.utc).isoformat()


def fingerprint(finding):
    """
    Build the deduplication key.

    Deliberately NOT the finding ID. Two separate findings describing the
    same problem on the same resource should collapse into one alert, and
    the finding ID would keep them apart. Type plus resource captures what
    an analyst would call "the same issue".
    """
    raw = "{}|{}|{}".format(
        finding["source"],
        finding["finding_type"],
        finding["resource_id"],
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


# ---------------------------------------------------------------------------
# Normalization: two input shapes, one output shape
# ---------------------------------------------------------------------------

def normalize_guardduty(event):
    """Convert a GuardDuty Finding event into the internal shape."""
    detail = event["detail"]
    resource = detail.get("resource", {})
    resource_type = resource.get("resourceType", "Unknown")

    # GuardDuty nests the identifier differently per resource type. These
    # three are the ones our Stage 4 remediation can act on.
    resource_id = "unknown"
    if resource_type == "Instance":
        resource_id = resource.get("instanceDetails", {}).get(
            "instanceId", "unknown")
    elif resource_type == "AccessKey":
        resource_id = resource.get("accessKeyDetails", {}).get(
            "userName", "unknown")
    elif resource_type == "S3Bucket":
        buckets = resource.get("s3BucketDetails") or []
        if buckets:
            resource_id = buckets[0].get("name", "unknown")

    # GuardDuty severity is 1-10. Multiply by 10 for the ASFF 0-100 scale.
    normalized = int(float(detail.get("severity", 0)) * 10)
    region = detail.get("region", event.get("region", "us-east-1"))
    finding_id = detail.get("id", "unknown")

    return {
        "source": "guardduty",
        "finding_id": finding_id,
        "finding_type": detail.get("type", "Unknown"),
        "title": detail.get("title", "GuardDuty finding"),
        "description": detail.get("description", ""),
        "severity_normalized": normalized,
        "severity_label": severity_label(normalized),
        "resource_type": resource_type,
        "resource_id": resource_id,
        "account_id": detail.get("accountId", event.get("account", "unknown")),
        "region": region,
        "created_at": detail.get("createdAt", now_iso()),
        "console_url": (
            "https://{r}.console.aws.amazon.com/guardduty/home"
            "?region={r}#/findings?macros=current&fId={f}"
        ).format(r=region, f=finding_id),
    }


def normalize_securityhub(finding, event):
    """Convert one ASFF finding from a Security Hub event into the internal shape."""
    severity = finding.get("Severity", {})
    normalized = int(severity.get("Normalized", 0))

    resources = finding.get("Resources") or []
    first = resources[0] if resources else {}

    region = finding.get("Region", event.get("region", "us-east-1"))

    # ASFF Types is a list like ["Software and Configuration Checks/..."].
    types = finding.get("Types") or []
    finding_type = types[0] if types else finding.get("GeneratorId", "Unknown")

    return {
        "source": "securityhub",
        "finding_id": finding.get("Id", "unknown"),
        "finding_type": finding_type,
        "title": finding.get("Title", "Security Hub finding"),
        "description": finding.get("Description", ""),
        "severity_normalized": normalized,
        "severity_label": severity.get("Label") or severity_label(normalized),
        "resource_type": first.get("Type", "Unknown"),
        "resource_id": first.get("Id", "unknown"),
        "account_id": finding.get("AwsAccountId", event.get("account", "unknown")),
        "region": region,
        "created_at": finding.get("CreatedAt", now_iso()),
        "console_url": (
            "https://{r}.console.aws.amazon.com/securityhub/home"
            "?region={r}#/findings"
        ).format(r=region),
    }


def extract_findings(event):
    """
    Return a list of normalized findings from any supported event.

    GuardDuty sends one finding per event. Security Hub sends a batch in
    detail.findings. Returning a list from both means the handler loop
    doesn't need to know the difference.
    """
    source = event.get("source", "")

    if source == "aws.guardduty":
        return [normalize_guardduty(event)]

    if source == "aws.securityhub":
        findings = event.get("detail", {}).get("findings") or []
        results = []
        for f in findings:
            # Skip anything an analyst has already dealt with.
            if f.get("RecordState") == "ARCHIVED":
                continue
            if f.get("Workflow", {}).get("Status") in ("SUPPRESSED", "RESOLVED"):
                continue
            results.append(normalize_securityhub(f, event))
        return results

    LOG.warning(json.dumps({
        "message": "unrecognized event source",
        "source": source,
    }))
    return []


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def claim_fingerprint(fp, finding):
    """
    Attempt to claim this fingerprint as a NEW finding.

    Returns True if this is the first time we have seen it inside the TTL
    window, False if it is a repeat.

    The conditional write is what makes this safe. Two Lambda containers can
    process the same finding simultaneously; DynamoDB guarantees only one
    write succeeds. A read-then-write would let both see "not present" and
    both send an alert.
    """
    expires_at = int(time.time()) + (DEDUPE_TTL_HOURS * 3600)

    try:
        dedupe_table.put_item(
            Item={
                "fingerprint": fp,
                "first_seen": now_iso(),
                "last_seen": now_iso(),
                "occurrence_count": 1,
                "finding_type": finding["finding_type"],
                "resource_id": finding["resource_id"],
                "severity_label": finding["severity_label"],
                "expires_at": expires_at,
            },
            ConditionExpression="attribute_not_exists(fingerprint)",
        )
        return True

    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ConditionalCheckFailedException":
            raise

        # Already present: record the repeat but do not alert again.
        dedupe_table.update_item(
            Key={"fingerprint": fp},
            UpdateExpression=(
                "SET last_seen = :now ADD occurrence_count :one"
            ),
            ExpressionAttributeValues={":now": now_iso(), ":one": 1},
        )
        return False


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_audit(finding, fp, action, detail=""):
    """Append an immutable record of what happened to this finding."""
    audit_table.put_item(Item={
        "finding_id": finding["finding_id"],
        "event_time": now_iso(),
        "action": action,
        "detail": detail,
        "fingerprint": fp,
        "source": finding["source"],
        "finding_type": finding["finding_type"],
        "title": finding["title"],
        "severity_label": finding["severity_label"],
        "severity_normalized": finding["severity_normalized"],
        "resource_type": finding["resource_type"],
        "resource_id": finding["resource_id"],
        "account_id": finding["account_id"],
        "region": finding["region"],
        "finding_created_at": finding["created_at"],
    })


def publish_alert(finding, fp):
    """Send the human-readable alert."""
    subject = "[{}] {}".format(
        finding["severity_label"],
        finding["title"],
    )[:100]  # SNS subject limit

    body = "\n".join([
        "SECURITY FINDING",
        "",
        "Severity:    {} ({}/100)".format(
            finding["severity_label"], finding["severity_normalized"]),
        "Source:      {}".format(finding["source"]),
        "Type:        {}".format(finding["finding_type"]),
        "Resource:    {} ({})".format(
            finding["resource_id"], finding["resource_type"]),
        "Account:     {}".format(finding["account_id"]),
        "Region:      {}".format(finding["region"]),
        "Detected:    {}".format(finding["created_at"]),
        "",
        "Description:",
        finding["description"] or "(none provided)",
        "",
        "Console: {}".format(finding["console_url"]),
        "",
        "Fingerprint: {}".format(fp),
        "Repeats of this finding are suppressed for {} hours.".format(
            DEDUPE_TTL_HOURS),
    ])

    sns.publish(
        TopicArn=SNS_TOPIC_ARN,
        Subject=subject,
        Message=body,
    )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    """EventBridge invokes this with a GuardDuty or Security Hub event."""
    LOG.info(json.dumps({
        "message": "event received",
        "source": event.get("source"),
        "detail_type": event.get("detail-type"),
    }))

    findings = extract_findings(event)

    stats = {"received": len(findings), "below_threshold": 0,
             "suppressed": 0, "alerted": 0, "errors": 0}

    for finding in findings:
        try:
            if finding["severity_normalized"] < MIN_SEVERITY:
                stats["below_threshold"] += 1
                LOG.info(json.dumps({
                    "message": "below severity threshold",
                    "finding_id": finding["finding_id"],
                    "severity": finding["severity_normalized"],
                    "threshold": MIN_SEVERITY,
                }))
                continue

            fp = fingerprint(finding)

            if not claim_fingerprint(fp, finding):
                stats["suppressed"] += 1
                write_audit(finding, fp, "SUPPRESSED_DUPLICATE",
                            "within {}h dedupe window".format(DEDUPE_TTL_HOURS))
                LOG.info(json.dumps({
                    "message": "duplicate suppressed",
                    "finding_id": finding["finding_id"],
                    "fingerprint": fp,
                }))
                continue

            write_audit(finding, fp, "TRIAGED", "new finding, alert sent")
            publish_alert(finding, fp)
            stats["alerted"] += 1

            LOG.info(json.dumps({
                "message": "alert published",
                "finding_id": finding["finding_id"],
                "fingerprint": fp,
                "severity": finding["severity_label"],
            }))

        except Exception as exc:
            # One malformed finding must not discard the rest of the batch.
            stats["errors"] += 1
            LOG.error(json.dumps({
                "message": "finding processing failed",
                "finding_id": finding.get("finding_id", "unknown"),
                "error": str(exc),
            }))

    LOG.info(json.dumps({"message": "batch complete", **stats}))
    return stats
