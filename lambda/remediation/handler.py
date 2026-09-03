"""
Automated containment for high-severity security findings.

Invoked by EventBridge for GuardDuty findings at severity 7.0 and above.
Two actions are supported:

    Instance   -> replace security groups with a quarantine group
    AccessKey  -> deactivate the user's active access keys

Every action passes four independent guardrails and defaults to dry run.

Guardrails, in evaluation order:
    1. Protected allow-list  - named resources are never touched
    2. Severity threshold    - below it, refuse and alert only
    3. Required tag          - the resource must opt in by tag
    4. Dry run flag          - global switch, defaults to ON

The IAM role backing this function is ALSO tag-scoped, so guardrail 3 is
enforced twice: once here, once by AWS. Code can have bugs. The IAM policy
is the backstop that survives them.
"""

import json
import logging
import os
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

LOG = logging.getLogger()
LOG.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

ec2 = boto3.client("ec2")
iam = boto3.client("iam")
sns = boto3.client("sns")
dynamodb = boto3.resource("dynamodb")

AUDIT_TABLE = os.environ["AUDIT_TABLE"]
SNS_TOPIC_ARN = os.environ["SNS_TOPIC_ARN"]
QUARANTINE_SG_ID = os.environ["QUARANTINE_SG_ID"]

MIN_SEVERITY = int(os.environ.get("MIN_SEVERITY", "70"))
REQUIRED_TAG_KEY = os.environ.get("REQUIRED_TAG_KEY", "SecurityAutomation")
REQUIRED_TAG_VALUE = os.environ.get("REQUIRED_TAG_VALUE", "enabled")

# Defaults to TRUE. A missing or misspelled variable results in NO action
# rather than unintended action. Fail safe, not fail open.
DRY_RUN = os.environ.get("DRY_RUN", "true").lower() != "false"

# Comma-separated resource IDs that must never be touched, whatever else
# the finding says. The last line of defence against a bad tag.
PROTECTED = {
    r.strip()
    for r in os.environ.get("PROTECTED_RESOURCES", "").split(",")
    if r.strip()
}

audit_table = dynamodb.Table(AUDIT_TABLE)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.now(timezone.utc).isoformat()


def extract_target(event):
    """Pull the actionable resource out of a GuardDuty finding event."""
    detail = event.get("detail", {})
    resource = detail.get("resource", {})
    rtype = resource.get("resourceType", "Unknown")

    target = {
        "finding_id": detail.get("id", "unknown"),
        "finding_type": detail.get("type", "Unknown"),
        "title": detail.get("title", ""),
        "severity_normalized": int(float(detail.get("severity", 0)) * 10),
        "resource_type": rtype,
        "resource_id": None,
        "account_id": detail.get("accountId", event.get("account", "unknown")),
        "region": detail.get("region", event.get("region", "us-east-1")),
    }

    if rtype == "Instance":
        target["resource_id"] = resource.get(
            "instanceDetails", {}).get("instanceId")
    elif rtype == "AccessKey":
        target["resource_id"] = resource.get(
            "accessKeyDetails", {}).get("userName")

    return target


# ---------------------------------------------------------------------------
# Guardrails
# ---------------------------------------------------------------------------

def instance_has_required_tag(instance_id):
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            for tag in inst.get("Tags", []):
                if (tag["Key"] == REQUIRED_TAG_KEY
                        and tag["Value"] == REQUIRED_TAG_VALUE):
                    return True
    return False


def user_has_required_tag(user_name):
    resp = iam.list_user_tags(UserName=user_name)
    for tag in resp.get("Tags", []):
        if (tag["Key"] == REQUIRED_TAG_KEY
                and tag["Value"] == REQUIRED_TAG_VALUE):
            return True
    return False


def check_guardrails(target):
    """
    Return (allowed, reason).

    Order matters. The allow-list is checked FIRST so that a protected
    resource is refused even if every other condition would permit action.
    """
    rid = target["resource_id"]

    if not rid:
        return False, "no actionable resource identified in finding"

    if rid in PROTECTED:
        return False, "resource is on the protected allow-list"

    if target["severity_normalized"] < MIN_SEVERITY:
        return False, "severity {} below remediation threshold {}".format(
            target["severity_normalized"], MIN_SEVERITY)

    try:
        if target["resource_type"] == "Instance":
            tagged = instance_has_required_tag(rid)
        elif target["resource_type"] == "AccessKey":
            tagged = user_has_required_tag(rid)
        else:
            return False, "resource type {} is not supported".format(
                target["resource_type"])
    except ClientError as exc:
        # A resource that cannot be inspected is not a resource we act on.
        # Sample findings reference instances that do not exist, and this
        # is the branch that catches them.
        return False, "could not verify tags: {}".format(
            exc.response["Error"]["Code"])

    if not tagged:
        return False, "resource is not tagged {}={}".format(
            REQUIRED_TAG_KEY, REQUIRED_TAG_VALUE)

    return True, "all guardrails passed"


# ---------------------------------------------------------------------------
# Containment actions
# ---------------------------------------------------------------------------

def isolate_instance(instance_id):
    """
    Replace the instance's security groups with the quarantine group.

    The original group IDs are captured and returned so they land in the
    audit trail. Containment that cannot be reversed is not containment.
    """
    resp = ec2.describe_instances(InstanceIds=[instance_id])
    original = []
    for reservation in resp.get("Reservations", []):
        for inst in reservation.get("Instances", []):
            original = [sg["GroupId"] for sg in inst.get("SecurityGroups", [])]

    if DRY_RUN:
        return {
            "performed": False,
            "detail": "DRY RUN: would replace {} with {}".format(
                original, QUARANTINE_SG_ID),
            "original_security_groups": original,
        }

    # Note this does NOT stop the instance. Forensic state in memory is
    # preserved; only its network reachability is removed.
    ec2.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=[QUARANTINE_SG_ID],
    )

    return {
        "performed": True,
        "detail": "security groups replaced with quarantine group",
        "original_security_groups": original,
    }


def disable_access_keys(user_name):
    """
    Deactivate every active access key for the user.

    Deactivate, not delete. An inactive key can be re-enabled if this turns
    out to be a false positive, and it remains available for investigation.
    """
    keys = iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
    active = [k["AccessKeyId"] for k in keys if k["Status"] == "Active"]

    if not active:
        return {
            "performed": False,
            "detail": "no active access keys to revoke",
            "keys": [],
        }

    if DRY_RUN:
        return {
            "performed": False,
            "detail": "DRY RUN: would deactivate {}".format(active),
            "keys": active,
        }

    for key_id in active:
        iam.update_access_key(
            UserName=user_name, AccessKeyId=key_id, Status="Inactive")

    return {
        "performed": True,
        "detail": "deactivated {} access key(s)".format(len(active)),
        "keys": active,
    }


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def write_audit(target, action, detail, extra=None):
    item = {
        "finding_id": target["finding_id"],
        "event_time": now_iso(),
        "action": action,
        "detail": detail,
        "source": "remediation",
        "finding_type": target["finding_type"],
        "resource_type": target["resource_type"],
        "resource_id": target["resource_id"] or "none",
        "severity_normalized": target["severity_normalized"],
        "account_id": target["account_id"],
        "region": target["region"],
        "dry_run": DRY_RUN,
    }

    if extra:
        # Original security groups or affected key IDs — the information
        # needed to reverse this action later.
        item["remediation_context"] = json.dumps(extra)

    audit_table.put_item(Item=item)


def notify(target, action, detail):
    subject = "[CONTAINMENT {}] {}".format(
        action, target["resource_id"] or "no target")[:100]

    body = "\n".join([
        "AUTOMATED CONTAINMENT",
        "",
        "Outcome:     {}".format(action),
        "Detail:      {}".format(detail),
        "Dry run:     {}".format(DRY_RUN),
        "",
        "Resource:    {} ({})".format(
            target["resource_id"] or "none", target["resource_type"]),
        "Finding:     {}".format(target["finding_type"]),
        "Severity:    {}/100".format(target["severity_normalized"]),
        "Account:     {}".format(target["account_id"]),
        "Region:      {}".format(target["region"]),
        "",
        "Full history for this finding is in the audit table under",
        "finding_id {}.".format(target["finding_id"]),
    ])

    sns.publish(TopicArn=SNS_TOPIC_ARN, Subject=subject, Message=body)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def lambda_handler(event, context):
    target = extract_target(event)

    LOG.info(json.dumps({
        "message": "remediation evaluating",
        "finding_id": target["finding_id"],
        "resource_id": target["resource_id"],
        "resource_type": target["resource_type"],
        "severity": target["severity_normalized"],
        "dry_run": DRY_RUN,
    }))

    allowed, reason = check_guardrails(target)

    if not allowed:
        write_audit(target, "REMEDIATION_REFUSED", reason)
        notify(target, "REFUSED", reason)
        LOG.warning(json.dumps({
            "message": "remediation refused",
            "finding_id": target["finding_id"],
            "resource_id": target["resource_id"],
            "reason": reason,
        }))
        return {"action": "REFUSED", "reason": reason}

    try:
        if target["resource_type"] == "Instance":
            result = isolate_instance(target["resource_id"])
            action = "CONTAINED_INSTANCE"
        else:
            result = disable_access_keys(target["resource_id"])
            action = "REVOKED_CREDENTIALS"
    except ClientError as exc:
        detail = "{}: {}".format(
            exc.response["Error"]["Code"], exc.response["Error"]["Message"])
        write_audit(target, "REMEDIATION_FAILED", detail)
        notify(target, "FAILED", detail)
        LOG.error(json.dumps({
            "message": "remediation failed",
            "finding_id": target["finding_id"],
            "error": detail,
        }))
        # Re-raise so the invocation is marked failed and retried, and so a
        # persistent failure eventually reaches the dead letter queue.
        raise

    if DRY_RUN:
        action = "DRY_RUN_" + action

    write_audit(target, action, result["detail"], extra=result)
    notify(target, action, result["detail"])

    LOG.info(json.dumps({
        "message": "remediation complete",
        "finding_id": target["finding_id"],
        "action": action,
        "performed": result["performed"],
    }))

    return {"action": action, "detail": result["detail"]}