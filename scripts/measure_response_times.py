#!/usr/bin/env python3
"""
Compute detection and containment latency from the audit trail.

Reads the audit table, groups events by finding, and reports the time
between each stage of the detection-to-containment workflow.

    python3 scripts/measure_response_times.py

WHAT THIS DOES AND DOES NOT MEASURE
-----------------------------------
True MTTD in the NIST sense is the interval between compromise and
detection. That is not measurable here: GuardDuty sample findings describe
events that never happened, so there is no compromise to measure from.

What IS measured, and is real:

    detection -> triage      GuardDuty published the finding; how long
                             until the pipeline recorded a decision
    triage -> containment    how long from that decision to action taken
    detection -> containment the sum, end to end

These are pipeline latencies. Reported honestly as such, they are the
component of MTTR that this system actually controls.
"""

import argparse
import statistics
from collections import defaultdict
from datetime import datetime

import boto3

TRIAGE_ACTIONS = {"TRIAGED"}

SYNTHETIC_PREFIX = "test-"

CONTAINMENT_ACTIONS = {
    "CONTAINED_INSTANCE",
    "REVOKED_CREDENTIALS",
    "DRY_RUN_CONTAINED_INSTANCE",
    "DRY_RUN_REVOKED_CREDENTIALS",
}


def parse_ts(value):
    """Parse an ISO 8601 timestamp, tolerating a trailing Z."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value)


def load_events(table_name, region):
    """
    Return every row in the audit table.

    DynamoDB scan returns at most 1MB per call, so a single scan() can
    silently give you a partial answer. Paginating on LastEvaluatedKey is
    how you actually read a whole table.
    """
    table = boto3.resource("dynamodb", region_name=region).Table(table_name)

    items = []
    kwargs = {}
    while True:
        response = table.scan(**kwargs)
        items.extend(response.get("Items", []))
        if "LastEvaluatedKey" not in response:
            break
        kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

    return items


def summarize(items, include_synthetic=False):
    """Group audit rows by finding and compute per-finding latencies."""
    by_finding = defaultdict(list)
    for item in items:
        by_finding[item["finding_id"]].append(item)

    results = []

    for finding_id, events in by_finding.items():
        # Fixture findings carry a fabricated createdAt, so any interval
        # measured from them is fiction. Excluded unless asked for.
        if not include_synthetic and finding_id.startswith(SYNTHETIC_PREFIX):
            continue

        events.sort(key=lambda e: e["event_time"])

        triage = next(
            (e for e in events if e.get("action") in TRIAGE_ACTIONS), None)
        contain = next(
            (e for e in events if e.get("action") in CONTAINMENT_ACTIONS), None)

        if not triage:
            continue

        detected_at = triage.get("finding_created_at")
        if not detected_at:
            continue

        t_detected = parse_ts(detected_at)
        t_triaged = parse_ts(triage["event_time"])

        row = {
            "finding_id": finding_id,
            "finding_type": triage.get("finding_type", "unknown"),
            "resource_id": triage.get("resource_id", "unknown"),
            "detect_to_triage": (t_triaged - t_detected).total_seconds(),
            "triage_to_contain": None,
            "detect_to_contain": None,
            "simulated": False,
        }

        if contain:
            t_contained = parse_ts(contain["event_time"])
            gap = (t_contained - t_triaged).total_seconds()
            # A negative interval means the audit rows are out of order,
            # which happens when a test invokes the functions directly
            # rather than letting one finding flow through both.
            if gap >= 0:
                row["triage_to_contain"] = gap
                row["detect_to_contain"] = (t_contained - t_detected).total_seconds()
            row["simulated"] = str(contain.get("action", "")).startswith("DRY_RUN")

        results.append(row)

    return results


def fmt(seconds):
    if seconds is None:
        return "-"
    if seconds < 60:
        return "{:.1f}s".format(seconds)
    return "{:.1f}m".format(seconds / 60)


def report(results):
    if not results:
        print("No triaged findings with a recorded detection time.")
        print("Run ./scripts/verify.sh first to populate the audit trail.")
        return

    print()
    print("PER-FINDING LATENCY")
    print("-" * 96)
    print("{:<34} {:<26} {:>12} {:>12} {:>10}".format(
        "FINDING TYPE", "RESOURCE", "DETECT>TRIAGE", "TRIAGE>CONT", "TOTAL"))
    print("-" * 96)

    for r in sorted(results, key=lambda r: r["detect_to_triage"]):
        marker = " (dry run)" if r["simulated"] else ""
        print("{:<34} {:<26} {:>12} {:>12} {:>10}{}".format(
            r["finding_type"][:34],
            str(r["resource_id"])[:26],
            fmt(r["detect_to_triage"]),
            fmt(r["triage_to_contain"]),
            fmt(r["detect_to_contain"]),
            marker,
        ))

    triage_times = [r["detect_to_triage"] for r in results]
    contain_times = [
        r["detect_to_contain"] for r in results
        if r["detect_to_contain"] is not None
    ]

    print()
    print("AGGREGATE")
    print("-" * 96)
    print("  findings triaged:            {}".format(len(triage_times)))
    print("  mean detection -> triage:    {}".format(
        fmt(statistics.mean(triage_times))))
    print("  median detection -> triage:  {}".format(
        fmt(statistics.median(triage_times))))
    print("  fastest:                     {}".format(fmt(min(triage_times))))
    print("  slowest:                     {}".format(fmt(max(triage_times))))

    if contain_times:
        print()
        print("  findings contained:          {}".format(len(contain_times)))
        print("  mean detection -> contain:   {}".format(
            fmt(statistics.mean(contain_times))))
        print("  median detection -> contain: {}".format(
            fmt(statistics.median(contain_times))))

    print()
    print("NOTE")
    print("-" * 96)
    print("  These are PIPELINE latencies, not MTTD in the NIST sense.")
    print("  Sample findings describe events that never occurred, so there")
    print("  is no compromise time to measure from. What is measured is the")
    print("  interval this system controls: from a finding being published")
    print("  to a decision being recorded and an action being taken.")
    print()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--table", default="secops-audit-log")
    parser.add_argument("--region", default="us-east-1")
    parser.add_argument("--include-synthetic", action="store_true",
                        help="include fixture findings, whose timestamps are fabricated")
    args = parser.parse_args()

    items = load_events(args.table, args.region)
    report(summarize(items, include_synthetic=args.include_synthetic))


if __name__ == "__main__":
    main()
