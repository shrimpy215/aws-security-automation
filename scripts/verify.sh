#!/usr/bin/env bash
#
# Verification harness for the security automation pipeline.
#
# Runs every claim the README makes and asserts on the result. Intended to
# be run against a deployed workload stack:
#
#     ./scripts/verify.sh
#
# Exits non-zero if any assertion fails, so CI can gate on it.

set -euo pipefail

# set -e   exit immediately if any command fails
# set -u   treat an unset variable as an error rather than an empty string
# set -o pipefail   a pipeline fails if ANY stage fails, not just the last
#
# Without pipefail, `false | true` succeeds, which silently hides errors in
# the middle of a pipeline. These three lines are the standard opening of
# any script you intend to trust.

REGION="${AWS_REGION:-us-east-1}"
PROJECT="${PROJECT_NAME:-secops}"

# Resolve the repo root from this script's own location, so the script works
# regardless of which directory you run it from.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

DEDUPE_TABLE="${PROJECT}-finding-dedupe"
AUDIT_TABLE="${PROJECT}-audit-log"
TRIAGE_FN="${PROJECT}-triage"
REMEDIATION_FN="${PROJECT}-remediation"

PASS=0
FAIL=0

# ---------------------------------------------------------------------------
# Assertion helpers
# ---------------------------------------------------------------------------

pass() {
  printf "  \033[32mPASS\033[0m  %s\n" "$1"
  # Written as an assignment rather than ((PASS++)) on purpose: the ++ form
  # returns a non-zero status when the variable was 0, which under `set -e`
  # would abort the script on the very first passing test.
  PASS=$((PASS + 1))
}

fail() {
  printf "  \033[31mFAIL\033[0m  %s\n" "$1"
  FAIL=$((FAIL + 1))
}

assert_contains() {
  local haystack="$1" needle="$2" label="$3"
  if [[ "$haystack" == *"$needle"* ]]; then
    pass "$label"
  else
    fail "$label"
    printf "        expected to contain: %s\n" "$needle"
    printf "        actual:              %s\n" "$haystack"
  fi
}

section() {
  printf "\n\033[1m%s\033[0m\n" "$1"
}

invoke() {
  # Invoke a Lambda synchronously and echo its response payload.
  local fn="$1" payload="$2" out
  out="$(mktemp)"
  aws lambda invoke \
    --function-name "$fn" \
    --payload "fileb://$payload" \
    --region "$REGION" \
    "$out" >/dev/null
  cat "$out"
  rm -f "$out"
}

reset_dedupe_table() {
  # Deduplication state persists across runs, so the first test would be
  # suppressed rather than alerting on a second execution. Clearing it makes
  # the harness repeatable — a test you can only run once is not a test.
  local keys
  keys="$(aws dynamodb scan \
    --table-name "$DEDUPE_TABLE" \
    --region "$REGION" \
    --projection-expression "fingerprint" \
    --query 'Items[].fingerprint.S' \
    --output text)"

  for fp in $keys; do
    aws dynamodb delete-item \
      --table-name "$DEDUPE_TABLE" \
      --region "$REGION" \
      --key "{\"fingerprint\":{\"S\":\"$fp\"}}" >/dev/null
  done
}

# ---------------------------------------------------------------------------
# Preconditions
# ---------------------------------------------------------------------------

section "Preconditions"

if aws lambda get-function --function-name "$TRIAGE_FN" --region "$REGION" >/dev/null 2>&1; then
  pass "triage function is deployed"
else
  fail "triage function is deployed"
  echo "Run: cd workload && terraform apply"
  exit 1
fi

if aws lambda get-function --function-name "$REMEDIATION_FN" --region "$REGION" >/dev/null 2>&1; then
  pass "remediation function is deployed"
else
  fail "remediation function is deployed"
  exit 1
fi

if aws guardduty list-detectors --region "$REGION" --query 'DetectorIds[0]' --output text | grep -qv '^None$'; then
  pass "GuardDuty detector exists"
else
  fail "GuardDuty detector exists"
fi

reset_dedupe_table
pass "deduplication state cleared for a repeatable run"

# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------

section "Triage: severity filtering and deduplication"

RESULT="$(invoke "$TRIAGE_FN" "$REPO_ROOT/scripts/events/guardduty-sample.json")"
assert_contains "$RESULT" '"alerted": 1' "MEDIUM finding produces an alert"

RESULT="$(invoke "$TRIAGE_FN" "$REPO_ROOT/scripts/events/guardduty-sample.json")"
assert_contains "$RESULT" '"suppressed": 1' "identical finding is suppressed as a duplicate"
assert_contains "$RESULT" '"alerted": 0' "no second alert is sent for the duplicate"

RESULT="$(invoke "$TRIAGE_FN" "$REPO_ROOT/scripts/events/guardduty-low-severity.json")"
assert_contains "$RESULT" '"below_threshold": 1' "LOW finding is filtered below threshold"
assert_contains "$RESULT" '"alerted": 0' "no alert is sent below threshold"

# ---------------------------------------------------------------------------
# Remediation guardrails
# ---------------------------------------------------------------------------

section "Remediation: guardrails refuse before they act"

RESULT="$(invoke "$REMEDIATION_FN" "$REPO_ROOT/scripts/events/guardduty-sample.json")"
assert_contains "$RESULT" '"action": "REFUSED"' "MEDIUM finding is refused for containment"
assert_contains "$RESULT" 'below remediation threshold' "refusal reason names the severity threshold"

# HIGH severity, but the instance does not exist and so cannot be verified.
TMP_FAKE="$(mktemp)"
sed 's/INSTANCE_PLACEHOLDER/i-0deadbeefdeadbeef/' \
  "$REPO_ROOT/scripts/events/guardduty-containment-template.json" > "$TMP_FAKE"

RESULT="$(invoke "$REMEDIATION_FN" "$TMP_FAKE")"
assert_contains "$RESULT" '"action": "REFUSED"' "unverifiable resource is refused"
assert_contains "$RESULT" 'could not verify tags' "refusal reason names the failed tag check"
rm -f "$TMP_FAKE"

# ---------------------------------------------------------------------------
# Remediation against the real demo target, if one is deployed
# ---------------------------------------------------------------------------

section "Remediation: dry run against a tagged resource"

INSTANCE_ID="$(terraform -chdir="$REPO_ROOT/workload" output -raw demo_instance_id 2>/dev/null || echo "")"

if [[ -z "$INSTANCE_ID" || "$INSTANCE_ID" == "null" ]]; then
  printf "  \033[33mSKIP\033[0m  no demo target deployed (set deploy_demo_targets = true)\n"
else
  TMP_REAL="$(mktemp)"
  sed "s/INSTANCE_PLACEHOLDER/$INSTANCE_ID/" \
    "$REPO_ROOT/scripts/events/guardduty-containment-template.json" > "$TMP_REAL"

  RESULT="$(invoke "$REMEDIATION_FN" "$TMP_REAL")"

  if [[ "$RESULT" == *"DRY_RUN_CONTAINED_INSTANCE"* ]]; then
    pass "tagged instance passes all guardrails (dry run, no action taken)"
  elif [[ "$RESULT" == *'"action": "CONTAINED_INSTANCE"'* ]]; then
    pass "tagged instance was contained (LIVE — dry run is disabled)"
    printf "  \033[33mNOTE\033[0m  containment was real. Restore the instance before continuing.\n"
  else
    fail "tagged instance passes all guardrails"
    printf "        actual: %s\n" "$RESULT"
  fi
  rm -f "$TMP_REAL"
fi

# ---------------------------------------------------------------------------
# Audit trail
# ---------------------------------------------------------------------------

section "Audit trail completeness"

ACTIONS="$(aws dynamodb scan \
  --table-name "$AUDIT_TABLE" \
  --region "$REGION" \
  --projection-expression "#a" \
  --expression-attribute-names '{"#a":"action"}' \
  --query 'Items[].action.S' \
  --output text)"

# "action" is a DynamoDB reserved word, which is why it must be aliased to
# #a via expression-attribute-names rather than named directly.

for expected in TRIAGED SUPPRESSED_DUPLICATE BELOW_THRESHOLD REMEDIATION_REFUSED; do
  if [[ "$ACTIONS" == *"$expected"* ]]; then
    pass "audit trail contains $expected"
  else
    fail "audit trail contains $expected"
  fi
done

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

printf "\n\033[1mResults\033[0m\n"
printf "  passed: %d\n" "$PASS"
printf "  failed: %d\n" "$FAIL"

if [[ "$FAIL" -gt 0 ]]; then
  printf "\n\033[31mVerification failed.\033[0m\n"
  exit 1
fi

printf "\n\033[32mAll checks passed.\033[0m\n"