# Troubleshooting

Failures encountered building this project, what caused them, and how they were
diagnosed. Every entry happened.

## Terraform

### `terraform plan` shows fewer resources than expected, with no error

**Cause.** A `.tf` file existed in the editor but had never been saved to disk.

**Why it hides.** Terraform merges every `.tf` file in the working directory and
has no way to know a file was *supposed* to be there. A missing file is not an
error; it is simply less configuration.

**Fix.** Know the resource count you expect and check it. `wc -c *.tf` catches a
zero-byte file immediately.

**Related.** In VS Code, an unsaved tab shows a dot instead of a close button.
Three separate incidents in this build traced to that dot.

### `terraform plan` ignores a file that is clearly in the repository

**Cause.** The file was one directory above where Terraform was running — saved
to the repo root instead of `workload/`.

**Why it hides.** Terraform reads one directory. It does not recurse into
subdirectories and does not look upward. A `.tf` file one level away might as
well not exist.

**Fix.** `ls` the working directory rather than trusting the editor's file tree.
The resource count in the plan is the only reliable signal.

### Security Hub standards subscription times out and is marked tainted

**Symptom.** `timeout while waiting for state to become 'READY, INCOMPLETE'
(last state: 'PENDING', timeout: 3m0s)`.

**Cause.** The subscription is created successfully. The provider then polls for
readiness and gives up after three minutes; first-time enablement in a fresh
account routinely takes fifteen to thirty.

**Fix.** Add `timeouts { create = "30m" }`. To recover an already-tainted
resource without recreating it, confirm the real status with
`aws securityhub get-enabled-standards`, then `terraform untaint`.

**Lesson.** "Created" and "ready" are different states. A tool reporting failure
does not always mean the resource failed.

### A Lambda code change does not take effect after `terraform apply`

**Cause.** `source_code_hash` was missing from the `aws_lambda_function`
resource.

**Why it hides.** Terraform compares `filename`, which has not changed. The plan
reports no changes even though the zip contents are completely different.

**Fix.** Always set `source_code_hash = data.archive_file.x.output_base64sha256`.

## AWS eventual consistency

Three separate incidents in this build had the same shape: AWS reported state
on a delay, and impatience looked identical to breakage.

### A sample finding is created but the Lambda never runs

**Cause A — the finding type was reused.** `create-sample-findings` for a type
that already exists *updates* the existing finding rather than creating a new
one. Updates are published on the detector's
`finding_publishing_frequency` schedule — fifteen minutes here. First
occurrences publish immediately; updates do not.

**Fix.** Use a finding type not yet generated in this account, or wait out the
publishing window.

**Cause B — the rule did not exist yet.** EventBridge is fire-and-forget. A
finding published before the rule was created is discarded, not queued.

**Fix.** Apply the stack first, then generate findings. Nothing recovers an
event that had no consumer.

### `list-findings` returns a stale count

**Symptom.** `length(FindingIds)` returned `1` twice while a second finding
already existed.

**Cause.** The GuardDuty list API is eventually consistent and lags
`create-sample-findings` by up to a minute or two.

**Lesson.** Eventual consistency applies to the *diagnostic* commands too, not
just the pipeline being diagnosed. A count taken too early sent this build
chasing a problem that did not exist.

### CloudWatch metrics appear empty while events are flowing

**Symptom.** `MatchedEvents` returned no datapoints for an EventBridge rule that
was in fact matching.

**Cause.** CloudWatch metric publication lags by several minutes.

**Lesson.** An empty metric is not evidence of absence within the first few
minutes. The definitive check is the downstream side effect — a row in DynamoDB
cannot appear without the function having run.

### Security Hub standards sit in `PENDING` for hours

**Cause.** First-time enablement in a fresh account, waiting on the initial AWS
Config snapshot.

**Fix.** Nothing to do. `StandardsControlsUpdatable: READY_FOR_UPDATES` in the
`get-enabled-standards` output indicates the controls are provisioned even while
the top-level status still reads `PENDING`.

## Python

### The function returns `received: 1` with every other counter at zero

**Symptom.** One finding received, nothing counted as alerted, suppressed,
below-threshold, or errored. No exception raised.

**Cause.** Indentation. The body of the loop had been nested inside the
`if severity < MIN_SEVERITY:` block, so for any finding *above* the threshold
the entire remainder of the loop was skipped.

**Why it hides.** Wrong indentation here is still valid Python.
`python3 -m py_compile` reports success. Only behaviour reveals it, and only for
inputs that take the branch that was broken.

**How it was caught.** The verification harness, which tests both a MEDIUM and a
LOW finding on every run. Manual testing had exercised LOW after the change and
MEDIUM before it, so neither run saw the defect.

**Lesson.** A test suite that runs every path every time finds what selective
manual testing cannot.

### `IndentationError: unexpected indent`, and the line looks fine

**Cause.** A pasted block landed eight spaces too deep rather than four.

**Diagnosis.** Editor indent guides are unreliable at a glance. What settles it:

    sed -n '327,335p' file.py | cat -et

`cat -et` renders tabs as `^I` and marks line ends with `$`, so leading
whitespace can be counted exactly. Mixed tabs and spaces produce a `TabError`
pointing at a line that looks correct on screen.

**Fix.** Dedent a range with `sed -i '' '332,381s/^        //' file.py`.

**Caution.** Running that twice removes sixteen spaces. It happened here: a
backup taken inside the same command that does the damage is only good for one
run. Verify with `cat -et` between attempts.

## Shell and tooling

### `zsh: event not found: DNS`

**Cause.** Several GuardDuty finding types contain `!`, for example
`CryptoCurrency:EC2/BitcoinTool.B!DNS`. In an interactive shell `!` triggers
history expansion, and **double quotes do not protect it**.

**Fix.** Single-quote the argument. The rule: double quotes expand variables,
single quotes expand nothing. Use single whenever the text contains `!`, `$` or
a backtick that must survive literally.

**Note.** The command aborts before the API is called, so nothing happens — and
the resource count that should have changed silently does not.

### The prompt changes to `>` and will not return

**Cause.** An unterminated heredoc. `cat > file <<'EOF'` reads until it sees a
line containing exactly `EOF`; if a long paste is truncated, that line never
arrives.

**Fix.** Type `EOF` and press return, or `Ctrl-C` to abort. Then check the
result — `cat >` truncates the target the moment it starts, so a partial or
empty file may be left behind.

**Prevention.** Write long files in blocks of roughly fifty lines, appending
with `>>` after the first, and check `wc -l` between them.

### `cat: illegal option -- A`

**Cause.** macOS ships BSD `cat`, which has no `-A`.

**Fix.** `cat -et` is the BSD equivalent: `-e` marks line ends, `-t` shows tabs.

### `ModuleNotFoundError: No module named 'boto3'`

**Cause.** The AWS CLI bundles its own Python and its own boto3. The system
Python has neither.

**Fix.** A project virtual environment:

    python3 -m venv .venv
    ./.venv/bin/pip install boto3
    ./.venv/bin/python scripts/measure_response_times.py

Calling the venv binaries directly avoids needing `source activate`.

## Measurement

### Latency figures in the hundreds of minutes, including a negative interval

**Cause.** The measurement was reading test fixtures whose `createdAt`
timestamps are hardcoded. It was faithfully reporting the gap between a
timestamp written by hand and the moment the test ran.

**Fix.** Exclude synthetic findings from the calculation and measure only live
GuardDuty findings, where AWS sets the timestamp. Reject negative intervals
rather than reporting them.

**Lesson.** A number that comes out of a script still has to be plausible. The
negative value was the giveaway; without it the four-hundred-minute figure might
have been believed.
