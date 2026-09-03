# Executive Summary

**Project:** Security Monitoring & Automated Incident Response
**Status:** In progress — detection, alerting, triage, and containment operational
**Last updated:** 2026-09-02

---

## What this is

An automated security guard for a cloud environment.

In most organizations a threat is detected by a monitoring tool, an alert
lands in someone's inbox, and a human eventually reads it and decides what to
do. That takes hours, sometimes days, and it only works during business
hours.

This system performs the first several steps automatically, in seconds,
around the clock — and keeps a permanent record of everything it saw and
everything it did.

## How it is structured

Three layers.

**1. Sensors.** Amazon GuardDuty watches network traffic, DNS queries, and
account activity for signs of compromise. AWS Security Hub continuously
checks the environment against two industry benchmarks: the CIS AWS
Foundations Benchmark and the AWS Foundational Security Best Practices
standard. AWS Config records the configuration of every resource so those
benchmark checks have something to evaluate.

**2. Plumbing.** An encrypted alert channel that reaches a real person, and
two databases with deliberately different retention rules:

- *Short-term memory* — if the same threat fires fifty times overnight, the
  system alerts once rather than fifty times. Records expire on a timer, so
  activity that resumes later is treated as new rather than silently
  swallowed. Alert fatigue is the main reason security teams stop trusting
  their tools; this is the countermeasure.
- *Permanent record* — every finding, every decision, every action taken,
  timestamped and immutable. This is the audit trail an investigator or a
  regulator would ask for, and it is what makes response-time metrics
  measurable rather than estimated.

**3. Decision logic.** The component that reads an incoming threat, judges
whether it is serious enough to act on, enriches it with context, notifies
the right people, and — for high-severity findings affecting pre-approved
systems — removes the compromised resource from the network automatically,
before a human is awake.

## Cost control

The system runs within free-tier and trial allowances.

Before any billable resource was deployed, a spending cap and an early-warning
alert were put in place, deliberately built to survive teardown of everything
else. The alert fires on *forecast* spend as well as actual, which gives days
of warning rather than notification after the fact.

Disposable components are destroyed at the end of every working session.
Expected total project spend: a few dollars.

## Architectural decision worth noting

The system is organized by **how long components live**, not by what they do.

| Layer | Lifecycle | Reason |
|---|---|---|
| Spending guardrail | Permanent | A cost control that can be torn down alongside the thing it guards is not a control. |
| Detection | Duration of project | Slow to enable; benchmark standards take hours to activate. |
| Application | Destroyed nightly | Rebuilds in seconds. No reason to leave it running. |

This is why the project is cheap to operate and fast to iterate on. Grouping
by service rather than by lifecycle would have made both worse.

## Standards alignment

The incident response process is documented against **NIST SP 800-61**, the
federal framework for computer security incident handling. Detection controls
are mapped to the MITRE ATT&CK techniques they mitigate.

## Progress

- [x] Cost guardrails
- [x] Detection layer — GuardDuty, Security Hub, AWS Config
- [x] Alerting and persistence — encrypted notifications, both databases
- [x] Triage logic — severity filtering, enrichment, deduplication
- [x] Automated containment — network isolation, credential revocation
- [ ] Verification — simulated findings, response-time measurement
- [ ] Incident response playbook and architecture documentation
