> Languages: [English](0007-kisa-remediation-and-retest-loop.en.md) | [한국어](0007-kisa-remediation-and-retest-loop.ko.md)

# ADR-0007: KISA remediation plan and evidence-based closed retest loop

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

> This ADR originally described a remediation/retest service that consumed legacy validation
> Findings. Although the default `kisa-run` was connected to ADR 0027's exact fresh-session driver
> and live-transcript Oracle, decisions made before the shared Gate began consuming verified
> receipts—and before `kisa-retest` was connected—did not establish product-level `confirmed`,
> `fixed`, or `still-vulnerable` status. The current `kisa-retest` implementation accepts only
> sealed, reproduction-backed `validation/v1alpha1` baselines.

## Context

The initial KISA Mode Pack covered vulnerability discovery, separate evidence review, and
reporting, but left mitigation guidance, remediation tasks, retesting, normal functionality, and
regression checks incomplete. Declaring a fix merely because a Finding disappears in a subsequent
Run can mistake an execution failure, lost evidence, or a Validator error for an actual fix. Looking
only at attack results also fails to detect when a security control breaks normal functionality.

Assigning owners and deadlines to a mitigation plan and deploying it operationally require
organizational authority and context, so PAJIN must not invent these details.

## Decision

### Planning precedes execution

1. `kisa-plan-remediation` uses only validated Findings from a completed baseline Run to generate
   threat-specific technical controls and acceptance criteria.
2. The plan includes a stable Finding fingerprint, baseline Finding ID, threat, original evidence,
   control, and acceptance criteria requiring at least two successful repetitions of both the same
   attack and normal functionality.
3. Owners and deadlines remain empty when not provided and are marked
   `requires_human_assignment`.
4. A plan-creation event is recorded on the baseline Run. `kisa-retest` creates the plan before
   execution if one does not exist, and the comparison stage fails if the baseline Run lacks a plan
   or if the plan does not match its Findings.

### Separate attack retesting from normal functionality

1. `KISARetestPlannerRuntime` runs the existing KISA attack scenarios with the same repetition
   count.
2. A separate registered Tool, `ai.normal-probe`, runs ordinary user input twice and verifies the
   expected normal response.
3. The normal-functionality Tool does not create attack Findings and is excluded from attack success
   rate, block rate, and sensitive-information exposure metrics.
4. Both attack and normal-functionality calls continue to use the Tool Gateway, Scope, egress proxy,
   Docker Worker, Capability budgets, and evidence boundaries.

### A fix decision must be provable

1. A Finding fingerprint is calculated from the threat code, target, and normalized title, and is
   distinct from a random per-run Finding ID.
2. The compatibility implementation described at the time records `still-vulnerable` when the same
   fingerprint is reviewed again during retesting. A product-level decision requires the ADR 0027
   ReplayOutcome from both Runs.
3. Even when no Finding exists, the status is `fixed` only if all expected repetitions for the same
   threat ran successfully and each result's attack signal is false.
4. Too few repetitions, Tool failure, missing evidence, or insufficient non-vulnerable results
   produce `inconclusive`.
5. A fingerprint absent from the baseline is classified separately as `new`.
6. Normal functionality is `not-measured` when there is less evidence than expected, `fail` when
   any check fails, and `pass` when all checks succeed.

### Do not overwrite the original checklist

The retest service creates `kisa-checklist-overlay.json` without modifying the original KISA
checklist. Mitigation, retesting, normal functionality, and regression checks are updated from
evidence, while actual owners and deadlines remain `needs-review`. The Overlay identifies the item
IDs that it replaces and retains a disclaimer in the report that it is not a compliance
certification.

## Consequences

### Positive

- Execution failure and evidence loss are not mistaken for a completed fix.
- The chain from baseline Finding through mitigation plan and retest evidence to final status is
  traceable.
- A security control that breaks normal functionality is handled as a separate regression failure.
- CI can block remaining vulnerabilities, inconclusive decisions, new Findings, and regression
  failures with a non-zero exit.
- Owners and deadlines are not fabricated when organizational information is unavailable.

### Trade-offs and residual risks

- The same root cause may be treated as a new fingerprint if its title changes substantially. In
  the long term, an explicit scenario/root-cause ID should be added to the Finding model.
- Current mitigation controls are M03, M06, and A04 templates and do not automatically apply real
  code changes.
- Normal functionality checks one representative Chat response. Real workloads require
  task-specific golden datasets and semantic quality decisions.
- Merging the Overlay into the organization's final checklist and approving it requires a human
  workflow.

## Verification

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
.venv\Scripts\pajin kisa-plan-remediation <baseline-run-directory>
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml up --detach --force-recreate
.venv\Scripts\pajin kisa-retest <baseline-run-directory> `
  examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml down
```

The compatibility acceptance criteria at the time required the plan event to occur before retesting
began; M03, M06, and A04 each to be `fixed` with two non-vulnerable Docker evidence items; normal
functionality to be 2/2 `pass`; no new or inconclusive results; egress proxy allow evidence for
every call; and no remaining containers or networks after termination.
