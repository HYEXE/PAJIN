> Languages: [English](0005-kisa-ai-red-team-mode-pack.en.md) | [한국어](0005-kisa-ai-red-team-mode-pack.ko.md)

# ADR-0005: KISA AI Red Team Mode Pack and Evidence-Based Checklist

- Status: Accepted
- Date: 2026-07-12
- Confirmation semantics amended by: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

> The independent validation and confirmation language in this document records the evidence-review
> implementation at the time. Since ADR 0027, product-level Confirmed also requires a separate
> Restricted Reproducer's fresh request and evidence, plus Oracle success.

> Historical scope note: references below to the initial A01/A02 vertical slice and to retesting as
> follow-up work describe the state when this ADR was accepted. The current implementation also
> covers A04, M03, and M06 and includes the retest closed loop; see
> [KISA Guide Traceability](../KISA_TRACEABILITY.en.md).

## Context

The KISA *AI Security Red Teaming Guide* presents threat classifications, red-teaming procedures,
evaluation criteria, scenario composition, logs and evidence, checklists, and artifacts for planning,
completion, and execution records. PAJIN must connect these requirements to an executable Mode Pack,
not merely a report template.

However, not every item in the guide can be verified from technical execution results alone.
Automatically passing legal and ethical reviews, personnel expertise and training, psychological
support, stakeholder consultation, business impact, or the operational adoption of improvement
tasks would create an unsupported compliance claim. The existence of a threat code in the catalog
must also be distinguished from actually testing that threat.

## Decision

### PAJIN-owned typed catalog

1. The 19 KISA threats are maintained in a typed catalog with their code, name, threat group, system
   layer, and source page.
2. Each scenario includes the target type, threat codes, attack surface, persona, preconditions,
   execution procedure, decision criteria, impact dimensions, evidence requirements, and registered
   Tool.
3. The Planner selects only scenarios that match the target type among the Campaign's requested
   threats. Requested threats without a scenario remain `untested` with a reason.
4. The first executable scenario targets `mock-agent` with indirect prompt injection and
   unauthorized tool invocation, covering A01 and A02.

### Evidence review separated from execution

1. A separate Specialist Task is created for each scenario repetition, reusing the existing Tool
   Gateway, policy, Capability attenuation, Docker Worker, budget, and Kill Switch boundaries.
2. A Specialist cannot confirm a Finding. A separate Semantic Validator reviews only evidence from
   the same Run, and PAJIN's deterministic Gate rechecks evidence provenance and Scope. This is not
   independent reproduction; ADR 0027's Restricted Reproducer is required separately.
3. Identical Findings from repeated executions are merged by title, threat, and target while all
   reproduction evidence is preserved and a conservative confidence level is applied.

### Evaluation and checklist

1. Attack success rate, block and refusal rate, reproduction rate, sensitive-information exposure
   count, average latency, and threat coverage are calculated as structured metrics.
2. The checklist uses four states: `yes`, `no`, `not-applicable`, and `needs-review`.
3. `yes` is used only when structured evidence from the same Run can verify the item.
4. Organizational judgments such as legal, ethical, personnel, training, HITL, and business-impact
   decisions are not automated and remain `needs-review`.
5. Mitigation, improvement, retest, and regression activities that were not performed are marked
   `no`.
6. Docker-environment items are `yes` only when a Docker backend is observed in actual Worker
   evidence.

### Artifacts

Evaluation results, all 52 checklist items, the test plan, completion report, execution record, and
Markdown report are added to the standard PAJIN Run artifacts. Every KISA artifact includes a source
page or supporting Artifact, and the report states that it is not a compliance certification.

## Consequences

### Positive

- Guide requirements are traceable from Campaign selection through execution, validation, and
  reporting.
- Cataloged threats and actual test coverage are separated, so omissions are not hidden.
- Repeated execution and a separate evidence review provide more confidence than one execution, but
  do not prove independent reproduction.
- Organizational judgments are not passed automatically, preventing excessive compliance claims.
- The Mode Pack reuses the same Tool Gateway and Worker without bypassing existing security
  boundaries.

### Trade-offs and residual risks

- The first vertical scenario executes only A01 and A02 among the 19 threats.
- Automated checklist decisions depend on the completeness of the supplied Campaign data and Run
  evidence.
- Human judgment is required between technical severity and the organization's final remediation
  priority.
- Real model nondeterminism requires more repetitions, varied inputs, independent models, and
  normal-query evaluation.
- The closed loop for mitigation recommendations, owners and deadlines, retesting, and regression
  testing is a follow-up objective.

## Verification

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker simulated --repetitions 2
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

The acceptance criteria at the time were schema validation for 19 threats and 52 checklist items,
two executions each of A01 and A02 and an explicit reason for not executing A04, one legacy Finding
and two Worker evidence records after evidence review, KISA JSON and Markdown artifacts, and passage
of the full static and dynamic test suite.
