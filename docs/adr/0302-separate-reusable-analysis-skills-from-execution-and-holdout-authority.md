# ADR-0302: Separate Reusable Analysis Skills from Execution and Holdout Authority

- Status: Accepted
- Date: 2026-09-16
- Scope: reusable analysis Skills, LLM campaign evaluation, and domain expansion
- Implementation status: SKILL-001 catalog implemented; runtime selection and binding are pending

## Context

WEB-003 through WEB-007 established an exact local Juice Shop browser flow, governed execution,
independent validation, Findings, attack paths, reports, a passive discovery substrate, and an inert
LLM proposal boundary. That work is useful as a deterministic development and regression oracle,
but the fixed three-diagnostic Juice Shop path is not the intended general product architecture.

PAJIN needs reusable security-analysis knowledge that a model can select and apply across targets.
It must remain distinct from the contracts that authorize target access or execution. Otherwise a
Skill document, imported corpus, prompt, or model response could accidentally become a Tool,
Capability, target selector, ActionPermit, Finding authority, or Graph writer.

The development target also cannot be the only effectiveness benchmark. Repeatedly tuning the
model, prompt, Skills, compiler, and recipes against Juice Shop would measure memorization and
target-specific engineering rather than transfer. The evaluation design therefore needs explicit
development, regression, holdout, and defended-negative roles before target-specific scaffolding is
retired or other security domains are added.

## Decision

### Introduce a knowledge-only Skill registry

Create a versioned `pajin.skills` registry whose records contain only reviewed analysis knowledge:

- exact Skill ID and version;
- content, input-schema, output-schema, and complete-definition digests;
- security-domain classifications and allowed Agent roles;
- supported Surface, Hypothesis, and Evidence types;
- concise objective, workflow, evidence requirements, false-positive controls, and safety
  constraints;
- pinned source revision and license provenance; and
- lifecycle evidence markers.

Skill metadata is listed first. Full instruction content is returned only after resolving an exact
ID, version, and digest tuple. There is no implicit `latest`, network fetch, dynamic import, callable,
Tool, recipe, target, credential, payload, command, route, selector, or Permit in a Skill record.
Unknown fields and content or schema drift fail closed.

Every Skill is knowledge-only and fixes Scope expansion, target selection, Tool request,
Capability, Permit, execution, Finding promotion, Graph admission, report delivery, and external
delivery authority to false. Lifecycle stages record evidence maturity only:

```text
catalogued
-> proposal-only
-> recipe-backed
-> lab-executable
-> independently-verified
```

No stage changes authority. A later, separate, code-owned binding contract may associate an exact
Skill reference with allowlisted Recipe and Capability identities. That binding still cannot mint
Scope, approval, Permit, or execution authority.

### Start with five target-neutral Web Skills

The initial repository-owned registry contains five `catalogued` Skills:

- assess SQL injection evidence;
- assess cross-principal object access;
- assess browser script-injection evidence;
- compose an attack-path hypothesis from separately supported hops; and
- draft a narrative from an already validated Finding.

They contain no Juice Shop route, selector, credential, payload, expected answer, challenge label,
target locator, private evaluator seed, or executable argument. They are not yet selectable by
WEB-007 and have no Recipe binding or runtime evidence. The existing fixed Juice Shop implementation
continues to serve as the regression oracle while this separation is built.

External corpora, including the previously discussed Claude-Red repository, are not imported by
SKILL-001. Any later adoption requires source and license review, a pinned revision, normalization
into the same knowledge-only schema, removal of target secrets and executable material, adversarial
tests, and an explicit versioned provenance record. Upstream text is never fetched and trusted at
runtime.

### Preserve the governed campaign loop

Skills can inform only the model-analysis and proposal step in the existing invariant:

```text
Surface
-> Hypothesis
-> exact Skill selection and bounded model projection
-> inert proposal
-> deterministic compiler
-> policy and recorded approval
-> ActionPermit
-> Gateway and Worker
-> Observation and Evidence
-> independent validation
-> Finding and Graph admission
-> reporting and replanning
```

The Skill registry, selected Skill, and model output are all inputs to policy and compilation. They
are not authority sources. Target content remains untrusted and cannot instruct Skill loading,
selection, Recipe binding, or execution.

### Evaluate transfer, not target memorization

Use four distinct evaluation roles:

1. Juice Shop remains the development and deterministic regression target.
2. A second authorized target validates ordinary cross-target transfer and adapter assumptions.
3. A sealed private holdout, not used during tuning, measures final model-plus-Skill campaign
   performance.
4. A defended negative target measures false positives, unsafe persistence, and graceful stopping.

Before each holdout evaluation, freeze and identify the model, prompt, Skill registry, compiler,
Recipe bindings, target version, seed, budgets, and success criteria. After a holdout is opened, it
is consumed and cannot be reused as an unbiased confirmation set for a retuned system.

Report at least vulnerability-class coverage, independently validated recall and precision,
false-positive and false-negative counts, attack-path validity, unsupported-claim rate, authority
violations, human interventions, model calls, target actions, elapsed time, and resource cost.
Synthetic conformance, deterministic Juice Shop replay, and live model effectiveness remain
separate results.

### Retire target-specific scaffolding only after replacement coverage exists

Do not broadly delete “test code” after the LLM path starts working. First map each Juice Shop
fixture, assertion, parser, authority gate, negative case, semantic oracle, and PoC replay to its
replacement. Only duplicate target-specific product branches may be removed after equivalent or
stronger coverage exists and a rollback point is preserved. Regression tests, authority tests,
strict loaders, independent oracles, negative controls, and holdout isolation checks remain.

### Expand domains through separate execution profiles

After Web transfer and holdout gates pass, extend the same analysis loop to System, Application,
and Forensics. Reuse the common Skill metadata and proposal boundary, but give each domain separate
Surface types, Profile, Capability, Worker isolation, Evidence schema, semantic oracle, cleanup,
and benchmark. A Web Skill or successful Web campaign never grants host, artifact, device,
credential, or evidence-custody authority.

## Consequences

### Positive

- The LLM becomes the analysis and replanning component without receiving execution authority.
- Skills can grow independently from target adapters and retain exact provenance and compatibility.
- Progressive disclosure bounds model context and prevents accidental loading of every Skill body.
- Juice Shop remains a strong regression oracle without being mislabeled as generalization proof.
- Holdout discipline produces comparable effectiveness evidence and limits benchmark leakage.
- Domain expansion can reuse orchestration while retaining domain-specific trust boundaries.

### Tradeoffs and residual risks

- The registry alone does not improve model performance; selection, projection, Recipe binding,
  live execution, and independent validation still require later milestones.
- Reviewed target-neutral instructions can still be incomplete, biased, or ineffective.
- Provenance identifies a source but does not make upstream content trustworthy.
- A private holdout can be contaminated operationally even when its bytes are absent from the
  repository; evaluation custody and access logging remain separate concerns.
- Retaining deterministic tests increases maintenance work, but deleting them early would remove
  the only trustworthy regression and authority evidence.

## Compatibility, migration, and rollback

SKILL-001 is additive. It does not change WEB-003 through WEB-007 artifacts, model requests,
Capabilities, Permits, Workers, Findings, Graph state, reports, SARIF, or PoC formats. Existing Web
flows do not import or consume the registry.

Later consumers must pin exact registry and Skill references. Changing instruction or schema
content requires a new Skill version or an explicitly reviewed digest update before release; a
consumer cannot silently substitute another version. Disabling the consumer leaves the registry as
inert metadata and restores the previous fixed proposal path without rewriting historical Runs.

## Rejected alternatives

- Treat the fixed Juice Shop diagnostics as the final general architecture.
- Store payloads, commands, routes, selectors, credentials, or callable implementations in Skills.
- Let a model or Skill mint Capability, approval, Permit, Finding, Graph, or delivery authority.
- Fetch or execute an upstream security-skill repository dynamically at campaign runtime.
- Tune on the same private target used to report final generalization performance.
- Delete the deterministic regression, authority, and independent-validation tests after one live
  LLM campaign succeeds.
- Reuse Web execution authority for System, Application, or Forensics workers.

## Verification status

The exact-version registry, strict immutable models, canonical digests, progressive metadata-first
disclosure, five repository-owned Web Skills, provenance validation, lifecycle invariants, and
explicit authority denial are implemented. Focused unit tests cover deterministic identity,
immutable storage, duplicate and drift rejection, moving version and provenance rejection, unknown
executable fields, lifecycle mismatch, literal authority markers, prohibited imports, forbidden
ground-truth fields, and reviewed target-specific canaries. These structural and canary tests do
not prove semantic absence of every disguised answer or secret; source review remains part of
admission.

SKILL-001 has not been projected into WEB-007, selected by a live model, bound to Recipes, executed
against Juice Shop or a second target, or evaluated on a sealed holdout. No external Skill corpus
has been vendored. Those gaps are tracked in `PLAN.md`, `HANDOFF.md`, and `KNOWN_ISSUES.md`.

## Related documents

- [SKILL-001 registry contract](../orchestration/SKILL-001-versioned-analysis-skill-registry.md)
- [WEB-007 LLM proposal contract](../orchestration/WEB-007-llm-assisted-web-analysis-proposal.md)
- [Current implementation plan](../../PLAN.md)
