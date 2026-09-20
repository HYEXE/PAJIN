# ADR-0303: Qualify and Split Proposal-only Skill Projection Before Model Dispatch

- Status: Accepted
- Date: 2026-09-16
- Scope: SKILL-002 and the WEB-007 successor preparation boundary
- Implementation status: implemented without Provider or target dispatch

## Context

SKILL-001 registered five target-neutral Web analysis Skills as exact, knowledge-only records. All
five were deliberately `catalogued`, with selection and model projection unavailable. WEB-007
already had a separate v1alpha1 digest spine from its sealed source Snapshot through its opaque
model projection, Provider request, draft, compiler, receipts, events, artifact inventory, and
strict loaders.

Changing a v1alpha1 Snapshot or projection in place would rewrite that spine and make historical
Runs ambiguous. Selecting a `catalogued` Skill would bypass its lifecycle contract. Putting Skill
instructions into the existing user message would also conflict with the existing developer
instruction, which says the entire user message is tainted evidence and must never be treated as
instructions.

The passive WEB-007 source evidence does not yet satisfy the Skills' independent replay, negative
control, semantic oracle, or validated-Finding requirements. Selection therefore cannot claim that
those requirements have already been met.

## Decision

### Preserve the catalogued registry and add an exact cumulative successor

Keep registry `pajin.analysis-skills/1.0.0` and its digest unchanged. Add exact registry `1.1.0` as
a cumulative installed registry containing:

- all five historical `1.0.0` catalogued records; and
- new `1.1.0` proposal-only records for SQL injection, cross-principal object access, browser XSS,
  and attack-path composition.

The Finding narrative Skill remains only `1.0.0 catalogued`: WEB-007 has no validated Finding and
uses the Planner role rather than the Reporter/Validator precondition.

There is no highest-version lookup, compatible fallback, mutation, or generic promotion operation.
An installed-registry resolver accepts only an exact version and digest known to code.

### Require explicit proposal-only qualification

Create a content-addressed `ProposalOnlySkillQualificationSet` that binds:

- the exact predecessor and successor registry references;
- each exact catalogued and proposal-only Skill reference;
- unchanged instruction semantics and input/output schema identity;
- the exact selection-policy and instruction-projection schema digests;
- target-neutrality and selected-only disclosure requirements; and
- literal denial of Recipe, lab execution, independent validation, Scope, Tool, Capability,
  Permit, execution, Finding, Graph, and delivery authority.

Qualification reconstructs and compares both exact installed registries. A caller-authored,
self-consistent registry is not accepted by the Web adapter.

### Select only by code-owned metadata

The WEB-007 selection policy binds the exact qualified registry, qualification, four allowed Skill
references, Planner role, registered Web classification, `web.http-operation` Surface type, and the
five code-owned diagnostic/path Hypothesis IDs. It also fixes a four-Skill limit and a 32 KiB
canonical UTF-8 instruction limit.

Selection is the deterministic intersection of that policy and exact Skill metadata. Target text,
routes, forms, control names, opaque Evidence values, count buckets, and model output cannot select
a Skill. Required Evidence types remain future requirements and are explicitly marked unsatisfied.

### Split instructions from tainted evidence

Create two separately digested projections:

1. `AnalysisSkillInstructionProjection` contains only the four selected, reviewed, target-neutral
   Skill bodies and is eligible for a future developer message.
2. The unchanged WEB-007 `WebAnalysisModelProjection/v1alpha1` remains tainted opaque evidence and
   is eligible only for a future user message.

A local `WebAnalysisSkillProjectionBundle` binds the two projections while fixing
`combinedUserMessageAuthorized=false` and `providerDispatchAuthorized=false`. SKILL-002 does not
construct a Provider request. A future WEB-007 successor must define a new prompt, request, draft,
compiler, receipt, event grammar, and strict loader that preserve the channel split.

### Seal a separate zero-dispatch preparation Run

Do not add artifacts to an existing WEB-007/v1alpha1 Run. Seal a predecessor preparation Run with
exactly four artifacts:

- `skill-bound-snapshot.json`;
- `instruction-projection.json`;
- `evidence-projection.json`; and
- `projection-index.json`.

The Run records exactly two events and zero model invocations, Provider dispatches, target
requests, Tool requests, ActionPermits, Findings, and Graph mutations. Its strict loader requires
independently supplied preparation Run/root, source Run/root, installed registry reference, and
selection-policy digest. It reconstructs the current exact source Snapshot, registry,
qualification, policy, selection, and projections before accepting the sealed artifacts.

## Consequences

### Positive

- Historical WEB-007/v1alpha1 artifacts and loaders remain byte- and grammar-compatible.
- A lifecycle marker cannot be flipped in place to make a catalogued Skill selectable.
- Only selected Skill bodies are disclosed; the Finding-writing body and full registry are absent.
- Reviewed instructions and target-influenced evidence have distinct future message roles.
- Selection and preparation are reproducible without target, Provider, Gateway, or Worker effects.

### Tradeoffs and residual risks

- SKILL-002 does not prove that the selected Skills improve model output.
- The qualification proves exact semantic continuity and projection conformance, not external
  security correctness or transfer across targets.
- Required replay/control/oracle evidence remains unavailable at this stage.
- A real model call still requires the separately versioned transport/runtime and successor
  request/draft/receipt boundary.

## Compatibility, migration, and rollback

Existing registry `1.0.0`, WEB-007/v1alpha1 types, Provider calls, Runs, compiler, and strict loaders
are unchanged. Consumers must pin registry `1.1.0`, its exact digest, qualification digest, and
policy digest. Adding a later registry must retain exact installed historical resolution rather
than reinterpret a sealed Run through the newest registry.

Rollback disables or removes only the SKILL-002 preparation consumer. The inert registries and
historical preparation Runs grant no execution authority and require no target cleanup.

## Rejected alternatives

- Change lifecycle fields on the existing `1.0.0` Skill definitions.
- Let a production adapter accept a caller-, target-, or model-supplied self-consistent registry or
  selection policy instead of reconstructing the installed registry, qualification, and registered
  policy. Low-level pure selection helpers are not policy-provenance trust boundaries.
- Treat passive discovery as satisfying replay, negative-control, oracle, or Finding evidence.
- Project all Skill bodies and ask the model to choose.
- Put reviewed Skill instructions and tainted Evidence in the existing user message.
- Add Skill artifacts to the existing WEB-007/v1alpha1 Run grammar.
- Build or dispatch a Provider request before the transport and successor message contract exist.
