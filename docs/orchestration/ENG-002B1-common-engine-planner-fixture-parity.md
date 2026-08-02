# ENG-002B1: Common Engine Planner Fixture Parity

- Status: Implemented
- Contract versions:
  - `pajin.dev/common-engine-planner-constructor/v1alpha1`
  - `pajin.dev/common-engine-normalized-plan/v1alpha1`
  - `pajin.dev/common-engine-planner-parity/v1alpha1`
- Decision: [ADR-0105](../adr/0105-measure-planner-parity-before-runtime-parity.md)

## Scope

ENG-002B1 measures the first behavioral subset of ENG-002 parity. For the same complete PROF-002
Campaign and the same typed Planner constructor inputs, it invokes the existing legacy-direct
Planner path and the ENG-002A-selected Profile adapter Planner path independently. It compares the
complete normalized `AgentPlan` and every `ToolRequest` semantic field.

This slice does not construct `MultiAgentCampaignRunner`, bind a Tool Registry, Policy, Worker, or
output path, invoke a Worker, validate a Tool result, run Mode-specific post-processing, compile a
`MissionEnvelope`, or authorize Common execution.

## Constructor authority

Each `CommonEnginePlannerConstructorBinding` binds:

- path identity: `legacy-direct` or `profile-adapter`;
- exact source Mode and module-qualified Planner class identity;
- all KISA evaluation thresholds for `ai-redteam`; and
- fixed false Tool Registry, Policy, Worker, and output-path binding flags.

Bug Hunt and CTF Planners have no constructor configuration in the current implementation and
reject AI thresholds. KISA thresholds are represented by a Mode-independent typed contract so
importing the public workflow package does not import a Mode package recursively. They are
converted to the existing KISA model only when an explicit measurement call constructs a Planner.

## Fresh identity normalization

Current Planners generate fresh `step_id` and `request_id` values on every invocation. Raw equality
would therefore report a false mismatch. ENG-002B1 replaces only those two fresh identities with
their stable ordered fixture ordinals:

- `fixture-step-0`, `fixture-step-1`, ...; and
- `fixture-request-0`, `fixture-request-1`, ....

The normalized payload is reloaded through the existing `AgentPlan` schema. Summary, ordering,
title, rationale, agent, Tool, target, method, arguments, scenario, threat classes, attack surface,
and persona remain unchanged. The semantic Plan digest excludes path and constructor identity, so
equal behavior produces the same digest; each arm's observation digest still binds its path and
constructor digest.

## Parity authority

`CommonEnginePlannerParityAuthority` revalidates the complete ENG-002A selection and binds both
constructor and normalized Plan observations. It fixes:

- measured dimensions to exactly `scope` and `tool-request`;
- unmeasured dimensions to exactly `capability` and `outcome`;
- `plannerBehaviorMeasured=true` and `plannerParityProven=true`; and
- fixture, Capability, Outcome, Envelope, Common runtime, Worker invocation, and Common execution
  flags to false.

Planner behavior drift raises an error before an authority is created. This content-addressed
record is a code-generated parity measurement, not an external signature or runtime attestation.

## Negative cases

Validation rejects:

- a selected Planner that differs from the legacy direct implementation;
- cross-Mode constructor identity or AI threshold misuse;
- non-canonical fresh-ID normalization or any retained payload/digest drift;
- changed or reordered measured/unmeasured dimension sets;
- different normalized Planner behavior between arms; and
- any Capability, Outcome, Envelope, runtime, Worker, or execution authority escalation.

## Compatibility, migration, and rollback

The measurement API is additive, async, and direct-call opt-in. Existing CLI/API paths and Mode
runtimes are unchanged. Rollback removes the B1 measurement schemas and function while retaining
ENG-002A and every legacy path.

ENG-002B2 must bind identical Tool Registry, Policy, Worker, output, and fixture-result coordinates;
execute validation and Mode-specific candidate/triage/writeup processing; compare Tool receipts and
Outcomes; and preserve independent fresh Run identity before full fixture parity can become true.
