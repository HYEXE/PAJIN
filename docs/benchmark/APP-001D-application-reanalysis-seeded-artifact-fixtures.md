# APP-001D: Deterministic Application Re-analysis and Seeded Artifact Fixtures

- Status: Implemented
- Version: `v1alpha1`
- Domain: Application
- Decision: [ADR-0235](../adr/0235-bind-application-reanalysis-and-fixtures-without-artifact-authority.md)
- Predecessors: [APP-001A](../discovery/APP-001A-binary-configuration-runtime-library-surface-model.md),
  [APP-001B](../capability/APP-001B-read-only-static-analysis-capability.md), and
  [APP-001C](../graph/APP-001C-sealed-application-static-analysis-knowledge-admission.md)

## Purpose

APP-001D reopens one stored APP-001C admission and one separately authorized sealed static-analysis
execution for the same immutable Application artifact. It returns only a neutral digest and bounded
review-signal comparison. It also registers future seeded binary, configuration, declared-runtime,
and library Ground Truth requirements without materializing an artifact, provisioning or invoking a
sandbox, cleaning up a fixture, or recording a benchmark measurement.

The implementation is a verification and projection boundary. It is not an artifact reader, parser,
sandbox runtime, Replay scheduler, Target Factory, benchmark Harness, vulnerability Oracle, or
Finding validator.

## Re-analysis inputs

The gate receives:

1. exact APP-001C source inputs;
2. the corresponding stored `ApplicationStaticAnalysisKnowledgeAdmission`;
3. exact separately authorized re-analysis inputs;
4. source and re-analysis SQLite Graph authority stores; and
5. the deployment-configured Application execution trust anchor.

Both executions are reopened through
`load_verified_application_static_analysis_observation_source`. This rechecks current activation and
Campaign Scope, the exact APP-001B preparation and approved job, exactly one consumed ActionPermit
and durable approval receipt, the Ed25519 execution signature, recomputed Gateway policy result,
exact custody and artifact digest, parser executable and sandbox image, non-root network-disabled
read-only/no-exec runtime assertion, detached result receipt, timing, and all declared budgets.

Only the source must already be admitted. Its Observation and optional Hypothesis events must exist
exactly in the supplied source Graph store. The re-analysis remains sealed evidence and is not
automatically admitted to the Graph.

## Exact deterministic semantics

Source and re-analysis must have the same:

- deployment trust anchor, code-backed Capability, signed release, and activation-set digest;
- exact APP-001A Surface, Surface class, operation, and immutable artifact SHA-256;
- custody binding and artifact byte count;
- sandbox binding, logical parser, parser executable SHA-256, sandbox image SHA-256, and non-root
  identity;
- output schema and artifact, output, runtime, memory, and process ceilings;
- Campaign Scope and matched exact Surface allow rule; and
- normalized parameters and request fields other than the intentionally fresh request ID.

A different artifact digest, parent coordinate, Surface class, operation, custody binding, parser,
image, output schema, Scope, release, or budget is not a changed result. It is an incomparable input
and fails closed.

## Separate authority and causal order

The following coordinates must all differ:

- Run and source-root digest;
- request and request digest;
- MissionEnvelope, proposal, Graph Decision, ActionPermit, and dispatch;
- approval envelope and approval-consumption receipt;
- execution ID and signed statement digest;
- sandbox-runtime receipt and attestation artifact digest; and
- result-receipt ID, receipt digest, and artifact digest.

The re-analysis statement's signed `startedAt` must be strictly later than the source statement's
signed `finishedAt`. Distinct identifiers alone cannot relabel an older or concurrent execution as
re-analysis.

The result receipt retains the exact signed `resultBytes` for each opaque result body. Equal
`resultBodySha256` values must have equal `resultBytes`; an equal digest with a different declared
byte count is inconsistent sealed provenance and fails closed. Different result digests may have
equal or different byte counts. Byte-count equality is recorded but is not artifact or vulnerability
truth and does not independently select a comparison state.

The result-body digest and review signal are comparison values and therefore may match. Stable
runtime identity, confinement digest, custody/sandbox binding, and relative evidence filenames may
also remain equal. The contract establishes separate action and evidence authority, not a different
physical host, Worker implementation, or parser implementation.

## Neutral comparison

`ApplicationStaticAnalysisReanalysisComparison` has three values:

- `analysis-result-match`: result-body digest, result byte count, and bounded review signal are all
  equal;
- `analysis-result-changed`: a bounded review signal differs or a signaled result digest differs;
  and
- `analysis-result-unresolved`: both executions lack a bounded review signal while their opaque
  result-body digests differ.

The projection also records exact digest, byte-count, and signal equality booleans. Every accepted
comparison satisfies the exact DOMAIN-006 Application `deterministic-artifact-reanalysis` strategy
because the gate has already required one identical immutable artifact and deterministic analyzer
boundary.

`changed` does not confirm a vulnerability, regression, configuration value, runtime support, or
dependency relationship. `unresolved` is not a negative conclusion. APP-001D never opens or
interprets the result body.

## Seeded artifact fixture profile

`ApplicationStaticAnalysisBenchmarkFixtureProfile` is content addressed and pins the DOMAIN-006
Application plan, all four APP-001A Surface classes, and eight sorted private Ground Truth
requirements:

| Surface | Known-positive expected outcome | Negative-Control expected outcome |
| --- | --- | --- |
| binary | binary security-metadata review signal | no review signal |
| configuration | configuration-structure review signal | no review signal |
| runtime | runtime-metadata review signal | no review signal |
| library | library-metadata review signal | no review signal |

Each case requires an externally seeded immutable artifact and one disposable, network-disabled,
non-root sandbox with a read-only no-exec exact-digest artifact mount. Each also requires four
evidence roles:

- execution attestation;
- non-root offline runtime receipt;
- bounded result receipt; and
- cleanup receipt.

The case registry embeds no artifact bytes, parser output, secret, path, credential, or configuration
value. It requires zero network requests, dynamic target executions, debugger attaches, and artifact
writes.

The fixture profile records positive/negative Controls, Surface coverage, deterministic re-analysis,
isolation, and evidence-completeness requirements only. It has no selected Target profile or Target
Factory authority, no materialized fixture, no provisioned sandbox, no observed cleanup, no bound
Replay evidence, and no numeric metric or Profile-floor evidence.

`privateGroundTruthRequirementsRegistered=true` means only that the exact eight requirements are
code registered. `privateGroundTruthVerified=false` remains explicit until a later boundary supplies
and verifies materialized artifact, execution, cleanup, and measurement evidence. Provider execution
and fixture execution authorization also remain false.

## Non-authority boundary

Re-analysis validation and fixture registration keep the following false:

- artifact format, configuration value, runtime support, dependency, vulnerability, or Hypothesis
  confirmation;
- Ground Truth or negative-Control observation;
- artifact-analysis coverage, evidence completeness, benchmark measurement, detection quality, or
  Profile validation floor;
- Finding authority;
- Scope expansion, Capability activation, approval, or Permit issuance;
- artifact access, custody-authorization authority, sandbox invocation, or Worker selection;
- network access, dynamic target execution, debugger attach, or artifact mutation; and
- Replay scheduling and execution authority.

The implementation imports no socket, HTTP client, subprocess, shell, package repository, parser,
container, VM, debugger, or artifact storage API.

## Audit and storage

The returned validation and fixture profile are deterministic content-addressed projections.
APP-001D writes no Graph node, edge, event, snapshot, approval, Permit, artifact, benchmark result,
sandbox journal, or cleanup receipt.

Bare `ApplicationStaticAnalysisReanalysisValidation.model_validate` is structural, content-addressed
parsing only and is not a trusted verification entry point. Trusted wire reload must use
`load_verified_application_static_analysis_reanalysis_validation` with the deployment-configured
trust anchor, both original evidence roots and inputs, and both exact Graph stores. That loader
reopens both APP-001C sources with the current verifier, confirms the stored source admission, rebuilds
the expected projection, and requires exact canonical model equality. An embedded trust anchor,
attestation SHA-256, Graph event, or recomputed public projection ID cannot replace that context.
The wire projection makes this explicit with `deploymentContextReverificationRequired=true` and
`selfAuthenticatingProjection=false`.

## Failure handling

The gate and contextful wire loader fail closed for invalid or substituted trust anchors, signatures, source admissions,
Campaign Scope, preparations, Surface/artifact semantics, custody/sandbox/parser/image identities,
output schemas, budgets, result receipts, reused authority coordinates, non-causal execution,
comparison fields, fixture cases, Domain plans, boolean/integer coercion, or any mismatch between a
serialized projection and the current evidence/Graph context.

## Compatibility and rollback

APP-001D is additive and does not change APP-001A~C public wire identities. Committed Web, AI,
Network, Cloud, Campaign, Graph, Capability, and benchmark contracts also remain unchanged.

Rollback removes the APP-001D workflow module, tests, this contract, and ADR-0235. APP-001D creates
no external side effect or admitted Graph event that requires cleanup or migration.

## Verification

Tests cover all four same-artifact Surface matches, changed and unresolved comparison states,
same-digest result byte-count inconsistency, stored source admission, the complete separate-authority
coordinate set, aggregate authority reuse, non-causal execution, foreign Surface semantics,
comparison and authority-marker drift, Graph event-count preservation, exact eight-case fixture
coverage, positive/negative signal binding, evidence requirements, coercion, digest drift,
structural wire round trip, and contextful wire reload.
Adversarial reload cases substitute a self-consistent but unstored Graph event, a recomputed
attestation/source-root projection, and a valid but foreign deployment trust anchor; all fail closed.
