# ADR-0235: Bind Application Re-analysis and Fixtures without Artifact Authority

- Status: Accepted
- Date: 2026-08-26
- Owners: PAJIN architecture and security boundary maintainers
- Scope: APP-001D

## Context

APP-001C can reverify one already completed, approved, offline static analysis and admit only neutral
Graph knowledge. The artifact and result body remain outside the repository. The Graph contains no
parser output, format conclusion, configuration value, runtime-support conclusion, dependency
relationship, confirmed vulnerability, or Finding.

APP-001D must compare that stored source with a separately authorized execution and register future
seeded Application benchmark requirements. Equal output digests alone do not prove the same input,
parser, sandbox image, Scope, or budget. Different output digests do not prove a security change.
Graph knowledge and an open APP-001C Hypothesis also cannot dispatch a parser or authorize another
artifact read.

## Decision

Add an APP-001D re-analysis gate that:

1. reopens the exact stored APP-001C source admission and independently reloads both sealed
   executions through the current APP-001C verifier and one deployment-configured trust anchor;
2. requires the exact immutable artifact SHA-256, APP-001A Surface and operation, custody and
   sandbox bindings, parser executable, sandbox image, output schema, Campaign Scope, release,
   normalized request semantics, and all budgets to match;
3. rejects reuse of any Run, source-root, request, envelope, proposal, Decision, Permit, dispatch,
   approval, approval-consumption, execution, sandbox-runtime receipt, statement, attestation, or
   result-receipt identity coordinate;
4. requires the re-analysis statement's signed start to be strictly later than the source
   statement's signed finish;
5. binds the exact DOMAIN-006 Application `deterministic-artifact-reanalysis` strategy;
6. emits only `analysis-result-match`, `analysis-result-changed`, or
   `analysis-result-unresolved`, plus exact digest/byte-count/signal equality booleans; and
7. performs no Graph write, artifact read, parser call, sandbox invocation, Worker selection,
   network operation, debugger attach, mutation, or Replay scheduling.

An exact body-digest, signed byte-count, and review-signal match is `match`. Equal body digests
with different signed byte counts fail closed. A differing bounded review signal is `changed`. If
both executions have no bounded signal and their opaque result digests differ, the comparison is
`unresolved`; APP-001D does not interpret raw output to manufacture a vulnerability or negative
conclusion.

Register a content-addressed eight-case fixture profile covering every APP-001A Surface class. Each
of binary, configuration, declared runtime, and library has one class-bound known-positive review
signal and one no-signal negative Control. Every case requires an externally seeded immutable
artifact, a disposable offline non-root sandbox, a read-only no-exec exact-digest mount, and
complete execution, runtime, result, and cleanup evidence. The profile materializes, provisions,
executes, cleans up, and measures nothing.

## Consequences

- Artifact equality is exact signed provenance, not an inference from equal output.
- Parser executable, sandbox image, output schema, Scope, and budget drift fails closed rather than
  becoming a misleading changed result.
- A disjoint but older or concurrent execution cannot be relabeled as deterministic re-analysis.
- A result-digest difference without either bounded signal remains unresolved.
- Known-positive fixtures expect a class-bound review signal, not a vulnerability Finding.
- Negative Controls and cleanup are requirements until externally executed evidence is admitted by
  a later measurement boundary.
- The validation and fixture profile create no artifact, parser, sandbox, Finding, Replay, or future
  execution authority.

## Alternatives considered

### Compare APP-001C Graph nodes only

Rejected because the Graph deliberately omits the exact runtime and detached result provenance
needed to prove same-artifact deterministic semantics and separate execution authority.

### Accept an unsigned caller label for the artifact or analyzer

Rejected because a caller label does not bind the custody object, immutable artifact digest, parser
executable, sandbox image, output schema, or deployment trust anchor.

### Treat every digest difference as a security change

Rejected because APP-001D cannot inspect raw output, distinguish nondeterministic serialization,
or establish format, configuration, runtime, dependency, or vulnerability truth.

### Materialize and execute seeded artifacts in APP-001D

Rejected because the repository has no governed Application artifact provider, parser runtime,
sandbox scheduler, or Target Factory for this slice. Registration must precede execution and
measurement.

## Security and authority impact

APP-001D consumes only prior signed, approved, and stored provenance. Artifact digests, parser and
image identities, admitted Observations, open Hypotheses, comparisons, and fixture Ground Truth are
knowledge. They do not grant Scope, Capability activation, approval, Permit issuance, artifact or
credential access, custody authority, sandbox or Worker selection, network, dynamic execution,
debugger, mutation, Replay, Finding, or execution authority.

The fixture registry contains no raw artifact, parser output, secret, credential, private key,
filesystem path, configuration value, or live runtime identity.

## Compatibility and rollback

APP-001D is additive. APP-001A through APP-001C wire identities do not change. Existing committed
Web, AI, Network, Cloud, Graph, Campaign, Capability, and benchmark readers require no migration.

Rollback removes the APP-001D module, tests, contract, and this ADR. No Graph event, external
artifact, sandbox, fixture, or cleanup operation is created by APP-001D.

## Verification

Positive and adversarial tests cover all four Surface classes, match/change/unresolved comparison,
stored source binding, separate authority, authority reuse, exact artifact semantics, non-causal
execution, marker coercion, Graph immutability, exact fixture registration, Ground Truth and signal
substitution, and serialization.

## Related contracts

- [APP-001C](../graph/APP-001C-sealed-application-static-analysis-knowledge-admission.md)
- [APP-001D](../benchmark/APP-001D-application-reanalysis-seeded-artifact-fixtures.md)
- [ADR-0234](0234-admit-application-analysis-knowledge-without-artifact-authority.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)

## Verification-boundary clarification (2026-08-26)

The content-addressed validation model is a wire projection, not a self-authenticating receipt. A
trusted reload must be given the deployment-configured trust anchor, both original APP-001C evidence
roots and source inputs, and both exact Graph stores. It re-runs the current APP-001C verifier,
rebuilds the expected APP-001D projection, and compares the complete result. Bare Pydantic parsing
cannot establish stored-event membership, exact evidence-file hashes, or deployment trust and must
not be treated as verification.

The fixture profile records that private Ground Truth requirements are registered while keeping
Ground Truth verification, provider execution, fixture execution, cleanup observation, and all
measurements false. Materialized evidence is required before any later boundary may change those
claims.
