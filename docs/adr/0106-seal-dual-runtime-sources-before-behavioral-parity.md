# ADR-0106: Seal Dual Runtime Sources Before Behavioral Parity

## Status

Accepted

## Context

ENG-002B1 proves deterministic Planner and ToolRequest semantics without constructing a runner.
Full behavioral parity requires two executions with identical Tool, Policy, Worker, Validator, and
Mode coordinates, but generated Run, request, grant, receipt, and evidence identities must remain
fresh. Comparing in-memory Outcomes alone would neither prove that both arms were sealed nor provide
a stable source from which normalization can be audited.

Combining runtime construction, execution, normalization, parity admission, Envelope compilation,
and Common execution activation in one step would also allow an incomplete comparison to be
mistaken for execution eligibility.

## Decision

PAJIN will add an ENG-002B2A checkpoint that binds the exact semantic runtime coordinate, executes
legacy-direct and Profile-adapter arms independently, verifies both completed sealed Runs, and
records their disjoint fresh identities in one content-addressed dual-runtime authority.

The checkpoint authorizes only the explicitly requested fixture executions. It fixes parity,
`MissionEnvelope`, and Common execution fields to false. Capability, receipt, Outcome, and
Mode-specific normalization remain a separate ENG-002B2B admission step that must consume the
complete B2A authority and sealed artifacts.

## Consequences

- Runtime-coordinate drift fails before a Worker can receive a request.
- Each comparison arm retains independent physical storage and fresh identities.
- A later parity decision has two complete sealed source trees rather than mutable in-memory data.
- Successful dual execution cannot be represented as successful behavioral parity.
- The content-addressed authority is not an external signature, binary attestation, or production
  execution grant.

## Compatibility and rollback

The harness is additive and opt-in. Existing Mode constructors, CLI/API execution, and artifact
readers remain unchanged. Rollback removes ENG-002B2A without changing ENG-002B1 or legacy runtime
behavior.

## Related documents

- [ADR-0104: Register Implementation Identity Before Runtime Parity](0104-register-implementation-identity-before-runtime-parity.md)
- [ADR-0105: Measure Planner Parity Before Runtime Parity](0105-measure-planner-parity-before-runtime-parity.md)
- [ENG-002B1 contract](../orchestration/ENG-002B1-common-engine-planner-fixture-parity.md)
- [ENG-002B2A contract](../orchestration/ENG-002B2A-common-engine-dual-runtime-fixture.md)
