# ADR-0107: Admit Parity Only from Sealed Semantic Behavior

## Status

Accepted

## Context

ENG-002B2A produces two independently fresh sealed Runs on the same semantic runtime coordinate,
but successful execution is not behavioral parity. Run, Agent, Capability, Task, request, Worker,
evidence, validation, event, and Mode output identities are intentionally fresh. Raw artifact hashes
must therefore differ, while broad removal of fields would hide real Scope, attenuation, receipt,
or Outcome drift.

Mode post-processing also has existing authoritative readers and artifact contracts. Reimplementing
their logic inside a parity harness would create a second interpretation path.

## Decision

PAJIN will admit ENG-002 behavioral parity only after the existing Mode processors independently
reload and extend both exact B2A source roots. A code-owned normalizer maps only typed fresh
identities, allowlisted execution timestamps, and schema-defined sets to canonical fixture values.
All remaining content is compared exactly across Scope, Capability, ToolRequest, receipt, Outcome,
and Mode post-processing axes.

The resulting content-addressed authority admits Profile-adapter parity for the exact fixture and
coordinate. It keeps `MissionEnvelope` compilation and Common execution authorization false.

## Consequences

- Equal raw hashes are neither expected nor required across fresh Runs.
- Capability attenuation and host-observed receipt semantics cannot be inferred from equal
  high-level Findings; they are compared as independent axes.
- Existing KISA, Bug Hunt, and CTF readers remain the Mode interpretation authority.
- Missing evidence on both arms is rejected rather than treated as equality.
- If the second Mode processor fails after the first Run is extended, no parity authority exists
  and retry requires a fresh B2A pair; sealed history is not rolled back.
- The normalized authority is reviewable and content-addressed, but is not an external signature,
  binary attestation, or production execution grant.

## Compatibility and rollback

The parity API is additive and opt-in. Legacy runtime and CLI/API defaults are unchanged. Rollback
removes ENG-002B2B while retaining any pre-B2B roots in the seal chain and leaves predecessor
contracts unchanged.

## Related documents

- [ADR-0105: Measure Planner Parity Before Runtime Parity](0105-measure-planner-parity-before-runtime-parity.md)
- [ADR-0106: Seal Dual Runtime Sources Before Behavioral Parity](0106-seal-dual-runtime-sources-before-behavioral-parity.md)
- [ENG-002B2A contract](../orchestration/ENG-002B2A-common-engine-dual-runtime-fixture.md)
- [ENG-002B2B contract](../orchestration/ENG-002B2B-common-engine-behavioral-parity.md)
