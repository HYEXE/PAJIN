# ADR-0214: Compose Web Knowledge through the Existing Graph Writer

## Status

Accepted

## Context

WEB-001B can prepare one exact concrete GET Surface through the existing signed Pentest Recon
CAP-002 action compiler, but deliberately stops before approval, Permit, Gateway, Worker execution,
Observation, Evidence, or Graph admission. The approved Pentest path already implements those
execution boundaries and PENTEST-002A already converts a fully sealed successful Recon Run into a
neutral Graph Observation with Evidence.

Creating a Web-specific result normalizer, Evidence store, producer, or Graph writer would
duplicate existing authority and risk letting a Security Domain label become an authority root.
Admitting the WEB-001A typed Surface as if the earlier prepared action authorized it would also
confuse registered knowledge with Campaign Scope.

## Decision

Add a thin content-addressed WEB-001C composition around PENTEST-002A. The composition requires the
complete WEB-001B `PreparedCapabilityAction` to equal the sealed Pentest dispatch intent and binds
the typed Surface reference and exact DOMAIN-002 Web semantic type-set to the neutral Pentest
Observation candidate.

PENTEST-002A remains the sole source verifier and producer for this path. It reopens sealed Run
artifacts and verifies the ActionPermit, approval receipt, Worker admission, trusted HTTP receipt,
normalized outcome, and Oracle. Its existing `GraphAdmissionAuthority` path remains the only
writer. WEB-001C returns a proof that exactly one Action, one neutral Observation, three Evidence
nodes, and their existing `produces`/`supported-by` edges were admitted.

The proof fixes the knowledge state to `registered-not-authorized`. It includes no Surface or
Hypothesis Graph node and cannot expand Scope, activate a Capability, issue a Permit, select a
Worker, authorize another request, Replay, or confirm a Finding. The Domain Observation type is a
classification of the existing Pentest Observation, not a rewrite of Graph wire identity or an
admission credential.

## Consequences

- WEB-001C closes the first sealed Web Observation/Evidence admission path without adding a
  parallel Tool, Capability, producer, writer, Event Log, or ledger.
- The Graph event preserves the already consumed ActionPermit as provenance and does not grant a
  retry. Exact Graph retry is idempotent and never repeats the HTTP action.
- The typed WEB-001A Surface remains a reference and registered knowledge, not Campaign Scope.
- Worker success is insufficient without sealed Run integrity, trusted receipt, and Oracle
  success.
- A content-addressed Web candidate/proof can be transported independently, while the authoritative
  Graph event and Evidence remain the existing PENTEST-002A artifacts.
- WEB-001D must separately authorize independent Replay and bind benchmark Ground Truth.

## Rejected alternatives

### Create a Web-specific Graph producer and writer

Rejected because PENTEST-002A already has the exact neutral Observation producer and the Canonical
Graph has one admission authority.

### Admit the typed Surface from the successful request

Rejected because successful discovery extends knowledge but cannot create Surface authority or
expand Campaign Scope. A future Surface proposal needs its own registered producer contract.

### Treat Domain Observation semantics as authority

Rejected because DOMAIN-002 identifiers classify knowledge only. The exact sealed source and
existing producer registration authorize the proposal path.

### Confirm a Finding from the successful Oracle

Rejected because the Recon Oracle proves execution success, not vulnerability validity. Replay,
controls, validation floors, and Finding admission remain separate.

## Compatibility and rollback

WEB-001C is additive and preserves all existing Profile, Domain, Capability, preparation, Permit,
Gateway, Worker, PENTEST-002A, Graph, Observation, Evidence, Event Log, and artifact identities.
Rollback removes the wrapper, tests, contract, and this ADR; existing sealed Runs and Graph events
require no migration.

## Related documents

- [WEB-001C contract](../graph/WEB-001C-sealed-web-discovery-graph-admission.md)
- [WEB-001B contract](../capability/WEB-001B-read-only-web-discovery-binding.md)
- [WEB-001A contract](../discovery/WEB-001A-typed-http-api-surface-locator-registry.md)
- [PENTEST-002A contract](../orchestration/PENTEST-002A-evidence-bound-discovery-admission.md)
- [ADR-0175](0175-admit-pentest-recon-observations-without-finding-authority.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
