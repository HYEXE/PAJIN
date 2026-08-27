# ADR-0230: Admit System Host Knowledge without Host-access Authority

## Status

Accepted

## Context

SYS-001B produces a current signed preparation for one exact metadata-only System inspection. It
binds an inert SYS-001A Surface, Campaign Scope, complete CAP-002 release, explicit host-agent
deployment configuration, public Worker mTLS identity, declared non-root run-as identity, and
bounded read ceilings. It deliberately has no live host-agent connector, Worker materializer,
host read, result, or Graph-admission authority.

PAJIN nevertheless needs a way to admit knowledge from an inspection that a deployment has
separately approved and completed. Treating the SYS-001B preparation as execution evidence would
fabricate runtime support. Adding a repository host client, accepting unsigned host output, or
copying raw paths and configuration values into Graph prose would weaken the existing authority,
privacy, and single-writer boundaries.

## Decision

Add a SYS-001C source-verification and Graph-admission boundary. Do not add a repository-owned host
agent or invoke a host during admission. Require a deployment-owned external runtime to provide:

1. an Ed25519-signed `SystemInspectionExecutionBundle`; and
2. a detached `SystemInspectionResultReceipt` containing only bounded result metadata, a body
   digest, and an optional fixed review signal.

The deployment configures the trust anchor when constructing the admission gate. Source inputs
cannot provide or override it. The trust anchor binds the exact SYS-001B host-agent deployment,
code-backed Capability, signed release, trust domain, issuer, and uniquely sorted Ed25519 keyring
with exactly one active key. It is verification-only and grants no current activation, Campaign,
approval, Permit, host access, Worker selection, root, Graph, or execution authority.

The signed statement must bind the exact Campaign, Run, rebuilt SYS-001B preparation and inspection
request, consumed ActionPermit, durable approval-consumption receipt, Gateway outcome digest,
`WorkerMTLSAdmission`, non-root runtime receipt, execution times, and detached result receipt. The
runtime receipt must match the deployment's opaque host, executable digest, and declared run-as
identity and provide digest-only runtime-identity and confinement evidence. One request and the
SYS-001B runtime/artifact ceilings apply; filesystem content reads, configuration value reads,
process signals, service control, and host writes remain zero.

Rebuild the preparation from the current activation, Campaign, exact Surface, operation, and
deployment adapter. Join it to exactly one consumed Permit and exactly one durable approval receipt
in the existing SQLite authority store. Recompute the Gateway policy decision from the current
Campaign, Grant, exact request, and network-disabled Tool spec, then bind that decision to the
Permit, mTLS admission, and result receipt in a code-owned sanitized outcome digest. Verify all
signature, key lifecycle, deployment, mTLS, non-root, request, timing, budget, file, and
content-addressed identities before registering Graph lineage.

Construct one Observation proposal containing one succeeded Action, one target-derived
`system.host-observation`, two restricted Evidence nodes, one `produces` edge, and two
`supported-by` edges. The fixed Observation prose states only that a separately authorized
metadata-only inspection produced sealed evidence for the exact bound System Surface. It includes
no raw host content, host path, service name, configuration key, or configuration value.

An optional Hypothesis is permitted only when the signed neutral receipt contains one of two fixed
signals:

- `configuration-metadata-drift` for an exact configuration metadata inspection; or
- `service-status-review` for an exact service status inspection.

Such a signal creates a separate confidence `0.5`, agent-derived, open
`system.security-configuration` Hypothesis with one `enables` edge. It requires a separately
authorized fresh inspection to reproduce the signal. No signal creates no Hypothesis and no
negative conclusion. A signal never confirms service state, configuration effect, vulnerability,
or Finding.

Submit the Observation and, when present, the immediately following Hypothesis through the
existing `GraphAdmissionAuthority` using compare-and-set heads. Exact retries return the prior
events without opening a host session or invoking a Tool, Gateway, Worker, or network operation.

## Consequences

- SYS-001C proves only that one separately authorized, bounded, non-root execution produced the
  sealed digest-only evidence it names.
- Repository code verifies deployment assertions but does not become a host-agent runtime or root
  conformance authority.
- Raw result bodies remain under external custody; Graph nodes contain only fixed prose and
  content-addressed evidence references.
- Optional service or configuration review signals motivate an open Hypothesis but never confirm
  a state, policy effect, weakness, or Finding.
- Surface, Scope, Capability, approval, Permit, host access, agent/Worker selection, credentials,
  root, privilege escalation, service control, mutation, Replay, Finding, and further execution
  authority remain false.
- SYS-001D remains responsible for separately authorized snapshot or fresh-inspection comparison,
  disposable fixtures, controls, and measurement contracts.

## Rejected alternatives

### Add a placeholder host-agent client to SYS-001B

Rejected because the repository has no deployment connector or authenticated host runtime. A
placeholder would convert static trust configuration into fictitious execution support.

### Trust a preparation, public certificate binding, or result digest as execution evidence

Rejected because none proves approval consumption, Permit consumption, Gateway policy re-entry,
direct mTLS admission, non-root runtime identity, or successful bounded completion.

### Embed raw host results in the Graph

Rejected because host output can contain paths, process data, configuration values, credentials,
or other sensitive target-controlled material. External custody plus digest-only Evidence preserves
verification without turning Graph prose into a raw host-data store.

### Treat a service or configuration signal as a Finding

Rejected because the bounded receipt is not an independent Oracle and does not establish security
impact. The signal may only motivate a fresh, separately authorized inspection.

### Add a System-specific Graph writer

Rejected because the existing writer already enforces producer registration, lineage, stale-head,
append-only, and semantic idempotency requirements.

## Compatibility and rollback

SYS-001C is additive and explicitly imported. It changes no SYS-001A/B, Campaign, Scope,
Capability, ToolRequest, approval, ActionPermit, Worker, Graph, Replay, Finding, or benchmark wire.
Rollback removes the specialized workflow, tests, contract, and this ADR. Existing external
artifacts and already admitted immutable Graph events require no migration.

## Related documents

- [SYS-001C contract](../graph/SYS-001C-sealed-system-host-knowledge-admission.md)
- [SYS-001B](../capability/SYS-001B-read-only-inspection-capability.md)
- [SYS-001A](../discovery/SYS-001A-host-process-filesystem-service-configuration-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-004](../orchestration/DOMAIN-004-domain-worker-trust-boundary-registry.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0229](0229-bind-system-read-only-inspection-without-host-access-authority.md)
