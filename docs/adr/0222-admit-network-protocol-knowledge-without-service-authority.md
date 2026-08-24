# ADR-0222: Admit Network Protocol Knowledge without Service Authority

## Status

Accepted

## Context

NET-001B can prepare and, through existing downstream authorities, execute one exact passive TCP
banner read. Its output is intentionally not Graph knowledge. Copying a banner or classifier label
directly into the Graph would let untrusted target bytes or Tool metadata masquerade as a service
confirmation. Treating the consumed Permit as reusable authority would also collapse execution
provenance into permission for another action.

The Canonical Graph already has one admission writer, immutable Action, Observation, Evidence, and
Hypothesis nodes, and an `enables` relation. The existing sealed Run and dispatch reconciliation
contracts can bind the complete Permit-to-Gateway lifecycle without introducing a Network ledger.

## Decision

Add a specialized NET-001C admission gate. Rebuild the exact NET-001B preparation from the current
signed activation and Campaign, then jointly verify the sealed Run and the existing SQLite Graph
approval/Permit authority. Require one exact durable approval-consumption receipt, consumed
ActionPermit, completed dispatch lifecycle, request reservation, Tool/Worker Evidence, recomputed
Gateway outcome, exact Worker egress metadata, and one host-observed matching CONNECT receipt.

Submit one neutral `network.protocol-observation` with the succeeded Action and two Evidence nodes
through the existing `GraphAdmissionAuthority`. Keep raw banner, product/version material, Target
coordinates, and Worker transcripts out of Graph prose; bind their safe identities only through
content digests.

Permit a second `network.exposure` Hypothesis only for the fixed classifier vocabulary `ftp`,
`imap`, `pop3`, `smtp`, and `ssh`. Link it from the admitted Observation with `enables`, fix its
confidence at `0.5`, and phrase it as a possibility requiring a separately authorized fresh
passive handshake. When the label is absent, create no Hypothesis and no negative conclusion.

Require the Observation proposal at the caller-bound current Graph head and require the optional
Hypothesis to be the immediately following semantic attempt. Exact retries reuse prior events and
must not redispatch. Keep all action-authority markers false.

## Consequences

- One approved passive result can become auditable neutral Network knowledge without another
  socket operation.
- A bounded label can seed an open validation question but cannot confirm a service or Finding.
- Approval and Permit records remain provenance, not bearer authority.
- Graph single-writer, event, node, edge, and lineage wire formats remain unchanged.
- Unknown banners remain observations without being misreported as service absence.
- NET-001D remains responsible for fresh-handshake Replay, controls, Ground Truth, and metrics.
- The gate verifies sealed Docker host evidence but does not compose an end-to-end Network
  deployment or re-authenticate live Worker mTLS; those remain prerequisites of source dispatch.

## Rejected alternatives

### Admit the service label as a confirmed Surface

Rejected because a deterministic banner prefix is neither independent validation nor durable
proof of the endpoint's service, product, or version. The existing `network-port` Surface remains
the exact identity authority.

### Copy raw banners into Graph text

Rejected because target-controlled bytes can contain secrets, misleading claims, control
characters, or high-cardinality product data. The sealed Evidence retains them and Graph binds
only the banner digest and bounded classifier enum.

### Create a Hypothesis for an unknown banner

Rejected because absence of a recognized prefix is not evidence that no service exists and does
not support a bounded protocol statement.

### Reuse the source Permit for validation

Rejected because ActionPermits are consumed-on-issuance, non-bearer proofs. NET-001D requires a
freshly authorized action and distinct execution identity.

### Add a Network-specific Graph store or writer

Rejected because it would split Campaign knowledge and bypass the established single-writer,
lineage, stale-head, and idempotency boundaries.

### Generalize the existing Capability dispatcher in this slice

Rejected because the current dispatcher is intentionally pinned to the existing-mode activation
bundle. Relaxing that security type boundary is unnecessary for sealed knowledge admission and
would expand NET-001C into a runtime migration.

## Compatibility and rollback

The change is additive. Existing NET-001A/B, Capability, approval, Permit, Gateway, Worker, Run,
Graph, Replay, Finding, and benchmark contracts retain their versions. Rollback removes the
specialized workflow, tests, contract, and this ADR. Already admitted immutable Graph events stay
valid and require no data migration.

## Related documents

- [NET-001C contract](../graph/NET-001C-sealed-network-protocol-knowledge-admission.md)
- [NET-001B](../capability/NET-001B-passive-service-identification-capability.md)
- [NET-001A](../discovery/NET-001A-host-service-protocol-port-surface-model.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DOMAIN-005](../graph/DOMAIN-005-cross-domain-graph-admission.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0221](0221-bind-passive-service-identification-without-network-authority.md)
