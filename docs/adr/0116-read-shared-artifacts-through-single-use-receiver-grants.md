# ADR-0116: Read Shared Artifacts Through Single-Use Receiver Grants

- Status: Accepted
- Date: 2026-08-04

## Context

MEM-002 deliberately returns metadata only, while Phase 5 eventually needs a bounded way for the
HANDOFF receiver to obtain content. Returning a Run path or adding a collaboration content store
would bypass the sealed Artifact boundary. A reader-owned token ledger would duplicate existing
Capability issuance, attenuation, revocation, and lineage accounting.

## Decision

Use the existing `CapabilityLedger` and a delegated `maxCalls=1` Grant scoped to the exact terminal
receiver, Campaign, `collaboration.artifact.read` tool, and Shared Artifact ID. Reverify the exact
HANDOFF-002 current Snapshot and MEM-002 sealed source, deny any HANDOFF-003 stop decision, consume
the existing Grant lineage, and load only that Artifact through `load_verified_run_artifacts`.

Fix delivery to one attempt/read, 65,536 cumulative bytes, and 60 seconds from terminal completion.
Use a reader-owned clock rather than caller-declared time. Return bytes only in the in-process
outcome and store a content-free receipt. Recheck Graph head and urgent decision before returning.

## Consequences

- receiver, Grant, Artifact, Snapshot, Run, TTL, byte, and read-count identities are exact;
- Capability replay remains blocked even across a fresh reader instance because the existing Grant
  and ancestor budget are consumed;
- failures after attempt start burn the attempt and do not refund the Grant call;
- an urgent stop denies reading but does not revoke the Grant itself;
- the receipt grants no Capability, Permit, Scope, prompt interpretation, or execution authority;
  and
- remote authentication, durable receipts, and atomic cross-authority fencing remain future work.

## Rejected alternatives

Returning a filesystem path was rejected because it bypasses Run locking and bounded reads.
Embedding bytes in the receipt was rejected because it creates a replayable content store. A
reader-local token without `CapabilityLedger` consumption was rejected because a new reader could
replay it. Caller-supplied timestamps were rejected because an old time could bypass TTL expiry.
