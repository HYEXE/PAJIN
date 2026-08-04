# HANDOFF-004: Capability-Scoped Artifact Reader

- Status: Implemented additive authority
- Date: 2026-08-04
- API: `pajin.dev/receiver-bound-artifact-read/v1alpha1`
- Implementation: `pajin.collaboration.reader`

## Outcome

HANDOFF-004 provides the first bounded content delivery from an existing MEM-002 sealed Artifact to
the exact receiver bound by HANDOFF-001/002. It reuses `CapabilityLedger`, the canonical Grant
digest, MEM-003 current Snapshot verification, and `load_verified_run_artifacts`; it creates no
Artifact store, Grant ledger, filesystem alias, Permit, Tool dispatch, or prompt interpreter.

Authorized bytes exist only on the in-process `ReceiverBoundArtifactReadOutcome`. The durable-shaped
`ReceiverBoundArtifactReadReceipt` is metadata-only, exposes no relative or absolute filesystem
path, and cannot return content again. A receipt is authoritative only when resolved from the same
process-local reader that emitted it.

## Capability and receiver boundary

The live existing Grant must:

- be the exact record currently held by the supplied `CapabilityLedger`;
- be unrevoked with exactly one remaining call and `maxCalls=1`;
- be delegated to the HANDOFF-002 terminal receiver Agent ID;
- name the same Campaign;
- include tool `collaboration.artifact.read`; and
- include the exact `SharedArtifactRef.sharedArtifactId` as its target.

The reader consumes the Grant through the existing ledger before loading bytes, which also consumes
every ancestor call budget. A fresh reader instance cannot replay the same Grant after consumption.
The receipt binds the complete Grant digest but does not grant a Capability itself.

## Snapshot, Artifact, TTL, and byte boundary

Before a read, the reader resolves the HANDOFF-002 result, reconstructs the same exact current
MEM-003 Snapshot, and reverifies the single MEM-002 source. The Artifact must still be an exact
Snapshot member. The authority-owned clock must fall between both the Grant window and a fixed
60-second window beginning at terminal-result completion.

One handoff/Artifact/receiver tuple gets one attempt, one read, and at most 65,536 cumulative bytes.
The sealed Run loader reads only the exact normalized Artifact path under its verified Run lock and
checks Run ID, current root, size, and SHA-256. The reader checks size and SHA-256 again before
returning an immutable `bytes` value. No raw path is returned.

An attempt is burned immediately before Capability consumption and disk access. If consumption or
the subsequent verified load fails, the reader does not retry or refund the Grant call. This avoids
ambiguous duplicate delivery after a partial failure.

## Urgent stop and concurrency boundary

The exact process-local HANDOFF-003 authority is queried before consumption and again after the
verified read. Any admitted urgent decision for the handoff denies content delivery. The Graph head
is also checked before consumption and after loading; a change discards the bytes and fails closed.

The final checks are cooperative in-process checks, not a distributed transaction. A decision or
Graph change immediately after the final check remains a known race until a downstream durable
fence exists.

## Negative and non-authority boundary

Foreign receiver, Artifact target, Campaign, Snapshot, source Run, or reader authority; mutated or
expired Grant; revoked or consumed lineage; stale Graph head; mutated sealed Artifact; TTL expiry;
second read; byte/count expansion; receipt forgery; and an admitted urgent stop fail closed.

`contentEmbedded`, `filesystemPathExposed`, `promptInterpretationAuthorized`,
`scopeExpansionAuthorized`, `capabilityGranted`, `permitGranted`, and `executionAuthorized` are
strict JSON `false`. Reading bytes is not prompt interpretation, Finding confirmation, Scope
expansion, Permit issuance, or Tool execution.

## Compatibility and boundaries

All existing Artifact, Run, Graph, Snapshot, Handoff, Capability, Permit, and execution formats
remain unchanged. Removing this module and exports requires no data migration. Ledger, reader
attempts, receipts, and HANDOFF-003 decision state are process-local and non-durable. The caller is
a trusted in-process delivery adapter; remote receiver authentication and cross-host fencing require
a later contract.

## Phase 5 adversarial regression

The Phase 5 exit test starts HANDOFF-001 from a MEM-003 Snapshot containing an admitted
prompt-shaped Campaign Fact, advances the same Graph chain to the HANDOFF-002 result Observation and
Artifact, and continues through HANDOFF-003/004. Snapshot, Handoff, decision, and receipt wires keep
only safe references and never copy the Fact statement or treat Artifact bytes as a prompt.

Additional integration cases combine independently valid material from another Run, another
Campaign, and another Capability ledger. Every combination fails before Capability consumption or
content delivery. Omitting the required urgent-decision authority fails reader construction.
