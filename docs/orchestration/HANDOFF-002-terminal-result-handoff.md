# HANDOFF-002: Terminal Result Handoff

- Status: Implemented additive authority
- Date: 2026-08-04
- API: `pajin.dev/terminal-result-handoff/v1alpha1`
- Implementation: `pajin.collaboration.terminal_result`

## Outcome

HANDOFF-002 binds one destination Task terminal outcome to an already admitted HANDOFF-001 record,
the destination Agent/Task lineage, one later current MEM-003 `CollaborationSnapshot`, and one exact
MEM-002 `SharedArtifactRef`. The wire contains result metadata only. It does not copy result bytes,
Task requests, prompts, messages, Tool requests, or filesystem paths, and it grants no read,
Scope, Capability, Permit, or execution authority.

The process-local `TerminalResultHandoffAuthority` admits at most one semantic result per handoff.
The terminal status is derived from the exact Agent/Task lifecycle pair rather than accepted as a
caller assertion.

## Required authority chain

Admission requires all of the following:

1. the supplied HANDOFF-001 record resolves exactly from the admitting `AgentHandoffAuthority`;
2. the historical Collaboration Snapshot identity and Campaign exactly match that handoff;
3. the historical Graph Snapshot and current Graph Snapshot occur, in that order, in the same
   `GraphSnapshotStore` append-only chain with every predecessor digest contiguous;
4. the current Collaboration Snapshot rebuilds exactly from the current Graph head and all supplied
   MEM-002 sealed Run sources;
5. the result Artifact reference is an exact member of that current Snapshot and belongs to the same
   Campaign;
6. the original receiver and destination Task equal the HANDOFF-001 safe references, while the
   terminal models retain every stable field of those originals; and
7. `completedAt` is not earlier than HANDOFF-001 admission.

The allowed lifecycle pairs are exact:

| Destination Task | Receiver Agent | Result status |
| --- | --- | --- |
| `succeeded` | `completed` | `succeeded` |
| `failed` | `failed` | `failed` |
| `cancelled` | `cancelled` | `cancelled` |

Here `succeeded` records Task lifecycle completion only. It does not confirm a Finding, validate the
semantic correctness of the artifact, or authorize another action.

## Retry, equivocation, and negative boundary

An exact semantic retry returns the first record even when a later caller supplies another
`completedAt`. A second status, Agent/Task terminal projection, Snapshot, or Artifact for the same
handoff is equivocation and fails closed. Non-terminal or mismatched Agent/Task states, lineage
mutation, stale or foreign Snapshot chains, cross-Campaign or non-member Artifacts, forged digests,
and authority substitution also fail closed.

`contentEmbedded`, `promptRelayAuthorized`, `scopeExpansionAuthorized`, `capabilityGranted`,
`permitGranted`, and `executionAuthorized` are strict JSON `false`; truthy and false-like non-boolean
values are invalid.

## Compatibility and boundaries

All HANDOFF-001, Agent, Task, Graph, Snapshot, Artifact, and execution formats remain unchanged.
Removing this module and its exports requires no data migration. The authority and admitted result
map are process-local and non-durable. There is no distributed transaction across Graph and Run
stores, no content reader, no Task scheduler, and no result dispatch. HANDOFF-003 owns the bounded
UrgentObservation Fast Gate; HANDOFF-004 owns receiver-bound content access.
