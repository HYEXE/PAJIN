# ADR 0037: Control Plane Claim-Specific Public Projection

- Status: Accepted
- Date: 2026-07-24
- Scope: Phase 4 Validation Refinement B2.6 first vertical slice
- Extends: [ADR 0029](0029-control-plane-replay-orchestration.md),
  [ADR 0035](0035-claim-replay-public-state-projection.md),
  [ADR 0036](0036-claim-bound-replay-execution-authority.md)

## Context

ADR 0036 gave each validity, impact, and severity Claim for exact KISA M03, M06, and A04 its own
compiled authority, Replay Run, fresh session, Oracle, and receipt. The PostgreSQL Control Plane,
however, still issued Candidate-wide confirmation items and could express only v1 Candidate or v2
Retest projection inputs. It therefore could not preserve the Local path's Claim-specific execution
authority through the durable claim-to-permit-to-finalize-to-projection path.

Changing existing Candidate confirmation and negative Retest implicitly would change stored
authority and API idempotency boundaries. Impact or severity support must also never bypass the
validity-based confirmation invariant.

## Decision

1. Add an explicit `CreateReplayBatchRequest.claim_projection` opt-in. It defaults to `false` and
   cannot be combined with remediation Retest. Existing confirmation v1 and negative Retest v1
   policies remain unchanged; only opt-in confirmation uses
   `pajin.kisa-claim-confirmation:v2`.
2. Derive three Replay items—validity, impact, and severity—for every exact KISA Candidate. Each
   item has its own Claim-bound contract, compilation, Run, ticket, execution context, permit set,
   finalization, and output Artifact.
3. Schema v13 adds append-only `cp_replay_claim_bindings`, binding each item to its source Candidate
   ID and exact `ReplayClaimBinding`. The existing `(batch_id, candidate_id)` uniqueness is not
   rewritten; a Claim item uses its Claim ID as the internal key. Public views restore the source
   Candidate ID and expose the Claim.
4. Projection input authority v3,
   `pajin.control-plane.replay-projection-inputs/v3`, seals Candidate ID and digest, Claim ID,
   digest, type and statement, ticket, compilation, Run, output, receipt, and Gate digests for
   every finalized item. Missing or duplicate Atomic Claim coverage fails closed.
5. The server reverifies every Claim output before publishing one versioned validation projection
   and `claim-replays.json`. The common Gate is retained and only validity drives internal
   confirmation. Impact and severity remain information-only and cannot independently confirm a
   Finding or mutate severity.
6. Claim binding rows reject UPDATE, DELETE, and REPLACE. Finalization retries and projection reads
   converge on the committed result, while v1 confirmation and v2 Retest projections remain
   readable.

## Authority and Recovery Boundary

Claim identity is derived from the source Candidate's deterministic Atomic Claims and must agree in
both compilation and the append-only binding ledger. Any Worker substitution of Candidate, Claim,
compilation, or ticket is rejected before claim or finalization. Projection publishes once through
CAS after every item is verified; a retry after response loss returns the same committed authority.

## Limitations and Follow-ups

- This first vertical slice is limited to exact KISA M03, M06, and A04 and Mode-owned impact and
  severity policy.
- Because `independent_execution_attested=false`, even a reproduced validity Claim can currently
  remain publicly `partially-confirmed`.
- Local seals, the PostgreSQL append-only ledger, and managed Artifacts provide content, lineage,
  and restart recovery, not cryptographic attestation of execution by another organization or
  off-host system.
- [ADR 0038](0038-portable-claim-receipt-attestation.md) implements this follow-up for Control
  Plane receipts with public-key signatures, key rotation and revocation, a verifier bundle, and
  an external trust anchor. Independent executor/target execution attestation remains follow-up.

## Verification Requirements

- An opted-in Candidate must have exactly three Claim items and three unique Replay Runs.
- Claim ID, digest, type, and statement plus Candidate digest must not change from derivation to the
  public v3 authority.
- Claim binding mutation and partial or duplicate Claim projection must be rejected.
- Impact or severity support alone must not create a confirmed Finding or confirmation basis.
- Existing v1/v2 batches, migrations, and finalization/projection idempotency must remain intact.
