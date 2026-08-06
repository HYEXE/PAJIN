# APPROVAL-001A: Single-action Approval Before Permit Consumption

- Status: locally implemented
- Date: 2026-08-05
- Prerequisites: PERMIT-003, PERMIT-004A, PERMIT-004B1, GRAPH-006, ADR-0134

## Purpose

Require one deployment-authenticated operator approval before a T2 no-write action, or a T0/T1
Capability whose definition sets `approvalRequired=true`, can consume an `ActionPermit`. The
approval is not a bearer execution token. It is one exact input to the existing GRAPH authority,
and approval, Permit, and a non-reusable consumption receipt become durable in one SQLite
transaction before Worker dispatch.

This is the first bounded slice of APPROVAL-001. It supports `mode=single`, `maxActions=1`, and
`cleanupRequired=false` only. T2 write, dual approval-plus-cleanup, T3+, batch, and asynchronous
claim coordination remain out of scope.

## Authority inputs

`ActionApprovalEnvelope` is content addressed and binds:

- issuer authority identity, version, implementation type, and deployment context digest;
- distinct requester and approver principals;
- exact Campaign ID/digest, Run ID, and complete `MissionEnvelope`;
- source-intent and activation-set digests;
- signed release ID/digest and exact Capability ID/version/definition digest;
- complete `GraphDecision`, `ActionProposal`, expected deterministic `ActionPermit` ID, target,
  request, normalized parameters, risk, and budget reservation;
- `sideEffectClass` restricted to `none` or `read-only` and `cleanupRequired=false`; and
- approval, not-before, and expiry times bounded by all predecessor authority windows.

The content digest proves canonical integrity, not issuer authenticity. A deployment-pinned
`ActionApprovalInputAuthority` must authenticate the complete envelope before and after the
storage mutation boundary. There is no permissive default. Exact JSON types are required for the
single-action and non-reuse flags; boolean/number coercion is rejected.

`ActionApprovalCapabilityPolicyRegistry` is a canonical full-activation snapshot. It exact-matches
Capability identity, side-effect class, `approvalRequired`, and `cleanupRequired`; a caller cannot
supply a per-call policy to widen the deployment inventory.

## Atomic consumption

The approved writer is a path-specific, non-transferable process token. Generic, plain,
reversible, and cleanup writers cannot call the approved transaction. The transaction:

1. verifies the pinned writer, policy registry, and approval input authority;
2. resolves exact retry and rejects Approval, Proposal, request, or consumption equivocation;
3. revalidates Envelope, Proposal, Decision, Snapshot, Capability, policy, scope, budgets, and
   current time;
4. appends the canonical `ActionApprovalEnvelope`;
5. appends the existing consumed `ActionPermit`; and
6. appends one `ActionApprovalConsumptionReceipt` binding the complete approval and Permit.

All three rows commit or roll back together. The receipt fixes `reusable=false` and
`redispatchAuthority=false`. The first successful claim may invoke the Worker once. Exact retry
returns the durable Permit and receipt with `dispatched=false`, even after approval expiry, and
never invokes the Worker again. A callback failure or unknown outcome does not restore authority.

## Runtime composition

- General Attack accepts this approval for T2 no-write and T0/T1 `approvalRequired` actions. Its
  outcome gate reloads and exact-matches the durable receipt, and the assessment binds approval and
  receipt IDs and digests.
- `capability-graph-v1` loads deployment-pinned approvals and issuer verification, requires an
  approval for T2 or definition-required actions, and exposes approval and receipt IDs/digests in
  the completed Job result. Release and activation bindings are rechecked before Permit claim.
- Common Engine and legacy `deterministic-local` have no approval-aware composition and therefore
  reject T2 before Permit or Worker dispatch. The Web Console default remains a bounded T0
  `mock-sleep` request.
- APPROVAL-001B separately combines approval with the existing reversible cleanup hold for one
  bounded General Attack reversible write. This no-write authority still rejects that scope.
  T3+, batch, and async remain closed until separately versioned authorities exist.

## Persistence and trust boundary

GRAPH schema v4 adds append-only `graph_action_approval_envelopes` and
`graph_action_approval_consumptions` ledgers, integrity triggers, canonical chain heads, and backup
manifest counts. Current direct and retained backup wires are `v1alpha3`/schema v4. Strict
`v1alpha2`/schema v3 and `v1alpha1`/schema v2 readers migrate verified legacy material without
fabricating approvals or receipts.

Policy registries, writer tokens, and `ActionApprovalInputAuthority` implementations are
process-local deployment TCB. Approval, Permit, and receipt consumption is durable; the verifier
pin itself is not. Reopening the same database requires the trusted deployment to re-inject the
same code/file verifier and full policy inventory. This contract does not claim durable
cross-process verifier pinning or protect a database reopened by attacker-selected runtime code.

## Fail-closed conditions

- forged digest, malformed canonical JSON type, or unauthenticated issuer;
- self-approval, inactive/stale approval, or authority-window expansion;
- cross-Campaign, cross-Run, cross-Envelope, cross-Decision, cross-Proposal, cross-request, target,
  release, activation, reservation, or Permit substitution;
- policy inventory drift, side-effect or cleanup drift, risk/scope/budget expansion;
- missing approval where required or extra approval outside policy;
- T2 write on this no-write path, T3+, `mode=batch`, `maxActions` other than the JSON integer `1`,
  or async claim;
- generic or wrong-path writer use; and
- duplicate identity with different bytes, partial durable claim, or automatic redispatch after an
  uncertain outcome.

## Compatibility and rollback

The existing `ActionProposal`, `ActionPermit`, Gateway, Worker, and discovery wires remain
unchanged. Approval models, the approved dispatcher, optional Job input/result fields, and optional
outcome-assessment fields are additive. No-approval outcome assessments omit the new fields from
their digest so existing `v1alpha1` material retains its canonical identity.

Public direct-call authority constructors now require an explicit execution-policy registry and
path-specific store claim. Callers must provide the full deployment policy inventory instead of a
per-call policy. This is an intentional fail-closed Python composition change.

Rollback removes approved runtime composition, not durable evidence. A schema-v4 database cannot
be downgraded in place. Preserve v4 readers and backups, keep consumed approvals and Permits
immutable, and manually adjudicate unknown outcomes.

## Verification

Tests cover canonical model identity and strict JSON types, issuer rejection before and after the
storage boundary, single-transaction rollback, exact retry, expiry, replay and substitution,
path-specific writer isolation, policy-registry drift, concurrent claims, schema migration,
backup/restore compatibility, General Attack outcome receipt binding, Control Plane release
binding, Common Engine rejection, and Worker non-redispatch.

## Follow-up

- APPROVAL-001B is delivered as the separate atomic approval plus reversible cleanup-hold path.
- APPROVAL-001C: define separately versioned bounded batch and asynchronous approval consumption,
  partial-claim handling, and unknown-outcome reconciliation.
- A future deployment-security slice may durably bind policy/verifier inventory across process or
  host restart. It must not reinterpret existing process-local pins as durable authority.
