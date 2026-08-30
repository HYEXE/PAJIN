# ADR-0248: Clarify Forensic Replay Semantic and Execution Identity

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: FORENSICS-001D clarification of ADR-0247

## Context

ADR-0247 correctly requires a later, separately approved sealed execution and disjoint action and
evidence provenance. Its disjoint-identity list also names the normalized-parameter digest and
Capability Grant, but those values do not have the same lifecycle as preparation, approval,
Permit, execution, and receipt identity.

FORENSICS-001B derives `normalizedParametersDigest` from the complete canonical analysis request.
Deterministic re-parse therefore legitimately reuses it. Independent-parser mode may change it
because the request contains the concrete parser executable, configuration, image, and sandbox
coordinates that must all differ. Each FORENSICS-001C loader already recomputes and binds that
digest to its own complete request and Permit.

A Capability Grant is a bounded authority that may cover more than one separately approved
action. Separate approval, approval-consumption receipt, Permit, dispatch, execution, and Evidence
identity establish the per-execution separation. Requiring a fresh Grant ID would conflate that
action provenance with the lifecycle of its enclosing authority.

ADR-0247 also describes trusted wire reload as receiving the stored admission separately. The
actual contextful loader receives a validation projection, takes its embedded source admission,
and verifies that admission against the supplied exact source Graph store.

## Decision

Clarify ADR-0247 as follows:

- preparation, Run, evidence-root, request, MissionEnvelope, ActionProposal, Graph Decision,
  approval, approval-consumption receipt, ActionPermit, dispatch, execution, Gateway outcome,
  signed statement, runtime receipt, outer evidence, result receipt, and structural-Oracle
  identities must be disjoint;
- normalized-parameter digest is not an independent execution identity: deterministic mode may
  reuse it, while independent mode may change it only with the required concrete parser-coordinate
  differences, and each complete C context must still recompute and bind it exactly;
- Capability Grant authority semantics must match after excluding Grant ID and issuance/expiry
  timestamps; those excluded values may be equal or different and do not prove separate action or
  evidence provenance; and
- trusted wire reload verifies the projection's embedded source admission against the exact source
  Graph store rather than taking a separate admission parameter.

All other ADR-0247 decisions remain in force. This clarification does not relax the distinct
approval, Permit, execution, evidence, signed timestamp ordering, or deployment-context
requirements.

## Consequences

- deterministic re-parse remains constructible without inventing a false normalized-parameter
  identity;
- a long-lived but bounded Grant can authorize two independently approved executions without being
  mislabeled as execution provenance;
- independent-parser mode still requires every concrete parser implementation coordinate to
  differ; and
- the documented trusted-loader API now matches the implemented contextful verification path.
