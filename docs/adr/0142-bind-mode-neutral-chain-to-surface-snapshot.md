# ADR-0142: Bind Mode-neutral Attack Chains to Sealed Surface Snapshots

- Status: Accepted
- Date: 2026-08-10

## Context

Phase 8 begins with Auth Bypass to AI Admin Surface coverage. Existing legacy Modes describe
operating context, while PROF-001 already establishes that Profiles cannot become another Campaign
authority. DISC-003 provides typed authentication and RAG boundaries, and ORCH-001 can reopen their
exact sealed Surface projection. No current evidence proves that authentication was bypassed or an
AI administration function was reached.

Inferring an admin surface from a path such as `/admin`, accepting a caller-built Surface Set, or
emitting an executable `AttackHypothesis` would turn descriptive coverage into unsupported semantic
or execution authority. Creating a new cross-mode Graph or validation store would also duplicate
existing authority.

## Decision

1. Register one code-owned CHAIN-001 contract independently of `CampaignMode`.
2. Interpret the currently supported AI administration surface narrowly as an explicit DISC-003C
   `http-rag` locator with `boundary=index-management`.
3. Require one non-anonymous `http-authentication` locator on the exact same typed route and
   Campaign target.
4. Reopen the Recon source and projection Runs through `load_recon_surface_authority()` and bind the
   resulting ORCH-001 `SurfaceSnapshotAuthority` and Campaign digest.
5. Store only bounded Surface references, their locator and complete Surface digests, and the exact
   route digest in a content-addressed authority.
6. Fix the result to `hypothesized-not-validated`, with Capability, execution, Claim Replay, and
   Finding confirmation authority false.
7. Rebuild and exact-match the authority against the sealed predecessor on every verification.

## Consequences

- The same chain semantics work for `ai-redteam`, `bug-bounty`, and `ctf` without discarding the
  original Campaign authority.
- A URL name, target description, model output, or caller-supplied digest cannot create the chain.
- Route, target, Campaign, Snapshot, and Recon publication substitution fail closed.
- The first Phase 8 chain remains a coverage hypothesis, not an exploit or validated Finding.
- Other AI administration surfaces require an explicit typed locator or a later contract version.

## Rejected alternatives

### Infer AI administration from route text

Rejected because target-controlled names and descriptions are not semantic authority and would
produce false coverage.

### Treat every authenticated RAG route as an admin surface

Rejected because corpus ingestion and retrieval do not necessarily grant index administration.
Only the explicit `index-management` boundary is accepted in v1.

### Add Campaign Mode to the chain contract

Rejected because Mode changes reporting and operating context, not the cross-surface security
relationship. The Campaign digest is still preserved to prevent cross-authority replay.

### Emit execution or validation authority

Rejected because Surface discovery alone proves neither bypass nor access. Existing Capability,
Permit, Replay, and validation gates remain the only applicable authorities.

## Compatibility and rollback

The new API is additive and consumes existing sealed artifacts without changing their wire shape.
Rollback removes the compiler, contract, and exports. Existing Recon, Surface Snapshot, Graph,
Profile, validation, and Replay artifacts remain unchanged and readable.

## Related documents

- [CHAIN-001 contract](../orchestration/CHAIN-001-mode-neutral-auth-bypass-ai-admin.md)
- [DISC-003 contract](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ORCH-001 contract](../orchestration/ORCH-001-surface-snapshot-plan-task-binding.md)
- [ADR-0046](0046-common-engine-and-campaign-profiles.md)
- [ADR-0065](0065-surface-snapshot-bound-orchestration.md)
