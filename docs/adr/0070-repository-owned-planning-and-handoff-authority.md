# ADR-0070: Repository-Owned Planning and Handoff Authority

- Status: Accepted
- Date: 2026-08-01

## Context

PAJIN previously kept code-coupled contracts and decisions in Git while treating a Notion page as
the authority for roadmap priority, current progress, blockers, and verification state. That page
preserved useful product direction, but an implementation agent could not reconstruct the complete
working state from a clean clone without connector availability and a separate mutable source.

Long-running work also needs explicit rules for resumption, checkpoint verification, known
environment constraints, and the first next action. Keeping that state only in conversation or a
remote page creates drift between the code commit and the instructions used to continue it.

## Decision

1. Make the repository the authority for operational development state.
2. Add root `AGENTS.md` for persistent working rules, `PLAN.md` for roadmap and priority,
   `HANDOFF.md` for the executable current checkpoint, and `KNOWN_ISSUES.md` for reproduced
   unresolved limitations.
3. Keep `DECISIONS.md` as a small routing index only. Accepted rationale remains in the existing
   append-only `docs/adr/` hierarchy.
4. Write the five root operational-state documents in Korean, the primary operator language. Keep
   README, RFC, ADR, versioned contracts, and other technical documentation in canonical English;
   do not create translated sibling files.
5. Keep code/tests authoritative for behavior and versioned contracts authoritative for security
   boundaries. Operational documents cannot override them.
6. Maintain `PLAN.md` and `HANDOFF.md` as current-state snapshots, not append-only work logs. Do
   not copy historical Notion progress entries into Git.
7. Reconcile the active Phase 4 state, later milestones, unresolved product decisions, and known
   verification constraints from the former Notion roadmap at `main@a94df30`.
8. After the migration commit is published, update Notion once with links to the repository-owned
   authorities and retain it only as a read-only historical snapshot. Do not maintain two live
   roadmaps.
9. Require explicit user approval for commits, pushes, merges, remote branch changes, publishing,
   and deployment; recording work state does not grant that authority.

## Consequences

- A clean clone contains the priority, current checkpoint, decisions routing, and known limitations
  required to resume work.
- Operational changes become reviewable alongside code and cannot silently diverge from a commit.
- The root gains a small set of mutable status documents, so each must stay bounded and current.
- Notion loses authority and becomes optional historical context after the one-time cutover.
- Existing contracts, RFCs, ADRs, and historical references to the Notion-era baseline remain
  valid; accepted ADRs are not rewritten merely to replace an old contextual link.

## Migration and rollback

Migration updates the documentation authority policy, documentation tests, repository navigation,
and Architecture v2 Definition of Done in the same change. The old Notion content is not deleted.

Rollback restores Notion as operational authority in the documentation policy and navigation, then
archives or removes the root state documents in one reviewed change. Do not allow both locations to
claim simultaneous authority during rollback.

## Related documents

- [Documentation authority policy](../DOCUMENTATION_POLICY.md)
- [Repository plan](../../PLAN.md)
- [Current handoff](../../HANDOFF.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
