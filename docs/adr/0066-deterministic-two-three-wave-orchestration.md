# ADR-0066: Deterministic Two-to-Three-Wave Orchestration

- Status: Accepted
- Date: 2026-07-30

## Context

A5 already promotes sealed Hypothesis results into append-only Observations and can select one
novel registered transition into a second fresh-Capability wave. It is fixed to two waves, compares
only the first and candidate Plan states, and does not reload the additive ORCH-001
`surface-bound-plan.json` when the replanning Run consumes a wave.

ORCH-002 requires a deterministic baseline that can express a bounded three-step chain while
proving that admitted Observations change subsequent Plans and that cycle, repeated state, and
authority expansion cannot create another dispatch.

## Decision

1. Extend `BoundedReplanningPolicy` to the exact pairs `(2, 1)` and `(3, 2)` for maximum waves and
   replans.
2. Add `DeterministicMultiWaveAuthority` over the complete Campaign, exact ORCH-001 Surface
   Snapshot, policy, deterministically previewed full ORCH-001 Compiler Plan states, Observation
   rules, and transitions.
3. Keep `BoundedReplanningRunner` and its default `next_wave` path. Add an opt-in `next_waves`
   configuration and iterate the same A5 admission logic up to the policy bound.
4. Compute every candidate state from the exact Surface Snapshot, Compiler ID, and rule set.
   Equality with the current state is `repeated-state`; equality with an earlier state is
   `cycle-detected`.
5. Select transitions only from the current wave's admitted Observations.
6. Reload and verify every wave's sealed ORCH-001 Plan, terminal state, and audit fields. Require
   every accepted wave to use the same complete Surface Snapshot authority and to equal its
   previewed Hypothesis Set, Wave Plan, and Plan digest.
7. Bind the Multi-wave authority into new Replan Decisions and bind ordered ORCH-001 Plan digests
   into new Observation Graph revisions.
8. Preserve legacy v1 identity calculation when the additive fields are absent.

## Consequences

- A deterministic `A -> B -> C` chain can run as three distinct fresh-Capability waves.
- `A -> B -> A` and `B -> B` stop before the third dispatch and remain auditable.
- Campaign Scope and ORCH-001 Snapshot replacement are detectable from one content-addressed
  authority.
- The Replanning Run now independently verifies the Plan/Task binding it consumes instead of
  relying only on the producing wave.
- The existing one-time Campaign Planner, Supervisor activation, multi-adapter scheduling, and
  canonical Campaign Graph integration remain unchanged.

## Compatibility and rollback

Existing two-wave construction, `next_wave`, artifacts, and readers remain supported. New fields
are additive; absent fields use the legacy identity domain. Rollback configures one follow-up
runner with the default two-wave policy and stops producing new ORCH-002 authorities. Already
sealed Runs are not rewritten.

## Related documents

- [ORCH-002 contract](../orchestration/ORCH-002-deterministic-multi-wave-baseline.md)
- [ORCH-001 contract](../orchestration/ORCH-001-surface-snapshot-plan-task-binding.md)
- [ADR-0065: Surface Snapshot-Bound Orchestration](0065-surface-snapshot-bound-orchestration.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
