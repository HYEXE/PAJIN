# ADR-0055: Explicit Existing Mode Capability Adapters

- Status: Accepted
- Date: 2026-07-27

## Context

CAP-001 through CAP-004 define immutable metadata, complete code authority, deterministic
authoring, and signed lifecycle admission. PAJIN already has bounded KISA, Bug Bounty, CTF, Tool,
and KISA Replay implementations, but those components predate the generalized Capability
registry.

Inferring Capabilities from every `ToolRegistry` entry would convert registration into execution
surface expansion. Replacing the existing Mode paths in the same change would also conflate
compatibility, activation, dispatch, and parity verification. The underlying Tools do not all
share the same semantics: KISA A01/A02 is a synthetic mock, only M03/M06/A04 support exact replay,
Bug Bounty is one fixed local lab, and CTF includes both a read-only Web probe and offline
analysis.

## Decision

1. CAP-005 provides one explicit, opt-in `existing_mode_capability_bundle()` bootstrap.
2. The bootstrap contains a closed seven-Capability inventory. It never scans modules or adapts
   arbitrary registered Tools.
3. Each Capability pins Tool version `1.0.0`, typed parameter schema plus scenario constraints,
   method, surface, threat classes, side effects, and a semantic Oracle policy.
4. All seven definitions begin at `experimental`. Existing Tool maturity does not bypass CAP-004
   first-release review.
5. Every Capability receives the full seven CAP-002 roles. Existing `Tool.prepare()` and
   `Tool.interpret()` remain executor and normalizer authority instead of being duplicated.
6. Success Oracles recompute semantics where a host-owned rule exists. They do not grant Finding
   authority or replace Gateway trusted-execution validation and sealed evidence.
7. Only KISA M03, M06, and A04 return a replay plan. The plan binds the existing exact replay
   identities, is explicitly non-executable, and requires new authorization.
8. Current adapters are `none` or `read-only` and have explicit no-op cleanup. A future write
   adapter requires a new version and cleanup design.
9. Existing Mode, CLI, Graph, Tool Gateway, Replay, API, and database paths remain unchanged.
   Runtime dispatch integration is a later opt-in vertical slice.

## Rejected alternatives

- **Adapt every registered Tool automatically:** silently expands the executable Capability
  surface and forces security metadata inference.
- **Use one generic Capability for all current Tools:** loses scenario, semantic Oracle, replay,
  side-effect, and parameter-schema identity.
- **Mark adapters stable because their Tools already run:** bypasses review of the new generalized
  authority path.
- **Let the Worker verdict drive success:** confuses an untrusted observation with semantic
  authority.
- **Return an immediately executable Replay request:** bypasses Replay compilation, grants,
  tickets, Policy, Gateway, and fresh-session enforcement.
- **Replace current Mode runtimes now:** removes the parity baseline before Hybrid and dispatch
  exit gates are measured.

## Consequences

- Existing bounded features now have exact CAP-001/002 identities suitable for review,
  measurement, and later dispatch.
- Unregistered and extra Tools stay outside the generalized Capability surface.
- Adapter and Tool drift is visible through stable-context and definition digests.
- Generalized execution is intentionally not yet live. Signed releases, CAP-006 metrics, runtime
  wiring, and one Web + AI Campaign remain required before the Phase 2 exit gate is complete.
- The small amount of explicit inventory duplication is intentional security configuration and
  must change through review.

## Compatibility, migration, and rollback

- The change is additive and in-memory; no persistent migration is required.
- Consumers opt in by constructing the bundle from an already populated `ToolRegistry`.
- Not constructing the bundle restores the prior behavior.
- Any incompatible adapter or Tool change requires a new Capability version, authority set, and
  CAP-004 release.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition and Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052 Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](0053-inert-deterministic-capability-scaffolds.md)
- [ADR-0054 Signed Reviewed Capability Lifecycle](0054-signed-reviewed-capability-lifecycle.md)
- [CAP-005 Existing Mode, Tool, and Replay Adapters](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
