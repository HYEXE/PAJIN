# ADR-0054: Signed Reviewed Capability Lifecycle

- Status: Accepted
- Date: 2026-07-26

## Context

CAP-001 creates immutable Capability metadata, CAP-002 binds all seven executable code authorities,
and CAP-003 produces an inert deterministic scaffold. None establishes who reviewed a change,
which policy was applied, whether the review is still applicable to the exact proposal, or which
release is allowed for a pentest or bug-hunting run.

Treating the mutable `maturity` label, a package signature, a branch, or the highest semantic
version as activation authority would permit rollback, substitution, self-approval, and accidental
execution of incomplete code. Organization-specific signing roles and external-contribution
workflow are not yet decided, so the code contract must not pretend to define them.

## Decision

1. CAP-004 defines an additive offline lifecycle verifier. It does not wire runtime dispatch or
   claim durable operational storage.
2. One content-addressed policy fixes publisher/reviewer separation and minimum distinct-reviewer
   quorums: experimental 1, canary 1, stable 2, deprecated 1, retired 0.
3. Out-of-band Ed25519 trust keys bind one principal and publisher/reviewer role. Active keys sign,
   retired bounded keys verify history, and revoked keys fail closed.
4. A signed review binds the exact CAP-001 definition and CAP-002 authority-set reference, target
   maturity, sequence, predecessor, policy, checklist, decision, and validity window.
5. A publisher-signed release binds the same exact authority plus the sorted complete review-digest
   set. Review omission, addition, reuse, duplicate principals, or publisher self-review fails.
6. A lifecycle starts at experimental sequence 1 and uses a contiguous predecessor-digest chain.
   Experimental cannot jump directly to stable, and retired has no successor.
7. CAP-001 maturity and signed release maturity must match. Every lifecycle step requires a new
   immutable definition reference, including a same-maturity behavior revision.
8. Execution resolution requires an exact release reference and the current chain head. No method
   infers the latest executable version.
9. Experimental is range-only, canary is range/canary-only, and stable additionally permits
   pentest, bug-hunt, and CTF profiles. Deprecated and retired permit no new execution.
10. Deprecated and retired releases require an explicit notice. An optional replacement must
    resolve to another exact registered CAP-001/002 authority.
11. Organization roles, human workflow, external contributions, transparency, persistent
    anti-rollback storage, and runtime wiring remain explicit follow-up decisions.

## Rejected alternatives

- **Mutable maturity on an existing definition:** breaks CAP-001 immutable identity and audit
  replay.
- **Highest semantic version or latest registration wins:** creates implicit activation and
  rollback ambiguity.
- **Publisher signature only:** cannot demonstrate independent semantic review.
- **Reviewer count without distinct principal identity:** allows one reviewer or key to manufacture
  a quorum.
- **Package/repository signature as Capability review:** does not bind the exact policy, checklist,
  maturity proposal, predecessor, and code authority set.
- **Retired keys rejected for all history:** destroys offline verification after normal key
  rotation.
- **Revoked keys accepted for statements before revocation:** is unsafe without a separately
  trusted transparency and compromise-time model.
- **Automatic runtime registration:** would make CAP-004 silently change existing execution paths
  before CAP-005 compatibility and GRAPH-006 wiring are proven.

## Consequences

- Maturity becomes a verifiable signed release state rather than a free-standing label.
- Stable execution requires independent quorum and exact immutable code authority.
- Historical releases remain inspectable but cannot be reused for new execution.
- Emergency retirement remains possible with a publisher signature and cannot grant authority.
- Revocation intentionally invalidates loaded history; deployments that need more nuanced
  compromise-time treatment require a later transparency decision.
- The first registry is in-memory. Durable multi-process activation, anti-rollback state, and
  production identity administration remain unresolved rather than being hidden behind a local
  implementation.

## Compatibility, migration, and rollback

- Existing Capability, Tool, Graph, Replay, CLI, API, and database contracts are unchanged.
- Bootstrapping CAP-004 is explicit and additive. Existing runtime components are not
  auto-adapted or auto-activated.
- Not constructing the lifecycle registry is the rollback path.
- The four schemas are `v1alpha1`; incompatible evolution requires new API versions and explicit
  migration rules.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition and Tool Binding](0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052 Code-backed Capability Authority Set](0052-code-backed-capability-authority-set.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](0053-inert-deterministic-capability-scaffolds.md)
- [CAP-004 Maturity, Signing, Review, and Deprecation](../capability/CAP-004-maturity-signing-review-deprecation.md)
