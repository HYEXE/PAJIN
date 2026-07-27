# CAP-004: Maturity, Signing, Review, and Deprecation

- Status: locally implemented
- Date: 2026-07-26
- Prerequisites: ARCH-001, CAP-001, CAP-002, CAP-003, ADR-0051, ADR-0052, ADR-0053

## Purpose

Turn an exact CAP-001 definition and complete CAP-002 code authority set into a reviewable release
without treating a package name, scaffold, maturity label, or "latest" lookup as activation
authority.

CAP-004 is an offline reference contract. It defines cryptographic and lifecycle invariants while
deliberately leaving organization-specific roles, external-contribution workflow, durable
operational storage, and runtime dispatch wiring open.

## Task contract

- **Task ID:** CAP-004
- **Threat model:** forged or replayed reviews, publisher self-review, duplicate-reviewer quorum,
  maturity skipping, rollback to an older release, definition or authority-set substitution,
  future-dated authority, expired review reuse, key compromise, silent deprecation, and implicit
  latest-version execution
- **Changed trust boundary:** reviewed CAP-001/002 authority to publisher-signed release admission
- **Schema/API versions:** `pajin.dev/capability-lifecycle-policy/v1alpha1`,
  `pajin.dev/capability-lifecycle-trust-key/v1alpha1`,
  `pajin.dev/capability-review/v1alpha1`, and
  `pajin.dev/capability-release/v1alpha1`
- **Audit artifacts:** content-derived policy, review, release, predecessor, definition, and
  authority-set digests plus detached Ed25519 signatures
- **Benchmark impact:** none until CAP-006 coverage measurement and later runtime wiring execute
  reviewed CAP-005 adapters

## Reference policy

`CapabilityLifecyclePolicy.reference_policy()` requires:

| Target maturity | Distinct approvals | New execution profiles |
| --- | ---: | --- |
| `experimental` | 1 | `range` |
| `canary` | 1 | `range`, `canary` |
| `stable` | 2 | `range`, `canary`, `pentest`, `bug-hunt`, `ctf` |
| `deprecated` | 1 | none |
| `retired` | 0 | none |

The policy always separates publisher and reviewer principals. Deployments may require a larger
quorum, but cannot configure a value below these safe minimums. A zero-review retirement remains
publisher-signed and exists as an emergency stop; it cannot activate execution.

## Signed authority

### Trust keys

Each out-of-band `CapabilityLifecycleTrustKey` binds one key ID, principal ID, `publisher` or
`reviewer` role, raw Ed25519 public key, validity window, and `active`, `retired`, or `revoked`
state.

- Active keys may create new signatures.
- Retired keys with a bounded `notAfter` may verify statements issued in their historical validity
  window, but cannot create a signer.
- Revoked keys fail closed for all loaded releases, including history.
- A principal may have at most one active key per role in one registry.
- Private key material is accepted only by the signing helper and is never stored in a Pydantic
  artifact.

### Reviews

A `CapabilityReviewStatement` binds the exact `CodeBackedCapabilityRef`, target maturity, lifecycle
sequence, predecessor release digest, policy digest, reviewer principal, checklist digest,
decision, issue time, and expiry. Its ID and digest are content-derived.

Only approved, correctly signed reviews that were valid when the publisher issued the release
count. Review principals must be distinct from each other and from the publisher. The release
contains the sorted exact review-digest set, so omission, addition, reordering, or cross-release
reuse fails.

### Releases

A `CapabilityReleaseStatement` binds the exact CAP-001 definition and CAP-002 authority-set
digests, maturity, contiguous sequence, predecessor digest, policy digest, review digests,
publisher principal, issue time, and any deprecation notice. Its ID and digest are content-derived,
then the publisher signs the complete canonical statement.

The CAP-001 definition maturity must equal the release maturity. Because CAP-001 definitions are
immutable, every lifecycle step, including a same-maturity revision, requires a new definition
version/digest and a corresponding code-backed authority reference.

## Lifecycle and resolution

Every chain begins at `experimental`, sequence 1, with no predecessor. Allowed transitions are:

```text
experimental -> experimental | canary | retired
canary       -> canary | stable | deprecated | retired
stable       -> stable | deprecated | retired
deprecated   -> deprecated | retired
retired      -> no successor
```

`CapabilityLifecycleRegistry` verifies complete chains regardless of input ordering. It exposes:

- exact historical inspection by `CapabilityReleaseRef`;
- explicit management lookup of a chain head; and
- execution admission only for the exact current head and an allowed profile.

There is no implicit latest-version execution lookup. A historical, deprecated, or retired release
cannot grant new execution authority. Resolution revalidates the CAP-002 code authority to catch
adapter drift after lifecycle construction.

## Deprecation

`deprecated` and `retired` releases require an explicit reason code, bounded summary, announcement
time, and effective time. An optional replacement must be a different, already registered exact
CAP-001/002 reference. Other maturity states cannot carry a deprecation notice.

The reference registry blocks new execution immediately when a definition is released as
deprecated or retired, even if the notice's effective time is later. A deployment that needs a
warning interval keeps the previous executable maturity current until the deprecation release is
issued.

## Verification

- exact Ed25519 review and release signature verification;
- policy-digest, principal-role, key-validity, retirement, and revocation checks;
- publisher/reviewer separation, distinct-reviewer quorum, rejection, expiry, and review-set
  binding;
- experimental range-only and stable pentest/bug-hunt admission;
- historical-head, deprecated, and retired execution rejection;
- contiguous predecessor chain, legal transition, and new immutable definition requirements;
- mandatory deprecation notice and exact replacement validation; and
- retired-key historical verification with new signing disabled.

## Compatibility, migration, and rollback

- CAP-004 adds contracts and an in-memory verification registry. It changes no existing Tool
  Gateway, Capability Grant, ActionPermit, CLI, API, or persistent schema.
- Existing CAP-001/002 definitions remain unactivated unless bootstrap code explicitly supplies a
  verified release chain.
- CAP-003 scaffolds remain inert and are never registered automatically.
- Rollback means not constructing the lifecycle registry; existing runtime paths remain unchanged.
- `v1alpha1` artifacts require an explicit version bump for incompatible field or policy changes.

## Follow-up boundaries

- organization-specific publisher/reviewer authorization and external-contribution workflow;
- durable signed Capability Registry storage, anti-rollback state, and operational key
  distribution;
- reviewed signed releases for the experimental CAP-005 existing-mode adapter definitions;
- CAP-006 coverage, lead-time, Oracle, Replay, and lifecycle measurement contracts are
  implemented; reviewed adapter releases and operational samples remain follow-up work;
- opt-in GRAPH-006 ActionPermit and Tool Gateway runtime wiring; and
- Linux CI and clean-clone verification.

## Related documents

- [ARCH-001 PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0051 Versioned Capability Definition and Tool Binding](../adr/0051-versioned-capability-definition-and-tool-binding.md)
- [ADR-0052 Code-backed Capability Authority Set](../adr/0052-code-backed-capability-authority-set.md)
- [ADR-0053 Inert Deterministic Capability Scaffolds](../adr/0053-inert-deterministic-capability-scaffolds.md)
- [ADR-0054 Signed Reviewed Capability Lifecycle](../adr/0054-signed-reviewed-capability-lifecycle.md)
- [CAP-005 Existing Mode, Tool, and Replay Adapters](CAP-005-existing-mode-tool-replay-adapters.md)
