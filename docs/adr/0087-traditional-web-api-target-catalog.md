# ADR-0087: Separate Public Target Registration from Private Ground Truth

- Status: Accepted
- Date: 2026-08-01

## Context

P0-C2B2B proves one exact local Docker lifecycle, but the adapter directly receives a profile and a
Manifest. There is no explicit authority saying that this profile is an admitted Target family,
which Ground Truth it owns, whether mutation is allowed, or whether the same provider profile was
selected before execution. Generalizing the adapter to arbitrary images or commands would widen
the provider's execution authority before those policy boundaries exist.

BENCH-001 also deliberately keeps private Ground Truth cases out of the public Manifest. A Target
catalog therefore cannot make the Ground Truth contents public merely to bind selection.

## Decision

1. Add a content-addressed public Target profile registration and canonically ordered catalog.
2. Put only the Ground Truth digest in the public registration and keep complete cases in a
   separate private binding that repeats the exact registration.
3. Code-register the first Traditional Web/API profile as the existing fixed Boolean-SQLi Docker
   lab, with an empty mutation allowlist and a matcher digest over exact P0-C2B2B execution evidence
   semantics.
4. Add a non-executable selection authority binding catalog, registration, Manifest, adapter,
   provider profile, and private Ground Truth binding digests.
5. Wrap the recoverable Docker provider additively. Validate selection before any provider call,
   recheck provider identity on every operation, and require execution evidence and measured counts
   to match the registered Ground Truth before returning an Observation.
6. Keep all existing BENCH-001 and P0-C wire formats unchanged. Catalog selection neither issues a
   Capability nor replaces measurement-registry activation and sealed Harness admission.

## Consequences

- The first concrete Target is selectable through an explicit family/profile authority instead of
  an implicit constructor convention.
- Public benchmark configuration continues to expose only the Ground Truth digest, while a private
  verifier can prove exact cases and matcher identity.
- Unknown/stale profiles, cross-profile Ground Truth, mutation expansion, provider drift, and
  receipt/evidence substitution fail before their claims are admitted.
- Exact image IDs remain trusted provisioning inputs. The catalog is content-addressed but not yet
  signed, durably activated, or linked as a sealed source in the final Harness authority.
- The implementation intentionally covers one seeded Traditional Web/API profile. It does not
  claim generic matching or the remaining P0-D families.

## Compatibility and rollback

This change is additive. Existing raw adapter callers and all prior artifacts remain readable. New
governed callers can insert the wrapper below the existing recovery and registry runners without
changing their interfaces.

Rollback stops constructing the catalog wrapper and retains historical Manifest, Ground Truth,
Target Run, registry Admission, and governed Harness artifacts. A rollback must not silently
replace the provisioned catalog with a different image or Ground Truth under the same digest.

## Related documents

- [P0-D1 contract](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-C2B2B contract](../benchmark/P0-C2B2B-local-docker-provider-evidence.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
