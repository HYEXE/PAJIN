# ADR-0080: Bind Measured Candidate Configuration to the Sealed Shadow Policy

- Status: Accepted
- Date: 2026-08-01

## Context

BENCH-003B1 can measure any valid adaptive candidate Manifest. A matching Campaign and metric set
does not prove that the candidate was configured with the exact WALK-006 policy represented by the
BENCH-003A structural record. Calling such a Result a measured Shadow comparison without an exact
policy binding would be a lineage error.

## Decision

1. Add a separate BENCH-003B2 source-binding authority without changing measured values.
2. Require the B1 Manifest envelope and baseline arm to equal the A Manifest exactly.
3. Require the candidate implementation ID, version, and configuration digest to equal the exact
   code-owned WALK-006 policy ID, version, and digest.
4. Reload both A and B1 from their sealed Runs and bind Run/root/artifact provenance.
5. Embed both complete source authorities so Results and Comparison remain content-addressed.
6. Keep Supervisor activation eligibility false.
7. Keep the external measurement authority as an explicit semantic trust root; source binding does
   not manufacture provider attestation.

## Consequences

- A numeric Result pair can be identified as the exact Shadow policy candidate only after B2.
- Structural and measured benchmark layers remain independently readable and auditable.
- Metric values cannot be adjusted while adding the policy binding.
- An operational Target Factory/measurement adapter and external attestation remain required for
  production-quality evidence.

## Compatibility and rollback

The B2 authority, Runner, reader, and exports are additive. Removing them leaves BENCH-003A/B1 and
all BENCH-001 contracts unchanged.

## Related documents

- [BENCH-003B2 contract](../benchmark/BENCH-003B2-walking-shadow-policy-binding.md)
- [BENCH-003B1 contract](../benchmark/BENCH-003B1-walking-measurement-admission.md)
- [ADR-0079](0079-sealed-raw-observation-benchmark-admission.md)
- [ADR-0078](0078-shadow-decision-structural-benchmark.md)
