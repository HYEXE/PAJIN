# BENCH-003B2: Walking Shadow Policy-Bound Measured Comparison

- Status: Implemented
- Authority contract: `pajin.dev/walking-shadow-measured-benchmark/v1alpha1`
- Decision: [ADR-0080](../adr/0080-shadow-policy-bound-measured-benchmark.md)

## Scope

BENCH-003B2 binds an exact sealed BENCH-003A structural source to an exact sealed BENCH-003B1
measured source. It does not calculate or rewrite any metric. Its purpose is to prove that the
adaptive candidate arm measured by B1 identifies the same code-owned WALK-006 Shadow policy that
produced the structural Task and Stop Decision in A.

## Required binding

The measured Manifest must be an exact two-arm extension of the structural baseline-only Manifest:

- benchmark, Target Factory/profile/mutation, Campaign, Ground Truth, and full protocol are equal;
- the deterministic baseline arm is exactly equal;
- the candidate is `adaptive-candidate` with `adaptiveSupervisor=true`;
- candidate `implementationId` equals the WALK-006 policy ID;
- candidate `implementationVersion` equals the WALK-006 policy version; and
- candidate `configurationDigest` equals the WALK-006 policy digest.

The authority embeds both complete source authorities and binds each source Run ID, root digest,
fixed artifact path, and artifact SHA-256. It preserves the B1 Comparison and Result values exactly.

The B2 reader requires exactly one seal, the exact three-artifact set (`campaign.json`, the fixed
authority path, and `run.json`), and the exact ordered three-event publication sequence. It parses
`run.json` as strict unambiguous JSON and reconstructs the complete start, created, completion, and
Run-record payloads. Extra artifacts or events, changed payloads, foreign Run state, and duplicate
JSON keys fail closed even when the forged envelope is otherwise integrity-sealed.

## Eligibility and trust boundary

The resulting state is `measured-shadow-policy-bound` and benchmark comparison eligibility is true.
Supervisor activation eligibility remains false: no threshold, rollout authorization, or
provider-backed measurement attestation is created here. B1's named external measurement authority
remains the semantic truth root; B2 proves configuration lineage, not the producer's honesty.

## Negative boundaries

A foreign policy digest, ID, or version; changed Manifest envelope or baseline arm; a non-adaptive
candidate; Campaign substitution; mutated A/B1 source; forged source provenance; modified metric,
Result, Comparison, policy field, output authority, publication event, artifact set, event payload,
or Run record fails closed.

## Compatibility and next step

BENCH-001, BENCH-003A, and BENCH-003B1 wire formats are unchanged. This closes the additive
BENCH-003 comparison Harness. Operational benchmark credibility still requires the existing P0-C
follow-up: a provider-backed Target Factory measurement adapter that actually performs and attests
reset, isolation, execution, observation, and cleanup for every coordinate.

## Related documents

- [BENCH-003B1 contract](BENCH-003B1-walking-measurement-admission.md)
- [BENCH-003A contract](BENCH-003A-walking-shadow-decision-comparison.md)
- [WALK-006 contract](../orchestration/WALK-006-shadow-supervisor-decision-record.md)
- [BENCH-001 contract](BENCH-001-benchmark-contract.md)
- [Architecture v2 RFC](../rfc/0001-pajin-architecture-v2.md)
