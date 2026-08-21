# ADR-0209: Measure Red Team Profiles without Finding Authority

## Status

Accepted

## Context

REDTEAM-001A through REDTEAM-001D now expose five exact Capability identities under four product
profiles. CAP-003 maps those Capabilities to benchmark IDs, CAP-006 records Oracle and Replay
support, and BENCH-001 defines a broad Finding-centered result contract. None of those facts is an
actual measurement of detection recall, false positives, Replay success, request or Tool cost.

BENCH-001 also assumes positive Ground Truth Finding and chain denominators that do not honestly
describe every initial REDTEAM profile. REDTEAM-001C and REDTEAM-001D explicitly create no
independent Replay, and no REDTEAM-001 profile satisfies a validation floor or creates a valid
Finding. Filling those fields with zero would confuse absence of authority with measured failure;
silently omitting them would hide the product boundary.

## Decision

Add a separate, additive `pajin.dev/redteam-benchmark-profile-set/v1alpha1` denominator over the
exact REDTEAM-001A/B/C/D profile digests, CAP-002 `CodeBackedCapabilityRef` values, CAP-003 mapping
digests, request-unit costs, and CAP-006 Replay support digests and contract IDs.

Record raw facts in `pajin.dev/redteam-benchmark-run-observation/v1alpha1`. Each observation is one
of:

- an exact profile execution with one Tool call and the Capability's exact request-unit cost;
- a zero-execution-cost deterministic re-analysis, such as a negative control; or
- an independent Replay Run bound to a supported CAP-006 contract and a different source Run; or
- an expected policy-denial case with no Permit, Tool, model, or cost claim.

Every detection source binds its exact Capability, profile, mapping, benchmark ID, source Run/root,
source artifact SHA-256, CAP-006 Oracle observation, Ground Truth case classification, and evidence
denominator. Independent Replay sources bind a Ground Truth case from another source Run and a
supported CAP-006 Replay observation. Raw observations are sealed separately and must be reopened
before the aggregate can be published.

The initial report records detection recall, false-positive rate, detection precision, Replay
success, request units, Tool calls, cost, cost per detection, evidence completeness, and policy
denial correctness. It records explicit `not-applicable` values when the exact profile lacks a
registered negative-control or Replay path. Time to first valid Finding is always N/A in v1 because
REDTEAM-001 creates no valid Finding. Cleanup success is always N/A because all five actions are
read-only and declare `cleanupRequired=false`.

The report sets execution authority, Finding authority, Scope expansion, and Security Domain
authority markers to false. Profile, Capability, Tool, and Security Domain remain separate
concepts; no metric or benchmark result is an ActionPermit.

## Consequences

- Capability registration and benchmark mapping can no longer be reported as measured detection.
- Available and unavailable metrics remain distinguishable without manufacturing zero values.
- M03, M06, and A04 Replay measurements must use exact CAP-006-supported contract IDs.
- Web can measure its fixed internal negative control, while the current MCP profile reports false
  positive and Replay metrics as N/A until a separately registered measurement path exists.
- Sealed reference tests prove the contract and aggregation behavior, not public-target or
  production benchmark scores.
- The generic BENCH-001 wire and all REDTEAM-001 execution contracts remain unchanged.

## Rejected alternatives

### Treat CAP-003 mapping coverage as a detection result

Rejected because mapping states what may be measured, not what was detected.

### Force every profile into BENCH-001 Finding denominators

Rejected because current REDTEAM Observations are not validated Findings and C/D do not have an
independent Replay path.

### Infer applicability from Tool categories or Security Domain metadata

Rejected because metadata is neither measurement Ground Truth nor execution authority.

### Report unavailable values as zero

Rejected because zero is a measured result and would misrepresent a missing semantic denominator.

## Compatibility and rollback

The new contracts, recorder, runner, and report are additive. Removing REDTEAM-002 publication
leaves BENCH-001, CAP-003, CAP-006, REDTEAM-001, execution, evidence, Replay, and Finding readers
unchanged. Already sealed REDTEAM-002 artifacts remain self-describing under their versioned API.

## Related documents

- [REDTEAM-002 contract](../benchmark/REDTEAM-002-initial-profile-benchmark.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [CAP-003 contract](../capability/CAP-003-capability-authoring-sdk-scaffold.md)
- [CAP-006 contract](../capability/CAP-006-registry-quality-metrics.md)
- [REDTEAM-001A contract](../orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md)
- [REDTEAM-001D contract](../orchestration/REDTEAM-001D-registered-mcp-capability-profile.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
