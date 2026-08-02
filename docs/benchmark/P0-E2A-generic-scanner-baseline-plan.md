# P0-E2A Generic Scanner Baseline Plan

## Status

Implemented as a non-runnable `v1alpha1` contract and measurement plan. No Scanner binary, image,
adapter implementation, invocation receipt, raw output, normalized Observation, or Benchmark Result
is claimed.

## Goal and trust boundary

The repository had no generic Scanner adapter, SARIF parser, Scanner identity contract, or concrete
Scanner dependency when P0-E2 began. Selecting a product or treating synthetic JSON as measured
output would invent an execution boundary. P0-E2A instead fixes the information that a future
runnable Scanner must prove and binds that contract to the exact P0-D1 Target selection and every
BENCH-001 seed/repetition coordinate.

## Versioned authorities

| Authority | API version | Role |
| --- | --- | --- |
| `GenericScannerAdapterContract` | `pajin.dev/generic-scanner-adapter-contract/v1alpha1` | Required implementation identity, SARIF parser contract, and Target access policy |
| `ScannerBaselineCoordinate` | `pajin.dev/scanner-baseline-coordinate/v1alpha1` | One planned Manifest arm, seed, and repetition |
| `ScannerBaselineMeasurementPlanAuthority` | `pajin.dev/scanner-baseline-measurement-plan/v1alpha1` | Exact Target selection, Scanner contract, and complete coordinate set |

Every authority rejects unknown fields and uses bounded canonical JSON with a separate digest
domain.

## Invariants

1. The Manifest contains exactly one deterministic baseline arm using the code-owned generic
   Scanner contract identity and configuration digest.
2. The Manifest has no mutation profile and cannot include an adaptive candidate.
3. The existing P0-D1 selector must reconstruct the exact Traditional Web/API Manifest, adapter,
   Docker profile, public catalog, and private Ground Truth before the plan is created.
4. The plan binds catalog revision 1, its selection authority, and every protocol seed/repetition
   coordinate exactly once in canonical order.
5. A future implementation must bind `scannerId`, `scannerVersion`, executable artifact SHA-256,
   and configuration digest.
6. Raw output must use SARIF 2.1.0 and remain sealed before normalization. The parser contract
   requires tool identity plus rule, message, and location evidence.
7. Scanner identity, invocation receipt, raw output, Result eligibility, candidate comparison, and
   Supervisor activation are literal `false` in P0-E2A.

## Required rejection behavior

- unregistered Scanner implementation/configuration or changed parser semantics;
- candidate-bearing, mutated, cross-Target, or cross-Ground-Truth Manifests;
- alternate Docker profile, Target catalog, adapter, or private Ground Truth;
- missing, duplicate, extra, or reordered seed/repetition coordinates;
- arbitrary Scanner identity or raw-output fields added to the plan; and
- attempts to promote execution, Result, comparison, or activation flags.

## Compatibility and rollback

The implementation adds opt-in contracts and exports only. Existing Target, Harness, P0-E1 Result,
and BENCH-003 wire formats do not change. Rollback removes the plan types; it cannot invalidate or
reinterpret an executed Result because P0-E2A creates none.

## Runnable specialization

[P0-E2B](P0-E2B-zap-scanner-baseline-measurement.md) specializes this plan with an exact OWASP ZAP
2.17.0 image ID, a code-owned Automation Framework configuration, fresh Target isolation,
receipt-bound raw SARIF, strict normalization, recovery/cleanup, and registry-governed measurement
admission. P0-E2A remains the product-neutral non-runnable planning authority and is not itself a
measured Result.
