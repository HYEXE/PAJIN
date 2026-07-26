# ADR 0030: Candidate-aware validation and Atomic Claim decisions

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement vertical slice
- Extends: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.md)
- Preserves: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

## Context

The generic Provider Validator regenerated a whole Finding and a trusted adapter compared it with
the Candidate afterward. Wording or evidence-order differences could therefore look like omission
even when the semantic judgment was useful. A composite Finding also could not express independent
judgments about exploit validity, impact, and severity.

## Decision

Trusted code deterministically decomposes an admitted Candidate into `validity`, optional `impact`,
and `severity` Atomic Claims. Every Claim has a canonical ID and SHA-256 digest bound to the
Candidate ID and digest, Claim type, statement, and evidence. The Provider does not return a
Candidate or Finding. It returns exactly one `supports`, `contradicts`, or `insufficient` Decision
for every exact Claim ID and digest, plus rationale and Candidate-owned evidence references.

The runtime requires the exact deterministic Claim set and order, one Decision per Claim, matching
IDs and digests, and evidence contained by that Claim. `supports` carries only supporting evidence,
`contradicts` only contradicting evidence, and `insufficient` classifies no evidence. Only the
`validity` Decision projects into the existing `CandidateAssessment`; impact and severity remain
separate sealed judgments and cannot mutate the Candidate, its severity, or its disposition.

Claims and Decisions are stored in `validator-output.json` with the exact Validator Agent and Task
identity and are included in the source Run seal. Durable consumers must rederive Claims from the
sealed Candidate and verify the stored set and Decisions.

## Authority boundary

This ADR refines semantic review only. A supported Claim is not product-level `confirmed`; the
existing Gate still caps it at `needs-review` with `independent-reproduction-missing`. Confirmation
continues to require Candidate-bound Restricted Replay, a Mode Oracle, the objective gate, and
independent execution attestation. A severity contradiction neither rejects validity nor rewrites
the original Finding.

Legacy execution without a trusted Candidate continues to use the whole-Finding Validator path.
When Provider validation falls back, results are rebound to exact Candidates and any Claim not
independently assessed remains `insufficient`.

## Current limitations

- Claim types are limited to validity, impact, and severity.
- Claim-level replay and independent execution attestation are not implemented.
- Public `partially-confirmed` and `not-reproduced` dispositions are not introduced.
- Impact/severity report UI and human-overturn measurement remain follow-on work.
- The legacy Validator adapter remains for compatibility.

## Validation requirements

- Exact validity support must reach the Candidate gate without Provider Finding regeneration.
- Validity support and severity contradiction must coexist in one sealed artifact.
- Candidate/Claim ID or digest, Claim order, and evidence substitution must fail closed.
- Atomic Claim review alone must never produce Candidate or Finding confirmation.
- Existing execution without a Candidate Producer must remain compatible.
