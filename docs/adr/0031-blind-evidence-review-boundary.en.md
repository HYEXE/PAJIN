> Languages: [English](0031-blind-evidence-review-boundary.en.md) | [한국어](0031-blind-evidence-review-boundary.ko.md)

# ADR 0031: Blind Evidence independent-review boundary

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.1 vertical slice
- Extends: [ADR 0030](0030-candidate-aware-atomic-claim-validation.en.md)
- Preserves: [ADR 0027](0027-independent-reproduction-confirmation-boundary.en.md)

## Context

Candidate-aware validation removed whole-Finding regeneration by judging the exact Candidate and
Atomic Claims, but a reviewer that sees the Candidate's conclusion, severity, and earlier decisions
remains exposed to confirmation bias. Giving the current Validator Tool authority to run controls
would instead merge semantic review with independent execution and weaken least privilege.

## Decision

B2 is split into two stages:

1. **B2.1 Blind Evidence Review:** implemented by this vertical slice.
2. **B2.2 Fresh-capability Controls:** follow-on work under a separate execution role and contract.

Trusted code projects only `validity` and optional `impact` Candidate-aware Atomic Claims into
`BlindEvidencePacket` objects. A Packet contains an opaque Claim ID, digest, type, the statement to
review, and allowlisted evidence references. It excludes Candidate ID, digest, source, disposition,
severity, prior Validator Decisions, and report context. A `severity` Claim is not projected because
its target statement would reveal the Candidate's proposed severity.

The Blind Reviewer receives a separate role and request and returns exactly one `supports`,
`contradicts`, or `insufficient` Decision per Packet. Evidence is limited to the Packet allowlist,
and ID, digest, or order substitution fails closed. The Candidate-aware Validator identity cannot
be reused as the Blind Reviewer identity. This first slice may use the same Provider, but the role,
input context, and output artifact are separate. The blind call has one attempt; failure, refusal,
or schema error seals every Packet as `insufficient`.

A deterministic Reconciler combines Candidate-aware and Blind Decisions for the same Claim:

- matching non-`insufficient` verdicts produce `corroborated`;
- `supports` versus `contradicts` produces `contested`; and
- either side being `insufficient` produces `inconclusive`.

Reconciliation is a sealed derived review artifact only. It cannot change the Candidate, severity,
disposition, existing `CandidateAssessment`, or replay eligibility.

## Authority boundary

Blind Review and Reconciliation cannot produce product-level `confirmed`. Confirmation still
requires Candidate-bound Restricted Replay, a Mode Oracle, the objective gate, and independent
execution attestation. The Validator receives no Tool execution Capability.

B2.2 Baseline, Negative Control, and Counterfactual execution belongs to a Control Executor with a
fresh Capability, separate request, evidence, and receipt. Incorporating those results into this
deterministic Reconciler requires a follow-on decision and implementation.

## Current limitations

- The first slice separates roles but may use the same Provider and model, so it does not guarantee
  true model diversity.
- Independent Candidate-severity derivation and severity Blind Review are not implemented.
- Baseline, Negative Control, Counterfactual execution, and independent receipts are not implemented.
- Claim-level replay, public `partially-confirmed` and `not-reproduced` states, and human-overturn
  measurement remain follow-on work.

## Validation requirements

- Blind Packets and Provider requests must omit Candidate identity, disposition, severity, and prior
  Decisions.
- Every Packet, Decision, and Reconciliation must bind deterministically to exact Claims and evidence.
- Reviewer-identity reuse and Claim order, ID, digest, or evidence substitution must fail closed.
- Blind-call failure must seal as `insufficient` and `inconclusive`.
- `contested` or `corroborated` alone must never confirm a Candidate or Finding.
- Legacy execution without a Candidate Producer must remain compatible.
