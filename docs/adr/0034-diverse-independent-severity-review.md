# ADR 0034: Diverse Provider/model independent severity review

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.3 first vertical slice

## Context

The B2.1 Blind Evidence Reviewer evaluates validity and impact Packets after Candidate identity,
disposition, severity, and prior decisions have been removed. The default Provider Runtime still
used the same Provider and model for the Primary Validator and Blind Reviewer. The existing
severity Atomic Claim also contains the Candidate's proposed severity string as its statement.
Sending that statement to another Reviewer would be a vote on a disclosed label, not an independent
derivation.

## Decision

1. `provider-agent-run` may explicitly opt into a separate review Provider registration.
2. The review registration must differ from the Primary in Provider ID, endpoint, and model. Any
   equality fails closed before execution.
3. The Primary Validator and diverse Reviewer use separate Agents, Tool allowlists, endpoints,
   Capability call budgets, and Secret Leases.
4. The diverse Reviewer may call only its Provider Tool, once for Blind Evidence Review and once
   for Severity Derivation. It receives no authority for the Primary Provider Tool.
5. A `SeverityDerivationPacket` contains only an opaque severity Claim ID plus validity and optional
   impact `BlindEvidencePacket` context. It excludes Candidate identity, proposed severity,
   disposition, Primary Decisions, and report context.
6. `IndependentSeverityDecision` records `derived` or `insufficient` plus allowlisted evidence.
   Failure, refusal, or schema error seals `insufficient` after one attempt.
7. `ProviderModelReviewBinding` canonically binds the Primary and Reviewer Provider IDs, endpoints,
   models, and the actual Reviewer Agent ID.
8. Deterministic `SeverityClaimReconciliation` compares the independent derivation with the original
   Candidate severity as `corroborated`, `contested`, or `inconclusive`.
9. Independent severity output and reconciliation always set `informationalOnly=true`,
   `confirmationEligible=false`, and `mutatesCandidate=false`. They cannot change Candidate,
   Finding, disposition, Replay eligibility, or confirmation.
10. `ValidatorOutput` defaults to v1alpha2 and seals the Provider/model binding, Severity Packet,
    Decision, and Reconciliation. v1alpha1 remains readable for existing Run verification.

## Consequences

- Blind Review and Severity Derivation are separated from the Primary Validator's Provider Tool,
  Capability, and Secret boundary.
- The Reviewer derives severity from minimal validity and impact evidence without seeing the
  proposed label.
- Disagreement is preserved as a review signal instead of overwriting the Candidate.
- One Candidate with diverse review uses five model calls: Planner, Candidate Validator, Blind
  Reviewer, Severity Deriver, and Reporter.

## Limits and follow-up

- Different Provider IDs and endpoints are configuration assertions; they do not cryptographically
  prove separate companies, infrastructure, or training lineage.
- Blind Review and Severity Derivation each use one attempt.
- Independent severity is not yet projected into canonical Finding severity or public status.
- Gold Datasets, Human Overturn Rate, calibration, multi-Reviewer consensus, and independent
  execution attestation remain follow-up work.
