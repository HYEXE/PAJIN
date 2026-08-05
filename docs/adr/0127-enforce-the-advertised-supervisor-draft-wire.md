# ADR-0127: Enforce the Advertised Supervisor Draft Wire

- Status: Accepted
- Date: 2026-08-05

## Context

SUP-002 through SUP-005B2 already preserve target taint, use fixed Provider roles, compile drafts
into inert typed proposals, bind B3 requests to benchmark coordinates, and isolate numeric metrics
behind external Target measurement. Their negative tests were distributed across each boundary and
did not exercise one adversarial payload through the complete Shadow path.

The Provider response schema advertises camelCase aliases. `SupervisorShadowProposalDraft` keeps
`populate_by_name=True` for internal Python compatibility, so using the model directly on raw JSON
also accepted snake_case field names absent from that schema. This was not an execution-authority
escalation, but it weakened exact schema admission.

## Decision

1. Keep the existing draft model and wire version unchanged.
2. Add one alias-only raw Provider draft parser that rejects field spellings absent from the
   advertised JSON Schema before typed validation.
3. Use that parser at both live Provider response admission and sealed receipt re-consumption.
4. Add one adversarial regression corpus for role injection, taint downgrade, Scope and mutation,
   ToolRequest, Capability, Permit, execution, threshold, activation, and schema escape attempts.
5. Treat schema-valid malicious rationale as untrusted input: bind it by digest, emit only the
   existing code-owned advisory payload, and copy no rationale into the typed proposal or measured
   authority.
6. Keep invalid post-dispatch output outcome-unknown, conservatively charged, manual-review-only,
   and non-retriable under the existing B3 journal contract.
7. Require SUP-005B2 candidate inputs to reference the exact current sealed Plan publication, not
   merely another publication with equal Plan content.
8. Reuse the existing external Target/Harness and BENCH-003B1 authorities for all metrics. Do not
   create a regression Result, score, threshold, activation, or execution authority.

## Consequences

- Raw Provider output now matches the schema visible to the Provider exactly.
- Internal Python construction remains compatible because alias-only enforcement is limited to the
  external JSON admission boundary.
- A model may follow an injected instruction in its rationale, but the accepted product output
  remains a non-executable typed advisory.
- A valid B3 completion cannot move between separately sealed Plan publications during measured
  admission.
- The regression demonstrates containment and metric-source isolation without claiming model
  robustness or causal improvement.

## Compatibility and rollback

All existing public wire versions remain unchanged. Valid camelCase Provider drafts are unaffected;
raw snake_case drafts that contradicted the advertised schema are newly rejected. No stored data or
database migration is required. Removing this hardening would restore the former wider raw parser
but would not invalidate existing canonical receipts.

## Related documents

- [SUP-006 contract](../orchestration/SUP-006-adversarial-prompt-injection-regression.md)
- [SUP-005B2 contract](../orchestration/SUP-005B2-registry-governed-model-backed-comparison.md)
- [SUP-004B3 contract](../orchestration/SUP-004B3-durable-supervisor-invocation-receipt.md)
- [SUP-003 contract](../orchestration/SUP-003-typed-non-executable-supervisor-proposal.md)
- [SUP-002 contract](../orchestration/SUP-002-snapshot-only-target-taint-input.md)
- [ADR-0126: Externally attested B3 relation](0126-bind-b3-completions-into-externally-attested-target-execution.md)
