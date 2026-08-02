# ADR-0097: Run a Concrete ZAP Baseline with Raw SARIF Evidence

## Status

Accepted.

## Context

ADR-0096 deliberately stopped P0-E2A before selecting or executing a Scanner. Completing P0-E2
requires a real product artifact, a provider isolation boundary, exact invocation evidence, and a
truthful result even when the Scanner finds no valid or confirmed Finding. Reusing the synthetic
P0-E1 worker would misrepresent PAJIN's deterministic probe as a general Scanner.

## Decision

1. Use OWASP ZAP 2.17.0 as the first concrete general Scanner baseline and bind the runtime's exact
   Docker image ID as the executable artifact SHA-256.
2. Keep the reviewed distribution reference in the registration, verify that it resolves to the
   registered ID, and create the runtime by immutable image ID.
3. Use a code-owned Automation Framework plan with one exact requestor seed, a bounded active scan,
   and the ZAP `sarif-json` report template.
4. Reuse the existing fenced P0-D1 reset, isolation, recovery, cleanup, attestation, catalog, and
   registry-governed Harness instead of creating a parallel lifecycle.
5. Run ZAP in a separate hardened container on the internal target network with no published ports
   and only an operation-specific artifact directory mounted.
6. Seal raw SARIF bytes unchanged before normalization. Bind raw hash/size, normalization,
   registration, plan, container, operation, receipt, Target Run, and Harness source into the
   P0-E2B measurement authority.
7. Match the known P0-D1 surface only on exact origin, port, route, and query-key semantics, and
   count a known Finding only for the registered ZAP SQL-injection rule set.
8. Permit explicit `not-applicable` values in a completed Result only for the five BENCH-001 metrics
   whose semantic denominator may legitimately be absent. Continue rejecting numeric comparison
   when either source Result contains an unmeasured metric.
9. Keep candidate comparison and Supervisor activation false.

## Consequences

- PAJIN can now distinguish a real ZAP execution from synthetic Scanner-shaped data and can reopen
  its exact raw evidence.
- The result truthfully records zero recall when ZAP does not emit a registered SQL-injection rule;
  it does not invent confirmation, replay, cost-per-confirmed-Finding, or human decisions.
- The mutable image reference cannot silently change a Run because execution is pinned to the
  registered image ID, although trusted provisioning of that ID remains a local input.
- The first Scanner baseline is intentionally specific to one local target and product version.
  P0-E3 must define a separate single-agent identity and authority instead of relabeling P0-E2B.

## Compatibility and rollback

The concrete Scanner types and artifacts are additive. The BENCH-001 Result relaxation represents
previously unrepresentable denominator-free observations without changing measured metric shapes;
comparisons remain stricter. Rollback disables new P0-E2B issuance and leaves existing sealed
artifacts and P0-E2A/P0-E1 readers intact.

## References

- [P0-E2B contract](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [P0-E2A contract](../benchmark/P0-E2A-generic-scanner-baseline-plan.md)
- [BENCH-001 contract](../benchmark/BENCH-001-benchmark-contract.md)
- [ADR-0096](0096-bind-scanner-contract-before-measurement.md)
