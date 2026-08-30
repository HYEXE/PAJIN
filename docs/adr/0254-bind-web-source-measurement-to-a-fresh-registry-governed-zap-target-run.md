# ADR-0254: Bind WEB-002B Source Measurement to a Fresh Registry-Governed ZAP Target Run

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: WEB-002B source measurement
- Implements: ADR-0253 source-measurement separation

## Context

WEB-002A registers one exact measured case over a private P0-D1 profile, public Target adapter and
registration, P0-E2B Scanner plan and ZAP registration, and DOMAIN-006 validation requirements. It
also registers a signed three-request route with the literal purpose `controlled-validation`.
ADR-0253 reserves that route for WEB-002D and keeps the ZAP source lifecycle distinct.

The existing P0-E2B stack already provides the Docker ZAP provider, signed measurement registry,
registry-governed Harness, completed Target Run, raw SARIF custody, strict normalization, and
Scanner Result. It has no bounded Web entrypoint, however, and its
`ScannerBaselineSourceBinding` binds execution evidence but not the cleanup provider evidence or
the exact completed durable journal. Generic Target authority can also represent an inline cleanup
failure that is reconciled later, so `measurementAdmissionEligible=true` is not sufficient proof
of the exact cleanup lifecycle required by WEB-002B.

Persisted JSON must not become authority merely because a permissive model can coerce it to the
same semantic value. Provider and journal stores, Scanner source/observation bundles, and the outer
authority therefore require canonical wire as well as content equality.

## Decision

1. Add one bounded programmatic `WebZAPSourceMeasurementRunner`. It contextfully reconstructs the
   exact WEB-002A authority and derives every Target coordinate from the committed Scanner plan.
   It accepts no caller-selected coordinate, route, approval, Permit, Worker action, request, or
   response.
2. Keep the existing P0-E2B provider, Harness, Target, Scanner measurement, raw SARIF, Result, and
   wire identities unchanged. WEB-002B composes them and adds an outer Web authority rather than
   widening the generic contracts.
3. Require a fresh recoverable Target attempt for every plan coordinate under constructor-owned
   provider, measurement Trust Anchor, signed registry distribution, activation store, and Target
   journal context.
4. Before sealing the generic Scanner measurement, require succeeded inline cleanup, a completed
   Target journal, exact cleanup receipt-bound provider evidence, and `resourcesAbsent=true`.
   Reconciled, open, incomplete, or cleanup-failed attempts are not WEB-002B sources.
5. The completed journal is authoritative only when it contains exactly reset, isolation,
   execution, and cleanup intent/receipt pairs. All eight records must be canonical and
   hash-chained, use stage-local ordinal one, share one attempt and fence, equal all four Target
   receipts, and have a causal nondecreasing timeline.
6. Add `WebZAPSourceLineage` as a public-safe digest and identity projection. It binds immutable
   Target, benchmark-Worker, and Scanner images, internal-network and zero-published-port evidence,
   raw SARIF hash/size, normalization, registry, Harness, Target, journal, execution, and cleanup
   identities. It excludes raw bodies and paths, private Ground Truth, container/network IDs,
   secrets, routes, approvals, Permits, and HTTP traffic.
7. Add `WebZAPSourceMeasurementAuthority` and a contextful loader. The loader reopens the Scanner
   measurement and every nested Harness, Target, provider evidence, raw SARIF, normalization,
   cleanup evidence, registry, and completed journal predecessor before rebuilding and comparing
   the outer authority exactly. Each Harness must contain the exact supplied signed distribution
   bundle and out-of-band Trust Anchor; a distinct valid bundle with equivalent registry contents
   is not interchangeable lineage.
8. Fresh execution requires the signed distribution to be currently valid before provider reset.
   Historical reload relies on the nested sealed-time registry verification and does not reject an
   otherwise valid immutable result solely because the distribution later expires.
9. Stored provider evidence/results, including idempotent replay, Target journal records, Scanner
   source/observation bundles, and the outer authority artifact must round-trip to their exact
   canonical JSON wire. All three outer audit event payloads must match exactly. Numeric booleans,
   string integers, duplicate-key normalization, and other semantically equivalent wire drift fail
   closed.
10. WEB-002B does not import, consume, or materialize `WebProxyRouteBundle`. Controlled validation,
    private Ground Truth disclosure, floor evaluation/satisfaction, Graph/Finding authority,
    comparison, Supervisor eligibility, product/report authority, and further execution remain
    literal false.
11. Do not mark WEB-002B complete in `PLAN.md` until the current opt-in real-Docker test exercises
    this exact outer runner and loader successfully. A past generic P0-E2B live result or a fake
    provider run does not satisfy that conformance condition.

## Consequences

- WEB-002B now has one exact entrypoint rather than test-only orchestration.
- Cleanup and durable operation identity are independently verifiable without changing the
  `ScannerBaselineSourceBinding` wire.
- A caller cannot substitute coordinates or controlled-validation authority into the ZAP source
  lifecycle.
- The public authority is useful to WEB-002C without disclosing adjudication material or granting
  admission, Finding, Graph, product, report, or execution authority.
- Contextful reload is intentionally dependent on the durable journal and provider custody store.
  Deleting those predecessors makes the outer source authority unverifiable rather than silently
  downgrading it to a self-authenticating claim.
- Canonical-wire hardening applies to existing provider and Scanner readers and remains compatible
  with artifacts emitted by the current writers.
- Implementation and deterministic tests alone do not complete the roadmap item. It remains at
  WEB-002B conformance until the exact opt-in real-Docker wrapper test succeeds.

## Rejected alternatives

### Reuse the WEB-002A controlled-validation route for ZAP

Rejected because the three fixed Boolean-probe GET requests, Worker action, proxy receipts, and
request budget are not a truthful ZAP Scanner lifecycle.

### Extend `ScannerBaselineSourceBinding` with cleanup fields

Rejected because that would change the existing P0-E2B wire. The additive Web lineage can bind
cleanup evidence and the completed journal without a migration.

### Trust the completed Target authority without the journal and provider cleanup evidence

Rejected because generic Target authority can represent cleanup failure and does not prove the
exact durable attempt state or provider resource absence required by WEB-002B.

### Accept semantically equivalent stored JSON

Rejected because permissive coercion can turn a different wire claim into the same in-memory value.
Exact provenance requires canonical bytes as well as semantic model validity.

### Mark implementation-only verification as complete

Rejected because ADR-0250 and ADR-0251 require current disposable real-Docker conformance for this
vertical slice. The opt-in test must pass through the new wrapper before WEB-002C becomes current.

## Security and authority impact

This decision authorizes only the exact existing Scanner lifecycle for the exact case-owned
coordinate under signed registry and measurement authority. It grants no arbitrary Docker image,
network, target, route, request, credential, private Ground Truth, Graph write, Finding, product,
report, or additional execution authority.

The runner creates disposable Target, Scanner, and internal-network resources only through the
existing recoverable provider. Failure before cleanup is handled by the existing fence and
reconciliation boundary, but a reconciled original run still cannot become WEB-002B source
authority. Missing cleanup proof fails closed.

## Compatibility and rollback

The change is additive and preserves all existing public imports and wire contracts. Rollback stops
issuing the two new WEB-002B APIs and removes the outer runner/loader. Existing P0-D1, P0-E2B,
WEB-002A, registry, Target, Scanner, Result, raw SARIF, route, and downstream identities remain
unchanged. Historical WEB-002B artifacts must not be reinterpreted as neutral admission or
controlled validation after rollback.

## Verification requirements

Tests must cover exact happy-path reconstruction and reload; immutable images; internal networking
and zero published ports; raw SARIF and normalization custody; completed eight-record journal;
receipt-bound cleanup resource absence; foreign case/provider/registry/Target/operation/fence and
wire drift; raw artifact mutation; literal boolean markers; public-safe serialization; no route
surface; and no floor, Graph, Finding, comparison, Supervisor, product, report, or additional
execution authority. The opt-in real-Docker test must execute and reload the same outer boundary
before the roadmap item is complete.

## Related contracts and decisions

- [ADR-0253](0253-separate-zap-measurement-routing-from-controlled-validation-routing.md)
- [ADR-0251](0251-require-additive-target-routing-and-validation-policy-for-measured-web.md)
- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [WEB-002B](../benchmark/WEB-002B-distinct-registry-governed-zap-source-measurement.md)
- [WEB-002A](../benchmark/WEB-002A-exact-measured-case-route-floor-finding.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
