# ADR-0253: Separate ZAP Measurement Routing from Controlled Validation Routing

- Status: Accepted
- Date: 2026-08-28
- Owners: PAJIN architecture and security boundary maintainers
- Scope: WEB-002A through WEB-002D
- Supersedes: ADR-0252 statements that one three-GET proxy route may be materialized by both WEB-002B and WEB-002D; all other ADR-0252 decisions remain accepted

## Context

[ADR-0252](0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md)
correctly preserves the existing proxy-only Worker topology and rejects direct Worker attachment
to the Target Factory network. Its materialization sequence then says that WEB-002B and WEB-002D
may materialize the signed route, while the same sequence permits only three fixed plaintext GET
requests using the controlled Boolean-SQLi Worker action.

Those are two different execution contracts.

WEB-002B is the P0-E2B ZAP source-measurement lifecycle. It uses a registered Scanner container,
Scanner-specific configuration and request behavior, raw SARIF retention, strict normalization,
signed measurement authority, a completed Target Run, and Target cleanup. A ZAP scan is not the
three-request `BooleanSQLiProbeTool` action and cannot be represented truthfully by its request
budget or Worker receipts.

WEB-002D is a separately approved controlled validation. It uses the existing
`bug-bounty-sqli-probe` Worker action, the fixed baseline, negative Control, and Boolean probe,
three host-observed request/response exchanges, and a fresh Target lifecycle independent of the
ZAP source.

The current WEB-002A implementation reflects the second contract. `WebProxyRouteStatement.purpose`
is the literal `controlled-validation`. `WebProxyRouteRuntimePolicy` fixes the controlled Worker
action, proxy-only topology, service alias, method, path, three-request budget, and response
ceiling. The measured-case authority binds the P0-E2B Scanner plan and registration as source
predecessors, but the signed proxy route neither starts nor authorizes that Scanner.

A second ambiguity concerns Target Run identity. The signed route must exist before controlled
execution and cleanup. `BenchmarkTargetRunAuthority` is a post-cleanup authority over the completed
Target lifecycle, so it cannot be a truthful prerequisite of the live route.

The same timing boundary excludes caller snapshots as current route authority. Approval and Permit
consumption can change independently of a copied object, and the Target journal can advance its
head or effective fence after a caller takes a snapshot. Issuance, verification, and verification
reload must therefore resolve those live predecessors from their durable owners.

## Decision

Narrow the WEB-002A signed proxy-route purpose to controlled validation only.

1. `WebProxyRouteStatement.purpose` remains exactly `controlled-validation`. It is the future
   WEB-002D route for the fixed `bug-bounty-sqli-probe` action and three code-owned GET requests.
2. WEB-002B does not consume or materialize `WebProxyRouteStatement`. It continues to use the
   existing P0-E2B Scanner registration, Scanner plan, registry-governed provider lifecycle, and
   Scanner-specific route to the isolated P0-D1 Target network.
3. The P0-E2B Scanner lifecycle and WEB-002D controlled proxy bridge remain distinct authority,
   routing, execution, evidence, and cleanup paths. A common Target Factory implementation does
   not make their routes interchangeable.
4. Route issuance and verification receive only approval and Permit IDs plus a read-only durable
   approval store for this boundary. They must load and strictly reconstruct the exact consumed
   `ActionApprovalAuthorization`, including its approval receipt and ActionPermit, rather than
   accepting caller-supplied approval or Permit snapshots.
5. Route issuance and verification receive the `BenchmarkTargetOperationJournal` and Target
   attempt ID, call `current_open_attempt`, derive the current effective fence and journal head,
   and bind the exact isolation and execution operations, succeeded isolation receipt, and Docker
   provider isolation evidence. They do not accept caller-supplied attempt, operation, receipt,
   fence, or cleanup snapshots. The issuable journal head is exactly reset intent/receipt,
   isolation intent/receipt, then a pending execution intent; reset, isolation, and execution are
   each stage-local first attempts with `ordinal=1`. The journal timeline must also satisfy
   attempt `startedAt` <= monotonically nondecreasing record `occurredAt` <= route `issuedAt`.
   For reset and isolation, intent-record `occurredAt` <= receipt `startedAt` <= receipt
   `completedAt` <= receipt-record `occurredAt`. Their receipts must carry the same `environmentId`,
   and reset receipt `completedAt` must be no later than isolation receipt `startedAt`. Canonical
   serialization cannot make an impossible lifecycle authoritative.
6. Loading a serialized `WebProxyRouteVerification` repeats all live predecessor verification and
   requires exact equality with the newly derived wire object. A self-consistent stored digest is
   not sufficient authority.
7. The complete route interval must remain inside the consumed Permit, `ActionApproval`, Mission
   Envelope, and Campaign authorization bounds. If Campaign testing windows are configured, the
   entire `issuedAt` through `expiresAt` interval must be continuously contained by one
   `WeeklyTestingWindow` occurrence; multiple windows or occurrences cannot be combined.
8. `consumptionSlotDigest` is derived only from the approval, approval-consumption receipt, and
   consumed Permit identities. Reissuing the same authorization with a different nonce, Target
   operation, or runtime policy must converge on the same future atomic-consumption slot. WEB-002A
   provides neither the ledger nor the compare-and-swap claim that would consume it.
9. A future completed controlled Target Run authority may be admitted as post-execution evaluation
   Evidence only after reconciliation and cleanup. It does not replace the route's live operation
   identity.
10. The validation floor binds `common.policy-denial-correctness` to a content-addressed exact
   code-owned denial-Control registry. The registered case expects cleanup-before-verification to
   be rejected before route materialization and without provider execution or network access; it
   is a denominator requirement, not an observed denial.
11. WEB-002A continues to issue and verify only an inert signed statement. Single use, cleanup
   invalidation, and proxy-only bridging are mandatory requirements and content-addressed slots,
   not claims that consumption, attachment, detachment, or cleanup occurred.

The WEB-002B source and WEB-002D controlled validation must use fresh and distinct Target attempts
and Runs, operation IDs and digests, fences, route identities, approvals, Permits, Worker or Scanner
sessions, dispatches, requests, responses, results, and Evidence. Neither path may reuse the other
as an independent Replay or Control.

The controlled route remains bound to the exact Campaign, Scope, Mission Envelope, consumed
approval receipt and ActionPermit, canonical Tool request, deployment, Gateway policy, Worker
backend, Worker image, proxy image, Target isolation, internal service coordinate, request budget,
response ceiling, short validity window, signing key, route revocation state, single-use slot, and
cleanup/fence invalidation scope. It grants no Docker socket, host port, arbitrary network,
arbitrary request, caller-authored payload, image selection, credential, private Ground Truth, or
general execution authority.

## Consequences

- The current WEB-002A schema and code-owned three-request semantics describe one truthful future
  controlled-validation route rather than a falsely generic Scanner route.
- WEB-002B can preserve the already governed P0-E2B Scanner provider, raw-SARIF, measurement, and
  cleanup lineage without being forced through the Gateway Worker request budget.
- WEB-002D retains the ADR-0252 proxy-only bridge: the Worker remains only on the ephemeral internal
  Worker-proxy network, and the proxy alone bridges to the exact Target network.
- The validation-floor policy can require both a completed WEB-002B source Run and a separately
  signed WEB-002D controlled route and receipts without confusing their provenance.
- The route verifier and verification loader derive approval consumption and the current Target
  journal head from durable authority, so a caller cannot preserve a stale route by replaying a
  formerly valid snapshot.
- The current journal head is causal authority only when record and receipt times are monotonic,
  reset and isolation retain one environment, and reset completes before isolation starts; a
  canonical but temporally impossible journal fails closed.
- Reissuing one approval/receipt/Permit authorization cannot mint a new future single-use allowance:
  all route variants retain one stable consumption-slot digest even when their route or network-slot
  identities differ.
- Route freshness is the intersection of all enclosing authorization intervals and, when configured,
  one continuous Campaign testing-window occurrence rather than a union across windows.
- Policy-denial correctness has one exact content-addressed code-owned denominator instead of an
  unconstrained caller-provided count.
- Completed Run authority is evaluated after a lifecycle; it is no longer described as a
  pre-execution route input.

## Rejected alternatives

### Generalize the route purpose to ZAP or controlled validation

Rejected because the two paths have different executors, request cardinality, configuration,
outputs, receipts, Oracles, and evidence custody. A union without two complete discriminated
contracts would hide authority drift rather than enable safe reuse.

### Route ZAP through the three-request Gateway Worker policy

Rejected because ZAP is a Scanner container governed by the P0-E2B lifecycle, not the fixed
Boolean-SQLi Tool action. Reporting that route as three GETs would be false measurement provenance.

### Treat the controlled route as a generic Docker network credential

Rejected because a raw network name or configured route map is ambient routing authority. The
controlled route must remain deployment-signed, exact, fenced, short-lived, single-use, and invalid
after cleanup.

### Bind the completed Target Run authority before execution

Rejected because the completed Run includes execution and cleanup receipts that do not exist when
the route is issued. Binding it would require invented or circular provenance.

### Trust caller-supplied approval or Target lifecycle snapshots

Rejected because a copied approval, Permit, attempt, operation, or fence can be stale while the
durable approval store or operation journal has advanced. Current route authority must be derived
from the store and `current_open_attempt`, and a persisted verification must be reloaded by exact
live reconstruction.

### Treat requirement markers as lifecycle receipts

Rejected because `singleUseRequired`, `cleanupInvalidationRequired`, and
`proxyOnlyBridgeRequired` state policy. They do not prove route consumption, proxy attachment,
request handling, detachment, reconciliation, or cleanup.

## Security and authority impact

This ADR narrows authority and executes nothing. WEB-002A keeps route materialization and
consumption, proxy and Worker attachment, Docker and ZAP execution, provider execution authority,
network access, measurement observation, Graph mutation, floor satisfaction, Finding projection,
product activation, and report delivery false.

WEB-002A has no route-consumption ledger or materializing runtime adapter. Its next roadmap step is
WEB-002B, which is scoped to materialize only the distinct P0-E2B Scanner lifecycle;
controlled-validation route consumption remains deferred to WEB-002D.

Future WEB-002B execution remains governed by the existing P0-E2B Scanner lifecycle. Future
WEB-002D materialization requires a separately approved current Permit and a deployment-owned
adapter that atomically consumes the exact route, records host-observed lifecycle and HTTP
receipts, detaches the proxy, reconciles the Target operation, verifies cleanup, and invalidates the
route. Missing, stale, reordered, duplicate, or untrusted lifecycle evidence fails the controlled
case closed.

Private Ground Truth remains adjudication input only. Neither the Scanner route nor the controlled
route can select a matcher, satisfy a metric, project a Finding, or authorize product behavior.

## Compatibility and rollback

The clarification is additive and matches the current `controlled-validation` route schema.
Existing P0-D1, P0-E2B, WEB-001, REDTEAM, Bug Bounty, Capability, Tool, ActionPermit, Gateway,
Worker, Scanner, Target Factory, benchmark, Graph, Evidence, and Finding identities remain
unchanged. No migration is required.

Rollback supersedes this ADR with a new discriminated routing decision and stops registering the
affected route schema. It must not silently widen the existing route purpose. Because WEB-002A
materializes nothing, rollback at this boundary requires no Docker or Target cleanup.

## Verification requirements

Tests must prove that the WEB-002A route purpose, Worker action, method, path, request count,
response ceiling, proxy image, deployment identity, and live Target operation identity are exact.
They must reject a ZAP Scanner registration or plan as a controlled-route substitute, a completed
Run authority as a pre-execution route input, missing or substituted durable approval authorization,
stale or non-open journal heads, source/validation identity reuse, foreign attempts, isolation
drift, effective-fence drift, post-cleanup use, expiry, revocation, route or key substitution,
caller-selected network or request fields, forged verification artifacts, denial-Control registry
drift, a non-first stage ordinal or reordered journal sequence, non-monotonic or future journal
records, receipts outside their intent/record intervals, reset/isolation environment drift or
causal overlap, an authorization or testing-window boundary crossing, a reissued authorization that
changes its consumption slot, and any true materialization or execution marker. Verification reload
must repeat every live predecessor check and require exact wire equality.

Future WEB-002B and WEB-002D conformance must verify their separate Target lifecycles and Evidence
lineages. Only WEB-002D uses the signed controlled-validation proxy route. Real Docker execution,
route consumption, attachment/detachment receipts, ZAP source measurement, controlled request
receipts, cleanup, metric evaluation, and Finding projection are not WEB-002A test claims.

## Related contracts and decisions

- [ADR-0252](0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md)
- [ADR-0251](0251-require-additive-target-routing-and-validation-policy-for-measured-web.md)
- [ADR-0250](0250-prioritize-governed-measured-web-validation-before-new-domain-runtimes.md)
- [WEB-002A measured validation Capability and Profile](../capability/WEB-002A-measured-validation-capability-profile.md)
- [WEB-002A exact measured case, route, floor, and Finding policy](../benchmark/WEB-002A-exact-measured-case-route-floor-finding.md)
- [P0-D1](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
