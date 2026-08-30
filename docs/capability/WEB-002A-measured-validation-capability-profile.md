# WEB-002A: Measured Validation Capability and Profile

- Status: Implemented as additive registration and inert policy authority only
- Capability: `pajin.web.measured.boolean-sqli-validation@1.0.0`
- Profile: `pajin.profile.web.measured-boolean-sqli@1.0.0`
- Profile API: `pajin.dev/web-measured-validation-profile/v1alpha1`
- Target: `GET http://target:8080/v1/users/lookup`
- Authority: `src/pajin/capabilities/web_measured_validation.py`
- Decisions: [ADR-0251](../adr/0251-require-additive-target-routing-and-validation-policy-for-measured-web.md), [ADR-0252](../adr/0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md), and [ADR-0253](../adr/0253-separate-zap-measurement-routing-from-controlled-validation-routing.md)

## Purpose

WEB-002A registers one additive Capability and Profile for an independently controlled validation
of the fixed synthetic P0-D1 Boolean-SQLi case. It reuses the reviewed
`BooleanSQLiProbeTool` implementation while preserving every existing REDTEAM, Bug Bounty,
WEB-001, Tool, and Capability identity. It does not reinterpret the existing REDTEAM Profile,
whose endpoint and digest are different.

This contract defines exact code-owned request semantics and the policy requirements that a future
WEB-002D execution must satisfy. Registration does not activate the Capability, satisfy approval,
issue an `ActionPermit`, select a Worker, materialize a proxy route, grant network access, execute
Docker or the Tool, observe a measurement, satisfy a validation floor, or produce a Finding.

## Additive Capability identity

`registered_web_measured_validation_capability_definition` creates a new experimental,
approval-required, read-only Capability Definition over the existing Tool specification. It is
restricted to the `web.http-operation` Surface type, CWE-89, a cost of three request units, and the
following exact preconditions:

- current authorized Scope;
- the exact P0-D1 Target operation;
- a fresh `ActionPermit`;
- host-observed HTTP receipts;
- a signed single-use proxy route; and
- the synthetic local lab.

`web_measured_validation_capability_bundle` binds all seven CAP-002 authority roles to the exact
reviewed `BooleanSQLiProbeTool` instance:

- the materializer validates only `BooleanSQLiProbeInput`;
- the action compiler accepts only the fixed Tool, method, and internal target;
- the executor adapter prepares the existing Tool job but does not dispatch it;
- the result normalizer delegates to the existing Tool interpreter;
- the success Oracle accepts only the exact three-observation Boolean-SQLi semantics;
- the Replay strategy returns no Replay plan; and
- the cleanup handler returns no cleanup plan.

The presence of these code-backed roles completes Capability identity. It does not make an
activation current or turn a prepared `WorkerJob` into an admitted Gateway dispatch. Future use
must still pass the existing lifecycle, approval, one-use Permit, Gateway, Worker, proxy-route, and
sealed-evidence boundaries.

## Exact Profile

`registered_web_measured_validation_profile` returns one content-addressed
`WebMeasuredValidationProfile`. `resolve_web_measured_validation_profile` resolves only the exact
Profile reference and current immutable Capability authority set.

The Profile binds:

- the additive code-backed Capability and action Capability;
- the existing exact Web Domain Worker boundary;
- the inert WEB-001A `web.http-operation` Surface for the Docker-internal endpoint;
- scenario `bug-bounty.api.boolean-sqli-lab`;
- method `GET`;
- exactly three request units;
- at most 32,768 response bytes per request;
- host-observed receipts;
- a fresh Target operation;
- a signed route whose cleanup is required; and
- a Worker that can reach the Target only through the proxy-only network boundary.

The code-owned requests are:

| Name | Query parameter | Query value |
| --- | --- | --- |
| `baseline` | `id` | `1` |
| `negative-control` | `id` | `1' AND '1'='2` |
| `boolean-probe` | `id` | `1' OR '1'='1` |

The caller supplies none of these query values, the service coordinate, method, action, request
count, or response ceiling. The Capability request carries only the fixed scenario identifier.
The internal endpoint is not a host-published endpoint and is not authority to resolve or join a
Docker network.

## Controlled-validation route boundary

The WEB-002 signed proxy route has the sole purpose `controlled-validation`. It is the future
WEB-002D route for the three fixed requests above. It is not the WEB-002B source-measurement route
and cannot start or route ZAP.

WEB-002B continues to use the existing P0-E2B Scanner registration, measurement plan, provider
lifecycle, and Scanner-specific Target-network route. The ZAP source and the controlled validation
must use distinct Target attempts, operations, fences, execution identities, results, and Evidence.
[ADR-0253](../adr/0253-separate-zap-measurement-routing-from-controlled-validation-routing.md)
records this clarification.

The signed controlled-validation route is described in
[WEB-002A exact measured-case, route, floor, and Finding policy](../benchmark/WEB-002A-exact-measured-case-route-floor-finding.md).
WEB-002A can issue and verify that inert statement only after resolving the exact
`ActionApprovalAuthorization` from a read-only durable approval store and resolving the live
Target attempt from `BenchmarkTargetOperationJournal.current_open_attempt`. The issuer and verifier
derive the current effective fence and journal head from that lookup; they do not trust
caller-supplied approval, Permit, attempt, operation, receipt, fence, or cleanup snapshots. The
verification loader repeats the live predecessor checks and requires exact wire equality with the
newly derived verification.

The current journal head must contain reset intent/receipt, isolation intent/receipt, then a
pending execution intent in that exact order. Reset, isolation, and execution are independent
stage-local counters and must each be the first attempt, `ordinal=1`; treating them as one global
ordinal sequence is invalid.

The route interval is contained by the consumed Permit, `ActionApproval`, Mission Envelope, and
Campaign authorization intervals. When Campaign testing windows exist, the complete interval from
route issuance through expiry must remain continuously within one `WeeklyTestingWindow` occurrence
rather than spanning or combining occurrences.

The route's `consumptionSlotDigest` uses only the exact approval, approval-consumption receipt, and
consumed Permit identities. Reissuance under another route nonce, Target operation, or runtime
policy therefore converges on the same atomic-consumption slot. WEB-002A contains no ledger
or compare-and-swap claim for that slot.

WEB-002A does not consume or materialize the route. It provides no consumption ledger or runtime
adapter. Atomic single-use claim, proxy attachment, request/response custody, detachment,
reconciliation, and cleanup receipts are implemented only by WEB-002D. WEB-002B remains the
distinct registry-governed ZAP source-measurement path and does not consume this route.

## Authority ceiling

The Profile state is `registered-not-activated`. Its requirement markers are literal true, but the
following authority and observation markers are literal false:

| Marker | WEB-002A value |
| --- | --- |
| `capabilityActivationAuthorized` | `false` |
| `approvalSatisfied` | `false` |
| `permitIssuanceAuthorized` | `false` |
| `proxyRouteMaterialized` | `false` |
| `workerSelected` | `false` |
| `networkAccessAuthorized` | `false` |
| `measurementObserved` | `false` |
| `graphAdmissionAuthorized` | `false` |
| `profileValidationFloorSatisfied` | `false` |
| `findingAuthority` | `false` |
| `productActivationAuthorized` | `false` |
| `reportDeliveryAuthorized` | `false` |
| `executionAuthorized` | `false` |

`proxyRouteRequired`, `proxyRouteCleanupRequired`, `hostObservedReceiptsRequired`,
`freshTargetOperationRequired`, and `workerProxyOnlyNetworkRequired` are requirements for a future
execution. They are not evidence that the route, Worker, Target, receipts, or cleanup exist.

The separate route statement and verification also keep route consumption, proxy and Worker
attachment, provider execution, validation-floor satisfaction, Finding projection, Graph writes,
product activation, report delivery, and all execution authority false.

## Exact success semantics

The registered success Oracle may return `SUCCEEDED` only for a successful normalized Tool result
whose target and scenario match, whose output declares that network activity occurred, and whose
three synthetic observations satisfy all of these checks:

- the baseline returns status 200 with one record;
- the negative Control returns status 200 or 400 with zero records;
- the Boolean probe returns status 200 with more records than the baseline; and
- all observations are explicitly synthetic.

That code-owned Oracle is not invoked by Profile registration. Even a matching future Tool result
does not by itself satisfy the WEB-002 validation floor or create a product Finding; the separate
measured source, fresh controlled validation, Replay/Control evidence, private matcher, and metric
policy must first be contextfully evaluated.

## Fail-closed behavior

The models forbid unknown fields and bind the Profile digest over every nested identity and marker.
Registration or resolution rejects Tool implementation or specification drift, Capability-role
drift, Worker-boundary drift, Surface or endpoint substitution, request changes, digest forgery,
and true authority markers. Capability adapters reject another Tool, method, target, scenario, or
result shape.

Strict Profile reconstruction remains an identity check. It does not inspect Docker, verify route
consumption, attest a Worker, observe HTTP receipts, or evaluate benchmark evidence.

Route issuance and verification additionally fail closed unless the durable approval store returns
the exact consumed approval/receipt/Permit authorization and the Target operation journal returns
the exact currently open attempt, expected journal sequence, and current effective fence. Reloading
a serialized route verification repeats those live checks and rejects any artifact that is not
exactly equal to the newly derived wire object. Issuance also rejects any stage ordinal, enclosing
authorization interval, configured testing-window occurrence, or stable consumption-slot identity
that differs from the code-owned rules above.

## Compatibility, migration, and rollback

The Capability and Profile are additive. Existing REDTEAM, Bug Bounty, WEB-001, P0-D1, P0-E2B,
Tool, Capability, Gateway, Worker, Graph, benchmark, Evidence, and Finding wire identities remain
unchanged. No database, artifact, Target, Docker, or network migration is required.

Rollback stops registering the additive Capability and Profile and removes their contract and
tests. Because WEB-002A performs no execution or route materialization, rollback at this boundary
requires no Worker, proxy, Target, or network cleanup.

## Verification

`tests/test_web_measured_case_authority.py` covers additive identity, preservation of the existing
REDTEAM identity, exact fixed-scenario materialization, request and Profile semantics, authority
marker literalness, predecessor reconstruction, the exact code-owned policy-denial registry, and
adversarial release or Scanner substitution. `tests/test_web_proxy_route_authority.py` covers the
durable approval lookup, current Target-journal head and effective fence, signature, freshness,
verification reload, stage-local ordinal-1 sequencing, authorization/testing-window interval
bounds, stable consumption-slot convergence, and inert-marker behavior. None of those tests
constitutes route materialization, execution, measurement, or Finding evidence.

## Related contracts

- [WEB-002A exact measured case, route, floor, and Finding policy](../benchmark/WEB-002A-exact-measured-case-route-floor-finding.md)
- [WEB-001D](../benchmark/WEB-001D-independent-web-replay-ground-truth.md)
- [P0-D1](../benchmark/P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](../benchmark/P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](../benchmark/DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
