# WEB-002A: Exact Measured Case, Controlled Route, Validation Floor, and Finding Policy

- Status: Implemented as registration and read-only verification authority; unmaterialized and unmeasured
- Measured-case API: `pajin.dev/web-measured-case-authority/v1alpha1`
- Route runtime-policy API: `pajin.dev/web-proxy-route-runtime-policy/v1alpha1`
- Route statement API: `pajin.dev/web-proxy-route-statement/v1alpha1`
- Route trust-anchor API: `pajin.dev/web-proxy-route-trust-anchor/v1alpha1`
- Route verification API: `pajin.dev/web-proxy-route-verification/v1alpha1`
- Floor-policy API: `pajin.dev/web-benchmark-validation-floor-policy/v1alpha1`
- Finding-projection API: `pajin.dev/web-benchmark-finding-projection-policy/v1alpha1`
- Authorities: `src/pajin/workflow/web_measured_case_authority.py`, `src/pajin/workflow/web_proxy_route_authority.py`, and `src/pajin/workflow/web_validation_floor.py`
- Decisions: [ADR-0251](../adr/0251-require-additive-target-routing-and-validation-policy-for-measured-web.md), [ADR-0252](../adr/0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md), and [ADR-0253](../adr/0253-separate-zap-measurement-routing-from-controlled-validation-routing.md)

## Purpose

WEB-002A composes four exact but non-executing authorities for the fixed synthetic Boolean-SQLi
case:

1. the additive measured-validation Capability and Profile;
2. a public-safe measured-case identity over the P0-D1 Target and Ground Truth, P0-E2B Scanner
   plan and registration, and DOMAIN-006 Web plan;
3. a deployment-signed, operation-fenced, controlled-validation proxy-route statement; and
4. a registered validation-floor policy and a separate public/private expected-Finding mapping.

These objects register identity, requirements, and future evaluation boundaries. WEB-002A does not
start the Target Factory, Docker, ZAP, proxy, or Worker; consume or materialize a route; observe a
measurement; evaluate a metric; satisfy the floor; project a Finding; mutate Graph; or authorize a
product action.

## Exact measured-case authority

`bind_web_measured_case_authority` contextfully rebuilds and binds:

- the exact `WebMeasuredValidationProfile` and its current experimental signed Capability release;
- the inert WEB-001A `GET http://target:8080/v1/users/lookup` Surface;
- the catalog-bound P0-D1 Target Factory adapter and public Target registration;
- the private Ground Truth digest and private binding digest, without exposing matcher contents;
- the exact P0-E2B Scanner baseline measurement plan;
- the exact ZAP registration reconstructed from that plan's parser-contract digest; and
- the exact DOMAIN-006 Web benchmark plan, whose strategy is `independent-replay`.

The resulting `WebMeasuredCaseAuthority` is content-addressed as
`web-measured-case_<sha256>`. Its state is
`registered-exact-measured-case-not-executable`. `predecessorsVerified`,
`publicSafeRegistration`, and `privateGroundTruthVerified` mean only that the supplied registration
context was reconstructed exactly.

All activation and observation markers remain false, including Capability activation, approval,
Permit issuance, route materialization, Target Factory and provider authorization, Scanner
execution, Worker selection, network access, measurement observation, raw-SARIF binding, Graph
admission, floor satisfaction, Finding authority, product activation, report delivery, and
execution authority.

`load_web_measured_case_authority` does not trust a serialized digest alone. It revalidates the
artifact and rebuilds the signed release, Target adapter, private profile, Scanner plan, and Scanner
registration from the current trusted context before requiring canonical equality.

## Two distinct execution paths

WEB-002 has two deliberately separate execution contracts.

### WEB-002B source measurement

WEB-002B uses the existing P0-E2B registry-governed Scanner lifecycle and its Scanner-specific
Target-network route. The ZAP registration, Scanner plan, provider authority, raw SARIF custody,
strict normalization, measurement registry, completed Target Run authority, and verified Target
cleanup form the source-measurement lineage.

The WEB-002A `WebProxyRouteStatement` does not authorize or route this Scanner. Its request budget,
Worker action, and proxy policy are the wrong semantics for ZAP.

### WEB-002D controlled validation

The signed WEB-002A proxy route has the literal purpose `controlled-validation`. It is reserved for
a future fresh WEB-002D execution of the code-owned baseline, negative Control, and Boolean probe.
The route binds exactly three plaintext GET requests and a Worker that can reach the Target only
through the deployment-owned egress proxy bridge.

The source and controlled-validation paths must not reuse a Target attempt or Run, operation,
fence, route, approval, Permit, Worker session, request, response, result, or Evidence identity.
The separate identities prevent Scanner output from manufacturing independent validation and
prevent controlled-validation receipts from being treated as source measurement.

## Registered controlled-route runtime policy

`registered_web_proxy_route_runtime_policy` content-addresses deployment configuration without
selecting or starting a Worker. `WebProxyRouteRuntimePolicy` binds:

- deployment, Gateway policy, Worker backend, immutable Worker image, and immutable proxy image
  identities;
- Worker action `bug-bounty-sqli-probe` and `NetworkMode.EGRESS_PROXY`;
- proxy alias `egress-proxy`;
- Target service alias `target`, scheme `http`, port 8080, path `/v1/users/lookup`, and method
  `GET`;
- a budget of exactly three requests and 32,768 response bytes per request; and
- no caller-authored payload, CONNECT, DNS, direct Worker-to-Target-network attachment, or host
  port publication.

The runtime policy state is registration only. `routeMaterialized` and `executionAuthorized` are
false. A configured `external_network_routes` entry or raw Docker network name cannot substitute
for this signed, current operation authority.

## Live Target binding, not completed Run authority

The route is issued before controlled execution and before Target cleanup. A completed
`BenchmarkTargetRunAuthority` does not yet exist at that point and therefore is not a route input.

`WebProxyRouteTargetBinding` instead binds the current live context:

- Target Factory adapter ID, version, and digest;
- P0-D1 Target profile version and Target Factory digest;
- immutable Target and benchmark-Worker image IDs;
- `BenchmarkTargetCoordinate` ID and digest;
- `BenchmarkTargetAttempt` ID, digest, and current active fence;
- the exact stage-local ordinal-1 `BenchmarkTargetOperation` ID and digest for stage `isolation`;
- the exact stage-local ordinal-1 `BenchmarkTargetOperation` ID and digest for stage `execution`;
- the succeeded isolation receipt ID and digest;
- the exact `DockerBenchmarkProviderEvidence` digest;
- environment and isolation IDs;
- the evidence-derived Target container and internal network IDs;
- an internal Target network, zero published ports, exactly one Target-network container at
  isolation, and a healthy Target.

The issuer and verifier accept a read-only `BenchmarkTargetOperationJournal`, the Target attempt
ID, and the exact isolation evidence. They call `current_open_attempt` themselves, derive the
current effective fence and complete journal head, and require the exact reset receipt, succeeded
isolation receipt, and pending execution-intent sequence. The only issuable live head is reset
intent, reset receipt, isolation intent, isolation receipt, and execution intent, in that order,
with reset, isolation, and execution each at its stage-local first attempt `ordinal=1`. Caller-
supplied attempt, operation, receipt, fence, or cleanup snapshots are not route authority. The
isolation evidence must match the journal-derived live identities and fail closed on disagreement.

Canonical record shape is not sufficient. The attempt `startedAt` must be no later than the first
record `occurredAt`; every record `occurredAt` must be monotonically nondecreasing; and the pending
execution-intent record must occur no later than the route `issuedAt`. For both reset and isolation,
the intent-record `occurredAt` must be no later than receipt `startedAt`, receipt `startedAt` must be
no later than receipt `completedAt`, and receipt `completedAt` must be no later than the receipt-
record `occurredAt`. The reset and isolation receipts must carry the same `environmentId`, and the
reset receipt `completedAt` must be no later than the isolation receipt `startedAt`. A strictly
parseable, content-addressed journal with time travel, an impossible receipt interval, an
environment discontinuity, or causal overlap is therefore rejected.

After controlled execution, reconciliation, and cleanup, a future implementation may bind the
completed Target Run authority into evaluation Evidence. It cannot retroactively replace the live
attempt, isolation operation, execution operation, isolation, and fence identity that authorized
the route. Cleanup or fence advancement invalidates the route.

## Signed route statement

`WebProxyRouteStatement` binds:

- a 32-lowercase-hex route nonce and content-addressed route ID and digest;
- purpose `controlled-validation`;
- trust domain, issuer, deployment, Trust Anchor digest, and signing key;
- the exact measured-case reference and complete runtime policy;
- Campaign ID and digest, exact Scope digest, Mission Envelope identity, durable approval and
  approval-receipt identities, consumed ActionPermit identity, dispatch, canonical Tool request,
  requesting agent, and Permit target digest;
- the complete live Target binding;
- content-addressed Worker-proxy network, route-consumption, and fence-invalidation slots; and
- UTC `issuedAt`, `notBefore`, and `expiresAt` timestamps.

The validity interval must satisfy `issuedAt <= notBefore < expiresAt`, and the interval from
`notBefore` to `expiresAt` cannot exceed five minutes. The complete route interval is capped by the
consumed Permit, `ActionApproval`, Mission Envelope, and Campaign authorization: `notBefore` cannot
precede their applicable lower bounds and `expiresAt` cannot exceed any of their expiries. Issuance
must also occur while the Permit, Envelope, and Campaign authorization are current. When the
Campaign defines `WeeklyTestingWindow` entries, the entire continuous interval from `issuedAt` to
`expiresAt` must fit within one occurrence of one window; separate occurrences or windows cannot be
stitched together. The bound request must be the exact existing Boolean-SQLi Tool, target, method,
and fixed scenario. Campaign and Scope must admit only the exact internal target for the required
method and risk boundary.

The network-slot digest is an expected pre-materialization identity. It is not an observed Docker
network ID. The actual ephemeral Worker-proxy network, proxy attachment, and cleanup can be proven
only by future host-observed lifecycle receipts.

## Signature and read-only verification

`WebProxyRouteTrustAnchor` binds one deployment-owned Ed25519 keyring, trust domain, issuer,
deployment, sorted unique key identities, explicit route-digest revocations, and a content digest.
Keys have `active`, `retired`, or `revoked` lifecycle states and bounded validity metadata.

`WebProxyRouteAuthoritySigner.from_private_key_bytes` accepts a 32-byte private key only when its
derived public key matches an exact Trust Anchor key. `issue` requires an active usable key. It
loads the exact `ActionApprovalAuthorization` by approval and Permit IDs from a read-only durable
approval store, derives the live Target context from the operation journal, reconstructs every
route input, signs the canonical statement under a route-specific signature domain, and returns a
detached `WebProxyRouteBundle`. Private key bytes never enter the artifact.

`verify_web_proxy_route_authority` revalidates the strict bundle and Trust Anchor, rejects route
revocation, requires a currently active usable key and current time within the route interval,
verifies the detached signature, reloads the durable approval authorization, derives the current
Target journal head and effective fence, rebuilds the route from all current predecessors, and
requires exact statement equality. `WebProxyRouteVerification` records only read-only identity
checks:

- signature, deployment, Target operation, current fence, freshness, Target isolation, durable
  approval consumption, and Target journal head were verified against live authority; and
- proxy-only bridging, single use, and cleanup invalidation remain mandatory requirements.

`load_web_proxy_route_verification` strictly parses a serialized verification, repeats signature
verification and every live measured-case, Capability, Target, journal, approval-store, Campaign,
Scope, Permit, request, and freshness predecessor check, and requires exact wire equality with the
newly derived verification. Neither verification form is a route-consumption or materialization
receipt.

## Single-use and cleanup boundary

The statement and verification fix `singleUseRequired`, `cleanupInvalidationRequired`, and
`proxyOnlyBridgeRequired` to true and bind exact consumption and fence-invalidation slot digests.
`consumptionSlotDigest` is derived only from the exact approval, approval-consumption receipt, and
consumed Permit digests. It therefore remains stable when the same authorization is reissued with a
different route nonce, Target operation, or runtime policy, even though the route and Worker-proxy
network identities change. Every such reissue converges on one future atomic-consumption slot and
cannot create a fresh single-use allowance.

WEB-002A does not implement the consumption ledger or compare-and-swap operation needed to claim
that slot. It also has no route adapter, attachment receipt, request/response receipt, detachment
receipt, or cleanup receipt.

Accordingly, both the signed statement and verification keep all of these fields false:

- `routeMaterialized` and `routeConsumed`;
- `proxyAttached`, `workerAttached`, and `proxyDetached`;
- `targetCleanupObserved`;
- `providerExecutionAuthorized`, `networkAccessAuthorized`, and `workerSelected`;
- `measurementObserved`;
- `graphWriteAuthorized` and `findingAuthorized`;
- `benchmarkValidationFloorSatisfied`, `findingProjectionAuthorized`,
  `productActivationAuthorized`, and `reportDeliveryAuthorized`; and
- `executionAuthorized`.

The WEB-002D runtime adapter atomically consumes the exact route before its first Docker side
effect, retain separate host-observed proxy attachment, request/response, detachment,
reconciliation, and cleanup receipts, and treat an attempted route as spent even if execution or
cleanup fails. No such adapter or consumption ledger exists in WEB-002A, and no current WEB-002A
object claims that those actions occurred.

## Validation-floor policy

`registered_web_benchmark_validation_floor_policy` binds policy
`web-002a:p0-d1-validation-floor@1.0.0` to the exact measured case, Profile, Capability,
DOMAIN-006 plan, private Ground Truth binding digest, fourteen metric requirements, six source
evidence requirements, ten controlled-validation evidence requirements, and one exact
content-addressed code-owned policy-denial Control registry.

The metric requirements are policy denominators and thresholds, not observations:

| DOMAIN-006 metric | Applicability | WEB-002A requirement |
| --- | --- | --- |
| `common.ground-truth-coverage` | required | at least 1/1, minimum denominator 1 |
| `common.detection-recall` | required | at least 1/1, minimum denominator 1 |
| `common.task-success-rate` | not applicable | detection recall is the primary outcome |
| `common.false-positive-rate` | required | at most 0/1, minimum denominator 1 |
| `common.detection-precision` | required | at least 1/1, minimum denominator 1 |
| `common.replay-or-reanalysis-success-rate` | required | at least 1/1, minimum denominator 1 |
| `common.time-to-first-valid-result` | required | measurement required, no quality threshold |
| `common.total-request-units` | required | measurement required, no quality threshold |
| `common.total-tool-calls` | required | measurement required, no quality threshold |
| `common.total-cost-usd` | not applicable | no monetary cost model |
| `common.evidence-completeness` | required | at least 1/1, minimum denominator 1 |
| `common.policy-denial-correctness` | required | at least 1/1 over registered code-owned denial-Control cases, minimum denominator 1 |
| `common.cleanup-success-rate` | not applicable | DOMAIN-006 read-only/no-cleanup applicability rule |
| `web.http-operation-coverage` | required | at least 1/1, minimum denominator 1 |

The DOMAIN-006 cleanup metric remains not applicable for this read-only Capability plan. That does
not waive Target reconciliation, route invalidation, or cleanup Evidence: those are separately
mandatory security and evidence requirements.

`registered_web_policy_denial_control_registry` provides the exact denominator for
`common.policy-denial-correctness`. Its single content-addressed case triggers when Target cleanup
is observed before controlled-route verification and expects rejection before route
materialization without provider execution or network access. The registry state is
`registered-not-evaluated`; its expected false markers are policy, not an observed denial or an
authorized execution.

Required WEB-002B source evidence is exactly:

1. a completed WEB-002B Target Run authority;
2. the exact ZAP registration and Scanner plan;
3. raw SARIF SHA-256 and byte size;
4. strict SARIF normalization digest;
5. signed measurement-registry authority; and
6. verified Target cleanup receipt.

Required WEB-002D controlled-validation evidence is exactly:

1. a fresh Target attempt, operation, and fence;
2. fresh Capability activation, approval, and ActionPermit;
3. the signed single-use controlled-validation proxy route;
4. proxy attachment and detachment receipts;
5. three host-observed request and response receipts;
6. baseline, negative-Control, and Boolean-probe observations;
7. sealed Worker-result Evidence;
8. an independent Replay comparison;
9. expected policy-denial Control evidence; and
10. verified Target reconciliation and cleanup.

`sourceAndValidationIdentitySeparationRequired` is true. The policy state is
`registered-policy-not-evaluated`; measurement evaluation, floor satisfaction, Ground Truth or
expected-reference disclosure, Finding projection or authority, product confirmation, Scope
expansion, Graph mutation, reporting, external delivery, Permit issuance, and execution authority
are all false.

## Private expected reference and public projection

`bind_web_expected_finding_projection_policy` rebuilds the exact private P0-D1 Ground Truth and
returns two distinct objects:

- `WebPrivateExpectedFindingBinding` retains the raw Ground Truth case, expected Finding ID,
  matcher identity and digest, Surface IDs, and expected-reference commitment. It is
  `privateOnly`, is not a public product artifact, and has no Finding or execution authority.
- `WebBenchmarkFindingProjectionPolicy` exposes only a content-addressed public commitment, the
  exact measured-case and floor-policy references, Profile and Capability references, and the
  claim ceiling `benchmark-ground-truth-match`.

The public policy state is `registered-mapping-not-produced`. Expected-reference match,
floor satisfaction, Finding projection, product confirmation, Finding authority, Graph mutation,
reporting, external delivery, Permit issuance, and execution remain false. The projection ID is a
reserved future identity, not a Finding.

An existing Bug Bounty `validated=true`, UUID-backed Finding, P0-D1 expected Finding string,
Pentest Finding, model assertion, Scanner alert, or matching content digest cannot substitute for
the future floor-satisfied WEB-002 projection.

## Fail-closed behavior

All public models forbid unknown fields and content-address their complete nested representation.
Binding and reload reject stale or substituted Capability releases, Profiles, Target adapters,
Target registrations, Scanner plans or registrations, DOMAIN-006 plans, private Ground Truth,
route deployment or key identity, Campaign, Scope, Envelope, durable approval authorization or
receipt, Permit, request, current Target-journal head or effective fence, isolation evidence,
policy metric, threshold, applicability, denial-Control registry, evidence list, private
commitment, and authority marker.

They also reject a canonical Target journal whose record timestamps are non-monotonic or later than
route issuance, whose reset or isolation receipt cannot fit causally between its intent and receipt
records, whose reset and isolation environments differ, or whose isolation starts before reset
completion.

Signature validity alone is insufficient. Route verification requires the complete exact current
context and fails after expiry, revocation, key drift, fence drift, Target cleanup, or any nested
identity change. Verification reload repeats those live checks and requires exact wire equality.
Policy registration alone cannot accept measurements or produce a Finding.

## Compatibility, migration, and rollback

WEB-002A is additive. Existing WEB-001, REDTEAM, Bug Bounty, P0-D1, P0-E2B, DOMAIN-006,
Capability, Tool, Permit, Gateway, Worker, Graph, Evidence, benchmark, and Finding wire identities
remain unchanged. No Target, Scanner, Docker network, result, Graph event, or product Finding is
created, and no migration is required.

Rollback stops registering or issuing the WEB-002A measured-case, controlled-route, floor, and
projection-policy authorities. Because this slice has no materialization or execution, it requires
no runtime cleanup. Future materialized routes and Target Runs must instead follow their own
receipt-backed reconciliation contract.

## Verification

`tests/test_web_measured_case_authority.py` verifies additive Capability and Profile identity,
exact predecessor reconstruction, public/private separation, the complete DOMAIN-006 policy,
the content-addressed denial-Control denominator, private/public Finding mapping, false-marker
literalness, numeric wire strictness, and adversarial substitution.
`tests/test_web_proxy_route_authority.py` additionally covers durable approval lookup, approval
receipt and Permit binding, the current operation-journal head and effective fence, trust-anchor and
signature drift, key lifecycle and route revocation, TTL, cleanup invalidation, verification reload
with exact wire comparison, stage-local ordinal-1 sequencing, authorization and single-occurrence
testing-window bounds, stable consumption-slot convergence across route reissuance,
Campaign/Scope/request drift, and proof that verification never changes any materialization or
authority marker.

Live Docker isolation, route consumption, ZAP measurement, controlled execution, lifecycle
receipts, metric evaluation, floor satisfaction, and Finding production are intentionally outside
WEB-002A verification. Unit construction or a valid signature cannot be reported as evidence of
those future behaviors.

## Related contracts

- [WEB-002A measured validation Capability and Profile](../capability/WEB-002A-measured-validation-capability-profile.md)
- [WEB-002B distinct registry-governed ZAP source measurement](WEB-002B-distinct-registry-governed-zap-source-measurement.md)
- [WEB-001D](WEB-001D-independent-web-replay-ground-truth.md)
- [P0-D1](P0-D1-traditional-web-api-target-catalog.md)
- [P0-E2B](P0-E2B-zap-scanner-baseline-measurement.md)
- [DOMAIN-006](DOMAIN-006-domain-aware-validation-replay-benchmark-registry.md)
