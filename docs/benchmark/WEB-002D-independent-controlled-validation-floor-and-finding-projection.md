# WEB-002D Independent Controlled Validation, Profile Floor, and Finding Projection

## Status

Implementation, deterministic/static verification, and exact-commit real-Docker conformance are
complete. Ubuntu 24.04 GitHub run `33310558350`, job `99254722600`, exact-checked-out commit
`975bf7876a186cefae66c289d09f530f3e0fe7aa`, passed the exact test in
`666.82s (0:11:06)`; the complete job took 12 minutes 20 seconds. Success and denial lifecycles,
cleanup, sealing, and fresh-session reopen all passed; six independent container/network
label/name queries returned zero matching resources.
The covered WEB runtime, Docker test, and conformance workflow paths remain unchanged at the current checkpoint.
This evidence is bounded to the registered synthetic P0-D1 case and does not authorize production
or external probing.

## Purpose

WEB-002D independently validates the same sealed WEB-002B source that WEB-002C may project as an
open Hypothesis. It does not consume or derive execution authority from the WEB-002C Graph
admission. Instead, it consumes the WEB-002A signed route, executes the exact baseline, negative
Control, and Boolean probe through a proxy-only Worker boundary, evaluates the registered Profile
floor, and projects only a benchmark-ground-truth-match Finding.

This contract does not authorize arbitrary requests, Scanner reuse, Scope expansion, Graph
mutation, reporting, external delivery, further Permit issuance, or additional execution.

## Versioned artifacts

| Artifact | Wire |
| --- | --- |
| Route claim | `pajin.dev/web-controlled-validation-route-claim-receipt/v1alpha1` |
| Route denial | `pajin.dev/web-controlled-validation-route-denial-receipt/v1alpha1` |
| Worker Evidence | `pajin.dev/web-controlled-validation-worker-evidence/v1alpha1` |
| Sealed authority | `pajin.dev/web-controlled-validation-authority/v1alpha1` |
| Source request units | `pajin.dev/web-source-request-unit-observation/v1alpha1` |
| Floor evaluation | `pajin.dev/web-validation-floor-evaluation/v1alpha1` |
| Finding projection | `pajin.dev/web-benchmark-finding/v1alpha1` |

All models are strict, content-addressed, and canonical-wire checked. JSON array-to-tuple conversion
is allowed only during JSON-mode reopen of tuple fields; Python-mode lists remain invalid.

The signed `WebProxyRouteRuntimePolicy` requires `claimLedgerIdentityDigest`. It is an opaque,
domain-separated digest of the deployment ID and the claim ledger's canonical absolute path. The
raw path is not serialized into the route or runtime-policy artifact. Moving the ledger or changing
the deployment therefore requires a newly signed runtime policy and route rather than caller-side
path substitution.

## Inputs and prerequisites

- the exact WEB-002A measured-case, Capability/Profile, signed route, floor policy, private
  expected-reference mapping, Campaign/Scope/approval/Permit, and Tool request authorities;
- a sealed WEB-002B source authority and its complete provider, Target-operation, raw SARIF,
  registry, normalization, cleanup, and audit predecessors;
- the exact source-owned production ZAP catalog provider for the current build or load call;
- one fresh controlled Target attempt and fence, exact Target journal, exact Docker validation
  adapter, append-only route ledger, and deployment Trust Anchor; and
- immutable Target, Worker, proxy, and ZAP image identities fixed by the registered authorities.

WEB-002B and WEB-002D execution identities must be disjoint. A valid artifact, matching digest,
completed Target Run, or current route signature cannot substitute for the complete context.

## Route claim and denial

`WebControlledValidationRouteClaimLedger` validates its exact SQLite schema, triggers, journal
mode, and integrity before every transaction. It never creates missing objects in an existing
store. The first controlled side effect is an atomic compare-and-set claim of the exact
consumption slot. Reissue with another route nonce cannot create another allowance for the same
approval/Permit consumption.

Before a production adapter can cause any Docker side effect, it recomputes the actual ledger
identity from its deployment ID and canonical absolute SQLite path and requires it to match the
digest in the signed runtime policy. A route signed for one ledger cannot be rebound to a second
SQLite claim ledger, even when every other route and deployment identity is unchanged.

Success produces one `WebControlledValidationRouteClaimReceipt`. Cleanup-before-route invokes the
registered denial case and produces one `WebControlledValidationRouteDenialReceipt`. The denial
path records a durable spent tombstone while keeping route materialization, provider execution,
and network access false. A denied or failed attempt cannot be retried as a fresh allowance.

## Controlled runtime and durable Evidence

`DockerWebControlledValidationAdapter` reconstructs the exact Target and Worker operations,
materializes only the Worker-proxy bridge, and obtains host-observed Target-before/after and proxy
topology receipts. The Worker cannot attach directly to the Target network and the Target publishes
no host port. Exactly three fixed GET request/response units are admitted for baseline, negative
Control, and Boolean probe; caller-authored query material is not accepted.

Production construction records an immutable binding to the exact live route-authority object,
claim-ledger object and identity digest, code-owned UTC clock, runtime-policy digest, deployment ID,
Gateway policy ID/version, and Worker backend ID/version. The production custody guard revalidates
that binding before dispatch or final use. Replacing any bound object, clock, or identity after
construction fails closed before the backend is called.

`WebControlledValidationWorkerEvidence` binds the route claim, Target attempt/fence and execution,
Worker result, exact request/response observations, proxy attach/detach, Target reconciliation and
cleanup. Production Evidence is stored in an exact append-only SQLite store and reopened by a
fresh adapter. Existing stores fail closed on missing or extra schema objects, trigger drift,
wrong journal mode, failed integrity checks, noncanonical records, or content mismatch.

## Provider custody

Final authority build and reload require the exact
`CatalogBoundDockerZAPScannerTargetFactoryAdapter` owned by the supplied WEB-002B reopen context in
that call. It must wrap the exact `DockerZAPScannerTargetFactoryAdapter`, which must use the exact
`SubprocessDockerCommandRunner` with executable `docker`, plan-derived timeout, canonical absolute
state path and artifact root, constructor-owned state, and unshadowed production methods.

Subclasses, delegating providers, a same-config different object, fake runners, instance or class
method shadowing, `__getattribute__` shadowing, unexpected attributes, executable/timeout drift,
artifact-root drift, and wrapper/inner authority-snapshot disagreement are rejected before floor or
Finding projection. A new exact provider may be reconstructed in a fresh process, but it must be
the one shared by that process's source reopen context and final build/load call.

This guard is an in-process construction boundary. Arbitrary private-memory mutation, interpreter,
Docker executable or daemon, operating-system, and host-administrator compromise remain outside
the artifact contract and inside the deployment trusted computing base.

## Sealing and reopen

A successful authority binds exactly eight canonical audit events covering route claim, controlled
execution, Worker Evidence, comparison, cleanup, evaluation, Finding, and seal. The registered
denial lifecycle binds exactly seven canonical events plus its durable tombstone. Event order,
predecessor heads, identities, timestamps, and canonical payloads are exact.

Fresh-session loaders reopen the source and all durable stores, rebuild route and Target history,
validate the completed journal, Worker Evidence, cleanup, floor evaluation, Finding, and outer
authority, and require byte-equivalent canonical JSON. Historical cleanup-invalidated route
verification proves only that the original signed predecessor chain matched; it never revives the
route.

## Independent evaluation

The evaluation gate derives the WEB-002B request-unit observation from the sealed source and does
not trust a caller count. It independently recomputes:

1. source and controlled Evidence inventories;
2. baseline, negative-Control, and Boolean-probe observations;
3. Worker and Tool result claims;
4. elapsed time from receipt timestamps;
5. the registered cleanup-before-route denial as exact 1/1 with zero side effects; and
6. all fourteen DOMAIN-006 metric observations and applicability decisions.

The private matcher executes only inside the gate. The public evaluation includes commitments and
the matched boolean but never the expected Finding reference, raw Ground Truth, controlled query,
or raw SARIF.

The floor is satisfied only when the exact six source-evidence names, ten controlled-evidence
names, all registered rational thresholds/applicability decisions, identity separation, trusted
execution, independent recomputation, denial Control, and cleanup proof pass.

## Finding ceiling

`WebBenchmarkFindingProjection` confirms only
`benchmark-ground-truth-match`. Its state explicitly leaves impact and severity unevaluated. It
sets Finding projection, benchmark match, Profile floor, and product Finding confirmation true,
while keeping all of the following false:

- private Ground Truth, expected-reference, raw SARIF, and controlled-query disclosure;
- Scope expansion and Graph mutation;
- reporting and external delivery; and
- Permit issuance and additional execution.

The artifact cannot substitute for a production exploitability assessment, severity decision,
Graph admission, report, or externally delivered Finding.

## Negative cases

Build and reload fail closed on route reuse, missing tombstones, live-route resurrection, foreign
or stale approval/Permit/Scope/Target/fence identities, source/validation identity overlap,
split-ledger substitution, provider substitution, provider method or state drift, post-construction
route-authority, claim-ledger, clock, deployment, Gateway, or Worker identity drift, incomplete or
altered audit journals, noncanonical JSON, modified durable stores, Worker/proxy/Target topology
mismatch, request count or body drift, cleanup failure, denial side effects, metric denominator or
applicability drift, private matcher mismatch, and any authority marker above its defined ceiling.

## Compatibility, migration, and rollback

WEB-002D remains additive to WEB-002A/B/C, P0-D1, P0-E2B, DOMAIN-006, Capability, Permit, Graph,
and Scanner authority, and their wire identities do not change. The
`pajin.dev/web-proxy-route-runtime-policy/v1alpha1` schema is nevertheless intentionally hardened:
`claimLedgerIdentityDigest` is now required. A pre-hardening `v1alpha1` route or runtime-policy
artifact lacks that field and fails closed under current canonical readers. It cannot be patched,
inferred from an artifact, or migrated in place because the raw ledger path is deliberately absent;
the runtime policy and signed route must be reissued for the intended deployment and ledger.
Consumers must deploy compatible readers and writers before retaining newly issued artifacts.

Rollback stops issuing and reading the new WEB-002D artifacts. It does not make an attempted route
reusable and must not rewrite append-only claim, denial, Worker Evidence, Target-operation, or audit
records. Any live disposable Docker resources still require normal reconciliation and cleanup.
Historical WEB-002D Finding projections must not be reinterpreted as generic findings with broader
authority. Rollback also must not restore acceptance of pre-hardening route/runtime-policy
artifacts that omit the required ledger identity.

## Verification

- `tests/test_web_controlled_validation_route.py`: exact CAS ledger, claim, denial tombstone,
  corruption, and concurrency boundaries.
- `tests/test_web_controlled_validation_runtime.py`: exact Docker adapter inputs, topology,
  request/response and cleanup Evidence, durable-store reopen, split-ledger rejection before
  Docker side effects, eight post-construction route-authority/ledger/clock/deployment/Gateway/
  Worker state-drift cases, and other tamper cases.
- `tests/test_web_controlled_validation_authority.py`: success/denial sealing, provider custody,
  fresh reopen, floor/Finding, canonical wire, predecessor, and false-authority cases.
- `tests/test_web_proxy_route_authority.py`: live and historical cleanup-invalidated route
  verification.
- `tests/test_web_validation_evaluation.py`: independent recomputation, fourteen metrics, private
  matcher, evidence inventory, strict JSON, and bounded Finding projection.
- `tests/test_web_controlled_validation_docker.py`: required opt-in real-Docker success and denial
  conformance. Ubuntu 24.04 run `33310558350`, job `99254722600`, checked out exact commit
  `975bf7876a186cefae66c289d09f530f3e0fe7aa` and passed the exact node in
  `666.82s (0:11:06)`. The complete 12-minute-20-second job verified cleanup, sealing, and
  fresh-session reopen after the current compatibility and custody hardening. Six independent
  container/network label/name queries returned zero matching resources.
- `.github/workflows/web-002d-conformance.yml`: manual, non-cancelling Ubuntu 24.04 lane that builds
  the four repository images, pulls the registered ZAP linux/amd64 manifest by registry digest,
  records runtime and exact image identities, runs the exact node, and audits residue without
  deleting it.
- `tests/test_ci_workflow.py`: static contract for manual confirmation, least privilege, digest pin,
  identity logging, exact test selection, and independent label/name residue filters.

## Related documents

- [WEB-002A](WEB-002A-exact-measured-case-route-floor-finding.md)
- [WEB-002B](WEB-002B-distinct-registry-governed-zap-source-measurement.md)
- [WEB-002C](../graph/WEB-002C-sealed-zap-source-knowledge-admission.md)
- [ADR-0256](../adr/0256-bind-web-002d-independent-controlled-validation-to-durable-evidence-floor-and-finding.md)
