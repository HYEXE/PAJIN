# UX-009C: Operator-only Measured Web Product View

## Purpose

Expose one exact UX-009A measured-Web product projection through an authenticated Control Plane
read and the existing same-origin Web Console. The transport consumes only the deployment-pinned,
zero-argument UX-009B reader and returns the unchanged `WebMeasuredProductFlowProjection`.

UX-009C is a consumption boundary, not a Web runtime or another product authority. It does not
select a Run, path, provider, adapter, source, verifier context, Campaign Scope, Profile, route,
approval, Permit, request, dispatch, or target. It creates no product artifact, application record,
Run, Graph event, report, delivery instruction, Tool call, Worker dispatch, or execution authority.

## Deployment composition and fixed endpoint

Deployment bootstrap may inject one fully composed
`pajin.workflow.web_measured_product_reader.WebMeasuredProductReader` through the keyword-only
`create_app(..., web_measured_product_reader=...)` argument. The injected object must have that
exact concrete type. UX-009C adds no settings field, environment variable, serialized registry, or
caller-controlled private reopen context.

The Control Plane always registers exactly one product route:

- method and path: `GET /v1/products/web-measured-flow`;
- response model: unchanged `WebMeasuredProductFlowProjection`;
- successful reader calls: `reader.read()` with zero arguments; and
- unconfigured deployment: a fixed `503` response after authentication and authorization.

The fixed path has no path selector. Any query string or non-empty request body is rejected with a
fixed `400` before the reader is called. Other methods are rejected by routing and cannot be
translated into a selector or action.

## Authentication, authorization, and cache boundary

The existing bearer authenticator and Control Plane role dependency apply before configuration or
reader state is inspected:

- a missing or invalid credential receives `401`;
- an authenticated principal without the `operator` role receives `403`; and
- an authenticated principal containing the `operator` role may perform the read.

An Approver, Auditor, generic Worker, or Replay Worker role alone is insufficient. UI control state
is only a usability constraint; the server dependency remains authoritative.

Every `/v1/` response, including `200`, `400`, `401`, `403`, `405`, `409`, and `503`, retains the
Control Plane `Cache-Control: no-store, max-age=0`, `Pragma: no-cache`, no-referrer, and `nosniff`
headers. UX-009C creates no response cache, conditional validator, cookie, CORS permission, or
browser storage entry. Every successful request calls the UX-009B reader again.
Concurrent requests within one application are serialized around that exact reader because UX-009B
does not require a deployment resolver to be thread-safe. Serialization does not cache or reuse a
projection; each request still performs its own integrity-validating read.

## Unchanged product wire

A successful response is the UX-009A `pajin.dev/web-measured-product-flow-projection/v1alpha1`
object serialized by alias without a wrapper, timestamp, principal, deployment ID, selector, path,
or reopen context. Its flow, source, measured-case, Evidence, floor, Finding, report, and authority
references remain bound exactly as defined by UX-009A.

In particular, the sealed UX-009A authority boundary still contains
`httpEntrypointAvailable=false` and `uiEntrypointAvailable=false`. Those literals mean that the
projection itself grants no transport authority. UX-009C is a separate Operator-authorized
consumer and neither changes those values nor recomputes the content-addressed flow.

A `WebMeasuredProductReaderError` becomes a fixed `409` that does not reflect an exception, path,
provider, private marker, or verifier context. The endpoint does not return the deployment
registration or any private UX-009B field.

## Same-origin strict text-only Web Console

The existing public `/ui` shell remains a non-authoritative same-origin static asset. It does not
load product data during login. An explicit button is enabled only while the current in-memory
credential has the `operator` role and sends one fixed
`GET /v1/products/web-measured-flow` request through the existing request helper with:

- bearer authorization from memory;
- `cache: "no-store"`;
- `credentials: "omit"`;
- `redirect: "error"`; and
- `referrerPolicy: "no-referrer"`.

The browser validates exact root and nested key sets, content-addressed identifier bindings,
cross-section reference equality, and the code-owned order, ID, digest, unit, applicability,
comparison, not-applicable reason, and signed-64 rational contract of all fourteen public metrics
with eleven required and three not applicable. It also validates the bounded claim ceiling,
information-only impact and severity, unavailable report state, and every disclosure or authority
boolean before rendering.

The view displays only text summaries through `textContent`. It provides no raw JSON dump, markup
sink, dynamic link, download, report, delivery, route, approval, Permit, or execution control.
Malformed, extra-field, reference-substituted, boolean-coerced, disclosure-escalated, or
claim-escalated responses remain hidden. Credential replacement, lock, and `pagehide` abort active
requests, invalidate request generations, and clear rendered product data. A late response from an
old credential generation cannot repopulate the view.

## Read-only and side-effect boundary

The route has no repository, service, approval, Graph, report, delivery, Tool, Worker, or execution
dependency. Endpoint tests take database and registered product/source Run snapshots after app
startup and require them to remain unchanged across denied, rejected, and successful reads.

The UX-009B loader's mandatory advisory snapshot locking remains an explicit exception: a fresh
host TEMP may create ephemeral `.pajin-run-locks` coordination files. These files are not product,
application, or security-authority records and must not be bypassed. Contextual WEB-002D reopening
may also perform its existing read-only provider database and Docker inspector Evidence checks.
Those checks do not create, reset, start, execute, connect, stop, remove, or otherwise mutate a
Target, provider, Docker, Worker, network, or credential resource.

UX-009C does not claim the fresh-process, whole-call side-effect audit reserved for UX-009D.

## Disclosure and authority ceiling

The response and view disclose none of the following:

- private Ground Truth or an expected reference;
- raw SARIF, controlled query, response body, transcript, or raw Evidence;
- route, approval, Permit, request, dispatch, container, network, or filesystem coordinates;
- Campaign Scope availability or expansion, or Profile inference;
- generic production-vulnerability confirmation, negative security conclusion, or evaluated impact
  or severity;
- Graph content or mutation;
- report creation, report delivery, or external delivery; or
- Capability activation, Permit issuance, route reuse, or additional execution.

The maximum displayed claim remains `benchmark-ground-truth-match` for the exact bounded case with
both impact and severity fixed to `not-evaluated-information-only`.

## Fail-closed cases

UX-009C rejects or withholds data for:

- a missing, invalid, or non-Operator credential;
- an unconfigured or foreign reader;
- any query string, request body, method substitution, or caller-selected input;
- a UX-009B integrity, source, product, context, tamper, or substitution failure;
- a response with missing or extra keys, invalid IDs or digests, mismatched references, duplicate
  metrics, metric-count drift, numeric wire drift, or strict-boolean drift;
- a changed claim ceiling, Finding confirmation, impact, severity, report, disclosure, Graph, or
  execution marker; and
- a stale response after credential replacement, lock, or page teardown.

## Compatibility, rollback, and remaining work

UX-009C is additive. It changes no UX-009A artifact, event, digest, or wire; no UX-009B registration
or reader API; no WEB-002A/B/C/D contract; and no database schema. Rollback removes the optional
reader injection, fixed route, and Console panel while retaining every sealed source and product
Run and their existing direct-call readers.

UX-009D remains required for independent fresh-OS-process repeated reads, canonical byte and digest
determinism, independent reload, event equivocation and stale-root cases, and a complete audit that
product consumption creates no provider, Docker, network, Graph, report, or delivery side effect.

## Related documents

- [ADR-0257](../adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)
- [UX-009B contract](UX-009B-deployment-pinned-contextful-product-reader.md)
- [UX-009A contract](UX-009A-sealed-measured-web-product-flow-projection.md)
- [WEB-002D contract](../benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md)
