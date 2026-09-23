# WEB-006: Installed Profile and Authenticated Discovery Evidence

- Status: Implementation integrated; fresh governed runtime verification pending
- Domain: Web / API
- Entry point: `pajin web-campaign-run-governed-local`
- Predecessor: [WEB-005](WEB-005-governed-local-authenticated-browser-campaign.md)
- Decision:
  [ADR-0300](../adr/0300-bind-governed-web-execution-to-a-closed-profile-and-passive-discovery-receipts.md)

## Objective

WEB-006 removes deployment selection and diagnostic dispatch assumptions from the WEB-005
coordinator without widening its live-target authority. One exact installed profile now supplies the
Campaign, target, product, adapter implementation, and plan identity used by the existing governed
Campaign path. A separate code-owned diagnostic catalog selects the executable diagnostic bundle.

The same authenticated Playwright context also performs bounded passive route and form discovery.
Each discovery response produces a bodyless boundary receipt, and the resulting proposal-only
aggregate is bound into the assessment Result, sealed Run, strict loader, and local report.

The production registry still contains only `juice-shop-local/v1` at exact
`http://127.0.0.1:3000`. Declarative schemas and closed catalogs make another reviewed adapter
possible; they do not make arbitrary sites executable.

## Bounded continuation flow

```text
exact operator-supplied adapter reference and numeric-loopback origin
-> closed production profile resolution with no fallback
-> code-owned adapter implementation and plan reconstruction
-> existing WEB-005 Campaign/Capability/Grant/Permit/Gateway sequence
-> independent Worker-side implementation re-resolution before network access
-> normal UI login in one fresh Playwright context
-> code-owned authenticated route navigation
-> same-context passive route/form discovery
-> one bodyless boundary receipt per completed discovery request
-> fixed code-owned diagnostic bundle execution
-> Result-bound discovery sidecar, sealed assessment Run, and strict reload
-> source/validation reconciliation and existing Graph/Finding admission
-> deterministic report, SARIF, and redacted PoC
-> delivery-readiness record with externalDeliveryPerformed=false
```

Discovery observations cannot add a route to the adapter plan, alter Campaign Scope, select a
diagnostic, mint a Permit, create a Graph proposal, or become a Finding. All executable input remains
deployment- and code-owned.

## Closed deployment profile and adapter selection

The public coordinator resolves only the exact pair of adapter reference and canonical origin from
the production `GovernedWebAdapterProfileRegistry`. The resolved immutable profile binds:

- adapter reference, ID, version, and signed-manifest inputs;
- implementation ID and implementation digest;
- reconstructed plan and expected plan digest;
- Campaign ID, target ID, target type, target product, description, and objective;
- adapter-catalog, profile, and registry digests.

The production adapter implementation catalog contains only the Juice Shop implementation. A second
code-owned implementation and profile exist only behind private test factories and are not installed
production inventory. Unknown references, other origins, changed implementation digests, changed plan
digests, caller-created catalog entries, and stale resolved objects fail closed.

The adapter plan is declarative for normal login and navigation behavior, including routes, selectors,
field bindings, token and object paths, and one-shot activation modes. These fields are accepted only
from a code-owned implementation selected by the closed catalog. The CLI, target content, discovery
output, artifacts, and model output cannot supply selectors, routes, payloads, Python import paths, or
callables.

The Worker receives the signed adapter implementation identity and independently reconstructs and
compares the exact plan after the subprocess boundary and before target network access. Coordinator
resolution alone is not sufficient Worker authority.

## Code-owned diagnostic catalog

The production `DiagnosticBundleCatalog` maps the exact Juice Shop adapter implementation ID and
digest to one immutable diagnostic bundle. The bundle binds:

- the ordered `sql-login`, `object-access`, and `dom-xss` checks;
- the fixed `sql-login -> object-access` and `dom-xss` attack-path shapes;
- diagnostic executor and path-builder IDs and implementation digests;
- the adapter implementation, catalog, and bundle digests;
- literal false local Finding and Graph authority.

The trusted runner resolves the bundle, revalidates the code-owned plan, and mints a task-bound,
one-use execution authority. Production execution creates its own exact `AssessmentNetwork` and
policies; callers cannot substitute a transport, session, browser callable, diagnostic callable, or
attack-path builder. The catalog validates DOM trial facts against the current Run's control/probe
page Evidence and screenshot hashes, executes the fixed HTTP diagnostics, then revalidates issue order
and attack-path structure before returning local diagnostic output.

The catalog digest binds the runtime profile and executable semantic identities. Private test catalogs
may use an injected transport, but the production catalog cannot. A replaced function, changed
implementation digest, reused execution authority, foreign task, mismatched Run, or non-code-owned
plan fails closed.

This catalog is an execution and provenance boundary for the existing fixed bundle. It does not yet
support variable diagnostic or attack-path cardinality in the downstream `validation/v1alpha1`
promotion and reporting contracts.

## Same-context authenticated passive discovery

Discovery runs after normal UI login and the installed route navigation, and before the DOM diagnostic,
inside that exact authenticated Playwright page and context. It does not create another login or copy a
session into a separate HTTP client.

The passive phase has the following non-negotiable request boundary:

- method exactly `GET`;
- origin exactly the installed canonical origin;
- no query component, including an empty `?` delimiter;
- zero request-body bytes;
- zero redirect hops and no redirect following;
- at most 20 discovery requests;
- the same monotonic assessment deadline and cumulative request counter as every earlier and later
  phase, with an overall ceiling of 100 requests.

The network reservation gate checks method, origin, query, body, redirects, phase budget, and cumulative
budget before allowing the browser request. A phase transition does not reset the cumulative counter.
The traversal itself is deterministic and limited to four query-free routes at depth one, with bounded
links, forms, fields, navigation time, and settle time. It records structural route and form metadata
only and never submits a discovered form.

## Per-request boundary receipts

The passive response path does not call `response.body()`. It uses browser-reported transfer size and
bounded response headers to complete one `PassiveDiscoveryBoundaryReceipt` for each accepted request.
Each receipt binds:

- the request Evidence ID and sequence;
- exact canonical origin and origin-relative path;
- `GET`, no query, zero request bytes, and zero redirect hops;
- status, browser-observed transfer bytes, and bounded Content-Type essence;
- zero retained response bytes and the SHA-256 digest of empty bytes;
- a content-addressed receipt digest.

The associated generic `RequestEvidence` retains the same empty response digest and zero response bytes.
Receipt order and identity must match the request Evidence exactly. Missing size metadata, a body-retaining
completion path, duplicate or reordered evidence, a changed path/status/media type, or any receipt digest
drift invalidates the aggregate.

## Proposal-only sidecar and strict loading

`AuthenticatedDiscoveryEvidence` uses
`pajin.dev/authenticated-passive-discovery-evidence/v1alpha1` and always declares `proposal-only`
semantics. It binds the exact discovery Plan and Result, ordered request Evidence, ordered boundary
receipts, their set digests, browser-closed state, retention markers, and literal false Scope-expansion,
Permit, form-submission, payload, Graph, Finding, execution, and external-delivery authorities.

A new assessment writes this aggregate as `discovery-evidence.json`. `LocalWebAssessmentResult` binds
its exact relative reference and evidence digest, and the Run seal therefore covers both the Result and
sidecar. The strict source loader requires the two optional Result fields to be both present or both
absent. When present, it loads the sidecar with a byte bound and verifies its digest, origin, Plan,
proposal-only markers, and exact discovery request subset against `result.json`. The deterministic local
report conditionally renders discovery route, form, request, and evidence-digest fields only after the
same checks.

Legacy WEB-003 and WEB-005 Results without the two optional discovery fields retain their previous
digest material in the Result model. The completed WEB-005 Campaign now strictly reloads because the
WEB-004 reference reader preserves the original wire when all five later defaulted plan/result fields
were absent. No sealed Run was rewritten. A new Result
cannot reference discovery Evidence without the sidecar or carry the sidecar without the matching
Result reference and digest.

## Existing governance and reporting authority

WEB-006 does not replace or shortcut WEB-005. Source and validation still require separate approvals,
one-use Permits, Gateway dispatches, observer and executor subprocesses, target and execution
attestations, sealed Runs, strict semantic reconciliation, and actual Graph admission before positive
results can become PAJIN Findings. SARIF and the redacted PoC remain downstream projections of the
strictly reloaded validation snapshot.

Discovery route/form metadata and boundary receipts remain observation only. They do not enter the
promoted three-Finding set or the two confirmed attack paths. The command accepts no destination and
continues to write a delivery-readiness record with no delivery receipt authority and
`externalDeliveryPerformed=false`.

## Failure and negative cases

The continuation fails closed when any of the following occurs:

- the adapter reference and origin do not resolve to one exact production profile;
- profile, adapter-catalog, implementation, plan, diagnostic-catalog, bundle, executor, or path-builder
  identity differs from the code-owned value;
- the coordinator and Worker reconstruct different plans or implementation identities;
- a caller attempts to inject a catalog, transport, network, browser, callable, route, selector, payload,
  or diagnostic shape into production execution;
- passive discovery attempts a non-GET method, query delimiter, request body, redirect, foreign origin,
  denied path, 21st phase request, or 101st cumulative request;
- the passive response path retains body bytes or cannot produce its bounded transfer-size metadata;
- request Evidence and boundary receipts are missing, duplicated, reordered, or differently bound;
- the sidecar digest, Plan, origin, Result, false authority markers, or sealed artifact inventory differs;
- a discovery observation is used to widen Scope, select an executable action, admit Graph state, promote
  a Finding, or claim external delivery.

Failure does not restore consumed WEB-005 approvals, Permits, bindings, leases, or target state. A retry
requires fresh governed authority.

## Compatibility, migration, and rollback

WEB-006 is additive for the currently supported Juice Shop flow. Production callers continue to use
the WEB-005 CLI and `juice-shop-local/v1`; the coordinator now resolves that identity through the closed
profile and diagnostic catalogs. Existing sealed Runs and legacy Result digests are not migrated,
rewritten, or promoted.

Deploying another application requires a reviewed code-owned implementation, an exact production
profile, signed adapter inventory, a code-owned diagnostic bundle, target-specific verification, and a
compatible downstream artifact contract. Variable diagnostic counts or attack-path shapes require a new
version, expected to be `v1alpha2`, rather than weakening `validation/v1alpha1` readers.

Rollback disables the new catalog entries or same-context discovery integration without rewriting
historical Runs. A Result already sealed with `discovery-evidence.json` must always be read with the
WEB-006-aware strict loader; removing only its sidecar is artifact tampering, not rollback.

## Known limitations

- Production inventory contains only the exact numeric-loopback OWASP Juice Shop profile. No second
  production adapter currently proves that the schema and catalogs work for another application.
- Arbitrary sites, user-supplied credentials, SSO, MFA, CAPTCHA, anti-CSRF workflows, multi-step form
  submission, generic payload generation, browser extensions, HTTPS/IPv6/private-network/Internet targets,
  and browser diversity remain unsupported.
- The diagnostic bundle still contains exactly three checks and two attack paths. The existing
  semantic, Graph, validation, report, SARIF, and PoC path has not been versioned for variable cardinality.
- Discovery is limited to passive query-free GET navigation and structural metadata. It does not prove
  that a discovered form is safe or authorized to submit.
- The host-loopback Worker, same-host trust boundary, target-side retained account/session, local Graph
  custody, and external-delivery limitations documented by WEB-005 remain unchanged.
- The exact Juice Shop aggregate browser aborts query-free product and carousel image GETs outside the
  passive phase to stay under the unchanged cumulative request ceiling. Screenshots retain their page
  and control evidence but omit those decorative pictures. The observed completed assessments used 95
  of 100 requests, so a changed target may fail closed at the same boundary.

## Verification status

The new profile/catalog/discovery-receipt path completed a fresh governed local Juice Shop Run and a
separate redacted PoC replay on 2026-09-23. Each Run sealed independent source and validation results,
nine Graph events, three validated Findings, two attack paths, a report, SARIF, and a local PoC bundle.
Both completed parent Runs passed strict reload in separate processes. Source and validation each
recorded 95 requests, including 19 passive discovery requests, four discovered routes, and one form.
The two output roots each contained 131 regular files; a bounded scan found no PEM private-key header,
Bearer/Cookie header, or nonempty JSON password/token value patterns. This screen is not a universal
secret detector. Expanded Web regression passed 573 tests, repository Ruff passed, and Linux-target
mypy passed 597 source files. Local accounts remain on the approved target; no external delivery was
authorized or performed. The initial budget-exhausted attempt remains terminal and is not replayed.
