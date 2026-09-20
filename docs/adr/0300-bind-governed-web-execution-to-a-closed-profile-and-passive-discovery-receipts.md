# ADR-0300: Bind Governed Web Execution to a Closed Profile and Passive Discovery Receipts

- Status: Accepted
- Date: 2026-09-15
- Scope: WEB-006 installed adapter selection, diagnostic dispatch, and authenticated discovery evidence

## Context

WEB-005 proves the full governed path for one exact local OWASP Juice Shop adapter, including Campaign
and Capability authority, separate source and validation execution, Graph admission, Finding promotion,
SARIF, and a redacted PoC. Its successful local evidence does not prove support for another application.
The coordinator and diagnostic runner also need explicit code-owned selection boundaries before the
existing plan schema can safely serve more than one reviewed implementation.

WEB-004 has a separate passive discovery runner, but running it in a fresh context after the governed
assessment would require another login or an unaudited session transfer. Merely retaining aggregate
route/form metadata would not prove that every discovery request stayed GET-only, query-free, bodyless,
same-origin, and redirect-free. Reading response bodies only to hash and discard them would also cross a
larger data-retention boundary than passive structural discovery requires.

The continuation must therefore make selection and discovery provenance explicit while preserving the
exact WEB-005 authority chain and existing artifact compatibility.

## Decision

### Resolve only closed deployment profiles

Add an immutable production `GovernedWebAdapterProfileRegistry` keyed by the exact adapter reference and
canonical origin. A resolved profile binds the adapter identity, code-owned implementation identity and
digest, reconstructed plan and digest, Campaign and target metadata, and catalog/profile/registry
digests. Resolution has no fallback and resolved objects revalidate their current code-owned identity.

The production registry initially contains only `juice-shop-local/v1` at
`http://127.0.0.1:3000`. A private second profile exists only to prove the catalog boundary in tests; it
is not production inventory. Schema generality, a test fixture, or a caller-authored manifest is not an
installed adapter.

The existing declarative login and navigation plan remains code-owned. The CLI, target response,
discovery output, model output, and artifacts cannot supply Python import paths, callables, routes,
selectors, field bindings, or payloads. The Worker independently resolves the signed implementation
identity and reconstructs the plan after the subprocess boundary and before target access.

### Dispatch diagnostics through a separate closed catalog

Add an immutable production `DiagnosticBundleCatalog` that maps the exact adapter implementation ID and
digest to the existing ordered SQL login, object access, and DOM XSS executor and the two fixed
attack-path shapes. The bundle digest binds adapter, executor, path-builder, diagnostic order, path
shape, runtime profile, and false local Finding/Graph authority.

The trusted runner, not a public caller, binds the exact current Run, reconstructed plan, production
network and policies, browser observation, and a task-scoped one-use execution authority. The catalog
checks current executable identities, DOM trial-to-page Evidence and screenshot lineage, issue order,
and attack-path structure. Private test catalogs may use an injected transport; production execution
cannot accept caller-created transports, networks, sessions, or callables.

This decision catalogs the existing fixed semantic bundle. It does not generalize the downstream
`validation/v1alpha1` contract to variable diagnostic or attack-path counts.

### Discover within the authenticated browser context

Run passive discovery after normal login and installed route navigation, and before DOM probing, using
the same Playwright page and context. Discovery does not mint another credential, copy cookies to a
direct client, or create a second browser login.

The shared network mediator starts a dedicated `browser-passive-discovery` phase. Before browser
continuation, it requires exact-origin `GET`, no query delimiter, zero request bytes, and zero redirect
hops. The phase allows at most 20 requests and remains inside the assessment-wide monotonic ceiling of
100 requests and the existing deadline. Starting a new phase does not reset the total counter.

Traversal is deterministic and structurally bounded. It retains query-free route and value-free form
metadata only, never submits a discovered form, and cannot change Campaign Scope or executable input.

### Seal one bodyless receipt per discovery response

For a passive response, do not call the browser response-body API. Complete the reservation from status,
bounded Content-Type essence, and the browser-reported transfer size. Create one content-addressed
`PassiveDiscoveryBoundaryReceipt` bound to the generic request Evidence identity and sequence, exact
origin-relative request metadata, zero retained response bytes, and the digest of empty bytes.

Build one `AuthenticatedDiscoveryEvidence` aggregate with `proposal-only` semantics over the exact
discovery Plan and Result, ordered request Evidence, ordered receipts, browser-closed state, retention
markers, and literal false Scope, Permit, form, payload, Graph, Finding, execution, and delivery
authorities.

Write the aggregate to `discovery-evidence.json`. Bind its relative reference and digest into
`LocalWebAssessmentResult`, include both in the Run seal, and make the strict loader verify the sidecar,
Result, origin, plan, exact passive request subset, and deterministic report together. The report may
render only bounded discovery counts and the aggregate digest after verification.

The two new Result fields are optional as a pair. When absent, they are omitted from legacy digest
material so existing WEB-003 and WEB-005 Results remain byte- and digest-compatible. When present, a
missing or mismatched sidecar fails closed.

### Preserve WEB-005 promotion and delivery boundaries

Discovery evidence remains proposal-only and cannot enter Graph or Finding promotion. The existing
separate source/validation authorities, target and execution attestations, strict reconciliation, Graph
admission, validation snapshot, SARIF, and redacted PoC requirements remain unchanged. The local command
still accepts no external destination and records `externalDeliveryPerformed=false` without a distinct
authenticated delivery action and receipt.

## Consequences and limitations

- Production selection is explicit and closed, but only one exact Juice Shop numeric-loopback profile
  and one fixed diagnostic bundle are installed.
- Adding a second production target requires reviewed implementation and diagnostic code, signed
  inventory, profile installation, and target-specific end-to-end verification.
- Variable diagnostic and attack-path cardinality is not supported by this decision. It requires a new
  downstream version, expected to be `v1alpha2`, rather than changing `validation/v1alpha1` in place.
- The same-context design proves session continuity without persisting or exporting a reusable session,
  but it retains the WEB-005 host-subprocess and same-host trust limitations.
- Boundary receipts prove the runtime's retained metadata contract. They are not a trusted host egress
  proxy record and do not prove independent network enforcement.
- Arbitrary sites, SSO, MFA, CAPTCHA, caller credentials, discovered-form submission, generic payloads,
  remote targets, container/VM isolation, session revocation, account cleanup, and external report
  delivery remain outside the supported slice.

## Compatibility, migration, and rollback

This decision is additive. The public CLI keeps the same bounded inputs. Existing sealed Runs, adapter
manifests, Campaign/Capability/Permit objects, Graph events, Findings, validation snapshots, SARIF files,
and PoC bundles are not rewritten or upgraded.

Migration installs the closed profile and diagnostic catalogs and enables same-context discovery for
new exact-profile executions. A future target or variable-cardinality diagnostic set must opt into its
own reviewed profile and compatible artifact version.

Rollback disables the new execution path or installed entries without altering historical evidence.
Already sealed WEB-006 Runs remain readable only when their bound sidecar is preserved and verified.

## Rejected alternatives

- Treating any syntactically valid adapter manifest as installed executable code.
- Resolving unknown references through a default or nearest matching profile.
- Letting the CLI, target, discovery result, model, or artifact supply executable selectors, routes,
  payloads, imports, transports, or callables.
- Running discovery in another authenticated context or transferring a reusable session outside the
  browser.
- Reading and discarding passive response bodies without a bodyless boundary receipt.
- Resetting the cumulative request counter when discovery starts.
- Using route/form discovery as Campaign Scope, Permit, Graph, or Finding authority.
- Changing `validation/v1alpha1` cardinality implicitly to accommodate a future diagnostic catalog.
- Reporting or delivering results externally without a separate destination-bound authorization and
  receipt.
