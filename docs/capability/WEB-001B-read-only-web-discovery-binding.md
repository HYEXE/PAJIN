# WEB-001B: Read-only Web Discovery Capability Binding

- Status: Implemented, preparation boundary only
- API versions:
  - `pajin.dev/web-read-only-discovery-binding/v1alpha1`
  - `pajin.dev/web-read-only-discovery-preparation/v1alpha1`
- Binding identity: `pajin.web.discovery.http-get-binding@1.0.0`
- Reused Capability: `pajin.pentest.http-get-recon@1.0.0`
- Authority: `src/pajin/capabilities/web_discovery.py`
- Decision: [ADR-0213](../adr/0213-reuse-get-recon-for-web-discovery-without-egress-authority.md)

## Purpose

WEB-001B binds one exact concrete WEB-001A GET Surface to the existing complete Pentest Recon
CAP-002 authority set and the DOMAIN-004 minimum Web Worker boundary. It adds no new Campaign
Profile, Capability, Tool, execution engine, or Graph ledger.

The binding and preparation records are non-authoritative composition artifacts. Preparation
proves that an exact request can be compiled by a current signed Capability activation; it does not
prove that the request is in current Campaign Scope or approved, and it cannot issue or consume an
ActionPermit, select a deployment, dispatch a Worker, or execute a network request.

## Exact binding

`WebReadOnlyDiscoveryBinding` content-addresses the following immutable identities and ceilings:

| Dimension | Exact value |
| --- | --- |
| Surface type and schema | `web.http-operation` / `pajin.locator.web.http-operation.v1` |
| Locator | registered concrete `http-endpoint`; URI templates unavailable |
| Capability | complete `pajin.pentest.http-get-recon@1.0.0` CAP-002 authority set |
| Domain classification | exact DOMAIN-003 Web classification of that Capability |
| Worker requirement | exact DOMAIN-004 `pajin.worker-boundary.web.minimum@1.0.0` |
| Action | GET, empty parameters, one request unit |
| Response ceiling | 4,096 bytes |
| Side effect | read-only |
| Redirects and credentials | no redirect follow; no ambient credentials |

This object is not a Campaign Profile. It contains no operating semantics, ROE, reporting
expectation, validation floor, or authority ceiling. The Web classification does not select the
Capability or Worker; the binding pins their exact independently registered identities.

## Preparation input

`prepare_web_read_only_discovery` requires:

- a canonical `WebHTTPOperationSurface` whose locator is an exact concrete `HTTPSurfaceLocator`;
- method `GET` and one canonical HTTP(S) URL;
- a `PentestReconCapabilityActivation` that revalidates a current signed experimental release for
  Range use;
- the exact release reference already bound to that activation; and
- bounded request and agent identifiers for the existing `ToolRequest` wire.

The helper does not accept Tool, Worker, Scope, approval, Permit, egress-policy, redirect, header,
credential, body, or arbitrary argument injection.

## Preparation output

`WebReadOnlyDiscoveryPreparation` contains the full content-addressed binding, detached typed
Surface, exact release, and existing `PreparedCapabilityAction`. Its state is
`prepared-not-authorized`. It explicitly records:

- Capability preparation completed through current CAP-002 authority;
- Gateway egress is still required;
- no Worker job or egress policy was materialized;
- no discovery Observation or Evidence was produced;
- no Graph admission or Scope expansion occurred; and
- approval, Permit issuance, Gateway dispatch, Worker selection, and execution remain false.

The existing executor may prepare a pre-Gateway `WorkerJob`, but that job has
`NetworkMode.NONE` and no egress policy. It is not the egress-enabled job used for dispatch.

## Required downstream authority path

```text
WEB-001A concrete GET Surface
-> WEB-001B exact binding
-> current signed Pentest Recon activation
-> PreparedCapabilityAction
-> current Campaign Scope / Graph Decision
-> Policy / Approval
-> one-use ActionPermit
-> Gateway policy re-entry and exact egress policy
-> deployment-bound direct-mTLS Web Worker
-> trusted receipt
```

WEB-001B stops at `PreparedCapabilityAction`. The remaining stages are existing independent
authorities and are not implied by the binding or preparation artifact.

## Fail-closed cases

Validation rejects:

- an unregistered binding ID, version, or digest;
- Capability, CAP-002 authority-set, DOMAIN-003 classification, Worker-profile, locator-registry,
  locator, method, side-effect, request-unit, or response-ceiling substitution;
- a URI-template Surface or non-GET concrete Surface;
- a non-canonical or authority-mutated WEB-001A Surface;
- a stale, forged, mismatched, or otherwise unusable signed release activation;
- Tool, Scope, Worker, or arbitrary request metadata injected into the binding;
- preparation request, Surface, release, action, ID, or digest drift; and
- authority-marker escalation or permissive boolean coercion.

## Explicit non-authority

Neither artifact grants Campaign Profile selection, Scope expansion, Capability activation,
approval, Permit issuance, Tool or Worker selection, network or filesystem access, credential use,
Graph admission, Finding confirmation, runtime support, or execution. The DOMAIN-004 Worker profile
is a minimum-requirement reference, not deployment conformance or an egress grant.

WEB-001C now exact-binds this preparation to an already approved sealed Pentest source and reuses
PENTEST-002A for neutral Observation/Evidence Graph admission. WEB-001D owns independent replay and
benchmark Ground Truth. WEB-001B itself still does not claim a Finding or validation path.

## Compatibility and rollback

The implementation is additive. It preserves all existing Campaign Profile, Capability, release,
ToolRequest, ActionPermit, Gateway, WorkerJob, Discovery, AttackSurface, Observation, Evidence, and
Graph wire identities. The specialized module is intentionally not imported from the eager
`pajin.capabilities` package facade, which keeps existing Discovery/Control Plane import order
unchanged. Consumers import `pajin.capabilities.web_discovery` explicitly.

Rollback removes the module, its WEB-001A Surface reference helper, tests, and this contract.
Existing stored artifacts require no migration.

## Verification

`tests/test_web_read_only_discovery.py` covers exact binding resolution, signed CAP-002
preparation, pre-Gateway network denial, URI-template and non-GET rejection, stale/substituted
release rejection, Surface and request identity, authority escalation, boolean coercion, metadata
injection, and digest drift. Existing WEB-001A, Pentest Recon, DOMAIN-003, DOMAIN-004, Gateway, and
Worker tests provide adjacent compatibility coverage.
