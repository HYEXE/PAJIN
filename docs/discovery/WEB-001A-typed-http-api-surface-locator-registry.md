# WEB-001A: Typed HTTP/API Surface and Locator Registry

- Status: Implemented, typed registry only
- API versions:
  - `pajin.dev/web-http-operation-locator/v1alpha1`
  - `pajin.dev/web-http-operation-locator-registry/v1alpha1`
  - `pajin.dev/web-http-operation-surface/v1alpha1`
- Authority: `src/pajin/discovery/web_surfaces.py`
- Decision: [ADR-0212](../adr/0212-type-web-http-surfaces-without-discovery-authority.md)

## Purpose

WEB-001A implements the locator schema reserved by DOMAIN-002 for `web.http-operation`. It binds
the exact DOMAIN-001 Web classification and DOMAIN-002 Web type-set to two existing discovery
locators. It also provides an inert typed Surface value whose initial state is
`registered-not-authorized`.

This is not a discovery Capability. It does not send a request, observe a target, seal Evidence,
admit a Graph node, select a Tool or Worker, expand Scope, issue a Permit, or authorize execution.

## Registered locator implementations

| Registry identity | Existing locator | Semantics |
| --- | --- | --- |
| `pajin.locator.web.http-operation.concrete@1.0.0` | `HTTPSurfaceLocator` / `http-endpoint` | One canonical HTTP method and concrete URL |
| `pajin.locator.web.http-operation.uri-template@1.0.0` | `HTTPRouteSurfaceLocator` / `http-route` | One canonical method, base URL, bounded whole-segment URI template, and ordered media types |

The locator models and `pajin.dev/discovery/v1alpha1` wire remain unchanged. Existing
normalization rejects ambiguous route delimiters, repeated or partial-segment parameters,
non-canonical URL forms, invalid methods, and invalid media types.

## Typed Surface identity

`WebHTTPOperationSurface` contains:

- the exact Web classification reference;
- the exact `web.http-operation` DOMAIN-002 type-set reference;
- the complete locator-registry reference;
- one discriminated existing `http-endpoint` or `http-route` locator; and
- a content-addressed Surface ID and digest.

The value is a pre-Observation knowledge record, not the existing evidence-bound `AttackSurface`.
It contains no Campaign, target authority, request, Observation, Evidence, Scope, Capability, Tool,
Worker, approval, or Permit field. `typedSurfaceOnly` is true while `discoveryObserved`,
`evidenceSealed`, and `graphAdmitted` are false.

## Identity and fail-closed resolution

Locator definitions and the complete registry are content-addressed. Resolution accepts only an
exact ID, version, digest, and locator kind. The registry also pins the current Security Domain
taxonomy digest, multi-domain Graph semantics digest, discovery API version, Surface type, locator
schema, exact model identity, membership, and order.

Domain relabeling, type-set or registry substitution, locator-model replacement, order drift,
digest mutation, extra Tool or Capability metadata, authority escalation, and non-boolean marker
coercion fail closed.

## Non-authority guarantees

The registry does not change DOMAIN-002's historical semantics-only object or the discovery and
`AttackSurface` wires. It grants none of the following:

- discovery or Graph admission;
- Scope expansion or Capability activation;
- approval satisfaction or Permit issuance;
- Tool or Worker selection;
- network access, runtime support, or execution; or
- Evidence, Replay, validation-floor, or Finding authority.

WEB-001B must introduce an exact read-only discovery Capability and conforming egress-only Worker
through the existing CAP-002, Policy/Approval, ActionPermit, Gateway, and deployment-bound Worker
path. WEB-001C must separately seal Observation/Evidence before Graph admission.

## Compatibility and rollback

The implementation is additive. `HTTPSurfaceLocator`, `HTTPRouteSurfaceLocator`, `SurfaceLocator`,
`SurfaceObservation`, and `AttackSurface` remain unchanged. Removing the new module, exports, and
consumers restores the earlier state without migrating existing artifacts.

## Verification

`tests/test_web_http_operation_surfaces.py` covers exact Domain/type-set/model membership,
content-addressed reference resolution, concrete and URI-template Surface construction, existing
canonical validation reuse, discovery-wire compatibility, registered-not-authorized state,
identity and order substitution, extra metadata, authority escalation, and boolean coercion.
