# ADR-0212: Type Web HTTP Surfaces without Discovery Authority

## Status

Accepted

## Context

DOMAIN-002 reserves `web.http-operation` and `pajin.locator.web.http-operation.v1` as semantic
identifiers, but intentionally does not implement a locator schema. PAJIN already has two strict,
compatible HTTP locator models: `HTTPSurfaceLocator` for a concrete operation and
`HTTPRouteSurfaceLocator` for a bounded URI-template route. DISC-002 uses those locators in its
evidence-bound discovery wire.

WEB-001A needs a typed Web Surface and an exact locator registry before a new discovery Capability
or Worker is introduced. Creating a second URL or OpenAPI locator wire would duplicate canonical
normalization and risk changing existing `SurfaceObservation` and `AttackSurface` readers.
Conversely, describing a locator implementation must not mean that a target was observed, Evidence
was sealed, a Graph node was admitted, or network execution was authorized.

## Decision

Add a content-addressed Web HTTP operation locator registry that binds the exact DOMAIN-001 Web
classification and DOMAIN-002 Web type-set to the unchanged discovery API and its two existing
locator implementations:

- `http-endpoint` / `HTTPSurfaceLocator` for one concrete method and URL; and
- `http-route` / `HTTPRouteSurfaceLocator` for one method and bounded URI template.

Add an inert `WebHTTPOperationSurface` value that embeds one of those registered locators and starts
as `registered-not-authorized`. Its identity is content-addressed over the exact Domain, type-set,
registry, locator, and false authority markers.

The registry asserts that this exact locator schema implementation is available, but it does not
change the DOMAIN-002 registry, discovery wire, or `AttackSurface` wire. The typed value explicitly
states that it is not an Observation, has no sealed Evidence, and is not Graph-admitted. Registry
and Surface records deny discovery, Scope expansion, Capability activation, approval, Permit, Tool
or Worker selection, network access, runtime-support, and execution authority.

## Consequences

- Future WEB-001B discovery code can target one exact typed locator schema without inventing a
  parallel Web model.
- Existing URL, method, route-template, path-parameter, and content-type canonicalization remains
  the source of truth.
- Constructing a typed Surface only records bounded knowledge. It cannot make a request or enter
  the Canonical Graph.
- WEB-001C must separately seal Observation/Evidence and use the existing Graph admission path.
- A generalized crawler, redirect policy, OpenAPI resolver, Capability, Worker, Replay, and Web
  benchmark remain outside WEB-001A.

## Rejected alternatives

### Add Domain fields to `AttackSurface`

Rejected because it would change an established evidence-bound wire and content identity before a
migration is needed.

### Create a new URI-template grammar

Rejected because `HTTPRouteSurfaceLocator` already supplies bounded whole-segment parameters and
canonical HTTP method, base URL, path, and media types.

### Treat locator registration as discovery or network authority

Rejected because schema availability describes representation, not permission to observe or act.

### Infer Web typing from a Tool or Capability name

Rejected because mutable metadata and naming conventions are not authority or semantic identity.

## Compatibility and rollback

WEB-001A is additive. Existing discovery, Graph, Capability, Tool, Worker, Permit, and artifact
readers are unchanged. Rollback removes the additive registry, typed wrapper, exports, and
consumers. Existing serialized discovery artifacts retain their exact wire and identity. Future
locator variants require a new versioned registry rather than silent membership changes.

## Related documents

- [WEB-001A contract](../discovery/WEB-001A-typed-http-api-surface-locator-registry.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [DISC-002](../discovery/DISC-002-http-openapi-surface-adapter.md)
- [ARCH-002](../rfc/0002-multi-domain-security-analysis-architecture.md)
- [ADR-0204](0204-separate-security-domain-from-profile-and-authority.md)
- [ADR-0205](0205-admit-cross-domain-knowledge-without-scope-expansion.md)
