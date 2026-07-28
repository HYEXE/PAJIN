# ADR-0060: Bounded HTTP and OpenAPI Route Discovery

- Status: Accepted
- Date: 2026-07-28

## Context

DISC-001 supplies exact versioned adapter authority but does not define how untrusted HTTP
responses become Surfaces. Treating every OpenAPI path as a concrete URL would lose path-template
semantics and could accidentally present `{parameter}` text as executable input. Trusting schema
servers, redirects, `$ref` targets, or response-declared methods without reapplying Campaign Scope
would also let target-controlled content attempt to expand authority.

The current `HTTPGetTool` already produces exact bounded response bytes with host-observed
execution validation. DISC-002 should reuse that evidence rather than introduce a second network
client or a schema-controlled fetch mechanism.

## Decision

1. `HTTPAndOpenAPISurfaceAdapter` interprets only the exact sealed result contract of
   `HTTPGetTool` version 1.0.0.
2. The exact adapter definition requires a trusted network execution receipt. Before extraction,
   admission requires the sealed Gateway `workerResult` and host-trusted network-log flag, then
   replays `HTTPGetTool.validate_trusted_execution()` against the exact request and result.
3. Every accepted successful response yields its exact GET URL as an `http-endpoint`.
4. Only strict inline JSON under the existing 4 KiB body limit is eligible for OpenAPI parsing.
   OpenAPI 3.0.x and 3.1.x are supported.
5. OpenAPI servers must be same-origin, query-free, and variable-free. Path-level and
   operation-level overrides fail closed.
6. The adapter performs no YAML parsing, redirect following, crawling, `$ref` resolution,
   callback/webhook expansion, or network access.
7. OpenAPI paths become additive `http-route` locators rather than executable URLs. A route binds
   canonical base, path template, method, and sorted request/response content types.
8. Path parameters occupy one complete segment and are unique. Canonical encoding, dot segments,
   encoded slashes, ambiguous delimiters, and resource limits fail closed.
9. The adapter emits only an explicit method allow-set bound into stable context. GET is required.
10. Trusted admission renders route parameters to fixed safe segments solely for Campaign
   allow/deny and method checks. A parameterized route requires a wildcard allow whose static
   prefix covers the template, and any possible overlap with a broad or narrow explicit deny fails
   closed. The rendered URL is never dispatched.
11. Registry-backed admission verifies that every emitted locator kind was declared by the exact
    adapter definition.

## Consequences

- OpenAPI output remains target-controlled evidence, not execution authority.
- A sealed success flag cannot substitute for the host-observed HTTP receipt at Discovery time.
- Route templates and content types are preserved without weakening the concrete endpoint model.
- Same-origin and no-dereference rules avoid schema-driven SSRF and unbounded document graphs.
- A 4 KiB document ceiling intentionally limits compatibility with large production schemas. A
  future larger schema Tool requires its own bounded evidence contract and adapter version.
- Parameterized routes can be admitted conservatively, but actual parameter materialization
  remains an ORCH/Capability responsibility.

## Compatibility and rollback

`http-route` and the HTTP/OpenAPI adapter are additive. Existing serialized `http-endpoint` and
`tool-interface` locators retain their wire shape and identity. Existing producer and Planner
paths are not auto-wired to the new adapter.

Rollback is to remove the explicit DISC-002 adapter reference from composition while preserving
already sealed Surface Sets and projection Runs. Previously admitted `http-route` artifacts remain
readable and must not be rewritten.

## Related documents

- [DISC-002: HTTP and OpenAPI Surface Adapter](../discovery/DISC-002-http-openapi-surface-adapter.md)
- [DISC-001: Versioned Discovery Adapter Registry](../discovery/DISC-001-versioned-discovery-adapter-registry.md)
- [ADR-0059: Versioned Discovery Adapter Authority](0059-versioned-discovery-adapter-authority.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
