# ADR-0061: Bounded OpenAPI Authentication Boundary Discovery

- Status: Accepted
- Date: 2026-07-29

## Context

DISC-002 preserves HTTP routes but intentionally does not describe their authentication
boundaries. Treating OpenAPI security declarations as executable authentication instructions
would let target-controlled documents choose identity-provider URLs, solicit credentials, or
weaken Campaign authority. Omitting the declarations entirely, however, loses useful evidence
about which operations share or differ in authentication requirements.

## Decision

1. Add a separate, explicitly selected `HTTPAndOpenAPIAuthenticationSurfaceAdapter`; do not
   change the exact DISC-002 adapter definition.
2. Compose DISC-002 parsing and emit authentication Surfaces only for routes already produced
   from the same sealed response.
3. Model each boundary as a non-executable route, referenced scheme identities, OpenAPI OR/AND
   requirements, declared scope names, and optional anonymous access.
4. Accept only bounded inline standard OpenAPI security schemes: `apiKey`, HTTP, OAuth2,
   OpenID Connect, and `mutualTLS` for OpenAPI 3.1.
5. Fail closed on unknown or `$ref` schemes, invalid shapes, duplicate alternatives, repeated
   anonymous alternatives, undeclared OAuth2 scopes, scopes on incompatible schemes, and
   unsupported mutual TLS versions.
6. Validate but never retain or fetch OAuth2 and OpenID Connect URLs. Never collect or retain
   authentication material.
7. Bind all limits and non-retention behavior into the adapter's stable execution context.
8. Require DISC-002's trusted network receipt and reapply the nested route's Campaign Scope and
   method checks during admission.

## Consequences

- Authentication topology becomes canonical, evidence-bound discovery data without becoming a
  credential or request-execution system.
- Operation overrides and optional-anonymous alternatives remain visible rather than being
  flattened into an inaccurate boolean.
- A new Surface kind and adapter reference are additive; consumers must explicitly understand or
  ignore them.
- OpenAPI extensions, remote security-scheme references, identity-provider metadata discovery,
  credential acquisition, and authentication testing remain unsupported.
- File Upload, RAG, and MCP adapters remain separate DISC-003 sub-slices.

## Compatibility and rollback

DISC-002 IDs, versions, outputs, and serialized locators are unchanged. Rollback consists of
removing the explicit DISC-003A adapter reference. Sealed `http-authentication` artifacts remain
immutable and readable.

## Related documents

- [DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [DISC-002: HTTP and OpenAPI Surface Adapter](../discovery/DISC-002-http-openapi-surface-adapter.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ADR-0060: Bounded HTTP and OpenAPI Route Discovery](0060-bounded-http-openapi-route-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
