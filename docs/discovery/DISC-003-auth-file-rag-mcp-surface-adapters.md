# DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters

- Status: in progress (`DISC-003A` implemented)
- Date: 2026-07-29
- Prerequisites: DISC-001, DISC-002, trusted Surface admission

## Purpose

Extend versioned Discovery across the authentication, file-upload, RAG, and MCP trust
boundaries without allowing target-controlled descriptions to become execution authority. Each
sub-slice must introduce its own bounded locator, exact adapter identity, negative authority
tests, compatibility boundary, and rollback path.

## DISC-003A: OpenAPI authentication boundary

`HTTPAndOpenAPIAuthenticationSurfaceAdapter` composes the DISC-002 HTTP/OpenAPI adapter and adds
non-executable `http-authentication` locators for explicitly secured operations. It preserves:

- the exact admitted `HTTPRouteSurfaceLocator`;
- sorted identities of referenced `apiKey`, HTTP, OAuth2, OpenID Connect, and OpenAPI 3.1
  mutual-TLS schemes;
- OpenAPI's OR alternatives and the AND-set of schemes inside each alternative;
- sorted OAuth/OpenID scope names; and
- an explicit optional-anonymous alternative.

Operation-level `security` overrides root security. An empty security array disables inherited
authentication and emits no authentication Surface. Referenced schemes must exist inline under
`components.securitySchemes`; `$ref` authentication schemes fail closed.

## Bounded and non-secret interpretation

The adapter applies fixed limits to schemes, requirements, requirement members, and scopes. It
validates the structural URLs required by OAuth2 and OpenID Connect but never retains or fetches
them. It also does not retain API keys, tokens, credentials, bearer formats, OAuth descriptions,
or other authentication material.

OAuth2 requirement scopes must be declared by the referenced flow. Scopes on non-OAuth/OpenID
schemes, duplicate alternatives, repeated anonymous alternatives, unknown schemes, malformed
scheme shapes, and `mutualTLS` in OpenAPI 3.0 fail closed.

## Authority and admission

The adapter remains bound to the exact DISC-001 ID, version, implementation digest, stable
context, and `HTTPGetTool` contract. It requires the same sealed Worker result and host-trusted
HTTP proxy receipt as DISC-002. Every authentication locator nests a previously parsed route, so
trusted admission reuses the existing Campaign method, allow, deny, wildcard-template, and
possible-deny-overlap checks before publication.

The locator is descriptive only. It cannot acquire credentials, call an identity provider,
materialize route parameters, schedule a request, or relax Scope.

## Verification

- root inheritance, operation override, and empty-array disable behavior;
- OR/AND alternatives, optional anonymous access, and canonical ordering;
- API key, HTTP, OAuth2, OpenID Connect, and OpenAPI 3.1 mutual-TLS identities;
- no authentication URL or authentication material retention;
- unknown, referenced, malformed, duplicate, undeclared-scope, and incompatible-version
  rejection;
- exact locator consistency and defensive factory copies;
- Registry definition and stable-context binding; and
- sealed admission, reused route authority, and projection audit integration.

## Remaining sub-slices

- `DISC-003B`: bounded file-upload boundary discovery;
- `DISC-003C`: bounded RAG corpus/index/retrieval boundary discovery; and
- `DISC-003D`: bounded MCP server/resource/prompt/tool boundary discovery.

None of these remaining adapters is implied by the authentication locator. Planner and
multi-wave orchestration wiring also remains outside DISC-003.

## Compatibility and rollback

The existing DISC-002 adapter and its exact reference remain unchanged. The authentication
adapter is a separate additive exact-version definition and must be selected explicitly. Existing
`http-endpoint`, `http-route`, and `tool-interface` artifacts keep their wire shape and identity.

Rollback removes the DISC-003A adapter reference from composition. Already sealed authentication
Surfaces remain readable and must not be rewritten.

## Related documents

- [DISC-002: HTTP and OpenAPI Surface Adapter](DISC-002-http-openapi-surface-adapter.md)
- [DISC-001: Versioned Discovery Adapter Registry](DISC-001-versioned-discovery-adapter-registry.md)
- [ADR-0061: Bounded OpenAPI Authentication Boundary Discovery](../adr/0061-bounded-openapi-authentication-boundary-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
