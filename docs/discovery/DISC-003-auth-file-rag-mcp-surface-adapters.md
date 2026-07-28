# DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters

- Status: in progress (`DISC-003A` and `DISC-003B` implemented)
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

## DISC-003B: OpenAPI file-upload boundary

`HTTPAndOpenAPIFileUploadSurfaceAdapter` is the cumulative exact-version interpreter for the same
`HTTPGetTool`: it preserves DISC-002 HTTP routes and DISC-003A authentication Surfaces, then adds
non-executable `http-file-upload` locators for direct file-bearing request schemas.

Each locator binds the exact admitted route, request-body requirement, and sorted inputs. An input
records only:

- the outer request content type;
- an optional multipart field name;
- required and multiple flags;
- binary or base64 representation; and
- explicitly declared part content types.

The bounded subset recognizes raw `format: binary`/`byte` string bodies, multipart object
properties, direct arrays of those properties, and OpenAPI 3.1 `contentEncoding: base64`.
Referenced request bodies and schemas are not resolved and emit no upload Surface. Nested schema
composition, nested object files, and raw arrays are unsupported.

Malformed required sets, unknown multipart encoding fields, duplicate media declarations,
contradictory encodings, wildcard outer upload types, and OpenAPI 3.1 encoding fields in 3.0
documents fail closed. The adapter never retains or produces file bytes, filenames, form values,
filesystem paths, destinations, or upload URLs.

## Authority and admission

The adapter remains bound to the exact DISC-001 ID, version, implementation digest, stable
context, and `HTTPGetTool` contract. It requires the same sealed Worker result and host-trusted
HTTP proxy receipt as DISC-002. Every authentication locator nests a previously parsed route, so
trusted admission reuses the existing Campaign method, allow, deny, wildcard-template, and
possible-deny-overlap checks before publication.

Both locators are descriptive only. They cannot acquire credentials, call an identity provider,
materialize route parameters, read or upload a file, schedule a request, or relax Scope.

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
- raw binary, multipart binary/base64, array multiplicity, required fields, declared media types,
  and canonical ordering;
- referenced-schema non-resolution and no file byte/destination retention;
- malformed required/encoding/media declarations, contradictory versions, raw arrays, and
  declaration-overflow rejection; and
- cumulative HTTP/Auth/File Registry definition plus sealed admission/projection integration.

## Remaining sub-slices

- `DISC-003C`: bounded RAG corpus/index/retrieval boundary discovery; and
- `DISC-003D`: bounded MCP server/resource/prompt/tool boundary discovery.

Neither remaining adapter is implied by the file-upload locator. Planner and
multi-wave orchestration wiring also remains outside DISC-003.

## Compatibility and rollback

The existing DISC-002 and DISC-003A adapters and their exact references remain unchanged. The
file-upload adapter is a separate cumulative exact-version definition and must be selected
explicitly. Existing `http-endpoint`, `http-route`, `http-authentication`, and `tool-interface`
artifacts keep their wire shape and identity.

Rollback removes the DISC-003B adapter reference and may select DISC-003A to retain authentication
discovery. Already sealed authentication and file-upload Surfaces remain readable and must not be
rewritten.

## Related documents

- [DISC-002: HTTP and OpenAPI Surface Adapter](DISC-002-http-openapi-surface-adapter.md)
- [DISC-001: Versioned Discovery Adapter Registry](DISC-001-versioned-discovery-adapter-registry.md)
- [ADR-0061: Bounded OpenAPI Authentication Boundary Discovery](../adr/0061-bounded-openapi-authentication-boundary-discovery.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](../adr/0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
