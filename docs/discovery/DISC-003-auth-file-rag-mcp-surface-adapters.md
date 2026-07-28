# DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters

- Status: implemented (`DISC-003A` through `DISC-003D`)
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

## DISC-003C: Explicit RAG boundary

`HTTPAndOpenAPIRAGSurfaceAdapter` is the next cumulative exact-version interpreter. It preserves
the HTTP, authentication, and file-upload Surfaces, then reads only an operation-level
`x-pajin-rag` object with exact version `"1"`.

The non-executable `http-rag` locator binds the admitted route and one declared
`corpus-ingest`, `index-management`, or `retrieval` boundary. It retains only sorted, unique,
portable corpus and index identifiers. Corpus ingestion requires a corpus identifier; index
management and retrieval require an index identifier.

Path names, summaries, descriptions, schemas, examples, root/path vendor extensions, and ordinary
request or response fields never imply a RAG boundary. Unsupported versions, unknown fields,
`$ref`, null or malformed declarations, noncanonical identifiers, missing required identifiers,
and declaration overflow fail closed. The adapter never retains or fetches corpus documents,
queries, retrieved chunks, embeddings, vector values, credentials, or destination URLs.

## DISC-003D: Registered MCP boundary

`RegisteredMCPDiscoveryTool` is separate from normal registered MCP invocation. It sends only a
sealed server ID to the fixed `mcp-discover` Worker action; neither an agent nor the host adapter
can provide an executable, process argument, cursor, resource URI, prompt value, or discovered
tool name.

The isolated bridge initializes the cataloged server and enumerates only its advertised tools,
resources, resource templates, and prompts. Enumeration is limited to eight pages and 64 entries
per category, with at most 32 arguments per prompt. Duplicate entries, repeated cursors, malformed
identifiers, noncanonical ordering, capability contradictions, and overflow fail closed.

The host-visible result and five new non-executable locators preserve only:

- server ID, negotiated protocol version, and sorted capabilities;
- tool names and canonical input/output schema digests;
- resource and resource-template URI schemes plus full-value SHA-256 digests; and
- prompt names plus sorted argument names and required flags.

Resource reads, template resolution, prompt retrieval, discovered tool calls, descriptions,
annotations, server instructions, raw schemas, raw URIs/templates, resource contents, prompt
contents, and prompt values are not retained or performed.

`MCPBoundarySurfaceAdapter` binds that exact digest-only result to the registered server and emits
at most 257 Surfaces. `RegisteredMCPBoundaryReconPlanner` supplies the argument-free request to the
existing single-call sealed Recon/admission/projection pipeline.

## Authority and admission

The adapter remains bound to the exact DISC-001 ID, version, implementation digest, stable
context, and `HTTPGetTool` contract. It requires the same sealed Worker result and host-trusted
HTTP proxy receipt as DISC-002. Every authentication, file-upload, and RAG locator nests a
previously parsed route, so trusted admission reuses the existing Campaign method, allow, deny,
wildcard-template, and possible-deny-overlap checks before publication.

All domain locators are descriptive only. They cannot acquire credentials, call an identity
provider, materialize route parameters, read or upload a file, access a corpus or index, schedule
a request, execute an MCP interface, or relax Scope. The MCP boundary uses a separate Tool and
does not alter the cumulative HTTP/OpenAPI adapter chain.

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
- explicit corpus-ingest, index-management, and retrieval topology with canonical identifiers;
- no inference from names, descriptions, schemas, examples, or root/path extensions;
- unknown, referenced, malformed, noncanonical, contradictory, and overflow declaration
  rejection;
- no corpus content, query, retrieved content, embedding, vector, or destination retention; and
- cumulative HTTP/Auth/File/RAG Registry definition plus sealed admission/projection integration.
- sealed server-only Worker input and no process-command exposure;
- bounded/paginated server, resource, resource-template, prompt, and tool enumeration;
- digest-only resource/template/schema identities and no content, description, URI, schema, or
  prompt-value retention;
- malformed, duplicate, unsorted, contradictory, overflow, and forged-identity rejection; and
- exact Registry binding plus sealed single-Recon-wave admission/projection integration.

## Remaining orchestration boundary

DISC-003 is complete. ORCH-001/002 own multi-adapter scheduling, Snapshot-to-Plan binding, and
bounded multi-wave orchestration.

## Compatibility and rollback

The existing DISC-002 and DISC-003A/B/C adapters and their exact references remain unchanged. The
RAG adapter remains a separate cumulative exact-version definition. MCP boundary discovery uses a
separate registered Tool and exact adapter definition that must be selected explicitly.
Existing `http-endpoint`, `http-route`, `http-authentication`, `http-file-upload`, and
`tool-interface` artifacts keep their wire shape and identity.

Rollback removes the MCP boundary adapter reference and discovery Tool registration without
changing registered MCP invocation or the HTTP/OpenAPI chain. Already sealed authentication,
file-upload, RAG, and MCP Surfaces remain readable and must not be rewritten.

## Related documents

- [DISC-002: HTTP and OpenAPI Surface Adapter](DISC-002-http-openapi-surface-adapter.md)
- [DISC-001: Versioned Discovery Adapter Registry](DISC-001-versioned-discovery-adapter-registry.md)
- [ADR-0061: Bounded OpenAPI Authentication Boundary Discovery](../adr/0061-bounded-openapi-authentication-boundary-discovery.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](../adr/0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ADR-0063: Bounded Explicit RAG Boundary Discovery](../adr/0063-bounded-explicit-rag-boundary-discovery.md)
- [ADR-0064: Bounded Registered MCP Boundary Discovery](../adr/0064-bounded-registered-mcp-boundary-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
