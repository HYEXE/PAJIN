# ADR-0062: Bounded OpenAPI File Upload Boundary Discovery

- Status: Accepted
- Date: 2026-07-29

## Context

DISC-003A describes route authentication but does not distinguish ordinary request bodies from
file-bearing inputs. Treating OpenAPI upload schemas as executable requests would let
target-controlled documents introduce file bytes, filenames, destinations, content paths, or
network behavior. Ignoring direct binary and multipart declarations loses the first Surface in
the planned File Upload to RAG to MCP walking skeleton.

The Discovery Registry permits only one selected interpreter per Tool. A file-upload interpreter
therefore cannot be selected beside the HTTP and authentication interpreters for the same
`HTTPGetTool`; it must preserve their behavior as one cumulative exact-version definition.

## Decision

1. Add an explicitly selected `HTTPAndOpenAPIFileUploadSurfaceAdapter` that composes the exact
   DISC-003A authentication interpretation, which already composes DISC-002 HTTP routes.
2. Add a non-executable `http-file-upload` locator that binds an admitted HTTP route, the
   request-body required flag, and sorted file-bearing inputs.
3. Each input preserves only the outer request content type, optional multipart field name,
   field requirement, multiplicity, binary/base64 encoding, and explicitly declared part media
   types.
4. Recognize only direct inline OpenAPI 3.0/3.1 schemas:
   - raw string bodies with `format: binary` or `format: byte`;
   - multipart object properties with those formats;
   - multipart arrays whose direct items use those formats; and
   - OpenAPI 3.1 strings with `contentEncoding: base64`.
5. Do not resolve request-body, multipart-object, property, or item `$ref` values. A referenced
   declaration emits no upload Surface.
6. Apply fixed limits to total upload declarations, multipart properties, multipart encodings,
   and declared part media types. Reject malformed required sets, unknown encoding fields,
   duplicate media declarations, raw file arrays, contradictory encodings, wildcards for the
   outer upload body, and OpenAPI 3.1 encoding fields in 3.0 documents.
7. Never retain, synthesize, or transmit file bytes, filenames, filesystem paths, destinations,
   upload URLs, or form values.
8. Require the inherited trusted network receipt and reapply the nested route's Campaign Scope
   and method checks before publication.

## Consequences

- Direct raw and multipart upload topology becomes canonical evidence without creating an upload
  capability.
- The file-upload adapter emits inherited endpoint, route, and authentication Surfaces, so it can
  be the sole selected interpreter for `HTTPGetTool`.
- Referenced and composed schemas intentionally produce no upload Surface. Supporting them would
  require a separately bounded local schema-graph contract and new adapter version.
- Nested object files, `oneOf`/`allOf`, multipart nesting, generated filenames, actual upload
  execution, RAG ingestion, and MCP behavior remain unsupported.
- RAG and MCP remain separate DISC-003 sub-slices.

## Compatibility and rollback

DISC-002 and DISC-003A IDs, versions, outputs, and locator wire shapes remain unchanged. The new
adapter and `http-file-upload` locator are additive. Existing consumers may continue selecting
the earlier exact adapter.

Rollback removes the DISC-003B adapter reference and selects DISC-003A when authentication
discovery is still desired. Already sealed upload Surfaces remain immutable and readable.

## Related documents

- [DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ADR-0061: Bounded OpenAPI Authentication Boundary Discovery](0061-bounded-openapi-authentication-boundary-discovery.md)
- [ADR-0060: Bounded HTTP and OpenAPI Route Discovery](0060-bounded-http-openapi-route-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
