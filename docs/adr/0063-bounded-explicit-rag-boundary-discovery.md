# ADR-0063: Bounded Explicit RAG Boundary Discovery

- Status: Accepted
- Date: 2026-07-29

## Context

DISC-003B identifies direct file-bearing HTTP inputs but cannot establish whether an operation
ingests content into a corpus, manages an index, or retrieves indexed content. OpenAPI has no
standard operation field for these RAG semantics. Inferring them from path names, descriptions,
request schemas, examples, or response text would let target-controlled prose create canonical
RAG topology and would make interpretation unstable across models and prompts.

The Discovery Registry permits only one selected interpreter per Tool. The RAG interpreter must
therefore preserve the existing HTTP, authentication, and file-upload results as one cumulative
exact-version definition.

## Decision

1. Add an explicitly selected `HTTPAndOpenAPIRAGSurfaceAdapter` that composes the exact DISC-003B
   file-upload interpretation.
2. Read RAG semantics only from an operation-level `x-pajin-rag` object with exact version `"1"`.
   Root-level and path-level extensions, path names, descriptions, schemas, examples, and ordinary
   request/response fields never imply a RAG Surface.
3. The extension contains only:
   - one `corpus-ingest`, `index-management`, or `retrieval` boundary;
   - a sorted, unique set of portable corpus identifiers; and
   - a sorted, unique set of portable index identifiers.
4. Corpus ingestion requires at least one corpus identifier. Index management and retrieval
   require at least one index identifier. Each identifier set is limited to 16 entries.
5. Add a non-executable `http-rag` locator that binds the exact admitted HTTP route and those
   declared identifiers. The adapter emits at most 32 RAG locators so the cumulative default
   HTTP/Auth/File/RAG result remains within the 500-Surface artifact limit.
6. Reject unsupported versions, unknown fields, `$ref`, malformed identifiers, noncanonical
   ordering, duplicates, missing required identifiers, explicit nulls, and declaration overflow.
7. Never retain or fetch corpus documents, ingestion payloads, retrieval queries, retrieved
   chunks, embeddings, vector values, credentials, or destination URLs.
8. Require the inherited host-trusted HTTP receipt and reapply the nested route's Campaign Scope
   and method checks before publication.

## Consequences

- The first File Upload to RAG chain can represent explicit corpus ingestion and retrieval
  topology without granting either operation execution authority.
- The RAG adapter is the sole selected interpreter for `HTTPGetTool` while emitting inherited
  endpoint, route, authentication, and file-upload Surfaces.
- Generic third-party OpenAPI documents without `x-pajin-rag` produce no RAG Surface, even when
  their names or descriptions strongly suggest RAG behavior.
- Runtime RAG probing, vector-store inspection, schema dereferencing, content-trust claims,
  Planner wiring, and MCP correlation remain outside this slice.

## Compatibility and rollback

DISC-002 and DISC-003A/B IDs, versions, outputs, and locator wire shapes remain unchanged. The new
adapter and `http-rag` locator are additive, and existing consumers may keep selecting an earlier
exact adapter.

Rollback removes the DISC-003C adapter reference and selects DISC-003B when file-upload discovery
is still desired. Already sealed RAG Surfaces remain immutable and readable.

## Related documents

- [DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ADR-0062: Bounded OpenAPI File Upload Boundary Discovery](0062-bounded-openapi-file-upload-boundary-discovery.md)
- [ADR-0060: Bounded HTTP and OpenAPI Route Discovery](0060-bounded-http-openapi-route-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
