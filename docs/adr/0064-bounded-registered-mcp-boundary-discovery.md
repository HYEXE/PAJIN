# ADR-0064: Bounded Registered MCP Boundary Discovery

- Status: Accepted
- Date: 2026-07-29

## Context

The existing registered MCP execution Tool invokes one fixed server/tool pair, but its call result
cannot authoritatively enumerate a server's resources, resource templates, prompts, and tools.
Reusing a normal call result would also mix interface discovery with target-controlled content.
Allowing a host or agent to provide a server executable, arguments, resource URI, prompt value, or
pagination cursor would turn Discovery into process or data-access authority.

The Discovery Registry also permits only one selected interpreter per Tool. MCP boundary discovery
therefore needs a separate Tool contract rather than a second interpretation of the existing call
Tool.

## Decision

1. Add a separate T0 `RegisteredMCPDiscoveryTool`. Its Worker job uses the fixed
   `mcp-discover` action and contains only a code-registered server ID. Agent-selected arguments,
   executable paths, process arguments, cursors, resource URIs, prompt values, and tool names are
   forbidden.
2. Keep server commands and arguments exclusively in the Worker catalog. The bridge initializes
   the registered stdio server through the pinned MCP SDK and enumerates only capabilities
   advertised by the negotiated session.
3. Bound each tools, resources, resource-templates, and prompts list to 64 entries, pagination to
   eight pages per category, and prompt arguments to 32. Repeated cursors, overflow, malformed
   identifiers, duplicate entries, and noncanonical output fail closed.
4. Return only:
   - registered server ID, negotiated protocol version, and sorted capability names;
   - tool name plus canonical input-schema digest and optional output-schema digest;
   - resource URI scheme plus SHA-256 of the complete URI;
   - resource-template URI scheme plus SHA-256 of the complete URI template; and
   - prompt name plus sorted argument names and required flags.
5. Never read resources, resolve templates, get prompts, call discovered tools, or retain server
   instructions, annotations, descriptions, raw schemas, raw URIs/templates, resource contents,
   prompt contents, or prompt values.
6. Add non-executable `mcp-server`, `mcp-resource`, `mcp-resource-template`, `mcp-prompt`, and
   `mcp-tool` locators. `MCPBoundarySurfaceAdapter` revalidates the exact digest-only envelope and
   sealed server/request identity before emitting at most 257 Surfaces.
7. Add an argument-free `RegisteredMCPBoundaryReconPlanner` that uses the existing single-call,
   sealed-source, trusted-admission, and immutable-projection flow. Multi-adapter scheduling and
   Snapshot-to-Plan orchestration remain ORCH-001/002 work.

## Consequences

- PAJIN can represent an MCP server's advertised boundary without granting access to its content
  or making discovered interfaces executable.
- The host evidence contains only normalized boundary metadata and digests. Raw resource and
  schema values exist transiently inside the isolated Worker bridge only.
- Existing registered MCP invocation behavior and its `tool-interface` locator remain unchanged.
- Discovery output is intentionally lossy: a digest identifies an interface value for comparison
  and lineage but cannot reconstruct it.

## Compatibility and rollback

The new discovery Tool, Planner, adapter, and five locator kinds are additive. Existing MCP call
Tools and sealed artifacts keep their wire shape and identity. Consumers must select the new exact
adapter reference explicitly.

Rollback removes the MCP boundary adapter reference and discovery Tool registration while leaving
registered MCP invocation available. Already sealed MCP boundary Surfaces remain immutable and
readable.

## Related documents

- [DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ADR-0003: Egress Proxy and Registered MCP Execution Boundary](0003-egress-proxy-and-mcp-boundary.md)
- [ADR-0059: Versioned Discovery Adapter Authority](0059-versioned-discovery-adapter-authority.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
