# DISC-001: Versioned Discovery Adapter Registry

- Status: locally implemented
- Date: 2026-07-28
- Prerequisites: ARCH-001, existing trusted Surface admission

## Purpose

Give every code-owned discovery result interpreter an immutable, exact-version authority record.
The Registry prevents a caller, model, or serialized proposal from selecting an unregistered
interpreter, silently moving to a newer version, or changing interpretation settings after
registration.

DISC-001 defines the common adapter boundary only. HTTP/OpenAPI Surface extraction,
Auth/File Upload/RAG/MCP adapters, orchestration waves, and Planner integration remain separate
slices.

## Common protocol

A `DiscoveryAdapter` declares:

- stable adapter ID and version;
- producer ID and one registered Tool ID;
- a sorted, unique set of supported `http-endpoint`, `http-route`, or `tool-interface` Surface
  kinds;
- whether successful extraction requires replay of a host-trusted network execution receipt;
- an explicit non-secret `stable_execution_context()`; and
- `extract_surfaces(request, result)`, which returns non-authoritative `SurfaceCandidate` values.

An adapter cannot grant execution authority. Candidates still pass the existing sealed-evidence,
Scope, Authorization, method, Tool-risk, chronology, and canonical Surface admission gates.

## Immutable definition and exact Tool binding

`DiscoveryAdapterDefinition` binds the adapter identity, producer, implementation type, supported
Surface kinds, trusted-network-receipt requirement, stable-context digest, and exact Tool
ID/version/full-ToolSpec digest. Bounded canonical JSON and a domain-separated SHA-256 digest form
the adapter identity.

`DiscoveryAdapterReference` always contains ID, version, and digest. There is no `latest` lookup,
compatible-version fallback, filesystem scan, entry-point discovery, or runtime import.

Stable contexts are strict JSON objects bounded to 64 KiB, depth 16, and 1,024 nodes. Secret-like
keys such as tokens, credentials, passwords, cookies, authorization values, API keys, and private
keys are rejected rather than persisted into adapter authority.

## Registry and drift behavior

`DiscoveryAdapterRegistry` is constructed explicitly from a `ToolRegistry` and code-provided
adapter objects. It:

- rejects duplicate adapter ID/version registrations;
- rejects missing or drifted Tools;
- resolves only exact references;
- re-snapshots live adapter identity, implementation context, and ToolSpec on every resolution;
- rejects duplicate selections and multiple selected interpreters for one Tool; and
- requires the Trusted Surface Producer to share the same `ToolRegistry` authority root.

Definitions returned to callers are detached canonical copies. Runtime adapter objects remain
process-local and cannot be reconstructed from serialized definitions.

## Trusted admission integration

`TrustedSurfaceProducer.from_adapter_registry()` selects an explicit set of adapter references.
Before each admission it resolves the exact reference again, detects drift, then uses the existing
trusted extraction and admission path.

When the selected definition requires a trusted network receipt, admission also requires the
sealed Gateway `workerResult` and a true host trust flag, then replays the registered Tool's
`validate_trusted_execution()` contract against the exact request and result before extraction.
The HTTP/OpenAPI adapter opts into this gate; the MCP interface adapter does not claim a network
receipt requirement.

The adapter reference is included in the process-local admission authority digest and the
`discovery.attack-surface-set.published` audit event. The current MCP interface adapter implements
the common protocol and binds its registered MCP server/tool identity, Tool version, and input
schema digest as stable context.

The earlier `TrustedSurfaceProducer(tools=..., adapters=...)` constructor remains available for
compatibility. It does not fabricate a versioned reference, and its existing projection event
shape remains unchanged.

## Verification

- exact ID/version/digest resolution and no-latest behavior;
- immutable definition and unknown Surface-kind rejection;
- duplicate registration, duplicate selection, and multiple-interpreters-per-Tool rejection;
- unknown Tool, live ToolSpec drift, and live adapter-context drift rejection;
- missing, untrusted, or mismatched required network execution receipt rejection;
- secret-like stable-context key rejection;
- existing admission and projection regression coverage; and
- an end-to-end MCP Recon wave whose projection audit binds the exact adapter reference.

## Remaining boundaries

- DISC-002 implements bounded HTTP route/method/content-type and OpenAPI Surface discovery.
- DISC-003 owns Auth, File Upload, RAG, and MCP domain adapters.
- ORCH-001/002 own multi-adapter scheduling, multi-wave execution, and Planner integration.
- Signed adapter releases, durable Registry storage, dynamic plugin loading, and remote Registry
  refresh are not implemented.

## Related documents

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0059: Versioned Discovery Adapter Authority](../adr/0059-versioned-discovery-adapter-authority.md)
- [ADR-0051: Versioned Capability Definition and Exact Tool Binding](../adr/0051-versioned-capability-definition-and-tool-binding.md)
