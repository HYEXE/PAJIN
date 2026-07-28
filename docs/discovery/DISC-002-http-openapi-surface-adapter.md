# DISC-002: HTTP and OpenAPI Surface Adapter

- Status: locally implemented
- Date: 2026-07-28
- Prerequisites: DISC-001, existing trusted Surface admission, `HTTPGetTool`

## Purpose

Interpret one exact, integrity-verified `HTTPGetTool` result as a directly observed HTTP endpoint
and, when the response is a bounded inline OpenAPI document, as non-executable HTTP route
templates. The adapter adds discovery evidence; it does not schedule requests, dereference remote
schemas, or expand Campaign authority.

## Exact HTTP evidence

`HTTPAndOpenAPISurfaceAdapter` accepts only a successful GET result whose request/result/Tool
identities match exactly and whose request arguments are empty. It independently revalidates:

- the sealed Docker `workerResult`, host-trusted network-log flag, and exactly one matching
  `HTTPGetTool` proxy receipt before adapter extraction;
- the exact response target and 2xx status;
- canonical bounded base64 under the existing 4 KiB `HTTPGetTool` body limit;
- response-body SHA-256 and UTF-8 replacement preview; and
- a syntactically valid response Content-Type.

Every accepted response produces one `http-endpoint` locator for the exact fetched URL. JSON
parsing occurs only for `application/json` or a `+json` media type. Malformed claimed JSON fails
closed; other media types remain endpoint-only observations.

## OpenAPI subset

The first adapter version accepts inline OpenAPI 3.0.x and 3.1.x JSON with these limits:

- at most 8 root servers;
- at most 100 path entries;
- at most 200 emitted routes by default, configurable up to 499;
- at most 32 request or response content types; and
- strict JSON depth 32 and 4,096 nodes within the 4 KiB response ceiling.

Root servers must be same-origin with the fetched request and contain no query or variables.
Path-level and operation-level server overrides are rejected. External or local `$ref` values are
never resolved; referenced bodies and responses contribute no inferred content type. YAML is not
parsed.

The adapter emits only explicitly configured standard HTTP methods. GET is mandatory because the
source endpoint itself is a GET observation. Unsupported methods are not promoted into Surfaces.

## Non-executable route locator

`HTTPRouteSurfaceLocator` separates an OpenAPI route template from a concrete executable URL. It
binds:

- canonical same-origin base URL;
- absolute path template;
- HTTP method; and
- sorted, unique request and response content-type sets.

Path parameters must occupy a complete segment such as `{user_id}`, have unique names, and use a
bounded identifier grammar. Empty segments, dot segments, encoded slashes, non-canonical percent
encoding, queries, fragments, backslashes, and control characters are rejected.

For Scope evaluation only, each parameter is replaced with the fixed single-segment value
`pajin-route-parameter`. Trusted admission then applies the existing Campaign allow, explicit
deny, and allowed-method checks. Parameterized routes additionally require a wildcard allow rule
whose static prefix covers the template, and they are rejected when a broad or narrow explicit
deny may overlap any parameter value. An allow rule for the placeholder value alone is
insufficient. The rendered value is never an execution request.

## DISC-001 integration

The versioned definition declares both `http-endpoint` and `http-route` and requires a trusted
network execution receipt. Registry-backed admission rejects any extracted locator kind not
declared by the selected definition and replays the registered Tool's trusted-execution validator
against the sealed request, result, and Worker receipt. Stable adapter context binds:

- exact Tool version;
- allowed methods and route limit;
- response, server, and path limits;
- supported OpenAPI major/minor versions;
- same-origin-only server policy; and
- disabled `$ref` resolution and YAML parsing.

The exact adapter reference continues into trusted admission authority and projection audit.

## Verification

- endpoint-only HTML, opaque, and ordinary JSON responses;
- canonical OpenAPI route, method, path-parameter, and content-type extraction;
- deterministic output independent of input object order;
- target, body digest, base64, preview, unknown-field, and malformed-JSON rejection;
- unsupported version, cross-origin/variable server, server override, malformed template,
  missing response, duplicate JSON key, and route-overflow rejection;
- Registry definition and stable-context binding;
- missing/untrusted required Worker receipt and receipt/result mismatch rejection;
- undeclared Surface-kind rejection;
- end-to-end sealed admission and projection audit; and
- full wildcard-allow, possible narrow-deny overlap, and method-authority rejection for declared
  routes.

## Compatibility and remaining boundaries

- Existing `HTTPSurfaceLocator`, Tool-interface discovery, legacy producer construction, and
  current Planner behavior remain unchanged.
- `http-route` is additive and explicitly non-executable.
- No crawler, redirect following, HTML link extraction, OpenAPI YAML, `$ref` graph, callbacks,
  webhooks, GraphQL introspection, or cross-origin server discovery is implemented.
- DISC-003 owns Auth, File Upload, RAG, and MCP domain adapters. Its cumulative Auth and File
  Upload slices are implemented by separate exact-version adapters; RAG and MCP remain pending.
- ORCH-001/002 own request scheduling, Snapshot-to-Plan binding, and bounded multi-wave execution.

## Related documents

- [DISC-001: Versioned Discovery Adapter Registry](DISC-001-versioned-discovery-adapter-registry.md)
- [DISC-003: Auth, File Upload, RAG, and MCP Surface Adapters](DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [ADR-0060: Bounded HTTP and OpenAPI Route Discovery](../adr/0060-bounded-http-openapi-route-discovery.md)
- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
