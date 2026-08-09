# ADR-0144: Bind URL Tool Chains to Explicit Surface Authority

- Status: Accepted
- Date: 2026-08-10

## Context

CHAIN-003 needs to represent Prompt Injection -> URL Tool Control -> Internal API across legacy
Campaign modes. Before this change, PAJIN had an MCP prompt locator and generic HTTP/OpenAPI route
discovery, but it had no typed authority for a URL-bearing Tool argument or for an operation that a
Target explicitly declares to be an Internal API.

Inferring those meanings from Tool names, descriptions, arbitrary schema text, URLs, private IP
ranges, or route names would turn untrusted annotations into authority. Treating an advertised URL
argument as proof that a Tool can reach an Internal API would further confuse discovery with
execution and validation.

## Decision

1. Add `MCPURLToolSurfaceLocator` only for top-level JSON Schema properties whose exact type is
   `string` and format is `uri`. Retain only the argument name and required flag; do not retain a
   runtime URL, description, or raw schema.
2. Add `HTTPInternalAPISurfaceLocator` only when an OpenAPI operation declares the exact boolean
   extension `x-pajin-internal-api: true`. String coercion and route-name inference are forbidden.
3. Add a dedicated `HTTPInternalAPIReconPlanner` that requires the trusted HTTP/OpenAPI adapter to
   publish `http-internal-api`, so a missing declaration fails the Recon wave closed.
4. Register CHAIN-003 as three ordered stages and two `enables` edges. The prompt and URL Tool must
   come from the same MCP server and Campaign target. The explicit Internal API may be a different
   target, but both targets must belong exactly once to the same Campaign.
5. Reopen and verify both sealed Recon source and projection Runs through their existing
   `SurfaceSnapshotAuthority`. Do not mint another Surface store or accept the in-memory outcome as
   authority.
6. Fix the chain to `hypothesized-not-validated`, `surfaceEvidenceOnly=true`, and
   `crossTargetBinding=same-campaign-hypothesis-only`. Capability, execution, Claim Replay, and
   Finding confirmation remain false.
7. Rebuild and exact-match the complete CHAIN-003 authority against both sealed predecessors on
   every verification.

## Consequences

- URL Tool and Internal API semantics are additive, bounded, typed discovery facts rather than
  string-derived labels.
- A discovered MCP prompt, URL argument, and Internal API can be recorded as one coverage
  hypothesis without claiming prompt influence, network reachability, SSRF, API access, or impact.
- Missing, malformed, stale, cross-Campaign, cross-Snapshot, generic-locator, and authority-marker
  substitutions fail closed.
- The same topology applies to every legacy Campaign mode while retaining the exact Campaign
  digest and both Snapshot identities.
- The advertised `inspect_url` demo Tool remains outside the invocation allowlist; discovery does
  not silently create an executable Tool registration.

## Rejected alternatives

### Infer URL control from Tool names or descriptions

Rejected because names and descriptions are untrusted annotations and do not prove a URL-bearing
input boundary.

### Classify private-looking routes or addresses as Internal APIs

Rejected because URL syntax, DNS resolution, address ranges, and route names are environment
observations, not Target-declared semantic authority.

### Treat the chain as proof of reachability

Rejected because discovery did not invoke the URL Tool, perform a network request to the Internal
API, establish prompt-to-argument influence, or run an independent negative control.

### Add execution authority to the chain compiler

Rejected because Capability, Permit, dispatch, Replay, and Finding authority have existing owners.
CHAIN-003 is a coverage contract and must not duplicate them.

## Compatibility and rollback

The change is additive. Existing MCP discovery, HTTP/OpenAPI discovery, CHAIN-001/002, Campaign,
Capability, Replay, and Finding wires keep their current meanings. Rollback removes the specialized
locators, dedicated planner, CHAIN-003 contract/compiler/verifier, and public exports. It does not
rewrite sealed predecessor Runs or enable generic-locator inference.

## Related documents

- [CHAIN-003 contract](../orchestration/CHAIN-003-prompt-url-tool-internal-api.md)
- [CHAIN-002 contract](../orchestration/CHAIN-002-file-upload-rag-tool-abuse.md)
- [CHAIN-001 contract](../orchestration/CHAIN-001-mode-neutral-auth-bypass-ai-admin.md)
- [ADR-0143](0143-bind-walking-lineage-to-mode-neutral-chain.md)
- [ADR-0142](0142-bind-mode-neutral-chain-to-surface-snapshot.md)
