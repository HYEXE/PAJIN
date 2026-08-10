# ADR-0145: Bind Tenant Data Chains to Explicit Retrieval Authority

- Status: Accepted
- Date: 2026-08-10

## Context

CHAIN-004 needs to represent Cross-tenant Retrieval -> Data Exposure across every legacy Campaign
mode. PAJIN already had an explicit RAG retrieval Surface, but it had no typed authority saying
that a retrieval operation accepts a tenant selector or that its response is declared to contain
a bounded class of data.

Inferring those meanings from tenant-like path segments, parameter names, descriptions, response
schemas, examples, or synthetic Findings would let target-controlled text manufacture attack-chain
authority. A declaration that a route is tenant-selectable or data-bearing also does not prove that
another tenant can be selected, that retrieval succeeds, or that any data is exposed.

## Decision

1. Add `HTTPTenantRetrievalSurfaceLocator` only for an operation that has both an exact
   `x-pajin-rag` retrieval declaration and an exact version-1 `x-pajin-tenant-retrieval`
   declaration. Retain only selector location and name; never retain a tenant value or query.
2. Add `HTTPDataResponseSurfaceLocator` only for an operation with an exact version-1
   `x-pajin-data-response` declaration, a non-empty declared response content type, and sorted
   code-owned data classes. Never retain response examples or content.
3. Treat header, query, and body selector names as explicit Target metadata. A path selector must
   additionally match an exact placeholder on the bound route. Do not infer declarations from
   ordinary OpenAPI parameters or schemas.
4. Add a separate cumulative exact-version adapter and dedicated Recon planner. Do not change the
   existing DISC-003C RAG adapter ID, digest, stable context, or wire interpretation.
5. Register CHAIN-004 as two ordered stages joined by one `enables` edge. Both exact Surfaces must
   belong to the same Campaign target and the same exact HTTP route.
6. Reopen and verify the existing sealed Recon source and projection Runs through their
   `SurfaceSnapshotAuthority`; do not mint another Surface store or trust the in-memory outcome.
7. Fix the chain to `hypothesized-not-validated` and `surfaceEvidenceOnly=true`. Cross-tenant
   access, data exposure, Capability, execution, Claim Replay, and Finding confirmation remain
   false.
8. Rebuild and exact-match the complete authority against the sealed predecessor on every
   verification.

## Consequences

- Tenant retrieval and data-response semantics become bounded, typed, additive discovery facts.
- A same-route pair can be recorded as a coverage hypothesis without claiming access-control
  failure, successful retrieval, confidentiality impact, or validation.
- Missing, malformed, stale, generic-locator, cross-route, cross-target, forged-marker, and
  publication substitutions fail closed.
- The topology is identical for every legacy Campaign mode while retaining the exact Campaign and
  Snapshot identities.
- Existing RAG discovery remains byte- and digest-compatible because the new interpretation is a
  separately selected adapter.

## Rejected alternatives

### Infer tenant selection from parameter or route names

Rejected because names such as `tenant_id` are target-controlled text and do not establish the
semantic boundary required by CHAIN-004.

### Infer data exposure from response schemas or examples

Rejected because a schema describes a possible response shape, while an example may contain
runtime-like content. Neither proves an actual response or cross-tenant exposure.

### Treat explicit declarations as proof of a vulnerability

Rejected because the declarations describe a testable surface only. They provide no credentials,
tenant identity, dispatch, retrieval result, negative control, or independent Replay evidence.

### Add execution authority to the compiler

Rejected because Capability, Permit, dispatch, Replay, and Finding authority already have separate
owners. CHAIN-004 must remain a coverage contract.

## Compatibility and rollback

The change is additive. Existing HTTP/OpenAPI and RAG adapter definitions, sealed Runs, Campaign,
Capability, Replay, Finding, and CHAIN-001/002/003 wires keep their meanings. Rollback removes the
specialized locators, adapter, planner, CHAIN-004 compiler/verifier, and public exports without
rewriting predecessor Runs or allowing generic RAG and route Surfaces to fill the new roles.

## Related documents

- [CHAIN-004 contract](../orchestration/CHAIN-004-cross-tenant-retrieval-data-exposure.md)
- [DISC-003 adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
- [CHAIN-003 contract](../orchestration/CHAIN-003-prompt-url-tool-internal-api.md)
- [ADR-0144](0144-bind-url-tool-chain-to-explicit-surface-authority.md)
- [ADR-0142](0142-bind-mode-neutral-chain-to-surface-snapshot.md)
