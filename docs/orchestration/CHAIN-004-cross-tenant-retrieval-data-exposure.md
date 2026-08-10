# CHAIN-004: Cross-tenant Retrieval to Data Exposure

## Purpose

Represent a Target-declared tenant-selectable RAG retrieval boundary and a Target-declared
data-bearing response on the same route as one mode-neutral coverage hypothesis without claiming
cross-tenant access, successful retrieval, data exposure, or validation.

## Typed discovery prerequisites

`HTTPTenantRetrievalSurfaceLocator` is emitted only when an OpenAPI operation contains an exact
version-1 `x-pajin-tenant-retrieval` object and the same operation already produced exactly one
`HTTPRAGSurfaceLocator` with `boundary=retrieval`. The declaration retains only a selector
`location` (`body`, `header`, `path`, or `query`) and a portable field name. It retains no tenant
value or retrieval query. Path selectors must match an exact placeholder in the bound route.

`HTTPDataResponseSurfaceLocator` is emitted only for an exact version-1
`x-pajin-data-response` object on a route with at least one declared response content type. Its
`dataClasses` must be a sorted, unique subset of the code-owned values `authentication-data`,
`customer-content`, `financial-record`, `personal-data`, `regulated-data`, and `support-record`.
Response examples, bodies, and schema contents are not admitted.

The dedicated `HTTPAndOpenAPITenantDataSurfaceAdapter` preserves the existing cumulative
HTTP/Auth/File/RAG Surfaces, while its distinct adapter identity leaves the DISC-003C RAG wire
unchanged. `HTTPTenantDataRetrievalReconPlanner` requires `http-rag`,
`http-tenant-retrieval`, and `http-data-response`, so a missing typed declaration fails the Recon
wave closed.

## Inputs and predecessor authority

The compiler accepts one canonical `CampaignManifest`, one `ReconWaveOutcome`, and two exact
Surface IDs. It calls `load_recon_surface_authority()`, which re-verifies the sealed Campaign and
Recon Plan, source Run root, projection Run root, publication event, artifact digest, and in-memory
outcome equality.

The two selected Surfaces must be the exact tenant-retrieval and data-response locator types, must
belong to the same Campaign target, and must wrap the same exact `HTTPRouteSurfaceLocator`. That
target must be declared exactly once by the Campaign. A generic RAG Surface or generic route cannot
stand in for either role.

## Registered stages and edge

`chain-004:cross-tenant-retrieval-data-exposure@1.0.0` fixes this exact order:

1. `cross-tenant-retrieval`: an explicit tenant-selectable retrieval boundary, recorded only as a
   `cross-tenant-retrieval-hypothesis`; and
2. `data-exposure`: the same route's declared data-response Surface, recorded only as a
   `declared-data-response-surface`.

One ordered `enables` edge connects the stages. Each stage has
`authorityKind=SurfaceSnapshotAuthority` and `executionState=discovered-not-authorized`.

Each Surface reference binds the exact Surface ID, Campaign target, locator kind and content,
locator digest, Surface digest, and observation count. Each stage also binds its Snapshot ID and
digest. The authority binds the canonical route digest. Verification rebuilds every coordinate
from the sealed Recon outcome and requires exact equality.

## Mode neutrality and authority ceiling

The contract has `campaignModeConstraint=none`; its topology is identical for `ai-redteam`,
`bug-bounty`, and `ctf`. It retains the exact Campaign digest and does not permit cross-Campaign
replay.

`ModeNeutralTenantAttackChainAuthority` is fixed to `hypothesized-not-validated` and
`surfaceEvidenceOnly=true`. Tenant values are absent. Cross-tenant access, data exposure,
Capability Grant, execution authorization, Claim Replay authorization, and Finding confirmation
are false. The compiler and verifier create no Tool request, credentials, Permit, dispatch,
retrieval result, Replay, Report, or benchmark result.

## Fail-closed boundaries

Compilation and verification reject:

- malformed, unsealed, mutated, stale, or cross-Campaign Recon authority;
- a generic RAG or route Surface substituted for an exact CHAIN-004 locator;
- missing or malformed extension declarations and arbitrary data-class strings;
- a tenant declaration without one exact co-located RAG retrieval declaration;
- Surfaces from different Campaign targets or different exact routes;
- a path selector absent from the bound route;
- reordered stages, changed edge topology, forged digests, and boolean marker coercion or
  escalation;
- verification against another sealed publication even when its semantics are equal; and
- attempts to derive authority from tenant values, parameter names, descriptions, schemas,
  examples, response names, or synthetic Findings.

## Audit artifacts and events

No new mutable chain store or event family is introduced. The authority retains the existing
`SurfaceSnapshotAuthority`, which identifies the sealed source and projection Runs, publication
artifact path and SHA-256 digest, and Surface Set ID. Those predecessor Runs remain the audit
authority.

## Compatibility and rollback

The new API version is `pajin.dev/mode-neutral-tenant-attack-chain/v1alpha1`. All additions are new
locator kinds, a separately selected cumulative adapter, a dedicated planner, compiler, verifier,
and public exports. Existing HTTP/RAG locators, adapter digests, CHAIN-001/002/003, Campaign,
Capability, Replay, and Finding artifacts do not change.

Rollback removes the additions while preserving sealed predecessor Runs and the rule that generic
locators cannot fill CHAIN-004 roles.

## Current limitations

The OpenAPI extensions are Target declarations, not observed runtime behavior. Header, query, and
body selector names are not resolved through parameter or schema references; path selectors alone
receive an extra exact-placeholder check. The data declaration does not bind a response status
code and does not prove that any response is returned. CHAIN-004 does not prove tenant isolation
failure, selector control, successful retrieval, response confidentiality, exposed data, or user
impact. VAL-001 must introduce a separate exact Claim and independent Replay authority before the
chain can advance beyond a coverage hypothesis.

## Related documents

- [CHAIN-003 contract](CHAIN-003-prompt-url-tool-internal-api.md)
- [CHAIN-002 contract](CHAIN-002-file-upload-rag-tool-abuse.md)
- [ADR-0145](../adr/0145-bind-tenant-data-chain-to-explicit-retrieval-authority.md)
- [DISC-003 adapters](../discovery/DISC-003-auth-file-rag-mcp-surface-adapters.md)
