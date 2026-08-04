# ADR-0110: Reuse the Canonical Graph for Campaign Facts

- Status: Accepted
- Date: 2026-08-04

## Context

Phase 5 needs structured collaboration facts, but GRAPH-001 and GRAPH-002 already define the
unprivileged `CampaignFactProposal`, authority-owned validation state, append-only admission event,
and immutable `GraphCampaignFact`. Creating a `CampaignFactRecord` model or collaboration ledger
would duplicate authority and allow the two histories to diverge.

The missing boundary was live verification that a proposed Fact actually refers to the current
sealed Campaign Run and exact evidence bytes before existing Graph admission.

## Decision

Add a narrow sealed-Run adapter in front of the existing `GraphAdmissionAuthority`.

The adapter reparses the existing Proposal and verifies, in one bounded Run snapshot:

- exact Run ID;
- exact Campaign manifest and one matching `campaign.started` event;
- exact current Run integrity root; and
- exact SHA-256 for every referenced evidence artifact.

It then submits the unchanged Proposal to the existing authority. Producer and complete lineage
trust remain independent Graph authority checks. The existing admission event and admitted
CampaignFact are the only canonical record.

Do not seal the Proposal itself into the same source Run. Its `sourceRootDigest` would then depend
on an artifact containing that digest, creating a circular identity. The Proposal instead remains
an unprivileged request bound to the already sealed source root and evidence.

## Consequences

- No new Fact wire format, record type, projection, or store is introduced.
- Existing retry, equivocation, single-writer, and immutable validation-state semantics are reused.
- The adapter cannot mint execution authority, expand Scope, or convert Fact text into commands.
- Full producer/request/Capability trust cannot be inferred from filesystem integrity and remains
  mandatory in the configured Graph registries.
- MEM-002 and MEM-003 can consume Graph-derived references and Snapshots without treating free-form
  Agent text as authority.

The adapter deliberately bounds evidence count and size. Broader evidence transport requires a
separate contract rather than relaxing this admission path.

## Rejected alternatives

### Add `CampaignFactRecord`

Rejected because `GraphAdmissionEvent` plus its admitted `GraphCampaignFact` already provides the
record, authority, ordering, provenance, and immutable state.

### Add a collaboration database

Rejected because Architecture v2 defines collaboration memory as Graph/Event-Log projections.

### Seal the complete Proposal in its source Run

Rejected because the Proposal contains that Run's root digest and would create a content-address
cycle.

### Let the adapter register caller lineage

Rejected because sealed file integrity alone cannot authenticate request, Grant, Capability,
Agent, or Task authority.
