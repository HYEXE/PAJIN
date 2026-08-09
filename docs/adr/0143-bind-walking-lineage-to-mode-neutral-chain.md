# ADR-0143: Bind Walking Lineage to an Ordered Mode-neutral Chain

- Status: Accepted
- Date: 2026-08-10

## Context

WALK-002 already binds a File Upload Surface to an explicit corpus-ingest RAG Hypothesis, and
WALK-003 binds that exact sealed Hypothesis to a registered MCP Tool authorization Hypothesis.
P0-D2B demonstrates the same semantic sequence in a runnable synthetic Docker benchmark. None of
these artifacts is a reusable Phase 8 mode-neutral chain contract: WALK remains tied to its
Hypothesis workflow, while P0-D2B provider evidence belongs to benchmark measurement authority.

Copying WALK into a new chain store would create duplicate Hypothesis and execution authority.
Treating P0-D2B's confirmed synthetic Finding as general chain validation would erase the Target,
provider, matcher, and measurement boundaries that make that evidence meaningful.

## Decision

1. Add reusable ordered stage, edge, and sealed stage-reference models under the existing
   mode-neutral attack-chain API without changing CHAIN-001's serialized form.
2. Register CHAIN-002 as exactly three stages: File Upload, RAG Injection, and Tool Abuse, connected
   by two ordered `enables` edges.
3. Reopen and verify the sealed WALK-003 outcome, then bind its complete nested WALK-002 coordinates
   rather than minting new Surface, Hypothesis, Capability, execution, or validation authority.
4. Require the exact code-owned WALK-002 and WALK-003 rules, both exact Campaign digests, and each
   stage's declared Campaign target, Snapshot, Surface, Run root, artifact, and Hypothesis digest.
5. Record the P0-D2B runnable profile only as a semantic cross-check. Do not admit its provider or
   matcher evidence into CHAIN-002.
6. Fix the authority to `hypothesized-not-validated`, with Capability, execution, Claim Replay,
   benchmark evidence admission, and Finding confirmation false.
7. Rebuild and exact-match CHAIN-002 against its sealed predecessor on every verification.

## Consequences

- Phase 8 gains a reusable step/edge representation while preserving CHAIN-001 compatibility.
- WALK-002/003 remain the sole predecessor Hypothesis authorities and P0-D2B remains benchmark-only.
- Missing, reordered, cross-Campaign, cross-target, cross-Snapshot, and cross-Run substitutions fail
  before a chain authority is accepted.
- The same code-owned topology applies to every legacy Campaign mode without weakening exact
  Campaign binding.
- A registered Capability nested in WALK-003 cannot be interpreted as a Capability Grant or Tool
  dispatch.

## Rejected alternatives

### Rename WALK-002/003 as CHAIN-002

Rejected because WALK artifacts have their own workflow state, sealed Run lineage, and consumers.
Relabeling them would change historical meaning and provide no reusable chain topology.

### Import P0-D2B measured evidence

Rejected because the synthetic Docker matcher proves only its exact lab protocol. Its confirmed
Finding and completed-chain count are not general validation of another Campaign's WALK lineage.

### Flatten the chain to one free-form list

Rejected because stage order, edge direction, authority kind, closed execution state, and exact
predecessor coordinates must all fail closed rather than depend on display text.

### Add execution or Claim Replay authority

Rejected because WALK Hypotheses and semantic benchmark comparison do not authorize a Tool call or
prove a replayed Claim. VAL-001 owns that later boundary.

## Compatibility and rollback

The change is additive. Existing mode-neutral CHAIN-001, WALK, Campaign, Capability, Replay,
Finding, and benchmark artifacts retain their current schemas and meanings. Rollback removes the
new contract, authority, verifier, and public loader; it does not rewrite predecessor Runs.

## Related documents

- [CHAIN-002 contract](../orchestration/CHAIN-002-file-upload-rag-tool-abuse.md)
- [CHAIN-001 contract](../orchestration/CHAIN-001-mode-neutral-auth-bypass-ai-admin.md)
- [WALK-002 contract](../orchestration/WALK-002-rag-injection-hypothesis.md)
- [WALK-003 contract](../orchestration/WALK-003-mcp-tool-authorization-hypothesis.md)
- [P0-D2B contract](../benchmark/P0-D2B-local-ai-rag-mcp-docker-provider.md)
