# WALK-002: RAG Injection Hypothesis

- Status: Implemented
- Hypothesis contract: `pajin.dev/walking-rag-injection-hypothesis/v1alpha1`
- Recon planner ID: `pajin.walk.rag-injection-recon.v1`
- Compiler ID: `pajin.walk.rag-injection-hypothesis-compiler.v1`
- Decision: [ADR-0068](../adr/0068-snapshot-bound-rag-injection-hypothesis.md)

## Scope

WALK-002 is the second Phase 4 walking-skeleton slice. It selects the cumulative DISC-003C
adapter, requires a trusted projection to contain both `http-file-upload` and `http-rag`, and
compiles a RAG-injection Hypothesis only when one explicit `corpus-ingest` RAG locator and exactly
one file-upload locator share the same Campaign target and complete HTTP route locator.

The Hypothesis is deliberately non-executable. WALK-002 creates no `ToolRequest`, Capability,
payload, document, corpus write, or Worker dispatch. The `rag-document-probe` identifier expresses
the required future capability; later walking slices must separately register, authorize, and bind
any executable Tool.

## Recon authority

`HTTPRAGInjectionReconPlanner` binds one Campaign-declared OpenAPI target, `HTTPGetTool`, method
`GET`, empty arguments, the exact DISC-003C adapter ID/version/digest, and the ordered required
Surface kinds `http-file-upload` and `http-rag`. The existing Recon runner fails before projection
if either kind is missing or the admitted adapter differs.

DISC-003C remains the only interpreter in this path. It recognizes RAG topology solely through an
operation-level `x-pajin-rag` declaration with version `"1"`; route names, schema fields, and prose
cannot imply RAG authority.

## Hypothesis authority

`RAGInjectionHypothesisAuthority` is content-addressed and binds:

- the complete canonical Campaign digest;
- the ORCH-001 `SurfaceSnapshotAuthority`, including projection/source roots, sealed artifact
  SHA-256, revision, and exact Surface Set ID;
- compiler ID and the complete code-registered H-17 rule digest;
- Campaign target ID;
- primary RAG Surface ID plus its complete `HTTPRAGSurfaceLocator`;
- dependency upload Surface ID plus its complete `HTTPFileUploadSurfaceLocator`;
- indirect-prompt-injection statement, rationale, and expected observable;
- required future Tool semantic, Risk Tier T1, corpus-write side effect, and four-call ceiling;
- success and stop conditions; and
- fixed execution state `not-authorized`.

Compilation re-verifies `campaign.json` and `recon-plan.json` from the sealed source Run, then
re-verifies the sealed projection and reconstructs its ORCH-001 Snapshot. The output identity is
independent of Run time and ordering.

## Audit path

```text
Campaign OpenAPI target
-> exact DISC-003C Recon plan
-> sealed source Run
-> trusted File Upload + explicit RAG admission
-> immutable AttackSurfaceSet projection
-> ORCH-001 SurfaceSnapshotAuthority reconstruction
-> deterministic co-location and corpus-ingest checks
-> content-addressed RAGInjectionHypothesisAuthority
-> separate sealed non-executable Hypothesis Run
```

The Hypothesis Run writes `campaign.json`, `rag-injection-hypotheses.json`, `run.json`, one
`walking.rag-injection-hypotheses.created` event, and terminal Campaign events. Its audit states
`executionState: not-authorized` and contains no capability or dispatch event.

## Negative boundaries

Compilation or Recon fails closed when:

- the planned or admitted adapter is not the exact DISC-003C authority;
- either required Surface kind is absent;
- no explicit `corpus-ingest` declaration exists;
- the RAG and upload Surfaces differ in target or complete route locator;
- a corpus-ingest Surface has zero or multiple co-located upload dependencies;
- the caller substitutes a Campaign, Recon Plan, source Run, projection, Snapshot, Surface, rule,
  or digest;
- a sealed artifact or publication event differs from its integrity authority; or
- any bounded canonical model validation fails.

Retrieval and index-management boundaries do not become injection hypotheses. An upload path named
for documents, knowledge, or RAG does not create a RAG Surface without the explicit extension.

## Compatibility, rollback, and next slice

WALK-002 adds a new model and Runner and makes the existing Recon Snapshot loader public; it does
not change the v1alpha1 `AttackHypothesis`, `HypothesisWavePlan`, ORCH-001 Plan/Task, or legacy Recon
wire shapes. Rollback stops selecting the WALK-002 planner/compiler while already sealed source,
projection, and Hypothesis Runs remain immutable and readable.

This slice closes only File Upload Surface to RAG Injection Hypothesis. WALK-003 must add the MCP
Tool Authorization Hypothesis and exact dependency without treating the semantic required Tool ID
as execution authority.
