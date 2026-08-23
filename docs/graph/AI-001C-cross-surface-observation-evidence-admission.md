# AI-001C: Cross-Surface Observation and Evidence Admission

- Status: Implemented, sealed knowledge admission only
- API versions:
  - `pajin.dev/ai-analysis-observation-admission-policy/v1alpha1`
  - `pajin.dev/ai-analysis-observation-candidate/v1alpha1`
  - `pajin.dev/ai-analysis-observation-admission/v1alpha1`
- Authority: `src/pajin/workflow/ai_analysis_admission.py`
- Decision: [ADR-0218](../adr/0218-admit-ai-observations-without-tool-authority.md)

## Purpose

AI-001C turns one already successful and sealed REDTEAM-001A/B/D execution into a neutral
`ai.behavior-observation` plus Evidence in the existing Canonical Graph. It binds the Observation
to the exact AI-001B preparation and ordered model/Tool, model/RAG/Tool, or MCP/Tool Surface set.
The Surface references classify what was analyzed; they are not admitted as new Surface nodes and
do not select a Tool or authorize another action.

This boundary adds no executor, Gateway, Worker, provider client, MCP client, Graph ledger, Graph
writer, Hypothesis, Finding, Scope, approval, Permit, credential, network, replay, or dispatch path.

## Accepted execution sources

The source must be one exact `CapabilityGraphCampaignJobInput` using:

| Existing execution Profile | AI-001B Surface set | Observation type |
| --- | --- | --- |
| `redteam-llm-v1` M03/M06 | model, Tool | `ai.behavior-observation` |
| `redteam-llm-rag-v1` A04 | model, RAG, Tool | `ai.behavior-observation` |
| `redteam-mcp-v1` | MCP, Tool | `ai.behavior-observation` |

The job Profile must exactly equal the code-owned AI-001B Capability binding. The release,
prepared action, request, ActionProposal, GraphDecision, Capability Grant, consumed ActionPermit,
Campaign, Run, Capability, target, normalized parameters, activation set, and request digest must
all agree.

## Sealed source verification

`load_verified_ai_analysis_observation_source` opens the source Run under the existing Run seal and
reconciliation logic. It requires:

- one consumed ActionPermit for the exact Run and request;
- one reconcilable `claimed -> completed` Capability dispatch lifecycle;
- a successful, executed, policy-allowed, Tool-success terminal event;
- the exact create-only Tool request reservation;
- one exact Tool evidence artifact with no unknown fields or Secret Lease material;
- a successful Worker result and code-owned Tool adapter re-interpretation;
- complete trusted host network receipts for LLM/RAG probes;
- network-disabled execution for the registered MCP Tool;
- exact non-secret Worker metadata, empty secret request and lease lists, and bounded egress matching
  the request target, method, and request-unit cost where network is required; and
- a recomputed Gateway outcome digest equal to the sealed terminal audit event.

The source may contain provider or model output, but Graph material records only content-addressed
digests and a fixed neutral summary. It does not copy prompts, responses, MCP content, Worker
transcripts, credentials, or model-authored claims into Graph text.

## Graph proposal

The candidate contains exactly:

- one successful `Action` bound to the consumed ActionPermit;
- one target-derived neutral `Observation` of type `ai.behavior-observation`;
- two `Evidence` nodes for the request reservation and Tool execution evidence;
- one `produces` edge; and
- two `supported-by` edges.

The lineage binds both the exact Capability Grant and ActionPermit, source Run seal root, Evidence
digests, request, Capability, and production time. The AI-001A Surface references and exact
DOMAIN-002 AI type-set are part of the content-addressed candidate and Observation value digest,
but no Surface node is proposed.

## Existing single writer and retry behavior

`AIAnalysisObservationAdmissionGate` requires a current non-empty Graph Snapshot and the exact
already-existing `GraphAdmissionAuthority` attached to the same SQLite event log and trusted
lineage registry. It registers the independently verified lineage and uses `submit_if_current`.
There is no AI-specific Graph store or writer.

An exact retry rebuilds the candidate from the sealed source and returns the existing semantic
attempt without re-executing a Tool. A changed candidate using the same identity is rejected by
the Graph equivocation and content-addressing boundaries.

## Resulting state and explicit non-authority

Successful admission has state `registered-not-authorized`. It proves only that the sealed source
supports one neutral Graph Observation across the referenced AI Surfaces. Policy, candidate, and
admission artifacts fix all of the following to false:

- Surface, Hypothesis, Finding, Profile metadata, Domain metadata, and Tool metadata authority;
- Scope expansion and Capability activation;
- approval and Permit issuance;
- Tool, Worker, network, and credential selection or access;
- execution and replay; and
- Finding confirmation.

The existing source ActionPermit is consumed evidence, not a bearer token. Source output, Profile
names, Domain labels, Surface classes, provider/model identities, RAG routes, MCP metadata, Tool
schemas, and Graph membership cannot authorize a subsequent action.

## Fail-closed behavior

Admission rejects an unsealed, tampered, failed, cancelled, incomplete, foreign, or ambiguously
reconciled Run; preparation/job/Profile/release/Grant/Permit/request/Capability drift; wrong or
reordered Surfaces; unknown Domain semantics; Tool adapter or Worker metadata mismatch; missing or
untrusted required network receipts; MCP network use; secret evidence fields; stale Graph heads;
Graph authority substitution; candidate drift; extra fields; true authority markers; and boolean
coercion.

## Compatibility and rollback

AI-001C is additive and explicitly imported. It changes no REDTEAM, AI-001B, Capability, Profile,
ToolRequest, ActionPermit, Gateway, Worker, Run, Graph, Discovery, Finding, replay, or benchmark
wire. Rollback removes the specialized module, tests, this contract, and ADR-0218. Existing sealed
Runs and Graph events require no migration.

## Verification

`tests/test_ai_analysis_admission.py` covers successful model/Tool, model/RAG/Tool, and MCP/Tool
admission; exact Surface ordering; Observation/Evidence-only Graph material; registered-not-
authorized state; exact retry without redispatch; Grant substitution; authority escalation; and
sealed evidence tampering.
