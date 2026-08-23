# ADR-0218: Admit AI Observations without Tool Authority

## Status

Accepted

## Context

AI-001B can bind and prepare four existing REDTEAM read-only AI Capabilities, but intentionally
stops before execution and Observation. The existing REDTEAM Capability Graph path can already
issue a one-use ActionPermit, dispatch through the Tool Gateway and isolated Worker, write
create-only request and Tool evidence, append a Capability dispatch lifecycle, and seal the Run.
That successful result was not yet connected to the DOMAIN-002 AI Observation semantic through a
dedicated AI vertical-slice admission boundary.

Model output, provider/model identity, Surface classes, Profile names, MCP advertisements, and Tool
metadata are untrusted or descriptive inputs. Allowing any of them to choose a Tool, expand Scope,
issue a Permit, select a Worker, or confirm a Finding would create an authority bypass. Creating a
second AI Graph writer or executor would duplicate the existing control path.

## Decision

Add one explicitly imported AI Observation admission module. Accept only the three existing
REDTEAM LLM, LLM/RAG, and registered MCP execution Profiles that exactly match an AI-001B
preparation. Reopen the sealed Run, locate the one exact consumed ActionPermit, use the existing
Capability dispatch reconciliation, verify the request reservation and Tool evidence, re-run the
code-owned Tool adapter interpretation and trusted-execution checks, validate bounded Worker
metadata, and recompute the Gateway outcome digest.

Build an Observation proposal containing one successful Action, one neutral
`ai.behavior-observation`, two Evidence nodes, one `produces` edge, and two `supported-by` edges.
Bind the exact ordered AI-001A Surface references and DOMAIN-002 AI type-set into the candidate and
Observation digest, but do not propose Surface nodes. Do not copy provider, model, prompt,
response, MCP, or Worker transcript content into Graph text.

Reuse the existing `GraphAdmissionAuthority`, SQLite event log, current Snapshot check, trusted
lineage registry, and semantic-attempt idempotency. The admitted state is
`registered-not-authorized`; every metadata, Scope, activation, approval, Permit issuance, Tool,
Worker, network, credential, execution, replay, and Finding authority marker remains false.

## Consequences

- The implemented model/Tool, model/RAG/Tool, and MCP/Tool slices can produce sealed neutral AI
  knowledge in the Canonical Graph.
- The source Capability Grant and consumed ActionPermit are both preserved in lineage.
- A stale Graph head, source tampering, failed dispatch, adapter drift, untrusted receipt, secret
  evidence, or authority injection fails closed.
- Exact retry reuses the prior Graph semantic attempt and never redispatches the Tool.
- Cross-Surface means one Observation is bound to the exact Surface set; it does not create Surface
  nodes or cross-Surface execution authority.
- AI-001D can add separately authorized fresh-session replay and controls without treating this
  admission as replay or Finding authority.

## Rejected alternatives

### Admit model output as a Finding or Hypothesis

Rejected because source output has not satisfied independent replay, controls, Profile assurance,
or Finding confirmation.

### Infer Tool selection from Surface or MCP metadata

Rejected because descriptive metadata is not current Campaign, Capability, approval, Permit,
Gateway, or Worker authority.

### Add AI Surface nodes during Observation admission

Rejected because AI-001B already supplies exact inert references. Adding Surface nodes would
silently broaden this slice from evidence admission to discovery authority.

### Create an AI-specific Graph store or writer

Rejected because Canonical Graph admission is a single-writer boundary. A parallel ledger would
split authority and stale-Snapshot protection.

### Reuse the consumed source Permit for replay

Rejected because the Permit is non-bearer and consumed. Replay needs a fresh Decision, approval,
Grant, Permit, Worker session, and sealed evidence.

## Compatibility and rollback

The change is additive. Existing REDTEAM, AI-001B, Tool, Gateway, Worker, Run, Graph, replay,
Finding, and benchmark wires are unchanged. The specialized module is not added to an eager package
facade. Rollback removes the module, tests, contract, and this ADR; existing artifacts need no
migration.

## Related documents

- [AI-001C contract](../graph/AI-001C-cross-surface-observation-evidence-admission.md)
- [AI-001B contract](../capability/AI-001B-provider-model-tool-bound-read-only-analysis.md)
- [AI-001A contract](../discovery/AI-001A-model-rag-agent-mcp-tool-surface-classification.md)
- [DOMAIN-002](../graph/DOMAIN-002-common-multi-domain-graph-semantics.md)
- [REDTEAM-001A](../orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md)
- [REDTEAM-001B](../orchestration/REDTEAM-001B-multi-turn-llm-rag-profile.md)
- [REDTEAM-001D](../orchestration/REDTEAM-001D-registered-mcp-capability-profile.md)
- [ADR-0217](0217-bind-ai-analysis-without-provider-authority.md)
