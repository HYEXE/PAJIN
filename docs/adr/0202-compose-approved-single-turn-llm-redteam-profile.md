# ADR-0202: Compose an Approved Single-turn LLM Red Team Profile

## Status

Accepted

## Context

CAP-005 already registers reviewed KISA AI chat Capabilities, and the Capability Graph Worker can
execute an activated T2 release through a deployment-pinned approval, ActionPermit, Tool Gateway,
Worker, trusted proxy receipts, and sealed Run audit. That generic profile does not define which
part of the inventory is a supported LLM pentest product surface. PENTEST-004B cannot be widened:
its activation, compiler, request, and receipt contracts are intentionally GET-only Recon.

The current M03 and M06 catalog probes each perform one network exchange. A04 performs two. The
current CAP-001 definitions reserve one request unit, while the Tool Gateway independently counts
the actual number of turns. Admitting A04 through a product profile before those two authorities
agree would understate its Graph reservation even though the Gateway still enforces its own
request count.

## Decision

Add `redteam-llm-v1` as an explicit product ceiling over the existing `capability-graph-v1`
execution path. It does not add a Permit, approval, deployment, Gateway, Worker, or result schema.
The MissionEnvelope must carry the code-owned profile ID, version, and digest; relabeling a generic
Capability Graph Job does not satisfy the product profile.

The profile admits only these exact experimental Capability definitions:

- `pajin.ai.kisa.system-prompt-disclosure@1.0.0` / M03; and
- `pajin.ai.kisa.jailbreak-policy-bypass@1.0.0` / M06.

Both must retain the exact `ai.chat-probe@1.0.0` binding, T2 risk, read-only side effect, network
access, no cleanup, one request unit, and the registered AI/RAG surface declaration. The prepared
request must be the exact catalog scenario, threat class, POST Tool call, and one-turn input.

The deployment Campaign must be `ai-redteam`, declare the corresponding threat class, permit POST
and T2, and contain exactly one `ai-chat-api` Target whose endpoint equals the request Target. A
`rag-chat-api` Target is rejected even though the underlying Capability definition advertises RAG
compatibility. T2 still requires the existing deployment-pinned approval and is consumed through
the unchanged Capability Graph transaction.

## Consequences

- REDTEAM-001 gains one real executable LLM vertical slice without changing PENTEST Recon.
- Exact retry reuses the existing terminal Permit and cannot invoke the Worker twice.
- Result evidence remains the existing sealed Capability dispatch and Gateway evidence. The new
  profile does not create Replay, Finding, confirmation, impact, severity, or reporting authority.
- A04, RAG, Web, MCP, browser, system, writes, cleanup, T3+, and unregistered scenarios remain
  closed.
- A later multi-turn slice must bind Graph reservation units to the exact prepared request before
  admitting A04 or other multi-exchange probes.

## Rejected alternatives

### Extend PENTEST-004B from GET to POST

Rejected because it would silently change the signed Recon activation, Scope, method, request,
receipt, and Replay contracts.

### Treat every CAP-005 AI definition as product-supported

Rejected because registration and Range activation do not define the narrower product boundary,
and A04 currently has a two-turn reservation mismatch.

### Infer LLM or RAG authority from Tool categories

Rejected because Tool metadata is not Capability or Campaign authority. The profile checks exact
Capability, Tool, request, Campaign, threat, and Target identities.

## Compatibility and rollback

The change is additive. Existing `capability-graph-v1`, batch, General Attack, Mode, Pentest, and
wire contracts are unchanged. Rollback removes recognition of `redteam-llm-v1`; already consumed
approval, Permit, dispatch, receipt, evidence, and Run records remain valid under their original
authorities.

## Related documents

- [REDTEAM-001A contract](../orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md)
- [CAP-005 contract](../capability/CAP-005-existing-mode-tool-replay-adapters.md)
- [ADR-0197](0197-expose-approved-recon-only-through-live-worker-session.md)
