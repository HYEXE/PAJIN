# REDTEAM-001A: Approved Single-turn LLM Capability Profile

- Status: implemented locally
- Profile: `redteam-llm-v1`
- Reused execution wire: `CapabilityGraphCampaignJobInput`
- Decision: [ADR-0202](../adr/0202-compose-approved-single-turn-llm-redteam-profile.md)

## Purpose

Expose the first product-specific, executable REDTEAM Capability without expanding the GET-only
Pentest Recon path or bypassing the existing signed release, approval, Permit, Gateway, Worker,
receipt, and sealed-evidence authorities.

## Exact inventory

| Capability | Threat | Tool | Exchanges | Target type |
| --- | --- | --- | ---: | --- |
| `pajin.ai.kisa.system-prompt-disclosure@1.0.0` | M03 | `ai.chat-probe@1.0.0` | 1 | `ai-chat-api` |
| `pajin.ai.kisa.jailbreak-policy-bypass@1.0.0` | M06 | `ai.chat-probe@1.0.0` | 1 | `ai-chat-api` |

No other Capability ID, version, Tool, threat, exchange count, or Target type is admitted.

## Admission and execution

The Job carries the existing Proposal, Decision, exact release reference, Tool request, Grant, and
approval. Startup still supplies the SHA-256-pinned Capability Graph deployment, complete signed
seven-release inventory, explicit activation subset, Campaign, MissionEnvelope, approval input
authority, Graph database, Run root, Tool registry, Worker, and clock.

Before opening the Run or consuming a Permit, the executor requires:

1. the code-owned `redteam-llm-v1@1.0.0` MissionEnvelope profile digest;
2. an exact admitted Capability from the table above;
3. the registered experimental AI Red Team definition with T2, read-only, network, no-cleanup, and
   one-request-unit metadata;
4. the exact `ai.chat-probe` POST request, registered scenario/threat pair, and one turn;
5. an `ai-redteam` Campaign declaring that threat, POST, and a T2 ceiling; and
6. exactly one `ai-chat-api` Target whose endpoint equals the request Target.

The unchanged Capability Graph path then prepares the action again, resolves the exact activation,
requires a deployment-pinned T2 approval, atomically consumes approval and Permit, dispatches
through the Tool Gateway, validates trusted host proxy receipts, seals the Run, and reconciles the
terminal event. Exact retry returns the consumed terminal identity without another Worker call.

## Fail-closed cases

Tests cover:

- another Tool or method in the product Job;
- relabeling a generic Capability Graph MissionEnvelope as the REDTEAM product profile;
- a missing deployment-pinned T2 approval;
- a `rag-chat-api` Target presented to the LLM-only profile;
- the two-turn A04 memory probe, which belongs only to the separate REDTEAM-001B profile; and
- exact retry after successful M03 and M06 dispatches, with one Worker invocation per action.

All product-profile failures occur before Permit creation and Worker invocation. Existing generic
profiles retain their own behavior.

## Evidence and non-authority

The result is the existing `capability-graph-gateway` completion projected with
`executionProfile=redteam-llm-v1`. Sealed dispatch and Tool evidence remain authoritative under
their existing contracts. The profile does not assert a live external Target was used in tests and
does not create Replay, Finding, confirmation, impact, severity, report, Scope expansion, or
additional execution authority.

## Remaining REDTEAM-001 boundary

REDTEAM-001B now binds A04 `1.1.0` to two request units in the separate
`redteam-llm-rag-v1` profile without widening this one. Web and MCP still require their own exact
Capability/Target/receipt slices. Browser and system actions remain outside the current Phase 11
exit wording and cannot be inferred from Tool names. See the
[REDTEAM-001B contract](REDTEAM-001B-multi-turn-llm-rag-profile.md).

## Compatibility and rollback

The profile is additive and reuses existing wire objects. Removing its routing and validation
restores the prior generic-only surface. Durable approvals, Permits, receipts, dispatch events, and
Run evidence are retained.
