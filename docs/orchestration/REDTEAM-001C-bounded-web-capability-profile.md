# REDTEAM-001C: Bounded Web Capability Profile

- Status: implemented locally
- Profile: `redteam-web-v1`
- Reused execution wire: `CapabilityGraphCampaignJobInput`
- Decision: [ADR-0207](../adr/0207-compose-bounded-web-redteam-profile.md)

## Purpose

Expose one exact Web product action over the existing synthetic Boolean SQL injection lab without
turning Web classification, Tool metadata, discovery, or a generic URL into execution authority.
The profile reuses the current signed release, deployment-pinned approval, ActionPermit, Gateway,
Worker, trusted receipt, Oracle, and sealed Run authorities.

## Exact inventory

| Capability | Threat | Tool | Method / request units | Target |
| --- | --- | --- | --- | --- |
| `pajin.bug-bounty.boolean-sqli-lab@1.0.0` | CWE-89 | `bug-bounty.boolean-sqli-probe@1.0.0` | GET / 3 | `http://host.docker.internal:8770/v1/users/lookup` |

The request arguments contain only the exact
`bug-bounty.api.boolean-sqli-lab` scenario. The trusted Worker, not the Job or model, owns the fixed
baseline, false-control, and true Boolean probe values. No other Capability, Tool, scenario,
method, endpoint, payload, query, fragment, crawler, or scanner is admitted.

## Admission and execution

Before opening the Run or consuming a Permit, the executor requires:

1. the code-owned `redteam-web-v1@1.0.0` MissionEnvelope profile digest;
2. the exact experimental CAP-005 Capability definition and Tool binding from the inventory;
3. legacy definition namespace `bug-bounty`, exact `bug-bounty-api` surface declaration, CWE-89,
   T2, read-only, network, no-cleanup, non-parallel, and three-request-unit metadata;
4. the exact GET request, fixed scenario arguments, and fixed synthetic local endpoint;
5. a Graph Proposal reserving exactly three request units;
6. a `bug-bounty` Campaign with exactly one matching `bug-bounty-api` Target, GET and T2 allowed,
   private-network access enabled, and the complete registered Tool category set; and
7. the existing deployment-pinned T2 approval bound to the exact Proposal and reservation.

The legacy `domain=bug-bounty` field is checked only as part of the existing signed Capability
identity. It does not classify the action as Web or grant Profile, Scope, Tool, Permit, or Worker
authority. REDTEAM-001C predates and does not implement the planned DOMAIN-001/003 projection.

The unchanged Capability Graph transaction atomically consumes the approval and Permit. The
unchanged CAP-005 dispatcher revalidates the current release and request-unit cost before Gateway
entry. The Gateway rechecks Campaign Scope, method, risk, rate, Grant, Worker, and evidence policy.
`BooleanSQLiProbeTool` then accepts only the fixed endpoint and scenario and validates exactly
three ordered host-observed HTTP receipts against the normalized observations.

## Execution and retry

A successful dispatch returns the existing `capability-graph-gateway` completion with
`executionProfile=redteam-web-v1`. Exact retry resolves the consumed terminal Permit and never
invokes the Worker again.

Fixture-backed tests use the fixed local target contract and trusted Docker receipt projection.
They do not prove execution against a public or production Web target.

## Fail-closed cases

Positive and adversarial tests cover:

- exact successful execution with Proposal, approval, and Permit reservations equal to three;
- exact retry with one Worker invocation;
- one-unit under-reservation and four-unit over-reservation before Permit creation;
- another Tool or method relabeled as the Web profile;
- another endpoint or scenario;
- a generic MissionEnvelope relabeled as the product profile; and
- a missing deployment-pinned T2 approval.

All product-profile failures occur before Permit creation and Worker invocation. Receipt,
observation, Oracle, and evidence failures remain fail-closed in the existing Tool/Gateway/CAP-002
contracts.

## Evidence and non-authority

The profile returns sealed dispatch and Tool evidence under existing contracts. A successful
Oracle result is not a confirmed security Finding. REDTEAM-001C creates no independent Replay,
validation-floor satisfaction, Finding, impact, severity, report, Scope expansion, discovery,
MCP, browser, system, write, cleanup, credential, or additional execution authority.

The separate legacy Bug Bounty workflow may still produce a review-only Candidate and draft from
its own validated evidence. This product profile does not invoke or inherit that reporting path.

## Compatibility and rollback

The change is additive. Existing Capability, Tool, Campaign, approval, Permit, Gateway, result,
artifact, REDTEAM-001A/B, PENTEST, Bug Bounty, and benchmark identities remain unchanged. Rollback
removes recognition of `redteam-web-v1`; durable approval, Permit, receipt, evidence, and Run
records remain readable under their original authorities.
