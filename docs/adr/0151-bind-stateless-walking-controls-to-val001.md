# ADR-0151: Bind Stateless WALK Controls to VAL-001

- Status: Accepted
- Date: 2026-08-10

## Context

VAL-004A evaluates sealed KISA Replay and Control evidence, but those Controls are bound to KISA
Claims, Tools, requests and explicit sessions. VAL-001 instead contains a WALK MCP validity Claim,
an original approved execution and one fresh WALK-005B2 Replay. Combining these artifacts by threat
label or Profile would assert a Control relationship that no executor produced.

Repository inspection also showed that the registered WALK MCP request contains exactly one `text`
argument and no session field. Requiring an invented session would change the Tool wire. Omitting an
independence coordinate entirely would make source, Replay and Control reuse difficult to detect.

## Decision

1. Add an explicit VAL-004B module instead of widening the KISA-specific VAL-004A models.
2. Derive a content-addressed non-executable Control Plan from one exact VAL-001 authority. Support
   only its CHAIN-002 and CHAIN-005 WALK lineage and validity Claim.
3. Register a deterministic Baseline, Negative Control and Counterfactual materialization for the
   exact stateless MCP text schema. Keep the source text for Baseline and Negative Control; use one
   registered benign text for the Counterfactual.
4. Keep the exact source request and result semantics for the Negative Control but replace the
   observation oracle with one nonce-derived canary that must be absent from MCP content. This
   mirrors the existing KISA absent-canary pattern without claiming target configuration authority.
   Require the Counterfactual to attest no hijacking pattern and no internal data access.
   Exact-match target, server and remote Tool to the source observation.
5. Do not dispatch from VAL-004B. Accept only existing `WalkingExecutionEvidence` that passes the
   current explicit approval, single-call Grant, Permit, Gateway, Worker, audit and Run-integrity
   verification.
6. Add a Plan-and-Control approval receipt and require it to be sealed before the dispatch claim.
   This prevents post-execution relabelling.
7. Require the Permit Capability to exact-match the registered WALK Capability and the Grant to
   retain the exact Campaign.
8. Record `sessionPolicy=stateless` and require all source, Replay and Control requests to have the
   exact one-field text schema. Do not mint a synthetic session. Count that evidence toward VAL-002
   only when the registered depth requirement explicitly accepts `ReplaySessionPolicy.STATELESS`.
9. Prove independence with five pairwise-distinct Run/root, execution, request, Grant, Permit,
   approval, Worker and Run-qualified evidence identities. Copy and reseal each Control evidence
   artifact in a distinct publication Run.
10. Re-verify VAL-001 and all sealed Control Runs when evaluating a Profile floor. Derive single
    depth without Controls and controlled depth with the exact observed contrast.
11. Reject repeated-controlled floors because current VAL-001 contains one Replay. Control
    executions are not Replay repetitions.
12. Fix Profile selection, Campaign mutation, execution, confirmation and Finding authority to
    false and keep the Control result informational only.

## Consequences

- WALK evidence can satisfy CTF, Bug Hunt and Pentest floors without borrowing KISA evidence.
- AI Assessment remains fail closed until a second independently planned and sealed WALK Replay is
  represented by a later authority.
- The stateless policy is explicit and testable even though no session identifier exists.
- The Negative Control measures an absent oracle value; it does not claim that target-side
  authorization was enabled or reconfigured.
- Reused approvals, requests, Grants, Permits, Workers, evidence or Runs cannot count as independent
  source, Replay or Control evidence.
- The additional Plan receipt adds a pre-dispatch binding without duplicating approval or execution
  authority.

## Rejected alternatives

### Reuse KISA Control evidence

Rejected because its Claim, Tool, request and session semantics do not match VAL-001.

### Add a synthetic session argument

Rejected because it would change the registered MCP Tool schema and claim evidence that no executor
produced.

### Treat each Control as another Replay

Rejected because the Control conditions intentionally change the request or authorization outcome.
They are causal contrasts, not repetitions of the exact validity Replay.

### Trust sealed output without a Control Plan receipt

Rejected because an independently approved execution could otherwise be assigned a Control meaning
only after dispatch.

## Compatibility and rollback

The change is additive and uses an explicit module API. No existing VAL-001, KISA VAL-004A,
Campaign, Profile, Replay, Validation Decision or Finding wire changes. Rollback removes the module,
tests, contract and this ADR without rewriting predecessor Runs.

## Related documents

- [VAL-004B contract](../orchestration/VAL-004B-mode-neutral-walking-profile-evidence.md)
- [VAL-004A contract](../orchestration/VAL-004A-kisa-profile-validation-evidence.md)
- [VAL-001 contract](../orchestration/VAL-001-mode-neutral-claim-replay.md)
- [ADR-0147](0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md)
- [ADR-0032](0032-fresh-capability-validation-controls.md)
