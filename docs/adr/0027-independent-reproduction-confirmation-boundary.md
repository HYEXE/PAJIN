# ADR 0027: Independent restricted reproduction as the confirmation boundary

- Status: Accepted
- Date: 2026-07-15
- Implementation: Planned; the current semantic/objective gate does not yet satisfy this boundary
- Amends: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.md), [ADR 0026](0026-trusted-kisa-candidate-admission.md)
- Clarifies: [ADR 0004](0004-dynamic-multi-agent-execution.md)
- Product baseline: [PAJIN Product Plan](../PAJIN_PRODUCT_PLAN.md)

## Context

The product baseline requires PAJIN to reproduce and independently validate a Candidate before it
is reported as confirmed. Reviewing an existing transcript with a different prompt or model can
detect unsupported claims and semantic mistakes, but it does not prove that the behavior is
reproducible. Semantic agreement over one execution is evidence review, not independent
reproduction.

ADR 0025 introduced the Candidate and Decision ledger, and ADR 0026 added trusted KISA Candidate
admission. Both boundaries remain necessary. Their interim confirmation rule, however, permits a
matching semantic Validator result plus the objective evidence gate to create `confirmed` without a
second execution. That rule conflicts with the product baseline.

Giving an LLM Validator general attack Tools does not correct the conflict safely. It would allow
untrusted evidence and model output to influence executable commands, targets, arguments, and
Capabilities. Independent reproduction therefore needs a separate, constrained execution boundary.

## Decision

### Confirmation invariant

A Candidate can become product-level `confirmed` only when all applicable conditions hold:

1. a trusted producer or compatibility adapter admits the Candidate with bounded provenance;
2. the objective Scope, target, request, and evidence gate passes;
3. a separate reproduction execution creates a successful `ReplayOutcome` bound to that Candidate;
4. the reproduction uses a new request identity and distinct evidence lineage;
5. a Mode-owned typed Oracle supports the precise claim from the reproduction observation; and
6. when the Mode declares semantic interpretation necessary, the Semantic Validator also supports
   the claim.

Semantic support, original evidence strength, producer admission, repeated Specialist observations,
or human confidence cannot replace the successful independent `ReplayOutcome`.

### Validator is a pipeline, not one LLM agent

The product-level Validator consists of separated roles:

1. **Candidate Producer** admits observations from typed Mode contracts. It has no Provider, Tool,
   process, or replay authority.
2. **Semantic Validator** receives a bounded, redacted Validation Packet and evaluates the claim,
   evidence, impact, and reproduction conditions. Its only executable capability is its Provider
   call.
3. **Replay Compiler** resolves a typed, non-executable `ReplayIntent` against the Candidate, the
   original Specialist request, a registered Mode scenario, and an allowlisted Tool template.
4. **Restricted Reproducer** receives a dedicated replay Grant and executes the compiled operation
   through the ordinary Tool Gateway and Worker boundary.
5. **Mode Oracle and objective gate** evaluate the new observation and determine the final
   disposition.

For an exact replay, PAJIN should derive `ReplayIntent` deterministically from the trusted Plan and
original Tool request. A Semantic Validator may recommend a typed intent or bounded comparison
criteria, but it cannot emit a raw `ToolRequest`, command, process path, arbitrary URL, Capability
Grant, or executable code.

### Replay binding and authority

The Replay Compiler must bind all of the following before PAJIN issues a Grant:

- Candidate ID, original Run ID, target ID, Tool ID, scenario ID, and threat class;
- the exact original operation and allowlisted arguments, with secrets represented only by leases;
- Campaign Scope, deny rules, risk tier, expiry, call budget, and cancellation state;
- session reset or preserved preconditions defined by the Mode contract; and
- the expected typed observation and Oracle contract.

The Reproducer cannot reuse the Specialist Grant. It receives a new, shorter-lived Grant limited to
the compiled target and operation. It cannot broaden the target, choose a new Tool, add attack
steps, or follow instructions found in evidence. Every replay produces a new request ID, audit
events, and evidence records linked to both the Candidate and original request.

Automatic replay is limited to operations that explicitly opt in as replay-safe and idempotent and
that remain within T0-T2. T3/T4, non-idempotent, destructive, ambiguous, or unregistered operations
require an approved future manual-reproduction contract and cannot run automatically.

### Disposition rules

| Condition | Disposition | Required reason |
| --- | --- | --- |
| Semantic support and objective gate pass, but replay has not run or is not implemented | `needs-review` | `independent-reproduction-missing` |
| Operation is not replay-safe or requires approval | `needs-review` | `replay-not-eligible` or `replay-approval-required` |
| Replay is cancelled, times out, is rate-limited, the target is unavailable, or a non-deterministic miss cannot decide the claim | `inconclusive` | bounded execution reason |
| Replay Oracle supports the claim, the objective gate passes, and Semantic Validator support exists when required by the Mode | `confirmed` | successful ReplayOutcome reference |
| Scope, provenance, identity, or evidence binding fails | `rejected-objective` | objective gate reason |
| A typed Oracle deterministically contradicts the exact claim | `rejected-objective` | Mode Oracle reason |

A single negative replay does not prove rejection when the Mode declares the behavior stochastic.
The Mode contract must define repetition count, threshold, session policy, and comparison rules. An
unexplained or non-deterministic mismatch is `inconclusive` or `needs-review`, not an objective
rejection.

`findings.json` remains a compatibility projection, but only Decisions satisfying this ADR may
enter it after migration. Candidate preservation, duplicate triage, reporting state, and retest
state remain separate concerns.

### Human reproduction

Human review cannot change a Candidate directly to `confirmed`. A future manual reproduction path
may confirm a Candidate only if it emits the same typed `ReplayOutcome`, request and evidence
provenance, actor identity, approval record, and Oracle result required of automated replay.

## Mode boundaries

- **KISA AI Red Team:** `ai.chat-probe` is designated as the first restricted-replay vertical slice.
  Reproduction must use the exact catalog scenario and target, a new request identity, a new session where the
  scenario requires isolation, and a separate evidence lineage. The Producer still ignores Worker
  verdict fields and independently recomputes catalog checks.
- **Bug Bounty:** an existing deterministic control-set Oracle satisfies this ADR only when it
  evaluates a distinct reproduction execution and evidence lineage. Re-reading the original
  Specialist result is not reproduction.
- **CTF:** flag and artifact digest solve validation remains a Mode-specific solve state, not a
  security Finding confirmation. This ADR does not add LLM replay to CTF.

## Current implementation gap and migration

As of 2026-07-15, PAJIN implements Candidate admission, semantic reconciliation, objective evidence
gating, Decision snapshots, and final Run sealing. It does not implement `ReplayIntent` compilation,
a replay-specific Grant, Restricted Reproducer execution, or `ReplayOutcome` artifacts.

The current ADR 0025/0026 compatibility path can write `confirmed` after semantic support and the
objective gate alone. This is a known product-baseline violation, not a new product decision. Until
the code is migrated, such output must be treated as **legacy semantic confirmation**, not
product-level Confirmed.

Migration proceeds in this order:

1. prevent semantic-only Decisions from entering the confirmed compatibility projection and retain
   them as `needs-review` with `independent-reproduction-missing`;
2. add typed `ReplayIntent`, compiled replay specification, replay Grant, and `ReplayOutcome`
   contracts with Candidate and request lineage;
3. implement the KISA `ai.chat-probe` restricted-replay vertical slice and Mode Oracle;
4. require a successful ReplayOutcome in the common confirmation gate;
5. version external artifacts and reports so consumers can distinguish legacy semantic
   confirmation from reproduction-backed confirmation; and
6. add eligible Mode contracts incrementally without introducing a generic replay predicate.

Existing sealed Runs are immutable and must not be rewritten. A historical `confirmed` Decision
without a ReplayOutcome is interpreted under legacy semantics and cannot be promoted by
reinterpretation; it must be reproduced in a new Run.

## Consequences

- PAJIN preserves the value of semantic review while restoring independent reproduction as the
  confirmation boundary.
- The LLM does not receive general offensive execution authority; the Reproducer gets only a
  compiled, candidate-bound Grant.
- Confirmed output will temporarily decrease until restricted replay is implemented, which is an
  intentional fail-closed result.
- Replay adds target effects, latency, cost, evidence volume, and non-determinism management.
- Unsafe or non-idempotent Candidates require a separately designed approval and manual
  reproduction path.

## Validation requirements

Implementation is complete only when tests prove that:

- semantic agreement plus an objective gate cannot create a confirmed projection;
- no Candidate becomes confirmed without a fresh replay request and Candidate-bound evidence;
- executable model output and model-authored Tool requests are rejected;
- out-of-scope, out-of-grant, target, Tool, scenario, Candidate, and evidence substitution fail
  closed;
- T3/T4, non-idempotent, destructive, and non-opted-in operations do not replay automatically;
- cancellation, timeout, target unavailability, and non-deterministic misses preserve the Candidate
  as `inconclusive` or `needs-review` according to the disposition table;
- only a successful typed Oracle result plus the objective gate, and Semantic Validator support
  where required by the Mode, creates `confirmed`;
- Local and Multi-Agent runners enforce the same confirmation rule;
- KISA reports and `findings.json` distinguish legacy and reproduction-backed confirmation; and
- migration does not rewrite historical Run seals.

## References

- [PAJIN Product Plan](../PAJIN_PRODUCT_PLAN.md)
- [ADR 0002: Tool Gateway and Worker isolation](0002-tool-gateway-and-worker-isolation.md)
- [ADR 0004: Dynamic multi-agent execution](0004-dynamic-multi-agent-execution.md)
- [ADR 0009: Provider-backed Agent Runtime](0009-provider-backed-agent-runtime.md)
- [ADR 0016: Tamper-evident Run integrity](0016-tamper-evident-run-integrity.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
- [ADR 0025: Candidate validation ledger and replay boundary](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR 0026: Trusted KISA candidate admission](0026-trusted-kisa-candidate-admission.md)
