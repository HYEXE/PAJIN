# ADR 0027: Independent restricted reproduction as the confirmation boundary

- Status: Accepted
- Date: 2026-07-15
- Implementation: In progress; restricted replay, the receipt-reloading common gate, append-only
  versioned validation projections, and exact KISA fresh-session integration are implemented, while
  durable ticket verification, baseline-bound negative retest, and additional Modes remain planned
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
gating, Decision snapshots, final Run sealing, and the first fail-closed migration step. Semantic
support without ReplayOutcome is retained as `needs-review` with
`independent-reproduction-missing` and is excluded from `findings.json`. PAJIN also defines strict,
versioned `ValidationPacket`, `ReplayIntent`, `ModeReplayContract`, `CompiledReplaySpec`,
`ReplayAttempt`, `ReplayOracleResult`, and `ReplayOutcome` contracts. The contracts bind Candidate,
Run, original and replay request, Mode, scenario, Tool, target, and threat identities; reject
executable intent fields and cross-artifact substitution; and give `ValidationDecision` an explicit
ReplayOutcome reference. `ai.chat-probe` Tool interpretation, trusted Candidate production, and
deterministic validation share the same strict `AIChatProbeOutput` contract while recomputing rather
than trusting Worker verdict fields.

PAJIN also implements a pure deterministic `ReplayCompiler`. It checks the trusted Plan, the actual
Specialist-bound `ToolRequest`, the original Specialist Grant, Candidate evidence, trusted request
and evidence digests, registered Scenario and Tool contracts, Scope, cancellation, authorization,
and remaining repetition budget. It copies only allowlisted original arguments, rejects
secret-bearing fields and known plaintext secret values, and emits a separate five-minute-or-less,
non-delegable, single-Tool, single-target `ReplayCapabilityGrant`. Compiler IDs are deterministic
over the authority-bearing inputs, while Semantic Validator rationale and comparison text cannot
alter the compiled operation.

PAJIN now implements a Restricted Reproducer foundation for stateless operations and explicitly
registered Mode-owned materializers. The Compiler issues
an opaque, single-use ticket bound to the Candidate source seal, Campaign, Tool specification, and
Scenario digest. The runtime atomically claims the ticket, rechecks trusted inputs, executes exact
compiled arguments through the existing Tool Gateway and Worker, and consumes shared Campaign
budget and rate-limit state. Campaign duration and cancellation bound both dispatch and the async
Mode Oracle, while Tool-authored Secret Lease requests fail closed. The runtime accepts only fresh
request evidence whose JSON provenance exactly matches the Gateway and Worker result. A successful
or terminal replay is stored in a distinct replay Run; an initial seal binds the outcome and artifact
set, and a second seal binds a verified receipt that references the first root. A dedicated loader
reopens the Run, verifies both seal roots and canonical artifact digests, and checks ticket-ledger
finalization against the originally issued compilation digest, Candidate source root, and replay Run
instead of trusting a mutable in-memory result. Session-bearing contracts fail closed as
`unsupported` unless an exact trusted Mode session materializer is registered.

The `kisa-run` Multi-Agent path verifies a sealed source Run and coordinates exact M03, M06,
and A04 `ai.chat-probe` Candidates in separate replay Runs. These three scenarios are explicitly
allowlisted; a structural predicate cannot opt future scenarios into automatic replay. The trusted
materializer changes only `session_id`, the Gateway charges every chat turn against the Campaign
request-rate ledger, and the live Oracle recomputes catalog checks from the raw transcript without
trusting Worker verdict flags. After replay, the common gate accepts only replay Run paths, reloads
each twice-sealed receipt with the ticket verifier, checks source-seal membership and exact Candidate
binding, and applies the shared reason matrix. It appends `validation/v1alpha1` Decision, Finding,
index, and Markdown artifacts in a new seal instead of rewriting the flat pre-replay snapshot. The
KISA assessment and replay index consume that projection and expose confirmation basis and receipt
lineage. Durable ticket verification across process restarts, baseline-bound negative retest proof,
Local/Control Plane replay orchestration, and additional Mode integrations remain follow-up work. A
CPU-bound production Oracle must still use a separately bounded execution boundary instead of
blocking the cooperative async runtime.

Migration proceeds in this order:

1. **Implemented:** prevent semantic-only Decisions from entering the confirmed compatibility
   projection and retain them as `needs-review` with `independent-reproduction-missing`;
2. **Implemented at the schema boundary:** add typed `ValidationPacket`, `ReplayIntent`, Mode
   contract, compiled replay specification, attempts, Oracle result, and `ReplayOutcome` contracts
   with Candidate and request lineage;
3. **Implemented at the pure compilation boundary:** add the deterministic Replay Compiler and
   replay-specific Capability Grant with fail-closed policy and lineage checks;
4. **Implemented at the standalone runtime boundary:** add opaque single-use tickets, stateless and
   registered-materializer Gateway/Worker execution, fresh evidence provenance, shared
   budget/rate/cancellation controls,
   bounded async Oracle dispatch, Secret Lease denial, distinct outcomes, and a twice-sealed replay
   receipt with a ticket-bound verified loader;
5. **Implemented at the KISA replay boundary:** add the exact M03, M06, and A04
   `ai.chat-probe` fresh-session driver, raw-transcript live Mode Oracle, sealed source/replay
   coordinator, and verified replay index;
6. **Implemented for the common gate and KISA path:** require a verified ReplayOutcome receipt,
   reloaded from its replay Run, before a Decision can become reproduction-backed `confirmed`;
7. **Implemented as an append-only v1alpha1 projection:** version Decisions, Findings, index, and
   report so consumers can distinguish legacy semantic confirmation from reproduction-backed
   confirmation; and
8. add eligible Mode contracts incrementally without introducing a generic replay predicate.

Existing sealed Runs are immutable and must not be rewritten. A historical `confirmed` Decision
without a ReplayOutcome is interpreted under legacy semantics and cannot be promoted by
reinterpretation; it must be reproduced in a new Run.

## Consequences

- PAJIN preserves the value of semantic review while restoring independent reproduction as the
  confirmation boundary.
- The LLM does not receive general offensive execution authority; the Reproducer gets only a
  compiled, candidate-bound Grant.
- Confirmed output remains fail-closed and is emitted only when the common gate consumes verified
  receipts; additional Modes require their own explicit replay integrations.
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
- KISA reports and versioned Finding artifacts distinguish legacy and reproduction-backed
  confirmation; and
- migration does not rewrite historical Run seals.

The schema-boundary regression suites are `tests/test_replay_models.py` and
`tests/test_ai_chat_contracts.py`. The compiler boundary is covered by
`tests/test_replay_compiler.py`, and `tests/test_replay_runtime.py` covers single-use and concurrent
ticket claims, stateless and registered fresh-session dispatch, fresh request/evidence provenance,
substitution rejection,
shared budget/rate limits, child cancellation, dispatch/Oracle deadlines, Tool-authored Secret
Lease denial, timeout and unavailable outcomes, typed Oracle binding, mutable-memory substitution,
distinct replay storage, issued-compilation-bound ticket finalization, and twice-verified seals.
Together they cover executable intent
rejection, version and legacy-read policy, replay eligibility metadata, duplicate and same-request
rejection, Candidate/Run/target/scenario/Tool/argument/evidence/Grant substitution,
confused-deputy inputs, Scope·budget·authorization·cancellation checks, shared Tool/Producer output
typing, and untrusted verdict flags. `tests/test_confirmation_gate.py` fixes the common disposition
matrix for supporting, contradicting, inconclusive, failed, cancelled, timed-out, unavailable, and
unsupported ReplayOutcomes. Versioned-artifact tests cover fail-closed legacy separation and fixed
paths. `tests/test_kisa_replay.py` additionally covers the explicit
three-scenario opt-in, fresh and unique sessions, raw-transcript recomputation, multi-turn request
rate accounting, mutable record rejection, sealed source-state binding, receipt reloading, immutable
source artifacts, and reproduction-backed KISA projection. The remaining requirements apply to
baseline-bound negative KISA retest, durable/offline ticket verification, Local and Control Plane
replay orchestration, and additional explicitly opted-in Mode contracts.

## References

- [PAJIN Product Plan](../PAJIN_PRODUCT_PLAN.md)
- [ADR 0002: Tool Gateway and Worker isolation](0002-tool-gateway-and-worker-isolation.md)
- [ADR 0004: Dynamic multi-agent execution](0004-dynamic-multi-agent-execution.md)
- [ADR 0009: Provider-backed Agent Runtime](0009-provider-backed-agent-runtime.md)
- [ADR 0016: Tamper-evident Run integrity](0016-tamper-evident-run-integrity.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
- [ADR 0025: Candidate validation ledger and replay boundary](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR 0026: Trusted KISA candidate admission](0026-trusted-kisa-candidate-admission.md)
