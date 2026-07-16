# ADR 0027: Independent restricted reproduction as the confirmation boundary

- Status: Accepted
- Date: 2026-07-15
- Amended: 2026-07-16 — M6-05 baseline-bound negative KISA retest 경계 추가
- Implementation: In progress; restricted replay, the receipt-reloading common confirmation/retest
  gates, append-only versioned validation projections, exact KISA fresh-session integration, and
  baseline-bound negative KISA retest are implemented, while durable ticket verification and
  additional Modes remain planned
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

### Retest invariant

이미 reproduction-backed `confirmed`가 된 Finding의 수정 여부는 confirmation disposition을
다시 쓰지 않고 별도의 retest lifecycle 결과로 기록한다. confirmation Gate에서 typed Oracle의
`contradicts`는 Candidate의 objective rejection 근거지만, sealed Confirmed baseline에 정확히
결박된 Retest Gate에서 verified `contradicts`는 `fixed` 근거다. 과거 Confirmed Decision과
Finding은 immutable history로 남으며 `rejected-objective`로 재해석하지 않는다.

Retest Gate는 다음 조건을 모두 요구한다.

1. baseline은 sealed `validation/v1alpha1`의 reproduction-backed Confirmed Decision/Finding과
   canonical receipt lineage를 가져야 한다. legacy flat Finding, semantic-only Candidate,
   unreproduced historical confirmation은 허용하지 않는다.
2. retest proof는 exact Candidate, source Decision, versioned Finding, remediation action,
   baseline/retest Run과 integrity root, original/replay request, Mode, scenario, threat, Tool,
   target을 결박한다. 표시용 fingerprint나 mutable in-memory record는 이 결박을 대신하지 않는다.
3. normal parent retest는 정상 기능 probe와 regression을 담당한다. baseline 취약점 상태는
   별도의 Candidate-bound Restricted Replay 공격 Run과 verified canonical receipt만 판정한다.
4. 모든 계약상 반복이 성공하고 retest 목적의 trusted negative Oracle이 원 claim에 대해
   `ReplayOracleVerdict.CONTRADICTS`를 반환할 때만 `fixed`다. verified
   `ReplayOracleVerdict.SUPPORTS`는 `still-vulnerable`이다.
5. support와 contradiction이 섞이거나, terminal outcome·반복 부족·명시적 방어 증적 부재가
   발생하면 `inconclusive`다. Candidate나 artifact 결박·무결성 불일치는 lifecycle 상태로
   축소하지 않고 Gate 전체를 fail closed로 거부한다.
6. 정상 기능 regression은 개별 Finding 상태와 독립적이다. `kisa-retest`의 범위 한정 성공은
   모든 baseline Finding이 `fixed`, unresolved와 실행 중 관찰된 new Finding이 없고 regression이
   `pass`일 때만 가능하다. 이 경계는 baseline 폐루프이며 신규 위협 유형은 평가하지 않는다.
   release Gate는 현재 실행 가능한 시나리오의 별도 fresh discovery Run을 요구하며, 미구현
   위협은 계속 `not assessed`다.

기존 positive confirmation Oracle의 의미는 바꾸지 않는다. zero support, non-match 또는
`supports_claim == false`는 계속 `inconclusive`일 수 있으며 negative 증명과 동치가 아니다.
Worker-authored `vulnerable=false`나 단순 compromise marker 부재도 `fixed` 근거가 아니다. 오직
전체 기대 반복의 canonical observation에서 명시적인 방어 결과를 검증하도록 등록된 trusted
negative Oracle만 `contradicts`를 만들 수 있다.

The first KISA negative predicates are deliberately narrow: exact deterministic-lab defense
responses registered for M03, M06, and both A04 turns, plus the absence of compromise markers,
tool calls, and memory writes. `safety.blocked` or its reason is not an independent contradiction
signal, and metadata inconsistent with the registered response fails closed. Unknown target wording
remains `inconclusive` until a separately reviewed predicate or trusted policy-enforcement receipt
is registered.

### Human reproduction

Human review cannot change a Candidate directly to `confirmed`. A future manual reproduction path
may confirm a Candidate only if it emits the same typed `ReplayOutcome`, request and evidence
provenance, actor identity, approval record, and Oracle result required of automated replay.

## Mode boundaries

- **KISA AI Red Team:** `ai.chat-probe` is designated as the first restricted-replay vertical slice.
  Reproduction must use the exact catalog scenario and target, a new request identity, a new session where the
  scenario requires isolation, and a separate evidence lineage. The Producer still ignores Worker
  verdict fields and independently recomputes catalog checks. Hardened retest는 normal parent Run과
  baseline-bound 공격 Replay를 분리하고, exact M03·M06·A04 baseline Candidate의 모든 기대 반복을
  trusted negative Oracle이 명시적으로 반증한 verified receipt만 `fixed`로 소비한다.
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
lineage.

M6-05의 `kisa-retest` 경로는 sealed versioned Confirmed baseline을 다시 검증하고 각 Finding의
Candidate, source Decision, remediation action과 모든 authority-bearing identity에 결박된 별도
Restricted Replay를 실행한다. normal parent retest의 정상 기능 결과는 negative proof로
재사용하지 않는다. Retest Gate는 replay Run의 canonical receipt를 다시 열어 trusted negative
Oracle이 모든 기대 반복을 `contradicts`했을 때만 `fixed`를 기록하고, `supports`는
`still-vulnerable`, mixed/terminal/증명 부족은 `inconclusive`로 닫는다. 결박이나 seal 불일치는
hard fail한다. remediation plan과 event는 versioned projection과 기존 seal entry를 덮어쓰지
않고 baseline에 append하며, retest는 그 뒤 확정된 current root를 receipt에 결박한다. 결박 후
baseline이 달라지면 Gate는 결과를 만들지 않는다.

Durable ticket verification across process restarts, Local/Control Plane replay orchestration, and
additional Mode integrations remain follow-up work. A CPU-bound production Oracle must still use a
separately bounded execution boundary instead of blocking the cooperative async runtime.

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
   confirmation;
8. **Implemented for M6-05 KISA retest:** accept only sealed reproduction-backed baselines, separate
   normal parent regression from baseline-bound attack replay, reload verified negative receipts,
   and require an all-repetition trusted `contradicts` verdict before `fixed`; and
9. add eligible Mode contracts incrementally without introducing a generic replay predicate.

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
- `fixed`도 fail-closed이며 baseline-bound Retest Gate가 verified canonical negative receipt를
  소비할 때만 생성된다. baseline의 과거 confirmation은 append-only retest 관계와 분리된다.
- 정상 기능 regression과 취약점 상태를 분리해 원 취약점이 수정됐더라도 기능 회귀가 있는
  실행을 전체 성공으로 보고하지 않는다.
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
  confirmation;
- migration does not rewrite historical Run seals;
- KISA retest가 legacy flat·semantic-only·미확정 baseline을 거부하고 sealed
  `validation/v1alpha1` Confirmed baseline만 소비한다;
- exact Candidate/Decision/Finding/remediation/baseline·retest Run/root/request/scenario/threat/
  Tool/target substitution과 receipt·seal 변조가 hard fail한다;
- 모든 기대 반복의 trusted negative Oracle verdict가 `contradicts`일 때만 `fixed`이고,
  `supports`는 `still-vulnerable`, mixed·terminal·반복 부족·증적 부재는 `inconclusive`다;
- positive Oracle의 zero-support와 Worker-authored negative flag가 `fixed`를 만들지 못한다;
- normal parent regression과 baseline-bound attack replay가 분리되고, regression 실패는 Finding
  상태를 덮어쓰지 않지만 CLI 성공을 차단한다; and
- remediation plan append가 versioned baseline projection과 기존 seal entry를 덮어쓰지 않고 새
  current root를 만들며, retest가 그 root와 outcome·request·evidence·receipt lineage를 정확히
  결박해 append-only로 봉인한다.

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
source artifacts, and reproduction-backed KISA projection. `tests/test_kisa_retest.py` and
`tests/test_kisa_retest_cli.py` cover the M6-05 sealed baseline admission, exact retest binding,
negative/supporting/mixed/terminal disposition matrix, canonical receipt reloading, forged negative
signal rejection, parent regression separation, immutable baseline, and CLI Exit Gate. The
remaining requirements apply to durable/offline ticket verification, Local and Control Plane replay
orchestration, and additional explicitly opted-in Mode contracts.

## References

- [PAJIN Product Plan](../PAJIN_PRODUCT_PLAN.md)
- [ADR 0002: Tool Gateway and Worker isolation](0002-tool-gateway-and-worker-isolation.md)
- [ADR 0004: Dynamic multi-agent execution](0004-dynamic-multi-agent-execution.md)
- [ADR 0009: Provider-backed Agent Runtime](0009-provider-backed-agent-runtime.md)
- [ADR 0016: Tamper-evident Run integrity](0016-tamper-evident-run-integrity.md)
- [ADR 0024: Cooperative execution cancellation](0024-cooperative-execution-cancellation.md)
- [ADR 0025: Candidate validation ledger and replay boundary](0025-candidate-validation-ledger-and-replay-boundary.md)
- [ADR 0026: Trusted KISA candidate admission](0026-trusted-kisa-candidate-admission.md)
