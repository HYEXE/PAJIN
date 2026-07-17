> Languages: [English](0027-independent-reproduction-confirmation-boundary.en.md) | [한국어](0027-independent-reproduction-confirmation-boundary.ko.md)

# ADR 0027: 확인 경계로서의 독립적인 제한적 재현

- 상태: 승인됨
- 날짜: 2026-07-15
- 개정: 2026-07-16 — M6-05 negative KISA retest와 M6-07A 명시적 Local KISA orchestration 경계 추가
- 구현: 진행 중. 제한적 replay, receipt를 다시 로드하는 공통 확인/retest Gate,
  append-only 버전형 validation projection, 정확한 KISA fresh-session 통합,
  baseline-bound negative KISA retest, 영속적 Local SQLite ticket 검증, 명시적인
  단일 프로세스 Local KISA orchestration은 구현되었으며, Control Plane orchestration과
  추가 Mode는 계획 상태
- 개정 대상: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.ko.md), [ADR 0026](0026-trusted-kisa-candidate-admission.ko.md)
- 명확히 하는 문서: [ADR 0004](0004-dynamic-multi-agent-execution.ko.md)
- 제품 기준선: [PAJIN 제품 계획](../PAJIN_PRODUCT_PLAN.ko.md)

## 맥락

제품 기준선은 PAJIN이 Candidate를 confirmed로 보고하기 전에 이를 재현하고 독립적으로
검증하도록 요구한다. 기존 transcript를 다른 prompt나 model로 검토하면 근거 없는 주장과
의미론적 오류를 발견할 수 있지만, 그 동작을 재현할 수 있다는 사실까지 증명하지는 못한다.
단 한 번의 실행에 대한 의미론적 합의는 증거 검토이지 독립적 재현이 아니다.

ADR 0025는 Candidate와 Decision ledger를 도입했고, ADR 0026은 신뢰할 수 있는 KISA Candidate
입장을 추가했다. 두 경계는 모두 여전히 필요하다. 그러나 두 ADR의 과도기적 확인 규칙은
일치하는 Semantic Validator 결과와 객관적 evidence Gate만으로 두 번째 실행 없이
`confirmed`를 만들 수 있게 한다. 이 규칙은 제품 기준선과 충돌한다.

LLM Validator에 범용 공격 Tool을 부여해도 이 충돌을 안전하게 바로잡을 수 없다. 그렇게 하면
신뢰할 수 없는 증거와 model 출력이 실행 가능한 command, target, argument, Capability에
영향을 줄 수 있다. 따라서 독립적 재현에는 별도의 제약된 실행 경계가 필요하다.

## 결정

### 확인 불변 조건

Candidate가 제품 수준의 `confirmed`가 되려면 적용 가능한 다음 조건을 모두 충족해야 한다.

1. 신뢰할 수 있는 producer나 compatibility adapter가 한정된 provenance와 함께 Candidate를
   입장시킨다.
2. 객관적인 Scope, target, request, evidence Gate를 통과한다.
3. 별도의 재현 실행이 해당 Candidate에 결박된 성공적인 `ReplayOutcome`을 만든다.
4. 재현은 새로운 request identity와 별개의 evidence lineage를 사용한다.
5. Mode 소유의 typed Oracle이 재현 관찰로부터 정확한 주장을 뒷받침한다.
6. Mode가 의미론적 해석이 필요하다고 선언한 경우 Semantic Validator도 주장을 뒷받침한다.

의미론적 지지, 원본 증거의 강도, producer 입장, Specialist의 반복 관찰 또는 사람의 확신은
성공적인 독립 `ReplayOutcome`을 대신할 수 없다.

### Validator는 하나의 LLM Agent가 아니라 파이프라인이다

제품 수준의 Validator는 다음과 같이 분리된 역할로 구성된다.

1. **Candidate Producer**는 typed Mode contract에서 관찰을 입장시킨다. Provider, Tool,
   process 또는 replay 권한은 없다.
2. **Semantic Validator**는 범위가 제한되고 민감 정보가 제거된 Validation Packet을 받아 주장,
   증거, 영향, 재현 조건을 평가한다. 실행 가능한 유일한 기능은 자체 Provider 호출이다.
3. **Replay Compiler**는 실행 불가능한 typed `ReplayIntent`를 Candidate, 원본 Specialist
   request, 등록된 Mode scenario, allowlist된 Tool template에 맞춰 해석한다.
4. **Restricted Reproducer**는 전용 replay Grant를 받아 일반 Tool Gateway와 Worker 경계를
   통해 compile된 operation을 실행한다.
5. **Mode Oracle과 objective Gate**는 새 관찰을 평가하고 최종 disposition을 결정한다.

정확한 replay의 경우 PAJIN은 신뢰할 수 있는 Plan과 원본 Tool request에서 `ReplayIntent`를
결정론적으로 파생해야 한다. Semantic Validator는 typed intent나 한정된 comparison criteria를
권고할 수 있지만, raw `ToolRequest`, command, process path, 임의 URL, Capability Grant 또는
실행 가능 code를 내보낼 수 없다.

### Replay 결박과 권한

Replay Compiler는 PAJIN이 Grant를 발급하기 전에 다음 항목을 모두 결박해야 한다.

- Candidate ID, 원본 Run ID, target ID, Tool ID, scenario ID, threat class
- 정확한 원본 operation과 allowlist된 argument. secret은 lease로만 표현한다.
- Campaign Scope, deny rule, risk tier, expiry, call budget, cancellation state
- Mode contract가 정의한 session reset 또는 유지된 precondition
- 예상 typed observation과 Oracle contract

Reproducer는 Specialist Grant를 재사용할 수 없다. compile된 target과 operation으로 제한되며
더 짧은 수명을 가진 새로운 Grant를 받는다. target 범위를 넓히거나 새 Tool을 선택하거나 공격
단계를 추가하거나 증거에서 발견한 지시를 따를 수 없다. 모든 replay는 새 request ID, audit
event, Candidate와 원본 request 양쪽에 연결된 evidence record를 만든다.

자동 replay는 replay-safe 및 idempotent로 명시적으로 opt-in하고 T0-T2 범위에 계속 머무는
operation으로 제한된다. T3/T4, non-idempotent, destructive, ambiguous 또는 등록되지 않은
operation은 승인된 향후 manual-reproduction contract가 필요하며 자동으로 실행할 수 없다.

### Disposition 규칙

| 조건 | Disposition | 필수 사유 |
| --- | --- | --- |
| 의미론적 지지와 objective Gate는 통과했지만 replay가 실행되지 않았거나 구현되지 않음 | `needs-review` | `independent-reproduction-missing` |
| operation이 replay-safe가 아니거나 승인이 필요함 | `needs-review` | `replay-not-eligible` 또는 `replay-approval-required` |
| replay가 취소되거나, timeout·rate limit이 발생하거나, target을 사용할 수 없거나, non-deterministic miss로 주장을 판정할 수 없음 | `inconclusive` | 한정된 실행 사유 |
| Replay Oracle이 주장을 뒷받침하고 objective Gate를 통과하며, Mode가 요구할 때 Semantic Validator 지지도 존재함 | `confirmed` | 성공적인 ReplayOutcome 참조 |
| Scope, provenance, identity 또는 evidence 결박 실패 | `rejected-objective` | objective Gate 사유 |
| typed Oracle이 정확한 주장을 결정론적으로 반박함 | `rejected-objective` | Mode Oracle 사유 |

Mode가 동작을 stochastic이라고 선언한 경우 한 번의 negative replay만으로 rejection을 증명할
수 없다. Mode contract는 repetition count, threshold, session policy, comparison rule을
정의해야 한다. 설명할 수 없거나 non-deterministic한 불일치는 objective rejection이 아니라
`inconclusive` 또는 `needs-review`다.

`findings.json`은 compatibility projection으로 남지만, 마이그레이션 후에는 이 ADR을 충족하는
Decision만 그 안에 들어갈 수 있다. Candidate 보존, duplicate triage, reporting state,
retest state는 계속 별개의 관심사로 남는다.

### Retest 불변 조건

이미 reproduction-backed `confirmed`가 된 Finding의 수정 여부는 confirmation disposition을
다시 쓰지 않고 별도의 retest lifecycle 결과로 기록한다. confirmation Gate에서 typed Oracle의
`contradicts`는 Candidate의 objective rejection 근거지만, sealed Confirmed baseline에 정확히
결박된 Retest Gate에서 verified `contradicts`는 `fixed`의 근거다. 과거 Confirmed Decision과
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
4. 모든 contract상 반복이 성공하고 retest 목적의 trusted negative Oracle이 원 claim에 대해
   `ReplayOracleVerdict.CONTRADICTS`를 반환할 때만 `fixed`다. verified
   `ReplayOracleVerdict.SUPPORTS`는 `still-vulnerable`이다.
5. support와 contradiction이 섞이거나, terminal outcome·반복 부족·명시적 방어 증적 부재가
   발생하면 `inconclusive`다. Candidate나 artifact 결박·무결성 불일치는 lifecycle 상태로
   축소하지 않고 Gate 전체를 fail closed로 거부한다.
6. 정상 기능 regression은 개별 Finding 상태와 독립적이다. `kisa-retest`의 범위 한정 성공은
   모든 baseline Finding이 `fixed`이고, unresolved Finding과 실행 중 관찰된 new Finding이
   없으며 regression이 `pass`일 때만 가능하다. 이 경계는 baseline 폐루프이며 신규 위협 유형은
   평가하지 않는다. release Gate는 현재 실행 가능한 scenario의 별도 fresh discovery Run을
   요구하며, 미구현 위협은 계속 `not assessed`다.

기존 positive confirmation Oracle의 의미는 바꾸지 않는다. zero support, non-match 또는
`supports_claim == false`는 계속 `inconclusive`일 수 있으며 negative 증명과 동치가 아니다.
Worker가 작성한 `vulnerable=false`나 단순히 compromise marker가 없다는 사실도 `fixed`의
근거가 아니다. 전체 예상 반복의 canonical observation에서 명시적인 방어 결과를 검증하도록
등록된 trusted negative Oracle만 `contradicts`를 만들 수 있다.

최초 KISA negative predicate는 의도적으로 좁게 한정한다. M03, M06, A04의 두 turn에 등록된
정확한 deterministic-lab 방어 response와 compromise marker, Tool call, memory write의 부재만
포함한다. `safety.blocked` 또는 그 reason은 독립적인 contradiction signal이 아니며, 등록된
response와 일치하지 않는 metadata는 fail closed된다. 알 수 없는 target 문구는 별도로 검토된
predicate나 신뢰할 수 있는 policy-enforcement receipt가 등록될 때까지 `inconclusive`로 남는다.

### 사람에 의한 재현

사람의 검토만으로 Candidate를 `confirmed`로 직접 변경할 수 없다. 향후 manual reproduction
경로가 Candidate를 확인하려면 자동 replay에 요구되는 것과 동일한 typed `ReplayOutcome`,
request 및 evidence provenance, actor identity, approval record, Oracle result를 내보내야 한다.

## Mode 경계

- **KISA AI Red Team:** `ai.chat-probe`는 최초의 제한적 replay vertical slice로 지정된다.
  재현은 정확한 catalog scenario와 target, 새로운 request identity, scenario가 격리를 요구할
  경우 새 session, 별도의 evidence lineage를 사용해야 한다. Producer는 계속 Worker verdict
  field를 무시하고 catalog check를 독립적으로 다시 계산한다. Hardened retest는 normal parent
  Run과 baseline-bound 공격 Replay를 분리하고, exact M03·M06·A04 baseline Candidate의 모든
  예상 반복을 trusted negative Oracle이 명시적으로 반증한 verified receipt만 `fixed`로
  소비한다.
- **Bug Bounty:** 기존 deterministic control-set Oracle이 이 ADR을 충족하려면 별개의 재현
  실행과 evidence lineage를 평가해야 한다. 원본 Specialist result를 다시 읽는 것은 재현이
  아니다.
- **CTF:** flag와 artifact digest를 통한 solve 검증은 Mode별 solve state로 남으며 보안 Finding
  확인이 아니다. 이 ADR은 CTF에 LLM replay를 추가하지 않는다.

## 현재 구현 격차 및 마이그레이션

2026-07-15 현재 PAJIN은 Candidate 입장, semantic reconciliation, objective evidence Gate,
Decision snapshot, 최종 Run sealing, 최초 fail-closed 마이그레이션 단계를 구현한다.
ReplayOutcome 없는 semantic support는 `independent-reproduction-missing` 사유와 함께
`needs-review`로 유지되며 `findings.json`에서 제외된다. PAJIN은 또한 strict versioned
`ValidationPacket`, `ReplayIntent`, `ModeReplayContract`, `CompiledReplaySpec`,
`ReplayAttempt`, `ReplayOracleResult`, `ReplayOutcome` contract를 정의한다. 이 contract들은
Candidate, Run, 원본 및 replay request, Mode, scenario, Tool, target, threat identity를
결박하고, 실행 가능한 intent field와 artifact 간 대체를 거부하며, `ValidationDecision`에
명시적인 ReplayOutcome 참조를 부여한다. `ai.chat-probe` Tool 해석, 신뢰할 수 있는 Candidate
생성, 결정론적 validation은 Worker verdict field를 신뢰하지 않고 다시 계산하면서 동일한
strict `AIChatProbeOutput` contract를 공유한다.

PAJIN은 pure deterministic `ReplayCompiler`도 구현한다. 이 Compiler는 신뢰할 수 있는 Plan,
실제 Specialist-bound `ToolRequest`, 원본 Specialist Grant, Candidate evidence, 신뢰할 수 있는
request 및 evidence digest, 등록된 Scenario와 Tool contract, Scope, cancellation,
authorization, 남은 repetition budget을 확인한다. allowlist된 원본 argument만 복사하고
secret-bearing field 및 알려진 plaintext secret 값을 거부하며, 5분 이하의 수명을 가진 별도의
non-delegable, single-Tool, single-target `ReplayCapabilityGrant`를 내보낸다. Compiler ID는
권한에 영향을 주는 입력에 대해 결정론적이며, Semantic Validator의 rationale과 comparison
text는 compile된 operation을 변경할 수 없다.

PAJIN은 이제 stateless operation과 명시적으로 등록된 Mode 소유 materializer를 위한
Restricted Reproducer 기반을 구현한다. Compiler는 Candidate source seal, Campaign, Tool
specification, Scenario digest에 결박된 opaque single-use ticket을 발급한다. runtime은 ticket을
원자적으로 claim하고 신뢰할 수 있는 입력을 다시 확인한 다음, 기존 Tool Gateway와 Worker를
통해 정확히 compile된 argument를 실행하고 공유 Campaign budget 및 rate-limit state를
소비한다. Campaign duration과 cancellation은 dispatch와 async Mode Oracle을 모두 제한하며,
Tool이 작성한 Secret Lease request는 fail closed된다. runtime은 JSON provenance가 Gateway 및
Worker result와 정확히 일치하는 fresh request evidence만 허용한다. 성공하거나 terminal인
replay는 별개의 replay Run에 저장된다. 첫 번째 seal은 outcome과 artifact set을 결박하고,
두 번째 seal은 첫 번째 root를 참조하는 verified receipt를 결박한다. 전용 loader는 Run을 다시
열고 두 seal root와 canonical artifact digest를 검증하며, mutable in-memory result를 신뢰하는
대신 원래 발급된 compilation digest, Candidate source root, replay Run에 대한 ticket-ledger
finalization을 확인한다. session-bearing contract는 정확하고 신뢰할 수 있는 Mode session
materializer가 등록되지 않으면 `unsupported`로 fail closed된다.

`kisa-run` Multi-Agent 경로는 sealed source Run을 검증하고 정확한 M03, M06, A04
`ai.chat-probe` Candidate를 각각 별개의 replay Run에서 조율한다. 이 세 scenario만 명시적으로
allowlist되며, structural predicate로 향후 scenario를 자동 replay 대상으로 opt-in할 수 없다.
신뢰할 수 있는 materializer는 `session_id`만 변경하고, Gateway는 모든 chat turn을 Campaign
request-rate ledger에 부과하며, live Oracle은 Worker verdict flag를 신뢰하지 않고 raw
transcript에서 catalog check를 다시 계산한다. replay 후 공통 Gate는 replay Run path만
허용하고, ticket verifier로 두 번 seal된 각 receipt를 다시 로드하며, source-seal membership과
정확한 Candidate 결박을 확인하고, 공유 reason matrix를 적용한다. flat pre-replay snapshot을
다시 쓰는 대신 새로운 seal에 `validation/v1alpha1` Decision, Finding, index, Markdown
artifact를 append한다. KISA assessment와 replay index는 이 projection을 소비하고 confirmation
basis 및 receipt lineage를 노출한다.

M6-07A는 operator가 `pajin run ... --kisa-replay`를 지정한 경우에만 동일한 exact allowlist와
공통 Gate를 일반 Local runner에 적용한다. Local source Run은 coordinator가 읽기 전에 먼저
capability, budget, request-rate snapshot과 completed state를 저장한 뒤 seal한다. source 실행과
replay는 동일한 live Campaign budget, request-rate ledger, cancellation context를 공유한다.
ticket은 안정적인 `<output>/local-replay/replay-tickets.sqlite3` authority를 사용하며, Gate
실행 전에 canonical receipt로 batch coverage를 검증한다. Candidate나 replay record가 누락되면
Gate를 실행하거나 confirmation을 만들지 않는다. flat `findings.json`은 sealed pre-replay
snapshot으로 남으며, append-only `validation/v1alpha1` projection만 reproduction-backed
Confirmed Finding을 추가할 수 있다. 이 경로는 의도적으로 단일 프로세스, 단일 writer로
제한한다. 기본 Local command에는 암묵적 replay, generic replay predicate, distributed lock,
lease 또는 PostgreSQL authority가 없다.

M6-05의 `kisa-retest` 경로는 sealed versioned Confirmed baseline을 다시 검증하고 각 Finding의
Candidate, source Decision, remediation action과 권한에 영향을 주는 모든 identity에 결박된
별도의 Restricted Replay를 실행한다. normal parent retest의 정상 기능 결과는 negative proof로
재사용하지 않는다. Retest Gate는 replay Run의 canonical receipt를 다시 열어 trusted negative
Oracle이 모든 예상 반복을 `contradicts`했을 때만 `fixed`를 기록하고, `supports`는
`still-vulnerable`, mixed/terminal/증명 부족은 `inconclusive`로 처리한다. 결박이나 seal
불일치는 hard fail한다. remediation plan과 event는 versioned projection과 기존 seal entry를
덮어쓰지 않고 baseline에 append하며, retest는 이후 확정된 current root를 receipt에 결박한다.
결박 후 baseline이 달라지면 Gate는 결과를 만들지 않는다.

프로세스 재시작을 견디는 영속적 Local SQLite ticket 검증과 명시적 Local KISA orchestration은
구현되었다. Control Plane replay orchestration과 추가 Mode 통합은 후속 작업으로 남는다.
Control Plane 작업은 sealed Artifact handoff, lease fencing, PostgreSQL batch/item/ticket/event
state, source-root CAS, 정확한 Gate finalization, 영속적 budget/request-rate state를 다루는
ADR 0029부터 시작해야 한다. Local absolute Run path나 임의의 Job result는 권한을 전달하는
handoff가 아니다. CPU-bound production Oracle도 cooperative async runtime을 차단하는 대신
별도로 제한된 실행 경계를 사용해야 한다.

마이그레이션은 다음 순서로 진행한다.

1. **구현 완료:** semantic-only Decision이 confirmed compatibility projection에 들어가지 못하게
   하고 `independent-reproduction-missing` 사유와 함께 `needs-review`로 유지한다.
2. **schema 경계에서 구현 완료:** typed `ValidationPacket`, `ReplayIntent`, Mode contract,
   compiled replay specification, attempt, Oracle result, Candidate 및 request lineage를 포함한
   `ReplayOutcome` contract를 추가한다.
3. **pure compilation 경계에서 구현 완료:** deterministic Replay Compiler와 fail-closed policy
   및 lineage check를 갖춘 replay 전용 Capability Grant를 추가한다.
4. **standalone runtime 경계에서 구현 완료:** opaque single-use ticket, stateless 및
   registered-materializer Gateway/Worker 실행, fresh evidence provenance, 공유
   budget/rate/cancellation control, 제한된 async Oracle dispatch, Secret Lease 거부, 별개의
   outcome, ticket-bound verified loader가 있는 두 번 seal된 replay receipt를 추가한다.
5. **KISA replay 경계에서 구현 완료:** 정확한 M03, M06, A04 `ai.chat-probe` fresh-session
   driver, raw-transcript live Mode Oracle, sealed source/replay coordinator, verified replay
   index를 추가한다.
6. **공통 Gate 및 KISA 경로에서 구현 완료:** Decision이 reproduction-backed `confirmed`가
   되기 전에 replay Run에서 다시 로드한 verified ReplayOutcome receipt를 요구한다.
7. **append-only v1alpha1 projection으로 구현 완료:** consumer가 legacy semantic confirmation과
   reproduction-backed confirmation을 구분할 수 있도록 Decision, Finding, index, report에
   version을 부여한다.
8. **M6-05 KISA retest에서 구현 완료:** sealed reproduction-backed baseline만 허용하고,
   normal parent regression을 baseline-bound attack replay와 분리하며, verified negative
   receipt를 다시 로드하고, 모든 반복에서 trusted `contradicts` verdict가 나와야만 `fixed`로
   판정한다.
9. **M6-06 Local durability에서 구현 완료:** KISA positive/negative replay ticket과 transition을
   안정적인 SQLite authority에 저장하고, 프로세스 재시작 후 read-only loader를 통해
   finalization을 검증한다.
10. **M6-07A 명시적 Local KISA orchestration에서 구현 완료:** complete Local source를 seal하고,
    live budget/rate/cancellation state를 공유하며, 정확히 allowlist된 Candidate replay를
    SQLite authority를 통해 실행하고, batch coverage를 검증하며, canonical replay receipt가
    있을 때만 공통 Gate를 호출한다.
11. generic replay predicate를 도입하지 않으면서 ADR 0029 이후 Control Plane orchestration과
    적격 Mode contract를 점진적으로 추가한다.

기존 sealed Run은 immutable이며 다시 써서는 안 된다. ReplayOutcome 없는 과거
`confirmed` Decision은 legacy semantics에 따라 해석되며 재해석만으로 승격할 수 없다. 새로운
Run에서 재현해야 한다.

## 결과

- PAJIN은 semantic review의 가치를 보존하면서 independent reproduction을 확인 경계로
  복원한다.
- LLM은 범용 offensive execution 권한을 받지 않는다. Reproducer는 compile되고
  Candidate-bound된 Grant만 받는다.
- confirmed 출력은 계속 fail-closed되며 공통 Gate가 verified receipt를 소비할 때만
  만들어진다. 추가 Mode에는 각자의 명시적 replay 통합이 필요하다.
- 일반 Local 실행은 계속 backward-compatible하다. replay 권한은 명시적인 KISA opt-in에
  대해서만 생성되며, 구현된 Local sequencing을 distributed Control Plane protocol로 간주할
  수 없다.
- `fixed`도 fail-closed이며 baseline-bound Retest Gate가 verified canonical negative receipt를
  소비할 때만 생성된다. baseline의 과거 confirmation은 append-only retest 관계와 분리된다.
- 정상 기능 regression과 취약점 상태를 분리해 원 취약점이 수정됐더라도 기능 회귀가 있는
  실행을 전체 성공으로 보고하지 않는다.
- replay는 target에 미치는 영향, latency, cost, evidence volume, non-determinism 관리 부담을
  추가한다.
- 안전하지 않거나 non-idempotent인 Candidate에는 별도로 설계된 approval 및 manual
  reproduction 경로가 필요하다.

## 검증 요구 사항

다음 사항이 test로 입증되어야만 구현이 완료된다.

- semantic agreement와 objective Gate만으로 confirmed projection을 만들 수 없다.
- fresh replay request와 Candidate-bound evidence 없이는 어떤 Candidate도 confirmed가 되지
  않는다.
- 실행 가능한 model 출력과 model이 작성한 Tool request가 거부된다.
- out-of-scope, out-of-grant, target, Tool, scenario, Candidate 및 evidence 대체가 fail
  closed된다.
- T3/T4, non-idempotent, destructive, opt-in하지 않은 operation은 자동 replay되지 않는다.
- cancellation, timeout, target unavailable, non-deterministic miss가 발생하면 disposition
  표에 따라 Candidate를 `inconclusive` 또는 `needs-review`로 유지한다.
- successful typed Oracle result와 objective Gate, 그리고 Mode가 요구하는 경우 Semantic
  Validator support가 모두 있어야만 `confirmed`가 생성된다.
- Local runner와 Multi-Agent runner가 동일한 확인 규칙을 적용한다.
- KISA report와 versioned Finding artifact가 legacy confirmation과 reproduction-backed
  confirmation을 구분한다.
- 마이그레이션이 과거 Run seal을 다시 쓰지 않는다.
- KISA retest가 legacy flat·semantic-only·미확정 baseline을 거부하고 sealed
  `validation/v1alpha1` Confirmed baseline만 소비한다.
- exact Candidate/Decision/Finding/remediation/baseline·retest Run/root/request/scenario/threat/
  Tool/target 대체와 receipt·seal 변조가 hard fail한다.
- 모든 예상 반복의 trusted negative Oracle verdict가 `contradicts`일 때만 `fixed`이고,
  `supports`는 `still-vulnerable`, mixed·terminal·반복 부족·증적 부재는 `inconclusive`다.
- positive Oracle의 zero-support와 Worker가 작성한 negative flag가 `fixed`를 만들지 못한다.
- normal parent regression과 baseline-bound attack replay가 분리되고, regression 실패는 Finding
  상태를 덮어쓰지 않지만 CLI 성공을 차단한다.
- remediation plan append가 versioned baseline projection과 기존 seal entry를 덮어쓰지 않고
  새 current root를 만들며, retest가 그 root와 outcome·request·evidence·receipt lineage를
  정확히 결박해 append-only로 봉인한다.

schema-boundary regression suite는 `tests/test_replay_models.py`와
`tests/test_ai_chat_contracts.py`다. compiler 경계는 `tests/test_replay_compiler.py`가
검증하며, `tests/test_replay_runtime.py`는 single-use 및 concurrent ticket claim, stateless 및
등록된 fresh-session dispatch, fresh request/evidence provenance, 대체 거부, 공유 budget/rate
limit, child cancellation, dispatch/Oracle deadline, Tool이 작성한 Secret Lease 거부, timeout 및
unavailable outcome, typed Oracle binding, mutable-memory 대체, 별개의 replay storage, 발급된
compilation에 결박된 ticket finalization, 두 번 검증된 seal을 다룬다. 이 test들은 함께 실행
가능한 intent 거부, version 및 legacy-read policy, replay eligibility metadata, duplicate 및
same-request 거부, Candidate/Run/target/scenario/Tool/argument/evidence/Grant 대체,
confused-deputy 입력, Scope·budget·authorization·cancellation check, 공유 Tool/Producer output
typing, 신뢰할 수 없는 verdict flag를 검증한다. `tests/test_confirmation_gate.py`는 support,
contradict, inconclusive, failed, cancelled, timed-out, unavailable, unsupported ReplayOutcome에
대한 공통 disposition matrix를 고정한다. versioned-artifact test는 fail-closed legacy 분리와
fixed 경로를 검증한다. `tests/test_kisa_replay.py`는 명시적인 3개 scenario opt-in, fresh 및
unique session, raw-transcript 재계산, multi-turn request rate accounting, mutable record 거부,
sealed source-state 결박, receipt 재로딩, immutable source artifact, reproduction-backed KISA
projection도 검증한다. `tests/test_local_replay.py`는 명시적인 단일 프로세스 Local
source→SQLite replay→Gate 경로, 공유 source state, immutable flat Finding snapshot, versioned
projection, Candidate가 없는 동작, semantic omission, 한정된 반복을 검증한다.
`tests/test_kisa_retest.py`와 `tests/test_kisa_retest_cli.py`는 M6-05 sealed baseline 입장,
정확한 retest 결박, negative/supporting/mixed/terminal disposition matrix, canonical receipt
재로딩, 위조된 negative signal 거부, parent regression 분리, immutable baseline, CLI Exit
Gate를 검증한다. 나머지 요구 사항은 Control Plane replay orchestration, portable/off-host
verification, 추가로 명시적 opt-in한 Mode contract에 적용된다.

## 참고 자료

- [PAJIN 제품 계획](../PAJIN_PRODUCT_PLAN.ko.md)
- [ADR 0002: Tool Gateway와 Worker 격리](0002-tool-gateway-and-worker-isolation.ko.md)
- [ADR 0004: 동적 Multi-Agent 실행](0004-dynamic-multi-agent-execution.ko.md)
- [ADR 0009: Provider 기반 Agent Runtime](0009-provider-backed-agent-runtime.ko.md)
- [ADR 0016: 변조 증거를 남기는 Run 무결성](0016-tamper-evident-run-integrity.ko.md)
- [ADR 0024: 협력적 실행 취소](0024-cooperative-execution-cancellation.ko.md)
- [ADR 0025: Candidate 검증 원장과 재실행 경계](0025-candidate-validation-ledger-and-replay-boundary.ko.md)
- [ADR 0026: 신뢰할 수 있는 KISA Candidate 입장](0026-trusted-kisa-candidate-admission.ko.md)
- [ADR 0028: 내구성 있는 로컬 Replay Ticket 원장](0028-durable-local-replay-ticket-ledger.ko.md)
