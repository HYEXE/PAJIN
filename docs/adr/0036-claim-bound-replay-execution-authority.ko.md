# ADR 0036: Claim별 Replay 실행 권위와 KISA Oracle

- 상태: Accepted
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement B2.5 첫 수직 조각
- 확장: [ADR 0030](0030-candidate-aware-atomic-claim-validation.ko.md),
  [ADR 0035](0035-claim-replay-public-state-projection.ko.md)

## 맥락

ADR 0035는 기존 Candidate Replay를 정확한 `validity` Atomic Claim에 투영했지만, 실행 권위 자체는
여전히 Candidate 단위였다. 따라서 `impact`와 `severity`는 별도 실행 계약과 Oracle이 없었고,
서로 다른 Claim이 같은 compiled authority나 receipt를 공유하지 않았다는 사실을 증명할 수 없었다.

단순히 기존 validity 결과를 세 Claim에 복제하면 실행한 주장과 공개한 주장이 달라질 수 있다.
반대로 impact·severity 지원만으로 Candidate 전체를 `confirmed`로 승격하면 기존 독립 재현 Gate의
권위를 약화한다.

## 결정

1. `ValidationPacket`, `ReplayIntent`, `ModeReplayContract`, `ReplayBinding`,
   `ReplayCapabilityGrant`, `CompiledReplaySpec`, Oracle와 Outcome 계보에 정확한
   `ReplayClaimBinding`을 반복한다. 이 결박은 Candidate Claim digest, Claim ID·digest·type·
   statement를 포함한다.
2. Compiler와 loader는 Claim이 Candidate의 결정론적 Atomic Claim 집합과 정확히 일치하는지
   검사한다. Claim 누락, 타입·statement·digest 치환, Contract와 Packet 불일치는 fail closed다.
3. KISA M03·M06·A04 confirmation coordinator는 Candidate마다 `validity`, `impact`, `severity`
   세 Claim을 각각 별도 Replay Run에서 실행한다. 각 Claim은 별도 compiled authority, 5분 이하
   non-delegable Grant, single-use ticket, fresh session, evidence, Oracle result와 receipt를 갖는다.
4. KISA impact statement와 severity는 Mode 소유 정책으로 고정한다. impact는 시나리오별 허용
   statement만, severity는 현재 `high`만 지원한다. Oracle은 compiled Claim과 이 정책을 대조하고
   같은 raw transcript의 카탈로그 check를 다시 계산한다. 임의 Provider 문장은 실행 권위를 얻지
   못한다.
5. `claim-replays.json`은 세 Claim assessment를 각각 기록한다. 모든 Claim의 exact coverage가
   없거나 한 Claim receipt가 다른 Claim으로 치환되면 projection을 거부한다.
6. 기존 confirmation 권위는 유지한다. `validity` Replay만 내부
   `ValidationDecision`과 `VERIFIED_INDEPENDENT_REPLAY` Gate를 구동한다. impact·severity
   assessment는 `independent_execution_attested=false`인 정보 전용 공개 projection이며,
   단독으로 Candidate나 Finding을 confirm하거나 severity를 변경할 수 없다.
7. 기존 Candidate-bound 호출자는 Claim이 없는 legacy contract를 계속 읽고 실행할 수 있다.
   새로운 KISA confirmation 경로만 명시적 Claim별 계약을 사용한다.

## 예산과 결과

- 세 시나리오·단일 target·2회 반복 예제는 source 6회와 Claim Replay 18회를 예약한다.
- Validation Control을 켜면 정보 전용 Control 9회를 더해 총 33회를 예약한다.
- `verified_results`의 Candidate별 validity view는 기존 소비자 호환을 위해 유지하고,
  `confirmation_results`는 모든 Claim receipt를 Gate에 전달한다.

## 권위 경계

Claim별 fresh 실행은 “어떤 주장을 어떤 권위로 실행했는가”를 명확히 하지만, impact·severity
지원이 제품 전체 확인을 뜻하지는 않는다. 공개 `confirmed`는 기존 validity 기반 독립 재현
invariant를 만족할 때만 생성된다. terminal 실패·취소·시간초과·target unavailable·Oracle 판단
불가는 여전히 `inconclusive`이며 반증으로 승격되지 않는다.

## 한계와 후속

- 첫 수직 조각은 exact KISA M03·M06·A04와 Mode 소유 impact·severity 정책에 한정된다.
- severity `high`는 카탈로그 정책의 재현이지 calibration, Gold Dataset, 다수 Reviewer 또는
  Human 합의가 아니다.
- negative retest는 보수적으로 기존 Candidate/validity 경계를 유지한다.
- Control Plane public projection과 portable/off-host attestation은 아직 Claim별 실행 권위를
  완전히 전달하지 않는다.
- 로컬 seal과 receipt는 계보와 내용 일관성을 증명하지만 별도 조직·인프라의 실행을 암호학적으로
  attest하지 않는다.

## 검증 요구 사항

- Packet부터 Grant·Spec·Oracle·Outcome까지 Claim ID·digest·type·statement가 보존돼야 한다.
- Candidate에 없는 Claim, 다른 Claim의 receipt, 일부 Claim만 있는 projection은 거부해야 한다.
- KISA Candidate마다 validity·impact·severity가 각각 고유 Replay Run과 fresh session을 가져야
  한다.
- impact·severity support만으로 confirmed Finding이나 confirmation basis를 만들 수 없어야 한다.
- legacy Candidate-bound Replay와 sealed projection은 계속 읽을 수 있어야 한다.
