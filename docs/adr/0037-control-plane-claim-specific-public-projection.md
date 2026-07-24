# ADR 0037: Control Plane Claim별 공개 Projection

- 상태: Accepted
- 날짜: 2026-07-24
- 범위: Phase 4 Validation Refinement B2.6 첫 수직 조각
- 확장: [ADR 0029](0029-control-plane-replay-orchestration.md),
  [ADR 0035](0035-claim-replay-public-state-projection.md),
  [ADR 0036](0036-claim-bound-replay-execution-authority.md)

## 맥락

ADR 0036은 exact KISA M03·M06·A04의 validity·impact·severity Claim마다 서로 다른
compiled authority, Replay Run, fresh session, Oracle, receipt를 만들었다. 하지만 PostgreSQL
Control Plane은 아직 Candidate 단위 confirmation item만 발급했고 공개 projection 입력도 v1
Candidate 또는 v2 Retest 권위만 표현했다. 따라서 Local 경로에서 봉인한 Claim별 실행 권위를
Control Plane의 durable claim→permit→finalize→projection 경로가 끝까지 보존하지 못했다.

기존 Candidate confirmation과 negative Retest를 암묵적으로 바꾸면 저장된 권위와 API 멱등성
경계가 달라진다. impact·severity support가 validity 기반 confirmation을 우회해서도 안 된다.

## 결정

1. `CreateReplayBatchRequest.claim_projection`을 명시적 opt-in으로 추가한다. 기본값은
   `false`이며 remediation Retest와 함께 사용할 수 없다. 기존 confirmation v1과 negative
   Retest v1 정책은 그대로 유지하고 opt-in confirmation만
   `pajin.kisa-claim-confirmation:v2`를 사용한다.
2. exact KISA Candidate마다 validity·impact·severity 세 Replay item을 파생한다. 각 item은
   Claim별 contract, compilation, Run, ticket, execution context, permit 집합, finalization,
   output Artifact를 가진다.
3. schema v13의 append-only `cp_replay_claim_bindings`가 item을 원 Candidate ID와 exact
   `ReplayClaimBinding`에 결박한다. 기존 `(batch_id, candidate_id)` 고유성은 변경하지 않고
   Claim item의 내부 key로 Claim ID를 사용한다. 공개 API에는 원 Candidate ID와 Claim을
   복원해 노출한다.
4. projection input authority v3
   `pajin.control-plane.replay-projection-inputs/v3`가 각 finalized item의 Candidate
   ID·digest, Claim ID·digest·type·statement, ticket, compilation, Run, output, receipt와 Gate
   digest를 봉인한다. Candidate마다 세 Atomic Claim이 정확히 한 번씩 없으면 fail closed한다.
5. 서버는 모든 Claim output을 다시 검증한 뒤 하나의 versioned validation projection과
   `claim-replays.json`을 발행한다. 기존 공통 Gate를 그대로 사용하며 validity만 내부
   confirmation 결정을 구동한다. impact·severity는 정보 전용이고 Finding confirmation이나
   severity를 독자적으로 변경하지 않는다.
6. Claim binding row는 UPDATE·DELETE·REPLACE할 수 없다. finalization 재요청과 projection
   재조회는 같은 결과로 수렴하며 v1 confirmation, v2 Retest projection은 계속 읽을 수 있다.

## 권위와 복구 경계

Claim identity는 source Candidate의 결정론적 Atomic Claim에서 파생되어 compilation과
append-only binding 원장 양쪽에서 일치해야 한다. Worker가 Candidate·Claim·compilation·ticket
중 하나라도 바꾸면 claim 또는 finalization 전에 거부된다. projection은 모든 item이 verified된
뒤 CAS로 한 번만 발행되며 응답 손실 뒤 재시도는 이미 커밋된 같은 권위를 반환한다.

## 한계와 후속

- 첫 수직 조각은 exact KISA M03·M06·A04와 Mode 소유 impact·severity 정책에 한정된다.
- `independent_execution_attested=false`이므로 validity 재현 성공도 현재 공개 상태에서는
  `partially-confirmed`일 수 있다.
- local seal, PostgreSQL append-only 원장, managed Artifact는 내용·계보·재시작 복구를
  보장하지만 별도 조직이나 off-host 실행의 암호학적 attestation은 아니다.
- 이 후속 범위의 Control Plane receipt 공개키 서명, key rotation·revocation, verifier bundle과
  외부 trust anchor는 [ADR 0038](0038-portable-claim-receipt-attestation.md)에서 구현됐다.
  독립 executor·target 실행 attestation은 계속 후속 범위다.

## 검증 요구 사항

- opt-in 한 Candidate는 정확히 세 Claim item과 세 고유 Replay Run을 가져야 한다.
- Claim ID·digest·type·statement와 Candidate digest가 파생부터 공개 v3 authority까지
  변하지 않아야 한다.
- Claim binding 원장 변조와 부분·중복 Claim projection은 거부되어야 한다.
- impact·severity support만으로 confirmed Finding이나 confirmation basis가 생기면 안 된다.
- 기존 v1/v2 배치, migration, finalization·projection 멱등성이 유지되어야 한다.
