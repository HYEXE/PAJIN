# ADR 0035: Claim Replay 계보와 공개 부분 검증 상태

- 상태: Accepted
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement B2.4 첫 수직 조각
- 확장: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md),
  [ADR 0030](0030-candidate-aware-atomic-claim-validation.md)

## 맥락

Restricted Replay는 Candidate·원 요청·Mode·Scenario·Tool·Target·Threat와 새 실행 증적을
결박하지만, 최종 Validation Decision은 Candidate 전체에 하나만 존재했다. 따라서 성공한
validity 재현과 전체 Finding confirmation 실패를 소비자에게 구분해서 보여 줄 수 없었고,
Mode Oracle의 명시적 반박도 일반 objective rejection과 같은 내부 disposition으로 보였다.

내부 `FindingDisposition`에 새 값을 바로 추가하면 기존 confirmation Gate, Control Plane
canonical decision 검증, KISA retest baseline과 과거 sealed Run 해석을 동시에 바꾸게 된다.
또한 실행 실패를 재현 실패로 표현하면 target unavailable·timeout·취소를 부정 증거로
오해하게 된다.

## 결정

1. 기존 Candidate-bound confirmation Replay를 Candidate의 정확한 `validity` Atomic Claim에
   투영한다.
2. `ClaimReplayAssessment`는 Candidate·Claim ID와 digest, Replay Run·Outcome·Oracle,
   request·evidence, 평가 시각과 독립 실행 attestation 여부를 canonical assessment ID에
   결박한다.
3. 새 `validation/v1alpha1/claim-replays.json`은 assessment 집합을 별도 artifact로 봉인한다.
4. `VersionedValidationIndex`는 새 projection에서 고정 `claimReplaysPath`와 모든 Candidate를
   정확히 한 번 포함하는 `publicStates` map을 제공한다. 과거 v1alpha1 projection은 두 필드가
   모두 없는 형태로 계속 읽는다.
5. 공개 상태는 내부 `FindingDisposition`과 분리한다.
   - `confirmed`: 기존 독립 실행 confirmation invariant를 만족한 경우
   - `partially-confirmed`: validity Claim은 typed Oracle support로 재현됐지만 전체
     confirmation invariant는 만족하지 못한 경우
   - `not-reproduced`: 성공한 typed Oracle이 정확한 validity Claim을 명시적으로 반박한 경우
   - `inconclusive`: 실행 실패·취소·시간초과·target unavailable 또는 Oracle 판단 불가
   - 나머지는 기존 `needs-review`·`rejected-objective` 의미를 보존
6. `partially-confirmed`와 `not-reproduced`는 `confirmed_findings`와 canonical
   `findings.json`에 들어가지 않는다.
7. loader는 assessment의 exact validity Claim, Decision replay lineage, attestation, Gate reason,
   public state와 seal 포함 관계를 다시 검증하고 치환을 fail-closed 한다.
8. Markdown projection은 내부 disposition과 공개 상태, Claim ID와 Claim replay status를 함께
   표시하며 `partially-confirmed`가 제품 confirmation이 아님을 명시한다.

## 권위 경계

이 변경은 기존 `confirmed` 권위를 낮추지 않는다. Claim support만으로
`ConfirmationBasis.VERIFIED_INDEPENDENT_REPLAY`를 만들 수 없으며, 내부 Decision과 Control
Plane canonical Gate 검증은 그대로다. `not-reproduced`도 terminal miss가 아니라 성공한
ReplayOutcome의 threshold-bound contradiction과 대응 Gate reason이 모두 있을 때만 생성된다.

## 마이그레이션

과거 sealed `validation/v1alpha1` projection은 immutable하다. index에
`claimReplaysPath`·`publicStates`가 없으면 legacy replay-evidence projection으로 읽고 내부
disposition을 기존 공개 view로 사용한다. 새 projection은 두 필드와
`claim-replays.json`을 함께 생성해야 하며, 하나만 있거나 artifact·seal·lineage가 불완전하면
loader가 거부한다.

## 한계와 후속

- 첫 수직 조각은 validity Claim만 지원한다. impact·severity의 별도 실행 계약과 Oracle은
  아직 없다. 이 로컬 KISA 후속은 [ADR 0036](0036-claim-bound-replay-execution-authority.md)에서
  완료했다.
- 기존 Candidate replay를 validity Claim에 투영하므로, Claim별로 서로 다른 compiled
  execution authority를 발급하는 완전한 Claim-by-Claim Replay는 후속이다. exact KISA
  M03·M06·A04 범위의 후속은 ADR 0036에서 완료했다.
- 로컬 seal과 receipt는 계보·내용 일관성을 증명하지만 별도 조직·off-host 실행을 portable
  attestation으로 증명하지 않는다.
- Human overturn, Gold Dataset, calibration과 다수 Reviewer 합의는 후속 범위다.

## 검증 요구 사항

- Claim·Candidate digest 또는 Replay Run·Outcome·request·evidence 계보 치환이 거부돼야 한다.
- typed Oracle support는 `partially-confirmed`, explicit contradiction은 `not-reproduced`로
  투영돼야 한다.
- failed·cancelled·timed-out·target-unavailable·Oracle inconclusive는
  `not-reproduced`가 아니라 `inconclusive`여야 한다.
- 공개 상태 치환과 부분 artifact/seal은 fail-closed 해야 한다.
- 과거 v1alpha1 projection은 새 artifact 없이 계속 읽혀야 한다.
- 새 공개 상태만으로 confirmed Finding이 생성돼서는 안 된다.
