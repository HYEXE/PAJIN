# ADR 0030: Candidate-aware Validator와 Atomic Claim 판정

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement 수직 조각
- Extends: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.md)
- Preserves: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

## 배경

일반 Provider Validator는 Campaign·Plan·Tool Result를 읽고 Finding 전체를 다시 생성했다. 이후
신뢰 어댑터가 Validator Finding과 Candidate의 의미 필드를 비교했기 때문에 표현이나 evidence
순서 차이가 실제 의미 판정과 무관하게 누락으로 처리될 수 있었다. 하나의 Finding에 공격 성립,
영향, severity가 함께 있으면 일부만 지지되는 상태도 표현하기 어려웠다.

## 결정

신뢰 코드는 승인된 `CandidateFinding`을 다음 Atomic Claim으로 결정론적으로 분해한다.

1. `validity`: title, summary, target, threat class, reproduction, component, root cause
2. `impact`: Candidate에 impact가 있을 때만 생성
3. `severity`: severity 값

각 Claim은 Candidate ID·Candidate digest·Claim type·statement·evidence에 결박된 canonical ID와
SHA-256 digest를 가진다. Provider는 Candidate나 Finding을 반환하지 않고 모든 exact Claim ID와
digest에 대해 `supports`, `contradicts`, `insufficient` 중 하나와 rationale, Candidate 소유
evidence reference만 반환한다.

신뢰 runtime은 다음을 강제한다.

- Candidate 순서와 결정론적 Claim 집합이 정확히 일치해야 한다.
- Claim마다 Decision이 정확히 하나 있어야 하며 순서·ID·digest 치환을 거부한다.
- supporting/contradicting evidence는 해당 Claim의 evidence 부분집합이어야 한다.
- `supports`는 supporting evidence만, `contradicts`는 contradicting evidence만 요구한다.
- `insufficient`는 evidence를 분류하지 않는다.
- `validity` Decision만 기존 `CandidateAssessment`로 투영한다.
- `impact`와 `severity` Decision은 원 Candidate, severity, disposition을 변경하지 않는다.

Atomic Claim과 Decision은 exact Validator Agent·Task identity와 함께
`validator-output.json`에 저장되고 source Run seal에 포함된다. durable consumer는 봉인된
Candidate에서 Claim을 다시 분해해 저장된 집합과 Decision을 검증해야 한다.

## 권위 경계

이 ADR은 의미 검토 정밀도만 높인다. `supports` Claim은 제품 수준 `confirmed`가 아니며 기존
Gate에서 최대 `needs-review`와 `independent-reproduction-missing`으로 남는다. 확인에는 계속
Candidate-bound Restricted Replay, Mode Oracle, 객관 Gate와 독립 실행 attestation이 필요하다.
Severity 반박도 원 Finding을 자동 하향하거나 validity를 거부하지 않는다.

trusted Candidate가 없는 legacy 실행은 기존 whole-Finding Validator 경로를 유지한다. Provider
실패 시 fallback 결과는 exact Candidate에 안전하게 다시 결박하며, 별도 평가되지 않은 Claim은
`insufficient`로 남긴다.

## 현재 한계

- Claim type은 `validity`·`impact`·`severity` 세 종류로 제한된다.
- Claim별 replay와 Claim별 독립 실행 attestation은 아직 없다.
- 공개 `partially-confirmed`·`not-reproduced` disposition은 추가하지 않았다.
- impact·severity Decision의 보고서·UI 표현과 human overturn 측정은 후속 작업이다.
- 일반 legacy Validator adapter는 호환성을 위해 유지한다.

## 검증 요구

- Provider 출력에 Finding이 없어도 exact validity support가 Candidate Gate에 전달되어야 한다.
- validity support와 severity contradiction이 한 artifact에 함께 봉인되어야 한다.
- Candidate·Claim ID/digest, Claim 순서, evidence 치환은 fail-closed여야 한다.
- Atomic Claim 판정만으로 Candidate나 Finding이 `confirmed`가 되어서는 안 된다.
- Candidate Producer가 없는 기존 실행은 동작이 바뀌지 않아야 한다.
