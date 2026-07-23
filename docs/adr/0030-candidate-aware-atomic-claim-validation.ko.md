> Languages: [English](0030-candidate-aware-atomic-claim-validation.en.md) | [한국어](0030-candidate-aware-atomic-claim-validation.ko.md)

# ADR 0030: Candidate-aware Validator와 Atomic Claim 판정

- 상태: 승인됨
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement 수직 조각
- 확장: [ADR 0025](0025-candidate-validation-ledger-and-replay-boundary.ko.md)
- 유지: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

## 배경

일반 Provider Validator는 Finding 전체를 다시 생성했고, 신뢰 어댑터가 이를 Candidate와 사후
비교했다. 표현이나 evidence 순서 차이가 실제 의미와 무관하게 누락을 만들 수 있었고, 공격 성립,
영향, severity 중 일부만 지지되는 상태를 독립적으로 표현하기 어려웠다.

## 결정

신뢰 코드는 승인된 Candidate를 `validity`·`impact`·`severity` Atomic Claim으로 결정론적으로
분해한다. 각 Claim은 Candidate ID·digest, type, statement와 evidence에 결박된 canonical ID와
digest를 가진다. Provider는 Finding을 다시 쓰지 않고 모든 exact Claim에 대해
`supports`·`contradicts`·`insufficient`, rationale과 Candidate 소유 evidence만 반환한다.

runtime은 Claim 집합·순서·ID·digest와 Claim당 Decision 하나를 검증하고, 외부 evidence나
support/contradiction 혼합을 거부한다. `validity`만 기존 Candidate semantic Gate에 투영하고
`impact`·`severity`는 별도 판정으로 봉인해 원 Candidate를 변경하지 않는다. Claim과 Decision은
exact Validator Agent·Task identity와 함께 `validator-output.json`에 저장된다.

## 권위 경계

Claim support는 제품 수준 confirmation이 아니다. 기존 `needs-review`와 Replay·Mode Oracle·객관
Gate·독립 실행 attestation 요구를 유지한다. Severity 반박은 validity를 거부하거나 원 Finding을
자동 변경하지 않는다. trusted Candidate가 없는 legacy 실행은 기존 whole-Finding 경로를 유지하며,
fallback이 별도로 평가하지 않은 Claim은 `insufficient`로 남긴다.

## 현재 한계

- Claim type은 세 종류로 제한된다.
- Claim별 replay·attestation과 공개 `partially-confirmed`·`not-reproduced` 상태는 아직 없다.
- impact·severity 보고서/UI와 human overturn 측정은 후속 작업이다.

## 검증 요구

- Finding 재생성 없이 validity support가 기존 Gate에 전달되어야 한다.
- validity support와 severity contradiction을 동시에 봉인할 수 있어야 한다.
- Candidate·Claim·evidence 치환은 fail-closed여야 한다.
- Atomic Claim 판정만으로 `confirmed`가 생성되어서는 안 된다.
- Candidate Producer가 없는 기존 실행은 호환되어야 한다.
