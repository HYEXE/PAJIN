# ADR 0031: Blind Evidence 독립 검토 경계

- Status: Accepted
- Date: 2026-07-23
- Scope: Phase 4 Validation Refinement B2.1 수직 조각
- Extends: [ADR 0030](0030-candidate-aware-atomic-claim-validation.md)
- Preserves: [ADR 0027](0027-independent-reproduction-confirmation-boundary.md)

## 배경

Candidate-aware Validator는 정확한 Candidate와 Atomic Claim을 판정하므로 Finding 재생성 문제를
없앴지만, Candidate의 결론·severity·기존 판정을 함께 보는 검토자는 확인 편향에 노출된다. 반대로
현재 Validator 역할에 Tool 실행 권한을 추가해 대조 실험까지 맡기면 의미 검토와 독립 실행의 권한
경계가 섞이고 최소 권한 원칙을 약화한다.

## 결정

B2를 두 단계로 분리한다.

1. **B2.1 Blind Evidence Review:** 현재 수직 조각에서 구현한다.
2. **B2.2 Fresh-capability Controls:** 별도 실행 역할과 계약으로 후속 구현한다.

신뢰 코드는 Candidate-aware Atomic Claim에서 `validity`와 선택적 `impact`만
`BlindEvidencePacket`으로 투영한다. Packet에는 opaque Claim ID·digest·type, 검토할 statement,
허용된 evidence reference만 포함한다. Candidate ID·digest·source·disposition·severity, 기존
Validator Decision, 보고 문맥은 포함하지 않는다. `severity` Claim은 목표 문장 자체가 Candidate가
제안한 severity를 노출하므로 Blind Packet을 만들지 않는다.

Blind Reviewer는 별도 역할·요청으로 Packet마다 정확히 하나의 `supports`·`contradicts`·
`insufficient` Decision을 반환한다. evidence는 Packet이 허용한 집합으로 제한하고 ID·digest·순서
치환은 fail closed한다. Candidate-aware Validator와 같은 reviewer identity를 재사용할 수 없다.
현재 첫 수직 조각은 동일 Provider를 사용할 수 있지만 역할, 입력 문맥, 출력 artifact는 분리한다.
Blind 호출은 한 번만 시도하며 실패·거부·schema 오류는 전체 Packet을 `insufficient`로 봉인한다.

결정론적 Reconciler는 같은 Claim의 Candidate-aware Decision과 Blind Decision을 다음과 같이
결합한다.

- 두 판정이 같은 비-`insufficient` verdict이면 `corroborated`
- `supports`와 `contradicts`가 충돌하면 `contested`
- 어느 한쪽이 `insufficient`이면 `inconclusive`

Reconciliation은 검토 상태를 표현하는 봉인된 파생 artifact일 뿐 Candidate, severity, disposition,
기존 `CandidateAssessment`, replay eligibility를 변경하지 않는다.

## 권위 경계

Blind Review와 Reconciliation은 제품 수준 `confirmed`를 만들 수 없다. Confirmation은 계속
Candidate-bound Restricted Replay, Mode Oracle, 객관적 Gate와 독립 실행 attestation을 요구한다.
또한 Validator는 Tool 실행 Capability를 받지 않는다.

B2.2 Baseline·Negative Control·Counterfactual은 fresh Capability, 별도 요청·증거·receipt를 가진
Control Executor에서 수행한다. 해당 결과를 이 ADR의 결정론적 Reconciler에 추가하는 작업은 별도
의사결정과 구현으로 남긴다.

## 현재 한계

- 첫 수직 조각은 별도 역할을 사용하지만 동일 Provider·model일 수 있어 진정한 model diversity를
  보장하지 않는다.
- Candidate severity의 독립 도출과 severity Blind Review는 구현하지 않는다.
- Baseline·Negative Control·Counterfactual 실행과 독립 receipt는 구현하지 않는다.
- Claim 단위 replay, 공개 `partially-confirmed`·`not-reproduced` 상태와 human overturn 측정은
  후속 작업이다.

## 검증 요구사항

- Blind Packet과 Provider 요청에 Candidate identity·disposition·severity·기존 Decision이 없어야
  한다.
- 모든 Packet·Decision·Reconciliation은 exact Claim·evidence와 결정론적으로 결박되어야 한다.
- reviewer identity 재사용, Claim 순서·ID·digest·evidence 치환은 fail closed해야 한다.
- Blind 호출 실패는 `insufficient`·`inconclusive`로 봉인되어야 한다.
- `contested` 또는 `corroborated`만으로 Candidate나 Finding이 `confirmed`가 되어서는 안 된다.
- Candidate Producer가 없는 legacy 실행은 동작을 바꾸지 않아야 한다.
