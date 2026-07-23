# ADR 0034: 다양한 Provider/model 기반 독립 Severity 도출

- 상태: Accepted
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement B2.3 첫 수직 조각

## 맥락

B2.1의 Blind Evidence Reviewer는 Candidate identity, disposition, severity와 기존 판정을
제거한 validity·impact Packet을 별도 역할 호출에서 검토한다. 하지만 기본 Provider
Runtime은 Primary Validator와 Blind Reviewer가 같은 Provider와 model을 사용했다. 또한
기존 severity Atomic Claim의 statement는 Candidate가 제안한 severity 문자열 자체이므로,
이를 그대로 다른 Reviewer에 전달하면 독립 도출이 아니라 제안 등급의 찬반 평가가 된다.

## 결정

1. `provider-agent-run`은 별도의 review Provider 등록을 명시적으로 선택할 수 있다.
2. review Provider는 Primary와 Provider ID, endpoint, model이 모두 달라야 한다. 하나라도
   같으면 실행 전에 fail-closed 한다.
3. Primary Validator와 다양한 Reviewer는 각각 별도 Agent, Tool allowlist, endpoint,
   Capability 호출 예산과 Secret Lease를 사용한다.
4. 다양한 Reviewer는 Blind Evidence Review와 Severity Derivation 두 번만 호출할 수 있다.
   Primary Provider Tool 권한은 받지 않는다.
5. `SeverityDerivationPacket`은 opaque severity Claim ID와 validity·선택적 impact
   `BlindEvidencePacket`만 포함한다. Candidate identity, 제안 severity, disposition, Primary
   Decision과 보고서 문맥은 포함하지 않는다.
6. `IndependentSeverityDecision`은 `derived` 또는 `insufficient`와 허용 목록 evidence만
   기록한다. 실패·거부·schema 오류는 한 번의 시도 뒤 `insufficient`로 봉인한다.
7. `ProviderModelReviewBinding`은 Primary와 Reviewer의 Provider ID, endpoint, model 및 실제
   Reviewer Agent ID를 canonical digest에 결박한다.
8. 결정론적 `SeverityClaimReconciliation`은 독립 도출과 Candidate의 원래 severity를
   `corroborated`, `contested`, `inconclusive`로 비교한다.
9. 독립 severity 결과와 reconciliation은 항상 `informationalOnly=true`,
   `confirmationEligible=false`, `mutatesCandidate=false`다. Candidate, Finding,
   disposition, Replay eligibility와 confirmation을 변경하지 않는다.
10. `ValidatorOutput`은 v1alpha2를 기본으로 사용하고 Provider/model binding, Severity
    Packet, Decision과 Reconciliation을 함께 봉인한다. v1alpha1 입력은 기존 Run 검증을
    위해 계속 읽을 수 있다.

## 결과

- Blind Reviewer와 Severity Deriver는 Primary Validator의 Provider Tool·Capability·Secret
  경계와 분리된다.
- Reviewer는 제안 severity를 보지 않고 최소 validity·impact 증적에서 등급을 새로
  도출한다.
- Primary와 독립 도출의 불일치는 Candidate를 덮어쓰지 않고 검토 신호로 보존된다.
- 다양한 review를 선택한 단일 Candidate 실행은 Planner 1회, Candidate Validator 1회,
  Blind Reviewer 1회, Severity Deriver 1회, Reporter 1회의 총 5회 model 호출을 사용한다.

## 한계와 후속

- Provider ID와 endpoint의 차이는 설정 계약이다. 별도 법인·인프라·학습 계보를
  암호학적으로 증명하지 않는다.
- Blind Review와 Severity Derivation은 각각 한 번만 시도한다.
- 독립 severity는 아직 보고서의 canonical Finding severity나 공개 상태에 투영되지 않는다.
- Gold Dataset, Human Overturn Rate, calibration, 다수 Reviewer 합의와 독립 실행
  attestation은 후속 범위다.
