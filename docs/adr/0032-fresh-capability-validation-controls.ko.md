# ADR 0032: Fresh-Capability Validation Control 실행 경계

- 상태: Accepted
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement B2.2 첫 수직 조각

## 맥락

B2.1은 Candidate-aware Validator와 Blind Evidence Reviewer를 분리했지만, 두 역할은 이미
수집된 증거만 심사한다. Baseline·Negative Control·Counterfactual을 같은 Validator가 직접
실행하면 검토 역할에 공격 Tool 권한이 추가되고, 같은 세션이나 Capability를 재사용하면 상태
오염과 권한 혼합을 구분하기 어렵다. 또한 Control 결과를 독립 재현과 같은 확인 근거로 취급하면
`needs-review`에서 `confirmed`로 가는 기존 경계를 우회한다.

## 결정

1. 첫 수직 조각은 KISA M03의 `validity` Atomic Claim만 지원한다.
2. `pajin kisa-run --validation-controls`는 봉인된 source Run과 기존 Candidate/Decision을 다시
   검증한 뒤 별도 Control Run을 만든다. 일반 Validator와 Blind Reviewer에는 Tool 권한을 주지
   않는다.
3. Baseline, Negative Control, Counterfactual은 각각 고유 request와 fresh session을 사용한다.
   Control Executor는 각 실행마다 부모에서 `max_calls=1`, non-delegable 하위 Capability를 새로
   발급하고 실행 직후 폐기한다.
4. Baseline은 catalog M03 공격 입력과 sentinel check를 유지한다. Negative Control은 같은 입력에
   실행별 부재 canary를 검사한다. Counterfactual은 benign `READY` 입력에서 원 sentinel의 부재를
   검사한다.
5. 각 실행은 별도 Gateway evidence와 `ValidationControlAttempt`,
   `ValidationControlReceipt`를 남긴다. Receipt는 request/result digest, Capability grant,
   evidence 경로를 결박하고 `pajin-local-sealed-run` 범위만 주장한다.
6. 결정론적 `ClaimControlReconciliation`은 기대한 `true/false/false` 대조를
   `contrast-observed`, 완료됐지만 다른 패턴을 `contrast-not-observed`, 유효 관찰이 빠진 경우를
   `inconclusive`로 기록한다.
7. 모든 Plan, Receipt, Reconciliation은 `informationalOnly=true`,
   `confirmationEligible=false`다. Candidate disposition, severity, confirmation basis는
   변경하지 않는다. 기존 Restricted Reproducer와 receipt 검증 Gate만 confirmation을 부여한다.
8. source 이후 Replay가 먼저 실행된 경우에도 같은 in-memory Campaign budget과 rate-limit
   ledger를 이어 사용한다. source보다 작은 counter나 다른 ledger identity는 거부한다.

## 결과

- 검토 모델의 판단과 새로운 공격 실행 권한이 분리된다.
- 세 Control의 요청·세션·Capability·증거·Receipt 계보를 독립적으로 감사할 수 있다.
- Control 결과가 유용한 대조 신호를 제공하지만 제품 confirmation을 우회하지 않는다.
- opt-in 실행이므로 기존 `kisa-run` 호출의 추가 네트워크 요청은 발생하지 않는다.

## 한계와 후속

- 이 ADR이 결정한 첫 조각은 M03 단일 check와 단일 Control attempt만 지원한다. M06·A04와
  등록형 materializer 확장은 [ADR 0033](0033-registered-validation-control-materializers.ko.md)에서
  후속 승인했다.
- local Run seal과 Docker proxy receipt를 사용하며 portable/off-host 독립 attestation은 아니다.
- 독립 severity 도출, Provider/model 다양성과 Claim 단위 public validation 상태는 후속 작업이다.
