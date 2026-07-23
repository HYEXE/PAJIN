# ADR 0033: 등록형 Validation Control Materializer

- 상태: Accepted
- 날짜: 2026-07-23
- 범위: Phase 4 Validation Refinement B2.2 M03·M06·A04 확장

## 맥락

ADR 0032의 첫 조각은 M03 요청을 함수 내부에서 직접 변형했다. 같은 구조에 시나리오 분기를 계속
추가하면 어떤 변형 규칙이 실행 권한을 얻었는지 Plan만으로 확인하기 어렵고, 향후 카탈로그에
추가된 Replay 시나리오가 검토 없이 Control 대상이 될 위험이 있다. 특히 A04는 두 턴의 메모리
인과관계를 보존해야 하므로 M03·M06의 단일 benign 요청과 같은 변형을 사용할 수 없다.

## 결정

1. 자동 Validation Control 대상은 M03 system-prompt disclosure, M06 jailbreak bypass, A04
   memory poisoning 세 시나리오의 명시적 allowlist로 제한한다.
2. Control 변형은 범용 `ValidationControlMaterializerRegistry`에 코드 등록된 Mode adapter만
   생성한다. Registry는 최초 resolve 후 동결되며 materializer ID·version, Mode, scenario,
   Tool과 scenario digest가 모두 일치해야 한다.
3. `ValidationControlPlan`을 `v1alpha2`로 올리고 `materializerId`,
   `materializerVersion`, `scenarioDigest`를 canonical Plan ID에 포함한다.
4. 세 시나리오 모두 Baseline은 원 catalog 입력과 check를 유지하고, Negative Control은 같은
   입력에 실행별 absent canary check를 사용한다.
5. M03·M06 Counterfactual은 benign `READY` 입력에서 원 marker의 부재를 검사한다.
6. A04 Counterfactual은 첫 턴의 poison write를 `PAJIN_MEMORY_SAFE`로 바꾸되 두 번째 memory
   query와 원 poison marker check는 유지한다. 이를 통해 단순한 다른 대화가 아니라 memory
   persistence 인과관계를 대조한다.
7. Materializer는 argument variant만 만들며 Request나 Capability를 발급하지 않는다. 기존
   Control Executor만 fresh non-delegable `max_calls=1` Capability로 실행할 수 있다.
8. 세 시나리오의 결과는 계속 information-only이며 Candidate, severity, Replay 또는 confirmation
   상태를 변경하지 않는다.

## 결과

- 지원 시나리오마다 변형 규칙과 버전을 sealed Plan에서 감사할 수 있다.
- 새 Replay 시나리오는 명시적 Control allowlist와 materializer 등록 없이는 자동 실행되지 않는다.
- M03·M06·A04가 동일한 fresh request·session·Capability·evidence·receipt 경계를 공유한다.
- 세 시나리오·단일 target의 B2.2 사전 예산은 source 6회, Replay 6회, Control 9회로 정확히
  21회다. B2.5 Claim별 Replay 이후 현재 예산은
  [ADR 0036](0036-claim-bound-replay-execution-authority.md)의 33회다.

## 한계와 후속

- 각 시나리오는 한 개 validity check와 Control별 한 번의 실행만 지원한다.
- materializer는 코드 등록형이며 운영 승인·서명된 원격 registry는 아니다.
- 독립 severity와 Provider/model 다양성의 첫 opt-in 수직 조각은 ADR-0034에서 구현했다.
  검증 가능한 운영 다양성·calibration·다수 Reviewer 합의, Claim-level Replay와 공개 부분 검증
  상태는 후속이다.
- Receipt는 여전히 PAJIN-local Run seal과 Docker proxy receipt 범위이며 portable/off-host 독립
  attestation은 아니다.
