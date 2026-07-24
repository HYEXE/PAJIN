# ADR 0040: Target 발급 challenge-bound Replay receipt

- 상태: 승인
- 날짜: 2026-07-24

## 배경

ADR 0039의 executor 서명은 별도 workload가 exact permit과 sealed output을 관찰했다는 사실을
증명하지만, executor가 전달한 target 응답 자체의 출처는 증명하지 않는다. Worker나 executor가
응답 JSON과 proxy receipt를 함께 조작할 수 있으므로 이 증명만으로 Finding을
`VERIFIED_INDEPENDENT_REPLAY`로 승격해서는 안 된다.

Target이 단순 nonce에 서명하는 방식도 충분하지 않다. nonce를 다른 permit, 요청 또는 응답에
재사용할 수 있고, host가 관찰한 실제 교환과 연결되지 않기 때문이다. 필요한 증명은 Control
Plane의 일회성 실행 권위에서 시작해 Target 응답, host proxy 관찰, executor 결과, 최종
projection까지 같은 exact Claim을 따라가야 한다.

## 결정

1. B2.8b는 명시적으로 `target_attestation=true`를 요청한 Claim projection batch에만
   `pajin.kisa-target-attestation:v4` 정책을 발급한다. 이 옵션은 B2.8a의
   `portable_attestation=true`와 별도 executor trust anchor를 전제로 한다. 기존 v1-v3
   요청과 서명 직렬화는 변경하지 않는다.
2. Control Plane은 각 durable Tool permit의 digest, Replay request ID, batch/item/ticket,
   fencing value, call ordinal, target digest, method, compiled argument digest, 발급·만료
   시각으로 최대 30초 수명의 deterministic challenge를 파생한다. Worker가 만든 nonce나
   caller가 제출한 challenge는 권위가 아니다.
3. Target은 별도 Ed25519 workload key로 challenge digest, exact request JSON digest,
   receipt를 제외한 response payload digest, HTTP status, exchange ordinal과 Target
   issuer/trust-domain/profile을 서명한다. Control Plane은 별도 경로로 배포된 keyring의
   `active`, `retired`, `revoked` lifecycle을 검증하며 Artifact가 제공한 공개키를 신뢰하지
   않는다.
4. Target receipt는 응답 JSON의 `targetReceipt`에 포함된다. 기존 host egress proxy는 이
   JSON 전체의 canonical digest를 기록한다. executor는 target receipt digest와 해당
   proxy request/response receipt를 `target_execution_proofs`로 묶어 기존 executor
   statement 안에서 서명한다.
5. Control Plane은 외부 Artifact 복사 전에 executor 서명과 proof shape를 검증하고, managed
   import와 seal 재검증 뒤에 permit에서 challenge를 다시 파생한다. 그 후 transcript의 exact
   request, receipt를 제외한 response, Target receipt signature/lifecycle, host proxy
   request/response digest, executor binding이 모두 일치하는지 검증한다. 누락, 중복,
   순서 변경, 다른 permit·target·exchange의 receipt 재사용은 fail closed다.
6. Target verification summary, proof-set digest와 trust-anchor digest는 finalization result
   digest에 포함된다. exact Claim의 기존 semantic/contradiction Gate가 성공하고 이 독립
   실행 증명까지 유효한 경우에만 `confirmed /
   VERIFIED_INDEPENDENT_REPLAY / INDEPENDENT_REPRODUCTION_CONFIRMED`로 승격한다.
   contradiction, inconclusive, negative-retest 조건은 Target 서명으로 우회할 수 없다.

## 신뢰 경계와 한계

이 결정은 Control Plane permit에서 Target 발급 receipt, host proxy 관찰, executor 서명,
sealed projection으로 이어지는 분리된 세 권위의 체인을 만든다. Worker나 executor의
자기주장만으로 독립 실행 상태를 만들 수 없다.

첫 수직 조각의 한계는 다음과 같다.

- 현재 host proxy는 평문 HTTP 응답 JSON만 canonical하게 관찰한다. 일반 HTTPS `CONNECT`
  터널의 내부 응답을 proxy receipt에 묶는 기능은 제공하지 않는다.
- 하나의 Control Plane 설정은 하나의 Target issuer/trust-domain/profile anchor를 받는다.
  다중 Target registry, target identity routing, HSM/KMS와 transparency log는 후속이다.
- challenge와 key lifecycle은 host 간 UTC clock 동기화를 전제로 한다. 허용 시간을 늘리는
  대신 짧은 만료와 fail-closed 검증을 유지한다.
- Target receipt는 실행 출처를 증명하지만 조직 영향도, remediation 적용 주체, production
  telemetry를 증명하지 않는다.
- portable Artifact의 2 MiB 한계와 대형 object-store/multipart 전송 문제는 ADR 0039의
  별도 후속 범위로 남는다.

## 결과

- 등록된 exact KISA M03/M06/A04 positive Replay가 Target-issued proof까지 갖추면 처음으로
  `VERIFIED_INDEPENDENT_REPLAY`가 될 수 있다.
- Target signer가 없거나 anchor가 설정되지 않은 v4 요청은 발급 또는 실행 단계에서
  거부된다.
- key rotation은 기존 receipt 검증을 위해 retired key를 보존하고, revoked key는 발급
  시각과 관계없이 거부한다.
- 다음 개선은 HTTPS에서도 host observation을 유지하는 attested transport와 다중 Target
  trust registry를 설계한 뒤, 대형 Artifact 전송을 같은 content-addressed 계약에
  연결하는 것이다.
