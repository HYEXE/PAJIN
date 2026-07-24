# ADR 0043: 서명된 Target registry 배포와 단조 회전

- 상태: 승인
- 날짜: 2026-07-24

## 배경

ADR 0042의 registry v2는 HTTPS endpoint key를 exact Target URL에 결박하지만 registry
JSON 자체의 출처·최신성·배포 순서를 증명하지 않는다. 운영자가 이전 registry를 다시
배포하면 폐기한 key가 복구될 수 있고, pin을 한 번에 바꾸면 정상 인증서 교체 중 가용성이
끊긴다.

## 결정

1. 서명 배포에는 `pajin.replay.target-attestation-trust-registry/v3`를 사용한다. v3
   HTTPS entry는 현재 `tls_leaf_spki_sha256` 하나와 선택적인
   `retiring_tls_leaf_spki_sha256` 하나를 가진다. 이전 pin은
   `retiring_tls_leaf_spki_not_after`와 함께만 존재하며 발행 시점부터 최대 24시간,
   번들 만료 이전까지만 유효하다.
2. registry는 별도 `TargetAttestationRegistryTrustAnchor`의 Ed25519 key로 domain-separated
   서명한다. 번들 statement는 trust domain, issuer, 1부터 시작하는 연속 `sequence`,
   이전 번들 SHA-256, issued/not-before/expires 시각과 registry 전체를 결박한다. 번들
   수명은 최대 7일이다. Target application receipt key와 배포 key는 재사용하지 않는다.
3. Control Plane은 inline 번들 또는 redirect 없는 absolute HTTPS URL에서 최대 512 KiB를
   시작 시 한 번 읽는다. 표준 TLS 인증서·hostname 검증을 사용하며, 배포 trust anchor는
   별도 out-of-band 설정으로 받는다. 서명·key lifecycle·현재 유효기간 검증 전에는
   registry를 사용하지 않는다.
4. schema v14의 append-only
   `cp_target_attestation_registry_versions`가 trust domain별 활성화 sequence와
   bundle/predecessor/registry digest를 기록한다. 첫 활성화는 sequence 1만 허용하고,
   재시작·다중 replica에서도 rollback, gap, predecessor 불일치, 동일 sequence의 다른
   내용(equivocation)을 거부한다.
5. Target receipt 발행 시각이 이전 pin 만료 전이면 현재 pin과 이전 pin을 모두 받을 수
   있다. 만료 시각부터는 현재 pin만 허용한다. 성공 summary에는 기대 pin이 아니라 실제
   Worker가 관찰하고 검증한 SPKI digest를 보존한다.
6. 기존 단일 anchor와 registry v1/v2 inline 경로는 호환성을 유지한다. registry v3는
   서명 번들 밖에서 사용할 수 없다.

## 신뢰 경계와 한계

이 결정은 registry 배포 출처와 순서, 제한된 pin 교체를 증명한다. 다음은 증명하지 않는다.

- TLS exporter나 handshake transcript에 대한 session binding
- CA revocation, Certificate Transparency 또는 조직 정책 준수
- 배포 trust anchor 자체의 온라인 갱신·transparency/federation
- DB 백업까지 소실된 뒤의 외부 anti-rollback 기준
- 실행 중 background refresh; 현재 구현은 시작 시 한 번 가져오며 만료 뒤 Replay를
  fail closed 한다

## 결과

정상 교체는 새 pin을 현재 값으로, 기존 pin을 최대 24시간 retiring 값으로 배포한 뒤 다음
버전에서 retiring 값을 제거한다. 서명 번들의 sequence와 이전 digest가 이어지지 않으면
Control Plane은 시작하지 않는다. 다음 우선순위는 TLS exporter 또는 동등한 session
binding이며, 그 뒤 object-store/multipart Artifact 전송이다.
