# ADR 0044: Target 서명 TLS session binding

- 상태: 승인
- 날짜: 2026-07-24

## 배경

ADR 0042와 0043은 Worker가 관찰한 HTTPS leaf SPKI, exact CONNECT route와 signed registry
권위를 결박한다. 그러나 같은 인증서 key를 쓰는 서로 다른 TLS session의 Target receipt와
Executor proof를 합쳐도 기존 필드만으로는 구분할 수 없다. application exchange가 Worker가
관찰한 바로 그 TLS session에서 발생했다는 양측 증명이 필요하다.

Python 3.12 표준 `ssl` API는 RFC 5929 `tls-unique` channel binding만 제공하고 TLS exporter
API는 제공하지 않는다. RFC 9266의 `tls-exporter`는 TLS 1.3에 필요한 후속 경계로 남긴다.

## 결정

1. session binding을 요구하는 signed registry는
   `pajin.replay.target-attestation-trust-registry/v4`를 사용한다. v4의 모든 HTTPS exact
   URL entry는 기존 leaf SPKI pin과 함께 `tls_session_binding: tls-unique-sha256`을
   선언한다. HTTP entry에는 이 필드를 허용하지 않는다.
2. PAJIN lab Target은 `PAJIN_TARGET_TLS_SESSION_BINDING=tls-unique-sha256`을 명시한
   경우에만 이 모드를 활성화한다. TLS certificate 설정을 필수화하고 protocol을 TLS 1.2로
   제한한 뒤 server-side `SSLSocket.get_channel_binding("tls-unique")` 값을
   `pajin.replay.target-tls-unique-binding/v1` domain과 함께 SHA-256한다.
3. Worker는 표준 PKIX·hostname 검증을 통과한 같은 socket에서 leaf SPKI와 TLS 1.2
   `tls-unique` 값을 response 반환 전에 읽고 동일한 domain-separated SHA-256을 transcript에
   기록한다. TLS 1.3이나 channel binding 미지원 runtime에서는 session digest를 만들지 않는다.
4. Target receipt statement v2는 exact request·response와 함께 `TLSv1.2`,
   `tls-unique-sha256`, Target 측 session digest를 Ed25519로 서명한다. Executor TLS binding
   v3는 CONNECT route, Worker 관찰 SPKI와 Worker 측 session digest를 별도 workload key로
   서명한다.
5. Control Plane은 registry v4 route에서 receipt v2와 TLS binding v3를 요구하고 Target·Worker
   session digest, binding type, TLS version과 SPKI pin을 모두 exact 비교한다. receipt v1,
   binding v1/v2, digest 불일치와 cross-session proof 조합은 fail closed 한다. 성공 summary에는
   실제 검증한 session digest 집합을 보존한다.
6. 기존 단일 anchor, registry v1~v3, receipt v1과 TLS binding v1/v2는 기존 의미로 계속 읽고
   검증한다. registry v4는 v3와 마찬가지로 signed distribution bundle 밖에서 사용할 수 없다.

## 신뢰 경계와 한계

이 결정은 PAJIN의 TLS 1.2 lab profile에서 Target 서명 application exchange와 Worker 관찰
HTTPS connection이 같은 `tls-unique` channel binding을 공유했음을 증명한다. 다음은 증명하지
않는다.

- TLS 1.3 `tls-exporter` channel binding. Python 표준 API가 exporter를 노출하지 않으므로
  registry v4는 TLS 1.3에서 약화하지 않고 거부한다.
- TLS 1.2 extended master secret 협상 자체의 별도 attestation. 현재 lab은 현대 OpenSSL
  양 endpoint와 renegotiation 없는 단일 request connection에 의존한다.
- 전체 handshake transcript, cipher·ALPN, session resumption 정책, client workload identity
  또는 mTLS
- CA revocation·Certificate Transparency, HSM/KMS custody, registry background refresh와
  외부 transparency/federation

## 결과

같은 certificate key를 공유하더라도 다른 TLS connection에서 생성된 Target receipt와 Worker
proof는 session digest가 달라 결합할 수 없다. 운영 TLS 1.3 지원은 RFC 9266
`tls-exporter`를 노출하는 runtime/client-server adapter를 도입하는 후속 과제로 유지한다.
다음 제품 우선순위는 2 MiB를 넘는 object-store/multipart portable Artifact 전송이다.
