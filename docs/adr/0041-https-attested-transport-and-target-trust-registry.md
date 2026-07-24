# ADR 0041: HTTPS-aware attested transport와 Target trust registry

- 상태: 승인
- 날짜: 2026-07-24

## 배경

ADR 0040의 B2.8b는 Target 서명 receipt와 host proxy의 평문 HTTP request/response digest를
결합했다. 이 계약을 HTTPS에 그대로 적용하면 proxy가 TLS 내부의 application bytes를
관찰했다는 거짓 주장이 된다. 또한 하나의 전역 Target anchor만 받는 설정은 서로 다른 Target
issuer를 안전하게 운영할 수 없고, 잘못된 anchor fallback을 발견하기 어렵다.

## 결정

1. 기존 `pajin.kisa-target-attestation:v4`, HTTP proxy binding v1, 단일 anchor 설정은 호환성을
   유지한다. HTTPS는 같은 명시적 `target_attestation=true` 정책 안에서 별도의 transport
   binding으로 표현한다.
2. egress proxy는 성공한 HTTPS tunnel마다
   `pajin.dev/egress-https-connect-receipt/v1`을 기록한다. receipt에는 canonical
   `host:port`, 그 SHA-256, DNS로 선택한 IP, 연속 sequence와
   `applicationVisibility=opaque`가 들어간다. request path, method, body 또는 response를
   관찰했다고 주장하지 않는다.
3. Executor는 각 CONNECT receipt를 Target이 서명한 exact application exchange와 결합해
   `pajin.replay.target-tls-binding/v1`으로 서명한다. Control Plane은 permit-derived target
   digest, CONNECT authority/sequence, transcript digest, Target receipt signature와 key
   lifecycle을 모두 재검증한다.
4. 일반 AI Tool과 Retest는 계속 완전한 평문 HTTP receipt 없이는 trusted execution으로
   인정되지 않는다. opaque CONNECT를 받아들이는 경로는 Target receipt가 필수인
   target-attested Replay로 제한한다.
5. `pajin.replay.target-attestation-trust-registry/v1`은 canonical exact Target URL을 최대
   128개까지 각각 하나의 public trust anchor에 연결한다. route는 정렬·중복 금지이며 wildcard,
   origin fallback, unknown-target fallback을 허용하지 않는다.
6. Control Plane의 `PAJIN_CP_TARGET_ATTESTATION_TRUST_REGISTRY`와 기존
   `PAJIN_CP_TARGET_ATTESTATION_TRUST_ANCHOR`는 상호 배타적이다. registry를 사용한 검증
   summary와 finalization authority에는 registry ID/digest와 실제 선택된 anchor digest를 함께
   결박한다.
7. 개발 AI Target은 `PAJIN_TARGET_TLS_CERTIFICATE`와
   `PAJIN_TARGET_TLS_PRIVATE_KEY`가 함께 제공될 때 TLS 1.2 이상 listener로 기동한다. 둘 중
   하나만 있으면 기동을 거부한다.

## 신뢰 경계와 한계

이 조각은 proxy가 어느 authority와 IP에 TCP tunnel을 만들었는지, 그리고 해당 tunnel을 통해
성공한 application exchange를 어떤 Target key가 서명했는지를 결합한다. proxy가 TLS plaintext,
certificate chain, negotiated protocol 또는 server certificate fingerprint를 관찰했다는 뜻은
아니다. TLS 인증서 검증은 Worker의 표준 HTTPS client에 남아 있으며, certificate pinning,
TLS exporter binding, mTLS workload identity와 HSM/KMS key custody는 후속 경계다.

registry는 exact URL 라우팅과 버전 digest를 제공하지만 동적 배포 discovery, transparency log,
조직 간 federation 또는 자동 key rotation을 제공하지 않는다. 하나의 Replay proof set이 여러
anchor를 가로지르면 현재 summary 계약은 fail closed 한다.

## 결과

- HTTPS Target-attested Replay는 평문 관찰로 위장하지 않고 CONNECT route와 Target 서명
  application exchange를 함께 검증할 수 있다.
- 여러 Target issuer를 하나의 versioned registry로 운영하되 잘못된 Target이나 fallback은
  검증 단계에서 거부된다.
- 다음 개발 단위는 certificate/exporter binding과 registry 배포·회전 자동화, 이어서
  object-store/multipart portable Artifact 전송이다.
