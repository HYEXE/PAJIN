# ADR 0042: Worker 관찰 TLS leaf SPKI 결박

- 상태: 승인
- 날짜: 2026-07-24

## 배경

ADR 0041의 HTTPS transport proof는 proxy가 관찰한 opaque CONNECT route와 Target 서명
application exchange를 정확히 결합하지만, Worker가 실제 TLS handshake에서 받은 server
certificate와 registry의 Target identity를 결박하지 않는다. DNS·route와 Target application
key가 맞더라도 TLS endpoint key가 예상과 다른 경우를 별도로 거부할 수 있어야 한다.

certificate 전체 DER fingerprint는 인증서 재발급 때 같은 public key를 유지해도 바뀐다.
반대로 SubjectPublicKeyInfo(SPKI) digest는 key가 유지되는 인증서 교체를 허용하면서 예상하지
않은 endpoint key를 검출한다. 이 범위는 TLS channel 전체나 인증서 체인의 운영 적합성을
증명하는 것이 아니라, 표준 HTTPS 검증 뒤에 관찰한 leaf key를 exact registry route에 추가로
결박하는 수직 조각이다.

## 결정

1. `pajin.replay.target-attestation-trust-registry/v2`를 추가한다. v2의 모든 HTTPS exact URL
   entry는 lowercase SHA-256 형식의 `tls_leaf_spki_sha256`을 반드시 가진다. HTTP entry에는
   이 필드를 허용하지 않는다. v1 registry와 기존 단일 anchor 설정은 직렬화와 검증 호환성을
   유지하고 certificate pin을 받을 수 없다.
2. Worker는 기본 Python HTTPS stack의 PKIX chain·hostname 검증을 그대로 수행한다. 검증된
   socket에서 public `SSLSocket.getpeercert(binary_form=True)`로 leaf certificate DER를 읽고,
   `SubjectPublicKeyInfo` DER의 SHA-256을 계산한다. certificate가 없거나 decode할 수 없거나
   digest 관찰이 누락되면 HTTPS AI exchange를 fail closed 한다.
3. Worker 관찰값은 transcript의 각 HTTPS turn에 `tlsPeerLeafSpkiSha256`으로 기록된다.
   Executor는 raw/typed transcript 일치를 다시 확인하고 기존 CONNECT receipt 및 Target
   receipt와 함께 `pajin.replay.target-tls-binding/v2`로 서명한다.
4. Control Plane이 registry v2 HTTPS entry를 검증할 때는 TLS binding v2와 registry의 exact
   SPKI digest 일치를 요구한다. pin 불일치나 TLS binding v1 downgrade는 거부한다. v1
   registry와 단일 anchor 경로는 기존 TLS binding v1을 계속 받을 수 있다.
5. 성공한 verification summary에는 실제 검증에 사용된 SPKI digest 집합을 정렬·중복 제거해
   결박한다. v1 경로에서는 새 필드를 직렬화하지 않아 기존 canonical digest를 바꾸지 않는다.

## 신뢰 경계와 한계

이 결정은 표준 PKIX·hostname 검증을 통과한 Worker의 peer leaf public key와 Control Plane의
exact Target registry route가 같음을 executor 서명 아래 증명한다. SPKI pin은 다음을 증명하지
않는다.

- 전체 certificate DER, issuer 또는 chain이 동일하다는 사실
- revocation, Certificate Transparency, 조직 정책 또는 CA 운영 적합성
- 특정 TLS session의 handshake transcript, negotiated protocol, cipher 또는 application
  bytes와의 cryptographic channel binding
- Worker·Executor 자체의 독립 workload identity나 HSM/KMS key custody

pin rotation은 현재 인증서/key 배포와 registry 환경 설정을 운영자가 원자적으로 조정해야 한다.
signed remote registry distribution, monotonic anti-rollback, old/new pin overlap, transparency와
자동 rotation은 제공하지 않는다. Python HTTPS connection hook은 현재 Worker runtime의 표준
library 계약에 의존한다. TLS exporter API를 사용할 수 있는 runtime과 protocol을 도입하기
전까지 이 증명은 endpoint key binding이며 session binding은 아니다. portable Artifact의
2 MiB 한계도 그대로 남는다.

## 결과

- registry v2를 선택한 HTTPS Target-attested Replay는 예상하지 않은 leaf public key와
  TLS binding v1 downgrade를 fail closed 한다.
- 인증서가 재발급되어도 동일 key를 유지하면 pin을 재사용할 수 있지만, key rotation에는
  명시적인 registry 변경이 필요하다.
- 다음 개발 단위는 signed registry 배포, monotonic anti-rollback과 old/new pin overlap
  rotation이다. 그 뒤 TLS exporter 또는 동등한 session binding을 검토하고,
  object-store/multipart portable Artifact 전송으로 확장한다.
