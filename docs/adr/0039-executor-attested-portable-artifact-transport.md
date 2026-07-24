# ADR 0039: Executor 서명 기반 휴대형 Replay Artifact 전송

- 상태: Accepted
- 날짜: 2026-07-24

## 배경

ADR 0038은 Control Plane이 발행한 exact Claim receipt 집합을 외부에서 검증할 수 있게 했지만,
실행 주체는 여전히 Control Plane과 같은 공유 staging volume에 출력해야 했다. 또한 공개 서명은
Control Plane receipt authority의 서명일 뿐, 별도 workload identity의 executor가 어떤
compilation·permit·sealed output을 실행했다고 관찰했는지는 증명하지 않았다.

공유 volume을 단순히 원격 경로 또는 caller-supplied filesystem path로 바꾸면 path substitution,
TOCTOU, link traversal과 불완전 업로드가 기존 managed Artifact admission 경계를 우회한다.
반대로 executor 서명만 추가하고 Artifact bytes를 결박하지 않으면 올바른 receipt를 다른 output에
재사용할 수 있다.

## 결정

1. B2.8a는 executor workload key와 Control Plane key를 분리한다. executor만 Ed25519 private
   key를 보유하고, Control Plane은 별도 배포된 issuer·trust-domain 공개키 trust anchor만
   보유한다. key lifecycle은 `active`·`retired`·`revoked`를 사용하며, bundle 안의 key material은
   신뢰하지 않는다.
2. `ReplayFinalizeRequest`의 휴대형 형태는 `artifact_bundle`과 `executor_attestation`을 항상
   함께 요구한다. bundle은 canonical 상대 경로로 정렬된 regular-file 목록과 각 file의
   size·SHA-256·base64 bytes, 전체 manifest SHA-256을 가진다. 첫 수직 조각의 상한은 raw
   2 MiB, file당 1 MiB, 256 files, depth 24다. 절대·상위·dot 경로, prefix collision,
   duplicate path, symbolic link, hard link와 special file은 fail closed한다.
3. executor statement는 issuer·trust domain·profile·발급 시각과 batch·item·Job·ticket·fence·
   Replay Run·source root·compilation·execution-context digest를 포함한다. canonical 순서의
   permit digest와 Replay request ID, bundle manifest·file count·total bytes, artifact-set
   digest와 두 seal root도 서명한다. 서명 domain은 Control Plane Claim receipt 서명과 분리한다.
4. Control Plane은 어떤 caller-supplied Artifact bytes도 복사하기 전에 외부 trust anchor로
   서명과 발급 authority를 검증한다. 서로 다른 host clock은 미래 방향 최대 30초만 허용하고
   attestation 시각은 execution context와 모든 permit 발급보다 빠를 수 없다. 그 다음 opaque
   server-owned staging reservation에 bundle을 원자적으로 materialize하고, 기존 managed
   repository가 tree content digest와 Run integrity, artifact-set, receipt와 seal을 다시 검증한다.
   portable manifest digest는 admitted `ArtifactRef.content_digest`와 정확히 같아야 한다.
5. Control Plane이 관찰한 transport receipt와 executor attestation은 두 digest 및 검증에 사용한
   trust-anchor digest와 함께 immutable Replay Job finalization result에 보존되고 finalization
   result digest에 결박된다. projection input authority도 transport·attestation digest를 포함하며,
   전체 executor attestation은
   `validation/v1alpha1/executor-attestations/{item_id}.json`으로 projection Run seal 안에
   봉인한다.
6. 기존 shared-staging finalization은 호환 경로로 유지한다. portable 요청과 기존 요청은
   idempotent retry에서 서로 대체할 수 없고, 동일 portable retry도 저장된 attestation과 exact
   manifest가 같아야 한다.

## 보안 경계

이 결정은 “고정된 executor trust domain의 workload key가 이 exact Control Plane authority,
permit set와 sealed output tree를 관찰해 서명했다”는 증거와 작은 Artifact의 다중 호스트 전송을
제공한다. Control Plane은 executor private key를 갖지 않으며, 서명 실패는 Artifact import 전에
거부한다.

그러나 executor는 여전히 target 응답을 중계하는 주체다. 이 증명만으로 target workload가 실제
응답했다거나 provider audit log·KMS·HSM·transparency log에 실행이 기록됐다고 판단할 수 없다.
따라서 confirmation Gate는 계속 `needs-review`와
`independent-execution-attestation-missing`을 유지한다. B2.8b가 target issuer의 challenge-bound
signed receipt를 host-observed proxy receipt와 결박한 뒤에만 독립 실행 승격을 검토한다.

## 결과

- Replay Worker와 Control Plane이 공유 filesystem을 사용하지 않아도 작은 sealed Run을 전송할
  수 있다.
- signer, issued authority, permit set와 transferred bytes가 하나의 검증 사슬로 묶인다.
- 2 MiB 상한은 현재 4 MiB Control Plane request fence 안에서 동작하는 최소 조각이다. 대형
  Artifact, resume, multipart와 object-store pre-signed upload는 content-addressed manifest
  계약을 재사용하는 후속 transport adapter 범위다.
- 운영자는 executor private key를 Control Plane에서 분리하고 trust anchor를 별도 채널에서
  배포·고정해야 한다.
