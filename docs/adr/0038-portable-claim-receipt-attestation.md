# ADR 0038: 휴대 가능한 Claim receipt 공개키 증명

- 상태: Accepted
- 날짜: 2026-07-24

## 배경

ADR 0037까지의 Control Plane은 exact KISA M03·M06·A04 validity·impact·severity Claim을
각각 실행하고, ticket·compilation·Replay Run·output Artifact·receipt seal root를 projection
input authority v3에 보존한다. 그러나 이 권위의 최종 trust anchor는 Control Plane DB와
Artifact repository의 OS 계정·ACL이다. 다른 호스트의 검증자는 서버 비밀키 없이 receipt가
동일한지 확인할 수 없고, 내부 checkpoint용 HMAC 키를 공개 검증에 재사용할 수도 없다.

서명 파일을 완성된 projection Artifact의 digest에 포함하면서 동시에 그 digest를 서명하면
순환 의존성이 생긴다. 따라서 공개키 증명은 projection Artifact 자기 자신이 아니라, 그
Artifact를 만드는 입력 권위와 각 Claim receipt root를 서명해야 한다.

## 결정

1. `CreateReplayBatchRequest.portable_attestation`을 명시적 opt-in으로 추가한다. 이 값은
   `claim_projection: true`와 confirmation에서만 사용할 수 있다. 이 경로는
   `pajin.kisa-claim-attestation:v3` 정책을 사용하고, Ed25519 signer가 없으면 batch 생성부터
   fail closed한다. 기존 v1/v2 정책과 projection input authority v1/v2/v3는 변경하지 않는다.
2. 서명 statement는 trust domain·issuer·정책·batch ID·발급 시각, 전체
   `ReplayClaimProjectionInputAuthority`, 그 canonical digest와 receipt 수를 포함한다. 각
   validity·impact·severity item의 Claim identity, finalization, Replay Run, output Artifact,
   artifact-set digest, receipt seal root, gate/result digest가 따라서 한 서명에 결박된다.
3. 서명은 별도 domain prefix가 붙은 canonical JSON bytes에 Ed25519로 수행한다. bundle은
   statement SHA-256, key ID, algorithm과 base64url signature를 포함한다.
4. bundle은 `validation/v1alpha1/portable-replay-attestation.json`으로 confirmation projection
   transaction에 추가된다. transaction은 이 파일의 digest도 기록하고, Run seal은 transaction과
   bundle을 함께 봉인한다. 발급 시각은 immutable batch snapshot에서 가져오므로 crash recovery와
   response-loss retry가 같은 bytes를 다시 만든다.
5. trust anchor는 issuer·trust domain과 정렬된 공개키 lifecycle을 가진 별도 JSON 계약이다.
   정확히 한 key만 `active`이고 이전 key는 `retired` 또는 `revoked`다. `retired` key의 과거
   bundle은 유효 기간 안에서 검증할 수 있지만, `revoked` key는 발급 시각과 무관하게 항상
   fail closed한다. active private key는 trust anchor의 공개키와 일치해야 하며 내부 HMAC
   checkpoint key와 분리한다.
6. verifier는 bundle 안의 key를 신뢰하지 않고 호출자가 별도 전달한 trust anchor를 반드시
   요구한다. `GET /v1/replay/batches/{batch_id}/attestation`과
   `GET /v1/replay/attestation/trust-anchor`는 전송 편의 API일 뿐 신뢰 설정이 아니다.
   `pajin replay-attestation-verify <bundle> --trust-anchor <anchor>`가 서버 비밀 없이 같은
   검증을 수행하고 anchor digest를 출력한다.

## 보안 경계

이 조각은 다른 호스트가 “해당 trust domain의 Control Plane key가 이 exact Claim receipt
집합을 서명했다”는 사실과 이후 변조 여부를 검증하게 한다. 외부에서 고정한 trust anchor를
사용하면 같은 서버 응답만으로 key를 자기 승인하는 오류를 피할 수 있다.

그러나 이 서명은 별도 조직의 Worker가 실행했다거나 target이 독립적으로 응답했다는 사실,
물리적 격리·quiescence, remediation 완료 또는 transparency log 등재를 증명하지 않는다.
따라서 현재 validity 결과의 제품 disposition은 계속 `needs-review` 상한과
`independent-execution-attestation-missing` 경계를 유지한다. 독립 executor/target issuer,
HSM·외부 key custody, multi-host/object-store Artifact 전송과 transparency log는 후속 범위다.

## 결과

- Claim receipt 권위는 서버 비밀을 공유하지 않고 off-host에서 검증할 수 있다.
- key rotation은 이전 공개키를 `retired`로 보존해 기존 bundle을 유지하고, compromise는
  `revoked`로 전체 거부할 수 있다.
- signature bundle은 기존 sealed projection transaction 안에 들어가므로 새 DB schema나
  mutable backfill 없이 append-only 성질을 유지한다.
- 운영자는 trust anchor를 Control Plane과 다른 채널·소유 경계에서 배포하고 pin해야 한다.
