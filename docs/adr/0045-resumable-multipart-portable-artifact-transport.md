# ADR 0045: 재개 가능한 multipart portable Artifact 전송

- 상태: 승인
- 날짜: 2026-07-25

## 배경

ADR 0039의 첫 수직 조각은 sealed Replay Run을 base64 인라인 bundle로 전송한다. 이 경로는
Control Plane의 4 MiB request fence 안에서 동작하도록 raw 전체 2 MiB, 파일당 1 MiB로
제한된다. 따라서 증적이 이 한도를 넘으면 executor 서명, Target 증명과 sealed Run이 모두
정상이더라도 다른 host의 Control Plane에 전달할 수 없다.

caller가 지정한 filesystem 경로나 공유 volume을 다시 허용하면 기존 managed Artifact
admission의 경로 치환·link traversal·TOCTOU 방어를 약화한다. 대형 bytes는 발급된 Replay
authority와 executor 서명을 먼저 검증한 뒤, 서버가 소유한 제한된 object namespace에
나누어 저장하고 최종 manifest와 sealed Run을 다시 검증해야 한다.

## 결정

1. 기존 `pajin.control-plane.portable-artifact-bundle/v1` 인라인 경로는 그대로 유지한다.
   raw 전체 2 MiB와 파일당 1 MiB를 넘을 때만
   `pajin.control-plane.portable-artifact-multipart-manifest/v1` 경로를 선택한다.
2. 첫 multipart 조각의 상한은 전체 64 MiB, 파일당 16 MiB, 256 files, depth 24다. part
   크기는 1 MiB로 고정한다. manifest는 canonical 상대 경로, 파일 size·SHA-256과 기존
   canonical manifest SHA-256만 포함하며 파일 bytes를 포함하지 않는다.
3. Replay Worker는 upload 시작 요청에 exact lease·ticket·fence·output staging capability,
   manifest와 executor attestation을 함께 보낸다. Control Plane은 live Replay authority,
   permit coverage, signer·trust anchor와 manifest metadata를 검증하기 전에는 part bytes를
   받지 않는다.
4. 검증된 upload는 owner-private repository의
   `pajin.control-plane.local-object-store/v1` namespace에 output staging ID별로 저장한다.
   namespace 작업은 process-shared directory lock으로 직렬화하고 upload authority는 완성된
   임시 디렉터리에서 원자적으로 publish하고 part도 완전히 기록·동기화한 임시 객체에서
   원자적으로 이동한다. begin과 part PUT은 exact retry에 멱등이다. 같은 file index·part
   number에 다른 bytes가 오거나 part size·digest·sequence가 manifest와 다르면 fail closed
   한다.
5. Worker는 Control Plane transient 오류에서 같은 begin 또는 part를 제한된 backoff로
   재전송한다. lease·fence·인증·protocol 오류는 재시도하지 않는다. 각 part request는
   base64를 포함해 기존 4 MiB request fence 안에 남는다.
6. 최종화 시 Control Plane은 모든 part의 완전한 집합과 순서를 확인하고 파일 size·SHA-256,
   canonical manifest와 tree content digest를 다시 계산한다. 그 뒤 owner-issued staging
   reservation에 원자적으로 publish하고 기존 managed Artifact import, Run integrity,
   artifact-set, receipt와 seal 검증을 그대로 수행한다.
7. multipart transport receipt는 object-store profile, staging ID, manifest·file·byte·part
   수와 executor attestation digest를 결박한다. receipt digest와 executor attestation
   digest는 기존 finalization result·projection authority에 보존한다.

## 보안 경계와 한계

이 조각은 Control Plane host의 owner-private filesystem을 object-store adapter로 사용한다.
외부 S3 호환 저장소, pre-signed URL, multi-tenant bucket policy, server-side encryption,
retention·garbage collection과 orphan upload 만료는 아직 제공하지 않는다. Worker snapshot은
64 MiB 상한 안에서 메모리에 수집되며, durable materialization은 기존 managed repository와
같이 POSIX directory `fsync`를 요구한다.

multipart receipt는 전송된 bytes와 executor authority의 일치를 증명하지만 Target 또는
조직의 독립성을 새로 증명하지 않는다. Target-attested Replay의 독립 실행 승격 조건은
ADR 0040~0044의 receipt·HTTPS·SPKI·session 검증을 그대로 요구한다.

## 결과

sealed Replay Run이 2 MiB를 넘더라도 64 MiB 경계 안에서는 공유 filesystem 없이 여러
요청으로 전송하고 transient 실패 뒤 exact part부터 다시 보낼 수 있다. 기존 작은 Run은
직렬화와 검증 의미가 변하지 않는다.

다음 전송 과제는 외부 object-store adapter와 pre-signed multipart upload, upload expiry와
garbage collection, encryption·tenant isolation, 더 큰 스트리밍 snapshot이다. TLS 1.3
RFC 9266 exporter와 registry runtime refresh도 별도 후속 경계로 유지한다.
