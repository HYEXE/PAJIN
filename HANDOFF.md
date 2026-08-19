# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-19
- 작업 체크아웃:
  `C:\\Users\\hyeon\\.codex\\visualizations\\2026\\08\\17\\01a00f73-cf28-7912-a9d0-cf9cc1ad7a95\\pajin-pentest-20260817`
- 브랜치: `main`
- 통합 기능 commit: `30124f2e99afb53fcb500219bb8e248746cd4b8d`
- branch/upstream: `main == origin/main`으로 최종 검증
- 완료 단계: `PENTEST-004C2B1` signed durable Worker coordination and verified 004C1 handoff
- 다음 단계: `PENTEST-004C2B2` concrete 004B/004C2A stage deployment adapters
- working-tree 통합 감사와 원격 반영: 완료
- Pull Request·merge·배포: 수행하지 않음

이 checkout은 검증된 recovery checkout의 비파괴 복제본이다. 원본
`C:\\Workspace\\HYEXEN\\PAJIN`은 변경하지 않았다. 이 worktree의
`UX-007B~R1`, `PENTEST-000~004C2B1` 통합 변경은 전체 감사 뒤 `30124f2`로 commit·push했다.
`UX-007R2`는 실제 production pilot inventory가 준비될 때까지 보류한다.

## PENTEST-004A/B/004C2A/B1 완료 상태

- `pajin pentest-compile`은 assessment YAML, signed authorization bundle, public trust anchor, exact evidence
  bytes와 외부 expected subject를 받아 현재 UTC에서 PENTEST-000/001A/001B를 다시 실행한다.
- output은 `<authorityDigest>/pentest-campaign-envelope-compilation.json`이며 no-follow atomic write 뒤 strict
  `PentestCampaignEnvelopeCompilationAuthority`로 즉시 재조회한다.
- raw authorization evidence와 private key는 artifact에 쓰지 않는다. activation·approval·Permit·Worker·network·
  execution과 Finding·report authority는 계속 false/absent다.
- local CLI의 `--expected-subject`는 identity 인증이 아니다. deployment가 authenticated principal에서 별도
  파생해야 하며, 004B C2 gate도 모든 실행 권위를 독립적으로 다시 검증한다.
- `PentestReconOperatorDeployment`는 004A artifact/evidence, current trust anchor, signed CAP-002 activation,
  Graph·approval·Run store, direct-mTLS Worker policy와 fixed Docker Gateway backend를 외부 SHA-256으로 고정한다.
- opt-in Worker route와 `pajin pentest-recon-dispatch`는 request가 이 권위를 대체하지 못하게 하고, 실제 server TLS
  evidence와 authenticated Worker principal을 기존 PENTEST-001C2 gate에 전달한다.
- runtime은 004A artifact를 raw evidence와 현재 trust anchor로 재컴파일하고 exact request binding 뒤 approval과
  one-use Permit을 소비해 signed-scope GET 하나만 dispatch한다. 성공·실패·취소 attempt를 terminal Run으로 봉인한다.
- exact retry는 봉인된 기존 receipt를 반환하고 Worker를 다시 호출하지 않는다. intent·approval·artifact·evidence·
  deployment digest 대체, 미인증 Worker와 미설정 runtime은 dispatch 전에 fail closed한다.
- `PentestReplayOperatorDeployment`는 sealed source·Discovery admission, fresh Replay compilation·approval,
  current Graph, signed activation, dedicated Replay Worker mTLS와 Run root를 외부 SHA-256으로 고정한다.
- `/v1/worker/pentest/replay/dispatch`와 `pajin pentest-replay-dispatch`는 기존 PENTEST-002B Plan과 freshness
  binding을 Permit 전에 기록하고 별도 Replay Worker TLS session에서만 실제 GET을 실행한다.
- 잘못된 selector는 mutation 전 거부되고, 잘못된 Worker는 Permit을 소비하거나 plan-only Run을 봉인하지 않는다.
  dispatch claim 이후 실패·취소와 성공은 봉인되며 exact retry는 동일 root를 재조회하고 Worker를 다시 호출하지 않는다.
- 004C2A는 comparison·Finding·추가 execution authority를 부여하지 않는다.
- 004C2B1은 `source → replay → baseline → negative-control → counterfactual`을 외부 Ed25519 stage activation과
  predecessor receipt digest로 결박한다. generic/Replay route는 별도 mTLS dependency를 유지하고 signed subject와
  live principal이 일치해야 한다.
- coordinator는 child 호출 전 `stage-started`를 봉인한다. 취소·restart 뒤 activation이 만료돼도 같은 start seal이
  있고 child adapter가 terminal seal을 반환할 때만 reconcile하며 새 dispatch는 금지한다.
- 다섯 terminal receipt와 body-free comparison을 모두 받은 뒤 생성한 004C1 deployment를 기존 loader로 즉시
  재검증한다. 성공한 경우에만 file SHA-256과 `workflowPreparationEligible=true`를 별도 봉인하며 execution·Finding
  authority는 계속 false다.

## UX-007O~R1 완료 상태

### concrete provider activation

- `ObjectStorageProviderDeploymentProfile`은 provider family, runtime-only credential custody,
  monotonic-fence idempotency, exact PUT/key/expiry signature coverage, redirect rejection, named
  server-side encryption policy, strong read-after-write consistency, observed idempotent prefix cleanup과
  local conformance profile을 content-address한다. 비밀정보와 URL은 포함하지 않는다.
- `ObjectStorageConcreteProviderActivation`은 exact UX-007M checkpoint, UX-007N adapter definition과
  deployment profile을 append-only chain에 결박한다. transport만 active이고 Artifact admission과
  finalization은 false다.
- journal `bootstrap()`은 명시적 provisioning이며 `open()`은 missing state를 생성하지 않는다. restart는
  SQLite integrity·foreign key·schema metadata/inventory, activation chain, attempt와 record chain을 다시 검증한다.
- UX-007P2는 local conformance 전용 `minio-s3-single-node` provider를 선택했다. production provider나
  deployment default는 아니며 deployment admission authority도 없다.

### intent-before-call journal과 fence

- 한 host-local journal에는 open attempt를 하나만 허용한다. attempt는 activation·adapter·authority checkpoint·
  binding digest, binding active window와 transactional monotonic fence를 결박한다.
- credential issue, completion, 모든 remote part read, cleanup, reconciliation은 각자 content-addressed operation을
  가진다. operation ID는 fixed-width fence를 포함하며 concrete provider가 binding별 high-water fence를
  적용해야 한다.
- 각 remote call 전에 `intent`가 먼저 commit되고 이후 `succeeded|rejected|unknown` 중 하나만 append된다.
  record는 digest chain이며 signed URL·credential·provider exception text·remote bytes를 저장하지 않는다.
- journaled provider 뒤에서도 UX-007N의 current-head-before-call, ephemeral credential 검증, remote manifest 전체
  재해시와 managed staging 경계가 그대로 적용된다.

### restart reconciliation과 successor guard

- restart는 새 attempt보다 pending attempt를 먼저 찾고 더 높은 recovery fence를 claim한다.
- provider-owned `reconcile_upload()`은 `completed|upload-open|absent|unknown`만 반환할 수 있다. `absent`는
  terminal 처리하고, `completed|upload-open`은 typed idempotent prefix cleanup 뒤 terminal 처리한다.
- `unknown`, invalid result 또는 provider exception은 secret-free 오류와 open attempt를 남겨 새 작업을 막는다.
  provider completion을 Artifact나 Replay finalization으로 승격하지 않는다.
- recovery fence 뒤 살아난 old session은 journal append 전에 거부된다. concrete provider도 lower operation fence를
  원격 호출에서 거부해야 한다.
- `activate_successor()`는 pending attempt가 없을 때만 UX-007M successor를 쓴 뒤 새 checkpoint에 provider
  activation을 append한다. 두 SQLite store 사이 crash는 새 head에서 provider runtime이 fail closed하고 operator가
  exact activation을 명시적으로 완결해야 한다.

### provider-common black-box conformance

- `ObjectStorageProviderConformancePlan`은 active activation·checkpoint·adapter·deployment profile·binding·
  local conformance profile·runtime challenge digest와 고정 case plan을 content-address한다.
- 공통 runner가 high-water fence, native multipart idempotency, redirect refusal, encryption receipt, strong
  read-after-write, idempotent prefix cleanup, exact PUT/key/expiry signature, adapter·SDK·HTTP log 비노출의
  8개 pass 기준을 소유한다. provider target은 pass boolean이 아니라 typed raw observation을 반환한다.
- 각 target call 전후에 durable current head, latest concrete activation, exact endpoint와 no-pending-attempt를
  재검증한다. suite 중 head/profile 변경은 report 전에 거부한다.
- expiry 음성 probe timestamp 이후에만 report를 만들며, raw log·signed URL·query·runtime secret·challenge bytes·
  provider exception은 durable model에 넣지 않는다. raw observation과 digest만 secret-free report에 남는다.
- repository target은 harness orchestration용 test fixture다. 실제 cloud/emulator adapter나 live evidence가 아니다.

### selected MinIO adapter와 live evidence

- exact inventory는 MinIO `RELEASE.2025-09-07T16-13-09Z` image index digest
  `sha256:14cea493d9a34af32f524e538b8346cf79f3321eff8e708c1e2960462bd8936e`, `linux/amd64`,
  `boto3==1.43.73`, `botocore==1.43.73`, `https://127.0.0.1:9443`, bucket
  `pajin-conformance-ux007p2`, path-style SigV4, runtime-only disposable root credential, SSE-C AES-256,
  per-run private CA와 single-node disposable isolation을 content-address한다.
- `MinioS3ObjectStorageAdapter`는 exact SDK/TLS CA/endpoint/bucket과 operation-ID fence를 검증하고 ephemeral
  presigned PUT+SSE-C headers, complete/read/cleanup/reconcile를 fail closed로 구현한다. runtime credential은
  redacted되고 durable model에 들어가지 않는다.
- `MinioS3ProviderConformanceTarget`은 실제 SDK와 no-follow HTTPS를 통해 8개 공통 case의 raw observation을
  만들고 common runner만 pass를 판정한다.
- latest retained inventory는
  `reports/object-storage-conformance/minio-inventory-0b7cb87b073c46d6e6729be1e207a5a70becf5fd2cf8503c245af1fffa472e85.json`,
  report는
  `reports/object-storage-conformance/minio-report-8118e37085ca0b707c30e15317bb690e857a14b8f825bbe38a9f29eb485f6c3f.json`이다.
  `2026-08-18T12:55:52.816069Z`부터 `2026-08-18T12:56:53.279149Z`까지 8/8가 통과했고
  `transportOnly=true`, Artifact admission/finalization은 false다.
- Docker lifecycle은 Windows host, actual TLS/S3 suite는 WSL Ubuntu에서 수행한다. Windows loopback TLS를
  가로채는 endpoint security는 우회하지 않았고 TLS verification을 끄지 않았다. 종료 뒤 exact container,
  named volume, runtime secret/certificate/SQLite temp가 남지 않았다.

### fresh·revocable deployment admission

- `ObjectStorageSelectedProviderEvidence`는 exact MinIO inventory, concrete activation과 passing report 전체를
  content-address하고 endpoint·provider family·encryption·profile·adapter·checkpoint digest를 교차 검증한다.
- v1 policy는 `maxReportAgeSeconds=3600`을 code-owned literal로 고정한다. `finishedAt <= now < validUntil`만
  허용하며 future report, exact expiry와 caller extension을 거부한다.
- `ObjectStorageProviderAdmissionStore`는 explicit bootstrap SQLite policy/admission chain이다. integrity·schema·
  metadata·identity·전체 predecessor를 다시 검증하고 exact external checkpoint로 rollback/stale write를 막는다.
- enabled policy는 evidence·inventory·report·activation·checkpoint·adapter·profile 전체를 선택한다. deny-all
  successor는 selection을 지우고 inventory/report revocation을 monotonic하게 누적해 기존 admission을 즉시 stale로 만든다.
- admission 전 current UX-007M head, UX-007O activation, runtime inventory, no-pending-attempt를 재검증한다.
  admitted runtime은 startup·attempt start와 credential/completion/read 직전에 gate를 다시 확인한다.
- cleanup/reconciliation은 freshness·revocation gate 밖에 둬 expired/revoked 상태에서도 기존 head·journal·fence 아래
  unknown remote state를 정리할 수 있다. Artifact admission/finalization과 public network는 계속 false다.
- latest live chain은 inventory `3351ef2b…610d`, report `57da9bf2…d8db`, evidence `647337e2…833a`,
  policy `3daca380…2b09`, admission `ab05ed89…238d`, checkpoint `c3bb8d01…d8b4`다. report 8/8가
  통과했고 admission window는 `2026-08-18T13:57:15.417767Z`부터 `14:57:15.417767Z`까지였다.
  target/store는 종료 시 제거돼 retained JSON만으로 current authority를 복원할 수 없다.

### AWS S3 production custody selection

- UX-007R1은 provider family `aws-s3`, Seoul `ap-northeast-2`, regional HTTPS endpoint, SigV4,
  virtual-hosted addressing과 pinned boto3/botocore `1.43.73`을 선택했다.
- tenant마다 exact account·bucket·`pajin/tenants/{tenantId}` prefix·VPC gateway endpoint·STS role·customer-managed
  symmetric KMS key를 요구한다. bucket/endpoint/organization/IAM/session/KMS policy는 값 대신 SHA-256으로 결박한다.
- STS는 900초 `AssumeRole`, external-ID digest, deterministic source identity와 exact tenant session tag만 허용한다.
  static credential과 credential persistence는 false다.
- KMS는 credential custodian과 분리된 security custodian, exact key ARN, 365일 rotation, disable-first revocation,
  30일 reviewed deletion을 요구한다. S3 Bucket Key는 object-level policy 경계를 위해 false다.
- transport bucket은 ephemeral cleanup용이라 unversioned·Object Lock false다. off-host immutable authority-state
  backup과 new-path restore drill은 별도 inventory/policy로 요구하며 transport cleanup과 섞지 않는다.
- operations·security·cost·external-checkpoint custodian은 서로 달라야 한다. retention·backup·restore·cleanup·cost
  policy digest와 RPO 5분/RTO 1시간을 선택하지만, 실제 수행됐다고 주장하지 않는다.
- `AwsS3ProductionProviderSelection`은 live inventory·issuer/KMS evidence·cross-tenant probe·restore drill을 요구하고
  production activation·transport admission·public network·Artifact admission·finalization·resource creation을 false로
  고정한다. AWS API 호출이나 외부 자원 생성은 수행하지 않았다.

## 주요 변경 파일

- `src/pajin/control_plane/pentest_workflow_coordination.py`
- `src/pajin/control_plane/api.py`, `src/pajin/control_plane/api_routes.py`
- `tests/test_pentest_recon_dispatch.py`, `tests/test_control_plane_web.py`
- `docs/orchestration/PENTEST-004C2B1-durable-worker-coordination.md`
- `docs/adr/0200-require-externally-signed-ordered-worker-stage-activation.md`
- `src/pajin/control_plane/pentest_replay.py`, `src/pajin/control_plane/pentest_replay_deployment.py`
- `src/pajin/control_plane/pentest_workflow_deployment.py`
- `tests/test_control_plane_actions.py`, `tests/test_control_plane_phase9_deployment.py`
- `docs/orchestration/PENTEST-004C2A-dedicated-replay-worker-entrypoint.md`
- `docs/adr/0199-dispatch-pentest-replay-through-dedicated-worker-session.md`
- `src/pajin/control_plane/pentest_recon.py`, `src/pajin/control_plane/pentest_recon_deployment.py`
- `src/pajin/control_plane/api.py`, `src/pajin/control_plane/api_routes.py`, `src/pajin/control_plane/client.py`
- `src/pajin/cli.py`, `tests/test_pentest_recon_dispatch.py`, `tests/test_pentest_compile_cli.py`
- `tests/test_control_plane_web.py`, `tests/test_control_plane_worker_mtls_config.py`
- `docs/orchestration/PENTEST-004B-approved-recon-operator-entrypoint.md`
- `docs/adr/0197-expose-approved-recon-only-through-live-worker-session.md`
- `src/pajin/modes/pentest/service.py`, `src/pajin/modes/pentest/__init__.py`
- `src/pajin/cli.py`, `tests/test_pentest_compile_cli.py`
- `docs/orchestration/PENTEST-004A-operator-compilation-entrypoint.md`
- `docs/adr/0196-expose-pentest-compilation-without-execution-authority.md`
- `src/pajin/control_plane/object_storage_recovery.py`
- `tests/test_control_plane_object_storage_recovery.py`
- `docs/orchestration/UX-007O-durable-object-storage-provider-recovery.md`
- `docs/adr/0191-journal-and-reconcile-object-storage-provider-attempts.md`
- `src/pajin/control_plane/object_storage_conformance.py`
- `tests/test_control_plane_object_storage_conformance.py`
- `docs/orchestration/UX-007P-provider-common-conformance-harness.md`
- `docs/adr/0192-derive-provider-conformance-from-raw-observations.md`
- `src/pajin/control_plane/object_storage_minio.py`
- `scripts/run-minio-object-storage-conformance.py`
- `tests/test_control_plane_object_storage_minio.py`
- `docs/orchestration/UX-007P2-minio-selected-provider-live-conformance.md`
- `docs/adr/0193-select-disposable-minio-for-local-provider-conformance.md`
- `src/pajin/control_plane/object_storage_admission.py`
- `docs/orchestration/UX-007Q-selected-provider-deployment-admission.md`
- `docs/adr/0194-require-fresh-revocable-selected-provider-admission.md`
- `src/pajin/control_plane/object_storage_production.py`
- `tests/test_control_plane_object_storage_production.py`
- `docs/orchestration/UX-007R1-aws-s3-production-custody-selection.md`
- `docs/adr/0195-select-aws-s3-seoul-production-custody-boundary.md`
- `reports/object-storage-conformance/`
- `pyproject.toml`, `uv.lock`
- `README.md`, `PLAN.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`, `HANDOFF.md`

통합 감사에서 공개 non-safe route inventory 누락 5건, operator workflow의 CA-only HTTPS 구성 불가,
`object.__new__` 기반 collaborator 테스트 seam의 maintenance authorizer 누락을 발견해 수정했다.
Human operator의 CA-only client 허용은 `require_client_certificate=False`를 명시한 경로에만 적용하고,
Recon·Replay Worker와 daemon은 기존 atomic mTLS 기본값 `True`를 유지한다.

## 현재 검증 근거

- Linux CI 수집 복구:
  - 최신 run `32214486821`과 기준 commit run `31615548549`는 모두 `from tests...` import 12건을
    `ModuleNotFoundError`로 중단했다. 설치·Ruff·mypy는 통과했다.
  - 테스트에는 `tests.test_x`와 `test_x` import가 함께 있으므로 package marker 대신 pytest
    `pythonpath = ["src", "."]`로 저장소 root만 명시했다.
  - 격리된 locked `uv run pytest --collect-only`: `4182 tests collected`, 오류 0건
  - 기존 수집 실패 12개 모듈의 격리 locked `uv run pytest`: `154 passed`
- 수정·신규 Python 테스트 전체 묶음: `419 passed, 2 skipped, 1 deselected`
  - skip: Node.js runtime 부재 1건, POSIX-only durable managed import 1건
  - deselect: Windows endpoint security가 간헐적으로 가로채는 실제 loopback mTLS handshake 1건
- 분리한 loopback mTLS handshake: 현재 `1 failed`
  - server thread 예외나 제품 assertion이 아니라 5초 내 health 응답을 받지 못했다.
  - 같은 구현은 이번 감사 중 격리 실행에서 3회 연속 통과한 뒤 다시 실패해 Windows 환경 비결정 제약으로
    분류했다. TLS 검증과 endpoint security는 우회하지 않았다.
- 전체 pytest: `3878 passed, 116 skipped, 187 failed`
  - 실패 다수는 Windows의 POSIX directory fsync·dirfd, symlink privilege와 그 downstream admission
    cascade에 집중됐다. clean checkout에서 validation status `409` 대 `404`, symlink `WinError 1314`,
    Worker health `16 passed, 3 failed`를 같은 원인으로 재현했다.
  - 전체 실행에서 새로 드러난 collaborator seam 누락은 수정했고 해당 테스트와 변경 테스트 전체 묶음을
    다시 통과시켰다. 전체 187건을 모두 clean checkout과 일대일 대조했다고 주장하지 않는다.
- codex-security working-tree diff 감사: coverage complete, reportable finding 0
  - Worker mTLS, exact ABAC, Pentest execution, Object Storage, Graph evidence, operator interface를 검토했다.
  - production AWS·실제 외부 target·multi-host deployment는 활성화하거나 검증하지 않았다.
- live MinIO TLS/S3 suite: 독립 3회 성공, 각 8/8 case 통과
  - latest report model digest: `57da9bf2da7c96e396e2da3ba9462575a109633a78347fcaf91abf3f1ec9d8db`
  - 종료 후 target container·named volume·temporary directory: 0
  - retained report secret pattern scan: match 없음
- UX-007Q live evidence/admission chain: 6개 strict model 재파싱·digest 교차 검증 통과
  - report 8/8, one-hour admission, public network·Artifact admission·finalization false
  - 종료 후 target container·named volume·temporary authority/admission stores: 0
- `ruff check src tests containers scripts`: 통과
- Linux 대상 전체 strict mypy: `Success: no issues found in 313 source files`
- 전체 `src` compileall: 통과
- 문서 정책 검사: `2 passed`
- `uv lock --check`: `Resolved 71 packages`, exact `boto3==1.43.73`·`botocore==1.43.73`
- `git diff --check`: 통과, 기존 CRLF 변환 경고만 출력

저장소 전체 `ruff format --check` 기준선은 아직 통과하지 않으며 이번 통합에서 unrelated 대규모 format
변경을 만들지 않았다. UX-007J Node runtime과 Windows/Avast live mTLS handshake도 보안 정책을 우회하지 않는다.

## 알려진 제한

- PENTEST-004B/004C2A는 fixed local Docker Gateway backend를 Control Plane process에서 실행한다. 004C2B1은
  five-stage journal과 crash reconciliation을 구현했지만 concrete child deployment registry/adapter는 아직 없다.
  runtime은 injection 전용이며 generic queue·distributed Worker 위임과 cross-host fence도 없다.
- 004B 검증은 deterministic backend를 사용했으며 실제 외부 target을 호출하지 않았다. 004C1도 이미 봉인된
  실행 증거의 조합만 검증했으며 live multi-Worker dispatch는 하지 않았다. 현재 실행 Capability는 signed Scope에
  제한된 one-shot GET Recon뿐이고 concrete execution adapter와 LLM/Web/RAG/MCP/System coverage는 각각
  PENTEST-004C2B2와 REDTEAM-001 범위다.
- selected MinIO는 archived final OSS image의 disposable single-node local conformance target일 뿐 production
  provider나 multi-node 지원 선언이 아니다.
- UX-007R1은 AWS S3 Seoul desired state와 custody requirement만 선택했다. 실제 AWS account·bucket·role·KMS key·
  VPC endpoint·live policy read·CloudTrail·isolation probe·backup/restore·cost approval은 제공되거나 검증되지 않았다.
- admission·authority-head·attempt-journal store는 하나의 cross-database transaction이 아니며 local cooperative
  pre-call recheck를 사용한다. admission checkpoint는 database 밖에 보관해야 rollback을 검출한다.
- automatic expiry scheduler, historical/old-revision garbage collection, multi-process service lock과 cross-host
  fence coordinator는 없다.
- provider journal과 authority head를 하나의 anti-rollback backup/restore 단위로 묶지 않았다.
- authority head와 provider activation은 cross-database transaction이 아니다. ordered fail-closed repair를 쓴다.
- 실제 provider SDK/HTTP log capture, KMS/HSM, tenant credential isolation, off-host retention, public API와
  Distributed Worker는 별도 검증 경계다.
- remote file tree는 기존 maximum 64 MiB까지 memory에 모아 staging 전 전체 검증한다.
- 저장소 전체 Ruff format에는 기존 기준선 차이가 있다.

## Git 재개 확인

- `origin`의 기존 `https://github.com/HYEXEN/PAJIN.git` URL은 push 과정에서
  `https://github.com/HYEXE/PAJIN.git`으로 이동했다는 GitHub 안내를 반환했지만 redirect를 통해 push는
  성공했다. remote URL 자체는 이번 작업에서 변경하지 않았다.
- GitHub는 push 응답에서 default branch의 high 등급 Dependabot 경고 1건을 알렸다. 경고 상세와 이번
  dependency diff의 관련성은 이 체크포인트에서 확인하지 않았으므로 해결 또는 무관하다고 주장하지 않는다.

```powershell
git status --short --branch
git rev-parse HEAD
git rev-parse '@{upstream}'
git diff --cached --stat
git diff --check
```

staged 변경과 진행 중인 merge/rebase/cherry-pick/revert/bisect가 없어야 한다. 실제 Git과 파일시스템이 이
문서와 다르면 실제 상태를 우선한다. 사용자 승인 없이 commit 또는 remote 작업을 수행하지 않는다.

## 다음 수직 슬라이스

`PENTEST-004C2B2`는 외부 서명 activation의 child deployment ID/digest를 server-owned registry에서 exact resolve한다.
004B source/세 Control runtime과 004C2A Replay runtime을 각각 live direct-mTLS scope/principal로 호출하고,
`dispatch_stage`는 active activation에서만, `reconcile_stage`는 기존 terminal child seal에서만 동작해야 한다. Replay
adapter는 002B body-free comparison을 생성하고 모든 adapter는 실제 `PentestWorkflowExecutionReference`를 반환한다.
request가 path·approval·Graph Decision·Worker identity를 공급할 수 없는 deployment loader, restart reload, CLI/operator
activation path와 adversarial 회귀까지 연결해 004C2B를 닫은 뒤 REDTEAM-001 Capability 확대를 시작한다.
