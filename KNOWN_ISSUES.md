# PAJIN 알려진 문제

재현된 미해결 제약만 기록한다. 비밀정보의 실제 값과 추측성 백로그는 기록하지 않는다.
로드맵 작업은 `PLAN.md`에서 관리한다.

## MEM-001/002/003 협업 source·reference·Snapshot 경계

- 상태: 의도적으로 제한된 source adapter, metadata-only reference와 receiver-neutral Snapshot 경계
- 현재 보장: 기존 CampaignFact Proposal을 다시 파싱하고 exact sealed Campaign·Run·현재 root와
  bounded evidence digest를 검증한 뒤에만 기존 Graph Admission Authority로 전달한다. MEM-002는
  기존 GraphEvidence identity와 exact current sealed artifact metadata만 content-addressed reference로
  연결하며 bytes나 filesystem path를 반환하지 않는다. MEM-003은 exact current Graph Snapshot에서
  admitted Fact 전체와 exact admitted Evidence에 대응하는 reference membership만 파생한다.
- 제한: filesystem seal은 producer·Agent·Task·request·Grant·Capability의 의미적 권위를 증명하지
  않는다. 이 전체 lineage는 caller가 구성한 기존 `GraphLineageVerifier`와 producer registry가 별도로
  공급해야 한다. SharedArtifactRef 자체도 Graph admission이나 receiver read authority를 증명하지
  않는다. CollaborationSnapshot도 sender·receiver·purpose나 content read authority를 증명하지
  않는다. Fact statement와 artifact content를 위한 최소·taint-aware receiver는 아직 없다.
- 해소 조건: HANDOFF-001에서 Supervisor-mediated sender·receiver binding을 추가하고 HANDOFF-004에서
  Capability·TTL·byte limit·receiver에 결박된 reader를 추가하되 기존 Graph/Event Log와 RunStore를
  새 저장소로 복제하지 않는다.

## MEM-003 cross-store current-view atomicity

- 상태: 의도적으로 제한된 cooperative in-process 경계
- 현재 보장: Graph Snapshot head를 exact resolve 전후와 각 bounded Run artifact 검증 뒤에 재확인해
  컴파일 중 협력적 Graph 변경을 fail closed한다. 이후 검증에서는 다시 current head와 모든 source를
  재구성한다.
- 제한: Graph Snapshot store와 여러 RunStore 사이에 하나의 분산 transaction이나 cross-host fence는
  없다. 마지막 head 확인 직후 새 Graph Snapshot이 publish될 수 있으며, 기존 CollaborationSnapshot은
  다음 검증 시 stale로 거부된다.
- 해소 조건: 저장소 경계가 cross-process 또는 cross-host로 확장될 때 signed checkpoint/fence나
  transaction coordinator를 별도 ADR과 contract로 정의한다.

## HANDOFF-001 process-local Supervisor authority

- 상태: 의도적으로 제한된 비영속 authority 경계
- 현재 보장: 단일 authority instance가 exact current CollaborationSnapshot과 기존 Agent/Task lineage,
  양쪽 parent Supervisor를 검증하고 Proposal당 하나의 non-executable record만 admission한다.
- 제한: Supervisor identity와 admitted record는 서명되거나 process restart 뒤 영속되지 않는다.
- 해소 조건: 외부/다중 process handoff가 필요할 때 signed Supervisor registry와 append-only record
  store/fence를 별도 계약으로 구현한다.

## Windows 비이식 파일명 정규화

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-04
- 명령: MEM-002 인접 회귀에 `tests\test_integrity.py` 전체를 포함한 pytest 실행
- 결과: Windows가 `evidence/result:.json`, 후행 점, 후행 공백 경로를 생성 시 정규화해
  `test_seal_rejects_externally_created_non_portable_artifact_paths`의 세 case가 예상 파일명을
  실제 디렉터리에서 관찰하지 못했다.
- 영향: 비이식 경로를 사전에 거부하는 코드 경계의 Linux 동작을 이 Windows 파일시스템에서
  같은 fixture로 증명할 수 없다. MEM-002의 normalized path validator와 새 집중 테스트는 통과했다.
- 해소 조건: Linux CI에서 해당 parameterized test를 실행한다.

## Windows 심볼릭 링크 테스트 권한

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-04
- 명령:
  `.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py`
- 결과: 349 passed, 6 skipped 이후
  `test_provider_checks_fail_closed_on_unsealed_symlink_artifact`가 테스트용 심볼릭 링크를
  생성하는 과정에서 `WinError 1314`로 중단됐다.
- 영향: 심볼릭 링크 생성 권한이 없는 Windows 세션에서는 전체 테스트를 완료할 수 없다.
  이는 PAJIN 코드 회귀의 증거가 아니다.
- 해소 조건: Linux CI 또는 심볼릭 링크 권한이 있는 Windows 환경에서 전체 테스트를
  실행한다.

## Benchmark Harness 고정 fixture 만료

- 상태: 활성 테스트 시간 의존성
- 마지막 재현: 2026-08-04
- 명령: `.\.venv\Scripts\python.exe -m pytest -x -q`
- 결과: 190 passed, 3 skipped 이후
  `test_single_agent_measurement_seals_completed_result_and_exact_trace`가
  `Benchmark registry distribution is not currently valid`로 중단됐다. 해당 파일을 제외하면
  `test_zap_baseline_seals_realistic_sarif_and_zero_recall_result`도 같은 원인으로 중단된다.
- 원인: 두 테스트가 `NOW = 2026-08-02`와 `expires_at=NOW + 1 day`로 bundle을 만들지만 Harness는
  주입된 fixture 시각이 아니라 실제 `datetime.now(UTC)`로 activation을 검사한다.
- 영향: 2026-08-03 이후 전체 pytest가 기존 Windows symlink 제약에 도달하기 전에 중단된다.
  MEM-001 코드 경로와 무관한 기존 fixture/harness clock 경계다.
- 해소 조건: Harness에 검증 clock을 명시적으로 주입하거나 테스트가 현재 시각에 의존하지 않는
  유효 기간을 사용하도록 별도 변경하고, 만료 음성 테스트는 고정 clock으로 유지한다.

## Windows POSIX 디렉터리 mode 검사

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-02
- 명령:
  `.\.venv\Scripts\python.exe -m pytest -q tests\test_workflow_integrity_regressions.py::test_confirmation_projection_keeps_private_permissions_and_escapes_markdown`
- 결과: PAJIN이 `0700`으로 생성한 validation·lock 디렉터리를 Windows `stat()`이 `0777`로
  보고해 `assert 511 == 448`에서 실패한다.
- 영향: POSIX private-directory mode assertion을 Windows에서 증명할 수 없다. 같은 실행의
  기능·escaping 검증에 도달하기 전에 플랫폼 mode 표현 차이로 중단되며 ENG-001 회귀 증거는 아니다.
- 해소 조건: Linux CI에서 검증하거나, 별도 작업으로 Windows ACL을 확인하는 platform-specific
  assertion과 POSIX mode assertion을 분리한다.

## PROF-001 Profile semantic authority 경계

- 상태: 의도적으로 제한된 registry 경계
- 현재 보장: 네 Profile의 exact identity·semantics·restrictive controls와 ENG-001 contract를
  content-addressed catalog에 결박하고 unknown version·unregistered substitution·authority flag
  escalation을 차단한다.
- 제한: Profile 자체는 Campaign이나 source Mode를 포함하지 않으며 ROE default 적용,
  MissionEnvelope compiler, benchmark measurement, external submission, execution 권한이 모두 false다.
  PROF-002 compatibility compiler는 별도 authority로 존재한다.
- 해소 조건: `ENG-002`에서 Campaign attenuation·parity가 증명된 opt-in Envelope/execution
  adapter를 별도로 구현한다.

## PROF-002 legacy compatibility compiler 비실행 경계

- 상태: 의도적으로 제한된 direct-call compiler
- 현재 보장: current v1alpha1 Campaign과 source Mode를 exact PROF-001 Profile, compiler, catalog,
  input/output digest에 결박하며 factory와 wire reload에서 substitution을 차단한다.
- 제한: legacy runtime에 연결되지 않았고 persisted audit event·sealed Run·ROE 적용·pentest 자동 선택·
  MissionEnvelope·execution authority가 없다.
- 해소 조건: `ENG-002`에서 exact implementation adapter와 동일 fixture parity authority를 먼저
  구현하고, 모든 parity dimension이 증명된 별도 opt-in 경로에서만 Envelope compilation을 검토한다.

## ENG-001 Common Engine 비실행 경계

- 상태: 의도적으로 제한된 migration 경계
- 현재 보장: 세 legacy Mode와 기존 `MultiAgentCampaignRunner`의 공유 경계를 code-owned contract로
  고정하고 complete Campaign·Mode·contract를 content-addressed Plan에 결박한다.
- 제한: `MissionEnvelope`, legacy/common parity evidence가 아직 없으며
  `commonExecutionAuthorized=false`다. PROF-002 compiler는 semantic projection만 만든다.
- 해소 조건: `ENG-002`에서 동일 fixture parity와 opt-in execution adapter를 별도 수직 슬라이스로
  구현한다.

## ENG-002A implementation adapter의 structural-only parity 경계

- 상태: 의도적으로 제한된 비실행 adapter selection 경계
- 현재 보장: PROF-002 compilation을 exact Mode별 Planner·Validator, AI candidate producer와 공통
  runner·scheduler·projector class identity에 결박하고, cross-Mode substitution·digest drift·parity
  dimension 누락·authority flag escalation을 wire reload에서 차단한다.
- 제한: module-qualified class identity는 source/binary attestation이 아니며 constructor configuration,
  Tool Registry, Policy, Worker, output path, generated ToolRequest, receipt, Outcome과 Mode별 후처리를
  결박하지 않는다. 네 parity dimension은 구조적으로만 존재하고 모두 측정·증명되지 않았다.
- 해소 조건: `ENG-002B`에서 동일 fixture를 legacy direct path와 별도 opt-in adapter path로 실행해
  전체 runtime input·request·receipt·outcome·post-processing의 exact parity를 봉인하고, 모든 음성
  경계를 통과한 별도 gate에서만 실행 eligibility 변경을 검토한다.

## ENG-002C2 Common execution gate의 explicit local 경계

- 상태: 명시적 direct-call CTF 수직 슬라이스에서 실행 가능하지만 default·분산 운영이 아닌 migration 경계
- 현재 보장: C1 false 권한을 보존한 별도 C2 compiler/Envelope, fresh request intent, exact latest
  GraphDecision, current signed activation, Capability Grant를 교차 검증하고 기존 GRAPH-006 원자 Permit과
  CAP-005 Gateway dispatcher만 사용한다. exact retry·request collision·stale Graph·authority/flag 치환은
  fail closed하며 Worker는 durable first consumption에서 한 번만 호출된다.
- 제한: caller가 current activation, local Graph store, matching RunStore, Gateway dependency와 Grant를
  공급한다. organization registry fetch·remote HA·default runtime wiring이 아니며 첫 실제 dispatch 회귀는
  CTF Profile이다. micro-USD reservation은 caller 선언이지 measured billing evidence가 아니다. Permit claim
  뒤 Gateway 실패·불확실 결과는 consumed terminal이고 자동 redispatch하지 않는다.
- 해소 조건: production 활성화 전 organization-issued activation distribution, durable registry/remote
  Graph authority, explicit operator selection과 AI/Bug Hunt end-to-end dispatch 증거를 별도 계약으로
  구현한다. 비용이 권한 결정에 쓰이면 trusted provider price/usage evidence를 reservation에 결박한다.

## P0-C2B2B provider fence의 host-local 범위

- 상태: 활성 분산 운영 공백
- 현재 보장: local Docker adapter는 별도 SQLite provider state에 fence를 side effect 전에
  영속하고 stale 호출을 Docker 전에 차단한다. 별도 SQLite operation lock이 같은 host의 live
  mutation과 higher-fence cleanup을 직렬화하며, receipt-bound evidence와 실제 Docker
  conformance가 이를 검증한다.
- 영향: 이 강제 경계는 하나의 host와 provider state 경로에 한정된다. 서로 다른 host나 원격
  Docker/cloud control plane이 같은 Target을 공유하면 local SQLite만으로 stale writer를 차단할
  수 없다.
- 해소 조건: 원격 provider의 원자적 compare-and-set fence 또는 lease authority와 독립 provider
  evidence를 구현하고 cross-host stale-call 음성 검증을 수행한다.

## P0-D1 Target catalog 배포 권위와 sealed Harness 연결

- 상태: 의도적으로 남긴 catalog 운영 경계
- 현재 보장: public registration/catalog, private Ground Truth binding, selection authority는
  domain-separated content digest로 exact equality를 증명한다. catalog wrapper는 provider 호출 전
  Manifest·adapter·Docker profile·catalog·private Ground Truth를 검증하고 실행 뒤 receipt-bound
  evidence와 등록된 count를 대조한다. selection은 `providerExecutionAuthorized=false`다.
- 영향: exact Docker image ID는 trusted provisioning input이다. catalog 자체를 누가 승인했는지,
  이전 revision으로 rollback하지 않았는지, 최종 registry-governed Harness authority가 어느 catalog
  selection을 사용했는지는 아직 외부 서명·durable activation·sealed source binding으로 증명하지
  않는다.
- 해소 조건: 별도 catalog distribution Trust Anchor와 contiguous durable activation을 추가하고,
  exact catalog selection Run/root/artifact를 governed Harness authority와 reader에 결박한다.

## P0-D2 fixture와 P0-D2B runnable provider의 분리 범위

- 상태: 의도적으로 분리된 선행 fixture와 host-local runnable provider
- 현재 보장: WALK-002/003/005A/005B2/005C1의 exact API version, 실제 state·target observation,
  private seeded Ground Truth를 content-addressed profile과 catalog selection에 결박한다. selection은
  adapter digest가 없고 `providerExecutionAuthorized=false`, `measurementAdmissionEligible=false`다.
- 영향: P0-D2 fixture는 계속 adapter digest가 없고 `networkLogTrusted=false`이므로 실제 Benchmark
  Run이나 metric 근거로 사용할 수 없다. P0-D2B는 별도 profile·Factory·catalog·Docker matcher로
  runnable 경계를 제공하지만 host-local single-container, deterministic no-model lab이다. MCP endpoint는
  Target 내부에 있어 별도 MCP service/process 격리를 증명하지 않는다.
- 해소 조건: fixture는 non-runnable 상태로 보존한다. production 범위가 필요하면 separate MCP service,
  model-backed RAG, external provider trust와 cross-host fence를 새 profile·ADR로 구현한다.

## P0-D3 Hybrid composition의 non-runnable 범위

- 상태: 의도적으로 실행·측정을 금지한 structural composition
- 현재 보장: exact P0-D1/P0-D2B selection, component order와 distinct identity, private Ground Truth,
  code-owned bridge를 content-addressed authority로 결박하고 substitution·repetition·scope expansion을
  차단한다.
- 영향: bridge는 `declared-not-executed`이며 combined Target Factory·Manifest·operation journal·transfer
  artifact·receipt·Observation이 없다. 독립 component Run 두 개를 Hybrid chain completion이나 metric으로
  합산할 수 없다.
- 해소 조건: 별도 Hybrid Factory/Manifest identity, coordinated network·fence·cleanup, exact transfer
  artifact와 bridge execution receipt, combined matcher와 measurement authority를 실제 provider 및
  partial-failure conformance로 검증한다.

## P0-D3B2 Hybrid provider의 host-local 합성 범위

- 상태: 실행 가능하지만 local Docker·deterministic no-model 합성 lab
- 현재 보장: 세 exact image, 한 internal network·coordinate·fence, causal source response→transfer artifact
  →upload→RAG/MCP receipt, Hybrid matcher와 reverse cleanup을 fake provider와 real Docker에서 검증한다.
- 영향: MCP endpoint는 AI Target process 내부 protocol boundary이며 별도 service 격리가 아니다. provider
  fence는 host-local SQLite에 의존하고, catalog distribution·anti-rollback activation과 production model
  behavior는 증명하지 않는다.
- 해소 조건: 필요 시 별도 MCP/model services, 외부 provider compare-and-set fence, signed catalog
  distribution과 governed Harness source binding을 별도 profile·ADR로 구현한다.

## P0-D4 Holdout authority의 비실행·비밀 저장 범위

- 상태: 의도적으로 non-runnable인 계약 경계
- 현재 보장: exact active Target selection과 별도 Holdout Factory·private suite·public commitment를
  결박하며 공개 artifact에서 case·Finding·matcher·evaluation seed를 제외한다. seeded/holdout replay,
  seed 재사용, catalog 확대와 cross-profile·binding 치환을 차단한다.
- 영향: deterministic private suite가 저장소 코드에 등록되어 있으므로 production 비밀 저장소나 blind
  evaluation을 증명하지 않는다. provider 실행·measurement admission·content disclosure는 false다.
- 해소 조건: access-controlled external evaluator, high-entropy one-time seed, signed bounded adjudication
  projection, leakage-safe log policy와 isolated provider lifecycle을 별도 authority로 구현한다.

## P0-D5 Mutation authority의 비실행 materialization 범위

- 상태: 의도적으로 non-runnable인 계약 경계
- 현재 보장: exact base Target selection, code-owned mutation seed·state·ordered operations, derived
  Manifest와 declared reset plan을 content-addressed authority로 결박한다. base catalog의 빈 mutation
  allowlist는 유지하고 scope expansion·cross-profile replay·순서·seed·state 치환을 차단한다.
- 영향: 실제 Target state를 restore·mutate·verify하지 않으며 reset receipt도 없다. 이 authority를
  Benchmark Result나 measurement admission 근거로 사용할 수 없다.
- 해소 조건: provider-specific materializer, observed base/expected-state evidence, fenced cleanup/recovery와
  registry-governed Harness admission을 새 runnable authority로 구현한다.

## P0-E1 측정의 local deterministic Target 범위

- 상태: 의도적으로 제한된 첫 실측 baseline
- 현재 보장: exact P0-D1 catalog selection, registry-governed Harness, sealed Target Run, execution
  receipt-bound Docker evidence와 private Ground Truth matcher를 다시 검증한 뒤 전체 seed/repetition raw
  Observation에서 12개 BENCH-001 metric을 계산한다.
- 영향: 결과는 고정된 local Docker SQLi lab의 deterministic PAJIN baseline이다. production Web/API
  conformance, 일반 Scanner·single-agent 성능, cross-host provider fence 또는 signed catalog distribution을
  증명하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: 별도 Scanner·single-agent measurement authority, signed catalog distribution과 필요한 외부
  provider trust 경계를 구현하고 동일 benchmark 좌표의 sealed Result를 비교한다.

## P0-E2B Scanner 측정의 local ZAP 범위

- 상태: 의도적으로 제한된 첫 일반 Scanner 실측 baseline
- 현재 보장: OWASP ZAP 2.17.0의 exact runtime image ID, code-owned automation plan, hardened Scanner
  container, internal P0-D1 network, receipt-bound raw SARIF와 strict normalization을 registry-governed
  Harness source 및 completed Result에 결박한다. 실행은 immutable image ID를 사용하고 종료 뒤 관리
  대상 container와 network 부재를 증명한다.
- 영향: 결과는 고정된 local Docker SQLi lab과 한 ZAP version/configuration에 한정된다. image ID의
  trusted provisioning, 일반 Web Scanner 성능, production 공급망, single-agent 성능, cross-host fence를
  증명하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: P0-E3 single-agent authority와 필요한 signed catalog distribution·외부 provider trust를
  별도 구현하고, 동일 좌표에서 모든 비교 metric이 measured인 sealed Result끼리만 비교한다.

## P0-E3B2 Single-agent 측정의 host-local 범위

- 상태: 제한된 local Docker·GPU baseline 측정 완료
- 현재 보장: digest-pinned llama.cpp CUDA image, exact Qwen GGUF, Policy Tool Loop implementation,
  Provider registration, prompt·Tool catalog, sampling·no-fallback configuration을 fresh P0-D1 Target
  coordinate에 결박한다. Provider와 fixed SQLi Tool의 action별 network route, exact Worker/proxy image ID,
  Target operation·cleanup receipt, Tool Loop Run/root, raw trace SHA-256와 normalization을 다시 검증한 뒤
  registry-governed source에서 completed `BenchmarkResult`를 봉인한다.
- 영향: 결과는 고정 local Docker SQLi lab, 한 llama.cpp/Qwen build, 한 seed·repetition 좌표에 한정된다.
  Docker image ID는 trusted provisioning input이며 cross-host fence, remote Provider trust, 일반 single-agent
  성능 또는 통계적 비교를 증명하지 않는다. local token 가격 USD 0은 marginal Provider 가격만 뜻하며
  GPU 전력·감가상각 비용을 포함하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: 비교가 필요하면 동일 Manifest·좌표·measurement authority의 sealed Scanner와 single-agent
  Result에서 모든 필수 비교 metric의 측정 가능성을 먼저 검증한다. production 범위는 signed catalog
  distribution, 외부 Provider trust와 cross-host fence를 별도 authority로 구현한다.

## P0-C2A recovery seal과 journal terminal 전이 사이 중복 감사

- 상태: 활성 보수적 중복 가능성
- 조건: Recovery Authority Run을 seal한 직후 journal attempt를 `reconciled`로 바꾸기 전에
  프로세스가 종료된다.
- 영향: 다음 시작은 이미 journaled된 성공 cleanup receipt를 재사용해 provider를 다시
  호출하지 않지만 동일 attempt에 대한 새 Recovery Authority Run을 하나 더 봉인할 수 있다.
  측정 Admission은 두 Run 모두 false라 안전성이나 metric에는 영향을 주지 않는다.
- 해소 조건: sealed Run ID를 journal terminal transition과 연결하는 재개 가능한 publication
  marker를 추가하고 동일 authority의 재봉인을 제거한다.

## P0-C2B2A1 activation store의 외부 복구 권위

- 상태: 활성 운영 복구 공백
- 현재 보장: registry distribution origin은 별도 Ed25519 key로 검증되고, intact host-local SQLite
  store는 마지막 accepted bundle을 append-only로 유지해 restart rollback·gap·equivocation을
  차단한다.
- 영향: activation database 전체가 삭제되거나 신뢰 경계 밖에서 교체되면 remembered head도 함께
  사라진다. local store만으로는 오래된 revision 1을 새 bootstrap처럼 복원한 상황을 구분할 수 없다.
  distribution Trust Anchor rotation과 remote HTTPS fetch도 아직 없다.
- 해소 조건: 운영 백업 또는 독립 transparency/checkpoint anchor와 명시적 distribution Trust
  Anchor rotation authority를 추가한다.

## Windows 애플리케이션 제어에 의한 mypy 네이티브 모듈 차단

- 상태: 현재 재현되지 않음, 재발 가능 환경 제약
- 마지막 확인: 2026-08-01
- 명령: `.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src`
- 현재 결과: 214 source files 통과
- 과거 증상: import 단계에서 Windows 애플리케이션 제어가 네이티브 `librt.base64` 모듈을
  차단했다.
- 재발 시 조치: Linux CI를 사용하거나 조직의 애플리케이션 제어 정책에서 서명된 네이티브
  모듈을 허용한다. mypy 실행을 위해 정책을 비활성화하지 않는다.

## Git OpenSSL CA 경로

- 상태: 활성 로컬 전송 제약
- 마지막 재현: 2026-08-01
- 증상: 기본 Git OpenSSL backend가 GitHub 원격에 대해
  `unable to get local issuer certificate`를 보고할 수 있다.
- 검증된 대안: TLS 검증을 끄지 않고 Windows 인증서 검증을 사용한다.
  - `git -c http.sslBackend=schannel push origin main`
  - `git -c http.sslBackend=schannel ls-remote origin refs/heads/main`
- 해소 조건: 로컬 Git CA bundle을 복구하거나 schannel override를 계속 사용한다.

## Docker daemon 가용성

- 상태: 현재 가용, 세션 의존 환경 제약
- 마지막 관찰: 2026-08-02
- 현재 결과: Docker Desktop 4.78.0 / Engine 29.5.3에서 P0-C2B2B SQLi, P0-D2B AI/RAG/MCP,
  P0-D3B2 Hybrid, P0-E2B ZAP와 P0-E3B2 local llama.cpp/Qwen governed measurement가 통과했고 종료 뒤
  관리 대상 container와 network가 남지 않았다.
- 영향: Docker Desktop이 다음 세션에 자동으로 가용하다는 보장은 없다. daemon이 꺼져 있으면
  opt-in live test는 실행할 수 있지만 일반 fake-provider 검증은 계속 가능하다.
- 필요한 조치: 실제 컨테이너 증거가 필요한 작업 전에 daemon 상태와 exact image ID를 다시
  확인한다. 실행하지 않은 live 검증을 성공으로 보고하지 않는다.
