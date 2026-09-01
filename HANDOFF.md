# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-09-02
- 작업 위치: 저장소 루트
- 브랜치: `main`
- UX-009D 성능 보정 체크포인트: `4440414` (`fix(benchmark): 도메인 레지스트리 반복 재구성 제거`)
- UX-009D JSON wire 보정 체크포인트: `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf`
  (`test(product): fresh 응답 JSON 검증 경로 수정`)
- Phase 24 구현 커밋은 `be94b713a4323dba971345bcb2524f6ce8395142`, Linux conformance 상태 경로 보정은
  `9b3d8035252d26334d35caa55c0270356c71683a`이며 둘 다 `main`에 push됐다.
- Phase 24 exact-SHA Ubuntu run `33494188536`, job `99812441408`은 `9b3d8035252d26334d35caa55c0270356c71683a`에서
  conformance `1 passed in 771.59s`와 unconditional zero-residue audit을 통과했다.
- 구현 상태: `DOMAIN-001~006`, 모든 `*-001A~D`, `WEB-002A~D`, `UX-009A~D` 코드·계약이 커밋·push됐고
  로컬 집중 검증을 통과했다.
- UX-009D exact-SHA Ubuntu real-Docker run `33410801762`, job `99549584968`은 checkpoint
  `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf`에서 fresh-spawn conformance
  `1 passed in 836.08s`와 unconditional PAJIN Docker residue audit을 모두 통과했다.
- `WEB-002D` 구현은 exact conformance commit `975bf7876a186cefae66c289d09f530f3e0fe7aa` 이후 불변이며,
  해당 commit의 Ubuntu 24.04 run `33310558350`, job `99254722600`에서 real-Docker 검증을 통과함
- 기준 체크포인트의 repo-wide Ubuntu 24.04 CI run `33316840636`은 Quality와 24개 pytest shard가
  모두 성공했다. 선택 합계는 `7,609 passed, 69 skipped`, 실패·취소 0, 전체 1시간 39분 7초이며
  최장 shard 17은 `5,925.98s (1:38:45)`의 pytest와 1시간 39분 3초 job으로 끝났다.
- Phase 22 Exit Gate는 완료됐다. UX-009C의 별도 Operator 소비 경로가 추가됐지만 UX-009A wire 자체,
  production/external probing, Graph/report와 추가 실행 권위는 여전히 없다.
- Phase 23 Exit Gate도 exact UX-009D conformance와 residue audit으로 완료됐다.
- Phase 24 Exit Gate도 exact NET-002D conformance와 residue audit으로 완료됐다.
- 현재 HEAD와 upstream은 AI-002A checkpoint
  `1f49c6b0b68da9c2e360eabef7cf38a9d8428522`로 같고 divergence는 `0/0`이다.
- 해당 SHA의 repo-wide CI run `33528649730`은 Quality와 24개 pytest shard가 모두
  `completed/success`다.
- 현재 단계: Phase 25 — Governed Measured AI System-Prompt Disclosure — `AI-002B` 로컬 구현·검증 완료
- 현재 우선순위: AI-002B checkpoint의 명시적 commit/push 승인과 새 exact-commit repo-wide green 확인
- 다음 우선순위: green 확인 뒤 `AI-002C` independent Replay, Controls, and AI floor
- AI-002B 변경은 모두 unstaged이고 새 source/test/contract 파일은 untracked다. staged 변경과 진행 중
  merge/rebase/cherry-pick/revert/bisect는 없다. commit·push·PR·merge·deploy는 수행하지 않았다.
- deterministic 24-shard/120분 CI와 canonical 모바일 substitution fixture는 기준 체크포인트에 포함됐다.
  UX-009D 성공 workflow는 Phase 23 conformance 증거이며 다른 Domain runtime의 증거로 확장하지 않는다.

문서보다 Git과 파일시스템의 실제 상태를 우선한다. 재개 즉시 아래 Git 명령으로 다시 확인한다.

## 현재 구현 상태

### 공통 기반과 완료된 도메인

- `DOMAIN-001~006`은 9개 Security Domain 분류, 공통 Graph semantics, Capability projection,
  최소 Worker profile, bounded cross-domain producer와 metric/Replay vocabulary를 제공한다.
  이 registry들은 Scope, approval, Permit, Worker 선택, 실행, Finding 또는 측정 권위가 아니다.
- `WEB-001A~D`, `AI-001A~D`, `NET-001A~D`, `CLOUD-001A~D`, `SYS-001A~D`,
  `APP-001A~D`, `MOBILE-001A~D`는 각 버전형 계약의 제한 안에서 완료됐다.
- `CRYPTO-001A~D`는 protocol/key-usage/ciphertext/configuration Surface, offline preparation,
  deployment-signed structural admission, distinct implementation-provenance comparison과 8개 미래 vector
  requirement까지 커밋됐다. 일반 analyzer, key use, semantic Oracle, vector materialization,
  benchmark 실행 또는 Finding 권위는 없다.
- `FORENSICS-001A~D`는 immutable artifact Surface, read-only parser preparation, 두 deployment trust
  anchor로 인증한 sealed neutral Graph admission, supplied deterministic/independent parser comparison과 12개
  seeded-evidence requirement까지 커밋됐다. parser 실행, 독립 provenance truth, semantic
  validation, Finding 또는 measurement 권위는 없다.

### Phase 11~21 통합 재평가와 Phase 22 선택

- 각 Phase의 `[x]`는 문서에 명시된 bounded contract/projection 범위에서는 실제 코드와 일치했다.
  이를 일반 multi-domain runtime이나 production benchmark 완료로 확대해석할 수는 없다.
- Phase 11은 Pentest compile/recon/replay/workflow와 제한된 KISA/MCP runtime을 실행할 수 있다.
  Phase 13은 그 Pentest GET 경로를 재사용하고, Phase 14는 제한된 KISA fresh-session Replay/Control을
  재사용한다. Phase 15~21 중 repository-owned domain action은 Network passive-banner Worker가 유일하다.
- Web에는 P0-D1 fixed Boolean-SQLi Target/Private Ground Truth, catalog-bound Docker Target Factory,
  P0-E2B runnable ZAP measurement, fixed Boolean-SQLi controlled probe가 모두 이미 존재한다. WEB-001D는
  이 자산을 의도적으로 `registered-ground-truth-not-measured`에 남겨 두었다.
- Network는 disposable Target Factory·measurement·CLI가 없고, AI는 concrete Ground Truth와 deterministic
  measurement 경계가 없다. Cloud/System/Application/Mobile/Cryptography/Forensics는 새 provider/agent/
  parser/sandbox runtime을 먼저 요구한다.
- ADR-0250은 다음 vertical slice를 Phase 22 Web으로 선정했다. 독립 review는 기존 REDTEAM Web endpoint
  `host.docker.internal:8770`과 no-published-port P0-D1/P0-E2B endpoint `target:8080`의 불일치, DOMAIN-006의
  floor authority 부재와 세 Finding identity의 불일치를 확인했다.
- ADR-0251은 endpoint와 floor/Finding identity를 보완했고,
  [ADR-0252](docs/adr/0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md)는
  direct Worker attachment를 supersede한다. Worker는 proxy-only network에 남고 proxy만 exact Target network를
  bridge한다. ADR-0253은 ZAP source measurement와 controlled-validation route를 분리한다. WEB-002A는
  additive Profile/Capability, signed controlled route, validation floor와 새 Finding projection policy를
  구현했다. ADR-0254와 WEB-002B는 exact WEB-002A case에서 plan-owned coordinate 하나만 fresh
  registry-governed P0-D1/P0-E2B lifecycle로 실행하고 completed journal과 cleanup evidence까지 봉인한다.
  해당 source path는 exact conformance commit `975bf787` 이후 불변이며 Ubuntu 24.04 combined run
  `33310558350`이 그 exact commit에서 검증했다. ADR-0255와 WEB-002C는 이 sealed source를
  knowledge-only Graph lineage로 다시 열어 neutral Observation/Evidence와 bounded Hypothesis만 admission한다.
  WEB-002D는 independently controlled validation, durable route/denial/Worker Evidence, Profile floor와 bounded
  Finding projection을 구현했다. Ubuntu 24.04 run `33310558350`은 exact commit `975bf787`에서 post-audit
  호환성·custody hardening을 검증했으며 해당 경로는 이후 불변이다.

### WEB-002A

- `src/pajin/capabilities/web_measured_validation.py`는 exact internal
  `http://target:8080/v1/users/lookup` Surface, 기존 `BooleanSQLiProbeTool`, DOMAIN-004 Web Worker
  boundary와 일곱 code-backed Capability role을 additive Profile/Capability identity로 결박한다. baseline,
  negative Control, Boolean probe 세 GET만 등록하며 activation, approval, Permit, Worker, network,
  measurement, Finding, product와 execution 권위는 모두 false다.
- `src/pajin/workflow/web_measured_case_authority.py`는 current signed Capability release, P0-D1 Target/
  private Ground Truth, P0-E2B Scanner plan/ZAP registration과 DOMAIN-006 Web plan을 contextfully 재구성한
  public-safe measured-case identity를 제공한다. bare artifact parsing은 trusted reload가 아니다.
- `src/pajin/workflow/web_proxy_route_authority.py`는 Ed25519 deployment Trust Anchor 아래 WEB-002D용
  `controlled-validation` route만 서명·검증한다. approval/Permit snapshot 대신 durable
  `ActionApprovalAuthorization`을 조회하고, `BenchmarkTargetOperationJournal.current_open_attempt`에서 exact
  Scanner coordinate와 ordinal-1 reset/isolation receipts, pending ordinal-1 execution intent, current fence를
  직접 유도한다. journal record/receipt 시간은 issue까지 단조·인과적이어야 하고 reset/isolation environment와
  비중첩 전이가 유지돼야 한다. verification artifact loader도 모든 live predecessor와 exact wire equality를
  재검증한다.
- route validity는 consumed Permit, ActionApproval, Mission Envelope, Campaign authorization과 하나의
  continuous WeeklyTestingWindow occurrence 안에 있어야 한다. 같은 approval receipt와 Permit은 nonce,
  Target operation 또는 runtime policy가 달라도 하나의 stable future atomic-consumption slot에 수렴한다.
  WEB-002A 자체에는 consumption ledger/CAS, route materializer, Docker/proxy/Worker runtime 또는 receipt가 없다.
- `src/pajin/workflow/web_validation_floor.py`는 DOMAIN-006 14개 metric requirement, exact source/controlled
  Evidence set, code-owned content-addressed policy-denial Control denominator와 private expected-Finding to
  public projection commitment를 등록한다. metric observation/evaluation, floor satisfaction, Graph/Finding/
  report/product 권위는 모두 false다.
- 추가된 공개 계약은
  `docs/capability/WEB-002A-measured-validation-capability-profile.md`,
  `docs/benchmark/WEB-002A-exact-measured-case-route-floor-finding.md`, ADR-0253에 있고, 주요 회귀는
  `tests/test_web_measured_case_authority.py`, `tests/test_web_proxy_route_authority.py`와 Target journal
  회귀에 있다.

### WEB-002B

- `src/pajin/workflow/web_source_measurement_authority.py`는 exact WEB-002A measured case와 하나의
  plan-owned Scanner coordinate를 contextfully 재구성하고, constructor-owned provider/Trust Anchor/
  activation store/signed distribution/Target journal로만 fresh P0-D1 Target, registry-governed Harness와
  기존 P0-E2B Scanner measurement를 실행한다. caller-selected coordinate, route, approval, Permit,
  Worker action, request 또는 response를 받지 않는다.
- `WebZAPSourceLineage`와 `WebZAPSourceMeasurementAuthority`는 exact signed distribution bundle,
  Scanner/Harness/Target Run과 root, immutable Target/Worker/ZAP image ID, completed attempt/fence,
  execution/cleanup operation·receipt·provider evidence, raw SARIF hash/size, strict normalization과
  cleanup `resourcesAbsent=true`를 public-safe identity/digest로 결박한다.
- completed journal은 reset/isolation/execution/cleanup의 intent/receipt 정확히 8개, 모두 ordinal 1,
  같은 attempt/fence/adapter/coordinate, Target receipt exact equality와 인과적 timestamp를 요구한다.
  open/reconciled/incomplete/reordered/foreign/noncanonical journal은 authority가 아니다.
- loader는 outer artifact만 신뢰하지 않고 exact WEB-002A, Scanner, 모든 Harness/Target, registry
  activation과 signed bundle, provider execution/raw SARIF/cleanup evidence 및 completed journal을 다시
  열어 authority를 재구성한다. provider direct/cached-replay result/evidence, Scanner source/observation,
  outer authority 저장 wire와 세 audit payload는 canonical/exact equality를 요구해 coercion과 resealed
  semantic drift를 거부한다.
- WEB-002A의 `controlled-validation` proxy route는 import·materialize·consume하지 않는다. private Ground
  Truth, metric/floor, Graph/Finding, comparison/Supervisor, product/report와 추가 실행 권위는 모두 false다.
- 공개 계약은
  `docs/benchmark/WEB-002B-distinct-registry-governed-zap-source-measurement.md`와 ADR-0254다.
  deterministic/fail-closed 검증과 exact outer runner/loader real-Docker conformance를 모두 통과해
  PLAN 상태를 완료로 올렸다.

### WEB-002C

- `src/pajin/workflow/web_source_measurement_admission.py`는 WEB-002B outer Run과 모든 measured-case,
  Scanner, registry, provider, journal predecessor를 다시 연다. 두 번째 outer snapshot의 canonical
  authority bytes와 세 audit event payload까지 exact equality로 대조한 뒤 registered Web Surface
  presence만 독립 재계산하며 private Ground Truth와 `knownFindingMatched`는 사용하지 않는다.
- 검증 결과는 complete measured case나 source lineage를 노출하지 않고 Surface, Domain type-set,
  source-authority의 content-addressed reference와 최소 scalar만 보존한다. current Graph Snapshot에 이미
  있는 exact trusted-core Surface가 아니면 admission하지 않는다.
- Graph의 additive `sealed-source-authority` lineage는 Capability/Grant/Permit tuple과 상호 배타적이며
  exact Proposal digest와 predecessor event-log head에 결박된다. generic direct submit, lineage 재사용,
  cross-domain source-authority transfer는 거부한다.
- 기존 single writer/CAS로 succeeded Action, neutral `web.zap-source-observation`, authority-reference
  Evidence만 기록한다. registered Surface signal이 있을 때만 confidence `0.5` open Hypothesis를 바로
  다음 event로 시도하고, 사이에 head가 바뀌면 Hypothesis를 거부하면서 이미 기록된 Observation은 보존한다.
- raw SARIF, private Ground Truth, Target/provider/runtime identity, controlled route, Scope, Capability,
  Permit, Worker, network, Replay, floor, Finding, product, report와 추가 실행 권위는 모두 제외한다.
  계약은 `docs/graph/WEB-002C-sealed-zap-source-knowledge-admission.md`, 결정은 ADR-0255다.
  새 event wire는 additive지만 구 reader가 알 수 없으므로 upgraded reader를 먼저 배포해야 하며,
  rollback은 event rewrite 없이 검증된 pre-event store를 복원하거나 새 reader를 유지한다.

### WEB-002D

- `src/pajin/workflow/web_controlled_validation_route.py`는 signed route의 stable consumption slot을 exact
  SQLite claim/denial ledger에 원자적으로 한 번만 결박한다. 신규 store만 독점 생성하며 existing store와
  모든 transaction은 DELETE journal, `quick_check`, exact table/index/view/trigger 계약을 다시 검증한다.
  실행되지 않은 cleanup-complete route는 claim과 경쟁하는 append-only denial tombstone으로 봉인한다.
- `src/pajin/workflow/web_controlled_validation_runtime.py`는 fresh Target attempt에서 proxy-only Worker의
  세 exact GET을 실행하고 route claim, request/response, backend/observer/topology, Worker·proxy image와
  cleanup 전 ephemeral identity를 durable Worker Evidence로 저장한다. production adapter의 fresh-session
  loader는 store, claim, current backend/image와 resources-absent를 다시 검증하며 test adapter는 reopen할 수 없다.
- `src/pajin/workflow/web_controlled_validation_authority.py`는 WEB-002B sealed source, 별도 성공 route/claim/
  Worker Evidence, cleanup-complete 8-record Target lifecycle과 실행되지 않은 별도 route의 7-record denial
  lifecycle/tombstone을 fresh context에서 다시 연다. 이후 더 높은 Target fence가 생겨도 sealed historical
  cleanup proof는 검증하되, 과거 route를 새 실행 권위로 되살리지는 않는다.
- `src/pajin/workflow/web_validation_evaluation.py`는 source request units와 private matcher를 독립 재계산하고
  실제 source/controlled Evidence inventory, identity 분리와 observed 1/1 zero-side-effect denial에서 14개
  DOMAIN-006 metric과 floor를 유도한다. Finding은 `benchmark-ground-truth-match` claim ceiling과
  information-only impact/severity에 제한되며 Graph/product/report, external target 또는 추가 실행 권위가 없다.
- `src/pajin/benchmark/scanner_docker_provider.py`와 final authority build/load는 source context와 동일한
  exact production provider, unshadowed wrapper/inner/runner method·state와 canonical custody path를 요구한다.
  동일 프로세스의 임의 private-memory/constructor 우회는 Python·호스트 TCB 잔여 위험이다.
- 버전형 계약은 `docs/benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md`,
  결정은 ADR-0256이다.
- opt-in `tests/test_web_controlled_validation_docker.py`는 source ZAP, fresh success/denial Target lifecycle,
  production Worker/proxy, seal과 fresh reload를 하나의 synthetic P0-D1 경로로 묶는다. 수정 전 실행이 식별한
  fresh JSON tuple/list strict bug는 수정·집중 회귀를 통과했고 prior-tree real-Docker도
  `1 passed in 545.95s`였다. 이후 exact source-owned production provider custody guard와 Worker observer
  hardening을 포함한 committed ref는 Ubuntu 24.04 run `33310558350`에서 exact test를 통과해
  exact-commit conformance와 Phase 22 Exit Gate를 완료했으며 해당 WEB 경로는 이후 불변이다.

### FORENSICS-001A

- `src/pajin/discovery/forensics_surfaces.py`
  - exact Forensics Domain과 DOMAIN-002 `forensics.immutable-artifact` type-set에 결박된 disk, memory,
    log, generic artifact sibling locator 4종을 제공한다.
  - 모든 locator는 code-owned `pajin.dev/run-integrity/v1` root kind, source-root SHA-256,
    source artifact-record SHA-256, provenance-record SHA-256, artifact SHA-256와 strict
    `0..2^63-1` artifact byte count 전체를 `ForensicSourceProvenanceCoordinate`로 내장한다.
  - 같은 artifact라도 root/record/provenance/byte count 또는 class가 바뀌면 Surface identity가 바뀐다.
  - source 존재, Run seal, authenticity, external anchoring, artifact membership, digest/size,
    immutability, chain of custody, evidence class, format과 provenance sanitization은 검증하지 않는다.
  - path, URI, object key, filename, host/device/case/operator/timestamp, raw evidence/provenance,
    credential/secret, parser output, Tool/Worker/Scope/Permit 필드는 허용하지 않는다.
  - public builder/registry/typed-Surface와 complete-Surface reference binding 경계는 nested instance와
    unmodeled state를 재검증한다. standalone reference는 class/kind claim을 운반하지 않는다.
  - registry와 typed Surface는 `registered-not-authorized`이며 source resolve/acquire/read/mount/copy,
    parser/analyzer, credential access/use, lateral movement, evidence mutation, Scope·Capability·approval·
    Permit·Tool/Worker·network·Graph·Hypothesis·Finding·execution 권위가 모두 false다.
- `src/pajin/discovery/__init__.py`에 additive public export를 연결했으며 기존 `SurfaceLocator`,
  `SurfaceObservation`, `AttackSurface`, DOMAIN-002와 Run-integrity wire는 변경하지 않았다.
- `tests/test_forensics_immutable_artifact_surfaces.py`는 284개 positive/adversarial case를 제공한다.
- 권위 문서:
  - `docs/discovery/FORENSICS-001A-disk-memory-log-artifact-provenance-surface-model.md`
  - `docs/adr/0244-type-forensic-evidence-surfaces-without-source-access-or-evidence-mutation-authority.md`
  - `PLAN.md`, `DECISIONS.md`, `README.md`, ARCH-002 RFC 갱신

### FORENSICS-001B

- `src/pajin/capabilities/forensic_evidence_analysis.py`
  - disk, memory, log, generic artifact 4종 모두 complete FORENSICS-001A Surface와 provenance를
    재검증하고 reference를 다시 유도해 exact match만 허용한다.
  - current externally signed Range CAP-002 release, exact parser-bound non-routable Campaign Surface Scope와
    DOMAIN-004 minimum Forensics Worker profile을 동시에 요구한다.
  - evidence class에서 input kind, operation, logical parser로 가는 exact mapping은 code-owned이고 neutral
    analysis signal은 별도의 bounded code-owned vocabulary다. caller가 operation/parser/rule/signal을
    선택하거나 확장할 수 없다.
  - opaque custody reference, parser executable/image/config digest와 output schema를 고정하고 immutable
    read-only/noexec input, read-only root, network/DNS disabled, non-root, no-new-privileges sandbox를 요구한다.
  - artifact/output/runtime/memory/process/parser-work/recursion/decompression-ratio/absolute
    decompressed-byte ceiling을 고정한다. parser work unit은
    `one-source-or-expanded-byte-processed`이며 모든 source write, evidence mutation, credential/secret,
    network, host read, target execution, shell/plugin과 lateral-movement authority budget은 0이다.
  - 결과는 `PreparedCapabilityAction`의 `prepared-not-authorized`에서 멈춘다. executor와 normalizer는
    fail closed, Oracle는 `INCONCLUSIVE`, Replay와 cleanup은 no-plan이며 source resolve/read/mount/copy,
    parser 실행, result, Observation/Evidence, Graph admission, Hypothesis, Finding 권위를 만들지 않는다.
- `tests/test_forensic_evidence_analysis.py`는 signed lifecycle, exact binding과 모든 ceiling/zero-authority,
  forged nested Pydantic state, runtime fail-closed 경계를 검증하는 286개 case를 제공한다.

### FORENSICS-001C

- `src/pajin/workflow/forensic_evidence_analysis_admission.py`
  - Gate 생성자는 deployment-owned absolute existing non-symlink evidence root와 서로 분리된 source-membership,
    parser-execution Ed25519 Trust Anchor를 필수로 받는다. caller source input은 root나 anchor를 선택할 수 없다.
  - 두 Evidence 파일은 bounded no-follow regular single-link reader로 읽고 exact file bytes SHA-256에서 유도한
    code-owned outer execution-bundle/result-receipt reference와 일치해야 한다. caller의 A
    `sourceRootSHA256` provenance coordinate와 Graph admission evidence `sourceRootDigest`는 별도로 유지한다.
  - source anchor와 signed membership attestation은 complete A Surface, root/artifact/provenance record,
    artifact digest·bytes, custody binding/authority/object/authorization, immutable version, purpose와 validity를
    exact하게 결박한다. execution anchor와 outer statement는 exact B preparation, parser/sandbox/profile,
    pre/post state, configured·observed ceiling, zero mutation/copy/write/network/credential/device/plugin/
    lateral-movement/target-execution/shell channel과 detached result를 결박한다.
  - loader는 current signed Range, exact Campaign Scope, current preparation, approval, one consumed Permit와
    signed `capabilityGrantId`/`capabilityGrantDigest`를 다시 만들고 비교한다. recomputed Gateway outcome에도
    exact Grant digest가 포함되며 foreign, missing, expired, revoked, cross-role 또는 drifted authority는
    fail closed한다.
  - pure structural Oracle는 source와 result body를 읽지 않고 code-owned class mapping으로 `review` 또는
    `no-signal`만 재계산한다. `review`일 때만 confidence `0.5`의 open
    `forensics.forensic-proposition` Hypothesis를 허용하며 `no-signal`은 Hypothesis를 금지한다.
  - existing Graph single writer에는 succeeded Action과 fixed neutral
    `forensics.analysis-observation`, restricted JSON Evidence 정확히 2개, 선택적인 open Hypothesis만
    admission한다. exact retry는 idempotent하고 Observation-only interruption은 같은 head에서 복구하며
    intervening head는 fail closed한다.
  - raw source/result/provenance/path/identity/secret/credential, Finding, Scope, Capability, approval, Permit,
    Worker, Replay, mutation, parser invocation, execution 또는 새 Graph admission authority를 만들지 않는다.
- `tests/test_forensic_evidence_analysis_admission.py`는 두 trust role, content-addressed Evidence, exact Grant와
  Gateway, runtime ceiling/zero channel, neutral Graph topology, CAS/retry와 no-signal 경계를 검증한다.
- 권위 문서:
  - `docs/adr/0246-authenticate-forensic-source-membership-and-parser-execution-with-distinct-deployment-trust.md`
  - `docs/graph/FORENSICS-001C-sealed-forensic-analysis-knowledge-admission.md`

### FORENSICS-001D

- `src/pajin/workflow/forensic_evidence_analysis_replay_benchmark.py`
  - exact stored C admission과 later separately authorized sealed execution을 두 exact evidence root와
    SQLite Graph authority store에서 current C loader로 다시 열고, one shared source-membership Trust Anchor와
    explicit source/replay execution Trust Anchor를 deployment context로 요구한다.
  - source admission의 stored Observation과 optional Hypothesis를 exact하게 확인하고 두 store event count를
    보존한다. bare model parsing은 self-authenticating하지 않으며 trusted loader는 projection 내부 admission을
    source store에 대조하고 nested hidden state를 dump 전에 거부한다.
  - immutable source/custody, complete Surface, logical parser/request, Scope, rule, activation/release, Grant
    authority semantics, resource/confinement/zero-channel semantics를 동일하게 유지하고 per-execution
    preparation·Run·request·approval·Permit·execution·runtime·result·Oracle provenance와 signed causal order를
    분리한다. Grant ID/time window는 같거나 달라도 되며 `tools`/`targets`는 canonical sort한다.
  - execution anchor/signer, parser executable/configuration/image와 sandbox ID/digest가 모두 같을 때만
    `deterministic-reparse`, 모두 다를 때만 `independent-parser-comparison`이며 partial drift는 fail closed한다.
    only independent mode가 DOMAIN-006 exact strategy를 만족한다.
  - result digest/bytes, result/Oracle disposition과 bounded signal로 neutral match/changed/unresolved만 유도하고
    equal digest/different bytes를 거부한다. source/result body, semantic truth, parser correctness, Finding,
    Graph write, Replay scheduling 또는 further execution authority는 만들지 않는다.
  - separate content-addressed profile은 disk/memory/log/artifact별 positive/no-signal/corrupted-input exact
    12-case와 four required unmeasured Forensics metric을 등록한다. corrupted Control은 fabricated success가
    아닌 future bounded parser-rejection receipt를 요구하며 fixture/parser 실행이나 measurement를 수행하지 않는다.
- `tests/test_forensic_evidence_analysis_replay_benchmark.py`는 11개 collected case로 four Surface/two mode,
  neutral comparison, partial implementation drift, reused/noncausal provenance, contextful reload, hidden state,
  Grant determinism, import authority와 fixture/metric/marker 경계를 검증한다.
- 권위 문서:
  - `docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md`
  - `docs/adr/0247-bind-independent-forensic-parser-comparison-and-seeded-evidence-without-source-or-measurement-authority.md`
  - `docs/adr/0249-cross-link-forensic-replay-identity-clarification.md`

## 핵심 결정과 불변식

- FORENSICS-001C의 deployment assertions는 공급된 provenance/custody/parser execution statement의 서명
  origin과 integrity를 인증하지만 source/custody 사실, evidence class/format, parser correctness 또는 semantic
  truth를 독립적으로 증명하지 않는다. production source·custody와 execution Trust Anchor, evidence root와
  key rotation은 계속 deployment 책임이다.
- FORENSICS-001A의 Run root는 caller coordinate일 뿐 authenticity나 external anchoring 증거가 아니며,
  FORENSICS-001C의 Graph `sourceRootDigest`는 두 admission Evidence와 verified interpretation의 별도 digest다.
- ADR-0016 Run integrity는 local tamper evidence를 제공하지만 작성자 인증이나 독립 anchor를 증명하지 않는다.
- SHA-256은 private 또는 low-entropy credential, token, key, operator/case identity의 redaction이 아니다.
  이런 preimage를 Forensic identity에 사용하지 않는다.
- disk/memory/log/artifact는 v1에서 sibling이다. 추출·custody 관계는 FORENSICS-001C의 sealed
  Observation/Evidence가 없이는 identity 관계로 주장하지 않는다.
- discovered credential material은 knowledge일 뿐이다. 사용, lateral movement, active probe 또는 evidence
  mutation에는 별도 Capability와 fresh authority가 필요하다.
- standalone Surface reference는 inert opaque pointer다. `bind_forensic_immutable_artifact_surface_reference`
  는 complete Surface와 provenance를 재검증하고 reference를 다시 유도해 exact match만 반환한다.
- 새 source-root kind, locator class, provenance field, class semantics 또는 digest algorithm은 silent
  expansion이 아니라 새 registry/schema version을 요구한다.
- FORENSICS-001B의 class-to-input-kind-to-operation-to-logical-parser mapping은 code-owned exact registry이고
  neutral signal vocabulary는 별도의 bounded registry다. caller 제공 operation/parser/rule/signal, wildcard
  Scope 또는 다른 Surface/provenance/custody/sandbox binding은
  authority 확장이 아니라 fail-closed 사유다.
- parser work unit `one-source-or-expanded-byte-processed`는 source 또는 expanded byte 하나를 처리한 작업량
  하나를 뜻한다. artifact byte ceiling과 별도로 parser work, decompression ratio와 absolute decompressed
  byte ceiling을 모두 만족해야 한다.
- `PreparedCapabilityAction`은 실행 허가나 admission 결과가 아니다. FORENSICS-001C는 이미 완료된 signed
  execution과 pre/post immutable assertion을 재검증해 neutral knowledge만 admission하며 parser를 실행하거나
  signed deployment assertion을 independent source truth로 승격하지 않는다.

## 최신 검증

### WEB-002D

- controlled-validation authority와 proxy route 묶음: `20 passed in 573.18s`
- durable claim/denial route ledger: `58 passed, 2 skipped`; 두 skip은 Windows의 심볼릭 링크 생성
  권한(`WinError 1314`)이며 코드 실패가 아니다.
- production Worker Evidence runtime과 fresh-session durable reopen: `9 passed in 140.90s`
- independent metric/floor/Finding evaluation: `7 passed in 452.72s`
- Target disconnect 처리, request-unit method 보존과 canonical JSON 집중 회귀:
  `15 passed, 34 deselected in 313.36s`
- repo-wide Ruff check와 WEB-002D 직접 변경/회귀 18개 파일의 format check가 통과했고,
  `.venv\Scripts\mypy.exe --strict --platform linux src/pajin`은 `370 source files`를 통과했다.
  repo-wide format check의 기존 184개 대상은 이번 범위와 구분한다.
- 독립 리뷰의 P1 provider trust-boundary gap을 수정했고 source-owned/fake/delegating/foreign exact provider,
  instance/class/`__getattribute__` shadow와 runner state drift 집중 회귀가 `2 passed in 211.55s`로 통과했다.
- 후속 통합 재평가에서 `DockerBenchmarkProviderEvidence/v1alpha1`에 잘못 추가된 request-unit mirror 6개를
  sidecar로 되돌려 exact legacy wire/digest를 복원했다. provider `18 passed, 2 skipped`, single-agent
  `5 passed, 1 skipped`, ZAP scanner `33 passed, 2 skipped`가 통과했고 skip은 모두 opt-in real-Docker였다.
- production controlled-validation Adapter/Inspector/Docker Worker의 exact descriptor·state·observer custody를
  생성, claim 전, Evidence 저장 전, fresh reopen store read 전에 fail closed로 재검증하도록 보강했다.
  독립 집중 회귀 4개는 `4 passed in 54.03s`, runtime 전체는 `9 passed in 142.56s`였고 관련
  Ruff/format과 Linux-target strict mypy도 통과했다.
- 최종 문서 계약 검증은 `2 passed in 0.05s`, `git diff --check`는 whitespace 오류 없이 기존
  LF→CRLF warning만 보고했다.
- 기본 Docker test는 opt-in 경계를 확인하며 `1 skipped in 2.70s`; real-Docker conformance 증거가 아니다.
- 수정 전 opt-in real-Docker가 식별한 fresh JSON tuple/list strict decoding bug는 수정·집중 회귀를 통과했다.
- 이 prior-tree 로컬 실행의 exact image ID는 Target `sha256:94800e670415d1ec44045b6ed76a7f41953d5632a84cbdeda2060962f4e607d6`,
  benchmark Worker `sha256:047fb728394c4c363b371deb736aeb81fdddefd6f99088b99f0501f9fa6f8a9d`,
  ZAP `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`, Worker
  `sha256:679356cf864c80e29ad5e6ae16f524f558f71c0b193918fab0e059ce071cab76`, proxy
  `sha256:5ee00b48322f61a9f0bbb58a4ed128eef804e07da8ee9985f7e82c59501cd3ff`였다.
- current post-audit hardening 전 post-fix opt-in real-Docker conformance는 `1 passed in 545.95s`. 테스트 뒤 managed/execution label과
  `pajin-bench-` exact-name container/network 독립 조회 6건은 모두 0개였고 daemon은 정상 유지됐다.
- GitHub-hosted conformance를 추가하기 전에는 Docker context가 local npipe 두 개뿐이고 기존 Linux CI에도
  opt-in env·image build/pull이 없어 당시 구현을 실행할 known-good alternate path가 없었다.
- 이 제약 때문에 전용 `.github/workflows/web-002d-conformance.yml`을 커밋했다. 기본값 false confirmation
  뒤에만 digest-pinned linux/amd64 경계를 실행하고 장기 run을 자동 취소하지 않는다.
- `tests/test_ci_workflow.py`는 `2 passed`; Ruff check/format과 Linux-target strict mypy도 통과했다.
  committed-ref GitHub-hosted run `33310558350`이 성공했다.

### WEB-002C

- `tests/test_web_source_measurement_admission.py`: `11 passed in 401.05s`. happy/idempotent,
  no-signal, resealed source tamper, second-read source swap, top-level/nested/dataclass hidden state,
  exact Proposal/head trust binding, forged/direct submit, stale Snapshot, Observation/Hypothesis
  사이 head race, lineage mixing과 exact Surface/Graph 경계를 포함한다.
- `tests/test_graph_models.py tests/test_graph_admission.py tests/test_cross_domain_graph_admission.py`:
  `40 passed in 3.86s`. legacy Action/event digest와 wire, sealed-source authority exclusivity,
  proposal/head binding 및 cross-domain 비전이를 검증한다.
- Graph downstream 소비자 `tests/test_graph_projection.py tests/test_graph_sqlite_store.py
  tests/test_control_plane_graph_views.py`: `48 passed, 2 skipped in 10.16s`. skip 2건은 기존
  Windows POSIX link/symlink 제약이다. sealed-source Action이 Capability 없이 operator view에 안전하게
  투영되는 별도 단독 회귀도 `1 passed in 2.55s`였다.
- 전체 `ruff check .`, WEB-002C 관련 Python format check와 Linux 대상
  `mypy --platform linux src` `366 source files`는 통과했다. Windows-native `mypy src`의
  37건은 기존 POSIX-only `os.O_NOFOLLOW`, `O_DIRECTORY`, `geteuid`, `fchmod`, `fcntl`
  stub 차이이며 WEB-002C 파일 오류는 아니다.
- `tests/test_documentation.py`: `2 passed in 0.05s`. `git diff --check`는 whitespace 오류 없이
  기존 LF→CRLF warning만 보고했고, private-key·대표 credential token 패턴 검색은 일치 항목이 없었다.
- 독립 공격/소비자/문서 review에서 처음 식별한 Proposal lineage 재사용, source 두 번 읽기 TOCTOU,
  hidden Pydantic/dataclass state, 과도한 public authority projection, cross-domain source transfer와
  reader rollback 문서 공백을 수정했다. 최종 재검토에서 남은 P1/P2 런타임 문제는 없다.

### WEB-002B

- `PAJIN_TEST_DOCKER_ZAP=1`로
  `test_real_docker_web_zap_source_measurement_conformance`를 실행해
  `1 passed in 69.27s`를 확인했다. Docker Engine은 29.7.2였고 exact Target/Worker/ZAP image ID는
  각각 `sha256:a6387af2d56e4d41fd208985227dc73099a3dc140ffa24abf08fe59550c7f2e0`,
  `sha256:047fb728394c4c363b371deb736aeb81fdddefd6f99088b99f0501f9fa6f8a9d`,
  `sha256:781a2bdaea47324e7bab583e2263f21d257b0aee61ed51521a5be45f5f5081ef`였다.
  테스트 뒤 독립 Docker 조회에서도 `pajin-bench-` container/network가 남지 않았다.
- `tests/test_benchmark_zap_scanner.py`: `21 passed, 2 skipped in 549.85s`. WEB-002B happy path,
  public-safe false authority, literal boolean, completed-journal fence, raw SARIF, exact signed
  distribution bundle, outer authority/세 audit payload reseal, provider direct/cached-replay
  evidence/result wire, Scanner source/observation wire와 journal-record coercion 회귀를 포함한다. 기본
  환경 실행의 skip 2건은 generic P0-E2B와 WEB-002B opt-in real-Docker conformance이며, WEB-002B 항목은
  위 별도 opt-in 실행으로 통과했다.
- `tests/test_benchmark_target_recovery.py`: `12 passed in 7.57s`. read-only journal reopen,
  operation-to-completed-attempt exact lookup, 8-record lifecycle, foreign canonical record-chain 이식 거부와
  multi-fence recovery 재조정을 포함한다.
- `test_web_002b_reload_rejects_foreign_distribution_bundle` 단독 보강 검증은 `1 passed in 44.62s`였다.
- WEB-002B 관련 product/test 7개는 Ruff lint와 format check를 통과했다. 전체 `ruff check .`도 통과했고
  Linux 대상 strict mypy는 `365 source files`에서 통과했다.
- `tests/test_documentation.py`: `2 passed in 0.05s`. 첫 검증에서 KNOWN_ISSUES 64 KiB 상한 초과를
  발견해 현재 상태 중심으로 압축한 뒤 재검증했다.
- 독립 API/테스트/문서 review가 찾은 cached provider replay canonical-wire 우회, outer artifact canonical
  JSON 및 시작/완료 audit payload 공백, journal record-chain 이식, authority-reference ID/digest와 transient
  ADR 상태 문제를 수정했다. 최신 tree 재검토에서 남은 P1/P2는 없다.

### WEB-002A

- measured-case/Capability/floor/Finding 경계 `tests/test_web_measured_case_authority.py`는 최종
  `9 passed in 708.72s`였다.
- signed proxy-route 적대적 회귀 `tests/test_web_proxy_route_authority.py`는 fresh process에서
  `17 passed in 354.43s`였다. 정상 issue/verify/contextful reload, stable consumption slot, 상위 권한과
  continuous testing-window cap, durable approval terminal state, signature/key/route revocation, exact Target
  coordinate/ordinal/current fence, journal environment/causal time/recovery/cleanup drift, public-safe strict wire를
  검증했다. 마지막 기계적 Ruff format 뒤 정상 route와 future execution-intent 거부를 다시 실행해
  `2 passed in 47.41s`를 확인했다.
- Target journal canonical-wire/fence 회귀 `tests/test_benchmark_target_recovery.py`는 `11 passed in 7.67s`였다.
  Web predecessor 8개 collection은 `150 passed, 1 skipped in 94.32s`였다. skip은 opt-in real Docker ZAP
  conformance이며 이번 단계에서는 Docker Target/Scanner/proxy/Worker를 실행하지 않았다.
- 최종 문서·비밀정보 검사는 `14 passed in 0.14s`, 전체 Ruff lint는 통과, 신규 WEB Python 6개는 Ruff
  format check 통과, Linux 대상 strict mypy는 `364 source files` 통과했다. `git diff --check`는 오류 없이
  기존 LF→CRLF warning만 보고했다.
- 독립 authority/hygiene review가 찾은 verification ID 길이, ordinal, approval 재발급 슬롯, 상위 권한 만료,
  continuous testing window, exact coordinate, durable terminal state, contextful reload, numeric coercion 및 journal
  인과성 공백을 수정하고 회귀로 고정했다. 최종 재검토에서 남은 P1/P2 제품 blocker는 없었다.

### Phase 11~21 통합 재평가와 Web predecessor

- Phase 11~21의 PLAN 완료 문구를 실제 CLI, Tool/Worker, provider, benchmark runner, Graph admission과
  false authority marker에 대조했다. 세 개의 독립 read-only 검토도 Phase 13 Web을 전체 후보 중 가장
  높은 재사용성과 가장 작은 새 runtime 경계로 평가했다.
- bundled Python과 project site-packages로
  `tests/test_benchmark_target_catalog.py tests/test_benchmark_zap_scanner.py`를 실행했다. 관리형 Windows
  임시 루트 정책이 첫 실행의 `tmp_path` setup 4건을 막았고, 격리한 전용 `--basetemp` 재실행은
  `16 passed, 1 skipped in 11.29s`였다.
- skip 1건은 opt-in real Docker ZAP conformance다. 이번 재평가에서는 실제 Docker daemon, image build/pull,
  Target/Scanner 실행을 수행하지 않았으므로 runnable contract와 현재 머신의 live conformance를 구분한다.
- 독립 review의 endpoint/network-route, floor/Finding identity 공백과 direct Worker attachment 충돌을 코드에
  대조했다. ADR-0251/0252와 PLAN/HANDOFF에 additive proxy-route/policy 선행 조건을 반영했고 기존 Accepted
  ADR-0250/0251 본문은 append-only로 보존했다.
- 후속 독립 review에서 남은 P1/P2는 없었다. 최종 `tests/test_documentation.py`는 `2 passed in 0.05s`,
  `PLAN.md`는 59,389 bytes이며 `git diff --check`는 오류 없이 기존 CRLF warning만 보고했다.

### CRYPTO-001A~D + FORENSICS-001A~D 검증 체크포인트

- FORENSICS-001D test collection 11개를 disjoint shard로 검증해 모두 통과했다. four Surface/two mode는
  disk `877.90s`, memory `740.92s`, log `716.64s`, artifact `779.36s`; changed/unresolved/equal-digest byte
  invariant는 `974.15s`; partial drift/reused context/noncausal 거부는 `692.00s`; contextful wire reload와
  stored admission/root/store/anchor/hidden-state/Graph-read-only 경계는 `1862.16s`; 순수 import/Grant/fixture/
  marker 4개는 최종 `16.19s`였다.
- `uv run ruff check .`: 통과. D source/test와 수정한 C test helper의 Ruff format check도 통과했다.
- `uv run mypy --no-sqlite-cache --strict --platform linux src/pajin`: `360 source files` 통과. D source/test
  exact strict check도 통과했다.
- 문서 계약 검증은 최종 `2 passed`; `git diff --check`는 오류 없이 기존 LF→CRLF warning만 보고했다.
- 두 독립 review가 찾은 hidden-state pre-dump 제거, CapabilityGrant set 비결정성/semantic ordering과
  debugger-zero marker 누락을 수정했다. 재검토 뒤 남은 P1/P2 finding은 없다.

- FORENSICS-001C test collection 79개를 세 disjoint shard로 검증한 Windows 결과는
  `77 passed, 2 skipped`, code failure 0이다. signature test fixture assertion은 content-addressed
  reference를 보존하도록 바로잡았고 해당 exact node 재실행은 `1 passed in 176.59s`였다. 두 skip은
  Windows directory/symlink 생성 제약이다. 이후 repo-wide Ubuntu CI run `33316840636`은 해당 파일의
  skip 기록 없이 전체 shard가 성공해 Linux 경계 증거를 확보했다.
- `uv run pytest -q tests/test_forensic_evidence_analysis.py`: `286 passed in 765.48s`
- FORENSICS-001A와 공통 discovery/capability/DOMAIN 통합 회귀: `575 passed in 68.43s`
- 문서 계약 검증: `2 passed in 0.05s`
- `.venv\Scripts\ruff.exe check .`: 모든 검사 통과
- 변경 Python 15개는 Ruff format check를 통과했다. 현재 repo-wide `ruff format --check`가 보고하는 184개
  reformat 대상은 기존 baseline이며 해당 변경 15개와 구분한다.
- `.venv\Scripts\mypy.exe --strict --platform linux src/pajin`: `359 source files` 통과;
  FORENSICS-001C source와 test 각각의 strict `--platform linux` 검사도 통과했다.
- 두 독립 boundary/hygiene review에서 수정 뒤 High/Medium finding은 없었다. 219개 Literal marker는 exact
  type validator에 모두 결박됐고 no-signal Hypothesis, secret/debug/placeholder와 raw result-body read 경로가
  없음을 확인했다.

## 알려진 제한

- 일반 multi-domain runtime, production benchmark score와 cross-host Worker fence 증거는 없다.
- repo-wide Linux CI 실행 증거는 commit `051cad4bb67b021dc998a60b1502c7425834ea0b`의 Ubuntu 24.04
  run `33316840636`이다. Quality와 24/24 shard가 성공했고 `7,609 passed, 69 skipped`, 실패·취소 0이었다.
  이는 repository test/quality conformance 증거이며 일반 Domain runtime이나 production benchmark
  실행 권위를 만들지 않는다.
- Phase 22의 WEB-002A registration/read-only authority, WEB-002B bounded ZAP source runtime,
  WEB-002C knowledge-only Graph admission과 WEB-002D controlled execution/floor/Finding 구현은 exact
  conformance commit `975bf787` 이후 불변이며 그 commit의 Ubuntu run `33310558350`을 통과했다. 이는
  product entrypoint, production/external probing, report/Graph admission 또는 일반 Domain runtime 권위를 부여하지 않는다.
- 현재 로컬 Windows container runtime은 host file-access policy 제약으로 시작되지 않는다. 저장소나
  runtime data를 삭제하거나 security policy를 우회하지 않았으며, host-specific incident와 repair 기록은
  저장소 밖에서 관리한다. real-Docker conformance의 권위는 Ubuntu committed-ref workflow다.
- FORENSICS-001A~B는 source 또는 provenance를 resolve/read/mount/copy하지 않는다. FORENSICS-001C는
  deployment-owned root 아래 두 signed/digest-only Evidence 파일만 bounded read하며 parser, target 또는 raw
  result body를 실행·조회하지 않는다.
- `pajin.dev/run-integrity/v1`은 허용된 source-root coordinate vocabulary일 뿐 trusted custody provider가 아니다.
- FORENSICS-001C의 source/custody와 parser execution signature는 configured deployment key에 대한
  authentication이며 external transparency anchor, independent custody truth, evidence class/format, parser
  correctness, negative security claim 또는 Finding을 증명하지 않는다.
- FORENSICS-001B는 parser 실행을 준비하고 FORENSICS-001C는 이미 완료된 signed execution을 admission할
  뿐 sandbox 생성, parser 실행, Ground Truth, deterministic Replay, benchmark measurement 또는 production
  score를 구현하지 않는다.
- FORENSICS-001D는 두 supplied sealed execution을 비교할 뿐 parser를 dispatch하지 않는다. deterministic
  mode는 repeated concrete configuration만 나타내고 DOMAIN-006를 만족하지 않으며, independent mode도
  source-code·algorithm·organization·supply-chain·physical host/Worker 또는 common-mode independence를
  증명하지 않는다. 12개 fixture와 four metric은 requirement registry이며 materialized/observed/measured
  benchmark가 아니다.
- FORENSICS-001C link-hardening 중 Windows directory/symlink 생성이 필요한 두 case는 이 host에서 skip된다.
  Ubuntu repo-wide run `33316840636`에는 해당 파일의 skip이 없고 전체 shard가 성공했으므로 Linux 경계는
  검증됐지만, 이 Windows host의 symlink 생성 권한 제약은 남아 있다.
- test source 전체를 strict mypy 대상으로 확장한 탐색 검증의 기존 helper annotation 7건과 Windows
  symlink 권한 제약은 `KNOWN_ISSUES.md`에 기록되어 있다. 공식 Linux CI 범위인 `src/pajin`은 선행
  체크포인트에서 통과했다.

## Git 재개 확인

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count origin/main...HEAD
git log -5 --oneline --decorate
git diff --check
```

작업 재개 시 staged/unstaged/untracked 파일과 진행 중인 merge/rebase/cherry-pick을 확인하고 발견한
변경을 보존한다. 이 문서 동기화 시작 시 CRYPTO-001A~D, FORENSICS-001A~D와 WEB-002A~D 코드는 이미
커밋돼 있었고 working tree에는 위 7개 문서 변경만 남아 있었다. 이후 Linux CI가 식별한 canonical 모바일
substitution fixture 보정은 `4208889bfc1b84ae50a2f8bbbff77109c342b3bc`, 24-shard/120분 CI는
`051cad4bb67b021dc998a60b1502c7425834ea0b`로 각각 커밋·push했고, run `33316840636`에서 전체 성공을
확인했다. 현재 문서 변경과 Git 상태는 재개 시 다시 대조한다.

## UX-009A~D 로컬 체크포인트

- `src/pajin/workflow/web_measured_product_flow.py`는 exact
  `load_web_controlled_validation_authority`를 publication과 reload 전에 각각 호출하고, 별도 sealed Run에
  measured-case Scope, content-free Evidence reference, 14개 public floor metric, bounded
  `benchmark-ground-truth-match` Finding과 unavailable report state만 투영한다.
- `tests/test_web_measured_product_flow.py`는 exact reopen-context 값 배선, source-before-product ordering,
  canonical JSON roundtrip, strict boolean·claim ceiling, source/product substitution, artifact/event tamper와
  Run 재사용 거부를 검증한다. WEB-002C Graph predecessor, raw/private content, route·Permit·path,
  Graph/report/HTTP/UI와 Target/provider/Docker/Worker/network/credential side effect 권위는 모두 false다.
- 새 영어 versioned contract는
  `docs/orchestration/UX-009A-sealed-measured-web-product-flow-projection.md`다. README, multi-domain RFC와
  PLAN은 현재 구현과 UX-009C/UX-009D 우선순위로 동기화했다.
- `src/pajin/workflow/web_measured_product_reader.py`는 frozen/slotted registration과 reader,
  `MappingProxyType` registry 및 deployment-owned resolver TCB를 제공한다. zero-argument `read()`는
  등록된 기존 product/source Run 경로와 모든 content identity를 매번 canonicalize하고 exact UX-009A
  loader를 호출한 뒤 bounded projection만 반환한다.
- caller root/path/provider/adapter/trust anchor/ledger/journal/private mapping/source/projection/bare JSON,
  중복 deployment/product Run/flow, product/source alias·reuse, foreign runtime type와 등록 후 remap은
  fail closed한다. contextual WEB-002D reload의 provider DB와 Docker inspector 조회는 read-only Evidence
  재검증이며 Target/provider mutation, controlled execution 또는 target-network action이 아니다.
- 새 영어 versioned contract는
  `docs/orchestration/UX-009B-deployment-pinned-contextful-product-reader.md`다. 실제 새 OS process에서의
  repeated canonical read와 전체 durable-state call audit는 계약과 ADR-0257에 따라 UX-009D가 검증한다.
- `create_app(..., web_measured_product_reader=...)`는 exact UX-009B concrete reader만 process-local로
  주입한다. 항상 등록되는 fixed `GET /v1/products/web-measured-flow`는 인증 뒤 Operator만 허용하고,
  body/query는 reader 호출 전에 400, reader 미구성은 503, 무결성 실패는 private context를 반사하지 않는
  fixed 409로 닫는다. 성공 응답은 wrapper 없이 unchanged UX-009A alias wire다. UX-009B resolver는
  thread-safety를 계약하지 않으므로 동시 HTTP read는 app-local lock 안에서 직렬화하되 매 요청마다
  별도의 reader 무결성 재검증을 수행한다.
- same-origin Web Console은 입력 없는 명시적 load button, fixed GET, memory-only bearer, no-store/omit/error
  request options를 사용한다. exact nested schema, 14/11/3 metric의 code-owned 순서·ID·digest·unit·
  applicability·comparison·N/A reason·signed-64 rational, reference equality, strict boolean과
  claim/impact/severity/report/disclosure/authority ceiling을 검증한 뒤 `textContent`로만 표시하고
  credential 교체, lock, `pagehide`와 stale response에서 결과를 제거한다.
- 새 영어 versioned contract는
  `docs/orchestration/UX-009C-operator-only-measured-web-product-view.md`다. UX-009A의
  `httpEntrypointAvailable=false`와 `uiEntrypointAvailable=false`는 projection 자체가 transport authority를
  주지 않는다는 의미로 그대로 보존한다. application durable file은 만들지 않지만 UX-009B loader의
  mandatory ephemeral `.pajin-run-locks` coordination과 read-only provider/inspector Evidence check는 유지한다.
- UX-009A 집중 전체 테스트 재실행: `15 passed in 664.79s`.
- UX-009B 집중 전체 테스트: `3 passed in 254.68s`. 이후 추가한 중복·foreign type·alias·deployment
  fail-closed assertion 영향 2건은 `2 passed, 1 deselected in 218.09s`로 다시 통과했다.
- 인접 WEB-002D production authority guard: `2 passed in 210.48s`.
- `.venv\Scripts\python.exe -m ruff check . --no-cache`: 통과. UX-009C route/test Python format check:
  `3 files already formatted`. `src/pajin/control_plane/api.py`의 전체 format check가 보고하는 기존
  두 formatting hunk는 HEAD에도 동일하게 재현되므로 이번 범위에서 무관한 줄을 재format하지 않았다.
- `.venv\Scripts\python.exe -m mypy --platform linux src`: `372 source files` 통과.
- 문서 계약: `3 passed in 0.17s`.
- tracked `git diff --check`: 통과.
- 관리형 Windows 임시 디렉터리 정책으로 기본 pytest root와 lock 쓰기가 제한됐다. 허용된 격리 임시
  루트와 `-p no:cacheprovider`를 사용한 재실행은 통과했으며 코드 실패와 구분한다.
- 독립 리뷰에서 발견한 mutable registry/reader, concurrent reader, metric identity/rational drift와 lossless
  BigInt P2는 frozen composition, app-local serialization, exact protocol validation과 회귀로 수정했다.
  provider/network 경계 문구도 실제 read-only inspector 동작에 맞췄으며 최종 재리뷰에는 P1/P2가 없다.
- UX-009C endpoint 통합 테스트는 실제 UX-009A/B chain과 4-way concurrent read로
  `3 passed in 184.07s`, 전체 기존 Web Console CSP/source/runtime/API 회귀는 `18 passed in 5.85s`였다.
  dependency-free Node runtime 직접 실행과 실제 FastAPI 응답의 strict protocol 재검증도 성공했고
  출력·외부 의존성은 없었다.
- `tests/web_measured_product_fresh_process.py`는 `spawn` child에서 production provider, adapter, route
  context, exact registry/reader와 Control Plane app을 재구성한다. 두 successful read와 auth/role/query/
  body/method denial을 검증하고, 별도 child에서 isolated sealed failure copy 13개를 fixed `409`로 거부한다.
  failure set은 strict boolean, claim/impact/severity, metric, product/source rehashed/resealed event, stale
  product/source, foreign Run/path pair와 non-canonical/duplicate-key/oversized JSON을 포함하며 13개 ID와
  순서는 별도 상수로 고정돼 producer-derived assertion이 누락을 숨길 수 없다.
- whole-call audit는 exact execution-label container/network 조회와 exact Worker/proxy image inspect만
  허용한다. provider/adapter/Worker/Graph/report/delivery mutation method, 다른 subprocess/process launch,
  socket/DNS, lock 경로 밖 filesystem mutation을 즉시 거부하고 audit root bytes/mtime와 six-way Docker
  inventory를 전후 비교한다. exact `.pajin-run-locks[-uid]/<64hex>.lock` 생성·갱신만 예외이며 다른 이름,
  nested entry, link와 특수 파일은 거부한다.
- `tests/test_web_controlled_validation_docker.py`의 기존 dedicated test는 WEB-002D lifecycle을 한 번만
  완료한 뒤 두 UX-009A publication과 hash seed가 다른 두 success child, 13-case integrity child를 실행한다.
  success child는 각각 300초, integrity child는 1200초 상한을 사용해 60분 job budget 안에서 startup과
  case 수를 반영하고 timeout diagnostic에 hash seed와 integrity case 수를 남긴다.
  `.github/workflows/web-002d-conformance.yml`의 기존 selector가 UX-009D도 실행한다. 로컬 container
  runtime을 사용할 수 없어 real-Docker test는 실행하지 않았다.
- UX-009D supplemental local regression 최신 재실행은 `3 passed in 224.05s`; D Python Ruff lint와
  format, compile 및 real-Docker test collection은 통과했다.
- DOMAIN-006 canonical registry template cache와 defensive-copy 회귀는 `4440414`에 반영했다. 관련
  DOMAIN-006·fresh monitor 집중 테스트는 `55 passed`, 인접 Web/DOMAIN-006 회귀는 `169 passed`, Ruff와
  Linux strict mypy 372 source files가 통과했다.
- strict model의 JSON array를 Python list로 재검증하던 fresh-process helper는
  `model_validate_json(first.content)`로 수정했고 집중 회귀 `4 passed`를 통과했다.
- exact checkpoint `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf`의 Ubuntu run `33410801762`, job
  `99549584968`에서 fresh-spawn conformance `1 passed in 836.08s`와 unconditional residue audit이
  모두 성공해 UX-009D와 Phase 23 Exit Gate를 완료했다.
- 새 영어 versioned contract는
  `docs/orchestration/UX-009D-fresh-session-deterministic-product-read-conformance.md`다.
- UX-009A~D는 `6b8faad`, `ee8b0ed`, `b50f81b`, `509e654`, `4440414`, exact verified checkpoint
  `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf`로 `main`에 push됐다.

## 다음 한 단계

[ADR-0259](docs/adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)의
`AI-002B` source 경계를 로컬 구현했다. `pajin.workflow.ai_fixture_runtime`은 AI-002A의 fixed
Target/Worker/proxy image contract를 실제 관찰 OCI ID에 결박하고 fresh internal no-published-port
vulnerable Target, proxy-only topology, signed Target receipt와 cleanup을 검증한다.
`pajin.workflow.ai_source_measurement`는 exact M03 한 건을 기존 AI-001B preparation, external approval,
one-use ActionPermit, Gateway, Docker Worker와 AI-001C reopen 경로로 한 번만 실행한다. scenario, prompt,
check, mode, image, route, Scope, authority 여덟 substitution은 dispatch 전에 code-owned 순서로 거부된다.
public authority에는 digest lineage와 denial만 남고 Ground Truth, prompt/check, transcript, session, request,
approval/Permit body, raw Worker/Tool result, Target coordinate·receipt·trust anchor·topology는 별도 private
binding에 남는다.

AI-002B 집중 파일은 `75 passed, 2 skipped in 13.75s`, AI-001A~D/KISA M03/Target/Worker/validation
회귀는 `249 passed, 2 skipped in 396.56s`다. 스킵은 opt-in real-Docker 한 건과 Windows의 POSIX 전용
cleanup 한 건이다. `src tests containers` 전체 Ruff, Linux 대상 strict mypy `381 source files`, 변경
파일 구문 검사, 문서 정책·링크 `4 passed in 0.30s`, tracked `git diff --check`가 통과했다. 관리형
Windows의 project Python 비동기 모듈 실행 제한과 기본 temp ACL은 코드 실패와 구분했고, 기존 Python
3.14 lockfile 격리 환경과 task-local temp root에서 검증했다. 현재 container daemon이 없어
`PAJIN_AI_002B_REAL_DOCKER=1`은 미실행이고,
전체 repository pytest와 현재 변경의 새 exact-commit CI도 실행하지 않았다.

새 영어 versioned contract는
`docs/benchmark/AI-002B-registry-governed-disposable-m03-source-measurement.md`다. 다음 첫 단계는
AI-002B diff와 Git 상태를 다시 검토한 뒤 명시적 승인으로 checkpoint를 commit/push하고 새 exact-commit
repo-wide green을 확인하는 것이다. 그 전에는 AI-002C를 시작하지 않는다. AI-002C는 두 supporting
fresh-session Replay, exact Baseline/Negative/Counterfactual Controls와 DOMAIN-006 AI floor만 추가하며,
product와 exact-clean Ubuntu conformance는 AI-002D에 남긴다.

저장소는 public, Apache-2.0이며 `main` protection과 private vulnerability reporting이 활성화돼 있다.
exact workflow용 원격 임시 브랜치 `hyexe/ux-009d-json-wire-6cb58c1`은 검증된 SHA를 확인한 뒤
삭제했으며, `hyexe/ux-009d-*` 원격 ref가 남아 있지 않음을 재검증했다.
