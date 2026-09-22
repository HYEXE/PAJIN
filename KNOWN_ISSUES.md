# PAJIN 알려진 문제

현재 구현의 미해결 제약과 검증 공백을 기록한다. 제품 우선순위는 `PLAN.md`, 실제 실행 결과와
Git 상태는 `HANDOFF.md`, 상세 요구와 권한 경계는 각 버전형 계약이 권위다.

## 현재 후속 목표의 한계와 남은 검증

- [AGENTIC-002](docs/orchestration/AGENTIC-002-durable-agentic-coordination.md)는 AGENTIC-001의
  current Graph head resolution, invocation journal, checkpoint CAS, outbox/inbox, verified restore와
  context compaction을 구현했다. 권위 backend는 Linux `/proc/self/fd`와 trusted hosting process에
  한정되며 macOS 등에서는 파일 mutation 전에 fail closed한다. reopen expected store ID는 다른 DB
  대체를 막지만 같은 DB 전체 rollback을 증명하지 못하므로 별도 head witness가 필요하다. Graph와
  coordination store는 비원자적이고 Provider outcome-unknown은 자동 재전송하지 않으며 sealed receipt
  또는 수동 reconciliation이 필요하다. terminal receipt는 Provider 실행 자체의 독립 증명이 아니다.
  hostile in-process FD/memory/monkeypatch 격리는 별도 broker 또는 descriptor-aware SQLite VFS가
  필요하다. 이 slice는 Scope·Capability·Permit·Gateway·Worker·Finding·Graph write·보고·PoC나
  실제 model/target 실행 권위를 만들지 않는다.
- [AGENTIC-003](docs/orchestration/AGENTIC-003-governed-specialist-execution.md)은 003A의 exact inert
  XSS·SQLi·authorization profile과 003B의 별도 code-owned executor closure·최소 browser split을
  구현했다. testing-only injected harness는 exact phase와 dependency/promotion 경계를 검증하지만
  production provenance가 아니다. 003C1은 current Graph·durable head, sender ACK·receiver inbox,
  selected Candidate·current specialist·live Agent Session을 exact reload한 뒤에만 store-local
  one-use reservation을 만들고 outcome-unknown 이후 자동 redispatch와 restart authority 재발급을
  거부한다. 003C2는 original reservation을 소비하지 않은 채 current Graph·durable head와 exact
  Juice Shop Campaign/Target/Scope/budget, production profile/executor를 content-addressed inert
  preparation에 결박했다. 003C3A는 세 specialist별 exact T2 read-only Capability·Tool·signed
  Range activation·deterministic `PreparedCapabilityAction`을 구현했지만 모든 dispatch role은
  fail closed한다. fixed 100 request-unit는 보수적 예산이지 실제 specialist Worker 비용 측정값이
  아니다. 003C3B1은 original reservation handle을 소비해 exact Campaign·preparation·action·
  live one-call non-delegable child Grant·approval tuple·expected Permit을 durable `awaiting-permit` plan에
  결박하지만 execution row는 `reserved`로 유지한다. preparation, Capability activation,
  `PreparedCapabilityAction`, Grant binding, approval envelope, reservation, plan audit entry 어느 것도
  signed approval·Permit·dispatch·execution authority가 아니다. reopen은 plan handle을 재발급하지 않고
  invalid·expired·never-submitted approval의 awaiting row를 자동 재활성화하지 않는다. Permit commit 뒤
  callback 미진입 구간은 인증된 reconciliation이 필요하며 자동 retry/redispatch는 금지된다.
  003C3B2는 deployment-owned exact Graph/Permit Store·live Ledger·approval keyring·shared Permit writer와
  fresh signed approval을 pin하고 one-winning callback 안에서 Permit·Grant 소비, Grant-consumption
  receipt, plan/execution crash fence를 구현했다. Graph와 coordination transaction은 여전히 원자적이지
  않으며 hard process failure 뒤의 audit-only `awaiting-permit`은 자동 reconciliation·refund·retry를
  제공하지 않는다. 기존 `begin_specialist_dispatch()` 결과, raw plan row, Permit, receipt, 직렬화된
  binding은 future Gateway의 bearer authority로 사용할 수 없다.

  현재 additive SQLi v2는 complete seven-role code-backed Capability bundle, externally signed current
  Range release activation, exact action registry와 deterministic `PreparedCapabilityAction`까지 제공한다.
  materializer/compiler 외 execution·interpretation·replay·cleanup role과 direct Tool dispatch는 fail
  closed한다. distinct v2 Plan wire/runtime generation, one-call Grant, signed approval, Permit callback,
  same-scheduler-Task started handle·private capsule과 Store-owned one-shot runtime claim은 구현됐다.
  이 predecessor claim은 current Graph·durable history·deployment·preparation/action·approval·terminal
  Permit·Grant lineage를 다시 검증하고 성공 또는 terminal failure 뒤 capsule을 폐기하며, 그 위의 live
  pre-backend admission은 exact Task/capsule에서 durable `claimed-before-backend` JobAttempt 및 opaque
  non-copyable claim을 발급한다. public deployment/claim에는 raw backend·verifier·key·template·inventory가
  없고 private control-plane owner vault만 exact factory anchors를 보유한다. 이 vault는 arbitrary
  same-interpreter reflection을 방어하는 sandbox가 아니므로 untrusted model·Skill·plugin·target 코드는
  별도 process/sandbox에 있어야 한다. v1 inert artifact를 Permit 뒤 v2 execution identity로 교체할 수도
  없다. schema v6는 JobAttempt·
  terminal receipt와 embedded canonical typed Claim/DispatchVerification DAG,
  indexed ID/digest, Capability authority-set, scheduler Task, runtime capsule, authorization lineage,
  runtime inventory pin을 저장한다. exact offline v5→v6 migration은 legacy row를 보존하고 새 table을
  비운 채 생성하지만 execution history나 authority를 만들지 않는다. reopen/recovery는 audit-only이며
  Task·capsule·handle·Gateway·backend 권위를 재발급하지 않는다.

  structured v2 fake backend는 exact `specialist_backend_v2.py` source bytes, compiler, image, job template,
  backend, verifier와 deployment Ed25519 key를 pin하고 one-call signed zero-Target-I/O result를 검증한다.
  이 source bytes는 현재 version의 identity-bearing input이라 수정 시 successor version이 필요하다.
  fake backend는 Gateway/Worker 성공이 아니고 durable conformance-success terminal kind도 없다. 결과는
  `completed-verified`가 될 수 없으며 model·browser·network·Target I/O 또는 execution·validation·Finding·
  Graph·report·SARIF·PoC authority를 만들지 않는다.

  trusted pre-backend abandonment producer는 owner Task 종료, Store close, explicit discard와 post-insert
  mint failure를 `abandoned-before-backend`로 기록하지만 backend provenance가 아니다. receipt writer
  실패 또는 JobAttempt commit 직후 hard process failure는 receipt 없는 claimed audit row를 남길 수 있다.
  recovery는 이를 분류만 하고 receipt 합성, handle 재발급, 자동 redispatch를 하지 않는다.
  dispatch-marker COMMIT은 성공했지만 호출 반환이나 cleanup이 실패한 모호성도 durable equality가 false
  abandonment를 막아 unreceipted unknown으로 fail closed하며, 정확한 COMMIT-success/return-failure
  fault injection으로 이 분류와 zero backend invocation을 검증했다.
  same-Task zero-I/O execution boundary는 opaque claim 소비, immediate authority/runtime re-observation,
  durable dispatch-start fence, private structured Worker one-shot, signed-result verification,
  Gateway-minted opaque completion과 Store-owned terminalization을 구현했다. proven zero-I/O result는
  `failed-before-target-io`, post-marker failure/cancellation은 `started-outcome-unknown`이며 receipt commit
  실패는 unreceipted unknown으로 남는다. 이 경계는 실제 browser/network/Target I/O를 수행하지 않는다.
  현재 cancellation 증거는 pinned zero-I/O backend 내부에서 발생한 `CancelledError` 분류까지이며,
  suspending target-I/O backend에 대한 실제 scheduler `Task.cancel()` race는 아직 검증되지 않았다.
  frozen fake backend를 수정하지 않는 target-I/O-capable successor, 실제 승인된 SQLi Juice Shop 실행,
  003D 독립 Replay·Finding·Graph admission·보고 승격이 남아 있다. Graph admission으로 head가 바뀐 뒤 dynamic replanning을
  계속하려면 최초 coordination binding을 무시하지 않는 명시적 epoch/rollover 계약도 필요하다.
  권위 폐기를 증명하는 Store close는 trusted composition 때 보관한 exact unbound close를 owner가
  직접 호출한 경우로 한정한다. 일반 `store.close()`, context-manager exit와 finalizer는 pre-call
  Python runtime mutation 아래 독립적인 zeroization 증거가 아니다. 최신 live zero-I/O execution 변경은
  network-none/read-only Linux JobAttempt claim/dispatch `39 passed`, v2 Plan `42 passed`, Capability
  activation·typed attempt·structured backend `62 passed`, dispatch binding `43 passed`다. 관련 Ruff,
  Python compile과 strict mypy source 검증은 통과했다. 2026-09-20 최종 전체 suite는 sandbox에서
  10,157 passed·293 skipped와 loopback bind 권한 실패 10건이었고, 실패한 네 파일은 loopback 허용
  경계에서 38 passed였다. 전체 suite를 sandbox 밖에서 다시 실행한 결과는 아니다.
  기존 aggregate Web runner/Capability/Tool/Worker를 subset executor로 재표시하거나 testing
  catalog/observation을 production 입력으로 받을 수 없다.
- [AGENTIC-004](docs/benchmark/AGENTIC-004-campaign-evaluation.md)는 public non-runnable
  3-arm·3-role·17-metric 계약만 구현했다. 별도 승인 transfer target, private holdout/evaluator,
  exact arm implementation digest, fresh approval/Permit이 없어 실제 성능 측정 근거는 아직 없다.
- [SKILL-001](docs/orchestration/SKILL-001-versioned-analysis-skill-registry.md)의 exact knowledge-only
  registry와 [SKILL-002](docs/orchestration/SKILL-002-proposal-only-selection-and-split-projection.md)의
  proposal-only successor·선택·split projection·zero-dispatch 준비 Run을 구현했다. SQLi·object
  access·XSS·attack path 네 Skill만 선택되며 Finding narrative는 catalogued다. 현재 passive
  discovery는 Skill이 요구하는 independent replay·negative control·semantic oracle를 충족하지
  않으므로 requirement는 전부 unsatisfied다. legacy `[developer,user]` wire는 pinned
  tokenizer context에 들어가지 않고 historical Capacity v1은 live gate에 사용할 수 없다.
  attested Capacity v2·zero-dispatch preparation·non-executing admission과 ADR-0319 Gate A의 actual
  live final-view materialization/attestation/cleanup, ADR-0320 Gate B dual-identity durable CAS와
  cleanup-only crash recovery는 검증됐다. Gate C one-call authorization, Gate D compact runtime/receipt,
  성공 model proposal, Skill→Recipe/Capability binding,
  target 실행과 독립 성능 검증은 없다. 별도 사용자 승인 없이는 새 model completion을 진행하지 않는다.
  금지 field와 알려진 target
  canary 검사는 의미적으로 위장된 모든
  정답·비밀의 부재를 증명하지 않으므로 source review가 계속 필요하다.
  외부 Skill corpus는 아직 provenance/license review나 vendoring을 거치지 않았고 runtime fetch는
  허용하지 않는다. Juice Shop은 개발·결정론적 회귀 target일 뿐 범용 성능 근거가 아니다. 두 번째
  승인 target, 동결된 private holdout, defended negative, holdout 소비/비재사용과 성능 지표 집계가
  남아 있다. 각 대체 coverage를 확인하기 전에 기존 target-specific regression, authority gate,
  strict loader, semantic oracle, negative control, PoC replay test를 삭제하면 안 된다. System,
  Application, Forensics 확장도 domain별 Profile/Capability/Worker/Evidence/oracle 계약 전에는 지원이
  아니다.

- [WEB-003](docs/orchestration/WEB-003-exact-loopback-browser-assessment.md)은 사용자가 승인한
  OWASP Juice Shop 19.2.1의 exact `127.0.0.1` origin 한 개에서 정상 browser login·세 SPA route·
  SQL login/basket object access/DOM XSS의 source/replay·대조군·두 attack path·봉인 보고를 실제
  검증했다. 임의 사이트·일반 form/route discovery·추가 취약점·user credential·IPv6/HTTPS·다른
  browser/버전·동시성·장기 실행·accessibility 탐색은 미검증이다. 이 로컬 권한은 기존 Campaign/
  Capability/Permit/Gateway와 Graph/Finding/SARIF/외부 전달 권위가 아니다. 실행이 만든 random
  local test account와 실패/성공 Run은 자동 삭제하지 않는다. Playwright browser runtime과
  `browser` extra가 필요하며 제한된 sandbox에서는 browser cache/process 실행 승인이 필요할 수 있다.
  WEB-003 실제 디버깅·최종 검증에서는 승인 범위 밖의 삭제를 하지 않아 random local 평가 account
  열한 개가 남았다. 초기 pre-mask 성공 Run 두 개에는 복원 가능한 application-masked test account
  suffix가 screenshot으로 남지만 전체 비밀번호·session token은 없다. 최종 Run은 account와 runtime
  DOM marker를 검게 가렸다. 집중 7개 검사와 실제 Run은 통과했다. 후속 리뷰 수정 전 전체 suite 한
  번의 결과는 8,791 passed·76 skipped·11 failed였으며, 열 건의 sandbox loopback listener 권한
  실패는 허용된 환경에서 통과했다.
  남은 생성 dependency export 불일치는 갱신 뒤 deployment 19개로 통과했지만, 그 수정 뒤 전체 suite는
  반복하지 않았다. clean checkout·원격 CI는 아직 실행하지 않았다.
- [WEB-004](docs/orchestration/WEB-004-bounded-authenticated-browser-campaign.md)는 exact
  `127.0.0.1:3000` Juice Shop에서 비실행 Campaign 초안/등록 전용 Capability 준비, 정상 로그인 뒤
  GET/HEAD-only passive route/form discovery, security-header·FTP-listing 추가 진단, strict
  source/semantic 검증, `sealed-source-authority` neutral Graph proposal과 봉인 local 보고를 구현했다.
  이 Capability는 login state를 보수적으로 `irreversible-write`·cleanup-required로 분류하므로
  credential/login-state/cleanup authority가 없는 현재 Profile/Plan은 실행할 수 없다. 인증된 core
  Campaign compilation, release/activation, approval input, durable T2 Permit 소비, Gateway/Worker 실행,
  독립 executor/target attestation, Graph admission, Finding/SARIF와 외부 전달은 없다. CLI가 방금 만든
  source의 Run/root pin은 producer-derived이며 독립 공급 또는 독립 실행이 아니다. form 제출·user
  credential·account cleanup·arbitrary target·IPv6/HTTPS·browser diversity도 지원하지 않는다.
  권한 재설계 확인과 종료 경고 수정 확인은 각각 새 로컬 계정 1개를 만들었고, 이전 WEB-004
  시도의 계정과 함께 삭제 권한 없이 보존한다. 현재 총계는 별도 인증된 inventory 없이 추정하지
  않는다.
- [WEB-005](docs/orchestration/WEB-005-governed-local-authenticated-browser-campaign.md)는 reusable
  signed recipe protocol과 activation 계약을 제공하지만 설치·실행 가능한 adapter는
  `juice-shop-local/v1` 하나뿐이다. exact `http://127.0.0.1:3000` 외 임의 사이트, SSO, MFA,
  CAPTCHA, arbitrary form, generic payload synthesis, IPv6/HTTPS/remote target은 지원하지 않는다.
  실제 source/validation과 redacted PoC 재실행은 OWASP Juice Shop 19.2.1에서 통과했지만 다른 버전과
  browser 다양성은 미검증이다.
- [WEB-006](docs/orchestration/WEB-006-installed-profile-and-authenticated-discovery-evidence.md)은
  closed production profile·adapter/diagnostic catalog와 같은 authenticated Playwright context의
  passive discovery Evidence를 연결하고 있다. production inventory는 여전히 exact
  `juice-shop-local/v1`/`http://127.0.0.1:3000` 한 개뿐이고 private fixture는 지원 대상이 아니다.
  discovery는 GET/query-free/bodyless/no-redirect, phase 20·전체 100 request로 제한되며 per-request
  receipt와 `discovery-evidence.json`은 `proposal-only`다. 발견 route/form은 Scope·Permit·Graph·
  Finding 권위가 아니다. 이전 WEB-005 actual Run과 PoC replay는 이 변경의 runtime 근거가 아니므로
  새 actual run, strict reload, redacted PoC replay, 비밀정보 검사와 확장 Web 회귀가 남아 있다.
  downstream `validation/v1alpha1`은 진단 3개·attack path 2개를 고정하므로 두 번째 production
  adapter와 가변 진단 cardinality는 별도 `v1alpha2` 계약·구현·실증 없이는 지원하지 않는다.
  SSO/MFA/CAPTCHA, user credential, anti-CSRF·multi-step form 제출, generic payload, 외부 target,
  container/remote Worker와 외부 보고 전달도 여전히 지원하지 않는다.
- [WEB-007](docs/orchestration/WEB-007-llm-assisted-web-analysis-proposal.md)의 historical v1 proof는
  readable하지만 live gate로 쓸 수 없다. attested Capacity v2 Run
  `run_20260921T052042Z_0932a478`과 zero-dispatch preparation Run
  `run_20260921T052213Z_801a9053`은 strict reload·cleanup을 통과했지만 다음 제약은 남아 있다.
  Gate A는 held descriptor에서 fresh owned volume으로 복사한 4.28 GB model과 actual live server의
  final read-only view를 Capacity v2에 exact 결박하고 cleanup/absence까지 검증한다. 다만 복사·반복
  hash의 분리된 시간·저장 비용은 측정·최적화하지 않았고, process SIGKILL·host·Docker-daemon 중단 후
  labelled container/volume/network를 시작 시 회수하는 sweeper는 없다. 한 process 안에서 Docker
  create 성공 뒤 CLI 결과가 불확실한 경우는 exact owner 재검증과 cleanup으로 회수한다.
  non-executing admission은 exact preparation·compact request를 결박하지만 권한 bearer가 아니다.
  Gate B journal은 한 pinned store 안의 독립 preparation/authorization UNIQUE와 single-use CAS,
  deterministic cleanup locator를 제공하지만 분산 consensus가 아니며 동일 store 전체 rollback을
  외부 retained head 없이 독립 감지하지 못한다. crash recovery는 quiescent 단일 coordinator가
  명시적으로 실행해야 하고 Gate D가 실제 owner-bound cleanup을 수행해야 한다. live completion 전에는
  외부 one-call authorization과 additive compact runtime/receipt가 모두 필요하다. 성공 structured output, model quality,
  latency·peak memory·stability, full WEB-006 governed Run·PoC replay, WEB-008 action 연결은 미검증이다.
  현재 artifact는 target request, Permit, Finding, Graph, report, SARIF, PoC, 외부 전달 권위를
  만들지 않는다.
- 역사적 WEB-007 legacy Worker metadata reader는 나머지 metadata를 code-owned request/runtime에서
  재구성하지만, 비정규화된 v1 stdin 호환을 위해 `stdinSha256`은 64자리 소문자 hex 형식만 확인하고
  현재 재구성값과 같다고 요구하지 않는다. Skill-bound successor는 전체 metadata를 exact canonical
  equality로 검증하므로 이 제한의 영향을 받지 않는다. legacy digest 강화는 기존 봉인 Run 호환성
  조사와 별도 migration/version 결정 없이는 수행하지 않는다.
- WEB-005의 네 observer/executor는 서로 다른 process/key/execution identity를 사용하지만 같은 host와
  coordinator 신뢰영역에 있다. host subprocess는 container/VM/remote Worker, 별도 조직·관리 영역,
  trusted egress-proxy receipt를 증명하지 않는다. pre/post fingerprint가 일치해도 그 사이의 일시적
  same-origin target 교체를 배제하지 못한다.
- WEB-005 browser는 닫히고 credential/private key/session material은 산출물에 저장되지 않지만,
  disposable account와 server-side session은 target에 남는다. 삭제·session revoke는 별도 승인된
  mutating cleanup이다. SARIF는 independently confirmed Finding 3건을 전달하지만 두 attack path의
  종적 설명은 Markdown report가 권위다. 외부 전달은 수행하지 않았으며 별도 authenticated delivery
  coordinator와 receipt가 필요하다.
- WEB-005 Graph/Grant DB와 checkpoint enrollment는 caller-owned host-local output에 있다. 동일 UID가
  output root와 enrollment marker를 함께 삭제하거나 rollback하면 이 로컬 상태만으로 손실을 증명·
  복구할 수 없으므로 별도 retained OPS-005 witness 연결이 남는다. DB checkpoint event append 뒤
  dedicated parent seal 전 crash는 fail-closed하지만 검증된 terminal failure journal을 만들지 못한다.
  현재 구현은 이 torn prefix를 자동 복구하거나 uncertain action을 redispatch하지 않는다.
- 기존 완료분과 OPS 순서·Replay 실행 직전 lease 재검사를 `39c66a2`까지 push했다.
  같은 SHA의 일반 CI 8,675 passed·76 skipped, Web·Network·AI·OPS·SYS 실증이 모두 통과했다.
  새 로컬 EFFECT-007·GRAPH-PERF-006·UX-014는 이 원격 검증에 포함되지 않는다.
  최초 실패 근거와 최종 성공을 구분해 보존하며 운영 배포는 없다.
- [EFFECT-007](docs/benchmark/EFFECT-007-structured-output-and-public-hash-families.md)의 새 384응답에서
  v5/v6 오탐은 72→44건, 미탐은 7→7건이다. 정밀도 56.10→67.65%·재현율 92.93% 유지로
  품질 기준은 통과했지만 평균 CPU가 38.04→38.97μs로 증가해 CPU·종합 개선 기준은 실패했다.
  기본 v1은 유지하고 v6는 실험 후보로 남는다. 생성 31·공개 대조 11·grouped 2건의 오탐과
  grouped의 일곱 미탐이 남는다. qualifying 생성 요청에서 UUID 형태의 실제 private 값도
  누락할 수 있다. 직전 EFFECT-006의 FP 62는 다른 평가군의 값이다. 모든 선행 평가군과
  이번 평가군은 소비됐으며 retune 후 미사용 확인 평가군으로 재사용할 수 없다.
- [GRAPH-PERF-006](docs/benchmark/GRAPH-PERF-006-history-memory-and-concurrent-readers.md)는 전후 각
  72개 조합의 실제 Linux 조회와 결과 일치·동시 RSS·정리를 검증했다. 큰 이력 cold 두 reader의
  과거 조회 RSS는 1,114.3→976.8 MiB, 반복 조회는 8.0919→0.2929초로 줄었다. 다만 최초 조회는
  8.0779→8.8719초로 늘었고 24개 조건 모두 최초 조회가 느려졌다. current-page 반복도 여덟 조건
  모두 느려졌다. 전체 hash·검증·독립 copy 비용은 남고 모든 조회가 빨라졌다는 결과는 아니다.
  첫 기준 실행의 66개 조합 뒤 중단 원인은 하위 로그가 없어 미확정이다. 같은 조합의 직접 실행과
  진단 보완 후 전후 전체 비교는 통과했다. 실패 결과는 최종 비교에 합치지 않았다.
  target 5ms sampling의 최대 실제 간격은 전후 37.88/16.80ms이며 짧은 peak를 놓칠 수 있다.
  동시 RSS는 공유 page를 process마다 계산한다. host/device cold·최대 크기·운영 SLO는 미검증이다.
- [OPS-005](docs/orchestration/OPS-005-separately-retained-recovery-witness.md)는 별도 witness가 최신이면
  anchor 한쪽 rollback·유효 suffix 삭제를 거부하고 새 빈 anchor에 명시적으로 재구성한다.
  `39c66a2` 원격 실증은 전체 47개 검사와 실제 SIGKILL·32회 새 process 검증을 통과했다.
  독립 스트레스가 승인 만료 시간을 소모하지 않도록 실제 재개 뒤에 수행하며 만료 거부를 유지한다.
  하위 process 각각의 30초 제한과 전체 1,200초 한도는 유지한다. 독립 cleanup 관찰도 통과했다.
  anchor와 witness가 함께 rollback된 경우, 별도 물리 host·power loss·운영 failover는 미검증이다.
- [UX-012](docs/orchestration/UX-012-registered-campaign-and-snapshot-history.md)의 여러 Campaign·과거
  Snapshot 조회는 배포자가 등록한 local DB에 한정되고 과거 결과는 실행·현재 승인 권위를 갖지 않는다.
  [UX-014](docs/orchestration/UX-014-review-work-filters-and-preserved-continuation.md)의 새 알림 receipt는
  200회 이력을 소모하지 않는다. 후속 검토는 원본 이력을 보존하지만 평가·판단·담당자를 자동 승계하지
  않는다. 기존 v1 알림 확인 API는 여전히 journal 공간이 필요하다. Auditor 수신자는 읽기만 가능하다.
  한 요청은 최대 열 개 review를 검증하므로 필터 결과가 없어도 다음 페이지가 남을 수 있다.
  외부 전달·백그라운드 알림·일반 queue SLA는 없다. schema 17과 v3 쓰기 전에 모든 reader/복구 도구를
  갱신해야 하며 데이터를 삭제하는 downgrade는 지원하지 않는다. 실제 browser 사용 경로와
  TLS PostgreSQL의 69개 검사는 통과했다. Console fake DOM 누락은 테스트 fixture에서 해결했고,
  당시 최종 통합 상태의 전체 suite는 8,970 passed·76 environment-gated skipped·실패 0이었다.
  운영 migration·배포는 하지 않았다.
- [SYS-004](docs/orchestration/SYS-004-authenticated-kernel-aslr-read.md)는 실제 guest kernel mode와
  독립 GNU 관찰·봉인 결과가 같고 네 Worker의 cleanup을 확인했다. malformed 값은 runc의 `/proc`
  교체 금지를 우회하지 않고 별도 test launcher의 fixed-open redirection으로 거부 검증했다.
  이 negative fixture를 실제 malformed kernel 관찰로 취급하지 않는다. 개별 process 보호·physical
  host·일반 System·Finding은 입증하지 않으며 새 API/Console도 제공하지 않는다.

## 의존성 보안 수정의 검증 경계

- 2026-09-10 `72bdbd9` push 뒤 GitHub 의존 그래프 재평가에서 기존 Dependabot 6건(high 3·medium 3)이
  모두 fixed로 바뀌었고 열린 경고는 0건이다. 시작 기준의 두 패키지 2.7.0은 영향 버전이었다.
  최종 `215d4fc` push 뒤에도 동일한 fixed 상태와 열린 경고 0건을 다시 확인했다.
  로컬 runtime 하한과 두 lock은 모두 수정했으며
  현재 httpx2/httpcore2는 2.12.0이다. 실제 의존 경로·도달 조건·공식 경고·호환성은
  [SEC-001](docs/orchestration/SEC-001-http-client-dependency-security.md)에 기록한다.
- 압축 해제·헤더·SSE·SOCKS TLS 회귀는 이전 패키지에서 17 failed/2 passed, 수정 후 19 passed다.
  SOCKS는 실제 로컬 TLS·불신 인증서 거부를 검증했다. optional Brotli/Zstandard와 Emscripten은 미검증이다.
- 승인된 여섯 커밋을 원격 main에 반영하고 그 동일 커밋의 일반 CI·Web/Network/AI Docker conformance를
  모두 확인했다. 로컬 취약 동작 재현/수정, 원격 경고 fixed 상태와 Docker 검증은 각각의 근거를 보존한다.

## 실제 탐지 효과와 측정 범위

- [EFFECT-001](docs/benchmark/EFFECT-001-local-llm-effectiveness.md)은 두 실제 모델의 고정 진단 평가군
  384개 응답을 검증했다. marker 탐지는 오탐 100·미탐 90건, 정밀도 21.9%·재현율 23.7%였다.
  private-canary 공개 여부를 판정하는 독립 정답의 제한된 표현만 다룬다. 일반 모델 안전성,
  semantic disclosure 전체, production 취약점이나 독립 서명 측정 권위를 증명하지 않는다.
  기존 응답은 EFFECT-002의 개발 자료로만 사용한다.
- [EFFECT-002](docs/benchmark/EFFECT-002-disclosure-detector-comparison.md)의 새 미사용 16개 사례와
  24개 모델 설정의 실제 384개 응답을 검증했다. 동일 평가군에서 정밀도 51.72%→80.38%,
  재현율 46.51%→98.45%지만 FP 31/FN 2가 남았다. 일부 조건의 FP는 늘었고, 두 미탐은 묶음별
  공백 분리였다. 16개 반복 진단 과제의 결과이지 일반 성능 추정이 아니다. 정상적인 ID·hash 생성 오탐과
  낮은 entropy·부분·semantic disclosure를 놓칠 수 있다. 의심 신호는 Finding 권위가 아니다.
- [EFFECT-003](docs/benchmark/EFFECT-003-context-disclosure-comparison.md)의 새 16개 과제는
  384번 시도 중 382개 응답만 받았다. 후보 정밀도 72.58%는 baseline 74.14%보다 낮으며
  완전성·정밀도 비감소 기준을 실패했다. 후보는 실험 버전이고 기본 탐지기는 바꾸지 않았다.
  실패한 두 호출의 세부 원인은 미확인이고 재시도/제외로 완전한 비교를 만들지 않는다.
  전용 평가가 아닌 공유 호스트에서 관측한 시간은 일반 처리량이나 모델 간 성능 지표가 아니다.
- WEB-002/UX-009는 고정 Web lab, NET-002는 합성 6-case, AI-002는 합성 M03 한 건이다.
  실제 Docker conformance는 해당 실행·Replay·Controls·cleanup 경계를 검증한다. 일반 Web/Network/AI
  탐지 성능·운영 영향이나 추가 실행 권위를 의미하지 않는다.
- P0-E1은 결정론적 SQLi Target, P0-E2B는 한 ZAP 버전/설정, P0-E3B2는 한 local llama.cpp/Qwen
  build·seed/repetition 좌표의 baseline이다. 이 결과로 일반 Scanner·single-agent 순위를 정하지 않는다.
  로컬 token USD 0은 전력·감가상각·저장소 비용을 포함하지 않는다.
- DOMAIN-001~006, 도메인 Surface·preparation·서명 증거 admission·fixture 등록은 실제 provider/parser
  실행이나 도메인 지원 완료가 아니다. 도메인별 현재 범위와 후속 runtime은 `PLAN.md`에서 구분한다.
- [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md)는 별도 승인·Permit을 거친
  최대 256 KiB의 offline ELF64 little-endian x86-64/AArch64 헤더 읽기·실제 Docker 재실행·보고만 지원한다.
  두 compiled fixture에서 LLVM이 확인한 것은 class/machine/entry/section count이며 모든 header field의
  독립 검증이나 취약점·일반 parser 안전성을 뜻하지 않는다. 실제 8개 Worker의 부재를 관측했지만
  custodied artifact와 봉인 증거는 의도적으로 보존한다. 기본 API/Console·동적 실행·일반 Application,
  Cloud/System provider 실행과 분산 Campaign 예산/전체 host 복구는 이 기능에 포함되지 않는다.
- [SYS-002](docs/orchestration/SYS-002-authenticated-os-release-read.md)는 새 격리 Linux container의
  고정 OS-release 한 파일을 mTLS로 읽는다. 독립 표준 parser·새 승인 재실행·제품 CLI·거부/실패·
  외부 cleanup을 실제 검증했지만 물리 host, 임의 경로/명령, 일반 System 또는 SYS-001 전체 지원은 아니다.
  agent의 중복 nonce 거부는 process-local이며 재시작을 넘는 ledger는 아니다. 기본 CP/Console의 자동
  활성화 경로가 아니고 별도 배포 pin·인증·현재 Capability·승인·Permit을 요구한다.

## 사람 검토·보고와 제품 조회

- [UX-011](docs/orchestration/UX-011-human-review-and-remediation-report.md)은 검증된 공개 요약을
  보여 준다. 원문 요청·응답·private Ground Truth 열람이 아니며 사람의 영향·심각도·수정 판단을
  source Finding·SARIF·실행 권위로 승격하지 않는다. 재검증 연결만으로 실행이 수정 이후였다고
  증명하거나 운영 대상의 수정 완료를 자동 판정하지 않는다.
- UX-006A SARIF는 별도로 independently confirmed Finding을 요구한다. UX-006B 전달은 endpoint
  acceptance까지이며 일반 vendor adapter·distributed exactly-once·backup/failover를 제공하지 않는다.
  unknown 전송은 자동 재전송하지 않고 authenticated `not-received`와 기존 재승인을 요구한다.
- UX-010 reader는 배포자가 고정한 host-local 증거와 이미지에 의존한다. inventory hash 자체는
  독립 서명·hot revocation·전체 host rollback 방지가 아니다.
- UX-002A는 sealed Discovery Surface/Wave, UX-002B는 설정된 단일 Campaign의 current Graph만
  조회한다. 여러 Campaign·과거 Snapshot 조회는 별도 UX-012 경로가 담당하며 raw content export는 없다.
  Graph `/pages`는 최대 100,000 node·200,000 edge를 Snapshot cursor로 분할한다.
  [GRAPH-PERF-002](docs/benchmark/GRAPH-PERF-002-first-and-history-page-cost.md)는 모든 이력 Projection을
  정확히 비교하면서 중복 prefix replay를 제거했다. DB ≤256 MiB / Snapshot ≤16 MiB 한 entry만
  재사용하며 매 요청 전체 bytes를 두 번 hash하고 schema/integrity/current head를 확인한다.
  5,002 node / 10,000 edge 최초 13.48→8.13초, 변경 직후 15.65→9.20초이며 큰 이력 반복은
  20.80→0.304초다. 작은 DB 반복은 소폭 느려졌고 history RSS는 평균 1,313→1,618 MiB로 늘었다.
  이력 전체 검증·defensive copy·hash 비용은 남는다. 크기 초과/플랫폼 fallback은 전체 검증이며
  이후 [GRAPH-PERF-003](docs/benchmark/GRAPH-PERF-003-memory-and-concurrent-reads.md)은 같은 process의
  reader 두 개까지 측정하고 RSS 감소·지연 악화를 기록했다. 후속 GRAPH-PERF-004는 별도 process
  두 개와 guest page cold/warm을 검증했고 GRAPH-PERF-005의 현재 결과는 위에 기록한다.
  더 긴 이력·물리 cold disk·최대 크기·운영 메모리/SLO는 미측정이다.
- UX-003A ranking은 최대 500개로 제한되고 confidence는 위험도·검증 진실이 아니다.
  UX-003B Decision audit도 최대 500개이며 off-host anchor·historical browsing·compaction이 없다.
- UX-004A KISA와 UX-004B WALK 비교는 각각의 증거 경계를 유지한다. semantic diff나 새 validation·
  remediation authority를 만들지 않는다. UX-005A queue에는 assignment·SLA·일반 알림이 없다.
  OPS-001 긴급 알림은 별도 제한된 경로다. UX-001B3 builder는 compiler handoff이며 실행 승인이 아니다.

## 단일 호스트 복구·예산·긴급 중단

- [OPS-001](docs/orchestration/OPS-001-single-host-recovery-and-urgent-stop.md)은 명시적으로 등록한
  POSIX local SQLite CP/Graph/journal/RunStore의 첫 사용, 같은 위치 재시작과 독립 pin을 사용하는
  수동 복원을 지원한다. 자동 경로 이전·실행 재활성화, Windows/network filesystem lock,
  cross-host consensus/fencing과 분산 exactly-once를 제공하지 않는다.
- [OPS-002](docs/orchestration/OPS-002-isolated-postgres-operations.md)는 실제 PG 17.11·Docker Worker
  71개 검사, crash/보수적 charge/검증키 보존과 독립 pin 기반 별도 DB 복원을 통과했다.
  기존 검증의 Python host는 macOS arm64이고 DB는 Linux arm64다. 사용자가 Linux 단일 호스트·
  PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal 구성을 선택해 선택 대기는 해소됐다.
  새 Linux aarch64 / Python 3.12.13 + PG 17.11 실행에서 84개 검사와 실제 CP/Worker mTLS·중단,
  강제 종료·재시작·PG/SQLite/RunStore 전체 cold checkpoint/별도 DB·볼륨 복원이 통과했다.
  실제 차감 1회가 보존됐고 downtime으로 30초 예산이 소진된 실행 및 미승인 재개는 거부됐다.
  원래 배포를 정지한 수동 복원 검증이며, 등록형 OPS-001 hybrid 지원·live atomic backup·물리 host
  장애·외부 rollback·자동 실행 재개·운영 배포를 증명하지 않는다. 소유 자원 부재는 별도 관측했고
  새 변경의 `215d4fc` commit·push·동일 커밋 CI/Web/Network/AI 검증까지 완료했다.
  OPS-002의 구성 선택·실행 승인 대기는 해소됐다. 이후 운영 변경은 별도 승인 범위다.
- [OPS-003](docs/orchestration/OPS-003-managed-hybrid-recovery.md)의 운영자 명령은 선정 hybrid의
  안전한 정지·암호화 cold checkpoint·독립 pin 검증·새 빈 대상 복원·현재 권한과 별도 승인 재개를
  실제 격리 환경에서 검증했다. 기존 OPS-001 등록형 API는 여전히 POSIX local SQLite 전용이다.
  source writer/DB를 정지한 복원이며 live backup·물리 장애·분산 failover·미확인 외부 rollback·
  운영 배포를 증명하지 않는다. manifest-bound journal과 host-local sealed RunStore만 지원하고
  외부 artifact/provider store는 거부한다. serialization 크기 제한은 peak RSS 보장이 아니다.
- code/config inventory 검증은 참여하는 CP·Worker·embedded producer의 배포 구성을 결박한다.
  서명되지 않은 다른 process-local verifier·writer·policy/Grant provenance를 자동으로 보정하지 않는다.
  참여하지 않는 writer, 잘못 신뢰한 외부 권위, 원격 자원의 side effect는 이 검증 밖이다.
- CP 키 ID 연속성과 필요한 이전 검증키를 유지해야 한다. 등록된 예산 이력 없는 legacy Campaign은
  잔액 0으로 재시작하지 않는다. 첫 durable 결박 이전 crash와 누락된 이력은 추정하지 않는다.
- Supervisor journal v2와 기본 Worker의 Run별 journal은 사용량을 실행 전에 저장한다.
  uncertain 호출은 보수적 charge를 유지하고 started 상태는 자동 redispatch하지 않는다.
  terminal receipt가 없는 경우 수동 확인이 필요하며 Graph 검증과 journal 전이는 별도 transaction이다.
  SUP-004B1 controller만 독립적으로 생성한 embedded 호출은 durable deployment 결박을 별도로 해야 한다.
- host gate는 등록된 활동을 배제한다. closed checkpoint는 모든 등록 store와 sealed Run을 포함해야
  하며 미등록 파일·변경된 source·누락된 store를 거부한다. mutable provider store는 별도 복구 계약이
  필요하다. expected checkpoint까지 함께 되돌린 전체 host rollback은 탐지할 수 없다.
- HANDOFF urgent decision 자체는 `admitted-not-applied`다. OPS-001 trusted producer가 exact
  Graph/source/CP/actor를 확인한 뒤 CP 취소·알림을 원자 저장한다. 기본 Worker는 stop observation을
  보고하지만 이 보고가 원격 자원 정리·side effect rollback·Replay child의 cleanup을 증명하지 않는다.
  미보고·실패는 unknown으로 남고 사람의 알림 확인은 실행을 재개하지 않는다. 외부 메시지 발송은 없다.
- HANDOFF-001~004의 Supervisor/result identity·admitted record, receiver 인증·single-use receipt는
  process-local trusted composition에 한정된다. MEM-003의 Graph와 여러 RunStore에는 분산 transaction이
  없고 마지막 head 확인 뒤 변경될 수 있으므로 다음 소비 때 다시 current 검증한다.

## Supervisor 전달·정책·유지보수

- [SUP-004A](docs/orchestration/SUP-004A-checkpoint-invocation-plan.md)의 큰 입력은 matching host,
  Worker v2와 proxy image가 필요하다. 4 MiB 분할·재구성은 외부 모델의 context 수용이나 입력 전체의
  올바른 사용을 보장하지 않는다. 기존 작은 입력은 동일한 v1alpha1 wire를 사용한다.
- SUP-008 `general-attack-v1`과 승인된 T2 profile은 no-write 범위다. T3+, production write,
  network·priced action은 별도 trusted pricing·egress·cleanup authority 없이 열리지 않는다.
  PERMIT-003의 Envelope/Decision provenance와 비용 provider는 deployment TCB다.
- SUP-005B2 Shadow proposal은 Target 동작에 적용되지 않으므로 수치 차이가 proposal의 개선 효과는 아니다.
  conservative charged cost와 externally adjudicated coordinate cost를 합치거나 동일시하지 않는다.
- SUP-006은 deterministic fake Provider의 authority-containment 회귀다. 실제 모델의 모든 prompt
  injection 거부를 증명하지 않는다. 새 Provider/schema에는 별도 corpus·실제 Provider 검증이 필요하다.
- SUP-005A/B1/B2/SUP-006 fixture는 기존 대형 테스트의 private helper에 결합되어 있다.
  일부 전체 실행은 단일 seed/repetition이며 별도 다중 좌표 실행 회귀가 남아 있다.
- code-owned metadata 캐시는 반환 객체를 격리하고 외부 검증·권한 결정을 캐시하지 않는다.
  로컬 프로파일 개선을 CI 실행 시간 개선으로 단정하지 않는다. duration profile은 배치 힌트이며
  실제 CI artifact로 갱신해야 한다. 대형 모듈 전체 분리와 남은 Graph Snapshot 검증/RSS 비용은 후속이다.

## 승인·cleanup·외부 저장소

- APPROVAL-001C3의 Graph 승인/Permit 소비와 batch journal 사이에는 하나의 transaction이 없다.
  pending/unknown은 retention 삭제나 자동 재실행 대상이 아니다. OPS-001에 등록되지 않은 batch/provider
  store에는 해당 계약의 별도 복구 절차가 필요하다.
- PERMIT-004B2의 reversible-write cleanup은 synthetic fixture로 검증했으며 production Capability는
  닫혀 있다. 실제 restored-state verifier 없이 성공을 추정하지 않고 expired/abandoned hold를 자동
  release하지 않는다. failed/unknown cleanup도 자동 재시도하지 않는다.
- P0-C2B2B와 P0-D3B2의 provider fence는 host-local SQLite다. 여러 host가 같은 외부 Target을 다룰 때
  원격 compare-and-set/lease와 독립 evidence가 필요하다.
- P0-C2A는 Recovery Run seal 직후 terminal journal 전이 전에 crash하면 같은 attempt의 감사 Run을
  추가 봉인할 수 있다. 이미 성공한 cleanup은 재호출하지 않는다. publication marker 결박이 후속이다.
- P0-C2B2A1 activation DB 전체와 remembered head를 교체하면 local store만으로 rollback을 식별할 수
  없다. 독립 retained checkpoint·Trust Anchor rotation·remote fetch authority가 별도로 필요하다.
- UX-007B-R의 mTLS와 exact ABAC unset은 기존 RBAC 호환이지 운영 권한 축소의 증명이 아니다.
  UX-007P2는 고정 single-node MinIO conformance다. UX-007Q의 activation/retention/revalidation store는
  단일 transaction이 아니며 외부 checkpoint를 보관해야 한다. UX-007R1은 AWS S3 custody 선정 계약이다.
  production pilot·외부 inventory/isolation/restore·자동 cleanup·cross-host fence는 별도 승인과 검증이 필요하다.

## 제한된 선행 계약의 해석

| 계약 | 유지되는 한계 |
| --- | --- |
| PENTEST-001C2~003D | caller의 signed predecessor·local Graph/Run 권위에 의존하고 validity만 confirmed. generic impact/severity·report·cross-host 권위는 없음 |
| PENTEST-004A~C2B2 | server-owned registry·concrete child adapter·restart 검증은 존재하나 registry 자동화·distributed queue/fence는 없음 |
| REDTEAM-001/002·UX-008 | 제한된 LLM/RAG·고정 Web/MCP 실행과 sealed aggregate. fixture를 production score로 취급하거나 no-Finding projection을 승격하지 않음 |
| CHAIN-001 | Target-declared AI admin Surface만 다루며 실제 auth bypass·admin access는 관찰하지 않음 |
| CHAIN-002 | WALK Hypothesis chain이며 upload/retrieval/Tool abuse를 이 projection 자체로 실행·확정하지 않음 |
| CHAIN-003 | 광고된 URI Tool·Internal API Surface이며 URL 호출·network reachability·SSRF 증거가 아님 |
| CHAIN-004 | Target-declared tenant/data Surface이며 selector control·cross-tenant access·data exposure 증거가 아님 |
| CHAIN-005 | approval-required Capability의 의미 결박이며 OS privilege·승인 우회·실제 영향 증거가 아님 |
| VAL-001~004 | KISA M03/M06/A04와 exact stateless WALK CHAIN-002/005 evidence의 validity depth/floor. 별도 fresh Replay를 Controls로 대체하거나 impact/severity를 추론하지 않음 |
| PROF-001/002·ENG-001/002A | 분류·compiler·structural parity 자체에는 실행 권위가 없음. 별도 ENG-002C2는 명시적 local CTF gate이며 default/분산·일반 AI/Bug Hunt dispatch 증거가 아님 |
| MEM-001~003 | seal·metadata reference만으로 producer 의미·receiver content 권위를 증명하지 않음. 별도 lineage verifier·HANDOFF reader 필요 |
| P0-D1 | catalog equality·image identity는 배포자가 신뢰하는 입력이며 catalog publisher·원격 anti-rollback 자체 증명이 아님 |
| P0-D2/D2B | fixture는 비실행, 별도 runnable provider도 deterministic no-model single-container lab. MCP의 별도 service 격리는 없음 |
| P0-D3/D3B2 | structural bridge 선언과 실제 local Hybrid provider를 구분. 독립 component 두 결과를 combined measurement로 합산하지 않음 |
| P0-D4/D5 | 코드에 등록된 holdout/mutation 계약은 production blind evaluator·실제 materialization/reset 증거가 아님 |

## 플랫폼·도구 제약

- Windows에서 directory `fsync`·secure `dirfd`, 비이식 파일명 materialization, symlink 생성 권한과
  POSIX `0700/0600` 검증의 제약이 확인됐다. Linux 검증과 구분하며 보안 assertion을 약화하지 않는다.
  일부 관리형 Windows에서는 project interpreter/console script 실행도 제한되어 승인된 환경의 검증이 필요하다.
- 로컬 샌드박스는 임시 TCP listener를 차단할 수 있다. 이 경우 실제 TLS/mTLS 테스트는 허용된
  로컬 실행 환경에서 재검증하며 인증·인증서 검사를 끄지 않는다.
- Git이 `unable to get local issuer certificate`를 반환하면 TLS 검증을 유지한다. `schannel`을
  지원하는 Windows Git에서는 저장소의 해당 backend 절차를 쓰고 다른 플랫폼에는 그대로 적용하지 않는다.
