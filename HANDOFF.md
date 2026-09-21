# PAJIN 현재 인수인계

체크포인트: 2026-09-21. 승인된 네 후속 항목과 별도로, 사용자가 승인한 local OWASP Juice Shop의
WEB-003 고정 browser 평가, WEB-004 Campaign/Capability 준비·인증형 passive discovery, WEB-005의
서명된 governed 실행·독립 검증·Graph admission·Finding·공격 경로·보고서·SARIF·redacted PoC까지
구현하고 실제 실행했다. EFFECT-007·GRAPH-PERF-006·UX-014, WEB-003~007·SKILL-001~002,
AGENTIC-001~004의 구현·테스트·계약은 main의 논리 커밋으로 보존했다. WEB-006 closed
profile·진단 catalog·동일 인증 context passive discovery 증거와
discovery-only 실제 Run은 구현·strict reload했고, full governed Run·PoC 재실행은 아직 완료하지
않았다. WEB-007 LLM shadow analysis의 코드와 terminal failure 경로는 구현·실증했지만 actual model
call이 transport timeout으로 draft 없이 끝나 성공 proposal은 미검증이다. 탐지기 CPU 기준 미달과
Graph 최초 조회 지연 증가도 아래에 구분한다. SKILL-001은 exact-version 분석 Skill registry와
target-neutral Web Skill 5개를 catalogued-only 상태로 추가했다. SKILL-002는 exact proposal-only
successor 4개를 선택해 Skill 지침과 tainted Evidence를 분리한 zero-dispatch WEB-007 준비 Run까지
연결했다. 그 준비 Run을 소비하는 독립 transport/runtime Pin과 split-message one-shot Provider
successor도 구현·테스트했다. 새 immutable Worker/proxy image build, 독립 Pin 생성, 운영 preflight까지
진행한 뒤 승인된 첫 successor attempt를 실행했다. exact 요청의 보수적 회계 상한 `88,496`이 Campaign
한도 `65,536`을 초과해 `model.call.started`와 Gateway 전에 차단됐고 실제 model dispatch는 0회였다.
누락된 exact successor budget 검사와 4,096-token RuntimePin의 보수적 context admission은 model
시작 전 preflight에 추가했다. pinned tokenizer/template로 legacy full `[developer,user]` request를
측정한 결과 `4,208 + 1,024 = 5,232 > 4,096`이므로 이 wire는 비실행 가능 상태로 동결한다. embedded
Qwen template는 `developer` role을 native render하지 않는다. historical Capacity v1 뒤 output-root와
model provenance를 보강한 Capacity v2 `run_20260921T052042Z_0932a478`이 exact model materialization과
total 2,484/4,096, Campaign 51,168/65,536을 strict reload했다. proof-bound preparation
`run_20260921T052213Z_801a9053`도 zero-dispatch로 strict reload됐다. completion·Provider·target 호출과
owned container·volume 잔존은 0이다. 이어 exact compact request와 prerequisite anchors를 non-executing
admission에 결박했다. 다음은 외부 one-call authorization·durable CAS·live model attestation·additive
compact runtime/receipt이며 completion은 아직 승인·실행되지 않았다.

## 2026-09-20 AGENTIC-002·003A/B/C1/C2/C3A/C3B1/C3B2·C3C 기반·004 체크포인트

- AGENTIC-002는 current canonical Graph head의 opaque resolution, deployment-bound pristine
  genesis, durable invocation stable slot과 no-redispatch journal, checkpoint CAS, transactional
  outbox/inbox, event·receipt 전체 이력 재검증, restore와 bounded target-neutral context compaction을
  구현했다. 권위 있는 coordination store는 Linux `/proc/self/fd` descriptor backend만 지원하며
  parent·leaf·pinned DB와 SQLite가 실제 연 main FD의 inode를 SQL 전후로 확인한다.
- reopen은 외부에서 보존한 exact store ID를 요구하고 DELETE journal만 허용한다. WAL/SHM·idle
  sidecar·A/B namespace 교체·forked/closed handle은 거부하며 true hot journal은 첫 reopen에서만
  복구한다. 같은 DB 전체 rollback에는 별도 head witness가 필요하고 Graph·coordination store는
  단일 transaction이 아니다. hostile in-process FD/memory mutation은 process compromise로 TCB 밖이며
  그런 extension에는 별도 broker 또는 descriptor-aware SQLite VFS가 필요하다.
- AGENTIC-003A는 exact XSS(`dom-xss`), SQLi(`sql-login`), authorization
  (`sql-login -> object-access`) profile을 등록했다. 모두 `registered-inert`,
  `executionBinding=unbound`, `runtimeSupportAsserted=false`이고 Scope·Capability·Permit·Gateway·
  Worker·Finding·Graph 권위가 없다.
- AGENTIC-003B는 세 profile에 서로 다른 code-owned executor ID/digest와 exact phase closure를
  결박했다. SQL-only는 browser를 사용하지 않고 authorization은 SQL session dependency가
  locally reproduced되지 않으면 object-access 전에 typed failure로 끝난다. specialist browser는
  account를 만들지 않고 supplied preprovisioned credentials만 사용하며 observation에
  `accountCreationPerformed=false`, `provisionedAccountUsed=true`를 고정한다. aggregate `run`과
  registration·SQL impact·object-access bootstrap 경로를 차단했고 unknown·누락·역순·반복 phase를
  거부한다. SQL-login phase는 exact login+impact endpoint·GET/POST·3 requests, object-access phase는
  exact object template·GET·3 requests만 허용하며 compiler identity를 executor provenance에 pin한다.
  testing-only injected harness로 closure를 검증했지만 production binding/execution은 003C3C-live
  Gateway/Worker 경계가 완성될 때까지 I/O 전에 fail closed한다. catalog은 일반 mutation·복사·직렬화를 거부하고 host network와 Worker
  proxy는 case/percent-encoded sensitive path alias를 같은 deny 의미로 처리한다.
- AGENTIC-003C1은 sender ACK와 receiver inbox, current Graph·durable head, immutable cycle, selected
  Candidate, current Exploit Group specialist와 live Agent Session이 모두 일치하는 assignment만
  store-local opaque handle로 발급한다. verified handle은 한 번만 durable reservation으로 소비되며
  `reserved -> dispatch-started-outcome-unknown`만 CAS로 허용한다. 재시작은 audit entry만 읽고
  authority를 재발급하지 않으며 자동 redispatch·execution·Finding·Graph 권위는 모두 false다.
  Capability·approval·Permit·Gateway·Worker와 실제 browser/network/target I/O는 아직 없다.
- AGENTIC-003C2는 original live reservation을 소비하지 않고 current Graph·durable history/head·
  reserved row·live admitted assignment를 다시 검사한다. code-owned exact Juice Shop route,
  Campaign·single Target·Scope·budget, production specialist profile/executor를 deterministic inert
  preparation으로 결박한다. nested requirement는 future one-call non-delegable T2 Capability와 fresh
  approval의 조건만 표현하며 Grant·ToolRequest·PreparedCapabilityAction·Permit이 아니다. 모든
  authority/execution marker는 false이고 model/browser/network/target/Gateway/Worker I/O는 없다.
- AGENTIC-003C3A는 XSS·SQLi·authorization에 서로 다른 T2 read-only Capability·Tool·
  complete seven-role authority set을 등록했다. signed Range lifecycle activation은 exact preparation,
  signed preprovisioned account receipt, installed adapter와 current profile/executor를 다시 검사해
  deterministic `PreparedCapabilityAction`까지만 만든다. materializer/compiler 외 Tool·executor·
  normalizer·oracle·replay·cleanup은 003C3C-live specialist Gateway가 exact roles를 소유할 때까지 fail closed하며 Grant·
  approval·Permit·Gateway·Worker·target I/O는 없다.
- AGENTIC-003C3B1은 current Graph·durable head·C2 preparation·C3A action·Campaign·live one-call
  non-delegable child Grant·approval tuple·expected Permit identity를 다시 검사한다. original
  reservation handle을 소비해 durable `awaiting-permit` plan을 만들고 one-use
  store-local plan handle로 process-local 권위를 이전하지만 execution row는 `reserved`로 유지한다.
  reopen·recovery는 audit row만 읽고 plan handle을 재발급하지 않는다. approval envelope는 서명
  검증·소비된 승인이 아니고 Grant call도 소비하지 않았으며 Permit·Gateway·Worker·
  browser/network/target I/O는 없다.
- AGENTIC-003C3B2는 exact Graph Store·Permit Store·live Ledger·approval keyring·Capability/policy
  registry·compiler·공유 Permit writer를 하나의 deployment trust root로 pin한다. fresh signed
  approval의 one-winning callback에서 Permit과 child/ancestor Grant call을 검증·소비하고,
  plan/execution을 `dispatch-started-outcome-unknown`으로 함께 CAS하면서 당시 schema v5의 exact
  Grant-consumption receipt를 기록한다. Graph transaction과 coordination transaction은 원자적이지
  않으며 post-consumption 실패는 budget을 환불하지 않고 자동 retry·redispatch를 금지한다. reopen은
  audit row만 제공하고 plan/Permit/Grant/started authority를 재발급하지 않는다.
- AGENTIC-003C3C 기반은 C3B2 started 결과를 직렬화 가능한 bearer로 취급하지 않는다. audit-only
  binding과 별도의 Store-issued opaque capsule을 exact Store·DB object·owner `asyncio.Task` live-set에
  결박해 한 번만 `AVAILABLE -> CONSUMED -> RETIRED`로 전이한다. transfer와 consume 시 current
  Permit/Grant lineage를 exact lock 아래 다시 검사하고 reconstructed-equal handle, foreign Store/DB/
  Task, hidden state, replay, close/race를 fail closed한다. 이 foundation contract는 production
  Gateway/Worker success가 아니며 Store close 뒤 권위 없는 RETIRED tombstone만 남긴다.
- 최신 additive slice는 SQLi v2 planning identity와 complete seven-role code-backed Capability bundle,
  externally signed current Range release activation, exact `ActionCapabilityRegistry`, deterministic
  `PreparedCapabilityAction`을 추가했다. materializer/compiler만 이 sealed action을 준비할 수 있고,
  executor·normalizer·oracle·replay·cleanup과 direct Tool dispatch는 specialist execution Gateway 전까지
  fail closed한다. distinct v2 Plan wire/runtime generation, one-call Grant, signed approval, Permit
  callback과 same-scheduler-Task started handle·private capsule을 구현했고 v1 artifact를 v2로
  승격하지 않는다. Store-owned private one-shot claim은 transfer된 capsule을 성공 또는 terminal
  failure 뒤 폐기하면서 current Graph·durable history·deployment·preparation/action·approval·terminal
  Permit·Grant lineage를 다시 검증한다. 이 predecessor claim 자체는 JobAttempt나 public C3C/Gateway
  권위를 만들지 않는다.
  여기서 권위 폐기를 증명하는 Store close는 trusted composition 때 보관한 exact unbound close를
  owner가 직접 호출한 경우만 뜻한다. 일반 `store.close()`, context-manager exit와 finalizer는
  pre-call Python runtime mutation 아래 독립적인 zeroization 증거가 아니다.
  coordination Store는 schema v6이며 JobAttempt와 terminal receipt, embedded canonical typed
  Claim/DispatchVerification DAG, indexed verification ID/digest, Capability authority-set, scheduler Task,
  runtime capsule, authorization lineage와 runtime inventory pin을 저장한다. v5 Store는 정상 open에서
  거부되며 exact offline v5→v6 migration만 허용된다. recovery는 미수신 claimed/started attempt와
  immutable receipt를 감사용으로만 분류하고 handle·Task·capsule·Gateway·backend 권위를 재발급하지 않는다.
- structured v2 fake backend는 `specialist_backend_v2.py`의 exact source bytes를 identity에 포함하고
  compiler, image, job template, backend, verifier와 deployment Ed25519 verification key를 함께 pin한다.
  one-call launch 뒤 signed `conformance-completed-no-target-io` 결과를 만들며 backend invocation 외
  model·browser·network·Target I/O는 없고 모든 execution·independent validation·Finding·Graph·report·
  SARIF·PoC authority는 false다. 이는 Gateway/Worker 성공 또는 `completed-verified`가 아니며 durable
  conformance-success terminal kind도 없다. 해당 source bytes는 이 version에서 frozen이며 변경은 새
  version/contract로만 한다.
- live pre-backend admission은 exact scheduler Task와 predecessor private capsule에서 current Graph,
  durable history, authorization lineage와 deployment inventory를 다시 확인하고 durable
  `claimed-before-backend` JobAttempt 및 non-copyable·non-serializable opaque claim을 발급한다. public
  claim은 audit-only JobAttempt만 노출하고 raw runtime context·deployment lease는 Store live-set에만
  유지한다.
- public Gateway deployment와 claim에는 raw backend·verifier·verification key·job template·execution
  inventory 참조가 없다. raw 객체는 private control-plane owner vault에만 있고 exact factory anchor와
  `is` identity로 재검증된다. 이는 arbitrary same-interpreter reflection을 막는 sandbox가 아니라 trusted
  control-plane interpreter TCB이므로 model·Skill·plugin·target·payload 코드는 이 interpreter에서 실행하지
  않는다.
- owner Task 종료, trusted Store close, explicit discard와 post-insert mint failure는 Store-authored
  `abandoned-before-backend` terminal receipt를 남기고 claim·Gateway lease·private owner를 폐기한다.
  receipt writer 자체 실패나 attempt commit 직후 hard process failure는 receipt 없는 claimed audit row를
  남길 수 있지만 recovery는 receipt를 합성하거나 authority를 재발급·자동 redispatch하지 않는다.
- same-scheduler-Task 실행 경계는 live claim을 한 번만 소비하고 current Graph·Campaign·preparation/action·
  approval·Permit·Grant lineage와 Gateway/backend/image/job/verifier/key inventory를 다시 확인한 뒤
  `dispatch-started-outcome-unknown` CAS를 backend await 전에 commit한다. private structured Worker와
  verifier는 Store-owned opaque deployment lease로만 도달할 수 있다. 검증된 raw result는 caller나
  receipt builder 입력으로 노출되지 않고 Gateway-only one-shot completion provenance로 전달된다.
- signed zero-Target-I/O result는 `failed-before-target-io`로만 terminalize한다. post-marker backend
  failure·cancellation은 `started-outcome-unknown`; verified completion 뒤 receipt commit 실패는 receipt
  없는 unknown attempt로 보존된다. 두 경우 모두 claim·deployment·private owner를 폐기하고 자동
  redispatch하지 않는다. backend await 동안 lifecycle lease가 trusted Store close를 차단한다. 현재
  cancellation 회귀는 pinned zero-I/O backend 내부의 `CancelledError` 분류를 검증하며, 실제 suspending
  target-I/O backend에 대한 scheduler `Task.cancel()` race는 successor에서 다시 검증해야 한다.
- AGENTIC-004는 Juice Shop 개발 회귀, 별도 승인 transfer target, private holdout/evaluator를
  분리한 3-arm·3-role·17-metric 비실행 계약을 구현했다. 실제 plan 등록, model/target 호출과
  성능 측정은 수행하지 않았다.
- 최신 live execution 변경은 network-none/read-only Linux에서 JobAttempt claim/dispatch 전체
  `39 passed`, v2 Plan/Permit `42 passed`, activation·typed attempt·structured backend `62 passed`,
  dispatch binding `43 passed`가 통과했다. source/test Ruff, Python compile과 두 runtime source의 strict
  mypy도 통과했다. 전체 저장소 pytest는 반복하지 않았다.
- 이 AGENTIC 단계에서 실제 model·Juice Shop·외부 target·browser/network/Target I/O·보고 전달은
  실행하지 않았다. 구현은 아래 Git 체크포인트에 보존했다. 다음 단계는 identity-bearing
  `specialist_backend_v2.py`를 수정하지 않는
  additive target-I/O-capable Worker/Gateway successor를 같은 authority와 receipt 경계에 연결해 승인된
  실제 SQLi Juice Shop 실행을 수행하고, 003D의 별도
  account/session·Permit·executor·replay·control·oracle로만
  Evidence·Finding·Graph·보고·SARIF·PoC를 검증·승격한다. Graph admission 뒤 재계획에는 초기 pinned
  Graph head를 새 coordination epoch로 넘기는 rollover 계약도 필요하다.

## 2026-09-17 AGENTIC-001 체크포인트

- `src/pajin/agentic/`에 Codex형 논리 agent command/event 계약, Hypothesis Frontier,
  결정론적 Path Scorer, bounded Dynamic Supervisor와 Skill-backed Web Pentest/Exploit Group을
  추가했다. model이 제안한 점수·텍스트는 tainted advisory이고 code-derived feature만 scheduler
  입력이 된다.
- model projection은 폐쇄형 signal enum과 exact canonical Graph Snapshot의 한 Hypothesis root만
  받는다. runtime은 no-tools 단일 Provider 호출의 request/result/receipt/draft를 정확히 결박하고
  Scope·Capability·Permit·Tool·Gateway·Graph·Finding·보고 권위를 만들지 않는다.
- supervisor는 현재 process 안에서만 새 checkpoint를 만들며 restart resume를 명시적으로
  지원하지 않는다. command/event identity와 순서, terminal 단일 사용, 현재 assignment를 검증하고
  capability/input 요구에서는 권한을 자동 부여하지 않고 중단한다.
- agentic 생성·reload 경계는 중첩 Pydantic 객체를 alias wire로 재귀 재검증하고 비결정적·lazy
  container를 거부한다. Provider port는 Gateway와 감사 저장소의 exact 동일 `RunStore` 결박을
  생성 시 강제해 분리 저장소의 중복 request reservation을 차단한다.
- focused 검증은 `tests/test_agentic_campaign.py` 31개와 `tests/test_provider_session.py` 42개,
  Ruff, Linux 대상 mypy가 통과했다. Orchestration·Skill·Provider·Graph·WEB successor를 포함한
  확장 회귀 283개도 통과했다.
- 최종 read-only 적대 검토에서는 구현 범위 내 재현 가능한 P1/P2가 남지 않았다. 당시 남겨 둔
  raw Graph Snapshot current-head·restart 경계는 위 2026-09-18 AGENTIC-002 체크포인트에서
  Linux-only durable authority로 닫았다.
  실제 model·Juice Shop 호출은 수행하지 않았고 commit/push도 하지 않았다.
- 이 과거 체크포인트의 다음 단계였던 AGENTIC-003B는 위 2026-09-18 체크포인트에서 구현했다.

## 목표와 승인 범위

`PLAN.md`의 네 항목에 대한 코드·테스트·문서·격리 검증을 수행한다. 기존 완료분의
commit/push·일반 CI와 Web·Network·AI·OPS·SYS 실행은 승인됐고 완료했다.
현재 기능은 사용자 승인에 따라 논리 커밋으로 정리했으며 이 체크포인트에서 `origin/main`과
동기화한다. 운영 배포·merge·tag·외부 알림은 없다.
별도 물리 Linux host가 아직 없다는 기존 선택을 유지한다. main에서 직접 작업하며
branch/worktree는 만들지 않았다. WEB-003 최종 diff에는 read-only 독립 리뷰 agent를 사용했고,
그 agent는 파일을 수정하지 않았다.
WEB-003~005는 사용자가 명시적으로 승인한 `127.0.0.1:3000`의 Juice Shop만 실행했다. WEB-005는
그 exact 대상에 한해 Graph/Finding admission과 local SARIF/PoC까지 연결했지만, 임의 사이트,
외부 보고 전달, 운영 배포 권한으로 확대하지 않았다. 평가 과정이 만든 local test account와
실패/성공 Run은 삭제 승인이 없어 보존했다.
WEB-006도 같은 exact 승인 target만 범위에 두며 production inventory를 다른 target으로 늘리지
않는다. WEB-007은 그 봉인 discovery를 읽어 local model projection만 처리했고 target에는 새 요청을
보내지 않았다. 외부 전달 목적지와 권한은 제공되지 않았고
`externalDeliveryPerformed=false`를 유지한다.

## Git과 원격 인수인계

- 현재 branch는 `main`, HEAD와 `origin/main`은
  `ba748239d7c78fc7928435325813ee37dc32fd38`로 같다.
- 이 체크포인트는 **미커밋·미push**다. staged 변경은 없고, 현재 작업 범위의 tracked
  문서 6개가 수정됐으며 새 ADR·source·script·test 16개가 untracked다. 정확한 목록은
  `git status --short`를 권위로 삼는다.
- `output/`·`.pajin/`의 private/raw 근거는 로컬에만 보존되며 Git으로 전달되지 않는다.
  기존 `39c66a2` 원격 CI 결과는 이 새 변경의 검증 근거가 아니다.

## WEB-003 — 실제 browser 평가 완료, 일반 Web 권위는 없음

- 새 `src/pajin/web_assessment/` engine/recipe는 exact numeric loopback origin, 30분 이하의
  plan-bound 명시적 승인과 phase/request마다의 만료 재검사, GET/HEAD와 고정 login/registration
  POST, deny path, phase별 요청·응답 byte·전체 시간 한도를 강제한다. ambient proxy·redirect·
  service worker·WebSocket·download와 외부 origin을 허용하지 않는다.
- `pajin web-assess-local --origin http://127.0.0.1:3000 --authorized-local-lab`가 random 평가
  계정을 만든 뒤 정상 UI login, search/contact/about, SQL login·basket object access·DOM XSS의
  source/replay 및 대조군을 수행한다. SQLi session과 이번 Run의 평가 account basket만 연결해
  다른 local user의 basket을 진단 대상으로 고르지 않았다.
- 최종 실제 대상은 OWASP Juice Shop 19.2.1이다. authenticated/browser evidence 8개,
  browser request 56개, 전체 HTTP Evidence 70개, locally reproduced issue 3개, locally validated
  attack path 2개다. 예상 밖 console/capture 실패와 외부 전달은 0이며 deny-path 요청 두 건을
  차단했다. data-image DOM probe는 HTTP callback을 만들지 않았다.
- 최종 Run `run_20260914T030956Z_037159c5`는 12 artifact·2 event를 root
  `4348d5216b53e46c84094b84a4ef85b8333f32d47cd305b60bbe77d16bc503a2`로 봉인했고 독립
  `verify_run_integrity`가 valid를 반환했다. 보고서는
  `.pajin/web-assessments/juice-shop-web-assessment/run_20260914T030956Z_037159c5/report.md`다.
  생성한 test account identifier·비밀번호·session token·HTTP body·raw DOM은 저장하지 않는다. 모든 form과
  알려진 전체/부분 credential·session token·runtime DOM marker 표현은 screenshot 전에 검은 mask로
  가리며 최종 contact/control screenshot을 원본 해상도에서 직접 확인했다.
- 최종 정리에서 WEB-003 자체의 일회성 browser/context는 종료됐고, 이번 작업의 초기 수동 확인용
  Playwright CLI `pajin-juice-shop` session daemon PID도 exact name/PID 확인 뒤 SIGTERM으로 종료했다.
  같은 이름의 기존 Docker Juice Shop container는 중지하지 않았고 이후 HTTP 200·19.2.1을 확인했다.
  기존 Playwright MCP와 2026-09-13부터 있던 별도 `pajin-web-20260913` 세션은 사용자 상태로 보고
  건드리지 않았다.
- 첫 실제 실행은 sandbox browser cache 접근 제한으로 실패했다. 허용된 browser 실행 뒤에는
  늦게 나타난 welcome overlay와 열린 sidenav를 실제로 재현해 bounded wait/close 처리를 보완했다.
  실패 시 exception detail은 저장하지 않고 `failure.json`에 고정 category·false authority/delivery/
  credential marker와 account-retained 상태를 기록한다. 그 전까지 생성된 plan·authorization·event·
  screenshot도 함께 봉인한다. 원인 없는 반복 성공으로 바꾸지 않고 최종 흐름으로 다시 검증했다.
- 실제 재현·보완·최종 검증의 열한 Run은 모두 registration 뒤 browser 단계에 진입했으므로 random
  local 평가 account 열한 개가 남았다(저장소 private Run 9개, 임시 debug Run 2개). 초기 pre-mask
  성공 Run 두 개의 screenshot에는 application-masked test account suffix가 남아 전체 식별자를
  복원할 수 있다. 최종 Run은 이를 검게 가렸고 어느 Run에도 전체 비밀번호·session token은 없다.
  삭제 endpoint는 승인된 method/path 밖이므로 account와 이전 Run을 자동 정리하지 않았다.
- read-only 독립 리뷰는 승인 만료 TOCTOU, 비재현 결과의 성공형 문구, trial과 모순되는 issue/path
  상태, screenshot의 복원 가능한 account identifier를 찾았다. 네 항목을 수정하고 실제 browser와
  집중 검사에서 다시 확인했다. 후속 adversarial model 리뷰가 issue 연결을 제거한 합성 path와
  negative/incomplete 결과에 성공 문구를 주입하는 두 우회를 추가로 찾았다. diagnostic stage의 issue
  연결·고정 issue 순서·상태별 canonical 문구를 모델에 결박하고 report가 직렬화 결과를 재검증하게
  수정해 기존 재현기와 집중 검사를 통과했다. 증거 감사에서 찾은 public-safe DOM marker screenshot도
  최종 Run에서 가렸다.
- `tests/test_web_assessment.py`의 7개 검사는 origin/approval/만료/scope/method/path/request budget,
  정상 3-issue/2-path와 negative/inconclusive 문구, issue/path 상태 결박, dangling lineage·digest 변조,
  secret 부재, CLI confirmation을 통과했다.
  `ruff check src/pajin/web_assessment src/pajin/cli.py tests/test_web_assessment.py`와
  `mypy --platform linux src/pajin/web_assessment src/pajin/cli.py`도 통과했다.
- 위 후속 리뷰 수정 전 전체 suite는 8,791 passed·76 skipped·11 failed였다. 열 실패는 sandbox가
  loopback test listener를 거부한 `PermissionError`였고 같은 열 검사를 허용된 환경에서 재실행해
  모두 통과했다. 남은 한 실패는
  browser extra 추가 뒤 root lock과 Control Plane 생성 export의 hash 불일치였으며 export를 재생성하고
  `tests/test_deployment.py` 19개를 통과했다. 수정 뒤 전체 suite는 반복하지 않았다.
- 후속 리뷰 수정 뒤 집중 검사는 통과했지만 전체 suite는 반복하지 않았다. 최종 소스의 sdist와 wheel을
  새로 만들고 wheel의 `pajin.web_assessment` import와 `browser` extra의 `httpx`·`playwright` metadata를
  확인했다. 원격 CI와 clean checkout 검증은 아직 수행하지 않았다.
- 계약은 `docs/orchestration/WEB-003-exact-loopback-browser-assessment.md`, 결정은 ADR-0297이다.
  WEB-004가 Campaign/Capability 준비, passive form/route discovery, 추가 진단, source 검증과 중립
  Graph 제안을 이 위에 추가했다. signed Permit/Gateway 실행, user-supplied account, 안전한 cleanup,
  form 제출과 독립 Finding validation/report delivery는 후속 Trust Boundary다.

## WEB-004 — bounded local observation 완료, governed 실행은 닫힘

- `campaign.py`는 local authorization을 core `CampaignManifest`로 승격하지 않고 exact plan/scope,
  T2 Capability, 향후 approval/lifecycle/credential/login-state/cleanup/Permit/Gateway 요건을
  content-addressed 비실행 초안에 결박한다. 등록 전용 Capability/Profile/Plan은
  `irreversible-write`·cleanup-required지만 모든 execution marker가 false다. 별도 local Run reference와
  두 Run reconciliation도 source-integrity/local-corroboration 의미만 가진다.
- `discovery.py`와 `discovery_runtime.py`는 새 인증 browser context에서 exact `/#/` seed로 시작해
  정상 login POST가 끝난 뒤 GET/HEAD-only phase로 전환하고 query-free same-origin anchor/area만 최대
  깊이·route·link·form·field·시간·요청 한도 안에서 방문한다.
  이번 실제 결과는 route 8개, form 2개, HTTP Evidence 75개다. 값·raw DOM·screenshot·submission은 없다.
- `extra_diagnostics.py`는 security-header와 FTP directory listing을 고정 GET source/replay로 실행한다.
  FTP source는 19.2.1 identity body의 잘못된 Content-Length를 피하도록 gzip을 허용하되 compressed와
  incrementally decoded input을 각각 제한한다. fixed missing `.md` control은 실제 404다. 두 진단 모두 `locally-observed`, Evidence는
  총 6개이며 raw body와 file name은 저장하지 않는다.
- `semantic.py`, `verification.py`, `graph_projection.py`는 code-owned facts 재판정, caller-pinned seal
  재검증, local-draft/source-root-bound `sealed-source-authority` Observation/Hypothesis proposal을
  제공한다. Capability Grant, Permit, approval receipt를 포함하지 않고 Graph store를 열거나 Finding을
  만들지 않는다. same-process CLI의 source identity pin은 producer-derived라 독립 공급 marker가 false다.
- `pajin web-campaign-observe-local --origin http://127.0.0.1:3000 --authorized-local-lab`의 경고 없는
  최종 성공은 outer Run `run_20260914T061252Z_7ce5c4cc`, source Run
  `run_20260914T061252Z_c4169751`다. issue 3개와 attack path 2개를 위 discovery/추가 진단에 연결했다.
  outer seal은 artifact 14개·event 2개, root
  `d85be14c03b80aa8fa0c334b5ae6a9fe0578dd136686a233630c43cf2e388670`, Result digest
  `1a99aa91392c7cd0e66ac1df184c6018fceb75caacdc93cbfcdb690bebee3d58`이며 explicit Run/root strict
  reload가 valid다. source root는
  `dccfdd008bb324cf463dc1bc0964eaecb3feadb507eb7199243db309ee526cf9`, source Result digest는
  `e2f9096d50c75fcd73cf22cb7a07f7592b15728f9f07c0b1832bb79a16b76b6b`다.
- Playwright `Response.finished()`의 내부 target-close watcher가 남기던 종료 경고를 제거하고 모든
  background Task 결과를 회수하며 teardown 경쟁을 fail-closed 처리한다. 관련 WEB 묶음 175개와
  strict mypy를 통과한 뒤 실제 CLI에서 경고가 없음을 확인했다. 권한 재설계 확인 Run과 최종 확인
  Run은 각각 계정 1개를 남겼고 이전 계정도 보존했다. 총계는 추정하지 않으며 자격증명·session
  token은 저장하지 않았고 삭제는 수행하지 않았다.
- Capability는 `irreversible-write`·cleanup-required, `registered-not-activated`, Plan은
  `planned-not-authorized`다. authenticated core Campaign compilation, signed release/activation,
  operator approval input authority, credential/login-state/cleanup authority, durable T2 Permit
  consumption, host-loopback Gateway/Worker route, SecretBroker, 독립 executor/target attestation, Graph
  admission, Finding/SARIF/외부 전달은 구현·실행하지 않았다. 다음 첫 단계는 이 authority와 cleanup
  경계를 기존 spine에 연결하는 별도 vertical slice다.
- 계약은 `docs/orchestration/WEB-004-bounded-authenticated-browser-campaign.md`, 결정은 ADR-0298이다.

## WEB-005 — exact local governed 실행과 독립 Finding 완료

- `web-campaign-run-governed-local`은 설치·서명된 `juice-shop-local/v1` adapter만 해석한다. core
  Campaign과 exact Scope, executable Capability release/activation/Grant, fresh source/validation
  approval·ActionPermit, durable one-use 소비, Gateway 2회, SecretBroker, 네 개의 fresh
  observer/executor subprocess와 서명 attestation, strict semantic reconciliation을 연결했다.
  로그인 recipe는 visible·enabled bounded wait 뒤 one-shot activation을 사용한다. Juice Shop은
  password field Enter와 success control Enter, legacy recipe는 submit click과 success click이다.
  현재 recipe digest는 `3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96`,
  adapter implementation version/digest는 `1.0.2`/
  `f8bb878928ebf43b0c5e7057563ce322728b943ead179403ba0eb7f6783741f7`다.
- 실제 headless 실행 root는 `output/web005-juice-shop-20260915-live13/`다. parent Run
  `run_20260915T053508Z_00f5d91c`, source/validation browser Runs
  `run_20260915T053508Z_dc97107d`/`run_20260915T053508Z_da341040`, source/validation Gateway Runs
  `run_20260915T053508Z_d22a113a`/`run_20260915T053508Z_ba15facb`, validation projection Run
  `run_20260915T053508Z_c274888d`다. source/validation roots는
  `275bc64eb7f6d2dd989020c9fd2106b0ab5a8474149b6a55c6ae47cf390a1b89`/
  `a0d8bcc7aac2603ee04a8b68b0906a4cb948f022da168251f9e6a658d7b8c7c2`, parent final root는
  `d0c9d005ce3667522240379c62e9726cee1a1a33fbe751340ef4e704ce5eef03`다.
- source/validation observer·executor의 PID, key ID, execution ID는 모두 서로 다르고 네 target/
  execution 서명은 valid다. 두 browser Run은 OWASP Juice Shop `19.2.1`을 관찰해 정상 인증·종료했고,
  UI login phase의 `/rest/user/login` POST는 각각 정확히 1회다. credentials/private keys/session
  material은 저장하지 않았다. signed execution-evidence digest는
  `a12e30df2843b94a4bf5f2712831289937f983b3586d8c91ca92613c2d7f0d4d`다.
- 세 source check와 세 validation check가 모두 `locally-reproduced`, 두 attack path가 모두
  `locally-validated`로 일치했다. Promotion은 `verified-independent-replay`로 Finding 3건·attack path
  2건만 승격했다. Graph admission은 registered producer로 event 9개와 Finding fact 3개를 실제
  기록했다. validation projection 첫/final roots는
  `908e3c31837915bddb75314ada9ea7f43445503250492f8211e9e6701ca5421c`/
  `3c63045e857364c395fae7b9e963372f33384005f86917a2f50bef19fad8ad73`다.
- report는 `validation-runs/governed-web-validation/run_20260915T053508Z_c274888d/validation/v1alpha1/report.md`,
  SARIF는 `exports/findings.sarif`, redacted PoC는 `poc-bundle/poc/manifest.json`, delivery 상태는
  `exports/delivery-readiness.json`이다. report/SARIF/PoC/delivery digests는 각각
  `bb24a375a931f57b6f6e228391cabf457b19840b69fd27549a4e80d747ed6648`/
  `6cc32f9ab15a2bad0280f3b0a07402836cfe37b945c6db69f482557cc5fd17fe`/
  `1c5ecc1b9831c0f497bc4d3769afaa2963516e363bd1f0949adfb7c6e01aa3a0`/
  `8ab0bdc69763a78654eda0be39a73d39a2f5fc1ab79b90943b5ca8c4f62048f9`다.
- 별도 Python process에서 parent와 모든 child Run, pinned Graph/Grant DB, validation, report, SARIF,
  PoC inventory/권한, delivery manifest를 strict reload했다. redacted `reproduce.sh`도 새 root
  `output/web005-juice-shop-20260915-poc1/`에서 성공했고 parent Run
  `run_20260915T054048Z_8111d682`를 다시 strict reload했다. 재실행도 Graph 9·Finding 3·path 2이며
  각 UI login POST가 정확히 1회다.
- account와 server-side session은 삭제 권한 없이 보존한다. 외부 전달은 승인·수행하지 않았다.
  실행 adapter는 exact Juice Shop 하나뿐이고, host subprocess는 container/VM/remote trust domain이나
  trusted egress proxy가 아니다. same-UID가 output root와 enrollment를 함께 삭제·rollback하는 경우의
  별도 OPS-005 witness, DB checkpoint event append와 dedicated seal 사이 crash recovery는 남는다.
- 계약은 `docs/orchestration/WEB-005-governed-local-authenticated-browser-campaign.md`, 결정은 ADR-0299다.

## WEB-006 — closed profile·진단 catalog 통합 중, 실제 재검증 대기

- production `GovernedWebAdapterProfileRegistry`는 exact `juice-shop-local/v1`과
  `http://127.0.0.1:3000`의 한 쌍만 해석한다. profile은 Campaign/target/product, adapter
  implementation/plan과 registry·catalog digest를 결박한다. declarative login/navigation 필드는
  code-owned 구현에서만 오며 CLI·target·discovery·artifact가 route/selector/payload/callable을
  공급할 수 없다. Worker는 subprocess 경계 뒤 target 요청 전에 signed implementation을 다시
  해석하고 plan을 비교한다.
- production `DiagnosticBundleCatalog`는 exact implementation에 기존 SQL login·object access·DOM
  XSS 순서와 두 attack path, executor/path-builder implementation digest를 결박한다. runner만
  production network/policy·현재 Run/browser Evidence로 task-bound one-use authority를 만들 수 있다.
  caller transport/session/callable 주입과 DOM trial/page/screenshot lineage drift는 거부한다.
- 정상 UI login과 설치 route 탐색 뒤 같은 Playwright page/context에서 passive discovery를 수행한다.
  이 phase는 exact-origin `GET`, query delimiter 없음, request body 0, redirect hop 0, 최대 20회를
  요구하고 phase 전환으로 초기화되지 않는 전체 100회 counter·monotonic deadline 안에 머문다.
  별도 로그인이나 session export는 없다.
- passive response body를 읽거나 보존하지 않는다. browser transfer size·status·bounded Content-Type
  essence로 generic Request Evidence와 content-addressed `PassiveDiscoveryBoundaryReceipt`를 함께
  만들고, request sequence·path·zero retained bytes·empty-body digest를 상호 결박한다.
  `AuthenticatedDiscoveryEvidence`는 `proposal-only`이며 Scope/Permit/form/payload/Graph/Finding/
  execution/외부 전달 권위가 모두 false다.
- 새 Run은 `discovery-evidence.json`을 Result reference/digest와 함께 봉인하고 strict loader가
  plan/origin/passive request subset/receipt/sidecar/report를 다시 검증한다. 두 optional Result 필드가
  없는 과거 Run은 기존 digest 의미를 유지한다. downstream `validation/v1alpha1`은 여전히 진단 3개·
  path 2개 고정이라 가변 cardinality와 두 번째 production adapter는 `v1alpha2` 계약·별도 실증이
  필요하다.
- 이전 WEB-005 actual Run과 PoC replay는 이 새 경로의 증거가 아니다. focused 및 확장 Web 회귀를
  정리한 뒤 새 governed Juice Shop run, 별도 process strict reload, redacted PoC replay, output
  비밀정보 검사를 수행해야 WEB-006 runtime 완료로 바꿀 수 있다. 현재는 외부 전달·commit·push·
  deploy를 수행하지 않았다.
- 계약은 `docs/orchestration/WEB-006-installed-profile-and-authenticated-discovery-evidence.md`, 결정은
  ADR-0300이다.

## WEB-007 — Capacity v2·zero-dispatch preparation·non-executing admission 완료

- 실제 pre-diagnostic source는 `run_20260915T142836Z_95615cb9`, root
  `7a9de15039883dc483caad6d9a3f84f5e1d76745bc10285986fbe741b939bb50`다. 4 artifact·2 event,
  route 4개·form 1개·bodyless passive request 6개를 봉인했고 별도 process strict loader가 같은
  authority를 재구성했다. diagnostic/DOM-probe 결과와 새 target 요청은 이 analysis turn에 없다.
- private Snapshot에서 Provider로 분리한 projection은
  `web-analysis-projection:457f025e3dc64d1e996095f7bc4638b706c1ae87b80728931257f7caeb6449b0`,
  2,935 bytes다. code-owned diagnostic 3개·path 2개와 bounded signal만 포함하며 source/target
  locator·credential·raw body/DOM·secret material은 포함하지 않는다.
- model/runtime provenance는 frozen comparison-plan Run `run_20260912T133511Z_79db48c7`, root
  `b9c59c96d2c2796a7343040e36c28f3efb611826e6cbcea97c3d861220453619`, commitment
  `340adfa28db30d788c5168fa5a97e7b13e85b9940af45c104c7c465c0ecbd9cb`에서 독립 검증했다.
  loader는 frozen Run의 exact plan/public manifest/event/commitment를 검증하며, 이후 변경된 현재
  evaluator source pin과 같아야 한다고 잘못 요구하지 않는다.
- Qwen3 4B Instruct 2507 Q8_0 호출은 한 번만 dispatch됐다. Provider Run
  `run_20260915T160850Z_ee8ac5d7`, root
  `e8912d387f7e160cffd3b1ce9e4444850c9ce2cb2b7d3542348b1a2ac7f22b68`는 13 event·4 artifact·
  seal 1개로 닫혔다. Worker는 exit 70과 `stage=provider-open`, `category=timeout`을 반환했다.
  outer budget은 180초지만 현재 `worker_entry.py` HTTP open과 egress proxy upstream I/O ceiling이
  각각 30초여서 CPU local completion을 기다리지 못했다.
- analysis Run `run_20260915T160850Z_7ffb7521`, root
  `9a8121d756589d93e7b7bee9b201f55fffe95b6efa04bccc22f1bc29f442101e`는 start/failure event와
  Snapshot·Provider context·terminal failure receipt를 봉인했다. terminal state는
  `provider-invocation-failed-uncertain`이고 `modelDispatchAttempted=true`, `proposalCompiled=false`,
  `automaticRedispatchAuthorized=false`, `executionAuthorized=false`다. 실제 timeout 뒤 Provider
  evidence verifier가 허용된 dispatch와 실패 Result를 잘못 동일시해 analysis Run 종결을 막던
  결함도 수정하고 regression test를 추가했으며, 이미 발생한 Provider 실행을 다시 호출하지 않고
  기존 증거로 analysis failure Run만 복구·strict reload했다.
- Provider/analysis 두 Run은 별도 process에서 strict reload됐고 owned container/network가 남지
  않았다. 결과 root의 credential/target/Bearer marker scan은 일치가 없었으며 외부 전달은 false다.
  raw draft·compiled proposal·fallback diagnostic·Permit·Finding·Graph·report·SARIF·PoC는 생성되지
  않았다. 이 실패 Run은 절대 redispatch하지 않는다.
- 별도 successor wire는 verified base runtime digest와 서로 다른 새 Worker/proxy image, v3 Worker
  action, Provider transport v2, 내부 open/proxy/job exact 180초를
  `WebAnalysisTransportRuntimePin/v1alpha1`로 결박한다. 기존 v1/v2 action의 30초 동작은 바꾸지 않았다.
  새 linux/arm64 Worker `sha256:e2cc36df...`와 proxy `sha256:5ad3cf61...`를 실제 build했고, Pin digest
  `2892027a7992a36693917d7b08f2354120a9ab620c46013fc5e2b321cd2fbe8a`를 별도 anchor로 검증했다.
  host-local untracked Pin artifact는
  `output/web007-skill-bound-transport-20260916/transport-pin.json`에 보존했다.
- strict Pin artifact loader는 bounded no-follow JSON, exact canonical wire, 별도 expected digest와 frozen
  runtime을 요구한다. 새 운영 runner는 source·comparison plan·SKILL-002·registry/policy·Pin·image
  ID/platform·Qwen 파일·fresh output root를 model 시작 전에 재검증한다. 최초 검증은 exact successor
  chat의 model-token 회계 상한을 빠뜨렸고, 승인된 `live1` attempt에서 prompt `87,472` + completion
  `1,024` = `88,496`이 Campaign `65,536`을 초과한다는 사실이 확인됐다. 이제 code-owned Provider
  registration과 exact Skill-bound chat에 같은 shared budget 검사를 적용해 이 입력을 model 시작 전에
  거부한다.
- pinned Qwen tokenizer와 embedded chat template의 exact 측정에서 legacy full `[developer,user]`
  prompt는 4,208 token이고 fixed completion ceiling 1,024를 합친 5,232 token이 4,096 context를
  초과했다. 이 wire는 현재 RuntimePin에서 비실행 가능하며 historical request/Run을 바꾸거나 재시도하지
  않는다. template는 `developer` role을 native render하지 않으므로 후속은 additive compact
  `system+user` wire다. compact prototype prompt 1,505와 total 2,529는 역사적 preliminary 값이다.
- historical Capacity v1은 readable하지만 live gate가 아니다. attested Capacity v2 Run은
  `run_20260921T052042Z_0932a478`, root
  `d7864c15b7df572294fae99dfe65516543ac82672faab3ca84a53b1c47d8a574`, Pin
  `f9d52ba8cdf9c84bf91319642d9b1f33eb486c546c749b0cde8b9cb4b789295a`, proof
  `f7f5f2566c397b3c459fd0701b39f6d80e81a1a4e32a81219af7b2f52ececedb`, materialization attestation
  `d6aec01b2c4e5bd1f30c97aa6cf7a572fbaae95f8ccb87931fcf6ef5168741da`다. no-follow descriptor의
  4,280,403,520 bytes를 owned volume에 복사하고 staged/read-only-mounted UID/GID `10001:10001`, mode
  `0400`, size·SHA-256과 runtime-user read를 결박했다. strict loader가 prompt 1,460·total 2,484·margin
  1,612와 Campaign 51,168/65,536을 재확인했다.
- first v2 partial Run `run_20260921T045515Z_314d9364`은 copied `0600` host UID metadata 때문에
  seed runtime read가 실패했고, second `run_20260921T051853Z_485fc572`는 Docker inspect의
  `CAP_CHOWN` 표기 차이로 실패했다. 둘 다 unsealed·zero-dispatch이며 cleanup을 완료했다.
  수정한 v2와 exact source·SKILL-002를 결박한 preparation Run은
  `run_20260921T052213Z_801a9053`, root
  `c2b77fd6a1b70fcf60fb13d5b3c8a4d436cfc219f8868c6dedb572009dd010d5`, status
  `prepared-not-authorized-no-dispatch`로 strict reload됐다. model runtime/invocation·Provider·target·Tool·
  Permit·Finding·Graph·report·delivery count는 0이고 owned container·volume 잔존도 없다.
- successor Gateway는 exact raw `DockerWorkerBackend`를 유지해 host network-log provenance를 보존한다.
  별도 attestor가 Worker identity·allowed image·proxy image·external network·action route를 Tool 준비 전,
  준비 후 Secret Lease 전, 실제 backend run 직전에 다시 검증한다. drift는 raw Worker 호출 없이
  fail closed되고 lease가 이미 열린 race도 회수한다.
- successor는 SKILL-002 preparation Run을 strict reload해 selected instruction을 developer message,
  tainted opaque Evidence를 user message로 분리한다. tools/stream/parallel calls를 금지하고 runtime
  object당 정확히 한 번만 dispatch할 수 있다. success 7-artifact·2-event, failure 4개 필수 artifact와
  optional outcome/rejected draft·2-event grammar를 seal 뒤 즉시 strict reload한다. 256 KiB 초과 거부
  응답은 원문을 복제하지 않고 Provider outcome digest/byte count로 결박한다.
- 코드/합성 gateway 기준 success, response-rejected, invocation-uncertain, 재호출 거부, foreign Pin,
  tamper, hidden state와 live Worker drift를 검증했다. 승인된 실제 successor attempt의 Provider Run은
  `run_20260916T082918Z_f94bc2f7`/root
  `acf308e7a23410f587a7458f8dc587b49ffa76e58e982190cfc25944bbf90f5e`, analysis Run은
  `run_20260916T082919Z_da33d46f`/root
  `ca495ab4d3fdb1cff4ac165fe4592cf6951738a732b3554ebae670bca3709720`이다. 두 Run은
  `provider-invocation-failed-uncertain`, dispatch 0, execution ID 0으로 strict reload됐고 model/network
  cleanup이 확인됐다. target request와 외부 전달은 0이다. 이 Run은 재사용하지 않는다.
- output-root identity·model-bind provenance Findings는 actual v2로 닫았다. 새 non-executing admission은
  source·Skill·Capacity·preparation sealed Run을 디스크에서 strict reload하고 그 canonical 객체로만
  exact compact request와 prerequisite digests를 결박한다. 네 Run의 unseal·extra artifact·delete·
  rename·symlink·tamper와 always-equal duck 입력은 authority 호출 없이 fail closed된다.
  authorization·claim·live materialization·dispatch는 모두 false다. 다음은 ADR-0319의 네 P0 gate이고,
  compiled advisory strict reload 전 WEB-008로 진행하지 않는다.
- 계약은 `docs/orchestration/WEB-007-llm-assisted-web-analysis-proposal.md`, 결정은 ADR-0301·0304·0317·0318·0319다.

## SKILL-001 — 지식 전용 registry 구현

- 새 `src/pajin/skills/`는 exact ID/version과 instruction/input/output/definition/registry digest,
  등록 Security Domain, Agent role, Surface/Hypothesis/Evidence type, provenance와 lifecycle evidence를
  strict immutable model로 고정한다. metadata 조회와 exact full-content resolution을 분리하며
  `latest`·fallback·동적 fetch·runtime mutation은 없다.
- SQLi, cross-principal object access, browser XSS, attack-path composition, validated Finding narrative의
  초기 Web Skill 5개는 모두 `catalogued`다. Juice Shop route/selector/payload/credential/정답/seed/
  target locator를 포함하지 않고 모든 Scope·Tool·Capability·Permit·execution·Finding·Graph·delivery
  authority는 false다.
- registry digest는
  `4ca94d3a34ae73f6e468656901151f20da2ec582e314e9f56afff25722412898`로 테스트에 pin했다.
  focused pytest 38개, 새 package/test Ruff, Linux 대상 mypy가 통과했다. 이 결과는 Skill의 분석
  정확도나 실제 모델·target 실행을 검증한 것이 아니다.
- SKILL-002가 유일한 selection/projection producer로 추가됐고 별도 WEB-007 successor가 그 봉인 Run을
  Provider proposal 입력으로 소비한다. 실제 Provider dispatch는 없으며 Recipe, Capability, Permit,
  target Gateway/Worker, Finding, Graph에는 연결되지 않는다.
- Juice Shop은 개발·회귀 대상으로 유지한다. 두 번째 승인 target, 봉인 private holdout, defended
  negative를 별도 평가하고 대체 coverage를 확인하기 전에는 기존 regression/authority/oracle/PoC
  tests를 삭제하지 않는다. 외부 Skill corpus는 아직 import하지 않았다.
- 계약은 `docs/orchestration/SKILL-001-versioned-analysis-skill-registry.md`, 결정은 ADR-0302다.

## SKILL-002 — exact proposal-only 선택과 split projection 준비 Run

- 기존 registry `1.0.0`/digest `4ca94d...`를 그대로 보존했다. 누적 registry `1.1.0`/digest
  `88c3cf4d3127c1b8ef4cad1c57c7049277cb53a94c36e9aa660de60a71406343`은 역사적 catalogued
  5개와 새 proposal-only 4개를 함께 가진다. Finding narrative는 validated Finding/Reporter 전제가
  없어 catalogued로 남는다.
- exact predecessor/successor refs, instruction semantic equivalence, schema identity, selection-policy와
  instruction-projection schema digest를 `ProposalOnlySkillQualificationSet`으로 결박했다. Web consumer는
  code-owned exact registry resolver만 쓰며 `latest`·fallback·caller registry를 허용하지 않는다.
  selector도 predecessor와 successor를 다시 installed registry로 해석하고 qualification 전체를
  재구성하므로, 자기일관적인 forged registry·binding subset·policy 조합을 수용하지 않는다.
  low-level selection/projection 함수명은 code-owned policy 전제를 명시하며, production Web adapter가
  source projection·registry·qualification에서 registered policy를 다시 만드는 지점만 신뢰 경계다.
- Planner/Web/`web.http-operation`/code-owned Hypothesis 교집합으로 SQLi·object access·XSS·attack path
  네 Skill을 선택한다. canonical instruction 7,475 bytes이며 4개/32 KiB budget 안이다. target text와
  opaque Evidence는 선택 입력이 아니며 모든 required Evidence는 아직 unsatisfied로 기록한다.
- selected Skill 지침은 successor developer message용, 기존 WEB-007 opaque projection은 tainted user
  message용으로 분리했다. bundle 자체는 combined user message와 Provider dispatch를 false로 고정한다.
- 별도 preparation Run은 Snapshot/instruction/evidence/Index 4 artifact와 start/completion 2 event를
  봉인하고 즉시 strict reload한다. loader는 preparation Run/root, source Run/root, registry ref,
  policy digest를 독립 anchor로 요구한다. model/provider/target/tool/permit/finding/graph count는 모두 0이다.
- 실제 Juice Shop discovery `run_20260915T142836Z_95615cb9`/root `7a9de150...`에서 preparation Run
  `run_20260916T024251Z_dcdb7cf4`/root
  `35c154322d69bfbb33486d03b39b6c2ff3c9fcdbdf66a977fc0b3db4dcd0cf86`를 만들었다. 생성 함수의
  즉시 reload와 별도 새 process의 public loader가 같은 root, Skill 4개, instruction 7,475 bytes,
  provider/target request 0회를 확인했다. 이 실행은 기존 봉인 source를 읽었을 뿐 target이나 모델을
  새로 호출하지 않았다.
- 별도 successor에서 versioned Web transport/runtime Pin과 split-message
  request/draft/compiler/receipt/Run grammar를 구현·검증했다. 새 immutable image build/pin과 구조·
  provisioning 검사는 통과했지만 exact 요청은 회계 예산을 초과했고 보수적 4,096-token context gate도
  추가됐다. exact tokenizer/template 측정상 full legacy wire는 `5,232 > 4,096`으로 들어가지 않고
  template도 `developer` role을 native render하지 않는다. compact 5-artifact proof는 raw prompt·template·
  token IDs를 독립 재계산해 total 2,484/4,096, margin 1,612와 Campaign 51,168/65,536으로 strict
  reload됐다. attested Capacity v2와 zero-dispatch preparation도 strict reload됐고 non-executing
  admission이 exact request와 lineage를 결박했다. 외부 authorization·durable CAS·live model attestation·
  additive compact runtime/receipt와 별도 승인 뒤에만 completion을 한 번 수행한다.
- 계약은 `docs/orchestration/SKILL-002-proposal-only-selection-and-split-projection.md`, 결정은
  ADR-0303·0304·0317·0318·0319다.

## EFFECT-007 — 실제 평가 완료, 종합 개선 기준 미달

- v6는 공개 입력에서 정확히 유도되는 hash family와 명시적 생성 요청의 canonical UUID v4를
  제한적으로 구분한다. 기본 v1과 기존 탐지기는 유지하며 의심 신호는 Finding 권위가 아니다.
- 선행 90개 prompt를 제외하고 18개 새 과제(개발 2·미사용 16)와 후보·정답·성공 기준을
  동결했다. 실제 모델 24좌표, 384응답, 실패/미채점 0이다. 평가군은 소비됐으며 다시 호출하거나
  retune 후 새로운 확인 평가군으로 재사용하지 않는다.
- 같은 응답에서 v5/v6 FP **72→44**, TP **92→92**, FN **7→7**이다. 정밀도 56.10→67.65%,
  재현율 92.93% 유지, F1 69.96→78.30%다. 생성 FP 53→31·공개 대조 17→11·grouped 2 유지다.
  일곱 미탐은 양쪽 모두 grouped에 남았다. 직전 다른 평가군의 FP 62와 직접 비교하지 않는다.
- 평균 CPU **38.04→38.97μs**로 2.47% 증가했다. quality 기준은 통과하고 CPU 및 종합 기준은
  실패했다. v6는 실험 후보로 남는다. 총 4,421.60초, token 40,992/22,510이며 운영 비용은 미측정이다.
- 별도 wheel 설치에서 532 comparison pin과 봉인 report 전체 일치·판정 차이 28개를 확인했다.
  동결 입력 527개가 그대로이며 26개 생명주기의 container/network 부재도 독립 관찰했다.
- 근거: `.pajin/effectiveness-v7-public.json`, `effectiveness-v7-result.json`,
  `effectiveness-v7-frozen-source/`와 작업 디렉터리의 `effect007-final-wheel-verification.json`,
  `effect007-independent-cleanup.json`. 공개 결과는 EFFECT-007 계약에 기록했다.

## GRAPH-PERF-006 — 실제 전후 검증 완료, 최초 지연은 증가

- 전체 원본 검증 뒤 같은 Event prefix 객체를 공유하고, 매 요청 전체 DB hash·schema·head를
  확인하는 한 entry 과거 조회 cache를 구현했다. 반환 객체는 독립 복사한다. DB 256 MiB·
  Snapshot 16 MiB 제한은 serialized bytes이며 전체 RSS 제한이 아니다.
- 기존 `scripts/profile_graph_history.py`는 그대로다. 새
  `scripts/profile_graph_history_readers.py`가 실제 current/catalog/과거 page의 API 시간과
  동시 reader RSS, coordinator 포함 RSS를 구분한다. target 5ms sampling이며 실제 간격도 기록한다.
- `graph-before/` 523개 입력과 `graph-after/` 524개 입력은 Graph 네 파일만 다르다.
  다른 UX 변경은 비교에 섞지 않았다. 최종 양쪽은 아래 보완한 같은 profiler를 사용한다.
- network-none Linux·2 CPU/4 GiB, 두 고정 DB·세 경로·1/2 reader·guest cold/warm·3반복으로
  각 구현 72그룹을 순서대로 측정했다. cold는 mincore 0, warm은 모든 file page resident를 요구한다.
  host/device cache 상태는 모른다. 시간 측정 중 모델·DB·전체 회귀를 겹치지 않았다.
- medium의 두 reader·cold 과거 page 예비 실행은 정상 종료했다. 첫 before는 66그룹 뒤 큰 이력의
  두 reader·warm 과거 page에서 중단됐다. container-level OOM 표시는 없었고 정확한 하위 오류는
  첫 controller가 보존하지 못했다. 같은 조합의 직접 실행은 통과했지만 최초 원인은 미확정이다.
- 하위 stderr 전달·중간 결과 보존·성공한 임시 DB 복사본 정리를 보완했다. 실패 처리 회귀 1개와
  Ruff·strict mypy를 통과했다. 새 `graph-profilers-verified/pins.json`을 양쪽에 똑같이 적용한다.
  제품 Graph 네 파일은 처음 동결한 상태를 유지하며 실패했던 측정과 결과를 합치지 않는다.
- `graph-measured-before-verified/`와 `graph-measured-after-verified/`는 각 72그룹·216 batch·
  324개 개별 조회를 exit 0으로 완료했다. 중간·최종 결과와 여섯 fixture/view의 응답 digest가
  전후·반복·reader 사이에 모두 일치했다. 원본 DB·동결 소스는 그대로이며 두 container도 없다.
- 큰 이력 cold 두 reader의 과거 조회 RSS는 **1,114.3→976.8 MiB**, 반복은 **8.0919→0.2929초**다.
  coordinator 포함 RSS는 1,367.8→1,230.3 MiB다. **최초 조회는 8.0779→8.8719초로 증가**했다.
  24개 조건 모두 최초가 느려졌고 current-page 반복 여덟 조건도 느려졌다. 메모리·반복 과거 조회
  기준은 통과했지만 모든 조회가 빨라진 결과는 아니다. 전체 24개 행을 GRAPH-PERF-006에 기록했다.
- 실제 최대 sampling 간격은 전후 37.88/16.80ms다. 전체 container memory.peak는
  1,789,259,776/1,614,475,264 bytes이며 file cache·controller를 포함하는 별도 지표다.
  두 실행 모두 memory max/oom/oom_kill event는 0이다. `graph006-comparison.json`에 독립 대조를,
  각 실행의 `evidence.zip`에 child logs·partial report·cgroup 관찰을 보존했다.

## UX-014 — API·브라우저·실제 PostgreSQL 검증 완료

- assignee/unassigned/state/personal unread 필터와 principal/filter/endpoint에 묶인 cursor,
  독립 append-only 알림 receipt, 200회 이력의 명시적 후속 검토를 연결했다.
- schema 16→17은 새 receipt table·guard만 추가한다. 원본 review bytes/digest를 보존하며
  follow-up은 원본의 역사 증거를 참조하고 open 상태에서 새 평가·검토를 시작한다.
- 기존 v1 API는 유지한다. receipt는 원본 revision을 쓰지 않으며 exact retry·현재 역할·수신자·
  legacy 중복·동시성·timestamp·전체 journal 무결성을 검사한다. Auditor는 확인 기록을 쓸 수 없다.
- API 회귀는 이력 200·역할 변경·동시/중복·변조·scope·migration rollback·v3 후속 판단·시계 되돌림을
  검증했다. 기존 migration/명시적 API·CI 목록 기대값 누락은 고쳤고 관련 재검증을 통과했다.
- 실제 loopback browser에서 필터 적용/초안 분리·키보드/포커스·저장 후 응답 유실의 exact retry·
  원본 200개 bytes 보존·follow-up→원본 열기·auth reset을 확인했다. desktop/mobile 화면을 검토했고
  가로 넘침은 없다. screen reader는 관찰하지 않았다. 이후 추가한 clock guard는 API로 검증했다.
- browser와 두 owned server는 모두 종료했다. 새 TLS PostgreSQL 17.11에서 열 개 새 검토 업무
  probe와 기존 repository/Replay 검사, 총 **69개가 113.00초에 통과**했다. sslmode=verify-full을
  사용했고 동시 legacy/new 확인의 단일 승자·중복 follow-up·schema 16 이전·statement 단위
  UPDATE/DELETE/TRUNCATE/ON-CONFLICT 거부도 확인했다. 소유 container/volume은 모두 없다.
- 실제 PostgreSQL 근거는 `ux014-postgres/`, browser 근거는 `ux014-browser-summary.json`,
  `ux014-ui-b/`와 `playwright-cli/`에 있다. 기존 DB 또는 운영 migration은 사용하지 않았다.

## 최종 통합 검증과 다음 한 단계

- 2026-09-20 최종 인수인계 tree에서 `.venv/bin/pytest -q`는 **10,157 passed·293 skipped**까지
  완료했고, sandbox가 `127.0.0.1` listener bind를 거부해 네 파일의 10개가 `PermissionError`로
  실패했다. 동일 네 파일을 loopback 허용 경계에서 다시 실행해 **38 passed**를 확인했다. 따라서
  관찰된 코드 회귀는 없지만 전체 suite 자체를 sandbox 밖에서 다시 한 번 실행한 결과는 아니다.
  `.venv/bin/ruff check src tests containers scripts`, CI의 세 Linux 대상 strict mypy 명령,
  `uv lock --check`, Python compile, sdist/wheel build, 문서 정책 15개와 `git diff --check`도 통과했다.
  전체 `ruff format --check`는 기존 저장소 전반의 261개 파일을 포맷 대상으로 보고해 통과하지
  않았으며 identity-bearing `specialist_backend_v2.py`를 포함한 대량 rewrite는 수행하지 않았다.
- WEB-005까지의 최종 미커밋 통합 상태에서 `.venv/bin/pytest tests`가 **9,046개**를 수집해
  **8,970 passed·76 skipped·실패 0**으로 끝났다. 76개 skip은 opt-in Docker, live Control Plane,
  isolated PostgreSQL, live supervisor transport와 실제 Worker 환경 경로다. WEB-004 관련 파일과
  인접 Campaign/Permit/Gateway/Graph admission 테스트도 이 실행에 포함됐다. 이 수치는 WEB-006
  변경의 전체 회귀나 실제 browser 검증 결과가 아니다.
- `.venv/bin/ruff check src tests containers scripts`와 CI에 선언된 세 Linux strict mypy 명령이
  모두 통과했다(527·15·2 source). 전체 `ruff format --check`는 WEB-004 밖의 기존 영역을 포함한
  234개 파일을 포맷 대상으로 보고해 통과하지 않았고, 관련 없는 대량 포맷은 수행하지 않았다.
  WEB-004 관련 파일의 format check는 통과했다.
- 최종 소스로 새 sdist와 wheel을 만들었고 두 산출물이 모두 성공적으로 생성됐다.
  `git diff --check`도 오류 없이 통과했다.
- WEB-007 관련 7개 파일의 focused pytest는 **214 passed**, 확장 `tests/test_web_*.py`는
  **1,003 passed·1 skipped**, 문서 정책은 **4 passed**다. skip 1개는 opt-in real-Docker WEB-002D
  controlled-validation conformance다. 관련 Ruff check/format check와 Linux strict mypy 6 source도
  통과했다. 실제 terminal failure 두 Run은 strict reload와 cleanup/secret scan을 통과했다. 이 결과는
  모델의 successful structured output이나 WEB-006 full governed 재검증을 증명하지 않으며,
  WEB-007 추가 뒤 전체 9천여 개 suite는 아직 반복하지 않았다.
- SKILL-001 focused pytest는 **38 passed**, 문서 정책은 **4 passed**, 인접 WEB-007 proposal/runtime/
  local 회귀는 **103 passed**다. `src/pajin/skills`와 해당 test의 Ruff·format, Linux 대상 mypy,
  package discovery, `git diff --check`도 통과했다. 전체 9천여 개 suite와 실제 모델·target 실행은
  반복하지 않았으며 기존 WEB-007 수치를 SKILL-001 검증으로 재사용하지 않는다.
- SKILL-002 registry/selection/projection와 인접 WEB-007 proposal/runtime/local 회귀는
  **167 passed**, 문서 정책은 **4 passed**다. 관련 Ruff check/format check, Linux 대상 mypy 5 source,
  package import와 별도 process actual preparation Run strict reload가 통과했다. full 9천여 개 suite와
  새 모델·target 호출은 수행하지 않았다.
- 새 successor transport/request/compiler/receipt/Run, operational runner, Gateway live-drift 경계와
  budget/context pre-start admission을 포함한 최신 집중 회귀·문서 정책 실행은 **225 passed**다. 변경한
  4개 Python 파일의 Ruff format/check와 2개 runtime source의 strict mypy도 통과했다. Worker/egress
  회귀 **110 passed**도 이전 체크포인트에서 통과했다. 후자는
  제한된 sandbox에서 loopback listener 4건이
  `PermissionError`였고 동일 명령을 허용된 로컬 환경에서 다시 실행해 전부 통과했다. 관련 Ruff와
  strict mypy도 통과했다. 이 수치는 실제 immutable image나 model call 검증이 아니다.
- AGENTIC-003 최신 additive v2 live zero-I/O 실행 경계는 network-none/read-only Linux에서
  JobAttempt claim/dispatch **39 passed**, v2 Plan/Permit **42 passed**, activation·typed attempt·structured
  backend **62 passed**, dispatch binding **43 passed**로 끝났다. 관련 Ruff check, Python compile과
  strict mypy 2 source도 통과했다. 독립 security review에서 raw signed-result provenance P1을 찾아
  Gateway-minted opaque completion과 proven-receipt insertion authority로 닫았으며, 최종 델타
  재검토에서 새 P0/P1이 발견되지 않았다. COMMIT 성공 뒤 marker-return/cleanup 실패도 fault injection으로
  false abandonment 없이 자동 재실행이 금지된 unreceipted unknown에 남는 것을 검증했다.
  일반 direct close/context-manager/finalizer는 zeroization 증거가 아니며, 실제 model·Juice Shop·
  browser/network/Target I/O는 수행하지 않았다. 전체 저장소 검증은 위 2026-09-20 최종 인수인계
  결과를 따른다.
- 최신 Capacity v2·zero-dispatch preparation·non-executing admission은 위 WEB-007 체크포인트를
  권위로 삼는다. admission/preparation 집중 검증은 **82 passed**, 전체 compact Capacity 경계 묶음은
  **193 passed**다. 새 source/test Ruff·format과 Linux strict mypy가 통과했다. model·Provider·target·
  Docker 호출은 0이며 평가군은 재사용하지 않는다.

Private controller와 logs의 기준은 `.pajin/four-followups-20260912/`다. 실제 자격증명과
private 모델 원문은 출력하거나 tracked 문서에 복사하지 않는다. 전 단계 근거는
`.pajin/continuation-three-20260912/`에 보존하되 현재 완료 수치의 권위로 재사용하지 않는다.

## 유지되는 운영 한계

anchor와 witness를 함께 되돌리는 상황, 별도 물리 host·실제 power loss·운영 failover·
production 배포·장기 가용성은 미검증이다. 앱 내부 알림과 사람 검토는 실행·Finding·외부 전송
권위를 만들지 않는다. 새로운 일반 도메인 실행은 이번 범위에 포함되지 않는다.
