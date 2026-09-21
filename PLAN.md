# PAJIN 구현 계획

2026-09-12 사용자는 이전 세 축의 구현을 바탕으로 아래 네 후속 항목을 순서대로 진행하도록 승인했다.
2026-09-13 체크포인트의 main/upstream/실제 원격 확인값은 `39c66a2`였다. 기존 완료분의 원격
검증은 끝났고 EFFECT-007·GRAPH-PERF-006·UX-014의 코드·테스트·문서와 로컬 검증도 완료했다.
이 세 항목과 이후 WEB-003~007·SKILL-001~002·AGENTIC-001~004 구현은 2026-09-20의 논리
커밋으로 보존했으며 최종 인수인계 상태는 Git의 `main`·`origin/main`을 권위로 확인한다.
2026-09-14 사용자가 승인한 local OWASP Juice Shop을 첫 실제 대상으로 삼아, WEB-003의
고정 수직 흐름과 WEB-004의 비실행 Campaign 초안/Capability 준비·인증형 수동 탐색·추가
진단·봉인 source Graph 제안·로컬 보고 흐름을 새 우선 작업으로 구현했다.
2026-09-15 WEB-005에서 같은 exact local 대상의 Campaign·Capability activation·Grant·승인·Permit·
Gateway·독립 Worker 증거·Graph admission·Finding·공격 경로·보고서·SARIF·redacted PoC까지 연결하고,
완료 산출물의 별도 process strict reload와 PoC 전체 재실행을 통과했다.
같은 날 WEB-006에서 closed 설치 profile과 code-owned 진단 catalog, 동일 인증 browser context의
bodyless passive discovery receipt와 봉인 sidecar를 연결했다. 새 discovery-only 경로의 실제 Juice
Shop Run과 strict reload는 통과했지만, 이 결과는 WEB-006의 전체 governed 실행·PoC 재실행 완료
근거가 아니다.
같은 날 사용자는 원래 구상의 중심이 코드에 고정된 진단이 아니라 LLM의 분석·가설·
우선순위·재계획 루프임을 다시 확인했다. WEB-006은 이 루프의 안전한 browser/evidence
기반으로 보존하되, 이후 Web 로드맵은 봉인 discovery → 비밀 제거 projection → 정책에
결박된 LLM proposal → 결정론적 compiler → 별도 승인·Permit·Gateway → 독립 Replay →
Finding·Graph·보고의 순서를 최우선으로 삼는다.
2026-09-16 WEB-007/v1alpha1의 비밀 제거 projection, 단일 local Provider 호출, strict parser,
결정론적 비실행 compiler와 success/failure Run 검증을 구현했다. 실제 Qwen3 4B Q8 호출은 target
요청이나 외부 전달 없이 한 번 dispatch됐지만, Worker/egress proxy의 30초 I/O 한도에서 timeout으로
끝나 raw draft와 compiled proposal은 생성되지 않았다. 실패 Run은 재시도 불가 terminal 상태로
봉인·strict reload했으며 다음 시도 전에 versioned Web transport/runtime pin 보완이 필요하다.
같은 날 SKILL-001에서 분석 지식과 실행 권위를 분리한 exact-version Skill registry와 target-neutral
Web Skill 5개를 `catalogued` 상태로 구현했다. 이 registry는 아직 WEB-007, Recipe, Capability,
Worker에 연결되지 않았으며 Juice Shop 외 target이나 실제 모델 성능을 증명하지 않는다.
같은 날 SKILL-002에서 기존 `1.0.0` registry를 보존한 채 누적 `1.1.0` proposal-only successor와
exact qualification을 추가하고, Planner에 맞는 진단 3개·attack-path 1개만 결정적으로 선택했다.
선택 지침과 tainted Evidence는 서로 다른 미래 message role로 분리해 4-artifact zero-dispatch
준비 Run과 strict loader에 결박했다. selector는 installed predecessor/successor로 qualification 전체를
재구성해 caller가 만든 자기일관적 lineage를 거부한다. 실제 model·target 호출과
Recipe/Capability/Permit은 없다.
같은 날 WEB-007의 proposal-only Skill consumer를 별도 successor wire로 구현했다. 독립
transport/runtime Pin은 새 Worker/proxy image와 v3 action, 내부 I/O/job의 exact 180초를 결박하고,
successor는 SKILL-002 Run을 strict reload해 instruction을 developer message, tainted Evidence를 user
message로 분리한다. 정확히 한 번의 no-tools dispatch, terminal success/failure Run, 즉시 strict reload와
모든 downstream authority false를 테스트했다. 새 linux/arm64 Worker/proxy image를 실제 build하고
독립 transport Pin과 source·plan·Skill·model·image 검증을 통과했다. 그러나 첫 승인된 successor
시도에서 exact 요청의 보수적 회계 상한 `88,496`이 Campaign 한도 `65,536`을 초과해
`model.call.started`와 Gateway 전에 차단됐고 model dispatch는 0회였다. 이 누락은 exact successor
요청을 model 시작 전에 검사하도록 수정했다. frozen 4,096-token context에 대한 pinned tokenizer/
chat-template 측정 결과 legacy full `[developer,user]` 요청은 `4,208 + 1,024 = 5,232`로 들어가지
않는다. embedded Qwen template도 `developer` role을 native render하지 않으므로 legacy wire는
비실행 가능 상태로 동결한다. additive compact `system+user` prototype의
`1,505 + 1,024 = 2,529`는 역사적 예비값으로만 남긴다. 2026-09-21 최종 5-artifact Capacity Run
`run_20260921T021716Z_b3939e0c`는 raw formatted prompt·chat template·1,460개 token ID를 봉인하고
strict loader가 이를 독립 재계산해 `1,460 + 1,024 = 2,484 <= 4,096`, margin 1,612와 Campaign
`50,144 + 1,024 = 51,168 <= 65,536`을 증명했다. completion·Provider dispatch·target request는 모두
0회이고 tokenizer container도 남지 않았다. 후속 security review의 output-root identity와 Docker
model-bind provenance Finding은 descriptor-pinned output root와 Capacity v2로 닫았다. v2 Run
`run_20260921T052042Z_0932a478`은 exact model bytes와 staged/read-only-mounted UID/GID `10001:10001`,
mode `0400`, size·SHA-256을 결박하고 strict reload됐다. 이를 exact source·SKILL-002에 결박한
zero-dispatch preparation Run `run_20260921T052213Z_801a9053`도
`prepared-not-authorized-no-dispatch`로 strict reload됐다. 두 Run의 model completion·Provider·target
호출은 0회다. 이어 sealed preparation과 exact compact request를 묶는 non-executing admission을
구현·검증했다. 다음은 외부 one-call authorization, durable single-use CAS, live descriptor-to-volume
attestation, additive compact receipt/runtime이며, 네 gate와 별도 사용자 승인 전에는 completion을
호출하지 않는다.

2026-09-17 AGENTIC-001에서 Codex형 논리 agent lifecycle, Canonical Graph root에 결박된
LLM 가설 확장, Hypothesis Frontier, 결정론적 Path Scorer, bounded Dynamic Supervisor와
Skill-backed Web Pentest/Exploit Group을 비실행 기반으로 구현했다. 이 단계는 model proposal과
스케줄링 계약만 제공하며 실제 model·target 호출, Scope·Capability·Permit·Gateway·Worker,
Finding·Graph write·보고·PoC 권위를 제공하지 않는다.
2026-09-18 AGENTIC-002에서 current Graph head의 독립 resolution, durable model invocation
journal, checkpoint CAS, command outbox/inbox, 전체 이력 재검증, 복구와 target-neutral context
compaction을 Linux descriptor-bound SQLite 권위로 구현했다. 같은 체크포인트에서 AGENTIC-003A의
XSS·SQLi·authorization inert specialist profile과 AGENTIC-004의 비실행 3-arm 평가 계약을
추가했다. 이어 003B에서 세 profile을 별도 code-owned executor closure와 최소 browser 흐름에
결박하고 production binding은 executable bridge 전까지 차단했다. 실제 execution·독립 검증과
별도 승인 target/private holdout 평가는 후속 단계로 분리했다.
같은 날 003C1에서 current Graph와 durable head, sender ACK와 receiver admission, selected Candidate,
current Exploit Group specialist, live Agent Session을 다시 검증한 assignment만 store-local one-use
reservation으로 전환했다. `reserved -> dispatch-started-outcome-unknown` CAS와 재시작 후 권위 미재발급,
자동 redispatch 금지를 구현했지만 Capability·approval·Permit·Gateway·Worker는 연결하지 않았다.
이어 003C2에서 live reservation을 소비하지 않은 채 current Graph·durable head를 다시 확인하고,
exact Juice Shop Target·Campaign·Scope·budget·production profile/executor를 content-addressed inert
preparation에 결박했다. future one-call non-delegable Capability requirement를 기록하지만 모든 실행
권위는 false이고 I/O는 없다. 이어 003C3A에서 XSS·SQLi·authorization별 T2 read-only Capability·
Tool·complete authority set과 signed Range activation을 추가하고 deterministic
`PreparedCapabilityAction`까지만 생성했다. 003C3B1은 original reservation handle을 소비해 exact
Campaign·preparation·prepared action·one-call child Grant·approval tuple·expected Permit을 durable
   `awaiting-permit` plan에 결박하고 one-use process-local plan handle로 권위를 이전했다. 003C3B2는
   deployment-owned Graph/Permit Store·Ledger·approval keyring과 공유 Permit writer를 pin하고, fresh
   signed approval의 one-winning callback 안에서 Permit·Grant 소비와 당시 schema v5의
   Grant-consumption receipt·plan/execution crash fence를 결박했다. 003C3C의 첫 비실행 기반은 그 결과를
   exact Store·DB·Task live-set과 opaque capsule로 한 번만 전달하는 binding 및 Target-I/O-zero Worker
   conformance 계약까지 구현했다.
2026-09-20 현재 additive SQLi v2 planning identity와 complete seven-role code-backed Capability bundle,
externally signed current Range release activation, exact action registry, deterministic
`PreparedCapabilityAction`을 구현했다. materializer/compiler 외 execution·interpretation·replay·cleanup
role과 direct Tool dispatch는 specialist execution Gateway 전까지 fail closed한다. schema v6의
JobAttempt·terminal receipt, embedded canonical typed claim/dispatch verification DAG, Capability
authority-set·scheduler Task·capsule token·authorization lineage·runtime inventory pin, 명시적 offline
v5→v6 migration과 audit-only recovery도 구현했다. 별도의 structured v2 fake backend는 exact source
bytes, compiler, image, job template, backend, verifier, deployment Ed25519 key를 content-addressed
inventory로 pin하고 정확히 한 번의 zero-Target-I/O 호출 결과에 서명한다. 이 conformance 결과
자체는 production Gateway/Worker 성공이 아니며 모든 실행·독립 검증·Finding·Graph·보고·SARIF·PoC
권위는 false다. model·browser·network·Target I/O도 수행하지 않았다.
`specialist_backend_v2.py`의 source bytes는 이제 이 version의 identity 일부이므로 수정하지 않고
successor version으로만 교체한다.
distinct SQLi v2 Plan wire와 durable runtime generation, one-call Grant, signed approval, Permit
callback, same-scheduler-Task started handle·private capsule도 구현했다. Store는 transfer된 capsule을
private one-shot claim으로 소비하면서 current Graph·durable history·deployment·preparation/action·
approval·terminal Permit·Grant lineage를 다시 검증하고, 성공 또는 terminal failure 뒤 capsule을
폐기한다. 이 predecessor claim 자체는 Target I/O를 수행하지 않고 JobAttempt나 public C3C/Gateway
권위를 만들지 않는다. 그 위의 live pre-backend admission은 exact scheduler Task와 private capsule에서
current authority와 deployment inventory를 다시 확인하고 durable `claimed-before-backend` JobAttempt와
non-copyable·non-serializable opaque claim을 발급한다. audit-only JobAttempt에는 typed
ClaimVerification이 embedded되지만 별도 ClaimVerification bearer는 없다. public deployment와 claim에는
raw backend·verifier·key·template·inventory가 없고, 이 객체들은 same-interpreter control-plane TCB의
private owner vault에만 남는다. owner Task 종료, trusted Store close, explicit discard, post-insert mint
failure는 Store-authored `abandoned-before-backend` receipt를 기록하고 모든 live authority를 폐기한다.
그 위의 same-Task 실행 경계는 opaque claim을 한 번만 소비하고 current authority와 exact runtime을
재관찰한 뒤 durable dispatch-start marker를 먼저 기록한다. Store-owned Gateway가 private structured
Worker를 한 번 호출하고 Ed25519 결과를 검증한 뒤에만 one-shot opaque completion을 발급한다. Store는
raw signed result가 아니라 이 provenance를 소비해 `failed-before-target-io` receipt를 기록한다.
post-marker failure/cancellation은 `started-outcome-unknown`, proven-result receipt commit 실패는 receipt
없는 unknown recovery로 남으며 자동 redispatch하지 않는다. active backend 동안 Store close도
fail closed한다. 이 slice는 backend conformance 호출만 수행했으며 browser·network·Target I/O는 0이다.

## Agentic campaign runtime 전환 순서

1. [x] **AGENTIC-001 bounded planning foundation** — typed logical-agent command/event lifecycle,
   closed-signal model projection, canonical Graph-root hypothesis expansion, deterministic path scoring,
   bounded supervisor scheduling과 exact-version Skill-backed Web Exploit Group을 추가했다. 모든
   proposal·score·decision·event text는 비권위이며 재시작 resume는 지원하지 않는다.
2. [x] **AGENTIC-002 durable coordination** — current Graph head 독립 resolution, durable model
   invocation journal, checkpoint CAS, transactional outbox/inbox, 검증된 복구와 target-neutral
   context compaction을 구현했다. 권위 backend는 Linux `/proc/self/fd`와 trusted hosting process를
   요구하며 target 실행 권위를 만들지 않는다.
3. [ ] **AGENTIC-003 governed specialist execution** — 003A~003C3B2와 초기 C3C 경계에 더해 additive
   SQLi v2 planning identity, schema-v6 JobAttempt·terminal receipt, typed claim/dispatch verification
   DAG, explicit offline v5→v6 migration, audit-only recovery와 source-byte-addressed structured v2 fake
   backend의 one-call Ed25519-signed zero-Target-I/O conformance까지 구현했다. 이 fake backend에는
   compiler/image/job/backend/verifier/key pin이 있지만 Gateway/Worker 성공이나 durable
   conformance-success terminal kind는 없고 모든 실행·승격 권위는 false다. SQLi v2 seven-role bundle,
   signed Range activation, action registry와 exact `PreparedCapabilityAction`, distinct v2
   Plan/Grant/signed approval/Permit, Store-owned private one-shot runtime claim과 live pre-backend
   JobAttempt admission까지 구현됐다. same-Task opaque claim 소비, immediate pre-handoff re-observation,
   durable dispatch-start marker, scheduler-owned Gateway의 private structured Worker one-shot invocation,
   signed-result verification, opaque completion provenance, zero-I/O terminal finalization과 post-marker
   failure/cancellation·Store-close fencing도 구현됐다. 현재 cancellation 증거는 pinned zero-I/O
   backend 내부 `CancelledError` 분류까지이고 실제 suspending target-I/O `Task.cancel()` race는
   successor 검증 범위다. 이 결과는 Target I/O가 없으므로
   `completed-verified`가 아니라 `failed-before-target-io`다. 남은 단계는 frozen fake backend를 수정하지
   않는 additive target-I/O-capable Worker/Gateway successor, 승인된 실제 SQLi Juice Shop 실행, 그리고
   003D의 독립 Evidence·Replay·Finding·Graph·보고·SARIF·PoC 검증·승격이다.
4. [ ] **AGENTIC-004 campaign evaluation** — 비실행 3-arm·3-role·17-metric 평가 계약은
   구현했다. 승인된 Juice Shop 개발 회귀와 별도 승인 target/private holdout에서의 실제
   attack-path 적중률·재계획 이득·오탐·권위 위반·시간·비용 측정은 아직 수행하지 않았다.

## 범용 Skill과 성능 평가 전환 순서

1. [x] **SKILL-001 지식 전용 registry** — metadata-first 조회, exact ID/version/content/schema
   digest, provenance, lifecycle evidence와 모든 실행·Finding·Graph·전달 권위 false를 강제한다.
   초기 SQLi·object access·XSS·attack path·Finding narrative Skill 5개는 모두 `catalogued`다.
2. [x] **SKILL-002 proposal-only 선택·projection** — exact registry/Skill refs를 별도 WEB-007
   준비 Run에 결박했다. 선택된 target-neutral instruction은 미래 developer message, opaque Evidence는
   미래 user message로 분리했고 allowlist·role/domain/Surface/Hypothesis·count/byte budget을 강제했다.
   model·target dispatch와 Scope·Recipe·Capability·Permit은 만들지 않았다.
3. [ ] **Recipe binding과 LLM 종단 loop** — WEB-specific transport/runtime pin과 proposal-only
   successor Run grammar, 새 immutable image build/pin을 완료했다. 첫 승인 시도는 request-capacity
   preflight 누락으로 dispatch 전에 종결됐고, 이제 Campaign budget과 보수적 4,096-token context
   admission이 같은 초과 요청을 model 시작 전에 거부한다. exact tokenizer 측정으로 legacy full
   request도 `5,232 > 4,096`임을 확인했다. embedded template가 지원하는 additive compact
   `system+user` wire와 두 message sentinel의 5-artifact offline sealed capacity proof는 구현·strict
   reload됐다. final `2,484 <= 4,096`, margin 1,612와 conservative Campaign
   `51,168 <= 65,536`이 권위값이고 prototype `2,529`는 역사적 예비값이다. output-root inode pin과
   descriptor-to-owned-volume model materialization을 attested Capacity v2로 보강했고, actual v2 Run과
   exact proof-bound zero-dispatch preparation Run을 strict reload하고 exact compact request와 모든
   prerequisite anchor를 non-executing admission에 결박했다. 다음은 외부 one-call authorization,
   durable single-use CAS, live descriptor-to-volume attestation, additive compact receipt/runtime이며,
   이 네 gate와 별도 사용자 승인 뒤 한 번의 fresh model
   completion으로 성공 WEB-007 proposal을 strict reload하고,
   별도 code-owned Skill→Recipe binding과
   WEB-008~010의 승인·Permit·Worker·독립 replay·Finding·Graph·보고·재계획을 연결한다.
4. [ ] **교차 target transfer 평가** — Juice Shop은 개발·결정론적 회귀 대상으로 유지하고, 별도
   승인된 두 번째 target에서 adapter 가정과 취약점 종류별 전이를 측정한다.
5. [ ] **봉인 private holdout·defended negative 평가** — model/prompt/Skill/compiler/Recipe/target
   version/seed/budget/성공 기준을 먼저 동결한다. 개봉한 holdout은 retune 뒤 새 확인군으로 재사용하지
   않으며 recall·precision·FP/FN·유효 attack path·근거 없는 주장·권위 위반·사람 개입·시간/비용을
   분리해 보고한다.
6. [ ] **중복 target-specific 제품 경로 정리** — 각 fixture/assertion/parser/authority gate/oracle/
   PoC replay의 대체 coverage를 표로 확인한 뒤 중복 제품 분기만 제거한다. 회귀 테스트, strict loader,
   독립 oracle, negative control, 권위·holdout 격리 테스트는 삭제하지 않는다.
7. [ ] **System→Application→Forensics 확장** — 공통 Skill/proposal loop만 재사용하고 domain별
   Surface/Profile/Capability/Worker isolation/Evidence/oracle/cleanup/benchmark를 별도 slice로 만든다.
   Web 성공이나 Skill membership은 host·artifact·custody 권위로 전이되지 않는다.

## LLM 웹 분석 루프 우선순위

1. [ ] **WEB-006 안전 기반 완료** — closed profile/catalog와 동일 인증 context의 passive
   discovery, bodyless request receipt, strict source loader의 실제 discovery-only Run은 통과했다.
   전체 governed Run·redacted PoC replay·확장 회귀는 아직 남으며, 고정 진단은 후속 LLM 루프의
   회귀 기준이지 최종 제품 구조가 아니다.
2. [ ] **WEB-007 봉인 discovery와 LLM advisory proposal** — 진단·DOM probe 전의 별도
   discovery-only Run, target 원문·자격증명·직접 source anchor를 제외한 projection, local
   policy-bound Provider, strict parser와 현재 source/catalog를 다시 여는 비실행 compiler를
   구현했다. 실제 단일 호출의 timeout failure/no-redispatch 경로는 봉인·strict reload했지만
   raw draft와 compiled proposal의 실제 성공 근거가 없어 미완료다. SKILL-002의 exact Skill
   selection과 split projection 준비 Run, versioned transport/runtime Pin, split-message
   request/draft/compiler/receipt와 success/failure Run grammar는 구현·테스트됐다. 새 immutable
   Worker/proxy image build/pin은 통과했다. 첫 successor attempt는 model-token 회계 예산에서
   zero-dispatch terminal failure로 닫혔고 budget/context fail-closed preflight를 추가했다. 보수적
   회계 guard와 별개로 pinned tokenizer/template가 legacy full request를
   `4,208 + 1,024 = 5,232 > 4,096`으로 측정했다. legacy wire는 비실행 가능 상태로 보존하고,
   additive compact `system+user` wire를 tokenizer-only 경로로 검증해 두 message sentinel, raw formatted
   prompt·chat template·token IDs, exact context/Campaign inequality를 5-artifact Run으로 봉인·strict
   reload했다. final `2,484 <= 4,096`, margin 1,612와 `51,168 <= 65,536`이 권위값이며 prototype
   compact total `2,529`는 역사적 예비값이다. descriptor-bound Capacity v2와 exact source·Skill·proof
   anchors를 가진 zero-dispatch preparation까지 actual strict reload됐고 non-executing admission이
   exact compact request와 prerequisite lineage를 다시 결박한다. 다음은 외부 one-call authorization,
   durable single-use CAS, live descriptor-to-volume attestation, additive compact receipt/runtime이고,
   이 네 gate와 별도 승인 뒤 새 invocation Run에서
   정확히 한 번 시도한다. fallback 진단이나 Permit 발급은 없다.
3. [ ] **WEB-008 governed Campaign topology 연결** — discovery Worker, model invocation Run,
   compiled proposal을 source/validation 전의 정식 stage로 추가한다. 두 fresh-login 실행은
   같은 compiled-plan digest를 독립적으로 재해석하고 각각 별도 승인·single-use Permit·
   Gateway·Worker를 거친다. 현 v1alpha1 호환 단계에서는 세 진단을 모두 code-owned
   위상 순서로 실행하며, LLM rank는 실행 권위가 아니다.
4. [ ] **WEB-009 가변 진단·재계획 v2** — validation/local-result/semantic/promotion/Graph/PoC
   계약을 함께 version-up해 LLM이 allowlisted 진단의 subset·의존성·추가 evidence 요구를
   제안하고, compiler가 dependency closure와 실행 순서를 결정하며, 실행 결과를 새 Snapshot으로
   되돌려 LLM이 재계획하는 루프를 완성한다.
5. [ ] **WEB-010 독립 증명·공격 경로·보고 완성** — 신선한 account/session/Permit의
   independent replay와 controls/oracle를 통과한 candidate만 Finding으로 승격한다. 공격 경로를
   Graph 관계로 입력하고, 모델 서술은 구조화된 결정론적 결과의 비권위 설명으로만
   보고서·SARIF·redacted 독립 PoC에 투영한다.

## 신규 우선 구현 목표

1. [x] **WEB-003 정확한 loopback browser 평가** — 명시적 `--authorized-local-lab` 확인을
   30분 이하의 exact plan/origin 권한에 묶고, 폐기형 Chromium에서 정상 UI 로그인과
   search/contact/about 탐색을 수행한다.
2. [x] **세 진단과 대조군·Replay** — SQL login true/false, 다른 평가 계정 basket 접근,
   외부 전송 없는 DOM marker를 각각 source/replay로 실행하고 대조군을 함께 기록한다.
3. [x] **공격 경로·영향·봉인 보고** — 로컬 issue 세 개를 두 attack path로 연결하고
   비밀번호·session token·원문 body/DOM을 제외한 JSON·Markdown·스크린샷과 요청 hash를
   RunStore에 봉인한다. 이 결과는 PAJIN Finding·Graph·외부 전달 권위가 아니다.
4. [x] **실제 Juice Shop 검증** — 19.2.1의 실제 UI/HTTP 경로에서 세 진단과 두 경로를
   재현하고 browser 종료·Run 무결성을 확인했다. 실패 시도와 생성된 로컬 평가 계정은
   삭제 승인 없이 보존한다.
5. [x] **WEB-004 Campaign/Capability 준비와 권한 계보** — local authorization에서 core
   `CampaignManifest`를 만들지 않고 exact plan/scope와 향후 승인 요건을 비실행 Campaign 초안에
   결박한다. code-backed browser Capability/Profile/Plan은 로그인 상태 변경을 보수적으로
   `irreversible-write`·cleanup-required로 분류하고 모든 실행 권위를 false로 유지한다.
6. [x] **인증형 수동 discovery와 추가 진단** — 새 browser context에서 정상 로그인 뒤
   query-free route와 값 없는 form 구조만 bounded BFS로 수집한다. 고정 GET-only security-header와
   FTP-listing source/replay를 추가하고 raw DOM·추가 진단 응답 본문·추출된 listing 항목·
   자격증명은 보존하지 않는다. 로그인 후 discovery phase는 GET/HEAD만 허용한다.
7. [x] **로컬 관찰 봉인·검증·중립 Graph 제안** — WEB-003 source를 caller-pinned Run/root로
   다시 검증하고 code-owned semantic oracle, 두 attack path, discovery, 추가 진단을 결정적 보고로
   봉인했다. Graph 출력은 `sealed-source-authority` Observation/Hypothesis proposal뿐이며
   Capability/Permit 실행 계보, admission·Finding·SARIF·외부 전달은 없다.
8. [x] **서명된 governed local 실행과 독립 Finding** — 인증된 core Campaign, 배포 inventory의
   lifecycle activation과 Grant, fresh operator approval, durable T2 Permit 소비, host-loopback
   Gateway/Worker, SecretBroker, 독립 executor/target attestation, Graph single-writer admission,
   Finding·공격 경로·보고서·SARIF·redacted PoC를 exact Juice Shop adapter에서 구현·실증했다.
9. [ ] **WEB-006 closed profile·진단 catalog·동일 context discovery 증거** — production registry가
   exact `juice-shop-local/v1`/`http://127.0.0.1:3000`만 선택하고 Worker가 구현을 독립 재해석하도록
   연결한다. 로그인한 같은 Playwright context에서 GET/query-free/bodyless/no-redirect discovery를
   phase 20·전체 100 request 한도 안에 수행하고 per-request receipt·proposal-only sidecar를
   Result/seal/strict loader/report에 결박한다. discovery-only 실제 Run과 strict reload는 통과했지만,
   새 full governed 실행과 PoC 재실행까지 통과해야 완료로 전환한다.
10. [ ] **WEB-007 local LLM 비실행 proposal** — exact sealed discovery와 frozen comparison-plan
    Run을 독립 anchor로 다시 열고, model-visible projection만 단 한 번 local Provider에 전달한다.
    schema/parser/compiler와 terminal failure 증거는 구현·검증했지만 실제 호출은 30초 upstream
    timeout으로 draft 없이 끝났다. versioned transport pin과 새 image 검증 뒤 승인된 successor
    시도는 exact 요청 `88,496`이 Campaign `65,536` 한도를 초과해 dispatch 전에 종결됐다. 이 요청
    예산은 이제 model 시작 전에 검사한다. pinned tokenizer/template 측정상 legacy full request는
    `5,232 > 4,096`으로 비실행 가능하다. additive compact wire의 최종 5-artifact offline proof는
    `2,484 <= 4,096`, margin 1,612와 Campaign `51,168 <= 65,536`을 독립 재계산·strict reload했다.
    non-executing admission은 exact preparation과 compact request를 다시 결박한다. 외부 one-call
    authorization·durable CAS·live model attestation·additive compact runtime/receipt와 별도 사용자
    승인 아래 새 Run의 성공 proposal·strict
    reload·latency/memory 측정 전까지 완료로 표시하지 않는다.

## 현재 순차 구현 목표

1. [x] **완료분 원격 검증** — OPS-005 검증 정책을 맞추고 승인된 논리적 commit/push 후
   `39c66a2` 같은 SHA에서 일반 CI 8,675 passed·76 skipped와 Web·Network·AI·OPS·SYS 실증/독립 cleanup을 확인했다.
2. [x] **EFFECT-007 후보·독립 평가 구현** — 새 미사용 384응답에서 v5/v6 FP 72→44·FN 7→7,
   정밀도 56.10→67.65%·재현율 92.93% 유지다. **CPU·종합 기준은 미달**이며 기본 v1을 유지한다.
   독립 설치 패키지의 봉인 결과 재계산과 동결 입력 보존·실제 runtime 정리를 확인했다.
3. [x] **GRAPH-PERF-006 메모리·과거 조회 비용** — 전체 검증을 유지하고 전후 각 72개 Linux 조합을
   검증했다. 큰 이력 cold 두 reader의 과거 조회 RSS 1,114.3→976.8 MiB·반복 8.0919→0.2929초다.
   **최초 지연과 current-page 반복은 증가**했다. 모든 조건과 최초 미완료 시도를 계약에 기록했다.
4. [x] **UX-014 검토 업무 필터·이력 후속 처리** — 담당자·미확인·상태 필터를 API와 Console에
   연결했다. 알림 확인은 별도 감사 기록에 저장하고 200회 한도의 원본을 보존하는 후속 검토를
   구현했다. API·실제 browser·schema 17의 TLS PostgreSQL 69개 검사를 통과했다.

## 직전 구현 체크포인트

1. [x] **EFFECT-006 후보·독립 평가 구현** — 새 v5·미사용 평가군·성공 기준을 호출 전에
   동결하고 동일한 실제 384응답의 정밀도·재현율·CPU를 비교했다. **오탐 감소 목표는 미달**이다.
   v4/v5 모두 FP 62/FN 0, 기본값 v1 유지, 소비한 평가군은 재사용하지 않는다.
2. [x] **GRAPH-PERF-005 조회 비용** — 전체 이력·원본 bytes·schema·chain/head·변조 검증을
   유지하며 중복 직렬화를 줄였다. Linux 독립 process의 전후 최초/반복 조회·CPU·RSS를 측정했고
   큰 이력 최초 지연은 약 19~21% 줄었다. RSS·반복 지연의 일관된 개선은 확인하지 못했다.
3. [x] **OPS-005 독립 복구 증명** — enrollment·서명·witness-first publication·중단 후 차단·
   한쪽 rollback 거부·원본 보존 재구성을 구현했다. 최신 source/image가 일치하는 격리 Linux에서
   21개 검사와 실제 SIGKILL 뒤 32회 새 process 검증을 통과했다. 물리 host 실증은 남는다.
4. [x] **UX-012 Campaign·Graph 이력 탐색** — 등록된 여러 Campaign과 검증된 과거 Snapshot의
   API·Console을 연결하고 실제 브라우저에서 탐색·인증 전환·오프라인 복구를 검증했다.
   과거 결과에는 실행·현재 권위를 부여하지 않고 기존 단일 Campaign API를 유지했다.
5. [x] **UX-013 검토 배정·내부 알림** — 명시적 담당자·변경 이력·개인별 알림·확인을 구현하고
   실제 배정→수신→확인과 역할·용량·동시성 회귀를 검증했다. 기존 승인·Finding 경계를 유지했다.

체크 표시는 각 slice의 코드·검증 작업 완료다. EFFECT-007의 CPU·종합 기준 실패와 물리 운영 실증,
Graph 최초 지연/current-page 반복 비용, 일반 queue·외부 알림은 별도로 남아 있다.

별도 Linux 물리 호스트는 아직 준비되지 않았다는 기존 선택을 유지한다. 실제 cross-host 장애
전환·운영 배포·장기 운영 보증은 해당 환경과 별도 승인 후 검증한다. 이번 격리 검증을 그 증명으로
표시하지 않는다. 네 항목의 구현·테스트·문서와 기존 완료분 commit/push·원격 검증은 승인됐다.
운영 배포·merge·tag·외부 알림 전송은 승인 범위에 포함하지 않는다.
main에서 직접 작업하고 branch/worktree를 만들지 않는다.

## 제품 목표와 현재 지원 범위

PAJIN은 9개 Security Domain을 하나의 Canonical Graph와 Capability authority model로 다루는
정책 기반 보안 분석·검증 플랫폼을 지향한다. 도메인 등록, 준비 모델, 외부 서명 증거의 검증,
실제 실행과 분석 효과를 각각 구분한다. 등록된 도메인 수는 지원 완료나 탐지 성능 지표가 아니다.

| 영역 | 현재 구현 범위 | 남은 제품 경계와 계약 |
| --- | --- | --- |
| 공통 엔진·Capability·Graph | CAP-001~006, GRAPH-001~006, legacy Profile 호환과 명시적 실행 gate | 기본·분산 실행으로 자동 확대하지 않음. [Capability](docs/capability/), [Graph](docs/graph/) |
| Hybrid·협업·Supervisor | 제한된 WALK/CHAIN, MEM/HANDOFF, 검증된 proposal·invocation·approval·Permit | model output·metadata 자체는 실행·Finding 권위가 아님. [오케스트레이션 계약](docs/orchestration/) |
| Pentest·Red Team | 승인된 GET Recon/Replay/Controls, 기존 KISA LLM/RAG와 고정 Web/MCP lab | 임의 대상·일반 보안 진단 전체 지원 아님. [Pentest adapter](docs/orchestration/PENTEST-004C2B2-concrete-child-deployment-adapters.md) |
| Web/API | typed discovery/admission, 고정 SQLi 측정·Replay·Controls·product read, [WEB-003](docs/orchestration/WEB-003-exact-loopback-browser-assessment.md)의 고정 browser 평가, [WEB-004](docs/orchestration/WEB-004-bounded-authenticated-browser-campaign.md)의 비실행 Campaign 준비·passive discovery, [WEB-005](docs/orchestration/WEB-005-governed-local-authenticated-browser-campaign.md)의 signed Campaign/activation/Grant·Permit·Gateway·독립 Worker·Graph admission·Finding 3건·attack path 2건·보고서·SARIF·local PoC, [WEB-006](docs/orchestration/WEB-006-installed-profile-and-authenticated-discovery-evidence.md)의 closed profile·진단 catalog·동일 인증 context bodyless discovery 증거, [WEB-007](docs/orchestration/WEB-007-llm-assisted-web-analysis-proposal.md)의 봉인 discovery 기반 local LLM 비실행 proposal 경계·attested Capacity v2·zero-dispatch live preparation·non-executing compact admission, [SKILL-001](docs/orchestration/SKILL-001-versioned-analysis-skill-registry.md)의 catalogued-only 분석 Skill 5개, [SKILL-002](docs/orchestration/SKILL-002-proposal-only-selection-and-split-projection.md)의 exact proposal-only selection·split projection·zero-dispatch 준비 Run | production 실행 inventory는 exact `127.0.0.1:3000`의 `juice-shop-local/v1` 하나다. Skill consumer는 compact admission까지 연결됐지만 live authorization·durable claim·live model attestation·Provider·Recipe·Capability·Worker에는 연결되지 않았다. WEB-006 전체 governed 재검증과 WEB-007 실제 성공 proposal은 진행 중이다. 임의 사이트·SSO/MFA/CAPTCHA·가변 진단 cardinality·generic payload·container/remote target Worker·trusted egress receipt·외부 전달은 아님 |
| Network | 서비스 Surface·준비·증거 admission와 합성 6-case 측정 | raw socket·일반 스캔·서비스 취약점 확정 아님. [NET-002D](docs/orchestration/NET-002D-bounded-network-measurement-product-read-and-conformance.md) |
| AI | 고정 M03 source·독립 Replay 2개·Controls 3개·product read, 별도 실제 모델 효과 평가 | 임의 모델·agent 안전성이나 일반 Finding으로 확장하지 않음. [AI-002D](docs/orchestration/AI-002D-bounded-ai-measurement-product-read-and-conformance.md) |
| Cloud | CLOUD-001A~D의 준비·서명 증거 admission·정책 비교·fixture 요구 | 실제 provider·credential 사용 runtime, 정책 translator·live benchmark 필요. [CLOUD-001D](docs/benchmark/CLOUD-001D-fresh-credential-policy-replay-disposable-fixtures.md) |
| System | SYS-001A~D 계약, SYS-002의 실제 mTLS OS-release 읽기·재실행·독립 확인과 SYS-003 Operator API/Console의 고정 결과 조회, SYS-004의 승인된 커널 ASLR 고정 읽기·독립 CLI 조회 | SYS-002는 격리 container userspace, SYS-004는 guest kernel 설정 한 값이다. 일반 host 실행과 [SYS-001D](docs/benchmark/SYS-001D-system-replay-disposable-host-fixtures.md) 전체 conformance는 별도다. |
| Application | APP-001A~D 준비·admission과 APP-002의 승인된 offline ELF64 헤더 실행·재실행·보고 | APP-002는 POSIX custody·Linux Docker의 한 읽기 기능만 지원; 일반 parser/동적 실행은 닫힘. [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md) |
| Mobile | MOBILE-001A~D의 package/static 분석 준비·증거 admission·비교 | 실제 parser·emulator/device·device-bound profile conformance 필요. [MOBILE-001D](docs/benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md) |
| Cryptography | CRYPTO-001A~D의 준비·서명된 재계산 증거 검증·중립 비교 | 실제 분석·semantic Oracle·수치 측정 필요. [CRYPTO-001D](docs/benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md) |
| Forensics | FORENSICS-001A~D의 provenance·증거 admission·parser 비교·요구 등록 | 실제 source/parser·custody·semantic 정확도·측정 필요. [FORENSICS-001D](docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md) |

DOMAIN-001~006의 분류·Graph semantics·Capability projection·Worker profile·cross-domain admission·
metric registry는 구현됐다. 각 registry의 false authority와 `required`/`not-applicable` 구분을
유지한다. Phase 0~25는 위 제한된 계약들의 완료 이력이며, 새로운 일반 도메인 실행 승인이 아니다.

## 후속 범위의 선정 기준

이번 목표 밖의 일반 도메인 확장·운영 배포·물리 장애 실증은 별도 선정한다. 도메인 기본
우선순위는 Web·AI, Network·Cloud·System, Application·Mobile, Cryptography·Forensics다.
기존 자산 재사용, 독립 Ground Truth, read-only first slice와 검증 가능한 isolation을 기준으로
재평가한다. 하나의 변경에 독립 도메인 runtime을 혼합하지 않는다.

## 미결정 사항

- legacy `CapabilityDefinition.domain` deprecation과 code-owned projection의 review/version 절차
- Surface locator registry의 publisher/review 권위와 Worker profile의 배포 서명·conformance 권위
- 도메인별 수치 artifact·aggregator·Ground Truth admission과 실제 provider/custodian 선정
- Network raw-socket, System privilege, Mobile device, Forensics custody의 최초 운영 범위
- production Graph Event Store, cross-host fence와 independently anchored evidence
- [UX-007R1](docs/orchestration/UX-007R1-aws-s3-production-custody-selection.md) 이후 production pilot

## 변경별 완료 기준

각 slice는 Task ID, 변경되는 Trust Boundary, schema/API version, 호환성, migration·rollback,
positive/adversarial test, audit/evidence lineage와 benchmark 영향을 명시한다.

- Discovery·model output·Domain metadata로 Scope·Capability·Permit을 확장하지 않는다.
- 기존 Policy/Approval → ActionPermit → Gateway/Worker → Evidence → Graph 경로를 유지한다.
- exact retry는 소비된 Action을 재실행하지 않으며 불확실한 결과는 보수적으로 남긴다.
- Finding은 Profile별 독립 Replay·validation floor를 충족하고 사람 판단과 구분한다.
- 관련 pytest, Ruff, Linux strict mypy, 필요한 packaging·실제 사용자 경로를 검증한다.
- 최종 통합은 같은 소스의 전체 회귀와 변경 경로별 conformance를 확인한다.
- 미실행 검증·환경 제한·미커밋 변경을 `HANDOFF.md`와 `KNOWN_ISSUES.md`에 정확히 남긴다.

## 현재 실행 체크포인트

- WEB-003 실제 Run은 OWASP Juice Shop 19.2.1에서 authenticated page 8개, HTTP Evidence 70개,
  로컬 재현 issue 3개와 검증된 attack path 2개를 만들었다. 12 artifact·2 event의 seal을
  독립 검증했고 비밀번호·session token 문자열은 결과물에 없으며 browser는 종료됐다.
- WEB-003 집중 pytest 7개, 구현 Ruff, Linux strict mypy와 새 sdist/wheel이 통과했다. 전체 suite는
  8,791 passed·76 skipped·11 failed였고, 열 건은 sandbox의 loopback listener 권한 제한으로 분류해
  허용된 환경에서 모두 통과했다. 나머지 생성 dependency export 불일치는 root lock에 맞게 갱신한 뒤
  deployment 19개로 검증했다. 갱신 뒤 전체 suite는 반복하지 않았다. 원격 CI·clean checkout·다른
  Juice Shop 버전/브라우저/IPv6·일반 사이트는 아직 검증하지 않았다.
- WEB-004 최종 실제 outer Run `run_20260914T061252Z_7ce5c4cc`는 WEB-003 source
  `run_20260914T061252Z_c4169751`, locally reproduced issue 3개, locally validated attack path 2개,
  authenticated passive route 8개·form 2개·discovery Evidence 75개, 추가 진단 2개·Evidence 6개를
  결박했다. outer Run은 14 artifact·2 event, root
  `d85be14c03b80aa8fa0c334b5ae6a9fe0578dd136686a233630c43cf2e388670`로 봉인했고 explicit Run/root
  strict reload가 valid를 반환했다. 권한 재설계 확인 Run과 종료 경고 수정 확인 Run은 각각 계정
  1개를 남겼으며 이전 계정도 삭제하지 않았다. 현재 총계는 추정하지 않는다.
  lifecycle/Permit/Gateway/Graph admission/Finding/SARIF/외부 전달은 수행하지 않았다.
- WEB-005 실제 parent Run `run_20260915T053508Z_00f5d91c`는 source/validation Gateway 2회와
  서로 다른 observer/executor subprocess 4개를 거쳐 source Run `run_20260915T053508Z_dc97107d`,
  validation Run `run_20260915T053508Z_da341040`, validation projection Run
  `run_20260915T053508Z_c274888d`를 결박했다. Graph event 9개, independently confirmed Finding
  3건과 attack path 2개, report/SARIF/PoC/delivery-readiness를 만들었고 별도 process strict reload가
  통과했다. redacted `reproduce.sh`도 새 root에서 전체 흐름을 다시 실행해 동일 count를 만들고
  parent Run `run_20260915T054048Z_8111d682`로 strict reload됐다. 두 실행 모두 자격증명·private key를
  저장하지 않았고 외부 전달을 수행하지 않았다. 생성 계정과 server-side session은 보존한다.
- WEB-006 구현은 production profile/adapter/diagnostic catalog, Worker-side implementation
  재해석, 같은 authenticated Playwright context의 passive discovery, phase 20·전체 100 request 한도,
  bodyless per-request receipt와 `discovery-evidence.json` Result/seal/strict-loader/report binding을
  연결하고 있다. production inventory는 여전히 exact Juice Shop 한 개이고 discovery는
  `proposal-only`다. 실제 discovery-only Run `run_20260915T142836Z_95615cb9`와 root
  `7a9de15039883dc483caad6d9a3f84f5e1d76745bc10285986fbe741b939bb50`는 strict reload됐지만
  이전 WEB-005 Run은 새 full governed 경로의 실행 근거로 재사용하지 않는다. redacted PoC replay와
  full governed actual, 비밀정보 검사 및 확장 Web 회귀는 아직 남았다.
- WEB-007 projection
  `web-analysis-projection:457f025e3dc64d1e996095f7bc4638b706c1ae87b80728931257f7caeb6449b0`은
  위 discovery-only source에서 생성됐고 target/source anchor·credential 원문을 Provider에 보내지
  않았다. Qwen3 4B Q8 실제 호출은 정확히 한 번 dispatch됐으나 30초 upstream timeout으로 끝났다.
  Provider Run `run_20260915T160850Z_ee8ac5d7` root
  `e8912d387f7e160cffd3b1ce9e4444850c9ce2cb2b7d3542348b1a2ac7f22b68`와 analysis Run
  `run_20260915T160850Z_7ffb7521` root
  `9a8121d756589d93e7b7bee9b201f55fffe95b6efa04bccc22f1bc29f442101e`는 terminal failure로
  strict reload됐다. draft/compiled proposal/target request/Permit/Finding/Graph/report/SARIF/PoC/
  외부 전달은 없고, 이 실패 Run의 redispatch는 금지된다. focused 214개, 확장 Web 1,003개와
  문서 4개 검사는 통과했고 opt-in real-Docker WEB-002D 한 건만 skip됐다. additive compact
  `system+user` wire의 attested Capacity v2 Run `run_20260921T052042Z_0932a478`, root
  `d7864c15b7df572294fae99dfe65516543ac82672faab3ca84a53b1c47d8a574`는 exact model
  materialization과 prompt 1,460·total 2,484·context margin 1,612·Campaign 51,168/65,536을 봉인했다.
  proof-bound preparation Run `run_20260921T052213Z_801a9053`, root
  `c2b77fd6a1b70fcf60fb13d5b3c8a4d436cfc219f8868c6dedb572009dd010d5`도 strict reload됐다.
  completion·Provider dispatch·target request는 0회다.
- `39c66a2`의 일반 CI와 Web·Network·AI·OPS·SYS를 모두 확인했다. 당시 새 소스의 결과와 구분한다.
- EFFECT-007 실제 모델 비교는 실패 없이 완료했다. 품질은 개선됐고 CPU는 증가했다. 소비한 평가군은
  다시 호출하지 않는다. 공개 결과는 EFFECT-007 계약, 봉인 원문은 private 근거에 보존한다.
- GRAPH-PERF-006의 실제 Linux 전후 각 72그룹과 독립 결과 대조·정리를 완료했다. 메모리와 반복
  과거 조회는 개선됐고 최초/current-page 반복은 느려졌다. 다른 무거운 검증을 시간 측정과 겹치지 않았다.
- UX-014의 API·JS·실제 browser 흐름과 schema 17의 실제 TLS PostgreSQL 69개 검사를 통과했다.
- WEB-005까지의 최종 미커밋 통합 상태에서 전체 9,046개를 다시 실행해 8,970 passed·76 skipped·실패 0을
  확인했다. skip은 opt-in Docker/live/PostgreSQL 환경 경로다. Ruff 전체 lint와 CI에 선언된 세
  Linux strict mypy 명령(527·15·2 source), 새 sdist/wheel도 통과했다. 이 수치는 WEB-006 변경의
  전체 회귀 또는 실제 browser 검증 결과가 아니다.
- 2026-09-20 최종 인수인계 tree의 전체 suite는 sandbox에서 10,157 passed·293 skipped와 loopback
  bind 권한 실패 10건으로 끝났다. 실패한 네 파일은 loopback 허용 경계에서 38 passed였고 관찰된
  코드 회귀는 없다. Ruff, 세 strict mypy, lock check, compile, package build, 문서 정책과 diff check도
  통과했다. 새 SHA의 원격 CI는 push 뒤 별도 상태로 확인해야 한다.
- 현재 변경의 논리 commit/push는 승인된 인수인계 단계에서 수행한다. 새 SHA의 원격 CI 결과가
  생기기 전에는 기존 완료분의 원격 결과를 재사용하지 않는다.
- private 작업 근거는 `.pajin/four-followups-20260912/`, 재개 절차와 상세 상태는 `HANDOFF.md`에 있다.
