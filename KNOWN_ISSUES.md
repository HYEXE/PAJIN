# PAJIN 알려진 문제

재현된 미해결 제약만 기록한다. 비밀정보의 실제 값과 추측성 백로그는 기록하지 않는다.
로드맵 작업은 `PLAN.md`에서 관리한다.

## Windows managed Artifact POSIX durability

- 2026-08-24 Windows 전체 pytest에서 managed Artifact/Replay 152건은 POSIX directory `fsync`, Worker
  status/resume 28건은 secure `dirfd`, integrity 4건은 비이식 파일명·symlink 제약으로 실패했다.
- Ubuntu CI run `33316840636`(commit `051cad4`)은 Quality·24/24 shard, `7,609 passed, 69 skipped`로
  성공했다. 따라서 위 실패는 Windows-local 제약으로 구분하며 보안 정책을 우회하지 않는다.

## UX-007B-R deployment validation limits

- Worker TLS는 bearer subject/SPKI에 결박하고 proxy header를 거부한다. 관리형 Windows 환경의 TLS
  interception으로 제한되는 live handshake는 host security policy를 우회하지 않고 Linux에서 검증한다.
- Human ABAC action은 서로 분리된 exact 정책이며 current Approval GET은 비변경 projection이다. unset은
  RBAC compatibility이지 production narrowing 증명이 아니다. Replay Worker token/profile partial은 거부한다.
- UX-007O unknown은 새 작업·successor를 막는다. UX-007P2의 pinned MinIO·boto3 single-node local target은
  WSL에서 실제 TLS/S3 8-case를 통과했지만 production·multi-node 선택이 아니다. UX-007Q는 exact evidence,
  1시간 freshness, append-only revocation/admission과 pre-call gate를 구현했다. 세 store는 단일 transaction이
  아니며 외부 checkpoint 보관이 필요하다. UX-007R1은 AWS S3 Seoul custody 계약만 고정했다. R2 live
  inventory·isolation·restore·cost 승인, 자동 cleanup, cross-host fence·public API는 닫혀 있다.

## PENTEST-001C2~003D Recon·validity Finding 경계

- 보장: signed GET, Observation, 독립 Replay, exact Oracle·세 Control, current Graph `plan` admission과
  validity-only Finding까지 전체 sealed predecessor를 재검증한다.
- 제한: direct-call이며 caller가 signed predecessor와 local Graph·Run authority를 공급한다. cross-host fence,
  generic Finding/API/report와 historical Graph authority는 없다.
- 비권위: 003D는 validity만 confirmed한다. impact·severity는 `not-evaluated-information-only`이고 Graph mutation,
  report·external delivery, Scope 확장, Decision issuance와 추가 execution은 계속 닫혀 있다.

## PENTEST-004A~C2B2 실행·조정 경계

- 보장: compile은 signed 입력, Recon은 deployment·현재 authority·direct-mTLS를 재검증한다. workflow는 봉인된
  source·Replay·세 Control과 외부 서명 current-Graph finalization만 validity-only local report로 조합한다.
  004C2B2는 server-owned child registry, concrete child adapter, direct-mTLS 재검증과 restart reload를 제공한다.
- 제한: registry 자동화, distributed Worker queue와 cross-host fence는 없고 host-local filesystem 권한이
  deployment TCB다. CLI는 누락 권위나 다른 Security Domain 실행 권위를 만들지 않는다.

## REDTEAM-001/002·UX-008 경계

- A/B는 LLM/RAG, C는 단일 synthetic Web endpoint, D는 network-disabled fixed MCP Tool만 실행한다.
- REDTEAM-002는 sealed raw Observation에서 metric과 explicit `not-applicable`을 집계한다. fixture는
  production score가 아니며 adapter가 source lineage를 책임진다.
- UX-008은 이를 Scope·Evidence·no-Finding·measurement view로 투영한다. Campaign Scope·PROF-001
  mapping·VAL-003·HTTP/UI·delivery와 Finding·Permit·execution 권위는 없다.

## ARCH-002 multi-domain architecture 경계

- DOMAIN-001~006 registry는 일반 runtime 권위가 아니다.
- WEB-002A~D/UX-009A~D는 단일 synthetic Web measured validation/product만 완료했다.
- NET-002A~D는 exact synthetic six-case Docker conformance만 증명하며 general Network 권위가 없다.
- AI-002A~D는 exact synthetic M03 한 건의 private Ground Truth, disposable source, 두 supporting Replay,
  exact 세 Controls, DOMAIN-006 floor와 public-safe bounded product read까지만 구현했다. Finding과 exact
  Ubuntu real-Docker conformance는 아직 없으며 general AI 권위가 아니다.
- registry, cross-domain edge와 fixture는 Domain 지원 완료 증거가 아니다.

## UX-006B authenticated external delivery 경계

- 보장: exact export·registered sink·authorization·one-use lease·stable key를 dispatch 전 journal에 결박한다.
  unknown은 자동 재전송하지 않고 authenticated `not-received` 뒤 한 번만 재시도한다.
- 제한: process-local registry·single-host journal·shared request/response secret이다. distributed exactly-once·
  backup·failover와 egress·expired authorization 복구는 deployment 밖 책임이다.
- 비권위: receipt는 endpoint acceptance만 증명하며 generic CLI/API·worker·vendor adapter가 없다.

## UX-006A local SARIF export 경계

- 보장: exact sealed Run/root의 independently confirmed Finding만 minimized SARIF로 private local write한다.
- 제한: reviewed prose를 자동 판정하지 않으며 local file은 delivery/receipt가 아니다. 외부 전달은 UX-006B를 쓴다.

## UX-005A queue 경계

- 보장: approval을 rollback-only 재검증한 redacted queue다.
- 제한: assignment·notification·SLA가 없고 GET은 action하지 않으며 action은 재인가한다.

## UX-004A/B coordinate comparison 경계

- 보장: KISA durable Replay와 exact WALK VAL-004C를 별도 Operator API/UI에서 검증한다. UX-004B는 sealed
  predecessor를 다시 열며 각 view는 lane·cardinality·digest·redaction·false authority를 고정한다.
- 제한: UX-004A Control과 UX-004B Retest는 `not-in-authority`다. 둘을 합성하거나 semantic diff, 새
  validation·remediation·Finding·execution authority로 사용하지 않는다.

## UX-003B durable Graph Decision audit 경계

- 상태/보장: complete canonical `GraphDecision`을 별도 single-Campaign SQLite hash chain에 append한다. read는
  complete Graph history·historical Snapshot binding·audit chain·current Snapshot을 검증하고, 500개 초과는
  거부하며 actor/recorder와 payload를 redaction한다.
- 제한: local SQLite·service-account 통제를 신뢰하며 signed off-host retention, independent anti-rollback,
  multi-Campaign routing, historical browsing·compaction·deletion은 없다. producer가 명시적으로 사용해야 한다.
- 영향/해소: query는 Decision·selection·schedule·approval·Permit·execution authority가 아니다. 외부 rollback
  탐지는 audit head transparency anchor, multi-Campaign은 signed deployment registry가 필요하다.

## UX-003A Hypothesis attention ranking 경계

- 보장/제한: exact current Graph에서 최대 500개를 consistency·confidence·ID로 정렬하고 내용을 redaction한다.
  confidence는 validation truth/risk score가 아니며 selection·Decision·schedule·execution authority는 false다.

## UX-002B current Canonical Graph view 경계

- 상태: 기존 single-Campaign SQLite Graph Store의 exact current Snapshot을 검증하는 Operator-only API와
  same-origin Web Console node/relationship inspector를 구현함
- 현재 보장: schema·Campaign metadata·SQLite integrity, complete Admission Event chain·node index,
  Projection history와 immutable Snapshot chain을 한 read-only transaction에서 검증한다. latest Event prefix와
  current Projection, 요청 Snapshot head가 모두 일치해야 하며 historical/stale/foreign/tampered authority는
  fail closed한다. 500 node·1,000 edge를 넘으면 자르지 않고 거부한다.
- 제한: 한 Control Plane process에 server-owned Graph database 하나만 설정한다. Snapshot listing·historical
  browsing·multi-Campaign registry·automatic reconciliation·full node content/export는 없다. node view는 statement,
  observation value, Evidence reference와 content digest, request/target digest를 redaction한다. local filesystem과
  service account를 신뢰하며 off-host attestation·tenant isolation을 주장하지 않는다.
- 영향: view는 Canonical Graph membership과 relation을 표시하지만 Graph admission·Projection refresh·Snapshot
  capture·Capability·Permit·execution authority를 만들지 않는다.
- 해소 조건: multi-Campaign 운영이 필요하면 caller path가 아닌 별도 signed/durable Graph deployment registry를
  정의한다. content 조회나 historical audit는 독립 authorization·redaction 계약으로 분리한다.

## UX-002A verified Discovery Surface·Wave view 경계

- 상태: exact sealed Hypothesis Run에서 Attack Surface와 Recon→Hypothesis wave를 재구성하는
  Operator-only Control Plane API와 same-origin Web Console panel을 구현함
- 현재 보장: server-owned `PAJIN_CP_DISCOVERY_RUN_ROOT` 아래 canonical Campaign·generated Run ID만
  허용한다. Hypothesis Run, referenced Recon source Run, Surface projection Run의 전체 seal과 root digest,
  Campaign·Snapshot·Surface Set·Plan·Task·artifact identity, 완료 상태와 unique audit event를 대조한다.
  link/junction·path escape, stale/cross-Campaign projection, artifact 변조와 event equivocation은 fail closed한다.
- 제한: canonical Graph Snapshot·node·edge는 포함하지 않고 generic Control Plane Run input/event에서
  추론하지 않는다. raw observation·evidence·Tool result/argument, Capability·Permit·path도 반환하지 않는다.
  local sealed Run과 service-account filesystem 통제를 신뢰하며 off-host attestation이나 tenant isolation을
  주장하지 않는다. Windows에서는 symlink 생성 권한이 없어 link 회귀가 skip될 수 있다.
- 영향: Operator는 실제 sealed Surface와 두 wave를 읽을 수 있지만 view 자체는 Capability·Permit·execution
  authority를 만들지 않는다. Approver·Auditor·Worker는 이 projection을 읽을 수 없다.
- 해소 조건: `UX-002B`에서 기존 canonical Graph Snapshot/admission authority를 exact하게 resolve하고
  재검증하는 read model을 정의한다. 새 Graph store나 inferred edge를 UI 편의를 위해 추가하지 않는다.

## UX-001B3 Campaign Builder compiler handoff 경계

- 보장: Bug Bounty·CTF draft의 verified source와 별도 기존 approval을 기존 compiler에 전달한다.
- 제한: Pentest는 별도 `pentest-compile` 경로이며 두 builder 모두 실행 권위를 만들지 않는다.

## VAL-004B/004C mode-neutral WALK evidence 경계

- 상태: VAL-001 CHAIN-002/005 exact validity Claim에 stateless Baseline·Negative Control·Counterfactual과
  두 exact fresh Replay를 결박하는 adapter와 전체 Profile floor 평가는 구현됨
- 현재 보장: code-owned exact text Control materializer, pre-dispatch Plan receipt, 기존 approval·단일 호출
  Grant·Permit·Gateway·Worker·Run seal을 검증한다. source·두 Replay·세 Control의 Run/root·execution·request·
  Grant·Permit·dispatch·approval·Worker·Run-qualified evidence 좌표는 모두 독립적이어야 한다. 두 Replay
  publication도 서로 달라야 한다. session 필드를 만들지 않고 exact one-field text schema와
  `sessionPolicy=stateless`를 명시한다. Control publication은 원 execution evidence를 byte-exact하게 다시
  봉인한다.
- 제한: CHAIN-001/003/004, sessionful Tool, impact·severity, Profile 선택, Campaign 변경,
  실행·confirmation·Finding authority는 지원하지 않는다. 모든 증거는 PAJIN-local sealed Run이다.
- 영향: `ctf`, `bug-hunt`, `pentest`, `ai-assessment` floor를 exact sealed WALK evidence로 평가할 수 있다.
  KISA VAL-004A evidence와 혼합하지 않는다.
- 해소 조건: 지원 Chain·Tool schema 또는 Claim ceiling을 넓힐 때 각각의 exact executed predecessor와
  독립 evidence admission authority를 추가한다.

## VAL-003 Profile별 assurance floor 경계

- 상태: exact PROF-001 Profile별 최소 VAL-002 validation depth, KISA evidence와 VAL-001 WALK의 세 depth
  충족 판정은 구현됨
- 현재 보장: complete registered Profile·Profile digest와 complete registered Validation depth
  requirement·ordinal·digest를 하나의 content-addressed policy로 고정한다. `ai-assessment`는
  `repeated-controlled-validity-replay`, `bug-hunt`·`pentest`는 `controlled-validity-replay`, `ctf`는
  `single-validity-replay`를 최소로 요구한다. unknown Profile·depth, stale catalog, mapping·ordinal·digest
  치환과 boolean 권위 상승은 fail closed한다.
- 제한: floor mapping 자체는 code-owned 제품 정책이며 Profile 설명 문구에서 추론한 validation 증명이 아니다.
  `VAL-004A`는 KISA M03·M06·A04, `VAL-004B/004C`는 VAL-001 stateless WALK MCP evidence만 읽는다.
  Profile 선택, Campaign 변경, impact·severity, 실행·confirmation·Finding authority는 없다. v1 Claim
  ceiling은 validity다.
- 영향: KISA와 현재 VAL-001 WALK evidence는 각각 등록된 세 depth를 평가할 수 있다.
- 해소 조건: Profile floor나 Claim ceiling을 변경할 때 code-owned policy와 해당 evidence evaluator를 함께
  version-up한다.

## VAL-002 validity-only 요구 정책 경계

- 상태: 단일 validity Replay, 세 Control 결박, 최소 2회 repeated controlled Replay의 mode-neutral depth
  catalog·Profile floor, KISA 충족 판정과 VAL-001 WALK의 세 depth 판정은 구현됨
- 현재 보장: exact 세 depth·ordinal·Claim/Control 요구·최소 반복·fresh lineage, exact ordered
  `fresh-session`·`stateless` 격리 정책과 false authority marker를 content-addressed policy로 고정한다.
  `preserve-scenario-session`, 부분·역순·추가 session policy, unknown alias, 순서·요구·digest 치환과
  boolean 권위 상승은 fail closed한다.
- 제한: v1 Claim ceiling은 validity다. `VAL-004A` KISA evidence는 explicit fresh session을 사용하고
  `VAL-004B` WALK evidence는 exact stateless Tool schema를 사용한다. 최소 2회는 별도 fresh Replay여야 하며
  Control 실행으로 대체할 수 없다. impact·severity, 실행·confirmation·Finding authority는 없다.
- 영향: 두 exact WALK-005B2 Replay와 세 Control이 모두 독립일 때 registered repeated-controlled depth를
  증명한다. 일부 증거만 있으면 하위 depth로 제한되거나 floor 평가가 fail closed한다.
- 해소 조건: impact·severity 등 validity 밖 Claim을 도입할 때 별도 requirement version과 독립 evaluator를
  추가한다.

## VAL-001 CHAIN-002/005 전용 fresh validity Replay 경계

- 상태: exact sealed WALK-005B2 validity Claim Replay를 CHAIN-002/005에 mode-neutral하게 결박하는 첫
  수직 슬라이스는 구현됐고 추가 실행·재실행·Finding confirmation은 닫힘
- 현재 보장: Chain과 Replay를 각 기존 verifier/loader로 다시 검증하고, 동일한 WALK-003 Run root·artifact·
  hypothesis authority를 공유해야 한다. exact validity Atomic Claim과 fresh approval·Grant·Permit·dispatch·
  Worker·evidence·Replay publication 좌표를 content-addressed binding으로 고정한다. stale/cross-lineage source,
  mutated Replay artifact, Chain·Claim·digest·boolean marker 치환은 fail closed한다.
- 제한: 지원 Chain은 CHAIN-002와 CHAIN-005뿐이다. CHAIN-001/003/004는 executed Candidate·Replay
  predecessor가 없다. reproduced validity Claim은 impact·severity·negative control·counterfactual·N-run 결과나
  full Finding confirmation을 증명하지 않는다. local WALK-005B2 freshness는 별도 off-host 조직의 암호학적
  독립 실행 증명이 아니다.
- 영향: VAL-001 authority는 완료된 Replay 증거 projection이며 재사용 가능한 ticket, approval, Grant, Permit,
  dispatch, Validation Decision, Finding 또는 Report가 아니다.
- 해소 조건: CHAIN-001/003/004는 각 exact Candidate·fresh Replay 경계를 별도로 구현한다. `VAL-002`는
  validity-only 요구를 정의했으며 실제 Control·N-run evidence와 confirmation gate는 `VAL-004` 이후 별도
  authority가 결박해야 한다.

## CHAIN-005 approval-gated Capability 의미 경계

- 상태: MCP Authorization Failure → Privileged Action의 mode-neutral ordered coverage 계약은 구현됐고
  실제 authorization failure·approval·Capability Grant·privileged execution·validation은 닫힘
- 현재 보장: exact sealed WALK-003 Run·artifact·publication과 code-owned authorization rule을 다시
  검증한다. `approvalRequired=true`, `mcp-tool` Surface support, exact threat class와
  `independent-user-approval` control을 가진 full `CapabilityDefinition`만 privileged-action stage로
  결박한다. stale publication, artifact mutation, non-approval Capability, stage·digest·boolean marker 위조는
  fail closed한다. execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: 여기서 privileged는 독립 승인 요구가 등록됐다는 뜻뿐이다. risk tier·side effect는 Capability
  digest에 보존되지만 운영체제 권한, admin access, 데이터 접근, 실제 영향이나 성공한 실행을 증명하지 않는다.
  WALK-003도 실제 승인 거부나 우회가 아니라 authorization-failure hypothesis다.
- 영향: CHAIN-005는 coverage hypothesis로만 사용할 수 있고 approval denial·bypass, Grant, Permit, dispatch,
  Worker outcome, Replay 성공, Finding 또는 Report의 근거가 될 수 없다.
- 후속 조건: `VAL-001`은 exact validity Claim과 fresh Replay 계보만 결박하고 `VAL-002/003`은 요구 depth와
  Profile floor만 정의한다. Finding confirmation에는 승인 경계 negative control과 impact·severity evidence가
  추가로 필요하다.

## CHAIN-004 Target-declared tenant·data Surface 경계

- 상태: Cross-tenant Retrieval → Data Exposure의 mode-neutral ordered coverage 계약은 구현됐고 실제
  selector control·cross-tenant access·retrieval success·data exposure·validation은 닫힘
- 현재 보장: exact version-1 `x-pajin-tenant-retrieval`과 `x-pajin-data-response`만 typed Surface로
  admission한다. tenant retrieval은 같은 operation의 exact `http-rag/retrieval`을 요구하고, data response는
  code-owned data class와 하나 이상의 response content type을 요구한다. 같은 Campaign Target·exact route의
  두 Surface를 sealed Recon·Surface Snapshot에서 다시 검증한다. generic RAG·route, cross-route, 다른
  publication, 변조 projection, forged digest·boolean marker 치환은 fail closed한다. Capability·execution·
  Claim Replay·Finding confirmation은 모두 false다.
- 제한: OpenAPI 확장은 Target이 제공한 선언이다. header·query·body selector 이름은 실제 parameter·schema
  reference에 해석하지 않고, path selector만 exact placeholder 존재를 추가 확인한다. response status code를
  결박하지 않으며 실제 response body나 tenant 값을 관찰·보존하지 않는다.
- 영향: CHAIN-004는 coverage hypothesis로만 사용할 수 있고 tenant isolation failure, 데이터 노출, Finding,
  Report, Permit, dispatch 또는 Replay 성공의 근거가 될 수 없다.
- 해소 조건: validation 상태를 올리려면 VAL-001 이후 exact Claim, 독립 fresh Replay, tenant selector control,
  authenticated request·response evidence와 negative control을 같은 Campaign·Snapshot·Surface lineage에
  결박한다.

## CHAIN-003 Surface-only URL Tool·Internal API 경계

- 상태: Prompt Injection → URL Tool Control → Internal API의 mode-neutral ordered coverage 계약은
  구현됐고 실제 prompt influence·URL dispatch·network reachability·API access·validation은 닫힘
- 현재 보장: MCP top-level JSON Schema의 exact `string/uri` argument와 OpenAPI operation의 exact boolean
  `x-pajin-internal-api: true`만 typed Surface로 admission한다. 같은 Target·MCP server의 prompt와 URL Tool,
  같은 Campaign의 명시적 Internal API를 두 sealed Recon·Surface Snapshot에서 다시 검증한다. generic Tool·
  route, 다른 publication, 변조 projection, forged digest·boolean authority marker 치환은 fail closed한다.
  Capability·execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: advertised prompt argument가 실제로 untrusted text의 영향을 받는지, URL Tool이 invocable한지, URL이
  해석·접속되는지, Internal API가 요청을 수락하거나 데이터를 노출하는지는 관찰하지 않는다. demo
  `inspect_url`은 discovery에만 광고되고 invocation allowlist에는 없다. Internal API 표시는 Target이 제공한
  OpenAPI 선언을 신뢰하며 실제 network 위치나 접근 제어를 증명하지 않는다.
- 영향: CHAIN-003은 coverage hypothesis로만 사용할 수 있고 SSRF, prompt injection, 내부 API 접근, 데이터
  노출, Finding, Report, Permit 또는 dispatch의 근거가 될 수 없다.
- 해소 조건: validation 상태를 올리려면 VAL-001 이후 exact Claim, 독립 fresh Replay, prompt-to-argument
  influence와 network receipt, negative control을 같은 Campaign·Snapshot·Surface lineage에 결박한다.

## CHAIN-002 WALK Hypothesis-only chain 경계

- 상태: File Upload → RAG Injection → Tool Abuse의 mode-neutral ordered chain 계약은 구현됐고 실제 upload·retrieval·Tool abuse·validation은 닫힘
- 현재 보장: sealed WALK-003 Run·artifact·publication과 그 안의 exact WALK-002 Run root·artifact SHA-256·
  Surface Snapshot·RAG Hypothesis를 다시 결박한다. 3개 stage와 2개 edge의 누락·재정렬, Campaign·Target·
  Snapshot·Surface·Run·Hypothesis 치환은 fail closed한다. P0-D2B는 profile identity 의미 대조만 기록하며
  fixture evidence admission, Capability·execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: CHAIN-002가 WALK-002의 원본 Run 경로를 별도로 소유하거나 다시 실행하지는 않는다. WALK-003가
  봉인할 때 검증해 포함한 nested root·artifact authority를 신뢰하며, 실제 문서 업로드·검색·MCP argument
  influence·승인 누락·내부 데이터 접근을 관찰하지 않는다. P0-D2B의 synthetic confirmed Finding은 다른
  Campaign에 일반화되지 않는다.
- 영향: CHAIN-002는 coverage hypothesis로만 사용할 수 있고 Capability Grant, Permit, dispatch, Report,
  benchmark completion 또는 validated Finding의 근거가 될 수 없다.
- 해소 조건: validation 상태를 올리려면 VAL-001 이후 exact Claim, fresh independent execution, negative
  control과 Replay authority를 CHAIN-002 Campaign·WALK Run·Snapshot lineage에 결박한다.

## CHAIN-001 Surface-only AI admin 해석 경계

- 상태: Auth Bypass → AI Admin Surface의 mode-neutral 비실행 계약은 구현됐고 실제 bypass·access·validation은 닫힘
- 현재 보장: exact sealed Recon과 ORCH-001 Surface Snapshot을 다시 검증하고, non-anonymous
  `http-authentication`과 같은 Campaign Target·exact route의 명시적 `http-rag/index-management`만
  content-addressed chain authority로 결박한다. Campaign mode에 따라 분기하지 않지만 exact Campaign digest는
  보존한다. 익명 대안, 다른 route·Target, 비관리 RAG, forged contract·digest, in-memory Recon 변경과 다른
  publication 재생은 fail closed한다. Capability·execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: DISC-003C의 target-declared `x-pajin-rag` 의미와 sealed discovery producer를 신뢰하며 실제 인증 우회나
  관리 기능 접근을 관찰하지 않는다. UI-only admin, MCP admin, provider console과 일반 HTTP admin은 typed AI
  admin Surface가 아니며 URL·설명·이름으로 추론하지 않는다. mode-neutral은 Campaign authority 제거가 아니고
  cross-Campaign replay를 허용하지 않는다.
- 영향: CHAIN-001은 coverage hypothesis로만 사용할 수 있고 Finding, Report, Replay 성공 또는 실행 승인 근거가
  될 수 없다.
- 해소 조건: 다른 AI admin family는 별도 bounded typed locator와 trusted admission을 먼저 추가한다. validation
  상태를 올리려면 VAL-001 이후 exact Claim, fresh independent execution, negative control과 Replay authority를
  chain·Snapshot lineage에 결박한다.

## SUP-008 approved profile의 verifier TCB·network·pricing 경계

- 상태: approval-free T0/T1 `general-attack-v1`과 deployment-approved T2 no-write
  `general-attack-approved-v1`은 구현됐고 T3+·write·network·priced action은 닫힘
- 현재 보장: SHA-256-pinned Capability Graph deployment가 Campaign·Envelope·activation·Graph store,
  managed Run root·Tool registry·Worker와 exact Approval inventory를 소유한다. executor는 strict Job source에서
  Proposal과 intent를 다시 만들고 Job approval을 deployment inventory와 exact-match한 뒤 기존 verifier를
  재사용한다. APPROVAL-001A가 Approval·GRAPH Permit·non-reusable receipt를 원자 소비하고 PERMIT-004A가 durable
  receipt를 authenticated outcome에 결박한다. exact retry, callback 실패와 cancellation은 Worker를 자동
  재호출하지 않는다. missing·forged·expired·cross-authority approval, 비표준 Run ID, T3+, write,
  cleanup-required, networked와 non-zero-cost action은 Permit 또는 Worker 전에 fail closed한다.
- 제한: leased Job admission, Envelope·Decision actor provenance, Grant의 출처, approval verifier code pin과
  deployment-selected Tool/Policy/Worker는 process-local Control Plane/deployment TCB다. durable Approval·receipt가
  future process의 verifier 동일성을 증명하지 않는다. `costMicrousd=0`은 Campaign max cost가 0이고 Definition이
  network를 금지한 profile에서만 사용한다. production inventory는 no-write이고 reversible-write product
  composition, trusted pricing·egress observation과 cross-host fencing은 활성화하지 않았다.
- 영향: Job이 Campaign·Envelope·Run root·activation·Gateway·verifier code를 선택하거나 approval digest만으로
  issuer 권위를 주장할 수 없고 exact retry로 Worker를 재호출할 수 없다. 반대로 운영 deployment가 Job
  admission·Decision·Grant provenance 또는 verifier code를 잘못 신뢰하면 이 profile이 별도 서명 권위를 만들어
  보정한다고 주장할 수 없다.
- 해소 조건: network 또는 priced action을 열기 전에 trusted fixed-point pricing과 egress observation authority를
  deployment 계약으로 고정한다. write를 열기 전에는 production Capability·cleanup Grant/mapping·restored-state
  verifier와 운영 복구 계약을 제품 surface에 결박한다. cross-host 재개에는 durable verifier pin과 fencing이
  필요하며 T3+는 별도 정책 승인 전까지 닫는다.

## APPROVAL-001C3 이후 process-local verifier·host-local journal 제한

- 상태: single no-write, bounded General Attack reversible-write, 2~8개 no-write/reversible async
  coordinator와 명시적 General Attack/Control Plane opt-in runtime은 구현됐고 cross-process verifier pin,
  Control Plane write와 cross-host coordination은 닫힘
- 현재 보장: deployment-pinned full Capability policy registry와 issuer input authority를 approval claim
  전후 검증하고, path-specific writer 아래 approval·ActionPermit·non-reusable receipt를 schema v4 SQLite
  transaction 하나에서 원자적으로 소비한다. General Attack T2 reversible-write는 기존 cleanup input
  authority도 함께 pin·검증하고 approval·ActionPermit·receipt·cleanup reservation을 한 transaction에서
  all-or-nothing 소비한다. General Attack outcome과 Control Plane no-write completion은 durable receipt를
  다시 결박하며 exact retry는 Worker를 재호출하지 않는다. C1은 기존 no-write 단일 승인 2~8개를 별도
  host-local journal에 ordered batch로 결박하고 claim-started와 dispatch-started/unknown을 구분한다. pending
  subset cancellation과 authenticated terminal/manual reconciliation만 허용하며 모든 상태의 redispatch
  authority는 false다. C2는 reversible 항목마다 기존 combined approval·cleanup authority를 재사용해 exact
  cleanup reservation을 callback 전에 결박하고 authenticated restored-state evidence 없이는 terminal을
  허용하지 않는다. C3 General Attack은 별도 batch 메서드에서 current approval·cleanup request를 재구성하고,
  Control Plane은 deployment v1alpha2와 `capability-graph-batch-v1`에서만 no-write batch를 실행한다. Control
  Plane completion은 sealed Gateway audit와 outcome digest를 다시 검증한다. journal local backup/restore는
  전체 logical state를 재검증하며 pending·unknown은 retention deletion 적격으로 판정하지 않는다.
- 제한: policy registry, writer token과 verifier 구현은 process-local deployment TCB다. 동일 DB를 새
  `SQLiteGraphStore`로 열 때 verifier code 자체는 DB에 영속 pin되지 않으므로 trusted deployment가 같은
  verifier와 complete policy inventory를 다시 주입해야 한다. 공격자가 재시작 runtime code를 선택할 수 있는
  환경에 대한 durable verifier identity·anti-rollback 보장은 없다. production inventory에는 실제
  reversible-write Capability가 없고 `capability-graph-v1`, Common Engine, legacy write는 cleanup authority
  composition이 없어 닫혀 있다. journal은 Graph DB와 하나의 transaction이 아니므로 Graph claim 전후
  crash는 보수적으로 manual review가 필요하다. backup manifest는 local integrity wire이며 서명·암호화된
  remote retention이나 anti-rollback 저장소가 아니다. journal 삭제는 구현하지 않았고 cross-host fencing,
  기본 batch workflow와 T3+도 계속 닫혀 있다.
- 영향: 신뢰된 deployment composition 밖에서 DB만 재사용해 승인 issuer를 인증했다고 주장할 수 없다.
  지원되지 않는 실행 형태는 Permit·Worker 전에 fail closed하고 unknown batch item은 자동 재호출할 수 없다.
- 해소 조건: Control Plane 등 다른 runtime에서 write를 열려면 current signed Definition, code-owned cleanup
  mapping, authenticated outcome, CleanupPermit과 restored-state verifier를 같은 수준으로 composition해야
  한다. cross-process verifier pin이나 remote retention이 필요하면 signed deployment inventory 또는
  host-attested activation, encryption과 anti-rollback repository를 별도 계약·ADR로 구현한다.

## PERMIT-004B2 production cleanup composition과 hold recovery 경계

- 상태: authenticated cleanup 경로는 구현됐지만 기본 제품 활성화는 의도적으로 닫힘
- 현재 보장: PERMIT-004A sealed-result authentication core가 managed Run·anchor·Grant·terminal
  lifecycle·Gateway·Worker·evidence와 current CAP-002 role을 Oracle·Handler 호출 전에 exact-rebuild한다.
  `reversible-write + cleanupRequired=true` source만 pre-action ActionPermit+cleanup hold를 원자적으로 확보한
  뒤 실행할 수 있다. code-owned mapping, distinct current cleanup release, current Handler의 단일 typed plan,
  cleanup Executor, fresh ToolRequest·Grant와 hold를 교차 결박하고, 별도 CleanupPermit·audit·reconciliation으로
  기존 Gateway·Worker를 정확히 한 번 호출한다. source identity는 immutable source-evidence seal root를 사용하며,
  deployment-owned Gateway·managed Run·verifier를 gate에 고정하고 stored CleanupPermit과 exact-match한다. sealed
  cleanup success 뒤에도 독립 verifier가 actual target-state digest를 관찰해야 restored로 판정한다.
- 제한: current CAP-005 production inventory에는 reversible-write Capability가 없으며 positive path는 격리된
  synthetic state fixture다. Envelope·Decision provenance, fixed-point pricing, managed Run/Grant, code-owned
  mapping, cleanup Grant와 restored-state verifier의 deployment composition은 명시적 TCB로 남는다. SUP-007A는
  no-write direct-call만 열며 B2 write 경로를 활성화하지 않는다. schema v3 생성 뒤 v2 code로 direct downgrade할
  수 없고 expired·abandoned hold를 자동 release하지 않으며, failed·unknown cleanup도 자동 retry하지 않는다.
- 해소 조건: 실제 reversible-write Capability를 활성화할 때 deployment authority 등록·운영 절차와 Target별
  restored-state verifier를 계약화한다. hold release나 unknown-outcome recovery가 필요하면 restored state를
  추정하지 않는 별도 v3-aware recovery authority, 감사 기록과 export/restore 절차를 정의한다.

## PERMIT-003 외부 Envelope·Decision·비용 권위 경계

- 상태: 기존 Permit bridge는 유지되며 SUP-007A가 별도 direct-call T0/T1 no-write 제품 조합으로 연결
- 현재 보장: complete PERMIT-001/002·ORCH·CAP-001/002 source를 exact-rebuild하고 current signed CAP-005
  activation에서 request를 다시 prepare한다. 외부 authority가 공급한 기존 run-level MissionEnvelope,
  current Graph Decision과 strict-integer cost도 current Campaign authorization/testing window, Envelope
  duration·autonomy·risk·Tool-call·cost·rate ceiling에 감쇠한다. request-unit은 activated Definition에서 직접
  파생하고 외부 호출 뒤 signed activation을 재검증한 다음 exact Capability·Target·Decision payload·Envelope
  budget에 교차 검증해 기존 GRAPH-006 SQLite atomic Permit과 first-consumption dispatcher만 사용한다.
  provider에는 canonical deep-detached predecessor copy만 전달해 gate-owned request·Campaign 변조를 막는다.
  exact retry는 consumer를 한 번만 호출하고 stale Graph는 final transaction에서 거부된다. Campaign-aware
  final claim clock은 provider 지연 중 authorization 또는 testing window가 닫힌 경우도 SQLite consumption
  전에 거부한다. synchronous callback과 외부 authority 운영 실패는 Permit claim 전에 typed fail-closed
  오류로 거부된다.
- 제한: 일반 공격용 verified Envelope producer, Graph Decision actor/provenance registry와 generic trusted
  micro-USD pricing service가 아직 없다. 따라서 `GeneralAttackActionPermitInputAuthority`와 SUP-007A execution
  input authority는 deployment가 공급하는 code-owned 또는 외부-backed TCB이며 그 구현의 잘못된 인증을
  gate가 암호학적으로 보정한다고 주장하지 않는다. SUP-007A는 명시적 direct-call에서만 Gateway, Worker,
  Grant·Run audit과 Success Oracle을 연결하며 default workflow와 cleanup write는 닫혀 있다. Permit callback
  실패는 consumed terminal이고 자동 redispatch하지 않는다.
- 해소 조건: `general-attack-v1` 밖의 profile을 열기 전에 조직이 승인한 Envelope·Decision provenance와
  pricing provider를 고정한다. T2는 기존 approval authority를 필수로 하고 write는 production cleanup
  Capability와 복구 운영 절차가 생기기 전까지 분리한다.

## SUP-004A model input 크기 경계

- 상태: SUP-004B actual invocation 전에 versioned input transport가 필요한 활성 계약 경계
- 현재 보장: complete canonical `SupervisorSnapshotInput`을 하나의 user message로 결박하되 기존
  `ProviderMessage`의 65,536-character 한도를 넘으면 schedule publication 전에 fail closed한다.
- 제한: SUP-002가 허용하는 최대 4 MiB projection은 유효하더라도 SUP-004A의 단일 메시지 request로
  계획할 수 없다. SUP-004A는 shared Provider wire 한도를 조용히 넓히거나 부분 입력을 전송하지 않는다.
- 해소 조건: versioned chunked 또는 content-addressed input envelope를 도입하고 모든 chunk와 순서를 stable
  Worker request ID, reservation, Gateway outcome, Provider result에 결박한 뒤 consumer-side에서 complete
  input을 재구성·검증한다.

## SUP-004B3 host-local journal과 process-local budget 경계

- 상태: 의도적으로 제한된 첫 durable Supervisor invocation 경계
- 현재 보장: 하나의 canonical SQLite journal이 exact SUP-004A checkpoint, deterministic stable request ID와
  preplanned Provider Run을 dispatch 전에 claim한다. started 상태는 자동 재호출 권위를 반환하지 않으며,
  complete two-seal Run이 있을 때만 terminal로 복구한다. consumer는 journal·seal·artifact·event와 Gateway
  evidence, B2 outcome, strict draft, dual budget scope를 재구성한 뒤에만 SUP-003 compiler를 호출한다.
- 제한: alternate journal 파일, database 복제·교체, cross-host dispatcher와 distributed exactly-once는
  보장하지 않는다. SUP-004B1 ledger는 process-local이므로 restart 뒤 receipt가 증명하는 것은 호출 당시의
  conservative charge projection이지 현재 in-memory 잔액이 아니다. final receipt 없는 started 상태는
  수동 검토가 필요하고, Graph current-view 검증과 journal 전이는 별도 transaction이다. 봉인된 Gateway
  evidence도 complete tainted request를 포함하는 민감 artifact다.
- 해소 조건: 다중 host 운영이 필요할 때 하나의 외부 consensus/fencing authority, durable distributed budget
  ledger와 독립 journal checkpoint/backup을 추가한다. 민감 evidence의 원격 보관은 별도 encryption과 access
  control 정책을 적용한다.

## SUP-005B2 host-local Shadow 측정과 proposal 비적용 경계

- 상태: 의도적으로 제한된 첫 model-backed Shadow 수치 비교
- 현재 보장: Target execution 구간 안의 exact B3 completion과 원시 Target evidence를 typed relation digest로
  묶고, 기존 execution receipt와 외부 measurement attestation이 관계를 서명한다. 모든 좌표는 동일한 signed
  registry activation, fresh Harness·Target·Observation, baseline model call 0회와 candidate 1회를 증명한 뒤
  기존 BENCH-003B1 Result·Comparison 계산에만 전달된다. caller aggregate와 generic Observation recorder는
  이 경계의 입력이 아니다.
- 제한: 외부 measurement signer와 host-local registry activation을 신뢰하며 distributed exactly-once를
  증명하지 않는다. proposal은 Shadow sidecar로 Target 동작에 적용되지 않으므로 numeric delta가 proposal
  내용의 causal improvement를 뜻하지 않는다. B3 charged cost는 conservative upper bound, Observation cost는
  externally adjudicated coordinate-total이라 동일값이나 합계로 추론할 수 없다. threshold와 activation은
  계속 false다.
- 해소 조건: production 활성화가 필요하면 SUP-006 adversarial regression 이후에도 별도 threshold,
  Permit·Approval authority를 통과해야 한다. 분산 실행에는 외부 fencing·durable budget·registry
  checkpoint를 추가한다. proposal 적용은 Phase 7 Permit·Approval 경계 밖에서 허용하지 않는다.

## SUP-006 adversarial corpus와 fake Provider 검증 경계

- 상태: 의도적으로 제한된 authority-containment 회귀
- 마지막 재현: 2026-08-05
- 현재 보장: system/developer 역할 위장, taint downgrade, Scope·Plan·TaskGraph mutation, ToolRequest,
  Capability, Permit, execution, threshold, activation과 draft schema escape를 SUP-002~SUP-005B2 경로에서
  검증한다. schema-valid 악성 rationale도 typed proposal과 final measurement lineage에서 digest-only이고,
  invalid output은 outcome-unknown·manual review·no-redispatch로 고정된다.
- 제한: deterministic fake Provider와 fake external measurement adapter를 사용하며 실제 production 모델이
  공격을 무시한다고 증명하지 않는다. corpus는 대표 공격 클래스의 authority containment를 고정하지만
  모든 언어·인코딩·Provider별 prompt injection 표현을 열거하지 않는다.
- 해소 조건: 새 Provider/model revision 또는 input/output schema가 추가될 때 corpus를 확장하고 real-provider
  opt-in conformance를 별도 환경에서 실행한다. 모델 품질과 activation 판단은 별도 threshold authority가
  소유해야 한다.

## SUP-005A/B1/B2/SUP-006 테스트 fixture 결합과 단일 좌표 집중 검증

- 상태: 활성 테스트 유지보수 제약
- 마지막 재현: 2026-08-05
- 현재 보장: SUP-005A/B1/B2/SUP-006 집중 테스트와 BENCH-003·P0-C·SUP-004B3 인접 회귀를 함께 실행한다. B1은 complete
  tuple equality, 누락·추가·재정렬, context equivocation, post-hoc legacy request, cross-Plan, foreign
  invoker·schedule·source와 권위 boolean을 직접 거부한다.
- 제한: 네 신규 테스트가 Supervisor invocation과 Walking benchmark source 생성을 위해 기존 대형 테스트
  모듈의 비공개 helper를 import한다. B2/SUP-006은 실제 외부 Ed25519 attestation·registry Harness·B3 호출을
  통과하지만 seed 1개·repetition 1개다. 다중 좌표 canonical ordering, schedule 전단사와 stable request
  uniqueness는 모델 invariant로 구현됐지만 별도 다중 좌표 실행 테스트가 아직 없다.
- 해소 조건: 최소 typed builder를 `tests/support/`에 추출하고 다중 seed/repetition에서 schedule·Harness 입력
  재정렬, 누락·중복, cross-coordinate receipt/relation 거부를 직접 검증한다.

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

## HANDOFF-001/002/003/004 process-local Handoff authorities

- 상태: 의도적으로 제한된 비영속 authority 경계
- 현재 보장: 단일 authority instance가 exact current CollaborationSnapshot과 기존 Agent/Task lineage,
  양쪽 parent Supervisor를 검증하고 Proposal당 하나의 non-executable record만 admission한다.
  terminal result authority는 이 역사적 admission, 같은 Graph store의 연속 후속 current Snapshot,
  destination Agent/Task terminal 상태와 exact sealed result Artifact를 결박하고 handoff당 한 semantic
  result만 admission한다. urgent fast gate는 같은 result Snapshot의 trusted-core|operator Observation과
  Action·Evidence lineage를 검증하고 handoff당 한 `stop-and-escalate` decision만 admission한다.
  reader는 existing delegated single-use Grant를 consume하고 exact receiver·Artifact·Snapshot을 60초·
  65,536 bytes·1회로 제한하며 urgent stop과 Graph head를 반환 전후에 확인한다.
- 제한: Supervisor와 result authority identity 및 admitted records는 서명되거나 process restart 뒤
  영속되지 않는다. fast-gate 1 unit은 local bound이며 runtime Budget reservation이 아니다. decision은
  `admitted-not-applied`이므로 기존 Permit을 revoke하거나 실행을 실제 중단하거나 사람에게 통지하지
  않는다. Graph와 Run store 사이에 분산 transaction은 없다. reader의 receiver 인증, attempt·receipt,
  CapabilityLedger와 urgent decision 확인은 같은 process의 trusted delivery adapter에 한정된다.
- 해소 조건: 외부/다중 process handoff가 필요할 때 signed Supervisor registry와 append-only record
  store/fence를 별도 계약으로 구현한다. 첫 downstream enforcement point는 urgent stop decision을
  명시적으로 소비해야 한다. remote content delivery가 필요하면 signed receiver authentication과
  durable single-use receipt/fence를 별도 계약으로 구현한다.

## Windows 비이식 파일명 정규화

- 상태: Windows-local 환경 제약, Linux 검증 완료
- 마지막 재현: 2026-08-04
- 명령: MEM-002 인접 회귀에 `tests\test_integrity.py` 전체를 포함한 pytest 실행
- 결과: Windows가 `evidence/result:.json`, 후행 점·공백 경로를 정규화해
  `test_seal_rejects_externally_created_non_portable_artifact_paths` 세 case를 관찰하지 못했다.
- 영향: 이 Windows filesystem의 이름 materialization 한계는 남지만, 위 Ubuntu run에는 해당 test와
  `tests/test_integrity.py` 관련 skip이 없었다.

## Windows 심볼릭 링크 테스트 권한

- 상태: Windows-local 환경 제약, Linux 검증 완료
- 마지막 재현: 2026-08-06
- 현재 결과: `tests/platform_test_support.py::symlink_or_skip`이 권한 없는 Windows의 `WinError 1314`를
  명시적 skip으로 분류한다. 관련 기능 테스트는 계속 실행하고 symlink 음성 사례만 skip한다.
- 영향: 이 host에서는 link-substitution fail-closed를 증명할 수 없지만 코드 회귀 증거가 아니다.
  위 Ubuntu run의 `symbolic links are unavailable`과 FORENSICS-001C admission skip은 모두 0이므로 Linux
  경계는 검증됐다.

## Windows POSIX 파일·디렉터리 mode 검사

- 상태: 테스트 플랫폼 분리 완료, Linux POSIX 보안 검증 완료
- 마지막 재현: 2026-08-06
- 명령: `.\.venv\Scripts\python.exe -m pytest -q tests\test_workflow_integrity_regressions.py::test_confirmation_projection_keeps_private_permissions_and_escapes_markdown`
- 추가: `.\.venv\Scripts\python.exe -m pytest -q tests\test_tool_loop.py::test_high_risk_tool_waits_for_exact_approval_and_resumes_in_new_run`
- 결과: 기능·escaping·approval은 Windows에서도 검증하고 `0700/0600` assertion만 POSIX로 분리했다.
  위 Ubuntu run에서 POSIX owner-only mode test skip은 0이었다. 이 Windows host에서는 private mode를
  재현할 수 없다.

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

## 관리형 Windows interpreter 실행 제한

- 상태: 일부 관리형 Windows에서 project interpreter·console script가 제한된다. 허용된 interpreter,
  격리 임시 루트와 `-p no:cacheprovider`는 통과한다.
- 해소: project Python, `pajin.exe`, installed wrapper를 Linux CI나 승인된 환경에서 검증한다.

## 로컬 Windows container runtime 가용성

- 상태: 현재 container daemon을 사용할 수 없어 AI-002B source opt-in과 AI-002D exact
  source/Replay/Controls/product/residue real-Docker 검증은 미실행이다. 정책 우회나 runtime data 삭제는
  수행하지 않는다.
- 영향: AI-002B~D의 in-process·fresh-process 검증은 실제 OCI lifecycle 증거가 아니다. 기존 exact Ubuntu
  run `33494188536`은 Phase 24 Network conformance만 증명하며, AI source/Replay/Controls/floor/product와
  residue는 AI-002D exact-clean Ubuntu conformance에서 별도로 검증해야 한다.

## Git OpenSSL CA 경로

- 상태: 활성. 기본 Git이 `unable to get local issuer certificate`를 보고하면 TLS 검증을 끄지 말고
  `git -c http.sslBackend=schannel <command>`를 사용한다. 로컬 CA 복구 전 push와 `ls-remote`에 동일하게
  적용한다.
