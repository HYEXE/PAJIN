# PAJIN 개발 인수인계

- 기록일: 2026-08-10
- 브랜치: `main`
- 현재 기능 HEAD: `1c03188d10e4bc60de9f6449201f83c1e26b707e`
- 현재 코드 체크포인트: Phase 9 `UX-001B2` Control Plane Campaign draft 검증 조회 완료
- 문서 동기화: 이 파일을 포함하는 후속 `docs(handoff)` 커밋에서 현재 체크포인트를 동기화
- 원격 기준: `origin/main@0ed5ac7168e17bcec5400109307f8ff732a11a7f`
- APPROVAL-001A 구현 커밋: `8733ccc51a00ab0efc34a2f6dfa288ca930f3e1b`
- APPROVAL-001B 구현 커밋: `6c75896ad7a52796d9dd2193e96b2f42724c407f`
- APPROVAL-001C1/C2 구현 커밋: `ba7274af4f96c1207b9d5dd509b659877f2a27b5`
- APPROVAL-001C3 구현 커밋: `613425367ef7a8f2e881812559efb48e4dc9d73d`
- SUP-007A 구현 커밋: `16fe8d1f44e5524cfe0f9a68b86d9126848ef091`
- SUP-007B 구현 커밋: `2434e83dd80df1dface1f0e68fab41d0b4ecfd1b`
- SUP-008 구현 커밋: `ac021a8a6eb314f9797a4c53ec93710731756a25`
- CHAIN-001 구현 커밋: `4c19ca81437a37e203fad71b0d97d4c4f586dec2`
- CHAIN-002 구현 커밋: `296c9a82ed7170f13082aed19e365d3331ef0c0e`
- 승인 배치 신뢰 경계 수정 커밋: `c01814c`
- CHAIN-003 typed Surface 구현 커밋: `9a2ad103a8f64ddb5289909f461b9d2e217b3dfe`
- CHAIN-003 chain 구현 커밋: `886236d053131697a674d67179ff1941959b6aed`
- CHAIN-004 구현 커밋: `b1dfa44fb2ffc2aa7750670ad506c10a6c863ce2`
- CHAIN-005 구현 커밋: `03d2c0a106794011c9f314668f6fa644a21f333a`
- VAL-001 구현 커밋: `a9949bcb13faed629d82558a40245272bf92c9a2`
- VAL-002 구현 커밋: `fadeed787ceab317fb81962d7ac7bc7736903f55`
- VAL-003 구현 커밋: `9b8cafff1138a596b85d8d9b0c7ea1861090b17d`
- VAL-003 순환 import 수정 커밋: `653f07caf898e8d5f2a707489f7c329f8836a2d4`
- VAL-004A 구현 커밋: `dfbd967cd4d88f866d8e7692a4c398b692fe69a8`
- VAL-004B 구현 커밋: `abfb167236831bfa113f41f97de6227b16a524cb`
- Replay 격리·HTTP Surface 등록 정합성 수정 커밋: `d5bd2e47bca3bcce7f4616cb220aa15a80464ebb`
- VAL-004C 구현 커밋: `56f5dcf2301b34d2cf8aa039da3809035515e4d7`
- UX-001A 구현 커밋: `6312215a8860e4a451de1af4d9d1f41d745f5817`
- UX-001B1 구현 커밋: `1c5f68e1c84c62a2099add5fe825937688ee7b7d`
- UX-001B2 구현 커밋: `1c03188d10e4bc60de9f6449201f83c1e26b707e`
- 현재 구현 체크포인트: configured root·exact digest 기반 operator-only redacted draft 조회
- 다음 로드맵: Phase 9 `UX-001B3` 원 typed source·별도 approval 기반 기존 compiler handoff
- 원격 push: 수행하지 않음. 이 문서 동기화 커밋 뒤 로컬 `main`은 `origin/main@0ed5ac7`보다 28 commits ahead

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. SUP-007A는 `16fe8d1`, SUP-007B는 `2434e83`, SUP-008은 `ac021a8`,
CHAIN-001은 `4c19ca8`, CHAIN-002는 `296c9a8`, 승인 배치 신뢰 경계 수정은 `c01814c`, CHAIN-003
typed Surface는 `9a2ad10`, chain authority는 `886236d`, CHAIN-004는 `b1dfa44`, CHAIN-005는
`03d2c0a`, VAL-001은 `a9949bc`, VAL-002는 `fadeed7`, VAL-003은 `9b8caff`와 순환 import 수정
`653f07c`, VAL-004A는 `dfbd967`, VAL-004B는 `abfb167`, Replay 격리·HTTP Surface 등록 정합성 수정은
`d5bd2e4`, VAL-004C는 `56f5dcf`, UX-001A는 `6312215`, UX-001B1은 `1c5f68e`, UX-001B2는
`1c03188`에 보존됐다. 이 문서 동기화 커밋 뒤 로컬 `main`은 `origin/main@0ed5ac7`보다 28 commits
ahead이고 working tree는 clean이어야 한다.
별도 detached worktree
`C:\Users\hyeon\.codex\worktrees\6b64\PAJIN`에는 이전 중복 변경이 남아 있으므로 사용자의 명시적
요청 없이 정리·reset·stash·삭제하지 않는다.

## 현재 구현 상태

`UX-001B2`는 `PAJIN_CP_CAMPAIGN_DRAFT_ROOT`와 exact lowercase SHA-256 digest로만 B1 artifact를 찾는
operator-only `GET /v1/campaign-drafts/{draft_digest}`를 추가했다. API는 B1 verified reader로 complete
source·Profile·preview·compiler·gate·digest·false authority를 다시 검증하고 요청 digest와 재구성 digest도
대조한다. 응답은 draft·Profile identity, source kind, bounded count, 남은 gate와 strict false authority만
포함하며 source·정책 문구·target endpoint·allow/deny 값·compiler entrypoint·path는 제외한다. Approver·Auditor·
Worker 접근, malformed/path-shaped digest, digest 디렉터리 치환과 source 변조는 fail closed하며 compiler·approval·
Campaign·Capability·Permit·Run·Graph·managed Artifact authority를 만들지 않는다.

`UX-001B1`은 UX-001A draft를 `<output>/<draftDigest>/campaign-profile-scope-draft.json`에 canonical
strict JSON으로 저장하고 같은 public verifier로 post-write reload한다. reader는 4 MiB·depth 64·50,000
node, duplicate key·non-finite number, no-follow parent·leaf, single hardlink와 stable revision을 요구한 뒤
complete source·Profile·preview·compiler·gate·digest를 다시 도출한다. `campaign-draft-create`와
`campaign-draft-inspect`는 source text·target endpoint를 출력하거나 기존 compiler를 호출하지 않는다.
RunStore·Control Plane managed artifact·Graph에는 admission하지 않으며 boolean `false` 대신 숫자 `0`을
넣는 authority wire 위조도 거부한다. Scope·Target·Campaign·Capability·Permit·execution authority는
계속 모두 false다.

`CHAIN-001`은 exact sealed Recon source·projection Run과 ORCH-001 `SurfaceSnapshotAuthority`를 다시
검증한다. non-anonymous `http-authentication`과 같은 Campaign Target·exact route의 명시적
`http-rag/index-management` Surface만 `chain-001:auth-bypass-to-ai-admin-surface@1.0.0`으로 결박한다.
Campaign mode에 따라 분기하지 않지만 exact Campaign digest는 보존한다. 결과는
`hypothesized-not-validated`, `surfaceEvidenceOnly=true`이고 Capability·execution·Claim Replay·Finding
confirmation은 모두 false다. URL·설명·이름으로 admin 의미를 추론하거나 ToolRequest·Grant·Permit·Replay·
Validation authority를 생성하지 않는다.

`CHAIN-002`는 sealed WALK-003 Run·artifact·publication을 다시 검증하고, 그 authority가 포함한 exact
WALK-002 Run root·artifact SHA-256·Surface Snapshot·RAG Hypothesis를 3개 ordered stage와 2개 `enables`
edge로 결박한다. File Upload와 RAG Injection은 동일 WALK-002 authority를, Tool Abuse는 exact WALK-003
authority를 참조하며 두 Target은 같은 Campaign에 각각 정확히 선언돼야 한다. Campaign mode에는 분기하지
않지만 WALK digest와 canonical Campaign digest를 모두 보존한다. P0-D2B는 profile identity 의미 대조만
기록하고 provider·matcher·measurement evidence는 admission하지 않는다. 결과는
`hypothesized-not-validated`, `hypothesisEvidenceOnly=true`이며 Capability·execution·Claim Replay·Finding
confirmation은 모두 false다.

`CHAIN-003A`는 MCP discovery에서 top-level JSON Schema의 exact `type=string`, `format=uri` property만
`mcp-url-tool`로 admission하고 argument 이름·strict required flag와 schema digest만 보존한다. OpenAPI는
operation의 exact boolean `x-pajin-internal-api: true`만 `http-internal-api`로 admission한다. URL 값·설명·
raw schema·private address·route 이름으로 의미를 추론하지 않는다. 전용 `HTTPInternalAPIReconPlanner`는
이 Surface가 누락되면 Recon을 fail closed한다. demo `inspect_url`은 discovery에는 광고되지만 invocation
allowlist에는 추가되지 않았다.

`CHAIN-003B`는 MCP와 Internal API의 exact sealed Recon source·projection Run을 다시 검증해 두
`SurfaceSnapshotAuthority`를 결박한다. non-empty prompt argument와 URL Tool은 같은 Campaign Target·MCP
server여야 하고, Internal API Target은 같은 Campaign에 정확히 한 번 선언돼야 한다. 세 단계는 각각
`prompt-injection-hypothesis`, `mcp-url-argument-control-hypothesis`,
`target-declared-internal-api-surface`로 기록되며 실제 influence나 reachability를 주장하지 않는다. 결과는
`hypothesized-not-validated`, `surfaceEvidenceOnly=true`,
`crossTargetBinding=same-campaign-hypothesis-only`이고 Capability·execution·Claim Replay·Finding
confirmation은 모두 false다.

`CHAIN-004`는 별도 cumulative OpenAPI adapter가 exact version-1
`x-pajin-tenant-retrieval`과 `x-pajin-data-response`만 typed Surface로 admission한다. tenant retrieval은
같은 operation의 exact `http-rag/retrieval`을 요구하고 selector location·name만 보존한다. data response는
하나 이상의 declared response content type과 code-owned data class만 보존한다. tenant 값·query·response
example·body·schema content는 보존하지 않는다. 같은 Campaign Target·exact route의 두 Surface를 exact
sealed Recon source·projection Run과 `SurfaceSnapshotAuthority`에서 다시 검증한다. 두 단계는
`cross-tenant-retrieval-hypothesis`와 `declared-data-response-surface`이며 실제 selector control·retrieval·
access·exposure를 주장하지 않는다. 결과는 `hypothesized-not-validated`, `surfaceEvidenceOnly=true`이고
cross-tenant access·data exposure·Capability·execution·Claim Replay·Finding confirmation은 모두 false다.

`CHAIN-005`는 exact sealed WALK-003 Run·artifact·publication과 code-owned MCP authorization rule을 다시
검증한다. Authorization Failure stage는 WALK-003 hypothesis를, Privileged Action stage는 그 안의 exact
`CapabilityDefinition`을 참조한다. privileged는 `approvalRequired=true`이고
`independent-user-approval` control 아래 등록된 MCP Capability라는 bounded 의미뿐이다. full Capability,
MCP server·tool Surface와 locator, invocation, Campaign lineage를 action digest에 결박하며 risk tier·side
effect·Tool 이름·설명·argument·synthetic Finding으로 권위를 추론하지 않는다. 결과는
`hypothesized-not-validated`, `hypothesisEvidenceOnly=true`이고 실제 authorization failure confirmation·
approval·Capability Grant·execution·Claim Replay·Finding confirmation은 모두 false다.

`VAL-001`은 기존 WALK-005B2 `WalkingMCPClaimReplayAuthority`를 새 실행 없이 재사용한다. CHAIN-002와
CHAIN-005만 지원하며, Chain과 Replay가 exact 같은 WALK-003 Run root·artifact SHA-256·hypothesis를
포함할 때만 validity `AtomicClaim`의 `REPRODUCED` 상태를 결박한다. Chain과 WALK-005B2 sealed
publication을 각각 기존 verifier/loader로 다시 열고, Candidate·Claim·Plan·approval receipt·fresh
Run·request·Grant·Permit·dispatch·Worker·evidence·Replay publication 좌표를 binding digest에 포함한다.
결과는 `validity-reproduced-not-confirmed`이고 추가 execution·Replay·confirmation·Finding authority는
모두 false다. executed Candidate·Replay predecessor가 없는 CHAIN-001/003/004는 지원하지 않는다.

`VAL-002`는 기존 validity Claim Replay·Validation Control·KISA repetition 경계를 실행하지 않고 세
`ValidationDepthRequirement`로 정규화한다. `single-validity-replay`, `controlled-validity-replay`,
`repeated-controlled-validity-replay` 순서와 exact Claim/Control 요구, 최소 1/1/2 Replay 반복, 최대 20회,
exact ordered `fresh-session`·`stateless` 격리 정책, fresh Capability·request·evidence lineage를
content-addressed catalog에 고정한다. v1은 validity만 지원하며 Profile floor·evidence evaluation·execution·
confirmation·Finding authority는 모두 false다.

`VAL-003`은 exact PROF-001 catalog와 VAL-002 policy를 다시 내장해 complete registered Profile·Profile
digest를 complete registered depth requirement·ordinal·digest에 결박한다. `ai-assessment`는
`repeated-controlled-validity-replay`, `bug-hunt`·`pentest`는 `controlled-validity-replay`, `ctf`는
`single-validity-replay`를 최소 floor로 요구한다. 더 높은 registered depth는 ordinal로만 충족하며 unknown·
stale·cross-catalog·mapping·digest·boolean marker 치환은 fail closed한다. Profile 선택, Campaign 변경,
evidence evaluation, 실행·confirmation·Finding authority는 모두 false다. API는 순환 import를 피하기 위해
eager `pajin.workflow` export가 아니라 `pajin.workflow.profile_assurance` 명시적 모듈로 제공한다.

`VAL-004A`는 exact sealed KISA source·validity Replay·Validation Control Run을 다시 열어 Profile floor의
실제 충족 여부를 평가한다. confirmation-purpose `SUPPORTS` Replay의 모든 1~20회 attempt와 fresh session,
disjoint request·evidence를 검증하고, controlled floor는 canonical Baseline·Negative Control·Counterfactual
Plan·request·attempt·receipt·reconciliation·Capability ledger를 exact-match한다. Control request의 결정적
ID·executor·Tool·target·method와 root/child Capability accounting을 원 Replay 의미에 결박하고, Replay와
Control의 source·Claim·scenario·original request는 같되 request·session·Capability·evidence lineage는
겹치지 않아야 한다. typed set은 canonical digest 전에 정렬한다. 결과는
`profile-floor-satisfied-not-confirmed`이며 Profile 선택·Campaign 변경·실행·confirmation·Finding 권위는
모두 false다. KISA M03·M06·A04만 지원하고 VAL-001 WALK Replay와 KISA Control은 결합하지 않는다.

`VAL-004B`는 VAL-001 CHAIN-002/005 validity Claim에서 exact stateless MCP text Baseline·Negative
Control·Counterfactual Plan을 materialize한다. Negative Control은 target authorization 변경을 주장하지 않고
동일 source request/result에 nonce-derived absent-content canary oracle을 적용한다. Counterfactual만 registered
benign text로 바뀐다. 각 Control은 기존 independent approval·`maxCalls=1` Grant·Permit·Gateway·Worker·Run
seal을 통과해야 하고 exact Plan receipt가 dispatch claim 전에 봉인돼야 한다. source·Replay·세 Control의
Run/root·execution·request·Grant·Permit·approval·Worker·Run-qualified evidence 5세트는 모두 달라야 하며,
session 필드를 만들지 않고 `sessionPolicy=stateless`를 고정한다. VAL-001의 Replay가 1회이므로 CTF single,
Bug Hunt·Pentest controlled floor까지만 이 wire에서 충족한다. Profile 선택·Campaign 변경·추가 실행·
confirmation·Finding 권위는 모두 false다.

`VAL-004C`는 VAL-004B wire를 바꾸지 않고 기존 VAL-001 primary Replay와 같은 exact WALK-005B1 Plan으로
완료된 두 번째 WALK-005B2 authority를 별도 repeated authority에 결박한다. 두 Replay는 각각 독립 approval·
Grant·Permit·dispatch·Worker·execution/publication Run을 가져야 한다. source·두 Replay·세 Control의
Run/root·execution·request·Grant·Permit·dispatch·approval·Worker·Run-qualified evidence 6세트와 두 Replay
publication은 pairwise-disjoint해야 한다. 첫 Replay는 VAL-004B Control anchor로 고정된다. 이 evidence는
AI Assessment repeated-controlled floor를 충족하지만 Profile 선택·Campaign 변경·추가 execution·Replay·
confirmation·Finding 권위는 모두 false다.

`APPROVAL-001A`는 기존 GRAPH-006 최종 transaction을 재사용해 deployment-authenticated 단일
operator approval, 기존 consumed `ActionPermit`, non-reusable consumption receipt를 원자적으로
소비한다.

`APPROVAL-001B`는 이 no-write 경계를 유지하면서 General Attack의
`reversible-write + cleanupRequired=true`에 한해 approval, 기존 consumed ActionPermit,
non-reusable receipt와 기존 cleanup reservation을 schema v4 transaction 하나에서 원자 소비한다.

`APPROVAL-001C1/C2`는 기존 single-action authority를 2~8개 ordered host-local async batch로
조정한다. no-write 항목은 APPROVAL-001A, reversible-write 항목은 APPROVAL-001B combined authority를
그대로 호출한다. reversible terminal은 exact cleanup reservation과 deployment-authenticated
restored-state evidence를 요구하며, partial/unknown 상태는 자동 redispatch 권위를 만들지 않는다.

`APPROVAL-001C3`는 기본 단건 경로를 유지하면서 두 opt-in surface만 추가한다. General Attack은
`dispatch_approved_batch_item_once()`가 current approval과 reversible cleanup request를 다시 만들고 gate의
기존 Graph store/verifier로 batch authority를 구성한다. Control Plane은 deployment v1alpha2가 exact batch,
journal path와 optional cancellation을 pin한 경우 `capability-graph-batch-v1` Job만 실행한다. Gateway Run
seal을 journal completion 전에 검증하고 exact retry는 Worker를 재호출하지 않는다. journal backup은 local
content-addressed manifest와 새 경로 restore만 제공하며 retention assessment는 pending·unknown을 항상
삭제 부적격으로 둔다. 실제 삭제, remote signature/encryption과 cross-host authority는 없다.

`SUP-007A`는 기존 General Attack Proposal·compiler, GRAPH Permit, Capability Gateway, managed Run audit와
PERMIT-004A outcome authority를 하나의 explicit direct-call gate로 조합한다. T0/T1 `none`·`read-only`만
허용하며 exact retry, callback 실패, 취소 또는 authority 대체가 Worker 재호출 권위를 만들지 않는다.

`SUP-007B`는 같은 조합을 기존 Control Plane Campaign executor의 `general-attack-v1` profile로 노출한다.
startup SHA-256-pinned Capability Graph deployment가 Campaign·Envelope·activation·Graph store·Run root·
Tool registry·Worker를 소유하고, executor는 strict Job source에서 Proposal과 intent를 다시 만든다. 첫 profile은
approval-free, non-networked, zero-cost T0/T1 no-write로 제한된다. T2, T3+, write, caller pricing과 기존 default
Campaign workflow는 계속 닫혀 있다.

`SUP-008`은 별도 `general-attack-approved-v1` profile에서 deployment가 이미 pin한 Approval inventory와
`ActionApprovalInputAuthority`를 `capability-graph-v1`과 동일한 인스턴스로 재사용한다. strict Job approval은
deployment inventory와 exact-match해야 하며 APPROVAL-001A가 Approval·Permit·non-reusable receipt를 원자
소비한다. 완료 결과와 PERMIT-004A assessment는 durable approval/receipt ID·digest를 결박한다. 승인 대상 T2
no-write와 Definition-required T0/T1만 허용하며 T3+, write, network, priced action은 닫혀 있다.

- `ActionApprovalEnvelope`는 `mode=single`, JSON integer `maxActions=1`로 고정하고 issuer·requester·
  approver, Campaign·Run·MissionEnvelope, source intent·activation set, signed release·Capability,
  GraphDecision·ActionProposal·request·target·risk·reservation·expected Permit·time window를 결박한다.
- content digest는 issuer 서명이 아니다. deployment-pinned `ActionApprovalInputAuthority`가 high-level
  authority와 SQLite transaction 안팎에서 complete input을 검증하며 permissive 기본 구현은 없다.
- full activation `ActionApprovalCapabilityPolicyRegistry`와 plain·approved·reversible·cleanup 전용
  non-transferable writer token을 사용한다. generic caller나 per-call policy/verifier가 specialized
  transaction을 호출할 수 없다.
- schema v4는 append-only approval·receipt ledger를 추가하고 approval·Permit·receipt를 all-or-nothing으로
  커밋한다. store post-verifier 실패는 rollback하고, high-level post-verifier 실패는 이미 소비된 tuple을
  유지해 다음 exact retry가 `newlyConsumed=false`로만 복구한다.
- exact retry는 approval expiry 뒤에도 같은 durable Permit·receipt를 반환하고 Worker를 재호출하지 않는다.
  callback 실패·unknown outcome도 authority를 복구하지 않는다.
- General Attack은 T2 no-write와 T0/T1 `approvalRequired`에 approval을 요구한다. outcome gate는 durable
  receipt를 다시 조회해 exact-match하고 assessment에 approval·receipt ID/digest를 결박한다.
- `capability-graph-v1`은 deployment approval inventory와 issuer verifier를 고정하고 Job·prepared action·
  activation의 release 5-tuple을 재검증한다. completion result는 durable approval·receipt ID/digest를
  최초 실행과 retry에 동일하게 노출한다.
- Common Engine과 legacy `deterministic-local`은 approval-aware composition이 없으므로 T2를 Permit 전에
  거부한다. Web Console 기본 실행은 bounded T0 `mock-sleep`으로 유지한다.
- T2 또는 Definition `approvalRequired` reversible-write는 deployment approval verifier와 code-owned
  cleanup mapping verifier가 모두 있을 때만 combined writer를 사용한다. 어느 insert나 transaction 내부
  post-verifier가 실패해도 네 ledger가 모두 rollback한다.
- exact retry와 verified backup/restore retry는 같은 네 레코드를 `newlyConsumed=false`로 반환하고
  Worker를 다시 호출하지 않는다. authenticated outcome은 approval side-effect·cleanup flags를 current
  signed Definition과 다시 exact-match한 뒤 기존 PERMIT-004B2 cleanup 경로에 전달한다.
- production inventory와 `capability-graph-v1`, Common Engine, legacy write는 계속 닫혀 있다. Control Plane
  batch write, T3+와 기본 runtime batch/async workflow도 fail closed한다.
- current direct/retained Graph backup은 v1alpha3/schema v4다. strict v1alpha2/schema v3와
  v1alpha1/schema v2 reader·migration은 legacy material을 검증하되 approval을 backfill하지 않는다.

핵심 위치:

- `src/pajin/workflow/campaign_builder.py`
- `src/pajin/cli.py`
- `src/pajin/control_plane/campaign_drafts.py`
- `src/pajin/control_plane/api.py`
- `src/pajin/control_plane/api_routes.py`
- `tests/test_campaign_builder.py`
- `tests/test_campaign_builder_artifacts.py`
- `tests/test_control_plane_campaign_drafts.py`
- `docs/orchestration/UX-001A-campaign-profile-scope-builder-draft.md`
- `docs/orchestration/UX-001B1-local-campaign-draft-artifact.md`
- `docs/orchestration/UX-001B2-control-plane-campaign-draft-read.md`
- `docs/adr/0153-build-campaign-drafts-without-compilation-authority.md`
- `docs/adr/0154-store-campaign-drafts-outside-run-authority.md`
- `docs/adr/0155-expose-campaign-drafts-as-redacted-operator-views.md`
- `src/pajin/graph/approval.py`
- `src/pajin/graph/approved_cleanup.py`
- `src/pajin/graph/approval_batch.py`
- `src/pajin/graph/sqlite_store.py`
- `src/pajin/graph/authority.py`
- `src/pajin/graph/cleanup.py`
- `src/pajin/graph/backup_retention.py`
- `src/pajin/supervision/action_permit.py`
- `src/pajin/supervision/action_outcome.py`
- `src/pajin/supervision/action_execution.py`
- `src/pajin/control_plane/capability_deployment.py`
- `src/pajin/control_plane/executors.py`
- `src/pajin/workflow/engine_execution_gate.py`
- `src/pajin/discovery/attack_chain.py`
- `src/pajin/discovery/claim_replay.py`
- `src/pajin/discovery/validation_depth.py`
- `src/pajin/workflow/profile_evidence.py`
- `src/pajin/discovery/mcp_privilege_attack_chain.py`
- `src/pajin/discovery/tenant_attack_chain.py`
- `src/pajin/discovery/tenant_data.py`
- `src/pajin/discovery/url_attack_chain.py`
- `src/pajin/discovery/walking_replanning.py`
- `tests/test_mode_neutral_attack_chain.py`
- `tests/test_discovery_tenant_data_adapter.py`
- `tests/test_mode_neutral_tenant_attack_chain.py`
- `tests/test_mode_neutral_url_attack_chain.py`
- `tests/test_walking_mcp_authorization.py`
- `tests/test_validation_depth_policy.py`
- `tests/test_profile_validation_evidence.py`
- `docs/orchestration/APPROVAL-001A-single-action-approval.md`
- `docs/orchestration/APPROVAL-001B-approved-reversible-cleanup-hold.md`
- `docs/orchestration/APPROVAL-001C1-bounded-async-approval-batch.md`
- `docs/orchestration/APPROVAL-001C2-reversible-async-approval-batch.md`
- `docs/orchestration/APPROVAL-001C3-opt-in-batch-runtime-and-retention.md`
- `docs/orchestration/SUP-007A-opt-in-general-attack-execution.md`
- `docs/orchestration/SUP-007B-control-plane-general-attack-profile.md`
- `docs/orchestration/SUP-008-approved-general-attack-control-plane-profile.md`
- `docs/orchestration/CHAIN-001-mode-neutral-auth-bypass-ai-admin.md`
- `docs/orchestration/CHAIN-002-file-upload-rag-tool-abuse.md`
- `docs/orchestration/CHAIN-003-prompt-url-tool-internal-api.md`
- `docs/orchestration/CHAIN-004-cross-tenant-retrieval-data-exposure.md`
- `docs/orchestration/CHAIN-005-mcp-authorization-privileged-action.md`
- `docs/orchestration/VAL-001-mode-neutral-claim-replay.md`
- `docs/orchestration/VAL-002-validation-depth-policy.md`
- `docs/orchestration/VAL-003-profile-assurance-floor.md`
- `docs/orchestration/VAL-004A-kisa-profile-validation-evidence.md`
- `docs/orchestration/VAL-004B-mode-neutral-walking-profile-evidence.md`
- `docs/orchestration/VAL-004C-mode-neutral-repeated-walking-profile-evidence.md`
- `docs/adr/0134-consume-single-approval-with-action-permit.md`
- `docs/adr/0135-atomically-bind-approval-and-cleanup-hold.md`
- `docs/adr/0136-coordinate-bounded-async-approval-batches.md`
- `docs/adr/0137-bind-reversible-batch-items-to-cleanup-authority.md`
- `docs/adr/0138-compose-opt-in-batch-runtime-and-journal-retention.md`
- `docs/adr/0139-compose-general-attack-through-managed-gateway.md`
- `docs/adr/0140-expose-general-attack-through-control-plane.md`
- `docs/adr/0141-compose-approved-general-attack-profile.md`
- `docs/adr/0142-bind-mode-neutral-chain-to-surface-snapshot.md`
- `docs/adr/0143-bind-walking-lineage-to-mode-neutral-chain.md`
- `docs/adr/0144-bind-url-tool-chain-to-explicit-surface-authority.md`
- `docs/adr/0145-bind-tenant-data-chain-to-explicit-retrieval-authority.md`
- `docs/adr/0146-bind-mcp-privilege-chain-to-approval-gated-capability.md`
- `docs/adr/0147-bind-mode-neutral-claim-replay-to-sealed-walking-evidence.md`
- `docs/adr/0148-register-validation-depth-requirements-without-evidence-authority.md`
- `docs/adr/0149-bind-profile-assurance-floors-without-campaign-selection.md`
- `docs/adr/0150-evaluate-kisa-profile-floors-from-sealed-evidence.md`
- `docs/adr/0151-bind-stateless-walking-controls-to-val001.md`
- `docs/adr/0152-bind-repeated-walking-replays-without-new-execution-authority.md`

## 현재 검증

### 2026-08-10 UX-001B2 Control Plane Campaign draft 검증 조회

- 구현 커밋: `1c03188`
- operator-only redacted 조회, 미인증·Approver·Auditor·Worker 거부, configured root 미설정, malformed·missing
  digest, digest 디렉터리 치환, source 변조 비반사, blank root 설정과 숫자 `0` 권위 marker 거부 포함:
  `tests/test_control_plane_campaign_drafts.py` 15 passed
- B1 artifact·핵심 Control Plane·문서 회귀: 138 passed, 1 skipped. Windows skip은 developer mode가 없어
  symlink를 만들 수 없는 `WinError 1314`이며 hardlink 음성 테스트는 통과
- 저장소 전체 Ruff `src tests containers`: 통과
- Linux 대상 strict mypy `--no-incremental`: 271 source files 통과
- `git diff --check`, staged 파일·전체 staged diff 검토: 통과
- 전체 `python -m pytest -q -x`: 677 passed, 12 skipped 뒤 기존 Artifact admission 진단 문자열 불일치
  1건에서 중단. 기대값 `not admission-bound`와 실제 `staged source Artifact failed managed admission`의
  차이이며 UX-001B2 변경 파일 밖이다.
- 나머지 Control Plane 확장 실행의 추가 실패는 Windows에서 의도적으로 닫히는 POSIX directory `fsync`
  미지원 경계이며 새 draft reader·route와 무관하다.

### 2026-08-10 UX-001B1 local Campaign Builder draft artifact 검증

- 구현 커밋: `1c5f68e`
- Bug Bounty·CTF local artifact canonical write·reload, CLI create·inspect, compiler 미호출과 문서 집중
  검증: 45 passed, 1 skipped
- source·digest·authority 치환, duplicate JSON key, symlink parent·leaf, hardlink alias와 boolean 대신 숫자
  `0`인 Scope·Target·Campaign·Capability·Permit·execution marker를 fail closed하는 음성 회귀 포함
- CLI·Bug Bounty·CTF 인접 회귀: 66 passed, 6 skipped
- Windows skip은 developer mode가 없어 test symlink를 만들 수 없는 `WinError 1314`이며 hardlink 음성
  테스트는 통과
- Ruff 전체 `src tests containers`와 변경 Python 포맷 검사: 통과
- Linux 대상 strict mypy: 270 source files 통과
- 변경 source 집중 mypy: 통과
- 문서 정책과 루트 상태 문서 크기 검사: 2 passed; `PLAN.md` 65,211 bytes
- staged diff check와 추가 line credential-like assignment scan: 통과
- 전체 `python -m pytest -q -x`: 677 passed, 12 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 UX-001B1 변경 파일 밖이다.

### 2026-08-10 VAL-004C mode-neutral repeated WALK Profile Validation Evidence 검증

- 구현 커밋: `56f5dcf`
- all CampaignMode에서 같은 exact WALK-005B1 Plan과 서로 다른 approval·Grant·Permit·dispatch·Worker·
  execution/publication Run을 가진 두 WALK-005B2 Replay를 검증하고 AI Assessment
  `repeated-controlled-validity-replay` floor를 충족했다.
- primary Replay 재사용, foreign Chain Replay, predecessor 순서 치환, Contract·authority boolean 권위 상승,
  Replay publication·6-way request lineage 중복을 fail closed하는 집중 테스트: 4 passed
- WALK·VAL-002/003·KISA VAL-004A·VAL-004B 인접 회귀: 167 passed
- Ruff 전체 `src tests containers`: 통과
- 변경 Python 포맷 검사: 통과
- Linux 대상 strict mypy: 269 source files 통과
- 문서 정책과 링크 검사: 2 passed
- staged diff check와 credential pattern scan: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-004C 변경 파일 밖이다.

### 2026-08-10 Replay 격리·HTTP Surface 등록 정합성 수정 검증

- 수정 커밋: `d5bd2e4`
- VAL-002는 `fresh-session`과 `stateless`만 exact ordered allowlist로 허용하고
  `preserve-scenario-session`·순서 변경·부분 allowlist를 fail closed한다.
- VAL-004A는 fresh-session, VAL-004B는 exact one-field text schema의 stateless Replay만 등록 요구와
  교차검증한다. source와 Replay arguments가 다르거나 session argument가 있으면 VAL-004B floor를
  충족하지 못한다.
- authentication·file-upload·RAG·tenant-data HTTP 어댑터가 상속된 `http-internal-api` 후보를
  `supportedSurfaceKinds`에 등록하며, 방출 종류가 선언 집합을 벗어나지 않는 회귀 테스트를 추가했다.
- 변경 직접·인접 회귀: 346 passed, 1 skipped
  - skip은 Windows 개발자 모드 부재의 `WinError 1314` symlink 환경 제한이다.
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 268 source files 통과
- 문서 정책과 링크 검사: 2 passed
- `git diff --check`: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 이번 변경 파일 밖이다.
- 위 1건을 제외한 전체 실행은 30분 제한에 걸려 79%에서 중단됐고 여러 실패가 있어 전체 통과로
  기록하지 않는다. `-x`로 추출한 첫 추가 실패는 Windows에서 POSIX directory fsync를 지원하지 않아
  `test_exact_concurrent_artifact_admission_creates_one_record_and_event`가 managed admission에 실패한
  환경 제한이었다.

### 2026-08-10 VAL-004B mode-neutral WALK Profile Validation Evidence 검증

- 구현 커밋: `abfb167`
- all CampaignMode WALK·VAL-002/003·KISA VAL-004A 인접 회귀: 170 passed
- stateless materialization, absent-canary Negative Control, single·controlled floor, AI Assessment floor 거부,
  source·Replay·Control 계보 재사용, pre-dispatch Plan receipt 누락, oracle·boolean marker 위조, copied evidence
  seal mutation 음성 경계: 집중 테스트 4 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 268 source files 통과
- 문서 정책과 링크 검사: 2 passed
- staged diff check와 credential pattern scan: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-004B 변경 파일 밖이다.

### 2026-08-10 VAL-004A KISA Profile Validation Evidence 검증

- 구현 커밋: `dfbd967`
- sealed KISA Replay·Control과 Profile floor 인접 회귀: 155 passed
- digest JSON round-trip·set 순서, cross-source·forged root·authority marker·Control artifact mutation 음성 경계:
  집중 테스트 2 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 267 source files 통과
- 문서 정책과 링크 검사: 2 passed
- staged diff check와 추가된 줄 credential pattern scan: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-004A 변경 파일 밖이다.

### 2026-08-10 VAL-003 Profile별 Assurance Floor 검증

- 구현 커밋: `9b8caff`
- 순환 import 수정 커밋: `653f07c`
- exact Profile/floor policy·resolver·digest·ordinal·mapping·authority marker 음성 회귀와 clean interpreter
  양방향 import 순서: 45 passed
- Profile·legacy compatibility·Validation depth/model/control·Replay 인접 회귀: 201 passed
- `pajin.modes.ai_redteam.replay`와 VAL-003 import 및 AI Chat 인접 수집 회귀: 64 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 266 source files 통과
- 문서 정책과 링크 검사: 2 passed
- staged diff check: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-003 변경 파일 밖이다.

### 2026-08-10 VAL-002 Validation depth policy 검증

- 구현 커밋: `fadeed7`
- exact catalog·resolver·digest·순서·Claim/Control 요구·authority marker 음성 회귀: 34 passed
- Validation·Control·Replay·Profile·VAL-001 인접 회귀: 184 passed, 4 deselected
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 265 source files 통과
- 변경 Python 3개 format check와 public import smoke: 통과
- 문서 정책 2건과 문서 링크 검사: 통과
- staged diff check와 추가 라인 credential pattern scan: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-002 변경 파일 밖이다.

### 2026-08-10 VAL-001 mode-neutral Claim Replay 검증

- 구현 커밋: `a9949bc`
- VAL-001 집중 mode-neutral·Chain/Claim/digest/marker 위조·cross-lineage·stale source·artifact mutation
  회귀: 7 passed
- CHAIN-001~005·WALK-003~005B2·공통 Replay/Validation 모델 결합 회귀: 145 passed
- CHAIN-002/005 동일 WALK-003 결박과 CHAIN-001/003/004 미지원 경계: 통과
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 264 source files 통과
- 변경 Python 3개 format check와 public import smoke: 통과
- changed-file credential pattern scan과 `git diff --cached --check`: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 VAL-001 변경 파일 밖이다.

### 2026-08-10 CHAIN-005 MCP authorization·privileged action chain 검증

- 구현 커밋: `03d2c0a`
- CHAIN-005 집중 mode-neutral·위조·Capability substitution·stale publication 회귀: 7 passed
- WALK-003·CHAIN-001/002 및 MCP·URL·tenant chain 결합 관련 회귀: 110 passed
- non-approval Capability, reordered stage, forged action digest·authority marker, stale equivalent
  publication과 artifact mutation 음성 경계: 통과
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 263 source files 통과
- 변경 Python 3개 format check와 public import smoke: 통과
- changed-file credential pattern scan과 `git diff --cached --check`: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 CHAIN-005 변경 파일 밖이다.

### 2026-08-10 CHAIN-004 explicit tenant retrieval·data response chain 검증

- 구현 커밋: `b1dfa44`
- CHAIN-004 adapter·chain 및 predecessor model·RAG 회귀: 82 passed
- CHAIN-001/003·HTTP/RAG Discovery·Recon 결합 확장 회귀: 137 passed
- 동일 route 결박, generic RAG·route 치환, missing declaration, stale publication, 변조 projection,
  forged authority marker와 arbitrary data class 음성 경계: 통과
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 262 source files 통과
- 변경 Python 8개 format check와 public import smoke: 통과
- changed-file credential pattern scan과 `git diff --cached --check`: 통과
- 전체 `python -m pytest -q -x`: 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지
  불일치 1건에서 중단. 기대값 `not admission-bound`와 실제 상위 오류
  `staged source Artifact failed managed admission`의 차이이며 CHAIN-004 변경 파일 밖이다.

### 2026-08-10 CHAIN-003 explicit URL Tool·Internal API chain 검증

- typed Surface 구현 커밋: `9a2ad10`
- Snapshot-bound chain 구현 커밋: `886236d`
- CHAIN-003 전용 mode-neutral·generic locator substitution·strict declaration·stale publication·
  authority forgery 회귀: 7 passed
- CHAIN-001/002·MCP authorization·HTTP/MCP discovery 결합 확장 회귀: 159 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 Python 3.12 strict mypy: 260 source files 통과
- CHAIN-003B 변경 Python format check: 통과. `src/pajin/runtime/worker.py` 전체 format check의 기존
  formatter-only 차이는 관련 없는 churn을 피하려고 복원했으며 Ruff lint 전체는 통과
- 변경 Markdown 상대 링크 검사: 통과
- changed-file credential pattern scan과 `git diff --cached --check`: 통과
- 전체 pytest는 기존 Artifact admission 오류 메시지 불일치가 미해결이므로 같은 원인의 전 범위 실행을
  반복하지 않았다. CHAIN-003 및 predecessor Discovery·CHAIN·WALK 경계는 위와 같이 통과했다.

### 2026-08-10 원격 전 승인 배치 신뢰 경계 점검

- 구현 커밋: `c01814c`
- journal은 canonical authorization 증거를 함께 보존하고 terminal/cancelled 조회·백업·복구 때 현재
  input/completion/cancellation authority를 다시 검증한다.
- Graph database와 batch journal의 Run audit root 하위 배치 및 SQLite sidecar 충돌을 거부하고,
  `itemOrdinal`의 문자열·실수·boolean 강제 변환을 거부한다.
- 직접 관련 회귀: 64 passed
- 원격 미반영 승인 배치·General Attack·Control Plane·체인 결합 회귀: 216 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 259 source files 통과
- 변경 Python format check: 통과
- staged credential pattern scan과 `git diff --cached --check`: 통과
- 전체 pytest는 기존 Artifact admission 오류 메시지 불일치가 미해결이므로 같은 원인의 전 범위 실행을
  반복하지 않았다.

### 2026-08-10 CHAIN-002 mode-neutral WALK chain 계약 검증

- CHAIN-002 구현 커밋: `296c9a8`
- CHAIN-001과 전체 WALK 계보 결합 회귀: 51 passed
- Walking·mode-neutral chain 관련 회귀: 67 passed
- P0-D2/P0-D2B AI/RAG/MCP target catalog 경계: 10 passed
- Ruff 저장소 전체: 통과
- Linux 대상 strict mypy: 259 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 7개 상대 링크 검사: 통과
- changed-file credential pattern scan과 `git diff --cached --check`: 통과
- 전체 pytest는 기존 Artifact admission 오류 메시지 불일치가 미해결이므로 같은 원인의 전 범위 실행을
  반복하지 않았다. CHAIN-002 관련 WALK·P0-D2B 경계는 위와 같이 통과했다.

### 2026-08-10 CHAIN-001 mode-neutral 공격 체인 계약 검증

- CHAIN-001 구현 커밋: `4c19ca8`
- CHAIN-001·RAG adapter·Surface Snapshot·Discovery model 인접 회귀: 77 passed
- Discovery 전 범위 회귀: 172 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 259 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 7개 상대 링크 검사: 통과
- staged credential pattern scan과 `git diff --cached --check`: 통과
- 전체 pytest는 기존 Artifact admission 오류 메시지 불일치가 미해결이므로 같은 원인의 전 범위 실행을
  반복하지 않았다. CHAIN-001 관련·Discovery 전 범위 묶음은 위와 같이 통과했다.

### 2026-08-09 SUP-008 사전 승인 T2 profile 집중·통합 검증

- SUP-008 구현 커밋: `ac021a8`
- General Attack approval·execution·Permit 집중 회귀: 55 passed
- Capability Graph approval store·rollout·outcome 인접 회귀: 77 passed
- General Attack Proposal·Permit·execution·outcome·Control Plane·rollout 통합 회귀: 161 passed
- Control Plane 인접 회귀: 116 passed, 1 skipped
  - skip: 격리된 `PAJIN_TEST_CONTROL_PLANE_URL` 미설정
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 258 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 13개 상대 링크 검사: 통과
- `git diff --cached --check`: 통과
- 전체 pytest는 SUP-007B 체크포인트에서 15분 상한과 기존 Artifact admission 메시지 불일치를 이미
  재현했으므로 동일 원인의 전 범위 실행을 반복하지 않았다. SUP-008 관련·인접 묶음은 위와 같이 통과했다.

### 2026-08-09 SUP-007A/B 집중·통합 검증

- SUP-007A 구현 커밋: `16fe8d1`
- SUP-007B 구현 커밋: `2434e83`
- General Attack 실행·Proposal·Permit·Outcome·Capability rollout 회귀: 156 passed
- General Attack direct-call·Control Plane 집중 회귀: 20 passed
- Control Plane 인접 회귀: 116 passed, 1 skipped
  - skip: 격리된 `PAJIN_TEST_CONTROL_PLANE_URL` 미설정
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 258 source files 통과
- 변경 Python format check: 통과
- 변경 Markdown 11개 상대 링크 검사: 통과
- `git diff --cached --check`: 통과
- 전체 pytest: 15분 상한에서 약 45%까지 진행 후 timeout. 여러 실패 표시가 관찰됐고,
  `-x` 최초 실패 재현은 634 passed, 11 skipped 뒤 기존 Artifact admission 오류 메시지 불일치 1건이다.
  이번 SUP-007B diff에는 해당 모듈과 테스트가 포함되지 않는다.

### 2026-08-09 APPROVAL-001C3 집중·통합 검증

- C3 batch runtime·backup/restore 집중 묶음: 85 passed
- APPROVAL-001A/B/C1/C2·General Attack outcome/cleanup·Control Plane 인접 회귀: 180 passed
- Ruff 전체 `src tests containers`: 통과
- Linux 대상 strict mypy: 257 source files 통과
- 변경 Python format check: 통과
- 전체 pytest: 20분 상한에서 약 64%까지 진행 후 timeout. 최초 실패 재현은
  `tests/test_control_plane_artifact_admission.py::test_artifact_admission_rejects_mismatched_sealed_run_without_authority`
  의 오류 메시지 기대값(`not admission-bound`)과 실제 상위 오류(`staged source Artifact failed managed admission`)
  불일치이며 C3 변경 파일 밖이다. `-x` 재현 결과 634 passed, 11 skipped 뒤 해당 1 failure다.

### 2026-08-06 APPROVAL-001C1/C2 집중 검증

- 새 no-write/reversible batch model·journal·dispatcher 집중 테스트: 13 passed
- 기존 APPROVAL-001A/B·Permit·General Attack과 C1/C2 결합 회귀: 161 passed
- Graph 전체 모듈 회귀: 178 passed, 2 skipped(POSIX link semantics)
- Ruff 전체: 통과
- Linux 대상 strict mypy: 257 source files 통과
- 변경 Python format check: 통과
- 공개 `pajin.graph` import: 통과

### 2026-08-06 저장소 전 범위 리팩터링·안정화 재검증

- APPROVAL-001B 중복 구조 정리 뒤 benchmark distribution fixture 만료, Capability 발급 wall-clock,
  긴 환경변수, Windows `uv`·절대 경로, MCP envelope, 패키징 source tree, POSIX mode·process-group,
  Linux container observation fixture의 실제 실패를 각각 독립 커밋으로 수정했다.
- Windows first-failure 전체 회귀는 POSIX 전용 파일을 제외한 상태에서 1,063 passed, 78 skipped까지
  진행한 뒤 stale MCP fixture를 찾았고, 수정 후 나머지는 파일 묶음으로 분할 검증했다.
- error-safety부터 Graph admission: 362 passed
- Graph backup·CampaignFact·SQLite·KISA·local replay: 195 passed, 2 skipped
- policy·provider·replay runtime 1차: 264 passed, 1 skipped
  - replay tickets 전체: 39 passed, 10 skipped
  - replay verify CLI·worker process: 11 passed, 1 skipped
- safe-files·scope·secrets·Supervisor: 206 passed, 2 skipped
- Tool Loop 전체: 37 passed, validation artifact 묶음: 51 passed
- Worker HTTP 전체: 35 passed, 1 skipped
- workflow integrity 전체: 20 passed, YAML loader: 18 passed
- 패키징은 생성 console-script 실행 smoke 1건을 제외한 16건이 통과했다. 제외한 한 건도 clean
  wheel/sdist build·install·import·metadata까지 통과한 뒤 조직 Windows 애플리케이션 제어가 임시
  console-script `.exe` 실행을 `WinError 4551`로 차단했다.
- Ruff 전체: 통과
- Linux 대상 strict mypy: 256 source files 통과
- Windows 대상 mypy: 배포 코드의 POSIX 전용 `os` API 33건만 실패
- `git diff --check`: 통과
- Windows에서 단일 전체 pytest는 POSIX directory fsync·dirfd·비이식 파일명·worker daemon 경계 때문에
  완료하지 못했다. `tests/test_control_plane_artifacts.py`, `test_control_plane_artifact_admission.py`,
  `test_control_plane_replay.py`, `test_integrity.py`, `test_worker_daemon.py`, `test_worker_health.py`의
  Linux 경로와 packaging console-wrapper smoke는 Linux CI 또는 허용된 환경에서 재검증해야 한다.

아래 항목은 APPROVAL-001B 구현 완료 시점의 더 넓은 검증 기록이다.

- APPROVAL/PERMIT/General Attack 집중 회귀: 131 passed
- approval store·legacy backup·Graph SQLite 인접 회귀: 36 passed, 2 skipped
- existing Capability rollout: 35 passed
- Control Plane Web: 14 passed, 1 skipped
  - Node.js 미제공으로 dependency-free Web Console runtime 1건 skip
- Common Engine execution gate: 8 passed
  - Windows 환경에서 마지막 두 테스트가 각각 약 60~70초 걸려 6+1+1로 분할 실행
- 관련 검증 합계: 224 passed, 3 skipped
- Ruff 전체: 통과
- Linux 대상 strict mypy: 256 source files 통과
- 변경 모듈 `python -B` import 검증: 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 Benchmark registry fixture 만료에서 중단
  - 오류: `Benchmark registry distribution is not currently valid`
  - 이번 승인 변경의 회귀와 구분한다.
- `git diff --check`: 통과
- `compileall`은 기존 `src/**/__pycache__` 권한 때문에 `.pyc` 교체에서 실패했다. 같은 모듈의
  no-bytecode import와 Ruff·mypy·pytest 통과로 구문 실패와 구분한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_approval_models.py tests\test_graph_action_permit.py tests\test_general_attack_action_permit.py tests\test_general_attack_action_outcome.py tests\test_general_attack_action_cleanup.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_action_approval_store.py tests\test_graph_backup_v2_compatibility.py tests\test_graph_sqlite_store.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_existing_capability_rollout.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_control_plane_web.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_execution_gate.py
.\.venv\Scripts\python.exe -m ruff check --no-cache src tests containers
New-Item -ItemType Directory -Path ..\.codex-tmp\pajin-mypy -Force | Out-Null
.\.venv\Scripts\python.exe -m mypy --platform linux --cache-dir ..\.codex-tmp\pajin-mypy src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 안정화 점검

contract·quality·trust 관점의 병렬 읽기 전용 검토에서 초기 구현의 retry registry object-identity,
stale test double, generic policy/verifier bypass, approval receipt outcome 누락, cross-release substitution,
strict JSON boolean/number coercion, Control Plane receipt surface와 store post-verification rollback 공백을
찾았다. canonical policy digest, path-specific writer, full activation registry, strict before-validator,
release 5-tuple, durable receipt assessment/completion binding과 transaction 내부 post-verification으로
수정했다. 다른 정상 receipt 치환, 다른 policy registry 재claim과 post-verifier 실패를 음성 테스트로
고정한 뒤 최종 검토에서 P0~P2가 남지 않았다.

이번 짧은 안정화 점검에서는 HANDOFF가 실제 `8733ccc` 커밋을 반영하지 않던 문서 드리프트,
reversible approval scope의 strict JSON pairing, 기존 no-write authority와 새 write authority의 policy
분리, outcome의 approval side-effect·cleanup Definition 교차검증 누락을 수정했다. generic writer,
cleanup insert failure, transaction post-verifier drift와 backup/restore retry를 음성·원자성 테스트로
고정했다.

동작 보존 리팩터링에서는 승인·Permit·receipt·cleanup hold 결과의 row decode와 authorization 조립을
단일 헬퍼로 모으고, SQLite 원자 트랜잭션의 기존 tuple 조회와 식별자 충돌 SQL을 분리했다. high-level
authority의 canonical·exact-result 검증과 General Attack dispatcher의 envelope·activation pin도 공통
경로로 모았다. wire shape, schema version, 공개 authority, error branch와 검증 순서는 변경하지 않았다.

## 현재 상태와 다음 한 단계

Phase 8 VAL-004C는 `56f5dcf`, Phase 9 UX-001A draft는 `6312215`, UX-001B1 local artifact·CLI는
`1c5f68e`, UX-001B2 Control Plane verified read는 `1c03188`에 보존됐다.
이 문서 커밋 뒤 working tree는 clean이어야 하며 push는 별도 명시 승인 전까지 수행하지 않는다.

다음 수직 슬라이스는 `UX-001B3`다. B2 exact locator 규칙과 B1 verifier로 exact draft·original typed source를
다시 검증한 뒤 Bug Bounty는 별도 scope-digest approval, CTF는 독립적인 authorization-window evaluation을
각 기존 compiler에 명시적으로 전달하는 operator handoff를 추가한다. preview·draft digest를 approval이나
compiler 입력으로 대체하지 않고, stale·foreign·missing approval과 source 치환은 compiler 호출 전에 fail
closed해야 한다. Campaign 생성 이외의 Capability·Permit·Run admission이나 새 compiler·approval authority는
추가하지 않는다.

## 알려진 경계

- UX-001B2는 exact digest 단건 redacted 조회만 지원한다. listing·편집·삭제·retention·compiler handoff,
  Pentest·AI Assessment·CTF Suite source는 없으며 조회 결과는 approval·authorization 충족이나 실행 준비를
  뜻하지 않는다.
- CHAIN-001은 DISC-003C의 explicit `x-pajin-rag/index-management`만 AI admin Surface로 해석한다. 실제
  authentication bypass나 admin access를 관찰하지 않으며 UI·MCP·provider admin은 미지원이다.
- CHAIN-002는 WALK-003가 봉인할 때 검증해 포함한 WALK-002 nested root·artifact authority를 신뢰하며
  실제 upload·retrieval·MCP argument influence·승인 누락·internal data access를 관찰하지 않는다.
  P0-D2B synthetic Finding은 CHAIN-002 validation authority가 아니다.
- CHAIN-003은 exact `string/uri` MCP argument와 `x-pajin-internal-api: true` OpenAPI operation만 결박한다.
  실제 prompt-to-argument influence, URL dispatch·resolution·reachability, Internal API access나 data
  exposure를 관찰하지 않는다. demo `inspect_url`은 invocation allowlist 밖에 있다.
- CHAIN-004는 exact version-1 tenant retrieval·data response OpenAPI 선언과 같은 exact route만 결박한다.
  header·query·body selector를 parameter/schema에 해석하지 않고 path placeholder만 추가 검증한다. 실제
  tenant 값·selector control·retrieval success·cross-tenant access·response body·data exposure는 관찰하지
  않는다.
- CHAIN-005의 privileged는 exact WALK-003 `approvalRequired=true` Capability의 독립 승인 경계만 뜻한다.
  실제 승인 거부·우회, operating-system privilege, admin·data access, Grant·Permit·dispatch·Worker outcome·
  impact는 관찰하지 않는다.
- VAL-001은 CHAIN-002/005의 validity Claim과 existing WALK-005B2 fresh Replay만 결박한다. impact·severity·
  negative control·counterfactual·N-run·full confirmation은 포함하지 않으며 CHAIN-001/003/004에는 대응
  Replay predecessor가 없다. local sealed freshness는 별도 off-host 조직의 cryptographic attestation이 아니다.
- VAL-002는 validity-only 요구 catalog이고 exact ordered `fresh-session`·`stateless` 격리 정책만
  허용하며 `preserve-scenario-session`은 거부한다. VAL-003은 exact Profile별 최소 registered depth만
  결박한다.
  VAL-004A는 KISA M03·M06·A04의 세 depth, VAL-004B/004C는 VAL-001 stateless WALK MCP의 single·controlled·
  repeated-controlled evidence를 실제 충족 판정에 연결한다. 두 adapter의 Claim·request·Tool·session 의미는
  혼합하지 않는다. impact·severity, Profile 선택, Campaign 변경, execution·confirmation·Finding authority는
  여전히 증명하지 않는다.
- policy registry, writer token, approval verifier와 cleanup verifier는 process-local deployment TCB다.
  approval·Permit·receipt·cleanup hold 소비는 durable하지만 verifier code identity는 SQLite에 pin되지
  않는다.
- current production inventory에는 reversible-write Capability가 없다. `capability-graph-v1`, Common
  Engine과 legacy write는 cleanup authority composition이 없어 닫혀 있다.
- C3는 General Attack 별도 메서드와 Control Plane 별도 Job profile에서만 opt-in된다. 기본 batch workflow,
  cleanup-hold aggregation, Control Plane write, cross-host coordination과 T3+는 미지원이다.
- batch journal과 Graph DB는 하나의 transaction이 아니므로 경계 crash는 manual review로 닫히며 자동
  redispatch하지 않는다. local backup/restore는 이를 그대로 보존하지만 signed/encrypted remote retention,
  anti-rollback repository와 durable verifier identity는 아직 없다. journal 삭제도 구현하지 않았다.
- Graph schema v4 direct downgrade는 없다. rollback 시 v4 reader와 immutable consumption evidence를
  유지해야 한다.
- Windows `dirfd`/directory fsync/symlink/비이식 파일명과 조직 AppControl 제약은 코드 회귀와 구분한다.
- Docker daemon과 real-container 경로는 이번 체크포인트에서 확인하지 않았다.
