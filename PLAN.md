# PAJIN 구현 계획

- 상태 권위: 이 파일
- 아키텍처 권위: `docs/rfc/0001-pajin-architecture-v2.md`,
  `docs/rfc/0002-multi-domain-security-analysis-architecture.md`
- 현재 단계: Phase 25 — Governed Measured AI System-Prompt Disclosure — `AI-002D` 로컬 구현·결정론적 검증 완료, exact conformance 대기
- 현재 우선순위: `AI-002D` checkpoint 전체 diff와 Git 상태 검토
- 다음 우선순위: 별도 승인된 checkpoint commit/push와 새 exact-commit repo-wide green 확인 뒤 manual `AI-002D` conformance

## 제품 목표

PAJIN은 Web, Network, System, Application, Mobile, Cloud, AI, Cryptography, Digital Forensics를
하나의 Canonical Graph와 Capability authority model 아래에서 다루는 policy-governed
autonomous security analysis and validation platform을 지향한다.

현재 실제 executable product coverage는 Pentest GET Recon/Replay, 제한된 KISA LLM/RAG,
고정 Bug Bounty·CTF lab과 관련 검증 경계다. 9개 Security Domain 전체 지원은 장기 목표이며
현재 구현 상태가 아니다.

## 상태 구분

- `[x] implemented`: 코드·테스트·버전형 계약이 연결된 상태
- `[ ] conformance-pending`: 실행 코드·계약·비실행 검증은 존재하지만 해당 단계가 요구하는
  live conformance가 아직 없는 상태
- `[ ] contract/scaffold`: RFC·ADR·schema 또는 비실행 scaffold만 존재하는 상태로 해당 항목에 명시
- `[ ] planned`: 구현과 실행 증거가 아직 없는 상태

문서를 추가하거나 로드맵에 넣은 사실만으로 executable support를 주장하지 않는다.

## 공통 불변식

```text
Surface
-> Hypothesis
-> Capability
-> Proposal
-> Policy / Approval
-> ActionPermit
-> Gateway / Worker
-> Observation
-> Evidence
-> Graph Admission
-> New Snapshot
-> Replan
```

```text
Candidate / Claim
-> Independent Replay
-> Controls / Oracle
-> Validation
-> Finding
-> Retest
```

- Discovery, Observation, model output, Tool metadata와 Security Domain은 권위가 아니다.
- 새 Surface는 `registered-not-authorized`로 시작하며 Scope를 자동 확장하지 않는다.
- 실행은 exact registered Capability, current Campaign/activation authority와 Permit이 필요하다.
- exact retry는 소비된 Action을 재실행하지 않는다.
- Finding은 Profile이 요구하는 Replay/validation floor 없이 확정하지 않는다.
- arbitrary shell agent와 silent Tool/plugin execution은 허용하지 않는다.
- 모든 경계는 fail closed한다.

## 완료된 기반 요약

상세 구현 경계와 음성 조건은 각 버전형 계약과 ADR이 권위다. 이 절은 현재 상태 탐색용
요약이며 커밋별 이력을 누적하지 않는다.

### Phase 0~3 — Common Engine, Capability, Canonical Graph

- [x] ARCH-001 Common Engine·Campaign Profile·MissionEnvelope·ActionPermit 방향
- [x] BENCH-001 deterministic benchmark schema와 Target Factory 기반
- [x] legacy Mode-to-Profile compatibility와 Common Engine parity
- [x] CAP-001 exact versioned Capability Definition과 Tool binding
- [x] CAP-002 seven-role code-backed authority set
- [x] CAP-003 authoring scaffold, CAP-004 signed lifecycle, CAP-005 compatibility adapters,
  CAP-006 quality metrics
- [x] GRAPH-001~006 single-Campaign Canonical Graph, single writer, append-only Event/Projection/
  Snapshot, stale Decision guard와 atomic one-use Permit dispatch

### Phase 4 — Hybrid Web·AI walking chain

- [x] `WALK-001~004` File Upload → RAG → MCP authorization Hypothesis → Graph admission/replan
- [x] `WALK-005A~C2` approval·Permit·Gateway evidence → Candidate/Claim → independent Replay →
  Finding/report → conservative Retest
- [x] `WALK-006` snapshot-only Shadow Task/Stop Decision 기록

### Phase 5~7 — Collaboration and bounded Supervisor

- [x] MEM-001~003 Graph-backed Campaign Fact, Artifact reference와 Collaboration Snapshot
- [x] HANDOFF-001~004 bounded handoff, urgent stop, receiver-bound content delivery
- [x] Shadow Supervisor proposal, provider/model binding, invocation journal, adversarial corpus와
  benchmark coordinate binding
- [x] limited activation, approval, cleanup, recovery와 bounded checkpoint scheduling

### Phase 8 — Coverage and validation generalization

- [x] CHAIN-001~005 bounded cross-Surface chain taxonomy
- [x] VAL-001 mode-neutral replay, VAL-002 validation depth, VAL-003 Profile assurance floor,
  VAL-004 evidence binding
- [x] Profile-compatible Finding projection과 validation comparison

### Phase 9 — Product UX and operations

- [x] Campaign Builder, Discovery/Graph/Decision views, review queue와 comparison views
- [x] verified SARIF export와 authenticated external delivery
- [x] OIDC MFA identity, ABAC mutation gates, Worker direct mTLS와 dedicated Replay Worker
- [x] resumable managed Artifact transport와 provider activation/revalidation/conformance contracts
- [x] local MinIO conformance 및 production AWS S3 custody selection contract

### Phase 10 — Pentest Profile activation

- [x] `PENTEST-000~001C2` inert Profile, signed authorization, Profile-native compile, signed
  Capability activation과 approved GET Recon
- [x] `PENTEST-002A~003D` neutral Observation, independently authorized Replay, controlled validity,
  current Graph confirmation과 Finding projection

Phase 10 Exit Gate: PENTEST-000~003D와 UX-007E~R1 완료. UX-007R2 production pilot은 보류한다.

## 현재 milestone

### Phase 11 — Initial Pentest / Red Team Productization

- [x] `PENTEST-004A` signed assessment compilation CLI
- [x] `PENTEST-004B` approved one-shot Recon CLI
- [x] `PENTEST-004C1` resumable sealed-evidence composition and local validity report
- [x] `PENTEST-004C2A` dedicated independently authorized Replay Worker entrypoint
- [x] `PENTEST-004C2B` durable source·Replay·three-Control Worker coordination and 004C1 handoff
  - [x] `PENTEST-004C2B1` signed durable journal and verified 004C1 handoff
  - [x] `PENTEST-004C2B2` concrete 004B/004C2A child adapters
- [x] `REDTEAM-001` initial executable Web/AI Capability bootstrap
  - [x] `REDTEAM-001A` approved single-turn LLM M03/M06 profile
  - [x] `REDTEAM-001B` multi-turn LLM/RAG A04 request-unit profile
  - [x] `REDTEAM-001C` bounded Web Capability profile
  - [x] `REDTEAM-001D` registered MCP Capability profile
- [x] `REDTEAM-002` initial detection·false-positive·replay·cost benchmark
  - exact REDTEAM-001A~D Profile·CAP-002·CAP-003·CAP-006 denominator
  - sealed positive·negative-control·Replay·policy-denial raw Observation과 aggregate report
  - valid Finding·cleanup·미등록 MCP negative/Replay metric은 explicit `not-applicable`
- [x] `UX-008` initial Scope·Evidence·Finding·report product flow
  - exact sealed REDTEAM-002 aggregate와 모든 source Observation을 재검증하는 read-only projection
  - Campaign Scope와 REDTEAM→PROF-001 mapping은 unavailable, Finding·delivery·execution authority는 false

Phase 11 Exit Gate: 완료. 현재 계약을 깨지 않고 승인된 초기 Pentest/Web/AI/MCP slice를 실행하며,
Profile별 Replay/validation floor와 초기 benchmark·product flow를 검증한다. REDTEAM-001은
모든 보안 도메인의 umbrella가 아니다.

## Multi-domain foundation

### Phase 12 — Multi-domain Security Analysis Foundation

ARCH-002와 ADR-0204~0206은 accepted architecture decision이다. 각 DOMAIN 항목은 아래 checkbox와
명시된 경계에 따라 상태를 구분하며 문서만으로 구현됐다고 보지 않는다.

- [x] `DOMAIN-001` code-owned Security Domain taxonomy
  - 9개 Domain을 exact versioned classification으로 정의
  - Campaign Profile과 orthogonal하고 authority marker는 모두 false
  - legacy `CapabilityDefinition.domain` identity를 변경하지 않음
  - classification-only이며 9개 Domain의 executable runtime 지원을 주장하지 않음
- [x] `DOMAIN-002` common multi-domain Surface/Hypothesis/Observation semantics
  - ARCH-001의 6개 node와 8개 relation 재사용
  - exact 9-domain locator/type semantic registry와 기존 one Graph writer 유지
  - semantics-only이며 locator implementation, Graph producer/admission과 runtime support는 false
- [x] `DOMAIN-003` domain-aware Capability inventory projection
  - exact CAP-001 definition과 complete CAP-002 authority set을 DOMAIN-001 classification에 결박
  - 현재 9개 Capability를 Web 3·AI 5·Cryptography 1로 explicit review하고 나머지는 미분류
  - signed release/activation과 Profile·Scope·Permit·Tool·Worker·runtime authority는 projection에 없음
  - legacy Domain namespace·surface·Tool metadata로 classification 또는 authority를 추론하지 않음
- [x] `DOMAIN-004` domain-specific Worker trust-boundary registry
  - exact lifecycle-verified signed Capability release bundle과 deployment-owned Worker mTLS
    subject/SPKI, exact code-owned minimum profile을 content-addressed binding으로 결박
  - 9개 Domain 최소 격리·identity·budget 요구를 등록하되 runtime conformance와 executable support는
    주장하지 않음
  - current activation·Campaign·Graph Decision·approval·Permit·Gateway authority는 기존 경로에만 남고
    Domain/Tool metadata로 Worker를 선택하지 않음
- [x] `DOMAIN-005` cross-domain Graph admission
  - exact admitted AI Observation에서 Web Surface `discovers`와 Hypothesis `enables`를 기존
    Canonical Graph single writer로 admission
  - current Snapshot prefix, source event, Campaign, Evidence lineage와 code-owned producer를 재검증
  - 새 Surface/Hypothesis는 `registered-not-authorized`; Scope·Capability·Permit·Worker·execution과
    source authority transfer는 불변
  - 현재 구현 producer는 AI→Web 1개뿐이며 일반 cross-domain runtime이나 executable Web/AI
    vertical slice를 주장하지 않음
- [x] `DOMAIN-006` domain-aware validation/replay/benchmark contract
  - 13개 common metric과 exact DOMAIN-001에 결박된 13개 domain-specific metric을 분리
  - 9개 Domain별 Replay/deterministic re-analysis 전략과 explicit `required`/`not-applicable` 등록
  - Forensics는 exploit Finding recall 대신 task success·artifact coverage·parsing accuracy·provenance
    preservation·corrupted-input handling을 사용
  - BENCH-001·REDTEAM-002 wire identity를 유지하고 measurement·quality·validation floor·Finding·
    Target Factory·Permit·execution authority를 모두 false로 고정

Phase 12 Exit Gate: 완료. Profile/Domain/Capability/Tool 관계가 코드와 테스트로 분리되고, 한
cross-domain Observation이 기존 Canonical Graph에 admission되지만 Scope·Capability·Permit·Worker
권위를 만들지 않으며 Domain metric registry가 측정·검증·실행 권위를 만들지 않음을
positive/adversarial test로 증명한다.

## Domain vertical slices

각 Phase는 하나의 domain 첫 slice만 닫는다. 기본 완료 범위는 typed Surface, read-only
discovery/analysis Capability, sealed Observation/Evidence, Graph admission, bounded Hypothesis,
independent Replay 또는 deterministic re-analysis, benchmark ground truth다. active probing,
mutation, credential use와 privilege-changing action은 별도 후속 milestone이다.

### Phase 13 — Web / API Security Analysis

- [x] `WEB-001A` typed HTTP/API Surface and locator registry
  - DOMAIN-001 Web classification과 DOMAIN-002 `web.http-operation`/locator schema를 exact 결박
  - 기존 `HTTPSurfaceLocator` concrete endpoint와 `HTTPRouteSurfaceLocator` URI-template route 재사용
  - typed Surface는 content-addressed `registered-not-authorized`이며 Observation/Evidence/Graph admission 아님
  - 기존 discovery·`AttackSurface` wire를 변경하지 않고 Scope·Capability·Permit·Tool·Worker·network·
    runtime·execution authority를 모두 false로 고정
- [x] `WEB-001B` read-only Web/API discovery Capability and egress-only Worker profile
  - 새 Campaign Profile이나 공격 엔진 없이 WEB-001A concrete GET Surface를 기존 complete Pentest
    Recon CAP-002와 DOMAIN-003 Web classification에 exact 결박
  - DOMAIN-004 minimum Web Worker profile의 bounded egress·no host filesystem·no credential·isolated
    non-root 요구를 pin하되 profile이나 Domain metadata로 Worker를 선택하지 않음
  - current signed activation 아래 `PreparedCapabilityAction`까지만 만들며 Worker job·egress policy·
    Observation/Evidence·Graph·Scope·approval·Permit·dispatch·execution authority는 만들지 않음
  - URI-template, non-GET, redirect, ambient credential, identity/budget/authority drift를 fail-closed
- [x] `WEB-001C` sealed Observation/Evidence and registered-not-authorized Graph admission
  - WEB-001B preparation을 동일한 existing Pentest dispatch intent와 exact 결박하고 PENTEST-002A가 sealed
    Run의 reservation·execution Evidence·normalized outcome과 Permit·approval·Worker receipt·Oracle을 재검증
  - existing PENTEST-002A producer와 Canonical Graph single writer만 재사용해 Action 1·neutral Observation 1·
    Evidence 3과 `produces`/`supported-by`만 admission하며 별도 Web ledger/writer를 만들지 않음
  - WEB-001A Surface와 DOMAIN-002 Web semantics는 classification/reference로만 결박하고 target knowledge를
    `registered-not-authorized`로 고정하며 Scope·Capability·approval·Permit·Worker·network·execution·Replay·
    Finding 권위를 만들지 않음
  - unsealed/failed/foreign source, preparation·Surface·semantic·Evidence·candidate drift와 authority escalation을
    fail-closed하고 exact Graph retry는 기존 semantic attempt를 재사용
- [x] `WEB-001D` independent replay and Web/API benchmark ground truth
  - WEB-001C exact source를 PENTEST-002B의 fresh Run·request·Decision·approval·one-use Permit·receipt·별도
    Worker session과 sealed body-free comparison에 결박하고 response match/change를 구분
  - exact DOMAIN-006 Web `independent-replay` plan을 재검증하되 source Graph admission이나 소비된 Permit으로
    Replay·Scope·Worker·network·execution 권위를 만들지 않음
  - 기존 P0-D1 Traditional Web/API catalog와 private code-owned Boolean SQLi Ground Truth를 별도
    `registered-ground-truth-not-measured` profile로 결박
  - generic GET Replay와 SQLi Ground Truth를 measured case/Finding으로 합치지 않으며 Target Factory selection,
    provider execution, detection quality, numeric metric과 Profile validation floor를 모두 false로 고정

Phase 13의 계획된 WEB-001A~D bounded bootstrap checkpoint는 완료했다. 이는 일반 Web/API bounded
Hypothesis, exact Ground Truth measurement linkage, Campaign Profile validation floor와 confirmed Finding까지
요구하는 ARCH-002의 전체 product vertical-slice 완료 주장은 아니다.

재사용: REDTEAM-001C, Pentest HTTP GET, HTTP/OpenAPI/auth/file-upload discovery, traditional Web
Target catalog, Docker/ZAP benchmark 자산.

### Phase 14 — AI / LLM / RAG / Agent / MCP Analysis

- [x] `AI-001A` model/RAG/agent/MCP/tool Surface classification
  - exact DOMAIN-001 AI classification과 DOMAIN-002 `ai.model-rag-agent-tool` semantics 아래 model, RAG,
    agent, MCP, Tool 5개 class와 10개 locator kind를 code-owned registry로 결박
  - RAG·MCP·Tool은 기존 locator를 재사용하고 model은 secret-free provider/model/immutable revision,
    agent는 existing model/Tool trace provenance dimension과 맞춘 additive locator로 표현
  - typed Surface는 `registered-not-authorized` pre-Observation knowledge이며 Profile·Scope·Capability·
    approval·Permit·Tool/Worker·network/credential·Graph·runtime·execution 권위를 모두 false로 고정
  - 기존 discovery `SurfaceLocator`/`AttackSurface`/DOMAIN-002/REDTEAM/walking/benchmark wire는 변경하지 않고
    class/kind/model/order/Domain/digest substitution, mutable alias, secret·authority injection과 boolean
    coercion을 fail-closed
- [x] `AI-001B` exact provider/model/tool-bound read-only analysis Capability
  - 기존 REDTEAM-001A M03/M06, REDTEAM-001B A04, REDTEAM-001D MCP의 exact Profile·CAP-002·Tool을
    DOMAIN-003 AI classification과 DOMAIN-004 minimum AI Worker profile에 결박
  - provider-backed action은 secret-free provider/model/immutable revision과 exact model/Tool 또는
    model/RAG/Tool Surface set을, MCP action은 fixed demo-security MCP/Tool Surface set을 고정
  - request/token/cost ceiling은 attenuation-only이며 provider registration을 preparation에서 재검증하지만
    budget reservation·credential lease·Worker job·Gateway dispatch를 만들지 않음
  - signed lifecycle `PreparedCapabilityAction`에서 멈추고 Product Profile·Campaign Scope·approval·Permit·
    deployment·credential·Observation/Evidence·Graph·Finding·execution 권위를 모두 false로 고정
- [x] `AI-001C` cross-Surface Observation/Evidence admission without Tool authority
  - exact AI-001B preparation과 기존 ActionPermit으로 실행·봉인된 REDTEAM LLM/RAG/MCP Capability Graph
    Run의 dispatch reconciliation, reservation, Tool/Worker Evidence와 Gateway outcome digest를 재검증
  - model/Tool, model/RAG/Tool, MCP/Tool Surface reference와 DOMAIN-002 `ai.behavior-observation`을
    content-addressed candidate에 결박하되 Surface node나 새 discovery authority는 만들지 않음
  - existing Canonical Graph single writer만 재사용해 Action 1·neutral Observation 1·Evidence 2와
    `produces`/`supported-by`만 admission하고 exact retry는 Tool을 재실행하지 않음
  - source output·Profile·Domain·MCP/Tool metadata를 Tool 선택, Scope·approval·Permit·Worker·network·
    credential·Replay·Finding·추가 execution authority로 전환하지 않고 `registered-not-authorized` 유지
- [x] `AI-001D` fresh-session replay, controls and AI benchmark extension
  - AI-001C exact sealed source/admission을 다시 열고 별도 KISA source의 2회 fresh-session Replay와
    Baseline·Negative Control·Counterfactual evidence를 VAL-004A로 완전 재검증
  - admitted AI source, KISA source, Replay 2회와 Control 3개의 target·Tool·scenario·threat class·turn·check를
    exact 결박하고 모든 session/request identity를 서로 분리
  - exact REDTEAM-002 Profile·Capability·CAP-003 mapping·CAP-006 Replay contract와 DOMAIN-006 AI
    `fresh-session-independent-replay` plan을 content-addressed projection에 결박
  - Ground Truth vocabulary/coverage requirement만 등록하고 concrete case·numeric measurement·AI Observation
    confirmation·Finding과 Scope·approval·Permit·Tool/Worker·network·credential·Replay·execution 권위는 만들지 않음

재사용: REDTEAM-001A/B/D, KISA Oracle/Replay, RAG/MCP walking chain과 local AI Target Factory.

Phase 14의 계획된 AI-001A~D bounded bootstrap checkpoint는 완료했다. 이는 arbitrary provider/agent/MCP
execution, concrete AI Ground Truth measurement, confirmed Finding 또는 일반 AI discovery/runtime 완료 주장이 아니다.

### Phase 15 — Network / Service Analysis

- [x] `NET-001A` host/service/protocol/port Surface model
  - exact Network classification과 `network.host-service` semantic을 host/port/service 3-class locator registry에 결박
  - DNS는 resolve하지 않고 IDNA canonicalize하며 IPv4/IPv6는 explicit address family와 대조
  - unknown service는 host/protocol/port로만 표현하고 service name을 well-known port에서 추론하지 않음
  - discovery/AttackSurface wire, Scope, scanner, raw socket, credential, Worker, network, Graph admission,
    execution 권위는 만들지 않음
- [x] `NET-001B` read-only service-identification Capability and scoped Network Worker
  - exact IPv4/IPv6 literal·TCP·단일 port Surface를 signed CAP-002 release와 fixed passive-banner budget에 결박
  - current Campaign의 exact host-wide CONNECT allow, same-authority deny 부재, CONNECT RoE와 private-network
    authority를 준비 단계에서 교차 검증
  - complete code-backed Capability와 local Network Domain classification, DOMAIN-004 minimum Network Worker
    profile을 content-addressed binding으로 고정하되 기존 global DOMAIN-003 inventory identity는 변경하지 않음
  - Worker는 egress proxy에만 CONNECT를 쓰고 Target application write 없이 banner 최대 1,024 bytes만 읽으며,
    Gateway는 exact authority로 egress를 축소하고 host-observed CONNECT receipt를 요구
  - preparation은 `PreparedCapabilityAction`에서 멈추고 approval·Permit·Worker·egress·network·Observation·
    Evidence·Graph admission·execution 권위를 만들지 않음
- [x] `NET-001C` protocol Observation/Evidence admission and bounded Hypothesis
  - current NET-001B activation·Campaign Scope와 sealed approved Run의 consumed Permit·approval receipt·
    completed dispatch·Gateway/Worker Evidence·host-observed CONNECT receipt를 함께 재검증
  - 기존 Graph single writer를 통해 neutral `network.protocol-observation`, succeeded Action과 2개 Evidence를
    admission하고 raw banner·target coordinate·product/version 문자열은 Graph prose에 복제하지 않음
  - bounded service label이 있을 때만 별도 fresh passive handshake를 요구하는 confidence `0.5` open
    `network.exposure` Hypothesis를 admit하고 unknown label에는 Hypothesis나 negative conclusion을 만들지 않음
  - service label, Graph membership과 source approval/Permit provenance는 Surface·Scope·Capability·approval·Permit·
    Tool·Worker·network·credential·Replay·Finding·execution 권위를 만들지 않음
- [x] `NET-001D` fresh handshake replay and isolated service benchmark
  - NET-001C source와 별도 승인·Permit·Run·request·Worker execution·sealed Evidence identity를 가진
    fresh passive handshake execution을 재검증하고 동일 Surface·Scope·Capability·protocol budget에 결박
  - bounded protocol label을 match/change/unresolved의 neutral comparison으로만 투영하고 banner digest
    일치는 별도 신호로 유지하며 어떤 상태도 service confirmation이나 Finding으로 승격하지 않음
  - ftp/imap/pop3/smtp/ssh known-positive와 unknown negative Control의 synthetic passive-banner Ground Truth를
    disposable loopback-container-per-case requirement로 등록하되 Target Factory·fixture 실행·numeric measurement·
    validation floor·Scope·approval·Permit·Worker·network·Replay·execution 권위를 만들지 않음

### Phase 16 — Cloud / IAM / Container Analysis

- [x] `CLOUD-001A` account/project/resource/IAM/container Surface model
  - DOMAIN-001 Cloud classification과 DOMAIN-002 `cloud.account-resource` semantics를 exact account, project,
    resource, IAM, container locator 5종과 content-addressed typed Surface registry에 결박
  - provider/partition/account parent와 account→project→resource/IAM/container parent lineage를 identity에
    포함하고 provider-local ID, explicit location, bounded IAM kind, immutable container/image digest를 유지
  - 기존 AWS S3/STS/KMS, MinIO와 Docker 계약의 좌표는 provider-local knowledge로만 표현할 수 있으며
    provider selection·tenant authority·credential lease·inventory/policy read·container access·Scope·Capability·
    Permit·Worker·network·Graph admission·mutation·execution 권위를 만들지 않음
- [x] `CLOUD-001B` read-only inventory/policy Capability with ephemeral credential lease
  - exact CLOUD-001A Surface와 complete signed CAP-002, local Cloud Domain classification, DOMAIN-004 minimum
    Cloud Worker profile, current Campaign의 exact Surface token·provider GET target Scope와 private-network
    authority를 함께 결박
  - `inventory-read`는 locator 5종, `policy-read`는 exact IAM Surface만 허용하고 explicit provider/partition·
    canonical HTTPS origin·exact Surface/operation GET route·TTL/runtime/response budget을 adapter에 고정
  - `allowPrivateNetworks`는 literal boolean만 허용하고 false일 때 non-global IP literal·`localhost`·fixed
    Docker host route를 exact allow와 별개로 거부하며 DNS/connect-time enforcement는 deployment runtime에 유지
  - trusted `SecretBroker` current snapshot과 일치하는 Campaign-scoped active single-use lease만 받아 raw lease
    ID·secret reference·material 없이 fingerprint-only reference로 준비하고 materialization은 허용하지 않음
  - adapter는 secret-free request description만 만들고 실제 provider runtime·WorkerJob·network call·result
    normalization은 제공하지 않으며 Oracle은 inconclusive로 유지
  - `PreparedCapabilityAction`에서 멈추고 provider selection/invocation·credential use·mutation·approval·Permit·
    Worker·egress·Observation·Evidence·Graph admission·execution 권위를 모두 false로 고정
- [x] `CLOUD-001C` resource/policy Observation admission without credential-use authority
  - current Cloud activation·Campaign Scope·CLOUD-001B preparation·Graph Decision/Proposal/Grant와 exactly one
    consumed Permit·durable approval-consumption receipt를 기존 권위 저장소에서 다시 결박
  - admission gate에 deployment-configured trust anchor를 고정해 exact Cloud Worker profile·direct mTLS identity·Capability/release·provider
    adapter·credential audience·Ed25519 key lifecycle를 검증하고 deployment-produced execution statement와
    detached neutral response receipt의 signature·file/content digest·timing·one-GET/zero-write budget을 재검증
  - credential-use receipt는 broker recheck·single-use materialization/consumption·discard를 나타내는 signed
    historical provenance로만 취급하며 bearer lease ID·secret reference·credential material을 저장하거나
    materialization·reuse·새 credential-use 권위를 만들지 않음
  - 기존 Graph single writer에 succeeded Action 1·neutral `cloud.api-observation` 1·signed execution Evidence 1·
    response-receipt Evidence 1과 `produces` 1·`supported-by` 2만 admission하고 raw provider body/header·resource·
    policy field·target coordinate를 Graph prose에 복제하지 않음
  - HTTP success나 body digest에서 resource existence/ownership·policy effect·effective permission을 추론하지
    않고 Hypothesis/Finding·Scope expansion·Capability activation·Permit issuance·provider/Worker selection·network·
    credential use·mutation·Replay·후속 execution 권위를 모두 false로 유지
- [x] `CLOUD-001D` deterministic policy replay and disposable cloud/emulator benchmark
  - 두 separately admitted CLOUD-001C policy-read execution을 deployment-configured trust anchor와 각 Graph
    authority store로 다시 열고 Surface·Scope·Capability·release·provider route·credential principal·query
    semantics는 같되 Run·preparation·request·Decision·Proposal·approval·Permit·dispatch·single-use lease·
    statement·external execution·source root·Graph admission·policy artifact identity는 모두 다르게 강제
  - CLOUD-001C response digest를 policy input으로 사용하지 않고 exact admission/execution/receipt/body/trust
    digest에 결박된 deployment-derived sanitized policy artifact를 별도 Ed25519 signature domain으로 검증
  - wildcard 없는 exact principal/action/resource rule에 deny-overrides allow deterministic evaluator를 적용해
    policy input+decision match, input changed+decision match, decision changed의 neutral state만 투영
  - exact allow·explicit deny override·implicit-deny negative Control 3개 Ground Truth와 per-case disposable
    account/emulator·fresh single-use credential·cleanup evidence requirement를 등록하되 실제 Target/credential
    provision·provider/emulator execution·cleanup·measurement·validation floor·Finding·Replay 권위는 만들지 않음

Phase 16의 계획된 CLOUD-001A~D bounded bootstrap checkpoint는 완료했다. 이는 repository-owned provider
runtime, provider-specific policy translator, effective-permission Oracle, live disposable Target measurement,
Cloud mutation 또는 general container runtime 완료 주장이 아니다.

### Phase 17 — System / Host Analysis

- [x] `SYS-001A` host/process/filesystem/service/configuration Surface model
  - DOMAIN-001 System classification과 DOMAIN-002 `system.host-resource` semantics를 exact host, process,
    filesystem, service, configuration locator 5종과 content-addressed typed Surface registry에 결박
  - 모든 child locator에 exact host 또는 resource parent lineage를 포함하고 process-instance/executable,
    filesystem content, service definition, sanitized configuration digest로 mutable local name과 분리
  - host ID·logical mount·configuration namespace를 canonicalize하고 PID, absolute/ambiguous path, symlink,
    service display name, raw configuration value, secret·credential·privilege metadata를 fail closed로 거부
  - 기존 discovery/AttackSurface wire, Docker/host journal, Scope, Capability, approval, Permit, authenticated
    host agent, Worker, network, Graph admission, credential/root, host mutation, execution 권위를 만들지 않음
- [x] `SYS-001B` read-only inspection Capability and authenticated non-root host-agent preparation boundary
  - complete signed CAP-002와 local System classification을 SYS-001A locator registry 및 DOMAIN-004
    deployment-scoped·bounded-host-read·deployment-authentication·authenticated-non-root-agent profile에 결박
  - host/process/filesystem/service/configuration class별 metadata-only read operation 5종을 exact mapping하고
    request 1회, artifact 1,024~1,048,576 bytes, runtime 1~60초 ceiling과 content/value read·signal·control·write 0을 강제
  - explicit host-agent deployment에 exact opaque host, public Worker mTLS policy digest와 selected subject/SPKI,
    executable digest, non-root run-as identity 및 attenuated operation set을 content-addressed 결박
  - 기존 pull-based Worker 경로와 맞지 않는 별도 agent endpoint를 만들지 않고 network-disabled Capability의
    current Campaign non-routable exact Surface token과 GET만 요구해 signed `PreparedCapabilityAction`까지 생성
  - bearer/direct-mTLS authentication, non-root attestation, agent session, host connection/read, budget reservation,
    WorkerJob, network, Observation/Evidence, Graph, approval, Permit, root·privilege escalation, mutation, execution 권위는 만들지 않음
- [x] `SYS-001C` host Observation/Evidence admission and bounded Hypothesis
  - current SYS-001B activation·Campaign Scope·exact preparation과 approved job, exactly one consumed
    ActionPermit·durable approval receipt를 기존 SQLite authority store에서 다시 결박
  - deployment-configured Ed25519 trust anchor가 exact host-agent deployment·Capability/release를 고정하고
    current Campaign·Grant·request·Tool spec으로 Gateway policy를 재계산한 sanitized outcome, Worker direct-mTLS
    admission, non-root runtime identity/confinement, detached result receipt의 file/content digest·timing·
    one-request/zero-content-read/zero-write budget을 검증
  - existing Graph single writer에 succeeded Action 1·neutral `system.host-observation` 1·restricted Evidence 2와
    `produces` 1·`supported-by` 2만 admission하고 raw host content·path·service/configuration 값을 Graph prose에
    복제하지 않으며 exact retry는 host agent·Tool·Gateway·Worker를 재실행하지 않음
  - fixed configuration-drift 또는 service-status review signal이 있을 때만 confidence `0.5` open
    `system.security-configuration` Hypothesis와 `enables` 1을 admission하고 signal 부재에는 Hypothesis나
    negative conclusion을 만들지 않음
  - source identity와 prior Permit provenance를 Surface·Scope·Capability·approval·Permit·host access·agent/Worker·
    network·credential·root·privilege escalation·service control·mutation·Replay·Finding·후속 execution 권위로
    전환하지 않음
- [x] `SYS-001D` snapshot/fresh-inspection replay and disposable host benchmark
  - SYS-001C signed result receipt에 raw-value-free `live-authenticated-host` 또는
    `immutable-host-snapshot` source kind를 요구하고 snapshot mode만 exact snapshot SHA-256을 결박
  - one stored SYS-001C source admission과 separately authorized sealed execution을 current C verifier로 다시
    열어 exact Capability/release·Surface/operation·deployment·Scope·request semantics를 맞추고 Run/request/
    Decision/Permit/approval/execution/statement/attestation/result identity 재사용을 거부하며 replay signed
    start가 source signed finish보다 이후인지 검증
  - wire projection의 trusted reload는 deployment trust anchor·양쪽 source evidence·exact Graph store로
    expected projection을 다시 만들고 전체 일치를 요구하며, bare model parse와 embedded anchor/Graph event는
    structural projection일 뿐 deployment verification으로 취급하지 않음
  - same immutable snapshot re-analysis와 fresh authenticated inspection을 명시적으로 구분하며 DOMAIN-006
    `immutable-snapshot-reanalysis` strategy는 전자에만 satisfied로 투영
  - equal result-body digest에는 exact signed result byte-count equality를 요구하고 digest·byte-count·bounded
    review signal로 neutral match/change/unresolved만 content-addressed projection하며 raw result를 해석하거나
    Graph write, Replay scheduling, host-agent/Tool/Worker/network 호출을 수행하지 않음
  - 5개 System Surface를 모두 포함하는 known-positive 2·negative Control 2·privilege-denial Control 1과
    disposable non-root container/VM, result-or-denial·cleanup evidence completeness 요구를 등록
  - private Ground Truth requirement registration과 실제 verification을 분리하고 fixture provision·execution·
    cleanup, raw host data, numeric measurement, Profile floor, host state/Finding, root·privilege escalation·
    service control·mutation 또는 후속 execution authority를 만들지 않음

### Phase 18 — Native Application / Binary Analysis

- [x] `APP-001A` binary/config/runtime/library Surface model
  - binary는 caller-supplied lowercase artifact SHA-256만으로 식별하고 path·filename·format·bytes·custody를
    Surface identity나 검증 주장으로 포함하지 않음
  - configuration과 runtime은 exact binary parent를, library는 exact binary 또는 runtime parent를 완전히
    내장해 parent substitution이 content identity를 바꾸도록 결박
  - configuration/runtime/library coordinate를 case-fold하고 path·URL·query·fragment·wildcard·mutable alias와
    floating/range version을 fail closed하며 raw content·process state·secret·credential field를 거부
  - typed Surface를 Application Domain과 DOMAIN-002 `application.artifact-runtime` semantics에 exact 결박하되
    artifact resolve/read·static/dynamic analysis·Scope·Capability·approval·Permit·sandbox/Worker·network·debugger·
    Graph·Finding·mutation·runtime support·execution authority를 만들지 않음
- [x] `APP-001B` sandboxed read-only static analysis Capability
  - exact APP-001A Surface와 deployment-supplied custody authority/object/authorization digest reference를
    content-addressed 결박하되 path·URL·raw bytes·secret·credential을 포함하지 않고 custody·authorization·
    artifact bytes 검증 또는 read를 수행했다고 주장하지 않음
  - Surface class별 operation/parser를 exact mapping하고 parser executable·sandbox image digest,
    non-root identity, read-only root와 no-exec artifact mount, disabled network, no-new-privileges 및
    artifact/output/runtime/memory/process ceiling을 configuration-only sandbox boundary에 결박
  - current signed CAP-002 release와 exact Campaign Surface-token Scope를 secret-free request 및
    `PreparedCapabilityAction`으로 준비하되 mount·sandbox/Worker·network·dynamic execution·debugger·
    Observation/Evidence·Graph·Finding·execution authority를 만들지 않음
- [x] `APP-001C` artifact-bound Observation/Evidence admission
  - current activation·Campaign Scope·exact APP-001B preparation과 approved job, exactly one consumed
    ActionPermit·durable approval receipt를 existing SQLite authority store에서 다시 결박
  - deployment-configured Ed25519 trust anchor와 signed execution이 exact custody/artifact digest,
    operation/parser, executable/image, non-root network-disabled read-only/no-exec sandbox, result receipt와
    causal budget을 주장하는지 재검증하되 repository가 live custody·sandbox conformance를 독립 주장하지 않음
  - existing Graph single writer에 succeeded Action 1, neutral `application.analysis-observation` 1,
    restricted Evidence 2와 `produces`/`supported-by`만 admission하고 fixed class-bound review signal에만
    confidence `0.5` open Hypothesis와 `enables`를 추가
  - raw artifact/output, format·configuration·runtime·dependency·vulnerability truth, Scope·Capability·approval·
    Permit·artifact access·sandbox/Worker·network·dynamic execution·debugger·mutation·Replay·Finding·후속 execution
    authority를 만들지 않음
- [x] `APP-001D` deterministic re-analysis and seeded binary benchmark
  - stored APP-001C admission과 separately authorized sealed re-analysis를 current verifier로 다시 열고 exact
    artifact/Surface/operation·custody/sandbox·parser executable/image·output schema·Scope·release·budget을 결박
  - wire projection의 trusted reload는 deployment trust anchor·양쪽 evidence root·exact Graph store를 요구하고
    current APP-001C verifier로 재구성한 결과와 전체 비교하며 bare model parse는 검증으로 취급하지 않음
  - Run/source-root/request/envelope/proposal/Decision/Permit/dispatch/approval/execution/attestation/result-receipt
    identity 재사용과 source finish 이전 re-analysis start를 fail closed
  - equal body digest에는 exact signed result byte-count equality를 요구하고 digest·byte-count·bounded review
    signal만으로 neutral match/change/unresolved를 투영하며 format·configuration·runtime·dependency·
    vulnerability·Hypothesis·Finding truth와 Graph write·Replay scheduling·후속 authority를 만들지 않음
  - binary/configuration/runtime/library 각각 known-positive와 negative Control 8건, disposable network-disabled
    non-root sandbox·read-only noexec mount·execution/runtime/result/cleanup evidence requirement를 등록하되
    Ground Truth verification·fixture materialization·provider/fixture execution·cleanup·coverage/quality/Profile-floor
    measurement를 수행하지 않음

Dynamic execution, debugger attach와 network access는 APP-001의 권위가 아니다.

### Phase 19 — Mobile Application Analysis

- [x] `MOBILE-001A` APK/IPA/app/runtime/storage/deeplink/TLS/auth Surface model
  - APP-001A exact binary를 부모로 재사용하는 APK/IPA package와 그 아래 exact application,
    runtime/storage/deeplink/TLS/auth locator 8종을 Mobile Domain 및 `mobile.application-runtime`
    semantics에 content-addressed registry로 결박
  - complete binary→package→application parent lineage, Android/iOS application ID·runtime·link·TLS
    platform 일치, canonical numeric/dotted exact runtime version, optional strict IDNA host와 path-free
    logical declaration coordinate를 강제
  - raw package/manifest/security configuration, signing·secret·credential material, storage value,
    full deeplink URI/path, device state/path와 mutable alias·range·wildcard·authority field를 거부하고
    preconstructed Pydantic parent/child도 public boundary에서 dump 후 재검증
  - typed Surface는 `registered-not-authorized`이며 package resolve/read·format/manifest/signing verification,
    static/dynamic analysis, sandbox/emulator/device/Tool/Worker selection·access·instrumentation, storage/network/
    credential use, Scope·Capability·approval·Permit·Graph·Finding·mutation·runtime·execution 권위를 만들지 않음
- [x] `MOBILE-001B` read-only package analysis Capability
  - exact MOBILE-001A Surface와 root APK/IPA package Surface, deployment-owned opaque
    custody/object/authorization digest reference 및 exact package byte ceiling을 함께 content-addressed 결박
  - 8개 Surface class별 operation을 완전 열거하고 parser family는 caller 입력이나 filename이 아니라
    canonical root package lineage에서만 APK/IPA로 도출
  - parser executable·sandbox image digest, non-root identity, network/DNS-disabled read-only/noexec mount,
    archive entry/uncompressed-size/path/nesting/compression-ratio ceiling과 traversal/symlink/duplicate-name 거부를
    configuration requirement로 결박하되 runtime conformance를 주장하지 않음
  - current signed CAP-002 release와 selected Surface 및 root package의 exact non-routable Campaign Scope를
    `PreparedCapabilityAction`으로 준비하되 current DOMAIN-004 device-bound Mobile profile에는 결박하지 않고
    WorkerJob·package read·device/emulator·install/launch/instrumentation·network·storage/TLS/auth·credential·
    Observation/Evidence·Graph·Hypothesis·Finding·mutation·execution authority를 만들지 않음
- [x] `MOBILE-001C` sealed package-analysis Observation/Evidence admission and bounded Hypothesis
  - current activation·Campaign selected/root exact Scope·MOBILE-001B preparation·approved job을 다시 만들고
    existing SQLite authority store의 exactly one consumed ActionPermit과 durable approval-consumption receipt에 결박
  - deployment-configured Ed25519 trust anchor와 signed external static-sandbox execution에서 selected/root Surface,
    package digest/bytes·custody authorization digest·operation/parser·executable/image·non-root identity·Gateway outcome·
    causal timing·zero live-channel budget과 detached digest-only result receipt를 검증
  - runtime receipt가 B의 package/output/runtime/memory/process 및 archive entry/uncompressed-size/path/nesting/
    compression-ratio ceiling과 observed archive maxima, traversal/symlink/duplicate-name rejection을 exact 결박하되
    configured deployment assertion을 repository-owned parser 또는 live sandbox proof로 승격하지 않음
  - existing Graph single writer에 succeeded Action 1, neutral `mobile.analysis-observation` 1, restricted Evidence 2,
    `produces` 1과 `supported-by` 2를 admission하고 8개 exact class/operation review signal에만 confidence `0.5`
    open `mobile.security-property` Hypothesis와 `enables` 1을 허용; no-signal에는 결론을 만들지 않음
  - current device-bound DOMAIN-004 Mobile profile은 계속 deferred/false로 유지하고 WorkerJob·package/raw output·
    format/manifest/signing/runtime/storage/deeplink/TLS/auth truth·device/emulator·install/launch/instrumentation·network·
    credential·mutation·Replay·Finding·후속 execution authority를 만들지 않음
- [x] `MOBILE-001D` package re-analysis and seeded mobile benchmark
  - one stored MOBILE-001C admission과 separately authorized sealed re-analysis를 current C verifier,
    deployment-configured trust anchor 및 양쪽 exact SQLite Graph store로 다시 열어 source admission과
    evidence context를 재검증하며 bare model parse를 trusted verification으로 취급하지 않음
  - selected/root Surface·complete parent lineage·platform·package digest/bytes·operation·custody/sandbox·
    lineage-derived parser·executable/image·output schema·selected/root exact Scope rule·release·activation·
    request/resource/archive ceiling과 6개 observed archive 값을 exact 결박해 drift를 changed result가 아닌
    incomparable input으로 fail closed
  - Run/source-root/request/envelope/proposal/Decision/Permit/dispatch/approval/execution/runtime receipt/
    attestation/result-receipt identity 재사용을 거부하고 re-analysis signed start가 source signed finish보다
    strictly later인지 검증
  - equal result-body digest에는 exact result byte-count equality를 요구하고 digest·bytes·bounded review signal의
    neutral match/change/unresolved만 투영하며 DOMAIN-006 `deterministic-package-reanalysis` strategy를 결박하되
    bytes equality 자체나 changed/unresolved를 package·manifest·runtime·security-property·Finding truth로 만들지 않음
  - APK/Android, IPA/iOS 및 application/runtime/storage/deeplink/TLS/auth의 양 플랫폼을 포함한 14개 valid
    selected/platform/root lineage마다 known-positive와 no-signal negative Control을 등록해 exact 28-case seeded
    profile을 만들고 disposable network/DNS-disabled non-root static sandbox·read-only/noexec package mount·archive
    safety·execution/runtime/result/cleanup evidence requirement를 결박하되 fixture materialization·provider/fixture
    execution·cleanup·manifest-component coverage/evidence completeness/detection quality/Profile-floor measurement를
    수행하지 않음
  - current device-bound DOMAIN-004 Mobile profile, profile conformance, WorkerJob, emulator/device, install/launch/
    instrumentation, storage/network/TLS/auth/credential use, Graph write, mutation, Replay scheduling, Finding 및
    후속 execution authority를 계속 false로 유지

Emulator/device instrumentation은 별도 device identity와 authority가 필요한 후속 slice다.

### Phase 20 — Cryptographic Analysis

- [x] `CRYPTO-001A` protocol/key-usage/ciphertext/configuration Surface model
  - protocol을 유일한 root로 두고 exact protocol parent를 내장한 key-usage, ciphertext,
    configuration sibling locator 4종을 Cryptography Domain 및 `cryptography.protocol-key-artifact`
    semantics에 content-addressed registry로 결박
  - typed Surface는 `registered-not-authorized`이며 artifact resolution/read, offline analysis, key material/
    credential access·use, cryptographic operation, protocol negotiation, Oracle/recomputation, Scope·Capability·
    approval·Permit·Tool/Worker·network·Graph·Finding·mutation·runtime·execution 권위를 만들지 않음
- [x] `CRYPTO-001B` offline cryptographic misuse analysis Capability
  - exact CRYPTO-001A Surface class·locator kind·input kind·digest source·operation·logical analyzer 전체 mapping과
    code-owned 4-signal rule set을 Tool/signed code-backed Capability identity에 결박하고 current Range activation·
    exact non-routable Campaign Scope를 하나의 content-addressed preparation으로 고정
  - all seven CAP-002 role을 등록하되 executor/normalizer는 fail closed, Oracle는 `INCONCLUSIVE`, Replay/cleanup은
    no-op이며 approval·Permit·Gateway dispatch·artifact access·analysis·Observation/Evidence·Graph·Hypothesis·Finding·
    execution authority를 계속 false로 유지
- [x] `CRYPTO-001C` Oracle-recomputed Observation/Evidence admission
  - current CRYPTO-001B preparation, Campaign Scope, consumed single-use Permit, approval receipt와
    Gateway outcome을 다시 계산하고 exact Surface·Tool·release·sandbox·custody·budget authority drift를 거부
  - existing Graph single writer와 Snapshot CAS로 exact Action 1, neutral
    `cryptography.analysis-observation` 1, restricted Evidence 2를 admission하고 `review`에서만 confidence `0.5`
    open `cryptography.misuse-weakness` Hypothesis를 추가하며 exact retry는 Evidence·current authority·Oracle를
    재검증한 뒤 idempotent하게 반환하고 non-exact retry와 intervening-event Hypothesis는 fail closed
  - Scope expansion, artifact/key/credential access, sandbox invocation, Worker selection, network/DNS,
    cryptographic operation, protocol negotiation, Replay, Finding confirmation 및 후속 action authority를 계속 false로 유지
- [x] `CRYPTO-001D` independent implementation replay and seeded vector benchmark
  - one stored CRYPTO-001C admission과 separately authorized sealed recomputation을 각 current C verifier,
    exact SQLite Graph store 및 별도 deployment trust anchor로 다시 열어 source admission과 양쪽 evidence를
    재검증하며 bare model parse를 trusted verification으로 취급하지 않음
  - opaque result-body digest·signed bytes·structural Oracle disposition·class-owned signal의 neutral
    matched/changed/unresolved만 투영하고 equal digest/different bytes를 fail closed하며 DOMAIN-006 exact
    `independent-recomputation` strategy를 결박하되 semantic misuse·negative claim·Finding·numeric metric을 만들지 않음
  - distinct implementation provenance는 executable/image/sandbox/signer identity까지만 뜻하며 source-code·algorithm·
    organization·supply-chain·physical host/Worker·common-mode independence, artifact/result-body/key access, target-domain
    cryptographic operation, network, Graph write, Replay scheduling 및 후속 execution authority를 계속 false로 유지

기존 CTF single-byte XOR는 재사용 자산이지 일반 Cryptography 지원 완료 증거가 아니다.

### Phase 21 — Read-only Digital Forensics Analysis

- [x] `FORENSICS-001A` disk/memory/log/artifact Surface and provenance model
  - four content-free sibling locator와 opaque complete-Surface reference를 exact Forensics Domain/type-set에 결박
  - root/artifact/provenance/digest/bytes를 identity로 쓰되 source 존재·custody·authenticity·immutability를 주장하지 않음
  - raw locator/evidence/credential을 배제하고 source read·mutation·parser·Scope·execution·Graph 권위를 만들지 않음
- [x] `FORENSICS-001B` immutable-source read-only parser/analyzer Capability
  - exact Surface/Scope/release와 code-owned class→input→operation→parser mapping을 preparation에 결박
  - non-root read-only/noexec sandbox, provenance/no-mutation Evidence와 resource/decompression ceilings를 고정
  - network/source read·write/credential/plugin 예산은 0이며 approval·Permit·Worker/parser 실행은 만들지 않음
- [x] `FORENSICS-001C` provenance-preserving Observation/Evidence admission
  - deployment-owned bounded evidence root와 distinct source/execution Trust Anchor로 two sealed receipts를 검증
  - exact Surface/preparation/Grant/Gateway/Permit/runtime assertions를 재검증하되 supplied truth를 독립 증명하지 않음
  - raw body 없이 neutral Observation/Evidence만 CAS admit하고 `review`에만 bounded open Hypothesis를 허용
  - semantic/negative truth, parser correctness, Finding, Replay, measurement와 후속 실행 권위는 만들지 않음
- [x] `FORENSICS-001D` deterministic re-parse or independent parser benchmark
  - stored C admission과 later sealed execution을 current loader/store/Trust Anchor로 다시 열고 Graph는 보존
  - all-same implementation은 deterministic, all-distinct는 independent로 유도하며 partial drift와 identity reuse 거부
  - digest/bytes/disposition/signal만 neutral 비교하고 agreement를 correctness·truth·Finding으로 승격하지 않음
  - four Surface의 positive/no-signal/corrupted exact 12-case와 metrics/Evidence 요구만 등록; 실행·측정은 false

Phase 21 Exit Gate: 완료. content-free Surface, read-only preparation, authenticated neutral admission과 supplied
comparison/requirements를 연결했다. Source provider, parser/Worker, semantic Oracle, materialized benchmark,
production 지원이나 credential/lateral movement/evidence mutation 권위의 증거는 아니다.

## 다음 milestone

### Phase 22 — Governed Measured Web/API Validation

[ADR-0252](docs/adr/0252-route-measured-web-validation-through-an-exact-egress-proxy-bridge.md)부터
[ADR-0255](docs/adr/0255-admit-sealed-web-source-measurement-without-execution-authority.md)까지가
additive identity, source/controlled route 분리, fresh Target lifecycle, floor와 knowledge-only admission 경계를
확정한다. 상세 authority와 검증 근거는 각 ADR 및 WEB-002 versioned contract가 담당한다.

- [x] `WEB-002A` exact measured Web case authority — P0-D1/P0-E2B private binding, signed route,
  DOMAIN-006 Web plan·floor·denial Control과 public-safe commitment를 실행 권위 없이 등록
- [x] `WEB-002B` disposable registry-governed Web measurement execution — fresh internal Target, immutable
  images, raw SARIF normalization, completed journal과 receipt-bound zero-residue cleanup을 sealed authority로 결박
- [x] `WEB-002C` measured Web Observation/Evidence admission — source chain을 다시 검증해 neutral
  Observation/Evidence와 bounded open Hypothesis만 Graph에 admission하고 Ground Truth·Finding·실행 권위는 제외
- [x] `WEB-002D` independent controlled validation and floor — disjoint approved Worker execution, denial
  tombstone, private matcher와 DOMAIN-006 floor를 재검증해 claim ceiling이 제한된 public-safe Finding만 projection

Phase 22 Exit Gate: 완료. exact commit `975bf7876a186cefae66c289d09f530f3e0fe7aa`의 Ubuntu run
`33310558350`에서 real-Docker conformance와 독립 residue audit이 성공했다. synthetic P0-D1의 source,
independent validation, floor와 Finding만 sealed lineage로 연결하며 Worker는 proxy-only이고 임의 target/scanner,
production/external probing과 다른 Domain runtime은 제외한다.

### Phase 23 — Bounded Measured Web Operator Product Read

[ADR-0257](docs/adr/0257-project-web-002d-through-a-read-only-operator-product-flow.md)은 완료된
WEB-002A~D wire를 변경하지 않고 exact WEB-002D authority를 Operator가 읽을 수 있는 bounded product
flow로 투영한다. 이 Phase는 새 Web runtime이 아니며, Network는 이후 fresh checkpoint review의 다음
new-domain runtime 우선순위로 유지한다.

- [x] `UX-009A` sealed measured-Web product-flow projection — complete
  - exact `load_web_controlled_validation_authority`로 source Run과 WEB-002A/002B, floor, denial,
    cleanup, bounded Finding chain을 publication과 reload 양쪽에서 contextfully 재검증
  - measured-case Scope, content-free Evidence reference, floor state, benchmark-ground-truth-match
    Finding과 unavailable report state만 새 content-addressed sealed Run에 projection
  - WEB-002C Graph Hypothesis를 인과적 predecessor로 결합하지 않고 HTTP/UI, report, delivery와
    Target/provider/Worker/network/additional execution 권위를 모두 false로 유지
- [x] `UX-009B` deployment-pinned contextful product reader — complete
  - deployment-owned registry/resolver만 exact product Run과 complete WEB-002D reopen context를 선택
  - caller-selected root/path/provider/adapter/trust anchor/journal/private mapping과 bare outer JSON 거부
  - fresh process에서 source와 projection을 모두 재구성하며 read 자체는 어떤 durable state도 변경하지 않음
- [x] `UX-009C` Operator-only Control Plane and same-origin Web Console view — complete
  - body/query 없는 fixed non-cacheable GET만 Operator에게 제공하고 다른 role, foreign/unconfigured reader와
    method substitution은 fail closed하며 concurrent request는 exact reader 주위에서 직렬화
  - Console은 exact metric identity·signed-64 rational을 포함한 wire와 authority ceiling 검증 뒤
    `textContent`만 쓰고 lock/token 교체/`pagehide`에서 폐기
  - durable application state와 private/runtime 좌표 공개 없음. UX-009B의 ephemeral advisory lock과
    read-only provider/inspector Evidence check는 유지
- [x] `UX-009D` fresh-session deterministic product-read conformance — complete
  - `spawn` production composition에서 두 publication/read, auth·transport와 isolated failure 13건을 검증
  - exact checkpoint `6cb58c1cf69795c86a4ccb6614b4e6fdf445ecbf`의 Ubuntu run
    `33410801762`, job `99549584968`에서 fresh-spawn conformance `1 passed in 836.08s`와
    unconditional PAJIN Docker residue audit이 모두 성공

Phase 23 Exit Gate: 완료. exact WEB-002D bounded Finding을 impact/severity가 미평가된
`benchmark-ground-truth-match`로만 표시하고, publication·fresh-session reader·Operator endpoint·Web Console이
동일한 false authority ceiling과 zero-side-effect를 유지한다. Phase 23 자체는 Network runtime 증거가 아니며,
후속 선정·Target Factory·governed measurement·product 경계 없이는 Network를 실행하지 않는다.

### Phase 24 — Governed Measured Network Service Identification

[ADR-0258](docs/adr/0258-select-governed-measured-network-service-identification-after-phase-23.md)은
Phase 23 이후 fresh checkpoint에서 Network를 다음 단일 measured runtime으로 선정한다. 범위는 NET-001D의
ftp/imap/pop3/smtp/ssh known-positive 5건과 unknown negative Control 1건뿐이며, DNS·UDP·port range·enumeration,
raw socket, active protocol write, credential, production/external target과 일반 scanner는 포함하지 않는다.

- [x] `NET-002A`: exact six-case public registration, private Ground Truth, fixed emitter/image와
  DOMAIN-006 protocol/floor를 등록하되 모든 실행 권위를 false로 유지
- [x] `NET-002B`: case별 fresh internal no-published-port Target과 proxy-only Worker source execution,
  public lineage/private raw lifecycle 분리 및 pre-dispatch denial 완료
- [x] `NET-002C`: source와 전역 identity가 분리된 six-case Replay, exact 14-metric floor와 public-safe
  aggregate 평가 완료. satisfied floor는 service confirmation이나 Finding이 아님
- [x] `NET-002D`: immutable zero-argument reader와 Operator GET, exact-commit Ubuntu real-Docker source/Replay
  12회, denial, cleanup, fresh reload와 unconditional zero-residue audit 완료

Phase 24 Exit Gate: 완료. exact checkpoint `9b3d8035252d26334d35caa55c0270356c71683a`가 여섯
code-owned fixture의 internal no-published-port Target, Worker zero-target-application-write, proxy-only bridge,
disjoint fresh authority, exact DOMAIN-006 metric/floor, read-only product ceiling과 zero residue를 Ubuntu 24.04
real-Docker에서 증명했다. 이 증거는 exact synthetic six-case 범위를 production/general Network 지원으로 확장하지 않는다.

### Phase 25 — Governed Measured AI System-Prompt Disclosure

[ADR-0259](docs/adr/0259-select-governed-measured-ai-system-prompt-disclosure-after-phase-24.md)은
Phase 24 이후 fresh checkpoint에서 code-owned KISA M03 system-prompt disclosure 한 건을 다음 단일
vertical slice로 선정한다. M06, A04, MCP, RAG, arbitrary prompt, external provider·target, provider credential과
general model/agent testing은 포함하지 않는다. current-main CI가 green이어야 runtime 구현을 시작한다.

- [x] `AI-002A` exact M03 measured-case authority — implemented locally, registration only
  - exact AI-001D M03 predecessor requirement, neutral public registration, private known-positive
    Ground Truth·prompt/check·Control derivation, immutable Target/Worker/proxy contracts, canonical
    source/two-Replay/three-Control protocol와 DOMAIN-006 AI floor를 결박하고 모든 runtime·product 권위를 false로 유지
- [x] `AI-002B` registry-governed disposable M03 source measurement — implemented locally
  - fresh internal no-published-port vulnerable Target을 기존 approval/Permit/Gateway/Worker 경로로 한 번 실행하고
    prompt/check/transcript/runtime을 private으로 격리하며 caller substitution을 dispatch 전에 거부
- [x] `AI-002C` independent fresh-session Replay, Controls, and AI floor — implemented locally
  - 두 supporting Replay와 exact Baseline/Negative/Counterfactual Controls를 fresh identity로 실행하고
    DOMAIN-006 AI metric/floor를 public-safe aggregate로만 평가
- [ ] `AI-002D` bounded product read and exact conformance — locally implemented, exact conformance pending
  - AI-only zero-argument Operator read와 exact-clean Ubuntu real-Docker source/Replay/Controls/denial/cleanup/
    residue conformance를 완료하되 Graph/Finding/report/delivery와 추가 실행 권위를 만들지 않음

AI-002C checkpoint `f52331dea30b6aa655fdfaca7c3f28c29b88f22d`와 CI duration 경계 보정
`f2b8d695b6ae03d0858be892f63f18cebf623ad9`가 `main`에 반영됐고, exact repo-wide CI run
`33603851321`은 Quality와 24개 pytest shard 모두 성공했다. 그 green을 전제로 AI-002D는 AI-002C를
contextfully reopen해 단일 public M03 case reference, exact 14-metric DOMAIN-006 aggregate, applicability,
floor state와 literal-false authority만 새 content-addressed product Run에 봉인한다. deployment-pinned
immutable registry와 zero-argument reader, authenticated Operator-only non-cacheable GET, fresh-spawn
no-execution/no-mutation reload, manual exact-clean Ubuntu workflow와 unconditional residue audit 계약을
추가했다.

AI-002D product/workflow 집중 검증은 `10 passed, 1 skipped`, AI-002A~D authority·fixture·source·Replay/
Controls·product 회귀는 `26 passed, 2 skipped`, 기존 Web/Network product 회귀는 `12 passed`다.
`src tests containers` 전체 Ruff, Linux 대상 strict mypy `384 source files`, 문서 정책·링크
`4 passed`가 통과했다. 기본 Windows-target mypy는 POSIX `os` symbol의 기존 49건에서 실패했지만
`--platform linux` 검증은 green이다. 스킵 두 건은 AI-002B와 AI-002D opt-in real-Docker다. 현재
container daemon을 사용할 수 없어 exact source/two-Replay/three-Control/product/residue 검증은
실행하지 않았고, 전체 repository pytest와 현재 AI-002D 변경의 새 exact-commit CI도 실행하지 않았다.

## 우선순위와 재평가 기준

- Tier 1: Web, AI
- Tier 2: Network, Cloud, System
- Tier 3: Application, Mobile
- Tier 4: Cryptography, Forensics

순서는 기존 자산 재사용, benchmark ground truth의 실현 가능성, read-only first slice와 안전한
Worker isolation을 기준으로 재평가할 수 있다. 한 PR에서 여러 domain runtime을 함께 구현하지
않는다.

Phase 23은 기존 WEB-002D를 소비하는 read-only product slice이고 Phase 24는 exact synthetic Network
measurement다. ADR-0259의 fresh checkpoint review는 exact KISA M03만 Phase 25로 선정했으며, 기존
AI-001/KISA/REDTEAM/P0-D2B 증거를 measured M03 또는 일반 AI 지원으로 계산하지 않는다.

## 미결정 제품 사항

다음 항목은 구현 중 암묵적으로 결정하지 않고 새 ADR 또는 버전형 계약으로 결정한다.

- legacy `CapabilityDefinition.domain`의 장기 deprecation 여부
- 향후 Capability 추가 시 code-owned Domain projection의 review·version 발행 절차
- Domain Surface locator registry의 publisher/review authority
- Worker trust-boundary profile의 deployment signing과 conformance authority
- Domain별 numeric measurement artifact, aggregator와 Ground Truth admission authority
- Network raw-socket 및 System agent privilege의 최초 허용 수준
- Cloud disposable benchmark provider와 credential custodian
- Mobile emulator/device provider와 signed app identity
- Forensics immutable evidence source와 chain-of-custody trust root
- 첫 production Graph Event Store, cross-host fence와 independently anchored evidence

## 완료 기준

각 Vertical Slice는 Task ID, Threat Model, 변경되는 Trust Boundary, Schema/API Version,
Backward Compatibility, Migration·Rollback, Positive·Adversarial Test, Audit Artifact/Event,
Benchmark 영향을 포함한다.

공통 완료 조건:

- 기존 Profile과 REDTEAM/PENTEST contract backward compatibility
- one Canonical Graph와 one Capability authority model 유지
- Security Domain metadata의 authority 부여 금지
- existing ActionPermit/Gateway/Worker 경로 재사용
- discovery와 cross-domain Observation의 Scope 비확장
- high-risk action의 approval 우회 금지
- no arbitrary shell authority, no silent Tool/plugin execution
- Profile별 Replay/validation floor와 audit/evidence lineage 유지
- documentation authority policy 준수
- positive/adversarial tests, Ruff, Linux 대상 strict mypy, 집중 pytest, 가능한 full pytest와
  Linux CI

환경 때문에 실행하지 못한 검증은 `HANDOFF.md`와 `KNOWN_ISSUES.md`에 정확히 기록한다.
