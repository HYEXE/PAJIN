# PAJIN 구현 계획

- 상태 권위: 이 파일
- 아키텍처 권위: `docs/rfc/0001-pajin-architecture-v2.md`,
  `docs/rfc/0002-multi-domain-security-analysis-architecture.md`
- 현재 단계: Phase 15 — Network / Service Analysis
- 현재 우선순위: `NET-001A` host/service/protocol/port Surface model
- 다음 우선순위: `NET-001B` read-only service-identification Capability and scoped Network Worker

## 제품 목표

PAJIN은 Web, Network, System, Application, Mobile, Cloud, AI, Cryptography, Digital Forensics를
하나의 Canonical Graph와 Capability authority model 아래에서 다루는 policy-governed
autonomous security analysis and validation platform을 지향한다.

현재 실제 executable product coverage는 Pentest GET Recon/Replay, 제한된 KISA LLM/RAG,
고정 Bug Bounty·CTF lab과 관련 검증 경계다. 9개 Security Domain 전체 지원은 장기 목표이며
현재 구현 상태가 아니다.

## 상태 구분

- `[x] implemented`: 코드·테스트·버전형 계약이 연결된 상태
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

- [ ] `NET-001A` host/service/protocol/port Surface model
- [ ] `NET-001B` read-only service-identification Capability and scoped Network Worker
- [ ] `NET-001C` protocol Observation/Evidence admission and bounded Hypothesis
- [ ] `NET-001D` fresh handshake replay and isolated service benchmark

### Phase 16 — Cloud / IAM / Container Analysis

- [ ] `CLOUD-001A` account/project/resource/IAM/container Surface model
- [ ] `CLOUD-001B` read-only inventory/policy Capability with ephemeral credential lease
- [ ] `CLOUD-001C` resource/policy Observation admission without credential-use authority
- [ ] `CLOUD-001D` deterministic policy replay and disposable cloud/emulator benchmark

### Phase 17 — System / Host Analysis

- [ ] `SYS-001A` host/process/filesystem/service/configuration Surface model
- [ ] `SYS-001B` read-only inspection Capability and authenticated non-root Worker
- [ ] `SYS-001C` host Observation/Evidence admission and bounded Hypothesis
- [ ] `SYS-001D` snapshot/fresh-inspection replay and disposable host benchmark

### Phase 18 — Native Application / Binary Analysis

- [ ] `APP-001A` binary/config/runtime/library Surface model
- [ ] `APP-001B` sandboxed read-only static analysis Capability
- [ ] `APP-001C` artifact-bound Observation/Evidence admission
- [ ] `APP-001D` deterministic re-analysis and seeded binary benchmark

Dynamic execution, debugger attach와 network access는 APP-001의 권위가 아니다.

### Phase 19 — Mobile Application Analysis

- [ ] `MOBILE-001A` APK/IPA/app/runtime/storage/deeplink/TLS/auth Surface model
- [ ] `MOBILE-001B` read-only package analysis Capability
- [ ] `MOBILE-001C` exact app/artifact Observation/Evidence admission
- [ ] `MOBILE-001D` package re-analysis and seeded mobile benchmark

Emulator/device instrumentation은 별도 device identity와 authority가 필요한 후속 slice다.

### Phase 20 — Cryptographic Analysis

- [ ] `CRYPTO-001A` protocol/key-usage/ciphertext/configuration Surface model
- [ ] `CRYPTO-001B` offline cryptographic misuse analysis Capability
- [ ] `CRYPTO-001C` Oracle-recomputed Observation/Evidence admission
- [ ] `CRYPTO-001D` independent implementation replay and seeded vector benchmark

기존 CTF single-byte XOR는 재사용 자산이지 일반 Cryptography 지원 완료 증거가 아니다.

### Phase 21 — Read-only Digital Forensics Analysis

- [ ] `FORENSICS-001A` disk/memory/log/artifact Surface and provenance model
- [ ] `FORENSICS-001B` immutable-source read-only parser/analyzer Capability
- [ ] `FORENSICS-001C` provenance-preserving Observation/Evidence admission
- [ ] `FORENSICS-001D` deterministic re-parse or independent parser benchmark

Forensics Observation은 Hypothesis를 만들 수 있지만 credential 사용, lateral movement,
evidence mutation 또는 공격 실행 권위를 만들지 않는다.

## 우선순위와 재평가 기준

- Tier 1: Web, AI
- Tier 2: Network, Cloud, System
- Tier 3: Application, Mobile
- Tier 4: Cryptography, Forensics

순서는 기존 자산 재사용, benchmark ground truth의 실현 가능성, read-only first slice와 안전한
Worker isolation을 기준으로 재평가할 수 있다. 한 PR에서 여러 domain runtime을 함께 구현하지
않는다.

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
