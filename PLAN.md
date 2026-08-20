# PAJIN 구현 계획

- 상태 권위: 이 파일
- 아키텍처 권위: `docs/rfc/0001-pajin-architecture-v2.md`,
  `docs/rfc/0002-multi-domain-security-analysis-architecture.md`
- 현재 단계: Phase 11 — Initial Pentest / Red Team Productization
- 현재 우선순위: `REDTEAM-001C` bounded Web Capability profile
- 다음 우선순위: `REDTEAM-001D` registered MCP Capability profile

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
- [ ] `REDTEAM-001` initial executable Web/AI Capability bootstrap
  - [x] `REDTEAM-001A` approved single-turn LLM M03/M06 profile
  - [x] `REDTEAM-001B` multi-turn LLM/RAG A04 request-unit profile
  - [ ] `REDTEAM-001C` bounded Web Capability profile
  - [ ] `REDTEAM-001D` registered MCP Capability profile
- [ ] `REDTEAM-002` initial detection·false-positive·replay·cost benchmark
- [ ] `UX-008` initial Scope·Evidence·Finding·report product flow

Phase 11 Exit Gate: 현재 계약을 깨지 않고 승인된 초기 Pentest/Web/AI/MCP slice를 실행하며,
Profile별 Replay/validation floor와 초기 benchmark·product flow를 검증한다. REDTEAM-001은
모든 보안 도메인의 umbrella가 아니다.

## Multi-domain foundation

### Phase 12 — Multi-domain Security Analysis Foundation

ARCH-002와 ADR-0204~0206은 accepted architecture decision이다. 아래 DOMAIN 항목은 모두
`planned`이며 문서만으로 구현됐다고 보지 않는다.

- [ ] `DOMAIN-001` code-owned Security Domain taxonomy
  - 9개 Domain을 exact versioned classification으로 정의
  - Campaign Profile과 orthogonal하고 authority marker는 모두 false
  - legacy `CapabilityDefinition.domain` identity를 변경하지 않음
- [ ] `DOMAIN-002` common multi-domain Surface/Hypothesis/Observation semantics
  - ARCH-001의 6개 node와 8개 relation 재사용
  - domain-specific locator/type registry와 one Graph writer 유지
- [ ] `DOMAIN-003` domain-aware Capability inventory projection
  - exact `CapabilityDefinitionRef`에 classification을 결박
  - Domain·surface·Tool metadata로 activation/Permit/Worker를 추론하지 않음
- [ ] `DOMAIN-004` domain-specific Worker trust-boundary registry
  - exact Capability release와 deployment-owned Worker profile 결박
  - 기존 Policy/Approval/Permit/Gateway/receipt 경로 재사용
- [ ] `DOMAIN-005` cross-domain Graph admission
  - Observation이 다른 Domain Surface/Hypothesis를 발견·활성화할 수 있음
  - 새 Surface는 `registered-not-authorized`; Scope와 execution authority는 불변
- [ ] `DOMAIN-006` domain-aware validation/replay/benchmark contract
  - 공통 metric과 exact domain-specific metric registry 분리
  - BENCH-001 v1 호환 유지, `not-applicable` 의미를 명시

Phase 12 Exit Gate: Profile/Domain/Capability/Tool 관계가 코드와 테스트로 분리되고, 한
cross-domain Observation이 기존 Canonical Graph에 admission되지만 Scope·Capability·Permit·Worker
권위를 만들지 않음을 positive/adversarial test로 증명한다.

## Domain vertical slices

각 Phase는 하나의 domain 첫 slice만 닫는다. 기본 완료 범위는 typed Surface, read-only
discovery/analysis Capability, sealed Observation/Evidence, Graph admission, bounded Hypothesis,
independent Replay 또는 deterministic re-analysis, benchmark ground truth다. active probing,
mutation, credential use와 privilege-changing action은 별도 후속 milestone이다.

### Phase 13 — Web / API Security Analysis

- [ ] `WEB-001A` typed HTTP/API Surface and locator registry
- [ ] `WEB-001B` read-only Web/API discovery Capability and egress-only Worker profile
- [ ] `WEB-001C` sealed Observation/Evidence and registered-not-authorized Graph admission
- [ ] `WEB-001D` independent replay and Web/API benchmark ground truth

재사용: REDTEAM-001C, Pentest HTTP GET, HTTP/OpenAPI/auth/file-upload discovery, traditional Web
Target catalog, Docker/ZAP benchmark 자산.

### Phase 14 — AI / LLM / RAG / Agent / MCP Analysis

- [ ] `AI-001A` model/RAG/agent/MCP/tool Surface classification
- [ ] `AI-001B` exact provider/model/tool-bound read-only analysis Capability
- [ ] `AI-001C` cross-Surface Observation/Evidence admission without Tool authority
- [ ] `AI-001D` fresh-session replay, controls and AI benchmark extension

재사용: REDTEAM-001A/B/D, KISA Oracle/Replay, RAG/MCP walking chain과 local AI Target Factory.

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

- DOMAIN-003 classification projection의 exact schema와 registry lifecycle
- legacy `CapabilityDefinition.domain`의 장기 deprecation 여부
- Domain Surface locator registry의 publisher/review authority
- Worker trust-boundary profile의 deployment signing과 conformance authority
- BENCH-001 v1과 domain-specific metric extension의 wire 관계
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
