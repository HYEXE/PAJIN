# PAJIN 구현 계획

- 상태 권위: 이 파일
- 기존 Notion 로드맵 최종 대조: 2026-08-01, `main@a94df30`
- 현재 단계: Phase 4 — Thin Walking Skeleton
- 현재 우선순위: `WALK-005` Candidate·Atomic Validation·Replay·Report·Retest

## 제품 목표

PAJIN은 자신의 권한을 확대하지 않으면서 공격표면을 발견하고 연결하며, 자신이 발견한
취약점을 증거에 결박된 독립 Replay 없이 확정할 수 없는 정책 통제형 공격 발견·독립 검증
시스템을 지향한다.

첫 번째 end-to-end Hybrid Chain은 다음과 같다.

```text
File Upload
-> RAG Indirect Prompt Injection
-> MCP Tool Authorization Failure
-> Internal Data Access
```

## 현재 마일스톤: Phase 4

- [x] `WALK-001` 정확한 File Upload Surface 발견
- [x] `WALK-002` Snapshot-bound RAG Injection Hypothesis 생성
- [x] `WALK-003` 실행을 활성화하지 않고 H-17 의존성을 정확한 등록 MCP Tool Authorization
  Hypothesis에 결박
- [x] `WALK-004` Observation을 Graph에 Admission하고 bounded replan 생성
- [ ] `WALK-005` Candidate·Atomic Validation·Replay·Report·Retest 폐루프 완성
- [ ] `WALK-006` Shadow Supervisor가 선택했을 Task와 Stop Decision 기록

Phase 4 Exit Gate: 하나의 Cross-surface Chain이 Recon부터 Retest까지 닫히고, 동일
Benchmark에서 결정론적 Baseline과 Shadow Decision을 비교할 수 있어야 한다.

### WALK-004 완료 결과

- [x] `pajin.dev/walking-observation-replan/v1alpha1` content-addressed authority를 추가했다.
- [x] 봉인된 WALK-003 `registered-not-authorized` 상태만 Observation으로 Admission한다.
- [x] admitted Observation이 baseline과 다른 `request-independent-approval` Plan을 선택한다.
- [x] Graph에 `supports`, `enables`, `depends-on` 관계를 기록하고 `contradicts` 어휘를
  예약했다. 불일치 증거는 Graph 생성 전에 거부한다.
- [x] forged evidence, Run·Hypothesis 치환, stale·repeated·cyclic state 및
  Scope·Snapshot·Capability 확대를 fail closed한다.
- [x] 봉인된 artifact와 exact audit event에서 전체 권위를 재구성하는 reader를 제공한다.
- [x] 실행 상태는 `proposed-not-authorized`이며 Grant, Permit, ToolRequest, MCP argument,
  Worker dispatch를 생성하지 않는다.
- [x] 기존 A4/A5, ORCH-001/002, WALK-001/002/003 wire shape과 reader를 변경하지 않았다.

### WALK-005 목표

WALK-004의 비실행 승인 요청 Plan 뒤에 별도로 승인되고 허가된 실행 결과만 Candidate로
Admission하며, 기존 Atomic Validation·Restricted Replay·Report·Retest 권위를 재사용해 첫
Hybrid Chain의 검증 폐루프를 닫는다.

먼저 기존 Candidate, Claim, Replay, Report, Retest 계약과 WALK-004 사이에서 이미 충족된
부분과 실제 누락된 연결을 조사한다. 승인 receipt, CapabilityGrant, ActionPermit, Gateway,
Budget, Policy 경계를 새 Plan이 우회하거나 암묵적으로 생성하지 않도록 최소 additive
bridge를 설계한다.

## 이전 기반 작업

Phase 2 Capability Authoring(`CAP-001`~`CAP-006`)과 구조적 Phase 3 Graph, Discovery,
Deterministic Multi-wave(`GRAPH-001`~`GRAPH-006`, `DISC-001`~`DISC-003D`, `ORCH-001/002`)는
구현됐다. 실제 provider-backed immutable retention, 독립 anchor/KMS, 다른 host restore drill,
organization-issued release 및 실제 isolated Web + AI Campaign은 운영 공백으로 남아 있다.

기존 로드맵에서는 Phase 0 Benchmark/Target Factory와 Phase 1 Common Engine/Profile
Compatibility 항목이 완료 표시되지 않았다. 이 작업을 선택하기 전에 실제 코드와 다시
대조하며, 과거 체크리스트만 보고 완료를 추정하거나 작업을 재시작하지 않는다.

대조가 필요한 Phase 0/1 항목:

- `ARCH-001` Architecture v2 RFC와 기존 ADR-0046/0047/0048 결정 정합성
- 기존 Mode, API, Artifact 호환·Deprecation 정책
- `BENCH-001` Metric·Ground Truth·Run Protocol
- `BENCH-002` Result Schema·Artifact Format
- `BENCH-003` Deterministic Baseline·Adaptive Candidate 비교
- reset, seed, isolation, cleanup, measurement, adjudication, sealed Benchmark Harness
- Traditional Web/API, AI/RAG/MCP, Hybrid, Holdout, Mutation Target Factory
- Deterministic PAJIN, 일반 Scanner, Single-agent Baseline 측정
- `ENG-001` 공통 Campaign Execution Engine 계약
- `PROF-001` Pentest, Bug Hunt, CTF, AI Assessment Profile
- `PROF-002` 기존 CampaignMode Compatibility Adapter
- `ENG-002` 현재 Planner, Scheduler, Validation 경로 Adapter

## 후속 마일스톤

### Phase 5 — 구조화된 협업과 Handoff

- [ ] `MEM-001` CampaignFact Proposal·Record
- [ ] `MEM-002` SharedArtifactRef
- [ ] `MEM-003` CollaborationSnapshot
- [ ] `HANDOFF-001` Supervisor-mediated AgentHandoff
- [ ] `HANDOFF-002` terminal result handoff
- [ ] `HANDOFF-003` bounded UrgentObservation Fast Gate
- [ ] `HANDOFF-004` capability-scoped reader, TTL, byte limit, receiver binding
- [ ] memory poisoning, prompt relay, confused deputy, cross-Campaign 테스트

Exit Gate: Agent A의 admitted Fact가 Agent B의 최소 Snapshot에 결박되고 Agent 간 직접 명령은
불가능해야 한다.

### Phase 6 — Supervisor Shadow Mode

- [ ] `SUP-001` SupervisorModelBinding
- [ ] `SUP-002` Snapshot-only input·Target Taint
- [ ] `SUP-003` Task·Replan·Stop·Escalation Proposal
- [ ] `SUP-004` Checkpoint Scheduler·전용 Budget
- [ ] `SUP-005` Deterministic Baseline 비교
- [ ] `SUP-006` Adversarial Prompt Injection Regression

활성화하려면 Confirmed Finding Yield 또는 Chain Completion이 개선되고, Policy Violation은
증가하지 않으며, 비용·지연·Variance·Human Overturn 기준을 충족해야 한다.

### Phase 7 — 제한된 Supervisor 활성화

- [ ] `PERMIT-001` 일반 공격 ActionProposal
- [ ] `PERMIT-002` Deterministic Action Compiler
- [ ] `PERMIT-003` Exact Single-use ActionPermit
- [ ] `PERMIT-004` Side-effect·Data-flow·Cleanup Gate
- [ ] `APPROVAL-001` T2 ApprovalEnvelope와 Batch·Async 승인
- [ ] `SUP-007` opt-in T0/T1 실행
- [ ] T2는 사전 승인 Envelope를 요구하고 T3+는 기본 거부

Exit Gate: Supervisor가 권한을 확대할 수 없고 모든 실행이 정확한 Permit, Receipt, Evidence를
남겨야 한다.

### Phase 8 — Coverage·Validation 일반화

- [ ] `CHAIN-001` Auth Bypass → AI Admin Surface
- [ ] `CHAIN-002` File Upload → RAG Injection → Tool Abuse
- [ ] `CHAIN-003` Prompt Injection → URL Tool Control → Internal API
- [ ] `CHAIN-004` Cross-tenant Retrieval → Data Exposure
- [ ] `CHAIN-005` MCP Authorization Failure → Privileged Action
- [ ] `VAL-001` Mode-neutral Claim Replay
- [ ] `VAL-002` ValidationDepthPolicy
- [ ] `VAL-003` Profile별 Assurance Floor
- [ ] `VAL-004` Baseline·Negative Control·Counterfactual·N-run Replay

### Phase 9 — Product UX·Operations

- [ ] Campaign·Profile·Scope Builder
- [ ] Attack Surface·Graph·Wave Timeline UI
- [ ] Hypothesis Ranking·Decision Audit
- [ ] Original·Replay·Control·Retest Diff
- [ ] Human Review·Approval·Kill Switch Queue
- [ ] SARIF·Issue Tracker·SIEM/SOAR Export
- [ ] OIDC·MFA·ABAC·Worker Identity·mTLS
- [ ] Object Storage·Distributed Worker·KMS/HSM
- [ ] TLS 1.3 Exporter·Registry Refresh·External Transparency Anchor

## 미결정 제품 사항

다음 항목을 구현 중 암묵적으로 결정하지 않는다. 먼저 새 ADR 또는 Profile Policy를
작성한다.

- 외부 Profile 명칭과 `ai-redteam` Deprecation 기간
- 첫 Benchmark Target을 현재 저장소에 둘지 별도 저장소에 둘지
- Supervisor Primary/Review Provider 조합
- T2 ApprovalEnvelope의 Action·누적 변경·TTL 기본값
- CampaignFact Retention·Human Correction Authority
- Bug Hunting Program별 A1/A2 Confirmation Floor
- Capability Signing·Review Authority와 외부 기여 모델
- 첫 Graph Event Store를 RunStore로 유지할지 별도 Component로 만들지

## 완료 기준

각 Vertical Slice는 관련 Task ID, Threat Model, 변경되는 Trust Boundary, Schema/API Version,
Backward Compatibility, Migration·Rollback, Positive·Adversarial Test, Audit Artifact/Event,
Benchmark 영향, 버전형 문서를 포함한다. Ruff, Linux 대상 strict mypy, 집중 pytest, 가능한
범위의 전체 pytest 및 가능한 Linux CI를 실행한다. 환경 때문에 실행하지 못한 검증은
`HANDOFF.md`와 `KNOWN_ISSUES.md`에 정확히 기록한다.
