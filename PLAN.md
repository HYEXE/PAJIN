# PAJIN 구현 계획

- 상태 권위: 이 파일
- 기존 Notion 로드맵 최종 대조: 2026-08-01, `main@a94df30`
- 현재 단계: Phase 4 — Thin Walking Skeleton
- 현재 우선순위: `P0-C2` real Docker/provider Target Factory adapter·key registry

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
- [x] `WALK-005` Candidate·Atomic Validation·Replay·Report·Retest 폐루프 완성
  - [x] `WALK-005A` 승인·Permit·봉인 Gateway 실행 기반 Candidate·Atomic Claim Admission
  - [x] `WALK-005B` MCP Claim-bound Restricted Replay·검증 projection
    - [x] `WALK-005B1` validity Claim-bound 비실행 Replay Plan authority
    - [x] `WALK-005B2` Plan-bound fresh 실행·Claim 검증 projection
  - [x] `WALK-005C` Report·Remediation Retest 폐루프
    - [x] `WALK-005C1` MCP 확인 정책·Report·비실행 Remediation baseline
    - [x] `WALK-005C2` baseline-bound fresh Retest·보수적 lifecycle 판정
- [x] `WALK-006` Shadow Supervisor가 선택했을 Task와 Stop Decision 기록

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

`WALK-005A`는 완료됐다. WALK-004 authority와 별도 실행 Run을 다시 열고, 정확한 승인
receipt가 canonical CapabilityGrant digest에 결박된 채 consumed ActionPermit dispatch보다 먼저
봉인됐으며 claimed·terminal event가 같은 Grant와 기존 reconciliation의 성공한 Gateway
lifecycle을 증명할 때만 미확정 A02 Candidate와 validity·impact·severity Atomic Claim을 생성한다.
의심 입력만으로 승인 실패나 내부 데이터 접근을 합성하지 않으며, 기본 demo MCP
inspector는 해당 대상 관찰값을 내지 않으므로 이 Candidate를 만들 수 없다.

`WALK-005B1`은 기존 KISA M03/M06/A04 Replay를 이름만 바꾸지 않고, WALK-005A의 exact
validity Claim과 원 실행·요청·Tool·target·parameter digest를 content-addressed 비실행 Plan에
결박한다. replay Run·request·approval·Grant·Permit·dispatch·Worker identity는 모두 fresh해야
한다. 다음 `WALK-005B2`가 이 Plan digest를 dispatch 전에 봉인하고 별도 Gateway 실행과 Claim
검증 projection을 만들기 전까지 Candidate는 `candidate-admitted-not-confirmed`를 벗어나지 않는다.

`WALK-005B2`는 B1 Plan/Claim digest와 exact approval·request·Grant를 replay receipt에 결박해
Permit claim 전에 봉인하고, 기존 WALK-005A verifier로 별도 Gateway 실행을 재검증한다. 원 실행
대비 Run·request·approval·Grant·Permit·dispatch·Worker ID가 모두 fresh하고 요청 의미와 새 validity
Claim statement가 exact equality일 때만 `reproduced / confirmationEligible=false` projection을
봉인한다. 다음 `WALK-005C`에서 확인 정책, 보고서, remediation Retest 폐루프를 연결한다.

`WALK-005C1`은 B2 authority를 다시 열어 Plan-bound fresh validity replay만 MCP 전용 제품 확인
근거로 채택한다. impact·severity는 replay됐다고 확장하지 않고 `source-bound-information-only`로
고정한다. validated Finding, typed Report와 exact Markdown, `planned-not-applied` Remediation
Plan을 하나의 content-addressed authority와 봉인 Run으로 묶는다. 다음 `WALK-005C2`는 이
baseline과 별도의 fresh B2 실행을 결박해 양성 재현을 `still-vulnerable`로 판정한다. 음성·실패
실행은 성공한 lifecycle 결과로 바꾸지 않고 fail closed하며, 독립적인 수정 증명 없이는 `fixed`를
금지한다.

`WALK-005C2`는 C1 confirmation publication 뒤에 승인·실행된 별도 B2 authority만 Retest로
받아들인다. B1 Plan·Candidate·Finding·validity Claim은 exact equality여야 하고, baseline
replay와 Run·request·approval·Grant·Permit·dispatch·Worker ID가 모두 달라야 한다. B2가 양성
재현만 나타내므로 현재 lifecycle 결과는 `still-vulnerable`로 제한한다. `fixedEligible=false`,
`remediationAppliedAttested=false`, regression `not-measured`를 고정하고, 음성·실패·불완전
실행을 `fixed`로 해석하지 않는다. 이로써 첫 Walking chain은 Retest까지 닫혔으며 다음 구현은
`WALK-006` Shadow Supervisor Decision 기록이다.

`WALK-006`은 봉인된 C2 `still-vulnerable` lifecycle만 snapshot-only 입력으로 받아 code-registered
Shadow policy가 선택했을 human remediation-review Task와 자율 실행 Stop·escalation Decision을
content-addressed authority로 기록한다. Task는 Capability가 없고 `proposed-not-authorized`, Stop은
`executionAllowed=false`, 전체 결과는 `recorded-not-applied`다. 기존 TaskGraph·Campaign·source
Run을 변경하거나 모델·Tool을 호출하지 않는다. 다음 `BENCH-003`은 동일 benchmark 좌표에서
이 Shadow record와 deterministic baseline을 실제 비교하는 측정 경계를 구현한다.

`BENCH-003A`는 baseline-only BENCH-001 Manifest와 WALK-006 sealed authority를 결박해
deterministic terminal Decision과 Shadow Task·Stop Decision의 구조 차이만 기록한다. 12개 필수
metric 이름은 보존하지만 값과 delta는 비워 두고, `not-measured-no-benchmark-results`,
`benchmarkComparisonEligible=false`, `supervisorActivationEligible=false`로 고정한다. 다음
`BENCH-003B`는 동일 seed·repetition·reset·isolation·cleanup 좌표의 실제 baseline/candidate
`BenchmarkResult`를 생성한 뒤에만 기존 numeric `BenchmarkComparison`을 허용한다.

`BENCH-003B1`은 동일 measurement authority가 봉인한 두 arm의 전체 좌표별 raw count·시간·비용·
Replay·정책·human·cleanup 관찰만 Admission하고, 12개 metric을 코드로 집계해 두 completed Result와
canonical Comparison을 함께 봉인한다. 외부 측정 authority의 의미적 진실성은 별도 trust root이며
Supervisor activation은 false다. 다음 `BENCH-003B2`는 candidate implementation/version/configuration을
exact WALK-006 Shadow policy와 sealed BENCH-003A source publication에 결박한다.

`BENCH-003B2`는 B1 numeric output을 다시 계산하지 않고 sealed A/B1 source를 함께 연다.
measured Manifest의 전체 envelope와 baseline arm은 A와 exact equality이고, candidate
implementation ID/version/configuration digest는 WALK-006 code-owned policy와 같아야 한다. 양쪽
source Run/root/artifact SHA를 content-addressed authority에 결박하며 activation eligibility는 false다.
BENCH-003 Harness는 닫혔지만 fixture가 운영 증거라는 뜻은 아니다. 다음 `P0-C`는 실제 Target
Factory reset·isolation·execution·observation·cleanup과 measurement authority attestation을 구현한다.

`P0-C1`은 provider-neutral async adapter와 좌표별 reset→isolation→execution→cleanup receipt를
정의한다. 다음 provider 호출 전에 각 authority를 검증하고, 유효한 isolation 이후 execution이
실패하거나 foreign raw Observation을 반환해도 cleanup을 먼저 시도한다. 네 receipt와 final B1
Observation은 외부 Ed25519 measurement key로 서명되며 public Trust Anchor로 검증된 뒤 같은 Run에
봉인된다. deterministic 테스트 adapter는 계약만 증명하며 실제 provider가 아니다. 다음 `P0-C2`는
real Docker/external provider implementation, evidence retrieval, network policy, key registry/rotation,
cleanup recovery를 연결한다.

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
- [x] `BENCH-003` Deterministic Baseline·Adaptive Candidate 비교
  - [x] `BENCH-003A` Walking Baseline·Shadow Decision structural-only comparison
  - [x] `BENCH-003B` 동일 좌표 sealed Result Harness·numeric comparison
    - [x] `BENCH-003B1` sealed raw Observation admission·두 Result·numeric comparison
    - [x] `BENCH-003B2` exact WALK-006 policy/configuration·source publication binding
- [ ] `P0-C` reset, seed, isolation, cleanup, measurement, adjudication, sealed Benchmark Harness
  - [x] `P0-C1` provider-neutral lifecycle·sealed Observation·external measurement signature
  - [ ] `P0-C2` real Docker/provider adapter·evidence·network policy·key registry
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
