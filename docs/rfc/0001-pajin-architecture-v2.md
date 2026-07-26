# ARCH-001: PAJIN Architecture v2

- 상태: Accepted
- 날짜: 2026-07-26
- 기준 코드: `main@a4d0582`
- 구현 상태: Phase 0 계약 수립 중

## 1. 목적

PAJIN을 Mode별 기능 사일로에서 다음 공통 구조로 점진적으로 전환한다.

1. 하나의 정책 통제형 공통 공격 엔진
2. 운영 규칙과 결과 형식을 정의하는 Campaign Profile
3. 코드에 등록되고 버전이 고정된 Capability
4. 여러 공격 표면의 탐색 상태를 잇는 Canonical Graph와 append-only Event Log
5. 검증된 snapshot 안에서만 다음 행동을 제안하는 선택적 Bounded Supervisor

AI는 prompt, RAG, memory, tool authorization 같은 고유 표면을 가진 first-class Capability
domain으로 유지한다. 다만 PAJIN 전체 제품을 AI red-team Mode 하나로 정의하지 않는다.

## 2. 현재 기준선과 문제

현재 코드는 다음 안전 자산을 이미 보유한다.

- Campaign authorization, Scope, Rules of Engagement, budget
- 감쇠 가능한 `CapabilityGrant`와 모든 실행을 통과시키는 Policy/Tool Gateway
- 격리 Worker와 등록된 Tool 실행
- Candidate 보존, Atomic Claim, Blind Review, 독립 Replay, Confirmation
- append-only Control Plane projection, portable receipt와 실행 증명
- 제한된 A3~A5 discovery 및 최대 두 wave의 replanning

그러나 `ai-redteam`, `bug-bounty`, `ctf`가 각각 실행·탐색·보고 구조를 소유해 cross-surface
공격 체인을 공통 상태로 표현하기 어렵다. A5 observation snapshot은 후속 계획에 사용되지만
모든 Specialist가 공유하는 canonical campaign memory는 아니다. 구현된 동적 Specialist와
wave 결과 병합도 peer-to-peer 대화나 검증된 공통 사실 저장소를 의미하지 않는다.

## 3. 확정 원칙

| ID | 불변식 |
| --- | --- |
| I-01 | 모든 실행은 Campaign 권위 안에서 발급된 Capability와 Permit으로 제한한다. |
| I-02 | 탐색은 감사 가능해야 하고 Finding은 독립적으로 재현 가능해야 한다. |
| I-03 | 전환은 strangler 방식으로 수행하며 대규모 rename-only 변경을 만들지 않는다. |
| I-04 | Discovery, Agent, Supervisor는 Scope·Risk·Budget·Capability를 확장할 수 없다. |
| I-05 | Canonical Graph를 변경하는 권위는 하나의 Admission Authority뿐이다. |
| I-06 | Supervisor는 선택 사항이고 proposal만 만들며 authority root가 될 수 없다. |

기존 Policy, Capability, Worker isolation, Evidence, Validation, Replay 경계는 폐기하지 않고
공통 엔진의 기반으로 재사용한다.

## 4. 목표 구조

```text
legacy Mode/API input
        │
        ▼
Campaign Profile Adapter ──► MissionEnvelope
                                  │
registered Capability ◄───────────┤
                                  ▼
                          Common Attack Engine
                                  │
Specialist/Supervisor ──► typed Proposal
                                  │
                 deterministic Compiler + Policy Gate
                                  │
                                  ▼
                      single-use ActionPermit
                                  │
                                  ▼
                         Worker / Tool Gateway
                                  │
                                  ▼
                Observation/Evidence/Fact Proposal
                                  │
                                  ▼
                 single Graph Admission Authority
                                  │
                   append-only Canonical Event Log
                                  │
                    Graph Projection + Snapshot
```

Campaign Profile은 pentest, bug bounty, AI red team, CTF 같은 운영 의미를 표현한다. Profile은
Scope나 권위를 추가하지 않으며 Campaign authorization을 실행 가능한 `MissionEnvelope`로
컴파일하는 입력이다. `ai-redteam`, `bug-bounty`, `ctf` 값과 현재 CLI/API는 migration 기간에
호환 입력으로 유지한다.

## 5. Minimum Canonical Graph

Phase 3 전까지 다음 최소 vocabulary만 canonical contract로 고정한다.

### 5.1 Node

| Node | 의미 |
| --- | --- |
| `Surface` | 관찰·검증할 수 있는 공격 표면 |
| `Hypothesis` | 특정 표면에 대해 검증할 명제 |
| `Action` | Permit으로 승인되어 실행된 동작 |
| `Observation` | Action 또는 trusted import에서 얻은 관찰 |
| `Evidence` | Observation을 지지하는 보존 증거 |
| `CampaignFact` | 출처와 validation state를 가진 캠페인 공통 사실 |

### 5.2 Edge

```text
Surface motivates Hypothesis
Hypothesis tested-by Action
Action produces Observation
Observation supported-by Evidence
Observation supports/contradicts Hypothesis
Observation discovers Surface
Observation enables Hypothesis
```

`Asset`, `Identity`, `Session`, `CredentialHandle`, `PrivilegeState`, `TrustBoundary`,
`DataObject`, `DataFlow`, `Pivot`, `Candidate`, `Finding`은 benchmark나 walking skeleton이
필요성을 입증한 뒤에만 추가한다.

### 5.3 Write path

```text
Specialist
→ ObservationProposal / SurfaceProposal / CampaignFactProposal
→ Admission Queue
→ single Graph Admission Authority
→ Append-only Canonical Event Log
→ Graph Projection
→ Immutable Checkpoint Snapshot
→ Supervisor or deterministic Planner
```

- Agent는 canonical graph를 직접 수정하지 않는다.
- Proposal은 campaign, run, agent, task, request, evidence lineage에 결박한다.
- 같은 proposal digest의 재시도는 멱등이다.
- 같은 ID에 다른 digest가 오면 equivocation으로 거부한다.
- 모순되는 Observation은 덮어쓰지 않고 함께 보존한다.
- Snapshot은 revision과 canonical digest를 가지며 이를 읽은 결정도 exact snapshot에
  결박한다.
- 결정 뒤 graph revision이 바뀌면 실행 전에 다시 검증한다.

Graph는 현재 `TaskGraph`와 별도다. `TaskGraph`는 실행 의존성, Canonical Graph는 검증된
캠페인 지식과 provenance를 표현한다.

## 6. Bounded Supervisor

Supervisor는 Minimum Graph와 benchmark가 준비되기 전에는 활성화하지 않는다. 이후에도
`shadow`에서 시작해 명시된 activation gate를 통과해야 한다.

입력은 검증된 Mission, immutable snapshot, admitted fact/artifact, 남은 budget으로 제한한다.
출력은 `TaskAssignmentProposal`, `ReplanProposal`, `VetoProposal`,
`EscalationRequest` 같은 typed proposal뿐이다.

Supervisor는 다음을 할 수 없다.

- Scope, risk tier, budget, rate, capability 또는 egress 확장
- credential 생성 또는 secret material 직접 수신
- 미등록 Capability나 임의 shell command 실행
- Finding 확인 또는 validation/replay gate 우회
- Canonical Graph 직접 수정

Supervisor 호출은 매 Tool call이 아니라 정해진 checkpoint에서만 발생한다. 비활성화해도
deterministic planner로 최소 기능이 동작해야 한다.

## 7. B2.9 재정의

구조화 협업 메모리는 별도 free-form Collaboration Store로 구현하지 않는다.

- 공유 사실: admitted `CampaignFact`
- 작업 인계: snapshot과 lineage에 결박된 Handoff projection
- 팀 상태: Canonical Event Log에서 재구성한 Snapshot projection

따라서 B2.9의 facts/snapshot/handoff는 Canonical Graph/Event Log의 projection으로
구현하며 별도의 권위 원장이 되지 않는다.

## 8. 호환성과 migration

1. 기존 `CampaignMode`, manifest, CLI command, API route, Artifact schema는 즉시 삭제하지
   않는다.
2. legacy Mode input을 Campaign Profile로 컴파일하는 adapter를 먼저 추가한다.
3. 공통 엔진과 기존 Mode path를 같은 fixture로 실행해 결과·정책 parity를 검증한다.
4. Capability와 Graph 기능은 feature flag 또는 opt-in path로 한 조각씩 연결한다.
5. parity 또는 negative test가 실패하면 adapter를 비활성화해 기존 Mode path로 rollback한다.
6. 대규모 directory move는 parity가 입증되고 각 consumer가 전환된 뒤 별도 변경으로 수행한다.

CTF는 공통 Profile/benchmark로 표현할 수 있지만 현재의 고정 lab validator 경계는 유지한다.
Target-signed lab attestation과 B2.8g local multipart 같은 기존 기능은 Architecture v2의
선행조건이 아니며, 실제 운영 가치가 입증된 범위에서 재사용한다.

## 9. 구현 순서

1. **P0-A Architecture Contract**
   - ARCH-001 이 RFC
   - ADR-0046 Common Engine + Campaign Profiles
   - ADR-0047 MissionEnvelope + ActionPermit Algebra
   - ADR-0048 Minimum Graph + Admission Consistency
2. **P0-B Benchmark Contract**
   - BENCH-001 benchmark manifest/result schema
   - deterministic target factory와 핵심 metric
3. **Phase 1**
   - legacy Mode → Profile adapter
   - common engine walking parity
4. **Phase 2**
   - Versioned Capability Registry와 deterministic proposal compiler
5. **Phase 3**
   - GRAPH-001 model
   - GRAPH-002 admission/event-log spike
   - projection, revision, snapshot, stale-decision tests
   - durable Graph Store와 atomic consumed ActionPermit dispatch claim
6. **Phase 4**
   - 첫 hybrid web + AI walking skeleton
7. **Phase 5 이후**
   - B2.9 projection
   - Supervisor shadow, 평가, 제한적 activation

이 RFC가 열어 둔 첫 Graph Event Store 선택은
[ADR-0049](../adr/0049-durable-single-campaign-sqlite-graph-store.md)에서 해소한다. 첫 backend는
한 Run의 `RunStore` 확장이 아니라 별도 single-Campaign SQLite Graph Store다. ADR-0048의
durable conformance 조각을 통과하며 future Control Plane/PostgreSQL adapter도 같은
storage-neutral protocol을 사용한다. 마지막 revision 검사와 consumed dispatch claim은
[ADR-0050](../adr/0050-consumed-action-permit-dispatch-claim.md)과
[GRAPH-006](../graph/GRAPH-006-atomic-action-permit-authority.md)에서 구체화한다.
Phase 2의 첫 versioned Capability 계약은
[ADR-0051](../adr/0051-versioned-capability-definition-and-tool-binding.md)과
[CAP-001](../capability/CAP-001-versioned-capability-definition.md)에서 exact ToolSpec
binding·definition digest·no-latest Registry로 구체화한다.

## 10. Definition of Done

각 수직 조각은 다음 조건을 만족해야 한다.

- code, schema, test, README/plan/ADR가 같은 변경에서 일치
- Ruff, strict mypy, focused/full pytest와 Linux CI 통과
- authority expansion, duplicate, contradiction, stale snapshot, race에 대한 negative test
- 중요한 결정과 admission에 canonical digest와 audit event 보존
- clean clone에서 재현 가능한 실행
- benchmark result와 regression metric 생성
- Notion status, 호환성, migration, rollback 경계 최신화

현재 committed 기준선은 `main@59cf210`이며 `origin/main@bc9f28f`보다 한 commit 앞서 있다.
GRAPH-006은 커밋됐고 CAP-001은 로컬 구현·집중 검증 상태다. Linux CI와 CAP-001 commit은
남아 있다.

## 11. 관련 결정

- [ADR-0046: 공통 엔진과 Campaign Profile](../adr/0046-common-engine-and-campaign-profiles.md)
- [ADR-0047: MissionEnvelope와 ActionPermit 대수](../adr/0047-mission-envelope-and-action-permit-algebra.md)
- [ADR-0048: Minimum Graph와 Admission 일관성](../adr/0048-minimum-graph-and-admission-consistency.md)
- [ADR-0049: Durable Single-Campaign SQLite Graph Store](../adr/0049-durable-single-campaign-sqlite-graph-store.md)
- [ADR-0050: Consumed ActionPermit Dispatch Claim](../adr/0050-consumed-action-permit-dispatch-claim.md)
- [ADR-0051: Versioned Capability Definition과 Tool Binding](../adr/0051-versioned-capability-definition-and-tool-binding.md)
