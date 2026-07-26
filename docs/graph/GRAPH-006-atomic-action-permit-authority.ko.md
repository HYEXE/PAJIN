> 언어: [English](GRAPH-006-atomic-action-permit-authority.en.md) | [한국어](GRAPH-006-atomic-action-permit-authority.ko.md)

# GRAPH-006: Atomic ActionPermit Authority

- 상태: 로컬 구현 완료
- 날짜: 2026-07-26
- 선행 조건: GRAPH-003, GRAPH-004, GRAPH-005, ADR-0047, ADR-0049

## 목적

`GraphDecisionPreflight` 뒤에 Graph가 바뀌는 race를 닫는다. 이전 preflight 결과를 실행
권위로 승격하지 않고, 같은 single-Campaign SQLite Graph Store의 마지막 write
transaction 안에서 다음을 함께 수행한다.

1. exact `MissionEnvelope`, `ActionProposal`, `GraphDecision`, registered Capability를 검증한다.
2. durable Event Log 전체를 다시 projection해 저장된 current Projection과 exact 비교한다.
3. decision의 immutable Snapshot이 그 latest Projection과 동일한지 확인한다.
4. Scope, target, risk, Campaign/Run, compiler, Tool/version/digest를 다시 확인한다.
5. MissionEnvelope의 누적 call/unit/cost budget과 rolling-window unit rate를 계산한다.
6. deterministic `ActionPermit`을 append하고 같은 순간 consumed dispatch claim으로 만든다.

## 권위 계약

### RegisteredActionCapability

`RegisteredActionCapability`은 Capability ID/version, Tool ID/version/digest와 risk tier를
canonical digest로 고정한다. `ActionCapabilityRegistry`는 exact version과 digest가 모두
일치할 때만 reference를 resolve한다. 이 registry는 현재 immutable process-local
contract이며 durable registry 배포는 후속 경계다.

### MissionEnvelope

`MissionEnvelope`은 한 Campaign/Run의 실행 상한이다.

- profile/compiler/source Campaign identity
- allowed Capability exact reference 집합
- allowed target digest 집합
- max risk tier와 autonomy
- tool-call, request-unit, fixed-point micro-USD budget
- optional rolling-window request-unit rate
- authorization/not-before/expiry 시간

Capability와 target 집합은 canonical 순서의 unique tuple이며 envelope ID/digest는 전체
권위 material에서 결정된다.

### ActionProposal

`ActionProposal`은 실행 권위가 아닌 의도다. exact MissionEnvelope, GraphDecision,
Snapshot, Capability, target digest, request ID/digest, normalized parameter digest와
budget reservation에 결박된다. 제안된 risk는 registered Capability risk와 같아야 한다.

### ActionPermit

`ActionPermit`은 다음 특징을 가진다.

- exact Envelope, Proposal, Decision, Snapshot, Capability, request binding
- compiler identity와 canonical permit/dispatch ID
- `status=consumed`
- issuance와 consumption이 같은 시각에 이루어진 non-bearer audit proof
- Envelope expiry보다 길 수 없는 짧은 dispatch authority window

Permit ID는 clock과 무관한 stable input에서 결정된다. response loss 뒤 exact retry는 같은
row를 돌려주지만 `newlyConsumed=false`이므로 Worker를 다시 호출할 수 없다.

## SQLite schema v2

GRAPH-005 schema v1에 다음 append-only table을 추가했다.

| Table | 의미 |
| --- | --- |
| `graph_action_permit_writers` | Campaign의 pinned compiler identity |
| `graph_action_permits` | consumed-on-issuance Permit 및 dispatch claim ledger |

Permit row는 Snapshot과 Projection revision을 foreign key로 참조하고, proposal ID와 request
ID를 각각 unique로 제한한다. update/delete/replace trigger와 schema fingerprint가 모든
Permit material을 보호한다.

정확한 v1 schema와 fingerprint를 먼저 검증한 뒤에만 v2 migration을 실행한다. migration은
기존 Event, Projection, Snapshot을 보존하고 Permit row를 만들지 않는다.

## 최종 권위 transaction

```text
BEGIN IMMEDIATE
  pinned compiler identity 확인
  deterministic attempt exact-retry 조회
  request/proposal equivocation 거부
  Envelope + Proposal + Capability 대수 검증
  durable Event Log -> latest Projection 재구성
  stored Projection + Snapshot exact 비교
  durable budget/rate 합계 계산
  consumed ActionPermit append
COMMIT  # dispatch claim이 시작된 권위 시점
```

Graph Event append와 Projection publish도 같은 database의 `BEGIN IMMEDIATE` writer lock을
사용한다. 따라서 Graph 변경과 dispatch claim은 하나의 직렬 순서를 가진다. commit 뒤에
들어온 Graph Event는 이미 권위가 확정된 dispatch보다 나중 사건이다.

`GraphActionPermitDispatcher.dispatch_once()`는 오직 `newlyConsumed=true`인 호출에서만
Worker callback을 호출한다. callback 실패나 응답 불확실성 뒤 Permit은 consumed로
남고 exact retry는 재dispatch하지 않는다. 이는 안전 우선 at-most-once 의미다.

## 거부 조건

- durable Event Log와 stored Projection 불일치
- Snapshot이 latest revision/head/projection과 불일치
- Campaign, Run, Envelope, Decision 또는 compiler lineage 불일치
- unknown Capability 또는 version/digest/Tool/risk drift
- Scope 밖 target 또는 risk ceiling 초과
- inactive/expired Envelope
- 누적 budget 또는 rolling rate 초과
- 같은 proposal/request ID의 다른 canonical material
- compiler writer identity drift

## 검증

- canonical identity와 Capability registry drift
- reopen 뒤 Permit 조회와 exact response-loss retry
- projection lag 및 recovery 뒤 stale Snapshot 거부
- cross-instance 경쟁에서 하나의 dispatch winner
- Worker callback 실패 뒤 terminal consumption과 no-redispatch
- durable budget와 rolling-window rate
- target Scope와 expiry fail-closed
- request equivocation
- append-only trigger와 schema fingerprint tamper
- v1→v2 migration이 Permit authority를 꾸며내지 않음

Windows focused Graph suite는 `64 passed, 2 skipped`다. skip 2개는 POSIX
symlink/hardlink 의미를 검증하는 기존 테스트다.

## 남은 경계

- Tool Gateway/Worker daemon의 opt-in runtime wiring과 실제 request/result audit 연결
- dispatch 성공·실패·만료·취소 lifecycle event 원장
- durable Capability Registry와 compiler rotation/activation 정책
- process-kill/fsync fault injection 및 backup/restore
- multi-host leader/lease와 PostgreSQL/HA adapter
- B2.9 Handoff projection과 Supervisor shadow

외부 Worker 부작용은 SQLite commit과 물리적으로 같은 transaction이 아니다. 이 조각은
commit을 one-time dispatch claim으로 정의하고 retry 시 재실행을 막아 duplicate side
effect를 방지한다. commit 뒤 process가 죽으면 작업이 실행되지 않은 채 consumed로 남을 수
있으며 자동 재dispatch하지 않는다.
