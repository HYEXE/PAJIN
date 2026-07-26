> 언어: [English](0050-consumed-action-permit-dispatch-claim.en.md) | [한국어](0050-consumed-action-permit-dispatch-claim.ko.md)

# ADR-0050: Consumed-on-Issuance ActionPermit Dispatch Claim

- 상태: Accepted
- 날짜: 2026-07-26

## 배경

GRAPH-004의 `GraphDecisionPreflight`는 Snapshot-bound stale decision을 탐지하지만 audit-only
record다. preflight 뒤 external Worker를 호출하기 전 Graph가 변경되면 이전 검증을 실행
권위로 재사용할 수 없다. GRAPH-005는 Event, Projection, Snapshot을 같은 single-Campaign
SQLite database에 영속화했으므로 마지막 권위 비교와 Permit 상태 변경을 같은 writer
transaction에 넣을 수 있다.

SQLite commit과 외부 Worker side effect를 하나의 물리 transaction으로 묶을 수는 없다.
Worker 호출을 transaction 안에서 먼저 수행하면 process crash 뒤 같은 요청이 다시
실행될 수 있고, commit을 먼저 수행하면 crash 시 실행되지 않은 consumed 작업이 생길 수
있다. 보안 검증 동작의 duplicate side effect보다 누락을 안전한 실패로 취급한다.

## 결정

1. Graph Store schema v2에 append-only `graph_action_permit_writers`와
   `graph_action_permits`를 추가한다.
2. `MissionEnvelope`, `ActionProposal`, registered Capability와 `ActionPermit`을 canonical,
   digest-bound immutable contract로 구현한다.
3. Permit 발급은 항상 같은 SQLite database의 `BEGIN IMMEDIATE` 안에서 latest durable
   Event Log/Projection/Snapshot을 재검증한다.
4. budget/rate 계산과 Permit append도 그 transaction 안에서 수행한다.
5. Permit은 issuance와 동시에 `status=consumed`인 non-bearer proof가 된다. commit은
   one-time dispatch claim의 권위 시점이다.
6. Permit ID는 clock과 무관한 exact authority material에서 결정한다. 동일 retry는 저장된
   Permit을 조회하지만 새 dispatch 권위를 받지 않는다.
7. `GraphActionPermitDispatcher`는 첫 transaction 결과의 `newlyConsumed=true`에서만 Worker
   callback을 호출한다. callback 실패 또는 응답 불확실성 뒤 자동 재dispatch하지 않는다.
8. v1→v2 migration은 먼저 기존 fingerprint 전체를 검증하고 Event/Projection/Snapshot을
   그대로 보존하며 Permit을 backfill하지 않는다.

CAP-001은 이 결정의 registered Capability reference에 별도 `definitionDigest`를 추가한다.
이는 Permit JSON authority를 강화하지만 SQLite table shape는 바꾸지 않으므로 schema
version을 다시 올리지는 않는다.

## 권위와 실패 의미

```text
Graph mutation ─┐
                ├─ same SQLite writer serialization
dispatch claim ─┘

COMMIT ActionPermit(consumed)
  -> optional one-time Worker callback
  -> success: result path continues
  -> failure/uncertain: terminal consumed, no automatic retry
```

commit 전 Graph 변경은 stale decision으로 거부된다. commit 뒤 Graph 변경은 dispatch claim
뒤에 일어난 더 늦은 사건이다. 이 경계는 duplicate execution을 막지만 guaranteed execution을
제공하지 않는다.

## 결과

- preflight-to-dispatch race가 final authority transaction 기준으로 닫힌다.
- cross-process exact retry에서 한 caller만 Worker callback 자격을 얻는다.
- response loss와 crash ambiguity에서 at-most-once가 유지된다.
- 안전을 위해 commit 뒤 crash 시 작업이 실행되지 않은 채 consumed로 남을 수 있다.
- Tool Gateway wiring, lifecycle event, durable Capability Registry, multi-host backend는
  후속 변경이다.

## 관련 문서

- [ADR-0047: MissionEnvelope와 ActionPermit 대수](0047-mission-envelope-and-action-permit-algebra.ko.md)
- [ADR-0049: Durable Single-Campaign SQLite Graph Store](0049-durable-single-campaign-sqlite-graph-store.ko.md)
- [GRAPH-006: Atomic ActionPermit Authority](../graph/GRAPH-006-atomic-action-permit-authority.ko.md)
