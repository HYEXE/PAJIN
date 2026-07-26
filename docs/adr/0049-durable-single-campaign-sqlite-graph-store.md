# ADR-0049: Durable Single-Campaign SQLite Graph Store

- 상태: 승인
- 날짜: 2026-07-26

## 배경

ADR-0048은 첫 durable Canonical Graph 저장 위치를 기존 `RunStore`와 별도 Graph 모듈 사이에서
결정하지 않았다. GRAPH-002부터 GRAPH-004는 append-only admission, exact retry/equivocation,
deterministic projection, immutable Snapshot, lag recovery, contradiction 보존, stale-decision
거부라는 conformance 계약을 만들었다.

`RunStore`는 의도적으로 한 Run에 결박되어 artifact와 audit history를 봉인한다. Canonical Graph
revision은 Campaign-wide이고 여러 Run에 걸쳐 이어지며 cross-process revision/head CAS와 독립적인
Snapshot publication이 필요하다. 두 책임을 `RunStore`에 넣으면 한 Campaign을 Run directory
여러 개로 분할하거나 Run 경계 안에 두 번째 Campaign authority를 만들게 된다.

첫 durable adapter는 production service dependency를 새로 요구하지 않으면서 Control Plane
database로 확장 가능한 경계를 보존해야 한다.

## 결정

### 1. 별도 Graph Store를 사용한다

첫 durable backend는 `pajin.graph.sqlite_store`의 `SQLiteGraphStore`다. `RunStore` format은
바꾸지 않는다. 한 database는 정확히 한 Campaign을 소유하고 Event Log, Projection Store,
Snapshot Store protocol adapter를 제공한다.

### 2. authoritative history를 append-only로 유지한다

Admission Event, admitted-node lookup row, Projection revision, Snapshot은 append-only다. 현재
Projection은 mutable last-write-wins row가 아니라 저장된 가장 큰 revision이다. Metadata와
Event/Snapshot writer identity도 초기화 후 immutable이다.

### 3. schema·Campaign·writer를 고정한다

database는 exact schema object를 fingerprint하고 schema version/digest, SQLite application ID,
Campaign ID를 고정한다. Event와 Snapshot writer ID/digest pair는 각각 한 번만 insert한다.
같은 identity로 process가 reopen할 수 있지만 다른 identity는 fail-closed한다.

### 4. host-local 직렬화에 SQLite transaction을 사용한다

write는 `BEGIN IMMEDIATE`, DELETE journal mode, `synchronous=FULL`을 사용한다.

- Event append는 Event와 새 admitted-node index를 atomic하게 기록한다.
- Projection CAS는 같은 durable Event Log의 exact prefix를 요구하고 immutable revision 하나를
  append한다.
- Snapshot append는 exact predecessor와 같은 database에 이미 발표된 Projection을 요구한다.

Projection publication 전에 Event가 commit된 상태는 지원하는 recovery 상태다.
`GraphProjectionReconciler`가 reopen 뒤 복구하며 divergent history를 rewrite하지 않는다.

### 5. storage read에서도 canonical validation을 유지한다

model은 제한된 canonical UTF-8 JSON BLOB으로 저장한다. read는 typed model, content-addressed
identity, canonical bytes, 중복 index column을 다시 검증한다. reopen 때 SQLite schema,
foreign-key, integrity check를 수행한다.

### 6. 실행 권위는 분리한다

이 store는 `GraphDecisionPreflight`를 ActionPermit으로 바꾸지 않는다. atomic latest-revision
비교와 ActionPermit 발급·소비, Worker dispatch는 별도 decision과 trust-boundary 조각이다.

## 검토한 대안

### `RunStore` 확장

한 Run lifecycle과 seal semantics가 Campaign-wide sequence와 cross-Run projection head를
자연스럽게 소유하지 못하므로 첫 adapter에서는 채택하지 않았다. `RunStore`는 source evidence와
legacy migration input으로 계속 사용한다.

### 지금 Control Plane database에 Graph table 추가

보류했다. PostgreSQL HA와 공유 operational lease를 제공할 수 있지만 local 계약을 검증하기 전에
첫 Graph conformance 조각을 optional service deployment와 database migration에 결합한다.

### Run 옆 JSONL file

multi-process append, exact CAS, schema constraint, Event/Projection/Snapshot transaction을 위해
새 filesystem database protocol이 필요하므로 채택하지 않았다.

## 호환성과 migration

adapter는 opt-in이다. 기존 Mode, manifest, CLI/API 계약, Run directory, in-memory Graph test는
바뀌지 않는다. migration할 production Graph database는 아직 없다.

향후 legacy adapter는 original Run/artifact digest를 provenance로 가진 typed Proposal을 만든다.
변환은 admission authority를 부여하지 않는다.

## Rollback

runtime integration 전에는 SQLite store 생성을 중단하고 file을 audit evidence로 보존한다. 한
Campaign이 이를 canonical로 취급한 뒤에는 rollback도 exact Event chain을 보존·검증해야 한다.
admitted history 삭제·truncate·rewrite는 금지한다. 대체 backend는 canonical Event를 import하고
conformance test를 통해 Projection/Snapshot digest를 재현해야 한다.

## 결과

장점:

- Campaign-wide Graph ownership이 한 Run의 seal과 충돌하지 않는다.
- cross-process host-local Event append와 Projection CAS가 한 database 직렬화 지점을 사용한다.
- 새 runtime dependency 없이 Event, revision, Snapshot이 재시작 뒤에도 유지된다.
- future PostgreSQL adapter도 같은 storage-neutral Graph protocol을 사용할 수 있다.

비용과 한계:

- SQLite는 one-host storage이며 multi-host leader election이나 HA가 아니다.
- Event append와 Projection publication은 의도적으로 별도 transaction이고 중단 뒤
  reconciliation이 필요하다.
- backup/restore, compaction, at-rest encryption, external anchoring, process-kill fault injection은
  미완료다.
- 외부 Worker side effect와 database commit의 physical atomicity는 제공하지 않는다.
- schema v2의 consumed dispatch claim 이후 runtime wiring과 lifecycle event가 남아 있다.

## 구현

[GRAPH-005](../graph/GRAPH-005-durable-sqlite-graph-store.md)에 schema, recovery,
filesystem, conformance, 호환성, 남은 경계를 기록한다. 후속
[GRAPH-006](../graph/GRAPH-006-atomic-action-permit-authority.md)은 exact v1 fingerprint를
검증한 뒤 append-only Permit table을 추가하는 schema v2 migration과 final authority
transaction을 구현한다.

## 관련 문서

- [ARCH-001: PAJIN Architecture v2](../rfc/0001-pajin-architecture-v2.md)
- [ADR-0048: Minimum Graph와 Admission 일관성](0048-minimum-graph-and-admission-consistency.md)
- [GRAPH-004: Consistency·Recovery·Stale Decision](../graph/GRAPH-004-consistency-recovery-stale-decision.md)
- [ADR-0050: Consumed ActionPermit Dispatch Claim](0050-consumed-action-permit-dispatch-claim.md)
