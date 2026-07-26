> 언어: [English](GRAPH-005-durable-sqlite-graph-store.en.md) | [한국어](GRAPH-005-durable-sqlite-graph-store.ko.md)

# GRAPH-005: Durable Single-Campaign SQLite Graph Store

- 상태: 첫 durable adapter 구현 및 로컬 검증 완료, Linux CI 확인 대기
- 날짜: 2026-07-26
- 결정: [ADR-0049](../adr/0049-durable-single-campaign-sqlite-graph-store.md)
- 구현: `pajin.graph.sqlite_store`
- 테스트: `tests/test_graph_sqlite_store.py`

## 결과

GRAPH-005는 Campaign-wide 상태를 `RunStore`에 넣는 대신 별도 Graph Store를 선택한다.
`RunStore`는 한 Run의 봉인된 artifact·audit 경계로 유지한다. 새 `SQLiteGraphStore`는 한
Campaign의 Canonical Event Log, append-only Projection history, immutable Snapshot chain을 한
로컬 SQLite 데이터베이스에서 소유한다.

공개 facade는 protocol 호환 adapter 세 개를 제공한다.

- `SQLiteGraphEventLog`
- `SQLiteGraphProjectionStore`
- `SQLiteGraphSnapshotStore`

기존 in-memory 구현은 reference semantics로 유지되며 migration이 필요 없다.

## Durable schema

한 데이터베이스는 정확히 한 Campaign ID와 schema fingerprint에 고정된다.

| Table | Authority | Mutation rule |
| --- | --- | --- |
| `graph_store_metadata` | schema version/digest와 Campaign ID | immutable |
| `graph_store_writers` | Event·Snapshot writer identity | 최초 insert 후 immutable |
| `graph_events` | 순서가 있는 admission/rejection Event Log | append-only |
| `graph_nodes` | exact admitted-node 조회 index | Event와 같은 transaction에서 append |
| `graph_projections` | genesis를 포함한 deterministic revision history | append-only |
| `graph_snapshots` | content-addressed Snapshot chain | append-only |

모든 관리 table에 update·delete·replacement 방지 trigger를 둔다. 초기화는 정확한 table,
index, trigger, schema version, application ID, metadata를 fingerprint한다. 다른 Campaign,
누락된 trigger, 예상하지 않은 table, foreign-key 위반, SQLite integrity 실패가 있으면 reopen을
fail-closed한다.

## Event transaction

Event append는 `BEGIN IMMEDIATE` 안에서 다음을 검증한다.

1. process-local writer token과 durable하게 고정된 authority ID/digest
2. exact Campaign, canonical Event bytes, sequence, previous digest
3. 고유한 Event identity와 semantic attempt
4. Event 내부 node 또는 durable admitted-node index에 대한 모든 Edge
5. 기존 canonical node ID가 있을 때 동일한 material

Event row와 새 admitted-node index row는 함께 commit된다. Event가 Projection refresh보다 먼저
commit될 수 있으며, 이는 partial Event가 아니라 명시적으로 복구 가능한 상태다.

두 process는 같은 고정 authority identity로 데이터베이스를 reopen할 수 있다. SQLite가 write
transaction을 직렬화한다. 둘이 같은 next sequence를 만들면 하나만 append에 성공하고 다른 쪽은
변경 없이 stale 실패한다. 호출자는 다시 읽고 authority를 통해 재제출해야 한다. 이 adapter는
multi-host leader lease를 제공한다고 주장하지 않는다.

## Projection transaction

Projection은 mutable head row가 아니라 immutable revision history다. `current()`는 가장 큰
revision을 읽는다. `compare_and_advance()`는 다음 순서를 따른다.

1. 전달된 Event를 재검증한다.
2. 이 데이터베이스의 durable Event Log와 exact prefix인지 확인한다.
3. `BEGIN IMMEDIATE`로 잠근다.
4. expected revision과 Event Log head를 비교한다.
5. rollback 또는 현재 prefix divergence를 거부한다.
6. deterministic candidate revision 하나를 append한다.

따라서 concurrent store instance 사이에서도 CAS winner는 하나다. Event commit 뒤 Projection
publication 전에 process가 중단되면 Projection이 뒤처진다. reopen 후
`GraphProjectionReconciler`가 exact durable prefix를 replay하며 divergence를 덮어쓰지 않는다.

## Snapshot transaction

Snapshot writer identity는 별도로 고정한다. Snapshot append는 creator, predecessor, 내장
Projection을 exact 검증하고 그 Projection revision/digest가 같은 데이터베이스에 이미 존재할 것을
요구한다. Snapshot identity와 predecessor는 immutable chain을 이룬다. exact
`GraphSnapshotRef` resolution은 재시작 후에도 GRAPH-003·GRAPH-004 decision 계약을 보존한다.

## SQLite와 filesystem 경계

adapter는 다음을 사용한다.

- SQLite DELETE journal mode와 `synchronous=FULL`
- write의 `BEGIN IMMEDIATE`
- foreign key 활성화, `trusted_schema` 비활성화, read-only/query-only reader
- 제한된 busy timeout
- model·index를 교차 검증하는 canonical UTF-8 JSON BLOB
- POSIX owner-only parent/file mode
- symlink path component, symlink/hard-linked database leaf, 안전하지 않은 journal/WAL sidecar
  거부
- connection open 시 file과 direct-parent identity 확인

이는 host-local durable adapter 경계다. 권한 있는 공격자가 상위 경로를 동시에 교체하는 상황,
SQLite 보장 밖의 disk/controller 장애, 검증된 backup/restore 재해복구 훈련까지 해결했다고
주장하지 않는다.

## 검증된 conformance

집중 Graph suite는 로컬에서 54개 테스트를 통과한다. 이 중 durable-store 테스트 8개는
Windows에서 통과했고 POSIX link 테스트 2개는 Windows에서 정상 skip되어 Linux CI 확인 대상으로
남는다.

durable 테스트는 다음을 포함한다.

- Event·Projection·Snapshot과 exact reference의 reopen
- 재시작 뒤 Proposal idempotent retry
- Event commit·Projection lag 복구와 reconciliation 멱등성
- cross-instance Event append와 Projection CAS의 단일 winner
- 다른 Event Log로 만든 Projection 거부
- Campaign과 writer identity 고정
- Snapshot predecessor와 durable Projection 확인
- append-only trigger와 schema fingerprint 변조 거부
- durable Event Log가 앞선 stale Decision 거부

## 호환성·migration·rollback

이 adapter는 opt-in이며 기존 Mode, CLI, API, `RunStore` format을 바꾸지 않는다. migration할
production Canonical Graph database도 아직 없다. ARCH-001의 trusted legacy-to-Proposal adapter는
후속이며 변환한 material을 자동 admission하지 않는다.

runtime wiring 전 rollback은 `SQLiteGraphStore` 생성을 중단하고 데이터베이스를 audit evidence로
보존하는 것이다. 한 Campaign이 이 Event Log를 canonical authority로 사용한 뒤에는 exact Event
chain을 export·검증해야 한다. admitted history 삭제나 rewrite는 허용되는 rollback이 아니다.

## 남은 경계

GRAPH-005는 다음을 구현하지 않는다.

- multi-host leader election·lease·PostgreSQL/HA storage
- Graph preflight, ActionPermit 발급·소비, Worker dispatch를 아우르는 atomic transaction
- 모든 fsync 경계의 process-kill/fault-injection test
- retention·compaction·검증된 backup/restore·at-rest encryption·external integrity anchoring
- admission queue/runtime service wiring
- B2.9 collaboration projection과 Supervisor 실행

다음 trust-boundary 조각은 `GraphDecisionPreflight`를 실행 권위로 취급하지 말고 latest revision
비교와 deterministic ActionPermit 발급·소비를 결합해야 한다.
