> Languages: [English](0011-durable-control-plane.en.md) | [한국어](0011-durable-control-plane.ko.md)

# ADR 0011: PostgreSQL 기반 영속 Control Plane

- 상태: 승인됨
- 날짜: 2026-07-12
- 확장: [ADR 0023](0023-fenced-control-plane-actions.ko.md)

## 배경

파일 기반 runtime은 인가된 단일 로컬 campaign에 유용하지만 여러 Supervisor 또는 Worker
프로세스를 안전하게 조정할 수 없다. 특히 운영 승인을 CLI 문자열로 나타낼 수 없고, filesystem
checkpoint claim은 해당 host에서만 유효하며, Worker가 crash하면 영속적인 소유자나 복구 기한
없이 작업이 남을 수 있다.

## 결정

PAJIN은 PostgreSQL을 사용하는 선택적 FastAPI Control Plane을 추가한다. 기존 파일 기반 CLI와
Run Artifact도 계속 지원한다. Control Plane은 오케스트레이션과 인가 경계이며 공격 Tool을 직접
실행하지 않는다.

저장소 모델은 다음 다섯 개 테이블을 포함한다.

| 테이블 | 용도 | 핵심 불변 조건 |
|---|---|---|
| `cp_runs` | 정규 campaign 수명 주기 | submission key는 멱등성을 보장한다 |
| `cp_jobs` | 영속 Worker queue | 하나의 hash된 lease token과 제한된 시도 횟수 |
| `cp_checkpoints` | 재개 가능한 상태 | 정규 payload hash와 HMAC 서명 |
| `cp_approvals` | T3/T4 사람 결정 | 정확한 checkpoint, 호출, Tool, 표적, 등급과 만료 |
| `cp_events` | 감사 이력 | 데이터베이스 trigger가 갱신과 삭제를 거부한다 |

PostgreSQL은 짧은 transaction에서 `SELECT ... FOR UPDATE SKIP LOCKED`로 사용 가능한 다음 Job을
claim한다. Claim하면 시도 횟수가 증가하고 무작위 lease token을 한 번 반환한다. 저장하는 값은
SHA-256 digest뿐이다. Heartbeat는 활성 lease를 연장하고, 완료와 실패에는 정확한 Worker ID와
token이 필요하다. 만료된 lease는 남은 시도가 있으면 원자적으로 queue에 다시 넣고, 그렇지
않으면 dead-letter 처리한다.

Checkpoint payload는 정규화된 JSON이다. 서명 envelope은 checkpoint ID, Run ID, sequence,
schema version, payload digest와 signing-key ID를 binding한다. Database는 key ID만 저장하고 key는
저장하지 않는다. 재개 시 승인 상태를 확인하기 전에 payload digest와 HMAC를 모두 검증한다.
승인된 T3/T4 결정은 서명된 대기 intent와 정확히 일치해야 한다. 재개 작업은 checkpoint를
원자적으로 claim하고 승인을 소비한 다음 하나의 멱등 continuation Job을 queue에 넣는다. 두 번째
재개는 거부한다.

불투명 bearer 자격증명은 database 외부에서 설정하며 API 프로세스에는 SHA-256 digest로만
보관한다. 역할은 Operator, Approver, Worker와 Auditor로 분리한다. Lab은 공개 fixture
자격증명을 사용한다. 운영에서는 서로 다른 자격증명과 서명 key를 secret manager에서 가져오고,
API 앞단에서 TLS를 종료하고, database와 API 네트워크를 제한해야 한다.

SQLite는 로컬 개발과 API unit test를 위해 같은 repository 계약을 구현한다. 외래 키와
append-only trigger를 명시적으로 활성화한다. SQLite는 PostgreSQL의 다중 consumer
`SKIP LOCKED` 의미론을 제공하지 않으며 운영 queue backend가 아니다.

## API 흐름

1. Operator가 멱등 Run을 제출하면 transaction이 첫 번째 queued Job과 이벤트를 생성한다.
2. Worker는 Job을 claim하고 완료하거나 승인 checkpoint를 만들 때까지 heartbeat를 보낸다.
3. Checkpoint를 만들면 해당 Job이 완료되고 Run은 `awaiting-approval` 상태가 된다.
4. Approver는 서명된 정확한 T3/T4 intent를 승인하거나 거부한다.
5. Operator는 승인된 checkpoint를 재개하여 한 번 소비하고 continuation Job을 생성한다.
6. Worker는 continuation Job을 claim하고 완료한다. Run은 `completed` 상태가 된다.
7. 유지보수 호출이나 이후의 어떤 claim도 crash 복구를 위해 만료된 lease를 정리한다.

## 결과

- 여러 Worker 프로세스가 중앙 in-memory broker 없이 작업을 claim할 수 있다.
- 승인자 신원과 일회성 소비가 영속적이고 감사 가능하다.
- 행과 signing key를 모두 변경할 수 있는 역할에 의한 database 침해는 이 경계 밖의 문제다.
  운영 signing key를 database와 같은 관리 주체에 두면 안 된다.
- `create_all`은 이 vertical slice에 충분하다. 이후 스키마 변경에서는 운영 upgrade 지원을
  주장하기 전에 관리되는 forward-only migration을 도입해야 한다.
- 영속 저장소는 정책, Capability, Scope, egress, Worker 격리 또는 Secret Lease 강제를
  대체하지 않는다. Worker는 Job을 실행할 때도 이러한 기존 경계에 다시 진입해야 한다.

## 참고 자료

- [PostgreSQL `SELECT` locking clause](https://www.postgresql.org/docs/17/sql-select.html)
- [SQLAlchemy `with_for_update(skip_locked=True)`](https://docs.sqlalchemy.org/en/20/core/selectable.html)
- [FastAPI 보안 dependency](https://fastapi.tiangolo.com/reference/security/)
