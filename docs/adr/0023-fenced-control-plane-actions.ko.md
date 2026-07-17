> Languages: [English](0023-fenced-control-plane-actions.en.md) | [한국어](0023-fenced-control-plane-actions.ko.md)

# ADR 0023: 펜싱된 Control Plane 승인 및 취소 작업

- 상태: Accepted
- 날짜: 2026-07-14
- 확장 문서: [ADR 0024](0024-cooperative-execution-cancellation.ko.md)

## 맥락

ADR 0011은 내구성 있는 승인 체크포인트를 도입했고, ADR 0022는 Web Console에 읽기 전용 Run
모니터링을 공개했다. Operator는 리소스 엔드포인트에서 현재 체크포인트에 연결된 Approval을 찾을
수 없었으며, 승인 결정, 재개, 취소에는 여전히 직접 작성한 API 호출이 필요했다.

`RunState.CANCELLED`는 존재했지만 해당 상태로의 전이가 없었다. Run 행만 바꾸는 것은 안전하지
않다. 대기 중인 Job이 계속 클레임될 수 있고, 리스된 Job이 계속 완료될 수 있으며, 리스 복구가
이를 다시 대기열에 넣을 수 있고, 승인된 체크포인트가 후속 Job을 다시 만들 수 있기 때문이다.
승인 거부 시에도 Run이 `awaiting-approval` 상태에 영구적으로 남았다. 만료 처리는 Approval 행을
변경한 다음 같은 트랜잭션 안에서 예외를 발생시켜 변경 사항이 롤백되었다.

취소는 이미 발생한 Tool의 부작용을 되돌린다고 약속할 수 없다. 대신 Worker와 운영자가 관측할 수
있는 정확하고 내구성 있는 의미를 가져야 한다.

## 결정

Control Plane에 다음과 같은 인증된 계약을 추가한다.

- `GET /v1/runs/{run_id}/approval`은 Run의 현재 체크포인트에 대한 Approval을 반환하고, 없으면
  `null`을 반환한다. Operator, Approver, Auditor는 읽을 수 있지만 Worker는 읽을 수 없다.
  `ApprovalView`를 반환하며 체크포인트 실행 상태, 서명 자료, Run 입력, Job 페이로드는 공개하지
  않는다. 서비스는 반환 전에 체크포인트 무결성, Run 소유권, 의도 필드의 정확한 일치 여부를
  검증한다.
- `POST /v1/runs/{run_id}/cancel`은 Operator만 사용할 수 있으며, 공백이 아닌 1,000자 이하의
  사유가 필요하다. 응답에는 취소가 새로 적용되었는지와 펜싱된 Job 및 철회된 Approval을 명시한다.
- 기존 결정 엔드포인트는 계속 Approver 전용이고 재개 엔드포인트는 계속 Operator 전용이다.
  Console은 인증된 역할에 따라 제어 기능을 활성화하지만 API 권한 부여가 최종 기준이다.

상태 전이는 다음과 같다.

| 초기 상태 | 작업 | 내구성 있는 결과 |
| --- | --- | --- |
| Run `queued` | 취소 | Run과 대기 중인 Job이 `cancelled` |
| Run `running`, Job `leased` | 취소 | Run과 Job이 `cancelled`, 리스 자료 제거 |
| Run `awaiting-approval` | 취소 | Run이 `cancelled`, 대기 중이거나 승인된 Approval이 `revoked` |
| Run `cancelled` | 다시 취소 | 200 무작업, 새 이벤트 없음, 사유 교체 없음 |
| Run `completed` 또는 `failed` | 취소 | 409 충돌 |
| Approval `pending` | 거부 | Approval이 `denied`, Run이 `cancelled` |
| Approval `pending` 또는 `approved` | 만료 관측 | Approval이 `expired`, Run이 `cancelled` |
| 현재 체크포인트의 Approval `approved` | 재개 | Approval이 `consumed`, 후속 Job 하나가 `queued` |

`JobState.CANCELLED`와 `ApprovalState.REVOKED`는 운영상 취소를 실행 실패 및 Approver의 거부와
구분한다. `run.cancelled`, `job.cancelled`, `approval.revoked`, `approval.denied`,
`approval.expired` 이벤트에는 행위자, 길이가 제한된 사유, 영향을 받은 ID를 보존한다. 현재
체크포인트 포인터는 거부, 만료 또는 취소 검토를 위해 보존하고 재개가 성공하면 지운다.

상태를 변경하는 모든 Worker 경로는 행 잠금을 보유한 상태에서 Run 상태를 다시 확인한다.
클레임에는 `queued`가 필요하고, 하트비트, 실패 처리, 체크포인트 생성에는 `running`이 필요하며,
Run이 취소되면 완료 처리를 펜싱한다. 재개와 결정에는 `awaiting-approval` 상태 및
`current_checkpoint_id`와의 정확한 일치가 필요하다. 리스 복구는 취소된 Run을 다시 대기열에
넣거나 실패 처리할 수 없다.

변경 작업은 기존의 종속 항목에서 Run으로 향하는 잠금 순서를 유지한다. Worker 경로는 Job을
잠근 다음 Run을 잠그고, 결정과 재개는 Checkpoint, Approval, Run 순으로 잠근다. 취소는 활성
Job을 안정적인 순서로 잠그고 철회 가능한 Approval을 안정적인 순서로 잠근 다음, 동시에 삽입된
후속 Job을 포착하도록 활성 Job을 다시 읽고 마지막으로 Run을 잠근다. 이를 통해 취소와 종속 항목
펜싱을 원자적으로 만들면서 Run에서 Job으로 향하는 잠금 순서 역전을 추가하지 않는다.

Approval 만료는 API가 충돌을 반환하기 전에 커밋한다. 이 버전에는 재계획이나 대체 승인 전이가
없으므로 거부와 만료는 Run을 종료한다.

Web Console은 `textContent`로 현재 의도를 렌더링하고, 결정 또는 취소 사유를 요구하며, 요청이
진행 중일 때 중복 작업을 비활성화하고, 모든 리소스 ID를 인코딩하며, 성공 또는 충돌 후 Run,
Approval, 이벤트 상태를 다시 로드한다. ADR 0022의 메모리 전용 자격 증명 및 동일 출처 보안
모델은 변경하지 않는다.

## 취소 경계

리스를 지우면 다음 Worker 하트비트 또는 마무리 호출이 리스 충돌을 반환한다. 기본 설정에서는
보통 한 번의 하트비트 간격 안에 이 펜스가 관측된다. 이미 클레임된 Job에 대한 모든 변경 작업
(하트비트, 완료, 실패 또는 체크포인트 생성)은 이 Run 펜스가 우선할 때 구조화된
`run_cancelled`를 반환한다. ADR 0024는 Operator의 사유를 Worker 자격 증명에 공개하지 않으면서
이 코드를 형식이 지정된 최초 기록 우선 취소 컨텍스트에 연결한다. 데몬은 제한된 협력적 정리 유예
기간을 허용한 다음 반환하지 않은 실행 작업을 강제로 취소한다. Local Campaign 및 Tool Loop
러너는 반환 전에 로컬 취소 영수증을 봉인할 수 있다.

내구성 있는 `cancelled` 상태는 Control Plane이 펜싱된 Job을 디스패치하지 않고 그 결과도
수락하지 않음을 뜻한다. 러너 영수증은 하나의 로컬 실행 경로가 취소를 관측하고 등록된 정리를
완료했다는 사실만 나타낸다. Control Plane은 이를 승인하거나 권위 있는 물리적 정지 상태 증거로
취급하지 않는다. 펜스와 영수증 어느 것도 완료된 외부 부작용을 롤백하거나, 취소를 억제하는
실행기가 중지되었음을 보장하거나, 대상 수준의 멱등성을 대체하지 않는다.

## 결과

- Approver와 Operator는 감사 이벤트 페이로드를 파싱하지 않고 승인 수명 주기를 완료할 수 있다.
- 취소된 Run은 지원되는 서비스 경로의 클레임, 완료, 리스 만료, 결정 또는 체크포인트 재개로
  되살릴 수 없다.
- 첫 번째 취소 사유가 우선하며 반복 취소는 안전하게 재시도할 수 있다.
- 철회 메타데이터는 Approval 행에 새로운 nullable 열을 추가하는 대신 추가 전용 이벤트로
  표현한다. 향후 쿼리 또는 보고 요구 사항에 따라 전진 전용 스키마 마이그레이션이 필요할 수 있다.
- SQLite 테스트는 기능적 상태 계약을 검증하지만, 프로덕션 행 잠금 의미와 동시 실행 검증에
  필요한 백엔드는 계속 PostgreSQL이다.
- 플릿 전체 승인 대기열, 관리형 ID, 테넌트 소유권, `cancelling` 상태 및 정리 확인 응답 프로토콜,
  Control Plane이 권위를 갖는 물리적 정지 상태 증명, 임의 외부 시스템 취소는 범위 밖이다.

## 검증

자동화된 테스트는 읽기 역할 분리 및 최소화된 Approval 응답, 대기 중인 Job과 리스된 Job의 취소,
리스 비밀 제거, 오래된 Worker 거부, 승인 후 취소된 재개 펜싱, 거부 시 종료, 만료 영속성, 현재
체크포인트 불변 조건, 종결 상태 충돌, 사유 길이 제한, 멱등적인 반복 취소, 읽기 전용 쿼리,
Console 소스 안전성을 다룬다. 기존 Worker 테스트는 리스 손실로 실행 중인 비동기 실행이 중단될
때 형식이 지정된 협력적 취소와 강제 폴백을 검증한다. 러너 테스트는 봉인된 로컬 취소 영수증을
검증한다. 무결성 테스트는 검토, 결정 또는 재개 전에 서명되지 않은 Approval 필드 드리프트와
Run 간 소유권 드리프트도 거부한다.
옵트인 PostgreSQL 테스트는 취소를 완료 및 체크포인트 재개와 경합시켜 프로덕션 데이터베이스
백엔드의 행 잠금 계약을 검증한다.

## 참조

- [ADR 0011: PostgreSQL 내구성 Control Plane](0011-durable-control-plane.ko.md)
- [ADR 0012: 리스 인식 Worker 데몬](0012-lease-aware-worker-daemon.ko.md)
- [ADR 0022: 동일 출처 Control Plane Web Console](0022-same-origin-control-plane-web-console.ko.md)
- [ADR 0024: 협력적 실행 취소](0024-cooperative-execution-cancellation.ko.md)
