> Languages: [English](0020-specialist-call-budget-allocation.en.md) | [한국어](0020-specialist-call-budget-allocation.ko.md)

# ADR 0020: Specialist 호출 예산 할당

- 상태: Accepted
- 날짜: 2026-07-13

## 맥락

자식 Tool 호출이 실행될 때 루트 Capability가 모든 상위 항목의 수를 차감하므로 형제 Grant는
Campaign 전체 한도를 초과할 수 없다. 그런데도 이전 로컬 오케스트레이터는 형제 간 호출을
예약하지 않은 채 위험도가 낮은 각 Specialist에게 최대 두 번의 시도를 독립적으로 위임했다.
전체 호출이 두 번인 다단계 계획에서는 첫 번째 T0/T1 작업이 재시도로 두 호출을 모두 소진할
수 있었다. 그러면 두 번째 Specialist가 생성되더라도 루트가 비어 있어 디스패치 전에 실패했다.

모델 기반 Validator와 Reporter 역할도 Provider Gateway를 통해 루트 Tool 호출 예산을
사용한다. Specialist 할당으로 인해 이 역할들이 이미 선언한 최대 시도 횟수를 실행할 수 없게
되어서는 안 된다.

## 결정

Planner가 검증된 계획을 반환한 후, 어떤 Specialist도 생성하기 전에 Supervisor는 다음 순서로
루트 호출을 할당한다.

1. 모델 기반 Validator와 Reporter가 있으면 이들이 선언한 최대 시도 횟수를 예약한다.
2. 계획된 모든 Specialist에 첫 번째 시도 한 번을 필수로 배정한다.
3. 남은 각 슬롯은 안정적인 계획 순서에 따라 T0 또는 T1 Specialist에 최대 한 번의 재시도로 배정한다.
4. 자격이 있는 모든 Specialist가 이미 최대치인 두 번을 배정받았다면 호출을 할당하지 않고 남긴다.

제어 역할 예약 후 남은 루트 용량으로 모든 Specialist의 첫 번째 시도를 지원할 수 없다면 부분적인
Specialist 팬아웃 전에 Campaign을 취소한다. 각 Specialist Grant의 `maxCalls`와 Task의
`maxAttempts`에는 같은 할당량을 지정한다. Supervisor는 루트 잔여량, 제어 역할 예약량,
요청별 할당량, 미할당 개수를 담은 `specialist.call-budget.allocated`를 기록한다.

이는 `CapabilityLedger` 내부의 변경 가능한 예약이 아니라 결정론적 로컬 할당이다. 계보 카운터는
디스패치 시점의 최종 원자적 권한 검사로 유지된다. 오케스트레이터가 부여한 자식 최대치의 합이
관측된 루트 잔여량을 초과할 수 없으므로, 성공하거나 실패한 자식이 형제에게 필요한 첫 번째 시도를
소진할 수 없다.

## 결과

- 다단계 계획의 최소 실행량이 예산에 맞지 않으면 부분 팬아웃 전에 실패한다.
- 일시적 실패가 뒤에 오는 Specialist의 첫 번째 승인된 시도를 빼앗을 수 없다.
- Campaign에 잉여 호출이 명시적으로 있으면 T0/T1 재시도 동작을 계속 사용할 수 있다.
- 공급자 기반 하위 역할은 선언한 최대 시도 횟수에 충분한 루트 용량을 유지한다.
- 희소한 선택적 재시도를 누가 받을지는 안정적인 계획 순서로 결정하며, 우선순위 또는 병렬
  스케줄러는 도입하지 않는다.

ADR 0021은 이 단일 Supervisor 할당이 디스패치 전에 모든 자식의 최대치를 확정하기 때문에
명시적으로 옵트인한 Tool에만 제한된 로컬 동시 실행을 허용한다. 분산 실행에는 여전히 내구성 있고
원자적인 예약이 필요하다.
