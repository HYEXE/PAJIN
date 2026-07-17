> Languages: [English](0004-dynamic-multi-agent-execution.en.md) | [한국어](0004-dynamic-multi-agent-execution.ko.md)

# ADR-0004: 동적 다중 에이전트 실행과 권한 감쇠 위임

- 상태: Accepted
- 날짜: 2026-07-12
- 확정 의미론 수정: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

> 아래 Validator와 최종 Gate 동작은 최초 구현 결정을 기록한다. ADR 0027 이후에는 의미론적
> 지지와 동일 Run의 증적 검사만으로 제품 수준의 `confirmed`를 만들 수 없다. Candidate에
> 결박된 새로운 ReplayOutcome도 필요하다.

- 호출 예산 할당 수정: ADR 0020
- Specialist 스케줄링 수정: ADR 0021

## 배경

PAJIN에는 에이전트 생성이 권한 생성으로 바뀌지 않는 여러 전문 에이전트가 필요하다. 모델이
생성한 계획은 신뢰할 수 없는 입력이며 에이전트 ID, 도구, 대상, 예산, 의존성 또는 Finding을
지어낼 수 있다. 프레임워크가 소유하는 에이전트 그래프는 캠페인 상태와 취소 의미론도 하나의
모델 런타임에 결합한다.

따라서 시스템에는 하나의 승인, 정책, 증적 및 Worker 경계를 유지하면서 결정론적 또는 모델
기반 Planner와 Validator Adapter를 사용할 수 있는 PAJIN 소유 실행 그래프가 필요하다.

## 결정

### 역할과 그래프 소유권

1. `MultiAgentCampaignRunner`는 로컬 Supervisor이며 전체 Run 상태를 소유한다.
2. 모든 Run은 Supervisor로 시작해 Planner, 계획된 단계별 Specialist, 별도의 Semantic
   Validator 및 Reporter를 동적으로 생성한다. ADR 0027은 제품 수준 검증 파이프라인에
   신뢰된 Restricted Reproducer 경계를 추가한다.
3. Planner는 타입이 지정된 `AgentPlan`을 반환하지만 에이전트를 생성하거나 도구를 실행할 수
   없다. Supervisor는 Planner가 제공한 모든 `agent_id`를 무시하고 각 요청을 실제
   Specialist에 결박한다.
4. Task는 waiting, running, succeeded, failed, cancelled 및 skipped 상태가 명시된 타입 기반
   비순환 의존성 그래프에 저장된다.
5. PAJIN은 에이전트, Task graph, Capability, 예산, 제어 상태, 이벤트, 증적, Finding 및
   보고서를 별도의 Run Artifact로 영속화한다.

### Capability 감쇠

1. Supervisor만 root Capability Grant를 받는다. 도구, 대상, 위험 상한, 호출 예산, 만료 및
   위임 깊이는 승인된 Campaign과 등록된 도구에서 가져온다.
2. 모든 child Grant는 parent를 참조하고 깊이를 정확히 1만큼 늘려야 하며 parent의 도구,
   대상, 위험 등급, 호출 횟수 및 만료 범위의 부분집합이어야 한다.
3. Planner, Validator 및 Reporter Grant에는 도구와 대상이 없고 호출 횟수는 0이다.
4. Specialist는 할당된 도구, 정확히 선언된 대상, 필요한 위험 등급 및 제한된 시도 횟수만
   받는다.
5. child 호출을 실행하면 해당 Grant와 모든 ancestor Grant의 남은 횟수가 감소한다. 따라서
   sibling Grant는 root Campaign 예산을 증폭할 수 없다.
6. Kill Switch가 활성화되면 root Grant와 모든 descendant Grant의 권한이 철회된다.

### 예산, 재시도 및 취소

1. 에이전트를 생성하기 전에 에이전트 수와 생성 깊이를 예약한다. 필요한 전체 팀이 캠페인
   에이전트 예산을 초과하면 Supervisor는 fan-out 전에 계획을 거부한다.
2. 도구 호출은 dispatch 전에 검사하고 실제 dispatch 후에만 계산한다. Campaign 경과 시간과
   비용은 PAJIN 런타임 상태다.
3. T0 및 T1 도구는 실행된 일시적 실패 후 한 번 재시도할 수 있다. T2 이상 도구는 자동으로
   재시도하지 않는다. 정책이 거부한 요청은 절대 재시도하지 않는다.
4. Kill Switch는 단방향이며 프로그램에서 직접, 정책이나 예산에 의해 또는 로컬 신호 파일을
   통해 활성화할 수 있다.
5. 대기 중인 모든 Planner, Worker 및 Validator 작업은 Kill Switch 및 캠페인 마감 시간과
   경합한다. 취소는 Worker Backend까지 전달되어 Docker CLI 프로세스를 종료하고, 이름이
   지정된 컨테이너를 강제로 제거하고, egress 리소스를 제거한 다음 상위로 전파된다.
6. 대기 중이거나 실행 중인 그래프 Task는 cancelled 상태가 되고, 활성 에이전트도 cancelled
   상태가 되며, Capability 계보의 권한이 철회되고, 부분 Run은 취소 사유와 함께 보고된다.

### 독립적인 Finding 검증

1. 실행하는 Specialist는 Finding을 confirmed로 표시하지 않는다.
2. 별도의 Validator 역할이 계획과 범위가 제한된 Tool Result를 받는다.
3. PAJIN은 Validator 출력 후 결정론적 최종 Gate를 적용한다. `validated`가 true여야 하고,
   대상이 Campaign에 선언되어야 하며, 증적이 비어 있지 않아야 하고, 인용한 모든 Artifact가
   같은 Run의 Specialist 결과에 존재해야 한다.
4. 거부된 Candidate와 사유는 감사 이벤트가 된다. 승인된 Finding만 `findings.json`과 최종
   보고서에 들어간다.

## 결과

### 장점

- 동적 에이전트 생성으로 권한을 늘릴 수 없다.
- 도구 권한은 Task별로 지정되며 전체 parent 계보를 통해 감사할 수 있다.
- PAJIN이 상태와 수명 주기 전이를 소유하므로 모델 런타임 Adapter를 교체할 수 있다.
- 운영자 취소는 도구가 끝날 때까지 기다리지 않고 활성 Docker Worker까지 전달된다.
- Finding에는 독립적인 에이전트 판정과 결정론적 증적 출처가 모두 필요하다.

### 절충점과 잔여 위험

- 로컬 Scheduler는 ADR 0021에서 정의한 제한된 명시적 동시성만 지원한다. 분산 실행에는
  내구성 있는 Backend의 원자적 예산 및 Capability 트랜잭션이 여전히 필요하다.
- 로컬 JSONL 및 JSON Artifact는 재현할 수 있지만 장애에도 견디는 Workflow checkpoint는
  아니다.
- 결정론적 Run에서는 공급자 token 및 비용 계산이 계속 0이다. 비용 예산으로 유료 호출을
  관리하려면 모델 Adapter가 공급자 사용량을 보고해야 한다.
- 로컬 신호 파일 Kill Switch는 짧은 간격으로 polling된다. 운영 Control Plane에는 인증된
  취소 API와 내구성 있는 취소 전달이 필요하다.
- Planner와 Validator 구현은 결정론적 테스트에서 코드를 공유할 수 있지만, 도구 호출 권한이
  없거나 제한된 서로 다른 Capability 및 증적 경계를 적용받는 별도 역할 ID로 실행된다.

## 검증

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker docker
.venv\Scripts\pajin multi-cancel-check --worker docker
.venv\Scripts\pytest -q
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

최초 인수 조건은 일반 Docker Run에서 완료된 역할 에이전트 5개와 legacy validation Finding
1개를 요구한다. 해당 Finding은 ADR 0027을 준수하는 재현이 성공하기 전까지 제품 수준
Confirmed가 아니다. 또한 활성 Worker dispatch 후 Specialist/Validator/Reporter Task가
cancelled 상태가 되고, Grant 권한이 완전히 철회되며, 취소 Run에 잔여 PAJIN 컨테이너나
네트워크가 없어야 한다. sibling 예산 비증폭, 동적 fan-out, 제한된 재시도, 외부 신호 취소 및
조작된 증적 거부 테스트도 통과해야 한다.
