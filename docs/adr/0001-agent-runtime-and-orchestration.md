# ADR-0001: Agent Runtime과 Orchestration 경계

- 상태: Accepted
- 날짜: 2026-07-12

## Context

PAJIN은 모델 호출뿐 아니라 캠페인 승인, 대상 범위, 도구 권한, 예산, 증적, Finding 검증 및 재검증 상태를 장기간 관리해야 한다. 이러한 도메인 상태를 특정 에이전트 프레임워크의 체크포인트에 종속시키면 정책 엔진, Web UI, 분산 워커와 감사 시스템을 독립적으로 발전시키기 어렵다.

검토 대상은 LangGraph, PydanticAI, OpenAI Agents SDK 및 자체 구현이었다.

## Decision

1. PAJIN Core가 Campaign, Capability, ToolSpec, AuditEvent, Finding 상태를 직접 소유한다.
2. `ProviderAgentRuntime`을 network-backed model planning 및 validation을 위한 유일한 운영
   runtime으로 사용한다.
3. `PydanticAIAgentRuntime`은 결정론적 test를 위한 PydanticAI의 정확한 로컬 `TestModel`만
   허용한다. Model name, 일반 model object 및 subclass는 Agent 생성 전에 거부한다.
4. Agent Runtime은 계획 및 검증과 같은 모델 기반 판단만 담당한다.
5. 모든 network-backed model call은 `PolicyBoundProviderPort`, Tool Gateway, Campaign model
   budget 및 run-scoped Secret Lease를 거친다. 모든 실제 Tool Invocation도 PAJIN Policy
   Engine과 Tool Gateway를 거친다.
6. 초기 Workflow Backend는 로컬 구현으로 시작하고, 운영 단계에서 Temporal Adapter를 추가한다.
7. LangGraph는 PAJIN Core가 아니라 특정 Mode Pack 내부의 선택적 워크플로 구현으로만 허용한다.

## Consequences

### Positive

- 모델 공급자와 에이전트 프레임워크를 교체할 수 있다.
- 권한 및 감사 경계가 LLM 제어 흐름과 분리된다.
- CLI와 Web UI가 동일한 Campaign 상태를 사용할 수 있다.
- 로컬 MVP에서 시작해 Temporal 기반 장기 실행으로 확장할 수 있다.

### Negative

- PAJIN이 작업 상태 머신과 실행 계약을 직접 유지해야 한다.
- 프레임워크가 제공하는 일부 그래프 시각화와 체크포인트 기능을 직접 연결해야 한다.
- Network-backed PydanticAI model은 repository-native governed-provider adapter가 추가될 때까지
  지원하지 않는다.
- 초기 구현량이 단순 LangGraph 애플리케이션보다 많다.

## References

- [PydanticAI Multi-Agent Patterns](https://pydantic.dev/docs/ai/guides/multi-agent-applications/)
- [PydanticAI Durable Execution](https://pydantic.dev/docs/ai/integrations/durable_execution/overview/)
- [LangGraph Overview](https://docs.langchain.com/oss/python/langgraph/overview)
- [Temporal Documentation](https://docs.temporal.io/)
