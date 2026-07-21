> Languages: [English](0001-agent-runtime-and-orchestration.en.md) | [한국어](0001-agent-runtime-and-orchestration.ko.md)

# ADR-0001: Agent Runtime and Orchestration Boundary

- Status: Accepted
- Date: 2026-07-12

## Context

PAJIN must manage not only model calls but also campaign authorization, target scope, tool
permissions, budgets, evidence, Finding validation, and retest state over long periods. Tying this
domain state to the checkpoints of a specific agent framework would make it difficult to evolve the
Policy Engine, Web UI, distributed Workers, and audit system independently.

The options considered were LangGraph, PydanticAI, the OpenAI Agents SDK, and a custom
implementation.

## Decision

1. PAJIN Core directly owns the state of Campaign, Capability, ToolSpec, AuditEvent, and Finding.
2. `ProviderAgentRuntime` is the only supported production runtime for network-backed model
   planning and validation.
3. `PydanticAIAgentRuntime` is restricted to PydanticAI's exact local `TestModel` for deterministic
   tests. Model names, general model objects, and subclasses are rejected before Agent construction.
4. The Agent Runtime is responsible only for model-based judgments such as planning and validation.
5. Every network-backed model call passes through `PolicyBoundProviderPort`, the Tool Gateway,
   Campaign model budgets, and run-scoped Secret Leases. Every actual Tool Invocation also passes
   through the PAJIN Policy Engine and Tool Gateway.
6. The initial Workflow Backend starts as a local implementation, with a Temporal Adapter added for
   production operation.
7. LangGraph is allowed only as an optional workflow implementation inside a specific Mode Pack,
   not as PAJIN Core.

## Consequences

### Positive

- Model providers and agent frameworks can be replaced.
- Authorization and audit boundaries are separated from the LLM control flow.
- The CLI and Web UI can use the same Campaign state.
- The system can start as a local MVP and expand to Temporal-based durable execution.

### Negative

- PAJIN must maintain the task state machine and execution contracts itself.
- Some graph visualization and checkpoint features provided by frameworks must be integrated
  directly.
- Network-backed PydanticAI models remain unsupported until they have a repository-native adapter
  to the governed provider boundary.
- The initial implementation is larger than a simple LangGraph application.

## References

- [PydanticAI Multi-Agent Patterns](https://pydantic.dev/docs/ai/guides/multi-agent-applications/)
- [PydanticAI Durable Execution](https://pydantic.dev/docs/ai/integrations/durable_execution/overview/)
- [LangGraph Overview](https://docs.langchain.com/oss/python/langgraph/overview)
- [Temporal Documentation](https://docs.temporal.io/)
