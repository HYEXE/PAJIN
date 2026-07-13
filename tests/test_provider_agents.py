import asyncio
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.base import ModelCallFailure
from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.agents.provider import ModelToolDescriptor, ProviderAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.providers import OpenAICompatibleChatTool, ProviderMessage, ProviderRegistration
from pajin.runtime.control import BudgetExceeded
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _registration() -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": "role-provider",
            "endpoint": "https://provider.example/v1/chat/completions",
            "model": "role-model",
            "secret_ref": "provider/role/api-key",
        }
    )


class RoleWorker:
    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        now = datetime.now(UTC)
        if job.command == ["mock-agent-probe"]:
            request = json.loads(job.stdin)
            output = {
                "target": request["target"],
                "vulnerable": True,
                "observation": "unauthorized tool call observed",
            }
        else:
            assert job.command == ["openai-chat-completion"]
            assert secrets and secrets[0].value == "role-provider-secret"
            request = json.loads(job.stdin)
            provider_request = request["request"]
            schema_name = provider_request["response_format"]["json_schema"]["name"]
            context = json.loads(provider_request["messages"][-1]["content"])
            if schema_name == "pajin_planner_output":
                campaign = context["campaign"]
                target = campaign["spec"]["targets"][0]["endpoint"]
                content = {
                    "summary": "Probe the declared mock target.",
                    "steps": [
                        {
                            "title": "Probe unauthorized tool use",
                            "rationale": "Use only the registered probe.",
                            "tool_id": "mock.agent-probe",
                            "target": target,
                            "method": "POST",
                            "arguments_json": json.dumps(
                                {"simulation": {"unauthorizedToolCall": True}}
                            ),
                            "scenario_id": "kisa.agent.indirect-tool-hijacking",
                            "threat_classes": ["A02"],
                            "attack_surface": "agent-tools",
                            "persona": "malicious-user",
                        }
                    ],
                }
            elif schema_name == "pajin_validator_output":
                result = context["results"][0]
                content = {
                    "findings": [
                        {
                            "title": "Provider validator confirmed unauthorized tool use",
                            "severity": "high",
                            "threat_class": "A02",
                            "target": result["data"]["target"],
                            "summary": "The same-run result reports unauthorized execution.",
                            "reproduction": ["Run the cited specialist probe."],
                            "evidence": result["evidence"],
                            "confidence": 1.0,
                            "validated": True,
                        }
                    ]
                }
            else:
                assert schema_name == "pajin_reporter_output"
                content = {
                    "summary": "One finding was validated.",
                    "risk_overview": "Unauthorized tool execution is high risk.",
                    "recommendations": ["Require independent tool authorization."],
                    "limitations": ["This is a deterministic provider fixture."],
                }
            output = {
                "provider_id": "role-provider",
                "response_id": f"response-{schema_name}",
                "model": "role-model",
                "content": json.dumps(content),
                "refusal": None,
                "finish_reason": "stop",
                "tool_calls": [],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2, "total_tokens": 5},
                "streamed": False,
                "chunks": 1,
                "target": request["target"],
            }
        return WorkerResult(
            execution_id=job.execution_id,
            backend="role-worker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(output),
            started_at=now,
            finished_at=now,
        )


def test_provider_roles_use_gateway_capabilities_budgets_and_same_run_evidence(
    tmp_path: Path,
) -> None:
    campaign = load_manifest(Path("examples/multi-agent.yaml"))
    budgets = campaign.spec.budgets.model_copy(
        update={"max_tool_calls": 7, "max_model_calls": 6, "max_model_tokens": 100}
    )
    campaign = campaign.model_copy(
        update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
    )
    registration = _registration()
    runtime = ProviderAgentRuntime(
        registration,
        tools=[
            ModelToolDescriptor(
                tool_id="mock.agent-probe",
                description="Probe a declared mock agent target.",
                allowed_methods=["POST"],
            )
        ],
        fallback_planner=DeterministicAgentRuntime(),
        fallback_validator=DeterministicAgentRuntime(),
    )
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(OpenAICompatibleChatTool(registration))
    secrets = SecretBroker()
    secrets.register(registration.secret_ref, "role-provider-secret")
    runner = MultiAgentCampaignRunner(
        planner=runtime,
        validator=runtime,
        reporter=runtime,
        tools=registry,
        policy=PolicyEngine(),
        worker=RoleWorker(),
        output_root=tmp_path,
        secrets=secrets,
    )

    outcome = asyncio.run(runner.run(campaign))

    assert outcome.status.value == "completed"
    assert len(outcome.findings) == 1
    assert outcome.findings[0].evidence == outcome.tool_results[0].evidence
    assert (outcome.run_path / "model-narrative.json").is_file()
    budget = json.loads((outcome.run_path / "budget.json").read_text(encoding="utf-8"))
    assert budget["toolCalls"] == 4
    assert budget["modelCalls"] == 3
    assert budget["modelTokens"] == 15
    events = (outcome.run_path / "events.jsonl").read_text(encoding="utf-8")
    assert events.count('"event_type":"model.call.completed"') == 3
    assert '"event_type":"model.fallback.activated"' not in events
    assert '"event_type":"specialist.call-budget.allocated"' in events
    assert '"reservedControlCalls":4' in events
    assert '"unallocatedCalls":1' in events
    capabilities = json.loads((outcome.run_path / "capabilities.json").read_text(encoding="utf-8"))
    role_grants = [
        item["grant"]
        for item in capabilities
        if any(
            item["grant"]["subject"].startswith(f"agent:{role}:")
            for role in ("planner", "validator", "reporter")
        )
    ]
    assert len(role_grants) == 3
    assert all(grant["tools"] == ["provider.role-provider.chat"] for grant in role_grants)
    specialist_grants = [
        item["grant"]
        for item in capabilities
        if item["grant"]["subject"].startswith("agent:specialist:")
    ]
    assert len(specialist_grants) == 1
    assert specialist_grants[0]["max_calls"] == 1
    provider_evidence = []
    for path in (outcome.run_path / "evidence").glob("*.json"):
        evidence = json.loads(path.read_text(encoding="utf-8"))
        if evidence["request"]["tool_id"] == "provider.role-provider.chat":
            provider_evidence.append(evidence)
    assert len(provider_evidence) == 3
    developer_prompts = {
        evidence["request"]["arguments"]["messages"][0]["content"] for evidence in provider_evidence
    }
    assert any("PAJIN Planner" in prompt for prompt in developer_prompts)
    assert any("PAJIN Validator" in prompt for prompt in developer_prompts)
    assert any("PAJIN Reporter" in prompt for prompt in developer_prompts)
    assert all(
        evidence["request"]["arguments"]["messages"][0]["role"] == "developer"
        and evidence["request"]["arguments"]["messages"][1]["role"] == "user"
        for evidence in provider_evidence
    )
    artifact_text = "\n".join(
        path.read_text(encoding="utf-8") for path in outcome.run_path.rglob("*") if path.is_file()
    )
    assert "role-provider-secret" not in artifact_text


def test_provider_runtime_retries_invalid_schema_then_uses_valid_plan(
    sample_campaign: CampaignManifest,
) -> None:
    registration = _registration()

    class RetryPort:
        def __init__(self) -> None:
            self.calls = 0
            self.messages: list[list[object]] = []

        async def complete(self, **kwargs: object) -> object:
            self.calls += 1
            self.messages.append(list(kwargs["messages"]))  # type: ignore[arg-type]
            content = "{}"
            if self.calls == 2:
                content = json.dumps(
                    {
                        "summary": "Use the declared tool.",
                        "steps": [
                            {
                                "title": "Probe",
                                "rationale": "Bounded probe",
                                "tool_id": "mock.agent-probe",
                                "target": sample_campaign.spec.targets[0].endpoint,
                                "method": "POST",
                                "arguments_json": "{}",
                                "scenario_id": "",
                                "threat_classes": [],
                                "attack_surface": "agent-tools",
                                "persona": "tester",
                            }
                        ],
                    }
                )
            return {
                "provider_id": "role-provider",
                "response_id": f"response-{self.calls}",
                "model": "role-model",
                "content": content,
                "tool_calls": [],
                "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                "streamed": False,
                "chunks": 1,
                "target": str(registration.endpoint),
            }

        def record_fallback(self, *, role: str, reason: str) -> None:
            raise AssertionError(f"unexpected fallback for {role}: {reason}")

    port = RetryPort()
    runtime = ProviderAgentRuntime(
        registration,
        tools=[
            ModelToolDescriptor(
                tool_id="mock.agent-probe",
                description="Probe target",
                allowed_methods=["POST"],
            )
        ],
        fallback_planner=DeterministicAgentRuntime(),
        fallback_validator=DeterministicAgentRuntime(),
    )
    runtime.bind_model_port(port)

    plan = asyncio.run(runtime.plan(sample_campaign))

    assert port.calls == 2
    assert plan.steps[0].request.tool_id == "mock.agent-probe"
    second_developer = port.messages[1][0]
    assert isinstance(second_developer, ProviderMessage)
    assert second_developer.role == "developer"
    assert "prior response was invalid" in second_developer.content


def test_provider_runtime_uses_fallback_only_after_bounded_model_failures(
    sample_campaign: CampaignManifest,
) -> None:
    registration = _registration()

    class FailedPort:
        def __init__(self) -> None:
            self.calls = 0
            self.fallbacks: list[str] = []

        async def complete(self, **kwargs: object) -> object:
            del kwargs
            self.calls += 1
            raise ModelCallFailure("temporary provider failure")

        def record_fallback(self, *, role: str, reason: str) -> None:
            self.fallbacks.append(f"{role}:{reason}")

    port = FailedPort()
    runtime = ProviderAgentRuntime(
        registration,
        tools=[
            ModelToolDescriptor(
                tool_id="mock.agent-probe",
                description="Probe target",
                allowed_methods=["POST"],
            )
        ],
        fallback_planner=DeterministicAgentRuntime(),
        fallback_validator=DeterministicAgentRuntime(),
    )
    runtime.bind_model_port(port)

    plan = asyncio.run(runtime.plan(sample_campaign))

    assert port.calls == 2
    assert plan.steps[0].request.tool_id == "mock.agent-probe"
    assert len(port.fallbacks) == 1
    assert port.fallbacks[0].startswith("planner:ModelCallFailure")


def test_provider_runtime_does_not_fallback_around_budget_exhaustion(
    sample_campaign: CampaignManifest,
) -> None:
    registration = _registration()

    class ExhaustedPort:
        async def complete(self, **kwargs: object) -> object:
            del kwargs
            raise BudgetExceeded("maximum model-token budget exceeded")

        def record_fallback(self, *, role: str, reason: str) -> None:
            raise AssertionError(f"budget failure must not activate fallback: {role}: {reason}")

    runtime = ProviderAgentRuntime(
        registration,
        tools=[
            ModelToolDescriptor(
                tool_id="mock.agent-probe",
                description="Probe target",
                allowed_methods=["POST"],
            )
        ],
        fallback_planner=DeterministicAgentRuntime(),
        fallback_validator=DeterministicAgentRuntime(),
    )
    runtime.bind_model_port(ExhaustedPort())

    with pytest.raises(BudgetExceeded, match="model-token"):
        asyncio.run(runtime.plan(sample_campaign))
