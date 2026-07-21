import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from pajin.agents.deterministic import DeterministicAgentRuntime
from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    AgentPlan,
    CampaignManifest,
    PlannedStep,
    ToolRequest,
    ToolResult,
)
from pajin.modes.ai_redteam.catalog import KISA_CATALOG
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.worker import WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.ai import AIChatProbeInput, ProbeCheckKind
from pajin.tools.base import ToolRegistry
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.multi_agent import MultiAgentCampaignRunner


def _result(
    request: ToolRequest,
    data: dict[str, object],
    *,
    request_id: str | None = None,
    tool_id: str | None = None,
) -> ToolResult:
    now = datetime.now(UTC)
    return ToolResult(
        request_id=request_id or request.request_id,
        tool_id=tool_id or request.tool_id,
        success=True,
        started_at=now,
        finished_at=now,
        data=data,
        evidence=[f"evidence/{request.request_id}.json"],
    )


def _mock_output(target: str, *, vulnerable: bool) -> dict[str, object]:
    return {
        "target": target,
        "vulnerable": vulnerable,
        "observation": (
            "target accepted an untrusted instruction and invoked a protected tool"
            if vulnerable
            else "target rejected the untrusted instruction"
        ),
        "networkPerformed": False,
    }


def _ai_validation_fixture() -> tuple[CampaignManifest, AgentPlan, ToolResult]:
    campaign = load_manifest(Path("examples/kisa-ai-chat-lab.yaml"))
    scenario = next(
        item
        for item in KISA_CATALOG.scenarios
        if item.scenario_id == "kisa.model.system-prompt-disclosure"
    )
    assert scenario.probe is not None
    probe = AIChatProbeInput(
        scenario_id=scenario.scenario_id,
        threat_class="M03",
        session_id="pajin:validator:binding:1",
        turns=scenario.probe.turns,
        checks=scenario.probe.checks,
    )
    request = ToolRequest(
        agent_id="agent:specialist:test",
        tool_id="ai.chat-probe",
        target=campaign.spec.targets[0].endpoint,
        method="POST",
        arguments=probe.model_dump(mode="json"),
    )
    plan = AgentPlan(
        summary="Validate one planned AI probe",
        steps=[
            PlannedStep(
                title="AI probe",
                rationale="Exercise the independent semantic validator.",
                request=request,
                scenario_id=scenario.scenario_id,
                threat_classes=scenario.threat_classes,
            )
        ],
    )
    turns: list[dict[str, object]] = []
    for index, turn in enumerate(probe.turns):
        included = [
            check.value
            for check in probe.checks
            if check.turn == index and check.kind is ProbeCheckKind.RESPONSE_CONTAINS
        ]
        turns.append(
            {
                "index": index,
                "name": turn.name,
                "request": {
                    "sessionId": probe.session_id,
                    "messages": [message.model_dump(mode="json") for message in turn.messages],
                    "metadata": {"scenarioId": probe.scenario_id, "turn": index},
                },
                "response": {
                    "sessionId": probe.session_id,
                    "message": {
                        "role": "assistant",
                        "content": " ".join(included) or "normal response",
                    },
                    "toolCalls": [],
                    "safety": {"blocked": False, "reason": None},
                    "memoryWrites": [],
                },
            }
        )
    data: dict[str, object] = {
        "target": request.target,
        "scenarioId": probe.scenario_id,
        "threatClass": probe.threat_class,
        "sessionId": probe.session_id,
        "purpose": "attack",
        "vulnerable": True,
        "observation": "all scenario compromise indicators were observed",
        "turns": turns,
        "checks": [
            {
                "checkId": check.check_id,
                "kind": check.kind.value,
                "turn": check.turn,
                "matched": True,
                "sensitive": check.sensitive,
            }
            for check in probe.checks
        ],
        "sensitiveExposureCount": sum(check.sensitive for check in probe.checks),
        "meanResponseLatencySeconds": 0.01,
        "networkPerformed": True,
    }
    return campaign, plan, _result(request, data)


class ForgedMockVerdictWorker:
    def stable_execution_context(self) -> dict[str, object]:
        return {"implementationVersion": "test.forged-mock-verdict/v1"}

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del secrets
        payload = json.loads(job.stdin)
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="forged-mock-verdict",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(_mock_output(payload["target"], vulnerable=True)),
            started_at=now,
            finished_at=now,
        )


@pytest.mark.asyncio
async def test_deterministic_runtime_plans_every_declared_target(
    sample_campaign: CampaignManifest,
) -> None:
    first = sample_campaign.spec.targets[0]
    targets = [
        first,
        first.model_copy(
            update={
                "type": "http",
                "id": "second-http-target",
                "endpoint": "https://second.example.invalid/health",
                "simulation": {},
            }
        ),
    ]
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"targets": targets})}
    )

    plan = await DeterministicAgentRuntime().plan(campaign)

    assert [step.request.tool_id for step in plan.steps] == ["mock.agent-probe", "http.get"]
    assert [step.request.target for step in plan.steps] == [
        first.endpoint,
        "https://second.example.invalid/health",
    ]
    assert len({step.request.request_id for step in plan.steps}) == 2


@pytest.mark.asyncio
async def test_deterministic_runtime_rejects_unsupported_target_instead_of_mock_success(
    sample_campaign: CampaignManifest,
) -> None:
    target = sample_campaign.spec.targets[0].model_copy(update={"type": "typo-target"})
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"targets": [target]})}
    )

    with pytest.raises(ValueError, match="unsupported deterministic target type: typo-target"):
        await DeterministicAgentRuntime().plan(campaign)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "foreign-request",
        "wrong-result-tool",
        "wrong-output-target",
        "undeclared-plan-target",
        "forged-verdict",
        "malformed-output",
        "duplicate-result",
        "duplicate-plan-request",
    ],
)
async def test_mock_validator_rejects_unbound_or_forged_results(
    sample_campaign: CampaignManifest,
    mutation: str,
) -> None:
    campaign = sample_campaign
    if mutation == "forged-verdict":
        target = campaign.spec.targets[0].model_copy(
            update={"simulation": {"unauthorizedToolCall": False}}
        )
        campaign = campaign.model_copy(
            update={"spec": campaign.spec.model_copy(update={"targets": [target]})}
        )
    plan = await DeterministicAgentRuntime().plan(campaign)
    request = plan.steps[0].request
    result_request_id = request.request_id
    result_tool_id = request.tool_id
    output_target = request.target
    data = _mock_output(output_target, vulnerable=True)

    if mutation == "foreign-request":
        result_request_id = "tool_foreign_result"
    elif mutation == "wrong-result-tool":
        result_tool_id = "mock.other-probe"
    elif mutation == "wrong-output-target":
        data["target"] = "https://outside.example.invalid/chat"
    elif mutation == "undeclared-plan-target":
        undeclared = "https://outside.example.invalid/chat"
        request = request.model_copy(update={"target": undeclared})
        plan = plan.model_copy(
            update={"steps": [plan.steps[0].model_copy(update={"request": request})]}
        )
        output_target = undeclared
        data = _mock_output(output_target, vulnerable=True)
    elif mutation == "malformed-output":
        data = {"target": output_target, "vulnerable": True}
    elif mutation == "duplicate-plan-request":
        plan = plan.model_copy(
            update={"steps": [plan.steps[0], plan.steps[0].model_copy(deep=True)]}
        )

    candidate = _result(
        request,
        data,
        request_id=result_request_id,
        tool_id=result_tool_id,
    )
    results = (
        [candidate, candidate.model_copy(deep=True)]
        if mutation == "duplicate-result"
        else [candidate]
    )

    findings = await DeterministicAgentRuntime().validate(campaign, plan, results)

    assert findings == []


@pytest.mark.asyncio
async def test_mock_validator_accepts_exact_authorized_synthetic_verdict(
    sample_campaign: CampaignManifest,
) -> None:
    plan = await DeterministicAgentRuntime().plan(sample_campaign)
    request = plan.steps[0].request

    findings = await DeterministicAgentRuntime().validate(
        sample_campaign,
        plan,
        [_result(request, _mock_output(request.target, vulnerable=True))],
    )

    assert len(findings) == 1
    assert findings[0].threat_class == "A02"
    assert findings[0].target == request.target


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "mutation",
    [
        "wrong-result-tool",
        "wrong-step-tool",
        "wrong-output-target",
        "undeclared-plan-target",
    ],
)
async def test_ai_validator_rejects_unbound_tool_or_target(mutation: str) -> None:
    campaign, plan, result = _ai_validation_fixture()
    request = plan.steps[0].request
    if mutation == "wrong-result-tool":
        result = result.model_copy(update={"tool_id": "mock.agent-probe"})
    elif mutation == "wrong-step-tool":
        mismatched_request = request.model_copy(update={"tool_id": "mock.agent-probe"})
        plan = plan.model_copy(
            update={"steps": [plan.steps[0].model_copy(update={"request": mismatched_request})]}
        )
    elif mutation == "wrong-output-target":
        result = result.model_copy(
            update={
                "data": {
                    **result.data,
                    "target": "https://outside.example.invalid/v1/chat",
                }
            }
        )
    elif mutation == "undeclared-plan-target":
        undeclared = "https://outside.example.invalid/v1/chat"
        mismatched_request = request.model_copy(update={"target": undeclared})
        plan = plan.model_copy(
            update={"steps": [plan.steps[0].model_copy(update={"request": mismatched_request})]}
        )
        result = result.model_copy(update={"data": {**result.data, "target": undeclared}})

    findings = await DeterministicAgentRuntime().validate(campaign, plan, [result])

    assert findings == []


@pytest.mark.asyncio
async def test_ai_validator_accepts_semantic_transcript_for_exact_planned_target() -> None:
    campaign, plan, result = _ai_validation_fixture()

    findings = await DeterministicAgentRuntime().validate(campaign, plan, [result])

    assert len(findings) == 1
    assert findings[0].threat_class == "M03"
    assert findings[0].target == plan.steps[0].request.target


@pytest.mark.asyncio
async def test_real_runner_does_not_admit_worker_forged_mock_verdict(
    tmp_path: Path,
) -> None:
    base_campaign = load_manifest(Path("examples/multi-agent.yaml"))
    target = base_campaign.spec.targets[0].model_copy(
        update={"simulation": {"unauthorizedToolCall": False}}
    )
    campaign = base_campaign.model_copy(
        update={"spec": base_campaign.spec.model_copy(update={"targets": [target]})}
    )
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    runner = MultiAgentCampaignRunner(
        planner=DeterministicAgentRuntime(),
        validator=DeterministicAgentRuntime(),
        tools=registry,
        policy=PolicyEngine(),
        worker=ForgedMockVerdictWorker(),
        output_root=tmp_path,
    )

    outcome = await runner.run(campaign)

    assert outcome.validation.candidates == []
    assert outcome.findings == []
