from __future__ import annotations

import asyncio
from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

import pajin.workflow.engine_planner_parity as planner_parity
from pajin.domain.models import AgentPlan, CampaignManifest
from pajin.modes.bug_bounty import (
    BugBountyScopeApproval,
    BugBountyScopeService,
    load_bug_bounty_program,
)
from pajin.modes.ctf import CTFChallengeService, load_ctf_challenge
from pajin.workflow.engine_planner_parity import (
    CommonEngineAIPlannerThresholds,
    CommonEnginePlannerParityAuthority,
    CommonEnginePlannerParityError,
    CommonEnginePlannerPath,
    measure_common_engine_planner_parity,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile


def _bug_bounty_campaign() -> CampaignManifest:
    program = load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))
    service = BugBountyScopeService()
    scope_digest = service.review(program).scope_digest
    return service.compile_campaign(
        program,
        BugBountyScopeApproval(
            scope_digest=scope_digest,
            approved_by="planner-parity-fixture",
            approved_at=datetime(2026, 8, 2, tzinfo=UTC),
            expires_at=datetime(2099, 8, 2, tzinfo=UTC),
            evidence="local-fixture-authorization",
        ),
    )


def _ctf_campaign() -> CampaignManifest:
    challenge = load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))
    return CTFChallengeService().compile_campaign(challenge)


def _campaigns(sample_campaign: CampaignManifest) -> tuple[CampaignManifest, ...]:
    return sample_campaign, _bug_bounty_campaign(), _ctf_campaign()


def test_all_legacy_modes_measure_exact_planner_parity_without_execution(
    sample_campaign: CampaignManifest,
) -> None:
    for campaign in _campaigns(sample_campaign):
        authority = asyncio.run(
            measure_common_engine_planner_parity(
                compile_legacy_campaign_profile(campaign)
            )
        )

        assert authority.legacy_plan.normalized_plan == authority.adapter_plan.normalized_plan
        assert (
            authority.legacy_plan.semantic_plan_digest
            == authority.adapter_plan.semantic_plan_digest
        )
        assert authority.measured_dimensions == ("scope", "tool-request")
        assert authority.unmeasured_dimensions == ("capability", "outcome")
        assert authority.planner_behavior_measured is True
        assert authority.planner_parity_proven is True
        assert authority.fixture_parity_proven is False
        assert authority.capability_parity_proven is False
        assert authority.outcome_parity_proven is False
        assert authority.mission_envelope_compiled is False
        assert authority.common_engine_runtime_constructed is False
        assert authority.worker_invoked is False
        assert authority.common_execution_authorized is False
        steps = authority.legacy_plan.normalized_plan["steps"]
        assert [step["step_id"] for step in steps] == [
            f"fixture-step-{index}" for index in range(len(steps))
        ]
        assert [step["request"]["request_id"] for step in steps] == [
            f"fixture-request-{index}" for index in range(len(steps))
        ]
        assert CommonEnginePlannerParityAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        ) == authority


def test_fresh_planner_ids_normalize_to_deterministic_authority(
    sample_campaign: CampaignManifest,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)

    first = asyncio.run(measure_common_engine_planner_parity(compilation))
    second = asyncio.run(measure_common_engine_planner_parity(compilation))

    assert first == second
    assert first.authority_id == f"common-engine-planner-parity:{first.authority_digest}"


def test_ai_constructor_thresholds_are_bound_and_change_plan_semantics(
    sample_campaign: CampaignManifest,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)
    once = asyncio.run(
        measure_common_engine_planner_parity(
            compilation,
            ai_thresholds=CommonEngineAIPlannerThresholds(repetitions=1),
        )
    )
    twice = asyncio.run(
        measure_common_engine_planner_parity(
            compilation,
            ai_thresholds=CommonEngineAIPlannerThresholds(repetitions=2),
        )
    )

    assert once.legacy_constructor.ai_thresholds is not None
    assert once.legacy_constructor.ai_thresholds.repetitions == 1
    assert once.legacy_constructor.constructor_digest != (
        twice.legacy_constructor.constructor_digest
    )
    assert once.legacy_plan.semantic_plan_digest != twice.legacy_plan.semantic_plan_digest


def test_non_ai_planner_rejects_ai_thresholds() -> None:
    compilation = compile_legacy_campaign_profile(_bug_bounty_campaign())

    with pytest.raises(CommonEnginePlannerParityError, match="cannot be supplied"):
        asyncio.run(
            measure_common_engine_planner_parity(
                compilation,
                ai_thresholds=CommonEngineAIPlannerThresholds(repetitions=1),
            )
        )


def test_behavioral_drift_fails_before_authority_creation(
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_construct = planner_parity._construct_planner

    class DriftPlanner:
        def __init__(self, delegate: object) -> None:
            self._delegate = delegate

        async def plan(self, campaign: CampaignManifest) -> AgentPlan:
            plan = await self._delegate.plan(campaign)  # type: ignore[attr-defined]
            return plan.model_copy(update={"summary": plan.summary + " drift"}, deep=True)

    def construct(binding: object) -> object:
        runtime = original_construct(binding)  # type: ignore[arg-type]
        if binding.path is CommonEnginePlannerPath.PROFILE_ADAPTER:  # type: ignore[attr-defined]
            return DriftPlanner(runtime)
        return runtime

    monkeypatch.setattr(planner_parity, "_construct_planner", construct)

    with pytest.raises(CommonEnginePlannerParityError, match="outputs differ"):
        asyncio.run(
            measure_common_engine_planner_parity(
                compile_legacy_campaign_profile(sample_campaign)
            )
        )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("authorityDigest",), "0" * 64),
        (("adapterSelectionDigest",), "1" * 64),
        (("sourceCampaignDigest",), "2" * 64),
        (("legacyPlan", "normalizedPlan", "summary"), "forged plan"),
        (("adapterPlan", "semanticPlanDigest"), "3" * 64),
        (("measuredDimensions",), ["tool-request", "scope"]),
        (("unmeasuredDimensions",), ["outcome", "capability"]),
        (("fixtureParityProven",), True),
        (("capabilityParityProven",), True),
        (("outcomeParityProven",), True),
        (("missionEnvelopeCompiled",), True),
        (("commonEngineRuntimeConstructed",), True),
        (("workerInvoked",), True),
        (("commonExecutionAuthorized",), True),
    ],
)
def test_planner_parity_rejects_drift_or_authority_escalation(
    sample_campaign: CampaignManifest,
    path: tuple[str, ...],
    replacement: object,
) -> None:
    authority = asyncio.run(
        measure_common_engine_planner_parity(
            compile_legacy_campaign_profile(sample_campaign),
            ai_thresholds=CommonEngineAIPlannerThresholds(repetitions=1),
        )
    )
    payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        CommonEnginePlannerParityAuthority.model_validate(payload)
