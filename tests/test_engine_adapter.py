from __future__ import annotations

import subprocess
import sys
from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.workflow.engine_adapter import (
    CommonEngineAdapterCatalog,
    CommonEngineAdapterSelectionAuthority,
    CommonEngineParityDimension,
    registered_common_engine_adapter_catalog,
    select_common_engine_adapter,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile

_EXPECTED_PLANNERS = {
    CampaignMode.AI_REDTEAM: "pajin.modes.ai_redteam.runtime.KISAPlannerRuntime",
    CampaignMode.BUG_BOUNTY: "pajin.modes.bug_bounty.runtime.BugBountyPlannerRuntime",
    CampaignMode.CTF: "pajin.modes.ctf.runtime.CTFTriagePlannerRuntime",
}
_EXPECTED_VALIDATORS = {
    CampaignMode.AI_REDTEAM: "pajin.modes.ai_redteam.runtime.KISAValidatorRuntime",
    CampaignMode.BUG_BOUNTY: "pajin.modes.bug_bounty.runtime.BugBountyValidatorRuntime",
    CampaignMode.CTF: "pajin.modes.ctf.runtime.CTFFlagValidatorRuntime",
}


def test_mode_package_can_load_before_workflow_adapter() -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "from pajin.modes.bug_bounty import BugBountyPlannerRuntime; "
                "from pajin.workflow import registered_common_engine_adapter_catalog; "
                "assert registered_common_engine_adapter_catalog().adapters"
            ),
        ],
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mode", tuple(CampaignMode))
def test_mode_compilation_selects_exact_non_executable_implementations(
    sample_campaign: CampaignManifest,
    mode: CampaignMode,
) -> None:
    campaign = sample_campaign.model_copy(
        update={"spec": sample_campaign.spec.model_copy(update={"mode": mode})},
        deep=True,
    )
    compilation = compile_legacy_campaign_profile(campaign)

    selection = select_common_engine_adapter(compilation)

    assert selection.compilation == compilation
    assert selection.source_campaign_digest == compilation.input_digest
    assert selection.adapter.source_mode is mode
    assert selection.adapter.profile_digest == compilation.profile_digest
    assert selection.adapter.planner.implementation_id == _EXPECTED_PLANNERS[mode]
    assert selection.adapter.validator.implementation_id == _EXPECTED_VALIDATORS[mode]
    assert selection.adapter.runner.implementation_id == (
        "pajin.workflow.multi_agent.MultiAgentCampaignRunner"
    )
    assert selection.adapter.scheduler.implementation_id == (
        "pajin.workflow.multi_agent_execution.MultiAgentExecutionScheduler"
    )
    assert selection.adapter.projector.implementation_id == (
        "pajin.workflow.multi_agent_projection.MultiAgentResultProjector"
    )
    assert tuple(item.dimension for item in selection.structural_parity) == tuple(
        CommonEngineParityDimension
    )
    assert all(item.fixture_measured is False for item in selection.structural_parity)
    assert all(item.parity_proven is False for item in selection.structural_parity)
    assert selection.all_required_dimensions_present is True
    assert selection.fixture_parity_proven is False
    assert selection.mission_envelope_compiled is False
    assert selection.runtime_constructed is False
    assert selection.common_execution_authorized is False
    assert selection.adapter.runtime_construction_authorized is False
    assert selection.adapter.tool_registry_bound is False
    assert selection.adapter.policy_bound is False
    assert selection.adapter.worker_bound is False
    assert selection.adapter.output_path_bound is False


def test_ai_adapter_alone_registers_candidate_producer() -> None:
    catalog = registered_common_engine_adapter_catalog()
    by_mode = {adapter.source_mode: adapter for adapter in catalog.adapters}

    assert by_mode[CampaignMode.AI_REDTEAM].candidate_producer is not None
    assert by_mode[CampaignMode.AI_REDTEAM].candidate_producer.implementation_id == (
        "pajin.modes.ai_redteam.candidates.KISACandidateProducer"
    )
    assert by_mode[CampaignMode.BUG_BOUNTY].candidate_producer is None
    assert by_mode[CampaignMode.CTF].candidate_producer is None


def test_adapter_catalog_registers_selection_only_and_no_pentest_path() -> None:
    catalog = registered_common_engine_adapter_catalog()

    assert tuple(adapter.source_mode for adapter in catalog.adapters) == tuple(CampaignMode)
    assert all(adapter.profile.purpose.value != "pentest" for adapter in catalog.adapters)
    assert catalog.adapter_selection_authorized is True
    assert catalog.runtime_construction_authorized is False
    assert catalog.common_execution_authorized is False
    implementations = [
        implementation
        for adapter in catalog.adapters
        for implementation in (
            adapter.planner,
            adapter.validator,
            adapter.candidate_producer,
            adapter.runner,
            adapter.scheduler,
            adapter.projector,
        )
        if implementation is not None
    ]
    assert all(item.construction_authorized is False for item in implementations)
    assert CommonEngineAdapterCatalog.model_validate(
        catalog.model_dump(mode="json", by_alias=True)
    ) == catalog


def test_adapter_selection_is_content_addressed_and_round_trips(
    sample_campaign: CampaignManifest,
) -> None:
    compilation = compile_legacy_campaign_profile(sample_campaign)
    first = select_common_engine_adapter(compilation)
    second = select_common_engine_adapter(compilation)

    assert first == second
    assert first.authority_id == f"common-engine-adapter-selection:{first.authority_digest}"
    assert CommonEngineAdapterSelectionAuthority.model_validate(
        first.model_dump(mode="json", by_alias=True)
    ) == first


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("authorityDigest",), "0" * 64),
        (("compilationDigest",), "1" * 64),
        (("sourceCampaignDigest",), "2" * 64),
        (("adapterCatalogDigest",), "3" * 64),
        (("adapterDigest",), "4" * 64),
        (("adapter", "planner", "implementationId"), "pajin.invalid.Planner"),
        (("adapter", "validator", "implementationDigest"), "5" * 64),
        (("adapter", "runtimeConstructionAuthorized"), True),
        (("structuralParity", 0, "parityDigest"), "6" * 64),
        (("structuralParity", 0, "fixtureMeasured"), True),
        (("structuralParity", 0, "parityProven"), True),
        (("structuralParity",), "reverse"),
        (("allRequiredDimensionsPresent",), False),
        (("fixtureParityProven",), True),
        (("missionEnvelopeCompiled",), True),
        (("runtimeConstructed",), True),
        (("commonExecutionAuthorized",), True),
    ],
)
def test_adapter_selection_rejects_substitution_or_authority_escalation(
    sample_campaign: CampaignManifest,
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    selection = select_common_engine_adapter(
        compile_legacy_campaign_profile(sample_campaign)
    )
    payload = deepcopy(selection.model_dump(mode="json", by_alias=True))
    if replacement == "reverse":
        replacement = list(reversed(payload["structuralParity"]))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        CommonEngineAdapterSelectionAuthority.model_validate(payload)


def test_adapter_catalog_rejects_cross_mode_implementation_substitution() -> None:
    catalog = registered_common_engine_adapter_catalog()
    payload = catalog.model_dump(mode="json", by_alias=True)
    payload["adapters"][0]["planner"] = deepcopy(payload["adapters"][1]["planner"])
    payload["adapters"][0]["adapterId"] = ""
    payload["adapters"][0]["adapterDigest"] = ""
    payload["catalogDigest"] = ""

    with pytest.raises(ValidationError, match="Adapter differs"):
        CommonEngineAdapterCatalog.model_validate(payload)
