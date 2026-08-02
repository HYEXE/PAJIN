from __future__ import annotations

import asyncio
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ai_chat_mode import ContractAIWorker
from test_ai_chat_mode import _campaign as ai_campaign
from test_bug_bounty_runtime import (
    ContractBugBountyWorker,
)
from test_bug_bounty_runtime import (
    _campaign as bug_bounty_campaign,
)
from test_bug_bounty_runtime import (
    _trusted_docker_backend as bug_bounty_backend,
)
from test_ctf_runtime import (
    ContractCTFWorker,
    _challenge,
)
from test_ctf_runtime import (
    _trusted_docker_backend as ctf_backend,
)
from test_kisa_replay import _trusted_docker_backend as ai_backend

from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.modes.ctf import CTFChallengeService
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import WorkerBackend
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import Tool, ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFWebBackupProbeTool
from pajin.tools.mock import MockAgentProbe
from pajin.workflow.engine_planner_parity import measure_common_engine_planner_parity
from pajin.workflow.engine_runtime_parity import (
    CommonEngineDualRuntimeExecutionAuthority,
    CommonEngineRuntimeComponents,
    CommonEngineRuntimeParityError,
    execute_common_engine_dual_runtime_fixture,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile


def _ctf_campaign() -> CampaignManifest:
    return CTFChallengeService().compile_campaign(_challenge())


def _registry(tool: Tool, *extra: Tool) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(tool)
    for item in extra:
        registry.register(item)
    return registry


@pytest.mark.parametrize(
    ("mode", "campaign_factory", "tool_factory", "worker_factory"),
    [
        (
            CampaignMode.AI_REDTEAM,
            ai_campaign,
            AIChatProbeTool,
            lambda: ai_backend(ContractAIWorker()),
        ),
        (
            CampaignMode.BUG_BOUNTY,
            bug_bounty_campaign,
            BooleanSQLiProbeTool,
            lambda: bug_bounty_backend(ContractBugBountyWorker()),
        ),
        (
            CampaignMode.CTF,
            _ctf_campaign,
            CTFWebBackupProbeTool,
            lambda: ctf_backend(ContractCTFWorker()),
        ),
    ],
)
def test_all_legacy_modes_execute_two_fresh_same_coordinate_runs(
    tmp_path: Path,
    mode: CampaignMode,
    campaign_factory: Callable[[], CampaignManifest],
    tool_factory: Callable[[], Tool],
    worker_factory: Callable[[], WorkerBackend],
) -> None:
    campaign = campaign_factory()
    planner_parity = asyncio.run(
        measure_common_engine_planner_parity(compile_legacy_campaign_profile(campaign))
    )
    legacy = CommonEngineRuntimeComponents(
        tools=_registry(tool_factory()),
        policy=PolicyEngine(),
        worker=worker_factory(),
        output_root=tmp_path / "legacy",
    )
    adapter = CommonEngineRuntimeComponents(
        tools=_registry(tool_factory()),
        policy=PolicyEngine(),
        worker=worker_factory(),
        output_root=tmp_path / "adapter",
    )

    result = asyncio.run(
        execute_common_engine_dual_runtime_fixture(
            planner_parity,
            legacy=legacy,
            adapter=adapter,
        )
    )
    authority = result.authority

    assert authority.legacy_execution.run_id != authority.adapter_execution.run_id
    assert authority.legacy_execution.tool_request_ids != (
        authority.adapter_execution.tool_request_ids
    )
    assert authority.legacy_execution.evidence_paths != (authority.adapter_execution.evidence_paths)
    assert authority.legacy_execution.coordinate.source_mode is mode
    assert authority.legacy_execution.coordinate.semantic_coordinate_digest == (
        authority.adapter_execution.coordinate.semantic_coordinate_digest
    )
    assert authority.legacy_execution.coordinate.coordinate_digest != (
        authority.adapter_execution.coordinate.coordinate_digest
    )
    assert authority.legacy_execution.sealed_root_digest
    assert authority.adapter_execution.sealed_root_digest
    assert authority.parity_evaluated is False
    assert authority.fixture_parity_proven is False
    assert authority.mission_envelope_compiled is False
    assert authority.common_execution_authorized is False
    assert (
        CommonEngineDualRuntimeExecutionAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        == authority
    )


def test_runtime_coordinate_drift_fails_before_worker_invocation(tmp_path: Path) -> None:
    campaign = _ctf_campaign()
    planner_parity = asyncio.run(
        measure_common_engine_planner_parity(compile_legacy_campaign_profile(campaign))
    )
    legacy_worker = ContractCTFWorker()
    adapter_worker = ContractCTFWorker()

    with pytest.raises(
        CommonEngineRuntimeParityError,
        match="Tool Registry must exactly match",
    ):
        asyncio.run(
            execute_common_engine_dual_runtime_fixture(
                planner_parity,
                legacy=CommonEngineRuntimeComponents(
                    tools=_registry(CTFWebBackupProbeTool()),
                    policy=PolicyEngine(),
                    worker=ctf_backend(legacy_worker),
                    output_root=tmp_path / "legacy",
                ),
                adapter=CommonEngineRuntimeComponents(
                    tools=_registry(CTFWebBackupProbeTool(), MockAgentProbe()),
                    policy=PolicyEngine(),
                    worker=ctf_backend(adapter_worker),
                    output_root=tmp_path / "adapter",
                ),
            )
        )

    assert legacy_worker.jobs == []
    assert adapter_worker.jobs == []


def test_overlapping_output_roots_fail_before_worker_invocation(tmp_path: Path) -> None:
    campaign = _ctf_campaign()
    planner_parity = asyncio.run(
        measure_common_engine_planner_parity(compile_legacy_campaign_profile(campaign))
    )
    legacy_worker = ContractCTFWorker()
    adapter_worker = ContractCTFWorker()

    with pytest.raises(CommonEngineRuntimeParityError, match="output roots must be disjoint"):
        asyncio.run(
            execute_common_engine_dual_runtime_fixture(
                planner_parity,
                legacy=CommonEngineRuntimeComponents(
                    tools=_registry(CTFWebBackupProbeTool()),
                    policy=PolicyEngine(),
                    worker=ctf_backend(legacy_worker),
                    output_root=tmp_path,
                ),
                adapter=CommonEngineRuntimeComponents(
                    tools=_registry(CTFWebBackupProbeTool()),
                    policy=PolicyEngine(),
                    worker=ctf_backend(adapter_worker),
                    output_root=tmp_path / "adapter",
                ),
            )
        )

    assert legacy_worker.jobs == []
    assert adapter_worker.jobs == []


def test_dual_runtime_authority_rejects_evidence_or_eligibility_forgery(
    tmp_path: Path,
) -> None:
    campaign = _ctf_campaign()
    planner_parity = asyncio.run(
        measure_common_engine_planner_parity(compile_legacy_campaign_profile(campaign))
    )
    result = asyncio.run(
        execute_common_engine_dual_runtime_fixture(
            planner_parity,
            legacy=CommonEngineRuntimeComponents(
                tools=_registry(CTFWebBackupProbeTool()),
                policy=PolicyEngine(),
                worker=ctf_backend(ContractCTFWorker()),
                output_root=tmp_path / "legacy",
            ),
            adapter=CommonEngineRuntimeComponents(
                tools=_registry(CTFWebBackupProbeTool()),
                policy=PolicyEngine(),
                worker=ctf_backend(ContractCTFWorker()),
                output_root=tmp_path / "adapter",
            ),
        )
    )

    for field, replacement in (
        ("semanticCoordinateDigest", "0" * 64),
        ("parityEvaluated", True),
        ("fixtureParityProven", True),
        ("missionEnvelopeCompiled", True),
        ("commonExecutionAuthorized", True),
    ):
        payload = deepcopy(result.authority.model_dump(mode="json", by_alias=True))
        payload[field] = replacement
        with pytest.raises(ValidationError):
            CommonEngineDualRuntimeExecutionAuthority.model_validate(payload)

    payload = deepcopy(result.authority.model_dump(mode="json", by_alias=True))
    payload["legacyExecution"]["normalizedPlanDigest"] = "1" * 64
    payload["legacyExecution"]["executionDigest"] = ""
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="dual runtime execution authority differs"):
        CommonEngineDualRuntimeExecutionAuthority.model_validate(payload)

    payload = deepcopy(result.authority.model_dump(mode="json", by_alias=True))
    payload["adapterExecution"]["coordinate"]["toolBindings"][0]["spec"]["unexpected"] = True
    with pytest.raises(ValidationError):
        CommonEngineDualRuntimeExecutionAuthority.model_validate(payload)
