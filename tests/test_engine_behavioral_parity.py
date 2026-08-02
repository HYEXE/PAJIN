from __future__ import annotations

import asyncio
from collections.abc import Callable
from copy import deepcopy
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_ai_chat_mode import ContractAIWorker
from test_ai_chat_mode import _campaign as ai_campaign
from test_bug_bounty_runtime import ContractBugBountyWorker, _program
from test_bug_bounty_runtime import _campaign as bug_bounty_campaign
from test_bug_bounty_runtime import _trusted_docker_backend as bug_bounty_backend
from test_ctf_runtime import ContractCTFWorker, _challenge
from test_ctf_runtime import _trusted_docker_backend as ctf_backend
from test_kisa_replay import _trusted_docker_backend as ai_backend

from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.modes.ctf import CTFChallengeService
from pajin.policy.engine import PolicyEngine
from pajin.runtime.worker import WorkerBackend
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import Tool, ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFWebBackupProbeTool
from pajin.workflow import engine_behavioral_parity as behavioral_parity_module
from pajin.workflow.engine_behavioral_parity import (
    CommonEngineBehavioralParityAuthority,
    CommonEngineBehavioralParityError,
    measure_common_engine_behavioral_parity,
)
from pajin.workflow.engine_planner_parity import measure_common_engine_planner_parity
from pajin.workflow.engine_runtime_parity import (
    CommonEngineDualRuntimeResult,
    CommonEngineRuntimeComponents,
    execute_common_engine_dual_runtime_fixture,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile


def _ctf_campaign() -> CampaignManifest:
    return CTFChallengeService().compile_campaign(_challenge())


def _registry(tool: Tool) -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(tool)
    return registry


def test_structured_normalization_does_not_replace_identity_substrings() -> None:
    normalized = behavioral_parity_module._normalize(
        {"workerResult": {"stdout": "semantic-prefix-fresh-id-semantic-suffix"}},
        {"fresh-id": "fixture-id"},
    )

    assert normalized["workerResult"]["stdout"] == (
        "semantic-prefix-fresh-id-semantic-suffix"
    )


def _dual_runtime(
    tmp_path: Path,
    campaign: CampaignManifest,
    tool_factory: Callable[[], Tool],
    legacy_worker: WorkerBackend,
    adapter_worker: WorkerBackend,
) -> CommonEngineDualRuntimeResult:
    planner_parity = asyncio.run(
        measure_common_engine_planner_parity(compile_legacy_campaign_profile(campaign))
    )
    return asyncio.run(
        execute_common_engine_dual_runtime_fixture(
            planner_parity,
            legacy=CommonEngineRuntimeComponents(
                tools=_registry(tool_factory()),
                policy=PolicyEngine(),
                worker=legacy_worker,
                output_root=tmp_path / "legacy",
            ),
            adapter=CommonEngineRuntimeComponents(
                tools=_registry(tool_factory()),
                policy=PolicyEngine(),
                worker=adapter_worker,
                output_root=tmp_path / "adapter",
            ),
        )
    )


@pytest.mark.parametrize(
    ("mode", "campaign_factory", "tool_factory", "worker_factory", "source_factory"),
    [
        (
            CampaignMode.AI_REDTEAM,
            ai_campaign,
            AIChatProbeTool,
            lambda: ai_backend(ContractAIWorker()),
            lambda: None,
        ),
        (
            CampaignMode.BUG_BOUNTY,
            bug_bounty_campaign,
            BooleanSQLiProbeTool,
            lambda: bug_bounty_backend(ContractBugBountyWorker()),
            _program,
        ),
        (
            CampaignMode.CTF,
            _ctf_campaign,
            CTFWebBackupProbeTool,
            lambda: ctf_backend(ContractCTFWorker()),
            _challenge,
        ),
    ],
)
def test_all_legacy_modes_admit_exact_sealed_behavioral_parity(
    tmp_path: Path,
    mode: CampaignMode,
    campaign_factory: Callable[[], CampaignManifest],
    tool_factory: Callable[[], Tool],
    worker_factory: Callable[[], WorkerBackend],
    source_factory: Callable[[], object | None],
) -> None:
    dual = _dual_runtime(
        tmp_path,
        campaign_factory(),
        tool_factory,
        worker_factory(),
        worker_factory(),
    )

    result = measure_common_engine_behavioral_parity(
        dual,
        mode_source=source_factory(),
    )
    authority = result.authority

    assert authority.legacy_observation.source_mode is mode
    assert authority.measured_dimensions == (
        "scope",
        "capability",
        "tool-request",
        "outcome",
    )
    assert authority.proven_dimensions == authority.measured_dimensions
    assert authority.receipt_parity_proven is True
    assert authority.mode_postprocessing_parity_proven is True
    assert authority.fixture_parity_proven is True
    assert authority.profile_adapter_parity_admitted is True
    assert authority.mission_envelope_compiled is False
    assert authority.common_execution_authorized is False
    assert authority.legacy_observation.semantic_behavior_digest == (
        authority.adapter_observation.semantic_behavior_digest
    )
    assert authority.legacy_observation.source_run_id != (
        authority.adapter_observation.source_run_id
    )
    assert authority.legacy_observation.final_root_digest != (
        authority.adapter_observation.final_root_digest
    )
    assert (
        CommonEngineBehavioralParityAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        == authority
    )


def test_different_worker_receipt_and_mode_outcome_fail_parity(tmp_path: Path) -> None:
    dual = _dual_runtime(
        tmp_path,
        _ctf_campaign(),
        CTFWebBackupProbeTool,
        ctf_backend(ContractCTFWorker()),
        ctf_backend(ContractCTFWorker("PAJIN{different_behavior}")),
    )

    with pytest.raises(
        CommonEngineBehavioralParityError,
        match="sealed behavior differs",
    ):
        measure_common_engine_behavioral_parity(dual, mode_source=_challenge())


def test_mutated_or_cross_mode_source_fails_before_parity_admission(
    tmp_path: Path,
) -> None:
    mutated = _dual_runtime(
        tmp_path / "mutated",
        _ctf_campaign(),
        CTFWebBackupProbeTool,
        ctf_backend(ContractCTFWorker()),
        ctf_backend(ContractCTFWorker()),
    )
    evidence_path = (
        mutated.adapter_outcome.run_path / mutated.authority.adapter_execution.evidence_paths[0]
    )
    evidence_path.write_bytes(evidence_path.read_bytes() + b"\n")

    with pytest.raises(
        CommonEngineBehavioralParityError,
        match="integrity verification failed",
    ):
        measure_common_engine_behavioral_parity(mutated, mode_source=_challenge())

    cross_mode = _dual_runtime(
        tmp_path / "cross-mode",
        _ctf_campaign(),
        CTFWebBackupProbeTool,
        ctf_backend(ContractCTFWorker()),
        ctf_backend(ContractCTFWorker()),
    )
    with pytest.raises(
        CommonEngineBehavioralParityError,
        match="exact Challenge manifest",
    ):
        measure_common_engine_behavioral_parity(cross_mode, mode_source=_program())


def test_behavioral_parity_authority_rejects_eligibility_or_payload_forgery(
    tmp_path: Path,
) -> None:
    dual = _dual_runtime(
        tmp_path,
        _ctf_campaign(),
        CTFWebBackupProbeTool,
        ctf_backend(ContractCTFWorker()),
        ctf_backend(ContractCTFWorker()),
    )
    authority = measure_common_engine_behavioral_parity(
        dual,
        mode_source=_challenge(),
    ).authority

    for field, replacement in (
        ("measuredDimensions", ["scope", "tool-request", "capability", "outcome"]),
        ("missionEnvelopeCompiled", True),
        ("commonExecutionAuthorized", True),
    ):
        payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
        payload[field] = replacement
        with pytest.raises(ValidationError):
            CommonEngineBehavioralParityAuthority.model_validate(payload)

    payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
    payload["adapterObservation"]["normalizedReceipt"]["evidence"][0]["policyDecision"][
        "allowed"
    ] = False
    payload["adapterObservation"]["receiptDigest"] = ""
    payload["adapterObservation"]["semanticBehaviorDigest"] = ""
    payload["adapterObservation"]["observationDigest"] = ""
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="behavioral parity evidence differs"):
        CommonEngineBehavioralParityAuthority.model_validate(payload)

    payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
    payload["legacyObservation"]["normalizedReceipt"]["evidence"][0].pop(
        "workerResult"
    )
    payload["legacyObservation"]["receiptDigest"] = ""
    payload["legacyObservation"]["semanticBehaviorDigest"] = ""
    payload["legacyObservation"]["observationDigest"] = ""
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="receipt evidence is incomplete"):
        CommonEngineBehavioralParityAuthority.model_validate(payload)

    payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
    payload["legacyObservation"]["normalizedModeProcessing"].pop("artifactInventory")
    payload["legacyObservation"]["modeProcessingDigest"] = ""
    payload["legacyObservation"]["semanticBehaviorDigest"] = ""
    payload["legacyObservation"]["observationDigest"] = ""
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="Mode processing evidence is incomplete"):
        CommonEngineBehavioralParityAuthority.model_validate(payload)
