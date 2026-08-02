from __future__ import annotations

from collections.abc import Callable
from copy import deepcopy
from datetime import timedelta
from hashlib import sha256
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
from test_engine_behavioral_parity import _ctf_campaign, _dual_runtime
from test_existing_capability_rollout import _admit
from test_kisa_replay import _trusted_docker_backend as ai_backend

from pajin.capabilities import (
    CapabilityUseProfile,
    ExistingModeCapabilityActivation,
    activate_existing_mode_capabilities,
)
from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.runtime.worker import WorkerBackend
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import Tool
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFWebBackupProbeTool
from pajin.workflow.engine_behavioral_parity import (
    CommonEngineBehavioralParityAuthority,
    CommonEngineNormalizedBehaviorObservation,
    measure_common_engine_behavioral_parity,
)
from pajin.workflow.engine_mission_envelope import (
    CommonEngineMissionEnvelopeCompilationAuthority,
    CommonEngineMissionEnvelopeCompilationError,
    compile_common_engine_mission_envelope,
)
from pajin.workflow.profile_compatibility import compile_legacy_campaign_profile


def _all_capability_activation() -> ExistingModeCapabilityActivation:
    rollout = _admit()
    return activate_existing_mode_capabilities(
        rollout=rollout,
        releases=tuple(item.release for item in rollout.release_set.bindings),
        profile=CapabilityUseProfile.RANGE,
    )


def _activation_for_capability(capability_id: str) -> ExistingModeCapabilityActivation:
    rollout = _admit()
    release = next(
        item.release
        for item in rollout.release_set.bindings
        if item.capability.capability.capability_id == capability_id
    )
    return activate_existing_mode_capabilities(
        rollout=rollout,
        releases=(release,),
        profile=CapabilityUseProfile.RANGE,
    )


def _parity(
    tmp_path: Path,
    campaign: CampaignManifest,
    tool_factory: Callable[[], Tool],
    worker_factory: Callable[[], WorkerBackend],
    mode_source: object | None,
) -> CommonEngineBehavioralParityAuthority:
    dual = _dual_runtime(
        tmp_path,
        campaign,
        tool_factory,
        worker_factory(),
        worker_factory(),
    )
    return measure_common_engine_behavioral_parity(
        dual,
        mode_source=mode_source,
    ).authority


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
def test_all_legacy_modes_compile_parity_bound_non_expanding_envelope(
    tmp_path: Path,
    mode: CampaignMode,
    campaign_factory: Callable[[], CampaignManifest],
    tool_factory: Callable[[], Tool],
    worker_factory: Callable[[], WorkerBackend],
    source_factory: Callable[[], object | None],
) -> None:
    campaign = campaign_factory()
    parity = _parity(
        tmp_path,
        campaign,
        tool_factory,
        worker_factory,
        source_factory(),
    )
    not_before = campaign.spec.authorization.approved_at + timedelta(seconds=1)
    authority = compile_common_engine_mission_envelope(
        compile_legacy_campaign_profile(campaign),
        parity,
        _all_capability_activation(),
        run_id=f"common-engine-{mode.value}",
        not_before=not_before,
    )
    envelope = authority.envelope

    assert envelope.campaign_id == campaign.metadata.name
    assert envelope.profile_id == authority.profile_compilation.profile.profile_id
    assert envelope.source_campaign_digest == authority.profile_compilation.input_digest
    expected_start = max(
        not_before,
        *(binding.authority_not_before for binding in authority.capability_bindings),
    )
    assert envelope.not_before == expected_start
    assert envelope.expires_at == min(
        campaign.spec.authorization.expires_at,
        expected_start + timedelta(seconds=campaign.spec.budgets.duration_seconds),
        *(binding.authority_expires_at for binding in authority.capability_bindings),
    )
    assert envelope.budget.tool_call_limit == len(authority.capability_bindings)
    assert envelope.budget.tool_call_limit <= campaign.spec.budgets.max_tool_calls
    assert envelope.allowed_target_digests == tuple(
        sorted(
            {
                sha256(binding.request.target.encode("utf-8")).hexdigest()
                for binding in authority.capability_bindings
            }
        )
    )
    assert authority.mission_envelope_compiled is True
    assert authority.action_permit_issued is False
    assert authority.common_runtime_dispatched is False
    assert authority.common_execution_authorized is False
    assert (
        CommonEngineMissionEnvelopeCompilationAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        == authority
    )


def test_compiler_rejects_cross_campaign_activation_run_or_time_substitution(
    tmp_path: Path,
) -> None:
    campaign = _ctf_campaign()
    parity = _parity(
        tmp_path,
        campaign,
        CTFWebBackupProbeTool,
        lambda: ctf_backend(ContractCTFWorker()),
        _challenge(),
    )
    compilation = compile_legacy_campaign_profile(campaign)
    not_before = campaign.spec.authorization.approved_at + timedelta(seconds=1)

    with pytest.raises(
        CommonEngineMissionEnvelopeCompilationError,
        match="authority intersection failed closed",
    ):
        compile_common_engine_mission_envelope(
            compile_legacy_campaign_profile(bug_bounty_campaign()),
            parity,
            _all_capability_activation(),
            run_id="common-engine-cross-mode",
            not_before=not_before,
        )

    with pytest.raises(
        CommonEngineMissionEnvelopeCompilationError,
        match="authority intersection failed closed",
    ):
        compile_common_engine_mission_envelope(
            compilation,
            parity,
            _activation_for_capability("pajin.bug-bounty.boolean-sqli-lab"),
            run_id="common-engine-wrong-capability",
            not_before=not_before,
        )

    for run_id, start in (
        (
            parity.dual_runtime.adapter_execution.run_id,
            not_before,
        ),
        (
            "common-engine-expired",
            campaign.spec.authorization.expires_at,
        ),
    ):
        with pytest.raises(
            CommonEngineMissionEnvelopeCompilationError,
            match="authority intersection failed closed",
        ):
            compile_common_engine_mission_envelope(
                compilation,
                parity,
                _all_capability_activation(),
                run_id=run_id,
                not_before=start,
            )


def test_compiler_requires_successful_trusted_behavioral_receipts(tmp_path: Path) -> None:
    campaign = _ctf_campaign()
    parity = _parity(
        tmp_path,
        campaign,
        CTFWebBackupProbeTool,
        lambda: ctf_backend(ContractCTFWorker()),
        _challenge(),
    )
    payload = deepcopy(parity.model_dump(mode="json", by_alias=True))
    observations = []
    for field in ("legacyObservation", "adapterObservation"):
        observation_payload = payload[field]
        observation_payload["normalizedReceipt"]["evidence"][0][
            "networkLogTrusted"
        ] = False
        observation_payload["receiptDigest"] = ""
        observation_payload["semanticBehaviorDigest"] = ""
        observation_payload["observationDigest"] = ""
        observations.append(
            CommonEngineNormalizedBehaviorObservation.model_validate(observation_payload)
        )
    payload["legacyObservation"] = observations[0].model_dump(mode="json", by_alias=True)
    payload["adapterObservation"] = observations[1].model_dump(mode="json", by_alias=True)
    payload["semanticBehaviorDigest"] = observations[0].semantic_behavior_digest
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    untrusted_parity = CommonEngineBehavioralParityAuthority.model_validate(payload)

    with pytest.raises(
        CommonEngineMissionEnvelopeCompilationError,
        match="authority intersection failed closed",
    ):
        compile_common_engine_mission_envelope(
            compile_legacy_campaign_profile(campaign),
            untrusted_parity,
            _all_capability_activation(),
            run_id="common-engine-untrusted-receipt",
            not_before=campaign.spec.authorization.approved_at + timedelta(seconds=1),
        )


def test_authority_rejects_scope_budget_time_or_execution_flag_forgery(
    tmp_path: Path,
) -> None:
    campaign = _ctf_campaign()
    parity = _parity(
        tmp_path,
        campaign,
        CTFWebBackupProbeTool,
        lambda: ctf_backend(ContractCTFWorker()),
        _challenge(),
    )
    authority = compile_common_engine_mission_envelope(
        compile_legacy_campaign_profile(campaign),
        parity,
        _all_capability_activation(),
        run_id="common-engine-forgery",
        not_before=campaign.spec.authorization.approved_at + timedelta(seconds=1),
    )

    for field, replacement in (
        ("missionEnvelopeCompiled", False),
        ("actionPermitIssued", True),
        ("commonRuntimeDispatched", True),
        ("commonExecutionAuthorized", True),
    ):
        payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
        payload[field] = replacement
        with pytest.raises(ValidationError):
            CommonEngineMissionEnvelopeCompilationAuthority.model_validate(payload)

    for mutate in (
        lambda envelope: envelope.update(
            {"allowedTargetDigests": sorted([*envelope["allowedTargetDigests"], "0" * 64])}
        ),
        lambda envelope: envelope["budget"].update(
            {"toolCallLimit": envelope["budget"]["toolCallLimit"] + 1}
        ),
        lambda envelope: envelope.update(
            {
                "expiresAt": (
                    authority.envelope.expires_at + timedelta(seconds=1)
                ).isoformat()
            }
        ),
    ):
        payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
        mutate(payload["envelope"])
        payload["envelope"]["envelopeId"] = ""
        payload["envelope"]["envelopeDigest"] = ""
        payload["envelopeDigest"] = "0" * 64
        payload["authorityId"] = ""
        payload["authorityDigest"] = ""
        with pytest.raises((ValidationError, ValueError)):
            CommonEngineMissionEnvelopeCompilationAuthority.model_validate(payload)

    payload = deepcopy(authority.model_dump(mode="json", by_alias=True))
    wrong_compilation = compile_legacy_campaign_profile(bug_bounty_campaign())
    payload["profileCompilation"] = wrong_compilation.model_dump(
        mode="json",
        by_alias=True,
    )
    payload["profileCompilationDigest"] = wrong_compilation.authority_digest
    payload["authorityId"] = ""
    payload["authorityDigest"] = ""
    with pytest.raises(ValidationError, match="complete behavioral parity"):
        CommonEngineMissionEnvelopeCompilationAuthority.model_validate(payload)


def test_compiler_rejects_mixed_recurring_testing_windows(tmp_path: Path) -> None:
    campaign_payload = ai_campaign().model_dump(mode="json", by_alias=True)
    campaign_payload["spec"]["rulesOfEngagement"]["testingWindows"] = [
        {
            "days": [
                "monday",
                "tuesday",
                "wednesday",
                "thursday",
                "friday",
                "saturday",
                "sunday",
            ],
            "startTime": "00:00:00",
            "endTime": "00:00:00",
            "timezone": "UTC",
        },
        {
            "days": ["monday"],
            "startTime": "00:00:00",
            "endTime": "01:00:00",
            "timezone": "UTC",
        },
    ]
    campaign = CampaignManifest.model_validate(campaign_payload)
    parity = _parity(
        tmp_path,
        campaign,
        AIChatProbeTool,
        lambda: ai_backend(ContractAIWorker()),
        None,
    )

    with pytest.raises(
        CommonEngineMissionEnvelopeCompilationError,
        match="authority intersection failed closed",
    ):
        compile_common_engine_mission_envelope(
            compile_legacy_campaign_profile(campaign),
            parity,
            _all_capability_activation(),
            run_id="common-engine-mixed-testing-windows",
            not_before=campaign.spec.authorization.approved_at + timedelta(seconds=1),
        )
