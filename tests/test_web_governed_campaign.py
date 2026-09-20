from __future__ import annotations

import inspect
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from itertools import pairwise
from pathlib import Path

import pytest
from pydantic import JsonValue

from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.runtime.store import (
    RunIntegrityError,
    RunStore,
    verify_run_integrity,
)
from pajin.web_assessment import governed
from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.governed_adapter_profile import (
    ResolvedGovernedWebAdapterProfile,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_campaign_evidence import (
    GovernedWebCampaignParentWriter,
    GovernedWebCampaignPlannedRuns,
    GovernedWebCampaignStageIntent,
    GovernedWebCampaignStageObservation,
    GovernedWebCampaignTrustMaterial,
    begin_governed_web_campaign_parent,
    load_verified_governed_web_incomplete_campaign_evidence,
)
from pajin.web_assessment.governed_models import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
)
from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    RequestEvidence,
    WebAssessmentPlan,
)
from pajin.web_assessment.runner import ProvisionedLocalWebAssessmentAccount


def _deployment_profile() -> ResolvedGovernedWebAdapterProfile:
    return production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
    )


def _campaign_parent_writer(tmp_path: Path) -> GovernedWebCampaignParentWriter:
    now = governed._now_utc()
    run_plan = governed._GovernedWebCampaignRunPlan.create()
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=_deployment_profile(),
        now=now,
    )
    return begin_governed_web_campaign_parent(
        tmp_path,
        planned_runs=run_plan.evidence_plan(),
        trust_material=trust.public_trust_material,
        started_at=now,
        signer_not_after=now + timedelta(hours=1),
    )


def _capture_parent_writer(
    monkeypatch: pytest.MonkeyPatch,
) -> list[GovernedWebCampaignParentWriter]:
    captured: list[GovernedWebCampaignParentWriter] = []
    original = begin_governed_web_campaign_parent

    def capture(
        output_root: Path,
        *,
        planned_runs: GovernedWebCampaignPlannedRuns,
        trust_material: GovernedWebCampaignTrustMaterial,
        started_at: datetime,
        signer_not_after: datetime,
    ) -> GovernedWebCampaignParentWriter:
        writer = original(
            output_root,
            planned_runs=planned_runs,
            trust_material=trust_material,
            started_at=started_at,
            signer_not_after=signer_not_after,
        )
        captured.append(writer)
        return writer

    monkeypatch.setattr(governed, "begin_governed_web_campaign_parent", capture)
    return captured


async def _run_in_process_test_campaign(output_root: Path) -> object:
    """Exercise the rich child-side executor without crossing the public process boundary."""

    return await governed._run_governed_local_web_campaign_in_workspace(
        origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
        output_root=output_root,
        selected_adapter_ref=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        headless=True,
    )


def test_public_executor_exposes_only_operator_selected_inputs() -> None:
    parameters = inspect.signature(governed.run_governed_local_web_campaign).parameters

    assert tuple(parameters) == (
        "origin",
        "output_root",
        "authorized_local_lab",
        "adapter_ref",
        "headless",
    )
    assert all(
        parameter.kind is inspect.Parameter.KEYWORD_ONLY for parameter in parameters.values()
    )
    assert {
        "clock",
        "key",
        "runner",
        "store",
        "credentials",
        "routes",
        "payload",
        "destination",
    }.isdisjoint(parameters)


def test_installed_profile_drives_campaign_adapter_and_trust_metadata() -> None:
    profile = _deployment_profile()
    now = governed._now_utc()
    campaign = governed._campaign(profile, now=now)
    trust = governed._prepare_governed_web_ephemeral_trust(profile=profile, now=now)

    assert campaign.metadata.name == profile.campaign_id
    assert campaign.metadata.description == profile.description
    assert campaign.spec.targets[0].id == profile.target_id
    assert campaign.spec.targets[0].type == profile.target_type
    assert campaign.spec.targets[0].endpoint == profile.origin
    assert campaign.spec.scope.allow == [profile.origin + "/**"]
    assert campaign.spec.scope.deny == [
        profile.origin + path + "*" for path in profile.plan.deny_paths
    ]
    assert campaign.spec.objectives == [profile.objective]
    assert trust.adapter.adapter_id == profile.adapter_id
    assert trust.adapter.adapter_version == profile.adapter_version
    assert trust.adapter.origin == profile.origin
    assert trust.adapter.implementation_id == profile.implementation_id
    assert trust.adapter.implementation_digest == profile.implementation_digest
    assert trust.adapter.recipe_digest == profile.plan_digest


def test_execution_rejects_trust_material_outside_selected_profile() -> None:
    profile = _deployment_profile()
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=profile,
        now=governed._now_utc(),
    )
    substituted_adapter = trust.adapter.model_copy(
        update={"implementation_id": "pajin.web-assessment.substituted.v1"}
    )

    with pytest.raises(
        governed.GovernedWebCampaignError,
        match="differ from the resolved deployment profile",
    ):
        governed._require_profile_execution_inputs(
            profile,
            origin=profile.origin,
            adapter_ref=profile.adapter_reference,
            plan=profile.plan,
            adapter=substituted_adapter,
        )


def test_code_owned_parent_trust_bindings_are_exact_and_distinct() -> None:
    bindings = governed._governed_code_trust_bindings(_deployment_profile())
    by_role = {binding.role: binding for binding in bindings}

    assert set(by_role) == {
        "adapter-implementation",
        "compiler",
        "profile",
        "worker",
        "gateway",
    }
    assert by_role["adapter-implementation"].implementation_id == (
        JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID
    )
    assert by_role["adapter-implementation"].implementation_digest == (
        JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
    )
    assert by_role["compiler"].implementation_id == governed._COMPILER_ID
    assert by_role["compiler"].implementation_digest == governed._COMPILER_DIGEST
    assert by_role["profile"].implementation_id == governed._PROFILE_ID
    assert by_role["profile"].implementation_digest == governed._PROFILE_DIGEST
    assert by_role["worker"].implementation_id == governed._WORKER_IMPLEMENTATION_ID
    assert by_role["worker"].implementation_digest == governed._WORKER_IMPLEMENTATION_DIGEST
    assert by_role["gateway"].implementation_id == governed._GATEWAY_IMPLEMENTATION_ID
    assert by_role["gateway"].implementation_digest == governed._GATEWAY_IMPLEMENTATION_DIGEST
    assert len({binding.implementation_id for binding in bindings}) == 5
    assert len({binding.implementation_digest for binding in bindings}) == 5


def test_ephemeral_authority_projects_only_distinct_public_trust_material() -> None:
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=_deployment_profile(),
        now=governed._now_utc(),
    )
    material = trust.public_trust_material
    document = material.model_dump_json(by_alias=True)
    public_keys = {
        material.adapter_key.public_key_base64url,
        material.account_key.public_key_base64url,
        material.source_approval_key.public_key_base64url,
        material.validation_approval_key.public_key_base64url,
        material.lifecycle_publisher_key.public_key_base64url,
        material.lifecycle_reviewer_key.public_key_base64url,
        *(key.public_key_base64url for key in material.worker_keys),
    }

    assert len(public_keys) == 10
    assert len(material.code_bindings) == 5
    assert "privateKey" not in document
    assert "password" not in document.casefold()
    assert "secret:" not in document


@pytest.mark.asyncio
async def test_internal_executor_requires_an_active_pinned_workspace(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def forbidden_execute(**_kwargs: object) -> object:
        raise AssertionError("execution must not be reached")

    monkeypatch.setattr(governed, "_execute_governed_local_web_campaign", forbidden_execute)

    with pytest.raises(governed.GovernedWebCampaignError, match="active pinned workspace"):
        await governed._run_governed_local_web_campaign_in_pinned_workspace(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            selected_adapter_ref=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
            headless=True,
        )


@pytest.mark.asyncio
async def test_internal_executor_keeps_all_output_below_pinned_relative_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}
    progress: list[governed._GovernedWebCampaignSealedProgress] = []
    sentinel = object()

    async def capture_execute(**kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    monkeypatch.setattr(governed, "_execute_governed_local_web_campaign", capture_execute)

    with (
        PinnedOutputRoot.create(tmp_path / "output") as pinned,
        pinned.activate(),
        governed._activate_governed_web_campaign_progress_sink(progress.append),
    ):
        result = await governed._run_governed_local_web_campaign_in_pinned_workspace(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            selected_adapter_ref=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
            headless=False,
        )

        assert result is sentinel
        assert captured["resolved_output"] == Path(".")
        profile = captured["profile"]
        assert isinstance(profile, ResolvedGovernedWebAdapterProfile)
        assert profile == _deployment_profile()
        assert captured["plan"] == profile.plan
        trust = captured["trust"]
        assert isinstance(trust, governed._GovernedWebEphemeralTrust)
        assert trust.adapter.implementation_id == profile.implementation_id
        assert trust.adapter.implementation_digest == profile.implementation_digest
        parent_writer = captured["parent_writer"]
        assert isinstance(parent_writer, GovernedWebCampaignParentWriter)
        assert not parent_writer.parent_run_path.is_absolute()
        assert parent_writer.parent_run_path.parts[:2] == (
            "campaign-runs",
            governed.GOVERNED_WEB_CAMPAIGN_ID,
        )
        assert verify_run_integrity(parent_writer.parent_run_path).seal_count == 1
        assert [(item.stage, item.status) for item in progress] == [("initial", "prepared")]


@pytest.mark.asyncio
async def test_internal_executor_requires_progress_ack_sink_before_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    execution_calls = 0

    async def forbidden_execute(**_kwargs: object) -> object:
        nonlocal execution_calls
        execution_calls += 1
        raise AssertionError("execution must wait for supervised progress custody")

    monkeypatch.setattr(
        governed,
        "_execute_governed_local_web_campaign",
        forbidden_execute,
    )

    with PinnedOutputRoot.create(tmp_path / "sink-required") as pinned, pinned.activate():
        with pytest.raises(
            governed.GovernedWebCampaignError,
            match="active supervised progress sink",
        ):
            await governed._run_governed_local_web_campaign_in_pinned_workspace(
                origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
                selected_adapter_ref=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
                headless=True,
            )

        assert execution_calls == 0
        assert not Path("campaign-runs").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("origin", "adapter_ref", "headless", "error"),
    [
        (
            "http://localhost:3000",
            governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
            True,
            governed.GovernedWebCampaignError,
        ),
        (
            governed.GOVERNED_JUICE_SHOP_ORIGIN,
            "caller-authored/v1",
            True,
            governed.GovernedWebCampaignError,
        ),
        (
            governed.GOVERNED_JUICE_SHOP_ORIGIN,
            governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
            1,
            TypeError,
        ),
    ],
)
async def test_internal_executor_revalidates_exact_inputs_before_any_output(
    tmp_path: Path,
    origin: str,
    adapter_ref: str,
    headless: object,
    error: type[Exception],
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned, pinned.activate():
        with pytest.raises(error):
            await governed._run_governed_local_web_campaign_in_pinned_workspace(
                origin=origin,
                selected_adapter_ref=adapter_ref,  # type: ignore[arg-type]
                headless=headless,  # type: ignore[arg-type]
            )

        assert not Path("campaign-runs").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("changes", "error"),
    [
        ({"authorized_local_lab": False}, governed.GovernedWebCampaignError),
        ({"authorized_local_lab": 1}, governed.GovernedWebCampaignError),
        ({"origin": "http://127.0.0.1:3001"}, governed.GovernedWebCampaignError),
        ({"origin": "http://localhost:3000"}, governed.GovernedWebCampaignError),
        ({"adapter_ref": "caller-authored/v1"}, governed.GovernedWebCampaignError),
        ({"headless": "true"}, TypeError),
        ({"output_root": "governed-output"}, TypeError),
    ],
)
async def test_invalid_public_inputs_fail_before_keys_provisioning_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    changes: dict[str, object],
    error: type[Exception],
) -> None:
    output = tmp_path / "must-not-exist"
    calls = 0

    def forbidden_key(*_args: object, **_kwargs: object) -> bytes:
        nonlocal calls
        calls += 1
        raise AssertionError("key creation must not be reached")

    async def forbidden_provision(*_args: object, **_kwargs: object) -> object:
        nonlocal calls
        calls += 1
        raise AssertionError("provisioning must not be reached")

    monkeypatch.setattr(governed, "_private_key", forbidden_key)
    monkeypatch.setattr(
        governed,
        "provision_local_web_assessment_account",
        forbidden_provision,
    )
    arguments: dict[str, object] = {
        "origin": governed.GOVERNED_JUICE_SHOP_ORIGIN,
        "output_root": output,
        "authorized_local_lab": True,
        "adapter_ref": governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        "headless": True,
    }
    arguments.update(changes)

    with pytest.raises(error):
        await governed.run_governed_local_web_campaign(**arguments)  # type: ignore[arg-type]

    assert calls == 0
    assert not output.exists()


@pytest.mark.asyncio
async def test_missing_operator_flag_is_rejected_by_public_signature(tmp_path: Path) -> None:
    with pytest.raises(TypeError, match="authorized_local_lab"):
        await governed.run_governed_local_web_campaign(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            output_root=tmp_path / "must-not-exist",
        )  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_output_parent_traversal_is_rejected_before_key_or_target_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    key_calls = 0

    def forbidden_key(*_args: object, **_kwargs: object) -> bytes:
        nonlocal key_calls
        key_calls += 1
        raise AssertionError("key creation must not be reached")

    monkeypatch.setattr(governed, "_private_key", forbidden_key)
    output = tmp_path / "unused-parent" / ".." / "must-not-exist"

    with pytest.raises(governed.GovernedWebCampaignError, match="parent traversal"):
        await governed.run_governed_local_web_campaign(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            output_root=output,
            authorized_local_lab=True,
        )

    assert key_calls == 0
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.asyncio
async def test_output_path_subclass_is_rejected_before_overridden_path_methods(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path_type = type(Path())
    method_calls = 0
    key_calls = 0

    class SubstitutedPath(path_type):  # type: ignore[misc, valid-type]
        def expanduser(self) -> Path:
            nonlocal method_calls
            method_calls += 1
            raise AssertionError("substituted Path methods must not be reached")

    def forbidden_key(*_args: object, **_kwargs: object) -> bytes:
        nonlocal key_calls
        key_calls += 1
        raise AssertionError("key creation must not be reached")

    monkeypatch.setattr(governed, "_private_key", forbidden_key)

    with pytest.raises(TypeError, match="output_root must be a Path"):
        await governed.run_governed_local_web_campaign(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            output_root=SubstitutedPath(tmp_path / "must-not-exist"),
            authorized_local_lab=True,
        )

    assert method_calls == 0
    assert key_calls == 0
    assert not (tmp_path / "must-not-exist").exists()


@pytest.mark.asyncio
async def test_public_facade_delegates_only_validated_inputs_to_isolated_process(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "must-not-exist"
    captured: dict[str, object] = {}
    sentinel = object()
    direct_calls = 0
    profile = _deployment_profile()
    resolution_calls: list[tuple[str, str]] = []
    from pajin.web_assessment import governed_process

    class InstalledProfiles:
        def resolve(
            self,
            *,
            adapter_reference: str,
            origin: str,
        ) -> ResolvedGovernedWebAdapterProfile:
            resolution_calls.append((adapter_reference, origin))
            return profile

    async def isolated_process(**kwargs: object) -> object:
        captured.update(kwargs)
        return sentinel

    async def forbidden_direct_execution(**_kwargs: object) -> object:
        nonlocal direct_calls
        direct_calls += 1
        raise AssertionError("the public facade must cross the isolated process boundary")

    monkeypatch.setattr(
        governed_process,
        "_run_governed_local_web_campaign_process",
        isolated_process,
    )
    monkeypatch.setattr(
        governed,
        "_run_governed_local_web_campaign_in_workspace",
        forbidden_direct_execution,
    )
    monkeypatch.setattr(
        governed,
        "production_governed_web_adapter_profile_registry",
        InstalledProfiles,
    )

    result = await governed.run_governed_local_web_campaign(
        origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
        output_root=output,
        authorized_local_lab=True,
    )

    assert result is sentinel
    assert direct_calls == 0
    assert resolution_calls == [
        (governed.GOVERNED_JUICE_SHOP_ADAPTER_REF, governed.GOVERNED_JUICE_SHOP_ORIGIN)
    ]
    assert captured == {
        "origin": governed.GOVERNED_JUICE_SHOP_ORIGIN,
        "output_root": output.absolute(),
        "authorized_local_lab": True,
        "selected_adapter_ref": governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        "headless": True,
    }
    assert not output.exists()


@pytest.mark.asyncio
async def test_provisioning_failure_seals_one_public_safe_incomplete_parent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "failed-campaign"
    captured = _capture_parent_writer(monkeypatch)
    committed: list[bool] = []
    secret_value = "never-persist-this-credential"

    async def fail_provisioning(*_args: object, **_kwargs: object) -> object:
        committed.append(True)
        raise RuntimeError(f"account committed after password={secret_value}")

    monkeypatch.setattr(
        governed,
        "provision_local_web_assessment_account",
        fail_provisioning,
    )

    with pytest.raises(RuntimeError, match="account committed"):
        await _run_in_process_test_campaign(output)

    assert committed == [True]
    assert len(captured) == 1
    writer = captured[0]
    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=writer.current_root_digest,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(writer.deployment_trust_anchor_digest),
    )
    persisted_bytes = b"".join(
        path.read_bytes() for path in writer.parent_run_path.rglob("*") if path.is_file()
    )
    assert loaded.terminal == "failed"
    assert loaded.incomplete.failure_stage == "provisioning"
    assert loaded.incomplete.account_provisioning_state == "may-have-executed"
    assert loaded.completed_stages == ()
    assert loaded.events[-1].event_type == "campaign.failed"
    assert loaded.seals[-1].root_digest == writer.current_root_digest
    assert secret_value.encode() not in persisted_bytes
    assert b"password" not in persisted_bytes.lower()
    assert b"privateKey" not in persisted_bytes
    assert not (output / "authority").exists()


@pytest.mark.asyncio
async def test_failure_before_provisioning_stage_records_not_started(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "pre-provision-failure"
    captured = _capture_parent_writer(monkeypatch)

    async def fail_before_stage(**_kwargs: object) -> object:
        raise RuntimeError("pre-stage failure")

    monkeypatch.setattr(
        governed,
        "_execute_governed_local_web_campaign",
        fail_before_stage,
    )
    with pytest.raises(RuntimeError, match="pre-stage failure"):
        await _run_in_process_test_campaign(output)

    assert len(captured) == 1
    writer = captured[0]
    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=writer.current_root_digest,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(writer.deployment_trust_anchor_digest),
    )
    assert loaded.terminal == "failed"
    assert loaded.active_stage is None
    assert loaded.incomplete.account_provisioning_state == "not-started"
    assert loaded.incomplete.may_have_executed is False


@pytest.mark.asyncio
async def test_private_progress_sink_observes_only_verified_seals_in_exact_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "progress-order"
    captured = _capture_parent_writer(monkeypatch)
    progress: list[governed._GovernedWebCampaignSealedProgress] = []

    class StopAfterSourceStart(RuntimeError):
        pass

    def observe(item: governed._GovernedWebCampaignSealedProgress) -> None:
        writer = captured[0]
        integrity = verify_run_integrity(writer.parent_run_path)
        assert integrity.valid
        assert integrity.root_digest == item.parent_root_digest
        assert writer.current_root_digest == item.parent_root_digest
        progress.append(item)

    async def fail_after_source_start(**kwargs: object) -> object:
        writer = kwargs["parent_writer"]
        assert isinstance(writer, GovernedWebCampaignParentWriter)
        governed._begin_campaign_stage(
            writer,
            "provisioning",
            {"accountProvisioningState": "may-have-executed"},
        )
        governed._complete_campaign_stage(
            writer,
            "provisioning",
            {"accountProvisioningState": "confirmed-retained"},
        )
        governed._begin_campaign_stage(writer, "source-gateway", {"requestId": "test"})
        raise StopAfterSourceStart

    monkeypatch.setattr(
        governed,
        "_execute_governed_local_web_campaign",
        fail_after_source_start,
    )
    with (
        governed._activate_governed_web_campaign_progress_sink(observe),
        pytest.raises(StopAfterSourceStart),
    ):
        await _run_in_process_test_campaign(output)

    assert [(item.stage, item.status, item.terminal) for item in progress] == [
        ("initial", "prepared", False),
        ("provisioning", "started", False),
        ("provisioning", "completed", False),
        ("source-gateway", "started", False),
        ("source-gateway", "failed", True),
    ]
    assert progress[0].previous_parent_root_digest is None
    assert all(
        current.previous_parent_root_digest == previous.parent_root_digest
        for previous, current in pairwise(progress)
    )
    assert len({item.parent_root_digest for item in progress}) == len(progress)


@pytest.mark.asyncio
async def test_initial_progress_ack_failure_prevents_provisioning_effects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "initial-ack-rejected"
    captured = _capture_parent_writer(monkeypatch)
    progress: list[governed._GovernedWebCampaignSealedProgress] = []
    execution_calls = 0

    class InitialAckRejected(RuntimeError):
        pass

    def reject_initial(item: governed._GovernedWebCampaignSealedProgress) -> None:
        progress.append(item)
        if item.stage == "initial":
            raise InitialAckRejected

    async def forbidden_execution(**_kwargs: object) -> object:
        nonlocal execution_calls
        execution_calls += 1
        raise AssertionError("provisioning must wait for the initial sealed progress ACK")

    monkeypatch.setattr(
        governed,
        "_execute_governed_local_web_campaign",
        forbidden_execution,
    )
    with (
        governed._activate_governed_web_campaign_progress_sink(reject_initial),
        pytest.raises(InitialAckRejected),
    ):
        await _run_in_process_test_campaign(output)

    assert execution_calls == 0
    assert [(item.stage, item.status, item.terminal) for item in progress] == [
        ("initial", "prepared", False),
        ("provisioning", "failed", True),
    ]
    assert progress[1].previous_parent_root_digest == progress[0].parent_root_digest
    writer = captured[0]
    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=writer.current_root_digest,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
    )
    assert loaded.incomplete.failure_stage == "provisioning"
    assert loaded.incomplete.account_provisioning_state == "not-started"


@pytest.mark.asyncio
async def test_async_progress_sink_cannot_bypass_initial_ack_barrier(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "async-progress-sink"
    captured = _capture_parent_writer(monkeypatch)
    execution_calls = 0
    sink_calls = 0

    async def invalid_async_sink(
        _item: governed._GovernedWebCampaignSealedProgress,
    ) -> None:
        nonlocal sink_calls
        sink_calls += 1

    async def forbidden_execution(**_kwargs: object) -> object:
        nonlocal execution_calls
        execution_calls += 1
        raise AssertionError("provisioning must wait for a synchronous progress ACK")

    monkeypatch.setattr(
        governed,
        "_execute_governed_local_web_campaign",
        forbidden_execution,
    )
    with (
        governed._activate_governed_web_campaign_progress_sink(invalid_async_sink),
        pytest.raises(TypeError, match="must complete synchronously"),
    ):
        await _run_in_process_test_campaign(output)

    assert execution_calls == 0
    assert sink_calls == 0
    writer = captured[0]
    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=writer.current_root_digest,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
    )
    assert loaded.incomplete.failure_stage == "provisioning"
    assert loaded.incomplete.account_provisioning_state == "not-started"


def test_progress_sink_cannot_reenter_sealed_emission(tmp_path: Path) -> None:
    writer = _campaign_parent_writer(tmp_path / "progress-reentry")
    initial_root = writer.current_root_digest
    calls = 0

    def reenter(_item: governed._GovernedWebCampaignSealedProgress) -> None:
        nonlocal calls
        calls += 1
        governed._emit_governed_web_campaign_sealed_progress(
            writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )

    with (
        governed._activate_governed_web_campaign_progress_sink(reenter),
        pytest.raises(RuntimeError, match="cannot re-enter"),
    ):
        governed._emit_governed_web_campaign_sealed_progress(
            writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )

    assert calls == 1
    integrity = verify_run_integrity(writer.parent_run_path)
    assert integrity.valid
    assert integrity.root_digest == initial_root


def test_database_fresh_authority_requires_a_successful_external_progress_sink(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "fresh-authority") as pinned, pinned.activate():
        writer = _campaign_parent_writer(Path("."))
        governed._emit_governed_web_campaign_sealed_progress(
            writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )
        with pytest.raises(ValueError, match="lacks a current external ACK"):
            writer.issue_database_fresh_authority(
                Path("authority/governed-web.sqlite3"),
                store_kind="governed-web-graph",
            )

        observed: list[governed._GovernedWebCampaignSealedProgress] = []
        with governed._activate_governed_web_campaign_progress_sink(observed.append):
            governed._emit_governed_web_campaign_sealed_progress(
                writer,
                previous_parent_root_digest=None,
                stage="initial",
                status="prepared",
                terminal=False,
            )

        authority = writer.issue_database_fresh_authority(
            Path("authority/governed-web.sqlite3"),
            store_kind="governed-web-graph",
        )
        assert authority is not None
        assert len(observed) == 1


def test_pinned_database_genesis_checkpoints_are_parent_sealed_and_acked(
    tmp_path: Path,
) -> None:
    progress: list[governed._GovernedWebCampaignSealedProgress] = []
    with (
        PinnedOutputRoot.create(tmp_path / "database-checkpoints") as pinned,
        pinned.activate(),
        governed._activate_governed_web_campaign_progress_sink(progress.append),
    ):
        writer = _campaign_parent_writer(Path("."))
        governed._emit_governed_web_campaign_sealed_progress(
            writer,
            previous_parent_root_digest=None,
            stage="initial",
            status="prepared",
            terminal=False,
        )
        governed._begin_campaign_stage(
            writer,
            "provisioning",
            {"accountProvisioningState": "may-have-executed"},
        )
        journal = governed._GovernedWebDatabaseCheckpointJournal(writer)

        graph_path = Path("authority/governed-web.sqlite3")
        graph_fresh = writer.issue_database_fresh_authority(
            graph_path,
            store_kind="governed-web-graph",
        )
        graph_store, graph_authority = governed.SQLiteGraphStore.create_governed_in_memory(
            graph_path,
            campaign_id=governed.GOVERNED_WEB_CAMPAIGN_ID,
            fresh_authority=graph_fresh,
            checkpoint_observer=journal.graph_checkpoint,
        )
        try:
            grant_path = Path("authority/capability-grant-consumptions.sqlite3")
            grant_fresh = writer.issue_database_fresh_authority(
                grant_path,
                store_kind="governed-web-grant",
            )
            (
                grant_store,
                grant_authority,
            ) = governed.WebAssessmentCapabilityGrantConsumptionStore.create_governed_in_memory(
                grant_path,
                campaign_id=governed.GOVERNED_WEB_CAMPAIGN_ID,
                fresh_authority=grant_fresh,
                checkpoint_observer=journal.grant_checkpoint,
            )
            try:
                assert graph_authority.latest_checkpoint().ordinal == 1
                assert grant_authority.latest_checkpoint().ordinal == 1
                now = governed._now_utc()
                campaign = governed._campaign(_deployment_profile(), now=now)
                ledger = governed.CapabilityLedger(max_depth=1)
                root_grant = ledger.issue_root(
                    campaign,
                    subject="agent:web-assessment-root",
                    tools={governed.WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
                    targets={governed.GOVERNED_JUICE_SHOP_ORIGIN},
                )
                source_grant = ledger.delegate(
                    root_grant.grant_id,
                    subject="agent:web-assessment-source",
                    tools={governed.WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
                    targets={governed.GOVERNED_JUICE_SHOP_ORIGIN},
                    max_risk_tier=governed.ToolRiskTier.T2,
                    max_calls=1,
                    expires_at=now + timedelta(minutes=10),
                )
                validation_grant = ledger.delegate(
                    root_grant.grant_id,
                    subject="agent:web-assessment-validation",
                    tools={governed.WEB_AUTHENTICATED_ASSESSMENT_TOOL_ID},
                    targets={governed.GOVERNED_JUICE_SHOP_ORIGIN},
                    max_risk_tier=governed.ToolRiskTier.T2,
                    max_calls=1,
                    expires_at=now + timedelta(minutes=10),
                )
                dispatch_authority = governed.WebAssessmentDispatchAuthority.create(
                    graph_store=graph_store,
                    capability_ledger=ledger,
                    grant_consumption_store=grant_store,
                    source_grant=source_grant,
                    validation_grant=validation_grant,
                )
                dispatch_registry = governed.WebAssessmentDispatchBindingRegistry(
                    authority=dispatch_authority,
                )
                assert dispatch_registry is not None
                graph_projection = governed.GraphProjectionCoordinator(
                    event_log=graph_store.event_log,
                    projection_store=graph_store.projection_store,
                )
                graph_projection.refresh()
                assert graph_authority.latest_checkpoint().ordinal == 2
                snapshot_authority = governed.GraphSnapshotAuthority(
                    creator_id="pajin.web.governed.snapshot-authority",
                    creator_digest="a" * 64,
                    projection_store=graph_store.projection_store,
                    snapshot_store=graph_store.snapshot_store,
                )
                snapshot_authority.capture(governed.GraphSnapshotReason.CHECKPOINT)
                assert graph_authority.latest_checkpoint().ordinal == 4
                assert not graph_path.exists()
                assert not grant_path.exists()
                assert graph_authority.freeze_and_publish().reference == graph_path.as_posix()
                assert grant_authority.freeze_and_publish().reference == grant_path.as_posix()
            finally:
                grant_authority.close()
        finally:
            graph_authority.close()

        database_progress = [item for item in progress if item.status == "database-checkpoint"]
        assert [item.database_store_kind for item in database_progress] == [
            "governed-web-graph",
            "governed-web-grant",
            "governed-web-graph",
            "governed-web-graph",
            "governed-web-graph",
        ]
        assert all(item.stage == "provisioning" for item in database_progress)
        assert [item.database_checkpoint_ordinal for item in database_progress] == [
            1,
            1,
            2,
            3,
            4,
        ]
        assert all(
            current.previous_parent_root_digest == previous.parent_root_digest
            for previous, current in pairwise(progress)
        )
        assert (
            verify_run_integrity(writer.parent_run_path).root_digest
            == progress[-1].parent_root_digest
        )
        assert graph_store.campaign_id == governed.GOVERNED_WEB_CAMPAIGN_ID

        incomplete = writer.fail("injected-stage-failure", governed._now_utc())
        loaded = load_verified_governed_web_incomplete_campaign_evidence(
            writer.parent_run_path,
            expected_parent_run_id=writer.parent_run_id,
            expected_parent_root_digest=writer.current_root_digest,
            expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=(writer.deployment_trust_anchor_digest),
        )
        assert incomplete.failure_stage == "provisioning"
        assert incomplete.active_stage == "provisioning"
        assert loaded.incomplete == incomplete
        assert (
            sum(event.event_type == "web.governed.database-checkpoint" for event in loaded.events)
            == 5
        )
        assert loaded.events[-1].event_type == "campaign.failed"


@pytest.mark.asyncio
async def test_pinned_source_dispatch_reaches_gateway_after_acked_grant_checkpoints(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GatewayReached(RuntimeError):
        pass

    progress: list[governed._GovernedWebCampaignSealedProgress] = []
    writers = _capture_parent_writer(monkeypatch)
    gateway_calls = 0

    class FakeGateway:
        async def execute_approved(
            self,
            *_args: object,
            **_kwargs: object,
        ) -> object:
            nonlocal gateway_calls
            gateway_calls += 1
            grant_checkpoints = [
                item for item in progress if item.database_store_kind == "governed-web-grant"
            ]
            assert [item.database_checkpoint_ordinal for item in grant_checkpoints] == [1, 2, 3]
            assert len(writers) == 1
            assert (
                verify_run_integrity(writers[0].parent_run_path).root_digest
                == grant_checkpoints[-1].parent_root_digest
            )
            raise GatewayReached("approved dispatch reached the Gateway boundary")

    async def fake_provision(
        *,
        plan: WebAssessmentPlan,
        authorization: LocalWebAssessmentAuthorization,
    ) -> ProvisionedLocalWebAssessmentAccount:
        current = datetime.now(UTC)
        return ProvisionedLocalWebAssessmentAccount(
            credentials=BrowserCredentials(
                username="pinned-dispatch@example.invalid",
                password="pinned-dispatch-proof",
            ),
            plan_digest=plan.plan_digest,
            authorization_id=authorization.authorization_id,
            origin=plan.origin,
            target_version="pinned-dispatch-test",
            provisioned_at=current,
            request_evidence=(
                RequestEvidence(
                    evidence_id="http-1-00000000",
                    phase="target-fingerprint",
                    method="GET",
                    path=plan.fingerprint_endpoint,
                    request_sha256=sha256(b"request").hexdigest(),
                    status=200,
                    response_sha256=sha256(b"response").hexdigest(),
                    response_bytes=len(b"response"),
                    media_type="application/json",
                ),
            ),
        )

    monkeypatch.setattr(
        governed,
        "provision_local_web_assessment_account",
        fake_provision,
    )
    monkeypatch.setattr(
        governed.HostLoopbackWebAssessmentGateway,
        "production",
        lambda **_kwargs: FakeGateway(),
    )

    with (
        PinnedOutputRoot.create(tmp_path / "pinned-source-dispatch") as pinned,
        pinned.activate(),
        governed._activate_governed_web_campaign_progress_sink(progress.append),
    ):
        with pytest.raises(GatewayReached, match="Gateway boundary"):
            await governed._run_governed_local_web_campaign_in_pinned_workspace(
                origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
                selected_adapter_ref=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
                headless=True,
            )

        assert gateway_calls == 1
        grant_checkpoints = [
            item for item in progress if item.database_store_kind == "governed-web-grant"
        ]
        assert [item.stage for item in grant_checkpoints] == [
            "provisioning",
            "source-gateway",
            "source-gateway",
        ]
        assert [item.database_checkpoint_ordinal for item in grant_checkpoints] == [1, 2, 3]
        assert all(
            current.previous_parent_root_digest == previous.parent_root_digest
            for previous, current in pairwise(progress)
        )

        writer = writers[0]
        loaded = load_verified_governed_web_incomplete_campaign_evidence(
            writer.parent_run_path,
            expected_parent_run_id=writer.parent_run_id,
            expected_parent_root_digest=writer.current_root_digest,
            expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
        )
        sealed_roots = {seal.root_digest for seal in loaded.seals}
        assert all(item.parent_root_digest in sealed_roots for item in grant_checkpoints)
        assert loaded.incomplete.failure_stage == "source-gateway"
        assert (
            sum(
                event.event_type == "web.governed.database-checkpoint"
                and event.payload.get("storeKind") == "governed-web-grant"
                for event in loaded.events
            )
            == 3
        )


@pytest.mark.parametrize(
    "stage",
    [
        "provisioning",
        "source-gateway",
        "validation-gateway",
        "graph-admission",
        "poc-publication",
        "export-publication",
    ],
)
def test_each_failure_stage_has_one_terminal_last_incomplete_record(
    tmp_path: Path,
    stage: governed._CampaignFailureStage,
) -> None:
    writer = _campaign_parent_writer(tmp_path / stage)
    stage_index = governed._CAMPAIGN_STAGE_ORDER.index(stage)
    for prior in governed._CAMPAIGN_STAGE_ORDER[:stage_index]:
        writer.begin_stage(
            prior,
            GovernedWebCampaignStageIntent(
                stage=prior,
                bindings={"testStage": prior},
            ),
            governed._now_utc(),
        )
        observed: dict[str, JsonValue] = {"testStage": prior}
        if prior == "provisioning":
            observed["accountProvisioningState"] = "confirmed-retained"
        writer.complete_stage(
            prior,
            GovernedWebCampaignStageObservation(
                stage=prior,
                observed=observed,
            ),
            governed._now_utc(),
        )
    writer.begin_stage(
        stage,
        GovernedWebCampaignStageIntent(
            stage=stage,
            bindings={
                "testStage": stage,
                **(
                    {"accountProvisioningState": "may-have-executed"}
                    if stage == "provisioning"
                    else {}
                ),
            },
        ),
        governed._now_utc(),
    )
    writer.fail("injected-stage-failure", governed._now_utc())

    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=writer.current_root_digest,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(writer.deployment_trust_anchor_digest),
    )
    assert loaded.incomplete.failure_stage == stage
    assert len(loaded.seals) == 3 + (2 * stage_index)
    assert loaded.events[0].event_type == "campaign.started"
    assert loaded.events[-2].event_type == "web.governed.stage.started"
    assert loaded.events[-1].event_type == "campaign.failed"
    artifacts = {artifact.path for seal in loaded.seals for artifact in seal.artifacts}
    assert "campaign-plan.json" in artifacts
    assert f"checkpoints/{stage_index + 1:02d}-{stage}-started.json" in artifacts
    assert "incomplete.json" in artifacts


def test_unsealed_completion_event_is_never_a_verified_complete_campaign(tmp_path: Path) -> None:
    writer = _campaign_parent_writer(tmp_path / "unsealed-completion")
    RunStore(writer.parent_run_id, writer.parent_run_path).append_event(
        "campaign.completed",
        {},
        occurred_at=governed._now_utc(),
    )

    with pytest.raises(RunIntegrityError, match=r"unsealed.*events"):
        verify_run_integrity(writer.parent_run_path)


@pytest.mark.asyncio
@pytest.mark.parametrize("through_symlink", [False, True])
async def test_output_nested_in_existing_run_is_rejected_before_any_key_or_write(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    through_symlink: bool,
) -> None:
    victim = RunStore.create(tmp_path / "victim-runs", "victim")
    victim.write_json_create_only("authority.json", {"public": True})
    victim.append_event("campaign.started", {"campaignId": "victim"})
    victim.append_event("campaign.completed", {"campaignId": "victim"})
    victim_seal = victim.seal()
    victim_integrity = verify_run_integrity(victim.path)
    parent = victim.path
    if through_symlink:
        parent = tmp_path / "victim-alias"
        parent.symlink_to(victim.path, target_is_directory=True)
    nested_output = parent / "attacker-output"
    key_calls = 0

    def forbidden_key(*_args: object, **_kwargs: object) -> bytes:
        nonlocal key_calls
        key_calls += 1
        raise AssertionError("key generation must not be reached")

    monkeypatch.setattr(governed, "_private_key", forbidden_key)

    with pytest.raises(
        governed.GovernedWebCampaignError,
        match=r"nested inside|symbolic link",
    ):
        await governed.run_governed_local_web_campaign(
            origin=governed.GOVERNED_JUICE_SHOP_ORIGIN,
            output_root=nested_output,
            authorized_local_lab=True,
        )

    assert key_calls == 0
    assert not nested_output.exists()
    assert verify_run_integrity(victim.path) == victim_integrity
    assert victim_integrity.root_digest == victim_seal.root_digest
