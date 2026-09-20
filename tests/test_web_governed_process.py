from __future__ import annotations

import asyncio
import os
import subprocess
import threading
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, cast

import pytest

import pajin.web_assessment.governed_process as governed_process
from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.runtime.store import RunStore
from pajin.web_assessment import governed
from pajin.web_assessment.governed_adapter_profile import (
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_campaign_evidence import (
    GOVERNED_WEB_ADAPTER_REF,
    GOVERNED_WEB_ORIGIN,
    GovernedWebCampaignHistoricalResult,
    GovernedWebCampaignParentWriter,
    GovernedWebCampaignStageIntent,
    begin_governed_web_campaign_parent,
)

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX process supervision")

NOW = datetime(2026, 9, 15, 1, 2, 3, tzinfo=UTC)
RUN_ID = "run_20260915T010203Z_deadbeef"
PLAN_DIGEST = "1" * 64
ANCHOR_DIGEST = "2" * 64
INITIAL_ROOT = "3" * 64
STARTED_ROOT = "4" * 64
MANIFEST_DIGEST = "5" * 64
DATABASE_SHA256 = "6" * 64
CHECKPOINT_DIGEST = "7" * 64


def _test_incomplete_receipt(
    output: Path,
    *,
    sequence: int,
    parent_root_digest: str,
    record_digest: str,
    stage: governed_process._ProgressStage,
    status: governed_process._ProgressStatus,
) -> governed_process.GovernedWebCampaignIncompleteReceipt:
    return governed_process.GovernedWebCampaignIncompleteReceipt(
        output_root=output,
        parent_run_path=(output / "campaign-runs" / "juice-shop-governed-local" / RUN_ID),
        parent_run_id=RUN_ID,
        initial_parent_root_digest=INITIAL_ROOT,
        parent_root_digest=parent_root_digest,
        campaign_plan_digest=PLAN_DIGEST,
        deployment_trust_anchor_digest=ANCHOR_DIGEST,
        last_verified_sequence=sequence,
        last_record_digest=record_digest,
        last_stage=stage,
        last_status=status,
        terminal_progress_observed=False,
    )


def _commit_test_ack(
    state: governed_process._SupervisorProgressState,
    receipt: governed_process.GovernedWebCampaignIncompleteReceipt | None,
    *,
    sequence: int,
) -> None:
    state.require_next_verified_ack(
        sequence=sequence,
        incomplete_receipt=receipt,
    )
    state.commit_verified_ack(
        sequence=sequence,
        incomplete_receipt=receipt,
    )


def _progress_content(
    *,
    sequence: int = 1,
    previous_record_digest: str | None = None,
    parent_run_id: str = RUN_ID,
    campaign_plan_digest: str = PLAN_DIGEST,
    deployment_trust_anchor_digest: str = ANCHOR_DIGEST,
    previous_parent_root_digest: str | None = None,
    parent_root_digest: str = INITIAL_ROOT,
    stage: str = "initial",
    status: str = "prepared",
    terminal: bool = False,
    database_store_kind: str | None = None,
    database_checkpoint_ordinal: int | None = None,
    database_manifest_digest: str | None = None,
    database_sha256: str | None = None,
    database_checkpoint_digest: str | None = None,
    extra: dict[str, object] | None = None,
) -> bytes:
    material: dict[str, object] = {
        "apiVersion": governed_process._PROGRESS_API_VERSION,
        "kind": governed_process._PROGRESS_KIND,
        "sequence": sequence,
        "previousRecordDigest": previous_record_digest,
        "parentRunId": parent_run_id,
        "campaignPlanDigest": campaign_plan_digest,
        "deploymentTrustAnchorDigest": deployment_trust_anchor_digest,
        "previousParentRootDigest": previous_parent_root_digest,
        "parentRootDigest": parent_root_digest,
        "stage": stage,
        "status": status,
        "terminal": terminal,
        "databaseStoreKind": database_store_kind,
        "databaseCheckpointOrdinal": database_checkpoint_ordinal,
        "databaseManifestDigest": database_manifest_digest,
        "databaseSha256": database_sha256,
        "databaseCheckpointDigest": database_checkpoint_digest,
    }
    if extra is not None:
        material.update(extra)
    return governed_process._canonical_json(
        {**material, "recordDigest": governed_process._progress_digest(material)}
    )


def _parsed_progress(**kwargs: object) -> governed_process._ProgressRecord:
    return governed_process._parse_progress_record(_progress_content(**kwargs))


def _parent_writer(output_root: Path) -> GovernedWebCampaignParentWriter:
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        origin=GOVERNED_WEB_ORIGIN,
    )
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=profile,
        now=NOW,
    )
    run_ids = tuple(RunStore.new_run_id() for _ in range(6))
    return begin_governed_web_campaign_parent(
        output_root,
        planned_runs=governed.GovernedWebCampaignPlannedRuns(
            parentRunId=run_ids[0],
            sourceBrowserRunId=run_ids[1],
            validationBrowserRunId=run_ids[2],
            sourceGatewayRunId=run_ids[3],
            validationGatewayRunId=run_ids[4],
            validationProjectionRunId=run_ids[5],
        ),
        trust_material=trust.public_trust_material,
        started_at=NOW,
        signer_not_after=NOW + timedelta(hours=1),
    )


def test_database_checkpoint_progress_requires_and_parses_all_five_fields() -> None:
    record = _parsed_progress(
        sequence=2,
        previous_record_digest="8" * 64,
        previous_parent_root_digest=INITIAL_ROOT,
        parent_root_digest=STARTED_ROOT,
        stage="provisioning",
        status="database-checkpoint",
        database_store_kind="governed-web-graph",
        database_checkpoint_ordinal=17,
        database_manifest_digest=MANIFEST_DIGEST,
        database_sha256=DATABASE_SHA256,
        database_checkpoint_digest=CHECKPOINT_DIGEST,
    )

    assert (
        record.database_store_kind,
        record.database_checkpoint_ordinal,
        record.database_manifest_digest,
        record.database_sha256,
        record.database_checkpoint_digest,
    ) == (
        "governed-web-graph",
        17,
        MANIFEST_DIGEST,
        DATABASE_SHA256,
        CHECKPOINT_DIGEST,
    )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("database_store_kind", None),
        ("database_checkpoint_ordinal", None),
        ("database_manifest_digest", None),
        ("database_sha256", None),
        ("database_checkpoint_digest", None),
        ("database_store_kind", "untrusted-store"),
        ("database_checkpoint_ordinal", True),
    ],
)
def test_database_checkpoint_progress_rejects_missing_or_inexact_field(
    field: str,
    value: object,
) -> None:
    values: dict[str, object] = {
        "sequence": 2,
        "previous_record_digest": "8" * 64,
        "previous_parent_root_digest": INITIAL_ROOT,
        "parent_root_digest": STARTED_ROOT,
        "stage": "provisioning",
        "status": "database-checkpoint",
        "database_store_kind": "governed-web-grant",
        "database_checkpoint_ordinal": 1,
        "database_manifest_digest": MANIFEST_DIGEST,
        "database_sha256": DATABASE_SHA256,
        "database_checkpoint_digest": CHECKPOINT_DIGEST,
    }
    values[field] = value

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="database-checkpoint progress is invalid",
    ):
        _parsed_progress(**values)


def test_progress_parser_requires_exact_schema_digest_and_canonical_json() -> None:
    canonical = _progress_content()
    unknown_field = _progress_content(extra={"callerClaim": "trusted"})
    tampered = canonical.replace(INITIAL_ROOT.encode(), ("f" * 64).encode(), 1)

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="schema is not exact",
    ):
        governed_process._parse_progress_record(unknown_field)
    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="JSON is not canonical",
    ):
        governed_process._parse_progress_record(canonical + b" ")
    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="digest differs",
    ):
        governed_process._parse_progress_record(tampered)
    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="prepared progress is invalid",
    ):
        _parsed_progress(status="completed")


def test_child_projects_the_initial_seal_as_canonical_prepared_progress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    emitted = bytearray()

    def capture_write(_descriptor: int, content: bytes) -> None:
        emitted.extend(content)

    def acknowledge(_descriptor: int, *, timeout_seconds: float, max_bytes: int) -> bytes:
        assert timeout_seconds == governed_process._ACK_TIMEOUT_SECONDS
        assert max_bytes == governed_process._MAX_PROGRESS_RECORD_BYTES
        record = governed_process._parse_progress_record(bytes(emitted).removesuffix(b"\n"))
        return governed_process._ack_bytes(record).removesuffix(b"\n")

    monkeypatch.setattr(governed_process, "_write_all", capture_write)
    monkeypatch.setattr(governed_process, "_read_one_line", acknowledge)
    sink = governed_process._ChildProgressSink(progress_fd=101, ack_fd=102)
    item = governed._GovernedWebCampaignSealedProgress(
        parent_run_id=RUN_ID,
        campaign_plan_digest=PLAN_DIGEST,
        deployment_trust_anchor_digest=ANCHOR_DIGEST,
        previous_parent_root_digest=None,
        parent_root_digest=INITIAL_ROOT,
        stage="initial",
        status="prepared",
        terminal=False,
    )

    sink(item)

    record = governed_process._parse_progress_record(bytes(emitted).removesuffix(b"\n"))
    assert record.stage == "initial"
    assert record.status == "prepared"
    assert record.parent_root_digest == INITIAL_ROOT


def test_progress_chain_is_contiguous_and_authority_stable() -> None:
    initial = _parsed_progress()
    started = _parsed_progress(
        sequence=2,
        previous_record_digest=initial.record_digest,
        previous_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=STARTED_ROOT,
        stage="provisioning",
        status="started",
    )

    governed_process._validate_progress_chain([], initial)
    governed_process._validate_progress_chain([initial], started)

    discontinuous = _parsed_progress(
        sequence=3,
        previous_record_digest=initial.record_digest,
        previous_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=STARTED_ROOT,
        stage="provisioning",
        status="started",
    )
    changed_authority = _parsed_progress(
        sequence=2,
        previous_record_digest=initial.record_digest,
        previous_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=STARTED_ROOT,
        stage="provisioning",
        status="started",
        campaign_plan_digest="9" * 64,
    )

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="chain is not contiguous",
    ):
        governed_process._validate_progress_chain([initial], discontinuous)
    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="authority changed",
    ):
        governed_process._validate_progress_chain([initial], changed_authority)


def test_real_parent_reload_binds_initial_and_started_progress_to_exact_events(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned:
        writer = _parent_writer(pinned.path)
        initial = _parsed_progress(
            parent_run_id=writer.parent_run_id,
            campaign_plan_digest=writer.plan.campaign_plan_digest,
            deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
            parent_root_digest=writer.current_root_digest,
        )

        loaded_initial = governed_process._verified_progress(pinned, [], initial)
        initial_root = writer.current_root_digest
        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(
                stage="provisioning",
                bindings={"accountProvisioningState": "may-have-executed"},
            ),
            NOW + timedelta(seconds=1),
        )
        started = _parsed_progress(
            sequence=2,
            previous_record_digest=initial.record_digest,
            parent_run_id=writer.parent_run_id,
            campaign_plan_digest=writer.plan.campaign_plan_digest,
            deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
            previous_parent_root_digest=initial_root,
            parent_root_digest=writer.current_root_digest,
            stage="provisioning",
            status="started",
        )

        loaded_started = governed_process._verified_progress(pinned, [initial], started)

        relabeled_initial = _parsed_progress(
            parent_run_id=writer.parent_run_id,
            campaign_plan_digest=writer.plan.campaign_plan_digest,
            deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
            parent_root_digest=initial_root,
            stage="provisioning",
            status="started",
        )
        with pytest.raises(
            governed_process.GovernedWebCampaignProcessError,
            match="active stage differs",
        ):
            governed_process._validate_loaded_progress(loaded_initial, relabeled_initial)

        relabeled_started = _parsed_progress(
            sequence=2,
            previous_record_digest=initial.record_digest,
            parent_run_id=writer.parent_run_id,
            campaign_plan_digest=writer.plan.campaign_plan_digest,
            deployment_trust_anchor_digest=writer.deployment_trust_anchor_digest,
            previous_parent_root_digest=initial_root,
            parent_root_digest=writer.current_root_digest,
            stage="provisioning",
            status="completed",
        )
        with pytest.raises(
            governed_process.GovernedWebCampaignProcessError,
            match="completed stage differs",
        ):
            governed_process._validate_loaded_progress(loaded_started, relabeled_started)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("authorized_local_lab", False, governed_process.GovernedWebCampaignProcessError),
        ("authorized_local_lab", 1, governed_process.GovernedWebCampaignProcessError),
        ("origin", "http://localhost:3000", governed_process.GovernedWebCampaignProcessError),
        ("origin", 1, governed_process.GovernedWebCampaignProcessError),
        ("selected_adapter_ref", "caller/v1", governed_process.GovernedWebCampaignProcessError),
        ("selected_adapter_ref", 1, governed_process.GovernedWebCampaignProcessError),
        ("headless", 1, TypeError),
        ("output_root", "output", TypeError),
    ],
)
async def test_invalid_public_authority_is_rejected_before_output_or_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: object,
    error: type[BaseException],
) -> None:
    output = tmp_path / "must-not-exist"
    values: dict[str, object] = {
        "origin": GOVERNED_WEB_ORIGIN,
        "output_root": output,
        "authorized_local_lab": True,
        "selected_adapter_ref": GOVERNED_WEB_ADAPTER_REF,
        "headless": True,
    }
    values[field] = value
    popen_calls = 0

    def forbidden_popen(*_args: object, **_kwargs: object) -> None:
        nonlocal popen_calls
        popen_calls += 1
        raise AssertionError("Popen must follow exact public authority validation")

    monkeypatch.setattr(governed_process.subprocess, "Popen", forbidden_popen)

    with pytest.raises(error):
        await governed_process._run_governed_local_web_campaign_process(
            origin=cast(str, values["origin"]),
            output_root=cast(Path, values["output_root"]),
            authorized_local_lab=cast(bool, values["authorized_local_lab"]),
            selected_adapter_ref=cast(
                Literal["juice-shop-local/v1"], values["selected_adapter_ref"]
            ),
            headless=cast(bool, values["headless"]),
        )

    assert popen_calls == 0
    assert not output.exists()


@pytest.mark.asyncio
async def test_lexically_ambiguous_output_is_rejected_before_popen(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "parent" / ".." / "must-not-exist"
    popen_calls = 0

    def forbidden_popen(*_args: object, **_kwargs: object) -> None:
        nonlocal popen_calls
        popen_calls += 1
        raise AssertionError("Popen must follow output-root validation")

    monkeypatch.setattr(governed_process.subprocess, "Popen", forbidden_popen)

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="isolated coordinator failed closed",
    ):
        await governed_process._run_governed_local_web_campaign_process(
            origin=GOVERNED_WEB_ORIGIN,
            output_root=output,
            authorized_local_lab=True,
            selected_adapter_ref=GOVERNED_WEB_ADAPTER_REF,
            headless=True,
        )

    assert popen_calls == 0
    assert not (tmp_path / "parent").exists()
    assert not (tmp_path / "must-not-exist").exists()


def test_child_pipe_validation_rejects_wrong_pipe_ends() -> None:
    read_fd, write_fd = os.pipe()
    try:
        governed_process._require_child_pipe(read_fd, writable=False, label="read")
        governed_process._require_child_pipe(write_fd, writable=True, label="write")
        with pytest.raises(ValueError, match="expected pipe end"):
            governed_process._require_child_pipe(read_fd, writable=True, label="read")
        with pytest.raises(ValueError, match="expected pipe end"):
            governed_process._require_child_pipe(write_fd, writable=False, label="write")
    finally:
        os.close(read_fd)
        os.close(write_fd)


def test_child_entrypoint_rejects_wrong_progress_pipe_before_execution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    progress_read, progress_write = os.pipe()
    ack_read, ack_write = os.pipe()
    monkeypatch.setenv(governed_process._COORDINATOR_MARKER, "1")
    execution_calls = 0

    def forbidden_authority() -> None:
        nonlocal execution_calls
        execution_calls += 1
        raise AssertionError("invalid child descriptors must prevent execution")

    monkeypatch.setattr(
        governed_process,
        "_create_governed_coordinator_worker_group_authority",
        forbidden_authority,
    )
    with PinnedOutputRoot.create(tmp_path / "child-output") as pinned:
        workspace_fd = os.dup(pinned.fd)
        arguments = [
            "--child",
            str(workspace_fd),
            str(progress_read),
            str(ack_read),
            str(pinned.identity.device),
            str(pinned.identity.inode),
            str(pinned.identity.uid),
            str(pinned.identity.mode),
            GOVERNED_WEB_ORIGIN,
            GOVERNED_WEB_ADAPTER_REF,
            "1",
        ]

        assert governed_process._child_main_exact(arguments) == 1

    os.close(progress_write)
    os.close(ack_write)
    assert execution_calls == 0


def test_process_receipt_is_frozen_and_computes_only_output_relative_paths(
    tmp_path: Path,
) -> None:
    validation_run_id = "run_20260915T010204Z_cafebabe"
    report_reference = (
        f"validation-runs/governed-web-validation/{validation_run_id}/validation/v1alpha1/report.md"
    )
    result = GovernedWebCampaignHistoricalResult.model_construct(
        validation_projection_run_id=validation_run_id,
        report_reference=report_reference,
        poc_manifest_reference="poc-bundle/poc/manifest.json",
        sarif_reference="exports/findings.sarif",
        delivery_readiness_reference="exports/delivery-readiness.json",
    )
    output = tmp_path / "output"
    parent_path = output / "campaign-runs" / "juice-shop-governed-local" / RUN_ID
    receipt = governed_process.GovernedWebCampaignProcessReceipt(
        output_root=output,
        parent_run_path=parent_path,
        parent_run_id=RUN_ID,
        initial_parent_root_digest=INITIAL_ROOT,
        parent_root_digest=STARTED_ROOT,
        campaign_plan_digest=PLAN_DIGEST,
        deployment_trust_anchor_digest=ANCHOR_DIGEST,
        result=result,
    )

    assert receipt.graph_path == output / "authority/governed-web.sqlite3"
    assert receipt.grant_path == (output / "authority/capability-grant-consumptions.sqlite3")
    assert receipt.validation_run_path == (
        output / "validation-runs/governed-web-validation" / validation_run_id
    )
    assert receipt.report_path == output / report_reference
    assert receipt.poc_bundle_path == output / "poc-bundle"
    assert receipt.poc_manifest_path == output / "poc-bundle/poc/manifest.json"
    assert receipt.sarif_path == output / "exports/findings.sarif"
    assert receipt.delivery_readiness_path == output / "exports/delivery-readiness.json"
    with pytest.raises(FrozenInstanceError):
        receipt.parent_run_id = "run_20260915T010205Z_badc0ffe"  # type: ignore[misc]


def test_incomplete_process_receipt_is_frozen_secret_free_and_never_completed(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    receipt = governed_process.GovernedWebCampaignIncompleteReceipt(
        output_root=output,
        parent_run_path=output / "campaign-runs" / "juice-shop-governed-local" / RUN_ID,
        parent_run_id=RUN_ID,
        initial_parent_root_digest=INITIAL_ROOT,
        parent_root_digest=STARTED_ROOT,
        campaign_plan_digest=PLAN_DIGEST,
        deployment_trust_anchor_digest=ANCHOR_DIGEST,
        last_verified_sequence=2,
        last_record_digest=MANIFEST_DIGEST,
        last_stage="provisioning",
        last_status="started",
        terminal_progress_observed=False,
    )
    error = governed_process.GovernedWebCampaignProcessError(
        "governed WEB coordinator stopped",
        incomplete_receipt=receipt,
    )

    assert error.incomplete_receipt is receipt
    assert receipt.campaign_completed is False
    assert not hasattr(receipt, "result")
    assert "secret" not in repr(receipt).casefold()
    with pytest.raises(FrozenInstanceError):
        receipt.parent_root_digest = INITIAL_ROOT  # type: ignore[misc]


def test_terminal_completed_progress_never_becomes_an_incomplete_receipt(
    tmp_path: Path,
) -> None:
    initial = _parsed_progress()
    terminal = _parsed_progress(
        sequence=2,
        previous_record_digest=initial.record_digest,
        previous_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=STARTED_ROOT,
        stage="parent-evidence",
        status="completed",
        terminal=True,
    )
    state = governed_process._SupervisorProgressState()

    with PinnedOutputRoot.create(tmp_path / "terminal-receipt") as pinned:
        initial_receipt = governed_process._candidate_incomplete_receipt(
            pinned,
            [initial],
        )
        assert initial_receipt is not None
        _commit_test_ack(state, initial_receipt, sequence=1)

        completed_receipt = governed_process._candidate_incomplete_receipt(
            pinned,
            [initial, terminal],
        )
        assert completed_receipt is None
        state.require_next_verified_ack(sequence=2, incomplete_receipt=None)

        assert state.incomplete_receipt is initial_receipt

        state.commit_verified_ack(sequence=2, incomplete_receipt=None)

    assert state.incomplete_receipt is None


def test_monitor_error_after_completed_ack_never_exposes_an_older_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "post-terminal-error"
    fake_process = object()
    terminated: list[object] = []
    initial = _parsed_progress()
    terminal = _parsed_progress(
        sequence=2,
        previous_record_digest=initial.record_digest,
        previous_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=STARTED_ROOT,
        stage="parent-evidence",
        status="completed",
        terminal=True,
    )

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return fake_process

    class CompletedThenErroredMonitor:
        def __init__(self, **kwargs: object) -> None:
            state = cast(
                governed_process._SupervisorProgressState,
                kwargs["progress_state"],
            )
            initial_receipt = _test_incomplete_receipt(
                output,
                sequence=1,
                parent_root_digest=INITIAL_ROOT,
                record_digest=initial.record_digest,
                stage="initial",
                status="prepared",
            )
            _commit_test_ack(state, initial_receipt, sequence=1)
            _commit_test_ack(state, None, sequence=2)

        def run(self) -> list[governed_process._ProgressRecord]:
            return [initial, terminal]

        def require_clean_exit(self) -> None:
            raise governed_process.GovernedWebCampaignProcessError("post-terminal monitor failure")

        def close(self) -> None:
            return None

    monkeypatch.setattr(governed_process.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(
        governed_process,
        "_ParentProcessMonitor",
        CompletedThenErroredMonitor,
    )
    monkeypatch.setattr(
        governed_process,
        "_terminate_process_group",
        terminated.append,
    )

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="post-terminal monitor failure",
    ) as raised:
        governed_process._run_parent_process(
            output_root=output,
            headless=True,
            cancellation=threading.Event(),
        )

    assert raised.value.incomplete_receipt is None
    assert terminated == [fake_process]


def test_parent_timeout_exposes_only_the_last_retained_incomplete_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "timed-out"
    fake_process = object()
    terminated: list[object] = []

    def fake_popen(*_args: object, **_kwargs: object) -> object:
        return fake_process

    class TimedOutMonitor:
        def __init__(self, **kwargs: object) -> None:
            state = cast(
                governed_process._SupervisorProgressState,
                kwargs["progress_state"],
            )
            _commit_test_ack(
                state,
                _test_incomplete_receipt(
                    output,
                    sequence=1,
                    parent_root_digest=INITIAL_ROOT,
                    record_digest=CHECKPOINT_DIGEST,
                    stage="initial",
                    status="prepared",
                ),
                sequence=1,
            )
            _commit_test_ack(
                state,
                _test_incomplete_receipt(
                    output,
                    sequence=2,
                    parent_root_digest=STARTED_ROOT,
                    record_digest=MANIFEST_DIGEST,
                    stage="provisioning",
                    status="started",
                ),
                sequence=2,
            )

        def run(self) -> list[governed_process._ProgressRecord]:
            raise TimeoutError("untrusted timeout detail")

        def close(self) -> None:
            return None

    monkeypatch.setattr(governed_process.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(governed_process, "_ParentProcessMonitor", TimedOutMonitor)
    monkeypatch.setattr(
        governed_process,
        "_terminate_process_group",
        terminated.append,
    )

    with pytest.raises(
        governed_process.GovernedWebCampaignProcessError,
        match="isolated coordinator failed closed",
    ) as raised:
        governed_process._run_parent_process(
            output_root=output,
            headless=True,
            cancellation=threading.Event(),
        )

    incomplete = raised.value.incomplete_receipt
    assert isinstance(incomplete, governed_process.GovernedWebCampaignIncompleteReceipt)
    assert incomplete.parent_root_digest == STARTED_ROOT
    assert incomplete.campaign_completed is False
    assert "untrusted timeout detail" not in str(raised.value)
    assert terminated == [fake_process]


@pytest.mark.parametrize(
    "injected",
    [
        governed_process.GovernedWebCampaignProcessError("injected failure"),
        asyncio.CancelledError(),
    ],
)
def test_parent_failure_and_cancellation_close_monitor_and_terminate_exact_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    injected: BaseException,
) -> None:
    fake_process = object()
    popen_kwargs: dict[str, object] = {}
    passed_descriptors: tuple[int, ...] = ()
    monitor_closed = False
    terminated: list[object] = []

    def fake_popen(*_args: object, **kwargs: object) -> object:
        nonlocal popen_kwargs, passed_descriptors
        popen_kwargs = kwargs
        passed_descriptors = cast(tuple[int, ...], kwargs["pass_fds"])
        return fake_process

    class FailingMonitor:
        def __init__(self, **kwargs: object) -> None:
            assert kwargs["process"] is fake_process

        def run(self) -> list[governed_process._ProgressRecord]:
            raise injected

        def close(self) -> None:
            nonlocal monitor_closed
            monitor_closed = True

    monkeypatch.setattr(governed_process.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(governed_process, "_ParentProcessMonitor", FailingMonitor)
    monkeypatch.setattr(
        governed_process,
        "_terminate_process_group",
        terminated.append,
    )

    with pytest.raises(type(injected)):
        governed_process._run_parent_process(
            output_root=tmp_path / f"failed-{type(injected).__name__}",
            headless=True,
            cancellation=threading.Event(),
        )

    assert popen_kwargs["start_new_session"] is True
    assert popen_kwargs["close_fds"] is True
    assert popen_kwargs["stdin"] is subprocess.DEVNULL
    assert "shell" not in popen_kwargs
    assert monitor_closed
    assert terminated == [fake_process]
    for descriptor in passed_descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)


@pytest.mark.asyncio
async def test_async_cancellation_waits_for_supervisor_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = threading.Event()
    cleanup_finished = threading.Event()

    def wait_for_cancellation(
        *,
        output_root: Path,
        headless: bool,
        cancellation: threading.Event,
        progress_state: governed_process._SupervisorProgressState,
    ) -> None:
        assert output_root == tmp_path / "cancelled"
        assert headless is True
        _commit_test_ack(
            progress_state,
            _test_incomplete_receipt(
                output_root,
                sequence=1,
                parent_root_digest=INITIAL_ROOT,
                record_digest=CHECKPOINT_DIGEST,
                stage="initial",
                status="prepared",
            ),
            sequence=1,
        )
        _commit_test_ack(
            progress_state,
            _test_incomplete_receipt(
                output_root,
                sequence=2,
                parent_root_digest=STARTED_ROOT,
                record_digest=MANIFEST_DIGEST,
                stage="provisioning",
                status="started",
            ),
            sequence=2,
        )
        started.set()
        assert cancellation.wait(timeout=2)
        cleanup_finished.set()
        raise asyncio.CancelledError

    monkeypatch.setattr(
        governed_process,
        "_run_parent_process",
        wait_for_cancellation,
    )
    task = asyncio.create_task(
        governed_process._run_governed_local_web_campaign_process(
            origin=GOVERNED_WEB_ORIGIN,
            output_root=tmp_path / "cancelled",
            authorized_local_lab=True,
            selected_adapter_ref=GOVERNED_WEB_ADAPTER_REF,
            headless=True,
        )
    )
    assert await asyncio.to_thread(started.wait, 1)

    task.cancel()

    with pytest.raises(governed_process.GovernedWebCampaignProcessCancelled) as cancelled:
        await task
    assert cleanup_finished.is_set()
    incomplete = getattr(cancelled.value, "incomplete_receipt", None)
    assert isinstance(incomplete, governed_process.GovernedWebCampaignIncompleteReceipt)
    assert incomplete.parent_root_digest == STARTED_ROOT
    assert incomplete.campaign_completed is False


def test_process_group_termination_is_bounded_to_the_selected_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected_pid = 4242
    unrelated_pid = 5252
    signaled_groups: list[tuple[int, int]] = []

    class SelectedProcess:
        pid = selected_pid

        def poll(self) -> int:
            return -15

    def capture_signal(process_group_id: int, sent_signal: int) -> None:
        assert process_group_id != unrelated_pid
        signaled_groups.append((process_group_id, sent_signal))

    monkeypatch.setattr(governed_process.os, "killpg", capture_signal)
    monkeypatch.setattr(governed_process, "_process_group_exists", lambda _pid: False)

    governed_process._terminate_process_group(cast(subprocess.Popen[bytes], SelectedProcess()))

    assert len(signaled_groups) == 1
    assert signaled_groups[0][0] == selected_pid
