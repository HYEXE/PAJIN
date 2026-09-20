from __future__ import annotations

import copy
import json
import sqlite3
import stat
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest

import pajin.runtime.pinned_sqlite as pinned_sqlite
import pajin.web_assessment.governed_campaign_evidence as campaign_evidence
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.pinned_sqlite import PinnedSQLiteCheckpoint
from pajin.runtime.pinned_workspace import PinnedOutputRoot
from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.web_assessment import governed
from pajin.web_assessment.governed_adapter_profile import (
    ResolvedGovernedWebAdapterProfile,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_campaign_evidence import (
    GOVERNED_WEB_ORIGIN,
    GovernedWebCampaignEvidenceError,
    GovernedWebCampaignPlan,
    GovernedWebCampaignPlannedRuns,
    GovernedWebCampaignStageIntent,
    GovernedWebCampaignStageObservation,
    VerifiedGovernedWebIncompleteCampaign,
    begin_governed_web_campaign_parent,
    load_verified_governed_web_completed_campaign_evidence,
    load_verified_governed_web_incomplete_campaign_evidence,
)
from pajin.web_assessment.governed_models import (
    WebAssessmentCapabilityGrantConsumptionReceipt,
    WebAssessmentCapabilityGrantConsumptionStore,
    WebAssessmentCapabilityGrantReservation,
    WebAssessmentSigningRole,
    _governed_web_grant_checkpoint_metadata,
)

NOW = datetime(2026, 9, 14, 4, 0, tzinfo=UTC)


def _deployment_profile() -> ResolvedGovernedWebAdapterProfile:
    return production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=governed.GOVERNED_JUICE_SHOP_ADAPTER_REF,
        origin=GOVERNED_WEB_ORIGIN,
    )


def test_public_safe_scan_distinguishes_recipe_descriptors_from_secrets() -> None:
    campaign_evidence._require_public_safe(
        {
            "plan": {
                "login": {
                    "password_selector": "#password",
                    "password_field": "password",
                },
                "registration": {
                    "password_field": "password",
                    "repeat_password_field": "passwordRepeat",
                },
            }
        },
        label="public recipe",
    )

    with pytest.raises(ValueError, match="forbidden private material"):
        campaign_evidence._require_public_safe(
            {"password": "not-a-real-secret"},
            label="unsafe payload",
        )
    with pytest.raises(ValueError, match="forbidden private material"):
        campaign_evidence._require_public_safe(
            {"privateKey": "not-a-real-key"},
            label="unsafe payload",
        )


def _planned_runs() -> GovernedWebCampaignPlannedRuns:
    run_ids = tuple(RunStore.new_run_id() for _ in range(6))
    return GovernedWebCampaignPlannedRuns(
        parentRunId=run_ids[0],
        sourceBrowserRunId=run_ids[1],
        validationBrowserRunId=run_ids[2],
        sourceGatewayRunId=run_ids[3],
        validationGatewayRunId=run_ids[4],
        validationProjectionRunId=run_ids[5],
    )


def _writer(tmp_path: Path) -> campaign_evidence.GovernedWebCampaignParentWriter:
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=_deployment_profile(),
        now=NOW,
    )
    return begin_governed_web_campaign_parent(
        tmp_path,
        planned_runs=_planned_runs(),
        trust_material=trust.public_trust_material,
        started_at=NOW,
        signer_not_after=NOW + timedelta(hours=1),
    )


def _load_incomplete(
    writer: campaign_evidence.GovernedWebCampaignParentWriter,
    *,
    expected_root: str | None = None,
) -> VerifiedGovernedWebIncompleteCampaign:
    return load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_parent_root_digest=(
            writer.current_root_digest if expected_root is None else expected_root
        ),
        expected_deployment_trust_anchor_digest=(
            writer.deployment_trust_anchor_digest
        ),
    )


def test_parent_initial_seal_loads_only_historical_interrupted_evidence(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)

    loaded = _load_incomplete(writer)

    assert loaded.terminal == "interrupted"
    assert loaded.completed_stages == ()
    assert loaded.active_stage is None
    assert loaded.incomplete.failure_stage == "provisioning"
    assert loaded.incomplete.account_provisioning_state == "not-started"
    assert loaded.parent_root_digest == writer.current_root_digest
    assert loaded.relative_references["sourceBrowser"].startswith(
        "worker-runs/juice-shop-web-assessment/"
    )
    assert verify_run_integrity(writer.parent_run_path).seal_count == 1


def test_stage_journal_retains_account_uncertainty_and_observed_completion(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    writer.begin_stage(
        "provisioning",
        GovernedWebCampaignStageIntent(
            stage="provisioning",
            bindings={"accountProvisioningState": "may-have-executed"},
        ),
        NOW + timedelta(seconds=1),
    )

    started = _load_incomplete(writer)

    assert started.active_stage == "provisioning"
    assert started.active_intent is not None
    assert started.active_intent.bindings["accountProvisioningState"] == (
        "may-have-executed"
    )
    assert started.incomplete.account_provisioning_state == "may-have-executed"

    writer.complete_stage(
        "provisioning",
        GovernedWebCampaignStageObservation(
            stage="provisioning",
            observed={"accountProvisioningState": "confirmed-retained"},
        ),
        NOW + timedelta(seconds=2),
    )
    completed = _load_incomplete(writer)

    assert completed.completed_stages == ("provisioning",)
    assert completed.active_stage is None
    assert completed.incomplete.failure_stage == "source-gateway"
    assert completed.incomplete.account_provisioning_state == "confirmed-retained"
    assert completed.observations[-1].observed["accountProvisioningState"] == (
        "confirmed-retained"
    )


def test_active_stage_seals_signed_database_checkpoint_and_returns_ack_root(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    writer.begin_stage(
        "provisioning",
        GovernedWebCampaignStageIntent(stage="provisioning"),
        NOW + timedelta(seconds=1),
    )
    previous_root = writer.current_root_digest
    database_digest = "a" * 64
    manifest_digest = "b" * 64
    checkpoint = PinnedSQLiteCheckpoint(
        ordinal=1,
        database_reference=(
            "authority/.governed-web.sqlite3.checkpoint-00000001-"
            f"{database_digest}.sqlite3"
        ),
        database_sha256=database_digest,
        database_size=4096,
        manifest_reference=(
            "authority/.governed-web.sqlite3.checkpoint-00000001-"
            f"{manifest_digest}.json"
        ),
        manifest_digest=manifest_digest,
        manifest_sha256="c" * 64,
        manifest_size=512,
        previous_manifest_digest=None,
        state_json=b'{"eventCount":0}',
    )

    ack_root = writer.record_database_checkpoint(
        stage="provisioning",
        store_kind="governed-web-graph",
        checkpoint=checkpoint,
        occurred_at=NOW + timedelta(seconds=2),
    )

    recorded = writer.latest_database_checkpoint
    loaded = _load_incomplete(writer)
    assert ack_root == writer.current_root_digest
    assert ack_root != previous_root
    assert recorded is not None
    assert recorded.previous_parent_root_digest == previous_root
    assert recorded.manifest_digest == manifest_digest
    assert loaded.active_stage == "provisioning"
    assert loaded.events[-1].event_type == "web.governed.database-checkpoint"
    assert verify_run_integrity(writer.parent_run_path).root_digest == ack_root
    with pytest.raises(ValueError, match="external ACK"):
        writer._require_database_checkpoint_external_ack(
            path="authority/governed-web.sqlite3",
            store_kind="governed-web-graph",
            checkpoint=checkpoint,
        )
    writer._acknowledge_external_progress(parent_root_digest=ack_root)
    writer._require_database_checkpoint_external_ack(
        path="authority/governed-web.sqlite3",
        store_kind="governed-web-graph",
        checkpoint=checkpoint,
    )
    grant_database_digest = "d" * 64
    grant_manifest_digest = "e" * 64
    grant_checkpoint = PinnedSQLiteCheckpoint(
        ordinal=1,
        database_reference=(
            "authority/.capability-grant-consumptions.sqlite3.checkpoint-00000001-"
            f"{grant_database_digest}.sqlite3"
        ),
        database_sha256=grant_database_digest,
        database_size=4096,
        manifest_reference=(
            "authority/.capability-grant-consumptions.sqlite3.checkpoint-00000001-"
            f"{grant_manifest_digest}.json"
        ),
        manifest_digest=grant_manifest_digest,
        manifest_sha256="f" * 64,
        manifest_size=512,
        previous_manifest_digest=None,
        state_json=b'{"consumptions":0,"reservations":0}',
    )
    grant_root = writer.record_database_checkpoint(
        stage="provisioning",
        store_kind="governed-web-grant",
        checkpoint=grant_checkpoint,
        occurred_at=NOW + timedelta(seconds=3),
    )
    writer._acknowledge_external_progress(parent_root_digest=grant_root)
    writer._require_database_checkpoint_external_ack(
        path="authority/governed-web.sqlite3",
        store_kind="governed-web-graph",
        checkpoint=checkpoint,
    )
    writer._require_database_checkpoint_external_ack(
        path="authority/capability-grant-consumptions.sqlite3",
        store_kind="governed-web-grant",
        checkpoint=grant_checkpoint,
    )
    with pytest.raises(ValueError, match="exact external ACK"):
        writer._require_database_checkpoint_external_ack(
            path="authority/governed-web.sqlite3",
            store_kind="governed-web-graph",
            checkpoint=replace(checkpoint, state_json=b'{"eventCount":1}'),
        )


def test_database_fresh_authority_requires_current_external_ack_and_is_one_use(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned, pinned.activate():
        writer = _writer(Path("."))
        graph_path = Path("authority/governed-web.sqlite3")

        with pytest.raises(ValueError, match="external ACK"):
            writer.issue_database_fresh_authority(
                graph_path,
                store_kind="governed-web-graph",
            )

        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(stage="provisioning"),
            NOW + timedelta(seconds=1),
        )
        writer._acknowledge_external_progress(
            parent_root_digest=writer.current_root_digest,
        )
        authority = writer.issue_database_fresh_authority(
            graph_path,
            store_kind="governed-web-graph",
        )
        with pytest.raises(ValueError, match="external ACK"):
            writer.issue_database_fresh_authority(
                graph_path,
                store_kind="governed-web-graph",
            )

        def observe(checkpoint: PinnedSQLiteCheckpoint) -> None:
            root = writer.record_database_checkpoint(
                stage="provisioning",
                store_kind="governed-web-graph",
                checkpoint=checkpoint,
                occurred_at=NOW + timedelta(seconds=2 + checkpoint.ordinal),
            )
            writer._acknowledge_external_progress(parent_root_digest=root)

        _store, database = SQLiteGraphStore.create_governed_in_memory(
            graph_path,
            campaign_id=writer.plan.campaign_id,
            fresh_authority=authority,
            checkpoint_observer=observe,
        )
        database.close()


def test_strict_database_reload_retains_verified_bytes_after_path_swap(
    tmp_path: Path,
) -> None:
    output = tmp_path / "output"
    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        writer = _writer(Path("."))
        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(stage="provisioning"),
            NOW + timedelta(seconds=1),
        )
        writer._acknowledge_external_progress(
            parent_root_digest=writer.current_root_digest,
        )
        authority = writer.issue_database_fresh_authority(
            Path("authority/governed-web.sqlite3"),
            store_kind="governed-web-graph",
        )
        parent_checkpoints: list[
            campaign_evidence.GovernedWebCampaignDatabaseCheckpoint
        ] = []

        def observe(checkpoint: PinnedSQLiteCheckpoint) -> None:
            root = writer.record_database_checkpoint(
                stage="provisioning",
                store_kind="governed-web-graph",
                checkpoint=checkpoint,
                occurred_at=NOW + timedelta(seconds=2 + checkpoint.ordinal),
            )
            recorded = writer.latest_database_checkpoint
            assert recorded is not None
            parent_checkpoints.append(recorded)
            writer._acknowledge_external_progress(parent_root_digest=root)

        _store, database = SQLiteGraphStore.create_governed_in_memory(
            Path("authority/governed-web.sqlite3"),
            campaign_id=writer.plan.campaign_id,
            fresh_authority=authority,
            checkpoint_observer=observe,
        )
        try:
            enrollment = database.enrollment_publication()
            publication = database.freeze_and_publish()
        finally:
            database.close()

        verified = campaign_evidence._verified_database_checkpoint_chain(
            output_root=output,
            store_kind="governed-web-graph",
            final_reference=publication.reference,
            final_sha256=publication.sha256,
            schema_digest=campaign_evidence._GRAPH_SCHEMA_DIGEST,
            max_bytes=campaign_evidence._MAX_GRAPH_BYTES,
            enrollment=campaign_evidence.GovernedWebCampaignDatabaseEnrollment(
                storeKind="governed-web-graph",
                reference=enrollment.reference,
                sha256=enrollment.sha256,
                size=enrollment.size,
            ),
            database_checkpoints=tuple(parent_checkpoints),
        )
        final_path = Path(publication.reference)
        parked_path = final_path.with_name(f"{final_path.name}.parked")
        final_path.rename(parked_path)
        final_path.write_bytes(b"attacker replacement")

        assert sha256(verified.database_bytes).hexdigest() == publication.sha256
        assert verified.database_bytes == parked_path.read_bytes()
        assert verified.database_bytes != final_path.read_bytes()

        final_path.unlink()
        parked_path.rename(final_path)
        original_enrollment_path = Path(enrollment.reference)
        original_enrollment = json.loads(original_enrollment_path.read_bytes())
        parked_authority = Path("authority-original")
        Path("authority").rename(parked_authority)
        Path("authority").mkdir(mode=0o700)
        for retained in parked_authority.iterdir():
            replacement = Path("authority") / retained.name
            replacement.write_bytes(retained.read_bytes())
            replacement.chmod(stat.S_IMODE(retained.stat().st_mode))
        parent_identity = pinned_sqlite._identity(Path("authority").stat())
        original_enrollment["authorityParentIdentity"] = {
            "device": parent_identity.device,
            "inode": parent_identity.inode,
            "uid": parent_identity.uid,
            "mode": stat.S_IMODE(parent_identity.mode),
        }
        material = {
            key: value
            for key, value in original_enrollment.items()
            if key != "enrollmentDigest"
        }
        original_enrollment["enrollmentDigest"] = sha256(
            pinned_sqlite._ENROLLMENT_DIGEST_DOMAIN
            + pinned_sqlite._canonical_json(material)
        ).hexdigest()
        forged_enrollment_reference = pinned_sqlite._governed_enrollment_name(
            path=publication.reference,
            store_kind="governed-web-graph",
            leaf=Path(publication.reference).name,
            parent_identity=parent_identity,
        )
        original_enrollment_path.unlink()
        forged_enrollment_path = Path(forged_enrollment_reference)
        forged_enrollment_path.write_bytes(
            pinned_sqlite._canonical_json(original_enrollment) + b"\n"
        )
        forged_enrollment_path.chmod(0o600)

        with pytest.raises(
            GovernedWebCampaignEvidenceError,
            match="failed strict reload",
        ):
            campaign_evidence._verified_database_checkpoint_chain(
                output_root=output,
                store_kind="governed-web-graph",
                final_reference=publication.reference,
                final_sha256=publication.sha256,
                schema_digest=campaign_evidence._GRAPH_SCHEMA_DIGEST,
                max_bytes=campaign_evidence._MAX_GRAPH_BYTES,
                enrollment=campaign_evidence.GovernedWebCampaignDatabaseEnrollment(
                    storeKind="governed-web-graph",
                    reference=enrollment.reference,
                    sha256=enrollment.sha256,
                    size=enrollment.size,
                ),
                database_checkpoints=tuple(parent_checkpoints),
            )


def test_grant_checkpoint_metadata_and_strict_reload_bind_exact_rows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign_id = campaign_evidence.GOVERNED_WEB_CAMPAIGN_ID
    database_path = tmp_path / "grant-consumptions.sqlite3"
    WebAssessmentCapabilityGrantConsumptionStore(
        database_path,
        campaign_id=campaign_id,
    )

    def record_pair(
        role: str,
    ) -> tuple[
        WebAssessmentCapabilityGrantReservation,
        WebAssessmentCapabilityGrantConsumptionReceipt,
    ]:
        def digest(label: str) -> str:
            return sha256(f"{role}:{label}".encode()).hexdigest()

        reservation = WebAssessmentCapabilityGrantReservation(
            campaignId=campaign_id,
            grantAuthorityDigest=digest("authority"),
            capabilityGrantId=f"grant:web:governed:{role}:1",
            capabilityGrantDigest=digest("grant"),
            requestId=f"request:web:governed:{role}:1",
            requestDigest=digest("request"),
            permitId=f"permit:web:governed:{role}:1",
            permitDigest=digest("permit"),
            approvalReceiptId=f"approval:web:governed:{role}:1",
            approvalReceiptDigest=digest("approval"),
            reservedAt=NOW,
        )
        receipt = WebAssessmentCapabilityGrantConsumptionReceipt(
            reservationId=reservation.reservation_id,
            reservationDigest=reservation.reservation_digest,
            campaignId=campaign_id,
            grantAuthorityDigest=reservation.grant_authority_digest,
            capabilityGrantId=reservation.capability_grant_id,
            capabilityGrantDigest=reservation.capability_grant_digest,
            requestId=reservation.request_id,
            requestDigest=reservation.request_digest,
            permitId=reservation.permit_id,
            permitDigest=reservation.permit_digest,
            approvalReceiptId=reservation.approval_receipt_id,
            approvalReceiptDigest=reservation.approval_receipt_digest,
            consumedAt=NOW + timedelta(seconds=1),
        )
        return reservation, receipt

    source_reservation, source_receipt = record_pair("source")
    validation_reservation, validation_receipt = record_pair("validation")
    with sqlite3.connect(database_path) as connection:
        for reservation in (source_reservation, validation_reservation):
            connection.execute(
                """
                INSERT INTO web_capability_grant_reservations (
                    reservation_id, reservation_digest, campaign_id,
                    capability_grant_id, request_id, permit_id,
                    approval_receipt_id, reservation_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    reservation.reservation_id,
                    reservation.reservation_digest,
                    reservation.campaign_id,
                    reservation.capability_grant_id,
                    reservation.request_id,
                    reservation.permit_id,
                    reservation.approval_receipt_id,
                    reservation.model_dump_json(by_alias=True),
                ),
            )
        for receipt in (source_receipt, validation_receipt):
            connection.execute(
                """
                INSERT INTO web_capability_grant_consumptions (
                    receipt_id, receipt_digest, reservation_id, campaign_id,
                    capability_grant_id, request_id, permit_id,
                    approval_receipt_id, receipt_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt.receipt_id,
                    receipt.receipt_digest,
                    receipt.reservation_id,
                    receipt.campaign_id,
                    receipt.capability_grant_id,
                    receipt.request_id,
                    receipt.permit_id,
                    receipt.approval_receipt_id,
                    receipt.model_dump_json(by_alias=True),
                ),
            )
        checkpoint_state = _governed_web_grant_checkpoint_metadata(connection)

    assert isinstance(checkpoint_state["reservations"], list)
    assert isinstance(checkpoint_state["consumptions"], list)
    assert {
        "reservationId",
        "reservationDigest",
        "capabilityGrantId",
        "requestId",
        "permitId",
        "approvalReceiptId",
    } == set(checkpoint_state["reservations"][0])
    assert {
        "receiptId",
        "receiptDigest",
        "reservationId",
        "capabilityGrantId",
        "requestId",
        "permitId",
        "approvalReceiptId",
    } == set(checkpoint_state["consumptions"][0])

    verified = SimpleNamespace(
        database_bytes=database_path.read_bytes(),
        checkpoints=(
            SimpleNamespace(
                state_json=json.dumps(
                    checkpoint_state,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ),
        ),
    )
    monkeypatch.setattr(
        campaign_evidence,
        "_verified_database_checkpoint_chain",
        lambda **_kwargs: verified,
    )
    models = SimpleNamespace(
        source=SimpleNamespace(grant_consumption_receipt=source_receipt),
        validation=SimpleNamespace(grant_consumption_receipt=validation_receipt),
    )
    evidence = SimpleNamespace(
        grant_database_sha256=sha256(verified.database_bytes).hexdigest(),
        grant_database_enrollment=object(),
    )

    campaign_evidence._verify_grant_database(
        output_root=tmp_path,
        models=models,
        evidence=evidence,
        database_checkpoints=(),
    )

    forged_state = copy.deepcopy(checkpoint_state)
    forged_state["reservations"][0]["requestId"] = "request:web:forged:1"
    verified.checkpoints = (
        SimpleNamespace(
            state_json=json.dumps(
                forged_state,
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
        ),
    )
    with pytest.raises(
        GovernedWebCampaignEvidenceError,
        match="Grant checkpoint state differs",
    ):
        campaign_evidence._verify_grant_database(
            output_root=tmp_path,
            models=models,
            evidence=evidence,
            database_checkpoints=(),
        )


def test_graph_strict_reload_configures_deserialized_verifier_connection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "governed-web.sqlite3"
    SQLiteGraphStore(
        database_path,
        campaign_id=campaign_evidence.GOVERNED_WEB_CAMPAIGN_ID,
    )
    verified = SimpleNamespace(database_bytes=database_path.read_bytes())
    monkeypatch.setattr(
        campaign_evidence,
        "_verified_database_checkpoint_chain",
        lambda **_kwargs: verified,
    )

    observed: dict[str, int] = {}
    validate_schema = campaign_evidence._validate_schema

    def validate_with_policy(
        connection: sqlite3.Connection,
        *,
        campaign_id: str,
    ) -> None:
        observed.update(
            foreign_keys=int(connection.execute("PRAGMA foreign_keys").fetchone()[0]),
            query_only=int(connection.execute("PRAGMA query_only").fetchone()[0]),
            trusted_schema=int(connection.execute("PRAGMA trusted_schema").fetchone()[0]),
        )
        validate_schema(connection, campaign_id=campaign_id)
        observed["schema_validated"] = 1

    class SchemaValidated(BaseException):
        pass

    def stop_after_schema(*_args: object, **_kwargs: object) -> None:
        raise SchemaValidated

    monkeypatch.setattr(campaign_evidence, "_validate_schema", validate_with_policy)
    monkeypatch.setattr(campaign_evidence, "_events_from_connection", stop_after_schema)
    evidence = SimpleNamespace(
        graph_database_sha256=sha256(verified.database_bytes).hexdigest(),
        graph_database_enrollment=object(),
    )

    with pytest.raises(SchemaValidated):
        campaign_evidence._verify_graph_database(
            output_root=tmp_path,
            models=object(),
            evidence=evidence,
            result=object(),
            database_checkpoints=(),
        )

    assert observed == {
        "foreign_keys": 1,
        "query_only": 1,
        "trusted_schema": 0,
        "schema_validated": 1,
    }


def test_database_fresh_authority_rejects_parent_root_advanced_after_issue(
    tmp_path: Path,
) -> None:
    with PinnedOutputRoot.create(tmp_path / "output") as pinned, pinned.activate():
        writer = _writer(Path("."))
        graph_path = Path("authority/governed-web.sqlite3")
        writer._acknowledge_external_progress(
            parent_root_digest=writer.current_root_digest,
        )
        authority = writer.issue_database_fresh_authority(
            graph_path,
            store_kind="governed-web-graph",
        )
        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(stage="provisioning"),
            NOW + timedelta(seconds=1),
        )

        with pytest.raises(RuntimeError, match="sealed-parent fresh authority"):
            SQLiteGraphStore.create_governed_in_memory(
                graph_path,
                campaign_id=writer.plan.campaign_id,
                fresh_authority=authority,
                checkpoint_observer=lambda _checkpoint: None,
            )


def test_rootless_loader_exposes_only_initial_plan_not_unkeyed_progression(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    writer.begin_stage(
        "provisioning",
        GovernedWebCampaignStageIntent(
            stage="provisioning",
            bindings={"accountProvisioningState": "may-have-executed"},
        ),
        NOW + timedelta(seconds=1),
    )
    writer.complete_stage(
        "provisioning",
        GovernedWebCampaignStageObservation(
            stage="provisioning",
            observed={"accountProvisioningState": "confirmed-retained"},
        ),
        NOW + timedelta(seconds=2),
    )

    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(
            writer.deployment_trust_anchor_digest
        ),
    )

    assert loaded.completed_stages == ()
    assert loaded.active_stage is None
    assert loaded.incomplete.account_provisioning_state == "not-started"
    assert loaded.parent_root_digest == loaded.seals[0].root_digest
    assert loaded.has_unsealed_tail


def test_loader_selects_exact_observed_older_seal_and_marks_later_tail(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    observed_initial_root = writer.current_root_digest
    writer.begin_stage(
        "provisioning",
        GovernedWebCampaignStageIntent(
            stage="provisioning",
            bindings={"accountProvisioningState": "may-have-executed"},
        ),
        NOW + timedelta(seconds=1),
    )

    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_parent_root_digest=observed_initial_root,
        expected_deployment_trust_anchor_digest=(
            writer.deployment_trust_anchor_digest
        ),
    )

    assert loaded.parent_root_digest == observed_initial_root
    assert len(loaded.seals) == 1
    assert loaded.active_stage is None
    assert loaded.completed_stages == ()
    assert loaded.has_unsealed_tail


@pytest.mark.parametrize(
    ("journal", "tail"),
    [
        ("events.jsonl", b"\n"),
        ("events.jsonl", b"x" * (16 * 1024 * 1024 + 1)),
        ("run-integrity.jsonl", b"\n"),
        ("run-integrity.jsonl", b"x" * (16 * 1024 * 1024 + 1)),
    ],
)
def test_loader_stops_at_observed_root_before_arbitrary_bounded_tail(
    tmp_path: Path,
    journal: str,
    tail: bytes,
) -> None:
    writer = _writer(tmp_path)
    observed_root = writer.current_root_digest
    with (writer.parent_run_path / journal).open("ab") as stream:
        stream.write(tail)

    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_parent_root_digest=observed_root,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_deployment_trust_anchor_digest=(
            writer.deployment_trust_anchor_digest
        ),
    )

    assert loaded.parent_root_digest == observed_root
    assert loaded.has_unsealed_tail


def test_rootless_loader_rejects_changed_child_ids_under_copied_anchor(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    original = writer.plan
    changed_runs = original.planned_runs.model_copy(
        update={"source_browser_run_id": RunStore.new_run_id()}
    )
    forged_raw = original.model_dump(mode="json", by_alias=True)
    forged_raw["plannedRuns"] = changed_runs.model_dump(mode="json", by_alias=True)
    forged_raw["campaignPlanDigest"] = ""
    forged = GovernedWebCampaignPlan.model_validate(forged_raw)
    forged_store = RunStore.create(
        tmp_path / "forged-parent-runs",
        campaign_evidence.GOVERNED_WEB_CAMPAIGN_ID,
        run_id=writer.parent_run_id,
    )
    forged_store.write_json_create_only(
        "campaign-plan.json",
        forged.model_dump(mode="json", by_alias=True),
    )
    forged_store.append_event(
        "campaign.started",
        campaign_evidence._expected_started_event_payload(forged),
        occurred_at=NOW,
    )
    forged_store.seal()

    with pytest.raises(GovernedWebCampaignEvidenceError, match="Plan signature"):
        load_verified_governed_web_incomplete_campaign_evidence(
            forged_store.path,
            expected_parent_run_id=writer.parent_run_id,
            expected_campaign_plan_digest=forged.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=(
                writer.deployment_trust_anchor_digest
            ),
        )


@pytest.mark.parametrize("offset", [timedelta(days=-1), timedelta(days=365)])
def test_loader_rejects_started_event_time_not_bound_to_signed_plan(
    tmp_path: Path,
    offset: timedelta,
) -> None:
    writer = _writer(tmp_path)
    plan = writer.plan
    forged_store = RunStore.create(
        tmp_path / "forged-time-parent-runs",
        campaign_evidence.GOVERNED_WEB_CAMPAIGN_ID,
        run_id=writer.parent_run_id,
    )
    forged_store.write_json_create_only(
        "campaign-plan.json",
        plan.model_dump(mode="json", by_alias=True),
    )
    forged_store.append_event(
        "campaign.started",
        campaign_evidence._expected_started_event_payload(plan),
        occurred_at=plan.signed_at + offset,
    )
    forged_root = forged_store.seal().root_digest

    with pytest.raises(GovernedWebCampaignEvidenceError, match="exact Plan event"):
        load_verified_governed_web_incomplete_campaign_evidence(
            forged_store.path,
            expected_parent_run_id=writer.parent_run_id,
            expected_parent_root_digest=forged_root,
            expected_campaign_plan_digest=plan.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=(
                writer.deployment_trust_anchor_digest
            ),
        )


def test_trust_bundle_rejects_noncanonical_public_key_alias(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    raw = writer.plan.trust_bundle.model_dump(mode="json", by_alias=True)
    encoded = raw["indexSigningKey"]["publicKeyBase64url"]
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    position = alphabet.index(encoded[-1])
    raw["indexSigningKey"]["publicKeyBase64url"] = (
        encoded[:-1] + alphabet[position ^ 1]
    )

    with pytest.raises(ValueError, match="wrong byte length"):
        campaign_evidence.GovernedWebCampaignTrustBundle.model_validate(raw)


@pytest.mark.parametrize(
    ("fault_point", "expected_active", "expected_seals"),
    [
        ("artifact-created", None, 1),
        ("event-appended", None, 1),
        ("seal-appended", "provisioning", 2),
    ],
)
def test_loader_returns_only_latest_complete_seal_at_checkpoint_faults(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
    expected_active: str | None,
    expected_seals: int,
) -> None:
    writer = _writer(tmp_path)

    class SimulatedCrash(BaseException):
        pass

    def crash(point: str, _artifact_path: str) -> None:
        if point == fault_point:
            raise SimulatedCrash

    monkeypatch.setattr(campaign_evidence, "_campaign_parent_checkpoint_fault", crash)
    with pytest.raises(SimulatedCrash):
        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(
                stage="provisioning",
                bindings={"accountProvisioningState": "may-have-executed"},
            ),
            NOW + timedelta(seconds=1),
        )

    current = verify_run_integrity(writer.parent_run_path) if expected_seals == 2 else None
    expected_root = current.root_digest if current is not None else writer.current_root_digest
    loaded = load_verified_governed_web_incomplete_campaign_evidence(
        writer.parent_run_path,
        expected_parent_run_id=writer.parent_run_id,
        expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
        expected_parent_root_digest=expected_root,
        expected_deployment_trust_anchor_digest=(
            writer.deployment_trust_anchor_digest
        ),
    )

    assert loaded.active_stage == expected_active
    assert len(loaded.seals) == expected_seals
    assert loaded.has_unsealed_tail is (expected_seals == 1)


@pytest.mark.parametrize("fault_point", ["artifact-created", "event-appended"])
def test_failure_seals_a_well_formed_checkpoint_tail_without_promoting_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    fault_point: str,
) -> None:
    writer = _writer(tmp_path)

    class SimulatedError(RuntimeError):
        pass

    def fail_once(point: str, _artifact_path: str) -> None:
        if point == fault_point:
            raise SimulatedError

    monkeypatch.setattr(campaign_evidence, "_campaign_parent_checkpoint_fault", fail_once)
    with pytest.raises(SimulatedError):
        writer.begin_stage(
            "provisioning",
            GovernedWebCampaignStageIntent(
                stage="provisioning",
                bindings={"accountProvisioningState": "may-have-executed"},
            ),
            NOW + timedelta(seconds=1),
        )
    monkeypatch.setattr(
        campaign_evidence,
        "_campaign_parent_checkpoint_fault",
        lambda _point, _path: None,
    )

    writer.fail("simulated-stage-failure", NOW + timedelta(seconds=2))
    loaded = _load_incomplete(writer)

    assert loaded.terminal == "failed"
    assert loaded.incomplete.failure_type == "simulated-stage-failure"
    assert loaded.completed_stages == ()
    assert loaded.active_stage == (
        "provisioning" if fault_point == "event-appended" else None
    )
    assert not loaded.has_unsealed_tail


def test_unsealed_completion_event_never_loads_as_complete(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    RunStore(writer.parent_run_id, writer.parent_run_path).append_event(
        "campaign.completed",
        {},
        occurred_at=NOW + timedelta(seconds=1),
    )

    loaded = _load_incomplete(writer)

    assert loaded.terminal == "interrupted"
    assert loaded.has_unsealed_tail
    with pytest.raises(GovernedWebCampaignEvidenceError, match="not a completed"):
        load_verified_governed_web_completed_campaign_evidence(
            writer.parent_run_path,
            expected_parent_run_id=writer.parent_run_id,
            expected_campaign_plan_digest=writer.plan.campaign_plan_digest,
            expected_parent_root_digest=writer.current_root_digest,
            expected_deployment_trust_anchor_digest=(
                writer.deployment_trust_anchor_digest
            ),
        )


def test_partial_event_record_is_ignored_only_as_an_unsealed_crash_tail(
    tmp_path: Path,
) -> None:
    writer = _writer(tmp_path)
    with (writer.parent_run_path / "events.jsonl").open("ab") as stream:
        stream.write(b'{"incomplete"')

    loaded = _load_incomplete(writer)

    assert loaded.terminal == "interrupted"
    assert loaded.has_unsealed_tail
    with pytest.raises(
        GovernedWebCampaignEvidenceError,
        match="malformed partial event tail",
    ):
        writer.fail("simulated-stage-failure", NOW + timedelta(seconds=1))


def test_unknown_unsealed_artifact_is_reported_but_never_surfaced(tmp_path: Path) -> None:
    writer = _writer(tmp_path)
    (writer.parent_run_path / "attacker-unknown.json").write_text(
        "{}\n",
        encoding="utf-8",
    )

    loaded = _load_incomplete(writer)

    assert loaded.has_unsealed_tail
    assert "attacker-unknown.json" not in loaded.relative_references.values()


def test_trust_anchor_rejects_reused_public_key_under_distinct_identity(
    tmp_path: Path,
) -> None:
    trust = governed._prepare_governed_web_ephemeral_trust(
        profile=_deployment_profile(),
        now=NOW,
    ).public_trust_material
    reused_account = trust.adapter_key.model_copy(
        update={
            "key_id": "web.account-reused",
            "principal_id": "principal.web.account-reused",
            "role": WebAssessmentSigningRole.ACCOUNT_ISSUER,
        }
    )
    reused = trust.model_copy(update={"account_key": reused_account})

    with pytest.raises(ValueError, match="distinct trust identities"):
        begin_governed_web_campaign_parent(
            tmp_path,
            planned_runs=_planned_runs(),
            trust_material=reused,
            started_at=NOW,
            signer_not_after=NOW + timedelta(hours=1),
        )

    assert not (tmp_path / "campaign-runs").exists()


def test_parent_writer_is_not_copyable_or_serializable(tmp_path: Path) -> None:
    writer = _writer(tmp_path)

    with pytest.raises(TypeError, match="cannot be copied"):
        copy.copy(writer)
    with pytest.raises(TypeError, match="cannot be copied"):
        copy.deepcopy(writer)
