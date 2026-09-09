from __future__ import annotations

import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event, inspect, select, text
from sqlalchemy.exc import DatabaseError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.checkpoint_keys import CheckpointKeyringGuard
from pajin.control_plane.database import (
    CHECKPOINT_KEY_IDENTITY_SCHEMA_VERSION,
    CURRENT_SCHEMA_VERSION,
    V15_CONTROL_PLANE_TABLES,
    CheckpointKeyIdentityRecord,
    CheckpointRecord,
    ControlPlaneRepository,
    SchemaInitializationError,
)
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.security import (
    CHECKPOINT_VERIFICATION_KEYS_ENV,
    CheckpointIntegrityError,
    CheckpointSigner,
    checkpoint_keys_from_environment,
)

_KEY_V1 = b"first-isolated-checkpoint-key-32-bytes"
_KEY_V2 = b"second-isolated-checkpoint-key-32-bytes"
_OPERATOR_TOKEN = "isolated-checkpoint-operator-token-32-bytes"
_APPROVER_TOKEN = "isolated-checkpoint-approver-token-32-bytes"
_WORKER_TOKEN = "isolated-checkpoint-worker-token-32-bytes"


def _settings(path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{path.as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="operator", roles=frozenset({PrincipalRole.OPERATOR})
            ),
            _APPROVER_TOKEN: Principal(
                subject="approver", roles=frozenset({PrincipalRole.APPROVER})
            ),
            _WORKER_TOKEN: Principal(subject="worker", roles=frozenset({PrincipalRole.WORKER})),
        },
        checkpoint_keys={"v1": _KEY_V1},
    )


def test_default_server_rejects_rebound_key_even_before_first_checkpoint(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "recovery.db")
    with TestClient(create_app(settings)) as client:
        assert client.get("/healthz").status_code == 200
    changed = replace(settings, checkpoint_keys={"v1": _KEY_V2})
    with (
        pytest.raises(CheckpointIntegrityError, match="key identity"),
        TestClient(create_app(changed)),
    ):
        pytest.fail("a rebound checkpoint key must not reach the serving state")


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _checkpoint(client: TestClient, suffix: str, *, campaign=None) -> tuple[str, str]:
    submitted = client.post(
        "/v1/runs",
        headers=_auth(_OPERATOR_TOKEN),
        json={
            "campaign_name": campaign.metadata.name if campaign is not None else "recovery-lab",
            "idempotency_key": f"checkpoint-recovery-{suffix}",
            "input": {"manifest": campaign.model_dump(mode="json", by_alias=True)}
            if campaign is not None else {},
        },
    )
    assert submitted.status_code == 200, submitted.text
    job_id = submitted.json()["job"]["job_id"]
    claimed = client.post(
        "/v1/worker/jobs/claim",
        headers=_auth(_WORKER_TOKEN),
        json={"worker_id": "local-worker", "kinds": ["campaign"], "lease_seconds": 30},
    )
    assert claimed.status_code == 200, claimed.text
    assert claimed.json()["job"]["job_id"] == job_id
    response = client.post(
        f"/v1/worker/jobs/{job_id}/checkpoints",
        headers=_auth(_WORKER_TOKEN),
        json={
            "worker_id": "local-worker",
            "lease_token": claimed.json()["lease_token"],
            "state": {"turn": 2, "intent": "preserve across restart"},
            "pending_intent": {
                "call_fingerprint": "a" * 64,
                "tool_id": "mock.approval-probe",
                "target": "lab://recovery-check",
                "risk_tier": 3,
                "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
            },
        },
    )
    assert response.status_code == 200, response.text
    return str(response.json()["checkpoint"]["checkpoint_id"]), str(
        response.json()["approval"]["approval_id"]
    )


def _stored_keys(repository: ControlPlaneRepository) -> dict[str, str]:
    with repository.read_transaction() as session:
        return {
            row.key_id: row.key_commitment
            for row in session.scalars(select(CheckpointKeyIdentityRecord))
        }


def test_rotation_verifies_previous_checkpoints_and_signs_only_with_active_key(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "rotation.db")
    original = create_app(settings)
    with TestClient(original) as client:
        first, _ = _checkpoint(client, "first")
        with original.state.repository.read_transaction() as session:
            old = session.get(CheckpointRecord, first)
            old_signature = old.signature
            assert old.key_id == "v1"
    rotated = replace(
        settings,
        active_checkpoint_key_id="v2",
        checkpoint_keys={
            "v1": _KEY_V1,
            "v2": _KEY_V2,
        },
    )
    application = create_app(rotated)
    with TestClient(application) as client:
        second, _ = _checkpoint(client, "second")
        with application.state.repository.read_transaction() as session:
            assert session.get(CheckpointRecord, first).signature == old_signature
            assert session.get(CheckpointRecord, second).key_id == "v2"
        assert set(_stored_keys(application.state.repository)) == {"v1", "v2"}
    with (
        pytest.raises(CheckpointIntegrityError, match="integrity"),
        TestClient(create_app(replace(rotated, checkpoint_keys={"v2": _KEY_V2}))),
    ):
        pytest.fail("removing a key required by stored checkpoints must block startup")


def test_unreferenced_key_may_be_omitted_but_its_id_cannot_be_reassigned(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "retired.db")
    with TestClient(create_app(settings)):
        pass
    rotated = replace(settings, active_checkpoint_key_id="v2", checkpoint_keys={"v2": _KEY_V2})
    with TestClient(create_app(rotated)) as client:
        assert client.get("/healthz").status_code == 200
    replaced_old = replace(rotated, checkpoint_keys={"v1": _KEY_V2, "v2": _KEY_V2})
    with (
        pytest.raises(CheckpointIntegrityError, match="key identity"),
        TestClient(create_app(replaced_old)),
    ):
        pytest.fail("omission must not release the permanent key-ID binding")


def test_corrupt_checkpoint_prevents_new_key_registration_without_repair(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "corrupt.db")
    original = create_app(settings)
    with TestClient(original) as client:
        checkpoint_id, _ = _checkpoint(client, "corrupt")
        with original.state.repository.transaction() as session:
            session.get(CheckpointRecord, checkpoint_id).payload = {"changed": True}
    rotated = replace(
        settings, active_checkpoint_key_id="v2", checkpoint_keys={"v1": _KEY_V1, "v2": _KEY_V2}
    )
    with pytest.raises(CheckpointIntegrityError), TestClient(create_app(rotated)):
        pytest.fail("a damaged checkpoint must block startup")
    repository = ControlPlaneRepository(settings.database_url)
    try:
        assert set(_stored_keys(repository)) == {"v1"}
        with repository.read_transaction() as session:
            assert session.get(CheckpointRecord, checkpoint_id).payload == {"changed": True}
    finally:
        repository.close()


def test_embedded_signing_guard_checks_recovery_even_if_active_key_was_previously_pinned(
    tmp_path: Path,
) -> None:
    settings = replace(
        _settings(tmp_path / "embedded.db"), checkpoint_keys={"v1": _KEY_V1, "v2": _KEY_V2}
    )
    with TestClient(create_app(settings)) as client:
        _checkpoint(client, "embedded")
    repository = ControlPlaneRepository(settings.database_url)
    guard = CheckpointKeyringGuard(
        repository, CheckpointSigner(active_key_id="v2", keys={"v2": _KEY_V2})
    )
    try:
        with pytest.raises(CheckpointIntegrityError), repository.transaction() as session:
            guard.require_signing_key(session)
    finally:
        repository.close()


def test_new_process_rotates_keys_and_consumes_previous_approval_only_once(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "process.db")
    with TestClient(create_app(settings)) as client:
        checkpoint_id, approval_id = _checkpoint(client, "restart-once")
        approved = client.post(
            f"/v1/approvals/{approval_id}/decision",
            headers=_auth(_APPROVER_TOKEN),
            json={"approve": True, "reason": "bounded local recovery test"},
        )
        assert approved.status_code == 200, approved.text
    environment = {
        key: value for key, value in os.environ.items() if not key.startswith("PAJIN_CP_")
    }
    environment.update(
        {
            "PAJIN_CP_DATABASE_URL": settings.database_url,
            "PAJIN_CP_OPERATOR_TOKEN": _OPERATOR_TOKEN,
            "PAJIN_CP_APPROVER_TOKEN": _APPROVER_TOKEN,
            "PAJIN_CP_WORKER_TOKEN": _WORKER_TOKEN,
            "PAJIN_CP_CHECKPOINT_KEY_ID": "v2",
            "PAJIN_CP_CHECKPOINT_KEY": _KEY_V2.decode(),
            CHECKPOINT_VERIFICATION_KEYS_ENV: json.dumps({"v1": _KEY_V1.decode()}),
            "PAJIN_CP_INITIALIZE_SCHEMA": "false",
        }
    )
    script = """
import os, sys
from fastapi.testclient import TestClient
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.security import CheckpointIntegrityError
try:
    with TestClient(create_app(ControlPlaneSettings.from_env())) as client:
        for _ in range(2):
            response = client.post(
                f'/v1/checkpoints/{sys.argv[1]}/resume',
                headers={'Authorization': 'Bearer ' + os.environ['PAJIN_CP_OPERATOR_TOKEN']},
                json={'approval_id': sys.argv[2]},
            )
            print(response.status_code)
except CheckpointIntegrityError:
    print('checkpoint startup rejected')
    sys.exit(42)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, checkpoint_id, approval_id],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["200", "409"]
    again = subprocess.run(
        [sys.executable, "-c", script, checkpoint_id, approval_id],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert again.returncode == 0, again.stderr
    assert again.stdout.splitlines() == ["409", "409"]
    environment[CHECKPOINT_VERIFICATION_KEYS_ENV] = json.dumps({"v1": _KEY_V2.decode()})
    rejected = subprocess.run(
        [sys.executable, "-c", script, checkpoint_id, approval_id],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    assert rejected.returncode == 42, rejected.stderr
    assert rejected.stdout.strip() == "checkpoint startup rejected"
    assert _KEY_V1.decode() not in rejected.stderr + rejected.stdout
    assert _KEY_V2.decode() not in rejected.stderr + rejected.stdout


def test_v15_upgrade_preserves_checkpoints_and_pins_keys_only_after_verification(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "legacy.db")
    with TestClient(create_app(settings)) as client:
        checkpoint_id, _ = _checkpoint(client, "legacy")
    repository = ControlPlaneRepository(settings.database_url)
    try:
        with repository.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE cp_checkpoint_key_identities")
            connection.execute(
                text("DELETE FROM cp_schema_version WHERE version = :version"),
                {"version": CHECKPOINT_KEY_IDENTITY_SCHEMA_VERSION},
            )
            before = connection.exec_driver_sql("SELECT * FROM cp_checkpoints").all()
        assert set(inspect(repository.engine).get_table_names()) == V15_CONTROL_PLANE_TABLES
        repository.initialize()
        assert repository.schema_version() == CURRENT_SCHEMA_VERSION
        assert _stored_keys(repository) == {}
        changed = CheckpointSigner(active_key_id="v1", keys={"v1": _KEY_V2})
        with pytest.raises(CheckpointIntegrityError):
            CheckpointKeyringGuard(repository, changed).activate()
        assert _stored_keys(repository) == {}
        with repository.engine.connect() as connection:
            assert connection.exec_driver_sql("SELECT * FROM cp_checkpoints").all() == before
        correct = CheckpointSigner(active_key_id="v1", keys={"v1": _KEY_V1})
        CheckpointKeyringGuard(repository, correct).activate()
        assert _stored_keys(repository) == correct.key_commitments()
        with repository.read_transaction() as session:
            assert session.get(CheckpointRecord, checkpoint_id) is not None
        repository.initialize()
    finally:
        repository.close()


def test_simultaneous_first_admission_does_not_allow_different_keys_under_one_id(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path / "race.db")
    repositories = [ControlPlaneRepository(settings.database_url) for _ in range(2)]
    barrier = Barrier(2)
    signers = [CheckpointSigner(active_key_id="v1", keys={"v1": key}) for key in (_KEY_V1, _KEY_V2)]
    try:
        repositories[0].initialize()

        def activate(index: int) -> str:
            barrier.wait(timeout=10)
            try:
                CheckpointKeyringGuard(repositories[index], signers[index]).activate()
                return "accepted"
            except CheckpointIntegrityError:
                return "rejected"

        with ThreadPoolExecutor(max_workers=2) as executor:
            results = list(executor.map(activate, range(2)))
        assert sorted(results) == ["accepted", "rejected"]
        assert _stored_keys(repositories[0]) == signers[results.index("accepted")].key_commitments()
    finally:
        for repository in repositories:
            repository.close()


@pytest.mark.parametrize("operation", ["update", "delete", "replace"])
def test_key_identity_ledger_cannot_be_changed_or_replaced(tmp_path: Path, operation: str) -> None:
    settings = _settings(tmp_path / "append-only.db")
    app = create_app(settings)
    with TestClient(app):
        repository = app.state.repository
        before = _stored_keys(repository)
        statement = {
            "update": "UPDATE cp_checkpoint_key_identities SET key_commitment = '" + "a" * 64 + "'",
            "delete": "DELETE FROM cp_checkpoint_key_identities",
            "replace": "INSERT OR REPLACE INTO cp_checkpoint_key_identities "
            "SELECT * FROM cp_checkpoint_key_identities",
        }[operation]
        with pytest.raises(DatabaseError), repository.engine.begin() as connection:
            connection.exec_driver_sql(statement)
        assert _stored_keys(repository) == before


def test_pin_transaction_failure_leaves_no_partial_keyring(tmp_path: Path) -> None:
    repository = ControlPlaneRepository(_settings(tmp_path / "rollback.db").database_url)
    signer = CheckpointSigner(active_key_id="v2", keys={"v1": _KEY_V1, "v2": _KEY_V2})

    def interrupt(_connection, _cursor, statement, _parameters, _context, _executemany):
        if statement.startswith("INSERT INTO cp_checkpoint_key_identities"):
            raise RuntimeError("simulated stop after key insertion")

    try:
        repository.initialize()
        event.listen(repository.engine, "after_cursor_execute", interrupt)
        with pytest.raises(RuntimeError, match="simulated stop"):
            CheckpointKeyringGuard(repository, signer).activate()
        event.remove(repository.engine, "after_cursor_execute", interrupt)
        assert _stored_keys(repository) == {}
        CheckpointKeyringGuard(repository, signer).activate()
        assert _stored_keys(repository) == signer.key_commitments()
    finally:
        repository.close()


def test_missing_key_identity_table_is_not_repaired_as_an_empty_registry(tmp_path: Path) -> None:
    settings = _settings(tmp_path / "missing-table.db")
    with TestClient(create_app(settings)):
        pass
    repository = ControlPlaneRepository(settings.database_url)
    try:
        with repository.engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE cp_checkpoint_key_identities")
        with pytest.raises(SchemaInitializationError, match="schema-v15"):
            repository.initialize()
        assert "cp_checkpoint_key_identities" not in inspect(repository.engine).get_table_names()
    finally:
        repository.close()


@pytest.mark.parametrize(
    "value",
    [
        "",
        "[]",
        "null",
        '{"v1":"' + "a" * 32 + '"}',
        '{"old":"a","old":"b"}',
        '{"old":true}',
        '{"old":32}',
        '{"old":"short"}',
        '{"old":{"nested":"secret"}}',
        '{"old":"\\ud800"}',
        '{"bad id":"' + "a" * 32 + '"}',
        " " * (64 * 1024 + 1),
    ],
    ids=[
        "empty", "array", "null", "active-key-reused", "duplicate-key", "boolean-key",
        "integer-key", "short-key", "nested-key", "surrogate-key", "invalid-id", "oversized",
    ],
)
def test_verification_environment_rejects_ambiguous_or_invalid_secret_input(value: str) -> None:
    with pytest.raises(RuntimeError, match="secret detail omitted") as raised:
        checkpoint_keys_from_environment(
            active_key_id="v1", active_key=_KEY_V1.decode(), verification_keys=value
        )
    assert raised.value.__suppress_context__
    assert raised.value.__cause__ is None


def test_environment_adds_previous_verification_keys_without_changing_active_signing() -> None:
    keys = checkpoint_keys_from_environment(
        active_key_id="v2",
        active_key=_KEY_V2.decode(),
        verification_keys=json.dumps({"v1": _KEY_V1.decode()}),
    )
    signer = CheckpointSigner(active_key_id="v2", keys=keys)
    assert (
        signer.sign(
            checkpoint_id="cp", run_id="run", sequence=1, schema_version=1, payload={}
        ).key_id
        == "v2"
    )
    keys["v1"] = _KEY_V2
    assert (
        signer.key_commitments()["v1"]
        == CheckpointSigner(
            active_key_id="v1",
            keys={"v1": _KEY_V1},
        ).key_commitments()["v1"]
    )
