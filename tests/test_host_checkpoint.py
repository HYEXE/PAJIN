from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from fastapi.testclient import TestClient
from test_control_plane_checkpoint_recovery import (
    _APPROVER_TOKEN,
    _KEY_V1,
    _OPERATOR_TOKEN,
    _auth,
    _checkpoint,
    _settings,
)
from test_control_plane_run_budgets import _campaign
from test_graph_backup_repository import _backup_key, _backup_signer
from test_host_activity import _enroll, _quiescence

from pajin.control_plane.api import create_app
from pajin.control_plane.security import CheckpointSigner
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime import host_checkpoint as checkpoint_module
from pajin.runtime.control import BudgetController
from pajin.runtime.host_checkpoint import create_host_checkpoint, restore_host_checkpoint
from pajin.runtime.host_checkpoint_models import (
    HostCheckpointError,
    HostCheckpointMember,
    HostCheckpointPlan,
    canonical,
)
from pajin.runtime.host_gate import HostActivityError, runtime_activity
from pajin.supervision.invocation_journal import SupervisorInvocationJournal
from pajin.supervision.run_binding import SupervisorRunBinding

pytestmark = pytest.mark.skipif(os.name != "posix", reason="local host checkpoint uses POSIX flock")
_ENCRYPTION_KEY = bytes(range(32))
_CREATED = datetime(2026, 9, 8, tzinfo=UTC)


def _cp_signer():
    return CheckpointSigner(active_key_id="v1", keys={"v1": _KEY_V1})


def _setup(tmp_path, monkeypatch):
    root = tmp_path / "host"
    state = root / "state"
    state.mkdir(parents=True, mode=0o700)
    root.chmod(0o700)
    app = create_app(_settings(state / "control-plane.db"))
    with TestClient(app) as client:
        checkpoint_id, approval_id = _checkpoint(client, "snapshot")
    with sqlite3.connect(state / "control-plane.db") as connection:
        run_id = connection.execute(
            "SELECT run_id FROM cp_checkpoints WHERE checkpoint_id = ?", (checkpoint_id,),
        ).fetchone()[0]
    campaign = _campaign()
    from pajin.control_plane.models import replay_execution_component_digest

    binding = SupervisorRunBinding(
        controlPlaneRunId=run_id, campaignDigest=replay_execution_component_digest(campaign),
        inputDigest="a" * 64, budgetMode="campaign-only",
    )
    journal = SupervisorInvocationJournal(state / "budget.sqlite3", run_binding=binding)
    budget = BudgetController(campaign.spec.budgets)
    journal.bind_campaign_budget(campaign_digest=binding.campaign_digest, campaign=budget)
    budget.reserve_agent(depth=0)
    budget.reserve_tool_usage()
    SQLiteGraphStore(state / "canonical-graph.sqlite3", campaign_id="recovery-lab")
    artifact = b"isolated-private-evidence-not-for-publication"
    (state / "evidence.txt").write_bytes(artifact)
    enrolled = _enroll(tmp_path, monkeypatch)
    plan = HostCheckpointPlan(
        recoverySetId="isolated-recovery", gate=enrolled[3],
        members=(
            HostCheckpointMember(
                path="budget.sqlite3", kind="supervisor-sqlite", runBinding=binding,
            ),
            HostCheckpointMember(
                path="canonical-graph.sqlite3", kind="graph-sqlite", campaignId="recovery-lab",
            ),
            HostCheckpointMember(path="control-plane.db", kind="control-plane-sqlite"),
            HostCheckpointMember(
                path="evidence.txt", kind="artifact", artifactSha256=sha256(artifact).hexdigest(),
            ),
        ),
    )
    return enrolled, plan, checkpoint_id, approval_id, budget


def _create(tmp_path, enrolled, plan, **changes):
    args = dict(
        plan=plan, expected_plan_sha256=plan.digest, destination=tmp_path / "retained.checkpoint",
        encryption_key_id="encryption-v1", encryption_key=_ENCRYPTION_KEY,
        signer=_backup_signer(), checkpoint_signer=_cp_signer(), created_at=_CREATED,
    )
    args.update(changes)
    with _quiescence(enrolled) as lease:
        return create_host_checkpoint(lease, **args)


def _restore(tmp_path, manifest, **changes):
    args = dict(
        source=tmp_path / "retained.checkpoint", destination=tmp_path / "restored",
        expected_checkpoint_sha256=manifest.digest,
        expected_plan_sha256=manifest.statement.plan.digest,
        encryption_key_id="encryption-v1", encryption_key=_ENCRYPTION_KEY,
        trusted_signing_keys=(_backup_key(),), checkpoint_signer=_cp_signer(),
    )
    args.update(changes)
    return restore_host_checkpoint(**args)


def _files(root):
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in root.rglob("*")
            if path.is_file()}


def test_closed_set_round_trip_keeps_approval_budget_graph_and_evidence(tmp_path, monkeypatch):
    enrolled, plan, checkpoint_id, approval_id, old_budget = _setup(tmp_path, monkeypatch)
    before = _files(enrolled[0])
    manifest = _create(tmp_path, enrolled, plan)
    assert _files(enrolled[0]) == before
    assert before["state/evidence.txt"] not in (tmp_path / "retained.checkpoint").read_bytes()
    assert _restore(tmp_path, manifest) == manifest
    restored = tmp_path / "restored"
    assert not (restored / "runtime-gate.json").exists()
    assert (restored / "restored-checkpoint.json").read_bytes() == canonical(manifest)
    assert _files(enrolled[0]) == before
    assert (restored / "state/evidence.txt").read_bytes() == before["state/evidence.txt"]
    SQLiteGraphStore(
        restored / "state/canonical-graph.sqlite3", campaign_id="recovery-lab", initialize=False,
    )
    # Restoration is passive. This isolated test explicitly starts an unenrolled
    # app with a reviewed path/key configuration; restore never does this itself.
    for name in (
        "PAJIN_HOST_RUNTIME_ROOT", "PAJIN_RUNTIME_INVENTORY_PATH", "PAJIN_RUNTIME_INVENTORY_SHA256",
    ):
        monkeypatch.delenv(name)
    binding = plan.members[0].run_binding
    journal = SupervisorInvocationJournal(
        restored / "state/budget.sqlite3", run_binding=binding, allow_create=False,
    )
    remaining = BudgetController(_campaign().spec.budgets)
    journal.bind_campaign_budget(campaign_digest=binding.campaign_digest, campaign=remaining)
    assert (remaining.agent_count, remaining.tool_calls) == (1, 1)
    assert remaining.elapsed_seconds >= old_budget.elapsed_seconds - 0.1
    settings = _settings(restored / "state/control-plane.db")
    with TestClient(create_app(settings)) as client:
        assert client.get("/healthz").status_code == 200
        approved = client.post(
            f"/v1/approvals/{approval_id}/decision", headers=_auth(_APPROVER_TOKEN),
            json={"approve": True, "reason": "isolated recovery review"},
        )
        assert approved.status_code == 200, approved.text
        resumed = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume", headers=_auth(_OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert resumed.status_code == 200, resumed.text
    with TestClient(create_app(settings)) as client:
        duplicate = client.post(
            f"/v1/checkpoints/{checkpoint_id}/resume", headers=_auth(_OPERATOR_TOKEN),
            json={"approval_id": approval_id},
        )
        assert duplicate.status_code == 409, duplicate.text
    with sqlite3.connect(restored / "state/control-plane.db") as connection:
        assert connection.execute(
            "SELECT checkpoint_id FROM cp_checkpoints WHERE checkpoint_id = ?", (checkpoint_id,),
        ).fetchone()[0] == checkpoint_id


@pytest.mark.parametrize("change", ["missing", "extra", "symlink", "hardlink", "artifact", "hot"])
def test_incomplete_or_unreviewed_state_cannot_publish(tmp_path, monkeypatch, change):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    state = enrolled[0] / "state"
    if change == "missing":
        (state / "budget.sqlite3").unlink()
    elif change == "extra":
        (state / "unknown.db").write_bytes(b"unregistered")
    elif change == "symlink":
        (state / "link").symlink_to(tmp_path, target_is_directory=True)
    elif change == "hardlink":
        os.link(state / "evidence.txt", tmp_path / "evidence-alias")
    elif change == "artifact":
        (state / "evidence.txt").write_bytes(b"changed")
    else:
        (state / "control-plane.db-journal").write_bytes(b"incomplete transaction")
    with pytest.raises(HostCheckpointError):
        _create(tmp_path, enrolled, plan)
    assert not (tmp_path / "retained.checkpoint").exists()


@pytest.mark.parametrize("change", [
    "pin", "encryption-id", "encryption-key", "cp-key", "signing-key",
])
def test_restore_requires_independent_identity_and_exact_trusted_keys(
    tmp_path, monkeypatch, change,
):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    manifest = _create(tmp_path, enrolled, plan)
    changes = {
        "pin": {"expected_checkpoint_sha256": "0" * 64},
        "encryption-id": {"encryption_key_id": "encryption-v2"},
        "encryption-key": {"encryption_key": b"x" * 32},
        "cp-key": {"checkpoint_signer": CheckpointSigner(
            active_key_id="v1", keys={"v1": b"x" * 32},
        )},
        "signing-key": {"trusted_signing_keys": ()},
    }[change]
    with pytest.raises((HostCheckpointError, InvalidTag)):
        _restore(tmp_path, manifest, **changes)
    assert not (tmp_path / "restored").exists()


@pytest.mark.parametrize("change", ["ciphertext", "truncated", "trailing", "signature"])
def test_corrupt_envelope_never_creates_restore_destination(tmp_path, monkeypatch, change):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    manifest = _create(tmp_path, enrolled, plan)
    retained = tmp_path / "retained.checkpoint"
    raw = retained.read_bytes()
    if change == "ciphertext":
        raw = raw[:-1] + bytes([raw[-1] ^ 1])
    elif change == "truncated":
        raw = raw[:len(raw) // 2]
    elif change == "trailing":
        raw += b"extra"
    else:
        # Even an independently supplied digest for a forged manifest cannot
        # replace signature verification under an external public key.
        forged = manifest.model_copy(update={"signature_hex": "0" * 128})
        raw = raw.replace(canonical(manifest), canonical(forged), 1)
        manifest = forged
    retained.write_bytes(raw)
    with pytest.raises((HostCheckpointError, InvalidSignature)):
        _restore(tmp_path, manifest)
    assert not (tmp_path / "restored").exists()


def test_old_valid_checkpoint_is_rejected_under_new_expected_head(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    older = _create(tmp_path, enrolled, plan)
    newer = _create(
        tmp_path, enrolled, plan, destination=tmp_path / "newer.checkpoint",
        created_at=_CREATED + timedelta(minutes=1),
    )
    assert older.digest != newer.digest
    with pytest.raises(HostCheckpointError, match="expected identity"):
        _restore(tmp_path, newer)
    assert not (tmp_path / "restored").exists()


def test_busy_expired_or_wrong_gate_cannot_publish(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    with runtime_activity("worker"), pytest.raises(HostActivityError):
        _create(tmp_path, enrolled, plan)
    with _quiescence(enrolled) as lease:
        pass
    with pytest.raises(HostActivityError):
        create_host_checkpoint(lease, plan=plan, expected_plan_sha256=plan.digest,
            destination=tmp_path / "retained.checkpoint", encryption_key_id="encryption-v1",
            encryption_key=_ENCRYPTION_KEY, signer=_backup_signer(), checkpoint_signer=_cp_signer())
    forged = plan.model_copy(update={"gate": plan.gate.model_copy(update={"gate_id": "f" * 32})})
    with pytest.raises(HostCheckpointError, match="different enrolled host"):
        _create(tmp_path, enrolled, forged)


def test_changed_database_during_multi_store_copy_cannot_publish(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    original = checkpoint_module._copy_database
    changed = False

    def copy_then_change(source, destination):
        nonlocal changed
        original(source, destination)
        if not changed:
            changed = True
            with sqlite3.connect(enrolled[0] / "state/control-plane.db") as connection:
                connection.execute("UPDATE cp_runs SET updated_at = created_at")

    monkeypatch.setattr(checkpoint_module, "_copy_database", copy_then_change)
    with pytest.raises(HostCheckpointError, match="changed while copying"):
        _create(tmp_path, enrolled, plan)
    assert not (tmp_path / "retained.checkpoint").exists()


@pytest.mark.parametrize("change", ["active", "missing-run", "budget-history", "schema"])
def test_inconsistent_domain_state_is_not_repaired_into_a_checkpoint(tmp_path, monkeypatch, change):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    state = enrolled[0] / "state"
    if change == "active":
        with sqlite3.connect(state / "control-plane.db") as connection:
            connection.execute("UPDATE cp_runs SET state = 'queued'")
            connection.execute("UPDATE cp_runs SET state = 'running'")
    elif change == "missing-run":
        binding = plan.members[0].run_binding.model_copy(update={"control_plane_run_id": "missing"})
        first = plan.members[0].model_copy(update={"run_binding": binding})
        plan = plan.model_copy(update={"members": (first, *plan.members[1:])})
    elif change == "budget-history":
        with sqlite3.connect(state / "budget.sqlite3") as connection:
            guard = connection.execute(
                "SELECT sql FROM sqlite_master "
                "WHERE name = 'supervisor_budget_checkpoints_no_delete'",
            ).fetchone()[0]
            connection.execute("DROP TRIGGER supervisor_budget_checkpoints_no_delete")
            connection.execute("DELETE FROM supervisor_budget_checkpoints WHERE revision = 1")
            connection.execute(guard)
    else:
        with sqlite3.connect(state / "control-plane.db") as connection:
            connection.execute("DROP TABLE cp_schema_version")
    before = _files(state)
    with pytest.raises((RuntimeError, ValueError)):
        _create(tmp_path, enrolled, plan)
    assert _files(state) == before
    assert not (tmp_path / "retained.checkpoint").exists()


def test_restore_and_create_refuse_any_existing_destination(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    manifest = _create(tmp_path, enrolled, plan)
    before = (tmp_path / "retained.checkpoint").read_bytes()
    with pytest.raises((FileExistsError, RuntimeError)):
        _create(tmp_path, enrolled, plan)
    assert (tmp_path / "retained.checkpoint").read_bytes() == before
    (tmp_path / "restored").mkdir()
    with pytest.raises((FileExistsError, RuntimeError)):
        _restore(tmp_path, manifest)
    assert list((tmp_path / "restored").iterdir()) == []


def test_invalid_plan_paths_and_omitted_members_fail_before_copy(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    for path in ("../state", "/absolute", "a/../b", "a//b", "a\\b", "."):
        with pytest.raises(ValueError):
            HostCheckpointMember(path=path, kind="control-plane-sqlite")
    omitted = plan.model_copy(update={"members": plan.members[1:]})
    with pytest.raises(HostCheckpointError, match="undeclared"):
        _create(tmp_path, enrolled, omitted)
    with pytest.raises(HostCheckpointError, match="external pin"):
        _create(tmp_path, enrolled, plan, expected_plan_sha256="0" * 64)
    assert not (tmp_path / "retained.checkpoint").exists()


def test_omitting_both_plan_member_and_journal_does_not_reset_attempted_run(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    (enrolled[0] / "state/budget.sqlite3").unlink()
    plan = plan.model_copy(update={"members": plan.members[1:]})
    with pytest.raises(HostCheckpointError, match="complete budget journals"):
        _create(tmp_path, enrolled, plan)
    assert not (tmp_path / "retained.checkpoint").exists()


def test_exclusion_lasts_through_publication_and_failed_publish_is_not_complete(
    tmp_path, monkeypatch,
):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    original = checkpoint_module._write_new
    observed = []

    def fail_publication(path, content):
        if path.name == "retained.checkpoint":
            with pytest.raises(HostActivityError), runtime_activity("worker"):
                pytest.fail("runtime restarted before complete checkpoint publication")
            observed.append(True)
            raise OSError("isolated publication failure")
        original(path, content)

    monkeypatch.setattr(checkpoint_module, "_write_new", fail_publication)
    with pytest.raises(OSError, match="publication failure"):
        _create(tmp_path, enrolled, plan)
    assert observed == [True]
    assert not (tmp_path / "retained.checkpoint").exists()
    assert not list(tmp_path.glob(".host-checkpoint-*"))


def test_failed_restore_publication_retains_an_unenrolled_incomplete_destination(
    tmp_path, monkeypatch,
):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    before = _files(enrolled[0])
    manifest = _create(tmp_path, enrolled, plan)
    original = checkpoint_module._write_new

    def fail_marker(path, content):
        if path.name == "restored-checkpoint.json":
            raise OSError("isolated restore interruption")
        original(path, content)

    monkeypatch.setattr(checkpoint_module, "_write_new", fail_marker)
    with pytest.raises(OSError, match="restore interruption"):
        _restore(tmp_path, manifest)
    assert (tmp_path / "restored/state").is_dir()
    assert not (tmp_path / "restored/restored-checkpoint.json").exists()
    assert not (tmp_path / "restored/runtime-gate.json").exists()
    assert _files(enrolled[0]) == before
    with pytest.raises(RuntimeError):
        _restore(tmp_path, manifest)


def test_fresh_process_restores_with_rotated_verification_keyring(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    manifest = _create(tmp_path, enrolled, plan)
    script = """
import sys
from pathlib import Path
from pajin.control_plane.security import CheckpointSigner
from pajin.graph.backup_retention import SQLiteGraphBackupVerificationKey
from pajin.runtime.host_checkpoint import restore_host_checkpoint
result = restore_host_checkpoint(
    Path(sys.argv[1]), destination=Path(sys.argv[2]),
    expected_checkpoint_sha256=sys.argv[3], expected_plan_sha256=sys.argv[4],
    encryption_key_id='encryption-v1', encryption_key=bytes(range(32)),
    trusted_signing_keys=(SQLiteGraphBackupVerificationKey(
        keyId=sys.argv[5], publicKeyBase64url=sys.argv[6],
    ),),
    checkpoint_signer=CheckpointSigner(active_key_id='v2', keys={
        'v1': b'first-isolated-checkpoint-key-32-bytes',
        'v2': b'new-test-key-material-32-bytes-long',
    }),
)
print(result.digest)
"""
    key = _backup_key()
    result = subprocess.run(
        [sys.executable, "-c", script, str(tmp_path / "retained.checkpoint"),
         str(tmp_path / "fresh-restored"), manifest.digest, plan.digest,
         key.key_id, key.public_key_base64url],
        env={key: value for key, value in os.environ.items() if not key.startswith("PAJIN_")},
        capture_output=True, text=True, check=False, timeout=30,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == manifest.digest
    assert (tmp_path / "fresh-restored/restored-checkpoint.json").read_bytes() == (
        canonical(manifest)
    )


def test_declared_graph_campaign_and_source_inode_must_remain_exact(tmp_path, monkeypatch):
    enrolled, plan, *_ = _setup(tmp_path, monkeypatch)
    graph_member = plan.members[1].model_copy(update={"campaign_id": "other-campaign"})
    changed = plan.model_copy(update={
        "members": (plan.members[0], graph_member, *plan.members[2:]),
    })
    with pytest.raises(RuntimeError):
        _create(tmp_path, enrolled, changed)
    original = checkpoint_module._copy_database
    replaced = False

    def copy_then_replace(source, destination):
        nonlocal replaced
        original(source, destination)
        if not replaced:
            replaced = True
            old = enrolled[0] / "state/control-plane.db"
            replacement = tmp_path / "replacement.db"
            replacement.write_bytes(old.read_bytes())
            replacement.replace(old)

    monkeypatch.setattr(checkpoint_module, "_copy_database", copy_then_replace)
    with pytest.raises(HostCheckpointError, match="source identity changed"):
        _create(tmp_path, enrolled, plan)
    assert not (tmp_path / "retained.checkpoint").exists()


def test_unknown_supervisor_dispatch_blocks_recovery_with_both_budgets_retained(tmp_path):
    from test_supervisor_invocation_journal import _publication

    from pajin.runtime.host_checkpoint_stores import verify_supervisor

    publication = _publication(tmp_path)
    binding = SupervisorRunBinding(
        controlPlaneRunId="isolated-supervisor-run",
        campaignDigest=publication.schedule.campaign_digest,
        inputDigest="b" * 64, budgetMode="campaign-and-supervisor",
    )
    path = tmp_path / "dual.sqlite3"
    journal = SupervisorInvocationJournal(path, run_binding=binding)
    campaign = BudgetController(_campaign().spec.budgets)
    dedicated = BudgetController(_campaign().spec.budgets)
    journal.bind_budgets(
        campaign_digest=binding.campaign_digest,
        policy_digest=publication.schedule.dedicated_budget_policy_digest,
        campaign=campaign, dedicated=dedicated,
    )
    campaign.reserve_tool_usage()
    dedicated.reserve_tool_usage()
    intent = journal.claim(publication)
    verify_supervisor(path, binding)
    unknown = journal.begin_dispatch(intent)
    before = path.read_bytes()
    with pytest.raises(HostCheckpointError, match="uncertain dispatch"):
        verify_supervisor(path, binding)
    assert path.read_bytes() == before
    assert journal.inspect(unknown.intent.intent_id) == unknown
    assert (campaign.tool_calls, dedicated.tool_calls) == (1, 1)
