"""Operator recovery denial and durability tests; live Linux evidence is a separate probe."""

import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.operations.hybrid_files import authenticate, collect, file_object, restore_local, seal
from pajin.operations.hybrid_models import (
    Checkpoint,
    Deployment,
    GraphMember,
    ResumeAuthorization,
    ResumeSigner,
    Writer,
    digest,
)
from pajin.operations.hybrid_resume import verify_authorization
from pajin.operations.hybrid_verify import require_resume_budget


def deployment(state: Path) -> Deployment:
    return Deployment(
        deployment_id="unit-source",
        writer_label="pajin.recovery-writer",
        writer_owner="unit-owner",
        writers=(
            Writer(container_id="a" * 64, image_id="sha256:" + "b" * 64, role="control-plane"),
        ),
        postgres=Writer(container_id="c" * 64, image_id="sha256:" + "d" * 64, role="postgres"),
        postgres_label="pajin.recovery-postgres",
        postgres_owner="unit-database",
        database="pajin",
        database_user="pajin",
        graphs=(GraphMember(path="graph.db", campaign_id="unit-test"),),
        journals=(),
        runs=(),
        checkpoint_key_commitments={"v1": "e" * 64},
        code_sha256="f" * 64,
        state_root_sha256=digest(str(state)),
        resume_signers={
            "approver": ResumeSigner(
                subject="recovery-operator",
                public_key_hex="1" * 64,
            )
        },
        operator_api_origin="https://127.0.0.1:8443",
        operator_ca_sha256="2" * 64,
    )


def checkpoint_fixture(tmp_path: Path) -> Checkpoint:
    state = tmp_path / "source"
    state.mkdir(mode=0o700)
    (state / "graph.db").write_bytes(b"unit bytes; semantic validity tested separately")
    return Checkpoint(
        deployment=deployment(state),
        source_database_identity="3" * 64,
        state_summary={},
        postgres_dump=file_object("postgres.dump", b"unit dump"),
        files=collect(state),
        created_at=datetime.now(UTC),
    )


def test_encryption_independent_pin_and_create_only_materialization(tmp_path: Path) -> None:
    checkpoint = checkpoint_fixture(tmp_path)
    key = os.urandom(32)
    sealed = seal(checkpoint, key)
    pin = sha256(sealed).hexdigest()
    assert authenticate(sealed, pin=pin, key=key) == checkpoint
    assert b"unit dump" not in sealed
    target = tmp_path / "restored"
    restore_local(checkpoint, target)
    assert collect(target) == checkpoint.files
    with pytest.raises(FileExistsError):
        restore_local(checkpoint, target)
    with pytest.raises(ValueError, match="pin"):
        authenticate(sealed, pin="0" * 64, key=key)


@pytest.mark.parametrize("kind", ["truncated", "modified", "wrong-key"])
def test_bad_checkpoint_never_authenticates(tmp_path: Path, kind: str) -> None:
    checkpoint = checkpoint_fixture(tmp_path)
    key = os.urandom(32)
    content = seal(checkpoint, key)
    if kind == "truncated":
        content = content[:-10]
    elif kind == "modified":
        content = content[:-1] + bytes([content[-1] ^ 1])
    else:
        key = os.urandom(32)
    with pytest.raises(InvalidTag):
        authenticate(content, pin=sha256(content).hexdigest(), key=key)


def test_inventory_rejects_links_and_oversized_state(tmp_path: Path, monkeypatch) -> None:
    checkpoint_fixture(tmp_path)
    state = tmp_path / "source"
    (state / "linked").symlink_to(state / "graph.db")
    with pytest.raises(ValueError, match="link"):
        collect(state)
    (state / "linked").unlink()
    from pajin.operations import hybrid_files

    monkeypatch.setattr(hybrid_files, "MAX_FILES", 0)
    with pytest.raises(ValueError, match="bound"):
        collect(state)


def test_file_substitution_and_duplicate_inventory_are_rejected(tmp_path: Path) -> None:
    checkpoint = checkpoint_fixture(tmp_path)
    modified = checkpoint.files[0].model_copy(update={"sha256": "0" * 64})
    for files in ((modified,), (checkpoint.files[0], checkpoint.files[0])):
        value = checkpoint.model_copy(update={"files": files})
        key = os.urandom(32)
        content = seal(value, key)
        with pytest.raises(ValueError):
            authenticate(content, pin=sha256(content).hexdigest(), key=key)


def signed_grant(report, key, *, now):
    values = dict(
        checkpoint_sha256=report["checkpoint_sha256"],
        verification_sha256=digest(report),
        target_database_identity=report["target_database_identity"],
        target_state_sha256=report["target_state_sha256"],
        checkpoint_id="checkpoint-1",
        approval_id="approval-1",
        expires_at=now + timedelta(minutes=5),
        operator_subject="recovery-operator",
        key_id="approver",
        signature_hex="0" * 128,
    )
    unsigned = ResumeAuthorization(**values)
    return unsigned.model_copy(update={"signature_hex": key.sign(unsigned.signed_bytes()).hex()})


def test_separate_resume_signature_requires_exact_receipt_target_subject_and_time() -> None:
    now = datetime.now(UTC)
    key = Ed25519PrivateKey.generate()
    report = dict(
        version="pajin-hybrid-restoration-v1",
        verified=True,
        checkpoint_sha256="1" * 64,
        target_database_identity="2" * 64,
        target_state_sha256="3" * 64,
    )
    grant = signed_grant(report, key, now=now)
    verify_authorization(
        grant,
        key=key.public_key(),
        subject="recovery-operator",
        report=report,
        checkpoint_pin=report["checkpoint_sha256"],
        now=now,
    )
    with pytest.raises(InvalidSignature):
        verify_authorization(
            grant,
            key=Ed25519PrivateKey.generate().public_key(),
            subject="recovery-operator",
            report=report,
            checkpoint_pin=report["checkpoint_sha256"],
            now=now,
        )
    with pytest.raises(ValueError, match="authenticated archive"):
        verify_authorization(
            grant,
            key=key.public_key(),
            subject="recovery-operator",
            report=report,
            checkpoint_pin="9" * 64,
            now=now,
        )
    for updated_report, subject, time in [
        ({**report, "verified": False}, "recovery-operator", now),
        ({**report, "target_database_identity": "4" * 64}, "recovery-operator", now),
        (report, "other-operator", now),
        (report, "recovery-operator", now + timedelta(minutes=6)),
    ]:
        with pytest.raises(ValueError):
            verify_authorization(
                grant,
                key=key.public_key(),
                subject=subject,
                report=updated_report,
                checkpoint_pin=report["checkpoint_sha256"],
                now=time,
            )


@pytest.mark.parametrize("duration_field", ["durationSeconds", "duration_seconds"])
def test_resume_rechecks_elapsed_budget_and_retains_uncertain_charge(duration_field) -> None:
    now = datetime.now(UTC)
    budget = dict(
        run_id="run-1",
        origin_at=(now - timedelta(seconds=20)).isoformat(),
        recorded_at=(now - timedelta(seconds=5)).isoformat(),
        usage={"elapsed_seconds": 15.0, "tool_calls": 1},
        uncertain_calls=0,
        scope={"limits": {duration_field: 60}},
    )
    summary = {"budgets": [budget]}
    require_resume_budget(summary, "run-1", now=now)
    for instant in [now + timedelta(seconds=60), now - timedelta(seconds=30)]:
        with pytest.raises(ValueError):
            require_resume_budget(summary, "run-1", now=instant)
    budget["uncertain_calls"] = 1
    with pytest.raises(ValueError, match="uncertain"):
        require_resume_budget(summary, "run-1", now=now)
    assert budget["usage"]["tool_calls"] == 1
