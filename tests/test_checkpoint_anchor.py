"""Independent high-water retention, live locking, enrollment and stale-restore denials."""

import os
from datetime import UTC, datetime

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_hybrid_operations import checkpoint_fixture, signed_grant

from pajin.control_plane.security import CheckpointSigner
from pajin.operations.checkpoint_anchor import (
    MAX_ENTRIES,
    AnchorBinding,
    CheckpointAnchor,
    initialize,
    recovery_head,
)
from pajin.operations.hybrid import (
    _compatible,
    create_checkpoint,
    restore_checkpoint,
    verify_restored,
)
from pajin.operations.hybrid_models import Deployment, canonical, digest
from pajin.operations.hybrid_resume import resume


@pytest.fixture
def enrolled(tmp_path):
    key = Ed25519PrivateKey.generate()
    binding = initialize(
        tmp_path / "independent",
        authority_id="recovery-test",
        public_key_hex=key.public_key().public_bytes_raw().hex(),
    )
    anchor = CheckpointAnchor(tmp_path / "independent", binding)
    return key, binding, anchor


def publish(anchor, key, sequence, *, checkpoint="1" * 64, source="2" * 64):
    return anchor.publish(
        checkpoint_pin=checkpoint,
        source_pin=source,
        expected_sequence=sequence,
        key=key,
    )


def test_archive_and_old_pin_rollback_does_not_replace_live_independent_head(enrolled):
    key, binding, anchor = enrolled
    assert anchor.head() is None
    first = publish(anchor, key, 0)
    assert first.previous_sha256 == binding.genesis_sha256
    with anchor.hold("1" * 64, "2" * 64) as held:
        assert held == first
    second = publish(anchor, key, 1, checkpoint="3" * 64)
    reopened = CheckpointAnchor(anchor.directory, binding)
    assert reopened.head() == second
    assert second.previous_sha256 == digest(first)
    with pytest.raises(ValueError, match="latest"), reopened.hold("1" * 64, "2" * 64):
        pytest.fail("stale recovery must not execute")
    with pytest.raises(ValueError, match="latest"), reopened.hold("3" * 64, "4" * 64):
        pytest.fail("wrong source must not execute")


def test_publication_cas_duplicates_signer_and_restart(enrolled):
    key, binding, anchor = enrolled
    with pytest.raises(ValueError, match="publisher"):
        publish(anchor, Ed25519PrivateKey.generate(), 0)
    assert anchor.head() is None
    publish(anchor, key, 0)
    for sequence in (0, 2):
        with pytest.raises(ValueError, match="stale"):
            publish(anchor, key, sequence, checkpoint="3" * 64)
    with pytest.raises(ValueError, match="repeats"):
        publish(anchor, key, 1)
    fresh = CheckpointAnchor(anchor.directory, binding)
    assert fresh.head().sequence == 1
    with pytest.raises(FileExistsError):
        initialize(anchor.directory, authority_id="reset", public_key_hex=binding.public_key_hex)


def test_recovery_holds_shared_lock_and_denies_concurrent_publisher(enrolled):
    key, binding, anchor = enrolled
    publish(anchor, key, 0)
    other = CheckpointAnchor(anchor.directory, binding)
    with (
        anchor.hold("1" * 64, "2" * 64),
        other.hold("1" * 64, "2" * 64),
        pytest.raises(BlockingIOError),
    ):
        publish(other, key, 1, checkpoint="3" * 64)
    assert publish(other, key, 1, checkpoint="3" * 64).sequence == 2


@pytest.mark.parametrize("mutation", ["signature", "partial", "duplicate", "reorder", "gap"])
def test_tampered_or_interrupted_chain_fails_without_repair(enrolled, mutation):
    key, _, anchor = enrolled
    first = publish(anchor, key, 0)
    second = publish(anchor, key, 1, checkpoint="3" * 64)
    lines = [canonical(first) + b"\n", canonical(second) + b"\n"]
    if mutation == "signature":
        lines[1] = canonical(second.model_copy(update={"signature_hex": "0" * 128})) + b"\n"
    elif mutation == "partial":
        lines[1] = lines[1][:-1]
    elif mutation == "duplicate":
        lines.append(lines[1])
    elif mutation == "reorder":
        lines.reverse()
    else:
        lines.pop(0)
    path = anchor.directory / "entries.jsonl"
    damaged = b"".join(lines)
    path.write_bytes(damaged)
    with pytest.raises((ValueError, InvalidSignature)):
        anchor.head()
    with pytest.raises((ValueError, InvalidSignature)):
        publish(anchor, key, 2, checkpoint="4" * 64)
    assert path.read_bytes() == damaged


@pytest.mark.parametrize("leaf", ["genesis.json", "entries.jsonl", "lock"])
def test_missing_or_symlinked_anchor_is_not_silently_created(enrolled, tmp_path, leaf):
    _, _, anchor = enrolled
    path = anchor.directory / leaf
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(FileNotFoundError):
        anchor.head()
    outside = tmp_path / "outside"
    outside.write_bytes(original)
    outside.chmod(0o600)
    path.symlink_to(outside)
    with pytest.raises((ValueError, OSError)):
        anchor.head()
    assert outside.read_bytes() == original


def test_live_head_recheck_detects_uncooperative_change(enrolled):
    key, _, anchor = enrolled
    publish(anchor, key, 0)
    with pytest.raises(ValueError, match="changed"), anchor.hold("1" * 64, "2" * 64):
        (anchor.directory / "entries.jsonl").write_bytes(b"")


def test_anchor_enrollment_disjoint_state_and_legacy_wire(enrolled, tmp_path):
    _, binding, anchor = enrolled
    state = tmp_path / "source"
    with (
        pytest.raises(ValueError, match="enrolled"),
        recovery_head(binding, None, state, "1" * 64, "2" * 64),
    ):
        pytest.fail("unenrolled recovery must not execute")
    with (
        pytest.raises(ValueError, match="not enrolled"),
        recovery_head(None, anchor, state, "1" * 64, "2" * 64),
    ):
        pytest.fail("unenrolled recovery must not execute")
    with pytest.raises(ValueError, match="disjoint"):
        anchor.require_outside(anchor.directory / "state")
    with pytest.raises(ValueError, match="disjoint"):
        anchor.require_outside(tmp_path)
    checkpoint = checkpoint_fixture(tmp_path)
    legacy = canonical(checkpoint.deployment)
    assert b"recovery_anchor" not in legacy
    assert canonical(Deployment.model_validate_json(legacy)) == legacy
    enrolled_source = checkpoint.deployment.model_copy(update={"recovery_anchor": binding})
    target = enrolled_source.model_copy(
        update={
            "deployment_id": "new-target",
            "state_root_sha256": "8" * 64,
            "postgres": enrolled_source.postgres.model_copy(update={"container_id": "9" * 64}),
            "writers": (enrolled_source.writers[0].model_copy(update={"container_id": "7" * 64}),),
        }
    )
    _compatible(enrolled_source, target)
    with pytest.raises(ValueError, match="contract"):
        _compatible(enrolled_source, target.model_copy(update={"recovery_anchor": None}))


def test_wrong_genesis_cannot_be_enrolled(enrolled):
    _, binding, anchor = enrolled
    incorrect = AnchorBinding.model_validate({**binding.model_dump(), "genesis_sha256": "0" * 64})
    with pytest.raises(ValueError, match="genesis"):
        CheckpointAnchor(anchor.directory, incorrect).head()


@pytest.mark.parametrize("operation", ["restore", "verify", "resume"])
def test_stale_archive_denied_before_any_target_or_api_activity(
    enrolled, tmp_path, monkeypatch, operation
):
    key, binding, anchor = enrolled
    checkpoint = checkpoint_fixture(tmp_path)
    plan = checkpoint.deployment.model_copy(update={"recovery_anchor": binding})
    checkpoint = checkpoint.model_copy(update={"deployment": plan})
    publish(anchor, key, 0, source=digest(plan))
    publish(anchor, key, 1, checkpoint="3" * 64, source=digest(plan))
    from pajin.operations import hybrid, hybrid_resume

    def forbidden(*args, **kwargs):
        pytest.fail("stale archive reached a side-effecting recovery body")

    monkeypatch.setattr(hybrid, "_restore_checkpoint", forbidden)
    monkeypatch.setattr(hybrid, "_verify_restored", forbidden)
    monkeypatch.setattr(hybrid_resume, "_resume", forbidden)
    kwargs = dict(
        database_url="must-not-connect",
        signer=CheckpointSigner(active_key_id="test", keys={"test": os.urandom(32)}),
        checkpoint_pin="1" * 64,
        anchor=anchor,
    )
    with pytest.raises(ValueError, match="latest"):
        if operation == "resume":
            report = dict(
                version="pajin-hybrid-restoration-v1",
                verified=True,
                checkpoint_sha256="1" * 64,
                target_database_identity="2" * 64,
                target_state_sha256="3" * 64,
            )
            resume(
                checkpoint,
                plan,
                tmp_path / "target",
                **kwargs,
                report=report,
                grant=signed_grant(report, key, now=datetime.now(UTC)),
                ca_path=tmp_path / "absent",
                token="unused",
                attempt_path=tmp_path / "attempt",
            )
        else:
            function = restore_checkpoint if operation == "restore" else verify_restored
            function(checkpoint, plan, tmp_path / "target", **kwargs)
    assert not (tmp_path / "target").exists()
    assert not (tmp_path / "attempt").exists()


def test_unenrolled_or_stale_publication_fails_before_source_stop(enrolled, tmp_path, monkeypatch):
    key, binding, anchor = enrolled
    checkpoint = checkpoint_fixture(tmp_path)
    plan = checkpoint.deployment.model_copy(update={"recovery_anchor": binding})
    from pajin.operations import hybrid

    def forbidden(*args, **kwargs):
        pytest.fail("invalid enrollment reached the source checkpoint operation")

    monkeypatch.setattr(hybrid, "_create_checkpoint", forbidden)
    for params in (
        {},
        {"anchor": anchor},
        {
            "anchor": anchor,
            "anchor_key": key,
            "expected_anchor_sequence": 1,
        },
    ):
        with pytest.raises(ValueError):
            create_checkpoint(
                plan,
                tmp_path / "source",
                database_url="must-not-connect",
                signer=CheckpointSigner(active_key_id="test", keys={"test": os.urandom(32)}),
                encryption_key=os.urandom(32),
                destination=tmp_path / "archive",
                **params,
            )


def test_full_anchor_is_rejected_before_stopping_the_source(enrolled, tmp_path, monkeypatch):
    from pajin.operations import hybrid

    key, binding, anchor = enrolled
    first = publish(anchor, key, 0)
    monkeypatch.setattr(anchor, "head", lambda: first.model_copy(update={"sequence": MAX_ENTRIES}))

    def forbidden(*args, **kwargs):
        pytest.fail("full anchor reached the source checkpoint operation")

    monkeypatch.setattr(hybrid, "_create_checkpoint", forbidden)
    with pytest.raises(ValueError, match="sequence"):
        create_checkpoint(
            checkpoint_fixture(tmp_path).deployment.model_copy(update={"recovery_anchor": binding}),
            tmp_path / "source",
            database_url="must-not-connect",
            signer=CheckpointSigner(active_key_id="test", keys={"test": os.urandom(32)}),
            encryption_key=os.urandom(32), destination=tmp_path / "archive",
            anchor=anchor, anchor_key=key, expected_anchor_sequence=MAX_ENTRIES,
        )
