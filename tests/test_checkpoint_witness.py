"""Separate recovery witness, rollback refusal and explicit crash recovery boundaries."""

import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from test_hybrid_operations import checkpoint_fixture

from pajin.control_plane.security import CheckpointSigner
from pajin.operations.checkpoint_anchor import (
    AnchorBinding,
    CheckpointAnchor,
    initialize,
    require_anchor,
)
from pajin.operations.checkpoint_witness import CheckpointWitness, initialize_witness
from pajin.operations.hybrid import create_checkpoint, restore_checkpoint
from pajin.operations.hybrid_models import canonical, digest


@pytest.fixture
def witnessed(tmp_path):
    key, witness_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    base = initialize(
        tmp_path / "anchor",
        authority_id="source",
        public_key_hex=key.public_key().public_bytes_raw().hex(),
    )
    old = CheckpointAnchor(tmp_path / "anchor", base)
    binding = initialize_witness(
        old,
        tmp_path / "witness",
        authority_id="retained-witness",
        public_key_hex=witness_key.public_key().public_bytes_raw().hex(),
    )
    witness = CheckpointWitness(tmp_path / "witness", binding.witness)
    return key, witness_key, base, CheckpointAnchor(old.directory, binding, witness=witness)


def publish(value, sequence, checkpoint):
    key, witness_key, _, anchor = value
    return anchor.publish(
        checkpoint_pin=checkpoint * 64,
        source_pin="f" * 64,
        expected_sequence=sequence,
        key=key,
        witness_key=witness_key,
    )


def test_independent_intent_and_anchor_have_the_same_fresh_head(witnessed):
    _, _, _, anchor = witnessed
    assert anchor.head() is None and anchor.witness.inspect() is None
    first = publish(witnessed, 0, "1")
    second = publish(witnessed, 1, "2")
    assert second.previous_sha256 == digest(first)
    assert anchor.head() == anchor.witness.inspect() == second
    fresh = CheckpointAnchor(anchor.directory, anchor.binding, witness=anchor.witness)
    with fresh.hold("2" * 64, "f" * 64) as held:
        assert held == second


@pytest.mark.parametrize("side", ["anchor", "witness"])
def test_one_store_rollback_or_valid_suffix_deletion_blocks_every_recovery(witnessed, side):
    _, _, _, anchor = witnessed
    publish(witnessed, 0, "1")
    path = (anchor.directory if side == "anchor" else anchor.witness.directory) / "entries.jsonl"
    previous = path.read_bytes()
    publish(witnessed, 1, "2")
    path.write_bytes(previous)
    for check in (lambda: anchor.head(), lambda: publish(witnessed, 1, "3")):
        with pytest.raises(ValueError, match="witness"):
            check()
    with pytest.raises(ValueError, match="witness"), anchor.hold("1" * 64, "f" * 64):
        pytest.fail("stale recovery must not execute")
    assert path.read_bytes() == previous


def test_simultaneous_rollback_of_both_trusted_stores_is_an_explicit_limit(witnessed):
    _, _, _, anchor = witnessed
    first = publish(witnessed, 0, "1")
    paths = [anchor.directory / "entries.jsonl", anchor.witness.directory / "entries.jsonl"]
    saved = [p.read_bytes() for p in paths]
    publish(witnessed, 1, "2")
    for p, raw in zip(paths, saved, strict=True):
        p.write_bytes(raw)
    assert anchor.head() == first


def test_crash_after_witness_intent_blocks_then_restores_into_a_new_anchor(
    witnessed, tmp_path, monkeypatch
):
    _, _, _, anchor = witnessed
    publish(witnessed, 0, "1")
    old_bytes = (anchor.directory / "entries.jsonl").read_bytes()

    def crash(_entry):
        raise OSError("simulated interruption before anchor append")

    monkeypatch.setattr(anchor, "_append_entry", crash)
    with pytest.raises(OSError, match="interruption"):
        publish(witnessed, 1, "2")
    assert anchor.witness.inspect().sequence == 2
    with pytest.raises(ValueError, match="witness"):
        anchor.head()
    new = tmp_path / "restored-anchor"
    binding = anchor.witness.restore_anchor(new)
    restored = CheckpointAnchor(new, binding, witness=anchor.witness)
    assert restored.head().checkpoint_sha256 == "2" * 64
    assert (anchor.directory / "entries.jsonl").read_bytes() == old_bytes
    with pytest.raises(FileExistsError):
        anchor.witness.restore_anchor(new)


def test_downgrade_missing_witness_and_signer_reuse_are_rejected(witnessed, tmp_path):
    key, witness_key, base, anchor = witnessed
    assert "witness" not in json.loads(base.model_dump_json())
    assert AnchorBinding.model_validate_json(base.model_dump_json()) == base
    assert anchor.binding.version == "pajin-recovery-anchor-v2"
    with pytest.raises(ValueError, match="requires"):
        CheckpointAnchor(anchor.directory, anchor.binding)
    with pytest.raises(ValueError, match="not enrolled"):
        CheckpointAnchor(anchor.directory, base, witness=anchor.witness)
    with pytest.raises(ValueError, match="enrolled"):
        require_anchor(anchor.binding, CheckpointAnchor(anchor.directory, base), tmp_path / "state")
    for value in (None, key, Ed25519PrivateKey.generate()):
        with pytest.raises(ValueError, match="witness publisher"):
            anchor.publish(
                checkpoint_pin="1" * 64,
                source_pin="f" * 64,
                expected_sequence=0,
                key=key,
                witness_key=value,
            )
    assert anchor.head() is None
    values = anchor.binding.model_dump(mode="json")
    values["version"] = "pajin-recovery-anchor-v1"
    with pytest.raises(ValueError, match="v2"):
        AnchorBinding.model_validate_json(json.dumps(values))
    values["version"] = "pajin-recovery-anchor-v2"
    values["witness"]["public_key_hex"] = base.public_key_hex
    with pytest.raises(ValueError, match="distinct"):
        AnchorBinding.model_validate_json(json.dumps(values))
    assert witness_key != key


@pytest.mark.parametrize("mutation", ["signature", "partial", "gap", "reordered", "duplicate"])
def test_witness_tampering_is_not_repaired_or_used_to_restore(witnessed, tmp_path, mutation):
    _, _, _, anchor = witnessed
    publish(witnessed, 0, "1")
    publish(witnessed, 1, "2")
    path = anchor.witness.directory / "entries.jsonl"
    lines = path.read_bytes().splitlines(keepends=True)
    if mutation == "signature":
        value = json.loads(lines[-1])
        value["signature_hex"] = "0" * 128
        lines[-1] = canonical(value) + b"\n"
    elif mutation == "partial":
        lines[-1] = lines[-1][:-1]
    elif mutation == "gap":
        lines.pop(0)
    elif mutation == "reordered":
        lines.reverse()
    else:
        lines.append(lines[-1])
    damaged = b"".join(lines)
    path.write_bytes(damaged)
    with pytest.raises((ValueError, InvalidSignature)):
        anchor.head()
    destination = tmp_path / "must-not-exist"
    with pytest.raises((ValueError, InvalidSignature)):
        anchor.witness.restore_anchor(destination)
    assert not destination.exists() and path.read_bytes() == damaged


@pytest.mark.parametrize("leaf", ["genesis.json", "entries.jsonl", "lock"])
def test_missing_symlink_and_shared_file_witness_are_rejected(witnessed, tmp_path, leaf):
    _, _, _, anchor = witnessed
    path = anchor.witness.directory / leaf
    content = path.read_bytes()
    path.unlink()
    with pytest.raises(FileNotFoundError):
        anchor.head()
    other = tmp_path / "other-file"
    other.write_bytes(content)
    other.chmod(0o600)
    path.symlink_to(other)
    with pytest.raises((OSError, ValueError)):
        anchor.head()
    path.unlink()
    path.hardlink_to(other)
    with pytest.raises((OSError, ValueError)):
        anchor.head()
    assert other.read_bytes() == content


def test_recovery_holds_both_read_locks_and_rechecks_the_witness(witnessed):
    _, _, _, anchor = witnessed
    publish(witnessed, 0, "1")
    with anchor.hold("1" * 64, "f" * 64), pytest.raises(BlockingIOError):
        publish(witnessed, 1, "2")
    with pytest.raises(ValueError, match="witness"), anchor.hold("1" * 64, "f" * 64):
        (anchor.witness.directory / "entries.jsonl").write_bytes(b"")


def test_two_publishers_cannot_commit_the_same_expected_sequence(witnessed):
    def attempt(checkpoint):
        try:
            return publish(witnessed, 0, checkpoint)
        except (ValueError, BlockingIOError):
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(attempt, ("1", "2")))
    assert sum(value is not None for value in results) == 1
    anchor = witnessed[-1]
    assert anchor.head() == anchor.witness.inspect()
    assert anchor.head().sequence == 1


def test_stale_anchor_refuses_before_target_materialization(witnessed, tmp_path):
    _, _, _, anchor = witnessed
    checkpoint = checkpoint_fixture(tmp_path)
    source = checkpoint.deployment.model_copy(update={"recovery_anchor": anchor.binding})
    checkpoint = checkpoint.model_copy(update={"deployment": source})
    key, witness_key, _, _ = witnessed
    anchor.publish(
        checkpoint_pin="1" * 64,
        source_pin=digest(source),
        expected_sequence=0,
        key=key,
        witness_key=witness_key,
    )
    old = (anchor.directory / "entries.jsonl").read_bytes()
    anchor.publish(
        checkpoint_pin="2" * 64,
        source_pin=digest(source),
        expected_sequence=1,
        key=key,
        witness_key=witness_key,
    )
    (anchor.directory / "entries.jsonl").write_bytes(old)
    target = tmp_path / "restored-state"
    with pytest.raises(ValueError, match="witness"):
        restore_checkpoint(
            checkpoint,
            source,
            target,
            database_url="unused",
            signer=CheckpointSigner(active_key_id="v1", keys={"v1": b"x" * 32}),
            checkpoint_pin="1" * 64,
            anchor=anchor,
        )
    assert not target.exists()


def test_missing_witness_publisher_is_rejected_before_source_stop(witnessed, tmp_path, monkeypatch):
    import pajin.operations.hybrid as hybrid

    key, _, _, anchor = witnessed
    checkpoint = checkpoint_fixture(tmp_path)
    plan = checkpoint.deployment.model_copy(update={"recovery_anchor": anchor.binding})
    called = []
    monkeypatch.setattr(hybrid, "_create_checkpoint", lambda *a, **k: called.append(True))
    with pytest.raises(ValueError, match="witness publisher"):
        create_checkpoint(
            plan,
            tmp_path / "source",
            database_url="unused",
            signer=CheckpointSigner(active_key_id="v1", keys={"v1": b"x" * 32}),
            encryption_key=b"z" * 32,
            destination=tmp_path / "archive",
            anchor=anchor,
            anchor_key=key,
            expected_anchor_sequence=0,
        )
    assert not called and anchor.head() is None


def test_fresh_cli_reconstructs_only_a_new_anchor(witnessed, tmp_path):
    _, _, _, anchor = witnessed
    latest = publish(witnessed, 0, "1")
    binding = tmp_path / "binding.json"
    binding.write_text(anchor.binding.model_dump_json())
    binding.chmod(0o600)
    new = tmp_path / "cli-anchor"
    output = tmp_path / "new-binding.json"
    command = [
        sys.executable,
        "-m",
        "pajin.operations.checkpoint_witness",
        "restore-anchor",
        "--directory",
        str(anchor.witness.directory),
        "--anchor-binding",
        str(binding),
        "--target-directory",
        str(new),
        "--output-binding",
        str(output),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    restored_binding = AnchorBinding.model_validate_json(output.read_bytes())
    assert CheckpointAnchor(new, restored_binding, witness=anchor.witness).head() == latest
    second = subprocess.run(command, capture_output=True, text=True, timeout=30)
    assert second.returncode != 0
