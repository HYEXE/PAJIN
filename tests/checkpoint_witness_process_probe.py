"""Owned test-only SIGKILL injection after actual witness fsync, before anchor append."""

import json
import os
import platform
import signal
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.operations.checkpoint_anchor import AnchorBinding, CheckpointAnchor, initialize
from pajin.operations.checkpoint_witness import CheckpointWitness, initialize_witness
from pajin.operations.hybrid_models import canonical


def anchor_at(root, name="anchor"):
    binding = AnchorBinding.model_validate_json((root / "binding.json").read_bytes())
    return CheckpointAnchor(
        root / name, binding, witness=CheckpointWitness(root / "witness", binding.witness)
    )


def child(root):
    keys = json.load(sys.stdin)
    anchor = anchor_at(root)

    def crash(_self, _entry):
        os.kill(os.getpid(), signal.SIGKILL)

    CheckpointAnchor._append_entry = crash
    anchor.publish(
        checkpoint_pin="2" * 64,
        source_pin="f" * 64,
        expected_sequence=1,
        key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[0])),
        witness_key=Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[1])),
    )
    raise AssertionError("crash injection was not reached")


def run(root):
    os.umask(0o077)
    root.mkdir(mode=0o700, exist_ok=False)
    keys = (Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate())
    old = initialize(
        root / "anchor",
        authority_id="source",
        public_key_hex=keys[0].public_key().public_bytes_raw().hex(),
    )
    binding = initialize_witness(
        CheckpointAnchor(root / "anchor", old),
        root / "witness",
        authority_id="retained",
        public_key_hex=keys[1].public_key().public_bytes_raw().hex(),
    )
    (root / "binding.json").write_bytes(canonical(binding))
    anchor = anchor_at(root)
    anchor.publish(
        checkpoint_pin="1" * 64,
        source_pin="f" * 64,
        expected_sequence=0,
        key=keys[0],
        witness_key=keys[1],
    )
    before = (root / "anchor/entries.jsonl").read_bytes()
    killed = subprocess.run(
        [sys.executable, __file__, str(root), "crash"],
        input=json.dumps([key.private_bytes_raw().hex() for key in keys]),
        text=True,
        capture_output=True,
        timeout=30,
    )
    assert killed.returncode == -signal.SIGKILL
    assert (root / "anchor/entries.jsonl").read_bytes() == before
    assert anchor.witness.inspect().sequence == 2
    inspect = [
        sys.executable,
        "-m",
        "pajin.operations.checkpoint_anchor",
        "inspect",
        "--directory",
        str(root / "anchor"),
        "--binding",
        str(root / "binding.json"),
        "--witness-directory",
        str(root / "witness"),
    ]
    denied = subprocess.run(inspect, capture_output=True, text=True, timeout=30)
    assert (
        denied.returncode != 0
        and "anchor differs from independently retained witness" in denied.stderr
    )
    restored = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.operations.checkpoint_witness",
            "restore-anchor",
            "--directory",
            str(root / "witness"),
            "--anchor-binding",
            str(root / "binding.json"),
            "--target-directory",
            str(root / "reconstructed"),
            "--output-binding",
            str(root / "restored.json"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert restored.returncode == 0, restored.stderr
    assert (root / "anchor/entries.jsonl").read_bytes() == before
    anchor = anchor_at(root, "reconstructed")
    inspect[inspect.index("--directory") + 1] = str(root / "reconstructed")
    for sequence in range(2, 34):
        entry = anchor.publish(
            checkpoint_pin=f"{sequence + 1:064x}",
            source_pin="f" * 64,
            expected_sequence=sequence,
            key=keys[0],
            witness_key=keys[1],
        )
        fresh = subprocess.run(inspect, capture_output=True, text=True, timeout=30)
        assert fresh.returncode == 0, fresh.stderr
        assert json.loads(fresh.stdout) == entry.model_dump(mode="json")
    print(
        json.dumps(
            dict(
                version="ops005-process-crash-v1",
                complete=True,
                cycles=32,
                system=platform.system(),
                sigkill_after_witness_fsync=True,
                stale_head_denied=True,
                original_retained=True,
                physical_host_failure_verified=False,
                power_loss_verified=False,
            )
        )
    )


if __name__ == "__main__":
    root = Path(sys.argv[1])
    if len(sys.argv) == 3 and sys.argv[2] == "crash":
        child(root)
    else:
        run(root)
