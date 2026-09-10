from __future__ import annotations

import base64
import os
from hashlib import sha256

import pytest
from cryptography.exceptions import InvalidTag

from scripts.operations_cold_checkpoint import (
    ColdCheckpoint,
    ColdFile,
    ColdFiles,
    authenticate,
    collect,
    encode,
    restore,
    seal,
)


def file(path="nested/state", data=b"retained evidence"):
    return ColdFile(
        path=path, sha256=sha256(data).hexdigest(), content=base64.b64encode(data).decode()
    )


def test_combined_checkpoint_round_trip_requires_external_pin_and_new_destination(tmp_path):
    local = ColdFiles(files=(file(),))
    checkpoint = ColdCheckpoint(
        source_sha256="a" * 64,
        runtime_image="sha256:" + "b" * 64,
        expected_state_sha256="c" * 64,
        postgres=file("db.dump"),
        local=local,
    )
    encrypted = seal(checkpoint, b"x" * 32)
    assert b"retained evidence" not in encrypted
    verified = authenticate(encrypted, expected_sha256=sha256(encrypted).hexdigest(), key=b"x" * 32)
    assert verified == checkpoint
    restore(verified.local, tmp_path / "restored")
    assert encode(collect(tmp_path / "restored")) == encode(local)
    with pytest.raises(FileExistsError):
        restore(verified.local, tmp_path / "restored")
    with pytest.raises(InvalidTag):
        authenticate(encrypted, expected_sha256=sha256(encrypted).hexdigest(), key=b"y" * 32)
    for changed in (encrypted[:-1], encrypted[:-1] + bytes([encrypted[-1] ^ 1])):
        with pytest.raises(ValueError, match="pin"):
            authenticate(changed, expected_sha256=sha256(encrypted).hexdigest(), key=b"x" * 32)


@pytest.mark.parametrize("path", ["../state", "/state", "a/../b", "a//b", "a\\b", "."])
def test_checkpoint_rejects_noncanonical_paths(path):
    with pytest.raises(ValueError):
        file(path)


@pytest.mark.parametrize("paths", [("a", "a"), ("b", "a"), ("a", "a/b")])
def test_checkpoint_rejects_duplicate_reordered_or_overlapping_members(paths):
    with pytest.raises(ValueError):
        ColdFiles(files=tuple(file(path) for path in paths))


@pytest.mark.parametrize("kind", ["symlink", "hardlink", "fifo"])
def test_collection_rejects_nonregular_or_aliased_state(tmp_path, kind):
    root = tmp_path / "state"
    root.mkdir()
    target = tmp_path / "outside"
    target.write_bytes(b"private")
    if kind == "symlink":
        (root / "data").symlink_to(target)
    elif kind == "hardlink":
        os.link(target, root / "data")
    else:
        os.mkfifo(root / "data")
    with pytest.raises(ValueError):
        collect(root)


def test_changed_file_digest_is_rejected():
    changed = file().model_copy(update={"sha256": "0" * 64})
    with pytest.raises(ValueError, match="digest"):
        ColdFiles(files=(changed,))
