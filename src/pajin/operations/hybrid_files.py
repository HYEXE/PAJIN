"""Private create-only recovery objects; no overwrite, migration, activation or silent repair."""

from __future__ import annotations

import base64
import os
import stat
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pajin.operations.hybrid_models import MAX_BYTES, MAX_FILES, Checkpoint, FileObject, canonical
from pajin.runtime.host_checkpoint import _safe_directory, _write_new
from pajin.runtime.safe_files import read_bounded_regular_bytes

DOMAIN = b"pajin.hybrid-cold-checkpoint/v1\0"


def read(path: Path, *, limit: int = MAX_BYTES) -> bytes:
    return read_bounded_regular_bytes(
        path,
        max_bytes=limit,
        label="hybrid recovery object",
        require_single_link=True,
    )


def object_bytes(obj: FileObject) -> bytes:
    data = base64.b64decode(obj.content, validate=True)
    if len(data) > MAX_BYTES or sha256(data).hexdigest() != obj.sha256:
        raise ValueError("recovery object digest or size differs")
    return data


def file_object(name: str, data: bytes) -> FileObject:
    if len(data) > MAX_BYTES:
        raise ValueError("recovery object exceeds its size limit")
    return FileObject(
        path=name, sha256=sha256(data).hexdigest(), content=base64.b64encode(data).decode()
    )


def collect(root: Path) -> tuple[FileObject, ...]:
    _safe_directory(root)
    if not root.is_dir() or root.stat().st_mode & 0o077:
        raise ValueError("state root must be an existing private directory")
    result = []
    total = 0
    for current, directories, files in os.walk(root, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            info = path.lstat()
            if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise ValueError("state contains a link or nonregular member")
            if stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    raise ValueError("state contains a hardlinked member")
                data = read(path)
                total += len(data)
                result.append(file_object(path.relative_to(root).as_posix(), data))
                if total > MAX_BYTES or len(result) > MAX_FILES:
                    raise ValueError("complete state exceeds the supported cold checkpoint bound")
    if not result:
        raise ValueError("empty recovery state is not a complete deployment")
    return tuple(sorted(result, key=lambda item: item.path))


def seal(checkpoint: Checkpoint, key: bytes) -> bytes:
    raw = canonical(checkpoint)
    if len(key) != 32 or len(raw) > MAX_BYTES * 3:
        raise ValueError("checkpoint encryption key or total size is invalid")
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, raw, DOMAIN)


def authenticate(content: bytes, *, pin: str, key: bytes) -> Checkpoint:
    if (
        len(key) != 32
        or not 28 <= len(content) <= MAX_BYTES * 3 + 28
        or sha256(content).hexdigest() != pin
    ):
        raise ValueError("independent checkpoint pin or key length differs")
    raw = AESGCM(key).decrypt(content[:12], content[12:], DOMAIN)
    checkpoint = Checkpoint.model_validate_json(raw)
    paths = [obj.path for obj in checkpoint.files]
    if (
        paths != sorted(set(paths))
        or sum(len(object_bytes(obj)) for obj in checkpoint.files) > MAX_BYTES
    ):
        raise ValueError("checkpoint inventory is not canonical or exceeds its bound")
    if any(str(parent) in paths for name in paths for parent in Path(name).parents):
        raise ValueError("checkpoint files overlap")
    object_bytes(checkpoint.postgres_dump)
    if canonical(checkpoint) != raw:
        raise ValueError("checkpoint encoding is not canonical")
    return checkpoint


def restore_local(checkpoint: Checkpoint, target: Path) -> None:
    _safe_directory(target)
    target.mkdir(mode=0o700, exist_ok=False)
    for obj in checkpoint.files:
        _write_new(target / obj.path, object_bytes(obj))
    if collect(target) != checkpoint.files:
        raise ValueError("restored complete file set differs; keep target quarantined")
