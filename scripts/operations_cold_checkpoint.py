"""Bounded private archive for the owned Linux rehearsal, not a runtime recovery API.

The caller must physically fence its owned writers. These byte checks do not supply
that authority and never activate a restored application or migrate a database.
"""

from __future__ import annotations

import base64
import json
import os
import stat
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from pajin.runtime.host_recovery_models import recovery_path
from pajin.runtime.safe_files import read_bounded_regular_bytes

MAX_BYTES = 64 * 1024 * 1024
MAX_FILES = 4096
DOMAIN = b"pajin.ops002.passive-cold-checkpoint/v1\0"
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class ColdFile(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    path: str
    sha256: Digest
    content: str

    @field_validator("path")
    @classmethod
    def canonical_path(cls, value: str) -> str:
        return recovery_path(value)

    def read(self) -> bytes:
        data = base64.b64decode(self.content, validate=True)
        if len(data) > MAX_BYTES or sha256(data).hexdigest() != self.sha256:
            raise ValueError("cold checkpoint file digest differs")
        return data


class ColdFiles(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["ops002-cold-files-v1"] = "ops002-cold-files-v1"
    files: tuple[ColdFile, ...] = Field(min_length=1, max_length=MAX_FILES)

    @model_validator(mode="after")
    def closed_set(self) -> Self:
        paths = [file.path for file in self.files]
        if paths != sorted(set(paths)):
            raise ValueError("cold checkpoint inventory must be unique and ordered")
        if any(str(parent) in paths for path in paths for parent in Path(path).parents):
            raise ValueError("cold checkpoint file and directory overlap")
        if sum(len(file.read()) for file in self.files) > MAX_BYTES:
            raise ValueError("cold checkpoint exceeds its total byte bound")
        return self


def encode(value: BaseModel) -> bytes:
    return json.dumps(value.model_dump(mode="json"), sort_keys=True, separators=(",", ":")).encode()


def _inventory(root: Path) -> list[Path]:
    paths: list[Path] = []
    for current, directories, files in os.walk(root, followlinks=False):
        for name in [*directories, *files]:
            path = Path(current) / name
            mode = path.lstat().st_mode
            if stat.S_ISLNK(mode) or not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
                raise ValueError("cold checkpoint requires regular local files and directories")
        paths.extend(Path(current) / name for name in files)
        if len(paths) > MAX_FILES:
            raise ValueError("cold checkpoint exceeds its file bound")
    return sorted(paths)


def collect(root: Path) -> ColdFiles:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("cold checkpoint root must be a regular directory")
    paths = _inventory(root)
    result = []
    total = 0
    for path in paths:
        data = read_bounded_regular_bytes(
            path,
            max_bytes=MAX_BYTES,
            label="cold checkpoint file",
            require_single_link=True,
        )
        total += len(data)
        if total > MAX_BYTES:
            raise ValueError("cold checkpoint exceeds its total byte bound")
        result.append(
            ColdFile(
                path=path.relative_to(root).as_posix(),
                sha256=sha256(data).hexdigest(),
                content=base64.b64encode(data).decode("ascii"),
            )
        )
    if _inventory(root) != paths:
        raise ValueError("cold checkpoint inventory changed during collection")
    return ColdFiles(files=tuple(result))


def restore(files: ColdFiles, destination: Path) -> None:
    # New leaf only; an interrupted restore stays incomplete and is never overwritten.
    destination.mkdir(mode=0o700, exist_ok=False)
    for file in files.files:
        target = destination / file.path
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with target.open("xb") as handle:
            handle.write(file.read())
            handle.flush()
            os.fsync(handle.fileno())
        target.chmod(0o600)
    if encode(collect(destination)) != encode(files):
        raise ValueError("restored local inventory differs from the checkpoint")


class ColdCheckpoint(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["ops002-linux-passive-cold-v1"] = "ops002-linux-passive-cold-v1"
    source_sha256: Digest
    runtime_image: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    expected_state_sha256: Digest
    postgres: ColdFile
    local: ColdFiles


def seal(checkpoint: ColdCheckpoint, key: bytes) -> bytes:
    content = encode(checkpoint)
    if len(key) != 32 or len(content) > MAX_BYTES * 3:
        raise ValueError("cold checkpoint key or envelope size is invalid")
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, content, DOMAIN)


def authenticate(data: bytes, *, expected_sha256: str, key: bytes) -> ColdCheckpoint:
    if (
        not 28 <= len(data) <= MAX_BYTES * 3 + 28
        or len(key) != 32
        or sha256(data).hexdigest() != expected_sha256
    ):
        raise ValueError("independent cold checkpoint pin differs")
    content = AESGCM(key).decrypt(data[:12], data[12:], DOMAIN)
    checkpoint = ColdCheckpoint.model_validate_json(content)
    checkpoint.postgres.read()
    if encode(checkpoint) != content:
        raise ValueError("cold checkpoint encoding differs")
    return checkpoint
