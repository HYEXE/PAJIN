"""An independently retained checkpoint head, outside the state being restored.

This is a trusted local-volume boundary, not a distributed witness. Restoring this
volume together with application state defeats its rollback protection.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field

from pajin.runtime.host_checkpoint import _safe_directory, _write_new
from pajin.runtime.safe_files import read_bounded_regular_bytes

DOMAIN = b"pajin.recovery-anchor/v1\0"
MAX_ENTRIES = 4096
MAX_LOG_BYTES = MAX_ENTRIES * 1024
Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class Model(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)


class AnchorBinding(Model):
    version: Literal["pajin-recovery-anchor-v1"] = "pajin-recovery-anchor-v1"
    authority_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
    public_key_hex: Digest
    genesis_sha256: Digest


class Genesis(Model):
    version: Literal["pajin-recovery-anchor-genesis-v1"] = "pajin-recovery-anchor-genesis-v1"
    authority_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
    public_key_hex: Digest
    nonce: Digest


class AnchorEntry(Model):
    version: Literal["pajin-recovery-anchor-entry-v1"] = "pajin-recovery-anchor-entry-v1"
    sequence: int = Field(ge=1, le=MAX_ENTRIES)
    previous_sha256: Digest
    checkpoint_sha256: Digest
    source_deployment_sha256: Digest
    signature_hex: str = Field(pattern=r"^[a-f0-9]{128}$")

    def signed_bytes(self) -> bytes:
        from pajin.operations.hybrid_models import canonical

        return DOMAIN + canonical(self.model_dump(mode="json", exclude={"signature_hex"}))


def _read(path: Path, limit: int) -> bytes:
    info = path.lstat()
    if info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("independent anchor must remain private and operator owned")
    return read_bounded_regular_bytes(
        path, max_bytes=limit, label="independent checkpoint anchor", require_single_link=True
    )


def initialize(directory: Path, *, authority_id: str, public_key_hex: str) -> AnchorBinding:
    from pajin.operations.hybrid_models import canonical, digest

    genesis = Genesis(
        authority_id=authority_id, public_key_hex=public_key_hex, nonce=os.urandom(32).hex()
    )
    _safe_directory(directory)
    directory.mkdir(mode=0o700, exist_ok=False)
    # A partial initialization fails closed. Neither readers nor publishers repair it.
    _write_new(directory / "genesis.json", canonical(genesis))
    _write_new(directory / "entries.jsonl", b"")
    _write_new(directory / "lock", b"")
    return AnchorBinding(
        authority_id=authority_id,
        public_key_hex=public_key_hex,
        genesis_sha256=digest(genesis),
    )


class CheckpointAnchor:
    def __init__(self, directory: Path, binding: AnchorBinding) -> None:
        self.directory = directory
        self.binding = AnchorBinding.model_validate_json(binding.model_dump_json())

    def require_outside(self, state: Path) -> None:
        _safe_directory(state)
        _safe_directory(self.directory)
        if self.directory.is_relative_to(state) or state.is_relative_to(self.directory):
            raise ValueError("independent anchor and application state must be disjoint")

    @contextmanager
    def lock(self, *, exclusive: bool) -> Iterator[None]:
        _safe_directory(self.directory)
        info = self.directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("independent anchor directory must be private and operator owned")
        descriptor = os.open(
            self.directory / "lock", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
                or info.st_size != 0
            ):
                raise ValueError("independent anchor lock differs")
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def _entries(self) -> tuple[AnchorEntry, ...]:
        from pajin.operations.hybrid_models import canonical, digest

        raw = _read(self.directory / "genesis.json", 4096)
        genesis = Genesis.model_validate_json(raw)
        if (
            raw != canonical(genesis)
            or digest(genesis) != self.binding.genesis_sha256
            or genesis.authority_id != self.binding.authority_id
            or genesis.public_key_hex != self.binding.public_key_hex
        ):
            raise ValueError("independent anchor genesis differs from deployment enrollment")
        data = _read(self.directory / "entries.jsonl", MAX_LOG_BYTES)
        lines = data.splitlines(keepends=True)
        if len(lines) > MAX_ENTRIES:
            raise ValueError("independent anchor exceeds its capacity")
        previous = self.binding.genesis_sha256
        key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.binding.public_key_hex))
        entries = []
        seen = set()
        for sequence, line in enumerate(lines, start=1):
            entry = AnchorEntry.model_validate_json(line)
            if (
                line != canonical(entry) + b"\n"
                or entry.sequence != sequence
                or entry.previous_sha256 != previous
                or entry.checkpoint_sha256 in seen
            ):
                raise ValueError("independent anchor chain is incomplete or inconsistent")
            key.verify(bytes.fromhex(entry.signature_hex), entry.signed_bytes())
            previous = digest(entry)
            seen.add(entry.checkpoint_sha256)
            entries.append(entry)
        return tuple(entries)

    def head(self) -> AnchorEntry | None:
        with self.lock(exclusive=False):
            entries = self._entries()
            return entries[-1] if entries else None

    @contextmanager
    def hold(self, checkpoint_pin: str, source_pin: str) -> Iterator[AnchorEntry]:
        """Prevent cooperating publishers from advancing during a recovery operation."""
        with self.lock(exclusive=False):
            entries = self._entries()
            if not entries or (
                entries[-1].checkpoint_sha256 != checkpoint_pin
                or entries[-1].source_deployment_sha256 != source_pin
            ):
                raise ValueError("checkpoint is not the independent latest recovery head")
            head = entries[-1]
            yield head
            if self._entries() != entries:
                raise ValueError("independent recovery head changed during verification")

    def publish(
        self,
        *,
        checkpoint_pin: str,
        source_pin: str,
        expected_sequence: int,
        key: Ed25519PrivateKey,
    ) -> AnchorEntry:
        from pajin.operations.hybrid_models import canonical, digest

        if key.public_key().public_bytes_raw().hex() != self.binding.public_key_hex:
            raise ValueError("checkpoint publisher differs from independent anchor authority")
        if type(expected_sequence) is not int or not 0 <= expected_sequence < MAX_ENTRIES:
            raise ValueError("checkpoint publication requires a bounded expected sequence")
        with self.lock(exclusive=True):
            entries = self._entries()
            if len(entries) != expected_sequence or any(
                entry.checkpoint_sha256 == checkpoint_pin for entry in entries
            ):
                raise ValueError("checkpoint publication is stale or repeats an old archive")
            value = AnchorEntry(
                sequence=len(entries) + 1,
                previous_sha256=digest(entries[-1]) if entries else self.binding.genesis_sha256,
                checkpoint_sha256=checkpoint_pin,
                source_deployment_sha256=source_pin,
                signature_hex="0" * 128,
            )
            signed = value.model_copy(
                update={"signature_hex": key.sign(value.signed_bytes()).hex()}
            )
            path = self.directory / "entries.jsonl"
            descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                info = os.fstat(descriptor)
                observed = path.stat(follow_symlinks=False)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or (info.st_dev, info.st_ino) != (observed.st_dev, observed.st_ino)
                    or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("independent anchor append target differs")
                content = canonical(signed) + b"\n"
                if os.write(descriptor, content) != len(content):
                    raise ValueError("independent anchor append is incomplete; keep source stopped")
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            if self._entries() != (*entries, signed):
                raise ValueError("independent anchor publication failed verification")
            return signed


def require_anchor(
    binding: AnchorBinding | None, anchor: CheckpointAnchor | None, state: Path
) -> None:
    if binding is None:
        if anchor is not None:
            raise ValueError("independent anchor is not enrolled in this deployment")
        return
    if type(anchor) is not CheckpointAnchor or anchor.binding != binding:
        raise ValueError("deployment requires its independently enrolled checkpoint anchor")
    anchor.require_outside(state)


@contextmanager
def recovery_head(
    binding: AnchorBinding | None,
    anchor: CheckpointAnchor | None,
    state: Path,
    checkpoint_pin: str,
    source_pin: str,
) -> Iterator[AnchorEntry | None]:
    require_anchor(binding, anchor, state)
    if anchor is None:
        yield None
    else:
        with anchor.hold(checkpoint_pin, source_pin) as head:
            yield head


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "inspect"))
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--binding", type=Path, required=True)
    parser.add_argument("--authority-id")
    parser.add_argument("--public-key")
    args = parser.parse_args()
    if args.operation == "init":
        if not args.authority_id or not args.public_key or args.binding.exists():
            parser.error("init requires an authority, public key and new binding output")
        binding = initialize(
            args.directory, authority_id=args.authority_id, public_key_hex=args.public_key
        )
        _write_new(args.binding, binding.model_dump_json().encode())
        print(binding.model_dump_json())
    else:
        binding = AnchorBinding.model_validate_json(_read(args.binding, 4096))
        head = CheckpointAnchor(args.directory, binding).head()
        print(head.model_dump_json() if head else "null")


if __name__ == "__main__":
    main()
