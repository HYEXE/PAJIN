"""Separately retained signed checkpoint intents; no automatic repair or execution authority."""

from __future__ import annotations

import argparse
import fcntl
import os
import stat
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import Field

from pajin.operations.checkpoint_anchor import (
    MAX_ENTRIES,
    AnchorBinding,
    AnchorEntry,
    CheckpointAnchor,
    Digest,
    Genesis,
    Model,
    WitnessBinding,
    _read,
)
from pajin.operations.hybrid_models import canonical, digest
from pajin.runtime.host_checkpoint import _safe_directory, _write_new

DOMAIN = b"pajin.recovery-witness/v1\0"
MAX_LOG_BYTES = MAX_ENTRIES * 2048


class WitnessGenesis(Model):
    version: Literal["pajin-recovery-witness-genesis-v1"] = "pajin-recovery-witness-genesis-v1"
    authority_id: str = Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$")
    public_key_hex: Digest
    nonce: Digest
    anchor_genesis: Genesis


class WitnessEntry(Model):
    version: Literal["pajin-recovery-witness-entry-v1"] = "pajin-recovery-witness-entry-v1"
    previous_sha256: Digest
    anchor_entry: AnchorEntry
    signature_hex: str = Field(pattern=r"^[a-f0-9]{128}$")

    def signed_bytes(self) -> bytes:
        return DOMAIN + canonical(self.model_dump(mode="json", exclude={"signature_hex"}))


def initialize_witness(
    anchor: CheckpointAnchor, directory: Path, *, authority_id: str, public_key_hex: str
) -> AnchorBinding:
    """Explicitly enroll an empty anchor; callers must pin the returned v2 deployment."""
    if anchor.binding.witness is not None:
        raise ValueError("anchor already has a witness enrollment")
    anchor.require_outside(directory)
    if public_key_hex == anchor.binding.public_key_hex:
        raise ValueError("witness and anchor publishers must use distinct signing keys")
    with anchor.lock(exclusive=True):
        if anchor._entries():
            raise ValueError("witness enrollment requires an empty anchor")
        genesis = WitnessGenesis(
            authority_id=authority_id,
            public_key_hex=public_key_hex,
            nonce=os.urandom(32).hex(),
            anchor_genesis=Genesis.model_validate_json(
                _read(anchor.directory / "genesis.json", 4096)
            ),
        )
        _safe_directory(directory)
        directory.mkdir(mode=0o700, exist_ok=False)
        _write_new(directory / "genesis.json", canonical(genesis))
        _write_new(directory / "entries.jsonl", b"")
        _write_new(directory / "lock", b"")
        return AnchorBinding(
            version="pajin-recovery-anchor-v2",
            authority_id=anchor.binding.authority_id,
            public_key_hex=anchor.binding.public_key_hex,
            genesis_sha256=anchor.binding.genesis_sha256,
            witness=WitnessBinding(
                authority_id=authority_id,
                public_key_hex=public_key_hex,
                genesis_sha256=digest(genesis),
            ),
        )


class CheckpointWitness:
    def __init__(self, directory: Path, binding: WitnessBinding) -> None:
        self.directory = directory
        self.binding = WitnessBinding.model_validate_json(binding.model_dump_json())

    def require_outside(self, path: Path) -> None:
        _safe_directory(path)
        _safe_directory(self.directory)
        if path.is_relative_to(self.directory) or self.directory.is_relative_to(path):
            raise ValueError("witness, anchor and application state must be disjoint")

    @contextmanager
    def lock(self, *, exclusive: bool) -> Iterator[None]:
        _safe_directory(self.directory)
        info = self.directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("witness directory must be private and operator owned")
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
                raise ValueError("witness lock differs")
            fcntl.flock(descriptor, (fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH) | fcntl.LOCK_NB)
            yield
        finally:
            os.close(descriptor)

    def _genesis(self) -> WitnessGenesis:
        raw = _read(self.directory / "genesis.json", 8192)
        genesis = WitnessGenesis.model_validate_json(raw)
        if (
            raw != canonical(genesis)
            or digest(genesis) != self.binding.genesis_sha256
            or genesis.authority_id != self.binding.authority_id
            or genesis.public_key_hex != self.binding.public_key_hex
            or genesis.public_key_hex == genesis.anchor_genesis.public_key_hex
        ):
            raise ValueError("witness genesis differs from enrollment")
        return genesis

    def _entries(self) -> tuple[WitnessEntry, ...]:
        genesis = self._genesis()
        lines = _read(self.directory / "entries.jsonl", MAX_LOG_BYTES).splitlines(keepends=True)
        if len(lines) > MAX_ENTRIES:
            raise ValueError("witness exceeds its capacity")
        previous, anchor_previous = self.binding.genesis_sha256, digest(genesis.anchor_genesis)
        witness_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(genesis.public_key_hex))
        anchor_key = Ed25519PublicKey.from_public_bytes(
            bytes.fromhex(genesis.anchor_genesis.public_key_hex)
        )
        values = []
        checkpoints: set[str] = set()
        for sequence, line in enumerate(lines, start=1):
            entry = WitnessEntry.model_validate_json(line)
            anchor = entry.anchor_entry
            if (
                line != canonical(entry) + b"\n"
                or entry.previous_sha256 != previous
                or anchor.sequence != sequence
                or anchor.previous_sha256 != anchor_previous
                or anchor.checkpoint_sha256 in checkpoints
            ):
                raise ValueError("witness chain is incomplete or inconsistent")
            witness_key.verify(bytes.fromhex(entry.signature_hex), entry.signed_bytes())
            anchor_key.verify(bytes.fromhex(anchor.signature_hex), anchor.signed_bytes())
            previous, anchor_previous = digest(entry), digest(anchor)
            checkpoints.add(anchor.checkpoint_sha256)
            values.append(entry)
        return tuple(values)

    def require_anchor(self, binding: AnchorBinding, entries: tuple[AnchorEntry, ...]) -> None:
        genesis = self._genesis().anchor_genesis
        if (
            binding.witness != self.binding
            or binding.genesis_sha256 != digest(genesis)
            or binding.authority_id != genesis.authority_id
            or binding.public_key_hex != genesis.public_key_hex
        ):
            raise ValueError("witness belongs to another anchor enrollment")
        if tuple(record.anchor_entry for record in self._entries()) != entries:
            raise ValueError(
                "anchor differs from independently retained witness; recovery is blocked"
            )

    def require_publisher(self, key: Ed25519PrivateKey | None) -> None:
        if key is None or key.public_key().public_bytes_raw().hex() != self.binding.public_key_hex:
            raise ValueError("checkpoint requires the separately enrolled witness publisher")

    def _publish_intent(
        self,
        binding: AnchorBinding,
        entries: tuple[AnchorEntry, ...],
        new: AnchorEntry,
        *,
        key: Ed25519PrivateKey | None,
    ) -> None:
        """Called only under both exclusive locks, before appending the anchor record."""
        self.require_publisher(key)
        self.require_anchor(binding, entries)
        records = self._entries()
        if (
            new.sequence != len(records) + 1
            or new.sequence > MAX_ENTRIES
            or new.previous_sha256 != (digest(entries[-1]) if entries else binding.genesis_sha256)
            or any(new.checkpoint_sha256 == old.checkpoint_sha256 for old in entries)
        ):
            raise ValueError("witness publication sequence differs")
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(binding.public_key_hex)).verify(
            bytes.fromhex(new.signature_hex), new.signed_bytes()
        )
        value = WitnessEntry(
            previous_sha256=digest(records[-1]) if records else self.binding.genesis_sha256,
            anchor_entry=new,
            signature_hex="0" * 128,
        )
        assert key is not None
        value = value.model_copy(update={"signature_hex": key.sign(value.signed_bytes()).hex()})
        self._append(value)
        if self._entries() != (*records, value):
            raise ValueError("witness publication is incomplete; keep source stopped")

    def _append(self, value: WitnessEntry) -> None:
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
                raise ValueError("witness append target differs")
            content = canonical(value) + b"\n"
            if os.write(descriptor, content) != len(content):
                raise ValueError("witness append is incomplete; keep source stopped")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def inspect(self) -> AnchorEntry | None:
        with self.lock(exclusive=False):
            values = self._entries()
            return values[-1].anchor_entry if values else None

    def restore_anchor(self, destination: Path) -> AnchorBinding:
        """Explicitly reconstruct into a new empty directory; retain the damaged original."""
        self.require_outside(destination)
        with self.lock(exclusive=False):
            genesis, records = self._genesis(), self._entries()
            _safe_directory(destination)
            destination.mkdir(mode=0o700, exist_ok=False)
            _write_new(destination / "genesis.json", canonical(genesis.anchor_genesis))
            _write_new(
                destination / "entries.jsonl",
                b"".join(canonical(record.anchor_entry) + b"\n" for record in records),
            )
            _write_new(destination / "lock", b"")
            binding = AnchorBinding(
                version="pajin-recovery-anchor-v2",
                authority_id=genesis.anchor_genesis.authority_id,
                public_key_hex=genesis.anchor_genesis.public_key_hex,
                genesis_sha256=digest(genesis.anchor_genesis),
                witness=self.binding,
            )
            anchor = CheckpointAnchor(destination, binding, witness=self)
            if anchor.head() != (records[-1].anchor_entry if records else None):
                raise ValueError("restored anchor differs from independent witness")
            return binding


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("init", "inspect", "restore-anchor"))
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("--anchor-binding", required=True, type=Path)
    parser.add_argument("--anchor-directory", type=Path)
    parser.add_argument("--target-directory", type=Path)
    parser.add_argument("--output-binding", type=Path)
    parser.add_argument("--authority-id")
    parser.add_argument("--public-key")
    args = parser.parse_args()
    binding = AnchorBinding.model_validate_json(_read(args.anchor_binding, 8192))
    if args.operation != "inspect" and (
        args.output_binding is None or args.output_binding.exists()
    ):
        parser.error("mutation requires a create-only binding output")
    if args.operation == "init":
        if not all((args.anchor_directory, args.authority_id, args.public_key)):
            parser.error("init requires an empty anchor, witness authority and public key")
        binding = initialize_witness(
            CheckpointAnchor(args.anchor_directory, binding),
            args.directory,
            authority_id=args.authority_id,
            public_key_hex=args.public_key,
        )
    else:
        if binding.witness is None:
            parser.error("operation requires a witness-enrolled anchor binding")
        witness = CheckpointWitness(args.directory, binding.witness)
        if args.operation == "inspect":
            head = witness.inspect()
            print(head.model_dump_json() if head else "null")
            return
        if args.target_directory is None:
            parser.error("restore-anchor requires a new empty destination")
        binding = witness.restore_anchor(args.target_directory)
    _write_new(args.output_binding, binding.model_dump_json().encode())
    print(binding.model_dump_json())


def _entrypoint() -> None:
    try:
        main()
    except (OSError, ValueError, InvalidSignature) as exc:
        # Do not echo malformed records, local paths or signing material.
        print(f"checkpoint witness operation refused: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(2) from None


if __name__ == "__main__":
    # Keep exact-class checks stable when runpy executes this module as __main__.
    from pajin.operations.checkpoint_witness import _entrypoint as entrypoint

    entrypoint()
