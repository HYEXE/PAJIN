"""Operator cold checkpoint and separate-target restore for a pinned managed Linux host."""

from __future__ import annotations

import fcntl
import os
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.control_plane.security import CheckpointSigner
from pajin.operations.checkpoint_anchor import (
    MAX_ENTRIES,
    CheckpointAnchor,
    recovery_head,
    require_anchor,
)
from pajin.operations.hybrid_docker import Postgres, WriterFence, command, inspect_writer
from pajin.operations.hybrid_files import (
    authenticate,
    collect,
    file_object,
    object_bytes,
    read,
    restore_local,
    seal,
)
from pajin.operations.hybrid_models import Checkpoint, Deployment, canonical, digest
from pajin.operations.hybrid_verify import verify_state
from pajin.runtime.host_checkpoint import _safe_directory, _write_new


def implementation_digest() -> str:
    # A different verifier build requires an explicit compatibility review and new inventory.
    root = Path(__file__).resolve().parents[1]
    sources = sorted(root.rglob("*.py"))
    return digest(
        {p.relative_to(root).as_posix(): sha256(p.read_bytes()).hexdigest() for p in sources}
    )


def load_deployment(path: Path, *, pin: str, state: Path) -> Deployment:
    content = read(path, limit=1024 * 1024)
    if sha256(content).hexdigest() != pin:
        raise ValueError("independent deployment pin differs")
    plan = Deployment.model_validate_json(content)
    if plan.code_sha256 != implementation_digest():
        raise ValueError("current code differs from the deployment verifier build")
    if plan.state_root_sha256 != digest(str(state)):
        raise ValueError("state location differs from the pinned deployment")
    _safe_directory(state)
    return plan


@contextmanager
def operator_lock(state: Path) -> Iterator[None]:
    if sys.platform != "linux":
        raise ValueError("hybrid operator recovery requires the selected Linux host")
    _safe_directory(state.parent)
    lock = state.parent / (".hybrid-recovery-" + state.name + ".lock")
    fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_nlink != 1 or info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise ValueError("operator lock is not private and independently owned")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


def preflight(plan: Deployment, state: Path) -> dict[str, object]:
    WriterFence(plan).inspect(stopped=False)
    identity = Postgres(plan).identity()
    files = collect(state)
    return {
        "version": "pajin-hybrid-preflight-v1",
        "deployment": digest(plan),
        "database_identity": identity,
        "writers": len(plan.writers),
        "files": len(files),
        "execution_authorized": False,
    }


def _source_stopped(source: Deployment) -> None:
    WriterFence(source).inspect(stopped=True)
    state = inspect_writer(source.postgres, source.postgres_label, source.postgres_owner)
    if state.get("Running") or state.get("Pid") != 0:
        raise ValueError("source PostgreSQL must remain physically stopped")


def _compatible(source: Deployment, target: Deployment) -> None:
    if (
        source.deployment_id == target.deployment_id
        or source.postgres.container_id == target.postgres.container_id
        or source.state_root_sha256 == target.state_root_sha256
    ):
        raise ValueError("restore requires a separate deployment and PostgreSQL target")
    for name in (
        "graphs",
        "journals",
        "runs",
        "checkpoint_key_commitments",
        "code_sha256",
        "resume_signers",
        "recovery_anchor",
    ):
        if getattr(source, name) != getattr(target, name):
            raise ValueError("target changes the source store or verifier contract")
    if {w.container_id for w in source.writers} & {w.container_id for w in target.writers}:
        raise ValueError("source and restored writers must be distinct")


def create_checkpoint(
    plan: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    encryption_key: bytes,
    destination: Path,
    anchor: CheckpointAnchor | None = None,
    anchor_key: Ed25519PrivateKey | None = None,
    witness_key: Ed25519PrivateKey | None = None,
    expected_anchor_sequence: int | None = None,
) -> str:
    require_anchor(plan.recovery_anchor, anchor, state)
    if anchor is None and (
        anchor_key is not None or witness_key is not None or expected_anchor_sequence is not None
    ):
        raise ValueError("checkpoint publication requires deployment enrollment")
    if anchor is not None:
        if destination.is_relative_to(anchor.directory):
            raise ValueError("checkpoint archive must remain outside the independent anchor")
        if anchor.witness is not None and destination.is_relative_to(anchor.witness.directory):
            raise ValueError("checkpoint archive must remain outside the independent witness")
        if (
            anchor_key is None
            or type(expected_anchor_sequence) is not int
            or not 0 <= expected_anchor_sequence < MAX_ENTRIES
            or anchor_key.public_key().public_bytes_raw().hex() != anchor.binding.public_key_hex
        ):
            raise ValueError("checkpoint requires the enrolled publisher and expected sequence")
        anchor.require_publication_keys(anchor_key, witness_key)
        head = anchor.head()
        if expected_anchor_sequence != (head.sequence if head else 0):
            raise ValueError("checkpoint publication expectation is stale")
    pin = _create_checkpoint(
        plan,
        state,
        database_url=database_url,
        signer=signer,
        encryption_key=encryption_key,
        destination=destination,
    )
    if anchor is not None and anchor_key is not None and expected_anchor_sequence is not None:
        anchor.publish(
            checkpoint_pin=pin,
            source_pin=digest(plan),
            key=anchor_key,
            witness_key=witness_key,
            expected_sequence=expected_anchor_sequence,
        )
    return pin


def _create_checkpoint(
    plan: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    encryption_key: bytes,
    destination: Path,
) -> str:
    if len(encryption_key) != 32:
        raise ValueError("checkpoint requires an independent 32-byte encryption key")
    if destination.exists() or destination.is_relative_to(state):
        raise ValueError("checkpoint output must be new and outside application state")
    fence, postgres = WriterFence(plan), Postgres(plan)
    fence.inspect(stopped=True)
    postgres.require_no_clients()
    summary = verify_state(state, plan, database_url=database_url, signer=signer)
    files = collect(state)
    dump = postgres.dump()
    if summary != verify_state(
        state, plan, database_url=database_url, signer=signer
    ) or files != collect(state):
        raise ValueError("source changed while producing the cold checkpoint")
    fence.inspect(stopped=True)
    postgres.require_no_clients()
    checkpoint = Checkpoint(
        deployment=plan,
        source_database_identity=postgres.identity(),
        state_summary=summary,
        postgres_dump=file_object("postgres.dump", dump),
        files=files,
        created_at=datetime.now(UTC),
    )
    # Retain a complete stopped source before publishing any usable recovery object.
    command(["docker", "stop", "--time", "30", plan.postgres.container_id])
    _source_stopped(plan)
    content = seal(checkpoint, encryption_key)
    _write_new(destination, content)
    pin = sha256(content).hexdigest()
    if (
        authenticate(
            read(destination, limit=3 * 64 * 1024 * 1024 + 28), pin=pin, key=encryption_key
        )
        != checkpoint
    ):
        raise ValueError("published checkpoint differs from the verified complete source")
    return pin


def verify_restored(
    checkpoint: Checkpoint,
    target: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    checkpoint_pin: str,
    anchor: CheckpointAnchor | None = None,
) -> dict[str, object]:
    with recovery_head(
        target.recovery_anchor, anchor, state, checkpoint_pin, digest(checkpoint.deployment)
    ) as head:
        report = _verify_restored(
            checkpoint,
            target,
            state,
            database_url=database_url,
            signer=signer,
            checkpoint_pin=checkpoint_pin,
        )
        if head is not None:
            report["independent_checkpoint"] = head.model_dump(mode="json")
        return report


def _verify_restored(
    checkpoint: Checkpoint,
    target: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    checkpoint_pin: str,
) -> dict[str, object]:
    _compatible(checkpoint.deployment, target)
    _source_stopped(checkpoint.deployment)
    WriterFence(target).inspect(stopped=True)
    postgres = Postgres(target)
    identity = postgres.identity()
    if identity == checkpoint.source_database_identity:
        raise ValueError("restoration resolved to the original database")
    if collect(state) != checkpoint.files:
        raise ValueError("target local bytes differ from the independently pinned checkpoint")
    summary = verify_state(state, target, database_url=database_url, signer=signer)
    if summary != checkpoint.state_summary:
        raise ValueError("restored domain evidence differs; target remains quarantined")
    _source_stopped(checkpoint.deployment)
    WriterFence(target).inspect(stopped=True)
    return {
        "version": "pajin-hybrid-restoration-v1",
        "checkpoint_sha256": checkpoint_pin,
        "target_database_identity": identity,
        "target_state_sha256": target.state_root_sha256,
        "target_deployment_sha256": digest(target),
        "state_summary": summary,
        "verified": True,
        "execution_authorized": False,
        "external_rollback": "unknown",
    }


def restore_checkpoint(
    checkpoint: Checkpoint,
    target: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    checkpoint_pin: str,
    anchor: CheckpointAnchor | None = None,
) -> dict[str, object]:
    with recovery_head(
        target.recovery_anchor, anchor, state, checkpoint_pin, digest(checkpoint.deployment)
    ):
        return _restore_checkpoint(
            checkpoint,
            target,
            state,
            database_url=database_url,
            signer=signer,
            checkpoint_pin=checkpoint_pin,
            anchor=anchor,
        )


def _restore_checkpoint(
    checkpoint: Checkpoint,
    target: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    checkpoint_pin: str,
    anchor: CheckpointAnchor | None,
) -> dict[str, object]:
    _compatible(checkpoint.deployment, target)
    _source_stopped(checkpoint.deployment)
    WriterFence(target).inspect(stopped=True)
    postgres = Postgres(target)
    if postgres.identity() == checkpoint.source_database_identity:
        raise ValueError("target aliases the source database")
    postgres.require_empty()
    if state.exists():
        # Exact interrupted materialization may retry only while the target DB is empty.
        if collect(state) != checkpoint.files:
            raise ValueError("partial or conflicting target requires a new empty destination")
    else:
        restore_local(checkpoint, state)
    postgres.restore(object_bytes(checkpoint.postgres_dump))
    return verify_restored(
        checkpoint,
        target,
        state,
        database_url=database_url,
        signer=signer,
        checkpoint_pin=checkpoint_pin,
        anchor=anchor,
    )


def write_report(destination: Path, report: dict[str, object]) -> str:
    content = canonical(report)
    _write_new(destination, content)
    return sha256(content).hexdigest()
