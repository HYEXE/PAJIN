"""Compose a closed checkpoint from actual first-use registrations and sealed Runs."""

from __future__ import annotations

import os
from hashlib import sha256
from pathlib import Path

from pajin.runtime.host_checkpoint_models import (
    MAX_CHECKPOINT_BYTES,
    MAX_CHECKPOINT_FILES,
    HostCheckpointError,
    HostCheckpointMember,
    HostCheckpointPlan,
)
from pajin.runtime.host_gate import HostActivityLease
from pajin.runtime.host_recovery import inspect_recovery_inventory
from pajin.runtime.inventory import load_runtime_inventory
from pajin.runtime.safe_files import read_bounded_regular_bytes
from pajin.runtime.store import verify_run_integrity


def build_registered_checkpoint_plan(
    lease: HostActivityLease,
    *,
    runtime_inventory_path: Path,
    expected_enrollment_sha256: str,
    recovery_set_id: str,
) -> HostCheckpointPlan:
    """Require a live exclusive gate and the separately expected enrollment identity."""
    lease.require_active(exclusive=True)
    runtime = load_runtime_inventory(runtime_inventory_path, lease.identity.inventory_sha256)
    enrollment = inspect_recovery_inventory(lease, require_complete=True)
    if (
        runtime.recovery_policy != "closed-local-sqlite-v1"
        or enrollment.digest != expected_enrollment_sha256
        or enrollment.components
        != tuple(sorted(runtime.components, key=lambda item: item.component_id))
    ):
        raise HostCheckpointError("checkpoint participants differ from their complete enrollment")
    members: list[HostCheckpointMember] = []
    for registration in enrollment.registrations:
        path = lease.root / "state" / registration.path
        if registration.kind == "run-store":
            verified = verify_run_integrity(path)
            if verified.run_id != registration.run_id:
                raise HostCheckpointError("registered RunStore identity differs from its seal")
            members.extend(_run_members(lease.root / "state", path))
        else:
            members.append(
                HostCheckpointMember(
                    path=registration.path,
                    kind=registration.kind,
                    campaignId=registration.campaign_id,
                    runBinding=registration.run_binding,
                )
            )
        if len(members) > MAX_CHECKPOINT_FILES:
            raise HostCheckpointError("registered checkpoint has too many member files")
    return HostCheckpointPlan(
        apiVersion="pajin.dev/host-checkpoint-plan/v2",
        recoverySetId=recovery_set_id,
        gate=lease.identity,
        enrollment=enrollment,
        members=tuple(sorted(members, key=lambda x: x.path)),
    )


def _run_members(state: Path, run: Path) -> list[HostCheckpointMember]:
    members: list[HostCheckpointMember] = []
    total = 0
    for directory, directories, filenames in os.walk(run, followlinks=False):
        for name in directories:
            if (Path(directory) / name).is_symlink():
                raise HostCheckpointError("registered RunStore contains a linked directory")
        for name in filenames:
            path = Path(directory) / name
            content = read_bounded_regular_bytes(
                path,
                max_bytes=MAX_CHECKPOINT_BYTES,
                label="registered RunStore member",
                require_single_link=True,
            )
            total += len(content)
            if total > MAX_CHECKPOINT_BYTES or len(members) >= MAX_CHECKPOINT_FILES:
                raise HostCheckpointError("registered RunStore exceeds checkpoint bounds")
            members.append(
                HostCheckpointMember(
                    path=path.relative_to(state).as_posix(),
                    kind="artifact",
                    artifactSha256=sha256(content).hexdigest(),
                )
            )
    return members


def verify_registered_checkpoint_members(state: Path, plan: HostCheckpointPlan) -> None:
    if plan.enrollment is None:
        return
    expected = {item.path: item for item in plan.members}
    covered: set[str] = set()
    for registration in plan.enrollment.registrations:
        if registration.kind == "run-store":
            run_path = state / registration.path
            verification = verify_run_integrity(run_path)
            if verification.run_id != registration.run_id:
                raise HostCheckpointError("checkpoint RunStore differs from its first registration")
            descendants = _run_members(state, run_path)
            for member in descendants:
                if expected.get(member.path) != member:
                    raise HostCheckpointError("registered RunStore is incomplete in the checkpoint")
                covered.add(member.path)
        else:
            member = HostCheckpointMember(
                path=registration.path,
                kind=registration.kind,
                campaignId=registration.campaign_id,
                runBinding=registration.run_binding,
            )
            if expected.get(member.path) != member:
                raise HostCheckpointError("checkpoint store differs from its first registration")
            covered.add(member.path)
    if covered != set(expected):
        raise HostCheckpointError(
            "checkpoint has members outside the complete first-use enrollment"
        )
