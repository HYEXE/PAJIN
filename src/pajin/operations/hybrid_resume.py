"""Separate signed recovery approval and current authenticated CP continuation; no Worker start."""

from __future__ import annotations

import ssl
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from sqlalchemy import select

from pajin.control_plane.database import CheckpointRecord, ControlPlaneRepository
from pajin.control_plane.models import Principal, PrincipalRole, ResumeView
from pajin.control_plane.security import CheckpointSigner
from pajin.operations.checkpoint_anchor import CheckpointAnchor, recovery_head
from pajin.operations.hybrid import _compatible, _source_stopped
from pajin.operations.hybrid_docker import Postgres, WriterFence, inspect_writer
from pajin.operations.hybrid_files import collect
from pajin.operations.hybrid_models import (
    Checkpoint,
    Deployment,
    ResumeAuthorization,
    canonical,
    digest,
)
from pajin.operations.hybrid_verify import require_resume_budget, verify_state
from pajin.runtime.host_checkpoint import _write_new


def verify_authorization(
    grant: ResumeAuthorization,
    *,
    key: Ed25519PublicKey,
    subject: str,
    report: dict[str, object],
    checkpoint_pin: str,
    now: datetime,
) -> None:
    key.verify(bytes.fromhex(grant.signature_hex), grant.signed_bytes())
    if grant.checkpoint_sha256 != checkpoint_pin:
        raise ValueError("recovery authorization binds another authenticated archive")
    if (
        grant.expires_at.tzinfo is None
        or grant.expires_at <= now
        or grant.operator_subject != subject
    ):
        raise ValueError("recovery resume authorization is expired or belongs to another operator")
    if report.get("version") != "pajin-hybrid-restoration-v1" or report.get("verified") is not True:
        raise ValueError("recovery approval requires a successful independent verification report")
    if grant.verification_sha256 != digest(report):
        raise ValueError("recovery approval binds another verification receipt")
    for field in ("checkpoint_sha256", "target_database_identity", "target_state_sha256"):
        if getattr(grant, field) != report.get(field):
            raise ValueError("recovery approval binds another checkpoint or target")


def resume(
    checkpoint: Checkpoint,
    plan: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    report: dict[str, object],
    checkpoint_pin: str,
    grant: ResumeAuthorization,
    ca_path: Path,
    token: str,
    attempt_path: Path,
    anchor: CheckpointAnchor | None = None,
) -> dict[str, object]:
    with recovery_head(
        plan.recovery_anchor, anchor, state, checkpoint_pin, digest(checkpoint.deployment)
    ) as head:
        if head is not None and (
            report.get("independent_checkpoint") != head.model_dump(mode="json")
        ):
            raise ValueError("resume receipt differs from the independent latest checkpoint")
        return _resume(
            checkpoint, plan, state, database_url=database_url, signer=signer, report=report,
            checkpoint_pin=checkpoint_pin, grant=grant, ca_path=ca_path, token=token,
            attempt_path=attempt_path,
        )


def _resume(
    checkpoint: Checkpoint,
    plan: Deployment,
    state: Path,
    *,
    database_url: str,
    signer: CheckpointSigner,
    report: dict[str, object],
    checkpoint_pin: str,
    grant: ResumeAuthorization,
    ca_path: Path,
    token: str,
    attempt_path: Path,
) -> dict[str, object]:
    now = datetime.now(UTC)
    trusted = plan.resume_signers.get(grant.key_id)
    if trusted is None:
        raise ValueError("recovery resume signer is not in the independent deployment inventory")
    verify_authorization(
        grant,
        key=Ed25519PublicKey.from_public_bytes(bytes.fromhex(trusted.public_key_hex)),
        subject=trusted.subject,
        report=report,
        checkpoint_pin=checkpoint_pin,
        now=now,
    )
    if report.get("target_deployment_sha256") != digest(plan):
        raise ValueError("resume target differs from the verified deployment")
    _compatible(checkpoint.deployment, plan)
    _source_stopped(checkpoint.deployment)
    WriterFence(plan).inspect(stopped=False)
    # The operator may start the control-only API after verification. Execution Workers
    # stay stopped; they are activated separately after the existing CP approval succeeds.
    for writer in plan.writers:
        observed = inspect_writer(writer, plan.writer_label, plan.writer_owner)
        if writer.role != "control-plane" and (observed.get("Running") or observed.get("Pid") != 0):
            raise ValueError("execution Workers must remain stopped until separate activation")
    if (
        Postgres(plan).identity() != grant.target_database_identity
        or collect(state) != checkpoint.files
    ):
        raise ValueError("restored database identity or local evidence changed before resume")
    summary = verify_state(state, plan, database_url=database_url, signer=signer)
    for field in ("files_sha256", "graphs", "runs", "budgets"):
        if summary[field] != checkpoint.state_summary[field]:
            raise ValueError("local authority or conservative budgets changed before resume")
    repository = ControlPlaneRepository(database_url)
    try:
        with repository.read_transaction() as session:
            stored = session.scalar(
                select(CheckpointRecord).where(
                    CheckpointRecord.checkpoint_id == grant.checkpoint_id,
                )
            )
            if stored is None or stored.claimed_at is not None:
                raise ValueError("current checkpoint is absent or already consumed")
            run_id = stored.run_id
            require_resume_budget(summary, run_id, now=datetime.now(UTC))
    finally:
        repository.close()
    api_origin = plan.operator_api_origin
    origin = urlsplit(api_origin)
    if (
        origin.scheme != "https"
        or origin.hostname not in ("localhost", "127.0.0.1", "::1")
        or origin.username
        or origin.password
        or origin.path not in ("", "/")
        or origin.query
        or origin.fragment
        or not token
    ):
        raise ValueError("resume requires the independently configured local TLS operator API")
    if sha256(ca_path.read_bytes()).hexdigest() != plan.operator_ca_sha256:
        raise ValueError("operator API CA differs from its independent pin")
    context = ssl.create_default_context(cafile=str(ca_path))
    intent = {"authorization": digest(grant), "state": "outcome-unknown", "run_id": run_id}
    # An uncertain request is never retried automatically. CP also enforces one-use approval.
    with httpx.Client(
        verify=context, trust_env=False, timeout=30, follow_redirects=False
    ) as client:
        headers = {"Authorization": f"Bearer {token}"}
        session_response = client.get(api_origin.rstrip("/") + "/v1/session", headers=headers)
        if session_response.status_code != 200:
            raise ValueError("current operator authentication denied")
        principal = Principal.model_validate(session_response.json())
        if (
            principal.subject != grant.operator_subject
            or PrincipalRole.OPERATOR not in principal.roles
            or PrincipalRole.WORKER in principal.roles
        ):
            raise ValueError("current operator identity differs from the recovery authorization")
        _write_new(attempt_path, canonical(intent))
        response = client.post(
            api_origin.rstrip("/") + f"/v1/checkpoints/{grant.checkpoint_id}/resume",
            headers=headers,
            json={"approval_id": grant.approval_id},
        )
    if response.status_code != 200:
        raise ValueError("current Control Plane authentication, approval or resume policy denied")
    result = ResumeView.model_validate(response.json())
    if (
        result.run.run_id != run_id
        or result.job.run_id != run_id
        or result.checkpoint.checkpoint_id != grant.checkpoint_id
        or result.approval.approval_id != grant.approval_id
    ):
        raise ValueError("Control Plane returned an unrelated continuation")
    receipt: dict[str, object] = {
        "version": "pajin-hybrid-resume-receipt-v1",
        "authorization": digest(grant),
        "run_id": run_id,
        "job_id": result.job.job_id,
        "state": "approved-continuation-queued",
        "worker_started": False,
        "execution_authorized_by_restore": False,
    }
    _write_new(attempt_path.with_suffix(".result.json"), canonical(receipt))
    return receipt
