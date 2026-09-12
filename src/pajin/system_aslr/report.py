"""Read pinned SYS-004 evidence with deployment trust supplied independently of the Run."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Literal

from pydantic import Field

from pajin.capabilities.adapters import registered_action_capability
from pajin.capabilities.authorities import CapabilityAuthorityRole, CapabilityOracleDecision
from pajin.capabilities.lifecycle import (
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
)
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    ToolResult,
    campaign_manifest_digest,
)
from pajin.graph import (
    ActionApprovalCapabilityPolicy,
    ActionApprovalConsumptionReceipt,
    ActionPermit,
)
from pajin.graph.approval import (
    build_action_approval_consumption_receipt,
    validate_action_approval_authority,
)
from pajin.graph.authority import build_action_permit
from pajin.runtime.secrets import SecretBroker, SecretLease, SecretLeaseStatus
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import EgressPolicy, WorkerResult
from pajin.system_aslr.capability import aslr_capability_bundle
from pajin.system_aslr.models import (
    SECRET_REF,
    AslrDeployment,
    AslrRunReference,
    AslrWorkerOutput,
    Digest,
    aslr_metadata,
    digest,
)
from pajin.system_aslr.runtime import (
    AslrActivation,
    AslrOperatorAuthority,
    SignedAslrApproval,
)
from pajin.system_aslr.tool import AslrReadTool, aslr_worker_limits
from pajin.tools.execution_receipts import NormalizedHostReceipt, project_tool_result
from pajin.tools.gateway import GatewayOutcome


class AslrReportTrust(StrictModel):
    """Trusted deployment configuration; never recovered as authority from execution evidence."""

    deployment: AslrDeployment
    operator_public_key: str = Field(pattern=r"^[a-f0-9]{64}$")
    operator_id: str = Field(min_length=1, max_length=200)
    policy: CapabilityLifecyclePolicy
    keys: tuple[CapabilityLifecycleTrustKey, ...]
    releases: tuple[CapabilityReleaseBundle, ...]
    release: CapabilityReleaseRef

    @property
    def commitment(self) -> str:
        return digest(self.model_dump(mode="json", by_alias=True))

    def activation(self, now: datetime) -> AslrActivation:
        tool = AslrReadTool(self.deployment)
        bundle = aslr_capability_bundle(tool)
        registry = CapabilityLifecycleRegistry(
            definitions=bundle.definitions,
            authorities=bundle.authorities,
            policy=self.policy,
            trust_keys=self.keys,
            releases=self.releases,
            clock=lambda: now,
        )
        return AslrActivation(bundle, registry, self.release)


class AslrExecutionRecord(StrictModel):
    version: Literal["pajin.sys-004.execution/v1"] = "pajin.sys-004.execution/v1"
    trust_commitment: Digest
    request_id: str
    outcome: GatewayOutcome
    cleanup: Literal["absent", "present", "unknown", "not-created"]
    cleanup_observed_at: datetime


def observe_worker_absence(
    result: WorkerResult | None,
) -> Literal["absent", "present", "unknown", "not-created"]:
    if result is None:
        return "not-created"
    if result.backend != "docker":
        return "unknown"
    for command in (("ps", "--all"), ("network", "ls")):
        try:
            process = subprocess.run(
                [
                    "docker",
                    *command,
                    "--filter",
                    "label=pajin.execution-id=" + result.execution_id,
                    "--format",
                    "{{.ID}}",
                ],
                capture_output=True,
                timeout=15,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return "unknown"
        if process.returncode:
            return "unknown"
        if process.stdout.strip():
            return "present"
    return "absent"


def seal_aslr_execution(
    store: RunStore, outcome: GatewayOutcome, trust: AslrReportTrust
) -> AslrRunReference:
    record = AslrExecutionRecord(
        trust_commitment=trust.commitment,
        request_id=outcome.result.request_id,
        outcome=outcome,
        cleanup=observe_worker_absence(outcome.worker_result),
        cleanup_observed_at=datetime.now(UTC),
    )
    store.write_json_create_only("execution.json", record.model_dump(mode="json"))
    store.append_event(
        "sys-004.execution-recorded", {"cleanup": record.cleanup, "success": outcome.result.success}
    )
    seal = store.seal()
    return AslrRunReference(run_id=store.run_id, root_digest=seal.root_digest)


def _read(root: Path, reference: AslrRunReference, names: tuple[str, ...]) -> dict[str, bytes]:
    root = root.absolute()
    path = root / "sys-004-run" / reference.run_id
    if root.resolve() != root or path.is_symlink() or path.parent.is_symlink():
        raise ValueError("System Run path contains a symbolic link")
    snapshot = load_verified_run_artifacts(
        path,
        requests={name: 1024 * 1024 for name in names},
        expected_run_id=reference.run_id,
    )
    if snapshot.verification.root_digest != reference.root_digest:
        raise ValueError("System Run differs from its independently pinned root")
    return {name: snapshot.artifact_bytes(name) for name in names}


def read_aslr_run(
    root: Path, reference: AslrRunReference, trust: AslrReportTrust,
    *, expected_campaign: str | None = None,
) -> dict[str, object]:
    """Recompute bindings and authenticated output without a agent credentials, Worker or signer."""
    inputs = _read(
        root, reference, ("authorization.json", "execution.json", "sys-004-plan-reservation.json")
    )
    authorization = json.loads(inputs["authorization.json"])
    record = AslrExecutionRecord.model_validate_json(inputs["execution.json"])
    signed = SignedAslrApproval.model_validate(authorization["signedApproval"])
    approval = signed.approval
    permit = ActionPermit.model_validate(authorization["permit"])
    receipt = ActionApprovalConsumptionReceipt.model_validate(authorization["approvalReceipt"])
    request = ToolRequest.model_validate(authorization["request"])
    campaign = CampaignManifest.model_validate(authorization["campaign"])
    if expected_campaign is not None and campaign.metadata.name != expected_campaign:
        raise ValueError("System Run differs from the deployment-pinned Campaign")
    grant = CapabilityGrant.model_validate(authorization["grant"])
    if json.loads(inputs["sys-004-plan-reservation.json"]) != {
        "request": request.model_dump(mode="json"),
        "campaignDigest": campaign_manifest_digest(campaign),
        "grantDigest": digest(grant.model_dump(mode="json")),
    }:
        raise ValueError("System Run reservation differs from its one approved request")
    if (
        record.trust_commitment != trust.commitment
        or record.request_id != request.request_id
        or approval.run_id != reference.run_id
        or authorization["operatorPublicKey"] != trust.operator_public_key
        or authorization["operatorId"] != trust.operator_id
    ):
        raise ValueError("System execution differs from independent deployment trust or Run")
    activation = trust.activation(permit.consumed_at)
    tool = AslrReadTool(trust.deployment)
    authority = AslrOperatorAuthority(
        activation=activation,
        public_key=bytes.fromhex(trust.operator_public_key),
        operator_id=trust.operator_id,
        signed=signed,
        campaign=campaign,
        grant=grant,
        request=request,
        tool=tool,
        clock=lambda: permit.consumed_at,
    )
    authority.verify_action_approval(
        approval.mission_envelope, approval.proposal, approval.graph_decision, approval
    )
    capability = registered_action_capability(activation.bundle.definition)
    validate_action_approval_authority(
        approval.mission_envelope,
        approval.proposal,
        approval.graph_decision,
        capability,
        ActionApprovalCapabilityPolicy(
            capability=capability.reference(),
            sideEffectClass="read-only",
            approvalRequired=True,
            cleanupRequired=False,
        ),
        approval,
        evaluated_at=permit.consumed_at,
    )
    expected = build_action_permit(
        approval.mission_envelope,
        approval.proposal,
        approval.graph_decision,
        evaluated_at=permit.consumed_at,
        permit_ttl=timedelta(seconds=30),
    )
    if permit != expected or receipt != build_action_approval_consumption_receipt(approval, permit):
        raise ValueError("System Permit or approval consumption differs")
    filename = "evidence/" + request.request_id + ".json"
    gateway = json.loads(_read(root, reference, (filename,))[filename])
    outcome = record.outcome
    if (
        gateway["request"] != request.model_dump(mode="json")
        or gateway["policyDecision"] != outcome.decision.model_dump(mode="json")
        or not outcome.result_identity_valid
        or outcome.result.request_id != request.request_id
        or outcome.result.evidence != [filename]
        or gateway["result"]
        != outcome.result.model_copy(update={"evidence": []}).model_dump(mode="json")
    ):
        raise ValueError("System detached Gateway evidence differs")
    worker = outcome.worker_result
    setting = None
    if worker is not None:
        if gateway.get("workerResult") != worker.model_dump(mode="json"):
            raise ValueError("System detached Worker receipt differs")
        job = gateway["workerJob"]
        if len(gateway["secretLeases"]) != 1:
            raise ValueError("System execution requires exactly one consumed Secret Lease")
        lease = SecretLease.model_validate(gateway["secretLeases"][0])
        if (
            lease.scope != reference.run_id
            or lease.audience != f"{request.agent_id}:{worker.execution_id}"
            or lease.binding != "system-mtls"
            or lease.max_uses != 1
            or lease.remaining_uses != 0
            or lease.secret_ref_fingerprint != SecretBroker.fingerprint(SECRET_REF)
            or lease.status is not SecretLeaseStatus.REVOKED
            or lease.expires_at - lease.issued_at != timedelta(seconds=30)
            or not permit.consumed_at <= lease.issued_at <= worker.started_at < lease.expires_at
        ):
            raise ValueError("System Secret Lease differs from the one approved invocation")
        if (
            worker.backend != "docker"
            or not outcome.executed
            or not outcome.decision.allowed
            or not permit.consumed_at <= worker.started_at < permit.expires_at
            or worker.finished_at > record.cleanup_observed_at
            or job["image"] != trust.deployment.image_id
            or job["executionId"] != worker.execution_id
            or job["command"] != ["system-aslr"]
            or job["network"] != "egress-proxy"
            or job["limits"] != aslr_worker_limits().model_dump(mode="json")
            or job["stdinBytes"] != len(tool.prepare(request).stdin.encode())
            or job["stdinSha256"] != sha256(tool.prepare(request).stdin.encode()).hexdigest()
            or EgressPolicy.model_validate(job["egressPolicy"])
            != EgressPolicy(
                allow=campaign.spec.scope.allow,
                deny=campaign.spec.scope.deny,
                allowed_methods=campaign.spec.rules_of_engagement.allowed_methods,
                allow_private_networks=campaign.spec.rules_of_engagement.allow_private_networks,
                max_requests=1,
            )
            or job["secretRequests"]
            != [
                {
                    "binding": "system-mtls",
                    "ttlSeconds": 30,
                    "secretRefFingerprint": SecretBroker.fingerprint(SECRET_REF),
                }
            ]
            or job["secretLeaseIds"] != []
        ):
            raise ValueError("System Worker execution identity, timing or confinement differs")
        normalized = project_tool_result(
            request=request,
            tool=tool,
            receipt=NormalizedHostReceipt(worker, True, False),
            materials=[],
        ).result
        expected_result = ToolResult.model_validate(gateway["result"])
        if normalized != expected_result:
            raise ValueError("System authenticated result differs from reinterpreted Worker output")
        oracle = activation.bundle.authorities.authority(
            activation.bundle.reference, CapabilityAuthorityRole.SUCCESS_ORACLE
        )
        if oracle.evaluate(request, normalized) is CapabilityOracleDecision.SUCCEEDED:
            output = AslrWorkerOutput.model_validate(normalized.data["receipt"])
            setting = {
                "metadata": aslr_metadata(output.agent.content()),
                "fileSha256": output.agent.file_sha256,
                "fileBytes": output.agent.file_bytes,
            }
    elif outcome.executed or outcome.result.success or record.cleanup != "not-created":
        raise ValueError("System execution without a Worker cannot claim success or cleanup")
    return {
        "version": "pajin.sys-004.product-read/v1",
        "run": reference.model_dump(),
        "trustCommitment": trust.commitment,
        "scopeDigest": digest(campaign.spec.scope.model_dump(mode="json")),
        "rulesDigest": digest(campaign.spec.rules_of_engagement.model_dump(mode="json")),
        "requestId": request.request_id,
        "approvalId": approval.approval_id,
        "permitId": permit.permit_id,
        "executionId": worker.execution_id if worker else None,
        "startedAt": worker.started_at.isoformat() if worker else None,
        "finishedAt": worker.finished_at.isoformat() if worker else None,
        "workerExecuted": outcome.executed,
        "aslr": setting,
        "cleanup": record.cleanup,
        "complete": setting is not None and record.cleanup == "absent",
        "findingAuthority": False,
        "generalSystemSupport": False,
        "processAslrVerified": False,
        "physicalHostVerified": False,
    }


def compare_aslr_runs(
    root: Path, source: AslrRunReference, replay: AslrRunReference, trust: AslrReportTrust,
    *, expected_campaign: str | None = None,
) -> dict[str, object]:
    if source.run_id == replay.run_id or source.root_digest == replay.root_digest:
        raise ValueError("System re-execution requires separately sealed fresh Runs")
    left = read_aslr_run(root, source, trust, expected_campaign=expected_campaign)
    right = read_aslr_run(root, replay, trust, expected_campaign=expected_campaign)
    if left["scopeDigest"] != right["scopeDigest"] or left["rulesDigest"] != right["rulesDigest"]:
        raise ValueError("System re-execution changed the approved Scope or rules")
    for coordinate in ("requestId", "approvalId", "permitId", "executionId"):
        if left[coordinate] == right[coordinate]:
            raise ValueError("System re-execution reused an execution authority coordinate")
    if (
        not isinstance(left["finishedAt"], str)
        or not isinstance(right["startedAt"], str)
        or datetime.fromisoformat(right["startedAt"]) <= datetime.fromisoformat(left["finishedAt"])
    ):
        raise ValueError("System re-execution must start after the source finishes")
    if not isinstance(left["aslr"], dict) or not isinstance(right["aslr"], dict):
        raise ValueError("System re-execution has no comparable authenticated result")
    match = left["aslr"] == right["aslr"]
    return {
        "version": "pajin.sys-004.reexecution-report/v1",
        "source": left,
        "replay": right,
        "aslrMatch": match,
        "complete": bool(left["complete"] and right["complete"] and match),
        "findingAuthority": False,
        "independentImplementationVerified": False,
    }
