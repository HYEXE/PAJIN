"""Fixed Web and Crypto Tools for synthetic local CTF challenges."""

from __future__ import annotations

import json
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.modes.ctf.models import (
    CTF_CRYPTO_ARTIFACT_HOST,
    CTF_WEB_BACKUP_PATH,
    CTF_WEB_LAB_HOST,
    CTF_WEB_LAB_PORT,
    CTFInlineArtifact,
    CTFScenario,
)
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import Tool, ToolSpec

CTF_WEB_BACKUP_TOOL_ID = "ctf.web-backup-probe"
CTF_CRYPTO_XOR_TOOL_ID = "ctf.crypto-single-byte-xor"


class CTFWebBackupProbeInput(StrictModel):
    challenge_id: str = Field(alias="challengeId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    scenario_id: Literal[CTFScenario.WEB_EXPOSED_BACKUP_CONFIG] = Field(alias="scenarioId")


class CTFWebBackupProbeOutput(StrictModel):
    target: str
    challenge_id: str = Field(alias="challengeId")
    scenario_id: Literal[CTFScenario.WEB_EXPOSED_BACKUP_CONFIG] = Field(alias="scenarioId")
    status: int = Field(ge=100, le=599)
    discovered: bool
    candidate_flag: str | None = Field(
        default=None,
        alias="candidateFlag",
        pattern=r"^PAJIN\{[A-Za-z0-9_-]{1,128}\}$",
    )
    body_sha256: str = Field(alias="bodySha256", pattern=r"^[a-f0-9]{64}$")
    synthetic: bool
    network_performed: bool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_consistent_discovery(self) -> CTFWebBackupProbeOutput:
        if self.discovered != (self.status == 200 and self.candidate_flag is not None):
            raise ValueError("CTF Web discovery state is inconsistent")
        if not self.synthetic:
            raise ValueError("CTF Web probe accepts only a synthetic lab response")
        return self


class CTFCryptoXORInput(StrictModel):
    challenge_id: str = Field(alias="challengeId", pattern=r"^[a-z0-9][a-z0-9-]*$")
    scenario_id: Literal[CTFScenario.CRYPTO_SINGLE_BYTE_XOR] = Field(alias="scenarioId")
    artifact_sha256: str = Field(alias="artifactSha256", pattern=r"^[a-f0-9]{64}$")
    ciphertext_hex: str = Field(alias="ciphertextHex", min_length=2, max_length=8_192)

    @model_validator(mode="after")
    def verify_inline_artifact(self) -> CTFCryptoXORInput:
        CTFInlineArtifact(
            data=self.ciphertext_hex,
            sha256=self.artifact_sha256,
        )
        return self


class CTFCryptoXOROutput(StrictModel):
    target: str
    challenge_id: str = Field(alias="challengeId")
    scenario_id: Literal[CTFScenario.CRYPTO_SINGLE_BYTE_XOR] = Field(alias="scenarioId")
    artifact_sha256: str = Field(alias="artifactSha256", pattern=r"^[a-f0-9]{64}$")
    solved: bool
    candidate_flag: str | None = Field(
        default=None,
        alias="candidateFlag",
        pattern=r"^PAJIN\{[A-Za-z0-9_-]{1,128}\}$",
    )
    key: int | None = Field(default=None, ge=0, le=255)
    attempted_keys: int = Field(alias="attemptedKeys", ge=1, le=256)
    synthetic: bool
    network_performed: bool = Field(alias="networkPerformed")

    @model_validator(mode="after")
    def require_consistent_analysis(self) -> CTFCryptoXOROutput:
        if self.solved != (self.candidate_flag is not None and self.key is not None):
            raise ValueError("CTF Crypto solve state is inconsistent")
        if self.attempted_keys != 256:
            raise ValueError("CTF Crypto Worker must evaluate the complete bounded keyspace")
        if not self.synthetic or self.network_performed:
            raise ValueError("CTF Crypto analysis must remain synthetic and offline")
        return self


def validate_ctf_web_target(target: str) -> None:
    parsed = urlsplit(target)
    if parsed.scheme != "http":
        raise ValueError("CTF Web probe requires the local HTTP lab")
    if parsed.hostname != CTF_WEB_LAB_HOST or parsed.port != CTF_WEB_LAB_PORT:
        raise ValueError("CTF Web probe target must use host.docker.internal:8780")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CTF Web probe target authority, query, or fragment is invalid")
    if parsed.path != CTF_WEB_BACKUP_PATH:
        raise ValueError(f"CTF Web probe is fixed to {CTF_WEB_BACKUP_PATH}")


def crypto_artifact_target(challenge_id: str, artifact_sha256: str) -> str:
    return f"http://{CTF_CRYPTO_ARTIFACT_HOST}/{challenge_id}/{artifact_sha256}"


def validate_ctf_crypto_target(
    target: str,
    *,
    challenge_id: str,
    artifact_sha256: str,
) -> None:
    parsed = urlsplit(target)
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("CTF Crypto artifact target authority, query, or fragment is invalid")
    if target != crypto_artifact_target(challenge_id, artifact_sha256):
        raise ValueError("CTF Crypto artifact target does not match its content address")


class CTFWebBackupProbeTool(Tool):
    """Fetch one fixed synthetic backup path without accepting an agent-authored path."""

    spec = ToolSpec(
        tool_id=CTF_WEB_BACKUP_TOOL_ID,
        version="1.0.0",
        description="Fetch the fixed backup configuration path in the local CTF Web lab",
        risk_tier=ToolRiskTier.T1,
        categories={"ctf", "discovery", "http", "web"},
        evidence_types={"http-observation", "json"},
        network_access=True,
        network_request_cost=1,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "GET":
            raise ValueError("CTF Web backup probe requires GET")
        validate_ctf_web_target(request.target)
        probe = CTFWebBackupProbeInput.model_validate(request.arguments)
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ctf-web-backup-probe"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "challengeId": probe.challenge_id,
                    "scenarioId": probe.scenario_id,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return _worker_failure(request, result)
        try:
            raw = json.loads(result.stdout)
            output = CTFWebBackupProbeOutput.model_validate(raw)
            probe = CTFWebBackupProbeInput.model_validate(request.arguments)
            if (
                output.target != request.target
                or output.challenge_id != probe.challenge_id
                or output.scenario_id != probe.scenario_id
            ):
                raise ValueError("worker output identity does not match the Tool request")
            if not output.network_performed:
                raise ValueError("worker did not attest network execution")
        except (json.JSONDecodeError, ValueError) as exc:
            return _invalid_output(request, result, "CTF Web", exc)
        return _success(request, result, output.model_dump(mode="json", by_alias=True))


class CTFCryptoXORTool(Tool):
    """Analyze one content-addressed small artifact over a fixed 256-key XOR search."""

    spec = ToolSpec(
        tool_id=CTF_CRYPTO_XOR_TOOL_ID,
        version="1.0.0",
        description="Solve a bounded synthetic single-byte XOR artifact without network access",
        risk_tier=ToolRiskTier.T0,
        categories={"crypto", "ctf", "offline-analysis"},
        evidence_types={"artifact-analysis", "json"},
        network_access=False,
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:
        if request.method != "POST":
            raise ValueError("CTF Crypto XOR analysis requires POST semantics")
        probe = CTFCryptoXORInput.model_validate(request.arguments)
        validate_ctf_crypto_target(
            request.target,
            challenge_id=probe.challenge_id,
            artifact_sha256=probe.artifact_sha256,
        )
        return WorkerJob(
            image="pajin-worker:dev",
            command=["ctf-crypto-single-byte-xor"],
            stdin=json.dumps(
                {
                    "target": request.target,
                    "challengeId": probe.challenge_id,
                    "scenarioId": probe.scenario_id,
                    "artifactSha256": probe.artifact_sha256,
                    "ciphertextHex": probe.ciphertext_hex,
                },
                separators=(",", ":"),
            ),
            network=NetworkMode.NONE,
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        if result.status is not WorkerStatus.SUCCEEDED:
            return _worker_failure(request, result)
        try:
            raw = json.loads(result.stdout)
            output = CTFCryptoXOROutput.model_validate(raw)
            probe = CTFCryptoXORInput.model_validate(request.arguments)
            if (
                output.target != request.target
                or output.challenge_id != probe.challenge_id
                or output.scenario_id != probe.scenario_id
                or output.artifact_sha256 != probe.artifact_sha256
            ):
                raise ValueError("worker output identity does not match the Tool request")
        except (json.JSONDecodeError, ValueError) as exc:
            return _invalid_output(request, result, "CTF Crypto", exc)
        return _success(request, result, output.model_dump(mode="json", by_alias=True))


def _worker_failure(request: ToolRequest, result: WorkerResult) -> ToolResult:
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=False,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=f"worker {result.status.value}: {result.stderr or 'no error detail'}",
    )


def _invalid_output(
    request: ToolRequest,
    result: WorkerResult,
    label: str,
    error: Exception,
) -> ToolResult:
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=False,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=f"invalid {label} probe output: {error}",
    )


def _success(
    request: ToolRequest,
    result: WorkerResult,
    data: dict[str, object],
) -> ToolResult:
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=result.started_at,
        finished_at=result.finished_at,
        data=data,
    )
