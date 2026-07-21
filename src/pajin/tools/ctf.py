"""Fixed Web and Crypto Tools for synthetic local CTF challenges."""

from __future__ import annotations

import json
from hashlib import sha256
from hmac import compare_digest
from re import fullmatch
from typing import Literal
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from pajin.domain.ctf import (
    CTF_CRYPTO_ARTIFACT_HOST,
    CTF_WEB_BACKUP_PATH,
    CTF_WEB_LAB_HOST,
    CTF_WEB_LAB_PORT,
    CTFInlineArtifact,
    CTFScenario,
)
from pajin.domain.models import StrictModel, ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_http_target,
    audit_safe_tool_interpretation_failure,
    audit_safe_worker_failure,
    decode_bounded_json_response,
    decode_strict_worker_json_object,
    host_observed_http_receipts,
    http_target_sha256,
)

CTF_WEB_BACKUP_TOOL_ID = "ctf.web-backup-probe"
CTF_CRYPTO_XOR_TOOL_ID = "ctf.crypto-single-byte-xor"
MAX_CTF_WEB_RESPONSE_BYTES = 16_384
MAX_CTF_WEB_RESPONSE_BASE64_CHARS = ((MAX_CTF_WEB_RESPONSE_BYTES + 2) // 3) * 4


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
    response_body_base64: str = Field(
        alias="responseBodyBase64",
        min_length=4,
        max_length=MAX_CTF_WEB_RESPONSE_BASE64_CHARS,
    )
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


def _solve_single_byte_xor(ciphertext_hex: str) -> tuple[int | None, str | None]:
    ciphertext = bytes.fromhex(ciphertext_hex)
    matches: list[tuple[int, str]] = []
    for key in range(256):
        plaintext_bytes = bytes(value ^ key for value in ciphertext)
        try:
            plaintext = plaintext_bytes.decode("ascii")
        except UnicodeDecodeError:
            continue
        if fullmatch(r"PAJIN\{[A-Za-z0-9_-]{1,128}\}", plaintext):
            matches.append((key, plaintext))
    if len(matches) > 1:
        raise ValueError("CTF Crypto host analysis produced ambiguous flag candidates")
    return matches[0] if matches else (None, None)


class CTFWebBackupProbeTool(Tool):
    """Fetch one fixed synthetic backup path without accepting an agent-authored path."""

    spec = ToolSpec(
        tool_id=CTF_WEB_BACKUP_TOOL_ID,
        version="1.0.0",
        description="Fetch the fixed backup configuration path in the local CTF Web lab",
        risk_tier=ToolRiskTier.T1,
        categories=frozenset({"ctf", "discovery", "http", "web"}),
        evidence_types=frozenset({"http-observation", "json"}),
        network_access=True,
        network_request_cost=1,
        parallel_safe=True,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

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
            raw = decode_strict_worker_json_object(result, label="CTF Web probe output")
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
        except ValueError as exc:
            return _invalid_output(request, result, "CTF Web", exc)
        return _success(request, result, output.model_dump(mode="json", by_alias=True))

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        output = CTFWebBackupProbeOutput.model_validate(result.data)
        receipts = host_observed_http_receipts(
            worker_result,
            network_log_trusted=network_log_trusted,
        )
        if receipts is None:
            raise ValueError("CTF Web result requires a host-observed HTTP receipt")
        if len(receipts) != 1:
            raise ValueError("CTF Web receipt must cover exactly one request")
        receipt = receipts[0]
        body, response, response_json_sha256 = decode_bounded_json_response(
            output.response_body_base64,
            max_bytes=MAX_CTF_WEB_RESPONSE_BYTES,
        )
        body_sha256 = sha256(body).hexdigest()
        if (
            receipt.sequence != 1
            or receipt.method != "GET"
            or receipt.target != audit_http_target(request.target)
            or receipt.target_sha256 != http_target_sha256(request.target)
            or receipt.status != output.status
            or not compare_digest(receipt.response_body_sha256, body_sha256)
            or not compare_digest(output.body_sha256, body_sha256)
            or receipt.response_json_sha256 is None
            or not compare_digest(receipt.response_json_sha256, response_json_sha256)
            or response.get("challengeId") != output.challenge_id
            or response.get("synthetic") is not output.synthetic
            or response.get("flag") != output.candidate_flag
        ):
            raise ValueError("CTF Web output differs from its host-observed HTTP receipt")


class CTFCryptoXORTool(Tool):
    """Analyze one content-addressed small artifact over a fixed 256-key XOR search."""

    spec = ToolSpec(
        tool_id=CTF_CRYPTO_XOR_TOOL_ID,
        version="1.0.0",
        description="Solve a bounded synthetic single-byte XOR artifact without network access",
        risk_tier=ToolRiskTier.T0,
        categories=frozenset({"crypto", "ctf", "offline-analysis"}),
        evidence_types=frozenset({"artifact-analysis", "json"}),
        network_access=False,
        parallel_safe=True,
    )

    def stable_execution_context(self) -> dict[str, object]:
        return self._stable_spec_context()

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
            raw = decode_strict_worker_json_object(
                result,
                label="CTF Crypto probe output",
            )
            output = CTFCryptoXOROutput.model_validate(raw)
            probe = CTFCryptoXORInput.model_validate(request.arguments)
            if (
                output.target != request.target
                or output.challenge_id != probe.challenge_id
                or output.scenario_id != probe.scenario_id
                or output.artifact_sha256 != probe.artifact_sha256
            ):
                raise ValueError("worker output identity does not match the Tool request")
        except ValueError as exc:
            return _invalid_output(request, result, "CTF Crypto", exc)
        return _success(request, result, output.model_dump(mode="json", by_alias=True))

    def validate_trusted_execution(
        self,
        request: ToolRequest,
        result: ToolResult,
        worker_result: WorkerResult,
        *,
        network_log_trusted: bool,
    ) -> None:
        del worker_result, network_log_trusted
        probe = CTFCryptoXORInput.model_validate(request.arguments)
        output = CTFCryptoXOROutput.model_validate(result.data)
        expected_key, expected_candidate = _solve_single_byte_xor(probe.ciphertext_hex)
        if (
            output.solved != (expected_candidate is not None)
            or output.candidate_flag != expected_candidate
            or output.key != expected_key
            or output.attempted_keys != 256
        ):
            raise ValueError("CTF Crypto output differs from host-recomputed XOR analysis")


def _worker_failure(request: ToolRequest, result: WorkerResult) -> ToolResult:
    return ToolResult(
        request_id=request.request_id,
        tool_id=request.tool_id,
        success=False,
        started_at=result.started_at,
        finished_at=result.finished_at,
        error=audit_safe_worker_failure(result),
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
        error=audit_safe_tool_interpretation_failure(
            f"invalid {label} probe output",
            error,
        ),
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
