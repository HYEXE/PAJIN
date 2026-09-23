"""One-shot, destination-bound Codex reconnaissance advisory invocation.

Only a trusted operator can register an exact hosted-transfer authorization.
The subprocess receives a bounded, target-neutral prompt and no PAJIN file
access. Its output remains an untrusted draft and has no target authority.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal, Protocol, Self

from pydantic import Field, field_validator, model_validator

from pajin.agentic.codex_recon_draft import (
    CodexReconDraft,
    CodexReconDraftError,
    parse_codex_recon_draft,
)
from pajin.agentic.codex_recon_projection import (
    CodexReconProjection,
    build_codex_recon_projection,
)
from pajin.agentic.codex_routing import CodexAdvisoryStage, CodexAdvisoryWireModel
from pajin.agentic.codex_usage import (
    CodexAdvisoryUsageError,
    CodexAdvisoryUsageJournal,
    CodexTurnUsage,
    parse_codex_exec_jsonl,
)
from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun

CODEX_RECON_TRANSFER_API_VERSION: Final = "pajin.dev/codex-recon-transfer-authorization/v1alpha1"
CODEX_RECON_RECEIPT_API_VERSION: Final = "pajin.dev/codex-recon-execution-receipt/v1alpha1"
CODEX_CLIENT_VERSION: Final = "codex-cli 0.156.1"
CODEX_CLIENT_SHA256: Final = "0196e89fe5a7598f816ee54232c3d7c26d75e502ab5cfe2c9240e81d90f7255a"
CODEX_DESTINATION: Final = "openai-codex-chatgpt-subscription"
_AUTH_DOMAIN: Final = "pajin.codex-recon-transfer-authorization/v1alpha1"
_RECEIPT_DOMAIN: Final = "pajin.codex-recon-execution-receipt/v1alpha1"
_MAX_PROMPT_BYTES: Final = 12 * 1024
_MAX_EVENT_BYTES: Final = 2 * 1024 * 1024
_MAX_STDERR_BYTES: Final = 64 * 1024
_MAX_TURN_SECONDS: Final = 120
_DISABLED_FEATURES: Final = (
    "shell_tool",
    "unified_exec",
    "apps",
    "hooks",
    "multi_agent",
    "multi_agent_v2",
    "plugins",
    "remote_plugin",
    "browser_use",
    "browser_use_external",
    "computer_use",
    "code_mode_host",
    "in_app_browser",
    "image_generation",
    "view_image",
    "skill_search",
    "tool_suggest",
    "goals",
    "memories",
    "sleep_tool",
    "workspace_dependencies",
)


class CodexExecutionError(ValueError):
    """A hosted invocation is unauthorized or lacks required isolation."""


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def build_codex_recon_prompt(projection: CodexReconProjection) -> bytes:
    """Construct the exact bytes that need explicit hosted-transfer approval."""

    projection = CodexReconProjection.model_validate(projection.model_dump(mode="json"))
    payload = _canonical_bytes(projection.model_dump(mode="json", by_alias=True))
    prompt = (
        b"Return exactly one JSON object for CodexReconDraft v1alpha1. "
        b"Use only the enclosed catalog IDs, allowed hypotheses, dispositions, and "
        b"opaque Evidence references. Rank all three diagnostics once and assess "
        b"both paths. A reference may support an entry only if its "
        b"supportsCatalogEntries includes that entry. Use no tools, external data, "
        b"target action, free-text narrative, or extra fields. All authority flags "
        b"must be false; proposalState must be "
        b"untrusted-hosted-draft-not-authorized. Projection JSON follows:\n"
        + payload
        + b"\nEnd projection."
    )
    if len(prompt) > _MAX_PROMPT_BYTES:
        raise CodexExecutionError("Codex recon prompt exceeds its exact transfer limit")
    return prompt


def _recon_output_schema(projection: CodexReconProjection) -> dict[str, object]:
    """Use JSON Schema features accepted by the pinned Codex client service."""

    def required_object(properties: dict[str, object]) -> dict[str, object]:
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties),
            "additionalProperties": False,
        }

    def singleton(value: str | bool) -> dict[str, object]:
        return {"type": "boolean" if type(value) is bool else "string", "enum": [value]}

    refs = [signal.evidence_ref for signal in projection.evidence_signals]
    diagnostics = [item.diagnostic_id for item in projection.diagnostics]
    diagnostic_entries = [item.catalog_entry_id for item in projection.diagnostics]
    diagnostic_hypotheses = [
        hypothesis for item in projection.diagnostics for hypothesis in item.allowed_hypothesis_ids
    ]
    path_entries = [item.catalog_entry_id for item in projection.attack_paths]
    path_hypotheses = [
        hypothesis for item in projection.attack_paths for hypothesis in item.allowed_hypothesis_ids
    ]
    diagnostic = required_object(
        {
            "rank": {"type": "integer", "enum": [1, 2, 3]},
            "diagnosticId": {"type": "string", "enum": diagnostics},
            "catalogEntryId": {"type": "string", "enum": diagnostic_entries},
            "hypothesisId": {"type": "string", "enum": diagnostic_hypotheses},
            "evidenceRefs": {"type": "array", "items": {"type": "string", "enum": refs}},
        }
    )
    path = required_object(
        {
            "catalogEntryId": {"type": "string", "enum": path_entries},
            "hypothesisId": {"type": "string", "enum": path_hypotheses},
            "issueSequence": {"type": "array", "items": {"type": "string", "enum": diagnostics}},
            "disposition": {
                "type": "string",
                "enum": ["investigate", "insufficient-evidence"],
            },
            "evidenceRefs": {"type": "array", "items": {"type": "string", "enum": refs}},
        }
    )
    return required_object(
        {
            "apiVersion": singleton("pajin.dev/codex-recon-draft/v1alpha1"),
            "kind": singleton("CodexReconDraft"),
            "projectionDigest": singleton(projection.projection_digest),
            "prioritizedDiagnostics": {"type": "array", "items": diagnostic},
            "pathAssessments": {"type": "array", "items": path},
            "proposalState": singleton("untrusted-hosted-draft-not-authorized"),
            "scopeExpansionAuthorized": singleton(False),
            "toolRequestCompiled": singleton(False),
            "capabilityGranted": singleton(False),
            "permitGranted": singleton(False),
            "executionAuthorized": singleton(False),
            "graphAdmissionAuthorized": singleton(False),
            "findingAuthorized": singleton(False),
            "reportDeliveryAuthorized": singleton(False),
        }
    )


class CodexReconTransferAuthorization(CodexAdvisoryWireModel):
    """Operator-admitted authorization for exactly one projection and prompt."""

    api_version: Literal["pajin.dev/codex-recon-transfer-authorization/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["CodexReconTransferAuthorization"]
    authorization_digest: str = Field(alias="authorizationDigest", pattern=r"^[a-f0-9]{64}$")
    stage: Literal[CodexAdvisoryStage.RECONNAISSANCE]
    destination: Literal["openai-codex-chatgpt-subscription"]
    model_id: Literal["gpt-6-luna"] = Field(alias="modelId")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    projection_digest: str = Field(alias="projectionDigest", pattern=r"^[a-f0-9]{64}$")
    prompt_sha256: str = Field(alias="promptSha256", pattern=r"^[a-f0-9]{64}$")
    client_version: Literal["codex-cli 0.156.1"] = Field(alias="clientVersion")
    client_sha256: Literal["0196e89fe5a7598f816ee54232c3d7c26d75e502ab5cfe2c9240e81d90f7255a"] = (
        Field(alias="clientSha256")
    )
    max_attempts: Literal[1] = Field(alias="maxAttempts")
    authorized_at: datetime = Field(alias="authorizedAt")
    expires_at: datetime = Field(alias="expiresAt")
    hosted_transfer_authorized: Literal[True] = Field(alias="hostedTransferAuthorized")
    tool_access_authorized: Literal[False] = Field(alias="toolAccessAuthorized")
    target_execution_authorized: Literal[False] = Field(alias="targetExecutionAuthorized")

    @field_validator("authorized_at", "expires_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("Codex transfer authorization time must have a timezone")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_exact_transfer(self) -> Self:
        if self.expires_at <= self.authorized_at:
            raise ValueError("Codex transfer authorization expiry is invalid")
        material = self.model_dump(mode="json", by_alias=True, exclude={"authorization_digest"})
        if self.authorization_digest != discovery_digest(_AUTH_DOMAIN, material):
            raise ValueError("Codex transfer authorization digest differs")
        return self


class CodexReconTransferAuthority(Protocol):
    """Trusted operator-controlled allowlist, separate from untrusted input."""

    def verify(
        self,
        authorization: CodexReconTransferAuthorization,
        *,
        source_run_id: str,
        source_root_digest: str,
        projection_digest: str,
        prompt_sha256: str,
        evaluated_at: datetime,
    ) -> None:
        """Reject an unregistered, expired, or differently bound transfer."""


class CodexReconTransferRegistry:
    """Process-local registry populated only after explicit operator approval."""

    def __init__(self, admitted: tuple[CodexReconTransferAuthorization, ...]) -> None:
        canonical = tuple(
            CodexReconTransferAuthorization.model_validate_json(
                _canonical_bytes(item.model_dump(mode="json", by_alias=True))
            )
            for item in admitted
        )
        if len({item.authorization_digest for item in canonical}) != len(canonical):
            raise CodexExecutionError("Codex transfer authorizations are duplicated")
        self._admitted = {item.authorization_digest: item for item in canonical}

    def verify(
        self,
        authorization: CodexReconTransferAuthorization,
        *,
        source_run_id: str,
        source_root_digest: str,
        projection_digest: str,
        prompt_sha256: str,
        evaluated_at: datetime,
    ) -> None:
        expected = self._admitted.get(authorization.authorization_digest)
        if expected is None or expected != authorization:
            raise PermissionError("Codex hosted transfer is not operator-admitted")
        if (
            authorization.source_run_id != source_run_id
            or authorization.source_root_digest != source_root_digest
            or authorization.projection_digest != projection_digest
            or authorization.prompt_sha256 != prompt_sha256
            or authorization.destination != CODEX_DESTINATION
            or authorization.model_id != "gpt-6-luna"
            or authorization.client_sha256 != CODEX_CLIENT_SHA256
        ):
            raise PermissionError("Codex hosted transfer differs from approval")
        now = evaluated_at.astimezone(UTC)
        if not authorization.authorized_at <= now < authorization.expires_at:
            raise PermissionError("Codex hosted transfer authorization is not active")


class CodexObservedUsage(CodexAdvisoryWireModel):
    """The exact terminal token fields retained in a successful receipt."""

    input_tokens: int = Field(alias="inputTokens", ge=1)
    cached_input_tokens: int = Field(alias="cachedInputTokens", ge=0)
    cache_write_input_tokens: int = Field(alias="cacheWriteInputTokens", ge=0)
    output_tokens: int = Field(alias="outputTokens", ge=0)
    reasoning_output_tokens: int = Field(alias="reasoningOutputTokens", ge=0)
    total_tokens: int = Field(alias="totalTokens", ge=1)

    @model_validator(mode="after")
    def consistent(self) -> Self:
        usage = CodexTurnUsage(
            input_tokens=self.input_tokens,
            cached_input_tokens=self.cached_input_tokens,
            cache_write_input_tokens=self.cache_write_input_tokens,
            output_tokens=self.output_tokens,
            reasoning_output_tokens=self.reasoning_output_tokens,
        )
        if self.total_tokens != usage.total_tokens:
            raise ValueError("Codex receipt token total differs from its components")
        return self


class CodexReconExecutionReceipt(CodexAdvisoryWireModel):
    """Bounded durable evidence for one terminal local client attempt."""

    api_version: Literal["pajin.dev/codex-recon-execution-receipt/v1alpha1"] = Field(
        alias="apiVersion"
    )
    kind: Literal["CodexReconExecutionReceipt"]
    receipt_digest: str = Field(alias="receiptDigest", pattern=r"^[a-f0-9]{64}$")
    attempt_id: str = Field(alias="attemptId", min_length=1, max_length=64)
    stage: Literal[CodexAdvisoryStage.RECONNAISSANCE]
    model_id: Literal["gpt-6-luna"] = Field(alias="modelId")
    reasoning_effort: Literal["high"] = Field(alias="reasoningEffort")
    destination: Literal["openai-codex-chatgpt-subscription"]
    authorization_digest: str = Field(alias="authorizationDigest", pattern=r"^[a-f0-9]{64}$")
    source_run_id: str = Field(alias="sourceRunId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    source_root_digest: str = Field(alias="sourceRootDigest", pattern=r"^[a-f0-9]{64}$")
    source_reloaded: Literal[True] = Field(alias="sourceReloaded")
    projection_digest: str = Field(alias="projectionDigest", pattern=r"^[a-f0-9]{64}$")
    prompt_sha256: str = Field(alias="promptSha256", pattern=r"^[a-f0-9]{64}$")
    client_version: Literal["codex-cli 0.156.1"] = Field(alias="clientVersion")
    client_sha256: str = Field(alias="clientSha256", pattern=r"^[a-f0-9]{64}$")
    invocation_sha256: str = Field(alias="invocationSha256", pattern=r"^[a-f0-9]{64}$")
    isolation_profile_sha256: str = Field(alias="isolationProfileSha256", pattern=r"^[a-f0-9]{64}$")
    isolation_probe_passed: Literal[True] = Field(alias="isolationProbePassed")
    started_at: datetime = Field(alias="startedAt")
    completed_at: datetime = Field(alias="completedAt")
    terminal_state: Literal["succeeded", "failed"] = Field(alias="terminalState")
    failure_code: Literal[
        "none", "process-error", "timeout", "event-rejected", "draft-rejected", "cleanup-failed"
    ] = Field(alias="failureCode")
    process_exit_code: int | None = Field(alias="processExitCode")
    event_stream_bytes: int = Field(alias="eventStreamBytes", ge=0)
    event_stream_sha256: str = Field(alias="eventStreamSha256", pattern=r"^[a-f0-9]{64}$")
    retained_event_bytes: int = Field(alias="retainedEventBytes", ge=0)
    retained_event_sha256: str = Field(alias="retainedEventSha256", pattern=r"^[a-f0-9]{64}$")
    event_stream_truncated: bool = Field(alias="eventStreamTruncated")
    stderr_bytes: int = Field(alias="stderrBytes", ge=0)
    stderr_sha256: str = Field(alias="stderrSha256", pattern=r"^[a-f0-9]{64}$")
    retained_stderr_bytes: int = Field(alias="retainedStderrBytes", ge=0)
    retained_stderr_sha256: str = Field(alias="retainedStderrSha256", pattern=r"^[a-f0-9]{64}$")
    stderr_truncated: bool = Field(alias="stderrTruncated")
    thread_id: str | None = Field(alias="threadId", max_length=200)
    observed_usage: CodexObservedUsage | None = Field(alias="observedUsage")
    output_sha256: str | None = Field(alias="outputSha256", pattern=r"^[a-f0-9]{64}$")
    draft_digest: str | None = Field(alias="draftDigest", pattern=r"^[a-f0-9]{64}$")
    tool_events_admitted: Literal[False] = Field(alias="toolEventsAdmitted")
    scratch_cleaned: bool = Field(alias="scratchCleaned")

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if self.completed_at < self.started_at:
            raise ValueError("Codex receipt predates dispatch")
        if (
            self.retained_event_bytes > self.event_stream_bytes
            or self.retained_stderr_bytes > self.stderr_bytes
            or self.event_stream_truncated != (self.retained_event_bytes < self.event_stream_bytes)
            or self.stderr_truncated != (self.retained_stderr_bytes < self.stderr_bytes)
        ):
            raise ValueError("Codex retained stream metadata is inconsistent")
        if self.terminal_state == "succeeded" and (
            self.failure_code != "none"
            or self.process_exit_code != 0
            or self.thread_id is None
            or self.observed_usage is None
            or self.output_sha256 is None
            or self.draft_digest is None
            or not self.scratch_cleaned
            or self.event_stream_truncated
            or self.stderr_truncated
        ):
            raise ValueError("Codex successful receipt is incomplete")
        if self.terminal_state == "failed" and self.failure_code == "none":
            raise ValueError("Codex failed receipt has no reason")
        material = self.model_dump(mode="json", by_alias=True, exclude={"receipt_digest"})
        if self.receipt_digest != discovery_digest(_RECEIPT_DOMAIN, material):
            raise ValueError("Codex execution receipt digest differs")
        return self


@dataclass(frozen=True, slots=True)
class CodexReconExecutionResult:
    receipt: CodexReconExecutionReceipt
    draft: CodexReconDraft | None


@dataclass(frozen=True, slots=True)
class _ClientRecord:
    command: tuple[str, ...]
    profile_bytes: bytes
    stdout: bytes
    stderr: bytes
    exit_code: int | None
    timed_out: bool
    scratch_cleaned: bool
    started_at: datetime
    completed_at: datetime


@dataclass(frozen=True, slots=True)
class _AdmittedResult:
    failure_code: str
    usage: CodexTurnUsage | None
    thread_id: str | None
    output_sha256: str | None
    draft_digest: str | None
    draft: CodexReconDraft | None


def _sha256_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _seatbelt_profile(*, scratch: Path, private_root: Path, auth_path: Path) -> bytes:
    home = Path.home().resolve()
    if not scratch.is_relative_to(home) or not private_root.is_relative_to(home):
        raise CodexExecutionError("Codex isolation root must be under the denied home")
    ancestors: list[Path] = []
    current = scratch.parent
    while current != home:
        ancestors.append(current)
        current = current.parent
    ancestors.extend((home, auth_path.parent))
    literals = " ".join(f"(literal {json.dumps(str(item))})" for item in sorted(set(ancestors)))
    profile = (
        "(version 1)\n"
        "(allow default)\n"
        f"(deny file-read* (subpath {json.dumps(str(home))}))\n"
        f"(deny file-write* (subpath {json.dumps(str(home))}))\n"
        f"(allow file-read* {literals} (subpath {json.dumps(str(scratch))}) "
        f"(literal {json.dumps(str(auth_path))}))\n"
        f"(allow file-write* (subpath {json.dumps(str(scratch))}))\n"
    )
    return profile.encode("utf-8")


def _probe_isolation(profile_path: Path, scratch: Path, private_root: Path) -> None:
    allowed = scratch / "allowed-probe"
    denied = private_root / f"denied-probe-{scratch.name}"
    allowed.write_bytes(b"CODEX_ALLOWED_PROBE")
    denied.write_bytes(b"CODEX_DENIED_PROBE")
    try:
        visible = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile_path), "/bin/cat", str(allowed)],
            capture_output=True,
            timeout=5,
            check=False,
        )
        hidden = subprocess.run(
            ["/usr/bin/sandbox-exec", "-f", str(profile_path), "/bin/cat", str(denied)],
            capture_output=True,
            timeout=5,
            check=False,
        )
        if (
            visible.returncode != 0
            or visible.stdout != b"CODEX_ALLOWED_PROBE"
            or hidden.returncode == 0
            or b"CODEX_DENIED_PROBE" in hidden.stdout
        ):
            raise CodexExecutionError("Codex file isolation probe did not deny sibling read")
    finally:
        allowed.unlink(missing_ok=True)
        denied.unlink(missing_ok=True)


def _client_environment(scratch: Path) -> dict[str, str]:
    environment = {
        "HOME": str(Path.home()),
        "CODEX_HOME": str(scratch / "codex-home"),
        "TMPDIR": str(scratch),
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "LANG": "en_US.UTF-8",
    }
    for key in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "SSL_CERT_FILE"):
        if key in os.environ:
            environment[key] = os.environ[key]
    return environment


def _invocation(binary: Path, scratch: Path) -> list[str]:
    command = [
        "/usr/bin/sandbox-exec",
        "-f",
        str(scratch / "profile.sb"),
        str(binary),
        "-a",
        "never",
        "exec",
        "--json",
        "--ephemeral",
        "--ignore-user-config",
        "--ignore-rules",
        "--skip-git-repo-check",
        "-s",
        "read-only",
        "-C",
        str(scratch / "work"),
        "-m",
        "gpt-6-luna",
        "-c",
        'web_search="disabled"',
        "-c",
        'model_reasoning_effort="high"',
        "--output-schema",
        str(scratch / "output-schema.json"),
    ]
    for feature in _DISABLED_FEATURES:
        command.extend(("--disable", feature))
    command.append("-")
    return command


def _stop_process_group(process: subprocess.Popen[bytes]) -> None:
    with suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)


def _preflight(
    source: VerifiedAuthenticatedDiscoveryRun,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    projection: CodexReconProjection,
    authorization: CodexReconTransferAuthorization,
    authority: CodexReconTransferAuthority,
    journal: CodexAdvisoryUsageJournal,
    binary: Path,
    private_root: Path,
) -> tuple[CodexReconProjection, CodexReconTransferAuthorization, bytes, Path, Path]:
    if sys.platform != "darwin":
        raise CodexExecutionError("Codex restricted-read adapter requires macOS Seatbelt")
    projection = CodexReconProjection.model_validate(projection.model_dump(mode="json"))
    rebuilt = build_codex_recon_projection(
        source,
        expected_run_id=expected_source_run_id,
        expected_root_digest=expected_source_root_digest,
    )
    if rebuilt != projection:
        raise CodexExecutionError("Codex recon input differs from strictly reloaded source")
    authorization = CodexReconTransferAuthorization.model_validate_json(
        _canonical_bytes(authorization.model_dump(mode="json", by_alias=True))
    )
    prompt = build_codex_recon_prompt(projection)
    authority.verify(
        authorization,
        source_run_id=expected_source_run_id,
        source_root_digest=expected_source_root_digest,
        projection_digest=projection.projection_digest,
        prompt_sha256=sha256(prompt).hexdigest(),
        evaluated_at=datetime.now(UTC),
    )
    if journal.plan.routes[0].stage is not CodexAdvisoryStage.RECONNAISSANCE:
        raise CodexExecutionError("Codex journal has no code-owned recon route")
    binary = binary.resolve(strict=True)
    if _sha256_file(binary) != CODEX_CLIENT_SHA256:
        raise CodexExecutionError("Codex client differs from the reviewed binary")
    repo_root = Path(__file__).resolve().parents[3]
    private_root = private_root.resolve(strict=True)
    if private_root != (repo_root / ".pajin").resolve(strict=True):
        raise CodexExecutionError("Codex runtime root is not the repository private area")
    if private_root.stat().st_mode & 0o077:
        raise CodexExecutionError("Codex runtime root is not owner-only")
    if journal.path.is_symlink() or journal.path.resolve() != (
        private_root / "codex-advisory-usage.sqlite"
    ):
        raise CodexExecutionError("Codex terminal journal must use its fixed private path")
    auth_path = Path.home() / ".codex" / "auth.json"
    if not auth_path.is_file() or auth_path.is_symlink():
        raise CodexExecutionError("Codex ChatGPT login file is absent or indirect")
    return projection, authorization, prompt, binary, auth_path


def _run_isolated_client(
    *,
    attempt_id: str,
    projection: CodexReconProjection,
    prompt: bytes,
    binary: Path,
    auth_path: Path,
    private_root: Path,
    journal: CodexAdvisoryUsageJournal,
) -> _ClientRecord:
    scratch = Path(tempfile.mkdtemp(prefix="codex-recon-", dir=private_root))
    dispatched = False
    profile_bytes = b""
    command: list[str] = []
    stdout = b""
    stderr = b""
    exit_code: int | None = None
    timed_out = False
    started_at: datetime | None = None
    try:
        (scratch / "codex-home").mkdir(mode=0o700)
        (scratch / "codex-home" / "auth.json").symlink_to(auth_path)
        (scratch / "work").mkdir(mode=0o700)
        profile_bytes = _seatbelt_profile(
            scratch=scratch, private_root=private_root, auth_path=auth_path
        )
        (scratch / "profile.sb").write_bytes(profile_bytes)
        _probe_isolation(scratch / "profile.sb", scratch, private_root)
        environment = _client_environment(scratch)
        status = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(scratch / "profile.sb"),
                str(binary),
                "login",
                "status",
            ],
            capture_output=True,
            env=environment,
            timeout=10,
            check=False,
        )
        if status.returncode != 0 or b"Logged in using ChatGPT" not in status.stderr:
            raise CodexExecutionError("Codex client is not using ChatGPT sign-in")
        version = subprocess.run(
            [
                "/usr/bin/sandbox-exec",
                "-f",
                str(scratch / "profile.sb"),
                str(binary),
                "--version",
            ],
            capture_output=True,
            env=environment,
            timeout=5,
            check=False,
        )
        if version.returncode != 0 or version.stdout.strip() != CODEX_CLIENT_VERSION.encode():
            raise CodexExecutionError("Codex client version differs from its reviewed version")
        schema = _canonical_bytes(_recon_output_schema(projection))
        (scratch / "output-schema.json").write_bytes(schema)
        command = _invocation(binary, scratch)
        journal.mark_started(attempt_id)
        dispatched = True
        started_at = datetime.now(UTC)
        process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=scratch / "work",
            env=environment,
            start_new_session=True,
        )
        try:
            stdout, stderr = process.communicate(prompt, timeout=_MAX_TURN_SECONDS)
        except subprocess.TimeoutExpired:
            timed_out = True
            _stop_process_group(process)
            stdout, stderr = process.communicate(timeout=5)
        finally:
            _stop_process_group(process)
        exit_code = process.returncode
    except (OSError, subprocess.SubprocessError) as exc:
        if not dispatched:
            journal.cancel_before_dispatch(attempt_id)
            raise CodexExecutionError(
                "Codex local isolation or setup failed before dispatch"
            ) from exc
        stderr = str(type(exc).__name__).encode()
    except CodexExecutionError:
        if not dispatched:
            journal.cancel_before_dispatch(attempt_id)
        raise
    finally:
        try:
            shutil.rmtree(scratch)
            scratch_cleaned = True
        except OSError:
            scratch_cleaned = False
    if started_at is None:
        raise CodexExecutionError("Codex attempt state is uncertain before process start")
    return _ClientRecord(
        command=tuple(command),
        profile_bytes=profile_bytes,
        stdout=stdout,
        stderr=stderr,
        exit_code=exit_code,
        timed_out=timed_out,
        scratch_cleaned=scratch_cleaned,
        started_at=started_at,
        completed_at=datetime.now(UTC),
    )


def _admit_client_result(
    record: _ClientRecord, projection: CodexReconProjection
) -> _AdmittedResult:
    failure_code = "none"
    usage: CodexTurnUsage | None = None
    thread_id: str | None = None
    output_sha256: str | None = None
    draft_digest: str | None = None
    draft: CodexReconDraft | None = None
    if not record.scratch_cleaned:
        failure_code = "cleanup-failed"
    elif record.timed_out:
        failure_code = "timeout"
    elif record.exit_code != 0:
        failure_code = "process-error"
    elif len(record.stdout) > _MAX_EVENT_BYTES or len(record.stderr) > _MAX_STDERR_BYTES:
        failure_code = "event-rejected"
    else:
        try:
            turn = parse_codex_exec_jsonl(record.stdout)
            usage = turn.usage
            thread_id = turn.thread_id
            output_sha256 = sha256(turn.message.encode()).hexdigest()
            draft = parse_codex_recon_draft(turn.message.encode(), expected_projection=projection)
            draft_digest = discovery_digest(
                "pajin.codex-recon-admitted-draft/v1alpha1",
                draft.model_dump(mode="json", by_alias=True),
            )
        except CodexAdvisoryUsageError:
            failure_code = "event-rejected"
        except CodexReconDraftError:
            failure_code = "draft-rejected"
    return _AdmittedResult(
        failure_code=failure_code,
        usage=usage,
        thread_id=thread_id,
        output_sha256=output_sha256,
        draft_digest=draft_digest,
        draft=draft,
    )


def execute_codex_recon_once(
    source: VerifiedAuthenticatedDiscoveryRun,
    projection: CodexReconProjection,
    *,
    expected_source_run_id: str,
    expected_source_root_digest: str,
    authorization: CodexReconTransferAuthorization,
    authority: CodexReconTransferAuthority,
    journal: CodexAdvisoryUsageJournal,
    binary: Path,
    private_root: Path,
) -> CodexReconExecutionResult:
    """Consume one approved Luna attempt; no automatic retry is possible."""

    projection, authorization, prompt, binary, auth_path = _preflight(
        source,
        expected_source_run_id,
        expected_source_root_digest,
        projection,
        authorization,
        authority,
        journal,
        binary,
        private_root,
    )
    private_root = private_root.resolve(strict=True)
    attempt = journal.reserve(
        stage=CodexAdvisoryStage.RECONNAISSANCE,
        input_digest=projection.projection_digest,
    )
    record = _run_isolated_client(
        attempt_id=attempt.attempt_id,
        projection=projection,
        prompt=prompt,
        binary=binary,
        auth_path=auth_path,
        private_root=private_root,
        journal=journal,
    )
    admitted = _admit_client_result(record, projection)
    retained_events = record.stdout[:_MAX_EVENT_BYTES]
    retained_stderr = record.stderr[:_MAX_STDERR_BYTES]

    material = {
        "apiVersion": CODEX_RECON_RECEIPT_API_VERSION,
        "kind": "CodexReconExecutionReceipt",
        "attemptId": attempt.attempt_id,
        "stage": CodexAdvisoryStage.RECONNAISSANCE.value,
        "modelId": "gpt-6-luna",
        "reasoningEffort": "high",
        "destination": CODEX_DESTINATION,
        "authorizationDigest": authorization.authorization_digest,
        "sourceRunId": expected_source_run_id,
        "sourceRootDigest": expected_source_root_digest,
        "sourceReloaded": True,
        "projectionDigest": projection.projection_digest,
        "promptSha256": sha256(prompt).hexdigest(),
        "clientVersion": CODEX_CLIENT_VERSION,
        "clientSha256": CODEX_CLIENT_SHA256,
        "invocationSha256": sha256(_canonical_bytes(record.command)).hexdigest(),
        "isolationProfileSha256": sha256(record.profile_bytes).hexdigest(),
        "isolationProbePassed": True,
        "startedAt": record.started_at.isoformat().replace("+00:00", "Z"),
        "completedAt": record.completed_at.isoformat().replace("+00:00", "Z"),
        "terminalState": "succeeded" if admitted.failure_code == "none" else "failed",
        "failureCode": admitted.failure_code,
        "processExitCode": record.exit_code,
        "eventStreamBytes": len(record.stdout),
        "eventStreamSha256": sha256(record.stdout).hexdigest(),
        "retainedEventBytes": len(retained_events),
        "retainedEventSha256": sha256(retained_events).hexdigest(),
        "eventStreamTruncated": len(retained_events) != len(record.stdout),
        "stderrBytes": len(record.stderr),
        "stderrSha256": sha256(record.stderr).hexdigest(),
        "retainedStderrBytes": len(retained_stderr),
        "retainedStderrSha256": sha256(retained_stderr).hexdigest(),
        "stderrTruncated": len(retained_stderr) != len(record.stderr),
        "threadId": admitted.thread_id,
        "observedUsage": (
            {
                "inputTokens": admitted.usage.input_tokens,
                "cachedInputTokens": admitted.usage.cached_input_tokens,
                "cacheWriteInputTokens": admitted.usage.cache_write_input_tokens,
                "outputTokens": admitted.usage.output_tokens,
                "reasoningOutputTokens": admitted.usage.reasoning_output_tokens,
                "totalTokens": admitted.usage.total_tokens,
            }
            if admitted.usage is not None
            else None
        ),
        "outputSha256": admitted.output_sha256,
        "draftDigest": admitted.draft_digest,
        "toolEventsAdmitted": False,
        "scratchCleaned": record.scratch_cleaned,
    }
    receipt = CodexReconExecutionReceipt.model_validate_json(
        _canonical_bytes({**material, "receiptDigest": discovery_digest(_RECEIPT_DOMAIN, material)})
    )
    journal.finalize(
        attempt.attempt_id,
        usage=admitted.usage,
        output_digest=admitted.output_sha256,
        success=receipt.terminal_state == "succeeded",
        receipt_bytes=_canonical_bytes(receipt.model_dump(mode="json", by_alias=True)),
        event_bytes=retained_events,
        stderr_bytes=retained_stderr,
    )
    return CodexReconExecutionResult(receipt=receipt, draft=admitted.draft)


def load_codex_recon_receipt(
    journal: CodexAdvisoryUsageJournal, attempt_id: str
) -> CodexReconExecutionReceipt:
    """Reload terminal evidence and reconcile receipt, streams, and charged usage."""

    attempt = journal.get(attempt_id)
    receipt_bytes = journal.terminal_receipt(attempt_id)
    streams = journal.terminal_streams(attempt_id)
    if attempt.state not in {"succeeded", "failed"} or receipt_bytes is None or streams is None:
        raise CodexExecutionError("Codex terminal attempt has no complete retained evidence")
    receipt = CodexReconExecutionReceipt.model_validate_json(receipt_bytes)
    events, stderr = streams
    if (
        receipt.attempt_id != attempt.attempt_id
        or receipt.stage is not attempt.stage
        or receipt.model_id != attempt.model_id
        or receipt.projection_digest != attempt.input_digest
        or receipt.terminal_state != attempt.state
        or receipt.retained_event_bytes != len(events)
        or receipt.retained_event_sha256 != sha256(events).hexdigest()
        or receipt.retained_stderr_bytes != len(stderr)
        or receipt.retained_stderr_sha256 != sha256(stderr).hexdigest()
        or (
            not receipt.event_stream_truncated
            and receipt.event_stream_sha256 != sha256(events).hexdigest()
        )
        or (not receipt.stderr_truncated and receipt.stderr_sha256 != sha256(stderr).hexdigest())
        or (receipt.observed_usage is None) != (attempt.observed_tokens is None)
        or (
            receipt.observed_usage is not None
            and receipt.observed_usage.total_tokens != attempt.observed_tokens
        )
        or receipt.output_sha256 != attempt.output_digest
    ):
        raise CodexExecutionError("Codex terminal receipt differs from its journal evidence")
    if receipt.terminal_state == "succeeded":
        turn = parse_codex_exec_jsonl(events)
        observed = receipt.observed_usage
        assert observed is not None
        if (
            receipt.thread_id != turn.thread_id
            or receipt.output_sha256 != sha256(turn.message.encode()).hexdigest()
            or observed.input_tokens != turn.usage.input_tokens
            or observed.cached_input_tokens != turn.usage.cached_input_tokens
            or observed.cache_write_input_tokens != turn.usage.cache_write_input_tokens
            or observed.output_tokens != turn.usage.output_tokens
            or observed.reasoning_output_tokens != turn.usage.reasoning_output_tokens
        ):
            raise CodexExecutionError("Codex successful receipt differs from its admitted events")
    return receipt
