"""Authorized local custody and one bounded real offline Worker Tool."""

from __future__ import annotations

import json
import os
import stat
from base64 import b64encode
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from re import fullmatch

from pajin.application_elf.models import TOOL_ID, ELFInput, ELFWorkerOutput
from pajin.domain.models import ToolRequest, ToolResult, ToolRiskTier
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerLimits, WorkerResult, WorkerStatus
from pajin.tools.base import (
    Tool,
    ToolSpec,
    audit_safe_worker_failure,
    decode_strict_worker_json_object,
)


def elf_worker_limits() -> WorkerLimits:
    return WorkerLimits(
        timeout_seconds=15,
        memory_mb=128,
        cpus=0.5,
        pids=16,
        workspace_mb=1,
        stdout_bytes=4096,
        stderr_bytes=1024,
    )


@dataclass(frozen=True)
class ELFCustody:
    """Trusted deployment input, not selected by ToolRequest or discovered metadata."""

    directory: Path
    authorized: tuple[ELFInput, ...]

    def __post_init__(self) -> None:
        if not self.authorized or len(set(self.authorized)) != len(self.authorized):
            raise ValueError("ELF custody requires unique authorized immutable inputs")
        self._directory_identity()

    def _directory_identity(self) -> tuple[int, int]:
        info = self.directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or self.directory.resolve() != self.directory.absolute()
        ):
            raise ValueError("ELF custody requires an owner-only directory without symbolic links")
        return info.st_dev, info.st_ino

    def read(self, requested: ELFInput) -> bytes:
        if requested not in self.authorized:
            raise ValueError("ELF artifact is not authorized by deployment custody")
        identity = self._directory_identity()
        descriptor = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            directory_info = os.fstat(descriptor)
            if (directory_info.st_dev, directory_info.st_ino) != identity:
                raise ValueError("ELF custody directory changed")
            source = os.open(
                requested.artifact_sha256 + ".elf",
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                dir_fd=descriptor,
            )
            with os.fdopen(source, "rb") as handle:
                before = os.fstat(handle.fileno())
                if (
                    not stat.S_ISREG(before.st_mode)
                    or before.st_uid != os.getuid()
                    or before.st_mode & 0o077
                    or before.st_nlink != 1
                    or before.st_size != requested.artifact_bytes
                ):
                    raise ValueError("ELF custody file violates its immutable byte contract")
                content = handle.read(requested.artifact_bytes + 1)
                after = os.fstat(handle.fileno())
                if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size,
                    after.st_mtime_ns,
                    after.st_ctime_ns,
                ):
                    raise ValueError("ELF custody file changed during read")
            if self._directory_identity() != identity:
                raise ValueError("ELF custody directory changed")
            if (
                len(content) != requested.artifact_bytes
                or sha256(content).hexdigest() != requested.artifact_sha256
            ):
                raise ValueError("ELF custody artifact digest differs")
            return content
        finally:
            os.close(descriptor)


class ELFHeaderTool(Tool):
    spec = ToolSpec(
        tool_id=TOOL_ID,
        version="1.0.0",
        description="Read structural ELF64 header metadata from one authorized immutable artifact",
        risk_tier=ToolRiskTier.T2,
        categories=frozenset({"application", "read-only", "offline"}),
        network_access=False,
        parallel_safe=False,
    )

    def __init__(self, custody: ELFCustody | None, *, image_id: str, parser_sha256: str) -> None:
        if fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
            raise ValueError("ELF Worker requires an exact observed OCI image ID")
        if fullmatch(r"[a-f0-9]{64}", parser_sha256) is None:
            raise ValueError("ELF Worker requires an exact parser digest")
        self.custody, self.image_id, self.parser_sha256 = custody, image_id, parser_sha256

    def stable_execution_context(self) -> dict[str, object]:
        spec = self.spec.model_dump(mode="json")
        spec["categories"] = sorted(self.spec.categories)
        spec["evidence_types"] = sorted(self.spec.evidence_types)
        return {
            "spec": spec,
            "implementationVersion": "pajin.app-002-tool/v1",
            "imageId": self.image_id,
            "limits": elf_worker_limits().model_dump(mode="json"),
            "parserSha256": self.parser_sha256,
            "transport": "bounded-immutable-stdin",
            "maximumArtifactBytes": 262_144,
            "workerBoundary": "pajin.worker-boundary.application.minimum",
        }

    def validate_request(self, request: ToolRequest) -> ELFInput:
        value = ELFInput.model_validate(request.arguments)
        if request.tool_id != TOOL_ID or request.method != "GET" or request.target != value.target:
            raise ValueError("ELF request differs from its exact read-only artifact coordinate")
        return value

    def prepare(self, request: ToolRequest) -> WorkerJob:
        value = self.validate_request(request)
        if self.custody is None:
            raise ValueError("ELF request lacks deployment custody authorization")
        content = self.custody.read(value)
        return WorkerJob(
            image=self.image_id,
            command=["elf-header-read"],
            network=NetworkMode.NONE,
            stdin=json.dumps(
                {
                    "pajinEnvelopeVersion": 1,
                    "payload": {
                        "sha256": value.artifact_sha256,
                        "bytes": value.artifact_bytes,
                        "content": b64encode(content).decode("ascii"),
                    },
                    "secrets": {},
                },
                separators=(",", ":"),
            ),
            limits=elf_worker_limits(),
        )

    def interpret(self, request: ToolRequest, result: WorkerResult) -> ToolResult:
        value = self.validate_request(request)
        data: dict[str, object] = {}
        succeeded = result.status is WorkerStatus.SUCCEEDED and result.exit_code == 0
        if succeeded:
            output = ELFWorkerOutput.model_validate(
                decode_strict_worker_json_object(result, label="ELF Worker result")
            )
            if (
                output.parser_sha256 != self.parser_sha256
                or output.header.artifact_sha256 != value.artifact_sha256
                or output.header.artifact_bytes != value.artifact_bytes
            ):
                raise ValueError("ELF result parser or artifact identity differs")
            data = output.model_dump(mode="json", by_alias=True)
        return ToolResult(
            request_id=request.request_id,
            tool_id=TOOL_ID,
            success=succeeded,
            started_at=result.started_at,
            finished_at=result.finished_at,
            data=data,
            error=None if succeeded else audit_safe_worker_failure(result),
        )
