"""Independent deployment pins and exact SYS-002 input/output."""

from __future__ import annotations

import base64
import json
import re
import shlex
from hashlib import sha256
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator

from pajin.domain.models import StrictModel

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
TOOL_ID = "system.os-release-read"
CAPABILITY_ID = "pajin.system.os-release-read"
SECRET_REF = "sys-002-client-credentials"


def digest(value: object) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


class SystemInput(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    target: str = Field(max_length=1000)
    instance: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    operation: Literal["linux-os-release-v1"] = "linux-os-release-v1"

    @field_validator("target")
    @classmethod
    def exact_endpoint(cls, value: str) -> str:
        url = urlsplit(value)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username
            or url.password
            or url.query
            or url.fragment
            or url.path != "/v1/os-release"
            or url.port is None
            or value != f"https://{url.hostname}:{url.port}/v1/os-release"
        ):
            raise ValueError("System input requires one canonical explicit-port HTTPS endpoint")
        return value

    @property
    def scope_authority(self) -> str:
        return self.target.removesuffix("v1/os-release") + "**"


class SystemDeployment(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    value: SystemInput
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    proxy_image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    ca_sha256: Digest
    server_cert_sha256: Digest
    client_cert_sha256: Digest
    agent_sha256: Digest
    client_sha256: Digest


class AgentRead(StrictModel):
    schema_version: Literal["pajin.sys-002.agent-read/v1"] = Field(alias="schema")
    instance: str
    request_id: str = Field(alias="requestId")
    agent_sha256: Digest = Field(alias="agentSha256")
    file_sha256: Digest = Field(alias="fileSha256")
    file_bytes: int = Field(alias="fileBytes", strict=True, ge=1, le=8192)
    file_base64: str = Field(alias="fileBase64", max_length=10924)
    source: Literal["/usr/lib/os-release"]

    def content(self) -> bytes:
        content = base64.b64decode(self.file_base64, validate=True)
        if (
            len(content) != self.file_bytes
            or sha256(content).hexdigest() != self.file_sha256
            or base64.b64encode(content).decode() != self.file_base64
        ):
            raise ValueError("System file bytes differ from their exact commitment")
        return content


class SystemWorkerOutput(StrictModel):
    schema_version: Literal["pajin.sys-002.worker-read/v1"] = Field(alias="schema")
    agent: AgentRead
    server_cert_sha256: Digest = Field(alias="serverCertSha256")
    client_cert_sha256: Digest = Field(alias="clientCertSha256")
    client_sha256: Digest = Field(alias="clientSha256")
    uid: int = Field(strict=True, ge=65532, le=65532)


def distribution_metadata(content: bytes) -> dict[str, str]:
    """Bounded strict shell-style assignments; never evaluate shell or variable expansion."""
    if not 1 <= len(content) <= 8192 or b"\x00" in content:
        raise ValueError("System OS-release content exceeds its contract")
    values: dict[str, str] = {}
    for line in content.decode("utf-8", errors="strict").splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or re.fullmatch(r"[A-Z][A-Z0-9_]*", key) is None or key in values:
            raise ValueError("System OS-release assignment is malformed or duplicate")
        parsed = shlex.split(value, comments=False, posix=True)
        if len(parsed) != 1 or len(parsed[0]) > 1024 or any(ord(c) < 32 for c in parsed[0]):
            raise ValueError("System OS-release value is malformed")
        values[key] = parsed[0]
    required = ("ID", "VERSION_ID", "PRETTY_NAME")
    if any(not values.get(key) for key in required):
        raise ValueError("System profile requires ID, VERSION_ID and PRETTY_NAME")
    return {key: values[key] for key in required}


class SystemRunReference(StrictModel):
    run_id: str = Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    root_digest: Digest
