"""Independent deployment pins and exact SYS-004 input/output."""

from __future__ import annotations

import base64
import json
from hashlib import sha256
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, field_validator

from pajin.domain.models import StrictModel

Digest = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
TOOL_ID = "system.aslr-read"
CAPABILITY_ID = "pajin.system.aslr-read"
SECRET_REF = "sys-004-client-credentials"


def digest(value: object) -> str:
    return sha256(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode()
    ).hexdigest()


class AslrInput(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    target: str = Field(max_length=1000)
    instance: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    operation: Literal["linux-aslr-v1"] = "linux-aslr-v1"

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
            or url.path != "/v1/aslr"
            or url.port is None
            or value != f"https://{url.hostname}:{url.port}/v1/aslr"
        ):
            raise ValueError("System input requires one canonical explicit-port HTTPS endpoint")
        return value

    @property
    def scope_authority(self) -> str:
        return self.target.removesuffix("v1/aslr") + "**"


class AslrDeployment(StrictModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)
    value: AslrInput
    image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    proxy_image_id: str = Field(pattern=r"^sha256:[a-f0-9]{64}$")
    ca_sha256: Digest
    server_cert_sha256: Digest
    client_cert_sha256: Digest
    agent_sha256: Digest
    client_sha256: Digest


class AslrAgentRead(StrictModel):
    schema_version: Literal["pajin.sys-004.agent-read/v1"] = Field(alias="schema")
    instance: str
    request_id: str = Field(alias="requestId")
    agent_sha256: Digest = Field(alias="agentSha256")
    file_sha256: Digest = Field(alias="fileSha256")
    file_bytes: int = Field(alias="fileBytes", strict=True, ge=2, le=2)
    file_base64: str = Field(alias="fileBase64", min_length=4, max_length=4)
    source: Literal["/proc/sys/kernel/randomize_va_space"]

    def content(self) -> bytes:
        content = base64.b64decode(self.file_base64, validate=True)
        if (
            len(content) != self.file_bytes
            or sha256(content).hexdigest() != self.file_sha256
            or base64.b64encode(content).decode() != self.file_base64
        ):
            raise ValueError("System file bytes differ from their exact commitment")
        return content


class AslrWorkerOutput(StrictModel):
    schema_version: Literal["pajin.sys-004.worker-read/v1"] = Field(alias="schema")
    agent: AslrAgentRead
    server_cert_sha256: Digest = Field(alias="serverCertSha256")
    client_cert_sha256: Digest = Field(alias="clientCertSha256")
    client_sha256: Digest = Field(alias="clientSha256")
    uid: int = Field(strict=True, ge=65532, le=65532)


def aslr_metadata(content: bytes) -> dict[str, int]:
    """Read exactly one kernel setting; never infer process protection or a vulnerability."""
    if content not in (b"0\n", b"1\n", b"2\n"):
        raise ValueError("System ASLR setting is outside the fixed kernel-read contract")
    return {"randomizeVaSpace": content[0] - ord("0")}


class AslrRunReference(StrictModel):
    run_id: str = Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    root_digest: Digest
