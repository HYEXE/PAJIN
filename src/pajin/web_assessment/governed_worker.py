"""Signed host-subprocess execution boundary for governed Web assessments.

This backend is intentionally narrower than :class:`DockerWorkerBackend`.  It is
used only for an explicitly approved numeric-loopback target that a container
cannot reach on the current host.  The boundary is a fresh, code-owned Python
subprocess plus exact-origin application-layer network gates; it does **not**
claim OCI/container isolation or a host-observed egress-proxy receipt.
"""

from __future__ import annotations

import asyncio
import base64
import binascii
import json
import os
import stat
import sys
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from contextvars import ContextVar, Token
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path
from threading import Lock
from typing import Literal, Protocol, Self, cast, final
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.domain.models import StrictModel, ToolRequest
from pajin.runtime.pinned_workspace import (
    PinnedWorkspaceIdentity,
    active_pinned_workspace_identity,
    pinned_workspace_relative_path,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import SecretMaterial, redact_text
from pajin.runtime.worker import (
    EgressPolicy,
    NetworkMode,
    WorkerBackend,
    WorkerFailureCode,
    WorkerJob,
    WorkerLimits,
    WorkerResult,
    WorkerSecretRequest,
    WorkerStatus,
)
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceipt,
    WebAssessmentAdapterManifest,
    WebAssessmentDispatchBinding,
    WebAuthenticatedAssessmentWorkerOutput,
)
from pajin.web_assessment.models import (
    DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
    LocalWebAssessmentAuthorization,
    RequestEvidence,
    WebAssessmentPlan,
    local_origin,
)
from pajin.web_assessment.verification import (
    load_verified_local_web_assessment_source_integrity,
)

WEB_HOST_WORKER_IMAGE = "pajin-web-assessment-worker:host-local-v1"
WEB_TARGET_OBSERVER_COMMAND = ("web-target-observer",)
WEB_ASSESSMENT_EXECUTOR_COMMAND = ("web-assessment-executor",)
WEB_WORKER_BACKEND_NAME = "host-loopback-browser"
WEB_WORKER_IMPLEMENTATION_VERSION = "pajin.host-loopback-browser-worker/v1"
WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION: Literal["pajin.web-assessment-process/v1"] = (
    "pajin.web-assessment-process/v1"
)
WEB_WORKER_SIGNING_KEY_BINDING = "worker-signing-key"
WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING = "target-observer-signing-key"
WEB_ACCOUNT_NAME_BINDING = "account-name"
WEB_ACCOUNT_PROOF_BINDING = "account-proof"

_TARGET_SIGNATURE_DOMAIN = b"pajin.web.target-observer-attestation/v1\0"
_EXECUTION_SIGNATURE_DOMAIN = b"pajin.web.execution-attestation/v1\0"
_WEB_WORKER_GATEWAY_EXECUTION_FACTORY_TOKEN = object()
_GOVERNED_COORDINATOR_WORKER_GROUP_FACTORY_TOKEN = object()
_GOVERNED_COORDINATOR_SUBPROCESS_MARKER = "PAJIN_GOVERNED_WEB_COORDINATOR_HOST_SUBPROCESS"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_RUN_ID_PATTERN = r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$"
_MAX_PROCESS_INPUT_BYTES = 1_000_000
_MAX_PROCESS_OUTPUT_BYTES = 1_000_000
_MAX_PROCESS_STDERR_BYTES = 64_000
_LEGACY_WEB_WORKER_ADAPTER_IMPLEMENTATION = "pajin.web-assessment.juice-shop/v1"
WEB_WORKER_OS_ENV_ALLOWLIST = frozenset(
    {
        "COMSPEC",
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "PATHEXT",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "TZ",
        "WINDIR",
    }
)


@final
@dataclass(frozen=True, slots=True)
class _GovernedCoordinatorWorkerGroupAuthority:
    """Process-local proof that the code-owned coordinator owns this Worker group."""

    _factory_token: object
    pid: int
    process_group_id: int
    session_id: int
    workspace_identity: PinnedWorkspaceIdentity

    def __post_init__(self) -> None:
        if self._factory_token is not _GOVERNED_COORDINATOR_WORKER_GROUP_FACTORY_TOKEN:
            raise TypeError("coordinator Worker-group authority is factory-only")


_ACTIVE_COORDINATOR_WORKER_GROUP: ContextVar[_GovernedCoordinatorWorkerGroupAuthority | None] = (
    ContextVar("pajin_governed_coordinator_worker_group", default=None)
)


def _create_governed_coordinator_worker_group_authority() -> (
    _GovernedCoordinatorWorkerGroupAuthority
):
    """Mint a non-serializable authority only inside the pinned coordinator child."""

    workspace_identity = active_pinned_workspace_identity()
    if os.environ.get(_GOVERNED_COORDINATOR_SUBPROCESS_MARKER) != "1" or workspace_identity is None:
        raise ValueError("coordinator Worker-group authority requires the marked pinned child")
    pid = os.getpid()
    process_group_id = os.getpgrp()
    session_id = os.getsid(0)
    if process_group_id != pid or session_id != pid:
        raise ValueError(
            "coordinator Worker-group authority requires a dedicated process group and session"
        )
    return _GovernedCoordinatorWorkerGroupAuthority(
        _factory_token=_GOVERNED_COORDINATOR_WORKER_GROUP_FACTORY_TOKEN,
        pid=pid,
        process_group_id=process_group_id,
        session_id=session_id,
        workspace_identity=workspace_identity,
    )


@contextmanager
def _activate_governed_coordinator_worker_group(
    authority: _GovernedCoordinatorWorkerGroupAuthority,
) -> Iterator[None]:
    """Keep nested Workers in the coordinator's killable POSIX process group."""

    if (
        type(authority) is not _GovernedCoordinatorWorkerGroupAuthority
        or authority._factory_token is not _GOVERNED_COORDINATOR_WORKER_GROUP_FACTORY_TOKEN
        or authority.pid != os.getpid()
        or authority.process_group_id != authority.pid
        or authority.process_group_id != os.getpgrp()
        or authority.session_id != authority.pid
        or authority.session_id != os.getsid(0)
        or authority.workspace_identity != active_pinned_workspace_identity()
        or os.environ.get(_GOVERNED_COORDINATOR_SUBPROCESS_MARKER) != "1"
    ):
        raise ValueError("coordinator Worker-group authority changed")
    current = _ACTIVE_COORDINATOR_WORKER_GROUP.get()
    if current is not None:
        raise ValueError("coordinator Worker-group authority is already active")
    token: Token[_GovernedCoordinatorWorkerGroupAuthority | None] = (
        _ACTIVE_COORDINATOR_WORKER_GROUP.set(authority)
    )
    try:
        yield
    finally:
        _ACTIVE_COORDINATOR_WORKER_GROUP.reset(token)


def _web_worker_starts_new_session() -> bool:
    if os.name != "posix":
        return False
    authority = _ACTIVE_COORDINATOR_WORKER_GROUP.get()
    if authority is None:
        return True
    if (
        type(authority) is not _GovernedCoordinatorWorkerGroupAuthority
        or authority._factory_token is not _GOVERNED_COORDINATOR_WORKER_GROUP_FACTORY_TOKEN
        or authority.pid != os.getpid()
        or authority.process_group_id != authority.pid
        or authority.process_group_id != os.getpgrp()
        or authority.session_id != authority.pid
        or authority.session_id != os.getsid(0)
        or authority.workspace_identity != active_pinned_workspace_identity()
        or os.environ.get(_GOVERNED_COORDINATOR_SUBPROCESS_MARKER) != "1"
    ):
        raise ValueError("coordinator Worker-group authority is no longer exact")
    return False


_WEB_WORKER_PRODUCTION_FACTORY_TOKEN = object()
_WEB_WORKER_GATEWAY_FACTORY_TOKEN = object()
_MACOS_USER_TEXT_ENCODING_ENV = "__CF_USER_TEXT_ENCODING"


@dataclass(frozen=True)
class _WebWorkerPythonRuntimeIdentity:
    entrypoint: str
    target_device: int
    target_inode: int
    target_mode: int
    prefix: str
    base_prefix: str
    exec_prefix: str
    base_exec_prefix: str


def _absolute_python_entrypoint(value: str) -> str:
    if not value or "\x00" in value:
        raise ValueError("Web Worker Python executable is invalid")
    entrypoint = os.path.abspath(value)
    if not os.path.isabs(value) or entrypoint != value:
        raise ValueError("authoritative Web Worker Python executable must be canonical absolute")
    return entrypoint


def _current_python_runtime_identity() -> _WebWorkerPythonRuntimeIdentity:
    entrypoint = _absolute_python_entrypoint(sys.executable)
    prefix = os.path.abspath(sys.prefix)
    base_prefix = os.path.abspath(sys.base_prefix)
    exec_prefix = os.path.abspath(sys.exec_prefix)
    base_exec_prefix = os.path.abspath(sys.base_exec_prefix)
    try:
        target = os.stat(entrypoint, follow_symlinks=True)
    except OSError as error:
        raise ValueError("authoritative Web Worker Python executable is unavailable") from error
    if not stat.S_ISREG(target.st_mode):
        raise ValueError("authoritative Web Worker Python executable target is not regular")
    try:
        inside_prefix = os.path.commonpath((entrypoint, prefix)) == prefix
    except ValueError:
        inside_prefix = False
    if prefix == base_prefix or not inside_prefix:
        raise ValueError("authoritative Web Worker Python executable requires its active venv")
    return _WebWorkerPythonRuntimeIdentity(
        entrypoint=entrypoint,
        target_device=target.st_dev,
        target_inode=target.st_ino,
        target_mode=target.st_mode,
        prefix=prefix,
        base_prefix=base_prefix,
        exec_prefix=exec_prefix,
        base_exec_prefix=base_exec_prefix,
    )


def _canonical_macos_user_text_encoding(value: str) -> str:
    parts = value.split(":")
    if len(parts) != 3:
        raise ValueError("macOS Web Worker text encoding marker is malformed")
    numbers: list[int] = []
    for part in parts:
        if not part.startswith("0x") or not part[2:] or len(part[2:]) > 8:
            raise ValueError("macOS Web Worker text encoding marker is malformed")
        try:
            number = int(part[2:], 16)
        except ValueError as error:
            raise ValueError("macOS Web Worker text encoding marker is malformed") from error
        if part != f"0x{number:X}":
            raise ValueError("macOS Web Worker text encoding marker is not canonical")
        numbers.append(number)
    if numbers[0] != os.getuid():
        raise ValueError("macOS Web Worker text encoding marker has a foreign user")
    return value


def _current_macos_user_text_encoding() -> str | None:
    if sys.platform != "darwin":
        return None
    value = os.environ.get(_MACOS_USER_TEXT_ENCODING_ENV)
    if value is None:
        raise ValueError("macOS Web Worker text encoding marker is unavailable")
    return _canonical_macos_user_text_encoding(value)


def canonical_web_worker_json(value: object) -> bytes:
    """Return the unique JSON representation used by every Web Worker signature."""

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def canonical_web_worker_sha256(value: object) -> str:
    return sha256(canonical_web_worker_json(value)).hexdigest()


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, size: int, label: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != size or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {size} bytes")
    return decoded


def web_worker_public_key_base64url(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 Web Worker private key must contain 32 bytes")
    public = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def web_worker_private_key_base64url(private_key: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 Web Worker private key must contain 32 bytes")
    return _base64url_encode(private_key)


def web_target_fingerprint_digest(
    *,
    origin: str,
    product: str,
    version: str,
    fingerprint_endpoint: str,
    response_sha256: str,
    adapter_implementation_digest: str,
    recipe_digest: str,
) -> str:
    canonical_origin = local_origin(origin)
    if canonical_origin != origin:
        raise ValueError("target fingerprint origin must be canonical")
    if (
        not product.strip()
        or product != product.strip()
        or len(product) > 100
        or not version.strip()
        or version != version.strip()
        or len(version) > 100
    ):
        raise ValueError("target fingerprint product and version are required")
    if not fingerprint_endpoint.startswith("/") or any(
        item in fingerprint_endpoint for item in ("?", "#", "\\")
    ):
        raise ValueError("target fingerprint endpoint must be an origin-relative path")
    digests = (response_sha256, adapter_implementation_digest, recipe_digest)
    if any(
        len(value) != 64 or any(character not in "0123456789abcdef" for character in value)
        for value in digests
    ):
        raise ValueError("target fingerprint inputs require lowercase SHA-256 digests")
    return canonical_web_worker_sha256(
        {
            "apiVersion": "pajin.dev/web-target-fingerprint/v2",
            "origin": origin,
            "product": product,
            "version": version,
            "fingerprintEndpoint": fingerprint_endpoint,
            "responseSha256": response_sha256,
            "adapterImplementationDigest": adapter_implementation_digest,
            "recipeDigest": recipe_digest,
        }
    )


class WebWorkerRole(StrEnum):
    SOURCE_TARGET_OBSERVER = "source-target-observer"
    SOURCE_EXECUTOR = "source-executor"
    VALIDATION_TARGET_OBSERVER = "validation-target-observer"
    VALIDATION_EXECUTOR = "validation-executor"


_OBSERVER_ROLES = frozenset(
    {
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.VALIDATION_TARGET_OBSERVER,
    }
)
_EXECUTOR_ROLES = frozenset(
    {
        WebWorkerRole.SOURCE_EXECUTOR,
        WebWorkerRole.VALIDATION_EXECUTOR,
    }
)


class WebWorkerKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class WebWorkerAuthorityBinding(StrictModel):
    """All upstream authority identities one process must sign back verbatim."""

    campaign_id: str = Field(alias="campaignId", pattern=_SAFE_ID_PATTERN)
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    capability_id: str = Field(alias="capabilityId", pattern=_SAFE_ID_PATTERN)
    capability_version: str = Field(
        alias="capabilityVersion",
        pattern=r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$",
    )
    capability_digest: str = Field(alias="capabilityDigest", pattern=_SHA256_PATTERN)
    capability_grant_id: str = Field(alias="capabilityGrantId", pattern=_SAFE_ID_PATTERN)
    capability_grant_digest: str = Field(
        alias="capabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_grant_consumption_receipt_id: str = Field(
        alias="capabilityGrantConsumptionReceiptId",
        pattern=_SAFE_ID_PATTERN,
    )
    capability_grant_consumption_receipt_digest: str = Field(
        alias="capabilityGrantConsumptionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)
    adapter_implementation_digest: str = Field(
        alias="adapterImplementationDigest",
        pattern=_SHA256_PATTERN,
    )
    recipe_digest: str = Field(alias="recipeDigest", pattern=_SHA256_PATTERN)
    account_receipt_digest: str = Field(alias="accountReceiptDigest", pattern=_SHA256_PATTERN)
    target_origin: str = Field(alias="targetOrigin")
    target_product: str = Field(alias="targetProduct", min_length=1, max_length=100)
    target_version: str = Field(alias="targetVersion", min_length=1, max_length=100)
    target_fingerprint_endpoint: str = Field(
        alias="targetFingerprintEndpoint",
        min_length=1,
        max_length=500,
    )
    expected_target_response_sha256: str = Field(
        alias="expectedTargetResponseSha256",
        pattern=_SHA256_PATTERN,
    )
    expected_target_fingerprint_digest: str = Field(
        alias="expectedTargetFingerprintDigest",
        pattern=_SHA256_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_SAFE_ID_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_SHA256_PATTERN)
    action_permit_id: str = Field(alias="actionPermitId", pattern=_SAFE_ID_PATTERN)
    action_permit_digest: str = Field(alias="actionPermitDigest", pattern=_SHA256_PATTERN)
    approval_id: str = Field(alias="approvalId", pattern=_SAFE_ID_PATTERN)
    approval_digest: str = Field(alias="approvalDigest", pattern=_SHA256_PATTERN)
    approval_receipt_id: str = Field(alias="approvalReceiptId", pattern=_SAFE_ID_PATTERN)
    approval_receipt_digest: str = Field(
        alias="approvalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    dispatch_binding_digest: str = Field(alias="dispatchBindingDigest", pattern=_SHA256_PATTERN)
    expected_run_id: str = Field(alias="expectedRunId", pattern=_RUN_ID_PATTERN)

    @field_validator("target_origin")
    @classmethod
    def require_canonical_loopback_origin(cls, value: str) -> str:
        if local_origin(value) != value:
            raise ValueError("Web Worker target origin must be canonical numeric loopback")
        return value

    @field_validator("target_product", "target_version")
    @classmethod
    def require_canonical_target_label(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("Web Worker target labels must be canonical")
        return value

    @field_validator("target_fingerprint_endpoint")
    @classmethod
    def require_origin_relative_fingerprint_endpoint(cls, value: str) -> str:
        if not value.startswith("/") or any(item in value for item in ("?", "#", "\\")):
            raise ValueError("Web Worker target fingerprint endpoint is invalid")
        return value

    @model_validator(mode="after")
    def bind_target_fingerprint(self) -> Self:
        expected = web_target_fingerprint_digest(
            origin=self.target_origin,
            product=self.target_product,
            version=self.target_version,
            fingerprint_endpoint=self.target_fingerprint_endpoint,
            response_sha256=self.expected_target_response_sha256,
            adapter_implementation_digest=self.adapter_implementation_digest,
            recipe_digest=self.recipe_digest,
        )
        if expected != self.expected_target_fingerprint_digest:
            raise ValueError("Web Worker authority target fingerprint digest differs")
        return self

    @property
    def digest(self) -> str:
        return canonical_web_worker_sha256(self.model_dump(mode="json", by_alias=True))

    @property
    def shared_scope(self) -> tuple[str, ...]:
        """Identity that must remain equal across observer/source/validation actions."""

        return (
            self.campaign_id,
            self.campaign_digest,
            self.capability_id,
            self.capability_version,
            self.capability_digest,
            self.adapter_digest,
            self.adapter_implementation_digest,
            self.recipe_digest,
            self.account_receipt_digest,
            self.target_origin,
            self.target_product,
            self.target_version,
            self.target_fingerprint_endpoint,
            self.expected_target_response_sha256,
            self.expected_target_fingerprint_digest,
        )


class WebProvisionedAccountMaterial(StrictModel):
    """Secret-free fields needed to reconstruct an already-provisioned account receipt."""

    account_receipt_digest: str = Field(alias="accountReceiptDigest", pattern=_SHA256_PATTERN)
    plan_digest: str = Field(alias="planDigest", pattern=_SHA256_PATTERN)
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    origin: str
    target_version: str = Field(alias="targetVersion", min_length=1, max_length=100)
    provisioned_at: datetime = Field(alias="provisionedAt")
    request_evidence: tuple[RequestEvidence, ...] = Field(
        default=(), alias="requestEvidence", max_length=20
    )

    @field_validator("origin")
    @classmethod
    def require_canonical_origin(cls, value: str) -> str:
        if local_origin(value) != value:
            raise ValueError("provisioned account origin must be canonical numeric loopback")
        return value

    @field_validator("provisioned_at")
    @classmethod
    def normalize_provisioned_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="account provision time")

    def target_fingerprint_evidence(self, plan: WebAssessmentPlan) -> RequestEvidence:
        matches = [
            evidence
            for evidence in self.request_evidence
            if evidence.phase == "target-fingerprint"
            and evidence.method == "GET"
            and evidence.path == plan.fingerprint_endpoint
            and evidence.status == 200
        ]
        if len(matches) != 1 or matches[0].response_bytes < 1:
            raise ValueError(
                "provisioned account requires exactly one successful target fingerprint Evidence"
            )
        return matches[0].model_copy(deep=True)


class WebWorkerVerificationKey(StrictModel):
    key_id: str = Field(alias="keyId", pattern=_SAFE_ID_PATTERN)
    role: WebWorkerRole
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(alias="publicKeyBase64url", pattern=r"^[A-Za-z0-9_-]{43}$")
    state: WebWorkerKeyState = WebWorkerKeyState.ACTIVE
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def validate_key_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            size=32,
            label="Web Worker public key",
        )
        not_before = _aware_utc(self.not_before, label="key not-before time")
        not_after = (
            _aware_utc(self.not_after, label="key not-after time")
            if self.not_after is not None
            else None
        )
        if not_after is not None and not_after <= not_before:
            raise ValueError("Web Worker key validity window is empty")
        if self.state is WebWorkerKeyState.RETIRED and not_after is None:
            raise ValueError("retired Web Worker key requires a not-after time")
        if self.state is WebWorkerKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Web Worker key requires a revocation time")
            _aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Web Worker key cannot have a revocation time")
        return self


class WebWorkerTrustRegistry(StrictModel):
    api_version: Literal["pajin.dev/web-worker-trust-registry/v1"] = Field(
        default="pajin.dev/web-worker-trust-registry/v1", alias="apiVersion"
    )
    trust_domain: str = Field(alias="trustDomain", pattern=_SAFE_ID_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    keys: tuple[WebWorkerVerificationKey, ...] = Field(min_length=4, max_length=32)

    @model_validator(mode="after")
    def require_unique_ordered_role_keys(self) -> Self:
        identities = [(key.role.value, key.key_id) for key in self.keys]
        if identities != sorted(identities) or len(identities) != len(set(identities)):
            raise ValueError("Web Worker keys must be uniquely sorted by role and key ID")
        active_keys: list[WebWorkerVerificationKey] = []
        for role in WebWorkerRole:
            active = [
                key
                for key in self.keys
                if key.role is role and key.state is WebWorkerKeyState.ACTIVE
            ]
            if len(active) != 1:
                raise ValueError("Web Worker trust registry requires one active key per role")
            active_keys.extend(active)
        if len({key.public_key_base64url for key in active_keys}) != len(active_keys):
            raise ValueError("independent Web Worker roles require distinct active public keys")
        return self

    def key(self, key_id: str, role: WebWorkerRole) -> WebWorkerVerificationKey:
        matches = [key for key in self.keys if key.key_id == key_id and key.role is role]
        if len(matches) != 1:
            raise ValueError("Web Worker attestation key is not trusted for the claimed role")
        return matches[0].model_copy(deep=True)

    def active_key(self, role: WebWorkerRole) -> WebWorkerVerificationKey:
        matches = [
            key for key in self.keys if key.role is role and key.state is WebWorkerKeyState.ACTIVE
        ]
        if len(matches) != 1:
            raise ValueError("Web Worker role does not have exactly one active key")
        return matches[0].model_copy(deep=True)

    @property
    def digest(self) -> str:
        return canonical_web_worker_sha256(self.model_dump(mode="json", by_alias=True))


class WebTargetIdentityStatement(StrictModel):
    api_version: Literal["pajin.dev/web-target-identity-statement/v1"] = Field(
        default="pajin.dev/web-target-identity-statement/v1", alias="apiVersion"
    )
    predicate_type: Literal["pajin.dev/deployment-observed-web-target/v1"] = Field(
        default="pajin.dev/deployment-observed-web-target/v1", alias="predicateType"
    )
    trust_domain: str = Field(alias="trustDomain", pattern=_SAFE_ID_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    authority: WebWorkerAuthorityBinding
    role: Literal[
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.VALIDATION_TARGET_OBSERVER,
    ]
    execution_id: str = Field(alias="executionId", pattern=_SAFE_ID_PATTERN)
    target_product: str = Field(alias="targetProduct", min_length=1, max_length=100)
    target_version: str = Field(alias="targetVersion", min_length=1, max_length=100)
    fingerprint_endpoint: str = Field(alias="fingerprintEndpoint", min_length=1, max_length=500)
    observed_target_fingerprint_digest: str = Field(
        alias="observedTargetFingerprintDigest", pattern=_SHA256_PATTERN
    )
    response_sha256: str = Field(alias="responseSha256", pattern=_SHA256_PATTERN)
    response_bytes: int = Field(alias="responseBytes", strict=True, ge=1, le=10_000_000)
    response_status: Literal[200] = Field(default=200, alias="responseStatus")
    process_id: int = Field(alias="processId", strict=True, ge=1, le=2_147_483_647)
    runtime_implementation_version: Literal["pajin.web-assessment-process/v1"] = Field(
        default=WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
        alias="runtimeImplementationVersion",
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    issued_at: datetime = Field(alias="issuedAt")

    @model_validator(mode="after")
    def bind_observed_identity(self) -> Self:
        started = _aware_utc(self.started_at, label="target observation start time")
        finished = _aware_utc(self.finished_at, label="target observation finish time")
        issued = _aware_utc(self.issued_at, label="target observation issue time")
        if not started <= finished <= issued:
            raise ValueError("target observation timestamps are not ordered")
        expected = web_target_fingerprint_digest(
            origin=self.authority.target_origin,
            product=self.target_product,
            version=self.target_version,
            fingerprint_endpoint=self.fingerprint_endpoint,
            response_sha256=self.response_sha256,
            adapter_implementation_digest=self.authority.adapter_implementation_digest,
            recipe_digest=self.authority.recipe_digest,
        )
        if (
            self.observed_target_fingerprint_digest != expected
            or expected != self.authority.expected_target_fingerprint_digest
            or self.target_product != self.authority.target_product
            or self.target_version != self.authority.target_version
            or self.fingerprint_endpoint != self.authority.target_fingerprint_endpoint
            or self.response_sha256 != self.authority.expected_target_response_sha256
        ):
            raise ValueError("observed target fingerprint differs from approved identity")
        if not self.fingerprint_endpoint.startswith("/") or any(
            item in self.fingerprint_endpoint for item in ("?", "#", "\\")
        ):
            raise ValueError("target fingerprint endpoint must be an origin-relative path")
        return self


class SignedWebTargetIdentity(StrictModel):
    api_version: Literal["pajin.dev/signed-web-target-identity/v1"] = Field(
        default="pajin.dev/signed-web-target-identity/v1", alias="apiVersion"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(alias="keyId", pattern=_SAFE_ID_PATTERN)
    statement: WebTargetIdentityStatement
    statement_sha256: str = Field(alias="statementSha256", pattern=_SHA256_PATTERN)
    signature_base64url: str = Field(alias="signatureBase64url", pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_web_worker_json(self.statement.model_dump(mode="json", by_alias=True))
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("target identity statement digest differs")
        _base64url_decode(
            self.signature_base64url,
            size=64,
            label="target identity signature",
        )
        return self

    @property
    def digest(self) -> str:
        return canonical_web_worker_sha256(self.model_dump(mode="json", by_alias=True))


class WebExecutionStatement(StrictModel):
    api_version: Literal["pajin.dev/web-execution-statement/v1"] = Field(
        default="pajin.dev/web-execution-statement/v1", alias="apiVersion"
    )
    predicate_type: Literal["pajin.dev/host-subprocess-web-execution/v1"] = Field(
        default="pajin.dev/host-subprocess-web-execution/v1", alias="predicateType"
    )
    trust_domain: str = Field(alias="trustDomain", pattern=_SAFE_ID_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    authority: WebWorkerAuthorityBinding
    role: Literal[WebWorkerRole.SOURCE_EXECUTOR, WebWorkerRole.VALIDATION_EXECUTOR]
    execution_id: str = Field(alias="executionId", pattern=_SAFE_ID_PATTERN)
    target_identity_attestation_digest: str = Field(
        alias="targetIdentityAttestationDigest", pattern=_SHA256_PATTERN
    )
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    run_root_digest: str = Field(alias="runRootDigest", pattern=_SHA256_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    process_id: int = Field(alias="processId", strict=True, ge=1, le=2_147_483_647)
    runtime_implementation_version: Literal["pajin.web-assessment-process/v1"] = Field(
        default=WEB_WORKER_PROCESS_IMPLEMENTATION_VERSION,
        alias="runtimeImplementationVersion",
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    issued_at: datetime = Field(alias="issuedAt")
    authenticated: Literal[True] = True
    browser_closed: Literal[True] = Field(default=True, alias="browserClosed")
    credentials_persisted: Literal[False] = Field(default=False, alias="credentialsPersisted")
    server_session_credential_persisted: Literal[False] = Field(
        default=False, alias="serverSessionCredentialPersisted"
    )
    host_subprocess_isolation_only: Literal[True] = Field(
        default=True, alias="hostSubprocessIsolationOnly"
    )
    container_isolation: Literal[False] = Field(default=False, alias="containerIsolation")

    @model_validator(mode="after")
    def bind_execution_lifecycle(self) -> Self:
        started = _aware_utc(self.started_at, label="Web execution start time")
        finished = _aware_utc(self.finished_at, label="Web execution finish time")
        issued = _aware_utc(self.issued_at, label="Web execution issue time")
        if not started <= finished <= issued:
            raise ValueError("Web execution timestamps are not ordered")
        if self.run_id != self.authority.expected_run_id:
            raise ValueError("Web execution Run ID differs from preallocated authority")
        return self


class SignedWebExecutionAttestation(StrictModel):
    api_version: Literal["pajin.dev/signed-web-execution-attestation/v1"] = Field(
        default="pajin.dev/signed-web-execution-attestation/v1", alias="apiVersion"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(alias="keyId", pattern=_SAFE_ID_PATTERN)
    statement: WebExecutionStatement
    statement_sha256: str = Field(alias="statementSha256", pattern=_SHA256_PATTERN)
    signature_base64url: str = Field(alias="signatureBase64url", pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = canonical_web_worker_json(self.statement.model_dump(mode="json", by_alias=True))
        if sha256(canonical).hexdigest() != self.statement_sha256:
            raise ValueError("Web execution statement digest differs")
        _base64url_decode(
            self.signature_base64url,
            size=64,
            label="Web execution signature",
        )
        return self

    @property
    def digest(self) -> str:
        return canonical_web_worker_sha256(self.model_dump(mode="json", by_alias=True))


class SignedWebWorkerActionEvidence(StrictModel):
    """One Gateway action's independently signed observer and executor pair."""

    api_version: Literal["pajin.dev/signed-web-worker-action-evidence/v1"] = Field(
        default="pajin.dev/signed-web-worker-action-evidence/v1", alias="apiVersion"
    )
    target_identity: SignedWebTargetIdentity = Field(alias="targetIdentity")
    execution_attestation: SignedWebExecutionAttestation = Field(alias="executionAttestation")

    @model_validator(mode="after")
    def bind_action_pair(self) -> Self:
        target = self.target_identity.statement
        execution = self.execution_attestation.statement
        expected_target_role = (
            WebWorkerRole.SOURCE_TARGET_OBSERVER
            if execution.role is WebWorkerRole.SOURCE_EXECUTOR
            else WebWorkerRole.VALIDATION_TARGET_OBSERVER
        )
        if (
            target.role is not expected_target_role
            or target.authority != execution.authority
            or execution.target_identity_attestation_digest != self.target_identity.digest
            or target.process_id == execution.process_id
            or self.target_identity.key_id == self.execution_attestation.key_id
            or target.execution_id == execution.execution_id
        ):
            raise ValueError("signed Web Worker observer/executor pair is not independent")
        return self

    @property
    def digest(self) -> str:
        return canonical_web_worker_sha256(self.model_dump(mode="json", by_alias=True))


class WebWorkerCompletedActionRecord(StrictModel):
    """Secret-free completion snapshot minted only by a successful backend run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-worker-completed-action/v1"] = Field(
        default="pajin.dev/web-worker-completed-action/v1",
        alias="apiVersion",
    )
    kind: Literal["WebWorkerCompletedActionRecord"] = "WebWorkerCompletedActionRecord"
    completion_digest: str = Field(default="", alias="completionDigest", max_length=64)
    backend_implementation_version: Literal["pajin.host-loopback-browser-worker/v1"] = Field(
        default="pajin.host-loopback-browser-worker/v1",
        alias="backendImplementationVersion",
    )
    worker_trust_registry_digest: str = Field(
        alias="workerTrustRegistryDigest",
        pattern=_SHA256_PATTERN,
    )
    role: Literal[WebWorkerRole.SOURCE_EXECUTOR, WebWorkerRole.VALIDATION_EXECUTOR]
    authority: WebWorkerAuthorityBinding
    gateway_launch_id: str = Field(alias="gatewayLaunchId", pattern=_SAFE_ID_PATTERN)
    gateway_audit_run_id: str = Field(alias="gatewayAuditRunId", pattern=_RUN_ID_PATTERN)
    gateway_execution_id: str = Field(alias="gatewayExecutionId", pattern=_SAFE_ID_PATTERN)
    worker_execution_id: str = Field(alias="workerExecutionId", pattern=_SAFE_ID_PATTERN)
    observer_execution_id: str = Field(alias="observerExecutionId", pattern=_SAFE_ID_PATTERN)
    observer_process_id: int = Field(alias="observerProcessId", strict=True, ge=1)
    executor_process_id: int = Field(alias="executorProcessId", strict=True, ge=1)
    observer_key_id: str = Field(alias="observerKeyId", pattern=_SAFE_ID_PATTERN)
    executor_key_id: str = Field(alias="executorKeyId", pattern=_SAFE_ID_PATTERN)
    target_identity_attestation_digest: str = Field(
        alias="targetIdentityAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    execution_attestation_digest: str = Field(
        alias="executionAttestationDigest",
        pattern=_SHA256_PATTERN,
    )
    worker_action_evidence_digest: str = Field(
        alias="workerActionEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    target_identity_digest: str = Field(alias="targetIdentityDigest", pattern=_SHA256_PATTERN)
    run_id: str = Field(alias="runId", pattern=_RUN_ID_PATTERN)
    run_root_digest: str = Field(alias="runRootDigest", pattern=_SHA256_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    worker_result_digest: str = Field(alias="workerResultDigest", pattern=_SHA256_PATTERN)
    completed_at: datetime = Field(alias="completedAt")

    @field_validator("completed_at")
    @classmethod
    def normalize_completed_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Web Worker completion time")

    @model_validator(mode="after")
    def bind_completion(self) -> Self:
        if (
            self.gateway_execution_id != self.worker_execution_id
            or self.worker_execution_id == self.observer_execution_id
            or self.observer_process_id == self.executor_process_id
            or self.observer_key_id == self.executor_key_id
            or self.target_identity_digest != self.authority.expected_target_fingerprint_digest
            or self.run_id != self.authority.expected_run_id
            or self.gateway_audit_run_id == self.run_id
        ):
            raise ValueError("Web Worker completion identities are not independently bound")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"completion_digest"},
        )
        digest = canonical_web_worker_sha256(
            {
                "domain": "pajin.web-worker.completed-action/v1",
                "record": material,
            }
        )
        if self.completion_digest and self.completion_digest != digest:
            raise ValueError("Web Worker completion digest differs")
        object.__setattr__(self, "completion_digest", digest)
        return self


@final
class WebWorkerCompletedActionAuthority:
    """Opaque backend-owned proof that one signed action actually completed."""

    __slots__ = ("__action_evidence", "__backend", "__factory_token", "__record")

    def __init__(
        self,
        *,
        _backend: object,
        _factory_token: object,
        _record: WebWorkerCompletedActionRecord,
        _action_evidence: SignedWebWorkerActionEvidence,
    ) -> None:
        self.__backend = _backend
        self.__factory_token = _factory_token
        self.__record = WebWorkerCompletedActionRecord.model_validate(
            _record.model_dump(mode="json", by_alias=True)
        )
        self.__action_evidence = SignedWebWorkerActionEvidence.model_validate(
            _action_evidence.model_dump(mode="json", by_alias=True)
        )

    @property
    def completion(self) -> WebWorkerCompletedActionRecord:
        return self.__record.model_copy(deep=True)

    @property
    def action_evidence(self) -> SignedWebWorkerActionEvidence:
        return self.__action_evidence.model_copy(deep=True)

    @property
    def completion_digest(self) -> str:
        return self.__record.completion_digest

    def _registered_by(self, backend: object, factory_token: object) -> bool:
        return self.__backend is backend and self.__factory_token is factory_token


@final
class _WebWorkerGatewayLaunchAuthority:
    """Process-local one-use capability issued only to the exact Gateway wrapper."""

    __slots__ = (
        "__backend",
        "__dispatch_binding_digest",
        "__execution_id",
        "__gateway_run_id",
        "__launch_id",
        "__owner",
        "__owner_token",
        "__request_id",
        "__task",
    )

    def __init__(
        self,
        *,
        backend: object,
        owner: object,
        owner_token: object,
        request_id: str,
        execution_id: str,
        dispatch_binding_digest: str,
        gateway_run_id: str,
        task: asyncio.Task[object],
    ) -> None:
        self.__backend = backend
        self.__owner = owner
        self.__owner_token = owner_token
        self.__request_id = request_id
        self.__execution_id = execution_id
        self.__dispatch_binding_digest = dispatch_binding_digest
        self.__gateway_run_id = gateway_run_id
        self.__task = task
        self.__launch_id = f"web-gateway-launch_{uuid4().hex}"

    @property
    def launch_id(self) -> str:
        return self.__launch_id

    def _matches(
        self,
        *,
        backend: object,
        owner: object,
        owner_token: object,
        request_id: str,
        execution_id: str,
        dispatch_binding_digest: str,
        gateway_run_id: str,
        task: asyncio.Task[object] | None,
    ) -> bool:
        return (
            self.__backend is backend
            and self.__owner is owner
            and self.__owner_token is owner_token
            and self.__request_id == request_id
            and self.__execution_id == execution_id
            and self.__dispatch_binding_digest == dispatch_binding_digest
            and self.__gateway_run_id == gateway_run_id
            and self.__task is task
        )


@final
class _WebWorkerGatewayExecutionAuthority:
    """Opaque authority minted only while consuming one registered Gateway launch."""

    __slots__ = (
        "__backend",
        "__execution_id",
        "__factory_token",
        "__gateway_audit_run_id",
        "__gateway_launch_id",
        "__task",
    )

    def __init__(
        self,
        *,
        factory_token: object,
        backend: object,
        execution_id: str,
        gateway_launch_id: str,
        gateway_audit_run_id: str,
        task: asyncio.Task[object],
    ) -> None:
        if factory_token is not _WEB_WORKER_GATEWAY_EXECUTION_FACTORY_TOKEN:
            raise TypeError("Web Worker Gateway execution authority is deployment-owned")
        self.__factory_token = factory_token
        self.__backend = backend
        self.__execution_id = execution_id
        self.__gateway_launch_id = gateway_launch_id
        self.__gateway_audit_run_id = gateway_audit_run_id
        self.__task = task

    def _binding(
        self,
        *,
        backend: object,
        execution_id: str,
        task: asyncio.Task[object] | None,
    ) -> tuple[str, str] | None:
        if (
            self.__factory_token is not _WEB_WORKER_GATEWAY_EXECUTION_FACTORY_TOKEN
            or self.__backend is not backend
            or self.__execution_id != execution_id
            or self.__task is not task
        ):
            return None
        return self.__gateway_launch_id, self.__gateway_audit_run_id


@dataclass(frozen=True, slots=True)
class WebWorkerAttestor:
    key_id: str
    role: WebWorkerRole
    trust_domain: str
    issuer: str
    private_key: Ed25519PrivateKey

    @classmethod
    def from_private_key_base64url(
        cls,
        *,
        key_id: str,
        role: WebWorkerRole,
        trust_domain: str,
        issuer: str,
        private_key_base64url: str,
    ) -> WebWorkerAttestor:
        private_bytes = _base64url_decode(
            private_key_base64url,
            size=32,
            label="Web Worker private key",
        )
        return cls(
            key_id=key_id,
            role=role,
            trust_domain=trust_domain,
            issuer=issuer,
            private_key=Ed25519PrivateKey.from_private_bytes(private_bytes),
        )

    def sign_target(self, statement: WebTargetIdentityStatement) -> SignedWebTargetIdentity:
        if self.role not in _OBSERVER_ROLES or statement.role is not self.role:
            raise ValueError("target identity signer role differs")
        self._require_issuer(statement.trust_domain, statement.issuer)
        canonical = canonical_web_worker_json(statement.model_dump(mode="json", by_alias=True))
        return SignedWebTargetIdentity(
            keyId=self.key_id,
            statement=statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_TARGET_SIGNATURE_DOMAIN + canonical)
            ),
        )

    def sign_execution(
        self,
        statement: WebExecutionStatement,
    ) -> SignedWebExecutionAttestation:
        if self.role not in _EXECUTOR_ROLES or statement.role is not self.role:
            raise ValueError("Web execution signer role differs")
        self._require_issuer(statement.trust_domain, statement.issuer)
        canonical = canonical_web_worker_json(statement.model_dump(mode="json", by_alias=True))
        return SignedWebExecutionAttestation(
            keyId=self.key_id,
            statement=statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_EXECUTION_SIGNATURE_DOMAIN + canonical)
            ),
        )

    def _require_issuer(self, trust_domain: str, issuer: str) -> None:
        if trust_domain != self.trust_domain or issuer != self.issuer:
            raise ValueError("Web Worker signer authority differs")


def _require_key_valid_for_statement(
    key: WebWorkerVerificationKey,
    issued_at: datetime,
) -> None:
    issued = _aware_utc(issued_at, label="attestation issue time")
    not_before = _aware_utc(key.not_before, label="key not-before time")
    not_after = (
        _aware_utc(key.not_after, label="key not-after time") if key.not_after is not None else None
    )
    if issued < not_before or (not_after is not None and issued >= not_after):
        raise ValueError("Web Worker signature is outside key validity")
    if key.state is WebWorkerKeyState.REVOKED:
        assert key.revoked_at is not None
        if issued >= _aware_utc(key.revoked_at, label="key revocation time"):
            raise ValueError("Web Worker signature was issued after key revocation")


def _require_live_active_key(
    *,
    registry: WebWorkerTrustRegistry,
    key_id: str,
    role: WebWorkerRole,
    issued_at: datetime,
    verification_time: datetime | None,
) -> WebWorkerVerificationKey:
    key = registry.key(key_id, role)
    active_key = registry.active_key(role)
    if key != active_key or key.state is not WebWorkerKeyState.ACTIVE:
        raise ValueError("Web Worker attestation key is not the current ACTIVE role key")
    verified_at = _aware_utc(
        verification_time if verification_time is not None else datetime.now(UTC),
        label="Web Worker verification time",
    )
    issued = _aware_utc(issued_at, label="attestation issue time")
    if issued > verified_at:
        raise ValueError("Web Worker attestation was issued after its verification time")
    _require_key_valid_for_statement(key, issued)
    _require_key_valid_for_statement(key, verified_at)
    return key


def verify_signed_web_target_identity(
    attestation: SignedWebTargetIdentity,
    registry: WebWorkerTrustRegistry,
    *,
    expected_authority: WebWorkerAuthorityBinding | None = None,
    expected_execution_id: str | None = None,
    verification_time: datetime | None = None,
) -> SignedWebTargetIdentity:
    statement = attestation.statement
    if statement.trust_domain != registry.trust_domain or statement.issuer != registry.issuer:
        raise ValueError("target identity trust authority differs")
    key = _require_live_active_key(
        registry=registry,
        key_id=attestation.key_id,
        role=statement.role,
        issued_at=statement.issued_at,
        verification_time=verification_time,
    )
    canonical = canonical_web_worker_json(statement.model_dump(mode="json", by_alias=True))
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(key.public_key_base64url, size=32, label="Web Worker public key")
        ).verify(
            _base64url_decode(
                attestation.signature_base64url,
                size=64,
                label="target identity signature",
            ),
            _TARGET_SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise ValueError("target identity signature verification failed") from exc
    if expected_authority is not None and statement.authority != expected_authority:
        raise ValueError("target identity authority binding differs")
    if expected_execution_id is not None and statement.execution_id != expected_execution_id:
        raise ValueError("target identity execution ID differs")
    return attestation.model_copy(deep=True)


def verify_signed_web_execution_attestation(
    attestation: SignedWebExecutionAttestation,
    registry: WebWorkerTrustRegistry,
    *,
    expected_authority: WebWorkerAuthorityBinding | None = None,
    expected_execution_id: str | None = None,
    expected_target_identity_digest: str | None = None,
    verification_time: datetime | None = None,
) -> SignedWebExecutionAttestation:
    statement = attestation.statement
    if statement.trust_domain != registry.trust_domain or statement.issuer != registry.issuer:
        raise ValueError("Web execution trust authority differs")
    key = _require_live_active_key(
        registry=registry,
        key_id=attestation.key_id,
        role=statement.role,
        issued_at=statement.issued_at,
        verification_time=verification_time,
    )
    canonical = canonical_web_worker_json(statement.model_dump(mode="json", by_alias=True))
    try:
        Ed25519PublicKey.from_public_bytes(
            _base64url_decode(key.public_key_base64url, size=32, label="Web Worker public key")
        ).verify(
            _base64url_decode(
                attestation.signature_base64url,
                size=64,
                label="Web execution signature",
            ),
            _EXECUTION_SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise ValueError("Web execution signature verification failed") from exc
    if expected_authority is not None and statement.authority != expected_authority:
        raise ValueError("Web execution authority binding differs")
    if expected_execution_id is not None and statement.execution_id != expected_execution_id:
        raise ValueError("Web execution ID differs")
    if (
        expected_target_identity_digest is not None
        and statement.target_identity_attestation_digest != expected_target_identity_digest
    ):
        raise ValueError("Web execution target identity binding differs")
    return attestation.model_copy(deep=True)


class WebIndependentWorkerEvidence(StrictModel):
    api_version: Literal["pajin.dev/web-independent-worker-evidence/v1"] = Field(
        default="pajin.dev/web-independent-worker-evidence/v1", alias="apiVersion"
    )
    trust_registry_digest: str = Field(alias="trustRegistryDigest", pattern=_SHA256_PATTERN)
    source_target_identity_attestation_digest: str = Field(
        alias="sourceTargetIdentityAttestationDigest", pattern=_SHA256_PATTERN
    )
    validation_target_identity_attestation_digest: str = Field(
        alias="validationTargetIdentityAttestationDigest", pattern=_SHA256_PATTERN
    )
    source_execution_attestation_digest: str = Field(
        alias="sourceExecutionAttestationDigest", pattern=_SHA256_PATTERN
    )
    validation_execution_attestation_digest: str = Field(
        alias="validationExecutionAttestationDigest", pattern=_SHA256_PATTERN
    )
    process_ids: tuple[int, int, int, int] = Field(alias="processIds")
    key_ids: tuple[str, str, str, str] = Field(alias="keyIds")
    execution_ids: tuple[str, str, str, str] = Field(alias="executionIds")
    independent_processes_verified: Literal[True] = Field(
        default=True, alias="independentProcessesVerified"
    )
    independent_keys_verified: Literal[True] = Field(default=True, alias="independentKeysVerified")
    common_authority_scope_verified: Literal[True] = Field(
        default=True, alias="commonAuthorityScopeVerified"
    )
    host_subprocess_isolation_only: Literal[True] = Field(
        default=True, alias="hostSubprocessIsolationOnly"
    )
    container_isolation: Literal[False] = Field(default=False, alias="containerIsolation")


def verify_independent_web_worker_evidence(
    *,
    source_target: SignedWebTargetIdentity,
    source: SignedWebExecutionAttestation,
    validation_target: SignedWebTargetIdentity,
    validation: SignedWebExecutionAttestation,
    registry: WebWorkerTrustRegistry,
    verification_time: datetime | None = None,
) -> WebIndependentWorkerEvidence:
    verified_at = _aware_utc(
        verification_time if verification_time is not None else datetime.now(UTC),
        label="independent Web Worker evidence verification time",
    )
    source_target = verify_signed_web_target_identity(
        source_target,
        registry,
        verification_time=verified_at,
    )
    source = verify_signed_web_execution_attestation(
        source,
        registry,
        expected_target_identity_digest=source_target.digest,
        verification_time=verified_at,
    )
    validation_target = verify_signed_web_target_identity(
        validation_target,
        registry,
        verification_time=verified_at,
    )
    validation = verify_signed_web_execution_attestation(
        validation,
        registry,
        expected_target_identity_digest=validation_target.digest,
        verification_time=verified_at,
    )
    if source_target.statement.role is not WebWorkerRole.SOURCE_TARGET_OBSERVER:
        raise ValueError("source Target evidence was not issued by its observer role")
    if source.statement.role is not WebWorkerRole.SOURCE_EXECUTOR:
        raise ValueError("source evidence was not issued by the source-executor role")
    if validation_target.statement.role is not WebWorkerRole.VALIDATION_TARGET_OBSERVER:
        raise ValueError("validation Target evidence was not issued by its observer role")
    if validation.statement.role is not WebWorkerRole.VALIDATION_EXECUTOR:
        raise ValueError("validation evidence was not issued by the validation-executor role")
    if source_target.statement.authority != source.statement.authority:
        raise ValueError("source observer and executor action authorities differ")
    if validation_target.statement.authority != validation.statement.authority:
        raise ValueError("validation observer and executor action authorities differ")
    statements = (
        source_target.statement,
        source.statement,
        validation_target.statement,
        validation.statement,
    )
    process_ids = (
        source_target.statement.process_id,
        source.statement.process_id,
        validation_target.statement.process_id,
        validation.statement.process_id,
    )
    key_ids = (
        source_target.key_id,
        source.key_id,
        validation_target.key_id,
        validation.key_id,
    )
    roles = (
        source_target.statement.role,
        source.statement.role,
        validation_target.statement.role,
        validation.statement.role,
    )
    execution_ids = (
        source_target.statement.execution_id,
        source.statement.execution_id,
        validation_target.statement.execution_id,
        validation.statement.execution_id,
    )
    if len(set(process_ids)) != 4:
        raise ValueError("source/validation observers and executors require distinct processes")
    if len(set(key_ids)) != 4:
        raise ValueError("source/validation observers and executors require distinct signing keys")
    public_keys = tuple(
        registry.key(key_id, role).public_key_base64url
        for key_id, role in zip(key_ids, roles, strict=True)
    )
    if len(set(public_keys)) != 4:
        raise ValueError("source/validation evidence requires distinct public key material")
    if len(set(execution_ids)) != 4:
        raise ValueError("source/validation observers and executors require distinct execution IDs")
    shared_scopes = {statement.authority.shared_scope for statement in statements}
    if len(shared_scopes) != 1:
        raise ValueError("source/validation evidence differs in governed authority scope")
    if source_target.digest == validation_target.digest:
        raise ValueError("source and validation require distinct target attestations")
    if source.statement.run_id == validation.statement.run_id:
        raise ValueError("source and validation evidence must reference distinct Runs")
    if source.statement.run_root_digest == validation.statement.run_root_digest:
        raise ValueError("source and validation evidence must reference distinct sealed roots")
    return WebIndependentWorkerEvidence(
        trustRegistryDigest=registry.digest,
        sourceTargetIdentityAttestationDigest=source_target.digest,
        sourceExecutionAttestationDigest=source.digest,
        validationTargetIdentityAttestationDigest=validation_target.digest,
        validationExecutionAttestationDigest=validation.digest,
        processIds=process_ids,
        keyIds=key_ids,
        executionIds=execution_ids,
    )


class WebWorkerJobSpec(StrictModel):
    """Persistable, secret-free input compiled by the code-owned Tool adapter."""

    api_version: Literal["pajin.dev/web-worker-job/v1"] = Field(
        default="pajin.dev/web-worker-job/v1", alias="apiVersion"
    )
    kind: Literal["WebWorkerJob"] = "WebWorkerJob"
    role: WebWorkerRole
    execution_id: str = Field(alias="executionId", pattern=_SAFE_ID_PATTERN)
    expected_run_id: str = Field(alias="expectedRunId", pattern=_RUN_ID_PATTERN)
    observer_execution_id: str | None = Field(
        default=None,
        alias="observerExecutionId",
        pattern=_SAFE_ID_PATTERN,
    )
    authority: WebWorkerAuthorityBinding
    adapter_implementation: str = Field(
        default=DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
        alias="adapterImplementation",
        pattern=_SAFE_ID_PATTERN,
    )
    plan: WebAssessmentPlan
    authorization: LocalWebAssessmentAuthorization
    provisioned_account: WebProvisionedAccountMaterial = Field(alias="provisionedAccount")
    signing_key_id: str = Field(alias="signingKeyId", pattern=_SAFE_ID_PATTERN)
    observer_signing_key_id: str | None = Field(
        default=None,
        alias="observerSigningKeyId",
        pattern=_SAFE_ID_PATTERN,
    )
    request_unit_ceiling: int = Field(
        default=100, alias="requestUnitCeiling", strict=True, ge=1, le=100
    )
    response_byte_ceiling: int = Field(
        default=8_000_000,
        alias="responseByteCeiling",
        strict=True,
        ge=1_024,
        le=10_000_000,
    )
    target_identity: SignedWebTargetIdentity | None = Field(default=None, alias="targetIdentity")
    headless: bool = Field(default=True, strict=True)

    @field_validator("adapter_implementation", mode="before")
    @classmethod
    def normalize_legacy_adapter_implementation(cls, value: object) -> object:
        if value == _LEGACY_WEB_WORKER_ADAPTER_IMPLEMENTATION:
            return DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID
        return value

    @model_validator(mode="after")
    def bind_job_inputs(self) -> Self:
        if (
            self.expected_run_id != self.authority.expected_run_id
            or self.plan.origin != self.authority.target_origin
            or self.plan.target_product != self.authority.target_product
            or self.plan.fingerprint_endpoint != self.authority.target_fingerprint_endpoint
            or self.adapter_implementation != self.plan.adapter_implementation_id
            or self.authorization.origin != self.plan.origin
            or self.authorization.plan_digest != self.plan.plan_digest
            or self.provisioned_account.origin != self.plan.origin
            or self.provisioned_account.plan_digest != self.plan.plan_digest
            or self.provisioned_account.authorization_id != self.authorization.authorization_id
            or self.provisioned_account.account_receipt_digest
            != self.authority.account_receipt_digest
        ):
            raise ValueError("Web Worker plan, authorization, account, and authority differ")
        fingerprint_evidence = self.provisioned_account.target_fingerprint_evidence(self.plan)
        expected_fingerprint = web_target_fingerprint_digest(
            origin=self.plan.origin,
            product=self.authority.target_product,
            version=self.provisioned_account.target_version,
            fingerprint_endpoint=self.plan.fingerprint_endpoint,
            response_sha256=fingerprint_evidence.response_sha256,
            adapter_implementation_digest=self.authority.adapter_implementation_digest,
            recipe_digest=self.plan.plan_digest,
        )
        if (
            self.authority.target_product != self.plan.target_product
            or self.authority.target_version != self.provisioned_account.target_version
            or self.authority.target_fingerprint_endpoint != self.plan.fingerprint_endpoint
            or self.authority.expected_target_response_sha256
            != fingerprint_evidence.response_sha256
            or self.authority.recipe_digest != self.plan.plan_digest
            or expected_fingerprint != self.authority.expected_target_fingerprint_digest
        ):
            raise ValueError("provisioned account target fingerprint differs from authority")
        if self.role in _OBSERVER_ROLES:
            if (
                self.target_identity is not None
                or self.observer_signing_key_id is not None
                or self.observer_execution_id is not None
            ):
                raise ValueError("target-observer process input cannot import paired authority")
        else:
            if self.observer_signing_key_id is None or self.observer_execution_id is None:
                raise ValueError("executor job requires its paired observer process identity")
            if self.observer_signing_key_id == self.signing_key_id:
                raise ValueError("observer and executor signing key IDs must differ")
            if self.observer_execution_id == self.execution_id:
                raise ValueError("observer and executor execution IDs must differ")
            if self.target_identity is not None:
                expected_target_role = (
                    WebWorkerRole.SOURCE_TARGET_OBSERVER
                    if self.role is WebWorkerRole.SOURCE_EXECUTOR
                    else WebWorkerRole.VALIDATION_TARGET_OBSERVER
                )
                if (
                    self.target_identity.statement.role is not expected_target_role
                    or self.target_identity.statement.authority != self.authority
                ):
                    raise ValueError("executor and paired target-observer authority differ")
        return self


class WebWorkerProcessSecrets(StrictModel):
    """Pipe-only secret payload. Never serialize this model into Run artifacts."""

    signing_private_key_base64url: str = Field(
        alias="signingPrivateKeyBase64url",
        repr=False,
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    account_name: str | None = Field(
        default=None, alias="accountName", repr=False, min_length=1, max_length=500
    )
    account_proof: str | None = Field(
        default=None, alias="accountProof", repr=False, min_length=1, max_length=500
    )

    @model_validator(mode="after")
    def require_role_credentials_later(self) -> Self:
        _base64url_decode(
            self.signing_private_key_base64url,
            size=32,
            label="Web Worker signing key",
        )
        if (self.account_name is None) != (self.account_proof is None):
            raise ValueError("Web account name and proof must be supplied together")
        return self


class WebWorkerProcessInput(StrictModel):
    """Ephemeral stdin contract assembled only after SecretBroker materialization."""

    api_version: Literal["pajin.dev/web-worker-process-input/v1"] = Field(
        default="pajin.dev/web-worker-process-input/v1", alias="apiVersion"
    )
    job: WebWorkerJobSpec
    output_root: str = Field(alias="outputRoot", min_length=1, max_length=4_096)
    pinned_workspace_device: int | None = Field(
        default=None,
        alias="pinnedWorkspaceDevice",
        ge=0,
    )
    pinned_workspace_inode: int | None = Field(
        default=None,
        alias="pinnedWorkspaceInode",
        gt=0,
    )
    pinned_workspace_uid: int | None = Field(
        default=None,
        alias="pinnedWorkspaceUid",
        ge=0,
    )
    pinned_workspace_mode: int | None = Field(
        default=None,
        alias="pinnedWorkspaceMode",
        gt=0,
    )
    trust_domain: str = Field(alias="trustDomain", pattern=_SAFE_ID_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    secrets: WebWorkerProcessSecrets = Field(repr=False)

    @model_validator(mode="after")
    def require_complete_pinned_workspace_identity(self) -> Self:
        values = (
            self.pinned_workspace_device,
            self.pinned_workspace_inode,
            self.pinned_workspace_uid,
            self.pinned_workspace_mode,
        )
        if any(value is None for value in values) and any(value is not None for value in values):
            raise ValueError("Web Worker pinned workspace identity must be complete")
        return self

    @property
    def pinned_workspace_identity(self) -> PinnedWorkspaceIdentity | None:
        if (
            self.pinned_workspace_device is None
            or self.pinned_workspace_inode is None
            or self.pinned_workspace_uid is None
            or self.pinned_workspace_mode is None
        ):
            return None
        return PinnedWorkspaceIdentity(
            device=self.pinned_workspace_device,
            inode=self.pinned_workspace_inode,
            uid=self.pinned_workspace_uid,
            mode=self.pinned_workspace_mode,
        )


@dataclass(frozen=True, slots=True)
class WebSubprocessCapture:
    pid: int
    exit_code: int | None
    stdout: bytes
    stderr: bytes
    started_at: datetime
    finished_at: datetime
    timed_out: bool = False
    output_limit_exceeded: bool = False


class WebWorkerSubprocessRunner(Protocol):
    async def run(
        self,
        command: tuple[str, ...],
        *,
        stdin: bytes,
        env: Mapping[str, str],
        timeout_seconds: float,
        stdout_limit_bytes: int,
        stderr_limit_bytes: int,
    ) -> WebSubprocessCapture: ...


class AsyncioWebWorkerSubprocessRunner:
    """No-shell, bounded pipe transport for one fresh host subprocess."""

    async def run(
        self,
        command: tuple[str, ...],
        *,
        stdin: bytes,
        env: Mapping[str, str],
        timeout_seconds: float,
        stdout_limit_bytes: int,
        stderr_limit_bytes: int,
    ) -> WebSubprocessCapture:
        if not command or any(not item or "\x00" in item for item in command):
            raise ValueError("Web Worker command is invalid")
        if len(stdin) > _MAX_PROCESS_INPUT_BYTES:
            raise ValueError("Web Worker process input exceeds its byte limit")
        started_at = datetime.now(UTC)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=dict(env),
            start_new_session=_web_worker_starts_new_session(),
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None

        async def read_bounded(
            stream: asyncio.StreamReader,
            limit: int,
        ) -> tuple[bytes, bool]:
            retained = bytearray()
            overflow = False
            while chunk := await stream.read(64 * 1024):
                remaining = max(0, limit - len(retained))
                retained.extend(chunk[:remaining])
                overflow = overflow or len(chunk) > remaining
            return bytes(retained), overflow

        stdout_task = asyncio.create_task(read_bounded(process.stdout, stdout_limit_bytes))
        stderr_task = asyncio.create_task(read_bounded(process.stderr, stderr_limit_bytes))
        timed_out = False
        try:
            process.stdin.write(stdin)
            await process.stdin.drain()
            process.stdin.close()
            await process.stdin.wait_closed()
            try:
                await asyncio.wait_for(process.wait(), timeout=timeout_seconds)
            except TimeoutError:
                timed_out = True
                process.kill()
                await process.wait()
        except (BaseException, asyncio.CancelledError):
            if process.returncode is None:
                process.kill()
                await process.wait()
            raise
        finally:
            if not process.stdin.is_closing():
                process.stdin.close()
        stdout, stdout_overflow = await stdout_task
        stderr, stderr_overflow = await stderr_task
        return WebSubprocessCapture(
            pid=process.pid,
            exit_code=process.returncode,
            stdout=stdout,
            stderr=stderr,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            timed_out=timed_out,
            output_limit_exceeded=stdout_overflow or stderr_overflow,
        )


_ASYNCIO_WEB_WORKER_RUN = AsyncioWebWorkerSubprocessRunner.run


class HostLoopbackBrowserWorkerBackend:
    """Code-owned host subprocess backend for one exact loopback Web recipe.

    The backend consumes a trusted dispatch binding exactly once.  This prevents
    an otherwise-valid caller-authored stdin object from changing Campaign,
    Capability, approval, ActionPermit, adapter, account, request, or Target
    identity before process launch.
    """

    name = WEB_WORKER_BACKEND_NAME

    @classmethod
    def production(
        cls,
        *,
        output_root: Path,
        trust_registry: WebWorkerTrustRegistry,
    ) -> HostLoopbackBrowserWorkerBackend:
        """Build the only backend profile eligible to mint completion authority."""

        if cls is not HostLoopbackBrowserWorkerBackend:
            raise TypeError("authoritative Web Worker backend factory rejects subclasses")
        return cls(
            output_root=output_root,
            trust_registry=trust_registry,
            _production_factory_token=_WEB_WORKER_PRODUCTION_FACTORY_TOKEN,
        )

    def __init__(
        self,
        *,
        output_root: Path,
        trust_registry: WebWorkerTrustRegistry,
        runner: WebWorkerSubprocessRunner | None = None,
        python_executable: str | None = None,
        _production_factory_token: object | None = None,
    ) -> None:
        requested_python = python_executable or sys.executable
        if not requested_python or "\x00" in requested_python:
            raise ValueError("Web Worker Python executable is invalid")
        resolved_python = os.path.abspath(requested_python)
        production_runtime = (
            _current_python_runtime_identity()
            if _production_factory_token is _WEB_WORKER_PRODUCTION_FACTORY_TOKEN
            else None
        )
        production_text_encoding = (
            _current_macos_user_text_encoding()
            if _production_factory_token is _WEB_WORKER_PRODUCTION_FACTORY_TOKEN
            else None
        )
        pinned_output_root = pinned_workspace_relative_path(
            output_root,
            label="Web Worker output root",
        )
        self.output_root = (
            pinned_output_root if pinned_output_root is not None else output_root.resolve()
        )
        self._pinned_workspace_identity = (
            active_pinned_workspace_identity() if pinned_output_root is not None else None
        )
        self.trust_registry = trust_registry.model_copy(deep=True)
        self._runner = runner or AsyncioWebWorkerSubprocessRunner()
        self._python = resolved_python
        self._production_profile = (
            _production_factory_token is _WEB_WORKER_PRODUCTION_FACTORY_TOKEN
            and runner is None
            and python_executable is None
            and type(self) is HostLoopbackBrowserWorkerBackend
            and production_runtime is not None
            and resolved_python == production_runtime.entrypoint
        )
        self.__production_factory_token = _production_factory_token
        self._pinned_output_root = self.output_root
        self._pinned_trust_registry_digest = self.trust_registry.digest
        self.__pinned_python_runtime = production_runtime
        self.__pinned_macos_user_text_encoding = production_text_encoding
        self._bindings: dict[str, WebWorkerAuthorityBinding] = {}
        self._binding_lock = Lock()
        self.__completion_factory_token = object()
        self._completion_lock = Lock()
        self._completion_inflight: dict[str, object] = {}
        self._completed_actions: dict[str, WebWorkerCompletedActionAuthority] = {}
        self._gateway_owners: dict[str, tuple[object, object]] = {}
        self._gateway_launches: dict[str, _WebWorkerGatewayLaunchAuthority] = {}
        self.__pinned_runner = self._runner
        self.__pinned_trust_registry = self.trust_registry
        self.__pinned_bindings = self._bindings
        self.__pinned_binding_lock = self._binding_lock
        self.__pinned_completion_lock = self._completion_lock
        self.__pinned_completion_inflight = self._completion_inflight
        self.__pinned_completed_actions = self._completed_actions
        self.__pinned_gateway_launches = self._gateway_launches
        self.__pinned_gateway_owners = self._gateway_owners

    def _bind_production_gateway(
        self,
        owner: object,
        factory_token: object,
        *,
        role: Literal["source", "validation"],
    ) -> object:
        """Bind exactly one code-owned governed Gateway to this production backend."""

        self.require_authoritative_completion_profile()
        if factory_token is not _WEB_WORKER_GATEWAY_FACTORY_TOKEN:
            raise ValueError("Web Worker rejected a foreign governed Gateway factory")
        with self._completion_lock:
            if role in self._gateway_owners:
                raise ValueError("Web Worker production Gateway role is already bound")
            owner_token = object()
            self._gateway_owners[role] = (owner, owner_token)
            return owner_token

    def _reserve_gateway_launch(
        self,
        *,
        owner: object,
        owner_token: object,
        dispatch: WebAssessmentDispatchBinding,
        gateway_run_id: str,
    ) -> _WebWorkerGatewayLaunchAuthority:
        """Reserve the only launch capability accepted by the production backend."""

        self.require_authoritative_completion_profile()
        canonical = WebAssessmentDispatchBinding.model_validate(
            dispatch.model_dump(mode="json", by_alias=True)
        )
        if self._gateway_owners.get(canonical.role) != (owner, owner_token):
            raise ValueError("Web Worker governed Gateway owner differs")
        task = asyncio.current_task()
        if task is None:
            raise ValueError("Web Worker Gateway launch requires an active asyncio Task")
        launch = _WebWorkerGatewayLaunchAuthority(
            backend=self,
            owner=owner,
            owner_token=owner_token,
            request_id=canonical.request_id,
            execution_id=canonical.worker_execution_id,
            dispatch_binding_digest=canonical.binding_digest,
            gateway_run_id=gateway_run_id,
            task=task,
        )
        with self._completion_lock:
            if canonical.worker_execution_id in self._gateway_launches:
                raise ValueError("Web Worker Gateway launch is already reserved")
            self._gateway_launches[canonical.worker_execution_id] = launch
        return launch

    def _clear_gateway_launch(
        self,
        *,
        owner: object,
        owner_token: object,
        launch: _WebWorkerGatewayLaunchAuthority,
        execution_id: str,
        role: Literal["source", "validation"],
    ) -> None:
        if self._gateway_owners.get(role) != (owner, owner_token):
            raise ValueError("Web Worker governed Gateway owner differs")
        with self._completion_lock:
            if self._gateway_launches.get(execution_id) is launch:
                self._gateway_launches.pop(execution_id)

    def register_trusted_dispatch(self, binding: WebWorkerAuthorityBinding) -> None:
        snapshot = WebWorkerAuthorityBinding.model_validate(
            binding.model_dump(mode="python", by_alias=True)
        )
        with self._binding_lock:
            if snapshot.request_id in self._bindings:
                raise ValueError("trusted Web dispatch request is already registered")
            self._bindings[snapshot.request_id] = snapshot

    def completed_action_authority(
        self,
        *,
        request_id: str,
        execution_id: str,
        dispatch_binding_digest: str,
    ) -> WebWorkerCompletedActionAuthority:
        """Return the opaque handle registered by one successful backend run."""

        self.require_authoritative_completion_profile()
        with self._completion_lock:
            authority = self._completed_actions.get(execution_id)
            if authority is None:
                raise ValueError("Web Worker execution has no completed-action authority")
            record = authority.completion
            if (
                not authority._registered_by(self, self.__completion_factory_token)
                or record.authority.request_id != request_id
                or record.authority.dispatch_binding_digest != dispatch_binding_digest
                or record.gateway_execution_id != execution_id
            ):
                raise ValueError("Web Worker completed-action lookup authority differs")
            return authority

    def consume_completed_action_authorities(
        self,
        *,
        source: WebWorkerCompletedActionAuthority,
        validation: WebWorkerCompletedActionAuthority,
    ) -> tuple[WebWorkerCompletedActionAuthority, WebWorkerCompletedActionAuthority]:
        """Atomically consume exact source/validation completion handles once."""

        if (
            type(source) is not WebWorkerCompletedActionAuthority
            or type(validation) is not WebWorkerCompletedActionAuthority
        ):
            raise TypeError("Web Worker completion consumption requires opaque authorities")
        self.require_authoritative_completion_profile()
        with self._completion_lock:
            source_record = source.completion
            validation_record = validation.completion
            if (
                source is validation
                or not source._registered_by(self, self.__completion_factory_token)
                or not validation._registered_by(self, self.__completion_factory_token)
                or self._completed_actions.get(source_record.gateway_execution_id) is not source
                or self._completed_actions.get(validation_record.gateway_execution_id)
                is not validation
                or source_record.role is not WebWorkerRole.SOURCE_EXECUTOR
                or validation_record.role is not WebWorkerRole.VALIDATION_EXECUTOR
            ):
                raise ValueError(
                    "Web Worker completion authority is foreign, reconstructed, or consumed"
                )
            source_evidence = source.action_evidence
            validation_evidence = validation.action_evidence
            verified = verify_independent_web_worker_evidence(
                source_target=source_evidence.target_identity,
                source=source_evidence.execution_attestation,
                validation_target=validation_evidence.target_identity,
                validation=validation_evidence.execution_attestation,
                registry=self.trust_registry,
                verification_time=datetime.now(UTC),
            )
            self._require_completion_matches(
                source_record,
                source_evidence,
                verified=verified,
                index=0,
            )
            self._require_completion_matches(
                validation_record,
                validation_evidence,
                verified=verified,
                index=2,
            )
            if source_record.completion_digest == validation_record.completion_digest:
                raise ValueError("source and validation completion authorities must differ")
            self._completed_actions.pop(source_record.gateway_execution_id)
            self._completed_actions.pop(validation_record.gateway_execution_id)
            return source, validation

    def stable_execution_context(self) -> dict[str, object]:
        context: dict[str, object] = {
            "implementationVersion": WEB_WORKER_IMPLEMENTATION_VERSION,
            "allowedImage": WEB_HOST_WORKER_IMAGE,
            "supportedCommands": [
                list(WEB_TARGET_OBSERVER_COMMAND),
                list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
            ],
            "networkBoundary": "code-owned-exact-loopback-application-gate",
            "targetIdentity": "deployment-observer-signed",
            "ephemeralInputTransport": "one-use-broker-lease-to-stdin-pipe",
            "isolationBoundary": "fresh-host-subprocess",
            "containerIsolation": False,
            "hostObservedEgressProxy": False,
            "trustRegistryDigest": self.trust_registry.digest,
            "completedActionAuthority": "backend-owned-opaque-one-time-pair",
            "productionAuthorityEligible": self._authoritative_completion_profile(),
            "subprocessRunner": (
                f"{type(self._runner).__module__}.{type(self._runner).__qualname__}"
            ),
            "pythonExecutable": self._python,
            "workerModule": "pajin.web_assessment.worker_process",
            "outputRoot": str(self.output_root),
        }
        if self._pinned_workspace_identity is not None:
            context["pinnedOutputWorkspace"] = True
        return context

    def require_authoritative_completion_profile(self) -> None:
        """Fail unless runtime identity still matches the production-only factory profile."""

        if not self._authoritative_completion_profile():
            raise ValueError(
                "Web Worker completion authority requires the production subprocess profile"
            )

    def _authoritative_completion_profile(self) -> bool:
        method_names = tuple(_HOST_LOOPBACK_BACKEND_METHODS)
        try:
            python_runtime = _current_python_runtime_identity()
            macos_user_text_encoding = _current_macos_user_text_encoding()
        except ValueError:
            return False
        return (
            self._production_profile
            and self.__production_factory_token is _WEB_WORKER_PRODUCTION_FACTORY_TOKEN
            and type(self) is HostLoopbackBrowserWorkerBackend
            and type(self._runner) is AsyncioWebWorkerSubprocessRunner
            and self._runner is self.__pinned_runner
            and "run" not in vars(self._runner)
            and type(self._runner).run is _ASYNCIO_WEB_WORKER_RUN
            and self.__pinned_python_runtime is not None
            and python_runtime == self.__pinned_python_runtime
            and self._python == self.__pinned_python_runtime.entrypoint
            and macos_user_text_encoding == self.__pinned_macos_user_text_encoding
            and self.output_root == self._pinned_output_root
            and (
                self._pinned_workspace_identity is None
                or active_pinned_workspace_identity() == self._pinned_workspace_identity
            )
            and self.trust_registry is self.__pinned_trust_registry
            and self.trust_registry.digest == self._pinned_trust_registry_digest
            and self._bindings is self.__pinned_bindings
            and self._binding_lock is self.__pinned_binding_lock
            and self._completion_lock is self.__pinned_completion_lock
            and self._completion_inflight is self.__pinned_completion_inflight
            and self._completed_actions is self.__pinned_completed_actions
            and self._gateway_launches is self.__pinned_gateway_launches
            and self._gateway_owners is self.__pinned_gateway_owners
            and all(name not in vars(self) for name in method_names)
            and all(
                getattr(type(self), name, None) is _HOST_LOOPBACK_BACKEND_METHODS[name]
                for name in method_names
            )
        )

    async def run(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        if self._production_profile:
            self.require_authoritative_completion_profile()
            raise ValueError(
                "production Web Worker execution requires a governed ToolGateway launch"
            )
        return await self._run_authorized(
            job,
            secrets=secrets,
            gateway_authority=None,
        )

    async def _run_from_production_gateway(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None,
        owner: object,
        owner_token: object,
        launch: _WebWorkerGatewayLaunchAuthority,
        dispatch: WebAssessmentDispatchBinding,
        gateway_run_id: str,
    ) -> WorkerResult:
        """Consume one exact Gateway launch before any Web subprocess may start."""

        self.require_authoritative_completion_profile()
        canonical = WebAssessmentDispatchBinding.model_validate(
            dispatch.model_dump(mode="json", by_alias=True)
        )
        if (
            job.execution_id != canonical.worker_execution_id
            or self._gateway_owners.get(canonical.role) != (owner, owner_token)
            or not launch._matches(
                backend=self,
                owner=owner,
                owner_token=owner_token,
                request_id=canonical.request_id,
                execution_id=canonical.worker_execution_id,
                dispatch_binding_digest=canonical.binding_digest,
                gateway_run_id=gateway_run_id,
                task=asyncio.current_task(),
            )
        ):
            raise ValueError("Web Worker governed Gateway launch authority differs")
        with self._completion_lock:
            if self._gateway_launches.get(job.execution_id) is not launch:
                raise ValueError("Web Worker governed Gateway launch is absent or consumed")
            self._gateway_launches.pop(job.execution_id)
        task = asyncio.current_task()
        assert task is not None
        return await self._run_authorized(
            job,
            secrets=secrets,
            gateway_authority=_WebWorkerGatewayExecutionAuthority(
                factory_token=_WEB_WORKER_GATEWAY_EXECUTION_FACTORY_TOKEN,
                backend=self,
                execution_id=job.execution_id,
                gateway_launch_id=launch.launch_id,
                gateway_audit_run_id=gateway_run_id,
                task=task,
            ),
        )

    async def _run_authorized(
        self,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None,
        gateway_authority: _WebWorkerGatewayExecutionAuthority | None,
    ) -> WorkerResult:
        started_at = datetime.now(UTC)
        reserved_completion: tuple[str, object] | None = None
        completion_binding = (
            gateway_authority._binding(
                backend=self,
                execution_id=job.execution_id,
                task=asyncio.current_task(),
            )
            if type(gateway_authority) is _WebWorkerGatewayExecutionAuthority
            else None
        )
        completion_authoritative = completion_binding is not None
        if self._production_profile:
            self.require_authoritative_completion_profile()
            if not completion_authoritative:
                raise ValueError("authoritative Web Worker completion requires a Gateway launch")
        elif gateway_authority is not None:
            raise ValueError("non-production Web Worker rejects Gateway launch authority")
        gateway_launch_id, gateway_audit_run_id = (
            completion_binding if completion_binding is not None else (None, None)
        )
        completion_token: object | None = None
        try:
            spec = self._validate_job(job)
            if completion_authoritative:
                completion_token = self._reserve_completion(spec.execution_id)
                reserved_completion = (spec.execution_id, completion_token)
            self._consume_trusted_binding(spec)
            material = self._validate_secrets(spec, secrets or [])
            if spec.role not in _EXECUTOR_ROLES:
                raise ValueError("Gateway Web Worker job must describe an executor action")
            assert spec.observer_signing_key_id is not None
            self._validate_signing_key(
                key_id=spec.observer_signing_key_id,
                role=self.paired_observer_role(spec.role),
                private_value=material[WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING],
            )
            self._validate_signing_key(
                key_id=spec.signing_key_id,
                role=spec.role,
                private_value=material[WEB_WORKER_SIGNING_KEY_BINDING],
            )
            loop = asyncio.get_running_loop()
            deadline = loop.time() + job.limits.timeout_seconds
            observer_spec = self._observer_spec(spec)
            observer_capture = await self._invoke_process(
                observer_spec,
                material,
                signing_binding=WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
                timeout_seconds=max(0.1, deadline - loop.time()),
                job=job,
            )
            target = self._parse_target_capture(
                observer_spec,
                observer_capture,
                secret_values=list(material.values()),
            )
            executor_spec = self._executor_spec(spec, target)
            executor_capture = await self._invoke_process(
                executor_spec,
                material,
                signing_binding=WEB_WORKER_SIGNING_KEY_BINDING,
                timeout_seconds=max(0.1, deadline - loop.time()),
                job=job,
            )
            execution = self._parse_execution_capture(
                executor_spec,
                executor_capture,
                secret_values=list(material.values()),
            )
            evidence = SignedWebWorkerActionEvidence(
                targetIdentity=target,
                executionAttestation=execution,
            )
            result = WorkerResult(
                execution_id=job.execution_id,
                backend=self.name,
                status=WorkerStatus.SUCCEEDED,
                exit_code=0,
                stdout=canonical_web_worker_json(
                    evidence.model_dump(mode="json", by_alias=True)
                ).decode("utf-8"),
                stderr="",
                network_log="",
                started_at=observer_capture.started_at,
                finished_at=executor_capture.finished_at,
            )
            if completion_authoritative:
                assert completion_token is not None
                assert gateway_launch_id is not None
                assert gateway_audit_run_id is not None
                self._register_completed_action(
                    job=job,
                    spec=spec,
                    evidence=evidence,
                    result=result,
                    completion_token=completion_token,
                    gateway_launch_id=gateway_launch_id,
                    gateway_audit_run_id=gateway_audit_run_id,
                )
                reserved_completion = None
            return result
        except asyncio.CancelledError:
            self._release_completion_reservation(reserved_completion)
            raise
        except TimeoutError:
            self._release_completion_reservation(reserved_completion)
            return self._failed(
                job,
                started_at,
                reason="host Web Worker action timed out",
                timed_out=True,
            )
        except Exception as exc:
            self._release_completion_reservation(reserved_completion)
            return self._failed(
                job,
                started_at,
                reason=f"host Web Worker rejected execution ({type(exc).__name__})",
            )

    def _reserve_completion(self, execution_id: str) -> object:
        self.require_authoritative_completion_profile()
        with self._completion_lock:
            if execution_id in self._completion_inflight or execution_id in self._completed_actions:
                raise ValueError("Web Worker execution identity is already completed or running")
            token = object()
            self._completion_inflight[execution_id] = token
            return token

    def _release_completion_reservation(
        self,
        reservation: tuple[str, object] | None,
    ) -> None:
        if reservation is None:
            return
        execution_id, token = reservation
        with self._completion_lock:
            if self._completion_inflight.get(execution_id) is token:
                self._completion_inflight.pop(execution_id)

    def _register_completed_action(
        self,
        *,
        job: WorkerJob,
        spec: WebWorkerJobSpec,
        evidence: SignedWebWorkerActionEvidence,
        result: WorkerResult,
        completion_token: object,
        gateway_launch_id: str,
        gateway_audit_run_id: str,
    ) -> None:
        self.require_authoritative_completion_profile()
        target = evidence.target_identity
        execution = evidence.execution_attestation
        if (
            result.status is not WorkerStatus.SUCCEEDED
            or result.backend != self.name
            or result.execution_id != job.execution_id
            or result.stdout
            != canonical_web_worker_json(evidence.model_dump(mode="json", by_alias=True)).decode(
                "utf-8"
            )
            or execution.statement.execution_id != spec.execution_id
            or execution.statement.authority != spec.authority
            or target.statement.authority != spec.authority
            or target.statement.execution_id != spec.observer_execution_id
            or result.finished_at < execution.statement.issued_at
        ):
            raise ValueError("Web Worker successful result differs from completed action")
        record = WebWorkerCompletedActionRecord(
            workerTrustRegistryDigest=self.trust_registry.digest,
            role=execution.statement.role,
            authority=spec.authority,
            gatewayLaunchId=gateway_launch_id,
            gatewayAuditRunId=gateway_audit_run_id,
            gatewayExecutionId=job.execution_id,
            workerExecutionId=execution.statement.execution_id,
            observerExecutionId=target.statement.execution_id,
            observerProcessId=target.statement.process_id,
            executorProcessId=execution.statement.process_id,
            observerKeyId=target.key_id,
            executorKeyId=execution.key_id,
            targetIdentityAttestationDigest=target.digest,
            executionAttestationDigest=execution.digest,
            workerActionEvidenceDigest=evidence.digest,
            targetIdentityDigest=spec.authority.expected_target_fingerprint_digest,
            runId=execution.statement.run_id,
            runRootDigest=execution.statement.run_root_digest,
            resultDigest=execution.statement.result_digest,
            workerResultDigest=canonical_web_worker_sha256(result.model_dump(mode="json")),
            completedAt=result.finished_at,
        )
        authority = WebWorkerCompletedActionAuthority(
            _backend=self,
            _factory_token=self.__completion_factory_token,
            _record=record,
            _action_evidence=evidence,
        )
        self._require_completion_matches(record, evidence)
        with self._completion_lock:
            if (
                self._completion_inflight.get(spec.execution_id) is not completion_token
                or spec.execution_id in self._completed_actions
            ):
                raise ValueError("Web Worker completion reservation changed before registration")
            self._completed_actions[spec.execution_id] = authority
            self._completion_inflight.pop(spec.execution_id)

    def _require_completion_matches(
        self,
        record: WebWorkerCompletedActionRecord,
        evidence: SignedWebWorkerActionEvidence,
        *,
        verified: WebIndependentWorkerEvidence | None = None,
        index: int | None = None,
    ) -> None:
        target = evidence.target_identity
        execution = evidence.execution_attestation
        if (
            record.worker_trust_registry_digest != self.trust_registry.digest
            or record.role is not execution.statement.role
            or record.authority != target.statement.authority
            or record.authority != execution.statement.authority
            or record.gateway_execution_id != execution.statement.execution_id
            or record.worker_execution_id != execution.statement.execution_id
            or record.observer_execution_id != target.statement.execution_id
            or record.observer_process_id != target.statement.process_id
            or record.executor_process_id != execution.statement.process_id
            or record.observer_key_id != target.key_id
            or record.executor_key_id != execution.key_id
            or record.target_identity_attestation_digest != target.digest
            or record.execution_attestation_digest != execution.digest
            or record.worker_action_evidence_digest != evidence.digest
            or record.target_identity_digest != record.authority.expected_target_fingerprint_digest
            or record.run_id != execution.statement.run_id
            or record.run_root_digest != execution.statement.run_root_digest
            or record.result_digest != execution.statement.result_digest
            or record.completed_at < execution.statement.issued_at
        ):
            raise ValueError("Web Worker completion record differs from signed action evidence")
        if verified is not None:
            assert index is not None
            if (
                verified.process_ids[index : index + 2]
                != (record.observer_process_id, record.executor_process_id)
                or verified.key_ids[index : index + 2]
                != (record.observer_key_id, record.executor_key_id)
                or verified.execution_ids[index : index + 2]
                != (record.observer_execution_id, record.worker_execution_id)
            ):
                raise ValueError("Web Worker completion differs from independent verification")

    def _validate_job(self, job: WorkerJob) -> WebWorkerJobSpec:
        if job.image != WEB_HOST_WORKER_IMAGE:
            raise ValueError("Web Worker image identity is not allowlisted")
        decoded = parse_strict_json_bytes(
            job.stdin.encode("utf-8"),
            label="Web Worker job input",
            max_bytes=_MAX_PROCESS_INPUT_BYTES,
            max_depth=64,
            max_nodes=100_000,
        )
        spec = WebWorkerJobSpec.model_validate(decoded)
        if (
            spec.role not in _EXECUTOR_ROLES
            or tuple(job.command) != WEB_ASSESSMENT_EXECUTOR_COMMAND
            or job.execution_id != spec.execution_id
            or spec.target_identity is not None
        ):
            raise ValueError("Web Worker command or execution identity differs")
        self._validate_egress_policy(job, spec)
        return spec

    @staticmethod
    def _validate_egress_policy(job: WorkerJob, spec: WebWorkerJobSpec) -> None:
        if job.network is not NetworkMode.EGRESS_PROXY or job.egress_policy is None:
            raise ValueError("host Web Worker requires Gateway-granted egress authority")
        policy = job.egress_policy
        expected = EgressPolicy(
            allow=[spec.plan.origin + "/**"],
            deny=[spec.plan.origin + path + "*" for path in spec.plan.deny_paths],
            allowed_methods={"GET", "HEAD", "POST"},
            allow_private_networks=True,
            max_response_bytes=spec.response_byte_ceiling,
            max_requests=spec.request_unit_ceiling,
            max_request_bytes=None,
        )
        if policy != expected:
            raise ValueError("Gateway egress policy differs from exact Web recipe authority")

    def _consume_trusted_binding(self, spec: WebWorkerJobSpec) -> None:
        with self._binding_lock:
            trusted = self._bindings.pop(spec.authority.request_id, None)
        if trusted is None or trusted != spec.authority:
            raise ValueError("Web Worker dispatch lacks its one-use trusted authority binding")

    @staticmethod
    def _validate_secrets(
        spec: WebWorkerJobSpec,
        materials: list[SecretMaterial],
    ) -> dict[str, str]:
        if spec.role not in _EXECUTOR_ROLES:
            raise ValueError("Gateway Web Worker secret scope requires an executor action")
        expected = {
            WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
            WEB_WORKER_SIGNING_KEY_BINDING,
            WEB_ACCOUNT_NAME_BINDING,
            WEB_ACCOUNT_PROOF_BINDING,
        }
        bindings = [material.binding for material in materials]
        if set(bindings) != expected or len(bindings) != len(expected):
            raise ValueError("Web Worker secret lease bindings differ from its role")
        return {material.binding: material.value for material in materials}

    def _validate_signing_key(
        self,
        *,
        key_id: str,
        role: WebWorkerRole,
        private_value: str,
    ) -> None:
        key = self.trust_registry.key(key_id, role)
        if key != self.trust_registry.active_key(role):
            raise ValueError("Web Worker signing key is not the current ACTIVE role key")
        _require_key_valid_for_statement(key, datetime.now(UTC))
        private_bytes = _base64url_decode(
            private_value,
            size=32,
            label="Web Worker signing private key",
        )
        if web_worker_public_key_base64url(private_bytes) != key.public_key_base64url:
            raise ValueError("Web Worker signing private key differs from trusted public key")

    async def _invoke_process(
        self,
        spec: WebWorkerJobSpec,
        materials: Mapping[str, str],
        *,
        signing_binding: str,
        timeout_seconds: float,
        job: WorkerJob,
    ) -> WebSubprocessCapture:
        credentials_required = spec.role in _EXECUTOR_ROLES
        pinned_workspace = self._pinned_workspace_identity
        process_input = WebWorkerProcessInput(
            job=spec,
            outputRoot=str(self.output_root),
            pinnedWorkspaceDevice=(
                pinned_workspace.device if pinned_workspace is not None else None
            ),
            pinnedWorkspaceInode=(pinned_workspace.inode if pinned_workspace is not None else None),
            pinnedWorkspaceUid=(pinned_workspace.uid if pinned_workspace is not None else None),
            pinnedWorkspaceMode=(pinned_workspace.mode if pinned_workspace is not None else None),
            trustDomain=self.trust_registry.trust_domain,
            issuer=self.trust_registry.issuer,
            secrets=WebWorkerProcessSecrets(
                signingPrivateKeyBase64url=materials[signing_binding],
                accountName=(materials[WEB_ACCOUNT_NAME_BINDING] if credentials_required else None),
                accountProof=(
                    materials[WEB_ACCOUNT_PROOF_BINDING] if credentials_required else None
                ),
            ),
        )
        process_payload = process_input.model_dump(mode="json", by_alias=True)
        if pinned_workspace is None:
            for field in (
                "pinnedWorkspaceDevice",
                "pinnedWorkspaceInode",
                "pinnedWorkspaceUid",
                "pinnedWorkspaceMode",
            ):
                process_payload.pop(field)
        process_stdin = canonical_web_worker_json(process_payload)
        command = (
            self._python,
            "-m",
            "pajin.web_assessment.worker_process",
            spec.role.value,
        )
        process_environment = self._sanitized_environment()
        stdout_limit = min(job.limits.stdout_bytes, _MAX_PROCESS_OUTPUT_BYTES)
        stderr_limit = min(job.limits.stderr_bytes, _MAX_PROCESS_STDERR_BYTES)
        if self._production_profile:
            self.require_authoritative_completion_profile()
            capture = await _ASYNCIO_WEB_WORKER_RUN(
                cast(AsyncioWebWorkerSubprocessRunner, self._runner),
                command,
                stdin=process_stdin,
                env=process_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit_bytes=stdout_limit,
                stderr_limit_bytes=stderr_limit,
            )
            self.require_authoritative_completion_profile()
        else:
            capture = await self._runner.run(
                command,
                stdin=process_stdin,
                env=process_environment,
                timeout_seconds=timeout_seconds,
                stdout_limit_bytes=stdout_limit,
                stderr_limit_bytes=stderr_limit,
            )
        process_stdin = b""
        return capture

    @staticmethod
    def paired_observer_role(role: WebWorkerRole) -> WebWorkerRole:
        if role is WebWorkerRole.SOURCE_EXECUTOR:
            return WebWorkerRole.SOURCE_TARGET_OBSERVER
        if role is WebWorkerRole.VALIDATION_EXECUTOR:
            return WebWorkerRole.VALIDATION_TARGET_OBSERVER
        raise ValueError("executor role does not have a paired target observer")

    def _observer_spec(self, spec: WebWorkerJobSpec) -> WebWorkerJobSpec:
        assert spec.observer_execution_id is not None
        assert spec.observer_signing_key_id is not None
        raw = spec.model_dump(mode="json", by_alias=True)
        raw.update(
            {
                "role": self.paired_observer_role(spec.role).value,
                "executionId": spec.observer_execution_id,
                "signingKeyId": spec.observer_signing_key_id,
                "observerExecutionId": None,
                "observerSigningKeyId": None,
                "targetIdentity": None,
            }
        )
        return WebWorkerJobSpec.model_validate(raw)

    @staticmethod
    def _executor_spec(
        spec: WebWorkerJobSpec,
        target: SignedWebTargetIdentity,
    ) -> WebWorkerJobSpec:
        raw = spec.model_dump(mode="json", by_alias=True)
        raw["targetIdentity"] = target.model_dump(mode="json", by_alias=True)
        return WebWorkerJobSpec.model_validate(raw)

    @staticmethod
    def _sanitized_environment() -> dict[str, str]:
        environment = {
            key: value
            for key, value in os.environ.items()
            if key.upper() in WEB_WORKER_OS_ENV_ALLOWLIST
        }
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        environment["PYTHONNOUSERSITE"] = "1"
        environment["PYTHONSAFEPATH"] = "1"
        environment["PAJIN_WEB_WORKER_HOST_SUBPROCESS"] = "1"
        environment.pop(_GOVERNED_COORDINATOR_SUBPROCESS_MARKER, None)
        return environment

    @staticmethod
    def _require_clean_capture(
        capture: WebSubprocessCapture,
        *,
        secret_values: list[str],
    ) -> object:
        if capture.timed_out:
            raise TimeoutError("host Web Worker process timed out")
        if capture.output_limit_exceeded:
            raise ValueError("host Web Worker process exceeded its output limit")
        secret_materials = [
            SecretMaterial(lease_id=f"projection-{index}", binding="projection", value=value)
            for index, value in enumerate(secret_values)
        ]
        stdout_text = capture.stdout.decode("utf-8", errors="replace")
        stderr_text = capture.stderr.decode("utf-8", errors="replace")
        if (
            redact_text(stdout_text, secret_materials) != stdout_text
            or redact_text(stderr_text, secret_materials) != stderr_text
        ):
            raise ValueError("host Web Worker process attempted to emit secret material")
        if capture.exit_code != 0 or capture.stderr:
            raise RuntimeError(
                "host Web Worker process failed; stderrSha256=" + sha256(capture.stderr).hexdigest()
            )
        return parse_strict_json_bytes(
            capture.stdout,
            label="Web Worker process output",
            max_bytes=_MAX_PROCESS_OUTPUT_BYTES,
            max_depth=64,
            max_nodes=100_000,
        )

    def _parse_target_capture(
        self,
        spec: WebWorkerJobSpec,
        capture: WebSubprocessCapture,
        *,
        secret_values: list[str],
    ) -> SignedWebTargetIdentity:
        decoded = self._require_clean_capture(capture, secret_values=secret_values)
        target = verify_signed_web_target_identity(
            SignedWebTargetIdentity.model_validate(decoded),
            self.trust_registry,
            expected_authority=spec.authority,
            expected_execution_id=spec.execution_id,
        )
        self._require_capture_identity(target.statement, capture)
        return target

    def _parse_execution_capture(
        self,
        spec: WebWorkerJobSpec,
        capture: WebSubprocessCapture,
        *,
        secret_values: list[str],
    ) -> SignedWebExecutionAttestation:
        decoded = self._require_clean_capture(capture, secret_values=secret_values)
        assert spec.target_identity is not None
        execution = verify_signed_web_execution_attestation(
            SignedWebExecutionAttestation.model_validate(decoded),
            self.trust_registry,
            expected_authority=spec.authority,
            expected_execution_id=spec.execution_id,
            expected_target_identity_digest=spec.target_identity.digest,
        )
        self._require_capture_identity(execution.statement, capture)
        self._verify_sealed_execution(spec, execution)
        return execution

    @staticmethod
    def _require_capture_identity(
        statement: WebTargetIdentityStatement | WebExecutionStatement,
        capture: WebSubprocessCapture,
    ) -> None:
        if statement.process_id != capture.pid:
            raise ValueError("signed Web Worker process ID differs from host observation")
        tolerance_seconds = 5
        if (
            statement.started_at < capture.started_at
            and (capture.started_at - statement.started_at).total_seconds() > tolerance_seconds
        ) or (
            statement.issued_at > capture.finished_at
            and (statement.issued_at - capture.finished_at).total_seconds() > tolerance_seconds
        ):
            raise ValueError("signed Web Worker lifecycle differs from host observation")

    def _verify_sealed_execution(
        self,
        spec: WebWorkerJobSpec,
        attestation: SignedWebExecutionAttestation,
    ) -> None:
        statement = attestation.statement
        run_path = self.output_root / spec.plan.name / statement.run_id
        expected_parent = self.output_root / spec.plan.name
        pinned_parent = pinned_workspace_relative_path(
            run_path.parent,
            label="Web Worker Run parent",
        )
        pinned_expected = pinned_workspace_relative_path(
            expected_parent,
            label="Web Worker expected Run parent",
        )
        if (
            pinned_parent != pinned_expected
            if pinned_parent is not None and pinned_expected is not None
            else run_path.parent.resolve() != expected_parent.resolve()
        ):
            raise ValueError("Web Worker Run path escaped its configured output root")
        verified = load_verified_local_web_assessment_source_integrity(
            run_path,
            expected_run_id=statement.run_id,
            expected_root_digest=statement.run_root_digest,
        )
        if (
            statement.run_id != spec.expected_run_id
            or verified.plan != spec.plan
            or verified.authorization != spec.authorization
            or verified.result.result_digest != statement.result_digest
            or verified.result.target_version != spec.provisioned_account.target_version
            or not verified.result.browser.browser_closed
            or verified.result.credentials_persisted
        ):
            raise ValueError("signed Web Worker execution differs from its sealed Run")

    @staticmethod
    def _failed(
        job: WorkerJob,
        started_at: datetime,
        *,
        reason: str,
        finished_at: datetime | None = None,
        timed_out: bool = False,
        failure_code: WorkerFailureCode | None = None,
    ) -> WorkerResult:
        return WorkerResult(
            execution_id=job.execution_id,
            backend=WEB_WORKER_BACKEND_NAME,
            status=WorkerStatus.TIMED_OUT if timed_out else WorkerStatus.FAILED,
            failure_code=None if timed_out else failure_code,
            exit_code=None,
            stdout="",
            stderr=reason[:1_000],
            network_log="",
            started_at=started_at,
            finished_at=finished_at or datetime.now(UTC),
        )


_HOST_LOOPBACK_BACKEND_METHODS: Mapping[str, object] = {
    name: getattr(HostLoopbackBrowserWorkerBackend, name)
    for name in (
        "register_trusted_dispatch",
        "_bind_production_gateway",
        "_reserve_gateway_launch",
        "_clear_gateway_launch",
        "completed_action_authority",
        "consume_completed_action_authorities",
        "stable_execution_context",
        "require_authoritative_completion_profile",
        "_authoritative_completion_profile",
        "run",
        "_run_from_production_gateway",
        "_run_authorized",
        "_reserve_completion",
        "_release_completion_reservation",
        "_register_completed_action",
        "_require_completion_matches",
        "_validate_job",
        "_validate_egress_policy",
        "_consume_trusted_binding",
        "_validate_secrets",
        "_validate_signing_key",
        "paired_observer_role",
        "_observer_spec",
        "_executor_spec",
        "_sanitized_environment",
        "_invoke_process",
        "_require_clean_capture",
        "_require_capture_identity",
        "_parse_target_capture",
        "_parse_execution_capture",
        "_verify_sealed_execution",
    )
}


class HostLoopbackWebDeploymentContext(StrictModel):
    """Deployment-owned, secret-free material that the generic Tool cannot invent."""

    account_receipt_digest: str = Field(alias="accountReceiptDigest", pattern=_SHA256_PATTERN)
    adapter: WebAssessmentAdapterManifest
    plan: WebAssessmentPlan
    source_authorization: LocalWebAssessmentAuthorization = Field(alias="sourceAuthorization")
    validation_authorization: LocalWebAssessmentAuthorization = Field(
        alias="validationAuthorization"
    )
    source_account: WebProvisionedAccountMaterial = Field(alias="sourceAccount")
    validation_account: WebProvisionedAccountMaterial = Field(alias="validationAccount")

    @model_validator(mode="after")
    def bind_deployment_context(self) -> Self:
        if (
            self.adapter.origin != self.plan.origin
            or self.adapter.implementation_id != self.plan.adapter_implementation_id
            or self.adapter.recipe_digest != self.plan.plan_digest
        ):
            raise ValueError("deployment Web adapter context differs from its plan")
        pairs = (
            (self.source_authorization, self.source_account),
            (self.validation_authorization, self.validation_account),
        )
        if self.source_authorization.authorization_id == (
            self.validation_authorization.authorization_id
        ):
            raise ValueError("source and validation require distinct local authorizations")
        for authorization, account in pairs:
            if (
                authorization.plan_digest != self.plan.plan_digest
                or authorization.origin != self.plan.origin
                or account.plan_digest != self.plan.plan_digest
                or account.origin != self.plan.origin
                or account.authorization_id != authorization.authorization_id
                or account.account_receipt_digest != self.account_receipt_digest
            ):
                raise ValueError("deployment Web account context differs from its plan")
        if self.source_account.target_version != self.validation_account.target_version:
            raise ValueError("source and validation account contexts target different versions")
        source_fingerprint = self.source_account.target_fingerprint_evidence(self.plan)
        validation_fingerprint = self.validation_account.target_fingerprint_evidence(self.plan)
        if (
            source_fingerprint.response_sha256 != validation_fingerprint.response_sha256
            or source_fingerprint.response_bytes != validation_fingerprint.response_bytes
        ):
            raise ValueError("source and validation provisioning fingerprints differ")
        return self


def _authority_from_dispatch(
    dispatch: WebAssessmentDispatchBinding,
    *,
    adapter: WebAssessmentAdapterManifest,
    target_product: str,
    target_version: str,
    target_fingerprint_endpoint: str,
    target_response_sha256: str,
    target_fingerprint_digest: str,
) -> WebWorkerAuthorityBinding:
    return WebWorkerAuthorityBinding(
        campaignId=dispatch.campaign_id,
        campaignDigest=dispatch.campaign_digest,
        capabilityId=dispatch.capability_id,
        capabilityVersion=dispatch.capability_version,
        capabilityDigest=dispatch.capability_digest,
        capabilityGrantId=dispatch.capability_grant_id,
        capabilityGrantDigest=dispatch.capability_grant_digest,
        capabilityGrantConsumptionReceiptId=(dispatch.capability_grant_consumption_receipt_id),
        capabilityGrantConsumptionReceiptDigest=(
            dispatch.capability_grant_consumption_receipt_digest
        ),
        adapterDigest=dispatch.adapter.adapter_digest,
        adapterImplementationDigest=adapter.implementation_digest,
        recipeDigest=adapter.recipe_digest,
        accountReceiptDigest=dispatch.account_receipt.receipt_digest,
        targetOrigin=adapter.origin,
        targetProduct=target_product,
        targetVersion=target_version,
        targetFingerprintEndpoint=target_fingerprint_endpoint,
        expectedTargetResponseSha256=target_response_sha256,
        expectedTargetFingerprintDigest=target_fingerprint_digest,
        requestId=dispatch.request_id,
        requestDigest=dispatch.request_digest,
        actionPermitId=dispatch.permit_id,
        actionPermitDigest=dispatch.permit_digest,
        approvalId=dispatch.approval_id,
        approvalDigest=dispatch.approval_digest,
        approvalReceiptId=dispatch.approval_receipt_id,
        approvalReceiptDigest=dispatch.approval_receipt_digest,
        dispatchBindingDigest=dispatch.binding_digest,
        expectedRunId=dispatch.expected_run_id,
    )


class HostLoopbackWebAssessmentJobCompiler:
    """Compile one signed adapter/account/dispatch set into the specialized Worker job."""

    def __init__(
        self,
        *,
        backend: HostLoopbackBrowserWorkerBackend,
        output_root_reference: str,
        contexts: tuple[HostLoopbackWebDeploymentContext, ...],
        implementation_id: str,
        implementation_digest: str,
        headless: bool = True,
    ) -> None:
        if not output_root_reference or len(output_root_reference) > 500:
            raise ValueError("Web Worker output-root reference is invalid")
        if not implementation_id or len(implementation_id) > 200:
            raise ValueError("Web Worker implementation ID is invalid")
        if len(implementation_digest) != 64 or any(
            item not in "0123456789abcdef" for item in implementation_digest
        ):
            raise ValueError("Web Worker implementation digest must be lowercase SHA-256")
        if type(headless) is not bool:
            raise TypeError("Web Worker headless setting must be a literal boolean")
        canonical_contexts = tuple(
            HostLoopbackWebDeploymentContext.model_validate(
                item.model_dump(mode="json", by_alias=True)
            )
            for item in contexts
        )
        indexed = {item.account_receipt_digest: item for item in canonical_contexts}
        if not indexed or len(indexed) != len(contexts):
            raise ValueError("Web Worker deployment contexts must be non-empty and unique")
        self.backend = backend
        self.output_root_reference = output_root_reference
        self.contexts = indexed
        self.implementation_id = implementation_id
        self.implementation_digest = implementation_digest
        self.headless = headless

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "implementationVersion": "pajin.web.host-loopback-job-compiler/v1",
            "adapterImplementationId": self.implementation_id,
            "adapterImplementationDigest": self.implementation_digest,
            "outputRootReference": self.output_root_reference,
            "headless": self.headless,
            "deploymentContextDigests": sorted(self.contexts),
            "workerBackend": self.backend.stable_execution_context(),
        }

    def compile_job(
        self,
        *,
        request: ToolRequest,
        adapter: WebAssessmentAdapterManifest,
        account_receipt: ProvisionedWebAccountReceipt,
        dispatch: WebAssessmentDispatchBinding,
    ) -> WorkerJob:
        try:
            context = self.contexts[account_receipt.receipt_digest].model_copy(deep=True)
        except KeyError as exc:
            raise ValueError("Web account receipt has no deployment Worker context") from exc
        if (
            request.request_id != dispatch.request_id
            or request.target != adapter.origin
            or adapter.origin != context.plan.origin
            or adapter.implementation_id != context.plan.adapter_implementation_id
            or adapter.recipe_digest != context.plan.plan_digest
            or adapter != context.adapter
            or adapter.implementation_id != self.implementation_id
            or adapter.implementation_digest != self.implementation_digest
            or adapter.reference() != dispatch.adapter
            or account_receipt.reference() != dispatch.account_receipt
            or account_receipt.receipt_digest != context.account_receipt_digest
            or account_receipt.authorization_ids
            != tuple(
                sorted(
                    (
                        context.source_authorization.authorization_id,
                        context.validation_authorization.authorization_id,
                    )
                )
            )
            or dispatch.output_root_reference != self.output_root_reference
        ):
            raise ValueError("Web Worker deployment context differs from signed dispatch material")
        role = (
            WebWorkerRole.SOURCE_EXECUTOR
            if dispatch.role == "source"
            else WebWorkerRole.VALIDATION_EXECUTOR
        )
        authorization, account = (
            (context.source_authorization, context.source_account)
            if role is WebWorkerRole.SOURCE_EXECUTOR
            else (context.validation_authorization, context.validation_account)
        )
        fingerprint_evidence = account.target_fingerprint_evidence(context.plan)
        target_digest = web_target_fingerprint_digest(
            origin=context.plan.origin,
            product=context.plan.target_product,
            version=account.target_version,
            fingerprint_endpoint=context.plan.fingerprint_endpoint,
            response_sha256=fingerprint_evidence.response_sha256,
            adapter_implementation_digest=adapter.implementation_digest,
            recipe_digest=adapter.recipe_digest,
        )
        if account_receipt.target_identity_digest != target_digest:
            raise ValueError("signed account receipt Target identity differs from deployment")
        if (
            account_receipt.target_fingerprint_response_sha256
            != fingerprint_evidence.response_sha256
        ):
            raise ValueError("signed account receipt fingerprint response differs from deployment")
        authority_raw = _authority_from_dispatch(
            dispatch,
            adapter=adapter,
            target_product=context.plan.target_product,
            target_version=account.target_version,
            target_fingerprint_endpoint=context.plan.fingerprint_endpoint,
            target_response_sha256=fingerprint_evidence.response_sha256,
            target_fingerprint_digest=target_digest,
        )
        authority = WebWorkerAuthorityBinding.model_validate(
            authority_raw.model_dump(mode="json", by_alias=True)
        )
        spec = WebWorkerJobSpec(
            role=role,
            executionId=dispatch.worker_execution_id,
            expectedRunId=dispatch.expected_run_id,
            observerExecutionId=dispatch.target_observer_execution_id,
            authority=authority,
            adapterImplementation=adapter.implementation_id,
            plan=context.plan,
            authorization=authorization,
            provisionedAccount=account,
            signingKeyId=self.backend.trust_registry.active_key(role).key_id,
            observerSigningKeyId=self.backend.trust_registry.active_key(
                self.backend.paired_observer_role(role)
            ).key_id,
            requestUnitCeiling=100,
            targetIdentity=None,
            headless=self.headless,
        )
        job = WorkerJob(
            execution_id=dispatch.worker_execution_id,
            image=WEB_HOST_WORKER_IMAGE,
            command=list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
            stdin=web_worker_job_stdin(spec),
            network=NetworkMode.NONE,
            limits=WorkerLimits(
                timeout_seconds=min(3_600, context.plan.duration_seconds + 120),
                memory_mb=1_024,
                cpus=2,
                pids=128,
                workspace_mb=512,
                stdout_bytes=_MAX_PROCESS_OUTPUT_BYTES,
                stderr_bytes=_MAX_PROCESS_STDERR_BYTES,
            ),
            secret_requests=[
                WorkerSecretRequest(
                    secret_ref=account_receipt.identity_material_ref,
                    binding=WEB_ACCOUNT_NAME_BINDING,
                    ttl_seconds=300,
                ),
                WorkerSecretRequest(
                    secret_ref=account_receipt.proof_material_ref,
                    binding=WEB_ACCOUNT_PROOF_BINDING,
                    ttl_seconds=300,
                ),
                WorkerSecretRequest(
                    secret_ref=dispatch.target_observer_signing_material_ref,
                    binding=WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
                    ttl_seconds=300,
                ),
                WorkerSecretRequest(
                    secret_ref=dispatch.worker_signing_material_ref,
                    binding=WEB_WORKER_SIGNING_KEY_BINDING,
                    ttl_seconds=300,
                ),
            ],
        )
        self.backend.register_trusted_dispatch(authority)
        return job


class HostLoopbackWebAssessmentOutputVerifier:
    """Verify the signed process pair and sealed WEB Run before Tool projection."""

    def __init__(
        self,
        *,
        output_root: Path,
        output_root_reference: str,
        trust_registry: WebWorkerTrustRegistry,
        contexts: tuple[HostLoopbackWebDeploymentContext, ...],
    ) -> None:
        canonical_contexts = tuple(
            HostLoopbackWebDeploymentContext.model_validate(
                item.model_dump(mode="json", by_alias=True)
            )
            for item in contexts
        )
        indexed = {item.account_receipt_digest: item for item in canonical_contexts}
        if not indexed or len(indexed) != len(contexts):
            raise ValueError("Web output verifier contexts must be non-empty and unique")
        pinned_output_root = pinned_workspace_relative_path(
            output_root,
            label="Web output verifier root",
        )
        self.output_root = (
            pinned_output_root if pinned_output_root is not None else output_root.resolve()
        )
        self.output_root_reference = output_root_reference
        self.trust_registry = trust_registry.model_copy(deep=True)
        self.contexts = indexed

    def stable_execution_context(self) -> Mapping[str, object]:
        return {
            "implementationVersion": "pajin.web.host-loopback-output-verifier/v1",
            "outputRootReference": self.output_root_reference,
            "trustRegistryDigest": self.trust_registry.digest,
            "deploymentContextDigests": sorted(self.contexts),
            "sealedRunVerification": True,
            "hostSubprocessIsolationOnly": True,
            "containerIsolation": False,
        }

    def verify_output(
        self,
        *,
        request: ToolRequest,
        dispatch: WebAssessmentDispatchBinding,
        worker_result: WorkerResult,
    ) -> WebAuthenticatedAssessmentWorkerOutput:
        if (
            worker_result.status is not WorkerStatus.SUCCEEDED
            or worker_result.backend != WEB_WORKER_BACKEND_NAME
            or worker_result.execution_id != dispatch.worker_execution_id
            or request.request_id != dispatch.request_id
            or dispatch.output_root_reference != self.output_root_reference
        ):
            raise ValueError("Web Worker host result differs from signed dispatch")
        try:
            context = self.contexts[dispatch.account_receipt.receipt_digest]
        except KeyError as exc:
            raise ValueError("Web Worker output has no deployment context") from exc
        if (
            context.adapter.reference() != dispatch.adapter
            or context.adapter.origin != context.plan.origin
            or context.adapter.implementation_id != context.plan.adapter_implementation_id
            or context.adapter.recipe_digest != context.plan.plan_digest
        ):
            raise ValueError("Web Worker output adapter differs from its deployment context")
        account = (
            context.source_account if dispatch.role == "source" else context.validation_account
        )
        fingerprint_evidence = account.target_fingerprint_evidence(context.plan)
        target_digest = web_target_fingerprint_digest(
            origin=context.plan.origin,
            product=context.plan.target_product,
            version=account.target_version,
            fingerprint_endpoint=context.plan.fingerprint_endpoint,
            response_sha256=fingerprint_evidence.response_sha256,
            adapter_implementation_digest=context.adapter.implementation_digest,
            recipe_digest=context.adapter.recipe_digest,
        )
        expected_raw = _authority_from_dispatch(
            dispatch,
            adapter=context.adapter,
            target_product=context.plan.target_product,
            target_version=account.target_version,
            target_fingerprint_endpoint=context.plan.fingerprint_endpoint,
            target_response_sha256=fingerprint_evidence.response_sha256,
            target_fingerprint_digest=target_digest,
        )
        expected = WebWorkerAuthorityBinding.model_validate(
            expected_raw.model_dump(mode="json", by_alias=True)
        )
        decoded = parse_strict_json_bytes(
            worker_result.stdout.encode("utf-8"),
            label="signed Web Worker action evidence",
            max_bytes=_MAX_PROCESS_OUTPUT_BYTES,
            max_depth=64,
            max_nodes=100_000,
        )
        evidence = SignedWebWorkerActionEvidence.model_validate(decoded)
        verification_time = datetime.now(UTC)
        target = verify_signed_web_target_identity(
            evidence.target_identity,
            self.trust_registry,
            expected_authority=expected,
            expected_execution_id=dispatch.target_observer_execution_id,
            verification_time=verification_time,
        )
        execution = verify_signed_web_execution_attestation(
            evidence.execution_attestation,
            self.trust_registry,
            expected_authority=expected,
            expected_execution_id=dispatch.worker_execution_id,
            expected_target_identity_digest=target.digest,
            verification_time=verification_time,
        )
        expected_roles = (
            (WebWorkerRole.SOURCE_TARGET_OBSERVER, WebWorkerRole.SOURCE_EXECUTOR)
            if dispatch.role == "source"
            else (
                WebWorkerRole.VALIDATION_TARGET_OBSERVER,
                WebWorkerRole.VALIDATION_EXECUTOR,
            )
        )
        if (target.statement.role, execution.statement.role) != expected_roles:
            raise ValueError("Web Worker process roles differ from the dispatch role")
        verified = load_verified_local_web_assessment_source_integrity(
            self.output_root / context.plan.name / execution.statement.run_id,
            expected_run_id=execution.statement.run_id,
            expected_root_digest=execution.statement.run_root_digest,
        )
        expected_authorization = (
            context.source_authorization
            if dispatch.role == "source"
            else context.validation_authorization
        )
        if (
            verified.plan != context.plan
            or verified.authorization != expected_authorization
            or verified.result.result_digest != execution.statement.result_digest
            or not verified.result.browser.authenticated
            or not verified.result.browser.browser_closed
            or verified.result.credentials_persisted
        ):
            raise ValueError("signed Web Worker output differs from the sealed assessment Run")
        worker_attestation = evidence.model_dump(mode="json", by_alias=True)
        return WebAuthenticatedAssessmentWorkerOutput(
            adapter=dispatch.adapter,
            accountReceipt=dispatch.account_receipt,
            dispatchBindingDigest=dispatch.binding_digest,
            workerExecutionId=dispatch.worker_execution_id,
            origin=context.plan.origin,
            runId=execution.statement.run_id,
            rootDigest=execution.statement.run_root_digest,
            resultDigest=execution.statement.result_digest,
            attestationDigest=evidence.digest,
            workerAttestation=worker_attestation,
            authenticated=True,
            browserClosed=True,
            targetMutated=False,
            serverSessionMaterialPersisted=False,
        )


def web_worker_job_stdin(spec: WebWorkerJobSpec) -> str:
    """Serialize only the non-secret portion accepted by Tool.prepare()."""

    return canonical_web_worker_json(spec.model_dump(mode="json", by_alias=True)).decode("utf-8")


def web_worker_backend_protocol(backend: HostLoopbackBrowserWorkerBackend) -> WorkerBackend:
    """Statically assert that the specialized backend satisfies the shared protocol."""

    return backend
