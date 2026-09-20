"""Structured, zero-target-I/O backend contract for specialist v2 dispatch.

This module is an execution-boundary conformance slice.  It deliberately stops
before any browser, socket, subprocess, container, or target operation.  The
pre-attempt job template contains no attempt or dispatch-verification reference;
the later launch envelope binds those digests without embedding either artifact.
The fake backend is one-shot and returns only a deployment-key-signed structured
statement that explicitly denies target I/O and every promotion authority.
"""

from __future__ import annotations

import base64
import binascii
import threading
from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import (
    Annotated,
    Final,
    Literal,
    Never,
    Protocol,
    Self,
    cast,
    final,
    runtime_checkable,
)

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.models import AgenticStrictModel, Identifier, Sha256, _literal_false
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest

SPECIALIST_BACKEND_JOB_TEMPLATE_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-backend-job-template/v1alpha1"
)
SPECIALIST_EXECUTION_INVENTORY_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-execution-inventory/v1alpha1"
)
SPECIALIST_BACKEND_LAUNCH_ENVELOPE_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-backend-launch-envelope/v1alpha1"
)
SPECIALIST_BACKEND_RESULT_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-backend-result/v1alpha1"
)
SIGNED_SPECIALIST_BACKEND_RESULT_API_VERSION: Final = (
    "pajin.dev/signed-agentic-specialist-backend-result/v1alpha1"
)
SPECIALIST_BACKEND_VERIFICATION_KEY_API_VERSION: Final = (
    "pajin.dev/agentic-specialist-backend-verification-key/v1alpha1"
)

SPECIALIST_GATEWAY_ID: Final = "pajin.gateway.agentic-specialist"
SPECIALIST_GATEWAY_VERSION: Final = "2.0.0"
STRUCTURED_FAKE_SPECIALIST_BACKEND_ID: Final = (
    "pajin.worker-backend.agentic-specialist.structured-fake"
)
STRUCTURED_FAKE_SPECIALIST_BACKEND_VERSION: Final = "2.0.0"
SPECIALIST_BACKEND_VERIFIER_ID: Final = "pajin.worker-verifier.agentic-specialist"
SPECIALIST_BACKEND_VERIFIER_VERSION: Final = "2.0.0"
SPECIALIST_BACKEND_COMPILER_ID: Final = "pajin.worker-compiler.agentic-specialist"
SPECIALIST_BACKEND_COMPILER_VERSION: Final = "2.0.0"
STRUCTURED_FAKE_SPECIALIST_IMAGE: Final = "pajin-specialist-structured-fake:no-target-io-v2"
STRUCTURED_FAKE_SPECIALIST_COMMAND: Final = ("specialist-structured-fake-no-target-io",)
CONFORMANCE_COMPLETED_NO_TARGET_IO: Final = "conformance-completed-no-target-io"

_TEMPLATE_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-backend-job-template/v2"
_COMMAND_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-worker-command/v2"
_INVENTORY_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-execution-inventory/v2"
_LAUNCH_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-backend-launch/v2"
_KEY_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-backend-verification-key/v2"
_SIGNED_RESULT_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-backend-signed-result/v2"
_SIGNATURE_DOMAIN: Final = b"pajin.agentic.specialist-backend-result/v2\0"
_IDEMPOTENCY_KEY_DOMAIN: Final = "pajin.agentic.specialist-backend-idempotency-key/v1"
_GATEWAY_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-gateway/v2"
_BACKEND_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-worker-backend/v2"
_VERIFIER_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-worker-verifier/v2"
_COMPILER_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-worker-compiler/v2"
_FAKE_IMAGE_DIGEST_DOMAIN: Final = "pajin.agentic.specialist-structured-fake-image/v2"
_MAX_CANONICAL_BYTES: Final = 256 * 1024
_BASE64URL_PUBLIC_KEY_PATTERN: Final = r"^[A-Za-z0-9_-]{43}$"
_BASE64URL_SIGNATURE_PATTERN: Final = r"^[A-Za-z0-9_-]{86}$"
_VERSION_PATTERN: Final = r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$"
_IDEMPOTENCY_KEY_PATTERN: Final = r"^specialist-job:[a-f0-9]{64}$"

CommandPart = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")]


class SpecialistBackendV2ContractError(ValueError):
    """Raised when the v2 backend boundary differs from its sealed contract."""


def _loaded_contract_source_digest() -> str:
    """Pin the exact source bytes that defined this in-process contract."""

    try:
        source = Path(__file__).read_bytes()
    except OSError as exc:
        raise SpecialistBackendV2ContractError(
            "specialist backend contract source cannot be content-addressed"
        ) from exc
    return sha256(source).hexdigest()


_CONTRACT_IMPLEMENTATION_DIGEST: Final = _loaded_contract_source_digest()


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, size: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != size or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {size} bytes")
    return decoded


def _utc(value: datetime, *, label: str) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    normalized = value.astimezone(UTC)
    offset = normalized.utcoffset()
    if offset is None or offset.total_seconds() != 0:
        raise ValueError(f"{label} must normalize to UTC")
    return normalized


def _format_timestamp(value: datetime, *, label: str) -> str:
    return _utc(value, label=label).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _require_literal_true(value: object, *, label: str) -> object:
    if type(value) is not bool or value is not True:
        raise ValueError(f"{label} must be literal true")
    return value


def _require_unmodified_model_state(value: object, *, label: str) -> None:
    """Reject fields injected through Pydantic's non-validating copy API."""

    active: set[int] = set()

    def visit(item: object, *, depth: int) -> None:
        if depth > 32:
            raise SpecialistBackendV2ContractError(f"{label} nesting is too deep")
        if isinstance(item, BaseModel):
            identity = id(item)
            if identity in active:
                raise SpecialistBackendV2ContractError(f"{label} contains a cycle")
            active.add(identity)
            try:
                expected = set(type(item).model_fields)
                if set(vars(item)) != expected or item.__pydantic_extra__:
                    raise SpecialistBackendV2ContractError(f"{label} contains hidden model state")
                for nested in vars(item).values():
                    visit(nested, depth=depth + 1)
            finally:
                active.remove(identity)
        elif type(item) in {tuple, list}:
            for nested in cast(tuple[object, ...] | list[object], item):
                visit(nested, depth=depth + 1)
        elif type(item) is dict:
            for nested in cast(dict[object, object], item).values():
                visit(nested, depth=depth + 1)

    visit(value, depth=0)


def _strict_reload[ModelT: BaseModel](
    value: ModelT,
    *,
    expected_type: type[ModelT],
    label: str,
) -> ModelT:
    if type(value) is not expected_type:
        raise SpecialistBackendV2ContractError(f"{label} requires its exact type")
    _require_unmodified_model_state(value, label=label)
    try:
        wire = value.model_dump(mode="json", by_alias=True)
        canonical = expected_type.model_validate(wire)
    except (AttributeError, TypeError, ValueError) as exc:
        raise SpecialistBackendV2ContractError(f"{label} failed strict reload") from exc
    if canonical != value or canonical.model_dump(mode="json", by_alias=True) != wire:
        raise SpecialistBackendV2ContractError(f"{label} differs after strict reload")
    return canonical


def _normalized_field_name(value: object) -> str:
    if type(value) is not str:
        return ""
    return value.replace("_", "").replace("-", "").casefold()


def _reject_reference_fields(
    value: object,
    *,
    forbidden: frozenset[str],
    label: str,
) -> None:
    active: set[int] = set()

    def visit(item: object, *, depth: int) -> None:
        if depth > 32:
            raise ValueError(f"{label} nesting is too deep")
        if isinstance(item, BaseModel):
            item = item.model_dump(mode="python", by_alias=True)
        if type(item) is dict:
            identity = id(item)
            if identity in active:
                raise ValueError(f"{label} cannot contain cycles")
            active.add(identity)
            try:
                for key, nested in cast(dict[object, object], item).items():
                    if _normalized_field_name(key) in forbidden:
                        raise ValueError(f"{label} contains a forbidden runtime reference")
                    visit(nested, depth=depth + 1)
            finally:
                active.remove(identity)
        elif type(item) in {list, tuple}:
            for nested in cast(list[object] | tuple[object, ...], item):
                visit(nested, depth=depth + 1)

    visit(value, depth=0)


class SpecialistBackendVerificationKeyV2(AgenticStrictModel):
    """Deployment-owned public key accepted by the v2 result verifier."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-backend-verification-key/v1alpha1"] = Field(
        default=SPECIALIST_BACKEND_VERIFICATION_KEY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistBackendVerificationKey"] = (
        "AgenticSpecialistBackendVerificationKey"
    )
    key_id: Identifier = Field(alias="keyId")
    key_digest: str = Field(default="", alias="keyDigest", max_length=64)
    trust_domain: Identifier = Field(alias="trustDomain")
    issuer: str = Field(min_length=1, max_length=200)
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=_BASE64URL_PUBLIC_KEY_PATTERN,
    )
    deployment_owned: Literal[True] = Field(default=True, alias="deploymentOwned")

    @field_validator("issuer")
    @classmethod
    def require_canonical_issuer(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("specialist backend key issuer is not canonical text")
        return value

    @field_validator("deployment_owned", mode="before")
    @classmethod
    def require_deployment_owned(cls, value: object) -> object:
        return _require_literal_true(value, label="deploymentOwned")

    @model_validator(mode="after")
    def bind_key(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            size=32,
            label="specialist backend public key",
        )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"key_digest"},
        )
        digest = discovery_digest(_KEY_DIGEST_DOMAIN, material)
        if self.key_digest and self.key_digest != digest:
            raise ValueError("specialist backend verification-key Digest differs")
        object.__setattr__(self, "key_digest", digest)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist backend verification key",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return self


class SpecialistBackendJobTemplateV2(AgenticStrictModel):
    """Pre-attempt job template with no attempt or dispatch-verification reference."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-backend-job-template/v1alpha1"] = Field(
        default=SPECIALIST_BACKEND_JOB_TEMPLATE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistBackendJobTemplate"] = "AgenticSpecialistBackendJobTemplate"
    template_id: str = Field(default="", alias="templateId", max_length=120)
    template_digest: str = Field(default="", alias="templateDigest", max_length=64)
    worker_image_reference: Identifier = Field(alias="workerImageReference")
    worker_image_digest: Sha256 = Field(alias="workerImageDigest")
    worker_command: tuple[CommandPart, ...] = Field(
        alias="workerCommand",
        min_length=1,
        max_length=8,
    )
    worker_command_digest: str = Field(
        default="",
        alias="workerCommandDigest",
        max_length=64,
    )
    network_mode: Literal["none"] = Field(default="none", alias="networkMode")
    secret_material_allowed: Literal[False] = Field(
        default=False,
        alias="secretMaterialAllowed",
    )
    target_io_allowed: Literal[False] = Field(default=False, alias="targetIOAllowed")
    attempt_binding_allowed: Literal[False] = Field(
        default=False,
        alias="attemptBindingAllowed",
    )
    dispatch_verification_binding_allowed: Literal[False] = Field(
        default=False,
        alias="dispatchVerificationBindingAllowed",
    )

    @model_validator(mode="before")
    @classmethod
    def reject_post_claim_references(cls, value: object) -> object:
        _reject_reference_fields(
            value,
            forbidden=frozenset(
                {
                    "attempt",
                    "attemptid",
                    "attemptref",
                    "attemptdigest",
                    "dispatchverification",
                    "dispatchverificationid",
                    "dispatchverificationref",
                    "dispatchverificationdigest",
                    "launchenvelope",
                    "launchenveloperef",
                }
            ),
            label="specialist backend job template",
        )
        return value

    @field_validator(
        "secret_material_allowed",
        "target_io_allowed",
        "attempt_binding_allowed",
        "dispatch_verification_binding_allowed",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_template(self) -> Self:
        if len(set(self.worker_command)) != len(self.worker_command):
            raise ValueError("specialist backend command contains repeated arguments")
        command_digest = discovery_digest(
            _COMMAND_DIGEST_DOMAIN,
            list(self.worker_command),
        )
        if self.worker_command_digest and self.worker_command_digest != command_digest:
            raise ValueError("specialist backend command Digest differs")
        object.__setattr__(self, "worker_command_digest", command_digest)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"template_id", "template_digest"},
        )
        digest = discovery_digest(_TEMPLATE_DIGEST_DOMAIN, material)
        expected_id = f"agentic-specialist-job-template_{digest}"
        if self.template_digest and self.template_digest != digest:
            raise ValueError("specialist backend job-template Digest differs")
        if self.template_id and self.template_id != expected_id:
            raise ValueError("specialist backend job-template ID differs")
        object.__setattr__(self, "template_digest", digest)
        object.__setattr__(self, "template_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist backend job template",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return self


class SpecialistExecutionInventoryV2(AgenticStrictModel):
    """Content-addressed pins for the exact zero-I/O execution deployment."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-execution-inventory/v1alpha1"] = Field(
        default=SPECIALIST_EXECUTION_INVENTORY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistExecutionInventory"] = "AgenticSpecialistExecutionInventory"
    inventory_id: str = Field(default="", alias="inventoryId", max_length=120)
    inventory_digest: str = Field(default="", alias="inventoryDigest", max_length=64)
    contract_implementation_digest: Sha256 = Field(alias="contractImplementationDigest")
    gateway_id: Identifier = Field(alias="gatewayId")
    gateway_version: str = Field(alias="gatewayVersion", pattern=_VERSION_PATTERN)
    gateway_digest: Sha256 = Field(alias="gatewayDigest")
    worker_backend_id: Identifier = Field(alias="workerBackendId")
    worker_backend_version: str = Field(
        alias="workerBackendVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_backend_digest: Sha256 = Field(alias="workerBackendDigest")
    job_template_id: str = Field(alias="jobTemplateId", min_length=1, max_length=120)
    job_template_digest: Sha256 = Field(alias="jobTemplateDigest")
    worker_image_reference: Identifier = Field(alias="workerImageReference")
    worker_image_digest: Sha256 = Field(alias="workerImageDigest")
    worker_command_digest: Sha256 = Field(alias="workerCommandDigest")
    worker_compiler_id: Identifier = Field(alias="workerCompilerId")
    worker_compiler_version: str = Field(
        alias="workerCompilerVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_compiler_digest: Sha256 = Field(alias="workerCompilerDigest")
    worker_verifier_id: Identifier = Field(alias="workerVerifierId")
    worker_verifier_version: str = Field(
        alias="workerVerifierVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_verifier_digest: Sha256 = Field(alias="workerVerifierDigest")
    verification_key_id: Identifier = Field(alias="verificationKeyId")
    verification_key_digest: Sha256 = Field(alias="verificationKeyDigest")
    network_mode: Literal["none"] = Field(default="none", alias="networkMode")
    one_call_backend: Literal[True] = Field(default=True, alias="oneCallBackend")
    structured_result_required: Literal[True] = Field(
        default=True,
        alias="structuredResultRequired",
    )
    target_io_allowed: Literal[False] = Field(default=False, alias="targetIOAllowed")
    production_authority_eligible: Literal[False] = Field(
        default=False,
        alias="productionAuthorityEligible",
    )

    @field_validator("one_call_backend", "structured_result_required", mode="before")
    @classmethod
    def require_true_markers(cls, value: object, info: ValidationInfo) -> object:
        return _require_literal_true(value, label=cast(str, info.field_name))

    @field_validator("target_io_allowed", "production_authority_eligible", mode="before")
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def bind_inventory(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"inventory_id", "inventory_digest"},
        )
        digest = discovery_digest(_INVENTORY_DIGEST_DOMAIN, material)
        expected_id = f"agentic-specialist-execution-inventory_{digest}"
        if self.inventory_digest and self.inventory_digest != digest:
            raise ValueError("specialist execution-inventory Digest differs")
        if self.inventory_id and self.inventory_id != expected_id:
            raise ValueError("specialist execution-inventory ID differs")
        object.__setattr__(self, "inventory_digest", digest)
        object.__setattr__(self, "inventory_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist execution inventory",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return self


class SpecialistBackendLaunchEnvelopeV2(AgenticStrictModel):
    """Post-verification handoff that contains digests, never authority artifacts."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-backend-launch-envelope/v1alpha1"] = Field(
        default=SPECIALIST_BACKEND_LAUNCH_ENVELOPE_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticSpecialistBackendLaunchEnvelope"] = (
        "AgenticSpecialistBackendLaunchEnvelope"
    )
    envelope_id: str = Field(default="", alias="envelopeId", max_length=120)
    envelope_digest: str = Field(default="", alias="envelopeDigest", max_length=64)
    attempt_digest: Sha256 = Field(alias="attemptDigest")
    dispatch_verification_digest: Sha256 = Field(alias="dispatchVerificationDigest")
    job_template_id: str = Field(alias="jobTemplateId", min_length=1, max_length=120)
    job_template_digest: Sha256 = Field(alias="jobTemplateDigest")
    runtime_inventory_id: str = Field(
        alias="runtimeInventoryId",
        min_length=1,
        max_length=120,
    )
    runtime_inventory_digest: Sha256 = Field(alias="runtimeInventoryDigest")
    backend_handoff_deadline: datetime = Field(alias="backendHandoffDeadline")
    idempotency_key: str = Field(
        default="",
        alias="idempotencyKey",
        max_length=96,
        pattern=_IDEMPOTENCY_KEY_PATTERN,
    )

    @model_validator(mode="before")
    @classmethod
    def reject_nested_authority_refs(cls, value: object) -> object:
        _reject_reference_fields(
            value,
            forbidden=frozenset(
                {
                    "attempt",
                    "attemptref",
                    "dispatchverification",
                    "dispatchverificationref",
                }
            ),
            label="specialist backend launch envelope",
        )
        return value

    @field_validator("backend_handoff_deadline")
    @classmethod
    def require_utc_deadline(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist backend handoff deadline")

    @model_validator(mode="after")
    def bind_envelope(self) -> Self:
        expected_key = _specialist_backend_idempotency_key(
            attempt_digest=self.attempt_digest,
            dispatch_verification_digest=self.dispatch_verification_digest,
            job_template_digest=self.job_template_digest,
            runtime_inventory_digest=self.runtime_inventory_digest,
        )
        if self.idempotency_key and self.idempotency_key != expected_key:
            raise ValueError("specialist backend idempotency key differs")
        object.__setattr__(self, "idempotency_key", expected_key)
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"envelope_id", "envelope_digest"},
        )
        digest = discovery_digest(_LAUNCH_DIGEST_DOMAIN, material)
        expected_id = f"agentic-specialist-backend-launch_{digest}"
        if self.envelope_digest and self.envelope_digest != digest:
            raise ValueError("specialist backend launch-envelope Digest differs")
        if self.envelope_id and self.envelope_id != expected_id:
            raise ValueError("specialist backend launch-envelope ID differs")
        object.__setattr__(self, "envelope_digest", digest)
        object.__setattr__(self, "envelope_id", expected_id)
        canonical_json_bytes(
            self.model_dump(mode="json", by_alias=True),
            label="specialist backend launch envelope",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        return self


class SpecialistBackendResultStatementV2(AgenticStrictModel):
    """Signed terminal statement for one successful zero-I/O conformance call."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-specialist-backend-result/v1alpha1"] = Field(
        default=SPECIALIST_BACKEND_RESULT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AgenticSpecialistBackendResult"] = "AgenticSpecialistBackendResult"
    predicate_type: Literal["pajin.dev/specialist-backend-conformance-no-target-io/v1"] = Field(
        default="pajin.dev/specialist-backend-conformance-no-target-io/v1",
        alias="predicateType",
    )
    trust_domain: Identifier = Field(alias="trustDomain")
    issuer: str = Field(min_length=1, max_length=200)
    contract_implementation_digest: Sha256 = Field(alias="contractImplementationDigest")
    worker_backend_id: Identifier = Field(alias="workerBackendId")
    worker_backend_version: str = Field(
        alias="workerBackendVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_backend_digest: Sha256 = Field(alias="workerBackendDigest")
    launch_envelope_id: str = Field(
        alias="launchEnvelopeId",
        min_length=1,
        max_length=120,
    )
    launch_envelope_digest: Sha256 = Field(alias="launchEnvelopeDigest")
    attempt_digest: Sha256 = Field(alias="attemptDigest")
    dispatch_verification_digest: Sha256 = Field(alias="dispatchVerificationDigest")
    job_template_id: str = Field(alias="jobTemplateId", min_length=1, max_length=120)
    job_template_digest: Sha256 = Field(alias="jobTemplateDigest")
    runtime_inventory_id: str = Field(
        alias="runtimeInventoryId",
        min_length=1,
        max_length=120,
    )
    runtime_inventory_digest: Sha256 = Field(alias="runtimeInventoryDigest")
    worker_image_reference: Identifier = Field(alias="workerImageReference")
    worker_image_digest: Sha256 = Field(alias="workerImageDigest")
    worker_command_digest: Sha256 = Field(alias="workerCommandDigest")
    worker_compiler_id: Identifier = Field(alias="workerCompilerId")
    worker_compiler_version: str = Field(
        alias="workerCompilerVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_compiler_digest: Sha256 = Field(alias="workerCompilerDigest")
    worker_verifier_id: Identifier = Field(alias="workerVerifierId")
    worker_verifier_version: str = Field(
        alias="workerVerifierVersion",
        pattern=_VERSION_PATTERN,
    )
    worker_verifier_digest: Sha256 = Field(alias="workerVerifierDigest")
    verification_key_id: Identifier = Field(alias="verificationKeyId")
    verification_key_digest: Sha256 = Field(alias="verificationKeyDigest")
    idempotency_key: str = Field(
        alias="idempotencyKey",
        pattern=_IDEMPOTENCY_KEY_PATTERN,
        max_length=96,
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    terminal_classification: Literal["conformance-completed-no-target-io"] = Field(
        default=CONFORMANCE_COMPLETED_NO_TARGET_IO,
        alias="terminalClassification",
    )
    backend_terminal_proven: Literal[True] = Field(
        default=True,
        alias="backendTerminalProven",
    )
    conformance_succeeded: Literal[True] = Field(
        default=True,
        alias="conformanceSucceeded",
    )
    network_mode: Literal["none"] = Field(default="none", alias="networkMode")
    backend_invoked: Literal[True] = Field(default=True, alias="backendInvoked")
    target_io_performed: Literal[False] = Field(default=False, alias="targetIOPerformed")
    secret_material_requested: Literal[False] = Field(
        default=False,
        alias="secretMaterialRequested",
    )
    production_authority_eligible: Literal[False] = Field(
        default=False,
        alias="productionAuthorityEligible",
    )
    gateway_authority: Literal[False] = Field(default=False, alias="gatewayAuthority")
    execution_authority: Literal[False] = Field(
        default=False,
        alias="executionAuthority",
    )
    independent_validation: Literal[False] = Field(
        default=False,
        alias="independentValidation",
    )
    finding: Literal[False] = False
    graph: Literal[False] = False
    report: Literal[False] = False
    sarif: Literal[False] = False
    poc: Literal[False] = False

    @field_validator("issuer")
    @classmethod
    def require_canonical_issuer(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("specialist backend result issuer is not canonical text")
        return value

    @field_validator("started_at", "finished_at")
    @classmethod
    def require_utc_times(cls, value: datetime) -> datetime:
        return _utc(value, label="specialist backend result timestamp")

    @field_validator(
        "backend_terminal_proven",
        "conformance_succeeded",
        "backend_invoked",
        mode="before",
    )
    @classmethod
    def require_true_markers(cls, value: object, info: ValidationInfo) -> object:
        return _require_literal_true(value, label=cast(str, info.field_name))

    @field_validator(
        "target_io_performed",
        "secret_material_requested",
        "production_authority_eligible",
        "gateway_authority",
        "execution_authority",
        "independent_validation",
        "finding",
        "graph",
        "report",
        "sarif",
        "poc",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @model_validator(mode="after")
    def validate_lifecycle(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("specialist backend result finished before it started")
        return self


class SignedSpecialistBackendResultV2(AgenticStrictModel):
    """Ed25519 envelope over one exact structured backend result."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/signed-agentic-specialist-backend-result/v1alpha1"] = Field(
        default=SIGNED_SPECIALIST_BACKEND_RESULT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["SignedAgenticSpecialistBackendResult"] = "SignedAgenticSpecialistBackendResult"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: Identifier = Field(alias="keyId")
    statement: SpecialistBackendResultStatementV2
    statement_sha256: Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=_BASE64URL_SIGNATURE_PATTERN,
    )

    @model_validator(mode="after")
    def bind_signed_result(self) -> Self:
        statement_bytes = canonical_json_bytes(
            self.statement.model_dump(mode="json", by_alias=True),
            label="specialist backend result statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.statement_sha256 != sha256(statement_bytes).hexdigest():
            raise ValueError("specialist backend result-statement Digest differs")
        _base64url_decode(
            self.signature_base64url,
            size=64,
            label="specialist backend result signature",
        )
        return self

    @property
    def result_digest(self) -> str:
        return discovery_digest(
            _SIGNED_RESULT_DIGEST_DOMAIN,
            self.model_dump(mode="json", by_alias=True),
        )


def specialist_backend_public_key_base64url_v2(private_key: bytes) -> str:
    """Derive the canonical raw Ed25519 public key used by deployment fixtures."""

    if type(private_key) is not bytes or len(private_key) != 32:
        raise ValueError("specialist backend private key must contain exactly 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def structured_fake_specialist_job_template_v2() -> SpecialistBackendJobTemplateV2:
    """Return the single code-owned, pre-attempt fake backend job template."""

    image_digest = discovery_digest(
        _FAKE_IMAGE_DIGEST_DOMAIN,
        {
            "imageReference": STRUCTURED_FAKE_SPECIALIST_IMAGE,
            "workerCommand": list(STRUCTURED_FAKE_SPECIALIST_COMMAND),
            "contractImplementationDigest": _CONTRACT_IMPLEMENTATION_DIGEST,
        },
    )
    return SpecialistBackendJobTemplateV2(
        workerImageReference=STRUCTURED_FAKE_SPECIALIST_IMAGE,
        workerImageDigest=image_digest,
        workerCommand=STRUCTURED_FAKE_SPECIALIST_COMMAND,
    )


def _gateway_context() -> dict[str, object]:
    return {
        "implementationVersion": "pajin.agentic.specialist-gateway/v2",
        "gatewayId": SPECIALIST_GATEWAY_ID,
        "gatewayVersion": SPECIALIST_GATEWAY_VERSION,
        "contractImplementationDigest": _CONTRACT_IMPLEMENTATION_DIGEST,
        "schedulerOwnedTaskRequired": True,
        "durablePreAwaitDispatchMarkerRequired": True,
        "callerSelectedTransportAllowed": False,
        "targetIOAllowedByThisInventory": False,
    }


def _backend_context(
    template: SpecialistBackendJobTemplateV2,
    key: SpecialistBackendVerificationKeyV2,
) -> dict[str, object]:
    return {
        "implementationVersion": "pajin.agentic.structured-fake-specialist-backend/v2",
        "backendId": STRUCTURED_FAKE_SPECIALIST_BACKEND_ID,
        "backendVersion": STRUCTURED_FAKE_SPECIALIST_BACKEND_VERSION,
        "contractImplementationDigest": _CONTRACT_IMPLEMENTATION_DIGEST,
        "jobTemplateId": template.template_id,
        "jobTemplateDigest": template.template_digest,
        "workerImageReference": template.worker_image_reference,
        "workerImageDigest": template.worker_image_digest,
        "workerCommandDigest": template.worker_command_digest,
        "verificationKeyId": key.key_id,
        "verificationKeyDigest": key.key_digest,
        "networkMode": "none",
        "oneCall": True,
        "targetIOAllowed": False,
        "productionAuthorityEligible": False,
    }


def _verifier_context(key: SpecialistBackendVerificationKeyV2) -> dict[str, object]:
    return {
        "implementationVersion": "pajin.agentic.specialist-backend-output-verifier/v2",
        "verifierId": SPECIALIST_BACKEND_VERIFIER_ID,
        "verifierVersion": SPECIALIST_BACKEND_VERIFIER_VERSION,
        "contractImplementationDigest": _CONTRACT_IMPLEMENTATION_DIGEST,
        "verificationKeyId": key.key_id,
        "verificationKeyDigest": key.key_digest,
        "trustDomain": key.trust_domain,
        "deploymentOwnedVerificationKey": True,
        "productionAuthorityEligible": False,
    }


def _compiler_context(template: SpecialistBackendJobTemplateV2) -> dict[str, object]:
    return {
        "implementationVersion": "pajin.agentic.specialist-backend-job-compiler/v2",
        "compilerId": SPECIALIST_BACKEND_COMPILER_ID,
        "compilerVersion": SPECIALIST_BACKEND_COMPILER_VERSION,
        "contractImplementationDigest": _CONTRACT_IMPLEMENTATION_DIGEST,
        "jobTemplateId": template.template_id,
        "jobTemplateDigest": template.template_digest,
        "workerImageReference": template.worker_image_reference,
        "workerImageDigest": template.worker_image_digest,
        "workerCommandDigest": template.worker_command_digest,
        "networkMode": "none",
        "targetIOAllowed": False,
    }


def specialist_execution_inventory_v2(
    *,
    job_template: SpecialistBackendJobTemplateV2,
    verification_key: SpecialistBackendVerificationKeyV2,
) -> SpecialistExecutionInventoryV2:
    """Build the only inventory admitted by the structured fake backend."""

    template = _strict_reload(
        job_template,
        expected_type=SpecialistBackendJobTemplateV2,
        label="specialist backend job template",
    )
    key = _strict_reload(
        verification_key,
        expected_type=SpecialistBackendVerificationKeyV2,
        label="specialist backend deployment verification key",
    )
    return SpecialistExecutionInventoryV2(
        contractImplementationDigest=_CONTRACT_IMPLEMENTATION_DIGEST,
        gatewayId=SPECIALIST_GATEWAY_ID,
        gatewayVersion=SPECIALIST_GATEWAY_VERSION,
        gatewayDigest=discovery_digest(_GATEWAY_DIGEST_DOMAIN, _gateway_context()),
        workerBackendId=STRUCTURED_FAKE_SPECIALIST_BACKEND_ID,
        workerBackendVersion=STRUCTURED_FAKE_SPECIALIST_BACKEND_VERSION,
        workerBackendDigest=discovery_digest(
            _BACKEND_DIGEST_DOMAIN,
            _backend_context(template, key),
        ),
        jobTemplateId=template.template_id,
        jobTemplateDigest=template.template_digest,
        workerImageReference=template.worker_image_reference,
        workerImageDigest=template.worker_image_digest,
        workerCommandDigest=template.worker_command_digest,
        workerCompilerId=SPECIALIST_BACKEND_COMPILER_ID,
        workerCompilerVersion=SPECIALIST_BACKEND_COMPILER_VERSION,
        workerCompilerDigest=discovery_digest(
            _COMPILER_DIGEST_DOMAIN,
            _compiler_context(template),
        ),
        workerVerifierId=SPECIALIST_BACKEND_VERIFIER_ID,
        workerVerifierVersion=SPECIALIST_BACKEND_VERIFIER_VERSION,
        workerVerifierDigest=discovery_digest(
            _VERIFIER_DIGEST_DOMAIN,
            _verifier_context(key),
        ),
        verificationKeyId=key.key_id,
        verificationKeyDigest=key.key_digest,
    )


def _require_inventory_material(
    *,
    inventory: SpecialistExecutionInventoryV2,
    template: SpecialistBackendJobTemplateV2,
    key: SpecialistBackendVerificationKeyV2,
) -> None:
    expected = specialist_execution_inventory_v2(
        job_template=template,
        verification_key=key,
    )
    if inventory != expected:
        raise SpecialistBackendV2ContractError("specialist backend deployment inventory differs")


def _specialist_backend_idempotency_key(
    *,
    attempt_digest: str,
    dispatch_verification_digest: str,
    job_template_digest: str,
    runtime_inventory_digest: str,
) -> str:
    digest = discovery_digest(
        _IDEMPOTENCY_KEY_DOMAIN,
        {
            "attemptDigest": attempt_digest,
            "dispatchVerificationDigest": dispatch_verification_digest,
            "jobTemplateDigest": job_template_digest,
            "runtimeInventoryDigest": runtime_inventory_digest,
        },
    )
    return f"specialist-job:{digest}"


def specialist_backend_launch_envelope_v2(
    *,
    attempt_digest: str,
    dispatch_verification_digest: str,
    job_template: SpecialistBackendJobTemplateV2,
    runtime_inventory: SpecialistExecutionInventoryV2,
    backend_handoff_deadline: datetime,
) -> SpecialistBackendLaunchEnvelopeV2:
    """Bind post-verification digests to one exact pre-attempt template."""

    template = _strict_reload(
        job_template,
        expected_type=SpecialistBackendJobTemplateV2,
        label="specialist backend job template",
    )
    inventory = _strict_reload(
        runtime_inventory,
        expected_type=SpecialistExecutionInventoryV2,
        label="specialist execution inventory",
    )
    if (
        inventory.job_template_id != template.template_id
        or inventory.job_template_digest != template.template_digest
        or inventory.worker_image_reference != template.worker_image_reference
        or inventory.worker_image_digest != template.worker_image_digest
        or inventory.worker_command_digest != template.worker_command_digest
    ):
        raise SpecialistBackendV2ContractError(
            "specialist launch template differs from execution inventory"
        )
    idempotency_key = _specialist_backend_idempotency_key(
        attempt_digest=attempt_digest,
        dispatch_verification_digest=dispatch_verification_digest,
        job_template_digest=template.template_digest,
        runtime_inventory_digest=inventory.inventory_digest,
    )
    return SpecialistBackendLaunchEnvelopeV2.model_validate(
        {
            "attemptDigest": attempt_digest,
            "dispatchVerificationDigest": dispatch_verification_digest,
            "jobTemplateId": template.template_id,
            "jobTemplateDigest": template.template_digest,
            "runtimeInventoryId": inventory.inventory_id,
            "runtimeInventoryDigest": inventory.inventory_digest,
            "backendHandoffDeadline": _format_timestamp(
                backend_handoff_deadline,
                label="specialist backend handoff deadline",
            ),
            "idempotencyKey": idempotency_key,
        }
    )


def _require_launch_material(
    *,
    envelope: SpecialistBackendLaunchEnvelopeV2,
    template: SpecialistBackendJobTemplateV2,
    inventory: SpecialistExecutionInventoryV2,
) -> None:
    if (
        envelope.job_template_id != template.template_id
        or envelope.job_template_digest != template.template_digest
        or envelope.runtime_inventory_id != inventory.inventory_id
        or envelope.runtime_inventory_digest != inventory.inventory_digest
        or inventory.job_template_id != template.template_id
        or inventory.job_template_digest != template.template_digest
        or inventory.worker_image_reference != template.worker_image_reference
        or inventory.worker_image_digest != template.worker_image_digest
        or inventory.worker_command_digest != template.worker_command_digest
    ):
        raise SpecialistBackendV2ContractError(
            "specialist backend launch material differs from deployment"
        )


@runtime_checkable
class SpecialistBackendV2(Protocol):
    """Exact typed boundary consumed later by the specialist-only Gateway."""

    def stable_execution_context(self) -> Mapping[str, object]:
        """Return canonical non-secret backend identity material."""

    async def run(
        self,
        envelope: SpecialistBackendLaunchEnvelopeV2,
    ) -> SignedSpecialistBackendResultV2:
        """Consume one post-verification launch envelope exactly once."""


@final
class StructuredFakeSpecialistBackendV2:
    """One-call backend that signs a result without any target or network I/O."""

    __slots__ = (
        "__consumed",
        "__inventory",
        "__key",
        "__lock",
        "__private_key",
        "__template",
    )

    def __init__(
        self,
        *,
        signing_private_key: bytes,
        deployment_verification_key: SpecialistBackendVerificationKeyV2,
        job_template: SpecialistBackendJobTemplateV2,
        execution_inventory: SpecialistExecutionInventoryV2,
    ) -> None:
        if type(signing_private_key) is not bytes or len(signing_private_key) != 32:
            raise ValueError("specialist backend private key must contain exactly 32 bytes")
        key = _strict_reload(
            deployment_verification_key,
            expected_type=SpecialistBackendVerificationKeyV2,
            label="specialist backend deployment verification key",
        )
        template = _strict_reload(
            job_template,
            expected_type=SpecialistBackendJobTemplateV2,
            label="specialist backend job template",
        )
        inventory = _strict_reload(
            execution_inventory,
            expected_type=SpecialistExecutionInventoryV2,
            label="specialist execution inventory",
        )
        if specialist_backend_public_key_base64url_v2(signing_private_key) != (
            key.public_key_base64url
        ):
            raise SpecialistBackendV2ContractError(
                "specialist backend signing key differs from deployment verification key"
            )
        _require_inventory_material(inventory=inventory, template=template, key=key)
        self.__private_key = Ed25519PrivateKey.from_private_bytes(signing_private_key)
        self.__key = key
        self.__template = template
        self.__inventory = inventory
        self.__lock = threading.Lock()
        self.__consumed = False

    @property
    def invocation_count(self) -> int:
        with self.__lock:
            return int(self.__consumed)

    def stable_execution_context(self) -> Mapping[str, object]:
        return _backend_context(self.__template, self.__key)

    async def run(
        self,
        envelope: SpecialistBackendLaunchEnvelopeV2,
    ) -> SignedSpecialistBackendResultV2:
        with self.__lock:
            if self.__consumed:
                raise SpecialistBackendV2ContractError(
                    "structured fake specialist backend is already consumed"
                )
            self.__consumed = True

        canonical_envelope = _strict_reload(
            envelope,
            expected_type=SpecialistBackendLaunchEnvelopeV2,
            label="specialist backend launch envelope",
        )
        _require_inventory_material(
            inventory=self.__inventory,
            template=self.__template,
            key=self.__key,
        )
        _require_launch_material(
            envelope=canonical_envelope,
            template=self.__template,
            inventory=self.__inventory,
        )
        started_at = datetime.now(UTC)
        if not started_at < canonical_envelope.backend_handoff_deadline:
            raise SpecialistBackendV2ContractError(
                "specialist backend handoff deadline expired before invocation"
            )
        finished_at = datetime.now(UTC)
        statement = SpecialistBackendResultStatementV2.model_validate(
            {
                "trustDomain": self.__key.trust_domain,
                "issuer": self.__key.issuer,
                "contractImplementationDigest": (self.__inventory.contract_implementation_digest),
                "workerBackendId": self.__inventory.worker_backend_id,
                "workerBackendVersion": self.__inventory.worker_backend_version,
                "workerBackendDigest": self.__inventory.worker_backend_digest,
                "launchEnvelopeId": canonical_envelope.envelope_id,
                "launchEnvelopeDigest": canonical_envelope.envelope_digest,
                "attemptDigest": canonical_envelope.attempt_digest,
                "dispatchVerificationDigest": (canonical_envelope.dispatch_verification_digest),
                "jobTemplateId": self.__template.template_id,
                "jobTemplateDigest": self.__template.template_digest,
                "runtimeInventoryId": self.__inventory.inventory_id,
                "runtimeInventoryDigest": self.__inventory.inventory_digest,
                "workerImageReference": self.__template.worker_image_reference,
                "workerImageDigest": self.__template.worker_image_digest,
                "workerCommandDigest": self.__template.worker_command_digest,
                "workerCompilerId": self.__inventory.worker_compiler_id,
                "workerCompilerVersion": self.__inventory.worker_compiler_version,
                "workerCompilerDigest": self.__inventory.worker_compiler_digest,
                "workerVerifierId": self.__inventory.worker_verifier_id,
                "workerVerifierVersion": self.__inventory.worker_verifier_version,
                "workerVerifierDigest": self.__inventory.worker_verifier_digest,
                "verificationKeyId": self.__key.key_id,
                "verificationKeyDigest": self.__key.key_digest,
                "idempotencyKey": canonical_envelope.idempotency_key,
                "startedAt": _format_timestamp(
                    started_at,
                    label="specialist backend result start",
                ),
                "finishedAt": _format_timestamp(
                    finished_at,
                    label="specialist backend result finish",
                ),
            }
        )
        statement_bytes = canonical_json_bytes(
            statement.model_dump(mode="json", by_alias=True),
            label="specialist backend result statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        signature = self.__private_key.sign(_SIGNATURE_DOMAIN + statement_bytes)
        return SignedSpecialistBackendResultV2(
            keyId=self.__key.key_id,
            statement=statement,
            statementSha256=sha256(statement_bytes).hexdigest(),
            signatureBase64url=_base64url_encode(signature),
        )

    def __copy__(self) -> Never:
        raise TypeError("structured fake specialist backend cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("structured fake specialist backend cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("structured fake specialist backend cannot be serialized")


@final
class SpecialistBackendOutputVerifierV2:
    """Verify results only against one deployment-pinned key and inventory."""

    __slots__ = ("__inventory", "__key", "__public_key", "__template")

    def __init__(
        self,
        *,
        deployment_verification_key: SpecialistBackendVerificationKeyV2,
        job_template: SpecialistBackendJobTemplateV2,
        execution_inventory: SpecialistExecutionInventoryV2,
    ) -> None:
        key = _strict_reload(
            deployment_verification_key,
            expected_type=SpecialistBackendVerificationKeyV2,
            label="specialist backend deployment verification key",
        )
        template = _strict_reload(
            job_template,
            expected_type=SpecialistBackendJobTemplateV2,
            label="specialist backend job template",
        )
        inventory = _strict_reload(
            execution_inventory,
            expected_type=SpecialistExecutionInventoryV2,
            label="specialist execution inventory",
        )
        _require_inventory_material(inventory=inventory, template=template, key=key)
        self.__key = key
        self.__template = template
        self.__inventory = inventory
        self.__public_key = Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                key.public_key_base64url,
                size=32,
                label="specialist backend public key",
            )
        )

    def stable_execution_context(self) -> Mapping[str, object]:
        return _verifier_context(self.__key)

    def verify_output(
        self,
        *,
        expected_envelope: SpecialistBackendLaunchEnvelopeV2,
        signed_result: SignedSpecialistBackendResultV2,
    ) -> SignedSpecialistBackendResultV2:
        envelope = _strict_reload(
            expected_envelope,
            expected_type=SpecialistBackendLaunchEnvelopeV2,
            label="specialist backend expected launch envelope",
        )
        result = _strict_reload(
            signed_result,
            expected_type=SignedSpecialistBackendResultV2,
            label="signed specialist backend result",
        )
        _require_inventory_material(
            inventory=self.__inventory,
            template=self.__template,
            key=self.__key,
        )
        _require_launch_material(
            envelope=envelope,
            template=self.__template,
            inventory=self.__inventory,
        )
        statement = result.statement
        if (
            result.key_id != self.__key.key_id
            or statement.trust_domain != self.__key.trust_domain
            or statement.issuer != self.__key.issuer
            or statement.contract_implementation_digest
            != self.__inventory.contract_implementation_digest
            or statement.worker_backend_id != self.__inventory.worker_backend_id
            or statement.worker_backend_version != self.__inventory.worker_backend_version
            or statement.worker_backend_digest != self.__inventory.worker_backend_digest
            or statement.launch_envelope_id != envelope.envelope_id
            or statement.launch_envelope_digest != envelope.envelope_digest
            or statement.attempt_digest != envelope.attempt_digest
            or statement.dispatch_verification_digest != envelope.dispatch_verification_digest
            or statement.job_template_id != self.__template.template_id
            or statement.job_template_digest != self.__template.template_digest
            or statement.runtime_inventory_id != self.__inventory.inventory_id
            or statement.runtime_inventory_digest != self.__inventory.inventory_digest
            or statement.worker_image_reference != self.__template.worker_image_reference
            or statement.worker_image_digest != self.__template.worker_image_digest
            or statement.worker_command_digest != self.__template.worker_command_digest
            or statement.worker_compiler_id != self.__inventory.worker_compiler_id
            or statement.worker_compiler_version != self.__inventory.worker_compiler_version
            or statement.worker_compiler_digest != self.__inventory.worker_compiler_digest
            or statement.worker_verifier_id != self.__inventory.worker_verifier_id
            or statement.worker_verifier_version != self.__inventory.worker_verifier_version
            or statement.worker_verifier_digest != self.__inventory.worker_verifier_digest
            or statement.verification_key_id != self.__key.key_id
            or statement.verification_key_digest != self.__key.key_digest
            or statement.idempotency_key != envelope.idempotency_key
            or not statement.started_at < envelope.backend_handoff_deadline
        ):
            raise SpecialistBackendV2ContractError(
                "signed specialist backend result differs from deployment authority"
            )
        statement_bytes = canonical_json_bytes(
            statement.model_dump(mode="json", by_alias=True),
            label="specialist backend result statement",
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        signature = _base64url_decode(
            result.signature_base64url,
            size=64,
            label="specialist backend result signature",
        )
        try:
            self.__public_key.verify(signature, _SIGNATURE_DOMAIN + statement_bytes)
        except InvalidSignature as exc:
            raise SpecialistBackendV2ContractError(
                "specialist backend result signature is not trusted"
            ) from exc
        return result.model_copy(deep=True)


__all__ = [
    "CONFORMANCE_COMPLETED_NO_TARGET_IO",
    "SIGNED_SPECIALIST_BACKEND_RESULT_API_VERSION",
    "SPECIALIST_BACKEND_COMPILER_ID",
    "SPECIALIST_BACKEND_COMPILER_VERSION",
    "SPECIALIST_BACKEND_JOB_TEMPLATE_API_VERSION",
    "SPECIALIST_BACKEND_LAUNCH_ENVELOPE_API_VERSION",
    "SPECIALIST_BACKEND_RESULT_API_VERSION",
    "SPECIALIST_BACKEND_VERIFICATION_KEY_API_VERSION",
    "SPECIALIST_EXECUTION_INVENTORY_API_VERSION",
    "STRUCTURED_FAKE_SPECIALIST_BACKEND_ID",
    "STRUCTURED_FAKE_SPECIALIST_BACKEND_VERSION",
    "STRUCTURED_FAKE_SPECIALIST_COMMAND",
    "STRUCTURED_FAKE_SPECIALIST_IMAGE",
    "SignedSpecialistBackendResultV2",
    "SpecialistBackendJobTemplateV2",
    "SpecialistBackendLaunchEnvelopeV2",
    "SpecialistBackendOutputVerifierV2",
    "SpecialistBackendResultStatementV2",
    "SpecialistBackendV2",
    "SpecialistBackendV2ContractError",
    "SpecialistBackendVerificationKeyV2",
    "SpecialistExecutionInventoryV2",
    "StructuredFakeSpecialistBackendV2",
    "specialist_backend_launch_envelope_v2",
    "specialist_backend_public_key_base64url_v2",
    "specialist_execution_inventory_v2",
    "structured_fake_specialist_job_template_v2",
]
