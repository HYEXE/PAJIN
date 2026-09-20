"""Target-I/O-zero Worker contract for one governed Web specialist dispatch.

This module is the deliberately inert first half of AGENTIC-003C3C.  It defines
only a versioned, secret-free reference wire, a deterministic network-disabled
``WorkerJob``, and a deployment-key-verified conformance output.  It does not
invoke a Worker backend, resolve a target, or reuse the aggregate Web
source/validation execution authorities.
"""

from __future__ import annotations

import base64
import binascii
import json
from hashlib import sha256
from typing import Annotated, Final, Literal, Self, cast, final

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator, model_validator

from pajin.agentic.models import AgenticStrictModel, _literal_false
from pajin.runtime.worker import NetworkMode, WorkerJob, WorkerLimits

SPECIALIST_WORKER_INPUT_API_VERSION: Final = (
    "pajin.dev/agentic-web-specialist-worker-input/v1alpha1"
)
SPECIALIST_WORKER_STATEMENT_API_VERSION: Final = (
    "pajin.dev/agentic-web-specialist-worker-statement/v1alpha1"
)
SPECIALIST_WORKER_SIGNED_OUTPUT_API_VERSION: Final = (
    "pajin.dev/signed-agentic-web-specialist-worker-output/v1alpha1"
)
SPECIALIST_WORKER_VERIFICATION_KEY_API_VERSION: Final = (
    "pajin.dev/agentic-web-specialist-worker-verification-key/v1alpha1"
)
SPECIALIST_WORKER_IMAGE: Final = "pajin-web-specialist-worker:target-io-zero-v1"
SPECIALIST_WORKER_COMMAND: Final = ("specialist-target-io-zero-conformance",)

_INPUT_DIGEST_DOMAIN: Final = "pajin.agentic.web-specialist-worker-input/v1"
_KEY_DIGEST_DOMAIN: Final = "pajin.agentic.web-specialist-worker-verification-key/v1"
_SIGNATURE_DOMAIN: Final = b"pajin.agentic.web-specialist-worker-output/v1\0"
_SHA256_PATTERN: Final = r"^[a-f0-9]{64}$"
_IDENTIFIER_PATTERN: Final = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_BASE64URL_PUBLIC_KEY_PATTERN: Final = r"^[A-Za-z0-9_-]{43}$"
_BASE64URL_SIGNATURE_PATTERN: Final = r"^[A-Za-z0-9_-]{86}$"
_FORBIDDEN_INPUT_FIELD_NAMES: Final = frozenset(
    {"route", "payload", "egresspolicy", "transport", "catalog"}
)
_SPECIALIST_IDENTITY_FAMILIES: Final = frozenset(
    {
        (
            "pajin.web-specialist.juice-shop.object-access-via-sql-login",
            "pajin.web-specialist.authorization",
            "pajin.bug-bounty.web-specialist.authorization",
            "web.specialist.authorization",
        ),
        (
            "pajin.web-specialist.juice-shop.sql-login-only",
            "pajin.web-specialist.sql-login",
            "pajin.bug-bounty.web-specialist.sql-login",
            "web.specialist.sql-login",
        ),
        (
            "pajin.web-specialist.juice-shop.dom-xss-only",
            "pajin.web-specialist.dom-xss",
            "pajin.bug-bounty.web-specialist.dom-xss",
            "web.specialist.dom-xss",
        ),
    }
)
_FALSE_STATEMENT_FIELDS: Final = (
    "target_io_performed",
    "backend_invoked",
    "secret_material_requested",
    "aggregate_source_authority_reused",
    "aggregate_validation_authority_reused",
    "production_authority_eligible",
    "independent_validation",
    "finding",
    "graph",
    "report",
    "sarif",
    "poc",
)

Sha256 = Annotated[str, Field(pattern=_SHA256_PATTERN)]


class SpecialistWorkerContractError(ValueError):
    """Raised when the inert specialist Worker contract differs or is untrusted."""


def _canonical_json(value: object) -> bytes:
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise SpecialistWorkerContractError(
            "specialist Worker value is not canonical JSON"
        ) from exc


def _domain_digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\0" + _canonical_json(value)).hexdigest()


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


def _normalized_field_name(value: object) -> str:
    if type(value) is not str:
        return ""
    return value.replace("_", "").replace("-", "").casefold()


def _reject_forbidden_input_fields(value: object) -> None:
    """Reject executable input names before Pydantic can normalize a wire value."""

    active: set[int] = set()

    def visit(item: object, *, depth: int) -> None:
        if depth > 32:
            raise ValueError("specialist Worker input nesting is too deep")
        if isinstance(item, BaseModel):
            item = item.model_dump(mode="python", by_alias=True)
        if type(item) is dict:
            identity = id(item)
            if identity in active:
                raise ValueError("specialist Worker input cannot contain cycles")
            active.add(identity)
            try:
                for key, nested in cast(dict[object, object], item).items():
                    if _normalized_field_name(key) in _FORBIDDEN_INPUT_FIELD_NAMES:
                        raise ValueError(
                            "specialist Worker input contains a forbidden executable field"
                        )
                    visit(nested, depth=depth + 1)
            finally:
                active.remove(identity)
        elif type(item) in {list, tuple}:
            for nested in cast(list[object] | tuple[object, ...], item):
                visit(nested, depth=depth + 1)

    visit(value, depth=0)


def _require_unmodified_model_state(value: BaseModel, *, label: str) -> None:
    """Reject fields injected through Pydantic's non-validating ``model_copy`` API."""

    expected = set(type(value).model_fields)
    if set(vars(value)) != expected or value.__pydantic_extra__:
        raise SpecialistWorkerContractError(f"{label} contains hidden model state")
    for nested in vars(value).values():
        if isinstance(nested, BaseModel):
            _require_unmodified_model_state(nested, label=label)


class SpecialistWorkerReference(AgenticStrictModel):
    """One exact, non-bearer reference; the referenced value is never embedded."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    reference_id: str = Field(alias="id", pattern=_IDENTIFIER_PATTERN)
    reference_digest: Sha256 = Field(alias="digest")


class SpecialistWorkerInput(AgenticStrictModel):
    """Secret-free exact references accepted by the inert specialist Worker job."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-web-specialist-worker-input/v1alpha1"] = Field(
        default=SPECIALIST_WORKER_INPUT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticWebSpecialistWorkerInput"] = "AgenticWebSpecialistWorkerInput"
    execution_ref: SpecialistWorkerReference = Field(alias="executionRef")
    binding_ref: SpecialistWorkerReference = Field(alias="bindingRef")
    preparation_ref: SpecialistWorkerReference = Field(alias="preparationRef")
    profile_ref: SpecialistWorkerReference = Field(alias="profileRef")
    executor_ref: SpecialistWorkerReference = Field(alias="executorRef")
    capability_ref: SpecialistWorkerReference = Field(alias="capabilityRef")
    tool_ref: SpecialistWorkerReference = Field(alias="toolRef")
    request_ref: SpecialistWorkerReference = Field(alias="requestRef")
    permit_ref: SpecialistWorkerReference = Field(alias="permitRef")
    grant_consumption_ref: SpecialistWorkerReference = Field(alias="grantConsumptionRef")

    @model_validator(mode="before")
    @classmethod
    def reject_executable_fields(cls, value: object) -> object:
        _reject_forbidden_input_fields(value)
        return value

    @model_validator(mode="after")
    def bind_content_addressed_authority_refs(self) -> Self:
        exact_prefixes = (
            (self.execution_ref, "agentic-specialist-reservation_"),
            (self.binding_ref, "agentic-specialist-dispatch-binding_"),
            (self.preparation_ref, "agentic-specialist-preparation_"),
            (self.permit_ref, "action-permit_"),
            (
                self.grant_consumption_ref,
                "agentic-specialist-grant-consumption_",
            ),
        )
        if any(
            reference.reference_id != prefix + reference.reference_digest
            for reference, prefix in exact_prefixes
        ):
            raise ValueError("specialist Worker content-addressed reference differs")
        specialist_identity = (
            self.profile_ref.reference_id,
            self.executor_ref.reference_id,
            self.capability_ref.reference_id,
            self.tool_ref.reference_id,
        )
        if specialist_identity not in _SPECIALIST_IDENTITY_FAMILIES:
            raise ValueError("specialist Worker code-owned identity family differs")
        request_id = self.request_ref.reference_id
        request_prefix = "agentic-specialist-request_"
        if (
            not request_id.startswith(request_prefix)
            or len(request_id) != len(request_prefix) + 64
            or any(
                character not in "0123456789abcdef"
                for character in request_id[len(request_prefix) :]
            )
        ):
            raise ValueError("specialist Worker request reference is not code-owned")
        ids = tuple(
            reference.reference_id
            for reference in (
                self.execution_ref,
                self.binding_ref,
                self.preparation_ref,
                self.profile_ref,
                self.executor_ref,
                self.capability_ref,
                self.tool_ref,
                self.request_ref,
                self.permit_ref,
                self.grant_consumption_ref,
            )
        )
        if len(ids) != len(set(ids)):
            raise ValueError("specialist Worker references must have distinct identities")
        return self

    @property
    def input_digest(self) -> str:
        return _domain_digest(
            _INPUT_DIGEST_DOMAIN,
            self.model_dump(mode="json", by_alias=True),
        )


class SpecialistWorkerStatement(AgenticStrictModel):
    """Signed no-I/O conformance statement with no production authority."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-web-specialist-worker-statement/v1alpha1"] = Field(
        default=SPECIALIST_WORKER_STATEMENT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["AgenticWebSpecialistWorkerStatement"] = "AgenticWebSpecialistWorkerStatement"
    predicate_type: Literal["pajin.dev/target-io-zero-specialist-worker-conformance/v1"] = Field(
        default="pajin.dev/target-io-zero-specialist-worker-conformance/v1",
        alias="predicateType",
    )
    trust_domain: str = Field(alias="trustDomain", pattern=_IDENTIFIER_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    input_digest: Sha256 = Field(alias="inputDigest")
    execution_ref: SpecialistWorkerReference = Field(alias="executionRef")
    binding_ref: SpecialistWorkerReference = Field(alias="bindingRef")
    preparation_ref: SpecialistWorkerReference = Field(alias="preparationRef")
    profile_ref: SpecialistWorkerReference = Field(alias="profileRef")
    executor_ref: SpecialistWorkerReference = Field(alias="executorRef")
    capability_ref: SpecialistWorkerReference = Field(alias="capabilityRef")
    tool_ref: SpecialistWorkerReference = Field(alias="toolRef")
    request_ref: SpecialistWorkerReference = Field(alias="requestRef")
    permit_ref: SpecialistWorkerReference = Field(alias="permitRef")
    grant_consumption_ref: SpecialistWorkerReference = Field(alias="grantConsumptionRef")
    network_mode: Literal["none"] = Field(default="none", alias="networkMode")
    target_io_performed: Literal[False] = Field(default=False, alias="targetIOPerformed")
    backend_invoked: Literal[False] = Field(default=False, alias="backendInvoked")
    secret_material_requested: Literal[False] = Field(
        default=False,
        alias="secretMaterialRequested",
    )
    aggregate_source_authority_reused: Literal[False] = Field(
        default=False,
        alias="aggregateSourceAuthorityReused",
    )
    aggregate_validation_authority_reused: Literal[False] = Field(
        default=False,
        alias="aggregateValidationAuthorityReused",
    )
    production_authority_eligible: Literal[False] = Field(
        default=False,
        alias="productionAuthorityEligible",
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

    @field_validator(*_FALSE_STATEMENT_FIELDS, mode="before")
    @classmethod
    def require_literal_false(cls, value: object, info: ValidationInfo) -> object:
        return _literal_false(value, label=info.field_name)

    @field_validator("issuer")
    @classmethod
    def require_canonical_issuer(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("specialist Worker issuer is not canonical text")
        return value

    @model_validator(mode="after")
    def bind_input(self) -> Self:
        worker_input = SpecialistWorkerInput.model_validate(
            {
                "apiVersion": SPECIALIST_WORKER_INPUT_API_VERSION,
                "kind": "AgenticWebSpecialistWorkerInput",
                "executionRef": self.execution_ref.model_dump(mode="json", by_alias=True),
                "bindingRef": self.binding_ref.model_dump(mode="json", by_alias=True),
                "preparationRef": self.preparation_ref.model_dump(mode="json", by_alias=True),
                "profileRef": self.profile_ref.model_dump(mode="json", by_alias=True),
                "executorRef": self.executor_ref.model_dump(mode="json", by_alias=True),
                "capabilityRef": self.capability_ref.model_dump(mode="json", by_alias=True),
                "toolRef": self.tool_ref.model_dump(mode="json", by_alias=True),
                "requestRef": self.request_ref.model_dump(mode="json", by_alias=True),
                "permitRef": self.permit_ref.model_dump(mode="json", by_alias=True),
                "grantConsumptionRef": self.grant_consumption_ref.model_dump(
                    mode="json", by_alias=True
                ),
            }
        )
        if self.input_digest != worker_input.input_digest:
            raise ValueError("specialist Worker statement input digest differs")
        return self


class SignedSpecialistWorkerOutput(AgenticStrictModel):
    """Ed25519 envelope whose verification key is supplied only by deployment code."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/signed-agentic-web-specialist-worker-output/v1alpha1"] = Field(
        default=SPECIALIST_WORKER_SIGNED_OUTPUT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["SignedAgenticWebSpecialistWorkerOutput"] = (
        "SignedAgenticWebSpecialistWorkerOutput"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    statement: SpecialistWorkerStatement
    statement_sha256: Sha256 = Field(alias="statementSha256")
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=_BASE64URL_SIGNATURE_PATTERN,
    )

    @model_validator(mode="after")
    def bind_canonical_envelope(self) -> Self:
        statement_bytes = _canonical_json(self.statement.model_dump(mode="json", by_alias=True))
        if self.statement_sha256 != sha256(statement_bytes).hexdigest():
            raise ValueError("specialist Worker statement digest differs")
        _base64url_decode(
            self.signature_base64url,
            size=64,
            label="specialist Worker signature",
        )
        return self

    @property
    def digest(self) -> str:
        return _domain_digest(
            "pajin.agentic.web-specialist-worker-signed-output/v1",
            self.model_dump(mode="json", by_alias=True),
        )


class SpecialistWorkerVerificationKey(AgenticStrictModel):
    """One out-of-band public key installed by the deployment."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        validate_by_alias=True,
        validate_by_name=False,
        serialize_by_alias=True,
    )

    api_version: Literal["pajin.dev/agentic-web-specialist-worker-verification-key/v1alpha1"] = (
        Field(default=SPECIALIST_WORKER_VERIFICATION_KEY_API_VERSION, alias="apiVersion")
    )
    kind: Literal["AgenticWebSpecialistWorkerVerificationKey"] = (
        "AgenticWebSpecialistWorkerVerificationKey"
    )
    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    trust_domain: str = Field(alias="trustDomain", pattern=_IDENTIFIER_PATTERN)
    issuer: str = Field(min_length=1, max_length=200)
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=_BASE64URL_PUBLIC_KEY_PATTERN,
    )

    @field_validator("issuer")
    @classmethod
    def require_canonical_issuer(cls, value: str) -> str:
        if value != value.strip() or any(ord(character) < 32 for character in value):
            raise ValueError("specialist Worker key issuer is not canonical text")
        return value

    @model_validator(mode="after")
    def validate_public_key(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            size=32,
            label="specialist Worker public key",
        )
        return self

    @property
    def key_digest(self) -> str:
        return _domain_digest(
            _KEY_DIGEST_DOMAIN,
            self.model_dump(mode="json", by_alias=True),
        )


def _canonical_input(value: SpecialistWorkerInput) -> SpecialistWorkerInput:
    if type(value) is not SpecialistWorkerInput:
        raise SpecialistWorkerContractError(
            "specialist Worker compiler requires the exact input type"
        )
    _require_unmodified_model_state(value, label="specialist Worker input")
    wire = value.model_dump(mode="json", by_alias=True)
    try:
        canonical = SpecialistWorkerInput.model_validate(wire)
    except (TypeError, ValueError) as exc:
        raise SpecialistWorkerContractError("specialist Worker input is invalid") from exc
    if canonical.model_dump(mode="json", by_alias=True) != wire or canonical != value:
        raise SpecialistWorkerContractError("specialist Worker input differs after strict reload")
    return canonical


def specialist_worker_statement_for_input(
    worker_input: SpecialistWorkerInput,
    *,
    trust_domain: str,
    issuer: str,
) -> SpecialistWorkerStatement:
    """Build the unique no-I/O statement for one exact reference input."""

    canonical = _canonical_input(worker_input)
    return SpecialistWorkerStatement(
        trustDomain=trust_domain,
        issuer=issuer,
        inputDigest=canonical.input_digest,
        executionRef=canonical.execution_ref,
        bindingRef=canonical.binding_ref,
        preparationRef=canonical.preparation_ref,
        profileRef=canonical.profile_ref,
        executorRef=canonical.executor_ref,
        capabilityRef=canonical.capability_ref,
        toolRef=canonical.tool_ref,
        requestRef=canonical.request_ref,
        permitRef=canonical.permit_ref,
        grantConsumptionRef=canonical.grant_consumption_ref,
    )


def specialist_worker_public_key_base64url(private_key: bytes) -> str:
    """Return the canonical raw Ed25519 public key for provisioning tests/tools."""

    if type(private_key) is not bytes or len(private_key) != 32:
        raise ValueError("specialist Worker private key must contain exactly 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def sign_specialist_worker_statement(
    statement: SpecialistWorkerStatement,
    *,
    key_id: str,
    private_key: bytes,
) -> SignedSpecialistWorkerOutput:
    """Sign one canonical statement; verification still requires deployment-owned trust."""

    if type(statement) is not SpecialistWorkerStatement:
        raise SpecialistWorkerContractError("specialist Worker signer requires exact statement")
    _require_unmodified_model_state(statement, label="specialist Worker statement")
    canonical = SpecialistWorkerStatement.model_validate(
        statement.model_dump(mode="json", by_alias=True)
    )
    if canonical != statement:
        raise SpecialistWorkerContractError(
            "specialist Worker statement differs after strict reload"
        )
    if type(private_key) is not bytes or len(private_key) != 32:
        raise ValueError("specialist Worker private key must contain exactly 32 bytes")
    statement_bytes = _canonical_json(canonical.model_dump(mode="json", by_alias=True))
    signature = Ed25519PrivateKey.from_private_bytes(private_key).sign(
        _SIGNATURE_DOMAIN + statement_bytes
    )
    return SignedSpecialistWorkerOutput(
        keyId=key_id,
        statement=canonical,
        statementSha256=sha256(statement_bytes).hexdigest(),
        signatureBase64url=_base64url_encode(signature),
    )


@final
class SpecialistWorkerJobCompiler:
    """Compile only a deterministic, secret-free, network-disabled Worker job."""

    __slots__ = ()

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "pajin.agentic.web-specialist-worker-compiler/v1",
            "inputApiVersion": SPECIALIST_WORKER_INPUT_API_VERSION,
            "image": SPECIALIST_WORKER_IMAGE,
            "command": list(SPECIALIST_WORKER_COMMAND),
            "networkMode": NetworkMode.NONE.value,
            "secretRequestsAllowed": False,
            "targetIOAllowed": False,
            "aggregateWebAuthorityReused": False,
        }

    def compile_job(self, worker_input: SpecialistWorkerInput) -> WorkerJob:
        canonical = _canonical_input(worker_input)
        job = WorkerJob(
            execution_id=f"specialist-worker:{canonical.input_digest}",
            image=SPECIALIST_WORKER_IMAGE,
            command=list(SPECIALIST_WORKER_COMMAND),
            stdin=_canonical_json(canonical.model_dump(mode="json", by_alias=True)).decode("utf-8"),
            network=NetworkMode.NONE,
            egress_policy=None,
            limits=WorkerLimits(
                timeout_seconds=30,
                memory_mb=256,
                cpus=0.5,
                pids=16,
                workspace_mb=8,
                stdout_bytes=64_000,
                stderr_bytes=64_000,
            ),
            secret_requests=[],
        )
        if (
            job.network is not NetworkMode.NONE
            or job.egress_policy is not None
            or job.secret_requests
        ):
            raise SpecialistWorkerContractError(
                "specialist Worker compiler produced an executable I/O surface"
            )
        return WorkerJob.model_validate(job.model_dump(mode="python"))

    def verify_job(
        self,
        *,
        expected_input: SpecialistWorkerInput,
        job: WorkerJob,
    ) -> WorkerJob:
        """Reject every mutation before a future handoff may cross a backend boundary."""

        if type(job) is not WorkerJob:
            raise SpecialistWorkerContractError(
                "specialist Worker handoff requires the exact WorkerJob type"
            )
        expected = self.compile_job(expected_input)
        try:
            canonical = WorkerJob.model_validate(job.model_dump(mode="python"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise SpecialistWorkerContractError(
                "specialist Worker job failed strict reload"
            ) from exc
        if canonical != job or canonical != expected:
            raise SpecialistWorkerContractError(
                "specialist Worker job differs from deterministic compilation"
            )
        return canonical


def compile_specialist_worker_job(worker_input: SpecialistWorkerInput) -> WorkerJob:
    """Functional API for the deterministic Target-I/O-zero compiler."""

    return SpecialistWorkerJobCompiler().compile_job(worker_input)


def verify_specialist_worker_job(
    *,
    expected_input: SpecialistWorkerInput,
    job: WorkerJob,
) -> WorkerJob:
    """Functional pre-handoff verification; it performs no backend invocation."""

    return SpecialistWorkerJobCompiler().verify_job(
        expected_input=expected_input,
        job=job,
    )


@final
class SpecialistWorkerOutputVerifier:
    """Verify output only with the public key pinned at deployment construction."""

    __slots__ = ("__key", "__public_key")

    def __init__(
        self,
        *,
        deployment_verification_key: SpecialistWorkerVerificationKey,
    ) -> None:
        if type(deployment_verification_key) is not SpecialistWorkerVerificationKey:
            raise TypeError("specialist Worker verifier requires a deployment key")
        _require_unmodified_model_state(
            deployment_verification_key,
            label="specialist Worker deployment verification key",
        )
        canonical = SpecialistWorkerVerificationKey.model_validate(
            deployment_verification_key.model_dump(mode="json", by_alias=True)
        )
        if canonical != deployment_verification_key:
            raise SpecialistWorkerContractError(
                "specialist Worker deployment key differs after strict reload"
            )
        self.__key = canonical
        self.__public_key = Ed25519PublicKey.from_public_bytes(
            _base64url_decode(
                canonical.public_key_base64url,
                size=32,
                label="specialist Worker public key",
            )
        )

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "pajin.agentic.web-specialist-output-verifier/v1",
            "verificationKeyId": self.__key.key_id,
            "verificationKeyDigest": self.__key.key_digest,
            "trustDomain": self.__key.trust_domain,
            "deploymentOwnedVerificationKey": True,
            "aggregateWebAuthorityReused": False,
            "productionAuthorityEligible": False,
        }

    def verify_output(
        self,
        *,
        expected_input: SpecialistWorkerInput,
        signed_output: SignedSpecialistWorkerOutput,
    ) -> SignedSpecialistWorkerOutput:
        canonical_input = _canonical_input(expected_input)
        if type(signed_output) is not SignedSpecialistWorkerOutput:
            raise SpecialistWorkerContractError(
                "specialist Worker verifier requires the exact signed output type"
            )
        _require_unmodified_model_state(
            signed_output,
            label="signed specialist Worker output",
        )
        try:
            canonical_output = SignedSpecialistWorkerOutput.model_validate(
                signed_output.model_dump(mode="json", by_alias=True)
            )
        except (TypeError, ValueError) as exc:
            raise SpecialistWorkerContractError(
                "signed specialist Worker output is invalid"
            ) from exc
        expected_statement = specialist_worker_statement_for_input(
            canonical_input,
            trust_domain=self.__key.trust_domain,
            issuer=self.__key.issuer,
        )
        if (
            canonical_output != signed_output
            or canonical_output.key_id != self.__key.key_id
            or canonical_output.statement != expected_statement
        ):
            raise SpecialistWorkerContractError(
                "signed specialist Worker output differs from deployment authority"
            )
        statement_bytes = _canonical_json(
            canonical_output.statement.model_dump(mode="json", by_alias=True)
        )
        signature = _base64url_decode(
            canonical_output.signature_base64url,
            size=64,
            label="specialist Worker signature",
        )
        try:
            self.__public_key.verify(signature, _SIGNATURE_DOMAIN + statement_bytes)
        except InvalidSignature as exc:
            raise SpecialistWorkerContractError(
                "specialist Worker output signature is not trusted"
            ) from exc
        return canonical_output.model_copy(deep=True)


__all__ = [
    "SPECIALIST_WORKER_COMMAND",
    "SPECIALIST_WORKER_IMAGE",
    "SPECIALIST_WORKER_INPUT_API_VERSION",
    "SPECIALIST_WORKER_SIGNED_OUTPUT_API_VERSION",
    "SPECIALIST_WORKER_STATEMENT_API_VERSION",
    "SPECIALIST_WORKER_VERIFICATION_KEY_API_VERSION",
    "SignedSpecialistWorkerOutput",
    "SpecialistWorkerContractError",
    "SpecialistWorkerInput",
    "SpecialistWorkerJobCompiler",
    "SpecialistWorkerOutputVerifier",
    "SpecialistWorkerReference",
    "SpecialistWorkerStatement",
    "SpecialistWorkerVerificationKey",
    "compile_specialist_worker_job",
    "sign_specialist_worker_statement",
    "specialist_worker_public_key_base64url",
    "specialist_worker_statement_for_input",
    "verify_specialist_worker_job",
]
