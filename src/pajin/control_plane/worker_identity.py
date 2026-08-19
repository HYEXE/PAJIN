"""Deployment-pinned mutual-TLS identity admission for Control Plane Workers."""

from __future__ import annotations

import json
from collections.abc import Mapping
from hashlib import sha256
from typing import Any, Literal, Self

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.security import AuthenticationError
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import parse_strict_json_bytes

_MAX_POLICY_BYTES = 128 * 1024
_MAX_CLIENT_CERTIFICATE_BYTES = 64 * 1024
_MAX_CLIENT_CERTIFICATE_CHAIN = 16


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class WorkerCertificateBinding(_FrozenStrictModel):
    """Bind one local Worker principal to one deployment-owned public key."""

    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    certificate_spki_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class WorkerMTLSTrustPolicy(_FrozenStrictModel):
    """Versioned offline mapping from Worker subjects to mTLS certificate keys."""

    api_version: Literal["pajin.control-plane.worker-mtls-trust-policy/v1"] = (
        "pajin.control-plane.worker-mtls-trust-policy/v1"
    )
    policy_id: str = Field(pattern=r"^worker-mtls-policy_[0-9a-f]{32}$")
    bindings: tuple[WorkerCertificateBinding, ...] = Field(min_length=1, max_length=256)

    @model_validator(mode="after")
    def require_unique_worker_subjects(self) -> Self:
        subjects = [binding.principal_subject for binding in self.bindings]
        if len(subjects) != len(set(subjects)):
            raise ValueError("Worker mTLS principal subjects must be unique")
        return self


class WorkerMTLSAdmission(_FrozenStrictModel):
    """Content-addressed result of one live bearer/direct-mTLS intersection."""

    api_version: Literal["pajin.control-plane.worker-mtls-admission/v1"] = (
        "pajin.control-plane.worker-mtls-admission/v1"
    )
    kind: Literal["WorkerMTLSAdmission"] = "WorkerMTLSAdmission"
    admission_id: str = Field(default="", max_length=96)
    admission_digest: str = Field(default="", pattern=r"^(?:|[0-9a-f]{64})$")
    policy_id: str = Field(pattern=r"^worker-mtls-policy_[0-9a-f]{32}$")
    principal_subject: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$")
    certificate_spki_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bearer_authenticated: Literal[True] = True
    direct_mtls_authenticated: Literal[True] = True
    execution_authority: Literal[False] = False

    @field_validator(
        "bearer_authenticated",
        "direct_mtls_authenticated",
        mode="before",
    )
    @classmethod
    def require_literal_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("Worker mTLS admission success flags must be boolean true")
        return value

    @field_validator("execution_authority", mode="before")
    @classmethod
    def require_literal_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("Worker mTLS admission authority flag must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_admission_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            exclude={"admission_id", "admission_digest"},
        )
        encoded = json.dumps(
            material,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = sha256(b"PAJIN-WORKER-MTLS-ADMISSION\0" + encoded).hexdigest()
        admission_id = f"worker-mtls-admission_{digest}"
        if self.admission_digest and self.admission_digest != digest:
            raise ValueError("Worker mTLS admission digest differs")
        if self.admission_id and self.admission_id != admission_id:
            raise ValueError("Worker mTLS admission ID differs")
        object.__setattr__(self, "admission_digest", digest)
        object.__setattr__(self, "admission_id", admission_id)
        return self


def parse_worker_mtls_trust_policy(content: bytes) -> WorkerMTLSTrustPolicy:
    """Parse one bounded strict-JSON deployment policy."""

    decoded = parse_strict_json_bytes(
        content,
        label="Worker mTLS trust policy",
        max_bytes=_MAX_POLICY_BYTES,
        max_depth=12,
        max_nodes=4_096,
    )
    return WorkerMTLSTrustPolicy.model_validate(decoded)


def certificate_spki_sha256(certificate: x509.Certificate) -> str:
    """Return the lowercase SHA-256 digest of a certificate's DER SPKI."""

    public_key = certificate.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return sha256(public_key).hexdigest()


class WorkerMTLSAuthenticator:
    """Require verified ASGI TLS evidence matching a bearer-authenticated Worker."""

    def __init__(self, policy: WorkerMTLSTrustPolicy) -> None:
        self._policy_id = policy.policy_id
        self._bindings = {
            binding.principal_subject: binding.certificate_spki_sha256
            for binding in policy.bindings
        }

    def authenticate(self, scope: Mapping[str, Any], principal: Principal) -> Principal:
        self.authenticate_with_admission(scope, principal)
        return principal

    def authenticate_with_admission(
        self,
        scope: Mapping[str, Any],
        principal: Principal,
    ) -> WorkerMTLSAdmission:
        """Recheck live TLS evidence and return a non-bearer audit projection."""

        if principal.roles != frozenset({PrincipalRole.WORKER}):
            raise AuthenticationError("mTLS admission is limited to separated Worker principals")
        expected_digest = self._bindings.get(principal.subject)
        if expected_digest is None:
            raise AuthenticationError("Worker principal has no mTLS binding")
        certificate = _verified_client_certificate(scope)
        observed_digest = certificate_spki_sha256(certificate)
        if observed_digest != expected_digest:
            raise AuthenticationError("Worker client certificate does not match its subject")
        return WorkerMTLSAdmission(
            policy_id=self._policy_id,
            principal_subject=principal.subject,
            certificate_spki_sha256=observed_digest,
        )


def _verified_client_certificate(scope: Mapping[str, Any]) -> x509.Certificate:
    if scope.get("scheme") != "https":
        raise AuthenticationError("Worker mutual TLS requires a direct HTTPS connection")
    extensions = scope.get("extensions")
    if not isinstance(extensions, Mapping):
        raise AuthenticationError("ASGI TLS evidence is unavailable")
    tls = extensions.get("tls")
    if not isinstance(tls, Mapping) or tls.get("client_cert_error") is not None:
        raise AuthenticationError("verified ASGI client certificate evidence is unavailable")
    chain = tls.get("client_cert_chain", ())
    if not isinstance(chain, (list, tuple)) or not 1 <= len(chain) <= _MAX_CLIENT_CERTIFICATE_CHAIN:
        raise AuthenticationError("verified ASGI client certificate evidence is unavailable")
    leaf = chain[0]
    if not isinstance(leaf, str):
        raise AuthenticationError("verified ASGI client certificate evidence is invalid")
    try:
        encoded = leaf.encode("ascii")
    except UnicodeEncodeError as exc:
        raise AuthenticationError("verified ASGI client certificate evidence is invalid") from exc
    if (
        not encoded
        or len(encoded) > _MAX_CLIENT_CERTIFICATE_BYTES
        or encoded.count(b"-----BEGIN CERTIFICATE-----") != 1
        or encoded.count(b"-----END CERTIFICATE-----") != 1
    ):
        raise AuthenticationError("verified ASGI client certificate evidence is invalid")
    try:
        return x509.load_pem_x509_certificate(encoded)
    except ValueError as exc:
        raise AuthenticationError("verified ASGI client certificate evidence is invalid") from exc
