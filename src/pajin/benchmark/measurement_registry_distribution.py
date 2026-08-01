"""P0-C2B2A1 signed measurement registry distribution and durable activation."""

from __future__ import annotations

import base64
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.benchmark.measurement_registry import (
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryError,
    BenchmarkMeasurementTrustRegistry,
    verify_benchmark_measurement_registry_transition,
)
from pajin.benchmark.models import benchmark_digest, canonical_benchmark_json
from pajin.domain.models import StrictModel

BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_TRUST_ANCHOR_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-registry-distribution-trust-anchor/v1alpha1"
] = "pajin.dev/benchmark-measurement-registry-distribution-trust-anchor/v1alpha1"
BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_STATEMENT_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-registry-distribution-statement/v1alpha1"
] = "pajin.dev/benchmark-measurement-registry-distribution-statement/v1alpha1"
BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_BUNDLE_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-registry-distribution-bundle/v1alpha1"
] = "pajin.dev/benchmark-measurement-registry-distribution-bundle/v1alpha1"
BENCHMARK_MEASUREMENT_REGISTRY_ACTIVATION_API_VERSION: Literal[
    "pajin.dev/benchmark-measurement-registry-activation/v1alpha1"
] = "pajin.dev/benchmark-measurement-registry-activation/v1alpha1"

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"),
]
_KeyIdentifier = Annotated[
    str,
    Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_PublicKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
_Signature = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
_MAX_BUNDLE_LIFETIME = timedelta(days=7)
_SIGNATURE_DOMAIN = b"pajin.benchmark.measurement-registry-distribution/v1\x00"
_BUSY_TIMEOUT_MS = 5_000


class BenchmarkMeasurementRegistryDistributionError(RuntimeError):
    """Raised when registry origin, activation order, or durable state is untrusted."""


class BenchmarkMeasurementRegistryDistributionKey(StrictModel):
    """One public key authorized only to sign measurement-registry bundles."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: _KeyIdentifier = Field(alias="keyId")
    public_key_base64url: _PublicKey = Field(alias="publicKeyBase64url")
    state: BenchmarkMeasurementKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")

    @field_validator("not_before", "not_after")
    @classmethod
    def normalize_timestamp(cls, value: datetime | None) -> datetime | None:
        if value is None:
            return None
        return _aware_utc(value, label="Benchmark registry distribution key timestamp")

    @model_validator(mode="after")
    def require_lifecycle(self) -> Self:
        if self.not_after is not None and self.not_after <= self.not_before:
            raise ValueError("Benchmark registry distribution key validity window is empty")
        if self.state is BenchmarkMeasurementKeyState.RETIRED and self.not_after is None:
            raise ValueError("Retired registry distribution key requires notAfter")
        _decode_base64url(
            self.public_key_base64url,
            expected_length=32,
            label="Benchmark registry distribution public key",
        )
        return self


class BenchmarkMeasurementRegistryDistributionTrustAnchor(StrictModel):
    """Out-of-band authority for one registry distribution trust domain."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-measurement-registry-distribution-trust-anchor/v1alpha1"
    ] = Field(
        default=BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_TRUST_ANCHOR_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementRegistryDistributionTrustAnchor"] = (
        "BenchmarkMeasurementRegistryDistributionTrustAnchor"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    keys: tuple[BenchmarkMeasurementRegistryDistributionKey, ...] = Field(
        min_length=1,
        max_length=32,
    )

    @model_validator(mode="after")
    def require_keyring(self) -> Self:
        key_ids = [key.key_id for key in self.keys]
        if key_ids != sorted(key_ids) or len(key_ids) != len(set(key_ids)):
            raise ValueError("Benchmark registry distribution keys must be uniquely sorted")
        if len([key for key in self.keys if key.state is BenchmarkMeasurementKeyState.ACTIVE]) != 1:
            raise ValueError("Benchmark registry distribution Trust Anchor requires one active key")
        return self

    @property
    def anchor_digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.measurement-registry-distribution-trust-anchor/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=256 * 1024,
        )

    @property
    def active_key(self) -> BenchmarkMeasurementRegistryDistributionKey:
        return next(key for key in self.keys if key.state is BenchmarkMeasurementKeyState.ACTIVE)


class BenchmarkMeasurementRegistryDistributionStatement(StrictModel):
    """Bounded signed statement containing one exact registry transition."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-measurement-registry-distribution-statement/v1alpha1"
    ] = Field(
        default=BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_STATEMENT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementRegistryDistributionStatement"] = (
        "BenchmarkMeasurementRegistryDistributionStatement"
    )
    trust_domain: _Identifier = Field(alias="trustDomain")
    issuer: _Identifier
    sequence: int = Field(ge=1, le=2**31 - 1)
    previous_bundle_digest: _Sha256 | None = Field(
        default=None,
        alias="previousBundleDigest",
    )
    issued_at: datetime = Field(alias="issuedAt")
    not_before: datetime = Field(alias="notBefore")
    expires_at: datetime = Field(alias="expiresAt")
    registry: BenchmarkMeasurementTrustRegistry
    predecessor_registry: BenchmarkMeasurementTrustRegistry | None = Field(
        default=None,
        alias="predecessorRegistry",
    )

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Benchmark registry distribution timestamp")

    @model_validator(mode="after")
    def require_bounded_transition(self) -> Self:
        if not self.issued_at <= self.not_before < self.expires_at:
            raise ValueError("Benchmark registry distribution validity window is invalid")
        if self.expires_at > self.issued_at + _MAX_BUNDLE_LIFETIME:
            raise ValueError("Benchmark registry distribution lifetime exceeds seven days")
        if self.issued_at < self.registry.issued_at:
            raise ValueError("Benchmark registry distribution predates its registry")
        if self.sequence != self.registry.registry_revision:
            raise ValueError(
                "Benchmark registry distribution sequence differs from registry revision"
            )
        if self.sequence == 1:
            if self.previous_bundle_digest is not None or self.predecessor_registry is not None:
                raise ValueError(
                    "Initial Benchmark registry distribution cannot bind a predecessor"
                )
        else:
            if self.previous_bundle_digest is None or self.predecessor_registry is None:
                raise ValueError("Benchmark registry distribution requires exact predecessors")
            try:
                verify_benchmark_measurement_registry_transition(
                    self.predecessor_registry,
                    self.registry,
                )
            except BenchmarkMeasurementRegistryError as exc:
                raise ValueError("Benchmark registry distribution transition differs") from exc
        return self


class BenchmarkMeasurementRegistryDistributionBundle(StrictModel):
    """Ed25519 envelope for one registry distribution statement."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-measurement-registry-distribution-bundle/v1alpha1"
    ] = Field(
        default=BENCHMARK_MEASUREMENT_REGISTRY_DISTRIBUTION_BUNDLE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementRegistryDistributionBundle"] = (
        "BenchmarkMeasurementRegistryDistributionBundle"
    )
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _KeyIdentifier = Field(alias="keyId")
    statement: BenchmarkMeasurementRegistryDistributionStatement
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    signature_base64url: _Signature = Field(alias="signatureBase64url")

    @model_validator(mode="after")
    def require_envelope(self) -> Self:
        canonical = _statement_bytes(self.statement)
        if self.statement_sha256 != sha256(canonical).hexdigest():
            raise ValueError("Benchmark registry distribution statement digest differs")
        _decode_base64url(
            self.signature_base64url,
            expected_length=64,
            label="Benchmark registry distribution signature",
        )
        return self

    @property
    def bundle_digest(self) -> str:
        return benchmark_digest(
            "pajin.benchmark.measurement-registry-distribution-bundle/v1",
            self.model_dump(mode="json", by_alias=True),
            max_bytes=_MAX_BUNDLE_BYTES,
        )


@dataclass(frozen=True, slots=True)
class BenchmarkMeasurementRegistryDistributionSigner:
    """Offline helper; private key bytes never enter a model or durable activation."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    ) -> BenchmarkMeasurementRegistryDistributionSigner:
        if len(private_key) != 32:
            raise ValueError("Ed25519 registry distribution private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        authoritative_anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
            self.trust_anchor.model_dump(mode="json", by_alias=True)
        )
        object.__setattr__(self, "trust_anchor", authoritative_anchor)
        key = next(
            (item for item in self.trust_anchor.keys if item.key_id == self.active_key_id),
            None,
        )
        if key is None or key.state is not BenchmarkMeasurementKeyState.ACTIVE:
            raise ValueError("Registry distribution signer is not the active Trust Anchor key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        if public_bytes != _decode_base64url(
            key.public_key_base64url,
            expected_length=32,
            label="Benchmark registry distribution public key",
        ):
            raise ValueError("Registry distribution private key differs from its Trust Anchor")

    def sign(
        self,
        *,
        registry: BenchmarkMeasurementTrustRegistry,
        predecessor_registry: BenchmarkMeasurementTrustRegistry | None = None,
        previous_bundle_digest: str | None = None,
        issued_at: datetime,
        not_before: datetime,
        expires_at: datetime,
    ) -> BenchmarkMeasurementRegistryDistributionBundle:
        key = self.trust_anchor.active_key
        issue_time = _aware_utc(issued_at, label="Benchmark registry distribution issue time")
        if issue_time < key.not_before or (
            key.not_after is not None and issue_time >= key.not_after
        ):
            raise ValueError("Registry distribution signing key is invalid at issue time")
        statement = BenchmarkMeasurementRegistryDistributionStatement(
            trustDomain=self.trust_anchor.trust_domain,
            issuer=self.trust_anchor.issuer,
            sequence=registry.registry_revision,
            previousBundleDigest=previous_bundle_digest,
            issuedAt=issue_time,
            notBefore=not_before,
            expiresAt=expires_at,
            registry=registry,
            predecessorRegistry=predecessor_registry,
        )
        canonical = _statement_bytes(statement)
        return BenchmarkMeasurementRegistryDistributionBundle(
            keyId=self.active_key_id,
            statement=statement,
            statementSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_encode_base64url(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


class BenchmarkMeasurementRegistryActivation(StrictModel):
    """Content-bound row persisted after one signed bundle is accepted."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/benchmark-measurement-registry-activation/v1alpha1"
    ] = Field(
        default=BENCHMARK_MEASUREMENT_REGISTRY_ACTIVATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["BenchmarkMeasurementRegistryActivation"] = (
        "BenchmarkMeasurementRegistryActivation"
    )
    activation_digest: str = Field(default="", alias="activationDigest", max_length=64)
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    bundle_digest: _Sha256 = Field(alias="bundleDigest")
    bundle: BenchmarkMeasurementRegistryDistributionBundle
    activated_at: datetime = Field(alias="activatedAt")

    @field_validator("activated_at")
    @classmethod
    def normalize_timestamp(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Benchmark registry activation time")

    @model_validator(mode="after")
    def bind_activation(self) -> Self:
        if self.bundle_digest != self.bundle.bundle_digest:
            raise ValueError("Benchmark registry activation bundle digest differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_digest"},
        )
        digest = benchmark_digest(
            "pajin.benchmark.measurement-registry-activation/v1",
            material,
            max_bytes=_MAX_BUNDLE_BYTES + 1024,
        )
        if self.activation_digest and self.activation_digest != digest:
            raise ValueError("Benchmark registry activation digest differs")
        object.__setattr__(self, "activation_digest", digest)
        return self


def verify_benchmark_measurement_registry_distribution_bundle(
    bundle: BenchmarkMeasurementRegistryDistributionBundle,
    *,
    trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
    now: datetime | None = None,
) -> BenchmarkMeasurementRegistryDistributionKey:
    """Verify exact trust domain, signing-key lifecycle, signature, and current validity."""

    try:
        authoritative_bundle = BenchmarkMeasurementRegistryDistributionBundle.model_validate(
            bundle.model_dump(mode="json", by_alias=True)
        )
        authoritative_anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )
    except ValueError as exc:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution input is structurally invalid"
        ) from exc
    bundle = authoritative_bundle
    trust_anchor = authoritative_anchor
    statement = bundle.statement
    if (
        statement.trust_domain != trust_anchor.trust_domain
        or statement.issuer != trust_anchor.issuer
    ):
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution issuer or trust domain is untrusted"
        )
    key = next((item for item in trust_anchor.keys if item.key_id == bundle.key_id), None)
    if key is None:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution signing key is unknown"
        )
    if key.state is BenchmarkMeasurementKeyState.REVOKED:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution signing key is revoked"
        )
    if statement.issued_at < key.not_before or (
        key.not_after is not None and statement.issued_at >= key.not_after
    ):
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution was signed outside key validity"
        )
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                key.public_key_base64url,
                expected_length=32,
                label="Benchmark registry distribution public key",
            )
        ).verify(
            _decode_base64url(
                bundle.signature_base64url,
                expected_length=64,
                label="Benchmark registry distribution signature",
            ),
            _SIGNATURE_DOMAIN + _statement_bytes(statement),
        )
    except (InvalidSignature, ValueError) as exc:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry distribution signature verification failed"
        ) from exc
    if now is not None:
        timestamp = _aware_utc(now, label="Benchmark registry distribution verification time")
        if not statement.not_before <= timestamp < statement.expires_at:
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry distribution is not currently valid"
            )
    return key.model_copy(deep=True)


class BenchmarkMeasurementRegistryActivationStore:
    """Host-local append-only SQLite checkpoint for accepted signed registry revisions."""

    def __init__(self, path: Path) -> None:
        self.path = Path(os.path.abspath(path))
        _initialize_activation_store(self.path)

    def activate(
        self,
        bundle: BenchmarkMeasurementRegistryDistributionBundle,
        *,
        trust_anchor: BenchmarkMeasurementRegistryDistributionTrustAnchor,
        now: datetime | None = None,
    ) -> BenchmarkMeasurementRegistryActivation:
        try:
            authoritative_bundle = BenchmarkMeasurementRegistryDistributionBundle.model_validate(
                bundle.model_dump(mode="json", by_alias=True)
            )
            authoritative_anchor = (
                BenchmarkMeasurementRegistryDistributionTrustAnchor.model_validate(
                    trust_anchor.model_dump(mode="json", by_alias=True)
                )
            )
        except ValueError as exc:
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry activation input is structurally invalid"
            ) from exc
        bundle = authoritative_bundle
        trust_anchor = authoritative_anchor
        activated_at = datetime.now(UTC) if now is None else _aware_utc(
            now,
            label="Benchmark registry activation time",
        )
        verify_benchmark_measurement_registry_distribution_bundle(
            bundle,
            trust_anchor=trust_anchor,
            now=activated_at,
        )
        statement = bundle.statement
        registry = statement.registry
        activation = BenchmarkMeasurementRegistryActivation(
            trustAnchorDigest=trust_anchor.anchor_digest,
            bundleDigest=bundle.bundle_digest,
            bundle=bundle,
            activatedAt=activated_at,
        )
        try:
            with _activation_write_transaction(self.path) as connection:
                latest = connection.execute(
                    """
                    SELECT * FROM activations
                    WHERE trust_domain = ? AND issuer = ? AND registry_id = ?
                    ORDER BY revision DESC LIMIT 1
                    """,
                    (statement.trust_domain, statement.issuer, registry.registry_id),
                ).fetchone()
                if latest is None:
                    if registry.registry_revision != 1:
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry activation cannot bootstrap after revision one"
                        )
                else:
                    previous = _activation_from_row(latest)
                    previous_statement = previous.bundle.statement
                    previous_registry = previous_statement.registry
                    if previous.trust_anchor_digest != trust_anchor.anchor_digest:
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry distribution Trust Anchor changed without authority"
                        )
                    if registry.registry_revision == previous_registry.registry_revision:
                        if activation.bundle_digest == previous.bundle_digest:
                            return previous.model_copy(deep=True)
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry revision equivocated"
                        )
                    if registry.registry_revision <= previous_registry.registry_revision:
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry activation rollback is forbidden"
                        )
                    if registry.registry_revision != previous_registry.registry_revision + 1:
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry activation gap is forbidden"
                        )
                    if (
                        statement.previous_bundle_digest != previous.bundle_digest
                        or registry.previous_registry_digest != previous_registry.registry_digest
                        or statement.predecessor_registry != previous_registry
                    ):
                        raise BenchmarkMeasurementRegistryDistributionError(
                            "Benchmark registry activation predecessor differs from durable head"
                        )
                connection.execute(
                    """
                    INSERT INTO activations(
                        trust_domain, issuer, registry_id, revision, bundle_digest,
                        registry_digest, trust_anchor_digest, activation_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        statement.trust_domain,
                        statement.issuer,
                        registry.registry_id,
                        registry.registry_revision,
                        activation.bundle_digest,
                        registry.registry_digest,
                        activation.trust_anchor_digest,
                        activation.model_dump_json(by_alias=True),
                    ),
                )
        except sqlite3.Error as exc:
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry activation checkpoint write failed"
            ) from exc
        return activation.model_copy(deep=True)

    def latest(
        self,
        *,
        trust_domain: str,
        issuer: str,
        registry_id: str,
    ) -> BenchmarkMeasurementRegistryActivation | None:
        try:
            with _activation_read_transaction(self.path) as connection:
                row = connection.execute(
                    """
                    SELECT * FROM activations
                    WHERE trust_domain = ? AND issuer = ? AND registry_id = ?
                    ORDER BY revision DESC LIMIT 1
                    """,
                    (trust_domain, issuer, registry_id),
                ).fetchone()
        except sqlite3.Error as exc:
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry activation checkpoint read failed"
            ) from exc
        if row is None:
            return None
        return _activation_from_row(row)


def benchmark_measurement_registry_distribution_public_key_base64url(
    private_key: bytes,
) -> str:
    """Derive the raw public key used only in non-secret test/offline setup."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 registry distribution private key must contain 32 bytes")
    public = Ed25519PrivateKey.from_private_bytes(private_key).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return _encode_base64url(public)


def _activation_from_row(row: sqlite3.Row) -> BenchmarkMeasurementRegistryActivation:
    try:
        activation = BenchmarkMeasurementRegistryActivation.model_validate_json(
            str(row["activation_json"])
        )
    except ValueError as exc:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation checkpoint content is invalid"
        ) from exc
    statement = activation.bundle.statement
    registry = statement.registry
    if (
        str(row["trust_domain"]) != statement.trust_domain
        or str(row["issuer"]) != statement.issuer
        or str(row["registry_id"]) != registry.registry_id
        or int(row["revision"]) != registry.registry_revision
        or str(row["bundle_digest"]) != activation.bundle_digest
        or str(row["registry_digest"]) != registry.registry_digest
        or str(row["trust_anchor_digest"]) != activation.trust_anchor_digest
    ):
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation row differs from its content"
        )
    return activation


def _statement_bytes(statement: BenchmarkMeasurementRegistryDistributionStatement) -> bytes:
    return canonical_benchmark_json(
        statement.model_dump(mode="json", by_alias=True),
        label="Benchmark registry distribution statement",
        max_bytes=_MAX_BUNDLE_BYTES,
    )


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_base64url(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + "=" * (-len(value) % 4),
            altchars=b"-_",
            validate=True,
        )
    except (ValueError, UnicodeEncodeError) as exc:
        raise ValueError(f"{label} is not canonical base64url") from exc
    if len(decoded) != expected_length or _encode_base64url(decoded) != value:
        raise ValueError(f"{label} length or encoding differs")
    return decoded


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} requires UTC offset")
    return value.astimezone(UTC)


def _initialize_activation_store(path: Path) -> None:
    _require_safe_activation_path(path)
    _require_safe_activation_sidecars(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _require_safe_activation_path(path)
    connection: sqlite3.Connection | None = None
    try:
        connection = _open_activation_write_connection(path)
        mode = connection.execute("PRAGMA journal_mode = DELETE").fetchone()
        if mode is None or str(mode[0]).lower() != "delete":
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry activation journal mode differs"
            )
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS activations (
                trust_domain TEXT NOT NULL,
                issuer TEXT NOT NULL,
                registry_id TEXT NOT NULL,
                revision INTEGER NOT NULL CHECK(revision >= 1),
                bundle_digest TEXT NOT NULL UNIQUE,
                registry_digest TEXT NOT NULL,
                trust_anchor_digest TEXT NOT NULL,
                activation_json TEXT NOT NULL,
                PRIMARY KEY(trust_domain, issuer, registry_id, revision)
            );
            CREATE TRIGGER IF NOT EXISTS activations_no_update
            BEFORE UPDATE ON activations
            BEGIN SELECT RAISE(ABORT, 'activations is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS activations_no_delete
            BEFORE DELETE ON activations
            BEGIN SELECT RAISE(ABORT, 'activations is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS activations_no_replace
            BEFORE INSERT ON activations
            WHEN EXISTS (
                SELECT 1 FROM activations
                WHERE (trust_domain = NEW.trust_domain AND issuer = NEW.issuer
                       AND registry_id = NEW.registry_id AND revision = NEW.revision)
                   OR bundle_digest = NEW.bundle_digest
            )
            BEGIN SELECT RAISE(ABORT, 'activations is append-only'); END;
            """
        )
        connection.commit()
        path.chmod(0o600)
        _require_activation_triggers(connection)
        _require_safe_activation_path(path)
        _require_safe_activation_sidecars(path)
    except sqlite3.Error as exc:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation checkpoint could not initialize"
        ) from exc
    finally:
        if connection is not None:
            connection.close()


def _require_activation_triggers(connection: sqlite3.Connection) -> None:
    rows = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'activations'"
    ).fetchall()
    expected = {"activations_no_update", "activations_no_delete", "activations_no_replace"}
    if {str(row[0]) for row in rows} != expected:
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation append-only guards differ"
        )


def _require_safe_activation_path(path: Path) -> None:
    parent = path.parent
    if any(
        ancestor.exists() and (ancestor.is_symlink() or ancestor.is_junction())
        for ancestor in (parent, *parent.parents)
    ):
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation ancestor is unsafe"
        )
    if parent.exists() and not parent.is_dir():
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation parent is unsafe"
        )
    if (path.exists() or path.is_symlink() or path.is_junction()) and (
        not path.is_file()
        or path.is_symlink()
        or path.is_junction()
        or path.stat().st_nlink != 1
    ):
        raise BenchmarkMeasurementRegistryDistributionError(
            "Benchmark registry activation store is not a single-link regular file"
        )


def _require_safe_activation_sidecars(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not (sidecar.exists() or sidecar.is_symlink() or sidecar.is_junction()):
            continue
        if (
            not sidecar.is_file()
            or sidecar.is_symlink()
            or sidecar.is_junction()
            or sidecar.stat().st_nlink != 1
        ):
            raise BenchmarkMeasurementRegistryDistributionError(
                "Benchmark registry activation sidecar is unsafe"
            )


@contextmanager
def _activation_write_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_activation_path(path)
    _require_safe_activation_sidecars(path)
    connection = _open_activation_write_connection(path)
    try:
        _require_activation_triggers(connection)
        connection.execute("BEGIN IMMEDIATE")
        yield connection
        connection.commit()
    except BaseException:
        connection.rollback()
        raise
    finally:
        connection.close()
        _require_safe_activation_path(path)
        _require_safe_activation_sidecars(path)


@contextmanager
def _activation_read_transaction(path: Path) -> Iterator[sqlite3.Connection]:
    _require_safe_activation_path(path)
    _require_safe_activation_sidecars(path)
    connection = sqlite3.connect(
        f"file:{path.as_posix()}?mode=ro",
        uri=True,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA query_only = ON")
    _require_activation_triggers(connection)
    connection.execute("BEGIN")
    try:
        yield connection
    finally:
        connection.rollback()
        connection.close()
        _require_safe_activation_path(path)
        _require_safe_activation_sidecars(path)


def _open_activation_write_connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(
        path,
        isolation_level=None,
        timeout=_BUSY_TIMEOUT_MS / 1_000,
    )
    connection.row_factory = sqlite3.Row
    connection.execute(f"PRAGMA busy_timeout = {_BUSY_TIMEOUT_MS}")
    connection.execute("PRAGMA synchronous = FULL")
    return connection
