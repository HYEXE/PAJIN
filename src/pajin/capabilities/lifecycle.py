"""Signed review and maturity lifecycle for exact code-backed Capabilities."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Annotated, ClassVar, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ConfigDict, Field, ValidationError, model_validator

from pajin.capabilities.authorities import (
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CodeBackedCapability,
    CodeBackedCapabilityRef,
)
from pajin.capabilities.models import (
    CapabilityDefinitionError,
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    canonical_capability_json,
    capability_definition_digest,
)
from pajin.domain.models import StrictModel

CAPABILITY_LIFECYCLE_POLICY_API_VERSION: Literal[
    "pajin.dev/capability-lifecycle-policy/v1alpha1"
] = "pajin.dev/capability-lifecycle-policy/v1alpha1"
CAPABILITY_REVIEW_API_VERSION: Literal["pajin.dev/capability-review/v1alpha1"] = (
    "pajin.dev/capability-review/v1alpha1"
)
CAPABILITY_RELEASE_API_VERSION: Literal["pajin.dev/capability-release/v1alpha1"] = (
    "pajin.dev/capability-release/v1alpha1"
)
CAPABILITY_TRUST_KEY_API_VERSION: Literal["pajin.dev/capability-lifecycle-trust-key/v1alpha1"] = (
    "pajin.dev/capability-lifecycle-trust-key/v1alpha1"
)

_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"),
]
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_RELEASE_ID_PATTERN = r"^capability-release_[a-f0-9]{64}$"
_REVIEW_SIGNATURE_DOMAIN = b"pajin.capability.review-signature/v1\0"
_RELEASE_SIGNATURE_DOMAIN = b"pajin.capability.release-signature/v1\0"


class CapabilityLifecycleError(ValueError):
    """Raised when signed Capability lifecycle authority cannot be trusted."""


class CapabilityLifecycleKeyRole(StrEnum):
    """Trust role granted to one out-of-band Ed25519 public key."""

    PUBLISHER = "publisher"
    REVIEWER = "reviewer"


class CapabilityLifecycleKeyState(StrEnum):
    """Lifecycle state for a trusted signing or review key."""

    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class CapabilityReviewDecision(StrEnum):
    """Bounded review result signed by one reviewer principal."""

    APPROVED = "approved"
    REJECTED = "rejected"


class CapabilityUseProfile(StrEnum):
    """Execution profile whose admission depends on signed maturity."""

    RANGE = "range"
    CANARY = "canary"
    PENTEST = "pentest"
    BUG_HUNT = "bug-hunt"
    CTF = "ctf"


def _require_aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty base64url")
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class CapabilityMaturityApproval(StrictModel):
    """Required distinct approvals for one target maturity."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    maturity: CapabilityMaturity
    required_approvals: int = Field(alias="requiredApprovals", strict=True, ge=0, le=8)


class CapabilityLifecyclePolicy(StrictModel):
    """Content-addressed review quorum policy for Capability releases."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-lifecycle-policy/v1alpha1"] = Field(
        default=CAPABILITY_LIFECYCLE_POLICY_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityLifecyclePolicy"] = "CapabilityLifecyclePolicy"
    policy_id: _Identifier = Field(alias="policyId")
    publisher_reviewer_separation: Literal[True] = Field(
        default=True,
        alias="publisherReviewerSeparation",
    )
    approvals: tuple[CapabilityMaturityApproval, ...] = Field(
        min_length=len(CapabilityMaturity),
        max_length=len(CapabilityMaturity),
    )

    @model_validator(mode="after")
    def require_safe_complete_policy(self) -> Self:
        maturities = [approval.maturity.value for approval in self.approvals]
        expected = sorted(maturity.value for maturity in CapabilityMaturity)
        if maturities != expected:
            raise ValueError("Capability lifecycle approvals must cover every maturity once")
        minimums = {
            CapabilityMaturity.EXPERIMENTAL: 1,
            CapabilityMaturity.CANARY: 1,
            CapabilityMaturity.STABLE: 2,
            CapabilityMaturity.DEPRECATED: 1,
            CapabilityMaturity.RETIRED: 0,
        }
        for approval in self.approvals:
            if approval.required_approvals < minimums[approval.maturity]:
                raise ValueError(
                    f"{approval.maturity.value} approval quorum is below the safe minimum"
                )
        return self

    @property
    def digest(self) -> str:
        """Return the exact policy identity embedded in signed releases."""

        return capability_definition_digest(
            "pajin.capability.lifecycle-policy/v1",
            self.model_dump(mode="json", by_alias=True),
        )

    def approvals_for(self, maturity: CapabilityMaturity) -> int:
        """Return the exact distinct-reviewer quorum for one maturity."""

        return next(
            approval.required_approvals
            for approval in self.approvals
            if approval.maturity is maturity
        )

    @classmethod
    def reference_policy(cls) -> CapabilityLifecyclePolicy:
        """Build the conservative CAP-004 reference policy."""

        return cls(
            policyId="pajin.reference-capability-lifecycle",
            approvals=tuple(
                CapabilityMaturityApproval(
                    maturity=maturity,
                    requiredApprovals=required,
                )
                for maturity, required in sorted(
                    (
                        (CapabilityMaturity.EXPERIMENTAL, 1),
                        (CapabilityMaturity.CANARY, 1),
                        (CapabilityMaturity.STABLE, 2),
                        (CapabilityMaturity.DEPRECATED, 1),
                        (CapabilityMaturity.RETIRED, 0),
                    ),
                    key=lambda item: item[0].value,
                )
            ),
        )


class CapabilityLifecycleTrustKey(StrictModel):
    """One out-of-band trusted Ed25519 key and its principal role."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-lifecycle-trust-key/v1alpha1"] = Field(
        default=CAPABILITY_TRUST_KEY_API_VERSION, alias="apiVersion"
    )
    kind: Literal["CapabilityLifecycleTrustKey"] = "CapabilityLifecycleTrustKey"
    key_id: _Identifier = Field(alias="keyId")
    principal_id: _Identifier = Field(alias="principalId")
    role: CapabilityLifecycleKeyRole
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: str = Field(
        alias="publicKeyBase64url",
        pattern=r"^[A-Za-z0-9_-]{43}$",
    )
    state: CapabilityLifecycleKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def require_valid_key_lifecycle(self) -> Self:
        _base64url_decode(
            self.public_key_base64url,
            expected_length=32,
            label="Capability lifecycle public key",
        )
        not_before = _require_aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _require_aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("Capability lifecycle key validity window is empty")
        if self.state is CapabilityLifecycleKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired Capability lifecycle key requires notAfter")
        if self.state is CapabilityLifecycleKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked Capability lifecycle key requires revokedAt")
            _require_aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked Capability lifecycle key cannot have revokedAt")
        return self


class CapabilityReviewStatement(StrictModel):
    """Exact lifecycle proposal and checklist decision signed by a reviewer."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-review/v1alpha1"] = Field(
        default=CAPABILITY_REVIEW_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityReview"] = "CapabilityReview"
    review_id: str = Field(default="", alias="reviewId", max_length=82)
    review_digest: str = Field(default="", alias="reviewDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    target_maturity: CapabilityMaturity = Field(alias="targetMaturity")
    sequence: int = Field(strict=True, ge=1)
    previous_release_digest: _Sha256 | None = Field(
        default=None,
        alias="previousReleaseDigest",
    )
    policy_digest: _Sha256 = Field(alias="policyDigest")
    reviewer_principal_id: _Identifier = Field(alias="reviewerPrincipalId")
    checklist_digest: _Sha256 = Field(alias="checklistDigest")
    decision: CapabilityReviewDecision
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")

    @model_validator(mode="after")
    def bind_review_identity(self) -> Self:
        issued_at = _require_aware_utc(self.issued_at, label="review issue time")
        expires_at = _require_aware_utc(self.expires_at, label="review expiry time")
        if expires_at <= issued_at:
            raise ValueError("Capability review validity window is empty")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"review_id", "review_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.review/v1",
            material,
        )
        review_id = f"capability-review_{digest}"
        if self.review_digest and self.review_digest != digest:
            raise ValueError("Capability review digest differs from canonical identity")
        if self.review_id and self.review_id != review_id:
            raise ValueError("Capability review ID differs from canonical identity")
        object.__setattr__(self, "review_digest", digest)
        object.__setattr__(self, "review_id", review_id)
        return self


class SignedCapabilityReview(StrictModel):
    """Detached Ed25519 signature over one exact review statement."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: _Identifier = Field(alias="keyId")
    statement: CapabilityReviewStatement
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_signature(self) -> Self:
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Capability review signature",
        )
        return self


class CapabilityDeprecationNotice(StrictModel):
    """Explicit removal notice attached to deprecated or retired releases."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    reason_code: _Identifier = Field(alias="reasonCode")
    summary: str = Field(min_length=1, max_length=1_000)
    announced_at: datetime = Field(alias="announcedAt")
    effective_at: datetime = Field(alias="effectiveAt")
    replacement: CodeBackedCapabilityRef | None = None

    @model_validator(mode="after")
    def require_ordered_notice(self) -> Self:
        announced_at = _require_aware_utc(
            self.announced_at,
            label="deprecation announcement time",
        )
        effective_at = _require_aware_utc(
            self.effective_at,
            label="deprecation effective time",
        )
        if effective_at < announced_at:
            raise ValueError("Capability deprecation predates its announcement")
        return self


class CapabilityReleaseStatement(StrictModel):
    """Publisher-signed activation of one reviewed immutable Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/capability-release/v1alpha1"] = Field(
        default=CAPABILITY_RELEASE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CapabilityRelease"] = "CapabilityRelease"
    release_id: str = Field(default="", alias="releaseId", max_length=83)
    release_digest: str = Field(default="", alias="releaseDigest", max_length=64)
    capability: CodeBackedCapabilityRef
    maturity: CapabilityMaturity
    sequence: int = Field(strict=True, ge=1)
    previous_release_digest: _Sha256 | None = Field(
        default=None,
        alias="previousReleaseDigest",
    )
    policy_digest: _Sha256 = Field(alias="policyDigest")
    review_digests: tuple[_Sha256, ...] = Field(alias="reviewDigests", max_length=8)
    publisher_principal_id: _Identifier = Field(alias="publisherPrincipalId")
    issued_at: datetime = Field(alias="issuedAt")
    deprecation: CapabilityDeprecationNotice | None = None

    @model_validator(mode="after")
    def bind_release_identity(self) -> Self:
        _require_aware_utc(self.issued_at, label="release issue time")
        if self.review_digests != tuple(sorted(set(self.review_digests))):
            raise ValueError("Capability release review digests must be unique and sorted")
        requires_notice = self.maturity in {
            CapabilityMaturity.DEPRECATED,
            CapabilityMaturity.RETIRED,
        }
        if requires_notice != (self.deprecation is not None):
            raise ValueError(
                "Capability deprecation notice must exist only for deprecated or retired maturity"
            )
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"release_id", "release_digest"},
        )
        digest = capability_definition_digest(
            "pajin.capability.release/v1",
            material,
        )
        release_id = f"capability-release_{digest}"
        if self.release_digest and self.release_digest != digest:
            raise ValueError("Capability release digest differs from canonical identity")
        if self.release_id and self.release_id != release_id:
            raise ValueError("Capability release ID differs from canonical identity")
        object.__setattr__(self, "release_digest", digest)
        object.__setattr__(self, "release_id", release_id)
        return self

    def reference(self) -> CapabilityReleaseRef:
        """Return the exact content-addressed release identity."""

        return CapabilityReleaseRef(
            releaseId=self.release_id,
            releaseDigest=self.release_digest,
        )


class CapabilityReleaseRef(StrictModel):
    """Exact release lookup that never implies a latest version."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release_id: str = Field(alias="releaseId", pattern=_RELEASE_ID_PATTERN)
    release_digest: _Sha256 = Field(alias="releaseDigest")


class SignedCapabilityRelease(StrictModel):
    """Detached publisher signature over one exact release statement."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: _Identifier = Field(alias="keyId")
    statement: CapabilityReleaseStatement
    signature_base64url: str = Field(
        alias="signatureBase64url",
        pattern=r"^[A-Za-z0-9_-]{86}$",
    )

    @model_validator(mode="after")
    def require_canonical_signature(self) -> Self:
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Capability release signature",
        )
        return self


class CapabilityReleaseBundle(StrictModel):
    """One signed release plus its exact signed review authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: SignedCapabilityRelease
    reviews: tuple[SignedCapabilityReview, ...] = Field(max_length=8)

    @model_validator(mode="after")
    def require_exact_review_set(self) -> Self:
        review_digests = tuple(review.statement.review_digest for review in self.reviews)
        if review_digests != tuple(sorted(set(review_digests))):
            raise ValueError("Capability release reviews must be unique and digest-sorted")
        if review_digests != self.release.statement.review_digests:
            raise ValueError("Capability release review set differs from signed authority")
        return self


class ResolvedCapabilityRelease(StrictModel):
    """Admission result for one exact signed release and usage profile."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    release: CapabilityReleaseRef
    capability: CodeBackedCapability
    maturity: CapabilityMaturity
    profile: CapabilityUseProfile


def capability_lifecycle_public_key(private_key: bytes) -> str:
    """Derive a canonical Ed25519 public key from a raw 32-byte seed."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 Capability lifecycle private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _base64url_encode(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


@dataclass(frozen=True, slots=True)
class CapabilityLifecycleSigner:
    """Sign review or release statements with one configured active key."""

    key: CapabilityLifecycleTrustKey
    private_key: Ed25519PrivateKey

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        key: CapabilityLifecycleTrustKey,
        private_key: bytes,
    ) -> CapabilityLifecycleSigner:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Capability lifecycle private key must contain 32 bytes")
        return cls(
            key=key,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
        )

    def __post_init__(self) -> None:
        try:
            canonical_key = CapabilityLifecycleTrustKey.model_validate(
                self.key.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ValueError("Capability lifecycle signer key is not canonical") from exc
        object.__setattr__(self, "key", canonical_key)
        if self.key.state is not CapabilityLifecycleKeyState.ACTIVE:
            raise ValueError("Capability lifecycle signer requires an active key")
        public_bytes = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            self.key.public_key_base64url,
            expected_length=32,
            label="Capability lifecycle signer public key",
        )
        if public_bytes != expected:
            raise ValueError("Capability lifecycle private key does not match its trust key")

    def sign_review(self, statement: CapabilityReviewStatement) -> SignedCapabilityReview:
        """Sign one review owned by this reviewer principal."""

        try:
            statement = CapabilityReviewStatement.model_validate(
                statement.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ValueError("Capability review statement is not canonical") from exc
        if self.key.role is not CapabilityLifecycleKeyRole.REVIEWER:
            raise ValueError("Capability review requires a reviewer key")
        if statement.reviewer_principal_id != self.key.principal_id:
            raise ValueError("Capability review belongs to another reviewer principal")
        self._require_valid_at(statement.issued_at)
        return SignedCapabilityReview(
            keyId=self.key.key_id,
            statement=statement,
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_REVIEW_SIGNATURE_DOMAIN + _canonical_review(statement))
            ),
        )

    def sign_release(
        self,
        statement: CapabilityReleaseStatement,
    ) -> SignedCapabilityRelease:
        """Sign one release owned by this publisher principal."""

        try:
            statement = CapabilityReleaseStatement.model_validate(
                statement.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise ValueError("Capability release statement is not canonical") from exc
        if self.key.role is not CapabilityLifecycleKeyRole.PUBLISHER:
            raise ValueError("Capability release requires a publisher key")
        if statement.publisher_principal_id != self.key.principal_id:
            raise ValueError("Capability release belongs to another publisher principal")
        self._require_valid_at(statement.issued_at)
        return SignedCapabilityRelease(
            keyId=self.key.key_id,
            statement=statement,
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_RELEASE_SIGNATURE_DOMAIN + _canonical_release(statement))
            ),
        )

    def _require_valid_at(self, issued_at: datetime) -> None:
        issued = _require_aware_utc(issued_at, label="signed statement issue time")
        not_before = _require_aware_utc(self.key.not_before, label="key not-before time")
        if issued < not_before or (
            self.key.not_after is not None
            and issued >= _require_aware_utc(self.key.not_after, label="key not-after time")
        ):
            raise ValueError("Capability lifecycle signing key is invalid at issue time")


class CapabilityLifecycleRegistry:
    """Verified in-memory registry for immutable signed Capability release chains."""

    _ALLOWED_TRANSITIONS: ClassVar[dict[CapabilityMaturity, frozenset[CapabilityMaturity]]] = {
        CapabilityMaturity.EXPERIMENTAL: frozenset(
            {
                CapabilityMaturity.EXPERIMENTAL,
                CapabilityMaturity.CANARY,
                CapabilityMaturity.RETIRED,
            }
        ),
        CapabilityMaturity.CANARY: frozenset(
            {
                CapabilityMaturity.CANARY,
                CapabilityMaturity.STABLE,
                CapabilityMaturity.DEPRECATED,
                CapabilityMaturity.RETIRED,
            }
        ),
        CapabilityMaturity.STABLE: frozenset(
            {
                CapabilityMaturity.STABLE,
                CapabilityMaturity.DEPRECATED,
                CapabilityMaturity.RETIRED,
            }
        ),
        CapabilityMaturity.DEPRECATED: frozenset(
            {
                CapabilityMaturity.DEPRECATED,
                CapabilityMaturity.RETIRED,
            }
        ),
        CapabilityMaturity.RETIRED: frozenset(),
    }
    _ALLOWED_PROFILES: ClassVar[dict[CapabilityMaturity, frozenset[CapabilityUseProfile]]] = {
        CapabilityMaturity.EXPERIMENTAL: frozenset({CapabilityUseProfile.RANGE}),
        CapabilityMaturity.CANARY: frozenset(
            {
                CapabilityUseProfile.RANGE,
                CapabilityUseProfile.CANARY,
            }
        ),
        CapabilityMaturity.STABLE: frozenset(CapabilityUseProfile),
        CapabilityMaturity.DEPRECATED: frozenset(),
        CapabilityMaturity.RETIRED: frozenset(),
    }

    def __init__(
        self,
        *,
        definitions: CapabilityDefinitionRegistry,
        authorities: CapabilityAuthorityRegistry,
        policy: CapabilityLifecyclePolicy,
        trust_keys: Iterable[CapabilityLifecycleTrustKey],
        releases: Iterable[CapabilityReleaseBundle],
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        if not isinstance(definitions, CapabilityDefinitionRegistry):
            raise TypeError("Capability lifecycle requires a CapabilityDefinitionRegistry")
        if not isinstance(authorities, CapabilityAuthorityRegistry):
            raise TypeError("Capability lifecycle requires a CapabilityAuthorityRegistry")
        if not isinstance(policy, CapabilityLifecyclePolicy):
            raise TypeError("Capability lifecycle requires a CapabilityLifecyclePolicy")
        try:
            policy = CapabilityLifecyclePolicy.model_validate(
                policy.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError) as exc:
            raise CapabilityLifecycleError("Capability lifecycle policy is not canonical") from exc
        keys = self._build_keyring(trust_keys)

        now = _require_aware_utc(clock(), label="Capability lifecycle clock")
        bundles_by_release: dict[tuple[str, str], CapabilityReleaseBundle] = {}
        grouped: dict[str, list[CapabilityReleaseBundle]] = {}
        for raw_bundle in releases:
            try:
                bundle = CapabilityReleaseBundle.model_validate(
                    raw_bundle.model_dump(mode="json", by_alias=True)
                )
            except (AttributeError, ValidationError) as exc:
                raise CapabilityLifecycleError(
                    "Capability release bundle is not canonical"
                ) from exc
            release = bundle.release.statement
            release_key = (release.release_id, release.release_digest)
            if release_key in bundles_by_release:
                raise CapabilityLifecycleError("Capability release is duplicated")
            self._verify_bundle(
                bundle,
                definitions=definitions,
                authorities=authorities,
                policy=policy,
                keys=keys,
                now=now,
            )
            bundles_by_release[release_key] = bundle.model_copy(deep=True)
            grouped.setdefault(release.capability.capability.capability_id, []).append(bundle)
        if not bundles_by_release:
            raise CapabilityLifecycleError("Capability lifecycle releases are empty")

        heads: dict[str, CapabilityReleaseRef] = {}
        for capability_id, bundles in grouped.items():
            ordered = sorted(bundles, key=lambda item: item.release.statement.sequence)
            self._verify_chain(capability_id, ordered)
            heads[capability_id] = ordered[-1].release.statement.reference()

        self._definitions = definitions
        self._authorities = authorities
        self._policy = policy
        self._keys = keys
        self._bundles = bundles_by_release
        self._heads = heads

    @staticmethod
    def _build_keyring(
        trust_keys: Iterable[CapabilityLifecycleTrustKey],
    ) -> dict[str, CapabilityLifecycleTrustKey]:
        keys: dict[str, CapabilityLifecycleTrustKey] = {}
        active_principals: set[tuple[str, CapabilityLifecycleKeyRole]] = set()
        for raw_key in trust_keys:
            try:
                key = CapabilityLifecycleTrustKey.model_validate(
                    raw_key.model_dump(mode="json", by_alias=True)
                )
            except (AttributeError, ValidationError) as exc:
                raise CapabilityLifecycleError(
                    "Capability lifecycle trust key is not canonical"
                ) from exc
            if key.key_id in keys:
                raise CapabilityLifecycleError("Capability lifecycle trust key is duplicated")
            principal_role = (key.principal_id, key.role)
            if (
                key.state is CapabilityLifecycleKeyState.ACTIVE
                and principal_role in active_principals
            ):
                raise CapabilityLifecycleError(
                    "Capability lifecycle principal has more than one active key per role"
                )
            if key.state is CapabilityLifecycleKeyState.ACTIVE:
                active_principals.add(principal_role)
            keys[key.key_id] = key
        if not keys:
            raise CapabilityLifecycleError("Capability lifecycle trust keys are empty")
        return keys

    def resolve_release(self, reference: CapabilityReleaseRef) -> CapabilityReleaseBundle:
        """Inspect one exact historical release without granting execution authority."""

        try:
            bundle = self._bundles[(reference.release_id, reference.release_digest)]
        except KeyError as exc:
            raise CapabilityLifecycleError("Capability release is not registered") from exc
        return bundle.model_copy(deep=True)

    def resolve_for_use(
        self,
        reference: CapabilityReleaseRef,
        profile: CapabilityUseProfile,
    ) -> ResolvedCapabilityRelease:
        """Admit only the exact current release allowed by signed maturity."""

        bundle = self.resolve_release(reference)
        release = bundle.release.statement
        if self._heads[release.capability.capability.capability_id] != reference:
            raise CapabilityLifecycleError(
                "historical Capability release cannot grant new execution authority"
            )
        requested_profile = CapabilityUseProfile(profile)
        if requested_profile not in self._ALLOWED_PROFILES[release.maturity]:
            raise CapabilityLifecycleError(
                f"{release.maturity.value} Capability cannot run in {requested_profile.value}"
            )
        try:
            capability = self._authorities.resolve(release.capability)
        except CapabilityAuthorityError as exc:
            raise CapabilityLifecycleError(
                "Capability code authority drifted after lifecycle registration"
            ) from exc
        return ResolvedCapabilityRelease(
            release=reference,
            capability=capability,
            maturity=release.maturity,
            profile=requested_profile,
        )

    def head(self, capability_id: str) -> CapabilityReleaseRef:
        """Return an explicit head reference for management, never implicit execution."""

        try:
            return self._heads[capability_id].model_copy(deep=True)
        except KeyError as exc:
            raise CapabilityLifecycleError("Capability lifecycle chain is not registered") from exc

    @classmethod
    def _verify_bundle(
        cls,
        bundle: CapabilityReleaseBundle,
        *,
        definitions: CapabilityDefinitionRegistry,
        authorities: CapabilityAuthorityRegistry,
        policy: CapabilityLifecyclePolicy,
        keys: dict[str, CapabilityLifecycleTrustKey],
        now: datetime,
    ) -> None:
        release = bundle.release.statement
        if release.policy_digest != policy.digest:
            raise CapabilityLifecycleError("Capability release uses another review policy")
        if _require_aware_utc(release.issued_at, label="release issue time") > now:
            raise CapabilityLifecycleError("Capability release is future-dated")
        try:
            definition = definitions.resolve(release.capability.capability)
            authorities.resolve(release.capability)
        except (CapabilityDefinitionError, CapabilityAuthorityError) as exc:
            raise CapabilityLifecycleError(
                "Capability release references unregistered immutable authority"
            ) from exc
        if definition.maturity is not release.maturity:
            raise CapabilityLifecycleError(
                "Capability definition maturity differs from its signed release"
            )
        cls._verify_signature(
            key_id=bundle.release.key_id,
            principal_id=release.publisher_principal_id,
            role=CapabilityLifecycleKeyRole.PUBLISHER,
            issued_at=release.issued_at,
            canonical=_canonical_release(release),
            signature=bundle.release.signature_base64url,
            domain=_RELEASE_SIGNATURE_DOMAIN,
            keys=keys,
        )

        reviewer_principals: set[str] = set()
        for signed_review in bundle.reviews:
            review = signed_review.statement
            if (
                review.capability != release.capability
                or review.target_maturity is not release.maturity
                or review.sequence != release.sequence
                or review.previous_release_digest != release.previous_release_digest
                or review.policy_digest != release.policy_digest
            ):
                raise CapabilityLifecycleError(
                    "Capability review does not bind the exact release proposal"
                )
            if review.decision is not CapabilityReviewDecision.APPROVED:
                raise CapabilityLifecycleError(
                    "rejected Capability review cannot authorize release"
                )
            if review.reviewer_principal_id == release.publisher_principal_id:
                raise CapabilityLifecycleError("Capability publisher cannot review its own release")
            if review.reviewer_principal_id in reviewer_principals:
                raise CapabilityLifecycleError(
                    "Capability review quorum requires distinct principals"
                )
            reviewer_principals.add(review.reviewer_principal_id)
            review_issued = _require_aware_utc(review.issued_at, label="review issue time")
            release_issued = _require_aware_utc(release.issued_at, label="release issue time")
            review_expires = _require_aware_utc(review.expires_at, label="review expiry time")
            if review_issued > release_issued or release_issued >= review_expires:
                raise CapabilityLifecycleError(
                    "Capability review is not valid at release issue time"
                )
            cls._verify_signature(
                key_id=signed_review.key_id,
                principal_id=review.reviewer_principal_id,
                role=CapabilityLifecycleKeyRole.REVIEWER,
                issued_at=review.issued_at,
                canonical=_canonical_review(review),
                signature=signed_review.signature_base64url,
                domain=_REVIEW_SIGNATURE_DOMAIN,
                keys=keys,
            )
        if len(reviewer_principals) < policy.approvals_for(release.maturity):
            raise CapabilityLifecycleError("Capability release review quorum is not satisfied")

        cls._verify_deprecation(
            release,
            definitions=definitions,
            authorities=authorities,
        )

    @staticmethod
    def _verify_deprecation(
        release: CapabilityReleaseStatement,
        *,
        definitions: CapabilityDefinitionRegistry,
        authorities: CapabilityAuthorityRegistry,
    ) -> None:
        notice = release.deprecation
        if notice is None:
            return
        if _require_aware_utc(
            notice.announced_at,
            label="deprecation announcement time",
        ) > _require_aware_utc(release.issued_at, label="release issue time"):
            raise CapabilityLifecycleError(
                "Capability deprecation was announced after release issue time"
            )
        replacement = notice.replacement
        if replacement is None:
            return
        if replacement == release.capability:
            raise CapabilityLifecycleError(
                "Capability deprecation replacement cannot reference itself"
            )
        try:
            definitions.resolve(replacement.capability)
            authorities.resolve(replacement)
        except (CapabilityDefinitionError, CapabilityAuthorityError) as exc:
            raise CapabilityLifecycleError(
                "Capability deprecation replacement is not registered"
            ) from exc

    @classmethod
    def _verify_chain(
        cls,
        capability_id: str,
        ordered: list[CapabilityReleaseBundle],
    ) -> None:
        previous: CapabilityReleaseStatement | None = None
        for bundle in ordered:
            release = bundle.release.statement
            if release.capability.capability.capability_id != capability_id:
                raise CapabilityLifecycleError("Capability release chain identity changed")
            if previous is None:
                if (
                    release.sequence != 1
                    or release.previous_release_digest is not None
                    or release.maturity is not CapabilityMaturity.EXPERIMENTAL
                ):
                    raise CapabilityLifecycleError(
                        "Capability lifecycle must begin at experimental sequence 1"
                    )
            else:
                if release.sequence != previous.sequence + 1:
                    raise CapabilityLifecycleError("Capability release sequence is not contiguous")
                if release.previous_release_digest != previous.release_digest:
                    raise CapabilityLifecycleError(
                        "Capability release predecessor digest is inconsistent"
                    )
                if release.maturity not in cls._ALLOWED_TRANSITIONS[previous.maturity]:
                    raise CapabilityLifecycleError(
                        f"Capability maturity cannot transition from "
                        f"{previous.maturity.value} to {release.maturity.value}"
                    )
                if release.capability.capability == previous.capability.capability:
                    raise CapabilityLifecycleError(
                        "Capability lifecycle change requires a new immutable definition"
                    )
                if _require_aware_utc(
                    release.issued_at,
                    label="release issue time",
                ) < _require_aware_utc(previous.issued_at, label="release issue time"):
                    raise CapabilityLifecycleError("Capability release issue time moved backwards")
            previous = release

    @staticmethod
    def _verify_signature(
        *,
        key_id: str,
        principal_id: str,
        role: CapabilityLifecycleKeyRole,
        issued_at: datetime,
        canonical: bytes,
        signature: str,
        domain: bytes,
        keys: dict[str, CapabilityLifecycleTrustKey],
    ) -> None:
        key = keys.get(key_id)
        if key is None or key.principal_id != principal_id or key.role is not role:
            raise CapabilityLifecycleError(
                "Capability lifecycle signing key is not trusted for this principal role"
            )
        if key.state is CapabilityLifecycleKeyState.REVOKED:
            raise CapabilityLifecycleError("Capability lifecycle signing key is revoked")
        issued = _require_aware_utc(issued_at, label="signed statement issue time")
        not_before = _require_aware_utc(key.not_before, label="key not-before time")
        if issued < not_before or (
            key.not_after is not None
            and issued >= _require_aware_utc(key.not_after, label="key not-after time")
        ):
            raise CapabilityLifecycleError("Capability lifecycle signature is outside key validity")
        try:
            Ed25519PublicKey.from_public_bytes(
                _base64url_decode(
                    key.public_key_base64url,
                    expected_length=32,
                    label="Capability lifecycle public key",
                )
            ).verify(
                _base64url_decode(
                    signature,
                    expected_length=64,
                    label="Capability lifecycle signature",
                ),
                domain + canonical,
            )
        except InvalidSignature as exc:
            raise CapabilityLifecycleError(
                "Capability lifecycle signature verification failed"
            ) from exc


def _canonical_review(statement: CapabilityReviewStatement) -> bytes:
    return canonical_capability_json(
        statement.model_dump(mode="json", by_alias=True),
        label="CapabilityReview",
    )


def _canonical_release(statement: CapabilityReleaseStatement) -> bytes:
    return canonical_capability_json(
        statement.model_dump(mode="json", by_alias=True),
        label="CapabilityRelease",
    )
