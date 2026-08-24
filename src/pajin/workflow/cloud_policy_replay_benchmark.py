"""CLOUD-001D fresh-credential policy Replay and disposable fixture contract."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from hashlib import sha256
from pathlib import Path, PurePosixPath
from re import fullmatch
from typing import Annotated, Literal, Self

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.benchmark.domain_metrics import (
    DomainBenchmarkPlanRef,
    DomainValidationStrategy,
    registered_domain_benchmark_registry,
    resolve_registered_domain_benchmark_plan,
)
from pajin.benchmark.models import benchmark_digest
from pajin.capabilities.cloud_inventory import (
    CloudReadOnlyInventoryPolicyPreparation,
    CloudReadOnlyOperation,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.domain.security_domain import SecurityDomain
from pajin.graph.approval import ActionApprovalConsumptionReceipt
from pajin.graph.authority import ActionPermit
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.safe_files import parse_strict_json_bytes, read_bounded_regular_bytes
from pajin.workflow.cloud_provider_admission import (
    CloudProviderExecutionKeyState,
    CloudProviderExecutionTrustAnchor,
    CloudProviderObservationAdmission,
    CloudProviderObservationSourceInputs,
    VerifiedCloudProviderObservationSource,
    load_verified_cloud_provider_observation_source,
)

CLOUD_POLICY_ARTIFACT_BUNDLE_API_VERSION: Literal[
    "pajin.dev/cloud-policy-artifact-bundle/v1alpha1"
] = "pajin.dev/cloud-policy-artifact-bundle/v1alpha1"
CLOUD_POLICY_REPLAY_VALIDATION_API_VERSION: Literal[
    "pajin.dev/cloud-policy-replay-validation/v1alpha1"
] = "pajin.dev/cloud-policy-replay-validation/v1alpha1"
CLOUD_POLICY_BENCHMARK_FIXTURE_PROFILE_API_VERSION: Literal[
    "pajin.dev/cloud-policy-benchmark-fixture-profile/v1alpha1"
] = "pajin.dev/cloud-policy-benchmark-fixture-profile/v1alpha1"

_SIGNATURE_DOMAIN = b"pajin.workflow.cloud-policy-sanitized-artifact/v1\0"
_MAX_ARTIFACT_BUNDLE_BYTES = 2 * 1024 * 1024
_MAX_CANONICAL_BYTES = 8 * 1024 * 1024
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]
_Identifier = Annotated[
    str,
    Field(min_length=1, max_length=200, pattern=r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,199}$"),
]
_PolicyCoordinate = Annotated[
    str,
    Field(
        min_length=1,
        max_length=512,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/@=+-]{0,511}$",
    ),
]
_ArtifactPath = Annotated[
    str,
    Field(pattern=r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$"),
]
_ReplayState = Literal[
    "fresh-credential-policy-input-and-decision-match",
    "fresh-credential-policy-input-changed-decision-match",
    "fresh-credential-policy-decision-changed",
]

_REPLAY_TRUE_FIELDS = (
    "sealed_source_reverified",
    "sealed_replay_reverified",
    "source_policy_artifact_verified",
    "replay_policy_artifact_verified",
    "separate_authorization_verified",
    "fresh_credential_lease_verified",
    "deterministic_evaluator_verified",
)
_REPLAY_FALSE_FIELDS = (
    "provider_policy_semantics_confirmed",
    "effective_permission_confirmed",
    "cloud_resource_confirmed",
    "benchmark_ground_truth_bound",
    "negative_control_observed",
    "benchmark_measurement_observed",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "provider_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "credential_use_authorized",
    "provider_invocation_authorized",
    "policy_mutation_authorized",
    "iam_mutation_authorized",
    "target_factory_authority",
    "replay_authorized",
    "execution_authorized",
)
_FIXTURE_TRUE_FIELDS = (
    "private_ground_truth_verified",
    "disposable_environment_required",
    "cleanup_evidence_required",
    "negative_control_registered",
    "fresh_credential_replay_required",
    "deterministic_evaluator_verified",
)
_FIXTURE_FALSE_FIELDS = (
    "target_profile_selected",
    "target_factory_authority",
    "provider_account_provisioned",
    "emulator_provisioned",
    "cleanup_performed",
    "credential_lease_acquired",
    "provider_execution_authorized",
    "fixture_execution_authorized",
    "replay_evidence_bound",
    "benchmark_measurement_observed",
    "detection_quality_established",
    "profile_validation_floor_satisfied",
    "provider_policy_semantics_confirmed",
    "effective_permission_confirmed",
    "finding_authority",
    "scope_expansion_authorized",
    "capability_activation_authorized",
    "approval_authority",
    "permit_issuance_authorized",
    "provider_selection_authorized",
    "worker_selection_authorized",
    "network_access_authorized",
    "credential_access_authorized",
    "credential_use_authorized",
    "replay_authorized",
    "execution_authorized",
)


class CloudPolicyReplayBenchmarkError(RuntimeError):
    """Raised when a CLOUD-001D predecessor or benchmark coordinate differs."""


class CloudPolicyEffect(StrEnum):
    """Provider-neutral effect vocabulary for the bounded evaluator."""

    ALLOW = "allow"
    DENY = "deny"


class CloudPolicyDecision(StrEnum):
    """Closed deterministic result vocabulary; it is not provider confirmation."""

    ALLOW = "allow"
    EXPLICIT_DENY = "explicit-deny"
    IMPLICIT_DENY = "implicit-deny"


class CloudPolicyReplayComparison(StrEnum):
    """Neutral source/replay comparison states."""

    INPUT_AND_DECISION_MATCHED = "policy-input-and-decision-match"
    INPUT_CHANGED_DECISION_MATCHED = "policy-input-changed-decision-match"
    DECISION_CHANGED = "policy-decision-changed"


class CloudPolicyBenchmarkGroundTruthClass(StrEnum):
    """Closed fixture classes for later disposable-environment measurement."""

    KNOWN_ALLOW = "known-allow"
    EXPLICIT_DENY = "explicit-deny"
    NEGATIVE_CONTROL = "negative-control"


class _FrozenStrictModel(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class CloudPolicyExactRule(_FrozenStrictModel):
    """One exact provider-neutral principal/action/resource rule."""

    rule_id: _Identifier = Field(alias="ruleId")
    effect: CloudPolicyEffect
    principal: _PolicyCoordinate
    action: _PolicyCoordinate
    resource: _PolicyCoordinate
    provider_neutral: Literal[True] = Field(default=True, alias="providerNeutral")
    exact_match_only: Literal[True] = Field(default=True, alias="exactMatchOnly")

    @field_validator("provider_neutral", "exact_match_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D policy rule markers must be boolean true")
        return value

    @model_validator(mode="after")
    def reject_pattern_semantics(self) -> Self:
        if any("*" in value for value in (self.principal, self.action, self.resource)):
            raise ValueError("CLOUD-001D policy rules do not support wildcards")
        return self


class CloudPolicyQuery(_FrozenStrictModel):
    """One exact query evaluated without provider access."""

    principal: _PolicyCoordinate
    action: _PolicyCoordinate
    resource: _PolicyCoordinate
    exact_match_only: Literal[True] = Field(default=True, alias="exactMatchOnly")

    @field_validator("exact_match_only", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D policy query marker must be boolean true")
        return value

    @model_validator(mode="after")
    def reject_pattern_semantics(self) -> Self:
        if any("*" in value for value in (self.principal, self.action, self.resource)):
            raise ValueError("CLOUD-001D policy queries do not support wildcards")
        return self


class CloudPolicyEvaluatorRef(_FrozenStrictModel):
    """Content-addressed reference to the code-owned exact-match evaluator."""

    evaluator_id: Literal["pajin.cloud-policy.exact-match-deny-overrides"] = Field(
        default="pajin.cloud-policy.exact-match-deny-overrides",
        alias="evaluatorId",
    )
    evaluator_version: Literal["1.0.0"] = Field(default="1.0.0", alias="evaluatorVersion")
    evaluator_digest: str = Field(default="", alias="evaluatorDigest", max_length=64)
    algorithm: Literal["exact-principal-action-resource-deny-overrides-v1"] = (
        "exact-principal-action-resource-deny-overrides-v1"
    )
    wildcard_support: Literal[False] = Field(default=False, alias="wildcardSupport")
    provider_semantics_imported: Literal[False] = Field(
        default=False,
        alias="providerSemanticsImported",
    )

    @field_validator("wildcard_support", "provider_semantics_imported", mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CLOUD-001D evaluator authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_evaluator_identity(self) -> Self:
        material = self.model_dump(mode="json", by_alias=True, exclude={"evaluator_digest"})
        digest = benchmark_digest(
            "pajin.workflow.cloud-policy-exact-evaluator/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        if self.evaluator_digest and self.evaluator_digest != digest:
            raise ValueError("CLOUD-001D evaluator Digest differs")
        object.__setattr__(self, "evaluator_digest", digest)
        return self


def registered_cloud_policy_evaluator() -> CloudPolicyEvaluatorRef:
    """Return the only evaluator accepted by this contract."""

    return CloudPolicyEvaluatorRef()


class CloudPolicySanitizedArtifact(_FrozenStrictModel):
    """Signed, provider-neutral policy projection bound to one CLOUD-001C admission."""

    api_version: Literal["pajin.dev/cloud-policy-sanitized-artifact/v1alpha1"] = Field(
        default="pajin.dev/cloud-policy-sanitized-artifact/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["CloudPolicySanitizedArtifact"] = "CloudPolicySanitizedArtifact"
    artifact_id: str = Field(default="", alias="artifactId", max_length=110)
    artifact_digest: str = Field(default="", alias="artifactDigest", max_length=64)
    source_admission_id: _Identifier = Field(alias="sourceAdmissionId")
    source_admission_digest: _Sha256 = Field(alias="sourceAdmissionDigest")
    source_execution_id: _Identifier = Field(alias="sourceExecutionId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    response_receipt_sha256: _Sha256 = Field(alias="responseReceiptSha256")
    response_receipt_digest: _Sha256 = Field(alias="responseReceiptDigest")
    response_body_sha256: _Sha256 = Field(alias="responseBodySha256")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    evaluator: CloudPolicyEvaluatorRef
    rules: tuple[CloudPolicyExactRule, ...] = Field(max_length=1_000)
    query: CloudPolicyQuery
    sanitized_at: datetime = Field(alias="sanitizedAt")
    state: Literal["sanitized-provider-derived-policy-not-provider-confirmed"] = (
        "sanitized-provider-derived-policy-not-provider-confirmed"
    )
    deployment_derivation_attested: Literal[True] = Field(
        default=True,
        alias="deploymentDerivationAttested",
    )
    provider_neutral_exact_match: Literal[True] = Field(
        default=True,
        alias="providerNeutralExactMatch",
    )
    raw_provider_response_embedded: Literal[False] = Field(
        default=False,
        alias="rawProviderResponseEmbedded",
    )
    credential_material_embedded: Literal[False] = Field(
        default=False,
        alias="credentialMaterialEmbedded",
    )
    provider_policy_semantics_confirmed: Literal[False] = Field(
        default=False,
        alias="providerPolicySemanticsConfirmed",
    )
    effective_permission_confirmed: Literal[False] = Field(
        default=False,
        alias="effectivePermissionConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("sanitized_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("CLOUD-001D policy artifact time must be timezone-aware")
        return value.astimezone(UTC)

    @field_validator(
        "deployment_derivation_attested",
        "provider_neutral_exact_match",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D policy artifact verified markers must be true")
        return value

    @field_validator(
        "raw_provider_response_embedded",
        "credential_material_embedded",
        "provider_policy_semantics_confirmed",
        "effective_permission_confirmed",
        "finding_authority",
        "credential_use_authorized",
        "provider_invocation_authorized",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CLOUD-001D policy artifact authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_artifact_identity(self) -> Self:
        if self.evaluator != registered_cloud_policy_evaluator():
            raise ValueError("CLOUD-001D policy artifact evaluator is not registered exactly")
        rule_ids = [rule.rule_id for rule in self.rules]
        rule_coordinates = [
            (rule.effect, rule.principal, rule.action, rule.resource) for rule in self.rules
        ]
        if (
            rule_ids != sorted(rule_ids)
            or len(rule_ids) != len(set(rule_ids))
            or len(rule_coordinates) != len(set(rule_coordinates))
        ):
            raise ValueError("CLOUD-001D policy rules must be uniquely sorted")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"artifact_id", "artifact_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cloud-policy-sanitized-artifact/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        artifact_id = f"cloud-policy-artifact_{digest}"
        if self.artifact_digest and self.artifact_digest != digest:
            raise ValueError("CLOUD-001D policy artifact Digest differs")
        if self.artifact_id and self.artifact_id != artifact_id:
            raise ValueError("CLOUD-001D policy artifact ID differs")
        object.__setattr__(self, "artifact_digest", digest)
        object.__setattr__(self, "artifact_id", artifact_id)
        return self


class CloudPolicyArtifactBundle(_FrozenStrictModel):
    """Detached Ed25519 signature over one sanitized policy artifact."""

    api_version: Literal["pajin.dev/cloud-policy-artifact-bundle/v1alpha1"] = Field(
        default=CLOUD_POLICY_ARTIFACT_BUNDLE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudPolicyArtifactBundle"] = "CloudPolicyArtifactBundle"
    algorithm: Literal["Ed25519"] = "Ed25519"
    key_id: _Identifier = Field(alias="keyId")
    artifact: CloudPolicySanitizedArtifact
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")
    signature_base64url: str = Field(alias="signatureBase64url", pattern=r"^[A-Za-z0-9_-]{86}$")

    @model_validator(mode="after")
    def require_canonical_envelope(self) -> Self:
        canonical = _canonical_artifact_bytes(self.artifact)
        if sha256(canonical).hexdigest() != self.artifact_sha256:
            raise ValueError("CLOUD-001D signed artifact digest is inconsistent")
        _base64url_decode(
            self.signature_base64url,
            expected_length=64,
            label="Cloud policy artifact signature",
        )
        return self


class CloudPolicyArtifactVerification(_FrozenStrictModel):
    """Result of verifying one caller-supplied artifact bundle."""

    valid: Literal[True] = True
    key_id: _Identifier = Field(alias="keyId")
    key_state: CloudProviderExecutionKeyState = Field(alias="keyState")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    artifact_sha256: _Sha256 = Field(alias="artifactSha256")
    sanitized_at: datetime = Field(alias="sanitizedAt")

    @field_validator("valid", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D artifact verification marker must be boolean true")
        return value

    @field_validator("sanitized_at")
    @classmethod
    def require_aware_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Cloud policy artifact verification time")


@dataclass(frozen=True, slots=True)
class CloudPolicyArtifactAttestor:
    """Signing helper for deployment-derived policy data; it performs no Cloud call."""

    active_key_id: str
    private_key: Ed25519PrivateKey
    trust_anchor: CloudProviderExecutionTrustAnchor

    @classmethod
    def from_private_key_bytes(
        cls,
        *,
        active_key_id: str,
        private_key: bytes,
        trust_anchor: CloudProviderExecutionTrustAnchor,
    ) -> CloudPolicyArtifactAttestor:
        if len(private_key) != 32:
            raise ValueError("Ed25519 Cloud policy private key must contain 32 bytes")
        return cls(
            active_key_id=active_key_id,
            private_key=Ed25519PrivateKey.from_private_bytes(private_key),
            trust_anchor=trust_anchor,
        )

    def __post_init__(self) -> None:
        matching = [key for key in self.trust_anchor.keys if key.key_id == self.active_key_id]
        if len(matching) != 1 or matching[0].state is not CloudProviderExecutionKeyState.ACTIVE:
            raise ValueError("Cloud policy signer key is not the active trust-anchor key")
        actual = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        expected = _base64url_decode(
            matching[0].public_key_base64url,
            expected_length=32,
            label="Cloud policy active public key",
        )
        if actual != expected:
            raise ValueError("Cloud policy private key does not match its trust anchor")

    def attest(self, artifact: CloudPolicySanitizedArtifact) -> CloudPolicyArtifactBundle:
        canonical_artifact = CloudPolicySanitizedArtifact.model_validate(
            artifact.model_dump(mode="json", by_alias=True)
        )
        if canonical_artifact.trust_anchor_digest != self.trust_anchor.digest:
            raise ValueError("Cloud policy artifact differs from its trust anchor")
        key = next(item for item in self.trust_anchor.keys if item.key_id == self.active_key_id)
        issued_at = canonical_artifact.sanitized_at
        if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
            raise ValueError("Cloud policy signing key is not valid at artifact issue time")
        canonical = _canonical_artifact_bytes(canonical_artifact)
        return CloudPolicyArtifactBundle(
            keyId=self.active_key_id,
            artifact=canonical_artifact,
            artifactSha256=sha256(canonical).hexdigest(),
            signatureBase64url=_base64url_encode(
                self.private_key.sign(_SIGNATURE_DOMAIN + canonical)
            ),
        )


def cloud_policy_artifact_bundle_bytes(bundle: CloudPolicyArtifactBundle) -> bytes:
    """Serialize a readable bundle whose signature covers canonical artifact bytes."""

    return (
        json.dumps(
            bundle.model_dump(mode="json", by_alias=True),
            ensure_ascii=False,
            indent=2,
            allow_nan=False,
        )
        + "\n"
    ).encode("utf-8")


def verify_cloud_policy_artifact_bundle(
    bundle: CloudPolicyArtifactBundle,
    *,
    trust_anchor: CloudProviderExecutionTrustAnchor,
) -> CloudPolicyArtifactVerification:
    """Verify an artifact with deployment-configured trust, never bundle-supplied trust."""

    artifact = bundle.artifact
    if artifact.trust_anchor_digest != trust_anchor.digest:
        raise CloudPolicyReplayBenchmarkError("Cloud policy artifact trust anchor differs")
    key = next((item for item in trust_anchor.keys if item.key_id == bundle.key_id), None)
    if key is None:
        raise CloudPolicyReplayBenchmarkError("Cloud policy signing key is not trusted")
    if key.state is CloudProviderExecutionKeyState.REVOKED:
        raise CloudPolicyReplayBenchmarkError("Cloud policy signing key is revoked")
    issued_at = artifact.sanitized_at
    if issued_at < key.not_before or (key.not_after is not None and issued_at >= key.not_after):
        raise CloudPolicyReplayBenchmarkError("Cloud policy artifact is outside key validity")
    canonical = _canonical_artifact_bytes(artifact)
    public_key = Ed25519PublicKey.from_public_bytes(
        _base64url_decode(
            key.public_key_base64url,
            expected_length=32,
            label="Cloud policy public key",
        )
    )
    try:
        public_key.verify(
            _base64url_decode(
                bundle.signature_base64url,
                expected_length=64,
                label="Cloud policy artifact signature",
            ),
            _SIGNATURE_DOMAIN + canonical,
        )
    except InvalidSignature as exc:
        raise CloudPolicyReplayBenchmarkError(
            "Cloud policy artifact signature verification failed"
        ) from exc
    return CloudPolicyArtifactVerification(
        keyId=key.key_id,
        keyState=key.state,
        trustAnchorDigest=trust_anchor.digest,
        artifactSha256=bundle.artifact_sha256,
        sanitizedAt=artifact.sanitized_at,
    )


def _canonical_artifact_bytes(artifact: CloudPolicySanitizedArtifact) -> bytes:
    return canonical_json_bytes(
        artifact.model_dump(mode="json", by_alias=True),
        label="Cloud policy sanitized artifact",
        max_bytes=_MAX_CANONICAL_BYTES,
    )


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str, *, expected_length: int, label: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{label} must be non-empty base64url")
    padding = "=" * (-len(value) % 4)
    try:
        decoded = base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _base64url_encode(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


class CloudPolicyEvaluation(_FrozenStrictModel):
    """Deterministic result over one sanitized artifact, not an effective permission."""

    evaluation_id: str = Field(default="", alias="evaluationId", max_length=110)
    evaluation_digest: str = Field(default="", alias="evaluationDigest", max_length=64)
    artifact_id: _Identifier = Field(alias="artifactId")
    artifact_digest: _Sha256 = Field(alias="artifactDigest")
    evaluator: CloudPolicyEvaluatorRef
    query: CloudPolicyQuery
    matching_allow_rule_ids: tuple[_Identifier, ...] = Field(alias="matchingAllowRuleIds")
    matching_deny_rule_ids: tuple[_Identifier, ...] = Field(alias="matchingDenyRuleIds")
    decision: CloudPolicyDecision
    deterministic: Literal[True] = True
    provider_effective_permission: Literal[False] = Field(
        default=False,
        alias="providerEffectivePermission",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator("deterministic", mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D evaluation marker must be boolean true")
        return value

    @field_validator(
        "provider_effective_permission",
        "finding_authority",
        "execution_authorized",
        mode="before",
    )
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CLOUD-001D evaluation authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_evaluation_identity(self) -> Self:
        allow_ids = list(self.matching_allow_rule_ids)
        deny_ids = list(self.matching_deny_rule_ids)
        if (
            self.evaluator != registered_cloud_policy_evaluator()
            or allow_ids != sorted(set(allow_ids))
            or deny_ids != sorted(set(deny_ids))
            or set(allow_ids).intersection(deny_ids)
        ):
            raise ValueError("CLOUD-001D evaluation projection is not canonical")
        expected = (
            CloudPolicyDecision.EXPLICIT_DENY
            if deny_ids
            else CloudPolicyDecision.ALLOW
            if allow_ids
            else CloudPolicyDecision.IMPLICIT_DENY
        )
        if self.decision is not expected:
            raise ValueError("CLOUD-001D deny-overrides decision differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"evaluation_id", "evaluation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cloud-policy-evaluation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        evaluation_id = f"cloud-policy-evaluation_{digest}"
        if self.evaluation_digest and self.evaluation_digest != digest:
            raise ValueError("CLOUD-001D evaluation Digest differs")
        if self.evaluation_id and self.evaluation_id != evaluation_id:
            raise ValueError("CLOUD-001D evaluation ID differs")
        object.__setattr__(self, "evaluation_digest", digest)
        object.__setattr__(self, "evaluation_id", evaluation_id)
        return self


def evaluate_cloud_policy_artifact(
    artifact: CloudPolicySanitizedArtifact,
) -> CloudPolicyEvaluation:
    """Evaluate exact coordinates with explicit deny overriding exact allow."""

    canonical = CloudPolicySanitizedArtifact.model_validate(
        artifact.model_dump(mode="json", by_alias=True)
    )
    allow_ids, deny_ids = _matching_rule_ids(canonical.rules, canonical.query)
    decision = (
        CloudPolicyDecision.EXPLICIT_DENY
        if deny_ids
        else CloudPolicyDecision.ALLOW
        if allow_ids
        else CloudPolicyDecision.IMPLICIT_DENY
    )
    return CloudPolicyEvaluation(
        artifactId=canonical.artifact_id,
        artifactDigest=canonical.artifact_digest,
        evaluator=canonical.evaluator,
        query=canonical.query,
        matchingAllowRuleIds=allow_ids,
        matchingDenyRuleIds=deny_ids,
        decision=decision,
    )


def _matching_rule_ids(
    rules: tuple[CloudPolicyExactRule, ...],
    query: CloudPolicyQuery,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    matching = tuple(
        rule
        for rule in rules
        if (rule.principal, rule.action, rule.resource)
        == (query.principal, query.action, query.resource)
    )
    allow_ids = tuple(
        sorted(rule.rule_id for rule in matching if rule.effect is CloudPolicyEffect.ALLOW)
    )
    deny_ids = tuple(
        sorted(rule.rule_id for rule in matching if rule.effect is CloudPolicyEffect.DENY)
    )
    return allow_ids, deny_ids


@dataclass(frozen=True, slots=True)
class CloudPolicyArtifactSourceInputs:
    """Bounded local path to one detached policy artifact bundle."""

    source_root: Path
    artifact_reference: str


@dataclass(frozen=True, slots=True)
class VerifiedCloudPolicyArtifactSource:
    """One signature- and predecessor-verified sanitized policy artifact."""

    artifact_reference: str
    artifact_bundle_sha256: str
    bundle: CloudPolicyArtifactBundle
    verification: CloudPolicyArtifactVerification


class CloudPolicyReplayExecution(_FrozenStrictModel):
    """Safe projection of one CLOUD-001C admission and its policy artifact."""

    admission: CloudProviderObservationAdmission
    preparation: CloudReadOnlyInventoryPolicyPreparation
    action_permit: ActionPermit = Field(alias="actionPermit")
    approval_receipt: ActionApprovalConsumptionReceipt = Field(alias="approvalReceipt")
    source_run_id: _Identifier = Field(alias="sourceRunId")
    source_root_digest: _Sha256 = Field(alias="sourceRootDigest")
    trust_anchor_digest: _Sha256 = Field(alias="trustAnchorDigest")
    statement_sha256: _Sha256 = Field(alias="statementSha256")
    execution_id: _Identifier = Field(alias="executionId")
    response_receipt_reference: _ArtifactPath = Field(alias="responseReceiptReference")
    response_receipt_sha256: _Sha256 = Field(alias="responseReceiptSha256")
    response_receipt_digest: _Sha256 = Field(alias="responseReceiptDigest")
    response_body_sha256: _Sha256 = Field(alias="responseBodySha256")
    policy_artifact_reference: _ArtifactPath = Field(alias="policyArtifactReference")
    policy_artifact_bundle_sha256: _Sha256 = Field(alias="policyArtifactBundleSha256")
    policy_artifact_verification: CloudPolicyArtifactVerification = Field(
        alias="policyArtifactVerification"
    )
    policy_artifact: CloudPolicySanitizedArtifact = Field(alias="policyArtifact")
    evaluation: CloudPolicyEvaluation

    @model_validator(mode="after")
    def bind_execution_projection(self) -> Self:
        candidate = self.admission.candidate
        artifact = self.policy_artifact
        expected_evaluation = evaluate_cloud_policy_artifact(artifact)
        if (
            self.preparation.operation is not CloudReadOnlyOperation.POLICY
            or candidate.preparation != self.preparation
            or candidate.source_run_id != self.source_run_id
            or candidate.source_root_digest != self.source_root_digest
            or candidate.trust_anchor_digest != self.trust_anchor_digest
            or candidate.statement_sha256 != self.statement_sha256
            or candidate.approval_receipt_id != self.approval_receipt.receipt_id
            or candidate.approval_receipt_digest != self.approval_receipt.receipt_digest
            or candidate.response_receipt_reference != self.response_receipt_reference
            or candidate.response_receipt_sha256 != self.response_receipt_sha256
            or candidate.response_receipt_digest != self.response_receipt_digest
            or candidate.response_body_sha256 != self.response_body_sha256
            or self.action_permit != self.approval_receipt.action_permit
            or artifact.source_admission_id != self.admission.admission_id
            or artifact.source_admission_digest != self.admission.admission_digest
            or artifact.source_execution_id != self.execution_id
            or artifact.source_root_digest != self.source_root_digest
            or artifact.statement_sha256 != self.statement_sha256
            or artifact.response_receipt_sha256 != self.response_receipt_sha256
            or artifact.response_receipt_digest != self.response_receipt_digest
            or artifact.response_body_sha256 != self.response_body_sha256
            or artifact.trust_anchor_digest != self.trust_anchor_digest
            or self.policy_artifact_reference == self.response_receipt_reference
            or self.policy_artifact_verification.artifact_sha256
            != sha256(_canonical_artifact_bytes(artifact)).hexdigest()
            or self.policy_artifact_verification.trust_anchor_digest != self.trust_anchor_digest
            or self.evaluation != expected_evaluation
        ):
            raise ValueError("CLOUD-001D execution projection differs from sealed authority")
        return self


class CloudPolicyFreshCredentialReplayValidation(_FrozenStrictModel):
    """Neutral comparison of two separately admitted fresh-credential policy reads."""

    api_version: Literal["pajin.dev/cloud-policy-replay-validation/v1alpha1"] = Field(
        default=CLOUD_POLICY_REPLAY_VALIDATION_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudPolicyFreshCredentialReplayValidation"] = (
        "CloudPolicyFreshCredentialReplayValidation"
    )
    validation_id: str = Field(default="", alias="validationId", max_length=110)
    validation_digest: str = Field(default="", alias="validationDigest", max_length=64)
    source_execution: CloudPolicyReplayExecution = Field(alias="sourceExecution")
    replay_execution: CloudPolicyReplayExecution = Field(alias="replayExecution")
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    comparison: CloudPolicyReplayComparison
    policy_input_matched: bool = Field(alias="policyInputMatched")
    decision_matched: bool = Field(alias="decisionMatched")
    state: _ReplayState
    sealed_source_reverified: Literal[True] = Field(default=True, alias="sealedSourceReverified")
    sealed_replay_reverified: Literal[True] = Field(default=True, alias="sealedReplayReverified")
    source_policy_artifact_verified: Literal[True] = Field(
        default=True,
        alias="sourcePolicyArtifactVerified",
    )
    replay_policy_artifact_verified: Literal[True] = Field(
        default=True,
        alias="replayPolicyArtifactVerified",
    )
    separate_authorization_verified: Literal[True] = Field(
        default=True,
        alias="separateAuthorizationVerified",
    )
    fresh_credential_lease_verified: Literal[True] = Field(
        default=True,
        alias="freshCredentialLeaseVerified",
    )
    deterministic_evaluator_verified: Literal[True] = Field(
        default=True,
        alias="deterministicEvaluatorVerified",
    )
    provider_policy_semantics_confirmed: Literal[False] = Field(
        default=False,
        alias="providerPolicySemanticsConfirmed",
    )
    effective_permission_confirmed: Literal[False] = Field(
        default=False,
        alias="effectivePermissionConfirmed",
    )
    cloud_resource_confirmed: Literal[False] = Field(
        default=False,
        alias="cloudResourceConfirmed",
    )
    benchmark_ground_truth_bound: Literal[False] = Field(
        default=False,
        alias="benchmarkGroundTruthBound",
    )
    negative_control_observed: Literal[False] = Field(
        default=False,
        alias="negativeControlObserved",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    provider_invocation_authorized: Literal[False] = Field(
        default=False,
        alias="providerInvocationAuthorized",
    )
    policy_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="policyMutationAuthorized",
    )
    iam_mutation_authorized: Literal[False] = Field(
        default=False,
        alias="iamMutationAuthorized",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_REPLAY_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D Replay verified markers must be boolean true")
        return value

    @field_validator("policy_input_matched", "decision_matched", mode="before")
    @classmethod
    def require_boolean(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("CLOUD-001D Replay comparison markers must be booleans")
        return value

    @field_validator(*_REPLAY_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CLOUD-001D Replay authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_replay_validation(self) -> Self:
        _require_cloud_domain_plan(self.domain_benchmark_plan)
        _require_equivalent_policy_read_semantics(self.source_execution, self.replay_execution)
        _require_distinct_replay_authority(self.source_execution, self.replay_execution)
        source_artifact = self.source_execution.policy_artifact
        replay_artifact = self.replay_execution.policy_artifact
        input_matched = source_artifact.rules == replay_artifact.rules
        decision_matched = (
            self.source_execution.evaluation.decision is self.replay_execution.evaluation.decision
        )
        comparison = _replay_comparison(input_matched, decision_matched)
        if (
            self.policy_input_matched is not input_matched
            or self.decision_matched is not decision_matched
            or self.comparison is not comparison
            or self.state != _replay_state(comparison)
        ):
            raise ValueError("CLOUD-001D neutral Replay comparison differs")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"validation_id", "validation_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cloud-policy-replay-validation/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        validation_id = f"cloud-policy-replay_{digest}"
        if self.validation_digest and self.validation_digest != digest:
            raise ValueError("CLOUD-001D Replay validation Digest differs")
        if self.validation_id and self.validation_id != validation_id:
            raise ValueError("CLOUD-001D Replay validation ID differs")
        object.__setattr__(self, "validation_digest", digest)
        object.__setattr__(self, "validation_id", validation_id)
        return self


class CloudPolicyBenchmarkFixtureCase(_FrozenStrictModel):
    """One private expected decision for a future disposable provider/emulator case."""

    fixture_id: _Identifier = Field(alias="fixtureId")
    ground_truth_class: CloudPolicyBenchmarkGroundTruthClass = Field(alias="groundTruthClass")
    rules: tuple[CloudPolicyExactRule, ...] = Field(min_length=1, max_length=20)
    query: CloudPolicyQuery
    expected_decision: CloudPolicyDecision = Field(alias="expectedDecision")
    isolation_requirement: Literal["disposable-account-or-emulator-per-case"] = Field(
        default="disposable-account-or-emulator-per-case",
        alias="isolationRequirement",
    )
    cleanup_evidence_requirement: Literal["destroyed-account-or-reset-emulator-receipt"] = Field(
        default="destroyed-account-or-reset-emulator-receipt",
        alias="cleanupEvidenceRequirement",
    )
    credential_requirement: Literal["fresh-single-use-ephemeral-lease-per-case"] = Field(
        default="fresh-single-use-ephemeral-lease-per-case",
        alias="credentialRequirement",
    )

    @model_validator(mode="after")
    def bind_fixture_case(self) -> Self:
        rule_ids = [rule.rule_id for rule in self.rules]
        rule_coordinates = [
            (rule.effect, rule.principal, rule.action, rule.resource) for rule in self.rules
        ]
        allow_ids, deny_ids = _matching_rule_ids(self.rules, self.query)
        expected = (
            CloudPolicyDecision.EXPLICIT_DENY
            if deny_ids
            else CloudPolicyDecision.ALLOW
            if allow_ids
            else CloudPolicyDecision.IMPLICIT_DENY
        )
        expected_class = {
            CloudPolicyDecision.ALLOW: CloudPolicyBenchmarkGroundTruthClass.KNOWN_ALLOW,
            CloudPolicyDecision.EXPLICIT_DENY: (CloudPolicyBenchmarkGroundTruthClass.EXPLICIT_DENY),
            CloudPolicyDecision.IMPLICIT_DENY: (
                CloudPolicyBenchmarkGroundTruthClass.NEGATIVE_CONTROL
            ),
        }[expected]
        if (
            rule_ids != sorted(rule_ids)
            or len(rule_ids) != len(set(rule_ids))
            or len(rule_coordinates) != len(set(rule_coordinates))
            or self.expected_decision is not expected
            or self.ground_truth_class is not expected_class
        ):
            raise ValueError("CLOUD-001D fixture Ground Truth differs from exact evaluation")
        return self


class CloudPolicyBenchmarkFixtureProfile(_FrozenStrictModel):
    """Registered disposable Cloud/emulator Ground Truth, never a measurement."""

    api_version: Literal["pajin.dev/cloud-policy-benchmark-fixture-profile/v1alpha1"] = Field(
        default=CLOUD_POLICY_BENCHMARK_FIXTURE_PROFILE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CloudPolicyBenchmarkFixtureProfile"] = "CloudPolicyBenchmarkFixtureProfile"
    profile_id: str = Field(default="", alias="profileId", max_length=110)
    profile_digest: str = Field(default="", alias="profileDigest", max_length=64)
    domain_benchmark_plan: DomainBenchmarkPlanRef = Field(alias="domainBenchmarkPlan")
    evaluator: CloudPolicyEvaluatorRef
    cases: tuple[CloudPolicyBenchmarkFixtureCase, ...] = Field(min_length=3, max_length=3)
    state: Literal["registered-fixture-ground-truth-not-provisioned-or-measured"] = (
        "registered-fixture-ground-truth-not-provisioned-or-measured"
    )
    private_ground_truth_verified: Literal[True] = Field(
        default=True,
        alias="privateGroundTruthVerified",
    )
    disposable_environment_required: Literal[True] = Field(
        default=True,
        alias="disposableEnvironmentRequired",
    )
    cleanup_evidence_required: Literal[True] = Field(
        default=True,
        alias="cleanupEvidenceRequired",
    )
    negative_control_registered: Literal[True] = Field(
        default=True,
        alias="negativeControlRegistered",
    )
    fresh_credential_replay_required: Literal[True] = Field(
        default=True,
        alias="freshCredentialReplayRequired",
    )
    deterministic_evaluator_verified: Literal[True] = Field(
        default=True,
        alias="deterministicEvaluatorVerified",
    )
    target_profile_selected: Literal[False] = Field(
        default=False,
        alias="targetProfileSelected",
    )
    target_factory_authority: Literal[False] = Field(
        default=False,
        alias="targetFactoryAuthority",
    )
    provider_account_provisioned: Literal[False] = Field(
        default=False,
        alias="providerAccountProvisioned",
    )
    emulator_provisioned: Literal[False] = Field(
        default=False,
        alias="emulatorProvisioned",
    )
    cleanup_performed: Literal[False] = Field(default=False, alias="cleanupPerformed")
    credential_lease_acquired: Literal[False] = Field(
        default=False,
        alias="credentialLeaseAcquired",
    )
    provider_execution_authorized: Literal[False] = Field(
        default=False,
        alias="providerExecutionAuthorized",
    )
    fixture_execution_authorized: Literal[False] = Field(
        default=False,
        alias="fixtureExecutionAuthorized",
    )
    replay_evidence_bound: Literal[False] = Field(
        default=False,
        alias="replayEvidenceBound",
    )
    benchmark_measurement_observed: Literal[False] = Field(
        default=False,
        alias="benchmarkMeasurementObserved",
    )
    detection_quality_established: Literal[False] = Field(
        default=False,
        alias="detectionQualityEstablished",
    )
    profile_validation_floor_satisfied: Literal[False] = Field(
        default=False,
        alias="profileValidationFloorSatisfied",
    )
    provider_policy_semantics_confirmed: Literal[False] = Field(
        default=False,
        alias="providerPolicySemanticsConfirmed",
    )
    effective_permission_confirmed: Literal[False] = Field(
        default=False,
        alias="effectivePermissionConfirmed",
    )
    finding_authority: Literal[False] = Field(default=False, alias="findingAuthority")
    scope_expansion_authorized: Literal[False] = Field(
        default=False,
        alias="scopeExpansionAuthorized",
    )
    capability_activation_authorized: Literal[False] = Field(
        default=False,
        alias="capabilityActivationAuthorized",
    )
    approval_authority: Literal[False] = Field(default=False, alias="approvalAuthority")
    permit_issuance_authorized: Literal[False] = Field(
        default=False,
        alias="permitIssuanceAuthorized",
    )
    provider_selection_authorized: Literal[False] = Field(
        default=False,
        alias="providerSelectionAuthorized",
    )
    worker_selection_authorized: Literal[False] = Field(
        default=False,
        alias="workerSelectionAuthorized",
    )
    network_access_authorized: Literal[False] = Field(
        default=False,
        alias="networkAccessAuthorized",
    )
    credential_access_authorized: Literal[False] = Field(
        default=False,
        alias="credentialAccessAuthorized",
    )
    credential_use_authorized: Literal[False] = Field(
        default=False,
        alias="credentialUseAuthorized",
    )
    replay_authorized: Literal[False] = Field(default=False, alias="replayAuthorized")
    execution_authorized: Literal[False] = Field(default=False, alias="executionAuthorized")

    @field_validator(*_FIXTURE_TRUE_FIELDS, mode="before")
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("CLOUD-001D fixture requirements must be boolean true")
        return value

    @field_validator(*_FIXTURE_FALSE_FIELDS, mode="before")
    @classmethod
    def require_false(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("CLOUD-001D fixture authority markers must be boolean false")
        return value

    @model_validator(mode="after")
    def bind_fixture_profile(self) -> Self:
        _require_cloud_domain_plan(self.domain_benchmark_plan)
        expected_cases = _registered_fixture_cases()
        if self.evaluator != registered_cloud_policy_evaluator() or self.cases != expected_cases:
            raise ValueError("CLOUD-001D fixture profile differs from code authority")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"profile_id", "profile_digest"},
        )
        digest = benchmark_digest(
            "pajin.workflow.cloud-policy-benchmark-fixture-profile/v1",
            material,
            max_bytes=_MAX_CANONICAL_BYTES,
        )
        profile_id = f"cloud-policy-fixtures_{digest}"
        if self.profile_digest and self.profile_digest != digest:
            raise ValueError("CLOUD-001D fixture profile Digest differs")
        if self.profile_id and self.profile_id != profile_id:
            raise ValueError("CLOUD-001D fixture profile ID differs")
        object.__setattr__(self, "profile_digest", digest)
        object.__setattr__(self, "profile_id", profile_id)
        return self


def registered_cloud_policy_benchmark_fixture_profile() -> CloudPolicyBenchmarkFixtureProfile:
    """Return the exact three-case profile without provisioning a Target or credential."""

    try:
        return CloudPolicyBenchmarkFixtureProfile(
            domainBenchmarkPlan=_cloud_domain_benchmark_plan_ref(),
            evaluator=registered_cloud_policy_evaluator(),
            cases=_registered_fixture_cases(),
        )
    except (ValidationError, ValueError, RuntimeError) as exc:
        raise CloudPolicyReplayBenchmarkError(
            "CLOUD-001D disposable fixture registration failed closed"
        ) from exc


def derive_cloud_policy_sanitized_artifact(
    *,
    source: VerifiedCloudProviderObservationSource,
    admission: CloudProviderObservationAdmission,
    rules: tuple[CloudPolicyExactRule, ...],
    query: CloudPolicyQuery,
    sanitized_at: datetime,
) -> CloudPolicySanitizedArtifact:
    """Bind deployment-derived policy data to one already verified CLOUD-001C source."""

    try:
        canonical_admission = CloudProviderObservationAdmission.model_validate(
            admission.model_dump(mode="json", by_alias=True)
        )
        _require_admission_projection(canonical_admission, source)
        if source.preparation.operation is not CloudReadOnlyOperation.POLICY:
            raise ValueError("CLOUD-001D artifacts require a policy read")
        normalized_time = _aware_utc(sanitized_at, label="Cloud policy sanitization time")
        if normalized_time < max(
            source.bundle.statement.issued_at,
            canonical_admission.observation_graph_event.occurred_at,
        ):
            raise ValueError("Cloud policy artifact predates its sealed admission")
        candidate = canonical_admission.candidate
        return CloudPolicySanitizedArtifact(
            sourceAdmissionId=canonical_admission.admission_id,
            sourceAdmissionDigest=canonical_admission.admission_digest,
            sourceExecutionId=source.bundle.statement.execution_id,
            sourceRootDigest=source.source_root_digest,
            statementSha256=source.verification.statement_sha256,
            responseReceiptSha256=source.response_receipt_sha256,
            responseReceiptDigest=source.response_receipt.receipt_digest,
            responseBodySha256=candidate.response_body_sha256,
            trustAnchorDigest=source.verification.trust_anchor_digest,
            evaluator=registered_cloud_policy_evaluator(),
            rules=rules,
            query=query,
            sanitizedAt=normalized_time,
        )
    except CloudPolicyReplayBenchmarkError:
        raise
    except (AttributeError, TypeError, ValidationError, ValueError) as exc:
        raise CloudPolicyReplayBenchmarkError(
            "CLOUD-001D sanitized policy derivation failed closed"
        ) from exc


class CloudPolicyReplayBenchmarkGate:
    """Reopen two C admissions and compare only separately signed policy projections."""

    def __init__(self, *, trust_anchor: CloudProviderExecutionTrustAnchor) -> None:
        if not isinstance(trust_anchor, CloudProviderExecutionTrustAnchor):
            raise TypeError("CLOUD-001D requires a deployment Cloud trust anchor")
        self._trust_anchor = CloudProviderExecutionTrustAnchor.model_validate(
            trust_anchor.model_dump(mode="json", by_alias=True)
        )

    def bind_fresh_credential_replay(
        self,
        source_inputs: CloudProviderObservationSourceInputs,
        source_admission: CloudProviderObservationAdmission,
        source_artifact_inputs: CloudPolicyArtifactSourceInputs,
        replay_inputs: CloudProviderObservationSourceInputs,
        replay_admission: CloudProviderObservationAdmission,
        replay_artifact_inputs: CloudPolicyArtifactSourceInputs,
        *,
        source_graph_store: SQLiteGraphStore,
        replay_graph_store: SQLiteGraphStore,
    ) -> CloudPolicyFreshCredentialReplayValidation:
        """Return one neutral comparison without invoking a provider or acquiring a lease."""

        try:
            canonical_source_admission = CloudProviderObservationAdmission.model_validate(
                source_admission.model_dump(mode="json", by_alias=True)
            )
            canonical_replay_admission = CloudProviderObservationAdmission.model_validate(
                replay_admission.model_dump(mode="json", by_alias=True)
            )
            source = load_verified_cloud_provider_observation_source(
                source_inputs,
                graph_store=source_graph_store,
                trust_anchor=self._trust_anchor,
            )
            replay = load_verified_cloud_provider_observation_source(
                replay_inputs,
                graph_store=replay_graph_store,
                trust_anchor=self._trust_anchor,
            )
            _require_stored_source_admission(canonical_source_admission, source_graph_store)
            _require_stored_source_admission(canonical_replay_admission, replay_graph_store)
            _require_admission_projection(canonical_source_admission, source)
            _require_admission_projection(canonical_replay_admission, replay)
            source_artifact = _load_verified_policy_artifact(
                source_artifact_inputs,
                source_inputs=source_inputs,
                admission=canonical_source_admission,
                source=source,
                trust_anchor=self._trust_anchor,
            )
            replay_artifact = _load_verified_policy_artifact(
                replay_artifact_inputs,
                source_inputs=replay_inputs,
                admission=canonical_replay_admission,
                source=replay,
                trust_anchor=self._trust_anchor,
            )
            source_projection = _execution_projection(
                canonical_source_admission,
                source,
                source_artifact,
            )
            replay_projection = _execution_projection(
                canonical_replay_admission,
                replay,
                replay_artifact,
            )
            input_matched = (
                source_projection.policy_artifact.rules == replay_projection.policy_artifact.rules
            )
            decision_matched = (
                source_projection.evaluation.decision is replay_projection.evaluation.decision
            )
            comparison = _replay_comparison(input_matched, decision_matched)
            return CloudPolicyFreshCredentialReplayValidation(
                sourceExecution=source_projection,
                replayExecution=replay_projection,
                domainBenchmarkPlan=_cloud_domain_benchmark_plan_ref(),
                comparison=comparison,
                policyInputMatched=input_matched,
                decisionMatched=decision_matched,
                state=_replay_state(comparison),
            )
        except CloudPolicyReplayBenchmarkError:
            raise
        except (
            AttributeError,
            KeyError,
            OSError,
            RuntimeError,
            TypeError,
            ValidationError,
            ValueError,
        ) as exc:
            raise CloudPolicyReplayBenchmarkError(
                "CLOUD-001D fresh-credential policy Replay failed closed"
            ) from exc


def bind_cloud_policy_fresh_credential_replay(
    source_inputs: CloudProviderObservationSourceInputs,
    source_admission: CloudProviderObservationAdmission,
    source_artifact_inputs: CloudPolicyArtifactSourceInputs,
    replay_inputs: CloudProviderObservationSourceInputs,
    replay_admission: CloudProviderObservationAdmission,
    replay_artifact_inputs: CloudPolicyArtifactSourceInputs,
    *,
    source_graph_store: SQLiteGraphStore,
    replay_graph_store: SQLiteGraphStore,
    trust_anchor: CloudProviderExecutionTrustAnchor,
) -> CloudPolicyFreshCredentialReplayValidation:
    """Functional entry point for the deployment-configured CLOUD-001D gate."""

    return CloudPolicyReplayBenchmarkGate(trust_anchor=trust_anchor).bind_fresh_credential_replay(
        source_inputs,
        source_admission,
        source_artifact_inputs,
        replay_inputs,
        replay_admission,
        replay_artifact_inputs,
        source_graph_store=source_graph_store,
        replay_graph_store=replay_graph_store,
    )


def _load_verified_policy_artifact(
    inputs: CloudPolicyArtifactSourceInputs,
    *,
    source_inputs: CloudProviderObservationSourceInputs,
    admission: CloudProviderObservationAdmission,
    source: VerifiedCloudProviderObservationSource,
    trust_anchor: CloudProviderExecutionTrustAnchor,
) -> VerifiedCloudPolicyArtifactSource:
    if not isinstance(inputs, CloudPolicyArtifactSourceInputs):
        raise TypeError("CLOUD-001D requires exact policy artifact source inputs")
    if inputs.source_root.resolve() != source_inputs.source_root.resolve():
        raise ValueError("Cloud policy artifact root differs from its CLOUD-001C source")
    reference = _artifact_reference(inputs.artifact_reference)
    if reference in {source.attestation_reference, source.response_receipt_reference}:
        raise ValueError("Cloud policy artifact must be distinct from CLOUD-001C receipts")
    content = read_bounded_regular_bytes(
        _artifact_path(inputs.source_root, reference),
        max_bytes=_MAX_ARTIFACT_BUNDLE_BYTES,
        label="Cloud policy artifact bundle",
        require_single_link=True,
    )
    bundle = CloudPolicyArtifactBundle.model_validate(
        parse_strict_json_bytes(
            content,
            label="Cloud policy artifact bundle",
            max_bytes=_MAX_ARTIFACT_BUNDLE_BYTES,
            max_depth=40,
            max_nodes=30_000,
        )
    )
    verification = verify_cloud_policy_artifact_bundle(
        bundle,
        trust_anchor=trust_anchor,
    )
    _require_policy_artifact_projection(bundle.artifact, admission, source)
    return VerifiedCloudPolicyArtifactSource(
        artifact_reference=reference,
        artifact_bundle_sha256=sha256(content).hexdigest(),
        bundle=bundle,
        verification=verification,
    )


def _execution_projection(
    admission: CloudProviderObservationAdmission,
    source: VerifiedCloudProviderObservationSource,
    policy: VerifiedCloudPolicyArtifactSource,
) -> CloudPolicyReplayExecution:
    candidate = admission.candidate
    artifact = policy.bundle.artifact
    return CloudPolicyReplayExecution(
        admission=admission,
        preparation=source.preparation,
        actionPermit=source.permit,
        approvalReceipt=source.approval_receipt,
        sourceRunId=source.bundle.statement.run_id,
        sourceRootDigest=source.source_root_digest,
        trustAnchorDigest=source.verification.trust_anchor_digest,
        statementSha256=source.verification.statement_sha256,
        executionId=source.bundle.statement.execution_id,
        responseReceiptReference=source.response_receipt_reference,
        responseReceiptSha256=source.response_receipt_sha256,
        responseReceiptDigest=source.response_receipt.receipt_digest,
        responseBodySha256=candidate.response_body_sha256,
        policyArtifactReference=policy.artifact_reference,
        policyArtifactBundleSha256=policy.artifact_bundle_sha256,
        policyArtifactVerification=policy.verification,
        policyArtifact=artifact,
        evaluation=evaluate_cloud_policy_artifact(artifact),
    )


def _require_stored_source_admission(
    admission: CloudProviderObservationAdmission,
    graph_store: SQLiteGraphStore,
) -> None:
    proposal = admission.candidate.observation_proposal
    stored = graph_store.event_log.event_for_attempt(proposal.proposal_id, proposal.digest())
    if stored != admission.observation_graph_event:
        raise ValueError("CLOUD-001D source Observation admission is not stored exactly")


def _require_admission_projection(
    admission: CloudProviderObservationAdmission,
    source: VerifiedCloudProviderObservationSource,
) -> None:
    candidate = admission.candidate
    statement = source.bundle.statement
    response = source.response_receipt
    if (
        source.preparation.operation is not CloudReadOnlyOperation.POLICY
        or candidate.preparation != source.preparation
        or candidate.source_execution_snapshot != source.job.decision.snapshot
        or candidate.source_run_id != statement.run_id
        or candidate.source_root_digest != source.source_root_digest
        or candidate.trust_anchor_digest != source.verification.trust_anchor_digest
        or candidate.statement_sha256 != source.verification.statement_sha256
        or candidate.approval_receipt_id != source.approval_receipt.receipt_id
        or candidate.approval_receipt_digest != source.approval_receipt.receipt_digest
        or candidate.attestation_reference != source.attestation_reference
        or candidate.attestation_sha256 != source.attestation_sha256
        or candidate.response_receipt_reference != source.response_receipt_reference
        or candidate.response_receipt_sha256 != source.response_receipt_sha256
        or candidate.response_receipt_digest != response.receipt_digest
        or candidate.response_body_sha256 != response.response_body_sha256
        or candidate.operation is not CloudReadOnlyOperation.POLICY
        or candidate.http_status != response.http_status
    ):
        raise ValueError("CLOUD-001D admission differs from its sealed policy execution")


def _require_policy_artifact_projection(
    artifact: CloudPolicySanitizedArtifact,
    admission: CloudProviderObservationAdmission,
    source: VerifiedCloudProviderObservationSource,
) -> None:
    statement = source.bundle.statement
    response = source.response_receipt
    if (
        artifact.source_admission_id != admission.admission_id
        or artifact.source_admission_digest != admission.admission_digest
        or artifact.source_execution_id != statement.execution_id
        or artifact.source_root_digest != source.source_root_digest
        or artifact.statement_sha256 != source.verification.statement_sha256
        or artifact.response_receipt_sha256 != source.response_receipt_sha256
        or artifact.response_receipt_digest != response.receipt_digest
        or artifact.response_body_sha256 != response.response_body_sha256
        or artifact.trust_anchor_digest != source.verification.trust_anchor_digest
        or artifact.sanitized_at
        < max(statement.issued_at, admission.observation_graph_event.occurred_at)
    ):
        raise ValueError("CLOUD-001D policy artifact differs from its sealed source")


def _require_equivalent_policy_read_semantics(
    source: CloudPolicyReplayExecution,
    replay: CloudPolicyReplayExecution,
) -> None:
    left = source.preparation
    right = replay.preparation
    left_request = left.prepared_action.request
    right_request = right.prepared_action.request
    if (
        left.binding != right.binding
        or left.surface != right.surface
        or left.operation is not CloudReadOnlyOperation.POLICY
        or right.operation is not CloudReadOnlyOperation.POLICY
        or left.provider_adapter != right.provider_adapter
        or _provider_request_semantics(left) != _provider_request_semantics(right)
        or left.campaign_scope != right.campaign_scope
        or left.matched_surface_allow_rule != right.matched_surface_allow_rule
        or left.matched_provider_allow_rule != right.matched_provider_allow_rule
        or left.release != right.release
        or left.prepared_action.activation_set_digest != right.prepared_action.activation_set_digest
        or left.prepared_action.capability != right.prepared_action.capability
        or (
            left_request.agent_id,
            left_request.tool_id,
            left_request.target,
            left_request.method,
        )
        != (
            right_request.agent_id,
            right_request.tool_id,
            right_request.target,
            right_request.method,
        )
        or _credential_semantics(left) != _credential_semantics(right)
        or source.trust_anchor_digest != replay.trust_anchor_digest
        or source.policy_artifact.evaluator != replay.policy_artifact.evaluator
        or source.policy_artifact.query != replay.policy_artifact.query
    ):
        raise ValueError("CLOUD-001D Replay differs from source policy-read semantics")


def _provider_request_semantics(
    preparation: CloudReadOnlyInventoryPolicyPreparation,
) -> dict[str, object]:
    return preparation.provider_request.model_dump(
        mode="json",
        by_alias=True,
        exclude={"credential_lease"},
    )


def _credential_semantics(
    preparation: CloudReadOnlyInventoryPolicyPreparation,
) -> tuple[str, str, str, int]:
    lease = preparation.credential_lease
    return (
        lease.secret_ref_fingerprint,
        lease.audience,
        lease.scope,
        lease.max_uses,
    )


def _require_distinct_replay_authority(
    source: CloudPolicyReplayExecution,
    replay: CloudPolicyReplayExecution,
) -> None:
    left = _execution_identity_coordinates(source)
    right = _execution_identity_coordinates(replay)
    reused = tuple(name for name in left if left[name] == right[name])
    if reused:
        raise ValueError(
            "CLOUD-001D Replay reused source execution authority: " + ", ".join(reused)
        )


def _execution_identity_coordinates(execution: CloudPolicyReplayExecution) -> dict[str, str]:
    preparation = execution.preparation
    permit = execution.action_permit
    receipt = execution.approval_receipt
    lease = preparation.credential_lease
    artifact = execution.policy_artifact
    return {
        "runId": execution.source_run_id,
        "preparationId": preparation.preparation_id,
        "preparationDigest": preparation.preparation_digest,
        "requestId": permit.request_id,
        "requestDigest": permit.request_digest,
        "normalizedParametersDigest": permit.normalized_parameters_digest,
        "envelopeId": permit.envelope_id,
        "envelopeDigest": permit.envelope_digest,
        "proposalId": permit.proposal_id,
        "proposalDigest": permit.proposal_digest,
        "decisionId": permit.decision_id,
        "decisionDigest": permit.decision_digest,
        "permitId": permit.permit_id,
        "permitDigest": permit.permit_digest,
        "dispatchId": permit.dispatch_id,
        "approvalReceiptId": receipt.receipt_id,
        "approvalReceiptDigest": receipt.receipt_digest,
        "credentialLeaseFingerprint": lease.lease_id_fingerprint,
        "credentialReferenceId": lease.reference_id,
        "credentialReferenceDigest": lease.reference_digest,
        "sourceRootDigest": execution.source_root_digest,
        "statementSha256": execution.statement_sha256,
        "executionId": execution.execution_id,
        "responseReceiptSha256": execution.response_receipt_sha256,
        "responseReceiptDigest": execution.response_receipt_digest,
        "admissionId": execution.admission.admission_id,
        "admissionDigest": execution.admission.admission_digest,
        "policyArtifactId": artifact.artifact_id,
        "policyArtifactDigest": artifact.artifact_digest,
        "policyArtifactBundleSha256": execution.policy_artifact_bundle_sha256,
    }


def _replay_comparison(
    input_matched: bool,
    decision_matched: bool,
) -> CloudPolicyReplayComparison:
    if input_matched:
        if not decision_matched:
            raise ValueError("deterministic policy decisions cannot differ for identical input")
        return CloudPolicyReplayComparison.INPUT_AND_DECISION_MATCHED
    if decision_matched:
        return CloudPolicyReplayComparison.INPUT_CHANGED_DECISION_MATCHED
    return CloudPolicyReplayComparison.DECISION_CHANGED


def _replay_state(comparison: CloudPolicyReplayComparison) -> _ReplayState:
    if comparison is CloudPolicyReplayComparison.INPUT_AND_DECISION_MATCHED:
        return "fresh-credential-policy-input-and-decision-match"
    if comparison is CloudPolicyReplayComparison.INPUT_CHANGED_DECISION_MATCHED:
        return "fresh-credential-policy-input-changed-decision-match"
    return "fresh-credential-policy-decision-changed"


def _fixture_case(
    fixture_id: str,
    ground_truth_class: CloudPolicyBenchmarkGroundTruthClass,
    rules: tuple[CloudPolicyExactRule, ...],
    query: CloudPolicyQuery,
    expected_decision: CloudPolicyDecision,
) -> CloudPolicyBenchmarkFixtureCase:
    return CloudPolicyBenchmarkFixtureCase(
        fixtureId=fixture_id,
        groundTruthClass=ground_truth_class,
        rules=rules,
        query=query,
        expectedDecision=expected_decision,
    )


def _registered_fixture_cases() -> tuple[CloudPolicyBenchmarkFixtureCase, ...]:
    principal = "principal:fixture-reader"
    action = "cloud:read-policy"
    resource = "resource:fixture-document"
    query = CloudPolicyQuery(principal=principal, action=action, resource=resource)
    allow = CloudPolicyExactRule(
        ruleId="rule:allow-exact",
        effect=CloudPolicyEffect.ALLOW,
        principal=principal,
        action=action,
        resource=resource,
    )
    deny = CloudPolicyExactRule(
        ruleId="rule:deny-exact",
        effect=CloudPolicyEffect.DENY,
        principal=principal,
        action=action,
        resource=resource,
    )
    unrelated = CloudPolicyExactRule(
        ruleId="rule:unrelated-allow",
        effect=CloudPolicyEffect.ALLOW,
        principal="principal:other-reader",
        action=action,
        resource=resource,
    )
    return (
        _fixture_case(
            "cloud-fixture:exact-allow",
            CloudPolicyBenchmarkGroundTruthClass.KNOWN_ALLOW,
            (allow,),
            query,
            CloudPolicyDecision.ALLOW,
        ),
        _fixture_case(
            "cloud-fixture:explicit-deny-overrides-allow",
            CloudPolicyBenchmarkGroundTruthClass.EXPLICIT_DENY,
            tuple(sorted((allow, deny), key=lambda item: item.rule_id)),
            query,
            CloudPolicyDecision.EXPLICIT_DENY,
        ),
        _fixture_case(
            "cloud-fixture:implicit-deny-negative-control",
            CloudPolicyBenchmarkGroundTruthClass.NEGATIVE_CONTROL,
            (unrelated,),
            query,
            CloudPolicyDecision.IMPLICIT_DENY,
        ),
    )


def _require_cloud_domain_plan(reference: DomainBenchmarkPlanRef) -> None:
    try:
        plan = resolve_registered_domain_benchmark_plan(reference)
    except Exception as exc:
        raise ValueError("CLOUD-001D Domain benchmark plan is not registered exactly") from exc
    if (
        plan.domain_classification.domain is not SecurityDomain.CLOUD
        or plan.validation_strategy
        is not DomainValidationStrategy.FRESH_CREDENTIAL_DETERMINISTIC_REEVALUATION
    ):
        raise ValueError("CLOUD-001D Domain benchmark strategy differs")


def _cloud_domain_benchmark_plan_ref() -> DomainBenchmarkPlanRef:
    for plan in registered_domain_benchmark_registry().plans:
        if plan.domain_classification.domain is SecurityDomain.CLOUD:
            return plan.reference()
    raise CloudPolicyReplayBenchmarkError("DOMAIN-006 Cloud benchmark plan is missing")


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _artifact_reference(value: str) -> str:
    try:
        path = PurePosixPath(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("Cloud policy artifact reference is invalid") from exc
    if (
        not isinstance(value, str)
        or fullmatch(r"^evidence/[A-Za-z0-9][A-Za-z0-9._-]{0,199}\.json$", value) is None
        or path.is_absolute()
        or len(path.parts) != 2
        or any(part in {"", ".", ".."} for part in path.parts)
        or path.suffix != ".json"
    ):
        raise ValueError("Cloud policy artifact reference is invalid")
    return path.as_posix()


def _artifact_path(root: Path, reference: str) -> Path:
    return Path(root).resolve().joinpath(*PurePosixPath(reference).parts)


__all__ = [
    "CLOUD_POLICY_ARTIFACT_BUNDLE_API_VERSION",
    "CLOUD_POLICY_BENCHMARK_FIXTURE_PROFILE_API_VERSION",
    "CLOUD_POLICY_REPLAY_VALIDATION_API_VERSION",
    "CloudPolicyArtifactAttestor",
    "CloudPolicyArtifactBundle",
    "CloudPolicyArtifactSourceInputs",
    "CloudPolicyArtifactVerification",
    "CloudPolicyBenchmarkFixtureCase",
    "CloudPolicyBenchmarkFixtureProfile",
    "CloudPolicyBenchmarkGroundTruthClass",
    "CloudPolicyDecision",
    "CloudPolicyEffect",
    "CloudPolicyEvaluation",
    "CloudPolicyEvaluatorRef",
    "CloudPolicyExactRule",
    "CloudPolicyFreshCredentialReplayValidation",
    "CloudPolicyQuery",
    "CloudPolicyReplayBenchmarkError",
    "CloudPolicyReplayBenchmarkGate",
    "CloudPolicyReplayComparison",
    "CloudPolicyReplayExecution",
    "CloudPolicySanitizedArtifact",
    "VerifiedCloudPolicyArtifactSource",
    "bind_cloud_policy_fresh_credential_replay",
    "cloud_policy_artifact_bundle_bytes",
    "derive_cloud_policy_sanitized_artifact",
    "evaluate_cloud_policy_artifact",
    "registered_cloud_policy_benchmark_fixture_profile",
    "registered_cloud_policy_evaluator",
    "verify_cloud_policy_artifact_bundle",
]
