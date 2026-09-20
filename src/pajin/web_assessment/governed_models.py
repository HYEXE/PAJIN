"""Signed deployment-owned inputs for governed authenticated web assessments.

The models in this module intentionally separate two kinds of runtime input from
caller-authored Tool parameters:

* an exact-origin adapter is installed and signed by a deployment authority; and
* an already-provisioned account is represented by a short-lived signed receipt.

Neither signature grants execution authority.  A lifecycle activation, fresh
ActionApproval, one-use ActionPermit, and Tool Gateway dispatch remain mandatory.
"""

from __future__ import annotations

import base64
import binascii
import os
import re
import sqlite3
import stat
from collections.abc import Awaitable, Callable, Iterable, Iterator
from contextlib import closing, contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from hashlib import sha256
from inspect import iscoroutinefunction
from pathlib import Path
from threading import Lock
from typing import Annotated, Final, Literal, Self, cast
from urllib.parse import quote, urlsplit, urlunsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    ValidationError,
    field_validator,
    model_validator,
)

from pajin.capabilities.activation import (
    capability_grant_digest,
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.models import canonical_capability_json, capability_definition_digest
from pajin.domain.models import (
    CampaignManifest,
    CapabilityGrant,
    StrictModel,
    ToolRequest,
    campaign_manifest_digest,
)
from pajin.graph.approval import (
    ActionApprovalAuthorization,
    ActionApprovalConsumptionReceipt,
    ActionApprovalEnvelope,
    ActionApprovalIssuerAuthorityBinding,
    ApprovedActionDispatchResult,
    GraphApprovedActionPermitAuthority,
    GraphApprovedActionPermitDispatcher,
    GraphApprovedActionPermitStore,
)
from pajin.graph.authority import (
    ActionPermit,
    ActionPermitAuthorization,
    ActionProposal,
    MissionEnvelope,
    RegisteredActionCapability,
)
from pajin.graph.consistency import GraphDecision
from pajin.graph.sqlite_store import SQLiteGraphActionPermitStore, SQLiteGraphStore
from pajin.policy.capability import CapabilityError, CapabilityLedger
from pajin.runtime.pinned_sqlite import (
    PinnedMemorySQLite,
    PinnedSQLiteCheckpoint,
    PinnedSQLitePublication,
    is_governed_pinned_sqlite_namespace,
    pinned_memory_sqlite_for_path,
)
from pajin.runtime.pinned_workspace import pinned_workspace_relative_path
from pajin.web_assessment.adapter_catalog import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    AdapterImplementationCatalog,
    AdapterImplementationCatalogError,
    production_adapter_implementation_catalog,
)

WEB_ASSESSMENT_ADAPTER_API_VERSION: Final[Literal["pajin.dev/web-assessment-adapter/v1alpha1"]] = (
    "pajin.dev/web-assessment-adapter/v1alpha1"
)
WEB_ACCOUNT_RECEIPT_API_VERSION: Final[
    Literal["pajin.dev/provisioned-web-account-receipt/v1alpha1"]
] = "pajin.dev/provisioned-web-account-receipt/v1alpha1"
WEB_ASSESSMENT_WORKER_OUTPUT_API_VERSION: Final[
    Literal["pajin.dev/web-authenticated-assessment-worker-output/v1alpha1"]
] = "pajin.dev/web-authenticated-assessment-worker-output/v1alpha1"

_ADAPTER_SIGNATURE_DOMAIN = b"pajin.web-assessment.adapter-signature/v1\0"
_ACCOUNT_RECEIPT_SIGNATURE_DOMAIN = b"pajin.web-assessment.account-receipt-signature/v1\0"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_MATERIAL_REFERENCE_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$"
_Base64UrlPublicKey = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{43}$")]
_Base64UrlSignature = Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{86}$")]
_WEB_DISPATCH_AUTHORITY_FACTORY_GUARD = object()

_WEB_GRANT_CONSUMPTION_SCHEMA_VERSION = 1
_WEB_GRANT_CONSUMPTION_MAX_BYTES = 8 * 1024 * 1024
_PINNED_WEB_GRANT_SQLITE_OWNER = object()
_GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD = object()
_WEB_GRANT_RESERVATION_TABLE_SQL = """
CREATE TABLE web_capability_grant_reservations (
    reservation_id TEXT PRIMARY KEY,
    reservation_digest TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    capability_grant_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    permit_id TEXT NOT NULL UNIQUE,
    approval_receipt_id TEXT NOT NULL UNIQUE,
    reservation_json TEXT NOT NULL
) WITHOUT ROWID
""".strip()
_WEB_GRANT_CONSUMPTION_TABLE_SQL = """
CREATE TABLE web_capability_grant_consumptions (
    receipt_id TEXT PRIMARY KEY,
    receipt_digest TEXT NOT NULL UNIQUE,
    reservation_id TEXT NOT NULL UNIQUE,
    campaign_id TEXT NOT NULL,
    capability_grant_id TEXT NOT NULL UNIQUE,
    request_id TEXT NOT NULL UNIQUE,
    permit_id TEXT NOT NULL UNIQUE,
    approval_receipt_id TEXT NOT NULL UNIQUE,
    receipt_json TEXT NOT NULL,
    FOREIGN KEY (reservation_id)
        REFERENCES web_capability_grant_reservations(reservation_id)
) WITHOUT ROWID
""".strip()
_WEB_GRANT_CONSUMPTION_METADATA_SQL = """
CREATE TABLE web_capability_grant_consumption_metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) WITHOUT ROWID
""".strip()
_WEB_GRANT_CONSUMPTION_RECEIPT_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_consumptions_no_update
BEFORE UPDATE ON web_capability_grant_consumptions
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant consumption receipts are append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_RECEIPT_DELETE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_consumptions_no_delete
BEFORE DELETE ON web_capability_grant_consumptions
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant consumption receipts are append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_RESERVATION_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_reservations_no_update
BEFORE UPDATE ON web_capability_grant_reservations
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant reservations are append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_RESERVATION_DELETE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_reservations_no_delete
BEFORE DELETE ON web_capability_grant_reservations
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant reservations are append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_METADATA_UPDATE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_consumption_metadata_no_update
BEFORE UPDATE ON web_capability_grant_consumption_metadata
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant consumption metadata is append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_METADATA_DELETE_TRIGGER_SQL = """
CREATE TRIGGER web_capability_grant_consumption_metadata_no_delete
BEFORE DELETE ON web_capability_grant_consumption_metadata
BEGIN
    SELECT RAISE(ABORT, 'Web capability grant consumption metadata is append-only');
END
""".strip()
_WEB_GRANT_CONSUMPTION_SCHEMA_OBJECTS = {
    "web_capability_grant_reservations": _WEB_GRANT_RESERVATION_TABLE_SQL,
    "web_capability_grant_consumptions": _WEB_GRANT_CONSUMPTION_TABLE_SQL,
    "web_capability_grant_consumption_metadata": _WEB_GRANT_CONSUMPTION_METADATA_SQL,
    "web_capability_grant_consumptions_no_update": (
        _WEB_GRANT_CONSUMPTION_RECEIPT_UPDATE_TRIGGER_SQL
    ),
    "web_capability_grant_consumptions_no_delete": (
        _WEB_GRANT_CONSUMPTION_RECEIPT_DELETE_TRIGGER_SQL
    ),
    "web_capability_grant_reservations_no_update": (
        _WEB_GRANT_CONSUMPTION_RESERVATION_UPDATE_TRIGGER_SQL
    ),
    "web_capability_grant_reservations_no_delete": (
        _WEB_GRANT_CONSUMPTION_RESERVATION_DELETE_TRIGGER_SQL
    ),
    "web_capability_grant_consumption_metadata_no_update": (
        _WEB_GRANT_CONSUMPTION_METADATA_UPDATE_TRIGGER_SQL
    ),
    "web_capability_grant_consumption_metadata_no_delete": (
        _WEB_GRANT_CONSUMPTION_METADATA_DELETE_TRIGGER_SQL
    ),
}
_WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST = capability_definition_digest(
    "pajin.web-assessment.capability-grant-consumption-schema/v1",
    {
        "schemaVersion": _WEB_GRANT_CONSUMPTION_SCHEMA_VERSION,
        "objects": _WEB_GRANT_CONSUMPTION_SCHEMA_OBJECTS,
    },
)


def _governed_web_grant_checkpoint_metadata(
    connection: sqlite3.Connection,
) -> dict[str, object]:
    reservation_rows = connection.execute(
        """
        SELECT
            reservation_id,
            reservation_digest,
            capability_grant_id,
            request_id,
            permit_id,
            approval_receipt_id
        FROM web_capability_grant_reservations
        ORDER BY reservation_id
        """
    ).fetchall()
    consumption_rows = connection.execute(
        """
        SELECT
            receipt_id,
            receipt_digest,
            reservation_id,
            capability_grant_id,
            request_id,
            permit_id,
            approval_receipt_id
        FROM web_capability_grant_consumptions
        ORDER BY receipt_id
        """
    ).fetchall()
    return {
        "reservations": [
            {
                "reservationId": str(row[0]),
                "reservationDigest": str(row[1]),
                "capabilityGrantId": str(row[2]),
                "requestId": str(row[3]),
                "permitId": str(row[4]),
                "approvalReceiptId": str(row[5]),
            }
            for row in reservation_rows
        ],
        "consumptions": [
            {
                "receiptId": str(row[0]),
                "receiptDigest": str(row[1]),
                "reservationId": str(row[2]),
                "capabilityGrantId": str(row[3]),
                "requestId": str(row[4]),
                "permitId": str(row[5]),
                "approvalReceiptId": str(row[6]),
            }
            for row in consumption_rows
        ],
    }


class GovernedWebAssessmentModelError(ValueError):
    """Raised when signed web-assessment deployment material fails closed."""


def web_assessment_system_utc_now() -> datetime:
    """Return the code-owned live UTC clock for production Web assessment state."""

    return datetime.now(UTC)


_system_utc_now = web_assessment_system_utc_now


def _canonical_grant_json(grant: CapabilityGrant) -> str:
    return canonical_capability_json(
        grant.model_dump(mode="json", by_alias=True),
        label="CapabilityGrant",
    ).decode("utf-8")


class WebAssessmentSigningRole(StrEnum):
    """Separated roles for adapter installation and account provisioning evidence."""

    ADAPTER_PUBLISHER = "adapter-publisher"
    ACCOUNT_ISSUER = "account-issuer"
    ACTION_APPROVER = "action-approver"


class WebAssessmentSigningKeyState(StrEnum):
    ACTIVE = "active"
    RETIRED = "retired"
    REVOKED = "revoked"


class WebAssessmentVerificationKey(StrictModel):
    """Out-of-band Ed25519 verification key pinned by the deployment."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    principal_id: str = Field(alias="principalId", pattern=_IDENTIFIER_PATTERN)
    role: WebAssessmentSigningRole
    algorithm: Literal["Ed25519"] = "Ed25519"
    public_key_base64url: _Base64UrlPublicKey = Field(alias="publicKeyBase64url")
    state: WebAssessmentSigningKeyState
    not_before: datetime = Field(alias="notBefore")
    not_after: datetime | None = Field(default=None, alias="notAfter")
    revoked_at: datetime | None = Field(default=None, alias="revokedAt")

    @model_validator(mode="after")
    def validate_key_lifecycle(self) -> Self:
        _decode_base64url(
            self.public_key_base64url,
            expected_length=32,
            label="web assessment public key",
        )
        not_before = _aware_utc(self.not_before, label="key not-before time")
        if self.not_after is not None:
            not_after = _aware_utc(self.not_after, label="key not-after time")
            if not_after <= not_before:
                raise ValueError("web assessment key validity window is empty")
        if self.state is WebAssessmentSigningKeyState.RETIRED and self.not_after is None:
            raise ValueError("retired web assessment key requires notAfter")
        if self.state is WebAssessmentSigningKeyState.REVOKED:
            if self.revoked_at is None:
                raise ValueError("revoked web assessment key requires revokedAt")
            _aware_utc(self.revoked_at, label="key revocation time")
        elif self.revoked_at is not None:
            raise ValueError("non-revoked web assessment key cannot have revokedAt")
        return self


class WebAssessmentAdapterRef(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    adapter_id: str = Field(alias="adapterId", pattern=_IDENTIFIER_PATTERN)
    adapter_version: str = Field(alias="adapterVersion", pattern=_IDENTIFIER_PATTERN)
    adapter_digest: str = Field(alias="adapterDigest", pattern=_SHA256_PATTERN)


class WebAssessmentAdapterManifest(StrictModel):
    """One signed exact-origin binding to a known code-backed recipe."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-assessment-adapter/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_ADAPTER_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["WebAssessmentAdapterManifest"] = "WebAssessmentAdapterManifest"
    adapter_id: str = Field(alias="adapterId", pattern=_IDENTIFIER_PATTERN)
    adapter_version: str = Field(alias="adapterVersion", pattern=_IDENTIFIER_PATTERN)
    adapter_digest: str = Field(default="", alias="adapterDigest", max_length=64)
    origin: str = Field(min_length=8, max_length=2_000)
    implementation_id: str = Field(alias="implementationId", pattern=_IDENTIFIER_PATTERN)
    implementation_digest: str = Field(alias="implementationDigest", pattern=_SHA256_PATTERN)
    recipe_digest: str = Field(alias="recipeDigest", pattern=_SHA256_PATTERN)
    allowed_methods: tuple[Literal["GET", "HEAD", "POST"], ...] = Field(
        default=("GET", "HEAD", "POST"),
        alias="allowedMethods",
        min_length=3,
        max_length=3,
    )
    authentication_state: Literal["client-memory-only", "server-stateful"] = Field(
        default="client-memory-only",
        alias="authenticationState",
    )
    recipe_side_effect: Literal["read-only", "reversible-write", "irreversible-write"] = Field(
        default="read-only",
        alias="recipeSideEffect",
    )
    target_mutation_allowed: bool = Field(default=False, alias="targetMutationAllowed")
    account_creation_allowed: bool = Field(default=False, alias="accountCreationAllowed")
    caller_authored_routes_allowed: bool = Field(
        default=False,
        alias="callerAuthoredRoutesAllowed",
    )
    caller_authored_payloads_allowed: bool = Field(
        default=False,
        alias="callerAuthoredPayloadsAllowed",
    )
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")

    @field_validator("origin")
    @classmethod
    def require_exact_origin(cls, value: str) -> str:
        return canonical_web_origin(value)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="adapter time")

    @field_validator(
        "target_mutation_allowed",
        "account_creation_allowed",
        "caller_authored_routes_allowed",
        "caller_authored_payloads_allowed",
        mode="before",
    )
    @classmethod
    def require_boolean_flags(cls, value: object) -> object:
        if type(value) is not bool:
            raise ValueError("adapter policy markers must be JSON booleans")
        return value

    @model_validator(mode="after")
    def bind_manifest(self) -> Self:
        if self.allowed_methods != ("GET", "HEAD", "POST"):
            raise ValueError("authenticated adapter methods must be exact and ordered")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(days=30):
            raise ValueError("web assessment adapter lifetime must be at most 30 days")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"adapter_digest"},
        )
        digest = capability_definition_digest(
            "pajin.web-assessment.adapter-manifest/v1",
            material,
        )
        if self.adapter_digest and self.adapter_digest != digest:
            raise ValueError("web assessment adapter digest differs")
        object.__setattr__(self, "adapter_digest", digest)
        return self

    def reference(self) -> WebAssessmentAdapterRef:
        return WebAssessmentAdapterRef(
            adapterId=self.adapter_id,
            adapterVersion=self.adapter_version,
            adapterDigest=self.adapter_digest,
        )


class SignedWebAssessmentAdapter(StrictModel):
    """Deployment-publisher signature over one adapter manifest."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    manifest: WebAssessmentAdapterManifest
    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    signature_base64url: _Base64UrlSignature = Field(alias="signatureBase64url")


class ProvisionedWebAccountReceiptRef(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt_id: str = Field(
        alias="receiptId",
        pattern=r"^provisioned-web-account_[a-f0-9]{64}$",
    )
    receipt_digest: str = Field(alias="receiptDigest", pattern=_SHA256_PATTERN)


class ProvisionedWebAccountReceipt(StrictModel):
    """Secret-free receipt for an account provisioned outside this Capability."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/provisioned-web-account-receipt/v1alpha1"] = Field(
        default=WEB_ACCOUNT_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["ProvisionedWebAccountReceipt"] = "ProvisionedWebAccountReceipt"
    receipt_id: str = Field(default="", alias="receiptId", max_length=90)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    adapter: WebAssessmentAdapterRef
    origin: str = Field(min_length=8, max_length=2_000)
    account_reference_digest: str = Field(alias="accountReferenceDigest", pattern=_SHA256_PATTERN)
    provisioning_evidence_digest: str = Field(
        alias="provisioningEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    target_fingerprint_response_sha256: str = Field(
        alias="targetFingerprintResponseSha256",
        pattern=_SHA256_PATTERN,
    )
    target_identity_digest: str = Field(alias="targetIdentityDigest", pattern=_SHA256_PATTERN)
    authorization_ids: tuple[str, str] = Field(alias="authorizationIds")
    identity_material_ref: str = Field(
        alias="identityMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )
    proof_material_ref: str = Field(
        alias="proofMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )
    issued_at: datetime = Field(alias="issuedAt")
    expires_at: datetime = Field(alias="expiresAt")
    account_already_provisioned: Literal[True] = Field(
        default=True,
        alias="accountAlreadyProvisioned",
    )
    account_creation_authorized: Literal[False] = Field(
        default=False,
        alias="accountCreationAuthorized",
    )
    material_values_included: Literal[False] = Field(
        default=False,
        alias="materialValuesIncluded",
    )
    server_session_material_persisted: Literal[False] = Field(
        default=False,
        alias="serverSessionMaterialPersisted",
    )

    @field_validator("origin")
    @classmethod
    def require_exact_origin(cls, value: str) -> str:
        return canonical_web_origin(value)

    @field_validator("issued_at", "expires_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="account receipt time")

    @field_validator("authorization_ids")
    @classmethod
    def require_two_distinct_authorizations(cls, value: tuple[str, str]) -> tuple[str, str]:
        if value != tuple(sorted(set(value))) or any(not item or len(item) > 200 for item in value):
            raise ValueError("account receipt requires two distinct sorted authorization IDs")
        return value

    @field_validator("account_already_provisioned", mode="before")
    @classmethod
    def require_preprovisioned(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("accountAlreadyProvisioned must be boolean true")
        return value

    @field_validator(
        "account_creation_authorized",
        "material_values_included",
        "server_session_material_persisted",
        mode="before",
    )
    @classmethod
    def forbid_authority_or_material_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("account receipt authority and material markers must be false")
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        if self.identity_material_ref == self.proof_material_ref:
            raise ValueError("account identity and proof material references must differ")
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=30):
            raise ValueError("provisioned account receipt lifetime must be at most 30 minutes")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = capability_definition_digest(
            "pajin.web-assessment.provisioned-account-receipt/v1",
            material,
        )
        receipt_id = f"provisioned-web-account_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("provisioned account receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("provisioned account receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self

    def reference(self) -> ProvisionedWebAccountReceiptRef:
        return ProvisionedWebAccountReceiptRef(
            receiptId=self.receipt_id,
            receiptDigest=self.receipt_digest,
        )

    def worker_receipt(self) -> dict[str, object]:
        """Return receipt evidence without deployment material references or values."""

        return {
            "receiptId": self.receipt_id,
            "receiptDigest": self.receipt_digest,
            "adapter": self.adapter.model_dump(mode="json", by_alias=True),
            "origin": self.origin,
            "accountReferenceDigest": self.account_reference_digest,
            "provisioningEvidenceDigest": self.provisioning_evidence_digest,
            "targetFingerprintResponseSha256": (self.target_fingerprint_response_sha256),
            "targetIdentityDigest": self.target_identity_digest,
            "authorizationIds": list(self.authorization_ids),
            "issuedAt": self.issued_at.isoformat(),
            "expiresAt": self.expires_at.isoformat(),
            "accountAlreadyProvisioned": True,
            "accountCreationAuthorized": False,
            "materialValuesIncluded": False,
            "serverSessionMaterialPersisted": False,
        }


class SignedProvisionedWebAccountReceipt(StrictModel):
    """Account-issuer signature over one secret-free provisioning receipt."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    receipt: ProvisionedWebAccountReceipt
    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    signature_base64url: _Base64UrlSignature = Field(alias="signatureBase64url")


class SignedWebActionApproval(StrictModel):
    """Role-bound Ed25519 signature over one exact fresh ActionApprovalEnvelope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/signed-web-action-approval/v1alpha1"] = Field(
        default="pajin.dev/signed-web-action-approval/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["SignedWebActionApproval"] = "SignedWebActionApproval"
    role: Literal["source", "validation"]
    approval: ActionApprovalEnvelope
    key_id: str = Field(alias="keyId", pattern=_IDENTIFIER_PATTERN)
    signature_base64url: _Base64UrlSignature = Field(alias="signatureBase64url")


def web_action_approval_issuer_binding(
    key: WebAssessmentVerificationKey,
    *,
    role: Literal["source", "validation"],
) -> ActionApprovalIssuerAuthorityBinding:
    """Bind one deployment-pinned approval key to one independent execution role."""

    if key.role is not WebAssessmentSigningRole.ACTION_APPROVER:
        raise GovernedWebAssessmentModelError("web approval key has the wrong trust role")
    return ActionApprovalIssuerAuthorityBinding(
        authorityId=f"pajin.web-action-approval.{role}",
        authorityVersion="1.0.0",
        implementationType=("pajin.web_assessment.governed_models.WebActionApprovalInputAuthority"),
        contextDigest=capability_definition_digest(
            "pajin.web-assessment.action-approval-issuer/v1",
            {
                "keyId": key.key_id,
                "principalId": key.principal_id,
                "publicKeyBase64url": key.public_key_base64url,
                "role": role,
            },
        ),
    )


class WebActionApprovalInputAuthority:
    """Graph-compatible verifier for one signed source or validation approval."""

    def __init__(
        self,
        *,
        role: Literal["source", "validation"],
        key: WebAssessmentVerificationKey,
        signed: SignedWebActionApproval,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        canonical_key = WebAssessmentVerificationKey.model_validate(
            key.model_dump(mode="json", by_alias=True)
        )
        canonical_signed = SignedWebActionApproval.model_validate(
            signed.model_dump(mode="json", by_alias=True)
        )
        if canonical_key.role is not WebAssessmentSigningRole.ACTION_APPROVER:
            raise GovernedWebAssessmentModelError("web approval authority key role differs")
        if canonical_signed.role != role or canonical_signed.key_id != canonical_key.key_id:
            raise GovernedWebAssessmentModelError("web approval signature role or key differs")
        self.role = role
        self.key = canonical_key
        self.signed = canonical_signed
        self._clock = clock or (lambda: datetime.now(UTC))
        self._verify_signature_and_freshness(self._now())

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationVersion": "pajin.web-action-approval-input/v1",
            "role": self.role,
            "issuerAuthorityDigest": web_action_approval_issuer_binding(
                self.key,
                role=self.role,
            ).authority_digest,
            "signedApprovalDigest": self.signed.approval.approval_digest,
            "freshnessWindowSeconds": 300,
        }

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        try:
            canonical_envelope = MissionEnvelope.model_validate(
                envelope.model_dump(mode="json", by_alias=True)
            )
            canonical_proposal = ActionProposal.model_validate(
                proposal.model_dump(mode="json", by_alias=True)
            )
            canonical_decision = GraphDecision.model_validate(
                decision.model_dump(mode="json", by_alias=True)
            )
            canonical_approval = ActionApprovalEnvelope.model_validate(
                approval.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "web action approval inputs are not canonical"
            ) from exc
        signed_approval = self.signed.approval
        if (
            canonical_approval != signed_approval
            or canonical_envelope != signed_approval.mission_envelope
            or canonical_proposal != signed_approval.proposal
            or canonical_decision != signed_approval.graph_decision
            or signed_approval.requested_by == signed_approval.approved_by
            or signed_approval.approved_by != self.key.principal_id
            or signed_approval.issuer
            != web_action_approval_issuer_binding(self.key, role=self.role)
            or signed_approval.side_effect_class != "read-only"
            or signed_approval.cleanup_required
        ):
            raise GovernedWebAssessmentModelError(
                "web action approval differs from exact signed read-only authority"
            )
        self._verify_signature_and_freshness(self._now())

    def _verify_signature_and_freshness(self, now: datetime) -> None:
        approval = self.signed.approval
        approved_at = _aware_utc(approval.approved_at, label="web approval time")
        approval_not_before = _aware_utc(
            approval.not_before,
            label="web approval not-before time",
        )
        expires_at = _aware_utc(approval.expires_at, label="web approval expiry")
        current = _aware_utc(now, label="web approval verification time")
        key_not_before = _aware_utc(
            self.key.not_before,
            label="web approval key not-before time",
        )
        key_not_after = (
            _aware_utc(self.key.not_after, label="web approval key expiry time")
            if self.key.not_after is not None
            else None
        )
        if (
            approval.requested_by == approval.approved_by
            or approval.approved_by != self.key.principal_id
            or approval.issuer != web_action_approval_issuer_binding(self.key, role=self.role)
            or approval.side_effect_class != "read-only"
            or approval.cleanup_required
            or expires_at - approved_at > timedelta(minutes=5)
        ):
            raise GovernedWebAssessmentModelError(
                "web approval is not a fresh separated read-only approval"
            )
        if self.key.state is not WebAssessmentSigningKeyState.ACTIVE:
            raise GovernedWebAssessmentModelError("web approval signing key is not active")
        if not approval_not_before <= current < expires_at:
            raise GovernedWebAssessmentModelError("web action approval is not currently active")
        if (
            approved_at < key_not_before
            or current < key_not_before
            or (
                key_not_after is not None
                and (current >= key_not_after or expires_at > key_not_after)
            )
        ):
            raise GovernedWebAssessmentModelError(
                "web approval signing key does not cover the current approval window"
            )
        _verify_signed(
            key_id=self.signed.key_id,
            issued_at=approved_at,
            expires_at=expires_at,
            signature=self.signed.signature_base64url,
            canonical=_canonical_action_approval(self.role, approval),
            domain=b"",
            keys={self.key.key_id: self.key},
            now=now,
        )

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), label="web approval authority clock")


class WebActionApprovalAuthoritySet:
    """Exactly one independently signed fresh approval for source and validation."""

    def __init__(
        self,
        *,
        keys: Iterable[WebAssessmentVerificationKey],
        approvals: Iterable[SignedWebActionApproval],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        keyring = _keyring(keys, role=WebAssessmentSigningRole.ACTION_APPROVER)
        signed_by_role: dict[str, SignedWebActionApproval] = {}
        for raw in approvals:
            signed = SignedWebActionApproval.model_validate(
                raw.model_dump(mode="json", by_alias=True)
            )
            if signed.role in signed_by_role:
                raise GovernedWebAssessmentModelError("web action approval role is duplicated")
            signed_by_role[signed.role] = signed
        if set(signed_by_role) != {"source", "validation"}:
            raise GovernedWebAssessmentModelError(
                "web assessment requires source and validation approvals"
            )
        if (
            signed_by_role["source"].approval.approval_digest
            == signed_by_role["validation"].approval.approval_digest
        ):
            raise GovernedWebAssessmentModelError(
                "source and validation approvals must bind distinct actions"
            )
        source_signed = signed_by_role["source"]
        validation_signed = signed_by_role["validation"]
        source_key = keyring.get(source_signed.key_id)
        validation_key = keyring.get(validation_signed.key_id)
        if source_key is None or validation_key is None:
            raise GovernedWebAssessmentModelError("web action approval signing key is not trusted")
        if (
            source_key.key_id == validation_key.key_id
            or source_key.public_key_base64url == validation_key.public_key_base64url
            or source_key.principal_id == validation_key.principal_id
        ):
            raise GovernedWebAssessmentModelError(
                "source and validation approvals require distinct key IDs, public keys, "
                "and principal IDs"
            )
        self._authorities = {
            "source": WebActionApprovalInputAuthority(
                role="source",
                key=source_key,
                signed=source_signed,
                clock=clock,
            ),
            "validation": WebActionApprovalInputAuthority(
                role="validation",
                key=validation_key,
                signed=validation_signed,
                clock=clock,
            ),
        }
        self._authorities_by_approval = {
            (
                authority.signed.approval.approval_id,
                authority.signed.approval.approval_digest,
            ): authority
            for authority in self._authorities.values()
        }
        if len(self._authorities_by_approval) != 2:
            raise GovernedWebAssessmentModelError("web action approval identity is ambiguous")

    def stable_execution_context(self) -> dict[str, object]:
        """Return one deterministic identity for the composite input authority."""

        return {
            "implementationVersion": "pajin.web-action-approval-authority-set/v1",
            "source": self._authorities["source"].stable_execution_context(),
            "validation": self._authorities["validation"].stable_execution_context(),
        }

    def verify_action_approval(
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
    ) -> None:
        """Verify either exact signed leg through one store-pinnable authority object."""

        try:
            canonical = ActionApprovalEnvelope.model_validate(
                approval.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "web action approval selection input is not canonical"
            ) from exc
        identity = (canonical.approval_id, canonical.approval_digest)
        try:
            authority = self._authorities_by_approval[identity]
        except KeyError as exc:
            raise GovernedWebAssessmentModelError(
                "web action approval is not one exact signed source or validation action"
            ) from exc
        authority.verify_action_approval(envelope, proposal, decision, canonical)

    def authority(
        self,
        role: Literal["source", "validation"],
    ) -> WebActionApprovalInputAuthority:
        return self._authorities[role]


def sign_web_action_approval(
    approval: ActionApprovalEnvelope,
    *,
    role: Literal["source", "validation"],
    key: WebAssessmentVerificationKey,
    private_key: bytes,
) -> SignedWebActionApproval:
    """Sign one exact approval after issuer and requester separation checks."""

    canonical = ActionApprovalEnvelope.model_validate(
        approval.model_dump(mode="json", by_alias=True)
    )
    if (
        key.role is not WebAssessmentSigningRole.ACTION_APPROVER
        or canonical.approved_by != key.principal_id
        or canonical.requested_by == canonical.approved_by
        or canonical.issuer != web_action_approval_issuer_binding(key, role=role)
        or canonical.side_effect_class != "read-only"
        or canonical.cleanup_required
    ):
        raise GovernedWebAssessmentModelError(
            "web action approval cannot be signed by this separated authority"
        )
    return SignedWebActionApproval(
        role=role,
        approval=canonical,
        keyId=key.key_id,
        signatureBase64url=_sign(
            private_key,
            _canonical_action_approval(role, canonical),
        ),
    )


class WebAssessmentCapabilityGrantReservation(StrictModel):
    """Durable one-use claim written before the ephemeral ledger is mutated."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-assessment-capability-grant-reservation/v1alpha1"] = Field(
        default="pajin.dev/web-assessment-capability-grant-reservation/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["WebAssessmentCapabilityGrantReservation"] = (
        "WebAssessmentCapabilityGrantReservation"
    )
    reservation_id: str = Field(default="", alias="reservationId", max_length=120)
    reservation_digest: str = Field(default="", alias="reservationDigest", max_length=64)
    campaign_id: str = Field(alias="campaignId", pattern=_IDENTIFIER_PATTERN)
    grant_authority_digest: str = Field(
        alias="grantAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    capability_grant_digest: str = Field(
        alias="capabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_SHA256_PATTERN)
    permit_id: str = Field(alias="permitId", pattern=_IDENTIFIER_PATTERN)
    permit_digest: str = Field(alias="permitDigest", pattern=_SHA256_PATTERN)
    approval_receipt_id: str = Field(
        alias="approvalReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    approval_receipt_digest: str = Field(
        alias="approvalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    reserved_at: datetime = Field(alias="reservedAt")

    @field_validator("reserved_at")
    @classmethod
    def normalize_reserved_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Web capability grant reservation time")

    @model_validator(mode="after")
    def bind_reservation_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"reservation_id", "reservation_digest"},
        )
        digest = capability_definition_digest(
            "pajin.web-assessment.capability-grant-reservation/v1",
            material,
        )
        reservation_id = f"web-grant-reservation_{digest}"
        if self.reservation_digest and self.reservation_digest != digest:
            raise ValueError("Web capability grant reservation digest differs")
        if self.reservation_id and self.reservation_id != reservation_id:
            raise ValueError("Web capability grant reservation ID differs")
        object.__setattr__(self, "reservation_digest", digest)
        object.__setattr__(self, "reservation_id", reservation_id)
        return self


class WebAssessmentCapabilityGrantConsumptionReceipt(StrictModel):
    """Completion proof appended only after the exact ledger also consumed the grant."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.dev/web-assessment-capability-grant-consumption-receipt/v1alpha1"
    ] = Field(
        default=("pajin.dev/web-assessment-capability-grant-consumption-receipt/v1alpha1"),
        alias="apiVersion",
    )
    kind: Literal["WebAssessmentCapabilityGrantConsumptionReceipt"] = (
        "WebAssessmentCapabilityGrantConsumptionReceipt"
    )
    receipt_id: str = Field(default="", alias="receiptId", max_length=120)
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    reservation_id: str = Field(alias="reservationId", pattern=_IDENTIFIER_PATTERN)
    reservation_digest: str = Field(alias="reservationDigest", pattern=_SHA256_PATTERN)
    campaign_id: str = Field(alias="campaignId", pattern=_IDENTIFIER_PATTERN)
    grant_authority_digest: str = Field(
        alias="grantAuthorityDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    capability_grant_digest: str = Field(
        alias="capabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    request_id: str = Field(alias="requestId", pattern=_IDENTIFIER_PATTERN)
    request_digest: str = Field(alias="requestDigest", pattern=_SHA256_PATTERN)
    permit_id: str = Field(alias="permitId", pattern=_IDENTIFIER_PATTERN)
    permit_digest: str = Field(alias="permitDigest", pattern=_SHA256_PATTERN)
    approval_receipt_id: str = Field(
        alias="approvalReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    approval_receipt_digest: str = Field(
        alias="approvalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    consumed_at: datetime = Field(alias="consumedAt")

    @field_validator("consumed_at")
    @classmethod
    def normalize_consumed_at(cls, value: datetime) -> datetime:
        return _aware_utc(value, label="Web capability grant consumption time")

    @model_validator(mode="after")
    def bind_receipt_identity(self) -> Self:
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"receipt_id", "receipt_digest"},
        )
        digest = capability_definition_digest(
            "pajin.web-assessment.capability-grant-consumption-receipt/v1",
            material,
        )
        receipt_id = f"web-grant-consumption_{digest}"
        if self.receipt_digest and self.receipt_digest != digest:
            raise ValueError("Web capability grant consumption receipt digest differs")
        if self.receipt_id and self.receipt_id != receipt_id:
            raise ValueError("Web capability grant consumption receipt ID differs")
        object.__setattr__(self, "receipt_digest", digest)
        object.__setattr__(self, "receipt_id", receipt_id)
        return self


@dataclass(frozen=True, slots=True)
class _WebAssessmentCapabilityGrantConsumptionWriter:
    store: WebAssessmentCapabilityGrantConsumptionStore
    authority: WebAssessmentDispatchAuthority
    ledger: CapabilityLedger
    campaign_id: str
    authority_digest: str
    guard: object


@dataclass(frozen=True, slots=True)
class GovernedWebGrantDatabaseAuthority:
    """Possession capability for freezing one governed Grant database."""

    store: WebAssessmentCapabilityGrantConsumptionStore
    _database: PinnedMemorySQLite
    _guard: object

    def freeze_and_publish(self) -> PinnedSQLitePublication:
        if (
            self._guard is not _GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD
            or type(self.store) is not WebAssessmentCapabilityGrantConsumptionStore
            or self._database.store_kind != "governed-web-grant"
            or self._database.campaign_id != self.store.campaign_id
            or self._database.schema_digest != _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST
        ):
            raise GovernedWebAssessmentModelError(
                "governed Grant database authority is invalid"
            )
        return self._database.freeze_and_publish(
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER
        )

    def latest_checkpoint(self) -> PinnedSQLiteCheckpoint:
        if self._guard is not _GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD:
            raise GovernedWebAssessmentModelError(
                "governed Grant database authority is invalid"
            )
        return self._database.latest_checkpoint(
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER
        )

    def enrollment_publication(self) -> PinnedSQLitePublication:
        if self._guard is not _GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD:
            raise GovernedWebAssessmentModelError(
                "governed Grant database authority is invalid"
            )
        return self._database.enrollment_publication(
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER
        )

    def install_checkpoint_observer(
        self,
        observer: Callable[[PinnedSQLiteCheckpoint], None],
    ) -> None:
        if self._guard is not _GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD:
            raise GovernedWebAssessmentModelError(
                "governed Grant database authority is invalid"
            )
        self._database.install_checkpoint_observer(
            observer,
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
        )

    def close(self) -> None:
        if self._guard is not _GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD:
            raise GovernedWebAssessmentModelError(
                "governed Grant database authority is invalid"
            )
        self._database.close(owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER)


class WebAssessmentCapabilityGrantConsumptionStore:
    """Private SQLite append-only store with one authority-owned writer."""

    __slots__ = (
        "_campaign_id",
        "_file_identity",
        "_lock",
        "_path",
        "_path_digest",
        "_sealed",
        "_writer",
        "_writer_guard",
    )

    _FROZEN_ATTRIBUTES = frozenset(
        {
            "_campaign_id",
            "_file_identity",
            "_lock",
            "_path",
            "_path_digest",
            "_sealed",
            "_writer",
            "_writer_guard",
        }
    )

    @classmethod
    def create_governed_in_memory(
        cls,
        path: Path,
        *,
        campaign_id: str,
        fresh_authority: object,
        checkpoint_observer: Callable[[PinnedSQLiteCheckpoint], None],
    ) -> tuple[
        WebAssessmentCapabilityGrantConsumptionStore,
        GovernedWebGrantDatabaseAuthority,
    ]:
        """Create a path-independent live Store with one frozen final database."""

        if cls is not WebAssessmentCapabilityGrantConsumptionStore:
            raise TypeError("governed in-memory Grant Store cannot construct subclasses")
        database = PinnedMemorySQLite.create(
            path,
            store_kind="governed-web-grant",
            campaign_id=campaign_id,
            schema_digest=_WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
            max_bytes=_WEB_GRANT_CONSUMPTION_MAX_BYTES,
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
            checkpoint_metadata=_governed_web_grant_checkpoint_metadata,
            checkpoint_observer=checkpoint_observer,
            fresh_authority=fresh_authority,
        )
        try:
            store = cls(path, campaign_id=campaign_id)
            return (
                store,
                GovernedWebGrantDatabaseAuthority(
                    store=store,
                    _database=database,
                    _guard=_GOVERNED_WEB_GRANT_DATABASE_AUTHORITY_GUARD,
                ),
            )
        except BaseException:
            database.close(owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER)
            raise

    def __init__(self, path: Path, *, campaign_id: str) -> None:
        if not isinstance(path, Path):
            raise TypeError("Web capability grant consumption store path must be a Path")
        if not isinstance(campaign_id, str) or not re.fullmatch(
            r"^[a-z0-9][a-z0-9-]{2,79}$",
            campaign_id,
        ):
            raise ValueError("Web capability grant consumption store Campaign ID is invalid")
        self._sealed = False
        self._path = _absolute_grant_store_path(path)
        self._campaign_id = campaign_id
        memory_database = pinned_memory_sqlite_for_path(
            self._path,
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
        )
        if memory_database is None and is_governed_pinned_sqlite_namespace(
            self._path,
            store_kind="governed-web-grant",
        ):
            raise GovernedWebAssessmentModelError(
                "governed Grant database namespace is historical and never writable"
            )
        self._lock = Lock()
        self._writer_guard = object()
        self._writer: _WebAssessmentCapabilityGrantConsumptionWriter | None = None
        _initialize_web_grant_consumption_store(self._path, campaign_id)
        self._file_identity = _web_grant_store_file_identity(self._path)
        self._path_digest = sha256(os.fsencode(self._path)).hexdigest()
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False) and name in self._FROZEN_ATTRIBUTES:
            raise AttributeError("Web capability grant consumption store identity is immutable")
        object.__setattr__(self, name, value)

    @property
    def campaign_id(self) -> str:
        return self._campaign_id

    def stable_execution_context(self) -> dict[str, object]:
        self._require_exact_runtime()
        return {
            "implementationVersion": ("pajin.web-assessment.capability-grant-consumption-store/v1"),
            "campaignId": self._campaign_id,
            "schemaVersion": _WEB_GRANT_CONSUMPTION_SCHEMA_VERSION,
            "schemaDigest": _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
            "pathDigest": self._path_digest,
            "fileIdentity": [list(item) for item in self._file_identity],
            "appendOnly": True,
            "publicWriterAvailable": False,
        }

    def receipt_for_grant(
        self,
        grant_id: str,
    ) -> WebAssessmentCapabilityGrantConsumptionReceipt | None:
        if not isinstance(grant_id, str) or not re.fullmatch(_IDENTIFIER_PATTERN, grant_id):
            raise ValueError("Web capability grant lookup ID is invalid")
        with self._lock:
            self._require_exact_runtime()
            with _web_grant_store_connection(self._path, readonly=True) as connection:
                _verify_web_grant_consumption_schema(connection, self._campaign_id)
                row = connection.execute(
                    """
                    SELECT receipt_json
                    FROM web_capability_grant_consumptions
                    WHERE capability_grant_id = ?
                    """,
                    (grant_id,),
                ).fetchone()
        if row is None:
            return None
        try:
            receipt = WebAssessmentCapabilityGrantConsumptionReceipt.model_validate_json(row[0])
        except (TypeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "stored Web capability grant consumption receipt is invalid"
            ) from exc
        if receipt.campaign_id != self._campaign_id or receipt.capability_grant_id != grant_id:
            raise GovernedWebAssessmentModelError(
                "stored Web capability grant consumption receipt identity differs"
            )
        return receipt

    def reservation_for_grant(
        self,
        grant_id: str,
    ) -> WebAssessmentCapabilityGrantReservation | None:
        if not isinstance(grant_id, str) or not re.fullmatch(_IDENTIFIER_PATTERN, grant_id):
            raise ValueError("Web capability grant lookup ID is invalid")
        with self._lock:
            self._require_exact_runtime()
            with _web_grant_store_connection(self._path, readonly=True) as connection:
                _verify_web_grant_consumption_schema(connection, self._campaign_id)
                row = connection.execute(
                    """
                    SELECT reservation_json
                    FROM web_capability_grant_reservations
                    WHERE capability_grant_id = ?
                    """,
                    (grant_id,),
                ).fetchone()
        if row is None:
            return None
        try:
            reservation = WebAssessmentCapabilityGrantReservation.model_validate_json(row[0])
        except (TypeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "stored Web capability grant reservation is invalid"
            ) from exc
        if (
            reservation.campaign_id != self._campaign_id
            or reservation.capability_grant_id != grant_id
        ):
            raise GovernedWebAssessmentModelError(
                "stored Web capability grant reservation identity differs"
            )
        return reservation

    def _claim_writer(
        self,
        *,
        authority: WebAssessmentDispatchAuthority,
        ledger: CapabilityLedger,
    ) -> _WebAssessmentCapabilityGrantConsumptionWriter:
        if (
            type(authority) is not WebAssessmentDispatchAuthority
            or type(ledger) is not CapabilityLedger
            or getattr(authority, "_campaign_id", None) != self._campaign_id
            or getattr(authority, "_capability_ledger", None) is not ledger
            or getattr(authority, "_grant_consumption_store", None) is not self
        ):
            raise TypeError(
                "Web capability grant writer requires its exact dispatch authority and ledger"
            )
        authority_digest = getattr(authority, "_grant_authority_digest", None)
        if not isinstance(authority_digest, str) or not re.fullmatch(
            _SHA256_PATTERN,
            authority_digest,
        ):
            raise TypeError("Web capability grant writer authority context is invalid")
        with self._lock:
            self._require_exact_runtime()
            if self._writer is not None:
                raise GovernedWebAssessmentModelError(
                    "Web capability grant consumption writer is already claimed"
                )
            writer = _WebAssessmentCapabilityGrantConsumptionWriter(
                store=self,
                authority=authority,
                ledger=ledger,
                campaign_id=self._campaign_id,
                authority_digest=authority_digest,
                guard=self._writer_guard,
            )
            object.__setattr__(self, "_writer", writer)
            return writer

    def _reserve_with_writer(
        self,
        writer: _WebAssessmentCapabilityGrantConsumptionWriter,
        reservation: WebAssessmentCapabilityGrantReservation,
    ) -> None:
        if (
            type(writer) is not _WebAssessmentCapabilityGrantConsumptionWriter
            or writer is not self._writer
            or writer.store is not self
            or writer.guard is not self._writer_guard
            or writer.campaign_id != self._campaign_id
            or writer.authority_digest != reservation.grant_authority_digest
            or getattr(writer.authority, "_capability_ledger", None) is not writer.ledger
            or getattr(writer.authority, "_grant_consumption_store", None) is not self
        ):
            raise GovernedWebAssessmentModelError(
                "Web capability grant consumption writer is foreign or changed"
            )
        canonical = WebAssessmentCapabilityGrantReservation.model_validate(
            reservation.model_dump(mode="json", by_alias=True)
        )
        if canonical.campaign_id != self._campaign_id:
            raise GovernedWebAssessmentModelError(
                "Web capability grant reservation belongs to another Campaign"
            )
        encoded = canonical_capability_json(
            canonical.model_dump(mode="json", by_alias=True),
            label="WebAssessmentCapabilityGrantReservation",
        ).decode("utf-8")
        with self._lock:
            self._require_exact_runtime()
            with _web_grant_store_connection(self._path, readonly=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    _verify_web_grant_consumption_schema(connection, self._campaign_id)
                    connection.execute(
                        """
                        INSERT INTO web_capability_grant_reservations (
                            reservation_id,
                            reservation_digest,
                            campaign_id,
                            capability_grant_id,
                            request_id,
                            permit_id,
                            approval_receipt_id,
                            reservation_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            canonical.reservation_id,
                            canonical.reservation_digest,
                            canonical.campaign_id,
                            canonical.capability_grant_id,
                            canonical.request_id,
                            canonical.permit_id,
                            canonical.approval_receipt_id,
                            encoded,
                        ),
                    )
                    connection.commit()
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    raise GovernedWebAssessmentModelError(
                        "Web capability grant, request, Permit, or approval receipt is already "
                        "reserved"
                    ) from exc
                except BaseException:
                    connection.rollback()
                    raise

    def _complete_with_writer(
        self,
        writer: _WebAssessmentCapabilityGrantConsumptionWriter,
        receipt: WebAssessmentCapabilityGrantConsumptionReceipt,
    ) -> None:
        if (
            type(writer) is not _WebAssessmentCapabilityGrantConsumptionWriter
            or writer is not self._writer
            or writer.store is not self
            or writer.guard is not self._writer_guard
            or writer.campaign_id != self._campaign_id
            or writer.authority_digest != receipt.grant_authority_digest
            or getattr(writer.authority, "_capability_ledger", None) is not writer.ledger
            or getattr(writer.authority, "_grant_consumption_store", None) is not self
        ):
            raise GovernedWebAssessmentModelError(
                "Web capability grant consumption writer is foreign or changed"
            )
        canonical = WebAssessmentCapabilityGrantConsumptionReceipt.model_validate(
            receipt.model_dump(mode="json", by_alias=True)
        )
        if canonical.campaign_id != self._campaign_id:
            raise GovernedWebAssessmentModelError(
                "Web capability grant consumption receipt belongs to another Campaign"
            )
        encoded = canonical_capability_json(
            canonical.model_dump(mode="json", by_alias=True),
            label="WebAssessmentCapabilityGrantConsumptionReceipt",
        ).decode("utf-8")
        with self._lock:
            self._require_exact_runtime()
            with _web_grant_store_connection(self._path, readonly=False) as connection:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    _verify_web_grant_consumption_schema(connection, self._campaign_id)
                    row = connection.execute(
                        """
                        SELECT reservation_json
                        FROM web_capability_grant_reservations
                        WHERE reservation_id = ?
                        """,
                        (canonical.reservation_id,),
                    ).fetchone()
                    if row is None:
                        raise GovernedWebAssessmentModelError(
                            "Web capability grant completion lacks its durable reservation"
                        )
                    reservation = WebAssessmentCapabilityGrantReservation.model_validate_json(
                        row[0]
                    )
                    if (
                        canonical.reservation_digest != reservation.reservation_digest
                        or canonical.campaign_id != reservation.campaign_id
                        or canonical.grant_authority_digest != reservation.grant_authority_digest
                        or canonical.capability_grant_id != reservation.capability_grant_id
                        or canonical.capability_grant_digest != reservation.capability_grant_digest
                        or canonical.request_id != reservation.request_id
                        or canonical.request_digest != reservation.request_digest
                        or canonical.permit_id != reservation.permit_id
                        or canonical.permit_digest != reservation.permit_digest
                        or canonical.approval_receipt_id != reservation.approval_receipt_id
                        or canonical.approval_receipt_digest != reservation.approval_receipt_digest
                        or canonical.consumed_at < reservation.reserved_at
                    ):
                        raise GovernedWebAssessmentModelError(
                            "Web capability grant completion differs from its reservation"
                        )
                    connection.execute(
                        """
                        INSERT INTO web_capability_grant_consumptions (
                            receipt_id,
                            receipt_digest,
                            reservation_id,
                            campaign_id,
                            capability_grant_id,
                            request_id,
                            permit_id,
                            approval_receipt_id,
                            receipt_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            canonical.receipt_id,
                            canonical.receipt_digest,
                            canonical.reservation_id,
                            canonical.campaign_id,
                            canonical.capability_grant_id,
                            canonical.request_id,
                            canonical.permit_id,
                            canonical.approval_receipt_id,
                            encoded,
                        ),
                    )
                    connection.commit()
                except sqlite3.IntegrityError as exc:
                    connection.rollback()
                    raise GovernedWebAssessmentModelError(
                        "Web capability grant completion is already recorded"
                    ) from exc
                except BaseException:
                    connection.rollback()
                    raise

    def _require_exact_runtime(self) -> None:
        if (
            _web_grant_store_file_identity(self._path) != self._file_identity
            or sha256(os.fsencode(self._path)).hexdigest() != self._path_digest
        ):
            raise GovernedWebAssessmentModelError(
                "Web capability grant consumption store path identity changed"
            )


class WebAssessmentDispatchBinding(StrictModel):
    """One already-approved Permit binding consumed exactly once by Tool.prepare."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-assessment-dispatch-binding/v1alpha1"] = Field(
        default="pajin.dev/web-assessment-dispatch-binding/v1alpha1",
        alias="apiVersion",
    )
    kind: Literal["WebAssessmentDispatchBinding"] = "WebAssessmentDispatchBinding"
    binding_id: str = Field(default="", alias="bindingId", max_length=100)
    binding_digest: str = Field(default="", alias="bindingDigest", max_length=64)
    request_id: str = Field(alias="requestId", pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    expected_run_id: str = Field(
        alias="expectedRunId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    role: Literal["source", "validation"]
    worker_execution_id: str = Field(
        alias="workerExecutionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    target_observer_execution_id: str = Field(
        alias="targetObserverExecutionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    request_digest: str = Field(alias="requestDigest", pattern=_SHA256_PATTERN)
    campaign_id: str = Field(alias="campaignId", pattern=_IDENTIFIER_PATTERN)
    campaign_digest: str = Field(alias="campaignDigest", pattern=_SHA256_PATTERN)
    capability_id: str = Field(alias="capabilityId", pattern=_IDENTIFIER_PATTERN)
    capability_version: str = Field(alias="capabilityVersion", pattern=_IDENTIFIER_PATTERN)
    capability_digest: str = Field(alias="capabilityDigest", pattern=_SHA256_PATTERN)
    capability_grant_id: str = Field(
        alias="capabilityGrantId",
        pattern=_IDENTIFIER_PATTERN,
    )
    capability_grant_digest: str = Field(
        alias="capabilityGrantDigest",
        pattern=_SHA256_PATTERN,
    )
    capability_grant_consumption_receipt_id: str = Field(
        alias="capabilityGrantConsumptionReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    capability_grant_consumption_receipt_digest: str = Field(
        alias="capabilityGrantConsumptionReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    adapter: WebAssessmentAdapterRef
    account_receipt: ProvisionedWebAccountReceiptRef = Field(alias="accountReceipt")
    approval_id: str = Field(alias="approvalId", pattern=_IDENTIFIER_PATTERN)
    approval_digest: str = Field(alias="approvalDigest", pattern=_SHA256_PATTERN)
    approval_receipt_id: str = Field(
        alias="approvalReceiptId",
        pattern=_IDENTIFIER_PATTERN,
    )
    approval_receipt_digest: str = Field(
        alias="approvalReceiptDigest",
        pattern=_SHA256_PATTERN,
    )
    permit_id: str = Field(alias="permitId", pattern=_IDENTIFIER_PATTERN)
    permit_digest: str = Field(alias="permitDigest", pattern=_SHA256_PATTERN)
    output_root_reference: str = Field(
        alias="outputRootReference",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}$",
    )
    worker_signing_material_ref: str = Field(
        alias="workerSigningMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )
    target_observer_signing_material_ref: str = Field(
        alias="targetObserverSigningMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )

    @model_validator(mode="after")
    def bind_dispatch_identity(self) -> Self:
        if self.worker_execution_id == self.target_observer_execution_id:
            raise ValueError("Web executor and target observer execution IDs must differ")
        if self.worker_signing_material_ref == self.target_observer_signing_material_ref:
            raise ValueError("Web executor and target observer signing references must differ")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"binding_id", "binding_digest"},
        )
        digest = capability_definition_digest(
            "pajin.web-assessment.dispatch-binding/v3",
            material,
        )
        binding_id = f"web-dispatch-binding_{digest}"
        if self.binding_digest and self.binding_digest != digest:
            raise ValueError("web assessment dispatch binding digest differs")
        if self.binding_id and self.binding_id != binding_id:
            raise ValueError("web assessment dispatch binding ID differs")
        object.__setattr__(self, "binding_digest", digest)
        object.__setattr__(self, "binding_id", binding_id)
        return self

    def worker_binding(self) -> dict[str, object]:
        """Return safe signed-attestation inputs without a signing-material reference."""

        return self.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "worker_signing_material_ref",
                "target_observer_signing_material_ref",
            },
        )


class WebAssessmentDispatchDeployment(StrictModel):
    """Deployment-selected process identities and in-memory material references."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    expected_run_id: str = Field(
        alias="expectedRunId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    worker_execution_id: str = Field(
        alias="workerExecutionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    target_observer_execution_id: str = Field(
        alias="targetObserverExecutionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    output_root_reference: str = Field(
        alias="outputRootReference",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,499}$",
    )
    worker_signing_material_ref: str = Field(
        alias="workerSigningMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )
    target_observer_signing_material_ref: str = Field(
        alias="targetObserverSigningMaterialRef",
        pattern=_MATERIAL_REFERENCE_PATTERN,
    )

    @model_validator(mode="after")
    def require_independent_process_material(self) -> Self:
        if self.worker_execution_id == self.target_observer_execution_id:
            raise ValueError("Web executor and target observer execution IDs must differ")
        if self.worker_signing_material_ref == self.target_observer_signing_material_ref:
            raise ValueError("Web executor and target observer signing references must differ")
        return self


class WebAssessmentDispatchAuthority:
    """Reload a consumed Graph approval tuple before constructing a Tool binding.

    ``ActionPermit`` and approval-receipt models are content-addressed but are not
    bearer capabilities.  This authority therefore treats caller-supplied copies
    only as lookup keys and accepts them solely when the exact terminal tuple can
    be reloaded from the injected durable Graph store.
    """

    _IMPLEMENTATION_ID = "pajin.web-assessment.durable-dispatch-authority"
    _IMPLEMENTATION_VERSION = "4.0.0"
    _FROZEN_ATTRIBUTES = frozenset(
        {
            "_campaign_id",
            "_capability_ledger",
            "_clock",
            "_context_digest",
            "_graph_event_log",
            "_graph_file_identity",
            "_graph_path",
            "_graph_permit_store_implementation",
            "_graph_projection_store",
            "_graph_snapshot_store",
            "_graph_store",
            "_grant_authority_digest",
            "_grant_consumption_store",
            "_grant_consumption_writer",
            "_grant_lock",
            "_grant_store_complete_implementation",
            "_grant_store_receipt_reload_implementation",
            "_grant_store_reservation_reload_implementation",
            "_grant_store_reserve_implementation",
            "_grant_store_runtime_implementation",
            "_ledger_can_consume_implementation",
            "_ledger_clock_identity",
            "_ledger_consume_implementation",
            "_ledger_lock_identity",
            "_ledger_max_depth",
            "_ledger_record_implementation",
            "_ledger_records_identity",
            "_permit_store",
            "_production_authoritative",
            "_root_grant_json",
            "_sealed",
            "_source_grant_json",
            "_validation_grant_json",
        }
    )

    @classmethod
    def create(
        cls,
        *,
        graph_store: SQLiteGraphStore,
        capability_ledger: CapabilityLedger,
        grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
        source_grant: CapabilityGrant,
        validation_grant: CapabilityGrant,
    ) -> WebAssessmentDispatchAuthority:
        """Create the production authority from exact code-owned durable stores."""

        if cls is not WebAssessmentDispatchAuthority:
            raise TypeError("Web dispatch authority factory cannot construct subclasses")
        return cls(
            graph_store=graph_store,
            capability_ledger=capability_ledger,
            grant_consumption_store=grant_consumption_store,
            source_grant=source_grant,
            validation_grant=validation_grant,
            _factory_guard=_WEB_DISPATCH_AUTHORITY_FACTORY_GUARD,
        )

    def __init__(
        self,
        *,
        graph_store: SQLiteGraphStore,
        capability_ledger: CapabilityLedger,
        grant_consumption_store: WebAssessmentCapabilityGrantConsumptionStore,
        source_grant: CapabilityGrant,
        validation_grant: CapabilityGrant,
        _factory_guard: object | None = None,
    ) -> None:
        if (
            type(self) is not WebAssessmentDispatchAuthority
            or _factory_guard is not _WEB_DISPATCH_AUTHORITY_FACTORY_GUARD
        ):
            raise TypeError("Web dispatch authority must be created by its production factory")
        if type(graph_store) is not SQLiteGraphStore:
            raise TypeError("Web dispatch authority requires the exact SQLite Graph store")
        campaign_id = graph_store.campaign_id
        if not isinstance(campaign_id, str) or not re.fullmatch(
            r"^[a-z0-9][a-z0-9-]{2,79}$",
            campaign_id,
        ):
            raise ValueError("Web dispatch authority Campaign ID is invalid")
        permit_store = graph_store.permit_store
        if type(permit_store) is not SQLiteGraphActionPermitStore:
            raise TypeError("Web dispatch authority requires the exact SQLite Permit store")
        if type(capability_ledger) is not CapabilityLedger:
            raise TypeError("Web dispatch authority requires the exact Capability Ledger")
        if type(grant_consumption_store) is not WebAssessmentCapabilityGrantConsumptionStore:
            raise TypeError("Web dispatch authority requires the exact durable Web grant store")
        if (
            "record" in vars(capability_ledger)
            or "can_consume" in vars(capability_ledger)
            or "consume" in vars(capability_ledger)
        ):
            raise TypeError("Web dispatch Capability Ledger methods must be code-owned")
        self._sealed = False
        self._production_authoritative = True
        self._campaign_id = campaign_id
        self._graph_store = graph_store
        self._graph_path = graph_store.path
        self._graph_file_identity = SQLiteGraphStore.runtime_file_identity(graph_store)
        self._graph_event_log = graph_store.event_log
        self._graph_projection_store = graph_store.projection_store
        self._graph_snapshot_store = graph_store.snapshot_store
        self._permit_store = permit_store
        self._graph_permit_store_implementation = (
            SQLiteGraphActionPermitStore.approved_authorization
        )
        self._capability_ledger = capability_ledger
        self._grant_consumption_store = grant_consumption_store
        self._clock = _system_utc_now
        self._grant_lock = Lock()
        self._ledger_max_depth = getattr(capability_ledger, "_max_depth", None)
        self._ledger_records_identity = getattr(capability_ledger, "_records", None)
        self._ledger_lock_identity = getattr(capability_ledger, "_lock", None)
        self._ledger_clock_identity = getattr(capability_ledger, "_clock", None)
        self._ledger_record_implementation = CapabilityLedger.record
        self._ledger_can_consume_implementation = CapabilityLedger.can_consume
        self._ledger_consume_implementation = CapabilityLedger.consume
        self._grant_store_receipt_reload_implementation = (
            WebAssessmentCapabilityGrantConsumptionStore.receipt_for_grant
        )
        self._grant_store_reservation_reload_implementation = (
            WebAssessmentCapabilityGrantConsumptionStore.reservation_for_grant
        )
        self._grant_store_reserve_implementation = (
            WebAssessmentCapabilityGrantConsumptionStore._reserve_with_writer
        )
        self._grant_store_complete_implementation = (
            WebAssessmentCapabilityGrantConsumptionStore._complete_with_writer
        )
        self._grant_store_runtime_implementation = (
            WebAssessmentCapabilityGrantConsumptionStore._require_exact_runtime
        )
        try:
            canonical_source = CapabilityGrant.model_validate(
                source_grant.model_dump(mode="json", by_alias=True)
            )
            canonical_validation = CapabilityGrant.model_validate(
                validation_grant.model_dump(mode="json", by_alias=True)
            )
            source_record = CapabilityLedger.record(
                capability_ledger,
                canonical_source.grant_id,
            )
            validation_record = CapabilityLedger.record(
                capability_ledger,
                canonical_validation.grant_id,
            )
        except (AttributeError, CapabilityError, TypeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "Web dispatch grants were not issued by the exact Capability Ledger"
            ) from exc
        if (
            canonical_source == canonical_validation
            or canonical_source.grant_id == canonical_validation.grant_id
            or canonical_source.subject == canonical_validation.subject
            or source_record.grant != canonical_source
            or validation_record.grant != canonical_validation
            or source_record.revoked
            or validation_record.revoked
            or source_record.remaining_calls != 1
            or validation_record.remaining_calls != 1
            or canonical_source.max_calls != 1
            or canonical_validation.max_calls != 1
            or canonical_source.campaign != campaign_id
            or canonical_validation.campaign != campaign_id
            or canonical_source.parent_grant_id is None
            or canonical_source.parent_grant_id != canonical_validation.parent_grant_id
            or canonical_source.depth != 1
            or canonical_validation.depth != 1
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch requires two distinct one-use child grants"
            )
        try:
            root_record = CapabilityLedger.record(
                capability_ledger,
                canonical_source.parent_grant_id,
            )
        except CapabilityError as exc:
            raise GovernedWebAssessmentModelError(
                "Web dispatch root grant is absent from the exact Capability Ledger"
            ) from exc
        root_grant = root_record.grant
        if (
            root_record.revoked
            or root_record.remaining_calls != 2
            or root_grant.campaign != campaign_id
            or root_grant.parent_grant_id is not None
            or root_grant.depth != 0
            or root_grant.max_calls != 2
            or not canonical_source.attenuates(root_grant)
            or not canonical_validation.attenuates(root_grant)
            or grant_consumption_store.campaign_id != campaign_id
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch root and child grant lineage is invalid"
            )
        self._root_grant_json = _canonical_grant_json(root_grant)
        self._source_grant_json = _canonical_grant_json(canonical_source)
        self._validation_grant_json = _canonical_grant_json(canonical_validation)
        self._context_digest = capability_definition_digest(
            "pajin.web-assessment.durable-dispatch-authority/v1",
            {
                "implementationId": self._IMPLEMENTATION_ID,
                "implementationVersion": self._IMPLEMENTATION_VERSION,
                "campaignId": campaign_id,
                "permitStoreContract": "durable-approved-authorization-reload-required",
                "capabilityGrantContract": (
                    "exact-ledger-issued-distinct-child-grants-with-durable-one-use-receipts"
                ),
                "grantConsumptionSchemaDigest": _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
            },
        )
        self._grant_authority_digest = self._current_grant_authority_digest()
        self._grant_consumption_writer = WebAssessmentCapabilityGrantConsumptionStore._claim_writer(
            grant_consumption_store,
            authority=self,
            ledger=capability_ledger,
        )
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False) and name in self._FROZEN_ATTRIBUTES:
            raise AttributeError("Web dispatch authority identity is immutable")
        object.__setattr__(self, name, value)

    def stable_execution_context(self) -> dict[str, object]:
        self._require_exact_runtime()
        return {
            "implementationId": self._IMPLEMENTATION_ID,
            "implementationVersion": self._IMPLEMENTATION_VERSION,
            "campaignId": self._campaign_id,
            "authorityDigest": self._context_digest,
            "permitStoreContract": "durable-approved-authorization-reload-required",
            "permitStoreImplementation": "pajin.graph.sqlite_store.SQLiteGraphActionPermitStore",
            "capabilityGrantContract": (
                "exact-ledger-issued-distinct-child-grants-with-durable-one-use-receipts"
            ),
            "grantConsumptionSchemaDigest": _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
        }

    def authorized_grant(
        self,
        role: Literal["source", "validation"],
    ) -> CapabilityGrant:
        self._require_exact_runtime()
        return self._grant_for_role(role)

    def _grant_for_role(self, role: Literal["source", "validation"]) -> CapabilityGrant:
        if role == "source":
            return CapabilityGrant.model_validate_json(self._source_grant_json)
        if role == "validation":
            return CapabilityGrant.model_validate_json(self._validation_grant_json)
        raise ValueError("Web dispatch grant role is invalid")

    def _canonical_grants(self) -> tuple[CapabilityGrant, CapabilityGrant, CapabilityGrant]:
        return (
            CapabilityGrant.model_validate_json(self._root_grant_json),
            CapabilityGrant.model_validate_json(self._source_grant_json),
            CapabilityGrant.model_validate_json(self._validation_grant_json),
        )

    def _current_grant_authority_digest(self) -> str:
        root_grant, source_grant, validation_grant = self._canonical_grants()
        return capability_definition_digest(
            "pajin.web-assessment.capability-grant-authority-runtime/v1",
            {
                "campaignId": self._campaign_id,
                "implementationId": self._IMPLEMENTATION_ID,
                "implementationVersion": self._IMPLEMENTATION_VERSION,
                "ledgerImplementation": "pajin.policy.capability.CapabilityLedger",
                "ledgerMaxDepth": self._ledger_max_depth,
                "rootGrantId": root_grant.grant_id,
                "rootGrantDigest": capability_grant_digest(root_grant),
                "sourceGrantId": source_grant.grant_id,
                "sourceGrantDigest": capability_grant_digest(source_grant),
                "validationGrantId": validation_grant.grant_id,
                "validationGrantDigest": capability_grant_digest(validation_grant),
                "grantStore": self._grant_consumption_store.stable_execution_context(),
            },
        )

    def _require_exact_graph_runtime(self) -> None:
        graph_store = self._graph_store
        permit_store = self._permit_store
        if (
            type(graph_store) is not SQLiteGraphStore
            or graph_store.campaign_id != self._campaign_id
            or graph_store.path != self._graph_path
            or graph_store.event_log is not self._graph_event_log
            or graph_store.projection_store is not self._graph_projection_store
            or graph_store.snapshot_store is not self._graph_snapshot_store
            or graph_store.permit_store is not permit_store
            or graph_store.approved_permit_store is not permit_store
            or type(permit_store) is not SQLiteGraphActionPermitStore
            or permit_store.path != self._graph_path
            or getattr(permit_store, "_campaign_id", None) != self._campaign_id
            or SQLiteGraphActionPermitStore.approved_authorization
            is not self._graph_permit_store_implementation
            or "approved_authorization" in vars(permit_store)
            or SQLiteGraphStore.runtime_file_identity(graph_store)
            != self._graph_file_identity
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch SQLite Graph store identity or implementation changed"
            )

    def _require_exact_runtime(self) -> None:
        if (
            type(self) is not WebAssessmentDispatchAuthority
            or self._production_authoritative is not True
            or self._clock is not _system_utc_now
            or "authorize_binding" in vars(self)
            or "require_exact_graph_dispatcher" in vars(self)
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch production authority identity or implementation changed"
            )
        self._require_exact_graph_runtime()
        self._require_exact_grant_runtime()

    def _require_exact_grant_runtime(self) -> None:
        ledger = self._capability_ledger
        store = self._grant_consumption_store
        root_grant, source_grant, validation_grant = self._canonical_grants()
        if (
            type(ledger) is not CapabilityLedger
            or CapabilityLedger.record is not self._ledger_record_implementation
            or CapabilityLedger.can_consume is not self._ledger_can_consume_implementation
            or CapabilityLedger.consume is not self._ledger_consume_implementation
            or getattr(ledger, "_max_depth", None) != self._ledger_max_depth
            or getattr(ledger, "_records", None) is not self._ledger_records_identity
            or getattr(ledger, "_lock", None) is not self._ledger_lock_identity
            or getattr(ledger, "_clock", None) is not self._ledger_clock_identity
            or "record" in vars(ledger)
            or "can_consume" in vars(ledger)
            or "consume" in vars(ledger)
            or type(store) is not WebAssessmentCapabilityGrantConsumptionStore
            or store.campaign_id != self._campaign_id
            or WebAssessmentCapabilityGrantConsumptionStore.receipt_for_grant
            is not self._grant_store_receipt_reload_implementation
            or WebAssessmentCapabilityGrantConsumptionStore.reservation_for_grant
            is not self._grant_store_reservation_reload_implementation
            or WebAssessmentCapabilityGrantConsumptionStore._reserve_with_writer
            is not self._grant_store_reserve_implementation
            or WebAssessmentCapabilityGrantConsumptionStore._complete_with_writer
            is not self._grant_store_complete_implementation
            or WebAssessmentCapabilityGrantConsumptionStore._require_exact_runtime
            is not self._grant_store_runtime_implementation
            or "receipt_for_grant" in getattr(store, "__dict__", {})
            or "reservation_for_grant" in getattr(store, "__dict__", {})
            or "_reserve_with_writer" in getattr(store, "__dict__", {})
            or "_complete_with_writer" in getattr(store, "__dict__", {})
            or "_claim_writer" in getattr(store, "__dict__", {})
            or self._grant_consumption_writer.store is not store
            or self._grant_consumption_writer.authority is not self
            or self._grant_consumption_writer.ledger is not ledger
            or self._grant_consumption_writer.authority_digest != self._grant_authority_digest
            or self._current_grant_authority_digest() != self._grant_authority_digest
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Capability Ledger or durable grant authority changed"
            )
        self._grant_store_runtime_implementation(store)
        try:
            root_record = self._ledger_record_implementation(
                ledger,
                root_grant.grant_id,
            )
            source_record = self._ledger_record_implementation(
                ledger,
                source_grant.grant_id,
            )
            validation_record = self._ledger_record_implementation(
                ledger,
                validation_grant.grant_id,
            )
        except CapabilityError as exc:
            raise GovernedWebAssessmentModelError(
                "Web dispatch grant lineage disappeared from the exact ledger"
            ) from exc
        if (
            root_record.grant != root_grant
            or source_record.grant != source_grant
            or validation_record.grant != validation_grant
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch grant lineage differs from its issued authority"
            )

    def _consume_authorized_grant(
        self,
        *,
        role: Literal["source", "validation"],
        grant: CapabilityGrant,
        request: ToolRequest,
        permit: ActionPermit,
        approval_receipt: ActionApprovalConsumptionReceipt,
        consumed_at: datetime,
    ) -> WebAssessmentCapabilityGrantConsumptionReceipt:
        with self._grant_lock:
            self._require_exact_runtime()
            pinned_grant = self._grant_for_role(role)
            if grant != pinned_grant:
                raise GovernedWebAssessmentModelError(
                    "Web dispatch grant differs from its ledger-issued execution role"
                )
            try:
                record = self._ledger_record_implementation(
                    self._capability_ledger,
                    pinned_grant.grant_id,
                )
                can_consume = self._ledger_can_consume_implementation(
                    self._capability_ledger,
                    pinned_grant.grant_id,
                )
            except CapabilityError as exc:
                raise GovernedWebAssessmentModelError(
                    "Web dispatch grant cannot be reloaded from its exact ledger"
                ) from exc
            existing_reservation = self._grant_store_reservation_reload_implementation(
                self._grant_consumption_store,
                pinned_grant.grant_id,
            )
            existing_receipt = self._grant_store_receipt_reload_implementation(
                self._grant_consumption_store,
                pinned_grant.grant_id,
            )
            if (
                record.grant != pinned_grant
                or record.revoked
                or record.remaining_calls != 1
                or not can_consume
                or existing_reservation is not None
                or existing_receipt is not None
            ):
                raise GovernedWebAssessmentModelError(
                    "Web dispatch capability grant is revoked, exhausted, or already consumed"
                )
            reservation = WebAssessmentCapabilityGrantReservation(
                campaignId=self._campaign_id,
                grantAuthorityDigest=self._grant_authority_digest,
                capabilityGrantId=pinned_grant.grant_id,
                capabilityGrantDigest=capability_grant_digest(pinned_grant),
                requestId=request.request_id,
                requestDigest=capability_tool_request_digest(request),
                permitId=permit.permit_id,
                permitDigest=permit.permit_digest,
                approvalReceiptId=approval_receipt.receipt_id,
                approvalReceiptDigest=approval_receipt.receipt_digest,
                reservedAt=consumed_at,
            )
            # The durable, unique reservation is written before the ephemeral ledger.
            # A crash at either later boundary permanently burns this grant and keeps
            # the caller callback unreachable after controller reconstruction.
            self._grant_store_reserve_implementation(
                self._grant_consumption_store,
                self._grant_consumption_writer,
                reservation,
            )
            try:
                self._ledger_consume_implementation(
                    self._capability_ledger,
                    pinned_grant.grant_id,
                )
            except CapabilityError as exc:
                raise GovernedWebAssessmentModelError(
                    "Web dispatch capability grant consumption failed closed"
                ) from exc
            completed_at = _aware_utc(self._clock(), label="Web dispatch authority clock")
            if not consumed_at <= completed_at < min(permit.expires_at, pinned_grant.expires_at):
                raise GovernedWebAssessmentModelError(
                    "Web dispatch authority expired while consuming its capability grant"
                )
            grant_receipt = WebAssessmentCapabilityGrantConsumptionReceipt(
                reservationId=reservation.reservation_id,
                reservationDigest=reservation.reservation_digest,
                campaignId=self._campaign_id,
                grantAuthorityDigest=self._grant_authority_digest,
                capabilityGrantId=pinned_grant.grant_id,
                capabilityGrantDigest=capability_grant_digest(pinned_grant),
                requestId=request.request_id,
                requestDigest=capability_tool_request_digest(request),
                permitId=permit.permit_id,
                permitDigest=permit.permit_digest,
                approvalReceiptId=approval_receipt.receipt_id,
                approvalReceiptDigest=approval_receipt.receipt_digest,
                consumedAt=completed_at,
            )
            self._grant_store_complete_implementation(
                self._grant_consumption_store,
                self._grant_consumption_writer,
                grant_receipt,
            )
            stored_receipt = self._grant_store_receipt_reload_implementation(
                self._grant_consumption_store,
                pinned_grant.grant_id,
            )
            if stored_receipt != grant_receipt:
                raise GovernedWebAssessmentModelError(
                    "Web capability grant completion could not be reloaded exactly"
                )
            return stored_receipt

    def require_exact_graph_dispatcher(
        self,
        dispatcher: GraphApprovedActionPermitDispatcher,
    ) -> None:
        self._require_exact_runtime()
        graph_authority = getattr(dispatcher, "_authority", None)
        if (
            type(dispatcher) is not GraphApprovedActionPermitDispatcher
            or type(graph_authority) is not GraphApprovedActionPermitAuthority
            or getattr(graph_authority, "_campaign_id", None) != self._campaign_id
            or getattr(graph_authority, "_permit_store", None) is not self._permit_store
            or "dispatch_once" in vars(dispatcher)
            or "authorize_for_dispatch" in vars(graph_authority)
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch requires the exact Graph authority and durable store identity"
            )

    def authorize_binding(
        self,
        *,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        capability: RegisteredActionCapability,
        request: ToolRequest,
        adapter: WebAssessmentAdapterManifest,
        account_receipt: ProvisionedWebAccountReceipt,
        permit: ActionPermit,
        approval_receipt: ActionApprovalConsumptionReceipt,
        deployment: WebAssessmentDispatchDeployment,
    ) -> WebAssessmentDispatchBinding:
        self._require_exact_runtime()
        try:
            canonical_campaign = CampaignManifest.model_validate(
                campaign.model_dump(mode="json", by_alias=True)
            )
            canonical_grant = CapabilityGrant.model_validate(
                grant.model_dump(mode="json", by_alias=True)
            )
            canonical_capability = RegisteredActionCapability.model_validate(
                capability.model_dump(mode="json", by_alias=True)
            )
            canonical_request = ToolRequest.model_validate(
                request.model_dump(mode="json", by_alias=True)
            )
            canonical_adapter = WebAssessmentAdapterManifest.model_validate(
                adapter.model_dump(mode="json", by_alias=True)
            )
            canonical_account = ProvisionedWebAccountReceipt.model_validate(
                account_receipt.model_dump(mode="json", by_alias=True)
            )
            canonical_permit = ActionPermit.model_validate(
                permit.model_dump(mode="json", by_alias=True)
            )
            canonical_receipt = ActionApprovalConsumptionReceipt.model_validate(
                approval_receipt.model_dump(mode="json", by_alias=True)
            )
            canonical_deployment = WebAssessmentDispatchDeployment.model_validate(
                deployment.model_dump(mode="json", by_alias=True)
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "Web dispatch authority inputs are not canonical"
            ) from exc

        stored_raw = self._graph_permit_store_implementation(
            self._permit_store,
            canonical_receipt.approval.approval_id,
            canonical_permit.permit_id,
        )
        if stored_raw is None:
            raise GovernedWebAssessmentModelError(
                "Web dispatch authority could not reload durable approved authority"
            )
        try:
            stored = ActionApprovalAuthorization.model_validate(
                stored_raw.model_dump(mode="json", by_alias=True)
            )
            supplied_terminal = ActionApprovalAuthorization(
                approval=canonical_receipt.approval,
                action=ActionPermitAuthorization(
                    permit=canonical_permit,
                    newlyConsumed=False,
                ),
                receipt=canonical_receipt,
            )
        except (AttributeError, TypeError, ValidationError, ValueError) as exc:
            raise GovernedWebAssessmentModelError(
                "Web dispatch durable approved authority is invalid"
            ) from exc
        if stored.action.newly_consumed or stored != supplied_terminal:
            raise GovernedWebAssessmentModelError(
                "Web dispatch inputs differ from durable approved authority"
            )

        approval = stored.approval
        issuer_roles = {
            "pajin.web-action-approval.source": "source",
            "pajin.web-action-approval.validation": "validation",
        }
        role = issuer_roles.get(approval.issuer.authority_id)
        if role is None:
            raise GovernedWebAssessmentModelError(
                "Web dispatch approval issuer does not identify an execution role"
            )
        current = _aware_utc(self._clock(), label="Web dispatch authority clock")
        campaign_digest = campaign_manifest_digest(canonical_campaign)
        grant_digest = capability_grant_digest(canonical_grant)
        capability_ref = canonical_capability.reference()
        request_digest = capability_tool_request_digest(canonical_request)
        parameters_digest = capability_normalized_parameters_digest(canonical_request.arguments)
        if (
            canonical_campaign.metadata.name != self._campaign_id
            or canonical_grant.campaign != self._campaign_id
            or canonical_grant.subject != canonical_request.agent_id
            or canonical_request.tool_id not in canonical_grant.tools
            or canonical_request.target not in canonical_grant.targets
            or canonical_grant.max_risk_tier < canonical_capability.risk_tier
            or canonical_grant.max_calls < 1
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Campaign or capability Grant binding differs"
            )
        if (
            not canonical_grant.issued_at <= current < canonical_grant.expires_at
            or not canonical_campaign.spec.authorization.is_active(current)
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Campaign or capability Grant is not active"
            )
        if (
            approval.campaign_id != self._campaign_id
            or approval.campaign_digest != campaign_digest
            or canonical_permit.campaign_id != self._campaign_id
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch approval or Permit Campaign binding differs"
            )
        if (
            canonical_permit.run_id != canonical_deployment.expected_run_id
            or approval.run_id != canonical_deployment.expected_run_id
            or approval.proposal.run_id != canonical_deployment.expected_run_id
            or approval.mission_envelope.run_id != canonical_deployment.expected_run_id
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Run lineage differs from deployment"
            )
        if (
            canonical_permit.capability != capability_ref
            or canonical_permit.request_id != canonical_request.request_id
            or canonical_permit.request_digest != request_digest
            or canonical_permit.normalized_parameters_digest != parameters_digest
            or canonical_capability.tool_id != canonical_request.tool_id
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Capability or request binding differs"
            )
        if (
            canonical_permit.target_digest != canonical_account.target_identity_digest
            or canonical_request.target != canonical_adapter.origin
            or canonical_account.origin != canonical_adapter.origin
            or canonical_account.adapter != canonical_adapter.reference()
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch Target, adapter, or account binding differs"
            )
        if not canonical_permit.consumed_at <= current < canonical_permit.expires_at:
            raise GovernedWebAssessmentModelError("Web dispatch ActionPermit is not active")
        grant_receipt = self._consume_authorized_grant(
            role=cast(Literal["source", "validation"], role),
            grant=canonical_grant,
            request=canonical_request,
            permit=canonical_permit,
            approval_receipt=canonical_receipt,
            consumed_at=current,
        )
        return WebAssessmentDispatchBinding(
            requestId=canonical_request.request_id,
            expectedRunId=canonical_deployment.expected_run_id,
            role=cast(Literal["source", "validation"], role),
            workerExecutionId=canonical_deployment.worker_execution_id,
            targetObserverExecutionId=canonical_deployment.target_observer_execution_id,
            requestDigest=request_digest,
            campaignId=self._campaign_id,
            campaignDigest=campaign_digest,
            capabilityId=canonical_capability.capability_id,
            capabilityVersion=canonical_capability.capability_version,
            capabilityDigest=canonical_capability.definition_digest,
            capabilityGrantId=canonical_grant.grant_id,
            capabilityGrantDigest=grant_digest,
            capabilityGrantConsumptionReceiptId=grant_receipt.receipt_id,
            capabilityGrantConsumptionReceiptDigest=grant_receipt.receipt_digest,
            adapter=canonical_adapter.reference(),
            accountReceipt=canonical_account.reference(),
            approvalId=approval.approval_id,
            approvalDigest=approval.approval_digest,
            approvalReceiptId=canonical_receipt.receipt_id,
            approvalReceiptDigest=canonical_receipt.receipt_digest,
            permitId=canonical_permit.permit_id,
            permitDigest=canonical_permit.permit_digest,
            outputRootReference=canonical_deployment.output_root_reference,
            workerSigningMaterialRef=canonical_deployment.worker_signing_material_ref,
            targetObserverSigningMaterialRef=(
                canonical_deployment.target_observer_signing_material_ref
            ),
        )


class _WebAssessmentLiveDispatchClaim:
    """Opaque callback capability scoped to one dispatcher and one registry instance."""

    __slots__ = ("audience", "guard", "issuer", "permit", "receipt")

    def __init__(
        self,
        *,
        issuer: WebAssessmentApprovedActionDispatcher,
        audience: object,
        permit: ActionPermit,
        receipt: ActionApprovalConsumptionReceipt,
        guard: object,
    ) -> None:
        if guard is not issuer._mint_guard:
            raise TypeError("live Web dispatch claims are minted only by their dispatcher")
        self.issuer = issuer
        self.audience = audience
        self.permit = permit
        self.receipt = receipt
        self.guard = guard


class WebAssessmentApprovedActionDispatcher:
    """Mint one live, audience-bound claim only inside a new Graph dispatch callback."""

    _IMPLEMENTATION_ID = "pajin.web-assessment.approved-action-dispatcher"
    _IMPLEMENTATION_VERSION = "1.0.0"

    def __init__(self) -> None:
        self._lock = Lock()
        self._dispatcher: GraphApprovedActionPermitDispatcher | None = None
        self._graph_authority: GraphApprovedActionPermitAuthority | None = None
        self._permit_store: GraphApprovedActionPermitStore | None = None
        self._mint_guard = object()
        self._open_claims: dict[int, _WebAssessmentLiveDispatchClaim] = {}

    def install(self, dispatcher: GraphApprovedActionPermitDispatcher) -> None:
        if type(dispatcher) is not GraphApprovedActionPermitDispatcher:
            raise TypeError("live Web dispatch requires the exact Graph approved dispatcher")
        graph_authority = getattr(dispatcher, "_authority", None)
        if type(graph_authority) is not GraphApprovedActionPermitAuthority:
            raise TypeError("live Web dispatch requires the exact Graph approved authority")
        with self._lock:
            if self._dispatcher is not None:
                raise GovernedWebAssessmentModelError(
                    "live Web Graph dispatcher is already installed"
                )
            self._dispatcher = dispatcher
            self._graph_authority = graph_authority
            self._permit_store = getattr(graph_authority, "_permit_store", None)

    def stable_execution_context(self) -> dict[str, object]:
        return {
            "implementationId": self._IMPLEMENTATION_ID,
            "implementationVersion": self._IMPLEMENTATION_VERSION,
            "graphDispatcherInstallation": "one-time-exact-authority",
            "claimLifetime": "new-consumption-callback-only",
            "claimAudienceBinding": "registry-object-identity",
        }

    async def dispatch_once[DispatchResultT](
        self,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        *,
        audience: object,
        dispatch: Callable[[_WebAssessmentLiveDispatchClaim], Awaitable[DispatchResultT]],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        if not _is_async_callable(dispatch):
            raise TypeError("live Web dispatch callback must be async")
        with self._lock:
            dispatcher = self._dispatcher
            graph_authority = self._graph_authority
            permit_store = self._permit_store
        if dispatcher is None or graph_authority is None or permit_store is None:
            raise GovernedWebAssessmentModelError("live Web Graph dispatcher is not installed")
        if (
            type(dispatcher) is not GraphApprovedActionPermitDispatcher
            or getattr(dispatcher, "_authority", None) is not graph_authority
            or type(graph_authority) is not GraphApprovedActionPermitAuthority
            or getattr(graph_authority, "_permit_store", None) is not permit_store
            or "dispatch_once" in vars(dispatcher)
            or "authorize_for_dispatch" in vars(graph_authority)
        ):
            raise GovernedWebAssessmentModelError(
                "live Web Graph dispatcher installation identity changed"
            )

        async def mint_and_dispatch(
            permit: ActionPermit,
            receipt: ActionApprovalConsumptionReceipt,
        ) -> DispatchResultT:
            claim = _WebAssessmentLiveDispatchClaim(
                issuer=self,
                audience=audience,
                permit=permit,
                receipt=receipt,
                guard=self._mint_guard,
            )
            claim_identity = id(claim)
            with self._lock:
                self._open_claims[claim_identity] = claim
            try:
                return await dispatch(claim)
            finally:
                with self._lock:
                    self._open_claims.pop(claim_identity, None)

        return await dispatcher.dispatch_once(
            envelope,
            proposal,
            decision,
            approval,
            mint_and_dispatch,
        )

    def consume_claim(
        self,
        claim: _WebAssessmentLiveDispatchClaim,
        *,
        audience: object,
    ) -> tuple[ActionPermit, ActionApprovalConsumptionReceipt]:
        with self._lock:
            if (
                not isinstance(claim, _WebAssessmentLiveDispatchClaim)
                or claim.issuer is not self
                or claim.guard is not self._mint_guard
                or claim.audience is not audience
                or self._open_claims.pop(id(claim), None) is not claim
            ):
                raise GovernedWebAssessmentModelError(
                    "live Web dispatch claim is foreign, expired, or already consumed"
                )
        return (
            ActionPermit.model_validate(claim.permit.model_dump(mode="json", by_alias=True)),
            ActionApprovalConsumptionReceipt.model_validate(
                claim.receipt.model_dump(mode="json", by_alias=True)
            ),
        )


class WebAssessmentDispatchBindingRegistry:
    """One-shot Tool handoff reachable only from a live Graph dispatch callback."""

    __slots__ = (
        "__approved_dispatcher",
        "__authority",
        "__authority_context_digest",
        "__campaign_id",
        "__grant_authority_digest",
        "__permit_store",
        "_approval_receipt_ids",
        "_available",
        "_consumed",
        "_dispatch_ids",
        "_lock",
        "_permit_ids",
        "_sealed",
    )

    _FROZEN_ATTRIBUTES = frozenset(
        {
            "_WebAssessmentDispatchBindingRegistry__approved_dispatcher",
            "_WebAssessmentDispatchBindingRegistry__authority",
            "_WebAssessmentDispatchBindingRegistry__authority_context_digest",
            "_WebAssessmentDispatchBindingRegistry__campaign_id",
            "_WebAssessmentDispatchBindingRegistry__grant_authority_digest",
            "_WebAssessmentDispatchBindingRegistry__permit_store",
            "_approved_dispatcher",
            "_authority",
            "_lock",
            "_sealed",
        }
    )

    def __init__(self, *, authority: WebAssessmentDispatchAuthority) -> None:
        if (
            type(authority) is not WebAssessmentDispatchAuthority
            or "authorize_binding" in vars(authority)
            or "require_exact_graph_dispatcher" in vars(authority)
        ):
            raise TypeError("Web dispatch registry requires its code-owned durable authority")
        approved_dispatcher = WebAssessmentApprovedActionDispatcher()
        self.__authority = authority
        self.__approved_dispatcher = approved_dispatcher
        self.__campaign_id = authority._campaign_id
        self.__permit_store = authority._permit_store
        self.__grant_authority_digest = authority._grant_authority_digest
        self.__authority_context_digest = capability_definition_digest(
            "pajin.web-assessment.dispatch-authority-context/v1",
            authority.stable_execution_context(),
        )
        self._lock = Lock()
        self._available: dict[str, WebAssessmentDispatchBinding] = {}
        self._consumed: dict[str, WebAssessmentDispatchBinding] = {}
        self._dispatch_ids: set[str] = set()
        self._permit_ids: set[str] = set()
        self._approval_receipt_ids: set[str] = set()
        self._sealed = True

    def __setattr__(self, name: str, value: object) -> None:
        if getattr(self, "_sealed", False) and name in self._FROZEN_ATTRIBUTES:
            raise AttributeError("Web dispatch registry authority identity is immutable")
        object.__setattr__(self, name, value)

    def _exact_runtime(
        self,
    ) -> tuple[WebAssessmentDispatchAuthority, WebAssessmentApprovedActionDispatcher]:
        authority = self.__authority
        approved_dispatcher = self.__approved_dispatcher
        if (
            type(authority) is not WebAssessmentDispatchAuthority
            or authority._campaign_id != self.__campaign_id
            or authority._permit_store is not self.__permit_store
            or authority._grant_authority_digest != self.__grant_authority_digest
            or "authorize_binding" in vars(authority)
            or "require_exact_graph_dispatcher" in vars(authority)
            or capability_definition_digest(
                "pajin.web-assessment.dispatch-authority-context/v1",
                WebAssessmentDispatchAuthority.stable_execution_context(authority),
            )
            != self.__authority_context_digest
            or type(approved_dispatcher) is not WebAssessmentApprovedActionDispatcher
            or "dispatch_once" in vars(approved_dispatcher)
            or "consume_claim" in vars(approved_dispatcher)
            or "install" in vars(approved_dispatcher)
        ):
            raise GovernedWebAssessmentModelError(
                "Web dispatch registry authority identity or implementation changed"
            )
        return authority, approved_dispatcher

    def authorized_grant(
        self,
        role: Literal["source", "validation"],
    ) -> CapabilityGrant:
        authority, _approved_dispatcher = self._exact_runtime()
        return WebAssessmentDispatchAuthority.authorized_grant(authority, role)

    def capability_grant_consumption_receipt(
        self,
        grant_id: str,
    ) -> WebAssessmentCapabilityGrantConsumptionReceipt | None:
        authority, _approved_dispatcher = self._exact_runtime()
        return WebAssessmentCapabilityGrantConsumptionStore.receipt_for_grant(
            authority._grant_consumption_store,
            grant_id,
        )

    def stable_execution_context(self) -> dict[str, object]:
        authority, approved_dispatcher = self._exact_runtime()
        return {
            "implementationVersion": "pajin.web-assessment.dispatch-binding-registry/v4",
            "authority": WebAssessmentDispatchAuthority.stable_execution_context(authority),
            "approvedDispatcher": (
                WebAssessmentApprovedActionDispatcher.stable_execution_context(approved_dispatcher)
            ),
            "bindingConstruction": "durable-approved-authority-only",
            "dispatchIdentityReuseAllowed": False,
        }

    def install_dispatcher(self, dispatcher: GraphApprovedActionPermitDispatcher) -> None:
        authority, approved_dispatcher = self._exact_runtime()
        WebAssessmentDispatchAuthority.require_exact_graph_dispatcher(
            authority,
            dispatcher,
        )
        WebAssessmentApprovedActionDispatcher.install(
            approved_dispatcher,
            dispatcher,
        )

    async def dispatch_approved_once[DispatchResultT](
        self,
        *,
        envelope: MissionEnvelope,
        proposal: ActionProposal,
        decision: GraphDecision,
        approval: ActionApprovalEnvelope,
        campaign: CampaignManifest,
        grant: CapabilityGrant,
        capability: RegisteredActionCapability,
        request: ToolRequest,
        adapter: WebAssessmentAdapterManifest,
        account_receipt: ProvisionedWebAccountReceipt,
        deployment: WebAssessmentDispatchDeployment,
        dispatch: Callable[[WebAssessmentDispatchBinding], Awaitable[DispatchResultT]],
    ) -> ApprovedActionDispatchResult[DispatchResultT]:
        if not _is_async_callable(dispatch):
            raise TypeError("approved Web Tool dispatch callback must be async")
        authority, approved_dispatcher = self._exact_runtime()

        async def bind_live_claim(
            claim: _WebAssessmentLiveDispatchClaim,
        ) -> DispatchResultT:
            exact_authority, exact_dispatcher = self._exact_runtime()
            if exact_authority is not authority or exact_dispatcher is not approved_dispatcher:
                raise GovernedWebAssessmentModelError(
                    "Web dispatch registry authority changed during approval consumption"
                )
            permit, approval_receipt = WebAssessmentApprovedActionDispatcher.consume_claim(
                approved_dispatcher,
                claim,
                audience=self,
            )
            binding = WebAssessmentDispatchAuthority.authorize_binding(
                authority,
                campaign=campaign,
                grant=grant,
                capability=capability,
                request=request,
                adapter=adapter,
                account_receipt=account_receipt,
                permit=permit,
                approval_receipt=approval_receipt,
                deployment=deployment,
            )
            canonical = WebAssessmentDispatchBinding.model_validate(
                binding.model_dump(mode="json", by_alias=True)
            )
            with self._lock:
                if (
                    canonical.request_id in self._available
                    or canonical.request_id in self._consumed
                    or permit.dispatch_id in self._dispatch_ids
                    or permit.permit_id in self._permit_ids
                    or approval_receipt.receipt_id in self._approval_receipt_ids
                ):
                    raise GovernedWebAssessmentModelError(
                        "web assessment dispatch authority is already bound or consumed"
                    )
                self._available[canonical.request_id] = canonical
                self._dispatch_ids.add(permit.dispatch_id)
                self._permit_ids.add(permit.permit_id)
                self._approval_receipt_ids.add(approval_receipt.receipt_id)
            try:
                return await dispatch(canonical.model_copy(deep=True))
            finally:
                with self._lock:
                    self._available.pop(canonical.request_id, None)

        return await WebAssessmentApprovedActionDispatcher.dispatch_once(
            approved_dispatcher,
            envelope,
            proposal,
            decision,
            approval,
            audience=self,
            dispatch=bind_live_claim,
        )

    def consume(self, request_id: str) -> WebAssessmentDispatchBinding:
        with self._lock:
            try:
                binding = self._available.pop(request_id)
            except KeyError as exc:
                raise GovernedWebAssessmentModelError(
                    "web assessment dispatch binding is unavailable or already consumed"
                ) from exc
            self._consumed[request_id] = binding
            return binding.model_copy(deep=True)

    def consumed(self, request_id: str) -> WebAssessmentDispatchBinding:
        with self._lock:
            try:
                return self._consumed[request_id].model_copy(deep=True)
            except KeyError as exc:
                raise GovernedWebAssessmentModelError(
                    "web assessment dispatch was not prepared"
                ) from exc

    def complete(self, request_id: str) -> None:
        with self._lock:
            if self._consumed.pop(request_id, None) is None:
                raise GovernedWebAssessmentModelError(
                    "web assessment dispatch completion is not current"
                )


class WebAuthenticatedAssessmentWorkerOutput(StrictModel):
    """Minimal bounded output normalized by the executable Capability Tool."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/web-authenticated-assessment-worker-output/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_WORKER_OUTPUT_API_VERSION, alias="apiVersion"
    )
    kind: Literal["WebAuthenticatedAssessmentWorkerOutput"] = (
        "WebAuthenticatedAssessmentWorkerOutput"
    )
    adapter: WebAssessmentAdapterRef
    account_receipt: ProvisionedWebAccountReceiptRef = Field(alias="accountReceipt")
    dispatch_binding_digest: str = Field(alias="dispatchBindingDigest", pattern=_SHA256_PATTERN)
    worker_execution_id: str = Field(
        alias="workerExecutionId",
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    origin: str = Field(min_length=8, max_length=2_000)
    run_id: str = Field(alias="runId", pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
    root_digest: str = Field(alias="rootDigest", pattern=_SHA256_PATTERN)
    result_digest: str = Field(alias="resultDigest", pattern=_SHA256_PATTERN)
    attestation_digest: str = Field(alias="attestationDigest", pattern=_SHA256_PATTERN)
    worker_attestation: dict[str, JsonValue] = Field(
        alias="workerAttestation",
        min_length=1,
        max_length=32,
    )
    authenticated: Literal[True]
    browser_closed: Literal[True] = Field(alias="browserClosed")
    target_mutated: Literal[False] = Field(alias="targetMutated")
    server_session_material_persisted: Literal[False] = Field(
        alias="serverSessionMaterialPersisted"
    )

    @field_validator("origin")
    @classmethod
    def require_exact_origin(cls, value: str) -> str:
        return canonical_web_origin(value)

    @field_validator("authenticated", "browser_closed", mode="before")
    @classmethod
    def require_true_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("successful web worker markers must be boolean true")
        return value

    @field_validator("target_mutated", "server_session_material_persisted", mode="before")
    @classmethod
    def require_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("read-only web worker markers must be boolean false")
        return value


class WebAssessmentAdapterRegistry:
    """Immutable verified inventory of deployment-installed code-owned adapters."""

    def __init__(
        self,
        *,
        keys: Iterable[WebAssessmentVerificationKey],
        adapters: Iterable[SignedWebAssessmentAdapter],
        clock: Callable[[], datetime] | None = None,
        catalog: AdapterImplementationCatalog | None = None,
    ) -> None:
        self._clock = clock or web_assessment_system_utc_now
        selected_catalog = (
            production_adapter_implementation_catalog() if catalog is None else catalog
        )
        if type(selected_catalog) is not AdapterImplementationCatalog:
            raise GovernedWebAssessmentModelError(
                "web assessment implementation catalog is not code-owned"
            )
        try:
            self.catalog_digest = selected_catalog.catalog_digest
        except AdapterImplementationCatalogError as exc:
            raise GovernedWebAssessmentModelError(
                "web assessment implementation catalog is not current"
            ) from exc
        self._catalog = selected_catalog
        self._keys = _keyring(keys, role=WebAssessmentSigningRole.ADAPTER_PUBLISHER)
        installed: dict[tuple[str, str, str], SignedWebAssessmentAdapter] = {}
        for raw in adapters:
            signed = SignedWebAssessmentAdapter.model_validate(
                raw.model_dump(mode="json", by_alias=True)
            )
            self._verify(signed, now=self._now())
            reference = signed.manifest.reference()
            key = (reference.adapter_id, reference.adapter_version, reference.adapter_digest)
            if key in installed:
                raise GovernedWebAssessmentModelError("web assessment adapter is duplicated")
            installed[key] = signed
        if not installed:
            raise GovernedWebAssessmentModelError("web assessment adapter registry is empty")
        self._adapters = installed
        self.registry_digest = capability_definition_digest(
            "pajin.web-assessment.adapter-registry/v1",
            {
                "catalogDigest": self.catalog_digest,
                "keys": [
                    self._keys[key].model_dump(mode="json", by_alias=True)
                    for key in sorted(self._keys)
                ],
                "adapters": [
                    self._adapters[key].model_dump(mode="json", by_alias=True)
                    for key in sorted(self._adapters)
                ],
            },
        )

    def resolve(self, reference: WebAssessmentAdapterRef) -> WebAssessmentAdapterManifest:
        canonical = WebAssessmentAdapterRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
        key = (canonical.adapter_id, canonical.adapter_version, canonical.adapter_digest)
        try:
            signed = self._adapters[key]
        except KeyError as exc:
            raise GovernedWebAssessmentModelError(
                "web assessment adapter is not installed"
            ) from exc
        self._verify(signed, now=self._now())
        return signed.manifest.model_copy(deep=True)

    def references(self) -> tuple[WebAssessmentAdapterRef, ...]:
        return tuple(self._adapters[key].manifest.reference() for key in sorted(self._adapters))

    def _verify(self, signed: SignedWebAssessmentAdapter, *, now: datetime) -> None:
        manifest = signed.manifest
        _verify_signed(
            key_id=signed.key_id,
            issued_at=manifest.issued_at,
            expires_at=manifest.expires_at,
            signature=signed.signature_base64url,
            canonical=_canonical_manifest(manifest),
            domain=_ADAPTER_SIGNATURE_DOMAIN,
            keys=self._keys,
            now=now,
        )
        if (
            manifest.authentication_state != "client-memory-only"
            or manifest.recipe_side_effect != "read-only"
            or manifest.target_mutation_allowed
            or manifest.account_creation_allowed
            or manifest.caller_authored_routes_allowed
            or manifest.caller_authored_payloads_allowed
        ):
            raise GovernedWebAssessmentModelError(
                "stateful or mutating web assessment adapter is not eligible"
            )
        try:
            resolved = self._catalog.resolve(
                implementation_id=manifest.implementation_id,
                implementation_digest=manifest.implementation_digest,
                origin=manifest.origin,
            )
        except AdapterImplementationCatalogError as exc:
            raise GovernedWebAssessmentModelError(
                "web assessment adapter implementation is not code-owned"
            ) from exc
        if manifest.recipe_digest != resolved.plan.plan_digest:
            raise GovernedWebAssessmentModelError(
                "web assessment adapter recipe differs from code authority"
            )

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), label="adapter registry clock")


class ProvisionedWebAccountReceiptRegistry:
    """Immutable short-lived receipt registry; it never stores material values."""

    def __init__(
        self,
        *,
        keys: Iterable[WebAssessmentVerificationKey],
        receipts: Iterable[SignedProvisionedWebAccountReceipt],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._clock = clock or web_assessment_system_utc_now
        self._keys = _keyring(keys, role=WebAssessmentSigningRole.ACCOUNT_ISSUER)
        installed: dict[tuple[str, str], SignedProvisionedWebAccountReceipt] = {}
        for raw in receipts:
            signed = SignedProvisionedWebAccountReceipt.model_validate(
                raw.model_dump(mode="json", by_alias=True)
            )
            self._verify(signed, now=self._now())
            reference = signed.receipt.reference()
            key = (reference.receipt_id, reference.receipt_digest)
            if key in installed:
                raise GovernedWebAssessmentModelError("provisioned account receipt is duplicated")
            installed[key] = signed
        if not installed:
            raise GovernedWebAssessmentModelError("provisioned account receipt registry is empty")
        self._receipts = installed
        self.trust_anchor_digest = capability_definition_digest(
            "pajin.web-assessment.account-receipt-trust-anchor/v1",
            [self._keys[key].model_dump(mode="json", by_alias=True) for key in sorted(self._keys)],
        )

    def resolve(self, reference: ProvisionedWebAccountReceiptRef) -> ProvisionedWebAccountReceipt:
        canonical = ProvisionedWebAccountReceiptRef.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
        key = (canonical.receipt_id, canonical.receipt_digest)
        try:
            signed = self._receipts[key]
        except KeyError as exc:
            raise GovernedWebAssessmentModelError(
                "provisioned account receipt is not registered"
            ) from exc
        self._verify(signed, now=self._now())
        return signed.receipt.model_copy(deep=True)

    def _verify(self, signed: SignedProvisionedWebAccountReceipt, *, now: datetime) -> None:
        receipt = signed.receipt
        _verify_signed(
            key_id=signed.key_id,
            issued_at=receipt.issued_at,
            expires_at=receipt.expires_at,
            signature=signed.signature_base64url,
            canonical=_canonical_receipt(receipt),
            domain=_ACCOUNT_RECEIPT_SIGNATURE_DOMAIN,
            keys=self._keys,
            now=now,
        )

    def _now(self) -> datetime:
        return _aware_utc(self._clock(), label="account receipt registry clock")


def sign_web_assessment_adapter(
    manifest: WebAssessmentAdapterManifest,
    *,
    key_id: str,
    private_key: bytes,
) -> SignedWebAssessmentAdapter:
    """Sign one canonical adapter without conferring lifecycle or execution authority."""

    canonical = WebAssessmentAdapterManifest.model_validate(
        manifest.model_dump(mode="json", by_alias=True)
    )
    return SignedWebAssessmentAdapter(
        manifest=canonical,
        keyId=key_id,
        signatureBase64url=_sign(
            private_key,
            _ADAPTER_SIGNATURE_DOMAIN + _canonical_manifest(canonical),
        ),
    )


def sign_provisioned_web_account_receipt(
    receipt: ProvisionedWebAccountReceipt,
    *,
    key_id: str,
    private_key: bytes,
) -> SignedProvisionedWebAccountReceipt:
    """Sign one canonical secret-free receipt without authorizing account creation."""

    canonical = ProvisionedWebAccountReceipt.model_validate(
        receipt.model_dump(mode="json", by_alias=True)
    )
    return SignedProvisionedWebAccountReceipt(
        receipt=canonical,
        keyId=key_id,
        signatureBase64url=_sign(
            private_key,
            _ACCOUNT_RECEIPT_SIGNATURE_DOMAIN + _canonical_receipt(canonical),
        ),
    )


def web_assessment_public_key_base64url(private_key: bytes) -> str:
    """Return the raw Ed25519 public key in canonical unpadded base64url."""

    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    public_key = Ed25519PrivateKey.from_private_bytes(private_key).public_key()
    return _encode_base64url(
        public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def canonical_web_origin(value: str) -> str:
    """Require one literal canonical HTTP(S) origin with no path or user information."""

    if not isinstance(value, str) or any(ord(char) <= 32 or char == "\\" for char in value):
        raise ValueError("web adapter requires a canonical HTTP(S) origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("web adapter origin is invalid") from exc
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port == 0
    ):
        raise ValueError("web adapter requires an exact HTTP(S) origin")
    hostname = parsed.hostname.encode("idna").decode("ascii").lower()
    host = f"[{hostname}]" if ":" in hostname else hostname
    default_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != default_port:
        host = f"{host}:{port}"
    canonical = urlunsplit((parsed.scheme.lower(), host, "", "", ""))
    if canonical != value:
        raise ValueError("web adapter origin is not canonical")
    return canonical


def _keyring(
    keys: Iterable[WebAssessmentVerificationKey],
    *,
    role: WebAssessmentSigningRole,
) -> dict[str, WebAssessmentVerificationKey]:
    result: dict[str, WebAssessmentVerificationKey] = {}
    for raw in keys:
        key = WebAssessmentVerificationKey.model_validate(
            raw.model_dump(mode="json", by_alias=True)
        )
        if key.role is not role:
            raise GovernedWebAssessmentModelError(
                "web assessment signing key has the wrong trust role"
            )
        if key.key_id in result:
            raise GovernedWebAssessmentModelError("web assessment signing key is duplicated")
        result[key.key_id] = key
    if not result:
        raise GovernedWebAssessmentModelError("web assessment signing keyring is empty")
    return result


def _verify_signed(
    *,
    key_id: str,
    issued_at: datetime,
    expires_at: datetime,
    signature: str,
    canonical: bytes,
    domain: bytes,
    keys: dict[str, WebAssessmentVerificationKey],
    now: datetime,
) -> None:
    key = keys.get(key_id)
    if key is None or key.state is not WebAssessmentSigningKeyState.ACTIVE:
        raise GovernedWebAssessmentModelError("web assessment signing key is not trusted")
    issued = _aware_utc(issued_at, label="signed statement issue time")
    expires = _aware_utc(expires_at, label="signed statement expiry time")
    current = _aware_utc(now, label="signature verification time")
    not_before = _aware_utc(key.not_before, label="key not-before time")
    not_after = _aware_utc(key.not_after, label="key expiry") if key.not_after is not None else None
    if (
        issued < not_before
        or current < not_before
        or (not_after is not None and (current >= not_after or expires > not_after))
        or not issued <= current < expires
    ):
        raise GovernedWebAssessmentModelError(
            "web assessment signed statement or key is not current"
        )
    try:
        Ed25519PublicKey.from_public_bytes(
            _decode_base64url(
                key.public_key_base64url,
                expected_length=32,
                label="web assessment public key",
            )
        ).verify(
            _decode_base64url(
                signature,
                expected_length=64,
                label="web assessment signature",
            ),
            domain + canonical,
        )
    except InvalidSignature as exc:
        raise GovernedWebAssessmentModelError(
            "web assessment signature verification failed"
        ) from exc


def _canonical_manifest(manifest: WebAssessmentAdapterManifest) -> bytes:
    return canonical_capability_json(
        manifest.model_dump(mode="json", by_alias=True),
        label="WebAssessmentAdapterManifest",
    )


def _canonical_receipt(receipt: ProvisionedWebAccountReceipt) -> bytes:
    return canonical_capability_json(
        receipt.model_dump(mode="json", by_alias=True),
        label="ProvisionedWebAccountReceipt",
    )


def _canonical_action_approval(
    role: Literal["source", "validation"],
    approval: ActionApprovalEnvelope,
) -> bytes:
    return _ACCOUNT_RECEIPT_SIGNATURE_DOMAIN.replace(
        b"account-receipt",
        b"action-approval",
    ) + canonical_capability_json(
        {
            "role": role,
            "approval": approval.model_dump(mode="json", by_alias=True),
        },
        label="SignedWebActionApproval",
    )


def _aware_utc(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must be timezone-aware")
    return value.astimezone(UTC)


def _is_async_callable(value: object) -> bool:
    return iscoroutinefunction(value) or (callable(value) and iscoroutinefunction(value.__call__))


def _encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_base64url(value: str, *, expected_length: int, label: str) -> bytes:
    try:
        decoded = base64.b64decode(
            value + ("=" * (-len(value) % 4)),
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"{label} must be canonical base64url") from exc
    if len(decoded) != expected_length or _encode_base64url(decoded) != value:
        raise ValueError(f"{label} must be canonical base64url for {expected_length} bytes")
    return decoded


def _sign(private_key: bytes, content: bytes) -> str:
    if len(private_key) != 32:
        raise ValueError("Ed25519 private key must contain 32 bytes")
    return _encode_base64url(Ed25519PrivateKey.from_private_bytes(private_key).sign(content))


def _absolute_grant_store_path(path: Path) -> Path:
    pinned = pinned_workspace_relative_path(path, label="Web capability grant store path")
    if pinned is not None:
        return pinned
    return Path(os.path.abspath(os.fspath(path.expanduser())))


def _prepare_web_grant_store_parent(directory: Path) -> None:
    current = Path(directory.anchor)
    components = directory.parts[1:] if directory.is_absolute() else directory.parts
    for component in components:
        current /= component
        try:
            metadata = current.lstat()
        except FileNotFoundError:
            with suppress(FileExistsError):
                current.mkdir(mode=0o700)
            metadata = current.lstat()
        if current.is_symlink() or current.is_junction() or not stat.S_ISDIR(metadata.st_mode):
            raise GovernedWebAssessmentModelError(
                "Web capability grant store parent contains a non-directory component"
            )
    metadata = directory.lstat()
    if directory.is_symlink() or directory.is_junction() or not stat.S_ISDIR(metadata.st_mode):
        raise GovernedWebAssessmentModelError(
            "Web capability grant store parent is not a regular directory"
        )
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise GovernedWebAssessmentModelError(
            "Web capability grant store parent must be private and owner-controlled"
        )


def _reject_web_grant_store_sidecar_links(path: Path) -> None:
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if not sidecar.exists() and not sidecar.is_symlink() and not sidecar.is_junction():
            continue
        metadata = sidecar.lstat()
        if (
            sidecar.is_symlink()
            or sidecar.is_junction()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or (os.name == "posix" and metadata.st_uid != os.geteuid())
        ):
            raise GovernedWebAssessmentModelError(
                "Web capability grant store sidecar is not a private regular file"
            )


def _prepare_web_grant_store_file(path: Path) -> tuple[bool, int]:
    _prepare_web_grant_store_parent(path.parent)
    _reject_web_grant_store_sidecar_links(path)
    flags = os.O_RDWR | getattr(os, "O_BINARY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        descriptor = os.open(path, flags | os.O_CREAT | os.O_EXCL, 0o600)
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(path, flags)
        except OSError as exc:
            raise GovernedWebAssessmentModelError(
                "Web capability grant store path is not a regular file"
            ) from exc
    try:
        opened = os.fstat(descriptor)
        observed = path.lstat()
        if (
            path.is_symlink()
            or path.is_junction()
            or not stat.S_ISREG(opened.st_mode)
            or not stat.S_ISREG(observed.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (observed.st_dev, observed.st_ino)
        ):
            raise GovernedWebAssessmentModelError(
                "Web capability grant store path is not a private regular file"
            )
        if os.name == "posix":
            if opened.st_uid != os.geteuid():
                raise GovernedWebAssessmentModelError(
                    "Web capability grant store is not owned by this user"
                )
            os.fchmod(descriptor, 0o600)
        return created, opened.st_size
    finally:
        os.close(descriptor)


def _web_grant_store_file_identity(path: Path) -> tuple[tuple[int, int], tuple[int, int]]:
    memory_database = pinned_memory_sqlite_for_path(
        path,
        owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
    )
    if memory_database is not None:
        return memory_database.runtime_identity(
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER
        )
    parent = path.parent.lstat()
    opened = path.lstat()
    if (
        path.parent.is_symlink()
        or path.parent.is_junction()
        or path.is_symlink()
        or path.is_junction()
        or not stat.S_ISDIR(parent.st_mode)
        or not stat.S_ISREG(opened.st_mode)
        or opened.st_nlink != 1
        or (
            os.name == "posix"
            and (
                parent.st_uid != os.geteuid()
                or stat.S_IMODE(parent.st_mode) & 0o077
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
            )
        )
    ):
        raise GovernedWebAssessmentModelError("Web capability grant store path identity is invalid")
    return (
        (parent.st_dev, parent.st_ino),
        (opened.st_dev, opened.st_ino),
    )


def _open_web_grant_consumption_store(
    path: Path,
    *,
    readonly: bool = False,
) -> sqlite3.Connection:
    _web_grant_store_file_identity(path)
    pinned = pinned_workspace_relative_path(path, label="Web capability grant store path")
    target: str | Path = (
        f"file:{quote(pinned.as_posix(), safe='/')}?mode=ro"
        if readonly and pinned is not None
        else f"{path.as_uri()}?mode=ro"
        if readonly
        else path
    )
    try:
        connection = sqlite3.connect(
            target,
            uri=readonly,
            timeout=5,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA trusted_schema = OFF")
        connection.execute("PRAGMA busy_timeout = 5000")
        if readonly:
            connection.execute("PRAGMA query_only = ON")
        return connection
    except sqlite3.DatabaseError as exc:
        raise GovernedWebAssessmentModelError(
            "Web capability grant consumption store could not be opened"
        ) from exc


@contextmanager
def _web_grant_store_connection(
    path: Path,
    *,
    readonly: bool,
) -> Iterator[sqlite3.Connection]:
    memory_database = pinned_memory_sqlite_for_path(
        path,
        owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
    )
    if memory_database is not None:
        with memory_database.connection(
            readonly=readonly,
            owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
        ) as connection:
            connection.row_factory = None
            yield connection
        return
    with closing(
        _open_web_grant_consumption_store(path, readonly=readonly)
    ) as connection:
        yield connection


def _normalized_sql(value: str) -> str:
    return " ".join(value.rstrip(";").split())


def _verify_web_grant_consumption_schema(
    connection: sqlite3.Connection,
    campaign_id: str,
) -> None:
    try:
        version_row = connection.execute("PRAGMA user_version").fetchone()
        integrity_row = connection.execute("PRAGMA quick_check").fetchone()
        objects = connection.execute(
            """
            SELECT name, sql
            FROM sqlite_master
            WHERE type IN ('table', 'trigger') AND name NOT LIKE 'sqlite_%'
            ORDER BY name
            """
        ).fetchall()
        metadata = connection.execute(
            """
            SELECT key, value
            FROM web_capability_grant_consumption_metadata
            ORDER BY key
            """
        ).fetchall()
    except sqlite3.DatabaseError as exc:
        raise GovernedWebAssessmentModelError(
            "Web capability grant consumption store schema is unreadable"
        ) from exc
    observed_objects = {str(name): _normalized_sql(str(sql)) for name, sql in objects}
    expected_objects = {
        name: _normalized_sql(sql) for name, sql in _WEB_GRANT_CONSUMPTION_SCHEMA_OBJECTS.items()
    }
    if (
        version_row is None
        or int(version_row[0]) != _WEB_GRANT_CONSUMPTION_SCHEMA_VERSION
        or integrity_row is None
        or str(integrity_row[0]).lower() != "ok"
        or observed_objects != expected_objects
        or metadata
        != [
            ("campaignId", campaign_id),
            ("schemaDigest", _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST),
        ]
    ):
        raise GovernedWebAssessmentModelError(
            "Web capability grant consumption store schema or Campaign differs"
        )


def _initialize_web_grant_consumption_store(path: Path, campaign_id: str) -> None:
    memory_database = pinned_memory_sqlite_for_path(
        path,
        owner_authority=_PINNED_WEB_GRANT_SQLITE_OWNER,
    )
    if memory_database is None:
        created, size = _prepare_web_grant_store_file(path)
        initialize = created or size == 0
    else:
        created = False
        initialize = True
    try:
        with _web_grant_store_connection(path, readonly=False) as connection:
            if initialize:
                try:
                    expected_mode = "memory" if memory_database is not None else "delete"
                    journal_mode = connection.execute(
                        f"PRAGMA journal_mode = {expected_mode.upper()}"
                    ).fetchone()
                    if journal_mode is None or str(journal_mode[0]).lower() != expected_mode:
                        raise GovernedWebAssessmentModelError(
                            "Web capability grant store requires DELETE journal mode"
                        )
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(_WEB_GRANT_RESERVATION_TABLE_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_TABLE_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_METADATA_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_RESERVATION_UPDATE_TRIGGER_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_RESERVATION_DELETE_TRIGGER_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_RECEIPT_UPDATE_TRIGGER_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_RECEIPT_DELETE_TRIGGER_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_METADATA_UPDATE_TRIGGER_SQL)
                    connection.execute(_WEB_GRANT_CONSUMPTION_METADATA_DELETE_TRIGGER_SQL)
                    connection.executemany(
                        """
                        INSERT INTO web_capability_grant_consumption_metadata (key, value)
                        VALUES (?, ?)
                        """,
                        (
                            ("campaignId", campaign_id),
                            ("schemaDigest", _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST),
                        ),
                    )
                    connection.execute(
                        f"PRAGMA user_version = {_WEB_GRANT_CONSUMPTION_SCHEMA_VERSION}"
                    )
                    connection.commit()
                except BaseException:
                    connection.rollback()
                    raise
            _verify_web_grant_consumption_schema(connection, campaign_id)
    except BaseException:
        if created:
            with suppress(OSError):
                path.unlink()
        raise
    _web_grant_store_file_identity(path)


def signed_web_assessment_material_digest(value: StrictModel) -> str:
    """Return a stable public digest for a signed-model artifact."""

    return sha256(
        canonical_capability_json(
            value.model_dump(mode="json", by_alias=True),
            label=type(value).__name__,
        )
    ).hexdigest()


__all__ = [
    "JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST",
    "JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID",
    "GovernedWebAssessmentModelError",
    "ProvisionedWebAccountReceipt",
    "ProvisionedWebAccountReceiptRef",
    "ProvisionedWebAccountReceiptRegistry",
    "SignedProvisionedWebAccountReceipt",
    "SignedWebActionApproval",
    "SignedWebAssessmentAdapter",
    "WebActionApprovalAuthoritySet",
    "WebActionApprovalInputAuthority",
    "WebAssessmentAdapterManifest",
    "WebAssessmentAdapterRef",
    "WebAssessmentAdapterRegistry",
    "WebAssessmentApprovedActionDispatcher",
    "WebAssessmentCapabilityGrantConsumptionReceipt",
    "WebAssessmentCapabilityGrantConsumptionStore",
    "WebAssessmentCapabilityGrantReservation",
    "WebAssessmentDispatchAuthority",
    "WebAssessmentDispatchBinding",
    "WebAssessmentDispatchBindingRegistry",
    "WebAssessmentSigningKeyState",
    "WebAssessmentSigningRole",
    "WebAssessmentVerificationKey",
    "WebAuthenticatedAssessmentWorkerOutput",
    "canonical_web_origin",
    "sign_provisioned_web_account_receipt",
    "sign_web_action_approval",
    "sign_web_assessment_adapter",
    "signed_web_assessment_material_digest",
    "web_action_approval_issuer_binding",
    "web_assessment_public_key_base64url",
]
