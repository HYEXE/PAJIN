"""Non-executable AWS S3 production selection and custody contract."""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from hashlib import sha256
from typing import Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.control_plane.object_storage_authority import ObjectStorageDeploymentAuthority
from pajin.domain.models import StrictModel

AWS_S3_PRODUCTION_BUCKET_SELECTION_API_VERSION = (
    "pajin.control-plane.aws-s3-production-bucket-selection/v1"
)
AWS_STS_TENANT_CREDENTIAL_SELECTION_API_VERSION = (
    "pajin.control-plane.aws-sts-tenant-credential-selection/v1"
)
AWS_KMS_TENANT_KEY_SELECTION_API_VERSION = "pajin.control-plane.aws-kms-tenant-key-selection/v1"
OBJECT_STORAGE_PRODUCTION_OPERATIONS_SELECTION_API_VERSION = (
    "pajin.control-plane.object-storage-production-operations-selection/v1"
)
AWS_S3_PRODUCTION_PROVIDER_SELECTION_API_VERSION = (
    "pajin.control-plane.aws-s3-production-provider-selection/v1"
)

AWS_S3_PRODUCTION_PROVIDER_FAMILY = "aws-s3"
AWS_S3_PRODUCTION_REGION = "ap-northeast-2"
AWS_S3_PRODUCTION_ENDPOINT_ORIGIN = "https://s3.ap-northeast-2.amazonaws.com"
AWS_S3_PRODUCTION_SDK_VERSION = "1.43.73"
AWS_S3_PRODUCTION_BOTOCORE_VERSION = "1.43.73"
AWS_S3_PRODUCTION_UPLOAD_TTL_SECONDS = 900

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_IDENTIFIER_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$"
_AWS_ACCOUNT_PATTERN = r"^[0-9]{12}$"
_BUCKET_PATTERN = r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"
_VPC_ENDPOINT_PATTERN = r"^vpce-[a-f0-9]{8,17}$"
_AWS_REGION_PATTERN = r"^[a-z]{2}(?:-gov)?-[a-z]+-[1-9][0-9]*$"
_KMS_KEY_ID_PATTERN = r"^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"


class ObjectStorageProductionSelectionError(RuntimeError):
    """Raised when production selection inputs do not form one exact authority."""


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _domain_digest(domain: str, value: object) -> str:
    return sha256(domain.encode("ascii") + b"\x00" + _canonical_json(value)).hexdigest()


def _source_identity(deployment_id: str, tenant_id: str) -> str:
    scope_digest = _domain_digest(
        "pajin.control-plane.aws-sts-source-identity/v1",
        {"deploymentId": deployment_id, "tenantId": tenant_id},
    )
    return f"pajin-{scope_digest[:32]}"


def _normalize_timestamp(value: datetime, *, label: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{label} must include an explicit UTC offset")
    return value.astimezone(UTC)


def _require_literal_boolean(value: object) -> object:
    if type(value) is not bool:
        raise ValueError("Object Storage production selection flags must be JSON booleans")
    return value


def _require_literal_integer(value: object) -> object:
    if type(value) is not int:
        raise ValueError("Object Storage production selection values must be JSON integers")
    return value


def _require_bucket_name(value: str) -> str:
    if (
        re.fullmatch(_BUCKET_PATTERN, value) is None
        or ".." in value
        or ".-" in value
        or "-." in value
    ):
        raise ValueError("AWS S3 production bucket name is not canonical")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("AWS S3 production bucket name cannot be an IP address")


class AwsS3ProductionBucketSelection(StrictModel):
    """Exact desired AWS S3 tenant bucket inventory without live-state authority."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.aws-s3-production-bucket-selection/v1"] = Field(
        default="pajin.control-plane.aws-s3-production-bucket-selection/v1",
        alias="apiVersion",
    )
    kind: Literal["AwsS3ProductionBucketSelection"] = "AwsS3ProductionBucketSelection"
    selection_digest: str = Field(default="", alias="selectionDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    aws_account_id: str = Field(alias="awsAccountId", pattern=_AWS_ACCOUNT_PATTERN)
    provider_family: Literal["aws-s3"] = Field(default="aws-s3", alias="providerFamily")
    aws_partition: Literal["aws"] = Field(default="aws", alias="awsPartition")
    region: Literal["ap-northeast-2"] = "ap-northeast-2"
    endpoint_origin: Literal["https://s3.ap-northeast-2.amazonaws.com"] = Field(
        default="https://s3.ap-northeast-2.amazonaws.com",
        alias="endpointOrigin",
    )
    bucket_name: str = Field(alias="bucketName", min_length=3, max_length=63)
    bucket_arn: str = Field(alias="bucketArn", min_length=16, max_length=128)
    tenant_object_key_prefix: str = Field(
        alias="tenantObjectKeyPrefix",
        min_length=1,
        max_length=512,
    )
    vpc_endpoint_id: str = Field(alias="vpcEndpointId", pattern=_VPC_ENDPOINT_PATTERN)
    bucket_policy_sha256: str = Field(alias="bucketPolicySha256", pattern=_SHA256_PATTERN)
    vpc_endpoint_policy_sha256: str = Field(
        alias="vpcEndpointPolicySha256",
        pattern=_SHA256_PATTERN,
    )
    organization_policy_sha256: str = Field(
        alias="organizationPolicySha256",
        pattern=_SHA256_PATTERN,
    )
    default_kms_key_arn: str = Field(alias="defaultKmsKeyArn", min_length=40, max_length=256)
    sdk_name: Literal["boto3"] = Field(default="boto3", alias="sdkName")
    sdk_version: Literal["1.43.73"] = Field(default="1.43.73", alias="sdkVersion")
    botocore_version: Literal["1.43.73"] = Field(
        default="1.43.73",
        alias="botocoreVersion",
    )
    signer: Literal["s3v4"] = "s3v4"
    addressing_style: Literal["virtual"] = Field(default="virtual", alias="addressingStyle")
    network_path: Literal["aws-vpc-gateway-endpoint"] = Field(
        default="aws-vpc-gateway-endpoint",
        alias="networkPath",
    )
    object_ownership: Literal["BucketOwnerEnforced"] = Field(
        default="BucketOwnerEnforced",
        alias="objectOwnership",
    )
    acl_enabled: Literal[False] = Field(default=False, alias="aclEnabled")
    block_public_acls: Literal[True] = Field(default=True, alias="blockPublicAcls")
    ignore_public_acls: Literal[True] = Field(default=True, alias="ignorePublicAcls")
    block_public_policy: Literal[True] = Field(default=True, alias="blockPublicPolicy")
    restrict_public_buckets: Literal[True] = Field(
        default=True,
        alias="restrictPublicBuckets",
    )
    versioning_policy: Literal["unversioned-ephemeral-transport"] = Field(
        default="unversioned-ephemeral-transport",
        alias="versioningPolicy",
    )
    object_lock_enabled: Literal[False] = Field(default=False, alias="objectLockEnabled")
    encryption_mode: Literal["SSE-KMS"] = Field(default="SSE-KMS", alias="encryptionMode")
    bucket_key_enabled: Literal[False] = Field(default=False, alias="bucketKeyEnabled")
    tls_required: Literal[True] = Field(default=True, alias="tlsRequired")
    public_network_eligible: Literal[False] = Field(
        default=False,
        alias="publicNetworkEligible",
    )
    live_inventory_verified: Literal[False] = Field(
        default=False,
        alias="liveInventoryVerified",
    )

    @field_validator("bucket_name")
    @classmethod
    def require_bucket_name(cls, value: str) -> str:
        return _require_bucket_name(value)

    @field_validator(
        "acl_enabled",
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
        "object_lock_enabled",
        "bucket_key_enabled",
        "tls_required",
        "public_network_eligible",
        "live_inventory_verified",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        return _require_literal_boolean(value)

    @model_validator(mode="after")
    def bind_bucket(self) -> Self:
        expected_prefix = f"pajin/tenants/{self.tenant_id}"
        expected_bucket_arn = f"arn:aws:s3:::{self.bucket_name}"
        if self.tenant_object_key_prefix != expected_prefix:
            raise ValueError("AWS S3 production tenant prefix differs")
        if self.bucket_arn != expected_bucket_arn:
            raise ValueError("AWS S3 production bucket ARN differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"selection_digest"})
        digest = _domain_digest(AWS_S3_PRODUCTION_BUCKET_SELECTION_API_VERSION, material)
        if self.selection_digest and self.selection_digest != digest:
            raise ValueError("AWS S3 production bucket selection digest differs")
        object.__setattr__(self, "selection_digest", digest)
        return self


class AwsStsTenantCredentialSelection(StrictModel):
    """Tenant-specific STS role issuance and runtime-only custody selection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.aws-sts-tenant-credential-selection/v1"] = Field(
        default="pajin.control-plane.aws-sts-tenant-credential-selection/v1",
        alias="apiVersion",
    )
    kind: Literal["AwsStsTenantCredentialSelection"] = "AwsStsTenantCredentialSelection"
    selection_digest: str = Field(default="", alias="selectionDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    aws_account_id: str = Field(alias="awsAccountId", pattern=_AWS_ACCOUNT_PATTERN)
    issuer: Literal["aws-sts:AssumeRole"] = "aws-sts:AssumeRole"
    role_arn: str = Field(alias="roleArn", min_length=30, max_length=256)
    custodian_id: str = Field(alias="custodianId", pattern=_IDENTIFIER_PATTERN)
    trust_policy_sha256: str = Field(alias="trustPolicySha256", pattern=_SHA256_PATTERN)
    permission_policy_sha256: str = Field(
        alias="permissionPolicySha256",
        pattern=_SHA256_PATTERN,
    )
    session_policy_sha256: str = Field(alias="sessionPolicySha256", pattern=_SHA256_PATTERN)
    external_id_sha256: str = Field(alias="externalIdSha256", pattern=_SHA256_PATTERN)
    source_identity: str = Field(alias="sourceIdentity", pattern=r"^pajin-[a-f0-9]{32}$")
    tenant_session_tag_key: Literal["pajin:tenant-id"] = Field(
        default="pajin:tenant-id",
        alias="tenantSessionTagKey",
    )
    tenant_session_tag_value: str = Field(
        alias="tenantSessionTagValue",
        pattern=_IDENTIFIER_PATTERN,
    )
    session_duration_seconds: Literal[900] = Field(
        default=900,
        alias="sessionDurationSeconds",
    )
    source_credentials: Literal["workload-identity-runtime-only"] = Field(
        default="workload-identity-runtime-only",
        alias="sourceCredentials",
    )
    static_credentials_allowed: Literal[False] = Field(
        default=False,
        alias="staticCredentialsAllowed",
    )
    credential_persistence_allowed: Literal[False] = Field(
        default=False,
        alias="credentialPersistenceAllowed",
    )
    live_issuer_verified: Literal[False] = Field(default=False, alias="liveIssuerVerified")

    @field_validator("session_duration_seconds", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        return _require_literal_integer(value)

    @field_validator(
        "static_credentials_allowed",
        "credential_persistence_allowed",
        "live_issuer_verified",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        return _require_literal_boolean(value)

    @model_validator(mode="after")
    def bind_credentials(self) -> Self:
        expected_role_arn = f"arn:aws:iam::{self.aws_account_id}:role/pajin-prod-{self.tenant_id}"
        if self.role_arn != expected_role_arn:
            raise ValueError("AWS STS tenant role ARN differs")
        if self.tenant_session_tag_value != self.tenant_id:
            raise ValueError("AWS STS tenant session tag differs")
        if self.source_identity != _source_identity(self.deployment_id, self.tenant_id):
            raise ValueError("AWS STS source identity differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"selection_digest"})
        digest = _domain_digest(AWS_STS_TENANT_CREDENTIAL_SELECTION_API_VERSION, material)
        if self.selection_digest and self.selection_digest != digest:
            raise ValueError("AWS STS tenant credential selection digest differs")
        object.__setattr__(self, "selection_digest", digest)
        return self


class AwsKmsTenantKeySelection(StrictModel):
    """Tenant-specific customer-managed AWS KMS key custody selection."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.aws-kms-tenant-key-selection/v1"] = Field(
        default="pajin.control-plane.aws-kms-tenant-key-selection/v1",
        alias="apiVersion",
    )
    kind: Literal["AwsKmsTenantKeySelection"] = "AwsKmsTenantKeySelection"
    selection_digest: str = Field(default="", alias="selectionDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    aws_account_id: str = Field(alias="awsAccountId", pattern=_AWS_ACCOUNT_PATTERN)
    region: Literal["ap-northeast-2"] = "ap-northeast-2"
    key_arn: str = Field(alias="keyArn", min_length=50, max_length=256)
    custodian_id: str = Field(alias="custodianId", pattern=_IDENTIFIER_PATTERN)
    key_policy_sha256: str = Field(alias="keyPolicySha256", pattern=_SHA256_PATTERN)
    grant_policy_sha256: str = Field(alias="grantPolicySha256", pattern=_SHA256_PATTERN)
    key_spec: Literal["SYMMETRIC_DEFAULT"] = Field(
        default="SYMMETRIC_DEFAULT",
        alias="keySpec",
    )
    key_usage: Literal["ENCRYPT_DECRYPT"] = Field(
        default="ENCRYPT_DECRYPT",
        alias="keyUsage",
    )
    key_origin: Literal["AWS_KMS"] = Field(default="AWS_KMS", alias="keyOrigin")
    key_material_custody: Literal["aws-kms-hsm"] = Field(
        default="aws-kms-hsm",
        alias="keyMaterialCustody",
    )
    customer_managed: Literal[True] = Field(default=True, alias="customerManaged")
    multi_region: Literal[False] = Field(default=False, alias="multiRegion")
    key_enabled: Literal[True] = Field(default=True, alias="keyEnabled")
    pending_deletion: Literal[False] = Field(default=False, alias="pendingDeletion")
    automatic_rotation_enabled: Literal[True] = Field(
        default=True,
        alias="automaticRotationEnabled",
    )
    rotation_period_days: Literal[365] = Field(default=365, alias="rotationPeriodDays")
    revocation_mode: Literal["disable-then-reviewed-deletion"] = Field(
        default="disable-then-reviewed-deletion",
        alias="revocationMode",
    )
    deletion_waiting_period_days: Literal[30] = Field(
        default=30,
        alias="deletionWaitingPeriodDays",
    )
    bucket_key_enabled: Literal[False] = Field(default=False, alias="bucketKeyEnabled")
    cross_tenant_grants_allowed: Literal[False] = Field(
        default=False,
        alias="crossTenantGrantsAllowed",
    )
    live_key_verified: Literal[False] = Field(default=False, alias="liveKeyVerified")

    @field_validator("rotation_period_days", "deletion_waiting_period_days", mode="before")
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        return _require_literal_integer(value)

    @field_validator(
        "customer_managed",
        "multi_region",
        "key_enabled",
        "pending_deletion",
        "automatic_rotation_enabled",
        "bucket_key_enabled",
        "cross_tenant_grants_allowed",
        "live_key_verified",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        return _require_literal_boolean(value)

    @model_validator(mode="after")
    def bind_key(self) -> Self:
        expected_prefix = f"arn:aws:kms:{self.region}:{self.aws_account_id}:key/"
        key_id = self.key_arn.removeprefix(expected_prefix)
        if (
            not self.key_arn.startswith(expected_prefix)
            or re.fullmatch(_KMS_KEY_ID_PATTERN, key_id) is None
        ):
            raise ValueError("AWS KMS tenant key ARN differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"selection_digest"})
        digest = _domain_digest(AWS_KMS_TENANT_KEY_SELECTION_API_VERSION, material)
        if self.selection_digest and self.selection_digest != digest:
            raise ValueError("AWS KMS tenant key selection digest differs")
        object.__setattr__(self, "selection_digest", digest)
        return self


class ObjectStorageProductionOperationsSelection(StrictModel):
    """Exact operational owners and state-protection requirements for later live admission."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal[
        "pajin.control-plane.object-storage-production-operations-selection/v1"
    ] = Field(
        default="pajin.control-plane.object-storage-production-operations-selection/v1",
        alias="apiVersion",
    )
    kind: Literal["ObjectStorageProductionOperationsSelection"] = (
        "ObjectStorageProductionOperationsSelection"
    )
    selection_digest: str = Field(default="", alias="selectionDigest", max_length=64)
    deployment_id: str = Field(alias="deploymentId", pattern=_IDENTIFIER_PATTERN)
    tenant_id: str = Field(alias="tenantId", pattern=_IDENTIFIER_PATTERN)
    operations_owner_id: str = Field(alias="operationsOwnerId", pattern=_IDENTIFIER_PATTERN)
    security_owner_id: str = Field(alias="securityOwnerId", pattern=_IDENTIFIER_PATTERN)
    cost_owner_id: str = Field(alias="costOwnerId", pattern=_IDENTIFIER_PATTERN)
    external_checkpoint_custodian_id: str = Field(
        alias="externalCheckpointCustodianId",
        pattern=_IDENTIFIER_PATTERN,
    )
    backup_region: str = Field(alias="backupRegion", pattern=_AWS_REGION_PATTERN)
    retention_policy_sha256: str = Field(alias="retentionPolicySha256", pattern=_SHA256_PATTERN)
    backup_policy_sha256: str = Field(alias="backupPolicySha256", pattern=_SHA256_PATTERN)
    restore_policy_sha256: str = Field(alias="restorePolicySha256", pattern=_SHA256_PATTERN)
    cleanup_policy_sha256: str = Field(alias="cleanupPolicySha256", pattern=_SHA256_PATTERN)
    cost_policy_sha256: str = Field(alias="costPolicySha256", pattern=_SHA256_PATTERN)
    recovery_point_objective_seconds: Literal[300] = Field(
        default=300,
        alias="recoveryPointObjectiveSeconds",
    )
    recovery_time_objective_seconds: Literal[3600] = Field(
        default=3600,
        alias="recoveryTimeObjectiveSeconds",
    )
    off_host_backup_required: Literal[True] = Field(
        default=True,
        alias="offHostBackupRequired",
    )
    immutable_backup_required: Literal[True] = Field(
        default=True,
        alias="immutableBackupRequired",
    )
    external_anti_rollback_required: Literal[True] = Field(
        default=True,
        alias="externalAntiRollbackRequired",
    )
    independent_restore_drill_required: Literal[True] = Field(
        default=True,
        alias="independentRestoreDrillRequired",
    )
    automatic_expired_upload_cleanup_required: Literal[True] = Field(
        default=True,
        alias="automaticExpiredUploadCleanupRequired",
    )
    cost_approval_required: Literal[True] = Field(default=True, alias="costApprovalRequired")
    live_operations_verified: Literal[False] = Field(
        default=False,
        alias="liveOperationsVerified",
    )

    @field_validator(
        "recovery_point_objective_seconds",
        "recovery_time_objective_seconds",
        mode="before",
    )
    @classmethod
    def require_integer_fields(cls, value: object) -> object:
        return _require_literal_integer(value)

    @field_validator(
        "off_host_backup_required",
        "immutable_backup_required",
        "external_anti_rollback_required",
        "independent_restore_drill_required",
        "automatic_expired_upload_cleanup_required",
        "cost_approval_required",
        "live_operations_verified",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        return _require_literal_boolean(value)

    @model_validator(mode="after")
    def bind_operations(self) -> Self:
        protected_owners = {
            self.operations_owner_id,
            self.security_owner_id,
            self.cost_owner_id,
            self.external_checkpoint_custodian_id,
        }
        if len(protected_owners) != 4:
            raise ValueError("Object Storage production control owners must be separated")
        material = self.model_dump(mode="json", by_alias=True, exclude={"selection_digest"})
        digest = _domain_digest(
            OBJECT_STORAGE_PRODUCTION_OPERATIONS_SELECTION_API_VERSION,
            material,
        )
        if self.selection_digest and self.selection_digest != digest:
            raise ValueError("Object Storage production operations selection digest differs")
        object.__setattr__(self, "selection_digest", digest)
        return self


class AwsS3ProductionProviderSelection(StrictModel):
    """Content-addressed AWS production choice that deliberately cannot activate transport."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.control-plane.aws-s3-production-provider-selection/v1"] = Field(
        default="pajin.control-plane.aws-s3-production-provider-selection/v1",
        alias="apiVersion",
    )
    kind: Literal["AwsS3ProductionProviderSelection"] = "AwsS3ProductionProviderSelection"
    selection_digest: str = Field(default="", alias="selectionDigest", max_length=64)
    selected_at: datetime = Field(alias="selectedAt")
    authority: ObjectStorageDeploymentAuthority
    authority_digest: str = Field(alias="authorityDigest", pattern=_SHA256_PATTERN)
    bucket: AwsS3ProductionBucketSelection
    bucket_selection_digest: str = Field(alias="bucketSelectionDigest", pattern=_SHA256_PATTERN)
    credentials: AwsStsTenantCredentialSelection
    credential_selection_digest: str = Field(
        alias="credentialSelectionDigest",
        pattern=_SHA256_PATTERN,
    )
    kms: AwsKmsTenantKeySelection
    kms_selection_digest: str = Field(alias="kmsSelectionDigest", pattern=_SHA256_PATTERN)
    operations: ObjectStorageProductionOperationsSelection
    operations_selection_digest: str = Field(
        alias="operationsSelectionDigest",
        pattern=_SHA256_PATTERN,
    )
    provider_family: Literal["aws-s3"] = Field(default="aws-s3", alias="providerFamily")
    region: Literal["ap-northeast-2"] = "ap-northeast-2"
    endpoint_origin: Literal["https://s3.ap-northeast-2.amazonaws.com"] = Field(
        default="https://s3.ap-northeast-2.amazonaws.com",
        alias="endpointOrigin",
    )
    requires_fresh_live_inventory: Literal[True] = Field(
        default=True,
        alias="requiresFreshLiveInventory",
    )
    requires_fresh_credential_issuer_evidence: Literal[True] = Field(
        default=True,
        alias="requiresFreshCredentialIssuerEvidence",
    )
    requires_fresh_kms_evidence: Literal[True] = Field(
        default=True,
        alias="requiresFreshKmsEvidence",
    )
    requires_tenant_isolation_probe: Literal[True] = Field(
        default=True,
        alias="requiresTenantIsolationProbe",
    )
    requires_restore_drill_evidence: Literal[True] = Field(
        default=True,
        alias="requiresRestoreDrillEvidence",
    )
    production_activation_eligible: Literal[False] = Field(
        default=False,
        alias="productionActivationEligible",
    )
    transport_admission_eligible: Literal[False] = Field(
        default=False,
        alias="transportAdmissionEligible",
    )
    public_network_eligible: Literal[False] = Field(
        default=False,
        alias="publicNetworkEligible",
    )
    artifact_admission_eligible: Literal[False] = Field(
        default=False,
        alias="artifactAdmissionEligible",
    )
    finalization_eligible: Literal[False] = Field(
        default=False,
        alias="finalizationEligible",
    )
    external_resource_creation_eligible: Literal[False] = Field(
        default=False,
        alias="externalResourceCreationEligible",
    )

    @field_validator("selected_at")
    @classmethod
    def require_selected_at(cls, value: datetime) -> datetime:
        return _normalize_timestamp(value, label="AWS S3 production selection time")

    @field_validator(
        "requires_fresh_live_inventory",
        "requires_fresh_credential_issuer_evidence",
        "requires_fresh_kms_evidence",
        "requires_tenant_isolation_probe",
        "requires_restore_drill_evidence",
        "production_activation_eligible",
        "transport_admission_eligible",
        "public_network_eligible",
        "artifact_admission_eligible",
        "finalization_eligible",
        "external_resource_creation_eligible",
        mode="before",
    )
    @classmethod
    def require_boolean_fields(cls, value: object) -> object:
        return _require_literal_boolean(value)

    @model_validator(mode="after")
    def bind_selection(self) -> Self:
        scope = (self.authority.deployment_id, self.authority.tenant_id)
        if self.selected_at < self.authority.issued_at:
            raise ValueError("AWS S3 production selection predates deployment authority")
        if (
            self.authority_digest != self.authority.authority_digest
            or self.bucket_selection_digest != self.bucket.selection_digest
            or self.credential_selection_digest != self.credentials.selection_digest
            or self.kms_selection_digest != self.kms.selection_digest
            or self.operations_selection_digest != self.operations.selection_digest
            or (self.bucket.deployment_id, self.bucket.tenant_id) != scope
            or (self.credentials.deployment_id, self.credentials.tenant_id) != scope
            or (self.kms.deployment_id, self.kms.tenant_id) != scope
            or (self.operations.deployment_id, self.operations.tenant_id) != scope
            or self.authority.endpoint_origin != self.endpoint_origin
            or self.authority.object_key_prefix != self.bucket.tenant_object_key_prefix
            or self.authority.upload_ttl_seconds != AWS_S3_PRODUCTION_UPLOAD_TTL_SECONDS
            or self.bucket.provider_family != self.provider_family
            or self.bucket.region != self.region
            or self.bucket.endpoint_origin != self.endpoint_origin
            or self.bucket.aws_account_id != self.credentials.aws_account_id
            or self.bucket.aws_account_id != self.kms.aws_account_id
            or self.bucket.default_kms_key_arn != self.kms.key_arn
            or self.bucket.bucket_key_enabled != self.kms.bucket_key_enabled
            or self.credentials.custodian_id == self.kms.custodian_id
        ):
            raise ValueError("AWS S3 production selection authority differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"selection_digest"})
        digest = _domain_digest(AWS_S3_PRODUCTION_PROVIDER_SELECTION_API_VERSION, material)
        if self.selection_digest and self.selection_digest != digest:
            raise ValueError("AWS S3 production provider selection digest differs")
        object.__setattr__(self, "selection_digest", digest)
        return self


def compile_aws_s3_production_provider_selection(
    *,
    authority: ObjectStorageDeploymentAuthority,
    bucket: AwsS3ProductionBucketSelection,
    credentials: AwsStsTenantCredentialSelection,
    kms: AwsKmsTenantKeySelection,
    operations: ObjectStorageProductionOperationsSelection,
    selected_at: datetime,
) -> AwsS3ProductionProviderSelection:
    """Compile one exact non-executable AWS S3 production choice."""

    try:
        trusted_authority = ObjectStorageDeploymentAuthority.model_validate(
            authority.model_dump(mode="json", by_alias=True)
        )
        trusted_bucket = AwsS3ProductionBucketSelection.model_validate(
            bucket.model_dump(mode="json", by_alias=True)
        )
        trusted_credentials = AwsStsTenantCredentialSelection.model_validate(
            credentials.model_dump(mode="json", by_alias=True)
        )
        trusted_kms = AwsKmsTenantKeySelection.model_validate(
            kms.model_dump(mode="json", by_alias=True)
        )
        trusted_operations = ObjectStorageProductionOperationsSelection.model_validate(
            operations.model_dump(mode="json", by_alias=True)
        )
        return AwsS3ProductionProviderSelection(
            selectedAt=selected_at,
            authority=trusted_authority,
            authorityDigest=trusted_authority.authority_digest,
            bucket=trusted_bucket,
            bucketSelectionDigest=trusted_bucket.selection_digest,
            credentials=trusted_credentials,
            credentialSelectionDigest=trusted_credentials.selection_digest,
            kms=trusted_kms,
            kmsSelectionDigest=trusted_kms.selection_digest,
            operations=trusted_operations,
            operationsSelectionDigest=trusted_operations.selection_digest,
        )
    except (AttributeError, ValidationError, ValueError) as exc:
        raise ObjectStorageProductionSelectionError(
            "AWS S3 production provider selection is invalid"
        ) from exc
