from __future__ import annotations

import json
import re
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import BaseModel, ValidationError

from pajin.control_plane.object_storage_authority import ObjectStorageDeploymentAuthority
from pajin.control_plane.object_storage_production import (
    AWS_S3_PRODUCTION_ENDPOINT_ORIGIN,
    AWS_S3_PRODUCTION_REGION,
    AWS_S3_PRODUCTION_UPLOAD_TTL_SECONDS,
    AwsKmsTenantKeySelection,
    AwsS3ProductionBucketSelection,
    AwsS3ProductionProviderSelection,
    AwsStsTenantCredentialSelection,
    ObjectStorageProductionOperationsSelection,
    ObjectStorageProductionSelectionError,
    compile_aws_s3_production_provider_selection,
)

NOW = datetime(2026, 8, 18, 15, 0, tzinfo=UTC)
ACCOUNT_ID = "123456789012"
KEY_ID = "01234567-89ab-cdef-0123-456789abcdef"


def _digest(label: str) -> str:
    return sha256(label.encode("utf-8")).hexdigest()


def _authority(
    *,
    deployment_id: str = "pajin-production-seoul",
    tenant_id: str = "tenant-alpha",
    object_key_prefix: str | None = None,
    upload_ttl_seconds: int = AWS_S3_PRODUCTION_UPLOAD_TTL_SECONDS,
) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId=deployment_id,
        revision=1,
        issuedAt=NOW,
        tenantId=tenant_id,
        endpointOrigin=AWS_S3_PRODUCTION_ENDPOINT_ORIGIN,
        objectKeyPrefix=(
            f"pajin/tenants/{tenant_id}" if object_key_prefix is None else object_key_prefix
        ),
        uploadTtlSeconds=upload_ttl_seconds,
    )


def _kms_key_arn(account_id: str = ACCOUNT_ID, key_id: str = KEY_ID) -> str:
    return f"arn:aws:kms:{AWS_S3_PRODUCTION_REGION}:{account_id}:key/{key_id}"


def _bucket(
    *,
    deployment_id: str = "pajin-production-seoul",
    tenant_id: str = "tenant-alpha",
    account_id: str = ACCOUNT_ID,
    kms_key_arn: str | None = None,
) -> AwsS3ProductionBucketSelection:
    bucket_name = f"pajin-prod-{tenant_id}-{account_id}"
    return AwsS3ProductionBucketSelection(
        deploymentId=deployment_id,
        tenantId=tenant_id,
        awsAccountId=account_id,
        bucketName=bucket_name,
        bucketArn=f"arn:aws:s3:::{bucket_name}",
        tenantObjectKeyPrefix=f"pajin/tenants/{tenant_id}",
        vpcEndpointId="vpce-0123456789abcdef0",
        bucketPolicySha256=_digest("bucket-policy"),
        vpcEndpointPolicySha256=_digest("endpoint-policy"),
        organizationPolicySha256=_digest("organization-policy"),
        defaultKmsKeyArn=_kms_key_arn(account_id) if kms_key_arn is None else kms_key_arn,
    )


def _credentials(
    *,
    deployment_id: str = "pajin-production-seoul",
    tenant_id: str = "tenant-alpha",
    account_id: str = ACCOUNT_ID,
    custodian_id: str = "pajin-credential-broker",
) -> AwsStsTenantCredentialSelection:
    source_identity = sha256(
        b"pajin.control-plane.aws-sts-source-identity/v1\x00"
        + json.dumps(
            {"deploymentId": deployment_id, "tenantId": tenant_id},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    return AwsStsTenantCredentialSelection(
        deploymentId=deployment_id,
        tenantId=tenant_id,
        awsAccountId=account_id,
        roleArn=f"arn:aws:iam::{account_id}:role/pajin-prod-{tenant_id}",
        custodianId=custodian_id,
        trustPolicySha256=_digest("trust-policy"),
        permissionPolicySha256=_digest("permission-policy"),
        sessionPolicySha256=_digest("session-policy"),
        externalIdSha256=_digest("external-id"),
        sourceIdentity=f"pajin-{source_identity[:32]}",
        tenantSessionTagValue=tenant_id,
    )


def _kms(
    *,
    deployment_id: str = "pajin-production-seoul",
    tenant_id: str = "tenant-alpha",
    account_id: str = ACCOUNT_ID,
    key_id: str = KEY_ID,
    custodian_id: str = "pajin-kms-security",
) -> AwsKmsTenantKeySelection:
    return AwsKmsTenantKeySelection(
        deploymentId=deployment_id,
        tenantId=tenant_id,
        awsAccountId=account_id,
        keyArn=_kms_key_arn(account_id, key_id),
        custodianId=custodian_id,
        keyPolicySha256=_digest("key-policy"),
        grantPolicySha256=_digest("grant-policy"),
    )


def _operations(
    *,
    deployment_id: str = "pajin-production-seoul",
    tenant_id: str = "tenant-alpha",
) -> ObjectStorageProductionOperationsSelection:
    return ObjectStorageProductionOperationsSelection(
        deploymentId=deployment_id,
        tenantId=tenant_id,
        operationsOwnerId="pajin-storage-operations",
        securityOwnerId="pajin-security-operations",
        costOwnerId="pajin-finops",
        externalCheckpointCustodianId="pajin-independent-checkpoint-custodian",
        backupRegion="ap-northeast-1",
        retentionPolicySha256=_digest("retention-policy"),
        backupPolicySha256=_digest("backup-policy"),
        restorePolicySha256=_digest("restore-policy"),
        cleanupPolicySha256=_digest("cleanup-policy"),
        costPolicySha256=_digest("cost-policy"),
    )


def _selection() -> AwsS3ProductionProviderSelection:
    return compile_aws_s3_production_provider_selection(
        authority=_authority(),
        bucket=_bucket(),
        credentials=_credentials(),
        kms=_kms(),
        operations=_operations(),
        selected_at=NOW,
    )


def _replace(model: BaseModel, **updates: object) -> dict[str, object]:
    raw = model.model_dump(mode="json", by_alias=True)
    raw.update(updates)
    return raw


def test_aws_s3_production_selection_binds_exact_non_executable_custody() -> None:
    selection = _selection()

    assert selection.provider_family == "aws-s3"
    assert selection.region == "ap-northeast-2"
    assert selection.endpoint_origin == AWS_S3_PRODUCTION_ENDPOINT_ORIGIN
    assert selection.authority_digest == selection.authority.authority_digest
    assert selection.bucket_selection_digest == selection.bucket.selection_digest
    assert selection.credential_selection_digest == selection.credentials.selection_digest
    assert selection.kms_selection_digest == selection.kms.selection_digest
    assert selection.operations_selection_digest == selection.operations.selection_digest
    assert selection.bucket.default_kms_key_arn == selection.kms.key_arn
    assert selection.bucket.versioning_policy == "unversioned-ephemeral-transport"
    assert selection.bucket.object_lock_enabled is False
    assert selection.bucket.bucket_key_enabled is False
    assert selection.credentials.session_duration_seconds == 900
    assert selection.credentials.static_credentials_allowed is False
    assert selection.kms.automatic_rotation_enabled is True
    assert selection.kms.rotation_period_days == 365
    assert selection.production_activation_eligible is False
    assert selection.transport_admission_eligible is False
    assert selection.public_network_eligible is False
    assert selection.artifact_admission_eligible is False
    assert selection.finalization_eligible is False
    assert selection.external_resource_creation_eligible is False

    restored = AwsS3ProductionProviderSelection.model_validate_json(
        selection.model_dump_json(by_alias=True)
    )
    assert restored == selection


@pytest.mark.parametrize(
    ("bucket", "credentials", "kms", "operations"),
    (
        (_bucket(tenant_id="tenant-beta"), _credentials(), _kms(), _operations()),
        (_bucket(), _credentials(account_id="210987654321"), _kms(), _operations()),
        (
            _bucket(),
            _credentials(),
            _kms(key_id="fedcba98-7654-3210-fedc-ba9876543210"),
            _operations(),
        ),
        (_bucket(), _credentials(), _kms(), _operations(tenant_id="tenant-beta")),
        (
            _bucket(),
            _credentials(custodian_id="shared-custodian"),
            _kms(custodian_id="shared-custodian"),
            _operations(),
        ),
    ),
)
def test_aws_s3_production_selection_rejects_scope_and_custody_substitution(
    bucket: AwsS3ProductionBucketSelection,
    credentials: AwsStsTenantCredentialSelection,
    kms: AwsKmsTenantKeySelection,
    operations: ObjectStorageProductionOperationsSelection,
) -> None:
    with pytest.raises(ObjectStorageProductionSelectionError):
        compile_aws_s3_production_provider_selection(
            authority=_authority(),
            bucket=bucket,
            credentials=credentials,
            kms=kms,
            operations=operations,
            selected_at=NOW,
        )


def test_aws_s3_production_selection_rejects_authority_and_time_substitution() -> None:
    bucket = _bucket()
    credentials = _credentials()
    kms = _kms()
    operations = _operations()
    with pytest.raises(ObjectStorageProductionSelectionError):
        compile_aws_s3_production_provider_selection(
            authority=_authority(upload_ttl_seconds=901),
            bucket=bucket,
            credentials=credentials,
            kms=kms,
            operations=operations,
            selected_at=NOW,
        )
    with pytest.raises(ObjectStorageProductionSelectionError):
        compile_aws_s3_production_provider_selection(
            authority=_authority(object_key_prefix="pajin/tenants/tenant-alpha/other"),
            bucket=bucket,
            credentials=credentials,
            kms=kms,
            operations=operations,
            selected_at=NOW,
        )
    with pytest.raises(ObjectStorageProductionSelectionError):
        compile_aws_s3_production_provider_selection(
            authority=_authority(),
            bucket=bucket,
            credentials=credentials,
            kms=kms,
            operations=operations,
            selected_at=NOW - timedelta(microseconds=1),
        )


def test_aws_s3_production_models_reject_scalar_coercion_and_authority_escalation() -> None:
    bucket = _bucket()
    with pytest.raises(ValidationError):
        AwsS3ProductionBucketSelection.model_validate(_replace(bucket, blockPublicAcls=1))

    kms = _kms()
    with pytest.raises(ValidationError):
        AwsKmsTenantKeySelection.model_validate(_replace(kms, rotationPeriodDays="365"))

    operations = _operations()
    with pytest.raises(ValidationError):
        ObjectStorageProductionOperationsSelection.model_validate(
            _replace(operations, costApprovalRequired=1)
        )

    selection = _selection()
    for field in (
        "productionActivationEligible",
        "transportAdmissionEligible",
        "publicNetworkEligible",
        "artifactAdmissionEligible",
        "finalizationEligible",
        "externalResourceCreationEligible",
    ):
        with pytest.raises(ValidationError):
            AwsS3ProductionProviderSelection.model_validate(_replace(selection, **{field: True}))


@pytest.mark.parametrize(
    ("model", "field"),
    (
        (_bucket(), "accessKeyId"),
        (_credentials(), "secretAccessKey"),
        (_credentials(), "sessionToken"),
        (_kms(), "plaintextKey"),
        (_operations(), "privateKey"),
        (_selection(), "credentialValue"),
    ),
)
def test_aws_s3_production_models_reject_secret_bearing_fields(
    model: BaseModel,
    field: str,
) -> None:
    with pytest.raises(ValidationError):
        type(model).model_validate(_replace(model, **{field: "must-not-persist"}))


def test_aws_s3_production_selection_serialization_is_secret_free() -> None:
    raw = _selection().model_dump_json(by_alias=True)
    secret_pattern = re.compile(
        r"(?i)(accessKeyId|secretAccessKey|sessionToken|privateKey|plaintextKey|credentialValue)"
    )
    assert secret_pattern.search(raw) is None


def test_aws_s3_production_models_reject_owner_collapse_and_digest_tamper() -> None:
    operations = _operations()
    with pytest.raises(ValidationError):
        ObjectStorageProductionOperationsSelection.model_validate(
            _replace(
                operations,
                securityOwnerId=operations.operations_owner_id,
            )
        )

    selection = _selection()
    with pytest.raises(ValidationError):
        AwsS3ProductionProviderSelection.model_validate(
            _replace(selection, selectionDigest=_digest("tampered-selection"))
        )

    credentials = _credentials()
    with pytest.raises(ValidationError):
        AwsStsTenantCredentialSelection.model_validate(
            _replace(
                credentials,
                roleArn=f"arn:aws:iam::{ACCOUNT_ID}:role/pajin-prod-tenant-beta",
            )
        )
