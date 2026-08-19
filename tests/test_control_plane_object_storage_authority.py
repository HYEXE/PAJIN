from __future__ import annotations

import base64
from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.models import ReplayFinalizeRequest
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageDeploymentAuthorityError,
    ObjectStorageTransportBinding,
    compile_object_storage_transport_binding,
    object_storage_part_key,
    select_object_storage_deployment_authority,
)

NOW = datetime(2026, 8, 18, 1, 0, tzinfo=UTC)
STAGING_ID = "stage_" + ("1" * 32)


def _manifest(content: bytes = b"A" * 1_048_577) -> PortableArtifactMultipartManifest:
    file = PortableArtifactManifestFile(
        path="sealed/output.bin",
        size=len(content),
        sha256=sha256(content).hexdigest(),
    )
    return PortableArtifactMultipartManifest(
        files=[file],
        file_count=1,
        total_bytes=len(content),
        manifest_sha256=portable_artifact_manifest_sha256([file]),
    )


def _authority(
    *,
    revision: int = 1,
    previous: str | None = None,
    issued_at: datetime = NOW,
    endpoint: str = "https://objects.example.test",
    prefix: str = "pajin-artifacts/tenant-a",
) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId="object-storage:prod-a",
        revision=revision,
        previousAuthorityDigest=previous,
        issuedAt=issued_at,
        tenantId="tenant:a",
        endpointOrigin=endpoint,
        objectKeyPrefix=prefix,
        uploadTtlSeconds=300,
    )


def test_deployment_authority_is_versioned_content_addressed_and_non_executable() -> None:
    authority = _authority()
    raw = authority.model_dump(mode="json", by_alias=True)

    assert raw["apiVersion"] == "pajin.control-plane.object-storage-deployment-authority/v1"
    assert raw["revision"] == 1
    assert raw["previousAuthorityDigest"] is None
    assert raw["transportOnly"] is True
    assert raw["providerIntegrationEligible"] is False
    assert raw["artifactAdmissionEligible"] is False
    assert raw["finalizationEligible"] is False
    assert len(raw["authorityDigest"]) == 64
    assert ObjectStorageDeploymentAuthority.model_validate(raw) == authority

    with pytest.raises(ValidationError, match="digest differs"):
        ObjectStorageDeploymentAuthority.model_validate({**raw, "authorityDigest": "f" * 64})
    with pytest.raises(ValidationError):
        ObjectStorageDeploymentAuthority.model_validate(
            {**raw, "uploadUrl": "https://objects.example.test/secret?signature=value"}
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("endpointOrigin", "http://objects.example.test"),
        ("endpointOrigin", "https://objects.example.test/path"),
        ("endpointOrigin", "https://Objects.example.test"),
        ("endpointOrigin", "https://objects.example.test:443"),
        ("objectKeyPrefix", "/absolute"),
        ("objectKeyPrefix", "relative/../escape"),
        ("objectKeyPrefix", "relative//non-canonical"),
    ],
)
def test_deployment_authority_rejects_noncanonical_transport_namespace(
    field: str,
    value: str,
) -> None:
    values = _authority().model_dump(mode="json", by_alias=True)
    values.pop("authorityDigest")
    values[field] = value
    with pytest.raises(ValidationError):
        ObjectStorageDeploymentAuthority.model_validate(values)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("maxFileBytes", 16_777_216.0),
        ("maxTotalBytes", 67_108_864.0),
        ("maxFiles", 256.0),
        ("partBytes", 1_048_576.0),
        ("transportOnly", 1),
        ("providerIntegrationEligible", 0),
        ("artifactAdmissionEligible", 0),
        ("finalizationEligible", 0),
    ],
)
def test_deployment_authority_rejects_json_scalar_type_coercion(
    field: str,
    value: object,
) -> None:
    values = _authority().model_dump(mode="json", by_alias=True)
    values.pop("authorityDigest")
    values[field] = value
    with pytest.raises(ValidationError):
        ObjectStorageDeploymentAuthority.model_validate(values)


def test_deployment_authority_selection_rejects_rollback_gap_and_equivocation() -> None:
    first = _authority()
    second = _authority(
        revision=2,
        previous=first.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
        endpoint="https://objects-2.example.test",
    )

    assert select_object_storage_deployment_authority(None, first) == first
    assert select_object_storage_deployment_authority(first, first) == first
    assert select_object_storage_deployment_authority(first, second) == second

    with pytest.raises(ObjectStorageDeploymentAuthorityError, match="rollback, gap"):
        select_object_storage_deployment_authority(second, first)

    gap = _authority(
        revision=4,
        previous=second.authority_digest,
        issued_at=NOW + timedelta(minutes=2),
    )
    with pytest.raises(ObjectStorageDeploymentAuthorityError, match="rollback, gap"):
        select_object_storage_deployment_authority(second, gap)

    equivocation = _authority(
        revision=2,
        previous=first.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
        prefix="pajin-artifacts/tenant-a-equivocation",
    )
    with pytest.raises(ObjectStorageDeploymentAuthorityError, match="equivocation"):
        select_object_storage_deployment_authority(second, equivocation)

    wrong_predecessor = _authority(
        revision=3,
        previous="f" * 64,
        issued_at=NOW + timedelta(minutes=2),
    )
    with pytest.raises(ObjectStorageDeploymentAuthorityError, match="rollback, gap"):
        select_object_storage_deployment_authority(second, wrong_predecessor)


def test_deployment_authority_selection_rejects_cross_tenant_substitution() -> None:
    first = _authority()
    values = _authority(
        revision=2,
        previous=first.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    ).model_dump(mode="json", by_alias=True)
    values.pop("authorityDigest")
    values["tenantId"] = "tenant:b"
    substituted = ObjectStorageDeploymentAuthority.model_validate(values)

    with pytest.raises(ObjectStorageDeploymentAuthorityError, match="deployment identity"):
        select_object_storage_deployment_authority(first, substituted)


def test_transport_binding_derives_key_expiry_and_retains_no_admission_authority() -> None:
    authority = _authority()
    manifest = _manifest()
    binding = compile_object_storage_transport_binding(
        authority,
        output_staging_id=STAGING_ID,
        manifest=manifest,
        executor_attestation_digest="a" * 64,
        issued_at=NOW,
    )

    assert binding.expires_at == NOW + timedelta(seconds=authority.upload_ttl_seconds)
    assert binding.object_key_root == (
        f"{authority.object_key_prefix}/v1/{authority.authority_digest}/"
        f"{STAGING_ID}/{manifest.manifest_sha256}"
    )
    assert object_storage_part_key(binding, file_index=0, part_number=1).endswith(
        "/files/0000/parts/000001"
    )
    assert object_storage_part_key(binding, file_index=0, part_number=2).endswith(
        "/files/0000/parts/000002"
    )
    assert binding.transport_only is True
    assert binding.provider_integration_eligible is False
    assert binding.artifact_admission_eligible is False
    assert binding.finalization_eligible is False

    with pytest.raises(ValueError, match="part number"):
        object_storage_part_key(binding, file_index=0, part_number=3)


def test_transport_binding_rejects_key_expiry_url_and_authority_escalation() -> None:
    binding = compile_object_storage_transport_binding(
        _authority(),
        output_staging_id=STAGING_ID,
        manifest=_manifest(),
        executor_attestation_digest="a" * 64,
        issued_at=NOW,
    )
    raw = binding.model_dump(mode="json", by_alias=True)

    for change in (
        {"objectKeyRoot": "caller-selected/object"},
        {"expiresAt": (binding.expires_at + timedelta(seconds=1)).isoformat()},
        {"artifactAdmissionEligible": True},
        {"finalizationEligible": True},
        {"providerIntegrationEligible": True},
        {"uploadUrl": "https://objects.example.test/secret?signature=value"},
    ):
        candidate = {**raw, **change, "bindingDigest": ""}
        with pytest.raises(ValidationError):
            ObjectStorageTransportBinding.model_validate(candidate)

    for field in (
        "transportOnly",
        "artifactAdmissionEligible",
        "finalizationEligible",
        "providerIntegrationEligible",
    ):
        candidate = {**raw, field: 0, "bindingDigest": ""}
        with pytest.raises(ValidationError):
            ObjectStorageTransportBinding.model_validate(candidate)


def test_external_transport_fields_cannot_enter_existing_finalization_wire() -> None:
    manifest = _manifest(b"sealed")
    raw = {
        "executor_profile": "kisa-exact-v1",
        "lease_token": base64.b64encode(b"x" * 32).decode("ascii"),
        "ticket_id": "replay-ticket_" + ("2" * 32),
        "fencing_value": 1,
        "output_staging_id": STAGING_ID,
        "artifact_manifest": manifest.model_dump(mode="json", by_alias=True),
        "executor_attestation": None,
        "object_key": "caller-selected/object",
        "upload_url": "https://objects.example.test/secret?signature=value",
        "tenant_id": "tenant:b",
        "expires_at": (NOW + timedelta(minutes=5)).isoformat(),
    }

    with pytest.raises(ValidationError):
        ReplayFinalizeRequest.model_validate(raw)
