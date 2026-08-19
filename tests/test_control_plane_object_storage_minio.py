from __future__ import annotations

import io
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import md5, sha256
from importlib import import_module
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest
from pydantic import ValidationError

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.artifacts import ManagedArtifactRepository
from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
from pajin.control_plane.object_storage_admission import (
    DeploymentAdmittedObjectStorageProviderRuntime,
    ObjectStorageProviderAdmissionError,
    ObjectStorageProviderAdmissionPolicy,
    ObjectStorageProviderAdmissionStore,
    ObjectStorageProviderDeploymentAdmission,
    ObjectStorageSelectedProviderEvidence,
    compile_object_storage_provider_admission_policy,
    compile_object_storage_selected_provider_evidence,
    revoke_object_storage_provider_admission,
)
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageTransportBinding,
    compile_object_storage_transport_binding,
)
from pajin.control_plane.object_storage_conformance import (
    ObjectStorageProviderConformanceCase,
    ObjectStorageProviderConformanceReport,
    run_object_storage_provider_conformance,
)
from pajin.control_plane.object_storage_minio import (
    MINIO_S3_BOTO3_VERSION,
    MINIO_S3_BOTOCORE_VERSION,
    MINIO_S3_ENCRYPTION_POLICY_ID,
    MINIO_S3_SERVER_IMAGE,
    MinioS3ObjectStorageAdapter,
    MinioS3ProviderConformanceTarget,
    MinioS3ProviderInventory,
    MinioS3RuntimeSecrets,
)
from pajin.control_plane.object_storage_provider import (
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderCallRejected,
    ObjectStorageProviderIntegrationError,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageConcreteProviderActivation,
    ObjectStorageProviderAttemptJournal,
)

NOW = datetime(2026, 8, 18, 10, 0, tzinfo=UTC)
CHALLENGE = b"minio-selected-provider-live-observation"
CA_BYTES = b"test-only-ca-certificate-bytes"


class _FakeS3Client:
    def __init__(self, endpoint_origin: str, bucket: str) -> None:
        self.endpoint_origin = endpoint_origin
        self.bucket = bucket
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, tuple[str, bytes]] = {}
        self.put_count = 0
        self._next_upload = 1

    def generate_presigned_url(
        self,
        _client_method_name: str,
        *,
        Params: Mapping[str, object],
        ExpiresIn: int,
        HttpMethod: str,
    ) -> str:
        assert HttpMethod == "PUT"
        assert ExpiresIn >= 1
        key = Params["Key"]
        assert type(key) is str
        return (
            f"{self.endpoint_origin}/{self.bucket}/{key}"
            f"?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Expires={ExpiresIn}"
            "&X-Amz-Credential=runtime-only-access"
        )

    def put_object(self, **kwargs: object) -> Mapping[str, object]:
        key = kwargs["Key"]
        body = kwargs["Body"]
        assert type(key) is str
        assert type(body) is bytes
        self.objects[key] = body
        self.put_count += 1
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ETag": sha256(body).hexdigest(),
            "SSECustomerAlgorithm": "AES256",
        }

    def get_object(self, **kwargs: object) -> Mapping[str, object]:
        key = kwargs["Key"]
        assert type(key) is str
        return {"ResponseMetadata": {"HTTPStatusCode": 200}, "Body": io.BytesIO(self.objects[key])}

    def head_object(self, **kwargs: object) -> Mapping[str, object]:
        key = kwargs["Key"]
        assert type(key) is str
        content = self.objects[key]
        customer_key = kwargs["SSECustomerKey"]
        assert type(customer_key) is bytes
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "ETag": sha256(content).hexdigest(),
            "SSECustomerAlgorithm": "AES256",
            "SSECustomerKeyMD5": md5(customer_key, usedforsecurity=False).hexdigest(),
        }

    def list_objects_v2(self, **kwargs: object) -> Mapping[str, object]:
        prefix = kwargs["Prefix"]
        assert type(prefix) is str
        contents = [{"Key": key} for key in sorted(self.objects) if key.startswith(prefix)]
        return {"IsTruncated": False, **({"Contents": contents} if contents else {})}

    def delete_objects(self, **kwargs: object) -> Mapping[str, object]:
        delete = kwargs["Delete"]
        assert isinstance(delete, Mapping)
        objects = delete["Objects"]
        assert isinstance(objects, list)
        for item in objects:
            assert isinstance(item, Mapping)
            key = item["Key"]
            assert type(key) is str
            self.objects.pop(key, None)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def create_multipart_upload(self, **kwargs: object) -> Mapping[str, object]:
        key = kwargs["Key"]
        assert type(key) is str
        upload_id = f"upload-{self._next_upload}"
        self._next_upload += 1
        self.uploads[upload_id] = (key, b"")
        return {"UploadId": upload_id, "ResponseMetadata": {"HTTPStatusCode": 200}}

    def upload_part(self, **kwargs: object) -> Mapping[str, object]:
        upload_id = kwargs["UploadId"]
        body = kwargs["Body"]
        assert type(upload_id) is str
        assert type(body) is bytes
        key, _old = self.uploads[upload_id]
        self.uploads[upload_id] = (key, body)
        return {"ETag": sha256(body).hexdigest(), "ResponseMetadata": {"HTTPStatusCode": 200}}

    def list_multipart_uploads(self, **kwargs: object) -> Mapping[str, object]:
        prefix = kwargs["Prefix"]
        assert type(prefix) is str
        uploads = [
            {"Key": key, "UploadId": upload_id}
            for upload_id, (key, _content) in sorted(self.uploads.items())
            if key.startswith(prefix)
        ]
        return {"IsTruncated": False, **({"Uploads": uploads} if uploads else {})}

    def abort_multipart_upload(self, **kwargs: object) -> Mapping[str, object]:
        upload_id = kwargs["UploadId"]
        assert type(upload_id) is str
        self.uploads.pop(upload_id)
        return {"ResponseMetadata": {"HTTPStatusCode": 204}}


def _inventory(ca_bytes: bytes = CA_BYTES) -> MinioS3ProviderInventory:
    return MinioS3ProviderInventory(
        endpointOrigin="https://127.0.0.1:9443",
        redirectProbeOrigin="https://127.0.0.1:9444",
        bucketName="pajin-conformance-ux007p2",
        tlsCaSha256=sha256(ca_bytes).hexdigest(),
    )


def _authority(*, upload_ttl_seconds: int = 60) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId="object-storage:minio-conformance",
        revision=1,
        issuedAt=NOW,
        tenantId="tenant:minio-conformance",
        endpointOrigin="https://127.0.0.1:9443",
        objectKeyPrefix="pajin-conformance/tenant",
        uploadTtlSeconds=upload_ttl_seconds,
    )


def _binding(
    authority: ObjectStorageDeploymentAuthority,
    *,
    issued_at: datetime = NOW + timedelta(seconds=2),
    staging_character: str = "e",
) -> ObjectStorageTransportBinding:
    content = b"binding-manifest-content"
    files = [
        PortableArtifactManifestFile(
            path="sealed/result.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
    ]
    manifest = PortableArtifactMultipartManifest(
        files=files,
        file_count=1,
        total_bytes=len(content),
        manifest_sha256=portable_artifact_manifest_sha256(files),
    )
    return compile_object_storage_transport_binding(
        authority,
        output_staging_id="stage_" + (staging_character * 32),
        manifest=manifest,
        executor_attestation_digest="f" * 64,
        issued_at=issued_at,
    )


def _adapter(
    tmp_path: Path,
    *,
    current: list[datetime] | None = None,
) -> tuple[MinioS3ObjectStorageAdapter, _FakeS3Client]:
    ca_path = tmp_path / "ca.pem"
    ca_path.write_bytes(CA_BYTES)
    inventory = _inventory()
    client = _FakeS3Client(inventory.endpoint_origin, inventory.bucket_name)
    clock = (lambda: current[0]) if current is not None else (lambda: NOW + timedelta(seconds=3))
    adapter = MinioS3ObjectStorageAdapter(
        inventory=inventory,
        secrets=MinioS3RuntimeSecrets(
            access_key="runtime-access",
            secret_key="runtime-secret-value",
            sse_customer_key=b"k" * 32,
        ),
        ca_bundle_path=ca_path,
        state_path=tmp_path / "provider" / "minio-state.sqlite3",
        client=client,
        clock=clock,
    )
    return adapter, client


@dataclass(frozen=True, slots=True)
class _SelectedEnvironment:
    current: list[datetime]
    adapter: MinioS3ObjectStorageAdapter
    client: _FakeS3Client
    authority: ObjectStorageDeploymentAuthority
    binding: ObjectStorageTransportBinding
    head: ObjectStorageAuthorityHeadStore
    journal: ObjectStorageProviderAttemptJournal
    activation: ObjectStorageConcreteProviderActivation
    report: ObjectStorageProviderConformanceReport


def _run_selected_environment(tmp_path: Path) -> _SelectedEnvironment:
    current = [NOW + timedelta(seconds=3)]
    adapter, client = _adapter(tmp_path, current=current)
    authority = _authority(upload_ttl_seconds=3_600)
    binding = _binding(authority)
    head = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "authority" / "head.sqlite3",
        authority,
        activated_at=NOW + timedelta(seconds=1),
    )
    journal = ObjectStorageProviderAttemptJournal.bootstrap(
        tmp_path / "journal" / "attempts.sqlite3",
        authority_checkpoint=head.checkpoint(),
        adapter=adapter.definition,
        deployment_profile=adapter.deployment_profile,
        activated_at=NOW + timedelta(seconds=1),
    )

    def http_request(method: str, url: str, _headers: Mapping[str, str], content: bytes) -> int:
        parsed = urlsplit(url)
        if parsed.netloc.endswith(":9444"):
            return 307
        if (
            method == "PUT"
            and "-mutated" not in parsed.path
            and not client.objects.get(unquote(parsed.path).split("/", 2)[2])
        ):
            key = unquote(parsed.path).split("/", 2)[2]
            client.objects[key] = content
            return 200
        return 403

    def sleeper(seconds: float) -> None:
        current[0] += timedelta(seconds=seconds)

    target = MinioS3ProviderConformanceTarget(
        adapter=adapter,
        ca_bundle_path=tmp_path / "ca.pem",
        clock=lambda: current[0],
        sleeper=sleeper,
        http_request=http_request,
    )
    report = run_object_storage_provider_conformance(
        authority_store=head,
        journal=journal,
        binding=binding,
        target=target,
        challenge=CHALLENGE,
        clock=lambda: current[0],
    )
    return _SelectedEnvironment(
        current=current,
        adapter=adapter,
        client=client,
        authority=authority,
        binding=binding,
        head=head,
        journal=journal,
        activation=journal.latest_activation(),
        report=report,
    )


def test_selected_inventory_pins_exact_provider_sdk_image_and_authority_ceiling() -> None:
    inventory = _inventory()
    boto3_version = vars(import_module("boto3"))["__version__"]
    botocore_version = vars(import_module("botocore"))["__version__"]

    assert inventory.server_image == MINIO_S3_SERVER_IMAGE
    assert inventory.sdk_version == MINIO_S3_BOTO3_VERSION == boto3_version
    assert inventory.botocore_version == MINIO_S3_BOTOCORE_VERSION == botocore_version
    assert inventory.encryption_policy_id == MINIO_S3_ENCRYPTION_POLICY_ID
    assert inventory.public_network_eligible is False
    assert inventory.artifact_admission_eligible is False
    assert inventory.finalization_eligible is False
    assert len(inventory.inventory_digest) == 64

    raw = inventory.model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError, match="digest differs"):
        MinioS3ProviderInventory.model_validate({**raw, "bucketName": "different-bucket"})


def test_runtime_secrets_and_upload_headers_are_redacted_and_not_durable(tmp_path: Path) -> None:
    adapter, _client = _adapter(tmp_path)
    binding = _binding(_authority())
    operation_id = "object-storage-attempt-operation_f00000000000000000001_" + ("a" * 64)

    credential = adapter.issue_upload_part(
        binding=binding,
        object_key=f"{binding.object_key_root}/files/0000/parts/000001",
        expires_at=binding.expires_at,
        operation_id=operation_id,
    )

    assert "runtime-only-access" not in repr(credential)
    assert "runtime-secret-value" not in repr(credential)
    assert "headers=<redacted>" in repr(credential)
    assert dict(credential.headers)["x-amz-server-side-encryption-customer-algorithm"] == "AES256"
    state = (tmp_path / "provider" / "minio-state.sqlite3").read_bytes()
    assert b"runtime-secret-value" not in state
    assert b"runtime-only-access" not in state
    assert b"kkkkkkkk" not in state


def test_adapter_deduplicates_operation_and_rejects_lower_fence(tmp_path: Path) -> None:
    adapter, client = _adapter(tmp_path)
    binding = _binding(_authority())
    key = f"{binding.object_key_root}/conformance/fence"
    high = "object-storage-attempt-operation_f00000000000000000002_" + ("b" * 64)
    low = "object-storage-attempt-operation_f00000000000000000001_" + ("c" * 64)

    first, _ = adapter.put_conformance_object(
        binding=binding,
        object_key=key,
        content=CHALLENGE,
        operation_id=high,
    )
    duplicate, _ = adapter.put_conformance_object(
        binding=binding,
        object_key=key,
        content=CHALLENGE,
        operation_id=high,
    )
    with pytest.raises(ObjectStorageProviderCallRejected, match="fence is stale"):
        adapter.put_conformance_object(
            binding=binding,
            object_key=key,
            content=b"stale",
            operation_id=low,
        )

    assert first is True
    assert duplicate is False
    assert client.put_count == 1
    assert client.objects[key] == CHALLENGE


def test_selected_minio_target_runs_all_common_cases_from_raw_observations(
    tmp_path: Path,
) -> None:
    environment = _run_selected_environment(tmp_path)
    report = environment.report

    assert report.black_box_observations_passed is True
    assert tuple(result.case for result in report.results) == tuple(
        ObjectStorageProviderConformanceCase
    )
    assert report.finished_at >= environment.binding.expires_at
    assert report.artifact_admission_eligible is False
    assert report.finalization_eligible is False
    serialized = report.model_dump_json(by_alias=True)
    assert "runtime-secret-value" not in serialized
    assert "runtime-only-access" not in serialized
    assert "X-Amz-Credential" not in serialized


def _admitted_environment(
    tmp_path: Path,
) -> tuple[
    _SelectedEnvironment,
    ObjectStorageSelectedProviderEvidence,
    ObjectStorageProviderAdmissionPolicy,
    ObjectStorageProviderAdmissionStore,
    ObjectStorageProviderDeploymentAdmission,
]:
    environment = _run_selected_environment(tmp_path)
    evidence = compile_object_storage_selected_provider_evidence(
        inventory=environment.adapter.inventory,
        activation=environment.activation,
        report=environment.report,
    )
    policy = compile_object_storage_provider_admission_policy(
        evidence,
        issued_at=environment.report.finished_at,
    )
    store = ObjectStorageProviderAdmissionStore.bootstrap(
        tmp_path / "admission" / "admission.sqlite3",
        store_id="object-storage-admission:minio-test",
        policy=policy,
        provisioned_at=environment.report.finished_at,
    )
    initial_checkpoint = store.checkpoint()
    assert initial_checkpoint.transport_admission_current is False
    admission = store.admit(
        evidence,
        inventory=environment.adapter.inventory,
        authority_store=environment.head,
        journal=environment.journal,
        expected_checkpoint=initial_checkpoint,
        evaluated_at=environment.report.finished_at,
    )
    return environment, evidence, policy, store, admission


def test_selected_provider_evidence_and_admission_restart_fail_closed(
    tmp_path: Path,
) -> None:
    environment, evidence, policy, store, admission = _admitted_environment(tmp_path)
    checkpoint = store.checkpoint()

    reopened = ObjectStorageProviderAdmissionStore.open(store.path)
    assert reopened.current_policy() == policy
    assert reopened.current_admission() == admission
    assert checkpoint.transport_admission_current is True
    assert (
        reopened.require_current(
            admission,
            evidence,
            inventory=environment.adapter.inventory,
            authority_store=environment.head,
            journal=environment.journal,
            expected_checkpoint=checkpoint,
            now=environment.report.finished_at + timedelta(seconds=1),
        )
        == admission
    )
    with pytest.raises(ObjectStorageProviderAdmissionError, match="checkpoint is stale"):
        reopened.require_current(
            admission,
            evidence,
            inventory=environment.adapter.inventory,
            authority_store=environment.head,
            journal=environment.journal,
            expected_checkpoint=ObjectStorageProviderAdmissionStore.bootstrap(
                tmp_path / "foreign" / "admission.sqlite3",
                store_id="object-storage-admission:foreign",
                policy=policy,
                provisioned_at=environment.report.finished_at,
            ).checkpoint(),
            now=environment.report.finished_at + timedelta(seconds=1),
        )

    serialized = evidence.model_dump_json(by_alias=True) + admission.model_dump_json(by_alias=True)
    assert "runtime-secret-value" not in serialized
    assert "runtime-only-access" not in serialized
    assert "X-Amz-Credential" not in serialized
    with pytest.raises(ObjectStorageProviderAdmissionError, match="absent"):
        ObjectStorageProviderAdmissionStore.open(tmp_path / "missing.sqlite3")


def test_admission_rejects_stale_report_and_revocation_is_retroactive(tmp_path: Path) -> None:
    environment, evidence, policy, store, admission = _admitted_environment(tmp_path)
    checkpoint = store.checkpoint()
    with pytest.raises(ObjectStorageProviderAdmissionError, match="not currently fresh"):
        store.require_current(
            admission,
            evidence,
            inventory=environment.adapter.inventory,
            authority_store=environment.head,
            journal=environment.journal,
            expected_checkpoint=checkpoint,
            now=environment.report.finished_at + timedelta(seconds=3_600),
        )

    revoked = revoke_object_storage_provider_admission(
        policy,
        issued_at=environment.report.finished_at + timedelta(seconds=2),
    )
    assert store.rotate_policy(revoked, expected_checkpoint=checkpoint) == revoked
    revoked_checkpoint = store.checkpoint()
    assert revoked_checkpoint.transport_admission_current is False
    assert evidence.inventory_digest in revoked.revoked_inventory_digests
    assert evidence.report_digest in revoked.revoked_report_digests
    with pytest.raises(ObjectStorageProviderAdmissionError, match="not admitted"):
        store.require_current(
            admission,
            evidence,
            inventory=environment.adapter.inventory,
            authority_store=environment.head,
            journal=environment.journal,
            expected_checkpoint=revoked_checkpoint,
            now=environment.report.finished_at + timedelta(seconds=3),
        )


def test_admitted_runtime_rechecks_freshness_but_keeps_cleanup_available(tmp_path: Path) -> None:
    environment, evidence, _policy, store, admission = _admitted_environment(tmp_path)
    current = [environment.report.finished_at + timedelta(seconds=1)]
    repository = ManagedArtifactRepository(
        staging_root=tmp_path / "admitted-staging",
        repository_root=tmp_path / "admitted-repository",
    )
    runtime = DeploymentAdmittedObjectStorageProviderRuntime(
        admission_store=store,
        expected_admission_checkpoint=store.checkpoint(),
        admission=admission,
        evidence=evidence,
        inventory=environment.adapter.inventory,
        authority_store=environment.head,
        repository=repository,
        provider=environment.adapter,
        journal=environment.journal,
        clock=lambda: current[0],
    )
    binding = _binding(
        environment.authority,
        issued_at=environment.report.finished_at,
        staging_character="d",
    )
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=environment.head.checkpoint(),
        now=current[0],
    )
    current[0] = admission.valid_until
    with pytest.raises(ObjectStorageProviderIntegrationError, match="rejected"):
        session.issue_upload_part(
            binding,
            file_index=0,
            part_number=1,
            now=admission.valid_until - timedelta(seconds=1),
        )

    assert session.cleanup_upload(binding) in {
        ObjectStorageCleanupDisposition.CLEANED,
        ObjectStorageCleanupDisposition.ALREADY_ABSENT,
    }
    assert environment.journal.pending() == ()


def test_admission_models_reject_boolean_age_and_evidence_substitution(tmp_path: Path) -> None:
    environment, evidence, policy, _store, _admission = _admitted_environment(tmp_path)
    policy_raw = policy.model_dump(mode="json", by_alias=True)
    policy_raw["maxReportAgeSeconds"] = True
    with pytest.raises(ValidationError):
        ObjectStorageProviderAdmissionPolicy.model_validate(policy_raw)

    evidence_raw = evidence.model_dump(mode="json", by_alias=True)
    evidence_raw["inventoryDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="binding differs"):
        ObjectStorageSelectedProviderEvidence.model_validate(evidence_raw)

    with pytest.raises(ObjectStorageProviderAdmissionError, match="inventory differs"):
        _store.require_current(
            _admission,
            evidence,
            inventory=_inventory(b"different-ca"),
            authority_store=environment.head,
            journal=environment.journal,
            expected_checkpoint=_store.checkpoint(),
            now=environment.report.finished_at + timedelta(seconds=1),
        )
