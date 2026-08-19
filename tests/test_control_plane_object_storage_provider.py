from __future__ import annotations

import os
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    PortableArtifactMultipartPart,
    PortableArtifactMultipartTransportReceipt,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.artifacts import (
    ManagedArtifactRepository,
    build_portable_artifact_multipart_upload,
)
from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageTransportBinding,
    compile_object_storage_transport_binding,
    object_storage_part_key,
)
from pajin.control_plane.object_storage_provider import (
    EphemeralObjectStorageUploadCredential,
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapterDefinition,
    ObjectStorageProviderIntegrationError,
    ObjectStorageProviderOutcomeUnknown,
    ObjectStorageProviderRuntime,
)
from pajin.runtime.store import RunStore, verify_run_integrity

NOW = datetime(2026, 8, 18, 5, 0, tzinfo=UTC)
STAGING_ID = "stage_" + ("8" * 32)
ATTESTATION_DIGEST = "9" * 64


def _authority(
    *,
    revision: int = 1,
    previous: str | None = None,
    issued_at: datetime = NOW,
) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId="object-storage:prod-a",
        revision=revision,
        previousAuthorityDigest=previous,
        issuedAt=issued_at,
        tenantId="tenant:a",
        endpointOrigin="https://objects.example.test",
        objectKeyPrefix="pajin-artifacts/tenant-a",
        uploadTtlSeconds=300,
    )


def _manifest(*contents: bytes) -> PortableArtifactMultipartManifest:
    files = [
        PortableArtifactManifestFile(
            path=f"sealed/file-{index}.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
        for index, content in enumerate(contents)
    ]
    return PortableArtifactMultipartManifest(
        files=files,
        file_count=len(files),
        total_bytes=sum(len(content) for content in contents),
        manifest_sha256=portable_artifact_manifest_sha256(files),
    )


def _binding(
    authority: ObjectStorageDeploymentAuthority,
    manifest: PortableArtifactMultipartManifest,
    *,
    staging_id: str = STAGING_ID,
) -> ObjectStorageTransportBinding:
    return compile_object_storage_transport_binding(
        authority,
        output_staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest=ATTESTATION_DIGEST,
        issued_at=NOW + timedelta(seconds=2),
    )


class _Provider:
    def __init__(self, binding: ObjectStorageTransportBinding, contents: tuple[bytes, ...]) -> None:
        self._definition = ObjectStorageProviderAdapterDefinition(
            adapterId="test-object-storage",
            endpointOrigin=binding.deployment.endpoint_origin,
        )
        self.parts: dict[str, bytes] = {}
        for file_index, content in enumerate(contents):
            for offset in range(0, len(content), binding.manifest.part_bytes):
                part_number = (offset // binding.manifest.part_bytes) + 1
                self.parts[
                    object_storage_part_key(
                        binding,
                        file_index=file_index,
                        part_number=part_number,
                    )
                ] = content[offset : offset + binding.manifest.part_bytes]
        self.calls: list[tuple[str, str]] = []
        self.credential_origin = binding.deployment.endpoint_origin
        self.credential_key: str | None = None
        self.credential_expiry: datetime | None = None
        self.credential_method = "PUT"
        self.complete_error: Exception | None = None
        self.complete_result: object = None
        self.cleanup_disposition = ObjectStorageCleanupDisposition.CLEANED
        self.after_read: Callable[[], None] | None = None

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._definition

    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        self.calls.append(("issue", operation_id))
        return EphemeralObjectStorageUploadCredential(
            url=f"{self.credential_origin}/upload/{object_key}?signature=do-not-log",
            method=self.credential_method,
            object_key=self.credential_key or object_key,
            expires_at=self.credential_expiry or expires_at,
        )

    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        self.calls.append(("complete", operation_id))
        if self.complete_error is not None:
            raise self.complete_error
        return cast(None, self.complete_result)

    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        self.calls.append(("read", operation_id))
        content = self.parts[object_key]
        callback = self.after_read
        if callback is not None:
            self.after_read = None
            callback()
        return content

    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        self.calls.append(("cleanup", operation_id))
        return self.cleanup_disposition


class _RecordingRepository:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.parts: dict[tuple[int, int], bytes] = {}

    def begin_portable_multipart_upload(self, **values: object) -> object:
        self.calls.append("begin")
        return object()

    def put_portable_multipart_part(
        self,
        *,
        staging_id: str,
        manifest_sha256: str,
        part: PortableArtifactMultipartPart,
    ) -> object:
        self.calls.append("put")
        self.parts[(part.file_index, part.part_number)] = part.content
        return object()

    def materialize_portable_multipart_upload(
        self,
        *,
        staging_id: str,
        manifest: PortableArtifactMultipartManifest,
        executor_attestation_digest: str,
    ) -> PortableArtifactMultipartTransportReceipt:
        self.calls.append("materialize")
        return PortableArtifactMultipartTransportReceipt(
            output_staging_id=staging_id,
            manifest_sha256=manifest.manifest_sha256,
            file_count=manifest.file_count,
            total_bytes=manifest.total_bytes,
            part_count=manifest.part_count,
            executor_attestation_digest=executor_attestation_digest,
        )


def _runtime(
    tmp_path: Path,
    *contents: bytes,
) -> tuple[
    ObjectStorageProviderRuntime,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageTransportBinding,
    _Provider,
    _RecordingRepository,
]:
    authority = _authority()
    store = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "authority" / "head.sqlite3",
        authority,
        activated_at=NOW + timedelta(seconds=1),
    )
    binding = _binding(authority, _manifest(*contents))
    provider = _Provider(binding, tuple(contents))
    repository = _RecordingRepository()
    runtime = ObjectStorageProviderRuntime(
        authority_store=store,
        repository=cast(ManagedArtifactRepository, repository),
        provider=provider,
    )
    return runtime, store, binding, provider, repository


def test_provider_definition_is_content_addressed_and_non_authoritative() -> None:
    definition = ObjectStorageProviderAdapterDefinition(
        adapterId="test-object-storage",
        endpointOrigin="https://objects.example.test",
    )
    raw = definition.model_dump(mode="json", by_alias=True)

    assert len(definition.adapter_digest) == 64
    assert raw["callerLocatorEligible"] is False
    assert raw["artifactAdmissionEligible"] is False
    assert raw["finalizationEligible"] is False
    assert ObjectStorageProviderAdapterDefinition.model_validate(raw) == definition

    with pytest.raises(ValidationError, match="digest differs"):
        ObjectStorageProviderAdapterDefinition.model_validate({**raw, "adapterDigest": "f" * 64})
    with pytest.raises(ValidationError, match="JSON booleans"):
        ObjectStorageProviderAdapterDefinition.model_validate(
            {**raw, "adapterDigest": "", "finalizationEligible": 0}
        )


def test_upload_credential_is_ephemeral_redacted_and_exactly_authorized(tmp_path: Path) -> None:
    content = b"remote-part"
    runtime, store, binding, provider, _repository = _runtime(tmp_path, content)

    credential = runtime.issue_upload_part(
        binding,
        expected_checkpoint=store.checkpoint(),
        file_index=0,
        part_number=1,
        now=NOW + timedelta(seconds=3),
    )

    assert credential.object_key == object_storage_part_key(
        binding,
        file_index=0,
        part_number=1,
    )
    assert credential.expires_at == binding.expires_at
    assert credential.url not in repr(credential)
    assert "do-not-log" not in repr(credential)
    assert not hasattr(credential, "model_dump")
    assert len(provider.calls) == 1
    assert provider.calls[0][0] == "issue"
    assert provider.calls[0][1].startswith("object-storage-operation_")


@pytest.mark.parametrize("substitution", ["origin", "key", "expiry", "method"])
def test_upload_credential_rejects_provider_substitution_without_disclosing_url(
    tmp_path: Path,
    substitution: str,
) -> None:
    runtime, store, binding, provider, _repository = _runtime(tmp_path, b"remote-part")
    if substitution == "origin":
        provider.credential_origin = "https://attacker.example.test"
    elif substitution == "key":
        provider.credential_key = "caller/chosen/key"
    elif substitution == "expiry":
        provider.credential_expiry = binding.expires_at + timedelta(seconds=1)
    else:
        provider.credential_method = "GET"

    with pytest.raises(
        ObjectStorageProviderIntegrationError,
        match="differs from pinned transport authority",
    ) as captured:
        runtime.issue_upload_part(
            binding,
            expected_checkpoint=store.checkpoint(),
            file_index=0,
            part_number=1,
            now=NOW + timedelta(seconds=3),
        )

    assert "do-not-log" not in str(captured.value)


def test_stale_binding_is_rejected_before_provider_call(tmp_path: Path) -> None:
    runtime, store, binding, provider, _repository = _runtime(tmp_path, b"remote-part")
    first_checkpoint = store.checkpoint()
    successor = _authority(
        revision=2,
        previous=binding.deployment.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    )
    store.activate(
        successor,
        expected_checkpoint=first_checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )

    with pytest.raises(ObjectStorageProviderIntegrationError, match="durable current authority"):
        runtime.issue_upload_part(
            binding,
            expected_checkpoint=first_checkpoint,
            file_index=0,
            part_number=1,
            now=NOW + timedelta(seconds=3),
        )

    assert provider.calls == []


def test_remote_bytes_are_fully_reverified_before_local_staging(tmp_path: Path) -> None:
    first = b"a" * (1_048_576 + 3)
    second = b"second-file"
    runtime, store, binding, provider, repository = _runtime(tmp_path, first, second)

    receipt = runtime.complete_and_stage(
        binding,
        expected_checkpoint=store.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )

    assert receipt.manifest_sha256 == binding.manifest.manifest_sha256
    assert receipt.object_store_profile == "pajin.control-plane.local-object-store/v1"
    assert repository.calls == ["begin", "put", "put", "put", "materialize"]
    assert repository.parts[(0, 1)] == first[:1_048_576]
    assert repository.parts[(0, 2)] == first[1_048_576:]
    assert repository.parts[(1, 1)] == second
    assert [call[0] for call in provider.calls] == ["complete", "read", "read", "read"]


def test_changed_remote_bytes_fail_before_managed_staging(tmp_path: Path) -> None:
    content = b"manifest-bound"
    runtime, store, binding, provider, repository = _runtime(tmp_path, content)
    key = object_storage_part_key(binding, file_index=0, part_number=1)
    provider.parts[key] = b"X" + content[1:]

    with pytest.raises(ObjectStorageProviderIntegrationError, match="canonical manifest"):
        runtime.complete_and_stage(
            binding,
            expected_checkpoint=store.checkpoint(),
            now=NOW + timedelta(seconds=3),
        )

    assert repository.calls == []


def test_current_head_is_rechecked_before_each_remote_read(tmp_path: Path) -> None:
    content = b"a" * (1_048_576 + 3)
    runtime, store, binding, provider, repository = _runtime(tmp_path, content)
    checkpoint = store.checkpoint()
    successor = _authority(
        revision=2,
        previous=binding.deployment.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    )

    def rotate_head() -> None:
        store.activate(
            successor,
            expected_checkpoint=checkpoint,
            activated_at=NOW + timedelta(minutes=2),
        )

    provider.after_read = rotate_head

    with pytest.raises(ObjectStorageProviderIntegrationError, match="durable current authority"):
        runtime.complete_and_stage(
            binding,
            expected_checkpoint=checkpoint,
            now=NOW + timedelta(seconds=3),
        )

    assert [call[0] for call in provider.calls] == ["complete", "read"]
    assert repository.calls == []


def test_unknown_completion_never_reads_or_stages_remote_bytes(tmp_path: Path) -> None:
    runtime, store, binding, provider, repository = _runtime(tmp_path, b"remote-part")
    provider.complete_error = ObjectStorageProviderOutcomeUnknown("contains-secret-url")

    with pytest.raises(ObjectStorageProviderIntegrationError, match="explicit cleanup") as captured:
        runtime.complete_and_stage(
            binding,
            expected_checkpoint=store.checkpoint(),
            now=NOW + timedelta(seconds=3),
        )

    assert "contains-secret-url" not in str(captured.value)
    assert "contains-secret-url" not in "".join(traceback.format_exception(captured.value))
    assert [call[0] for call in provider.calls] == ["complete"]
    assert repository.calls == []


def test_expiry_closes_upload_use_but_cleanup_remains_explicit(tmp_path: Path) -> None:
    runtime, store, binding, provider, repository = _runtime(tmp_path, b"remote-part")
    checkpoint = store.checkpoint()

    with pytest.raises(ObjectStorageProviderIntegrationError, match="not currently usable"):
        runtime.complete_and_stage(
            binding,
            expected_checkpoint=checkpoint,
            now=binding.expires_at,
        )
    assert provider.calls == []
    assert repository.calls == []

    assert (
        runtime.cleanup_upload(binding, expected_checkpoint=checkpoint)
        is ObjectStorageCleanupDisposition.CLEANED
    )
    provider.cleanup_disposition = ObjectStorageCleanupDisposition.UNKNOWN
    with pytest.raises(ObjectStorageProviderIntegrationError, match="operator reconciliation"):
        runtime.cleanup_upload(binding, expected_checkpoint=checkpoint)
    assert [call[0] for call in provider.calls] == ["cleanup", "cleanup"]


def test_cleanup_rejects_string_coercion_from_provider(tmp_path: Path) -> None:
    runtime, store, binding, provider, _repository = _runtime(tmp_path, b"remote-part")
    provider.cleanup_disposition = cast(ObjectStorageCleanupDisposition, "cleaned")

    with pytest.raises(ObjectStorageProviderIntegrationError, match="invalid cleanup disposition"):
        runtime.cleanup_upload(binding, expected_checkpoint=store.checkpoint())


def test_provider_completion_metadata_cannot_become_artifact_authority(tmp_path: Path) -> None:
    runtime, store, binding, provider, repository = _runtime(tmp_path, b"remote-part")
    provider.complete_result = {"etag": "provider-observation"}

    with pytest.raises(
        ObjectStorageProviderIntegrationError,
        match="unsupported authority metadata",
    ):
        runtime.complete_and_stage(
            binding,
            expected_checkpoint=store.checkpoint(),
            now=NOW + timedelta(seconds=3),
        )

    assert repository.calls == []


@pytest.mark.skipif(os.name != "posix", reason="durable managed import is POSIX-only")
def test_verified_remote_tree_enters_only_through_existing_managed_import(tmp_path: Path) -> None:
    source = RunStore.create(tmp_path / "source", "remote-replay-run")
    source.write_text("result.json", '{"status":"verified"}\n')
    source.append_event("remote-replay.completed")
    source.seal()
    manifest, contents = build_portable_artifact_multipart_upload(source.path)
    authority = _authority()
    head = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "authority" / "head.sqlite3",
        authority,
        activated_at=NOW + timedelta(seconds=1),
    )
    binding = _binding(authority, manifest, staging_id="stage_" + ("7" * 32))
    provider = _Provider(binding, contents)
    repository = ManagedArtifactRepository(
        staging_root=tmp_path / "staging",
        repository_root=tmp_path / "repository",
    )
    repository.reserve_staging(binding.output_staging_id)
    runtime = ObjectStorageProviderRuntime(
        authority_store=head,
        repository=repository,
        provider=provider,
    )

    runtime.complete_and_stage(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )
    assert not any((tmp_path / "repository" / "objects").iterdir())

    snapshot = repository.import_run(
        staging_id=binding.output_staging_id,
        producer_run_id="replay-job-run",
        media_type="application/vnd.pajin.run.v1+json",
        schema_kind="pajin.replay.output.v1",
        created_by="control-plane",
    )

    assert snapshot.ref.run_id == source.run_id
    assert snapshot.ref.integrity_root_digest == verify_run_integrity(source.path).root_digest
