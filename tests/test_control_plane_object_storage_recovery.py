from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
import textwrap
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from typing import cast

import pytest

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    PortableArtifactMultipartPart,
    PortableArtifactMultipartTransportReceipt,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.artifacts import ManagedArtifactRepository
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
    ObjectStorageProviderCallRejected,
    ObjectStorageProviderIntegrationError,
    ObjectStorageProviderOutcomeUnknown,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageProviderAttemptJournal,
    ObjectStorageProviderDeploymentProfile,
    ObjectStorageProviderReconciliationDisposition,
    ObjectStorageProviderRecoveryError,
    RecoverableObjectStorageProviderRuntime,
    object_storage_provider_operation_fence,
)

NOW = datetime(2026, 8, 18, 7, 0, tzinfo=UTC)
STAGING_ID = "stage_" + ("a" * 32)
ATTESTATION_DIGEST = "b" * 64


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


def _manifest(content: bytes) -> PortableArtifactMultipartManifest:
    files = [
        PortableArtifactManifestFile(
            path="sealed/result.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
    ]
    return PortableArtifactMultipartManifest(
        files=files,
        file_count=1,
        total_bytes=len(content),
        manifest_sha256=portable_artifact_manifest_sha256(files),
    )


def _binding(
    authority: ObjectStorageDeploymentAuthority,
    content: bytes,
) -> ObjectStorageTransportBinding:
    return compile_object_storage_transport_binding(
        authority,
        output_staging_id=STAGING_ID,
        manifest=_manifest(content),
        executor_attestation_digest=ATTESTATION_DIGEST,
        issued_at=NOW + timedelta(seconds=2),
    )


class _Repository:
    def __init__(self) -> None:
        self.calls: list[str] = []

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


class _Provider:
    def __init__(self, binding: ObjectStorageTransportBinding, content: bytes) -> None:
        self._definition = ObjectStorageProviderAdapterDefinition(
            adapterId="test-concrete-object-storage",
            endpointOrigin=binding.deployment.endpoint_origin,
        )
        self._profile = ObjectStorageProviderDeploymentProfile(
            providerFamily="test-memory",
            serverSideEncryptionPolicyId="test-sse-required",
            localConformanceProfileId="test-object-storage-v1",
        )
        self.parts = {
            object_storage_part_key(binding, file_index=0, part_number=1): content,
        }
        self.calls: list[tuple[str, int]] = []
        self.highest_fence = 0
        self.complete_error: Exception | None = None
        self.cleanup_disposition = ObjectStorageCleanupDisposition.CLEANED
        self.reconciliation = ObjectStorageProviderReconciliationDisposition.ABSENT
        self.reconciliation_error: Exception | None = None
        self.on_call: Callable[[str, int], None] | None = None

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._definition

    @property
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        return self._profile

    def _record(self, action: str, operation_id: str) -> None:
        fence = object_storage_provider_operation_fence(operation_id)
        if fence < self.highest_fence:
            raise ObjectStorageProviderCallRejected("stale provider fence")
        self.highest_fence = fence
        self.calls.append((action, fence))
        if self.on_call is not None:
            self.on_call(action, fence)

    def issue_upload_part(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        expires_at: datetime,
        operation_id: str,
    ) -> EphemeralObjectStorageUploadCredential:
        self._record("issue", operation_id)
        return EphemeralObjectStorageUploadCredential(
            url=(
                f"{binding.deployment.endpoint_origin}/upload/{object_key}"
                "?signature=must-never-be-durable"
            ),
            method="PUT",
            object_key=object_key,
            expires_at=expires_at,
        )

    def complete_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> None:
        self._record("complete", operation_id)
        if self.complete_error is not None:
            error = self.complete_error
            self.complete_error = None
            raise error

    def read_object(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        object_key: str,
        max_bytes: int,
        operation_id: str,
    ) -> bytes:
        self._record("read", operation_id)
        return self.parts[object_key]

    def cleanup_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageCleanupDisposition:
        self._record("cleanup", operation_id)
        return self.cleanup_disposition

    def reconcile_upload(
        self,
        *,
        binding: ObjectStorageTransportBinding,
        operation_id: str,
    ) -> ObjectStorageProviderReconciliationDisposition:
        self._record("reconcile", operation_id)
        if self.reconciliation_error is not None:
            raise self.reconciliation_error
        return self.reconciliation


def _runtime(
    tmp_path: Path,
    content: bytes = b"remote-object",
) -> tuple[
    RecoverableObjectStorageProviderRuntime,
    ObjectStorageProviderAttemptJournal,
    ObjectStorageAuthorityHeadStore,
    ObjectStorageTransportBinding,
    _Provider,
    _Repository,
]:
    authority = _authority()
    head = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "authority" / "head.sqlite3",
        authority,
        activated_at=NOW + timedelta(seconds=1),
    )
    binding = _binding(authority, content)
    provider = _Provider(binding, content)
    journal = ObjectStorageProviderAttemptJournal.bootstrap(
        tmp_path / "provider" / "attempts.sqlite3",
        authority_checkpoint=head.checkpoint(),
        adapter=provider.definition,
        deployment_profile=provider.deployment_profile,
        activated_at=NOW + timedelta(seconds=1),
    )
    repository = _Repository()
    runtime = RecoverableObjectStorageProviderRuntime(
        authority_store=head,
        repository=cast(ManagedArtifactRepository, repository),
        provider=provider,
        journal=journal,
    )
    return runtime, journal, head, binding, provider, repository


def test_concrete_provider_activation_is_durable_exact_and_non_authoritative(
    tmp_path: Path,
) -> None:
    runtime, journal, head, binding, provider, repository = _runtime(tmp_path)
    del runtime, binding, repository

    activation = journal.latest_activation()
    assert activation.authority_checkpoint == head.checkpoint()
    assert activation.adapter == provider.definition
    assert activation.deployment_profile == provider.deployment_profile
    assert activation.transport_active is True
    assert activation.artifact_admission_eligible is False
    assert activation.finalization_eligible is False
    assert ObjectStorageProviderAttemptJournal.open(journal.path).latest_activation() == activation

    with pytest.raises(ObjectStorageProviderRecoveryError, match="already exists"):
        ObjectStorageProviderAttemptJournal.bootstrap(
            journal.path,
            authority_checkpoint=head.checkpoint(),
            adapter=provider.definition,
            deployment_profile=provider.deployment_profile,
            activated_at=NOW + timedelta(seconds=2),
        )


def test_every_remote_call_has_durable_intent_and_credentials_are_not_persisted(
    tmp_path: Path,
) -> None:
    runtime, journal, head, binding, provider, _repository = _runtime(tmp_path)
    observed: list[tuple[str, str]] = []

    def observe_intent(action: str, _fence: int) -> None:
        records = journal.pending()[0][3]
        observed.append((action, records[-1].record_type))

    provider.on_call = observe_intent
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )
    credential = session.issue_upload_part(
        binding,
        file_index=0,
        part_number=1,
        now=NOW + timedelta(seconds=3),
    )

    records = journal.pending()[0][3]
    assert observed == [("issue", "intent")]
    assert [record.record_type for record in records] == ["intent", "succeeded"]
    assert records[0].operation.fence == 1
    assert records[0].operation.operation_id.startswith(
        "object-storage-attempt-operation_f00000000000000000001_"
    )
    assert credential.url not in journal.path.read_bytes().decode("latin-1")
    assert "must-never-be-durable" not in journal.path.read_bytes().decode("latin-1")


def test_new_attempt_requires_current_binding_window(tmp_path: Path) -> None:
    runtime, journal, head, binding, provider, _repository = _runtime(tmp_path)

    with pytest.raises(ObjectStorageProviderRecoveryError, match="active binding window"):
        runtime.begin_attempt(
            binding,
            expected_checkpoint=head.checkpoint(),
            now=binding.expires_at,
        )

    assert journal.pending() == ()
    assert provider.calls == []


def test_restart_reconciles_unknown_completion_before_allowing_new_work(
    tmp_path: Path,
) -> None:
    runtime, journal, head, binding, provider, repository = _runtime(tmp_path)
    provider.complete_error = ObjectStorageProviderOutcomeUnknown("secret-provider-message")
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )

    with pytest.raises(ObjectStorageProviderIntegrationError, match="explicit cleanup"):
        session.complete_and_stage(binding, now=NOW + timedelta(seconds=3))
    assert repository.calls == []
    assert [record.record_type for record in journal.pending()[0][3]] == [
        "intent",
        "unknown",
    ]

    provider.reconciliation = ObjectStorageProviderReconciliationDisposition.COMPLETED
    reopened = ObjectStorageProviderAttemptJournal.open(journal.path)
    restarted = RecoverableObjectStorageProviderRuntime(
        authority_store=head,
        repository=cast(ManagedArtifactRepository, repository),
        provider=provider,
        journal=reopened,
    )
    assert restarted.reconcile_pending() == (session.attempt.attempt_id,)
    assert reopened.pending() == ()
    assert provider.calls == [("complete", 1), ("reconcile", 2), ("cleanup", 2)]

    next_session = restarted.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=4),
    )
    assert next_session.attempt.fence == 3


def test_hard_process_exit_leaves_attempt_for_restart_reconciliation(
    tmp_path: Path,
) -> None:
    _parent, journal, head, binding, provider, repository = _runtime(tmp_path)
    script = textwrap.dedent(
        """
        import os
        import sys
        from datetime import datetime

        from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
        from pajin.control_plane.object_storage_authority import ObjectStorageTransportBinding
        from pajin.control_plane.object_storage_provider import (
            ObjectStorageProviderAdapterDefinition,
        )
        from pajin.control_plane.object_storage_recovery import (
            ObjectStorageProviderAttemptJournal,
            ObjectStorageProviderDeploymentProfile,
            RecoverableObjectStorageProviderRuntime,
        )

        binding = ObjectStorageTransportBinding.model_validate_json(sys.argv[3])

        class Provider:
            @property
            def definition(self):
                return ObjectStorageProviderAdapterDefinition(
                    adapterId="test-concrete-object-storage",
                    endpointOrigin=binding.deployment.endpoint_origin,
                )

            @property
            def deployment_profile(self):
                return ObjectStorageProviderDeploymentProfile(
                    providerFamily="test-memory",
                    serverSideEncryptionPolicyId="test-sse-required",
                    localConformanceProfileId="test-object-storage-v1",
                )

        head = ObjectStorageAuthorityHeadStore.open(sys.argv[1])
        journal = ObjectStorageProviderAttemptJournal.open(sys.argv[2])
        runtime = RecoverableObjectStorageProviderRuntime(
            authority_store=head,
            repository=object(),
            provider=Provider(),
            journal=journal,
        )
        runtime.begin_attempt(
            binding,
            expected_checkpoint=head.checkpoint(),
            now=datetime.fromisoformat(sys.argv[4]),
        )
        os._exit(23)
        """
    )
    child = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            str(head.path),
            str(journal.path),
            binding.model_dump_json(by_alias=True),
            (NOW + timedelta(seconds=3)).isoformat(),
        ],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "PYTHONPATH": str(Path.cwd() / "src")},
    )
    assert child.returncode == 23, child.stderr

    reopened = ObjectStorageProviderAttemptJournal.open(journal.path)
    abandoned = reopened.pending()[0][2]
    restarted = RecoverableObjectStorageProviderRuntime(
        authority_store=head,
        repository=cast(ManagedArtifactRepository, repository),
        provider=provider,
        journal=reopened,
    )
    assert restarted.reconcile_pending() == (abandoned.attempt_id,)
    assert reopened.pending() == ()
    assert provider.calls == [("reconcile", 2)]


def test_successful_remote_verification_closes_attempt_as_staged(tmp_path: Path) -> None:
    runtime, journal, head, binding, provider, repository = _runtime(tmp_path)
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )

    receipt = session.complete_and_stage(binding, now=NOW + timedelta(seconds=3))

    assert receipt.manifest_sha256 == binding.manifest.manifest_sha256
    assert repository.calls == ["begin", "put", "materialize"]
    assert provider.calls == [("complete", 1), ("read", 1)]
    assert journal.pending() == ()


def test_unknown_reconciliation_blocks_new_attempt_and_successor_activation(
    tmp_path: Path,
) -> None:
    runtime, journal, head, binding, provider, _repository = _runtime(tmp_path)
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )
    checkpoint = head.checkpoint()
    provider.reconciliation = ObjectStorageProviderReconciliationDisposition.UNKNOWN

    with pytest.raises(ObjectStorageProviderRecoveryError, match="remains unknown"):
        runtime.reconcile_pending()
    with pytest.raises(ObjectStorageProviderRecoveryError, match="reconciled first"):
        runtime.begin_attempt(
            binding,
            expected_checkpoint=checkpoint,
            now=NOW + timedelta(seconds=4),
        )
    successor = _authority(
        revision=2,
        previous=binding.deployment.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    )
    with pytest.raises(ObjectStorageProviderRecoveryError, match="reconciled first"):
        runtime.activate_successor(
            successor,
            expected_checkpoint=checkpoint,
            activated_at=NOW + timedelta(minutes=2),
        )
    assert head.checkpoint() == checkpoint
    assert journal.pending()[0][2].attempt_id == session.attempt.attempt_id


def test_provider_reconciliation_error_is_sanitized_and_remains_pending(
    tmp_path: Path,
) -> None:
    runtime, journal, head, binding, provider, _repository = _runtime(tmp_path)
    runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )
    provider.reconciliation_error = RuntimeError("secret-provider-endpoint")

    with pytest.raises(ObjectStorageProviderRecoveryError, match="reconciliation failed") as exc:
        runtime.reconcile_pending()

    rendered = "".join(traceback.format_exception(exc.value))
    assert "secret-provider-endpoint" not in str(exc.value)
    assert "secret-provider-endpoint" not in rendered
    assert journal.pending()


def test_recovery_fence_rejects_stale_session_before_provider_call(tmp_path: Path) -> None:
    runtime, journal, head, binding, provider, _repository = _runtime(tmp_path)
    session = runtime.begin_attempt(
        binding,
        expected_checkpoint=head.checkpoint(),
        now=NOW + timedelta(seconds=3),
    )
    stale_rejected: list[bool] = []

    def attempt_stale_call(action: str, fence: int) -> None:
        if action != "reconcile" or fence != 2:
            return
        with pytest.raises(ObjectStorageProviderIntegrationError, match="outcome is unknown"):
            session.issue_upload_part(
                binding,
                file_index=0,
                part_number=1,
                now=NOW + timedelta(seconds=3),
            )
        stale_rejected.append(True)

    provider.on_call = attempt_stale_call
    assert runtime.reconcile_pending() == (session.attempt.attempt_id,)
    assert stale_rejected == [True]
    assert provider.calls == [("reconcile", 2)]
    assert journal.pending() == ()


def test_successor_head_and_provider_activation_rotate_only_when_clear(tmp_path: Path) -> None:
    runtime, journal, head, binding, _provider, _repository = _runtime(tmp_path)
    checkpoint = head.checkpoint()
    successor = _authority(
        revision=2,
        previous=binding.deployment.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    )

    head_activation, provider_activation = runtime.activate_successor(
        successor,
        expected_checkpoint=checkpoint,
        activated_at=NOW + timedelta(minutes=2),
    )

    assert head_activation.authority == successor
    assert provider_activation.sequence == 2
    assert provider_activation.previous_activation_digest is not None
    assert provider_activation.authority_checkpoint == head.checkpoint()
    assert journal.latest_activation() == provider_activation


def test_unactivated_provider_profile_is_rejected_on_restart(tmp_path: Path) -> None:
    _runtime_instance, journal, head, binding, provider, repository = _runtime(tmp_path)
    provider._profile = ObjectStorageProviderDeploymentProfile(
        providerFamily="different-provider",
        serverSideEncryptionPolicyId="different-sse",
        localConformanceProfileId="different-conformance",
    )

    with pytest.raises(ObjectStorageProviderRecoveryError, match="not active"):
        RecoverableObjectStorageProviderRuntime(
            authority_store=head,
            repository=cast(ManagedArtifactRepository, repository),
            provider=provider,
            journal=journal,
        )
    assert binding.deployment == head.latest().authority


def test_restart_rejects_changed_journal_schema(tmp_path: Path) -> None:
    _runtime_instance, journal, _head, _binding_value, _provider, _repository = _runtime(tmp_path)
    connection = sqlite3.connect(journal.path)
    try:
        connection.execute("DROP TRIGGER records_no_delete")
        connection.commit()
    finally:
        connection.close()

    with pytest.raises(ObjectStorageProviderRecoveryError, match="schema inventory differs"):
        ObjectStorageProviderAttemptJournal.open(journal.path)
