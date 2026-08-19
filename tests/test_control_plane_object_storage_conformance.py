from __future__ import annotations

import base64
import traceback
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote_from_bytes, urlsplit

import pytest
from pydantic import ValidationError

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    ObjectStorageTransportBinding,
    compile_object_storage_transport_binding,
)
from pajin.control_plane.object_storage_conformance import (
    ObjectStorageCleanupObservation,
    ObjectStorageEncryptionObservation,
    ObjectStorageFenceObservation,
    ObjectStorageLogNonDisclosureObservation,
    ObjectStorageMultipartIdempotencyObservation,
    ObjectStorageProviderConformanceCase,
    ObjectStorageProviderConformanceCasePlan,
    ObjectStorageProviderConformanceError,
    ObjectStorageProviderConformanceObservation,
    ObjectStorageProviderConformanceReport,
    ObjectStorageProviderLogCapture,
    ObjectStorageReadAfterWriteObservation,
    ObjectStorageRedirectObservation,
    ObjectStorageSignatureObservation,
    run_object_storage_provider_conformance,
)
from pajin.control_plane.object_storage_provider import (
    ObjectStorageCleanupDisposition,
    ObjectStorageProviderAdapterDefinition,
)
from pajin.control_plane.object_storage_recovery import (
    ObjectStorageProviderAttemptJournal,
    ObjectStorageProviderDeploymentProfile,
    object_storage_provider_operation_fence,
)

NOW = datetime(2026, 8, 18, 9, 0, tzinfo=UTC)
CHALLENGE = b"provider-conformance-challenge-v1"
STAGING_ID = "stage_" + ("c" * 32)
ATTESTATION_DIGEST = "d" * 64


def _authority(
    *,
    revision: int = 1,
    previous: str | None = None,
    issued_at: datetime = NOW,
) -> ObjectStorageDeploymentAuthority:
    return ObjectStorageDeploymentAuthority(
        deploymentId="object-storage:conformance",
        revision=revision,
        previousAuthorityDigest=previous,
        issuedAt=issued_at,
        tenantId="tenant:conformance",
        endpointOrigin="https://objects.example.test",
        objectKeyPrefix="pajin-conformance/tenant",
        uploadTtlSeconds=300,
    )


def _binding(authority: ObjectStorageDeploymentAuthority) -> ObjectStorageTransportBinding:
    content = b"binding-manifest-content"
    files = [
        PortableArtifactManifestFile(
            path="sealed/result.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        ),
    ]
    manifest = PortableArtifactMultipartManifest(
        files=files,
        file_count=1,
        total_bytes=len(content),
        manifest_sha256=portable_artifact_manifest_sha256(files),
    )
    return compile_object_storage_transport_binding(
        authority,
        output_staging_id=STAGING_ID,
        manifest=manifest,
        executor_attestation_digest=ATTESTATION_DIGEST,
        issued_at=NOW + timedelta(seconds=2),
    )


class _Target:
    def __init__(self, binding: ObjectStorageTransportBinding) -> None:
        self._definition = ObjectStorageProviderAdapterDefinition(
            adapterId="test-live-provider-adapter",
            endpointOrigin=binding.deployment.endpoint_origin,
        )
        self._profile = ObjectStorageProviderDeploymentProfile(
            providerFamily="test-black-box",
            serverSideEncryptionPolicyId="test-sse-required",
            localConformanceProfileId="test-isolated-provider-v1",
        )
        self.calls: list[ObjectStorageProviderConformanceCase] = []
        self.case_plans: list[ObjectStorageProviderConformanceCasePlan] = []
        self.fail_case: ObjectStorageProviderConformanceCase | None = None
        self.exception_case: ObjectStorageProviderConformanceCase | None = None
        self.on_execute: Callable[[], None] | None = None
        self.log_bytes = b"adapter provider-sdk http-transport credentials=<redacted>\n"
        self.credential_url = (
            f"{binding.deployment.endpoint_origin}/upload/exact-part"
            "?signature=credential-query-value"
        )
        self.sensitive_value = b"provider-runtime-secret"

    @property
    def definition(self) -> ObjectStorageProviderAdapterDefinition:
        return self._definition

    @property
    def deployment_profile(self) -> ObjectStorageProviderDeploymentProfile:
        return self._profile

    def execute(
        self,
        *,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture:
        self.calls.append(case_plan.case)
        self.case_plans.append(case_plan)
        if self.on_execute is not None:
            callback = self.on_execute
            self.on_execute = None
            callback()
        if case_plan.case is self.exception_case:
            raise RuntimeError(self.credential_url)
        handlers: dict[
            ObjectStorageProviderConformanceCase,
            Callable[
                [ObjectStorageProviderConformanceCasePlan, ObjectStorageTransportBinding, bytes],
                ObjectStorageProviderConformanceObservation | ObjectStorageProviderLogCapture,
            ],
        ] = {
            ObjectStorageProviderConformanceCase.OPERATION_FENCE: self._fence,
            ObjectStorageProviderConformanceCase.MULTIPART_IDEMPOTENCY: self._idempotency,
            ObjectStorageProviderConformanceCase.REDIRECT_REFUSAL: self._redirect,
            ObjectStorageProviderConformanceCase.SERVER_SIDE_ENCRYPTION: self._encryption,
            ObjectStorageProviderConformanceCase.STRONG_READ_AFTER_WRITE: self._consistency,
            ObjectStorageProviderConformanceCase.PREFIX_CLEANUP: self._cleanup,
            ObjectStorageProviderConformanceCase.SIGNATURE_COVERAGE: self._signature,
            ObjectStorageProviderConformanceCase.LOG_NON_DISCLOSURE: self._logs,
        }
        return handlers[case_plan.case](case_plan, binding, challenge)

    def _fence(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageFenceObservation:
        high, low = case_plan.operation_ids
        value = ObjectStorageFenceObservation(
            casePlanDigest=case_plan.case_plan_digest,
            highOperationId=high,
            lowOperationId=low,
            acceptedOperationIds=(high,),
            rejectedOperationIds=(low,),
            observedHighWaterFence=object_storage_provider_operation_fence(high),
            highRemoteEffectCount=1,
            lowRemoteEffectCount=0,
            namespaceInitialObjectCount=0,
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"low_remote_effect_count": 1})
        return value

    def _idempotency(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageMultipartIdempotencyObservation:
        part, completion = case_plan.operation_ids
        value = ObjectStorageMultipartIdempotencyObservation(
            casePlanDigest=case_plan.case_plan_digest,
            partOperationId=part,
            completionOperationId=completion,
            partAttemptCount=2,
            partMutationCount=1,
            completionAttemptCount=2,
            completionMutationCount=1,
            observedContentSha256=sha256(challenge).hexdigest(),
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"part_mutation_count": 2})
        return value

    def _redirect(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageRedirectObservation:
        count = len(case_plan.operation_ids)
        value = ObjectStorageRedirectObservation(
            casePlanDigest=case_plan.case_plan_digest,
            operationIds=case_plan.operation_ids,
            redirectResponseCount=count,
            providerRejectionCount=count,
            followedRedirectCount=0,
            remoteEffectCount=0,
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"followed_redirect_count": 1})
        return value

    def _encryption(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageEncryptionObservation:
        value = ObjectStorageEncryptionObservation(
            casePlanDigest=case_plan.case_plan_digest,
            operationIds=case_plan.operation_ids,
            writeStatusCode=204,
            receiptPolicyId=self.deployment_profile.server_side_encryption_policy_id,
            receiptSha256="e" * 64,
            observedContentSha256=sha256(challenge).hexdigest(),
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"receipt_policy_id": "wrong-policy"})
        return value

    def _consistency(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageReadAfterWriteObservation:
        value = ObjectStorageReadAfterWriteObservation(
            casePlanDigest=case_plan.case_plan_digest,
            operationIds=case_plan.operation_ids,
            writeStatusCode=204,
            immediateReadAttemptCount=1,
            immediateReadStatusCode=200,
            observedContentSha256=sha256(challenge).hexdigest(),
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"immediate_read_attempt_count": 2})
        return value

    def _cleanup(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageCleanupObservation:
        value = ObjectStorageCleanupObservation(
            casePlanDigest=case_plan.case_plan_digest,
            operationId=case_plan.operation_ids[0],
            firstDisposition=ObjectStorageCleanupDisposition.CLEANED,
            secondDisposition=ObjectStorageCleanupDisposition.ALREADY_ABSENT,
            remainingObjectCount=0,
            remainingNativeUploadCount=0,
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"remaining_object_count": 1})
        return value

    def _signature(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        binding: ObjectStorageTransportBinding,
        challenge: bytes,
    ) -> ObjectStorageSignatureObservation:
        value = ObjectStorageSignatureObservation(
            casePlanDigest=case_plan.case_plan_digest,
            credentialOperationId=case_plan.operation_ids[0],
            exactObjectKeySha256=case_plan.exact_object_key_sha256,
            mutatedObjectKeySha256=sha256(b"different-object-key").hexdigest(),
            expiresAt=case_plan.expires_at,
            validProbeAt=binding.issued_at + timedelta(seconds=1),
            expiredProbeAt=case_plan.expires_at + timedelta(seconds=1),
            validStatusCode=204,
            methodMutationStatusCode=403,
            keyMutationStatusCode=403,
            expiredStatusCode=403,
            validRemoteEffectCount=1,
            invalidRemoteEffectCount=0,
            observedContentSha256=sha256(challenge).hexdigest(),
        )
        if self.fail_case is case_plan.case:
            value = value.model_copy(update={"method_mutation_status_code": 204})
        return value

    def _logs(
        self,
        case_plan: ObjectStorageProviderConformanceCasePlan,
        _binding: ObjectStorageTransportBinding,
        _challenge: bytes,
    ) -> ObjectStorageProviderLogCapture:
        log_bytes = self.log_bytes
        if self.fail_case is case_plan.case:
            log_bytes += self.credential_url.encode("utf-8")
        return ObjectStorageProviderLogCapture(
            case_plan_digest=case_plan.case_plan_digest,
            captured_channels=("adapter", "http-transport", "provider-sdk"),
            log_bytes=log_bytes,
            credential_urls=(self.credential_url,),
            additional_sensitive_values=(self.sensitive_value,),
        )


def _context(
    tmp_path: Path,
) -> tuple[
    ObjectStorageAuthorityHeadStore,
    ObjectStorageProviderAttemptJournal,
    ObjectStorageTransportBinding,
    _Target,
]:
    authority = _authority()
    head = ObjectStorageAuthorityHeadStore.bootstrap(
        tmp_path / "authority" / "head.sqlite3",
        authority,
        activated_at=NOW + timedelta(seconds=1),
    )
    binding = _binding(authority)
    target = _Target(binding)
    journal = ObjectStorageProviderAttemptJournal.bootstrap(
        tmp_path / "provider" / "attempts.sqlite3",
        authority_checkpoint=head.checkpoint(),
        adapter=target.definition,
        deployment_profile=target.deployment_profile,
        activated_at=NOW + timedelta(seconds=1),
    )
    return head, journal, binding, target


def _run(
    head: ObjectStorageAuthorityHeadStore,
    journal: ObjectStorageProviderAttemptJournal,
    binding: ObjectStorageTransportBinding,
    target: _Target,
) -> ObjectStorageProviderConformanceReport:
    times = iter((NOW + timedelta(seconds=3), binding.expires_at + timedelta(seconds=2)))
    return run_object_storage_provider_conformance(
        authority_store=head,
        journal=journal,
        binding=binding,
        target=target,
        challenge=CHALLENGE,
        clock=lambda: next(times),
    )


def test_common_harness_binds_active_profile_and_emits_secret_free_report(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)

    report = _run(head, journal, binding, target)

    assert target.calls == list(ObjectStorageProviderConformanceCase)
    assert tuple(result.case for result in report.results) == tuple(
        ObjectStorageProviderConformanceCase
    )
    assert report.activation_digest == journal.latest_activation().activation_digest
    assert report.plan.plan_digest == report.plan_digest
    assert tuple(item.case_plan_digest for item in report.plan.cases) == tuple(
        item.case_plan_digest for item in report.results
    )
    assert report.authority_checkpoint_digest == head.checkpoint().checkpoint_digest
    assert report.adapter_digest == target.definition.adapter_digest
    assert report.deployment_profile_digest == target.deployment_profile.profile_digest
    assert report.binding_digest == binding.binding_digest
    assert report.finished_at > binding.expires_at
    assert report.black_box_observations_passed is True
    assert report.transport_only is True
    assert report.artifact_admission_eligible is False
    assert report.finalization_eligible is False
    first_fences = tuple(
        object_storage_provider_operation_fence(operation_id)
        for operation_id in target.case_plans[0].operation_ids
    )
    assert first_fences == (2, 1)
    raw = report.model_dump(mode="json", by_alias=True)
    serialized = report.model_dump_json(by_alias=True)
    assert target.credential_url not in serialized
    assert "credential-query-value" not in serialized
    assert target.sensitive_value.decode("ascii") not in serialized
    assert CHALLENGE.decode("ascii") not in serialized
    assert ObjectStorageProviderConformanceReport.model_validate(raw) == report


@pytest.mark.parametrize("case", list(ObjectStorageProviderConformanceCase))
def test_each_failed_black_box_observation_blocks_the_report(
    tmp_path: Path,
    case: ObjectStorageProviderConformanceCase,
) -> None:
    head, journal, binding, target = _context(tmp_path)
    target.fail_case = case

    with pytest.raises(ObjectStorageProviderConformanceError, match="observation was rejected"):
        _run(head, journal, binding, target)


def test_target_identity_substitution_is_rejected_before_any_probe(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    target._profile = ObjectStorageProviderDeploymentProfile(
        providerFamily="different-provider",
        serverSideEncryptionPolicyId="test-sse-required",
        localConformanceProfileId="test-isolated-provider-v1",
    )

    with pytest.raises(ObjectStorageProviderConformanceError, match="exact active provider"):
        _run(head, journal, binding, target)

    assert target.calls == []


def test_head_rotation_during_a_probe_invalidates_the_suite(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    successor = _authority(
        revision=2,
        previous=binding.deployment.authority_digest,
        issued_at=NOW + timedelta(minutes=1),
    )

    def rotate_head() -> None:
        head.activate(
            successor,
            expected_checkpoint=head.checkpoint(),
            activated_at=NOW + timedelta(minutes=2),
        )

    target.on_execute = rotate_head

    with pytest.raises(ObjectStorageProviderConformanceError, match="exact active provider"):
        _run(head, journal, binding, target)

    assert target.calls == [ObjectStorageProviderConformanceCase.OPERATION_FENCE]


def test_pending_provider_attempt_blocks_conformance_before_any_probe(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    journal.begin_attempt(
        activation=journal.latest_activation(),
        binding=binding,
        started_at=NOW + timedelta(seconds=3),
    )

    with pytest.raises(ObjectStorageProviderConformanceError, match="exact active provider"):
        _run(head, journal, binding, target)

    assert target.calls == []


def test_provider_exception_is_sanitized_without_credential_url(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    target.exception_case = ObjectStorageProviderConformanceCase.OPERATION_FENCE

    with pytest.raises(
        ObjectStorageProviderConformanceError, match="observation failed"
    ) as captured:
        _run(head, journal, binding, target)

    rendered = "".join(traceback.format_exception(captured.value))
    assert target.credential_url not in str(captured.value)
    assert target.credential_url not in rendered
    assert "credential-query-value" not in rendered


@pytest.mark.parametrize("encoding", ["query", "percent", "base64", "short"])
def test_log_capture_rejects_encoded_credential_material(
    tmp_path: Path,
    encoding: str,
) -> None:
    head, journal, binding, target = _context(tmp_path)
    if encoding == "query":
        target.log_bytes += urlsplit(target.credential_url).query.encode("utf-8")
    elif encoding == "percent":
        target.log_bytes += quote_from_bytes(target.sensitive_value, safe="").encode("ascii")
    elif encoding == "base64":
        target.log_bytes += base64.b64encode(target.sensitive_value)
    else:
        target.sensitive_value = b"key"
        target.log_bytes += target.sensitive_value

    with pytest.raises(ObjectStorageProviderConformanceError, match="observation was rejected"):
        _run(head, journal, binding, target)


def test_log_capture_credential_url_must_use_the_active_endpoint(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    target.credential_url = "https://attacker.example.test/upload?signature=credential-query-value"

    with pytest.raises(ObjectStorageProviderConformanceError, match="observation was rejected"):
        _run(head, journal, binding, target)


def test_report_cannot_finish_before_the_expiry_probe(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)

    with pytest.raises(ObjectStorageProviderConformanceError, match="finished before"):
        run_object_storage_provider_conformance(
            authority_store=head,
            journal=journal,
            binding=binding,
            target=target,
            challenge=CHALLENGE,
            clock=lambda: NOW + timedelta(seconds=3),
        )


def test_report_tampering_and_boolean_coercion_are_rejected(tmp_path: Path) -> None:
    head, journal, binding, target = _context(tmp_path)
    report = _run(head, journal, binding, target)
    raw = report.model_dump(mode="json", by_alias=True)
    raw["results"][0]["observationDigest"] = "f" * 64

    with pytest.raises(ValidationError, match="digest differs"):
        ObjectStorageProviderConformanceReport.model_validate(raw)

    raw = report.model_dump(mode="json", by_alias=True)
    raw["reportDigest"] = ""
    raw["artifactAdmissionEligible"] = 0
    with pytest.raises(ValidationError, match="JSON booleans"):
        ObjectStorageProviderConformanceReport.model_validate(raw)


def test_log_observation_has_no_runtime_secret_fields() -> None:
    assert "log_bytes" not in ObjectStorageLogNonDisclosureObservation.model_fields
    assert "credential_urls" not in ObjectStorageLogNonDisclosureObservation.model_fields
    assert "credential_url_digests" not in ObjectStorageLogNonDisclosureObservation.model_fields
    assert (
        "additional_sensitive_values" not in ObjectStorageLogNonDisclosureObservation.model_fields
    )
    assert "sensitive_value_digests" not in ObjectStorageLogNonDisclosureObservation.model_fields
