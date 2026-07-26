from __future__ import annotations

import base64
import json
import os
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

import pajin.control_plane.api as control_plane_api_module
import pajin.control_plane.replay_worker_main as replay_worker_main_module
from pajin.control_plane.artifact_transfer import (
    MULTIPART_ARTIFACT_PART_BYTES,
    PortableArtifactBundle,
    PortableArtifactFile,
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    PortableArtifactMultipartPart,
    PortableArtifactMultipartPartView,
    PortableArtifactMultipartTransportReceipt,
    PortableArtifactMultipartUploadView,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.artifacts import (
    ArtifactConflict,
    ArtifactValidationError,
    ManagedArtifactRepository,
    build_portable_artifact_bundle,
)
from pajin.control_plane.client import ControlPlaneClient, ControlPlaneTransientError
from pajin.control_plane.execution_attestation import (
    ExecutorAttestationKeyState,
    ExecutorAttestationTrustAnchor,
    ExecutorAttestationVerificationKey,
    ExecutorExecutionAttestation,
    ExecutorExecutionAttestor,
    executor_execution_attestation_bytes,
    executor_public_key_base64url,
    verify_executor_execution_attestation,
)
from pajin.control_plane.models import (
    ReplayArtifactUploadBeginRequest,
    ReplayArtifactUploadPartRequest,
    ReplayFinalizeRequest,
)
from pajin.control_plane.replay_executor import KISAExactReplayExecutor
from pajin.control_plane.service import ControlPlaneService
from pajin.runtime.store import RunStore, verify_run_integrity


def _file(path: str, content: bytes) -> PortableArtifactFile:
    return PortableArtifactFile(
        path=path,
        size=len(content),
        sha256=sha256(content).hexdigest(),
        content_base64=base64.b64encode(content).decode("ascii"),
    )


def _bundle(*files: PortableArtifactFile) -> PortableArtifactBundle:
    ordered = sorted(files, key=lambda item: item.path)
    return PortableArtifactBundle(
        files=ordered,
        file_count=len(ordered),
        total_bytes=sum(item.size for item in ordered),
        manifest_sha256=portable_artifact_manifest_sha256(ordered),
    )


def _multipart_manifest(
    *files: PortableArtifactManifestFile,
) -> PortableArtifactMultipartManifest:
    ordered = sorted(files, key=lambda item: item.path)
    return PortableArtifactMultipartManifest(
        files=ordered,
        file_count=len(ordered),
        total_bytes=sum(item.size for item in ordered),
        manifest_sha256=portable_artifact_manifest_sha256(ordered),
    )


def _trust_anchor(
    *,
    seed: bytes = bytes(range(32)),
    state: ExecutorAttestationKeyState = ExecutorAttestationKeyState.ACTIVE,
) -> ExecutorAttestationTrustAnchor:
    now = datetime(2026, 7, 24, tzinfo=UTC)
    return ExecutorAttestationTrustAnchor(
        trust_domain="pajin.dev/replay-executor",
        issuer="spiffe://pajin.dev/replay-worker",
        keys=[
            ExecutorAttestationVerificationKey(
                key_id="executor-2026-07",
                public_key_base64url=executor_public_key_base64url(seed),
                state=state,
                not_before=now - timedelta(days=1),
                not_after=now + timedelta(days=1),
                revoked_at=now if state is ExecutorAttestationKeyState.REVOKED else None,
            )
        ],
    )


def _attestation(
    bundle: PortableArtifactBundle | PortableArtifactMultipartManifest,
    *,
    seed: bytes = bytes(range(32)),
) -> ExecutorExecutionAttestation:
    now = datetime(2026, 7, 24, 1, tzinfo=UTC)
    attestor = ExecutorExecutionAttestor.from_private_key_bytes(
        active_key_id="executor-2026-07",
        private_key=seed,
        trust_anchor=_trust_anchor(seed=seed),
        clock=lambda: now,
    )
    return attestor.attest(
        {
            "executor_profile": "kisa-exact-v1",
            "batch_id": f"replay-batch_{'1' * 32}",
            "item_id": f"replay-item_{'2' * 32}",
            "job_id": f"job_{'3' * 32}",
            "ticket_id": f"replay-ticket_{'4' * 32}",
            "fencing_value": 7,
            "replay_run_id": "replay-run-portable",
            "source_root_digest": "5" * 64,
            "compilation_digest": "6" * 64,
            "execution_context_digest": "7" * 64,
            "permit_digests": ["8" * 64],
            "replay_request_ids": [f"tool_replay_{'9' * 32}"],
            "artifact_bundle_manifest_sha256": bundle.manifest_sha256,
            "artifact_bundle_file_count": bundle.file_count,
            "artifact_bundle_total_bytes": bundle.total_bytes,
            "artifact_set_digest": "a" * 64,
            "artifact_seal_root_digest": "b" * 64,
            "receipt_seal_root_digest": "c" * 64,
        }
    )


@pytest.mark.skipif(os.name != "posix", reason="descriptor-relative tree scan is POSIX-only")
def test_portable_bundle_binds_sorted_paths_bytes_and_manifest(tmp_path: Path) -> None:
    root = tmp_path / "run"
    (root / "evidence").mkdir(parents=True)
    (root / "run.json").write_bytes(b'{"status":"ok"}\n')
    (root / "evidence" / "request.json").write_bytes(b'{"id":"request-1"}\n')

    bundle = build_portable_artifact_bundle(root)

    assert [item.path for item in bundle.files] == [
        "evidence/request.json",
        "run.json",
    ]
    assert bundle.total_bytes == sum(item.size for item in bundle.files)
    assert bundle.manifest_sha256 == portable_artifact_manifest_sha256(bundle.files)


def test_portable_bundle_rejects_path_escape_and_changed_content() -> None:
    content = b"sealed"
    escaped = {
        "path": "../run.json",
        "size": len(content),
        "sha256": sha256(content).hexdigest(),
        "content_base64": base64.b64encode(content).decode("ascii"),
    }
    changed = {
        **escaped,
        "path": "run.json",
        "content_base64": base64.b64encode(b"altered").decode("ascii"),
    }

    with pytest.raises(ValidationError, match="canonical bounded relatives"):
        PortableArtifactFile.model_validate(escaped)
    with pytest.raises(ValidationError, match="differs from its manifest"):
        PortableArtifactFile.model_validate(changed)


def test_multipart_manifest_and_parts_extend_inline_limit_without_embedding_tree() -> None:
    content_size = (2 * 1024 * 1024) + 1
    file = PortableArtifactManifestFile(
        path="evidence/large.bin",
        size=content_size,
        sha256="a" * 64,
    )
    manifest = _multipart_manifest(file)
    part_content = b"x" * MULTIPART_ARTIFACT_PART_BYTES
    part = PortableArtifactMultipartPart(
        file_index=0,
        part_number=1,
        sha256=sha256(part_content).hexdigest(),
        content_base64=base64.b64encode(part_content).decode("ascii"),
    )

    assert manifest.total_bytes > 2 * 1024 * 1024
    assert manifest.part_count == 3
    assert "contentBase64" not in manifest.model_dump_json(by_alias=True)
    assert part.content == part_content

    with pytest.raises(ValidationError, match="differs from its digest"):
        PortableArtifactMultipartPart(
            file_index=0,
            part_number=1,
            sha256="0" * 64,
            content_base64=part.content_base64,
        )


def test_executor_attestation_verifies_external_key_and_rejects_tampering() -> None:
    bundle = _bundle(_file("run.json", b"sealed"))
    attestation = _attestation(bundle)

    result = verify_executor_execution_attestation(
        attestation,
        trust_anchor=_trust_anchor(),
    )

    assert result.valid is True
    assert result.attestation_digest == attestation.digest
    assert result.artifact_bundle_manifest_sha256 == bundle.manifest_sha256

    signature = base64.urlsafe_b64decode(attestation.signature_base64url + "==")
    tampered = ExecutorExecutionAttestation.model_validate(
        {
            **attestation.model_dump(mode="python"),
            "signature_base64url": base64.urlsafe_b64encode(
                bytes([signature[0] ^ 1]) + signature[1:]
            )
            .decode("ascii")
            .rstrip("="),
        }
    )
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_executor_execution_attestation(
            tampered,
            trust_anchor=_trust_anchor(),
        )


def test_executor_attestation_accepts_multipart_manifest_over_inline_limit() -> None:
    manifest = _multipart_manifest(
        PortableArtifactManifestFile(
            path="large.bin",
            size=(2 * 1024 * 1024) + 1,
            sha256="a" * 64,
        )
    )
    attestation = _attestation(manifest)

    verified = verify_executor_execution_attestation(
        attestation,
        trust_anchor=_trust_anchor(),
    )

    assert verified.artifact_bundle_manifest_sha256 == manifest.manifest_sha256
    assert attestation.statement.artifact_bundle_total_bytes == manifest.total_bytes


@pytest.mark.asyncio
async def test_multipart_upload_retry_resumes_after_transient_transport_failure() -> None:
    executor = object.__new__(KISAExactReplayExecutor)
    executor._permit_attempts = 3
    executor._retry_base_seconds = 0.0001
    executor._retry_max_seconds = 0.0001
    attempts = 0

    async def operation() -> str:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise ControlPlaneTransientError("transient")
        return "accepted"

    assert await executor._retry_multipart_upload(operation) == "accepted"
    assert attempts == 2


@pytest.mark.asyncio
async def test_control_plane_client_uses_separate_multipart_upload_requests() -> None:
    manifest = _multipart_manifest(
        PortableArtifactManifestFile(
            path="large.bin",
            size=(2 * 1024 * 1024) + 1,
            sha256="a" * 64,
        )
    )
    attestation = _attestation(manifest)
    part_content = b"part"
    part = PortableArtifactMultipartPart(
        file_index=0,
        part_number=1,
        sha256=sha256(part_content).hexdigest(),
        content_base64=base64.b64encode(part_content).decode("ascii"),
    )
    staging_id = f"stage_{'d' * 32}"
    job_id = f"job_{'3' * 32}"
    observed: list[tuple[str, str, dict[str, object]]] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        payload = json.loads(request.content)
        assert isinstance(payload, dict)
        observed.append((request.method, request.url.path, payload))
        if request.method == "POST":
            response = PortableArtifactMultipartUploadView(
                output_staging_id=staging_id,
                manifest_sha256=manifest.manifest_sha256,
                file_count=manifest.file_count,
                total_bytes=manifest.total_bytes,
                part_count=manifest.part_count,
                executor_attestation_digest=attestation.digest,
            )
        else:
            response = PortableArtifactMultipartPartView(
                output_staging_id=staging_id,
                manifest_sha256=manifest.manifest_sha256,
                file_index=part.file_index,
                part_number=part.part_number,
                part_sha256=part.sha256,
            )
        return httpx.Response(
            200,
            json=response.model_dump(mode="json", by_alias=True),
        )

    async with ControlPlaneClient(
        base_url="https://control-plane.example",
        bearer_token="worker-token-" + ("x" * 32),
        transport=httpx.MockTransport(handler),
    ) as client:
        await client.begin_replay_artifact_upload(
            job_id,
            ReplayArtifactUploadBeginRequest(
                lease_token="l" * 32,
                ticket_id=f"replay-ticket_{'4' * 32}",
                fencing_value=7,
                output_staging_id=staging_id,
                artifact_manifest=manifest,
                executor_attestation=attestation,
            ),
        )
        await client.put_replay_artifact_upload_part(
            job_id,
            ReplayArtifactUploadPartRequest(
                lease_token="l" * 32,
                ticket_id=f"replay-ticket_{'4' * 32}",
                fencing_value=7,
                output_staging_id=staging_id,
                manifest_sha256=manifest.manifest_sha256,
                part=part,
            ),
        )

    assert [(method, path) for method, path, _payload in observed] == [
        ("POST", f"/v1/worker/replay/jobs/{job_id}/artifact-upload"),
        ("PUT", f"/v1/worker/replay/jobs/{job_id}/artifact-upload/parts"),
    ]


def test_finalize_request_requires_bundle_and_attestation_as_one_authority() -> None:
    bundle = _bundle(_file("run.json", b"sealed"))
    common = {
        "lease_token": "l" * 32,
        "ticket_id": f"replay-ticket_{'4' * 32}",
        "fencing_value": 7,
        "output_staging_id": f"stage_{'d' * 32}",
    }

    with pytest.raises(ValidationError, match="must be supplied together"):
        ReplayFinalizeRequest(**common, artifact_bundle=bundle)
    request = ReplayFinalizeRequest(
        **common,
        artifact_bundle=bundle,
        executor_attestation=_attestation(bundle),
    )
    assert request.artifact_bundle == bundle

    manifest = _multipart_manifest(
        PortableArtifactManifestFile(
            path="large.bin",
            size=(2 * 1024 * 1024) + 1,
            sha256="a" * 64,
        )
    )
    multipart_request = ReplayFinalizeRequest(
        **common,
        artifact_manifest=manifest,
        executor_attestation=_attestation(manifest),
    )
    assert multipart_request.artifact_manifest == manifest
    with pytest.raises(ValidationError, match="mutually exclusive"):
        ReplayFinalizeRequest(
            **common,
            artifact_bundle=bundle,
            artifact_manifest=manifest,
            executor_attestation=_attestation(manifest),
        )


def test_executor_attestation_environment_requires_exact_public_private_pair(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    names = (
        "PAJIN_REPLAY_EXECUTOR_ATTESTATION_KEY_ID",
        "PAJIN_REPLAY_EXECUTOR_ATTESTATION_PRIVATE_KEY",
        "PAJIN_REPLAY_EXECUTOR_ATTESTATION_TRUST_ANCHOR",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)
    assert replay_worker_main_module._execution_attestor_from_env() is None

    monkeypatch.setenv(names[0], "executor-2026-07")
    with pytest.raises(RuntimeError, match="must be configured together"):
        replay_worker_main_module._execution_attestor_from_env()

    private_key = bytes(range(32))
    monkeypatch.setenv(
        names[1],
        base64.urlsafe_b64encode(private_key).decode("ascii").rstrip("="),
    )
    monkeypatch.setenv(names[2], _trust_anchor(seed=private_key).model_dump_json())
    attestor = replay_worker_main_module._execution_attestor_from_env()

    assert attestor is not None
    assert attestor.active_key_id == "executor-2026-07"
    assert attestor.trust_anchor == _trust_anchor(seed=private_key)


def test_control_plane_executor_anchor_requires_replay_worker_identity() -> None:
    raw = _trust_anchor().model_dump_json()

    with pytest.raises(RuntimeError, match="requires PAJIN_CP_REPLAY_WORKER_TOKEN"):
        control_plane_api_module._parse_executor_attestation_anchor(
            raw,
            replay_worker_token=None,
        )
    assert (
        control_plane_api_module._parse_executor_attestation_anchor(
            raw,
            replay_worker_token="replay-worker-token",
        )
        == _trust_anchor()
    )


def test_retest_projection_appends_executor_proof_in_a_new_seal(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "portable-retest")
    store.write_text("kisa-retest.json", "{}")
    store.append_event("mode-pack.kisa.retest.completed")
    first = store.seal()
    attestation = _attestation(_bundle(_file("run.json", b"sealed")))
    relative_path = f"validation/v1alpha1/executor-attestations/replay-item_{'2' * 32}.json"

    ControlPlaneService._seal_retest_executor_attestations(
        store.path,
        run_id=store.run_id,
        artifacts={
            relative_path: executor_execution_attestation_bytes(attestation),
        },
    )

    verification = verify_run_integrity(store.path)
    assert verification.seal_count == 2
    assert verification.root_digest != first.root_digest
    assert (store.path / relative_path).read_bytes() == (
        executor_execution_attestation_bytes(attestation)
    )


@pytest.mark.skipif(os.name != "posix", reason="durable directory fsync is POSIX-only")
def test_repository_materializes_portable_bundle_idempotently(tmp_path: Path) -> None:
    staging_root = tmp_path / "staging"
    repository_root = tmp_path / "repository"
    repository = ManagedArtifactRepository(
        staging_root=staging_root,
        repository_root=repository_root,
    )
    staging_id = f"stage_{'e' * 32}"
    repository.reserve_staging(staging_id)
    bundle = _bundle(
        _file("evidence/request.json", b"request"),
        _file("run.json", b"sealed"),
    )

    first = repository.materialize_portable_bundle(
        staging_id=staging_id,
        bundle=bundle,
    )
    second = repository.materialize_portable_bundle(
        staging_id=staging_id,
        bundle=bundle,
    )

    assert first == second
    assert (staging_root / staging_id / "run.json").read_bytes() == b"sealed"
    with pytest.raises(ArtifactConflict, match="different portable Artifact"):
        repository.materialize_portable_bundle(
            staging_id=staging_id,
            bundle=_bundle(_file("run.json", b"different")),
        )


@pytest.mark.skipif(os.name != "posix", reason="durable directory fsync is POSIX-only")
def test_repository_resumes_and_materializes_large_multipart_upload(tmp_path: Path) -> None:
    repository = ManagedArtifactRepository(
        staging_root=tmp_path / "staging",
        repository_root=tmp_path / "repository",
    )
    staging_id = f"stage_{'f' * 32}"
    repository.reserve_staging(staging_id)
    content = b"large-object-" + (b"x" * (2 * 1024 * 1024))
    manifest = _multipart_manifest(
        PortableArtifactManifestFile(
            path="evidence/large.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
    )
    attestation_digest = "d" * 64

    first_begin = repository.begin_portable_multipart_upload(
        staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest=attestation_digest,
    )
    second_begin = repository.begin_portable_multipart_upload(
        staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest=attestation_digest,
    )
    assert first_begin == second_begin

    for offset in range(0, len(content), manifest.part_bytes):
        part_content = content[offset : offset + manifest.part_bytes]
        part = PortableArtifactMultipartPart(
            file_index=0,
            part_number=(offset // manifest.part_bytes) + 1,
            sha256=sha256(part_content).hexdigest(),
            content_base64=base64.b64encode(part_content).decode("ascii"),
        )
        first_part = repository.put_portable_multipart_part(
            staging_id=staging_id,
            manifest_sha256=manifest.manifest_sha256,
            part=part,
        )
        second_part = repository.put_portable_multipart_part(
            staging_id=staging_id,
            manifest_sha256=manifest.manifest_sha256,
            part=part,
        )
        assert first_part == second_part

    receipt = repository.materialize_portable_multipart_upload(
        staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest=attestation_digest,
    )
    retried = repository.materialize_portable_multipart_upload(
        staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest=attestation_digest,
    )

    assert receipt == retried
    assert isinstance(receipt, PortableArtifactMultipartTransportReceipt)
    assert receipt.part_count == 3
    assert (tmp_path / "staging" / staging_id / "evidence" / "large.bin").read_bytes() == content


@pytest.mark.skipif(os.name != "posix", reason="durable directory fsync is POSIX-only")
def test_repository_rejects_incomplete_multipart_upload(tmp_path: Path) -> None:
    repository = ManagedArtifactRepository(
        staging_root=tmp_path / "staging",
        repository_root=tmp_path / "repository",
    )
    staging_id = f"stage_{'a' * 32}"
    repository.reserve_staging(staging_id)
    content = b"x" * (MULTIPART_ARTIFACT_PART_BYTES + 1)
    manifest = _multipart_manifest(
        PortableArtifactManifestFile(
            path="large.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
    )
    repository.begin_portable_multipart_upload(
        staging_id=staging_id,
        manifest=manifest,
        executor_attestation_digest="e" * 64,
    )
    first_part = content[:MULTIPART_ARTIFACT_PART_BYTES]
    repository.put_portable_multipart_part(
        staging_id=staging_id,
        manifest_sha256=manifest.manifest_sha256,
        part=PortableArtifactMultipartPart(
            file_index=0,
            part_number=1,
            sha256=sha256(first_part).hexdigest(),
            content_base64=base64.b64encode(first_part).decode("ascii"),
        ),
    )

    with pytest.raises(ArtifactValidationError, match="incomplete"):
        repository.materialize_portable_multipart_upload(
            staging_id=staging_id,
            manifest=manifest,
            executor_attestation_digest="e" * 64,
        )
