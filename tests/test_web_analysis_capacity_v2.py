from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError

from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin, model_pins
from pajin.runtime.store import RunIntegrityError, RunStore, load_verified_run_snapshot
from pajin.web_assessment.analysis_capacity import (
    WEB_ANALYSIS_COMPLETION_TOKENS,
    TokenizerModelMountObservation,
    WebAnalysisCapacityError,
    WebAnalysisCapacityPin,
    _conservative_campaign_prompt_bound,
    _create_web_analysis_capacity_run_with_backend,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    WebAnalysisCapacityV2Index,
    WebAnalysisCapacityV2Pin,
    WebAnalysisModelMaterializationAttestation,
    _create_web_analysis_capacity_v2_run_with_backend,
    _model_mount_event_payload,
    build_web_analysis_capacity_v2_pin,
    create_web_analysis_capacity_v2_run,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_projection import (
    _create_web_analysis_skill_projection_run_with_loader,
)
from tests.test_web_analysis_capacity import _FakeTokenizer
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source


class _FakeV2Tokenizer:
    def __init__(
        self,
        *,
        prompt_tokens: int = 1_505,
        staged_sha256: str | None = None,
        cleanup_failure: bool = False,
        absence_failure: bool = False,
    ) -> None:
        self.prompt_tokens = prompt_tokens
        self.staged_sha256 = staged_sha256
        self.cleanup_failure = cleanup_failure
        self.absence_failure = absence_failure
        self.calls: list[object] = []
        self.observation: TokenizerModelMountObservation | None = None

    def start(self, pin: WebAnalysisCapacityPin) -> None:
        self.calls.append(("start", pin.pin_digest))
        self.observation = TokenizerModelMountObservation(
            model_pin_digest=pin.model_pin_digest,
            expected_model_sha256=pin.model_sha256,
            expected_model_size_bytes=pin.model_size_bytes,
            staged_model_sha256=self.staged_sha256 or pin.model_sha256,
            staged_model_size_bytes=pin.model_size_bytes,
            staged_model_uid=10001,
            staged_model_gid=10001,
            staged_model_mode="0400",
            mounted_model_sha256=pin.model_sha256,
            mounted_model_size_bytes=pin.model_size_bytes,
            mounted_model_uid=10001,
            mounted_model_gid=10001,
            mounted_model_mode="0400",
            tokenizer_image_id=pin.tokenizer_image_id,
            staging_strategy="descriptor-to-docker-volume",
            materialization_kind="docker-copy",
            mount_type="volume",
            mount_destination="/models",
            mount_read_only=True,
            digest_algorithm="sha256",
            attested_before_tokenizer_requests=True,
            runtime_user_read_verified=True,
            cleanup_required=True,
        )

    def model_mount_observation(self) -> TokenizerModelMountObservation:
        self.calls.append("model-mount-observation")
        assert self.observation is not None
        return self.observation

    def get_props(self) -> object:
        self.calls.append(("GET", "/props"))
        return {
            "chat_template": "{{ system }}{{ user }}",
            "default_generation_settings": {"n_ctx": 4096},
        }

    def apply_template(self, messages: Sequence[Mapping[str, JsonValue]]) -> object:
        self.calls.append(("POST", "/apply-template"))
        system = cast(str, messages[0]["content"])
        user = cast(str, messages[1]["content"])
        return {"prompt": f"<system>{system}</system><user>{user}</user>"}

    def tokenize(self, formatted_prompt: str) -> object:
        self.calls.append(("POST", "/tokenize"))
        assert formatted_prompt.startswith("<system>")
        return {"tokens": list(range(self.prompt_tokens))}

    def cleanup(self) -> None:
        self.calls.append("cleanup")
        if self.cleanup_failure:
            raise RuntimeError("injected cleanup failure")

    def verify_absent(self) -> None:
        self.calls.append("verify-absent")
        if self.absence_failure:
            raise RuntimeError("injected absence failure")


def _inputs_v2(tmp_path: Path):
    source = _verified_source()
    skill_run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill",
        source_loader=_synthetic_loader(source),
    )
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    request = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    runtime = RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + "1" * 64,
        proxy_image="sha256:" + "2" * 64,
    )
    pin = build_web_analysis_capacity_v2_pin(
        skill_run,
        projection,
        request,
        runtime=runtime,
        model_pin=model_pins()[0],
        transport_pin_digest="3" * 64,
        conservative_campaign_prompt_tokens=_conservative_campaign_prompt_bound(
            request,
            model_id=model_pins()[0].name,
        ),
    )
    return skill_run, projection, request, pin


def _reload(verified, *, skill_run, **overrides: str):
    anchors = {
        "expected_run_id": verified.run_id,
        "expected_root_digest": verified.root_digest,
        "expected_pin_digest": verified.pin.pin_digest,
        "expected_transport_pin_digest": verified.pin.transport_pin_digest,
        "expected_proof_digest": verified.proof.proof_digest,
        "expected_model_materialization_attestation_digest": (
            verified.model_materialization_attestation_digest
        ),
    }
    anchors.update(overrides)
    return load_verified_web_analysis_capacity_v2_run(
        verified.run_path,
        skill_run=skill_run,
        **anchors,
    )


def test_capacity_v2_public_producer_rejects_injected_backend(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    output_root = tmp_path / "capacity"

    with pytest.raises(WebAnalysisCapacityError, match=r"exact pinned llama\.cpp backend"):
        create_web_analysis_capacity_v2_run(
            output_root,
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=cast(Any, _FakeV2Tokenizer()),
        )

    assert not output_root.exists()


def test_capacity_v2_seals_attested_five_artifact_run_and_strictly_reloads(
    tmp_path: Path,
) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    backend = _FakeV2Tokenizer()

    verified = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=backend,
    )

    attestation = verified.evidence.model_materialization_attestation
    assert verified.pin.api_version.endswith("/v1alpha2")
    assert verified.evidence.api_version.endswith("/v1alpha2")
    assert verified.proof.api_version.endswith("/v1alpha2")
    assert verified.index.api_version.endswith("/v1alpha2")
    assert attestation.expected_model_sha256 == pin.model_sha256
    assert attestation.staged_model_sha256 == pin.model_sha256
    assert attestation.mounted_model_sha256 == pin.model_sha256
    assert attestation.expected_model_size_bytes == pin.model_size_bytes
    assert attestation.staged_model_size_bytes == pin.model_size_bytes
    assert attestation.mounted_model_size_bytes == pin.model_size_bytes
    assert attestation.staged_model_uid == 10001
    assert attestation.staged_model_gid == 10001
    assert attestation.staged_model_mode == "0400"
    assert attestation.mounted_model_uid == 10001
    assert attestation.mounted_model_gid == 10001
    assert attestation.mounted_model_mode == "0400"
    assert attestation.staging_strategy == "descriptor-to-docker-volume"
    assert attestation.materialization_kind == "docker-copy"
    assert attestation.mount_type == "volume"
    assert attestation.mount_destination == "/models"
    assert attestation.read_only is True
    assert attestation.runtime_user_read_verified is True
    assert attestation.tokenizer_image_id == pin.tokenizer_image_id
    assert verified.proof.model_materialization_attestation_digest == (
        attestation.attestation_digest
    )
    assert verified.index.model_materialization_attestation_digest == (
        attestation.attestation_digest
    )
    assert verified.proof.prompt_tokens == 1_505
    assert verified.proof.total_tokens == 1_505 + WEB_ANALYSIS_COMPLETION_TOKENS
    assert backend.calls == [
        ("start", cast(tuple[str, str], backend.calls[0])[1]),
        "model-mount-observation",
        ("GET", "/props"),
        ("POST", "/apply-template"),
        ("POST", "/tokenize"),
        "cleanup",
        "verify-absent",
    ]
    snapshot = load_verified_run_snapshot(verified.run_path, expected_run_id=verified.run_id)
    assert tuple(event.event_type for event in snapshot.events) == (
        "web-analysis.capacity-proof-v2.started",
        "web-analysis.capacity-proof-v2.model-mount-attested",
        "web-analysis.capacity-proof-v2.completed",
    )
    assert snapshot.verification.artifact_count == 5
    assert snapshot.verification.event_count == 3
    assert snapshot.verification.seal_count == 1
    assert {item.name for item in verified.run_path.iterdir() if item.name.endswith(".json")} == {
        "compact-projection.json",
        "capacity-pin.json",
        "capacity-evidence.json",
        "capacity-proof.json",
        "capacity-index.json",
    }
    evidence_wire = json.loads(
        (verified.run_path / "capacity-evidence.json").read_text(encoding="utf-8")
    )
    attestation_wire = evidence_wire["modelMaterializationAttestation"]
    assert not ({"hostPath", "modelPath", "inode", "device"} & set(attestation_wire))

    assert _reload(verified, skill_run=skill_run) == verified


def test_capacity_v2_rejects_mismatched_materialization_before_tokenization(
    tmp_path: Path,
) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    backend = _FakeV2Tokenizer(staged_sha256="9" * 64)

    with pytest.raises(WebAnalysisCapacityError, match="measurement failed"):
        _create_web_analysis_capacity_v2_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )

    assert ("GET", "/props") not in backend.calls
    assert ("POST", "/apply-template") not in backend.calls
    assert ("POST", "/tokenize") not in backend.calls
    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


@pytest.mark.parametrize(
    "anchor",
    (
        "expected_root_digest",
        "expected_pin_digest",
        "expected_transport_pin_digest",
        "expected_proof_digest",
        "expected_model_materialization_attestation_digest",
    ),
)
def test_capacity_v2_strict_loader_requires_every_independent_anchor(
    tmp_path: Path,
    anchor: str,
) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    verified = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        _reload(verified, skill_run=skill_run, **{anchor: "0" * 64})


def test_capacity_v2_loader_rejects_v1_run(tmp_path: Path) -> None:
    skill_run, projection, request, v2_pin = _inputs_v2(tmp_path)
    v1_payload = v2_pin.model_dump(mode="json", by_alias=True)
    v1_payload["apiVersion"] = "pajin.dev/web-analysis-capacity-pin/v1alpha1"
    v1_payload["pinDigest"] = ""
    del v1_payload["modelMaterializationPolicyDigest"]
    v1_pin = WebAnalysisCapacityPin.model_validate(v1_payload)
    v1 = _create_web_analysis_capacity_run_with_backend(
        tmp_path / "v1-capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=v1_pin,
        tokenizer_backend=_FakeTokenizer(),
    )

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_v2_run(
            v1.run_path,
            skill_run=skill_run,
            expected_run_id=v1.run_id,
            expected_root_digest=v1.root_digest,
            expected_pin_digest=v1.pin.pin_digest,
            expected_transport_pin_digest=v1.pin.transport_pin_digest,
            expected_proof_digest=v1.proof.proof_digest,
            expected_model_materialization_attestation_digest="0" * 64,
        )


def test_capacity_v2_loader_rejects_defaulted_wire_fields(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    verified = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    projection_raw = json.loads(
        (verified.run_path / "compact-projection.json").read_text(encoding="utf-8")
    )
    pin_raw = json.loads((verified.run_path / "capacity-pin.json").read_text(encoding="utf-8"))
    evidence_raw = json.loads(
        (verified.run_path / "capacity-evidence.json").read_text(encoding="utf-8")
    )
    proof_raw = json.loads((verified.run_path / "capacity-proof.json").read_text(encoding="utf-8"))
    pin_raw.pop("offline")

    forged = RunStore.create(tmp_path / "forged", "web-analysis-capacity-proof")
    attestation = verified.evidence.model_materialization_attestation
    index = WebAnalysisCapacityV2Index(
        runId=forged.run_id,
        projectionDigest=verified.projection_digest,
        pinDigest=pin.pin_digest,
        evidenceDigest=verified.evidence.evidence_digest,
        proofDigest=verified.proof.proof_digest,
        modelMaterializationAttestationDigest=attestation.attestation_digest,
    )
    forged.append_event(
        "web-analysis.capacity-proof-v2.started",
        {
            "pinDigest": pin.pin_digest,
            "projectionDigest": verified.projection_digest,
            "requestDigest": pin.chat_request_digest,
            "modelInferencePerformed": False,
            "providerDispatch": False,
            "targetRequests": 0,
        },
    )
    forged.append_event(
        "web-analysis.capacity-proof-v2.model-mount-attested",
        _model_mount_event_payload(attestation),
    )
    forged.write_json_create_only("compact-projection.json", projection_raw)
    forged.write_json_create_only("capacity-pin.json", pin_raw)
    forged.write_json_create_only("capacity-evidence.json", evidence_raw)
    forged.write_json_create_only("capacity-proof.json", proof_raw)
    forged.write_json_create_only(
        "capacity-index.json",
        index.model_dump(mode="json", by_alias=True),
    )
    forged.append_event(
        "web-analysis.capacity-proof-v2.completed",
        {
            "indexDigest": index.index_digest,
            "evidenceDigest": verified.evidence.evidence_digest,
            "proofDigest": verified.proof.proof_digest,
            "modelMaterializationAttestationDigest": attestation.attestation_digest,
            "promptTokens": verified.proof.prompt_tokens,
            "totalTokens": verified.proof.total_tokens,
            "remainingTokens": verified.proof.remaining_tokens,
            "modelInferencePerformed": False,
            "providerDispatch": False,
            "targetRequests": 0,
        },
    )
    seal = forged.seal()

    with pytest.raises(WebAnalysisCapacityError, match="verification failed closed"):
        load_verified_web_analysis_capacity_v2_run(
            forged.path,
            skill_run=skill_run,
            expected_run_id=forged.run_id,
            expected_root_digest=seal.root_digest,
            expected_pin_digest=pin.pin_digest,
            expected_transport_pin_digest=pin.transport_pin_digest,
            expected_proof_digest=verified.proof.proof_digest,
            expected_model_materialization_attestation_digest=(attestation.attestation_digest),
        )


def test_capacity_v2_artifacts_reject_wrong_versions_and_nonliteral_markers(
    tmp_path: Path,
) -> None:
    _skill_run, _projection, _request, pin = _inputs_v2(tmp_path)
    raw = pin.model_dump(mode="json", by_alias=True)
    raw["apiVersion"] = "pajin.dev/web-analysis-capacity-pin/v1alpha1"
    raw["pinDigest"] = ""
    with pytest.raises(ValidationError):
        WebAnalysisCapacityV2Pin.model_validate(raw)

    policy_raw = pin.model_dump(mode="json", by_alias=True)
    policy_raw["pinDigest"] = ""
    policy_raw["modelMaterializationPolicyDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="policy digest differs"):
        WebAnalysisCapacityV2Pin.model_validate(policy_raw)

    with pytest.raises(ValidationError):
        WebAnalysisModelMaterializationAttestation(
            modelPinDigest=pin.model_pin_digest,
            expectedModelSha256=pin.model_sha256,
            expectedModelSizeBytes=pin.model_size_bytes,
            stagedModelSha256=pin.model_sha256,
            stagedModelSizeBytes=pin.model_size_bytes,
            stagedModelUid=10001,
            stagedModelGid=10001,
            stagedModelMode="0400",
            mountedModelSha256=pin.model_sha256,
            mountedModelSizeBytes=pin.model_size_bytes,
            mountedModelUid=10001,
            mountedModelGid=10001,
            mountedModelMode="0400",
            tokenizerImageId=pin.tokenizer_image_id,
            stagingStrategy="descriptor-to-docker-volume",
            materializationKind="docker-copy",
            mountType="volume",
            mountDestination="/models",
            readOnly=1,
            digestAlgorithm="sha256",
            attestedBeforeTokenizerEndpoints=True,
            runtimeUserReadVerified=True,
            cleanupRequired=True,
        )


@pytest.mark.parametrize(("cleanup_failure", "absence_failure"), ((True, False), (False, True)))
def test_capacity_v2_cleanup_failure_is_never_reported_as_success(
    tmp_path: Path,
    cleanup_failure: bool,
    absence_failure: bool,
) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    backend = _FakeV2Tokenizer(
        cleanup_failure=cleanup_failure,
        absence_failure=absence_failure,
    )

    with pytest.raises(WebAnalysisCapacityError, match="cleanup"):
        _create_web_analysis_capacity_v2_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )

    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


@pytest.mark.parametrize(("cleanup_failure", "absence_failure"), ((True, False), (False, True)))
def test_capacity_v2_cleanup_failure_takes_priority_over_measurement_failure(
    tmp_path: Path,
    cleanup_failure: bool,
    absence_failure: bool,
) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    backend = _FakeV2Tokenizer(
        prompt_tokens=4_096,
        cleanup_failure=cleanup_failure,
        absence_failure=absence_failure,
    )

    with pytest.raises(
        WebAnalysisCapacityError,
        match="cleanup did not prove resource absence",
    ):
        _create_web_analysis_capacity_v2_run_with_backend(
            tmp_path / "capacity",
            skill_run=skill_run,
            projection=projection,
            chat_request=request,
            pin=pin,
            tokenizer_backend=backend,
        )

    assert backend.calls[-2:] == ["cleanup", "verify-absent"]


def test_capacity_v2_direct_artifact_tamper_fails_integrity(tmp_path: Path) -> None:
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    verified = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    proof_path = verified.run_path / "capacity-proof.json"
    raw = json.loads(proof_path.read_text(encoding="utf-8"))
    raw["promptTokens"] += 1
    proof_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises((WebAnalysisCapacityError, RunIntegrityError)):
        _reload(verified, skill_run=skill_run)
