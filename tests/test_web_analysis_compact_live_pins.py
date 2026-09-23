from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

import pytest

from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin, model_pins
from pajin.web_assessment.analysis_capacity import (
    WebAnalysisCapacityPin,
    _conservative_campaign_prompt_bound,
)
from pajin.web_assessment.analysis_capacity_v2 import (
    _create_web_analysis_capacity_v2_run_with_backend,
    build_web_analysis_capacity_v2_pin,
)
from pajin.web_assessment.analysis_compact_live_pins import (
    COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION,
    COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION,
    CompactWebAnalysisPinError,
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
    build_compact_web_analysis_runtime_pin,
    build_compact_web_analysis_transport_pin,
    load_verified_compact_web_analysis_runtime_pin,
    load_verified_compact_web_analysis_transport_pin,
    verify_compact_web_analysis_live_pin_binding,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
    build_compact_skill_bound_web_analysis_projection,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    CompactSkillBoundWebAnalysisLiveRequest,
    plan_compact_skill_bound_web_analysis_call,
)
from pajin.web_assessment.analysis_skill_projection import (
    _create_web_analysis_skill_projection_run_with_loader,
)
from pajin.web_assessment.analysis_transport import (
    WebAnalysisTransportRuntimePin,
    web_analysis_transport_runtime_pin,
)
from tests.test_web_analysis_capacity_v2 import _FakeV2Tokenizer
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source


def _inputs(
    tmp_path: Path,
) -> tuple[
    Any,
    CompactSkillBoundWebAnalysisLiveRequest,
    RuntimePin,
    WebAnalysisTransportRuntimePin,
]:
    source = _verified_source()
    skill_run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill",
        source_loader=_synthetic_loader(source),
    )
    projection = build_compact_skill_bound_web_analysis_projection(skill_run.snapshot)
    capacity_request = build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    predecessor_runtime = RuntimePin(
        platform="linux/arm64",
        platform_manifest=PLATFORM_MANIFESTS["linux/arm64"],
        worker_image="sha256:" + "1" * 64,
        proxy_image="sha256:" + "2" * 64,
    )
    lineage_transport = web_analysis_transport_runtime_pin(
        predecessor_runtime,
        worker_image="sha256:" + "3" * 64,
        proxy_image="sha256:" + "4" * 64,
    )
    model_pin = model_pins()[0]
    capacity_pin = build_web_analysis_capacity_v2_pin(
        skill_run,
        projection,
        capacity_request,
        runtime=predecessor_runtime,
        model_pin=model_pin,
        transport_pin_digest=lineage_transport.pin_digest,
        conservative_campaign_prompt_tokens=_conservative_campaign_prompt_bound(
            capacity_request,
            model_id=model_pin.name,
        ),
    )
    capacity = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity",
        skill_run=skill_run,
        projection=projection,
        chat_request=capacity_request,
        pin=capacity_pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    planned = plan_compact_skill_bound_web_analysis_call(
        skill_run=skill_run,
        capacity_run=capacity,
        expected_skill_run_id=skill_run.verification.run_id,
        expected_skill_root_digest=skill_run.verification.root_digest,
        expected_capacity_run_id=capacity.run_id,
        expected_capacity_root_digest=capacity.root_digest,
        expected_capacity_pin_digest=capacity.pin.pin_digest,
        expected_capacity_proof_digest=capacity.proof.proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            capacity.model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=lineage_transport.pin_digest,
    )
    return capacity, planned.live_request, predecessor_runtime, lineage_transport


def _pins(
    tmp_path: Path,
) -> tuple[
    Any,
    CompactSkillBoundWebAnalysisLiveRequest,
    RuntimePin,
    WebAnalysisTransportRuntimePin,
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
]:
    capacity, request, predecessor_runtime, lineage = _inputs(tmp_path)
    runtime = build_compact_web_analysis_runtime_pin(capacity, request, lineage)
    transport = build_compact_web_analysis_transport_pin(runtime, lineage)
    return capacity, request, predecessor_runtime, lineage, runtime, transport


def test_compact_live_pins_bind_exact_capacity_request_and_effective_transport(
    tmp_path: Path,
) -> None:
    capacity, request, _, lineage, runtime, transport = _pins(tmp_path)

    assert runtime.capacity_pin_digest == capacity.pin.pin_digest
    assert runtime.live_request_digest == request.request_digest
    assert runtime.capacity_compact_projection_digest == (
        request.capacity_compact_projection_digest
    )
    assert runtime.capacity_chat_request_digest == request.capacity_chat_request_digest
    assert runtime.live_request_compact_projection_digest == request.compact_projection_digest
    assert runtime.live_request_chat_request_digest == request.chat_request_digest
    assert runtime.model_id == capacity.pin.model_id
    assert runtime.context_tokens == 4096
    assert runtime.completion_tokens == request.chat_request.max_completion_tokens == 1024
    assert (
        runtime.model_cpus,
        runtime.model_memory_mb,
        runtime.model_pids,
        runtime.parallel,
        runtime.cache_ram_mb,
    ) == (4, 6144, 128, 1, 0)
    assert runtime.model_image == capacity.pin.model_image
    assert runtime.model_platform == capacity.pin.model_platform
    assert runtime.model_platform_manifest == capacity.pin.model_platform_manifest
    assert runtime.lineage_transport_pin_digest == lineage.pin_digest

    assert transport.runtime_pin_digest == runtime.pin_digest
    assert transport.lineage_transport_pin_digest == lineage.pin_digest
    assert transport.transport_version == COMPACT_WEB_ANALYSIS_TRANSPORT_PIN_VERSION
    assert (
        transport.worker_wire_protocol_version
        == lineage.transport_version
        == COMPACT_WEB_ANALYSIS_WORKER_WIRE_PROTOCOL_VERSION
    )
    assert transport.worker_image == lineage.worker_image
    assert transport.proxy_image == lineage.proxy_image
    assert transport.worker_action == lineage.worker_action
    assert transport.worker_open_timeout_seconds == 180
    assert transport.proxy_exchange_timeout_seconds == 180
    assert transport.job_timeout_seconds == 180
    assert transport.single_dispatch_only is True

    for pin in (runtime, transport):
        wire = pin.model_dump(mode="json", by_alias=True)
        assert not any("authority" in field.lower() for field in wire)

    assert verify_compact_web_analysis_live_pin_binding(
        runtime,
        transport,
        capacity=capacity,
        live_request=request,
        lineage_transport_pin=lineage,
        expected_runtime_pin_digest=runtime.pin_digest,
        expected_transport_pin_digest=transport.pin_digest,
    ) == (runtime, transport)

    drifted_transport = transport.model_copy(
        update={"worker_wire_protocol_version": transport.transport_version}
    )
    with pytest.raises(CompactWebAnalysisPinError, match="verification failed closed"):
        verify_compact_web_analysis_live_pin_binding(
            runtime,
            drifted_transport,
            capacity=capacity,
            live_request=request,
            lineage_transport_pin=lineage,
            expected_runtime_pin_digest=runtime.pin_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )


def test_compact_runtime_rejects_capacity_request_and_transport_recombination(
    tmp_path: Path,
) -> None:
    capacity, request, predecessor_runtime, lineage, runtime, transport = _pins(tmp_path)
    request_raw = request.model_dump(mode="json", by_alias=True)
    request_raw["requestDigest"] = ""
    request_raw["capacityChatRequestDigest"] = "a" * 64
    recombined_request = CompactSkillBoundWebAnalysisLiveRequest.model_validate(request_raw)
    alternate_lineage = web_analysis_transport_runtime_pin(
        predecessor_runtime,
        worker_image="sha256:" + "5" * 64,
        proxy_image="sha256:" + "6" * 64,
    )

    with pytest.raises(CompactWebAnalysisPinError, match="construction failed closed"):
        build_compact_web_analysis_runtime_pin(capacity, recombined_request, lineage)
    with pytest.raises(CompactWebAnalysisPinError, match="construction failed closed"):
        build_compact_web_analysis_runtime_pin(capacity, request, alternate_lineage)

    runtime_raw = runtime.model_dump(mode="json", by_alias=True)
    runtime_raw["pinDigest"] = ""
    runtime_raw["modelSha256"] = "b" * 64
    drifted_runtime = CompactWebAnalysisRuntimePin.model_validate(runtime_raw)
    with pytest.raises(CompactWebAnalysisPinError, match="verification failed closed"):
        verify_compact_web_analysis_live_pin_binding(
            drifted_runtime,
            transport,
            capacity=capacity,
            live_request=request,
            lineage_transport_pin=lineage,
            expected_runtime_pin_digest=drifted_runtime.pin_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )


def test_compact_pin_loaders_are_bounded_strict_and_independently_anchored(
    tmp_path: Path,
) -> None:
    capacity, request, _, lineage, runtime, transport = _pins(tmp_path)
    runtime_path = tmp_path / "compact-runtime-pin.json"
    transport_path = tmp_path / "compact-transport-pin.json"
    runtime_path.write_text(
        json.dumps(runtime.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    transport_path.write_text(
        json.dumps(transport.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True)
        + "\n",
        encoding="utf-8",
    )

    loaded_runtime = load_verified_compact_web_analysis_runtime_pin(
        runtime_path,
        capacity=capacity,
        live_request=request,
        lineage_transport_pin=lineage,
        expected_pin_digest=runtime.pin_digest,
    )
    loaded_transport = load_verified_compact_web_analysis_transport_pin(
        transport_path,
        runtime_pin=loaded_runtime,
        lineage_transport_pin=lineage,
        expected_pin_digest=transport.pin_digest,
    )
    assert loaded_runtime == runtime
    assert loaded_transport == transport

    with pytest.raises(CompactWebAnalysisPinError, match="verification failed closed"):
        load_verified_compact_web_analysis_runtime_pin(
            runtime_path,
            capacity=capacity,
            live_request=request,
            lineage_transport_pin=lineage,
            expected_pin_digest="f" * 64,
        )

    duplicate_path = tmp_path / "duplicate-runtime-pin.json"
    duplicate_path.write_text(
        '{"pinDigest":"' + runtime.pin_digest + '","pinDigest":"' + runtime.pin_digest + '"}',
        encoding="utf-8",
    )
    with pytest.raises(CompactWebAnalysisPinError, match="loading failed closed"):
        load_verified_compact_web_analysis_runtime_pin(
            duplicate_path,
            capacity=capacity,
            live_request=request,
            lineage_transport_pin=lineage,
            expected_pin_digest=runtime.pin_digest,
        )


def test_compact_binding_rejects_predecessor_pin_types(tmp_path: Path) -> None:
    capacity, request, predecessor_runtime, lineage, runtime, transport = _pins(tmp_path)
    old_capacity_raw = capacity.pin.model_dump(mode="json", by_alias=True)
    old_capacity_raw.pop("modelMaterializationPolicyDigest")
    old_capacity_raw["apiVersion"] = "pajin.dev/web-analysis-capacity-pin/v1alpha1"
    old_capacity_raw["pinDigest"] = ""
    old_capacity = cast(Any, WebAnalysisCapacityPin.model_validate(old_capacity_raw))

    with pytest.raises(CompactWebAnalysisPinError, match="construction failed closed"):
        build_compact_web_analysis_runtime_pin(old_capacity, request, lineage)
    with pytest.raises(CompactWebAnalysisPinError, match="construction failed closed"):
        build_compact_web_analysis_transport_pin(cast(Any, predecessor_runtime), lineage)
    with pytest.raises(CompactWebAnalysisPinError, match="verification failed closed"):
        verify_compact_web_analysis_live_pin_binding(
            runtime,
            cast(Any, lineage),
            capacity=capacity,
            live_request=request,
            lineage_transport_pin=lineage,
            expected_runtime_pin_digest=runtime.pin_digest,
            expected_transport_pin_digest=transport.pin_digest,
        )
