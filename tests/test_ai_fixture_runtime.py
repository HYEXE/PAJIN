from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

from pajin.workflow.ai_fixture_runtime import (
    AIFixtureDockerProvider,
    AIFixtureProxyTopologyObservation,
    AIFixtureRuntimeError,
    AIFixtureTargetAttempt,
    AIFixtureTargetCoordinate,
    ai_fixture_resource_names,
    load_ai_source_image_binding,
    registered_ai_source_image_binding,
)
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_PROXY_IMAGE,
    AI_M03_TARGET_IMAGE,
    AI_M03_WORKER_IMAGE,
    AIMeasurementImageRole,
    registered_ai_measured_case_mapping,
)


def _digest(label: str) -> str:
    return sha256(label.encode()).hexdigest()


class _ImageInspector:
    def __init__(self, *, worker_id: str | None = None) -> None:
        self.ids = {
            AI_M03_TARGET_IMAGE: f"sha256:{_digest('ai-target')}",
            AI_M03_WORKER_IMAGE: worker_id or f"sha256:{_digest('ai-worker')}",
            AI_M03_PROXY_IMAGE: f"sha256:{_digest('ai-proxy')}",
        }
        self.calls: list[str] = []

    def image_id(self, reference: str) -> str:
        self.calls.append(reference)
        return self.ids[reference]


def _runtime_models() -> tuple[
    AIFixtureTargetAttempt,
    AIFixtureTargetCoordinate,
    AIFixtureProxyTopologyObservation,
]:
    inspector = _ImageInspector()
    images = registered_ai_source_image_binding(inspector)
    case = registered_ai_measured_case_mapping().public_authority.public_registry.cases[
        0
    ].reference()
    now = datetime(2026, 9, 2, 1, 2, 3, tzinfo=UTC)
    attempt = AIFixtureTargetAttempt(
        nonce="1" * 32,
        case=case,
        images=images.reference(),
        createdAt=now,
    )
    names = ai_fixture_resource_names(attempt)
    target_container_id = _digest("target-container")
    target_network_id = _digest("target-network")
    coordinate = AIFixtureTargetCoordinate(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        case=case,
        images=images.reference(),
        targetContainerName=names.target_container_name,
        targetContainerId=target_container_id,
        targetImageId=images.role(AIMeasurementImageRole.TARGET).observed_image_id,
        targetNetworkName=names.target_network_name,
        targetNetworkId=target_network_id,
        targetUrl="http://host.docker.internal:8080/v1/chat",
        observedAt=now,
    )
    internal_network_id = _digest("internal-network")
    topology = AIFixtureProxyTopologyObservation(
        executionId="execution_ai002b_source",
        workerContainerName="pajin-worker-ai002b",
        workerContainerId=_digest("worker-container"),
        workerImageId=images.role(AIMeasurementImageRole.WORKER).observed_image_id,
        proxyContainerName="pajin-proxy-ai002b",
        proxyContainerId=_digest("proxy-container"),
        proxyImageId=images.role(AIMeasurementImageRole.PROXY).observed_image_id,
        internalNetworkName="pajin-egress-ai002b",
        internalNetworkId=internal_network_id,
        targetNetworkName=names.target_network_name,
        targetNetworkId=target_network_id,
        targetContainerId=target_container_id,
        targetImageId=coordinate.target_image_id,
        workerNetworkIds=(internal_network_id,),
        proxyNetworkIds=tuple(sorted((internal_network_id, target_network_id))),
        targetNetworkIds=(target_network_id,),
        attachedAt=now,
        ephemeralResourcesAbsentAt=now + timedelta(seconds=1),
    )
    return attempt, coordinate, topology


def test_ai_source_image_binding_is_canonical_reinspected_and_non_authorizing() -> None:
    inspector = _ImageInspector()
    binding = registered_ai_source_image_binding(inspector)

    assert tuple(item.role for item in binding.roles) == (
        AIMeasurementImageRole.TARGET,
        AIMeasurementImageRole.WORKER,
        AIMeasurementImageRole.PROXY,
    )
    assert inspector.calls == [
        AI_M03_TARGET_IMAGE,
        AI_M03_WORKER_IMAGE,
        AI_M03_PROXY_IMAGE,
    ]
    assert binding.docker_image_build_authorized is False
    assert binding.caller_selected_image_authorized is False
    assert binding.runtime_image_use_bound is True
    assert load_ai_source_image_binding(binding, inspector=_ImageInspector()) == binding

    foreign_worker = f"sha256:{_digest('foreign-worker')}"
    with pytest.raises(AIFixtureRuntimeError, match="OCI identity differs"):
        load_ai_source_image_binding(
            binding,
            inspector=_ImageInspector(worker_id=foreign_worker),
        )

    reordered = binding.model_dump(mode="python", by_alias=True)
    reordered["bindingId"] = ""
    reordered["bindingDigest"] = ""
    reordered["roles"] = tuple(reversed(reordered["roles"]))
    with pytest.raises(ValidationError, match="membership, order, or identity"):
        type(binding).model_validate(reordered)

    drifted = binding.model_dump(mode="python", by_alias=True)
    drifted["bindingDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="Digest differs"):
        type(binding).model_validate(drifted)

    authorized = binding.model_dump(mode="json", by_alias=True)
    authorized["dockerImageBuildAuthorized"] = True
    with pytest.raises(ValidationError, match="boolean false"):
        type(binding).model_validate(authorized)


def test_ai_fixture_models_require_fixed_target_proxy_only_topology_and_no_ports() -> None:
    attempt, coordinate, topology = _runtime_models()

    assert coordinate.target_url == "http://host.docker.internal:8080/v1/chat"
    assert coordinate.target_mode == "vulnerable"
    assert coordinate.published_port_count == 0
    assert topology.worker_network_ids == (topology.internal_network_id,)
    assert topology.target_network_ids == (topology.target_network_id,)
    assert topology.proxy_network_ids == tuple(
        sorted((topology.internal_network_id, topology.target_network_id))
    )

    caller_selected = attempt.model_dump(mode="python", by_alias=True)
    caller_selected["attemptId"] = ""
    caller_selected["attemptDigest"] = ""
    caller_selected["callerConfigurationAuthorized"] = True
    with pytest.raises(ValidationError, match="caller configuration authority"):
        AIFixtureTargetAttempt.model_validate(caller_selected)

    foreign_target = coordinate.model_dump(mode="python", by_alias=True)
    foreign_target["coordinateDigest"] = ""
    foreign_target["targetUrl"] = "http://foreign.invalid:8080/v1/chat"
    with pytest.raises(ValidationError, match="fixed Target"):
        AIFixtureTargetCoordinate.model_validate(foreign_target)

    direct_worker = topology.model_dump(mode="json", by_alias=True)
    direct_worker["topologyDigest"] = ""
    direct_worker["workerNetworkIds"] = [
        topology.internal_network_id,
        topology.target_network_id,
    ]
    with pytest.raises(ValidationError):
        AIFixtureProxyTopologyObservation.model_validate(direct_worker)

    published = topology.model_dump(mode="json", by_alias=True)
    published["topologyDigest"] = ""
    published["publishedPortCount"] = 1
    with pytest.raises(ValidationError):
        AIFixtureProxyTopologyObservation.model_validate(published)


def test_ai_fixture_docker_json_boundary_rejects_duplicate_and_non_finite_logs() -> None:
    with pytest.raises(AIFixtureRuntimeError, match="log is invalid"):
        AIFixtureDockerProvider._decode_log_lines(
            b'{"event":"ready","event":"ready"}'
        )
    with pytest.raises(AIFixtureRuntimeError, match="log is invalid"):
        AIFixtureDockerProvider._decode_log_lines(b'{"event":"ready","port":NaN}')
