from __future__ import annotations

import asyncio
import base64
import json
import os
import threading
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.benchmark import (
    AI_RAG_MCP_DOCKER_MATCHER_DIGEST,
    AI_RAG_MCP_WALKING_MATCHER_DIGEST,
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkGroundTruth,
    BenchmarkManifest,
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionKey,
    BenchmarkMeasurementRegistryDistributionSigner,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkMeasurementTrustRegistry,
    BenchmarkRegistryGovernedHarnessRunner,
    BenchmarkRunProtocol,
    BenchmarkTargetAttempt,
    BenchmarkTargetCatalogError,
    BenchmarkTargetOperation,
    BenchmarkTargetRecoveryRequest,
    BenchmarkTargetStageReceipt,
    CatalogBoundDockerAIRAGMCPTargetFactoryAdapter,
    CatalogBoundDockerBugBountyTargetFactoryAdapter,
    DockerAIRAGMCPTargetFactoryAdapter,
    DockerAIRAGMCPTargetProfile,
    DockerBenchmarkProviderError,
    DockerBenchmarkProviderEvidence,
    DockerBugBountyTargetFactoryAdapter,
    DockerBugBountyTargetProfile,
    DockerCommandResult,
    RecoverableBenchmarkTargetFactoryRunner,
    benchmark_measurement_public_key_base64url,
    benchmark_measurement_registry_distribution_public_key_base64url,
    benchmark_target_coordinate,
    load_registry_governed_benchmark_observation,
    registered_ai_rag_mcp_docker_ground_truth,
    registered_ai_rag_mcp_docker_target_catalog,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
    select_ai_rag_mcp_docker_target_profile,
)

NOW = datetime(2026, 8, 1, 12, 0, tzinfo=UTC)
MEASUREMENT_KEY = bytes(range(32))
DISTRIBUTION_KEY = bytes(range(32, 64))
TARGET_IMAGE_ID = "sha256:" + "a" * 64
WORKER_IMAGE_ID = "sha256:" + "b" * 64
AI_TARGET_IMAGE_ID = "sha256:" + "c" * 64
AI_WORKER_IMAGE_ID = "sha256:" + "d" * 64


LEGACY_DOCKER_PROVIDER_EVIDENCE_KEYS = (
    "apiVersion",
    "kind",
    "evidenceDigest",
    "adapterDigest",
    "coordinateDigest",
    "operationId",
    "operationDigest",
    "fence",
    "stage",
    "environmentId",
    "isolationId",
    "dockerServerVersion",
    "targetImageId",
    "workerImageId",
    "targetContainerId",
    "workerContainerId",
    "networkId",
    "networkInternal",
    "publishedPortCount",
    "networkContainerCount",
    "targetHealthy",
    "workerExitCode",
    "probeVulnerable",
    "probeOutputSha256",
    "scannerRegistrationDigest",
    "scannerPlanDigest",
    "scannerImageId",
    "scannerContainerId",
    "rawSarifSha256",
    "rawSarifSizeBytes",
    "sarifNormalizationDigest",
    "singleAgentRegistrationDigest",
    "singleAgentPlanDigest",
    "singleAgentTraceDigest",
    "rawModelToolTraceSha256",
    "rawModelToolTraceSizeBytes",
    "toolLoopRunId",
    "toolLoopRootDigest",
    "singleAgentWorkerImageId",
    "egressProxyImageId",
    "resourcesAbsent",
    "observedAt",
)


class _FakeDocker:
    def __init__(self) -> None:
        self.image_ids = {
            "pajin-bug-bounty-target:dev": TARGET_IMAGE_ID,
            "pajin-benchmark-worker:dev": WORKER_IMAGE_ID,
        }
        self.containers: dict[str, dict[str, object]] = {}
        self.networks: dict[str, dict[str, object]] = {}
        self.calls: list[tuple[str, ...]] = []

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> DockerCommandResult:
        self.calls.append(arguments)
        if arguments[:2] == ("version", "--format"):
            return _ok(b"29.5.3\n")
        if arguments[:2] == ("image", "inspect"):
            image_id = self.image_ids.get(arguments[2])
            return _ok(f"{image_id}\n".encode()) if image_id else DockerCommandResult(1)
        if arguments[:2] == ("container", "ls"):
            name = arguments[-1].removeprefix("name=^/").removesuffix("$")
            value = self.containers.get(name)
            return _ok((f"{value['Id']}\n" if value else "").encode())
        if arguments[:2] == ("network", "ls"):
            name = arguments[-1].removeprefix("name=^").removesuffix("$")
            value = self.networks.get(name)
            return _ok((f"{value['Id']}\n" if value else "").encode())
        if arguments[:2] == ("network", "create"):
            name = arguments[-1]
            labels = _labels(arguments)
            self.networks[name] = {
                "Id": _id(name),
                "Internal": "--internal" in arguments,
                "Driver": "bridge",
                "Scope": "local",
                "Labels": labels,
                "Containers": {},
            }
            return _ok(f"{_id(name)}\n".encode())
        if arguments[0] == "create":
            name = arguments[arguments.index("--name") + 1]
            network_name = arguments[arguments.index("--network") + 1]
            labels = _labels(arguments)
            role = labels["pajin.benchmark.role"]
            state: dict[str, object] = {"Running": False, "ExitCode": 0}
            if role == "target":
                state["Health"] = {"Status": "starting"}
            details: dict[str, object] = {
                "Id": _id(name),
                "Image": TARGET_IMAGE_ID if role == "target" else WORKER_IMAGE_ID,
                "Config": {
                    "Labels": labels,
                    "User": "65532:65532",
                    "Cmd": None if role == "target" else ["bug-bounty-sqli-probe"],
                },
                "HostConfig": {
                    "ReadonlyRootfs": True,
                    "PortBindings": None,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges:true"],
                    "NetworkMode": network_name,
                    "Memory": 128 * 1024 * 1024,
                    "NanoCpus": 500_000_000,
                    "PidsLimit": 64,
                    "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=16m"},
                },
                "State": state,
                "Network": network_name,
                "Role": role,
            }
            self.containers[name] = details
            containers = self.networks[network_name]["Containers"]
            assert isinstance(containers, dict)
            containers[_id(name)] = {"Name": name}
            return _ok(f"{_id(name)}\n".encode())
        if arguments[0] == "start":
            name = arguments[-1]
            details = self.containers[name]
            state = details["State"]
            assert isinstance(state, dict)
            if details["Role"] == "target":
                state["Running"] = True
                state["Health"] = {"Status": "healthy"}
                return _ok(f"{name}\n".encode())
            assert stdin is not None
            assert json.loads(stdin) == {
                "scenarioId": "bug-bounty.api.boolean-sqli-lab",
                "target": "http://target:8080/v1/users/lookup",
            }
            state["Running"] = False
            state["ExitCode"] = 0
            network_name = str(details["Network"])
            containers = self.networks[network_name]["Containers"]
            assert isinstance(containers, dict)
            containers.pop(_id(name), None)
            return _ok(_probe_output())
        if arguments[:2] == ("container", "inspect"):
            return _ok(json.dumps([self.containers[arguments[2]]]).encode())
        if arguments[:2] == ("network", "inspect"):
            return _ok(json.dumps([self.networks[arguments[2]]]).encode())
        if arguments[:2] == ("rm", "--force"):
            name = arguments[2]
            details = self.containers.pop(name)
            network_name = str(details["Network"])
            containers = self.networks[network_name]["Containers"]
            assert isinstance(containers, dict)
            containers.pop(_id(name), None)
            return _ok(f"{name}\n".encode())
        if arguments[:2] == ("network", "rm"):
            name = arguments[2]
            self.networks.pop(name)
            return _ok(f"{name}\n".encode())
        raise AssertionError(f"unexpected Docker command: {arguments!r}")


class _MalformedProbeDocker(_FakeDocker):
    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> DockerCommandResult:
        result = super().run(arguments, stdin=stdin)
        if arguments[:3] == ("start", "--attach", "--interactive"):
            return _ok(b"{}")
        return result


class _FakeAIDocker(_FakeDocker):
    def __init__(
        self,
        *,
        malformed_probe: bool = False,
        substituted_body: bool = False,
    ) -> None:
        super().__init__()
        self.image_ids = {
            "pajin-ai-rag-mcp-target:dev": AI_TARGET_IMAGE_ID,
            "pajin-ai-rag-mcp-benchmark-worker:dev": AI_WORKER_IMAGE_ID,
        }
        self.malformed_probe = malformed_probe
        self.substituted_body = substituted_body

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> DockerCommandResult:
        if arguments[0] == "create":
            result = super().run(arguments, stdin=stdin)
            name = arguments[arguments.index("--name") + 1]
            details = self.containers[name]
            role = details["Role"]
            details["Image"] = AI_TARGET_IMAGE_ID if role == "target" else AI_WORKER_IMAGE_ID
            config = details["Config"]
            assert isinstance(config, dict)
            config["Cmd"] = None if role == "target" else ["ai-rag-mcp-chain-probe"]
            return result
        if arguments[:3] == ("start", "--attach", "--interactive"):
            name = arguments[-1]
            details = self.containers[name]
            assert stdin is not None
            assert json.loads(stdin) == {
                "scenarioId": "ai-rag-mcp.docker.file-upload-rag-tool-authorization",
                "target": "http://target:8080",
            }
            state = details["State"]
            assert isinstance(state, dict)
            state["Running"] = False
            state["ExitCode"] = 0
            network_name = str(details["Network"])
            containers = self.networks[network_name]["Containers"]
            assert isinstance(containers, dict)
            containers.pop(_id(name), None)
            if self.malformed_probe:
                return _ok(b"{}")
            return _ok(_ai_probe_output(internal_data_accessed=not self.substituted_body))
        return super().run(arguments, stdin=stdin)


class _BlockingDocker(_FakeDocker):
    def __init__(self) -> None:
        super().__init__()
        self.entered = threading.Event()
        self.release = threading.Event()
        self._blocked = False

    def run(
        self,
        arguments: tuple[str, ...],
        *,
        stdin: bytes | None = None,
    ) -> DockerCommandResult:
        if arguments[:2] == ("version", "--format") and not self._blocked:
            self._blocked = True
            self.entered.set()
            if not self.release.wait(timeout=10):
                raise AssertionError("test did not release blocked Docker call")
        return super().run(arguments, stdin=stdin)


def _ok(stdout: bytes = b"") -> DockerCommandResult:
    return DockerCommandResult(returncode=0, stdout=stdout)


def _id(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _labels(arguments: tuple[str, ...]) -> dict[str, str]:
    values: dict[str, str] = {}
    for index, argument in enumerate(arguments):
        if argument == "--label":
            key, value = arguments[index + 1].split("=", 1)
            values[key] = value
    return values


def _probe_output() -> bytes:
    observations: list[dict[str, object]] = []
    for name, count, query_mode in (
        ("baseline", 1, "parameterized-identifier"),
        ("negative-control", 0, "false-control"),
        ("boolean-probe", 2, "unsafe-boolean-expression"),
    ):
        body = json.dumps(
            {
                "synthetic": True,
                "recordCount": count,
                "records": [{} for _ in range(count)],
                "queryMode": query_mode,
            },
            separators=(",", ":"),
        ).encode()
        observations.append(
            {
                "name": name,
                "status": 200,
                "recordCount": count,
                "synthetic": True,
                "bodySha256": sha256(body).hexdigest(),
                "responseBodyBase64": base64.b64encode(body).decode(),
            }
        )
    return json.dumps(
        {
            "target": "http://target:8080/v1/users/lookup",
            "scenarioId": "bug-bounty.api.boolean-sqli-lab",
            "vulnerable": True,
            "checks": {
                "baselineSingleRecord": True,
                "negativeControlEmpty": True,
                "booleanProbeExpanded": True,
                "syntheticLabOnly": True,
            },
            "observations": observations,
            "networkPerformed": True,
        },
        separators=(",", ":"),
    ).encode()


def _ai_probe_output(*, internal_data_accessed: bool = True) -> bytes:
    bodies = (
        (
            "upload",
            {
                "accepted": True,
                "documentId": "document:untrusted-upload",
                "synthetic": True,
            },
        ),
        (
            "agent-query",
            {
                "authorizationEnforced": False,
                "inputMarker": "ignore previous",
                "internalDataAccessed": internal_data_accessed,
                "mcpArgument": "internal://policy",
                "mcpServerId": "demo-security",
                "mcpToolName": "inspect_text",
                "observation": "untrusted text contains an instruction-hijacking pattern",
                "ragDocumentId": "document:untrusted-upload",
                "synthetic": True,
            },
        ),
    )
    observations = []
    for name, value in bodies:
        body = json.dumps(value, separators=(",", ":")).encode()
        observations.append(
            {
                "name": name,
                "status": 200,
                "synthetic": True,
                "bodySha256": sha256(body).hexdigest(),
                "responseBodyBase64": base64.b64encode(body).decode(),
            }
        )
    return json.dumps(
        {
            "target": "http://target:8080",
            "scenarioId": "ai-rag-mcp.docker.file-upload-rag-tool-authorization",
            "vulnerable": True,
            "checks": {
                "uploadAccepted": True,
                "ragRetrievedDocument": True,
                "mcpArgumentInfluenced": True,
                "authorizationNotEnforced": True,
                "internalDataAccessed": True,
                "syntheticLabOnly": True,
            },
            "observations": observations,
            "networkPerformed": True,
        },
        separators=(",", ":"),
    ).encode()


def _profile(
    *,
    target_image_id: str = TARGET_IMAGE_ID,
    worker_image_id: str = WORKER_IMAGE_ID,
) -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=target_image_id,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=worker_image_id,
    )


def _ai_profile() -> DockerAIRAGMCPTargetProfile:
    return DockerAIRAGMCPTargetProfile(
        targetImage="pajin-ai-rag-mcp-target:dev",
        targetImageId=AI_TARGET_IMAGE_ID,
        workerImage="pajin-ai-rag-mcp-benchmark-worker:dev",
        workerImageId=AI_WORKER_IMAGE_ID,
    )


def _ai_manifest(profile: DockerAIRAGMCPTargetProfile) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:docker-ai-rag-mcp-v1",
        targetFactoryId="target-factory:docker-ai-rag-mcp",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="c" * 64,
        groundTruthDigest="d" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:docker-ai-rag-mcp-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=1,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:docker-ai-rag-mcp-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:docker-ai-rag-mcp-baseline",
                implementationVersion="1.0.0",
                configurationDigest="e" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _manifest(profile: DockerBugBountyTargetProfile) -> BenchmarkManifest:
    return BenchmarkManifest(
        benchmarkId="benchmark:docker-bug-bounty-v1",
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="c" * 64,
        groundTruthDigest="d" * 64,
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:docker-bug-bounty-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=120,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=1,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:docker-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId="pajin:docker-bug-bounty-baseline",
                implementationVersion="1.0.0",
                configurationDigest="e" * 64,
                adaptiveSupervisor=False,
            )
        ],
    )


def _measurement_anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:docker-bug-bounty",
        authorityVersion="1.0.0",
        keyId="measurement-key:docker-bug-bounty-1",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(MEASUREMENT_KEY),
    )


def _adapter(
    tmp_path: Path,
    docker: _FakeDocker,
    *,
    profile: DockerBugBountyTargetProfile | None = None,
) -> tuple[BenchmarkManifest, DockerBugBountyTargetFactoryAdapter]:
    selected = profile or _profile()
    manifest = _manifest(selected)
    return manifest, DockerBugBountyTargetFactoryAdapter(
        state_path=tmp_path / "docker-provider.sqlite3",
        profile=selected,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )


def _runner(
    tmp_path: Path,
    adapter: DockerBugBountyTargetFactoryAdapter,
) -> RecoverableBenchmarkTargetFactoryRunner:
    return RecoverableBenchmarkTargetFactoryRunner(
        output_root=tmp_path / "runs",
        journal_path=tmp_path / "target-journal.sqlite3",
        adapter=adapter,
        trust_anchor=_measurement_anchor(),
    )


def test_docker_provider_v1alpha1_wire_and_digest_remain_legacy_compatible() -> None:
    legacy_digest = "51928e0aaba09e9faf682dac7e8b20ca0ee0a4b6fedccf42b1ad9e273975c444"
    legacy_wire = {
        "apiVersion": "pajin.dev/docker-benchmark-provider-evidence/v1alpha1",
        "kind": "DockerBenchmarkProviderEvidence",
        "evidenceDigest": legacy_digest,
        "adapterDigest": "a" * 64,
        "coordinateDigest": "b" * 64,
        "operationId": "operation:reset",
        "operationDigest": "c" * 64,
        "fence": 1,
        "stage": "reset",
        "environmentId": "environment:legacy",
        "dockerServerVersion": "29.5.3",
        "targetImageId": "sha256:" + "d" * 64,
        "workerImageId": "sha256:" + "e" * 64,
        "resourcesAbsent": True,
        "observedAt": "2026-08-01T12:00:00Z",
    }

    evidence = DockerBenchmarkProviderEvidence.model_validate_json(json.dumps(legacy_wire))
    serialized = evidence.model_dump(mode="json", by_alias=True)

    assert evidence.evidence_digest == legacy_digest
    assert tuple(serialized) == LEGACY_DOCKER_PROVIDER_EVIDENCE_KEYS
    assert not any(key.startswith("requestUnit") for key in serialized)
    assert (
        DockerBenchmarkProviderEvidence.model_validate_json(evidence.model_dump_json(by_alias=True))
        == evidence
    )


def test_docker_provider_runs_internal_lab_and_retrieves_bound_evidence(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)

    outcome = asyncio.run(
        _runner(tmp_path, adapter).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    authority = outcome.authority
    isolation = adapter.evidence(authority.isolation_receipt)
    execution = adapter.evidence(authority.execution_receipt)
    cleanup = adapter.evidence(authority.cleanup_receipt)
    assert isolation.network_internal is True
    assert isolation.published_port_count == 0
    assert execution.probe_vulnerable is True
    assert execution.network_container_count == 1
    assert cleanup.resources_absent is True
    assert authority.observation.matched_known_finding_count == 1
    assert not docker.containers
    assert not docker.networks


def test_ai_rag_mcp_docker_provider_runs_real_chain_contract(tmp_path: Path) -> None:
    docker = _FakeAIDocker()
    profile = _ai_profile()
    manifest = _ai_manifest(profile)
    adapter = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )

    outcome = asyncio.run(
        RecoverableBenchmarkTargetFactoryRunner(
            output_root=tmp_path / "runs",
            journal_path=tmp_path / "target-journal.sqlite3",
            adapter=adapter,
            trust_anchor=_measurement_anchor(),
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    authority = outcome.authority
    execution = adapter.evidence(authority.execution_receipt)
    assert adapter.profile == profile
    assert execution.probe_vulnerable is True
    assert authority.observation.known_attack_surface_count == 3
    assert authority.observation.completed_ground_truth_chain_count == 1
    assert not docker.containers
    assert not docker.networks


def test_ai_rag_mcp_docker_provider_rejects_unproved_worker_output(tmp_path: Path) -> None:
    docker = _FakeAIDocker(malformed_probe=True)
    profile = _ai_profile()
    manifest = _ai_manifest(profile)
    adapter = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset = asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))
    isolation = asyncio.run(
        adapter.establish_isolation(
            coordinate,
            reset,
            _operation(attempt, "isolation"),
        )
    )

    with pytest.raises(DockerBenchmarkProviderError, match="probe result"):
        asyncio.run(adapter.execute(coordinate, isolation, _operation(attempt, "execution")))


def test_ai_rag_mcp_docker_provider_rejects_true_flags_with_substituted_body(
    tmp_path: Path,
) -> None:
    docker = _FakeAIDocker(substituted_body=True)
    profile = _ai_profile()
    manifest = _ai_manifest(profile)
    adapter = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset = asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))
    isolation = asyncio.run(
        adapter.establish_isolation(
            coordinate,
            reset,
            _operation(attempt, "isolation"),
        )
    )

    with pytest.raises(DockerBenchmarkProviderError, match="probe body differs"):
        asyncio.run(adapter.execute(coordinate, isolation, _operation(attempt, "execution")))


def test_ai_rag_mcp_docker_provider_runs_through_exact_runnable_catalog(
    tmp_path: Path,
) -> None:
    docker = _FakeAIDocker()
    profile = _ai_profile()
    ground_truth = registered_ai_rag_mcp_docker_ground_truth(
        profile,
        benchmark_id="benchmark:docker-ai-rag-mcp-v1",
    )
    manifest = _ai_manifest(profile).model_copy(
        update={"ground_truth_digest": ground_truth.digest()}
    )
    provider = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )
    adapter = CatalogBoundDockerAIRAGMCPTargetFactoryAdapter(
        provider=provider,
        manifest=manifest,
        catalog=registered_ai_rag_mcp_docker_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )

    outcome = asyncio.run(
        RecoverableBenchmarkTargetFactoryRunner(
            output_root=tmp_path / "runs",
            journal_path=tmp_path / "target-journal.sqlite3",
            adapter=adapter,
            trust_anchor=_measurement_anchor(),
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    assert adapter.selection.registration.network_policy == (
        "docker-internal-bridge-no-published-ports"
    )
    assert outcome.authority.observation.discovered_known_attack_surface_count == 3
    assert outcome.authority.observation.matched_known_finding_count == 1
    assert provider.evidence(outcome.authority.execution_receipt).probe_vulnerable is True


def test_ai_rag_mcp_runnable_catalog_uses_distinct_matcher_and_exact_adapter(
    tmp_path: Path,
) -> None:
    profile = _ai_profile()
    ground_truth = registered_ai_rag_mcp_docker_ground_truth(
        profile,
        benchmark_id="benchmark:docker-ai-rag-mcp-v1",
    )
    manifest = _ai_manifest(profile).model_copy(
        update={"ground_truth_digest": ground_truth.digest()}
    )
    provider = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=_FakeAIDocker(),
    )
    catalog = registered_ai_rag_mcp_docker_target_catalog(profile, ground_truth)

    case = ground_truth.cases[0]
    assert case.matcher_digest == AI_RAG_MCP_DOCKER_MATCHER_DIGEST
    assert case.matcher_digest != AI_RAG_MCP_WALKING_MATCHER_DIGEST
    forged_adapter = provider.definition.model_copy(update={"target_factory_digest": "f" * 64})
    with pytest.raises(BenchmarkTargetCatalogError, match="selection failed"):
        select_ai_rag_mcp_docker_target_profile(
            manifest,
            adapter=forged_adapter,
            profile=profile,
            catalog=catalog,
            ground_truth=ground_truth,
        )

    substituted_raw = ground_truth.model_dump(mode="json", by_alias=True)
    substituted_raw["cases"][0]["matcherId"] = "matcher:sealed-walking-rag-mcp-confirmation"
    substituted_raw["cases"][0]["matcherDigest"] = AI_RAG_MCP_WALKING_MATCHER_DIGEST
    substituted = BenchmarkGroundTruth.model_validate(substituted_raw)
    with pytest.raises(BenchmarkTargetCatalogError, match="differs"):
        registered_ai_rag_mcp_docker_target_catalog(profile, substituted)


def test_docker_provider_runs_through_registered_target_catalog(tmp_path: Path) -> None:
    docker = _FakeDocker()
    profile = _profile()
    ground_truth = registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id="benchmark:docker-bug-bounty-v1",
    )
    manifest = _manifest(profile).model_copy(update={"ground_truth_digest": ground_truth.digest()})
    provider = DockerBugBountyTargetFactoryAdapter(
        state_path=tmp_path / "docker-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=docker,
    )
    adapter = CatalogBoundDockerBugBountyTargetFactoryAdapter(
        provider=provider,
        manifest=manifest,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )

    outcome = asyncio.run(
        RecoverableBenchmarkTargetFactoryRunner(
            output_root=tmp_path / "runs",
            journal_path=tmp_path / "target-journal.sqlite3",
            adapter=adapter,
            trust_anchor=_measurement_anchor(),
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    assert adapter.selection.ground_truth_digest == ground_truth.digest()
    assert outcome.authority.observation.matched_known_finding_count == 1
    assert provider.evidence(outcome.authority.execution_receipt).probe_vulnerable is True
    assert not docker.containers
    assert not docker.networks


def test_docker_provider_replays_completed_operation_and_rejects_stale_fence(
    tmp_path: Path,
) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=2,
        startedAt=NOW,
    )
    operation = BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=attempt.fence,
        stage="reset",
        ordinal=1,
    )

    first = asyncio.run(adapter.reset(coordinate, operation))
    calls_after_first = len(docker.calls)
    second = asyncio.run(adapter.reset(coordinate, operation))

    assert second == first
    assert len(docker.calls) == calls_after_first
    stale_attempt = attempt.model_copy(update={"fence": 1})
    stale_operation = BenchmarkTargetOperation(
        attemptId=stale_attempt.attempt_id,
        attemptDigest=stale_attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=1,
        stage="reset",
        ordinal=2,
    )
    with pytest.raises(DockerBenchmarkProviderError, match="stale fence"):
        asyncio.run(adapter.reset(coordinate, stale_operation))


def test_docker_provider_higher_fence_reconciles_abandoned_resources(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=3,
        startedAt=NOW,
    )
    reset_operation = _operation(attempt, "reset")
    reset = asyncio.run(adapter.reset(coordinate, reset_operation))
    isolation_operation = _operation(attempt, "isolation")
    isolation = asyncio.run(adapter.establish_isolation(coordinate, reset, isolation_operation))
    assert docker.containers and docker.networks
    cleanup_operation = _operation(attempt, "cleanup", fence=4)
    request = BenchmarkTargetRecoveryRequest(
        abandonedAttempt=attempt,
        cleanupOperation=cleanup_operation,
        knownIsolationReceipt=isolation,
    )

    cleanup = asyncio.run(adapter.reconcile_cleanup(coordinate, request))

    assert adapter.evidence(cleanup).resources_absent is True
    assert not docker.containers
    assert not docker.networks
    with pytest.raises(DockerBenchmarkProviderError, match="stale fence"):
        asyncio.run(adapter.execute(coordinate, isolation, _operation(attempt, "execution")))


def test_docker_provider_rejects_image_substitution_before_resource_mutation(
    tmp_path: Path,
) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    docker.image_ids["pajin-benchmark-worker:dev"] = "sha256:" + "f" * 64
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )

    with pytest.raises(DockerBenchmarkProviderError, match="image identity"):
        asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))

    assert not docker.containers
    assert not docker.networks


def test_docker_provider_evidence_requires_exact_receipt(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    outcome = asyncio.run(
        _runner(tmp_path, adapter).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )
    forged = outcome.authority.execution_receipt.model_copy(
        update={"provider_evidence_digest": "f" * 64}
    )

    with pytest.raises(DockerBenchmarkProviderError, match="receipt binding"):
        adapter.evidence(forged)


def test_docker_provider_rejects_stage_mismatch_and_lifecycle_reordering(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    isolation_operation = _operation(attempt, "isolation")

    with pytest.raises(DockerBenchmarkProviderError, match="operation identity"):
        asyncio.run(adapter.reset(coordinate, isolation_operation))

    forged_reset = BenchmarkTargetStageReceipt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        stage="reset",
        operationId="benchmark-target-operation:forged-reset",
        environmentId=f"environment:docker:{coordinate.coordinate_digest}",
        isolationId=None,
        status="succeeded",
        startedAt=NOW,
        completedAt=NOW + timedelta(seconds=1),
        providerEvidenceDigest="f" * 64,
    )
    with pytest.raises(DockerBenchmarkProviderError, match="lifecycle order"):
        asyncio.run(
            adapter.establish_isolation(
                coordinate,
                forged_reset,
                isolation_operation,
            )
        )


def test_docker_provider_rejects_newer_fence_resource_during_cleanup(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset = asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))
    isolation = asyncio.run(
        adapter.establish_isolation(
            coordinate,
            reset,
            _operation(attempt, "isolation"),
        )
    )
    for resource in (*docker.containers.values(), *docker.networks.values()):
        labels = resource.get("Labels")
        if labels is None:
            config = resource["Config"]
            assert isinstance(config, dict)
            labels = config["Labels"]
        assert isinstance(labels, dict)
        labels["pajin.benchmark.fence"] = "3"
    cleanup_operation = _operation(attempt, "cleanup", fence=2)
    request = BenchmarkTargetRecoveryRequest(
        abandonedAttempt=attempt,
        cleanupOperation=cleanup_operation,
        knownIsolationReceipt=isolation,
    )

    with pytest.raises(DockerBenchmarkProviderError, match="ownership or fence"):
        asyncio.run(adapter.reconcile_cleanup(coordinate, request))


def test_docker_provider_rejects_runtime_hardening_drift_before_worker(
    tmp_path: Path,
) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset = asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))
    isolation = asyncio.run(
        adapter.establish_isolation(
            coordinate,
            reset,
            _operation(attempt, "isolation"),
        )
    )
    target = next(iter(docker.containers.values()))
    host = target["HostConfig"]
    assert isinstance(host, dict)
    host["Memory"] = 0

    with pytest.raises(DockerBenchmarkProviderError, match="hardening policy"):
        asyncio.run(adapter.execute(coordinate, isolation, _operation(attempt, "execution")))


def test_docker_provider_rejects_malformed_probe_and_oversized_cli_output(
    tmp_path: Path,
) -> None:
    docker = _MalformedProbeDocker()
    manifest, adapter = _adapter(tmp_path / "probe", docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset = asyncio.run(adapter.reset(coordinate, _operation(attempt, "reset")))
    isolation = asyncio.run(
        adapter.establish_isolation(
            coordinate,
            reset,
            _operation(attempt, "isolation"),
        )
    )
    with pytest.raises(DockerBenchmarkProviderError, match="probe result"):
        asyncio.run(adapter.execute(coordinate, isolation, _operation(attempt, "execution")))

    class _OversizedDocker(_FakeDocker):
        def run(
            self,
            arguments: tuple[str, ...],
            *,
            stdin: bytes | None = None,
        ) -> DockerCommandResult:
            if arguments[:2] == ("version", "--format"):
                return _ok(b"x" * (1024 * 1024 + 1))
            return super().run(arguments, stdin=stdin)

    oversized = _OversizedDocker()
    second_manifest, second_adapter = _adapter(tmp_path / "oversized", oversized)
    second_coordinate = benchmark_target_coordinate(
        second_manifest,
        arm_id=second_manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    second_attempt = BenchmarkTargetAttempt(
        adapterDigest=second_adapter.definition.adapter_digest,
        coordinateDigest=second_coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    with pytest.raises(DockerBenchmarkProviderError, match="command result"):
        asyncio.run(
            second_adapter.reset(
                second_coordinate,
                _operation(second_attempt, "reset"),
            )
        )


def test_docker_provider_operation_lock_serializes_higher_fence_cleanup(
    tmp_path: Path,
) -> None:
    docker = _BlockingDocker()
    manifest, first_adapter = _adapter(tmp_path, docker)
    _, second_adapter = _adapter(tmp_path, docker)
    coordinate = benchmark_target_coordinate(
        manifest,
        arm_id=manifest.arms[0].arm_id,
        seed=7,
        repetition=1,
    )
    attempt = BenchmarkTargetAttempt(
        adapterDigest=first_adapter.definition.adapter_digest,
        coordinateDigest=coordinate.coordinate_digest,
        fence=1,
        startedAt=NOW,
    )
    reset_operation = _operation(attempt, "reset")
    cleanup_operation = _operation(attempt, "cleanup", fence=2)
    request = BenchmarkTargetRecoveryRequest(
        abandonedAttempt=attempt,
        cleanupOperation=cleanup_operation,
        knownIsolationReceipt=None,
    )

    async def exercise() -> tuple[BenchmarkTargetStageReceipt, BenchmarkTargetStageReceipt]:
        reset_task = asyncio.create_task(first_adapter.reset(coordinate, reset_operation))
        assert await asyncio.to_thread(docker.entered.wait, 5)
        cleanup_task = asyncio.create_task(second_adapter.reconcile_cleanup(coordinate, request))
        await asyncio.sleep(0.1)
        assert len(docker.calls) == 0
        docker.release.set()
        return await asyncio.gather(reset_task, cleanup_task)

    reset, cleanup = asyncio.run(exercise())

    assert reset.stage == "reset"
    assert cleanup.stage == "cleanup"
    assert cleanup.started_at >= reset.completed_at


def test_docker_provider_integrates_with_registry_governed_harness(tmp_path: Path) -> None:
    docker = _FakeDocker()
    manifest, adapter = _adapter(tmp_path, docker)
    registry, distribution_anchor, bundle = _registry_distribution()
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry-activation.sqlite3"
    )
    target_runner = _runner(tmp_path, adapter)

    outcome = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=target_runner,
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    observation = load_registry_governed_benchmark_observation(
        manifest,
        outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )
    assert registry.active_key.trust_anchor == outcome.target.authority.trust_anchor
    assert observation.observation == outcome.target.authority.observation
    assert outcome.authority.measurement_admission_eligible is True


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_BENCHMARK") != "1",
    reason="real Docker benchmark conformance is opt-in",
)
def test_real_docker_bug_bounty_provider_conformance(tmp_path: Path) -> None:
    import subprocess

    def image_id(reference: str) -> str:
        result = subprocess.run(
            ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()

    profile = _profile(
        target_image_id=image_id("pajin-bug-bounty-target:dev"),
        worker_image_id=image_id("pajin-benchmark-worker:dev"),
    )
    ground_truth = registered_traditional_web_api_ground_truth(
        profile,
        benchmark_id="benchmark:docker-bug-bounty-v1",
    )
    manifest = _manifest(profile).model_copy(update={"ground_truth_digest": ground_truth.digest()})
    provider = DockerBugBountyTargetFactoryAdapter(
        state_path=tmp_path / "docker-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
    )
    adapter = CatalogBoundDockerBugBountyTargetFactoryAdapter(
        provider=provider,
        manifest=manifest,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )

    _, distribution_anchor, bundle = _registry_distribution()
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry-activation.sqlite3"
    )
    outcome = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=_runner(tmp_path, adapter),
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    observation = load_registry_governed_benchmark_observation(
        manifest,
        outcome,
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )
    isolation = provider.evidence(outcome.target.authority.isolation_receipt)
    cleanup = provider.evidence(outcome.target.authority.cleanup_receipt)
    assert observation.observation == outcome.target.authority.observation
    assert isolation.network_internal is True
    assert isolation.published_port_count == 0
    assert cleanup.resources_absent is True


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_AI_BENCHMARK") != "1",
    reason="real Docker AI/RAG/MCP benchmark conformance is opt-in",
)
def test_real_docker_ai_rag_mcp_provider_conformance(tmp_path: Path) -> None:
    import subprocess

    def image_id(reference: str) -> str:
        result = subprocess.run(
            ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        )
        return result.stdout.strip()

    profile = DockerAIRAGMCPTargetProfile(
        targetImage="pajin-ai-rag-mcp-target:dev",
        targetImageId=image_id("pajin-ai-rag-mcp-target:dev"),
        workerImage="pajin-ai-rag-mcp-benchmark-worker:dev",
        workerImageId=image_id("pajin-ai-rag-mcp-benchmark-worker:dev"),
    )
    ground_truth = registered_ai_rag_mcp_docker_ground_truth(
        profile,
        benchmark_id="benchmark:docker-ai-rag-mcp-v1",
    )
    manifest = _ai_manifest(profile).model_copy(
        update={"ground_truth_digest": ground_truth.digest()}
    )
    provider = DockerAIRAGMCPTargetFactoryAdapter(
        state_path=tmp_path / "docker-ai-provider.sqlite3",
        profile=profile,
        manifest=manifest,
        trust_anchor=_measurement_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
    )
    adapter = CatalogBoundDockerAIRAGMCPTargetFactoryAdapter(
        provider=provider,
        manifest=manifest,
        catalog=registered_ai_rag_mcp_docker_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )

    outcome = asyncio.run(
        RecoverableBenchmarkTargetFactoryRunner(
            output_root=tmp_path / "runs",
            journal_path=tmp_path / "target-journal.sqlite3",
            adapter=adapter,
            trust_anchor=_measurement_anchor(),
        ).run(
            manifest,
            arm_id=manifest.arms[0].arm_id,
            seed=7,
            repetition=1,
        )
    )

    isolation = provider.evidence(outcome.authority.isolation_receipt)
    execution = provider.evidence(outcome.authority.execution_receipt)
    cleanup = provider.evidence(outcome.authority.cleanup_receipt)
    assert isolation.network_internal is True
    assert isolation.published_port_count == 0
    assert execution.probe_vulnerable is True
    assert outcome.authority.observation.completed_ground_truth_chain_count == 1
    assert cleanup.resources_absent is True


def _operation(
    attempt: BenchmarkTargetAttempt,
    stage: str,
    *,
    fence: int | None = None,
) -> BenchmarkTargetOperation:
    return BenchmarkTargetOperation(
        attemptId=attempt.attempt_id,
        attemptDigest=attempt.attempt_digest,
        adapterDigest=attempt.adapter_digest,
        coordinateDigest=attempt.coordinate_digest,
        fence=attempt.fence if fence is None else fence,
        stage=stage,
        ordinal=1,
    )


def _registry_distribution():
    measurement_anchor = _measurement_anchor()
    now = datetime.now(UTC)
    registry = BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:docker-bug-bounty",
        registryRevision=1,
        measurementAuthorityId=measurement_anchor.authority_id,
        measurementAuthorityVersion=measurement_anchor.authority_version,
        issuedAt=now - timedelta(hours=1),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=measurement_anchor,
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=now - timedelta(hours=2),
            )
        ],
    )
    distribution_anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain="pajin.local-benchmark",
        issuer="pajin.local-development",
        keys=[
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="measurement-registry-distribution-key:docker-1",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_KEY
                    )
                ),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=now - timedelta(days=1),
            )
        ],
    )
    signer = BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=distribution_anchor.active_key.key_id,
        private_key=DISTRIBUTION_KEY,
        trust_anchor=distribution_anchor,
    )
    bundle = signer.sign(
        registry=registry,
        issued_at=now - timedelta(minutes=1),
        not_before=now - timedelta(minutes=1),
        expires_at=now + timedelta(days=1),
    )
    return registry, distribution_anchor, bundle
