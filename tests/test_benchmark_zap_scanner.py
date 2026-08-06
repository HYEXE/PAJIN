from __future__ import annotations

import asyncio
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.benchmark import (
    BenchmarkArm,
    BenchmarkArmKind,
    BenchmarkManifest,
    BenchmarkMeasurementKeyState,
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionKey,
    BenchmarkMeasurementRegistryDistributionSigner,
    BenchmarkMeasurementRegistryDistributionTrustAnchor,
    BenchmarkMeasurementRegistryKey,
    BenchmarkMeasurementTrustAnchor,
    BenchmarkMeasurementTrustRegistry,
    BenchmarkMetric,
    BenchmarkMetricStatus,
    BenchmarkRegistryGovernedHarnessRunner,
    BenchmarkRunProtocol,
    CatalogBoundDockerZAPScannerTargetFactoryAdapter,
    DockerBenchmarkProviderError,
    DockerBugBountyTargetProfile,
    DockerCommandResult,
    DockerZAPScannerTargetFactoryAdapter,
    RecoverableBenchmarkTargetFactoryRunner,
    RegisteredBenchmarkTargetFactoryAdapter,
    ScannerBaselineMeasurementError,
    ScannerBaselineMeasurementRunner,
    benchmark_measurement_public_key_base64url,
    benchmark_measurement_registry_distribution_public_key_base64url,
    load_scanner_baseline_measurement_authority,
    parse_zap_sarif,
    plan_generic_scanner_baseline,
    registered_generic_scanner_adapter_contract,
    registered_traditional_web_api_ground_truth,
    registered_traditional_web_api_target_catalog,
    registered_zap_scanner,
)

NOW = datetime(2026, 8, 2, 6, 0, tzinfo=UTC)
MEASUREMENT_KEY = bytes(range(32))
DISTRIBUTION_KEY = bytes(range(32, 64))
TARGET_IMAGE_ID = "sha256:" + "a" * 64
WORKER_IMAGE_ID = "sha256:" + "b" * 64
ZAP_IMAGE_ID = "sha256:" + "c" * 64


class _FakeZAPDocker:
    def __init__(self, *, sarif: bytes | None = None) -> None:
        self.sarif = sarif or _sarif(rule_id="10036")
        self.image_ids = {
            "pajin-bug-bounty-target:dev": TARGET_IMAGE_ID,
            "pajin-benchmark-worker:dev": WORKER_IMAGE_ID,
            "ghcr.io/zaproxy/zaproxy:stable": ZAP_IMAGE_ID,
        }
        self.containers: dict[str, dict[str, object]] = {}
        self.networks: dict[str, dict[str, object]] = {}

    def run(
        self, arguments: tuple[str, ...], *, stdin: bytes | None = None
    ) -> DockerCommandResult:
        del stdin
        if arguments[:2] == ("version", "--format"):
            return _ok(b"29.5.3\n")
        if arguments[:2] == ("image", "inspect"):
            image_id = self.image_ids.get(arguments[2])
            return _ok(f"{image_id}\n".encode()) if image_id else DockerCommandResult(1)
        if arguments[:2] == ("container", "ls"):
            name = arguments[-1].removeprefix("name=^/").removesuffix("$")
            found = self.containers.get(name)
            return _ok((f"{found['Id']}\n" if found else "").encode())
        if arguments[:2] == ("network", "ls"):
            name = arguments[-1].removeprefix("name=^").removesuffix("$")
            found = self.networks.get(name)
            return _ok((f"{found['Id']}\n" if found else "").encode())
        if arguments[:2] == ("network", "create"):
            name = arguments[-1]
            self.networks[name] = {
                "Id": _id(name),
                "Internal": True,
                "Driver": "bridge",
                "Scope": "local",
                "Labels": _labels(arguments),
                "Containers": {},
            }
            return _ok(f"{_id(name)}\n".encode())
        if arguments[0] == "create":
            return self._create(arguments)
        if arguments[0] == "start":
            return self._start(arguments)
        if arguments[:2] == ("container", "inspect"):
            return _ok(json.dumps([self.containers[arguments[2]]]).encode())
        if arguments[:2] == ("network", "inspect"):
            return _ok(json.dumps([self.networks[arguments[2]]]).encode())
        if arguments[:2] == ("rm", "--force"):
            name = arguments[2]
            details = self.containers.pop(name)
            network = self.networks[str(details["Network"])]["Containers"]
            assert isinstance(network, dict)
            network.pop(_id(name), None)
            return _ok(f"{name}\n".encode())
        if arguments[:2] == ("network", "rm"):
            self.networks.pop(arguments[2])
            return _ok()
        raise AssertionError(f"unexpected Docker command: {arguments!r}")

    def _create(self, arguments: tuple[str, ...]) -> DockerCommandResult:
        name = arguments[arguments.index("--name") + 1]
        network_name = arguments[arguments.index("--network") + 1]
        labels = _labels(arguments)
        role = labels["pajin.benchmark.role"]
        if role == "target":
            image = TARGET_IMAGE_ID
            user = "65532:65532"
            command = None
            memory = 128 * 1024 * 1024
            cpus = 500_000_000
            pids = 64
            tmpfs = {"/tmp": "rw,noexec,nosuid,nodev,size=16m"}
            mounts: list[dict[str, object]] = []
            state: dict[str, object] = {
                "Running": False,
                "ExitCode": 0,
                "Health": {"Status": "starting"},
            }
            workspace = None
        else:
            image = ZAP_IMAGE_ID
            user = "1000:1000"
            command = ["zap.sh", "-cmd", "-autorun", "/zap/wrk/zap.yaml"]
            memory = 2 * 1024 * 1024 * 1024
            cpus = 2_000_000_000
            pids = 512
            tmpfs = {
                "/tmp": "rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000",
                "/home/zap/.ZAP": "rw,nosuid,nodev,size=512m,uid=1000,gid=1000",
            }
            raw_mount = arguments[arguments.index("--mount") + 1]
            source = raw_mount.split("source=", 1)[1].split(",target=", 1)[0]
            workspace = Path(source)
            mounts = [
                {
                    "Type": "bind",
                    "Source": str(workspace),
                    "Destination": "/zap/wrk",
                    "RW": True,
                }
            ]
            state = {"Running": False, "ExitCode": 0}
        self.containers[name] = {
            "Id": _id(name),
            "Image": image,
            "Config": {"Labels": labels, "User": user, "Cmd": command},
            "HostConfig": {
                "ReadonlyRootfs": True,
                "PortBindings": None,
                "CapDrop": ["ALL"],
                "SecurityOpt": ["no-new-privileges:true"],
                "NetworkMode": network_name,
                "Memory": memory,
                "NanoCpus": cpus,
                "PidsLimit": pids,
                "Tmpfs": tmpfs,
            },
            "Mounts": mounts,
            "State": state,
            "Network": network_name,
            "Role": role,
            "Workspace": None if workspace is None else str(workspace),
        }
        network = self.networks[network_name]["Containers"]
        assert isinstance(network, dict)
        network[_id(name)] = {"Name": name}
        return _ok(f"{_id(name)}\n".encode())

    def _start(self, arguments: tuple[str, ...]) -> DockerCommandResult:
        name = arguments[-1]
        details = self.containers[name]
        state = details["State"]
        assert isinstance(state, dict)
        if details["Role"] == "target":
            state["Running"] = True
            state["Health"] = {"Status": "healthy"}
            return _ok()
        workspace_value = details["Workspace"]
        assert isinstance(workspace_value, str)
        workspace = Path(workspace_value)
        (workspace / "p0-e2b.sarif.json").write_bytes(self.sarif)
        state["Running"] = False
        state["ExitCode"] = 0
        network = self.networks[str(details["Network"])]["Containers"]
        assert isinstance(network, dict)
        network.pop(_id(name), None)
        return _ok()


def _ok(stdout: bytes = b"") -> DockerCommandResult:
    return DockerCommandResult(returncode=0, stdout=stdout)


def _id(value: str) -> str:
    return sha256(value.encode()).hexdigest()


def _labels(arguments: tuple[str, ...]) -> dict[str, str]:
    labels: dict[str, str] = {}
    for index, value in enumerate(arguments):
        if value == "--label":
            key, item = arguments[index + 1].split("=", 1)
            labels[key] = item
    return labels


def _sarif(*, rule_id: str, extra_root: bool = False) -> bytes:
    value: dict[str, object] = {
        "runs": [
            {
                "results": [
                    {
                        "level": "note" if rule_id == "10036" else "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "http://target:8080/v1/users/lookup?id=1"
                                    },
                                    "region": {"startLine": 1},
                                },
                                "properties": {"attack": "fixed-test"},
                            }
                        ],
                        "message": {"text": "bounded ZAP finding"},
                        "ruleId": rule_id,
                        "webRequest": {},
                        "webResponse": {},
                    }
                ],
                "taxonomies": [],
                "tool": {
                    "driver": {
                        "guid": "840570e4-2388-38c0-8afe-ed426f2f5199",
                        "informationUri": "https://www.zaproxy.org/",
                        "name": "ZAP",
                        "rules": [{"id": rule_id}],
                        "semanticVersion": "2.17.0",
                        "supportedTaxonomies": [],
                        "version": "2.17.0",
                    }
                },
            }
        ],
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
    }
    if extra_root:
        value["invented"] = True
    return json.dumps(value, separators=(",", ":")).encode()


def _profile() -> DockerBugBountyTargetProfile:
    return DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=TARGET_IMAGE_ID,
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=WORKER_IMAGE_ID,
    )


def _anchor() -> BenchmarkMeasurementTrustAnchor:
    return BenchmarkMeasurementTrustAnchor(
        authorityId="measurement-authority:zap-baseline",
        authorityVersion="1.0.0",
        keyId="measurement-key:zap-baseline",
        publicKeyBase64url=benchmark_measurement_public_key_base64url(MEASUREMENT_KEY),
    )


def _plan(profile: DockerBugBountyTargetProfile):
    contract = registered_generic_scanner_adapter_contract()
    ground_truth = registered_traditional_web_api_ground_truth(
        profile, benchmark_id="benchmark:zap-scanner-baseline-v1"
    )
    definition = RegisteredBenchmarkTargetFactoryAdapter(
        adapterId="target-adapter:docker-bug-bounty",
        adapterVersion="1.0.0",
        targetFactoryId="target-factory:docker-bug-bounty",
        targetFactoryVersion=profile.profile_version,
        targetFactoryDigest=profile.target_factory_digest,
        measurementAuthorityId=_anchor().authority_id,
        measurementAuthorityVersion=_anchor().authority_version,
        measurementAuthorityDigest=_anchor().anchor_digest,
    )
    manifest = BenchmarkManifest(
        benchmarkId=ground_truth.benchmark_id,
        targetFactoryId=definition.target_factory_id,
        targetFactoryVersion=definition.target_factory_version,
        targetFactoryDigest=definition.target_factory_digest,
        targetProfileId=profile.profile_id,
        targetProfileVersion=profile.profile_version,
        mutationProfileId=None,
        campaignDigest="d" * 64,
        groundTruthDigest=ground_truth.digest(),
        protocol=BenchmarkRunProtocol(
            protocolId="pajin:zap-scanner-baseline-protocol",
            protocolVersion="1.0.0",
            seeds=[7],
            repetitionsPerSeed=1,
            timeoutSeconds=180,
            maxCostUsd=1,
            maxToolCalls=10,
            maxModelCalls=0,
        ),
        arms=[
            BenchmarkArm(
                armId="arm:generic-scanner-baseline",
                kind=BenchmarkArmKind.DETERMINISTIC_BASELINE,
                implementationId=contract.benchmark_implementation_id,
                implementationVersion=contract.benchmark_implementation_version,
                configurationDigest=contract.benchmark_configuration_digest,
                adaptiveSupervisor=False,
            )
        ],
    )
    return (
        plan_generic_scanner_baseline(
            manifest,
            adapter=definition,
            profile=profile,
            catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
            ground_truth=ground_truth,
        ),
        ground_truth,
    )


def _distribution():
    registry = BenchmarkMeasurementTrustRegistry(
        registryId="measurement-registry:zap-baseline",
        registryRevision=1,
        measurementAuthorityId=_anchor().authority_id,
        measurementAuthorityVersion=_anchor().authority_version,
        issuedAt=NOW - timedelta(minutes=10),
        keys=[
            BenchmarkMeasurementRegistryKey(
                trustAnchor=_anchor(),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )
    distribution_anchor = BenchmarkMeasurementRegistryDistributionTrustAnchor(
        trustDomain="benchmark-registry:zap-baseline",
        issuer="benchmark-registry-issuer:zap-baseline",
        keys=[
            BenchmarkMeasurementRegistryDistributionKey(
                keyId="distribution-key:zap-baseline",
                publicKeyBase64url=(
                    benchmark_measurement_registry_distribution_public_key_base64url(
                        DISTRIBUTION_KEY
                    )
                ),
                state=BenchmarkMeasurementKeyState.ACTIVE,
                notBefore=NOW - timedelta(hours=1),
            )
        ],
    )
    signer = BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=distribution_anchor.active_key.key_id,
        private_key=DISTRIBUTION_KEY,
        trust_anchor=distribution_anchor,
    )
    issued_at = max(datetime.now(UTC) - timedelta(minutes=1), registry.issued_at)
    bundle = signer.sign(
        registry=registry,
        issued_at=issued_at,
        not_before=issued_at,
        expires_at=issued_at + timedelta(days=1),
    )
    return distribution_anchor, bundle


def _run(tmp_path: Path):
    profile = _profile()
    plan, ground_truth = _plan(profile)
    registration = registered_zap_scanner(
        ZAP_IMAGE_ID,
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    )
    provider = DockerZAPScannerTargetFactoryAdapter(
        state_path=tmp_path / "provider.sqlite3",
        profile=profile,
        plan=plan,
        registration=registration,
        trust_anchor=_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=_FakeZAPDocker(),
    )
    catalog_provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry.sqlite3"
    )
    distribution_anchor, bundle = _distribution()
    source = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=RecoverableBenchmarkTargetFactoryRunner(
                output_root=tmp_path / "runs",
                journal_path=tmp_path / "journal.sqlite3",
                adapter=catalog_provider,
                trust_anchor=_anchor(),
            ),
        ).run(plan.manifest, arm_id=plan.manifest.arms[0].arm_id, seed=7, repetition=1)
    )
    return plan, catalog_provider, activation_store, distribution_anchor, source, provider


def test_zap_baseline_seals_realistic_sarif_and_zero_recall_result(tmp_path: Path) -> None:
    plan, provider, store, anchor, source, _ = _run(tmp_path)
    outcome = ScannerBaselineMeasurementRunner(output_root=tmp_path / "measurement").run(
        plan,
        catalog_provider=provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    authority = load_scanner_baseline_measurement_authority(
        plan,
        outcome,
        catalog_provider=provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )

    metrics = {item.metric: item for item in authority.baseline_result.metrics}
    assert metrics[BenchmarkMetric.ATTACK_SURFACE_RECALL].value == 1
    assert metrics[BenchmarkMetric.FINDING_RECALL].value == 0
    assert metrics[BenchmarkMetric.FINDING_PRECISION].value == 0
    assert metrics[BenchmarkMetric.COST_PER_CONFIRMED_FINDING].status is (
        BenchmarkMetricStatus.NOT_APPLICABLE
    )
    assert metrics[BenchmarkMetric.REPLAY_SUCCESS_RATE].status is (
        BenchmarkMetricStatus.NOT_APPLICABLE
    )
    assert authority.sources[0].normalization.known_finding_matched is False
    assert authority.candidate_comparison_eligible is False
    assert authority.supervisor_activation_eligible is False


def test_zap_measurement_reader_rejects_raw_sarif_mutation(tmp_path: Path) -> None:
    plan, catalog_provider, store, anchor, source, provider = _run(tmp_path)
    outcome = ScannerBaselineMeasurementRunner(output_root=tmp_path / "measurement").run(
        plan,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    evidence = provider.evidence(source.target.authority.execution_receipt)
    provider._artifact_path(evidence.operation_digest).write_bytes(_sarif(rule_id="40018"))

    with pytest.raises(ScannerBaselineMeasurementError):
        load_scanner_baseline_measurement_authority(
            plan,
            outcome,
            catalog_provider=catalog_provider,
            source_outcomes=(source,),
            activation_store=store,
            distribution_trust_anchor=anchor,
        )


def test_zap_provider_rejects_multi_link_raw_sarif(tmp_path: Path) -> None:
    _, _, _, _, source, provider = _run(tmp_path)
    evidence = provider.evidence(source.target.authority.execution_receipt)
    artifact = provider._artifact_path(evidence.operation_digest)
    os.link(artifact, artifact.with_suffix(".linked.json"))

    with pytest.raises(DockerBenchmarkProviderError):
        provider.raw_sarif(source.target.authority.execution_receipt)


def test_zap_measurement_authority_rejects_registration_substitution(
    tmp_path: Path,
) -> None:
    plan, catalog_provider, store, anchor, source, _ = _run(tmp_path)
    outcome = ScannerBaselineMeasurementRunner(output_root=tmp_path / "measurement").run(
        plan,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=store,
        distribution_trust_anchor=anchor,
    )
    raw = outcome.authority.model_dump(mode="json", by_alias=True)
    raw["registration"] = registered_zap_scanner(
        "sha256:" + "d" * 64,
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    ).model_dump(mode="json", by_alias=True)

    with pytest.raises(ValueError, match="Measurement Authority differs"):
        outcome.authority.__class__.model_validate(raw)


def test_zap_sarif_parser_rejects_unknown_properties_and_identity() -> None:
    plan, _ = _plan(_profile())
    registration = registered_zap_scanner(
        ZAP_IMAGE_ID,
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    )
    with pytest.raises(ValueError, match="root properties differ"):
        parse_zap_sarif(_sarif(rule_id="10036", extra_root=True), registration=registration)

    raw = json.loads(_sarif(rule_id="10036"))
    raw["runs"][0]["tool"]["driver"]["version"] = "invented"
    with pytest.raises(ValueError, match="tool identity differs"):
        parse_zap_sarif(json.dumps(raw).encode(), registration=registration)

    duplicate_root_key = b'{"version":"2.1.0",' + _sarif(rule_id="10036")[1:]
    with pytest.raises(ValueError, match="not strict JSON"):
        parse_zap_sarif(duplicate_root_key, registration=registration)


def test_zap_sarif_sql_rule_matches_only_exact_known_surface() -> None:
    plan, _ = _plan(_profile())
    registration = registered_zap_scanner(
        ZAP_IMAGE_ID,
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    )
    normalization = parse_zap_sarif(
        _sarif(rule_id="40018"), registration=registration
    )
    assert normalization.known_surface_detected is True
    assert normalization.known_finding_matched is True

    foreign = json.loads(_sarif(rule_id="40018"))
    foreign["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
        "artifactLocation"
    ]["uri"] = "http://foreign:8080/v1/users/lookup?id=1"
    normalization = parse_zap_sarif(
        json.dumps(foreign).encode(), registration=registration
    )
    assert normalization.known_surface_detected is False
    assert normalization.known_finding_matched is False


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_ZAP") != "1",
    reason="real Docker ZAP benchmark conformance is opt-in",
)
def test_real_docker_zap_scanner_measurement_conformance(tmp_path: Path) -> None:
    def image_id(reference: str) -> str:
        return subprocess.run(
            ["docker", "image", "inspect", reference, "--format", "{{.Id}}"],
            capture_output=True,
            check=True,
            text=True,
            timeout=30,
        ).stdout.strip()

    profile = DockerBugBountyTargetProfile(
        targetImage="pajin-bug-bounty-target:dev",
        targetImageId=image_id("pajin-bug-bounty-target:dev"),
        workerImage="pajin-benchmark-worker:dev",
        workerImageId=image_id("pajin-benchmark-worker:dev"),
    )
    plan, ground_truth = _plan(profile)
    registration = registered_zap_scanner(
        image_id("ghcr.io/zaproxy/zaproxy:stable"),
        parser_contract_digest=plan.scanner_contract.parser_contract_digest,
    )
    concrete_provider = DockerZAPScannerTargetFactoryAdapter(
        state_path=tmp_path / "provider.sqlite3",
        profile=profile,
        plan=plan,
        registration=registration,
        trust_anchor=_anchor(),
        measurement_private_key=MEASUREMENT_KEY,
    )
    catalog_provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=concrete_provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "registry.sqlite3"
    )
    distribution_anchor, bundle = _distribution()
    source = asyncio.run(
        BenchmarkRegistryGovernedHarnessRunner(
            output_root=tmp_path / "runs",
            activation_store=activation_store,
            bundle=bundle,
            distribution_trust_anchor=distribution_anchor,
            target_runner=RecoverableBenchmarkTargetFactoryRunner(
                output_root=tmp_path / "runs",
                journal_path=tmp_path / "journal.sqlite3",
                adapter=catalog_provider,
                trust_anchor=_anchor(),
            ),
        ).run(plan.manifest, arm_id=plan.manifest.arms[0].arm_id, seed=7, repetition=1)
    )
    outcome = ScannerBaselineMeasurementRunner(
        output_root=tmp_path / "measurement"
    ).run(
        plan,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )
    authority = load_scanner_baseline_measurement_authority(
        plan,
        outcome,
        catalog_provider=catalog_provider,
        source_outcomes=(source,),
        activation_store=activation_store,
        distribution_trust_anchor=distribution_anchor,
    )

    evidence = concrete_provider.evidence(source.target.authority.execution_receipt)
    cleanup = concrete_provider.evidence(source.target.authority.cleanup_receipt)
    assert authority.sources[0].normalization.known_surface_detected is True
    assert authority.sources[0].normalization.known_finding_matched is False
    assert evidence.raw_sarif_sha256 == authority.sources[0].raw_sarif_sha256
    assert cleanup.resources_absent is True
