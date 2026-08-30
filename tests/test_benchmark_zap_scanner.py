from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import pajin.benchmark.scanner_docker_provider as scanner_docker_provider_module
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
    BenchmarkTargetFactoryError,
    BenchmarkTargetOperationJournal,
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
from pajin.benchmark.scanner_docker_provider import (
    _target_lookup_request_count,
    _write_exclusive_regular_bytes,
)
from pajin.benchmark.scanner_measurement import _parse_observations, _parse_sources
from pajin.runtime.store import AuditEvent, RunStore
from pajin.workflow.web_source_measurement_authority import (
    WebZAPSourceMeasurementAuthority,
    WebZAPSourceMeasurementError,
    WebZAPSourceMeasurementRunner,
    load_web_zap_source_measurement_authority,
)
from tests.test_web_measured_case_authority import _case as measured_case_fixture

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
        self.logs: dict[str, list[bytes]] = {}

    def run(self, arguments: tuple[str, ...], *, stdin: bytes | None = None) -> DockerCommandResult:
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
        if arguments[0] == "logs":
            return _ok(b"".join(self.logs.get(arguments[1], [])))
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
            plan_path = None
        else:
            image = ZAP_IMAGE_ID
            user = "1000:1000"
            command = ["zap.sh", "-cmd", "-autorun", "/zap/zap.yaml"]
            memory = 2 * 1024 * 1024 * 1024
            cpus = 2_000_000_000
            pids = 512
            tmpfs = {
                "/tmp": "rw,noexec,nosuid,nodev,size=128m,uid=1000,gid=1000",
                "/home/zap/.ZAP": "rw,nosuid,nodev,size=512m,uid=1000,gid=1000",
            }
            raw_mounts = tuple(
                arguments[index + 1] for index, value in enumerate(arguments) if value == "--mount"
            )
            assert len(raw_mounts) == 2
            mounts = []
            workspace = None
            plan_path = None
            for raw_mount in raw_mounts:
                source, target_and_options = raw_mount.split("source=", 1)[1].split(",target=", 1)
                destination, *options = target_and_options.split(",")
                mount = {
                    "Type": "bind",
                    "Source": source,
                    "Destination": destination,
                    "RW": "readonly" not in options,
                }
                mounts.append(mount)
                if destination == "/zap/wrk":
                    workspace = Path(source)
                elif destination == "/zap/zap.yaml":
                    plan_path = Path(source)
            assert workspace is not None and plan_path is not None
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
            "PlanPath": None if plan_path is None else str(plan_path),
        }
        self.logs[name] = []
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
            self.logs[name].append(_target_log_record("/health"))
            return _ok()
        workspace_value = details["Workspace"]
        assert isinstance(workspace_value, str)
        workspace = Path(workspace_value)
        (workspace / "p0-e2b.sarif.json").write_bytes(self.sarif)
        target_names = [
            item for item, candidate in self.containers.items() if candidate["Role"] == "target"
        ]
        assert len(target_names) == 1
        self.logs[target_names[0]].extend(
            (
                *(_target_log_record("/v1/users/lookup") for _ in range(8)),
                _target_log_record(
                    "/v1/users/lookup",
                    method="POST",
                    status=501,
                ),
            )
        )
        state["Running"] = False
        state["ExitCode"] = 0
        network = self.networks[str(details["Network"])]["Containers"]
        assert isinstance(network, dict)
        network.pop(_id(name), None)
        return _ok()


class _WorkspaceBoundaryCheckingZAPDocker(_FakeZAPDocker):
    def __init__(
        self,
        *,
        fail_scanner: bool = False,
        drift_workspace_mode: int | None = None,
    ) -> None:
        super().__init__()
        self.fail_scanner = fail_scanner
        self.drift_workspace_mode = drift_workspace_mode
        self.scanner_workspace: Path | None = None
        self.scanner_plan_path: Path | None = None
        self.scanner_mounts: tuple[dict[str, object], ...] = ()

    def _start(self, arguments: tuple[str, ...]) -> DockerCommandResult:
        details = self.containers[arguments[-1]]
        if details["Role"] != "scanner":
            return super()._start(arguments)
        workspace = Path(str(details["Workspace"]))
        plan_path = Path(str(details["PlanPath"]))
        mounts = details["Mounts"]
        assert isinstance(mounts, list)
        mount_by_destination = {
            str(item["Destination"]): item for item in mounts if isinstance(item, dict)
        }
        assert mount_by_destination["/zap/wrk"]["RW"] is True
        assert mount_by_destination["/zap/zap.yaml"]["RW"] is False
        assert plan_path.parent == workspace.parent
        assert workspace not in plan_path.parents
        assert stat.S_IMODE(workspace.parent.stat().st_mode) == 0o700
        assert stat.S_IMODE(workspace.stat().st_mode) == 0o733
        assert stat.S_IMODE(plan_path.stat().st_mode) == 0o644
        assert workspace.parent.stat().st_uid == os.geteuid()
        assert workspace.stat().st_uid == os.geteuid()
        assert plan_path.stat().st_uid == os.geteuid()
        self.scanner_workspace = workspace
        self.scanner_plan_path = plan_path
        self.scanner_mounts = tuple(mount_by_destination.values())
        if self.drift_workspace_mode is not None:
            workspace.chmod(self.drift_workspace_mode)
        if self.fail_scanner:
            return DockerCommandResult(returncode=1, stderr=b"expected scanner failure")
        return super()._start(arguments)


class _RequestUnitHardlinkClaimingZAPDocker(_FakeZAPDocker):
    def __init__(self, victim: Path) -> None:
        super().__init__()
        self.victim = victim

    def _start(self, arguments: tuple[str, ...]) -> DockerCommandResult:
        result = super()._start(arguments)
        details = self.containers[arguments[-1]]
        if details["Role"] == "scanner":
            workspace = Path(str(details["Workspace"]))
            os.link(self.victim, workspace / "p0-e2b.request-units.json")
        return result


def _ok(stdout: bytes = b"") -> DockerCommandResult:
    return DockerCommandResult(returncode=0, stdout=stdout)


def _target_log_record(
    path: str,
    *,
    method: str = "GET",
    status: int = 200,
) -> bytes:
    return (
        json.dumps(
            {
                "event": "pajin.synthetic-http-response",
                "method": method,
                "path": path,
                "status": status,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    ).encode()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode boundary")
@pytest.mark.parametrize(
    ("fail_scanner", "drift_workspace_mode"),
    ((False, None), (True, None), (False, 0o777)),
    ids=("success", "start-failure", "scanner-mode-drift"),
)
def test_zap_scanner_workspace_is_temporarily_open_and_always_resealed(
    tmp_path: Path,
    fail_scanner: bool,
    drift_workspace_mode: int | None,
) -> None:
    docker = _WorkspaceBoundaryCheckingZAPDocker(
        fail_scanner=fail_scanner,
        drift_workspace_mode=drift_workspace_mode,
    )

    if fail_scanner or drift_workspace_mode is not None:
        with pytest.raises(BenchmarkTargetFactoryError):
            _run(tmp_path, docker=docker)
    else:
        _run(tmp_path, docker=docker)

    assert docker.scanner_workspace is not None
    assert docker.scanner_plan_path is not None
    workspace = docker.scanner_workspace
    plan_path = docker.scanner_plan_path
    assert stat.S_IMODE(workspace.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(workspace.stat().st_mode) == 0o700
    assert stat.S_IMODE(plan_path.stat().st_mode) == 0o644
    assert workspace.parent.stat().st_uid == os.geteuid()
    assert workspace.stat().st_uid == os.geteuid()
    assert plan_path.stat().st_uid == os.geteuid()


@pytest.mark.skipif(os.name != "posix", reason="POSIX mode boundary")
@pytest.mark.parametrize(
    "rollback_verification_fails",
    (False, True),
    ids=("rollback-verified", "rollback-verification-fails"),
)
def test_zap_scanner_open_failure_reseals_before_reporting_verification_error(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    rollback_verification_fails: bool,
) -> None:
    original_verify = scanner_docker_provider_module._verify_posix_owned_directory_descriptor
    call_count = 0

    def injected_verify(
        path: Path,
        descriptor: int,
        *,
        expected_mode: int,
        label: str,
    ) -> None:
        nonlocal call_count
        call_count += 1
        if call_count == 2 or (rollback_verification_fails and call_count == 3):
            raise DockerBenchmarkProviderError(f"injected workspace verification {call_count}")
        original_verify(
            path,
            descriptor,
            expected_mode=expected_mode,
            label=label,
        )

    monkeypatch.setattr(
        scanner_docker_provider_module,
        "_verify_posix_owned_directory_descriptor",
        injected_verify,
    )
    with pytest.raises(BenchmarkTargetFactoryError) as caught:
        _run(tmp_path, docker=_FakeZAPDocker())

    artifact_root = tmp_path / "provider-zap-artifacts"
    workspaces = tuple(item for item in artifact_root.iterdir() if item.is_dir())
    assert len(workspaces) == 1
    assert stat.S_IMODE(workspaces[0].stat().st_mode) == 0o700
    messages: list[str] = []
    current: BaseException | None = caught.value
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        messages.append(str(current))
        current = current.__cause__ or current.__context__
    assert any("injected workspace verification 2" in message for message in messages)
    if rollback_verification_fails:
        assert any("open and rollback both failed" in message for message in messages)
        assert any("injected workspace verification 3" in message for message in messages)


def test_target_lookup_request_count_accepts_only_query_free_canonical_jsonl() -> None:
    raw = (
        _target_log_record("/health")
        + _target_log_record("/health", method="POST", status=501)
        + _target_log_record("/v1/users/lookup")
        + _target_log_record("/v1/users/lookup", status=400)
        + _target_log_record("/v1/users/lookup", method="POST", status=501)
    )

    assert _target_lookup_request_count(raw) == 3


@pytest.mark.parametrize(
    "raw",
    (
        b"not-json\n",
        b'{"event":"pajin.synthetic-http-response","method":"GET","path":'
        b'"/v1/users/lookup?id=secret","status":200}\n',
        b'{"method":"GET","event":"pajin.synthetic-http-response","path":'
        b'"/v1/users/lookup","status":200}\n',
        _target_log_record("/v1/users/lookup", method="PUT"),
        _target_log_record("/v1/users/lookup", method="DELETE"),
        _target_log_record("/v1/users/lookup", method="TRACE"),
        b'{"event":"pajin.synthetic-http-response","method":"GET","path":'
        b'"v1/users/lookup","status":200}\n',
        b"\xff\n",
    ),
)
def test_target_lookup_request_count_rejects_untrusted_log_wire(raw: bytes) -> None:
    with pytest.raises(DockerBenchmarkProviderError):
        _target_lookup_request_count(raw)


def test_target_lookup_request_count_rejects_oversized_log() -> None:
    with pytest.raises(DockerBenchmarkProviderError, match="Evidence bound"):
        _target_lookup_request_count(b"x" * (8 * 1024 * 1024 + 1))


@pytest.mark.skipif(os.name != "posix", reason="symlink leaf behavior is a POSIX boundary")
def test_zap_request_unit_artifact_write_rejects_preclaimed_symlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"preserve")
    artifact = tmp_path / "request-units.json"
    artifact.symlink_to(victim)

    with pytest.raises(DockerBenchmarkProviderError, match="created safely"):
        _write_exclusive_regular_bytes(artifact, b"forged", label="test artifact")

    assert victim.read_bytes() == b"preserve"


def test_zap_request_unit_artifact_write_rejects_preclaimed_hardlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"preserve")
    artifact = tmp_path / "request-units.json"
    os.link(victim, artifact)

    with pytest.raises(DockerBenchmarkProviderError, match="created safely"):
        _write_exclusive_regular_bytes(artifact, b"forged", label="test artifact")

    assert victim.read_bytes() == b"preserve"


@pytest.mark.skipif(os.name != "posix", reason="open-file leaf swap is a POSIX boundary")
def test_zap_request_unit_artifact_write_rejects_post_write_leaf_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifact = tmp_path / "request-units.json"
    displaced = tmp_path / "request-units.displaced.json"
    original_fsync = os.fsync
    swapped = False

    def swap_after_flush(descriptor: int) -> None:
        nonlocal swapped
        original_fsync(descriptor)
        if not swapped:
            artifact.rename(displaced)
            artifact.write_bytes(b"attacker replacement")
            swapped = True

    monkeypatch.setattr(os, "fsync", swap_after_flush)

    with pytest.raises(DockerBenchmarkProviderError, match="created safely"):
        _write_exclusive_regular_bytes(artifact, b"receipt-bound", label="test artifact")

    assert displaced.read_bytes() == b"receipt-bound"
    assert artifact.read_bytes() == b"attacker replacement"


def test_zap_provider_rejects_scanner_created_request_unit_hardlink(tmp_path: Path) -> None:
    victim = tmp_path / "victim.txt"
    victim.write_bytes(b"preserve")

    with pytest.raises(BenchmarkTargetFactoryError, match="execution failed") as failure:
        _run(tmp_path, docker=_RequestUnitHardlinkClaimingZAPDocker(victim))

    assert isinstance(failure.value.__cause__, DockerBenchmarkProviderError)
    assert "created safely" in str(failure.value.__cause__)
    assert victim.read_bytes() == b"preserve"


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


def _run(
    tmp_path: Path,
    *,
    docker: _FakeZAPDocker | None = None,
):
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
        command_runner=docker or _FakeZAPDocker(),
    )
    catalog_provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(tmp_path / "registry.sqlite3")
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


def _run_web_source(
    tmp_path: Path,
    *,
    target_profile: DockerBugBountyTargetProfile | None = None,
    scanner_image_id: str = ZAP_IMAGE_ID,
    sarif: bytes | None = None,
    real_docker: bool = False,
):
    profile = target_profile or _profile()
    measurement_anchor = _anchor()
    measured_case, capability_bundle, lifecycle, private_profile, target_adapter = (
        measured_case_fixture(
            target_profile=profile,
            measurement_trust_anchor=measurement_anchor,
            scanner_image_id=scanner_image_id,
        )
    )
    ground_truth = private_profile.private_ground_truth.ground_truth
    fake_docker = None if real_docker else _FakeZAPDocker(sarif=sarif)
    provider_state_path = tmp_path / "web-provider.sqlite3"
    concrete_provider = DockerZAPScannerTargetFactoryAdapter(
        state_path=provider_state_path,
        profile=profile,
        plan=measured_case.scanner_plan,
        registration=measured_case.scanner_registration,
        trust_anchor=measurement_anchor,
        measurement_private_key=MEASUREMENT_KEY,
        command_runner=fake_docker,
    )
    catalog_provider = CatalogBoundDockerZAPScannerTargetFactoryAdapter(
        provider=concrete_provider,
        catalog=registered_traditional_web_api_target_catalog(profile, ground_truth),
        ground_truth=ground_truth,
    )
    activation_store = BenchmarkMeasurementRegistryActivationStore(
        tmp_path / "web-registry.sqlite3"
    )
    distribution_anchor, distribution_bundle = _distribution()
    journal_path = tmp_path / "web-journal.sqlite3"
    outcome = asyncio.run(
        WebZAPSourceMeasurementRunner(
            output_root=tmp_path / "web-source-runs",
            journal_path=journal_path,
            catalog_provider=catalog_provider,
            measurement_trust_anchor=measurement_anchor,
            activation_store=activation_store,
            distribution_bundle=distribution_bundle,
            distribution_trust_anchor=distribution_anchor,
        ).run(
            measured_case,
            capability_bundle=capability_bundle,
            lifecycle=lifecycle,
            release=measured_case.capability_release,
            target_adapter=target_adapter,
            private_ground_truth_profile=private_profile,
            scanner_plan=measured_case.scanner_plan,
            scanner_registration=measured_case.scanner_registration,
        )
    )
    return SimpleNamespace(
        outcome=outcome,
        measured_case=measured_case,
        capability_bundle=capability_bundle,
        lifecycle=lifecycle,
        private_profile=private_profile,
        target_adapter=target_adapter,
        catalog_provider=catalog_provider,
        concrete_provider=concrete_provider,
        activation_store=activation_store,
        distribution_anchor=distribution_anchor,
        distribution_bundle=distribution_bundle,
        measurement_anchor=measurement_anchor,
        journal_path=journal_path,
        provider_state_path=provider_state_path,
        fake_docker=fake_docker,
    )


def _reload_web_source(context) -> WebZAPSourceMeasurementAuthority:
    return load_web_zap_source_measurement_authority(
        context.outcome,
        measured_case=context.measured_case,
        capability_bundle=context.capability_bundle,
        lifecycle=context.lifecycle,
        release=context.measured_case.capability_release,
        target_adapter=context.target_adapter,
        private_ground_truth_profile=context.private_profile,
        scanner_plan=context.measured_case.scanner_plan,
        scanner_registration=context.measured_case.scanner_registration,
        journal_path=context.journal_path,
        catalog_provider=context.catalog_provider,
        measurement_trust_anchor=context.measurement_anchor,
        activation_store=context.activation_store,
        distribution_bundle=context.distribution_bundle,
        distribution_trust_anchor=context.distribution_anchor,
    )


def _reseal_web_source_run(context) -> None:
    (context.outcome.run_path / "run-integrity.jsonl").unlink()
    RunStore(
        run_id=context.outcome.run_id,
        path=context.outcome.run_path,
    ).seal()


def _rewrite_web_source_events(context, events: list[AuditEvent]) -> None:
    previous_hash: str | None = None
    encoded: list[str] = []
    for sequence, event in enumerate(events, start=1):
        pending = event.model_copy(
            update={
                "sequence": sequence,
                "previous_hash": previous_hash,
                "event_hash": "0" * 64,
            }
        )
        finalized = pending.model_copy(update={"event_hash": pending.computed_hash()})
        encoded.append(finalized.model_dump_json())
        previous_hash = finalized.event_hash
    (context.outcome.run_path / "events.jsonl").write_text(
        "\n".join(encoded) + "\n",
        encoding="utf-8",
    )
    _reseal_web_source_run(context)


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


def test_web_002b_executes_and_reloads_exact_public_safe_source_lineage(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path)
    authority = _reload_web_source(context)
    lineage = authority.lineages[0]
    target = context.outcome.source_outcomes[0].target.authority

    assert authority == context.outcome.authority
    reference = authority.reference()
    assert reference.authority_id == authority.authority_id
    assert reference.authority_digest == authority.authority_digest
    foreign_digest = "0" * 64 if reference.authority_digest != "0" * 64 else "1" * 64
    with pytest.raises(ValidationError, match="reference differs"):
        reference.__class__.model_validate(
            {
                "authorityId": f"web-zap-source-measurement:{foreign_digest}",
                "authorityDigest": reference.authority_digest,
            }
        )
    assert authority.measurement_state == "registry-governed-zap-source-measurement-complete"
    assert lineage.target_run_id == context.outcome.source_outcomes[0].target.run_id
    assert lineage.execution_operation_id == target.execution_receipt.operation_id
    assert lineage.request_unit_evidence.request_units == 9
    assert authority.source_request_units == 9
    execution_evidence = context.concrete_provider.evidence(target.execution_receipt)
    assert (
        execution_evidence.scanner_request_unit_evidence_digest
        == lineage.request_unit_evidence.evidence_digest
    )
    assert (
        execution_evidence.scanner_target_log_before_sha256
        == lineage.request_unit_evidence.target_log_before_sha256
    )
    assert (
        execution_evidence.scanner_target_log_after_sha256
        == lineage.request_unit_evidence.target_log_after_sha256
    )
    assert (
        execution_evidence.scanner_target_log_delta_sha256
        == lineage.request_unit_evidence.target_log_delta_sha256
    )
    assert execution_evidence.scanner_request_units == lineage.request_unit_evidence.request_units
    request_unit_delta = context.concrete_provider._request_unit_delta_path(
        execution_evidence.operation_digest
    )
    assert b'"method":"POST"' in request_unit_delta.read_bytes()
    assert lineage.cleanup_operation_id == target.cleanup_receipt.operation_id
    assert lineage.cleanup_receipt_digest == target.cleanup_receipt.receipt_digest
    assert lineage.target_image_id == TARGET_IMAGE_ID
    assert lineage.worker_image_id == WORKER_IMAGE_ID
    assert lineage.scanner_image_id == ZAP_IMAGE_ID
    assert all(
        getattr(authority, name) is True
        for name in (
            "source_measurement_observed",
            "raw_sarif_custody_verified",
            "strict_normalization_verified",
            "signed_registry_authority_verified",
            "target_run_completed",
            "target_cleanup_verified",
            "internal_network_verified",
            "no_published_ports_verified",
            "source_and_controlled_validation_identity_separated",
        )
    )
    assert all(
        getattr(authority, name) is False
        for name in (
            "controlled_validation_route_used",
            "controlled_validation_executed",
            "private_ground_truth_disclosed",
            "domain_metric_floor_evaluated",
            "benchmark_validation_floor_satisfied",
            "graph_admission_authorized",
            "graph_write_authorized",
            "finding_projection_authorized",
            "finding_authorized",
            "candidate_comparison_eligible",
            "supervisor_activation_eligible",
            "product_activation_authorized",
            "report_delivery_authorized",
            "additional_execution_authorized",
        )
    )
    serialized = authority.model_dump_json(by_alias=True)
    assert str(tmp_path) not in serialized
    assert "p0-e2b.sarif.json" not in serialized
    assert "groundTruth" not in serialized
    assert context.fake_docker.containers == {}
    assert context.fake_docker.networks == {}


@pytest.mark.parametrize(
    ("field", "value"),
    (("targetCleanupVerified", 1), ("controlledValidationExecuted", 0)),
)
def test_web_002b_authority_rejects_boolean_number_coercion(
    tmp_path: Path,
    field: str,
    value: int,
) -> None:
    authority = _run_web_source(tmp_path).outcome.authority
    raw = authority.model_dump(mode="python", by_alias=True)
    raw[field] = value

    with pytest.raises(ValidationError, match="boolean"):
        WebZAPSourceMeasurementAuthority.model_validate(raw)


def test_web_002b_reload_rejects_completed_journal_fence_drift(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path)
    with sqlite3.connect(context.journal_path) as connection:
        connection.execute(
            "UPDATE attempts SET active_recovery_fence = fence + 1 WHERE state = 'completed'"
        )

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_provider_raw_sarif_drift(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path)
    target = context.outcome.source_outcomes[0].target.authority
    evidence = context.concrete_provider.evidence(target.execution_receipt)
    context.concrete_provider._artifact_path(evidence.operation_digest).write_bytes(
        _sarif(rule_id="40018")
    )

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_coherent_four_file_request_unit_substitution(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path)
    target = context.outcome.source_outcomes[0].target.authority
    receipt = target.execution_receipt
    evidence = context.concrete_provider.evidence(receipt)
    observed = context.concrete_provider.request_unit_evidence(receipt)
    before_path = context.concrete_provider._request_unit_before_path(evidence.operation_digest)
    after_path = context.concrete_provider._request_unit_after_path(evidence.operation_digest)
    delta_path = context.concrete_provider._request_unit_delta_path(evidence.operation_digest)
    forged_before = before_path.read_bytes() + _target_log_record("/health")
    delta_records = delta_path.read_bytes().splitlines(keepends=True)
    assert len(delta_records) == observed.request_units
    forged_delta = b"".join(delta_records[:-1])
    forged_after = forged_before + forged_delta
    forged_request_units = _target_lookup_request_count(forged_delta)
    raw = observed.model_dump(mode="python", by_alias=True)
    raw["evidenceDigest"] = ""
    raw["targetLogBeforeSha256"] = sha256(forged_before).hexdigest()
    raw["targetLogAfterSha256"] = sha256(forged_after).hexdigest()
    raw["targetLogDeltaSha256"] = sha256(forged_delta).hexdigest()
    raw["targetLogDeltaSizeBytes"] = len(forged_delta)
    raw["targetRequestsBefore"] = _target_lookup_request_count(forged_before)
    raw["targetRequestsAfter"] = _target_lookup_request_count(forged_after)
    raw["requestUnits"] = forged_request_units
    substituted = observed.__class__.model_validate(raw)
    before_path.write_bytes(forged_before)
    after_path.write_bytes(forged_after)
    delta_path.write_bytes(forged_delta)
    context.concrete_provider._request_unit_evidence_path(evidence.operation_digest).write_bytes(
        (substituted.model_dump_json(by_alias=True) + "\n").encode("utf-8")
    )

    with pytest.raises(DockerBenchmarkProviderError, match="differs from execution Evidence"):
        context.concrete_provider.request_unit_evidence(receipt)
    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_request_unit_log_delta_drift(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path)
    target = context.outcome.source_outcomes[0].target.authority
    receipt = target.execution_receipt
    evidence = context.concrete_provider.evidence(receipt)
    delta_path = context.concrete_provider._request_unit_delta_path(evidence.operation_digest)
    delta = delta_path.read_bytes()
    assert b"/v1/users/lookup" in delta
    delta_path.write_bytes(delta.replace(b"/v1/users/lookup", b"/v1/users/lookuX", 1))

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_foreign_distribution_bundle(tmp_path: Path) -> None:
    context = _run_web_source(tmp_path)
    statement = context.distribution_bundle.statement
    signer = BenchmarkMeasurementRegistryDistributionSigner.from_private_key_bytes(
        active_key_id=context.distribution_anchor.active_key.key_id,
        private_key=DISTRIBUTION_KEY,
        trust_anchor=context.distribution_anchor,
    )
    context.distribution_bundle = signer.sign(
        registry=statement.registry,
        issued_at=statement.issued_at + timedelta(seconds=1),
        not_before=statement.not_before + timedelta(seconds=1),
        expires_at=statement.expires_at,
    )

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_noncanonical_outer_authority_wire(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path)
    authority_path = context.outcome.run_path / context.outcome.authority_path
    raw = json.loads(authority_path.read_text(encoding="utf-8"))
    authority_path.write_text(
        json.dumps(raw, allow_nan=False, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _reseal_web_source_run(context)

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


@pytest.mark.parametrize("event_index", (0, 1, 2))
def test_web_002b_reload_rejects_rehashed_outer_audit_payload_drift(
    tmp_path: Path,
    event_index: int,
) -> None:
    context = _run_web_source(tmp_path)
    events = [
        AuditEvent.model_validate_json(line)
        for line in (context.outcome.run_path / "events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    events[event_index] = events[event_index].model_copy(
        update={"payload": {**events[event_index].payload, "foreign": True}}
    )
    _rewrite_web_source_events(context, events)

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


def test_web_002b_reload_rejects_noncanonical_completed_journal_record(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path)
    with sqlite3.connect(context.journal_path) as connection:
        row = connection.execute(
            "SELECT sequence, record_json FROM records ORDER BY sequence LIMIT 1"
        ).fetchone()
        assert row is not None and '"ordinal":1' in str(row[1])
        connection.execute(
            "UPDATE records SET record_json = ? WHERE sequence = ?",
            (str(row[1]).replace('"ordinal":1', '"ordinal":"1"'), int(row[0])),
        )

    with pytest.raises(WebZAPSourceMeasurementError):
        _reload_web_source(context)


@pytest.mark.parametrize(
    ("stage", "column", "old", "new"),
    (
        ("cleanup", "evidence_json", '"resourcesAbsent":true', '"resourcesAbsent":1'),
        (
            "execution",
            "result_json",
            '"cleanupSucceeded":false',
            '"cleanupSucceeded":0',
        ),
    ),
)
def test_zap_provider_rejects_noncanonical_cached_wire(
    tmp_path: Path,
    stage: str,
    column: str,
    old: str,
    new: str,
) -> None:
    context = _run_web_source(tmp_path)
    target = context.outcome.source_outcomes[0].target.authority
    receipt = target.cleanup_receipt if stage == "cleanup" else target.execution_receipt
    with sqlite3.connect(context.provider_state_path) as connection:
        row = connection.execute(
            f"SELECT {column} FROM operations WHERE operation_id = ?",
            (receipt.operation_id,),
        ).fetchone()
        assert row is not None and old in str(row[0])
        connection.execute(
            f"UPDATE operations SET {column} = ? WHERE operation_id = ?",
            (str(row[0]).replace(old, new), receipt.operation_id),
        )

    with pytest.raises(DockerBenchmarkProviderError, match="wire is not canonical"):
        context.concrete_provider.evidence(receipt)


def test_zap_provider_cached_replay_rejects_noncanonical_evidence_wire(
    tmp_path: Path,
) -> None:
    context = _run_web_source(tmp_path)
    target = context.outcome.source_outcomes[0].target.authority
    journal = BenchmarkTargetOperationJournal.open_existing(context.journal_path)
    _, coordinate, _, records = journal.completed_attempt_for_operation(
        target.cleanup_receipt.operation_id
    )
    cleanup_operation = next(
        record.operation for record in records if record.operation.stage == "cleanup"
    )
    with sqlite3.connect(context.provider_state_path) as connection:
        row = connection.execute(
            "SELECT evidence_json FROM operations WHERE operation_id = ?",
            (cleanup_operation.operation_id,),
        ).fetchone()
        assert row is not None and '"resourcesAbsent":true' in str(row[0])
        connection.execute(
            "UPDATE operations SET evidence_json = ? WHERE operation_id = ?",
            (
                str(row[0]).replace('"resourcesAbsent":true', '"resourcesAbsent":1'),
                cleanup_operation.operation_id,
            ),
        )

    with pytest.raises(DockerBenchmarkProviderError, match="wire is not canonical"):
        asyncio.run(
            context.concrete_provider.cleanup(
                coordinate,
                target.isolation_receipt,
                cleanup_operation,
            )
        )


def test_scanner_source_bundles_reject_semantically_coercible_wire(
    tmp_path: Path,
) -> None:
    authority = _run_web_source(tmp_path).outcome.scanner_measurement_outcome.authority
    source = authority.sources[0]
    source_raw = (
        json.dumps(
            [source.model_dump(mode="json", by_alias=True)],
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    size = source.normalization.raw_sarif_size_bytes
    coerced_source = source_raw.replace(
        f'"rawSarifSizeBytes": {size}'.encode(),
        f'"rawSarifSizeBytes": "{size}"'.encode(),
    )
    assert coerced_source != source_raw
    with pytest.raises(ValueError, match="wire is not canonical"):
        _parse_sources(coerced_source)

    observation_raw = (
        json.dumps(
            [source.observation.model_dump(mode="json", by_alias=True)],
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode()
    coerced_observation = observation_raw.replace(
        b'"cleanupSucceeded": true',
        b'"cleanupSucceeded": 1',
    )
    assert coerced_observation != observation_raw
    with pytest.raises(ValueError, match="wire is not canonical"):
        _parse_observations(coerced_observation)


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
    normalization = parse_zap_sarif(_sarif(rule_id="40018"), registration=registration)
    assert normalization.known_surface_detected is True
    assert normalization.known_finding_matched is True

    foreign = json.loads(_sarif(rule_id="40018"))
    foreign["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "http://foreign:8080/v1/users/lookup?id=1"
    normalization = parse_zap_sarif(json.dumps(foreign).encode(), registration=registration)
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
    activation_store = BenchmarkMeasurementRegistryActivationStore(tmp_path / "registry.sqlite3")
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
    outcome = ScannerBaselineMeasurementRunner(output_root=tmp_path / "measurement").run(
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


@pytest.mark.skipif(
    os.environ.get("PAJIN_TEST_DOCKER_ZAP") != "1",
    reason="real Docker WEB-002B source conformance is opt-in",
)
def test_real_docker_web_zap_source_measurement_conformance(tmp_path: Path) -> None:
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
    context = _run_web_source(
        tmp_path,
        target_profile=profile,
        scanner_image_id=image_id("ghcr.io/zaproxy/zaproxy:stable"),
        real_docker=True,
    )
    authority = _reload_web_source(context)
    lineage = authority.lineages[0]

    assert lineage.target_image_id == profile.target_image_id
    assert lineage.worker_image_id == profile.worker_image_id
    assert lineage.scanner_image_id == context.measured_case.scanner_registration.scanner_image_id
    assert lineage.cleanup_resources_absent is True
    assert authority.internal_network_verified is True
    assert authority.no_published_ports_verified is True
    assert authority.controlled_validation_executed is False
