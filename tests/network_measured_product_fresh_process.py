"""Fresh-spawn read-only conformance support for NET-002D."""

from __future__ import annotations

import multiprocessing
import os
import pickle
import re
import stat
import tempfile
import traceback
from collections.abc import Sequence
from contextlib import ExitStack
from dataclasses import dataclass, replace
from hashlib import sha256
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from fastapi.testclient import TestClient
from test_network_fixture_runtime import _runtime

from pajin.control_plane.api import create_app
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.workflow import network_measured_product_flow
from pajin.workflow.network_fixture_runtime import (
    NETWORK_BANNER_EMITTER_IMAGE,
    NETWORK_EGRESS_PROXY_IMAGE,
    NETWORK_WORKER_IMAGE,
    NetworkDockerCommandResult,
    NetworkFixtureDockerProvider,
    NetworkFixtureTargetLifecycleRunner,
    SubprocessNetworkDockerCommandRunner,
)
from pajin.workflow.network_measured_case_authority import NetworkMeasuredCaseMapping
from pajin.workflow.network_measured_product_flow import (
    NetworkMeasuredProductOutcome,
    NetworkMeasuredProductProjector,
    NetworkMeasuredProductSourceReopenContext,
    _strict_json_bytes,
)
from pajin.workflow.network_measured_product_reader import (
    NetworkMeasuredProductReader,
    NetworkMeasuredProductReadRegistration,
    NetworkMeasuredProductReadRegistry,
)
from pajin.workflow.network_replay_evaluation import NetworkReplayEvaluationRunner
from pajin.workflow.network_source_measurement import (
    NetworkSourceExecutionContext,
    NetworkSourceMeasurementOutcome,
    NetworkSourceMeasurementRunner,
)
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)

_PRODUCT_PATH = "/v1/products/network-measured-service-identification"
_DEPLOYMENT_ID = "deployment.network-measured-product-conformance"
_GETUID = getattr(os, "getuid", None)
_LOCK_ROOT_NAME = f".pajin-run-locks-{_GETUID()}" if _GETUID is not None else ".pajin-run-locks"
_LOCK_FILE = re.compile(r"^[0-9a-f]{64}\.lock$")
_IMAGE_REFERENCES = frozenset(
    {
        NETWORK_BANNER_EMITTER_IMAGE,
        NETWORK_WORKER_IMAGE,
        NETWORK_EGRESS_PROXY_IMAGE,
    }
)
_MANAGED_FILTER = "label=pajin.network-fixture.managed=true"


@dataclass(frozen=True, slots=True)
class FreshNetworkMeasuredProductRecipe:
    """Picklable product coordinates without a provider, resolver, reader, or app."""

    audit_root: Path
    process_root: Path
    outcome: NetworkMeasuredProductOutcome
    measured_cases: NetworkMeasuredCaseMapping
    real_docker: bool
    graph_store_coordinates: tuple[_GraphStoreCoordinate, ...] = ()

    def validate(self) -> None:
        if (
            type(self) is not FreshNetworkMeasuredProductRecipe
            or type(self.outcome) is not NetworkMeasuredProductOutcome
            or type(self.measured_cases) is not NetworkMeasuredCaseMapping
            or type(self.real_docker) is not bool
        ):
            raise TypeError("fresh NET-002D recipe type differs")
        audit_root = self.audit_root.resolve(strict=True)
        if not audit_root.is_dir():
            raise ValueError("fresh NET-002D audit root must be a directory")
        process_root = self.process_root.resolve(strict=False)
        _require_beneath(process_root, audit_root, label="process")
        for label, path in (
            ("product", self.outcome.run_path),
            ("evaluation", self.outcome.source.run_path),
            ("source", self.outcome.source.source.run_path),
            ("Replay", self.outcome.source.replay.run_path),
        ):
            _require_beneath(path.resolve(strict=True), audit_root, label=label)
        for coordinate in self.graph_store_coordinates:
            if type(coordinate) is not _GraphStoreCoordinate:
                raise TypeError("fresh NET-002D Graph store coordinate type differs")
            _require_beneath(
                coordinate.path.resolve(strict=True),
                audit_root,
                label="Graph store",
            )


@dataclass(frozen=True, slots=True)
class _GraphStoreCoordinate:
    path: Path
    campaign_id: str


@dataclass(frozen=True, slots=True)
class FreshNetworkMeasuredProductProbeResult:
    process_id: int
    statuses: tuple[int, ...]
    resolver_calls: tuple[str, ...]
    source_reload_calls: int
    product_id: str
    product_digest: str
    canonical_bytes_sha256: str
    docker_argv: tuple[tuple[str, ...], ...]
    filesystem_unchanged: bool


class _ReadOnlyDockerRunner:
    def __init__(self, delegate: Any) -> None:
        if not callable(getattr(delegate, "run", None)):
            raise TypeError("fresh NET-002D Docker delegate differs")
        self._delegate = delegate
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: Sequence[str]) -> NetworkDockerCommandResult:
        command = tuple(arguments)
        if not _read_only_docker_command(command):
            raise AssertionError(f"fresh NET-002D attempted mutable Docker command: {command!r}")
        self.calls.append(command)
        result = self._delegate.run(command)
        if type(result) is not NetworkDockerCommandResult:
            raise TypeError("fresh NET-002D Docker delegate returned another result type")
        return result


@dataclass
class _CountingResolver:
    registry: NetworkMeasuredProductReadRegistry
    calls: list[str]

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> NetworkMeasuredProductReadRegistration:
        self.calls.append(deployment_id)
        return self.registry.resolve_for_product_read(deployment_id=deployment_id)


def run_fresh_network_measured_product_probe(
    recipe: FreshNetworkMeasuredProductRecipe,
    *,
    hash_seed: int,
    timeout_seconds: int,
) -> FreshNetworkMeasuredProductProbeResult:
    """Run one independent spawn interpreter and surface its assertions."""

    if type(hash_seed) is not int or hash_seed < 0:
        raise ValueError("fresh NET-002D hash seed must be a non-negative integer")
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("fresh NET-002D timeout must be a positive integer")
    recipe.validate()
    if recipe.graph_store_coordinates:
        raise ValueError("fresh NET-002D caller cannot supply Graph store coordinates")
    spawn_recipe = _serializable_recipe(recipe)
    pickle.dumps(spawn_recipe, protocol=pickle.HIGHEST_PROTOCOL)

    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    previous_hash_seed = os.environ.get("PYTHONHASHSEED")
    previous_no_bytecode = os.environ.get("PYTHONDONTWRITEBYTECODE")
    os.environ["PYTHONHASHSEED"] = str(hash_seed)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    process = context.Process(target=_child_entry, args=(send, spawn_recipe))
    try:
        process.start()
    finally:
        send.close()
        _restore_environment("PYTHONHASHSEED", previous_hash_seed)
        _restore_environment("PYTHONDONTWRITEBYTECODE", previous_no_bytecode)

    if not receive.poll(timeout_seconds):
        process.terminate()
        process.join(timeout=10)
        receive.close()
        raise TimeoutError("fresh NET-002D product child did not finish")
    try:
        state, payload = receive.recv()
    except EOFError as exc:
        process.join(timeout=10)
        raise RuntimeError(
            f"fresh NET-002D product child exited without a result ({process.exitcode})"
        ) from exc
    finally:
        receive.close()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)
        raise RuntimeError("fresh NET-002D product child did not exit")
    if state != "ok" or process.exitcode != 0:
        raise AssertionError(cast(str, payload))
    if type(payload) is not FreshNetworkMeasuredProductProbeResult:
        raise TypeError("fresh NET-002D product child returned another result type")
    return payload


def _child_entry(send: Any, recipe: FreshNetworkMeasuredProductRecipe) -> None:
    try:
        send.send(("ok", _run_child(recipe)))
    except BaseException:  # pragma: no cover - diagnostics cross the process boundary
        send.send(("error", traceback.format_exc()))
    finally:
        send.close()


def _run_child(
    recipe: FreshNetworkMeasuredProductRecipe,
) -> FreshNetworkMeasuredProductProbeResult:
    recipe.validate()
    process_root = recipe.process_root.resolve(strict=False)
    temp_root = process_root / "TEMP"
    temp_root.mkdir(parents=True, exist_ok=False)
    os.environ["TEMP"] = str(temp_root)
    os.environ["TMP"] = str(temp_root)
    os.environ["TMPDIR"] = str(temp_root)
    tempfile.tempdir = str(temp_root)
    outcome = _restore_product_outcome(
        recipe.outcome,
        coordinates=recipe.graph_store_coordinates,
    )

    if recipe.real_docker:
        delegate: Any = SubprocessNetworkDockerCommandRunner()
    else:
        delegate, _provider, _images = _runtime()
    docker = _ReadOnlyDockerRunner(delegate)
    provider = NetworkFixtureDockerProvider(command_runner=docker)
    reopen = NetworkMeasuredProductSourceReopenContext(
        measured_cases=recipe.measured_cases,
        provider=provider,
    )
    registration = NetworkMeasuredProductReadRegistration.from_outcome(
        deployment_id=_DEPLOYMENT_ID,
        outcome=outcome,
        reopen_context=reopen,
    )
    registry = NetworkMeasuredProductReadRegistry((registration,))
    resolver = _CountingResolver(registry=registry, calls=[])
    reader = NetworkMeasuredProductReader(
        deployment_id=_DEPLOYMENT_ID,
        resolver=resolver,
    )
    source_reload_calls = 0
    source_loader = network_measured_product_flow.load_network_replay_floor_evaluation

    def monitored_source_loader(*args: Any, **kwargs: Any) -> Any:
        nonlocal source_reload_calls
        source_reload_calls += 1
        return source_loader(*args, **kwargs)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("fresh NET-002D invoked an execution or mutation authority")

    app = create_app(
        _settings(process_root / "control-plane.sqlite3"),
        network_measured_product_reader=reader,
    )
    with TestClient(app) as client, ExitStack() as stack:
        stack.enter_context(patch.object(RunStore, "create", forbidden))
        stack.enter_context(patch.object(NetworkMeasuredProductProjector, "project", forbidden))
        stack.enter_context(patch.object(NetworkSourceMeasurementRunner, "run", forbidden))
        stack.enter_context(patch.object(NetworkReplayEvaluationRunner, "run", forbidden))
        stack.enter_context(patch.object(DockerWorkerBackend, "run", forbidden))
        for name in ("reconcile_abandoned", "start", "finish"):
            stack.enter_context(patch.object(NetworkFixtureTargetLifecycleRunner, name, forbidden))
        stack.enter_context(
            patch.object(
                network_measured_product_flow,
                "load_network_replay_floor_evaluation",
                monitored_source_loader,
            )
        )

        before = _tree_snapshot(recipe.audit_root, temp_root=temp_root)
        denied = (
            client.get(_PRODUCT_PATH),
            client.get(_PRODUCT_PATH, headers=_auth("invalid-bearer")),
            client.get(_PRODUCT_PATH, headers=_auth(APPROVER_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(AUDITOR_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(WORKER_TOKEN)),
            client.get(f"{_PRODUCT_PATH}?case=caller-selected", headers=_auth(OPERATOR_TOKEN)),
            client.request("GET", _PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), content=b"{}"),
            client.post(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), json={}),
            client.head(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN)),
        )
        successful = (
            client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN)),
        )
        after = _tree_snapshot(recipe.audit_root, temp_root=temp_root)

    statuses = tuple(response.status_code for response in (*denied, *successful))
    if statuses != (401, 401, 403, 403, 403, 400, 400, 405, 405, 200, 200):
        raise AssertionError(f"fresh NET-002D response statuses differ: {statuses!r}")
    for response in (*denied, *successful):
        _assert_non_cacheable(response)
    canonical = tuple(_strict_json_bytes(response.json()) for response in successful)
    sealed = outcome.run_path.joinpath(outcome.artifact_path).read_bytes()
    if canonical != (sealed, sealed):
        raise AssertionError("fresh NET-002D response bytes differ from the sealed product")
    if resolver.calls != [_DEPLOYMENT_ID, _DEPLOYMENT_ID] or source_reload_calls != 2:
        raise AssertionError("fresh NET-002D zero-argument reload count differs")
    if before != after:
        raise AssertionError("fresh NET-002D product read mutated the audited filesystem")
    if not provider.managed_resources_absent():
        raise AssertionError("fresh NET-002D product read left managed Docker residue")
    product = outcome.product
    return FreshNetworkMeasuredProductProbeResult(
        process_id=os.getpid(),
        statuses=statuses,
        resolver_calls=tuple(resolver.calls),
        source_reload_calls=source_reload_calls,
        product_id=product.product_id,
        product_digest=product.product_digest,
        canonical_bytes_sha256=sha256(sealed).hexdigest(),
        docker_argv=tuple(docker.calls),
        filesystem_unchanged=True,
    )


def _serializable_recipe(
    recipe: FreshNetworkMeasuredProductRecipe,
) -> FreshNetworkMeasuredProductRecipe:
    source, source_coordinates = _strip_graph_stores(recipe.outcome.source.source)
    replay, replay_coordinates = _strip_graph_stores(recipe.outcome.source.replay)
    stripped_evaluation = replace(recipe.outcome.source, source=source, replay=replay)
    stripped_outcome = replace(recipe.outcome, source=stripped_evaluation)
    coordinates = (*source_coordinates, *replay_coordinates)
    if len(coordinates) != 12 or len({item.path for item in coordinates}) != 12:
        raise ValueError("fresh NET-002D requires twelve distinct durable Graph stores")
    return replace(
        recipe,
        outcome=stripped_outcome,
        graph_store_coordinates=coordinates,
    )


def _strip_graph_stores(
    outcome: NetworkSourceMeasurementOutcome,
) -> tuple[NetworkSourceMeasurementOutcome, tuple[_GraphStoreCoordinate, ...]]:
    stripped: list[NetworkSourceExecutionContext] = []
    coordinates: list[_GraphStoreCoordinate] = []
    for execution in outcome.executions:
        store = execution.graph_store
        if type(store) is not SQLiteGraphStore:
            raise TypeError("fresh NET-002D requires exact SQLite Graph stores")
        coordinate = _GraphStoreCoordinate(
            path=store.path.resolve(strict=True),
            campaign_id=store.campaign_id,
        )
        if coordinate.campaign_id != execution.source_inputs.campaign.metadata.name:
            raise ValueError("fresh NET-002D Graph store Campaign differs")
        coordinates.append(coordinate)
        stripped.append(replace(execution, graph_store=cast(SQLiteGraphStore, None)))
    return replace(outcome, executions=tuple(stripped)), tuple(coordinates)


def _restore_product_outcome(
    outcome: NetworkMeasuredProductOutcome,
    *,
    coordinates: tuple[_GraphStoreCoordinate, ...],
) -> NetworkMeasuredProductOutcome:
    source_count = len(outcome.source.source.executions)
    replay_count = len(outcome.source.replay.executions)
    if source_count != 6 or replay_count != 6 or len(coordinates) != source_count + replay_count:
        raise ValueError("fresh NET-002D Graph store coordinate count differs")
    source = _restore_graph_stores(
        outcome.source.source,
        coordinates=coordinates[:source_count],
    )
    replay = _restore_graph_stores(
        outcome.source.replay,
        coordinates=coordinates[source_count:],
    )
    return replace(outcome, source=replace(outcome.source, source=source, replay=replay))


def _restore_graph_stores(
    outcome: NetworkSourceMeasurementOutcome,
    *,
    coordinates: tuple[_GraphStoreCoordinate, ...],
) -> NetworkSourceMeasurementOutcome:
    restored: list[NetworkSourceExecutionContext] = []
    for execution, coordinate in zip(outcome.executions, coordinates, strict=True):
        if (
            execution.graph_store is not None
            or coordinate.campaign_id != execution.source_inputs.campaign.metadata.name
        ):
            raise ValueError("fresh NET-002D stripped Graph store binding differs")
        restored.append(
            replace(
                execution,
                graph_store=SQLiteGraphStore(
                    coordinate.path,
                    campaign_id=coordinate.campaign_id,
                ),
            )
        )
    return replace(outcome, executions=tuple(restored))


def _read_only_docker_command(command: tuple[str, ...]) -> bool:
    if (
        len(command) == 5
        and command[:2] == ("image", "inspect")
        and command[2] in _IMAGE_REFERENCES
        and command[3:] == ("--format", "{{.Id}}")
    ):
        return True
    return command in {
        (
            "container",
            "ls",
            "--all",
            "--quiet",
            "--filter",
            _MANAGED_FILTER,
        ),
        ("network", "ls", "--quiet", "--filter", _MANAGED_FILTER),
    }


def _tree_snapshot(
    root: Path,
    *,
    temp_root: Path,
) -> tuple[tuple[str, str, int, int | None, int | None, str | None], ...]:
    resolved_root = root.resolve(strict=True)
    lock_root = (temp_root / _LOCK_ROOT_NAME).resolve(strict=False)
    if lock_root.exists():
        _validate_lock_tree(lock_root)
    entries: list[tuple[str, str, int, int | None, int | None, str | None]] = []
    for path in sorted(resolved_root.rglob("*"), key=lambda item: item.as_posix()):
        resolved = path.resolve(strict=False)
        if resolved == lock_root or lock_root in resolved.parents:
            continue
        details = path.lstat()
        relative = path.relative_to(resolved_root).as_posix()
        mode = stat.S_IMODE(details.st_mode)
        if stat.S_ISDIR(details.st_mode):
            entries.append((relative, "directory", mode, None, None, None))
        elif stat.S_ISREG(details.st_mode):
            content = path.read_bytes()
            entries.append(
                (
                    relative,
                    "file",
                    mode,
                    len(content),
                    details.st_mtime_ns,
                    sha256(content).hexdigest(),
                )
            )
        else:
            raise AssertionError(f"fresh NET-002D audit found a special file: {relative}")
    return tuple(entries)


def _validate_lock_tree(lock_root: Path) -> None:
    root_details = lock_root.lstat()
    if lock_root.is_symlink() or not stat.S_ISDIR(root_details.st_mode):
        raise AssertionError("fresh NET-002D lock root is not a real directory")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and root_details.st_uid != getuid():
        raise AssertionError("fresh NET-002D lock root owner differs")
    if os.name == "posix" and stat.S_IMODE(root_details.st_mode) != 0o700:
        raise AssertionError("fresh NET-002D lock root mode differs")
    for lock_file in lock_root.iterdir():
        details = lock_file.lstat()
        if (
            _LOCK_FILE.fullmatch(lock_file.name) is None
            or lock_file.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            raise AssertionError("fresh NET-002D lock root contains another entry")
        if getuid is not None and details.st_uid != getuid():
            raise AssertionError("fresh NET-002D lock file owner differs")
        if os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o600:
            raise AssertionError("fresh NET-002D lock file mode differs")


def _assert_non_cacheable(response: Any) -> None:
    if (
        response.headers.get("cache-control") != "no-store, max-age=0"
        or response.headers.get("pragma") != "no-cache"
        or response.headers.get("referrer-policy") != "no-referrer"
        or response.headers.get("x-content-type-options") != "nosniff"
        or "set-cookie" in response.headers
        or "access-control-allow-origin" in response.headers
        or "etag" in response.headers
        or "last-modified" in response.headers
    ):
        raise AssertionError("fresh NET-002D response cache or browser boundary differs")


def _require_beneath(path: Path, root: Path, *, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"fresh NET-002D {label} path is outside its audit root") from exc


def _restore_environment(name: str, previous: str | None) -> None:
    if previous is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = previous


__all__ = [
    "FreshNetworkMeasuredProductProbeResult",
    "FreshNetworkMeasuredProductRecipe",
    "run_fresh_network_measured_product_probe",
]
