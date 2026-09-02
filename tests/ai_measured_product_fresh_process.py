"""Fresh-spawn read-only conformance support for AI-002D."""

from __future__ import annotations

import multiprocessing
import os
import pickle
import re
import stat
import sys
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

from pajin.control_plane.api import create_app
from pajin.graph.sqlite_store import SQLiteGraphStore
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.workflow import ai_measured_product_flow
from pajin.workflow.ai_fixture_runtime import (
    AIDockerCommandResult,
    AIFixtureDockerProvider,
    SubprocessAIDockerCommandRunner,
)
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_PROXY_IMAGE,
    AI_M03_TARGET_IMAGE,
    AI_M03_WORKER_IMAGE,
    AIMeasuredCaseMapping,
)
from pajin.workflow.ai_measured_product_flow import (
    AIMeasuredProductOutcome,
    AIMeasuredProductProjector,
    AIMeasuredProductSourceReopenContext,
    _strict_json_bytes,
)
from pajin.workflow.ai_measured_product_reader import (
    AIMeasuredProductReader,
    AIMeasuredProductReadRegistration,
    AIMeasuredProductReadRegistry,
)
from pajin.workflow.ai_replay_evaluation import (
    AIMeasurementExecutionContext,
    AIReplayEvaluationRunner,
)
from pajin.workflow.ai_source_measurement import (
    AISourceExecutionContext,
    AISourceMeasurementRunner,
)
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)

_PRODUCT_PATH = "/v1/products/ai-measured-system-prompt-disclosure"
_DEPLOYMENT_ID = "deployment.ai-measured-product-conformance"
_GETUID = getattr(os, "getuid", None)
_LOCK_ROOT_NAME = f".pajin-run-locks-{_GETUID()}" if _GETUID is not None else ".pajin-run-locks"
_LOCK_FILE = re.compile(r"^[0-9a-f]{64}\.lock$")
_IMAGE_REFERENCES = frozenset(
    {
        AI_M03_TARGET_IMAGE,
        AI_M03_WORKER_IMAGE,
        AI_M03_PROXY_IMAGE,
    }
)
_MANAGED_FILTER = "label=pajin.ai-fixture.managed=true"
_FAKE_IMAGE_IDS = {
    AI_M03_TARGET_IMAGE: "sha256:" + sha256(b"ai002b-target-image").hexdigest(),
    AI_M03_WORKER_IMAGE: "sha256:" + sha256(b"ai002b-worker-image").hexdigest(),
    AI_M03_PROXY_IMAGE: "sha256:" + sha256(b"ai002b-proxy-image").hexdigest(),
}
_FRESH_CHILD_STAGES = (
    "not-started",
    "child-entered",
    "recipe-validated",
    "environment-prepared",
    "outcome-restored",
    "provider-rebuilt",
    "registration-rebuilt",
    "application-created",
    "guards-installed",
    "baseline-snapshotted",
    "denial-requests-complete",
    "first-source-reload-entered",
    "first-product-read-complete",
    "second-source-reload-entered",
    "second-product-read-complete",
    "post-read-audit-complete",
    "client-closed",
    "result-built",
)


@dataclass(frozen=True, slots=True)
class FreshAIMeasuredProductRecipe:
    """Picklable product coordinates without a provider, resolver, reader, or app."""

    audit_root: Path
    process_root: Path
    outcome: AIMeasuredProductOutcome
    measured_cases: AIMeasuredCaseMapping
    real_docker: bool
    graph_store_coordinates: tuple[_GraphStoreCoordinate, ...] = ()

    def validate(self) -> None:
        if (
            type(self) is not FreshAIMeasuredProductRecipe
            or type(self.outcome) is not AIMeasuredProductOutcome
            or type(self.measured_cases) is not AIMeasuredCaseMapping
            or type(self.real_docker) is not bool
        ):
            raise TypeError("fresh AI-002D recipe type differs")
        audit_root = self.audit_root.resolve(strict=True)
        if not audit_root.is_dir():
            raise ValueError("fresh AI-002D audit root must be a directory")
        process_root = self.process_root.resolve(strict=False)
        _require_beneath(process_root, audit_root, label="process")
        for label, path in (
            ("product", self.outcome.run_path),
            ("evaluation", self.outcome.source.run_path),
            ("source measurement", self.outcome.source.source.run_path),
            (
                "source execution",
                self.outcome.source.source.execution.source_inputs.run_path,
            ),
            *(
                ("follow-up execution", item.source_inputs.run_path)
                for item in self.outcome.source.executions
            ),
        ):
            _require_beneath(path.resolve(strict=True), audit_root, label=label)
        for coordinate in self.graph_store_coordinates:
            if type(coordinate) is not _GraphStoreCoordinate:
                raise TypeError("fresh AI-002D Graph store coordinate type differs")
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
class FreshAIMeasuredProductProbeResult:
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
            raise TypeError("fresh AI-002D Docker delegate differs")
        self._delegate = delegate
        self.calls: list[tuple[str, ...]] = []

    def run(self, arguments: Sequence[str]) -> AIDockerCommandResult:
        command = tuple(arguments)
        if not _read_only_docker_command(command):
            raise AssertionError(f"fresh AI-002D attempted mutable Docker command: {command!r}")
        self.calls.append(command)
        result = self._delegate.run(command)
        if type(result) is not AIDockerCommandResult:
            raise TypeError("fresh AI-002D Docker delegate returned another result type")
        return result


class _FakeAIDockerRunner:
    def run(self, arguments: Sequence[str]) -> AIDockerCommandResult:
        command = tuple(arguments)
        if (
            len(command) == 5
            and command[:2] == ("image", "inspect")
            and command[2] in _FAKE_IMAGE_IDS
            and command[3:] == ("--format", "{{.Id}}")
        ):
            return AIDockerCommandResult(
                returncode=0,
                stdout=(_FAKE_IMAGE_IDS[command[2]] + "\n").encode(),
                stderr=b"",
            )
        if command in {
            (
                "container",
                "ls",
                "--all",
                "--quiet",
                "--filter",
                _MANAGED_FILTER,
            ),
            ("network", "ls", "--quiet", "--filter", _MANAGED_FILTER),
        }:
            return AIDockerCommandResult(returncode=0, stdout=b"", stderr=b"")
        raise AssertionError(f"fake fresh AI-002D Docker command differs: {command!r}")


@dataclass
class _CountingResolver:
    registry: AIMeasuredProductReadRegistry
    calls: list[str]

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> AIMeasuredProductReadRegistration:
        self.calls.append(deployment_id)
        return self.registry.resolve_for_product_read(deployment_id=deployment_id)


def run_fresh_ai_measured_product_probe(
    recipe: FreshAIMeasuredProductRecipe,
    *,
    hash_seed: int,
    timeout_seconds: int,
) -> FreshAIMeasuredProductProbeResult:
    """Run one independent spawn interpreter and surface its assertions."""

    if type(hash_seed) is not int or hash_seed < 0:
        raise ValueError("fresh AI-002D hash seed must be a non-negative integer")
    if type(timeout_seconds) is not int or timeout_seconds <= 0:
        raise ValueError("fresh AI-002D timeout must be a positive integer")
    recipe.validate()
    if recipe.graph_store_coordinates:
        raise ValueError("fresh AI-002D caller cannot supply Graph store coordinates")
    spawn_recipe = _serializable_recipe(recipe)
    pickle.dumps(spawn_recipe, protocol=pickle.HIGHEST_PROTOCOL)

    context = multiprocessing.get_context("spawn")
    receive, send = context.Pipe(duplex=False)
    progress = context.RawValue("i", 0)
    previous_hash_seed = os.environ.get("PYTHONHASHSEED")
    previous_no_bytecode = os.environ.get("PYTHONDONTWRITEBYTECODE")
    os.environ["PYTHONHASHSEED"] = str(hash_seed)
    os.environ["PYTHONDONTWRITEBYTECODE"] = "1"
    process = context.Process(target=_child_entry, args=(send, spawn_recipe, progress))
    try:
        process.start()
    finally:
        send.close()
        _restore_environment("PYTHONHASHSEED", previous_hash_seed)
        _restore_environment("PYTHONDONTWRITEBYTECODE", previous_no_bytecode)

    if not receive.poll(timeout_seconds):
        last_stage = _fresh_child_stage(progress)
        process.terminate()
        process.join(timeout=10)
        receive.close()
        raise TimeoutError(
            "fresh AI-002D product child did not finish within "
            f"{timeout_seconds}s (hash seed {hash_seed}, real Docker {recipe.real_docker}, "
            f"last stage {last_stage})"
        )
    try:
        state, payload = receive.recv()
    except EOFError as exc:
        process.join(timeout=10)
        raise RuntimeError(
            "fresh AI-002D product child exited without a result "
            f"({process.exitcode}, last stage {_fresh_child_stage(progress)})"
        ) from exc
    finally:
        receive.close()
    process.join(timeout=10)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)
        raise RuntimeError(
            f"fresh AI-002D product child did not exit (last stage {_fresh_child_stage(progress)})"
        )
    if state != "ok" or process.exitcode != 0:
        raise AssertionError(cast(str, payload))
    if type(payload) is not FreshAIMeasuredProductProbeResult:
        raise TypeError("fresh AI-002D product child returned another result type")
    return payload


def _child_entry(
    send: Any,
    recipe: FreshAIMeasuredProductRecipe,
    progress: Any,
) -> None:
    try:
        _mark_fresh_child_stage(progress, "child-entered")
        send.send(("ok", _run_child(recipe, progress=progress)))
    except BaseException:  # pragma: no cover - diagnostics cross the process boundary
        send.send(("error", traceback.format_exc()))
    finally:
        send.close()


def _run_child(
    recipe: FreshAIMeasuredProductRecipe,
    *,
    progress: Any,
) -> FreshAIMeasuredProductProbeResult:
    recipe.validate()
    _mark_fresh_child_stage(progress, "recipe-validated")
    process_root = recipe.process_root.resolve(strict=False)
    temp_root = process_root / "TEMP"
    temp_root.mkdir(parents=True, exist_ok=False)
    os.environ["TEMP"] = str(temp_root)
    os.environ["TMP"] = str(temp_root)
    os.environ["TMPDIR"] = str(temp_root)
    tempfile.tempdir = str(temp_root)
    _mark_fresh_child_stage(progress, "environment-prepared")
    outcome = _restore_product_outcome(
        recipe.outcome,
        coordinates=recipe.graph_store_coordinates,
    )
    _mark_fresh_child_stage(progress, "outcome-restored")

    if recipe.real_docker:
        delegate: Any = SubprocessAIDockerCommandRunner()
    else:
        delegate = _FakeAIDockerRunner()
    docker = _ReadOnlyDockerRunner(delegate)
    provider = AIFixtureDockerProvider(command_runner=docker)
    reopen = AIMeasuredProductSourceReopenContext(
        measured_cases=recipe.measured_cases,
        provider=provider,
    )
    _mark_fresh_child_stage(progress, "provider-rebuilt")
    registration = AIMeasuredProductReadRegistration.from_outcome(
        deployment_id=_DEPLOYMENT_ID,
        outcome=outcome,
        reopen_context=reopen,
    )
    registry = AIMeasuredProductReadRegistry((registration,))
    resolver = _CountingResolver(registry=registry, calls=[])
    reader = AIMeasuredProductReader(
        deployment_id=_DEPLOYMENT_ID,
        resolver=resolver,
    )
    _mark_fresh_child_stage(progress, "registration-rebuilt")
    source_reload_calls = 0
    source_loader = ai_measured_product_flow.load_ai_replay_floor_evaluation

    def monitored_source_loader(*args: Any, **kwargs: Any) -> Any:
        nonlocal source_reload_calls
        source_reload_calls += 1
        _mark_fresh_child_stage(
            progress,
            "first-source-reload-entered"
            if source_reload_calls == 1
            else "second-source-reload-entered",
        )
        return source_loader(*args, **kwargs)

    def forbidden(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("fresh AI-002D invoked an execution or mutation authority")

    app = create_app(
        _settings(process_root / "control-plane.sqlite3"),
        ai_measured_product_reader=reader,
    )
    _mark_fresh_child_stage(progress, "application-created")
    with TestClient(app) as client, ExitStack() as stack:
        stack.enter_context(patch.object(RunStore, "create", forbidden))
        stack.enter_context(patch.object(AIMeasuredProductProjector, "project", forbidden))
        stack.enter_context(patch.object(AISourceMeasurementRunner, "run", forbidden))
        stack.enter_context(patch.object(AIReplayEvaluationRunner, "run", forbidden))
        stack.enter_context(patch.object(DockerWorkerBackend, "run", forbidden))
        for name in ("start", "finish", "finish_measurement", "abort"):
            stack.enter_context(patch.object(AIFixtureDockerProvider, name, forbidden))
        stack.enter_context(
            patch.object(
                ai_measured_product_flow,
                "load_ai_replay_floor_evaluation",
                monitored_source_loader,
            )
        )
        _mark_fresh_child_stage(progress, "guards-installed")

        before = _tree_snapshot(recipe.audit_root, temp_root=temp_root)
        _mark_fresh_child_stage(progress, "baseline-snapshotted")
        denied = (
            client.get(_PRODUCT_PATH),
            client.get(_PRODUCT_PATH, headers=_auth("invalid-bearer")),
            client.get(_PRODUCT_PATH, headers=_auth(APPROVER_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(AUDITOR_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(WORKER_TOKEN)),
            client.get(f"{_PRODUCT_PATH}?prompt=caller-selected", headers=_auth(OPERATOR_TOKEN)),
            client.request("GET", _PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), content=b"{}"),
            client.post(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), json={}),
            client.head(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN)),
        )
        _mark_fresh_child_stage(progress, "denial-requests-complete")
        first_success = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        _mark_fresh_child_stage(progress, "first-product-read-complete")
        second_success = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        _mark_fresh_child_stage(progress, "second-product-read-complete")
        successful = (first_success, second_success)
        after = _tree_snapshot(recipe.audit_root, temp_root=temp_root)
        _mark_fresh_child_stage(progress, "post-read-audit-complete")
    _mark_fresh_child_stage(progress, "client-closed")

    statuses = tuple(response.status_code for response in (*denied, *successful))
    if statuses != (401, 401, 403, 403, 403, 400, 400, 405, 405, 200, 200):
        raise AssertionError(f"fresh AI-002D response statuses differ: {statuses!r}")
    for response in (*denied, *successful):
        _assert_non_cacheable(response)
    canonical = tuple(_strict_json_bytes(response.json()) for response in successful)
    sealed = outcome.run_path.joinpath(outcome.artifact_path).read_bytes()
    if canonical != (sealed, sealed):
        raise AssertionError("fresh AI-002D response bytes differ from the sealed product")
    if resolver.calls != [_DEPLOYMENT_ID, _DEPLOYMENT_ID] or source_reload_calls != 2:
        raise AssertionError("fresh AI-002D zero-argument reload count differs")
    if before != after:
        raise AssertionError("fresh AI-002D product read mutated the audited filesystem")
    if not provider.managed_resources_absent():
        raise AssertionError("fresh AI-002D product read left managed Docker residue")
    product = outcome.product
    _mark_fresh_child_stage(progress, "result-built")
    return FreshAIMeasuredProductProbeResult(
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
    recipe: FreshAIMeasuredProductRecipe,
) -> FreshAIMeasuredProductRecipe:
    evaluation = recipe.outcome.source
    source_execution, source_coordinate = _strip_source_execution(evaluation.source.execution)
    followups: list[AIMeasurementExecutionContext] = []
    coordinates = [source_coordinate]
    for execution in evaluation.executions:
        stripped, coordinate = _strip_measurement_execution(execution)
        followups.append(stripped)
        coordinates.append(coordinate)
    stripped_evaluation = replace(
        evaluation,
        source=replace(evaluation.source, execution=source_execution),
        executions=tuple(followups),
    )
    stripped_outcome = replace(recipe.outcome, source=stripped_evaluation)
    coordinate_tuple = tuple(coordinates)
    if len(coordinate_tuple) != 6 or len({item.path for item in coordinate_tuple}) != 6:
        raise ValueError("fresh AI-002D requires six distinct durable Graph stores")
    return replace(
        recipe,
        outcome=stripped_outcome,
        graph_store_coordinates=coordinate_tuple,
    )


def _graph_store_coordinate(
    store: SQLiteGraphStore,
    *,
    campaign_id: str,
) -> _GraphStoreCoordinate:
    if type(store) is not SQLiteGraphStore:
        raise TypeError("fresh AI-002D requires exact SQLite Graph stores")
    coordinate = _GraphStoreCoordinate(
        path=store.path.resolve(strict=True),
        campaign_id=store.campaign_id,
    )
    if coordinate.campaign_id != campaign_id:
        raise ValueError("fresh AI-002D Graph store Campaign differs")
    return coordinate


def _strip_source_execution(
    execution: AISourceExecutionContext,
) -> tuple[AISourceExecutionContext, _GraphStoreCoordinate]:
    coordinate = _graph_store_coordinate(
        execution.graph_store,
        campaign_id=execution.source_inputs.job.proposal.campaign_id,
    )
    return replace(execution, graph_store=cast(SQLiteGraphStore, None)), coordinate


def _strip_measurement_execution(
    execution: AIMeasurementExecutionContext,
) -> tuple[AIMeasurementExecutionContext, _GraphStoreCoordinate]:
    coordinate = _graph_store_coordinate(
        execution.graph_store,
        campaign_id=execution.source_inputs.job.proposal.campaign_id,
    )
    return replace(execution, graph_store=cast(SQLiteGraphStore, None)), coordinate


def _restore_product_outcome(
    outcome: AIMeasuredProductOutcome,
    *,
    coordinates: tuple[_GraphStoreCoordinate, ...],
) -> AIMeasuredProductOutcome:
    if len(outcome.source.executions) != 5 or len(coordinates) != 6:
        raise ValueError("fresh AI-002D Graph store coordinate count differs")
    source_execution = _restore_source_execution(
        outcome.source.source.execution,
        coordinate=coordinates[0],
    )
    followups = tuple(
        _restore_measurement_execution(execution, coordinate=coordinate)
        for execution, coordinate in zip(
            outcome.source.executions,
            coordinates[1:],
            strict=True,
        )
    )
    return replace(
        outcome,
        source=replace(
            outcome.source,
            source=replace(outcome.source.source, execution=source_execution),
            executions=followups,
        ),
    )


def _restore_source_execution(
    execution: AISourceExecutionContext,
    *,
    coordinate: _GraphStoreCoordinate,
) -> AISourceExecutionContext:
    if (
        execution.graph_store is not None
        or coordinate.campaign_id != execution.source_inputs.job.proposal.campaign_id
    ):
        raise ValueError("fresh AI-002D stripped source Graph store binding differs")
    return replace(
        execution,
        graph_store=SQLiteGraphStore(
            coordinate.path,
            campaign_id=coordinate.campaign_id,
        ),
    )


def _restore_measurement_execution(
    execution: AIMeasurementExecutionContext,
    *,
    coordinate: _GraphStoreCoordinate,
) -> AIMeasurementExecutionContext:
    if (
        execution.graph_store is not None
        or coordinate.campaign_id != execution.source_inputs.job.proposal.campaign_id
    ):
        raise ValueError("fresh AI-002D stripped follow-up Graph store binding differs")
    return replace(
        execution,
        graph_store=SQLiteGraphStore(
            coordinate.path,
            campaign_id=coordinate.campaign_id,
        ),
    )


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
            raise AssertionError(f"fresh AI-002D audit found a special file: {relative}")
    return tuple(entries)


def _validate_lock_tree(lock_root: Path) -> None:
    root_details = lock_root.lstat()
    if lock_root.is_symlink() or not stat.S_ISDIR(root_details.st_mode):
        raise AssertionError("fresh AI-002D lock root is not a real directory")
    getuid = getattr(os, "getuid", None)
    if getuid is not None and root_details.st_uid != getuid():
        raise AssertionError("fresh AI-002D lock root owner differs")
    if os.name == "posix" and stat.S_IMODE(root_details.st_mode) != 0o700:
        raise AssertionError("fresh AI-002D lock root mode differs")
    for lock_file in lock_root.iterdir():
        details = lock_file.lstat()
        if (
            _LOCK_FILE.fullmatch(lock_file.name) is None
            or lock_file.is_symlink()
            or not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
        ):
            raise AssertionError("fresh AI-002D lock root contains another entry")
        if getuid is not None and details.st_uid != getuid():
            raise AssertionError("fresh AI-002D lock file owner differs")
        if os.name == "posix" and stat.S_IMODE(details.st_mode) != 0o600:
            raise AssertionError("fresh AI-002D lock file mode differs")


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
        raise AssertionError("fresh AI-002D response cache or browser boundary differs")


def _require_beneath(path: Path, root: Path, *, label: str) -> None:
    try:
        path.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"fresh AI-002D {label} path is outside its audit root") from exc


def _restore_environment(name: str, previous: str | None) -> None:
    if previous is None:
        os.environ.pop(name, None)
    else:
        os.environ[name] = previous


def _mark_fresh_child_stage(progress: Any, stage: str) -> None:
    progress.value = _FRESH_CHILD_STAGES.index(stage)
    print(f"fresh AI-002D product child stage: {stage}", file=sys.stderr, flush=True)


def _fresh_child_stage(progress: Any) -> str:
    stage_index = int(progress.value)
    if 0 <= stage_index < len(_FRESH_CHILD_STAGES):
        return _FRESH_CHILD_STAGES[stage_index]
    return f"unknown-{stage_index}"


__all__ = [
    "FreshAIMeasuredProductProbeResult",
    "FreshAIMeasuredProductRecipe",
    "run_fresh_ai_measured_product_probe",
]
