from __future__ import annotations

import asyncio
import json
import os
from collections.abc import Iterator
from dataclasses import dataclass, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.api import create_app
from pajin.runtime.store import RunStore
from pajin.runtime.worker import DockerWorkerBackend
from pajin.workflow.ai_fixture_runtime import registered_ai_source_image_binding
from pajin.workflow.ai_measured_case_authority import (
    AI_M03_WORKER_IMAGE,
    AIMeasuredCaseMapping,
)
from pajin.workflow.ai_measured_product_flow import (
    AI_MEASURED_PRODUCT_PATH,
    AIMeasuredProduct,
    AIMeasuredProductError,
    AIMeasuredProductOutcome,
    AIMeasuredProductProjector,
    AIMeasuredProductSourceReopenContext,
    load_ai_measured_product,
)
from pajin.workflow.ai_measured_product_reader import (
    AIMeasuredProductReader,
    AIMeasuredProductReaderError,
    AIMeasuredProductReadRegistration,
    AIMeasuredProductReadRegistry,
)
from pajin.workflow.ai_replay_evaluation import (
    AIReplayEvaluationOutcome,
    AIReplayEvaluationRunner,
)
from pajin.workflow.ai_source_measurement import AISourceMeasurementRunner
from tests.ai_measured_product_fresh_process import (
    FreshAIMeasuredProductRecipe,
    run_fresh_ai_measured_product_probe,
)
from tests.test_ai_source_measurement import (
    _ImageInspector,
    _InProcessProvider,
    _run_ai002c_checkpoint,
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
_CASE_ID = "ai-fixture:m03-system-prompt-disclosure"
_PRIVATE_KEYS = {
    "promptText",
    "checkValue",
    "groundTruth",
    "privateEvaluation",
    "sourcePrivateMeasurement",
    "followupMeasurements",
    "executionIdentities",
    "accountingObservations",
    "request",
    "challenge",
    "lifecycle",
    "workerResult",
    "toolResult",
    "output",
    "turns",
    "checks",
    "targetUrl",
    "targetContainerName",
    "targetNetworkName",
    "observedImageId",
}


@dataclass(frozen=True)
class _ProductContext:
    root: Path
    source: AIReplayEvaluationOutcome
    measured: AIMeasuredCaseMapping
    provider: _InProcessProvider
    reopen: AIMeasuredProductSourceReopenContext
    outcome: AIMeasuredProductOutcome


@pytest.fixture(scope="module")
def ai_product_context(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_ProductContext]:
    root = tmp_path_factory.mktemp("ai-002d")
    monkeypatch = pytest.MonkeyPatch()
    try:
        source, _authorizer, provider, measured = asyncio.run(
            _run_ai002c_checkpoint(root, monkeypatch)
        )
        assert isinstance(measured, AIMeasuredCaseMapping)
        reopen = AIMeasuredProductSourceReopenContext(
            measured_cases=measured,
            provider=provider,
        )
        outcome = AIMeasuredProductProjector(output_root=root / "product-runs").project(
            source,
            reopen_context=reopen,
        )
        yield _ProductContext(
            root=root,
            source=source,
            measured=measured,
            provider=provider,
            reopen=reopen,
            outcome=outcome,
        )
    finally:
        monkeypatch.undo()


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()), set())
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value), set())
    return set()


def _source_roots(source: AIReplayEvaluationOutcome) -> tuple[Path, ...]:
    return (
        source.run_path,
        source.source.run_path,
        source.source.execution.source_inputs.run_path,
        *(item.source_inputs.run_path for item in source.executions),
    )


def _tree_state(*roots: Path) -> tuple[tuple[str, str, bytes, int], ...]:
    state: list[tuple[str, str, bytes, int]] = []
    for root in roots:
        for path in sorted(root.rglob("*")):
            if path.is_file() and ".pajin-run-locks" not in path.parts:
                stat = path.stat()
                state.append(
                    (
                        str(root),
                        path.relative_to(root).as_posix(),
                        path.read_bytes(),
                        stat.st_mtime_ns,
                    )
                )
    return tuple(state)


def _registration(
    context: _ProductContext,
    *,
    deployment_id: str = "deployment.ai-measured-product",
    outcome: AIMeasuredProductOutcome | None = None,
    reopen: AIMeasuredProductSourceReopenContext | None = None,
) -> AIMeasuredProductReadRegistration:
    return AIMeasuredProductReadRegistration.from_outcome(
        deployment_id=deployment_id,
        outcome=outcome or context.outcome,
        reopen_context=reopen or context.reopen,
    )


def _assert_non_cacheable(response: Any) -> None:
    directives = {item.strip().lower() for item in response.headers["cache-control"].split(",")}
    assert "no-store" in directives
    assert response.headers["pragma"] == "no-cache"


def test_ai_002d_projects_only_case_metrics_floor_and_false_authority(
    ai_product_context: _ProductContext,
) -> None:
    context = ai_product_context
    product = load_ai_measured_product(context.outcome, reopen_context=context.reopen)
    payload = product.model_dump(mode="json", by_alias=True)

    assert set(payload) == {
        "apiVersion",
        "kind",
        "productId",
        "productDigest",
        "sourceEvaluation",
        "cases",
        "floor",
        "authorityBoundary",
    }
    assert tuple(item.case.case_id for item in product.cases) == (_CASE_ID,)
    assert tuple(item.comparison_state for item in product.cases) == (
        "synthetic-known-positive-observed",
    )
    assert product.floor.observations == context.source.mapping.public_evaluation.observations
    assert product.floor.required_metric_count == 12
    assert product.floor.not_applicable_metric_count == 2
    assert product.floor.validation_floor_satisfied is True
    assert product.floor.synthetic_benchmark_only is True
    assert not _all_keys(payload).intersection(_PRIVATE_KEYS)
    assert all(value is False for value in payload["authorityBoundary"].values())

    source_roots = _source_roots(context.source)
    assert len(set(source_roots)) == 8
    assert context.outcome.run_path not in source_roots
    assert context.outcome.artifact_path == AI_MEASURED_PRODUCT_PATH
    assert context.outcome.run_path.joinpath(context.outcome.artifact_path).read_bytes() == (
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    )


def test_ai_002d_wire_rejects_case_metric_private_and_boolean_drift(
    ai_product_context: _ProductContext,
) -> None:
    payload = ai_product_context.outcome.product.model_dump(mode="json", by_alias=True)

    foreign_case = json.loads(json.dumps(payload))
    foreign_case["productId"] = ""
    foreign_case["productDigest"] = ""
    foreign_case["cases"][0]["case"]["caseDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="case, floor, or source"):
        AIMeasuredProduct.model_validate_json(json.dumps(foreign_case))

    reordered = json.loads(json.dumps(payload))
    reordered["productId"] = ""
    reordered["productDigest"] = ""
    observations = reordered["floor"]["observations"]
    observations[0], observations[1] = observations[1], observations[0]
    with pytest.raises(ValidationError, match="metric membership or order"):
        AIMeasuredProduct.model_validate_json(json.dumps(reordered))

    metric = json.loads(json.dumps(payload))
    metric["productId"] = ""
    metric["productDigest"] = ""
    metric["floor"]["observations"][0]["numerator"] = 7
    with pytest.raises(ValidationError, match="fixed metric rational"):
        AIMeasuredProduct.model_validate_json(json.dumps(metric))

    leaked = json.loads(json.dumps(payload))
    leaked["promptText"] = "forbidden"
    with pytest.raises(ValidationError):
        AIMeasuredProduct.model_validate_json(json.dumps(leaked))

    for value in (True, 0, "false"):
        escalated = json.loads(json.dumps(payload))
        escalated["authorityBoundary"]["additionalExecutionAuthorized"] = value
        with pytest.raises(ValidationError):
            AIMeasuredProduct.model_validate_json(json.dumps(escalated))


def test_ai_002d_loader_rejects_digest_profile_route_and_image_substitution(
    ai_product_context: _ProductContext,
) -> None:
    context = ai_product_context

    foreign_public = context.source.mapping.public_evaluation.model_copy(
        update={"evaluation_digest": "0" * 64}
    )
    foreign_mapping = replace(context.source.mapping, public_evaluation=foreign_public)
    with pytest.raises(AIMeasuredProductError, match="not sealed and reproducible"):
        load_ai_measured_product(
            replace(context.outcome, source=replace(context.source, mapping=foreign_mapping)),
            reopen_context=context.reopen,
        )

    foreign_profile = context.measured.public_authority.target_profile.model_copy(
        update={"profile_digest": "0" * 64, "route_path": "/foreign"}
    )
    foreign_authority = context.measured.public_authority.model_copy(
        update={"target_profile": foreign_profile}
    )
    foreign_measured = AIMeasuredCaseMapping(
        public_authority=foreign_authority,
        private_binding=context.measured.private_binding,
    )
    with pytest.raises(AIMeasuredProductError, match="not sealed and reproducible"):
        load_ai_measured_product(
            context.outcome,
            reopen_context=AIMeasuredProductSourceReopenContext(
                measured_cases=foreign_measured,
                provider=context.provider,
            ),
        )

    inspector = _ImageInspector()
    inspector.ids[AI_M03_WORKER_IMAGE] = "sha256:" + ("0" * 64)
    foreign_provider = _InProcessProvider(registered_ai_source_image_binding(inspector))
    with pytest.raises(AIMeasuredProductError, match="not sealed and reproducible"):
        load_ai_measured_product(
            context.outcome,
            reopen_context=AIMeasuredProductSourceReopenContext(
                measured_cases=context.measured,
                provider=foreign_provider,
            ),
        )


class _CountingResolver:
    def __init__(self, registry: AIMeasuredProductReadRegistry) -> None:
        self.registry = registry
        self.calls: list[str] = []

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> AIMeasuredProductReadRegistration:
        self.calls.append(deployment_id)
        return self.registry.resolve_for_product_read(deployment_id=deployment_id)


class _FixedResolver:
    def __init__(self, registration: AIMeasuredProductReadRegistration) -> None:
        self.registration = registration

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> AIMeasuredProductReadRegistration:
        del deployment_id
        return self.registration


def test_ai_002d_reader_is_zero_argument_deployment_pinned_and_read_only(
    ai_product_context: _ProductContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ai_product_context
    registration = _registration(context)
    resolver = _CountingResolver(AIMeasuredProductReadRegistry((registration,)))
    reader = AIMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    roots = (context.outcome.run_path, *_source_roots(context.source))
    before = _tree_state(*roots)

    def forbidden(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("AI-002D read must not create, project, or execute")

    async def forbidden_run(*_args: object, **_kwargs: object) -> None:
        forbidden()

    monkeypatch.setattr(RunStore, "create", forbidden)
    monkeypatch.setattr(AIMeasuredProductProjector, "project", forbidden)
    monkeypatch.setattr(AISourceMeasurementRunner, "run", forbidden_run)
    monkeypatch.setattr(AIReplayEvaluationRunner, "run", forbidden_run)
    monkeypatch.setattr(DockerWorkerBackend, "run", forbidden_run)
    monkeypatch.setattr(type(context.provider), "start", forbidden)

    assert reader.read() == context.outcome.product
    assert reader.read() == context.outcome.product
    assert resolver.calls == [registration.deployment_id, registration.deployment_id]
    assert _tree_state(*roots) == before
    assert context.provider.managed_resources_absent()
    with pytest.raises(TypeError):
        cast(Any, reader).read({"prompt": "caller-selected"})
    with pytest.raises(TypeError):
        cast(Any, reader).read(provider=object())


def test_ai_002d_reader_rejects_duplicate_foreign_and_path_registration(
    ai_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    context = ai_product_context
    registration = _registration(context)
    duplicate = replace(registration, deployment_id="deployment.ai-duplicate")
    with pytest.raises(ValueError, match="product Run IDs must be unique"):
        AIMeasuredProductReadRegistry((registration, duplicate))

    with pytest.raises(TypeError, match="registration type"):
        AIMeasuredProductReadRegistry(cast(Any, (object(),)))

    alternate = tmp_path / "caller-selected"
    alternate.mkdir()
    substituted = _registration(
        context,
        outcome=replace(context.outcome, run_path=alternate),
    )
    reader = AIMeasuredProductReader(
        deployment_id=substituted.deployment_id,
        resolver=_FixedResolver(substituted),
    )
    with pytest.raises(AIMeasuredProductReaderError):
        reader.read()

    wrong_deployment = AIMeasuredProductReader(
        deployment_id="deployment.ai-other",
        resolver=_FixedResolver(registration),
    )
    with pytest.raises(AIMeasuredProductReaderError):
        wrong_deployment.read()


def test_ai_002d_operator_get_is_authenticated_body_free_and_non_cacheable(
    ai_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    context = ai_product_context
    registration = _registration(context)
    resolver = _CountingResolver(AIMeasuredProductReadRegistry((registration,)))
    reader = AIMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    with TestClient(
        create_app(
            _settings(tmp_path / "ai-product-control-plane.sqlite3"),
            ai_measured_product_reader=reader,
        )
    ) as client:
        responses = (
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
        assert tuple(response.status_code for response in responses) == (
            401,
            401,
            403,
            403,
            403,
            400,
            400,
            405,
            405,
        )
        assert resolver.calls == []
        successful = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert successful.status_code == 200
        assert successful.json() == context.outcome.product.model_dump(
            mode="json",
            by_alias=True,
        )
        for response in (*responses, successful):
            _assert_non_cacheable(response)
    assert resolver.calls == [registration.deployment_id]


def test_ai_002d_unconfigured_foreign_integrity_and_registry_storage_are_fixed(
    ai_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    with TestClient(create_app(_settings(tmp_path / "unconfigured.sqlite3"))) as client:
        response = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 503
        assert response.json() == {"detail": "Measured AI product read is not configured"}

    with pytest.raises(TypeError, match="exact AI-002D reader"):
        create_app(
            _settings(tmp_path / "foreign.sqlite3"),
            ai_measured_product_reader=cast(Any, object()),
        )

    context = ai_product_context
    bad_product = context.outcome.product.model_copy(update={"product_digest": "0" * 64})
    bad_outcome = replace(context.outcome, product=bad_product)
    registration = replace(_registration(context), outcome=bad_outcome)
    registry = AIMeasuredProductReadRegistry((_registration(context),))
    assert isinstance(registry._registrations, MappingProxyType)
    with pytest.raises(TypeError):
        cast(Any, registry._registrations)[_registration(context).deployment_id] = registration

    reader = AIMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=_FixedResolver(registration),
    )
    with TestClient(
        create_app(
            _settings(tmp_path / "integrity.sqlite3"),
            ai_measured_product_reader=reader,
        )
    ) as client:
        response = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 409
        assert response.json() == {"detail": "Measured AI product authority is not integrity-valid"}
        assert "promptText" not in response.text
        assert "checkValue" not in response.text


def test_ai_002d_fresh_process_reloads_without_execution_or_mutation(
    ai_product_context: _ProductContext,
) -> None:
    context = ai_product_context
    result = run_fresh_ai_measured_product_probe(
        FreshAIMeasuredProductRecipe(
            audit_root=context.root,
            process_root=context.root / "fresh-product-process",
            outcome=context.outcome,
            measured_cases=context.measured,
            real_docker=False,
        ),
        hash_seed=25002,
        timeout_seconds=300,
    )

    assert result.process_id != os.getpid()
    assert result.statuses == (401, 401, 403, 403, 403, 400, 400, 405, 405, 200, 200)
    assert result.resolver_calls == (
        "deployment.ai-measured-product-conformance",
        "deployment.ai-measured-product-conformance",
    )
    assert result.source_reload_calls == 2
    assert result.product_id == context.outcome.product.product_id
    assert result.product_digest == context.outcome.product.product_digest
    assert result.filesystem_unchanged is True
    assert result.docker_argv
    assert all(command[0] in {"image", "container", "network"} for command in result.docker_argv)
