from __future__ import annotations

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
from test_network_fixture_runtime import _runtime

from pajin.control_plane.api import create_app
from pajin.runtime.store import RunStore
from pajin.workflow.network_fixture_runtime import NETWORK_WORKER_IMAGE
from pajin.workflow.network_measured_case_authority import NetworkMeasuredCaseMapping
from pajin.workflow.network_measured_product_flow import (
    NETWORK_MEASURED_PRODUCT_PATH,
    NetworkMeasuredProduct,
    NetworkMeasuredProductError,
    NetworkMeasuredProductOutcome,
    NetworkMeasuredProductProjector,
    NetworkMeasuredProductSourceReopenContext,
    load_network_measured_product,
)
from pajin.workflow.network_measured_product_reader import (
    NetworkMeasuredProductReader,
    NetworkMeasuredProductReaderError,
    NetworkMeasuredProductReadRegistration,
    NetworkMeasuredProductReadRegistry,
)
from pajin.workflow.network_replay_evaluation import NetworkReplayEvaluationRunner
from pajin.workflow.network_source_measurement import NetworkSourceMeasurementRunner
from tests.network_measured_product_fresh_process import (
    FreshNetworkMeasuredProductRecipe,
    run_fresh_network_measured_product_probe,
)
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)

pytest_plugins = ("tests.test_network_replay_evaluation",)

_PRODUCT_PATH = "/v1/products/network-measured-service-identification"
_EXPECTED_CASE_IDS = (
    "network-fixture:ftp-known-positive",
    "network-fixture:imap-known-positive",
    "network-fixture:pop3-known-positive",
    "network-fixture:smtp-known-positive",
    "network-fixture:ssh-known-positive",
    "network-fixture:unknown-negative-control",
)
_PRIVATE_KEYS = {
    "rawBannerBase64",
    "expectedServiceName",
    "observedServiceName",
    "privateGroundTruthBindingDigest",
    "privateEvaluationDigest",
    "sourceLineageDigest",
    "replayLineageDigest",
    "sourceIdentityDigest",
    "replayIdentityDigest",
    "targetContainerId",
    "targetNetworkId",
    "workerContainerId",
    "proxyContainerId",
    "internalNetworkId",
    "workerResult",
    "toolResult",
    "images",
}


@dataclass(frozen=True)
class _ProductContext:
    source: Any
    measured: Any
    provider: Any
    reopen: NetworkMeasuredProductSourceReopenContext
    outcome: NetworkMeasuredProductOutcome


@pytest.fixture(scope="module")
def network_product_context(
    network_replay_context: Any,
) -> Iterator[_ProductContext]:
    reopen = NetworkMeasuredProductSourceReopenContext(
        measured_cases=network_replay_context.measured,
        provider=network_replay_context.provider,
    )
    outcome = NetworkMeasuredProductProjector(
        output_root=network_replay_context.root / "product-runs"
    ).project(network_replay_context.outcome, reopen_context=reopen)
    yield _ProductContext(
        source=network_replay_context.outcome,
        measured=network_replay_context.measured,
        provider=network_replay_context.provider,
        reopen=reopen,
        outcome=outcome,
    )


def _all_keys(value: object) -> set[str]:
    if isinstance(value, dict):
        return set(value).union(*(_all_keys(item) for item in value.values()))
    if isinstance(value, list):
        return set().union(*(_all_keys(item) for item in value)) if value else set()
    return set()


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
    deployment_id: str = "deployment.network-measured-product",
    outcome: NetworkMeasuredProductOutcome | None = None,
    reopen: NetworkMeasuredProductSourceReopenContext | None = None,
) -> NetworkMeasuredProductReadRegistration:
    return NetworkMeasuredProductReadRegistration.from_outcome(
        deployment_id=deployment_id,
        outcome=outcome or context.outcome,
        reopen_context=reopen or context.reopen,
    )


def _assert_non_cacheable(response: Any) -> None:
    directives = {item.strip().lower() for item in response.headers["cache-control"].split(",")}
    assert "no-store" in directives
    assert response.headers["pragma"] == "no-cache"


def test_net_002d_projects_only_cases_metrics_floor_and_false_authority(
    network_product_context: _ProductContext,
) -> None:
    context = network_product_context
    product = load_network_measured_product(context.outcome, reopen_context=context.reopen)
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
    assert tuple(item.case.case_id for item in product.cases) == _EXPECTED_CASE_IDS
    assert tuple(item.comparison_state for item in product.cases) == (
        *("synthetic-known-positive-matched" for _ in range(5)),
        "synthetic-negative-control-unresolved",
    )
    assert product.floor.observations == context.source.mapping.public_evaluation.observations
    assert product.floor.required_metric_count == 11
    assert product.floor.not_applicable_metric_count == 3
    assert product.floor.validation_floor_satisfied is True
    assert product.floor.synthetic_benchmark_only is True
    assert not _all_keys(payload).intersection(_PRIVATE_KEYS)
    assert all(value is False for value in payload["authorityBoundary"].values())
    assert context.outcome.run_id not in {
        context.source.run_id,
        context.source.source.run_id,
        context.source.replay.run_id,
    }
    assert context.outcome.artifact_path == NETWORK_MEASURED_PRODUCT_PATH
    assert context.outcome.run_path.joinpath(context.outcome.artifact_path).read_bytes() == (
        (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode()
    )


def test_net_002d_wire_rejects_order_metric_unknown_private_and_boolean_drift(
    network_product_context: _ProductContext,
) -> None:
    payload = network_product_context.outcome.product.model_dump(mode="json", by_alias=True)

    reordered = json.loads(json.dumps(payload))
    reordered["productId"] = ""
    reordered["productDigest"] = ""
    reordered["cases"][0], reordered["cases"][1] = reordered["cases"][1], reordered["cases"][0]
    with pytest.raises(ValidationError, match="case, floor, or source"):
        NetworkMeasuredProduct.model_validate_json(json.dumps(reordered))

    metric = json.loads(json.dumps(payload))
    metric["productId"] = ""
    metric["productDigest"] = ""
    metric["floor"]["observations"][0]["numerator"] = 7
    with pytest.raises(ValidationError, match="fixed metric rational"):
        NetworkMeasuredProduct.model_validate_json(json.dumps(metric))

    unknown = json.loads(json.dumps(payload))
    unknown["productId"] = ""
    unknown["productDigest"] = ""
    unknown["cases"][-1]["comparisonState"] = "synthetic-known-positive-matched"
    with pytest.raises(ValidationError, match="case, floor, or source"):
        NetworkMeasuredProduct.model_validate_json(json.dumps(unknown))

    leaked = json.loads(json.dumps(payload))
    leaked["privateExpectedLabel"] = "ftp"
    with pytest.raises(ValidationError):
        NetworkMeasuredProduct.model_validate_json(json.dumps(leaked))

    for value in (True, 0, "false"):
        escalated = json.loads(json.dumps(payload))
        escalated["authorityBoundary"]["additionalExecutionAuthorized"] = value
        with pytest.raises(ValidationError):
            NetworkMeasuredProduct.model_validate_json(json.dumps(escalated))


def test_net_002d_loader_rejects_source_digest_profile_and_image_substitution(
    network_product_context: _ProductContext,
) -> None:
    context = network_product_context
    foreign_public = context.source.mapping.public_evaluation.model_copy(
        update={"evaluation_digest": "0" * 64}
    )
    foreign_mapping = replace(context.source.mapping, public_evaluation=foreign_public)
    foreign_source = replace(context.source, mapping=foreign_mapping)
    with pytest.raises(NetworkMeasuredProductError, match="not sealed and reproducible"):
        load_network_measured_product(
            replace(context.outcome, source=foreign_source),
            reopen_context=context.reopen,
        )

    foreign_emitter = context.measured.public_authority.emitter_profile.model_copy(
        update={"profile_digest": "0" * 64}
    )
    foreign_authority = context.measured.public_authority.model_copy(
        update={"emitter_profile": foreign_emitter}
    )
    foreign_measured = NetworkMeasuredCaseMapping(
        public_authority=foreign_authority,
        private_binding=context.measured.private_binding,
    )
    with pytest.raises(NetworkMeasuredProductError, match="not sealed and reproducible"):
        load_network_measured_product(
            context.outcome,
            reopen_context=NetworkMeasuredProductSourceReopenContext(
                measured_cases=foreign_measured,
                provider=context.provider,
            ),
        )

    docker, provider, _images = _runtime()
    docker.image_ids[NETWORK_WORKER_IMAGE] = "sha256:" + ("0" * 64)
    with pytest.raises(NetworkMeasuredProductError, match="not sealed and reproducible"):
        load_network_measured_product(
            context.outcome,
            reopen_context=NetworkMeasuredProductSourceReopenContext(
                measured_cases=context.measured,
                provider=provider,
            ),
        )


class _CountingResolver:
    def __init__(self, registry: NetworkMeasuredProductReadRegistry) -> None:
        self.registry = registry
        self.calls: list[str] = []

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> NetworkMeasuredProductReadRegistration:
        self.calls.append(deployment_id)
        return self.registry.resolve_for_product_read(deployment_id=deployment_id)


class _FixedResolver:
    def __init__(self, registration: NetworkMeasuredProductReadRegistration) -> None:
        self.registration = registration

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> NetworkMeasuredProductReadRegistration:
        del deployment_id
        return self.registration


def test_net_002d_reader_is_zero_argument_deployment_pinned_and_read_only(
    network_product_context: _ProductContext,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = network_product_context
    registration = _registration(context)
    registry = NetworkMeasuredProductReadRegistry((registration,))
    resolver = _CountingResolver(registry)
    reader = NetworkMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    roots = (
        context.outcome.run_path,
        context.source.run_path,
        context.source.source.run_path,
        context.source.replay.run_path,
    )
    before = _tree_state(*roots)

    def forbidden_create(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("NET-002D read must not create a Run")

    async def forbidden_run(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("NET-002D read must not execute a measurement")

    monkeypatch.setattr(RunStore, "create", forbidden_create)
    monkeypatch.setattr(NetworkSourceMeasurementRunner, "run", forbidden_run)
    monkeypatch.setattr(NetworkReplayEvaluationRunner, "run", forbidden_run)

    assert reader.read() == context.outcome.product
    assert reader.read() == context.outcome.product
    assert resolver.calls == [registration.deployment_id, registration.deployment_id]
    assert _tree_state(*roots) == before
    assert context.provider.managed_resources_absent()
    with pytest.raises(TypeError):
        cast(Any, reader).read({"target": "caller-selected"})
    with pytest.raises(TypeError):
        cast(Any, reader).read(provider=object())


def test_net_002d_reader_rejects_duplicate_foreign_and_path_registration(
    network_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    context = network_product_context
    registration = _registration(context)
    duplicate = replace(registration, deployment_id="deployment.network-duplicate")
    with pytest.raises(ValueError, match="product Run IDs must be unique"):
        NetworkMeasuredProductReadRegistry((registration, duplicate))

    with pytest.raises(TypeError, match="registration type"):
        NetworkMeasuredProductReadRegistry(cast(Any, (object(),)))

    alternate = tmp_path / "caller-selected"
    alternate.mkdir()
    substituted_outcome = replace(context.outcome, run_path=alternate)
    substituted = _registration(context, outcome=substituted_outcome)
    reader = NetworkMeasuredProductReader(
        deployment_id=substituted.deployment_id,
        resolver=_FixedResolver(substituted),
    )
    with pytest.raises(NetworkMeasuredProductReaderError):
        reader.read()

    wrong_deployment = NetworkMeasuredProductReader(
        deployment_id="deployment.network-other",
        resolver=_FixedResolver(registration),
    )
    with pytest.raises(NetworkMeasuredProductReaderError):
        wrong_deployment.read()


def test_net_002d_operator_get_is_authenticated_body_free_and_non_cacheable(
    network_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    context = network_product_context
    registration = _registration(context)
    resolver = _CountingResolver(NetworkMeasuredProductReadRegistry((registration,)))
    reader = NetworkMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    with TestClient(
        create_app(
            _settings(tmp_path / "network-product-control-plane.sqlite3"),
            network_measured_product_reader=reader,
        )
    ) as client:
        responses = (
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
        assert successful.json() == context.outcome.product.model_dump(mode="json", by_alias=True)
        for response in (*responses, successful):
            _assert_non_cacheable(response)
    assert resolver.calls == [registration.deployment_id]


def test_net_002d_unconfigured_foreign_and_integrity_failure_are_fixed(
    network_product_context: _ProductContext,
    tmp_path: Path,
) -> None:
    with TestClient(create_app(_settings(tmp_path / "unconfigured.sqlite3"))) as client:
        response = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 503
        assert response.json() == {"detail": "Measured Network product read is not configured"}

    with pytest.raises(TypeError, match="exact NET-002D reader"):
        create_app(
            _settings(tmp_path / "foreign.sqlite3"),
            network_measured_product_reader=cast(Any, object()),
        )

    context = network_product_context
    bad_product = context.outcome.product.model_copy(update={"product_digest": "0" * 64})
    bad_outcome = replace(context.outcome, product=bad_product)
    registration = replace(_registration(context), outcome=bad_outcome)
    reader = NetworkMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=_FixedResolver(registration),
    )
    with TestClient(
        create_app(
            _settings(tmp_path / "integrity.sqlite3"),
            network_measured_product_reader=reader,
        )
    ) as client:
        response = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 409
        assert response.json() == {
            "detail": "Measured Network product authority is not integrity-valid"
        }
        assert "rawBanner" not in response.text
        assert "expectedService" not in response.text


def test_net_002d_registry_storage_is_immutable(
    network_product_context: _ProductContext,
) -> None:
    registration = _registration(network_product_context)
    registry = NetworkMeasuredProductReadRegistry((registration,))
    assert isinstance(registry._registrations, MappingProxyType)
    with pytest.raises(TypeError):
        cast(Any, registry._registrations)[registration.deployment_id] = registration


def test_net_002d_fresh_process_reloads_without_execution_or_mutation(
    network_product_context: _ProductContext,
) -> None:
    context = network_product_context
    audit_root = context.outcome.run_path.parents[2]
    result = run_fresh_network_measured_product_probe(
        FreshNetworkMeasuredProductRecipe(
            audit_root=audit_root,
            process_root=audit_root / "fresh-product-process",
            outcome=context.outcome,
            measured_cases=context.measured,
            real_docker=False,
        ),
        hash_seed=24002,
        timeout_seconds=300,
    )

    assert result.process_id != os.getpid()
    assert result.statuses == (401, 401, 403, 403, 403, 400, 400, 405, 405, 200, 200)
    assert result.resolver_calls == (
        "deployment.network-measured-product-conformance",
        "deployment.network-measured-product-conformance",
    )
    assert result.source_reload_calls == 2
    assert result.product_id == context.outcome.product.product_id
    assert result.product_digest == context.outcome.product.product_digest
    assert result.filesystem_unchanged is True
    assert result.docker_argv
    assert all(command[0] in {"image", "container", "network"} for command in result.docker_argv)
