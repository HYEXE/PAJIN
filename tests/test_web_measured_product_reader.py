from __future__ import annotations

import json
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from pajin.runtime.store import RunStore
from pajin.workflow.web_measured_product_flow import (
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductSourceReopenContext,
)
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReaderError,
    WebMeasuredProductReadRegistration,
    WebMeasuredProductReadRegistry,
)
from tests.test_web_measured_product_flow import _project

pytest_plugins = ("tests.test_web_validation_evaluation",)


class _CountingProductReadResolver:
    def __init__(self, registry: WebMeasuredProductReadRegistry) -> None:
        self.registry = registry
        self.calls: list[str] = []

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> WebMeasuredProductReadRegistration:
        self.calls.append(deployment_id)
        return self.registry.resolve_for_product_read(deployment_id=deployment_id)


class _BareOuterJSONResolver:
    def resolve_for_product_read(self, *, deployment_id: str) -> object:
        return json.dumps({"deploymentId": deployment_id})


class _FixedProductReadResolver:
    def __init__(self, registration: WebMeasuredProductReadRegistration) -> None:
        self.registration = registration

    def resolve_for_product_read(
        self,
        *,
        deployment_id: str,
    ) -> WebMeasuredProductReadRegistration:
        return self.registration


def _read_registration(
    *,
    outcome: WebMeasuredProductFlowOutcome,
    context: WebMeasuredProductSourceReopenContext,
) -> WebMeasuredProductReadRegistration:
    outcome.source.run_path.mkdir(parents=True, exist_ok=True)
    return WebMeasuredProductReadRegistration.from_outcome(
        deployment_id="deployment.web-measured-product",
        outcome=outcome,
        reopen_context=context,
    )


def _run_tree_state(*roots: Path) -> tuple[tuple[str, str, bytes, int], ...]:
    state: list[tuple[str, str, bytes, int]] = []
    for ordinal, root in enumerate(roots):
        for path in sorted(item for item in root.rglob("*") if item.is_file()):
            state.append(
                (
                    str(ordinal),
                    path.relative_to(root).as_posix(),
                    path.read_bytes(),
                    path.stat().st_mtime_ns,
                )
            )
    return tuple(state)


def test_ux_009b_reads_only_the_deployment_registered_product(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, source, authority, context, _, calls, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    registration = _read_registration(outcome=outcome, context=context)
    registry = WebMeasuredProductReadRegistry((registration,))
    resolver = _CountingProductReadResolver(registry)
    reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    before = _run_tree_state(outcome.run_path, source.run_path)

    def reject_run_creation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("UX-009B read must not create a Run")

    monkeypatch.setattr(RunStore, "create", reject_run_creation)
    projection = reader.read()
    fresh_projection = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=_CountingProductReadResolver(WebMeasuredProductReadRegistry((registration,))),
    ).read()

    assert resolver.calls == [registration.deployment_id]
    assert calls == [source, source, source, source]
    assert projection == outcome.projection
    assert fresh_projection == projection
    assert projection.flow_id == registration.product_flow_id
    assert projection.flow_digest == registration.product_flow_digest
    assert _run_tree_state(outcome.run_path, source.run_path) == before

    public_wire = json.dumps(
        projection.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        sort_keys=True,
    )
    for forbidden in (
        str(outcome.run_path),
        str(source.run_path),
        authority.private_marker,
        authority.route_marker,
        authority.worker_marker,
        authority.graph_marker,
        '"provider":',
        '"adapter":',
        "trustAnchor",
        "claimLedger",
        "targetJournal",
        "privateBinding",
    ):
        assert forbidden not in public_wire


def test_ux_009b_rejects_duplicate_or_mismatched_registration(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _, _, context, _, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    registration = _read_registration(outcome=outcome, context=context)
    registry = WebMeasuredProductReadRegistry((registration,))
    duplicate_product = replace(
        registration,
        deployment_id="deployment.duplicate-product",
    )
    alternate_product_path = tmp_path / "alternate-product-run"
    alternate_product_path.mkdir()
    duplicate_flow = WebMeasuredProductReadRegistration.from_outcome(
        deployment_id="deployment.duplicate-flow",
        outcome=replace(
            outcome,
            run_id="b" * 64,
            run_path=alternate_product_path,
        ),
        reopen_context=context,
    )

    with pytest.raises(ValueError, match="deployment IDs must be unique"):
        WebMeasuredProductReadRegistry((registration, registration))
    with pytest.raises(ValueError, match="product Run IDs must be unique"):
        WebMeasuredProductReadRegistry((registration, duplicate_product))
    with pytest.raises(ValueError, match="Flow IDs must be unique"):
        WebMeasuredProductReadRegistry((registration, duplicate_flow))
    with pytest.raises(ValueError, match="registration identities differ"):
        WebMeasuredProductReadRegistry((replace(registration, product_flow_digest="0" * 64),))
    with pytest.raises(ValueError, match="Runs must be distinct"):
        WebMeasuredProductReadRegistry(
            (
                WebMeasuredProductReadRegistration.from_outcome(
                    deployment_id="deployment.aliased-path",
                    outcome=replace(outcome, run_path=outcome.source.run_path),
                    reopen_context=context,
                ),
            )
        )
    with pytest.raises(ValueError, match="Runs must be distinct"):
        WebMeasuredProductReadRegistry(
            (
                WebMeasuredProductReadRegistration.from_outcome(
                    deployment_id="deployment.reused-run-id",
                    outcome=replace(outcome, run_id=outcome.source.run_id),
                    reopen_context=context,
                ),
            )
        )
    with pytest.raises(TypeError, match="another registration type"):
        WebMeasuredProductReadRegistry(cast(Any, (object(),)))
    with pytest.raises(TypeError, match="exact product outcome"):
        WebMeasuredProductReadRegistry((replace(registration, outcome=cast(Any, object())),))
    with pytest.raises(TypeError, match="exact source outcome"):
        WebMeasuredProductReadRegistry(
            (
                replace(
                    registration,
                    outcome=replace(outcome, source=cast(Any, object())),
                ),
            )
        )
    with pytest.raises(TypeError, match="complete reopen context"):
        WebMeasuredProductReadRegistry((replace(registration, reopen_context=cast(Any, object())),))
    with pytest.raises(TypeError):
        cast(Any, registry)._registrations[registration.deployment_id] = registration
    with pytest.raises(FrozenInstanceError):
        cast(Any, registry)._registrations = {}

    reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=registry,
    )
    with pytest.raises(FrozenInstanceError):
        cast(Any, reader)._deployment_id = "deployment.substituted"
    with pytest.raises(FrozenInstanceError):
        cast(Any, reader)._resolver = object()


def test_ux_009b_rejects_resolver_path_context_and_outer_json_substitution(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _, _, context, _, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    registration = _read_registration(outcome=outcome, context=context)

    caller_selected_root = tmp_path / "caller-selected-product-root"
    caller_selected_root.mkdir()
    path_registration = replace(
        registration,
        outcome=replace(outcome, run_path=caller_selected_root),
    )
    path_reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=WebMeasuredProductReadRegistry((path_registration,)),
    )
    with pytest.raises(WebMeasuredProductReaderError, match="failed closed"):
        path_reader.read()

    context_registration = replace(
        registration,
        reopen_context=replace(context, provider=cast(Any, object())),
    )
    context_reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=WebMeasuredProductReadRegistry((context_registration,)),
    )
    with pytest.raises(WebMeasuredProductReaderError, match="failed closed"):
        context_reader.read()

    bare_reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=cast(Any, _BareOuterJSONResolver()),
    )
    with pytest.raises(WebMeasuredProductReaderError, match="failed closed"):
        bare_reader.read()

    unknown_deployment_reader = WebMeasuredProductReader(
        deployment_id="deployment.unknown",
        resolver=WebMeasuredProductReadRegistry((registration,)),
    )
    with pytest.raises(WebMeasuredProductReaderError, match="failed closed"):
        unknown_deployment_reader.read()

    mismatched_deployment_reader = WebMeasuredProductReader(
        deployment_id="deployment.other",
        resolver=_FixedProductReadResolver(registration),
    )
    with pytest.raises(WebMeasuredProductReaderError, match="failed closed"):
        mismatched_deployment_reader.read()

    valid_reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=WebMeasuredProductReadRegistry((registration,)),
    )
    with pytest.raises(TypeError):
        cast(Any, valid_reader).read({"root": tmp_path})
    with pytest.raises(TypeError):
        cast(Any, valid_reader).read(provider=object())
