from __future__ import annotations

import asyncio
import json
import stat
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar

import pytest
from test_llm_effectiveness_structured import structured_fixture

import scripts.operational_web_analysis as module
from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.benchmark.effectiveness_structured.plan import ComparisonPlan, comparison_pins
from pajin.runtime.store import RunStore
from pajin.web_assessment.analysis_local import LocalWebAnalysisProviderCleanup
from pajin.web_assessment.analysis_runtime import (
    WebAnalysisCancelledError,
    WebAnalysisInvocationError,
)

_ANALYSIS_RUN_ID = "run_20260916T010101Z_1234abcd"
_PROVIDER_RUN_ID = "run_20260916T010100Z_5678abcd"
_ANALYSIS_ROOT = "a" * 64
_PROVIDER_ROOT = "b" * 64
_SOURCE_RUN_ID = "run_20260916T000000Z_90abcdef"
_SOURCE_ROOT = "c" * 64
_PLAN_RUN_ID = "run_20260916T000001Z_89abcdef"
_PLAN_ROOT = "e" * 64
_EXECUTION_ID = "exec_" + "d" * 32


def _inputs(tmp_path: Path) -> module.OperationalWebAnalysisInputs:
    return module.OperationalWebAnalysisInputs(
        source_run_path=tmp_path / "source-run",
        source_run_id=_SOURCE_RUN_ID,
        source_root_digest=_SOURCE_ROOT,
        comparison_plan_run_path=tmp_path / "effect-001-plan" / _PLAN_RUN_ID,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        qwen_model_path=tmp_path / "qwen.gguf",
        provider_output_root=tmp_path / "provider-output",
        analysis_output_root=tmp_path / "analysis-output",
    )


def _comparison_plan_run(
    tmp_path: Path,
    *,
    plan: ComparisonPlan | None = None,
    public_manifest: object | None = None,
    commitment: str | None = None,
    extra_artifact: bool = False,
    extra_event: bool = False,
    seal: bool = True,
) -> tuple[ComparisonPlan, Path, str, str]:
    value = plan or structured_fixture()
    store = RunStore.create(tmp_path / "plan-input", "effect-001-plan")
    store.write_json_create_only("plan.json", value.model_dump(mode="json"))
    store.write_json_create_only(
        "public-manifest.json",
        value.public_manifest() if public_manifest is None else public_manifest,
    )
    if extra_artifact:
        store.write_json_create_only("unexpected.json", {"unexpected": True})
    store.append_event(
        "comparison.preregistered",
        {"commitment": value.commitment if commitment is None else commitment},
    )
    if extra_event:
        store.append_event("comparison.unexpected", {})
    root_digest = store.seal().root_digest if seal else _PLAN_ROOT
    return value, store.path, store.run_id, root_digest


def test_cli_accepts_only_local_evidence_and_output_coordinates() -> None:
    destinations = {action.dest for action in module._parser()._actions if action.dest != "help"}

    assert destinations == {
        "source_run_path",
        "source_run_id",
        "source_root_digest",
        "comparison_plan_run_path",
        "comparison_plan_run_id",
        "comparison_plan_root_digest",
        "qwen_model_path",
        "provider_output_root",
        "analysis_output_root",
    }
    assert not destinations & {
        "target",
        "origin",
        "url",
        "destination",
        "retry",
        "api_key",
    }


def test_preflight_strictly_verifies_source_plan_images_and_qwen_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    values.source_run_path.mkdir()
    current = structured_fixture()
    plan = current.model_copy(
        update={
            "implementation": (
                current.implementation[0].model_copy(update={"sha256": "f" * 64}),
                *current.implementation[1:],
            )
        }
    )
    plan, plan_path, plan_run_id, plan_root = _comparison_plan_run(tmp_path, plan=plan)
    values = replace(
        values,
        comparison_plan_run_path=plan_path,
        comparison_plan_run_id=plan_run_id,
        comparison_plan_root_digest=plan_root,
    )
    values.qwen_model_path.write_bytes(b"not-read-by-fake")
    source = SimpleNamespace(run_path=values.source_run_path)
    calls: list[tuple[str, object]] = []

    def load_source(
        run_path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> Any:
        calls.append(
            (
                "source",
                (run_path, expected_run_id, expected_root_digest),
            )
        )
        return source

    def verify_images(runtime: object) -> None:
        calls.append(("images", runtime))

    def verify_model(path: Path, model: object) -> Path:
        calls.append(("model", (path, model)))
        return path.absolute()

    monkeypatch.setattr(module, "load_verified_authenticated_discovery", load_source)
    monkeypatch.setattr(module, "verify_images", verify_images)
    monkeypatch.setattr(module, "verify_model", verify_model)

    verified = module._verify_inputs(values)

    assert plan.implementation != comparison_pins()
    qwen = next(model for model in plan.models if model.name == "qwen3-4b")
    assert calls == [
        (
            "source",
            (values.source_run_path, _SOURCE_RUN_ID, _SOURCE_ROOT),
        ),
        ("images", plan.runtime),
        ("model", (values.qwen_model_path, qwen)),
    ]
    assert verified.source is source
    assert verified.plan == plan
    assert verified.comparison_plan_run_id == plan_run_id
    assert verified.comparison_plan_root_digest == plan_root
    assert verified.model == qwen
    assert verified.model_path == values.qwen_model_path.absolute()


def test_plan_loader_requires_independent_run_and_root_anchors(tmp_path: Path) -> None:
    _plan, run_path, run_id, root_digest = _comparison_plan_run(tmp_path)

    with pytest.raises(module.OperationalWebAnalysisError):
        module._load_verified_comparison_plan_run(
            run_path,
            expected_run_id="run_20260916T000002Z_01234567",
            expected_root_digest=root_digest,
        )
    with pytest.raises(
        module.OperationalWebAnalysisError,
        match="Run shape differs",
    ):
        module._load_verified_comparison_plan_run(
            run_path,
            expected_run_id=run_id,
            expected_root_digest="0" * 64,
        )


@pytest.mark.parametrize(
    "run_option",
    ["extra_artifact", "extra_event"],
)
def test_plan_loader_rejects_unexpected_sealed_run_grammar(
    tmp_path: Path,
    run_option: str,
) -> None:
    options = {run_option: True}
    _plan, run_path, run_id, root_digest = _comparison_plan_run(tmp_path, **options)

    with pytest.raises(module.OperationalWebAnalysisError):
        module._load_verified_comparison_plan_run(
            run_path,
            expected_run_id=run_id,
            expected_root_digest=root_digest,
        )


@pytest.mark.parametrize(
    ("fixture_options", "message"),
    [
        ({"public_manifest": {}}, "public manifest differs"),
        ({"commitment": "0" * 64}, "preregistration commitment differs"),
    ],
)
def test_plan_loader_rejects_cross_artifact_binding_mismatch(
    tmp_path: Path,
    fixture_options: dict[str, object],
    message: str,
) -> None:
    _plan, run_path, run_id, root_digest = _comparison_plan_run(
        tmp_path,
        **fixture_options,
    )

    with pytest.raises(module.OperationalWebAnalysisError, match=message):
        module._load_verified_comparison_plan_run(
            run_path,
            expected_run_id=run_id,
            expected_root_digest=root_digest,
        )


def test_plan_loader_rejects_tampered_or_unsealed_plan(tmp_path: Path) -> None:
    _plan, sealed_path, sealed_id, sealed_root = _comparison_plan_run(tmp_path / "sealed")
    (sealed_path / "plan.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(module.OperationalWebAnalysisError, match="strict verification"):
        module._load_verified_comparison_plan_run(
            sealed_path,
            expected_run_id=sealed_id,
            expected_root_digest=sealed_root,
        )

    _plan, unsealed_path, unsealed_id, unsealed_root = _comparison_plan_run(
        tmp_path / "unsealed",
        seal=False,
    )
    with pytest.raises(module.OperationalWebAnalysisError, match="strict verification"):
        module._load_verified_comparison_plan_run(
            unsealed_path,
            expected_run_id=unsealed_id,
            expected_root_digest=unsealed_root,
        )


def test_preflight_rejects_reused_output_before_loading_source_or_docker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    values.provider_output_root.mkdir()
    calls: list[str] = []
    monkeypatch.setattr(
        module,
        "load_verified_authenticated_discovery",
        lambda *_args, **_kwargs: calls.append("source"),
    )
    monkeypatch.setattr(module, "verify_images", lambda _runtime: calls.append("images"))
    monkeypatch.setattr(
        module,
        "verify_model",
        lambda _path, _model: calls.append("model"),
    )

    with pytest.raises(module.OperationalWebAnalysisError, match="must not already exist"):
        module._verify_inputs(values)

    assert calls == []


class _FakeModelRuntime:
    instances: ClassVar[list[_FakeModelRuntime]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.lifecycle = Lifecycle(owner="e" * 32)
        self.start_calls = 0
        self.cleanup_calls: list[list[str]] = []
        self.key_path = kwargs["key_file"]
        self.key_mode = stat.S_IMODE(self.key_path.stat().st_mode)
        self.key_value = self.key_path.read_text(encoding="ascii")
        self.instances.append(self)

    def start(self) -> None:
        self.start_calls += 1
        self.lifecycle = self.lifecycle.model_copy(
            update={
                "healthy": True,
                "internal_network": True,
                "read_only": True,
            }
        )

    def cleanup(self, execution_ids: list[str]) -> None:
        self.cleanup_calls.append(execution_ids)
        self.lifecycle = self.lifecycle.model_copy(
            update={
                "execution_ids": tuple(execution_ids),
                "cleanup_observed": True,
                "remaining_containers": (),
                "remaining_networks": (),
            }
        )


class _FakeAssembly:
    def __init__(self, model_runtime: _FakeModelRuntime, execution_context: object) -> None:
        self.model_runtime = model_runtime
        self.provider_runtime = SimpleNamespace(
            registration=object(),
            execution_context=execution_context,
        )
        self.cleanup_calls = 0

    @property
    def execution_ids(self) -> tuple[str, ...]:
        return (_EXECUTION_ID,)

    def cleanup(self) -> LocalWebAnalysisProviderCleanup:
        self.cleanup_calls += 1
        self.model_runtime.cleanup([_EXECUTION_ID])
        return LocalWebAnalysisProviderCleanup(
            execution_ids=(_EXECUTION_ID,),
            lifecycle=self.model_runtime.lifecycle,
        )


def _verified_inputs(
    tmp_path: Path,
) -> module.VerifiedOperationalWebAnalysisInputs:
    plan = structured_fixture()
    return module.VerifiedOperationalWebAnalysisInputs(
        source=SimpleNamespace(run_path=tmp_path / "source-run"),
        plan=plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        model=next(model for model in plan.models if model.name == "qwen3-4b"),
        model_path=tmp_path / "qwen.gguf",
        provider_output_root=tmp_path / "provider-output",
        analysis_output_root=tmp_path / "analysis-output",
    )


def _publications() -> tuple[SimpleNamespace, SimpleNamespace]:
    publication = SimpleNamespace(
        run_path=Path("/sealed/analysis"),
        run_id=_ANALYSIS_RUN_ID,
        root_digest=_ANALYSIS_ROOT,
    )
    provider_publication = SimpleNamespace(
        run_path=Path("/sealed/provider"),
        run_id=_PROVIDER_RUN_ID,
        root_digest=_PROVIDER_ROOT,
        execution_context=SimpleNamespace(context_digest="untrusted-returned-context"),
    )
    return publication, provider_publication


def _patch_success_or_failure_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure: bool,
) -> tuple[
    module.OperationalWebAnalysisInputs,
    module.VerifiedOperationalWebAnalysisInputs,
    dict[str, Any],
]:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    independent_context = SimpleNamespace(context_digest="f" * 64)
    publication, provider_publication = _publications()
    state: dict[str, Any] = {
        "invoke_calls": [],
        "success_loads": [],
        "failure_loads": [],
        "snapshot_calls": [],
        "builder_calls": [],
        "independent_context": independent_context,
    }
    _FakeModelRuntime.instances = []
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "LocalModelRuntime", _FakeModelRuntime)
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _bytes: "private-test-key")

    def build_assembly(**kwargs: Any) -> _FakeAssembly:
        state["builder_calls"].append(kwargs)
        for root_name in ("provider_store_root", "analysis_output_root"):
            root = kwargs[root_name]
            assert root.is_dir()
            assert list(root.iterdir()) == []
            assert stat.S_IMODE(root.stat().st_mode) == 0o700
        assembly = _FakeAssembly(kwargs["model_runtime"], independent_context)
        state["assembly"] = assembly
        return assembly

    def build_snapshot(source: object, **kwargs: Any) -> object:
        state["snapshot_calls"].append((source, kwargs))
        snapshot = object()
        state["snapshot"] = snapshot
        return snapshot

    class FakeInvocationRuntime:
        def __init__(self, *, provider_runtime: object) -> None:
            state["provider_runtime"] = provider_runtime

        async def invoke(self, **kwargs: Any) -> object:
            state["invoke_calls"].append(kwargs)
            if failure:
                raise WebAnalysisInvocationError(
                    "provider response rejected",
                    publication=publication,
                    provider_publication=provider_publication,
                )
            return SimpleNamespace(
                publication=publication,
                provider_publication=provider_publication,
            )

    def strict_success(run_path: Path, **kwargs: Any) -> object:
        state["success_loads"].append((run_path, kwargs))
        return SimpleNamespace(
            verification=SimpleNamespace(
                run_id=_ANALYSIS_RUN_ID,
                root_digest=_ANALYSIS_ROOT,
            ),
            provider_publication=SimpleNamespace(
                run_id=_PROVIDER_RUN_ID,
                root_digest=_PROVIDER_ROOT,
                execution_context=independent_context,
            ),
            semantics="compiled-proposal-not-authority",
            receipt=SimpleNamespace(response_state="untrusted-draft-compiled-not-admitted"),
            execution_authority=False,
            graph_admission_authority=False,
            finding_authority=False,
        )

    def strict_failure(run_path: Path, **kwargs: Any) -> object:
        state["failure_loads"].append((run_path, kwargs))
        return SimpleNamespace(
            verification=SimpleNamespace(
                run_id=_ANALYSIS_RUN_ID,
                root_digest=_ANALYSIS_ROOT,
            ),
            provider_publication=SimpleNamespace(
                run_id=_PROVIDER_RUN_ID,
                root_digest=_PROVIDER_ROOT,
                execution_context=independent_context,
            ),
            receipt=SimpleNamespace(
                terminal_state="provider-response-rejected",
                failure_class="provider-response-contract-error",
                automatic_redispatch_authorized=False,
                graph_admission_authorized=False,
                finding_authorized=False,
            ),
            semantics="terminal-failure-no-redispatch",
            execution_authority=False,
        )

    monkeypatch.setattr(module, "build_local_web_analysis_provider_runtime", build_assembly)
    monkeypatch.setattr(module, "build_web_analysis_snapshot", build_snapshot)
    monkeypatch.setattr(module, "WebAnalysisInvocationRuntime", FakeInvocationRuntime)
    monkeypatch.setattr(module, "load_verified_web_analysis_invocation", strict_success)
    monkeypatch.setattr(module, "load_verified_web_analysis_failure", strict_failure)
    return values, verified, state


@pytest.mark.parametrize(
    ("failure", "expected_status", "expected_success_loads", "expected_failure_loads"),
    [
        (False, "proposal-compiled", 1, 0),
        (True, "model-attempt-failed", 0, 1),
    ],
)
def test_runner_invokes_once_strictly_reloads_and_cleans_exact_owned_resources(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: bool,
    expected_status: str,
    expected_success_loads: int,
    expected_failure_loads: int,
) -> None:
    values, verified, state = _patch_success_or_failure_boundaries(
        tmp_path,
        monkeypatch,
        failure=failure,
    )

    result = asyncio.run(module.run_operational_web_analysis(values))

    assert len(state["invoke_calls"]) == 1
    invocation = state["invoke_calls"][0]
    assert invocation == {
        "source": verified.source,
        "snapshot": state["snapshot"],
        "expected_source_run_id": _SOURCE_RUN_ID,
        "expected_source_root_digest": _SOURCE_ROOT,
    }
    assert state["snapshot_calls"] == [
        (
            verified.source,
            {
                "expected_run_id": _SOURCE_RUN_ID,
                "expected_root_digest": _SOURCE_ROOT,
            },
        )
    ]
    builder = state["builder_calls"][0]
    assert builder["source"] is verified.source
    assert builder["expected_run_id"] == _SOURCE_RUN_ID
    assert builder["expected_root_digest"] == _SOURCE_ROOT
    assert builder["provider_store_root"] == values.provider_output_root
    assert builder["analysis_output_root"] == values.analysis_output_root
    assert builder["api_key"] == "private-test-key"
    assert len(state["success_loads"]) == expected_success_loads
    assert len(state["failure_loads"]) == expected_failure_loads
    strict_load = (state["failure_loads"] or state["success_loads"])[0]
    assert strict_load[0] == Path("/sealed/analysis")
    assert strict_load[1] == {
        "expected_run_id": _ANALYSIS_RUN_ID,
        "expected_root_digest": _ANALYSIS_ROOT,
        "source": verified.source,
        "expected_source_run_id": _SOURCE_RUN_ID,
        "expected_source_root_digest": _SOURCE_ROOT,
        "registration": state["assembly"].provider_runtime.registration,
        "provider_run_path": Path("/sealed/provider"),
        "expected_provider_run_id": _PROVIDER_RUN_ID,
        "expected_provider_root_digest": _PROVIDER_ROOT,
        "expected_provider_execution_context": state["independent_context"],
    }
    runtime = _FakeModelRuntime.instances[0]
    assert runtime.start_calls == 1
    assert runtime.cleanup_calls == [[_EXECUTION_ID]]
    assert runtime.key_mode == 0o600
    assert runtime.key_value == "private-test-key"
    assert not runtime.key_path.exists()
    assert state["assembly"].cleanup_calls == 1
    assert stat.S_IMODE(values.provider_output_root.stat().st_mode) == 0o700
    assert stat.S_IMODE(values.analysis_output_root.stat().st_mode) == 0o700

    assert result.succeeded is (not failure)
    assert result.summary["status"] == expected_status
    assert result.summary["invocationAttempts"] == 1
    assert result.summary["strictTerminalReloaded"] is True
    assert result.summary["cleanupObserved"] is True
    assert result.summary["comparisonPlanRunId"] == _PLAN_RUN_ID
    assert result.summary["comparisonPlanRootDigest"] == _PLAN_ROOT
    assert result.summary["targetRequestsPerformed"] is False
    assert result.summary["externalDeliveryPerformed"] is False
    assert result.summary["executionAuthority"] is False
    serialized = json.dumps(result.summary, sort_keys=True)
    assert "private-test-key" not in serialized
    assert str(tmp_path) not in serialized
    assert "Structured development-only test input" not in serialized


def test_partial_model_start_failure_cleans_only_the_owned_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    _FakeModelRuntime.instances = []

    class FailedStartRuntime(_FakeModelRuntime):
        def start(self) -> None:
            self.start_calls += 1
            raise RuntimeError("model start failed")

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "LocalModelRuntime", FailedStartRuntime)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_runtime",
        lambda **_kwargs: pytest.fail("assembly cannot be built after start failure"),
    )

    with pytest.raises(RuntimeError, match="model start failed"):
        asyncio.run(module.run_operational_web_analysis(values))

    runtime = _FakeModelRuntime.instances[0]
    assert runtime.cleanup_calls == [[]]
    assert runtime.lifecycle.clean
    assert not runtime.key_path.exists()
    assert not values.provider_output_root.exists()
    assert not values.analysis_output_root.exists()


def test_fresh_root_race_fails_before_assembly_and_cleans_model(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    _FakeModelRuntime.instances = []
    builder_calls: list[dict[str, Any]] = []

    class RacedRootRuntime(_FakeModelRuntime):
        def start(self) -> None:
            super().start()
            values.provider_output_root.mkdir()

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "LocalModelRuntime", RacedRootRuntime)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_runtime",
        lambda **kwargs: builder_calls.append(kwargs),
    )

    with pytest.raises(module.OperationalWebAnalysisError, match="could not be reserved"):
        asyncio.run(module.run_operational_web_analysis(values))

    assert builder_calls == []
    assert _FakeModelRuntime.instances[0].cleanup_calls == [[]]
    assert not values.analysis_output_root.exists()


def test_cancellation_is_strictly_reloaded_cleaned_and_re_raised(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values, _verified, state = _patch_success_or_failure_boundaries(
        tmp_path,
        monkeypatch,
        failure=False,
    )
    publication, provider_publication = _publications()
    cancelled = WebAnalysisCancelledError(
        publication=publication,
        provider_publication=provider_publication,
    )

    class CancelledInvocationRuntime:
        def __init__(self, *, provider_runtime: object) -> None:
            state["provider_runtime"] = provider_runtime

        async def invoke(self, **kwargs: Any) -> object:
            state["invoke_calls"].append(kwargs)
            raise cancelled

    monkeypatch.setattr(
        module,
        "WebAnalysisInvocationRuntime",
        CancelledInvocationRuntime,
    )

    with pytest.raises(WebAnalysisCancelledError) as raised:
        asyncio.run(module.run_operational_web_analysis(values))

    assert raised.value is cancelled
    assert len(state["invoke_calls"]) == 1
    assert state["success_loads"] == []
    assert len(state["failure_loads"]) == 1
    assert (
        state["failure_loads"][0][1]["expected_provider_execution_context"]
        is state["independent_context"]
    )
    assert _FakeModelRuntime.instances[0].cleanup_calls == [[_EXECUTION_ID]]
    summary = module._cancelled_summary(cancelled)
    assert summary["strictTerminalReloaded"] is True
    assert summary["cleanupObserved"] is True
    assert summary["status"] == "cancelled"


def test_operational_error_summary_never_serializes_exception_text() -> None:
    sensitive = RuntimeError("secret=/tmp/private-model target=http://example.invalid")

    payload = json.dumps(module._error_summary(sensitive), sort_keys=True)

    assert "RuntimeError" in payload
    assert "private-model" not in payload
    assert "example.invalid" not in payload
