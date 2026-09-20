from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, ClassVar, cast

import pytest
from test_llm_effectiveness_structured import structured_fixture

import scripts.operational_skill_bound_web_analysis as module
from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.skills.catalog import built_in_proposal_analysis_skill_registry
from pajin.web_assessment.analysis_local import LocalWebAnalysisProviderCleanup
from pajin.web_assessment.analysis_skill_runtime import SkillBoundWebAnalysisRuntimeError
from pajin.web_assessment.analysis_transport import web_analysis_transport_runtime_pin

_SOURCE_RUN_ID = "run_20260916T000000Z_90abcdef"
_SOURCE_ROOT = "c" * 64
_PLAN_RUN_ID = "run_20260916T000001Z_89abcdef"
_PLAN_ROOT = "e" * 64
_SKILL_RUN_ID = "run_20260916T000002Z_76543210"
_SKILL_ROOT = "f" * 64
_ANALYSIS_RUN_ID = "run_20260916T010101Z_1234abcd"
_ANALYSIS_ROOT = "a" * 64
_PROVIDER_RUN_ID = "run_20260916T010100Z_5678abcd"
_PROVIDER_ROOT = "b" * 64
_EXECUTION_ID = "exec_" + "d" * 32
_EXTERNAL_NETWORK = "pajin-effect-" + "1" * 32


def _inputs(tmp_path: Path) -> module.OperationalSkillBoundWebAnalysisInputs:
    return module.OperationalSkillBoundWebAnalysisInputs(
        source_run_path=tmp_path / "source-run",
        source_run_id=_SOURCE_RUN_ID,
        source_root_digest=_SOURCE_ROOT,
        comparison_plan_run_path=tmp_path / "effect-001-plan" / _PLAN_RUN_ID,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        skill_run_path=tmp_path / "skill-run",
        skill_run_id=_SKILL_RUN_ID,
        skill_root_digest=_SKILL_ROOT,
        transport_pin_path=tmp_path / "transport-pin.json",
        expected_transport_pin_digest="9" * 64,
        qwen_model_path=tmp_path / "qwen.gguf",
        provider_output_root=tmp_path / "provider-output",
        analysis_output_root=tmp_path / "analysis-output",
    )


def _base_verified(tmp_path: Path) -> SimpleNamespace:
    plan = structured_fixture()
    return SimpleNamespace(
        source=SimpleNamespace(run_path=tmp_path / "source-run"),
        plan=plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        model=next(model for model in plan.models if model.name == "qwen3-4b"),
        model_path=tmp_path / "qwen.gguf",
        provider_output_root=tmp_path / "provider-output",
        analysis_output_root=tmp_path / "analysis-output",
    )


def _verified_inputs(
    tmp_path: Path,
) -> module.VerifiedOperationalSkillBoundWebAnalysisInputs:
    base = _base_verified(tmp_path)
    transport = web_analysis_transport_runtime_pin(
        base.plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    snapshot = SimpleNamespace(snapshot_digest="8" * 64)
    skill_run = SimpleNamespace(
        snapshot=snapshot,
        verification=SimpleNamespace(run_id=_SKILL_RUN_ID, root_digest=_SKILL_ROOT),
        index=SimpleNamespace(selected_skill_count=4),
    )
    return module.VerifiedOperationalSkillBoundWebAnalysisInputs(
        source=cast(Any, base.source),
        plan=base.plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        skill_run=cast(Any, skill_run),
        expected_registry_ref=built_in_proposal_analysis_skill_registry().reference(),
        expected_policy_digest="8" * 64,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
        model=base.model,
        model_path=base.model_path,
        provider_output_root=base.provider_output_root,
        analysis_output_root=base.analysis_output_root,
    )


def test_cli_accepts_only_local_successor_evidence_and_output_coordinates() -> None:
    destinations = {action.dest for action in module._parser()._actions if action.dest != "help"}

    assert destinations == {
        "source_run_path",
        "source_run_id",
        "source_root_digest",
        "comparison_plan_run_path",
        "comparison_plan_run_id",
        "comparison_plan_root_digest",
        "skill_run_path",
        "skill_run_id",
        "skill_root_digest",
        "transport_pin_path",
        "expected_transport_pin_digest",
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
        "expected_external_network",
        "expected_policy_digest",
    }


def test_preflight_uses_code_owned_skill_anchors_and_successor_image_runtime(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    base = _base_verified(tmp_path)
    transport = web_analysis_transport_runtime_pin(
        base.plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    values = replace(
        values,
        expected_transport_pin_digest=transport.pin_digest,
    )
    registry = built_in_proposal_analysis_skill_registry().reference()
    policy_digest = "8" * 64
    expected_snapshot = SimpleNamespace(
        selection_policy=SimpleNamespace(registry=registry, policy_digest=policy_digest)
    )
    skill_run = SimpleNamespace(snapshot=expected_snapshot)
    calls: dict[str, Any] = {}
    registration = object()
    chat = object()

    monkeypatch.setattr(module._legacy, "_verify_inputs", lambda _values: base)

    def load_pin(path: Path, **kwargs: Any) -> object:
        calls["pin"] = (path, kwargs)
        return transport

    def verify_images(runtime: object) -> None:
        calls["runtime"] = runtime

    def build_snapshot(source: object, **kwargs: Any) -> object:
        calls["snapshot"] = (source, kwargs)
        return expected_snapshot

    def load_skill(path: Path, **kwargs: Any) -> object:
        calls["skill"] = (path, kwargs)
        return skill_run

    monkeypatch.setattr(module, "load_verified_web_analysis_transport_runtime_pin", load_pin)
    monkeypatch.setattr(module, "verify_images", verify_images)
    monkeypatch.setattr(module, "build_skill_bound_web_analysis_snapshot", build_snapshot)
    monkeypatch.setattr(module, "load_verified_web_analysis_skill_projection", load_skill)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_registration",
        lambda **kwargs: calls.setdefault("registration", kwargs) and registration,
    )
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_chat_request",
        lambda snapshot: calls.setdefault("chat", snapshot) and chat,
    )

    def require_budget(request: object, **kwargs: object) -> None:
        calls["budget"] = (request, kwargs)

    def require_context(request: object, **kwargs: object) -> None:
        calls["context"] = (request, kwargs)

    monkeypatch.setattr(
        module,
        "require_local_web_analysis_request_fits_model_budget",
        require_budget,
    )
    monkeypatch.setattr(
        module,
        "require_local_web_analysis_request_fits_runtime_context",
        require_context,
    )

    verified = module._verify_inputs(values)

    assert calls["pin"] == (
        values.transport_pin_path,
        {
            "runtime": base.plan.runtime,
            "expected_pin_digest": transport.pin_digest,
        },
    )
    successor_runtime = calls["runtime"]
    assert successor_runtime.worker_image == transport.worker_image
    assert successor_runtime.proxy_image == transport.proxy_image
    assert successor_runtime.model_image == base.plan.runtime.model_image
    assert calls["snapshot"] == (
        base.source,
        {
            "expected_source_run_id": _SOURCE_RUN_ID,
            "expected_source_root_digest": _SOURCE_ROOT,
        },
    )
    assert calls["skill"][1]["expected_registry_ref"] == registry
    assert calls["skill"][1]["expected_policy_digest"] == policy_digest
    assert verified.expected_registry_ref == registry
    assert verified.expected_policy_digest == policy_digest
    assert verified.transport_pin == transport
    assert calls["registration"] == {
        "runtime": base.plan.runtime,
        "model": base.model,
    }
    assert calls["chat"] is expected_snapshot
    assert calls["budget"] == (chat, {"registration": registration})
    assert calls["context"] == (
        chat,
        {"registration": registration, "runtime": base.plan.runtime},
    )


def test_successor_budget_mismatch_fails_before_model_start_or_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    base = _base_verified(tmp_path)
    transport = web_analysis_transport_runtime_pin(
        base.plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    values = replace(values, expected_transport_pin_digest=transport.pin_digest)
    registry = built_in_proposal_analysis_skill_registry().reference()
    expected_snapshot = SimpleNamespace(
        selection_policy=SimpleNamespace(registry=registry, policy_digest="8" * 64)
    )
    skill_run = SimpleNamespace(snapshot=expected_snapshot)
    calls: list[str] = []

    monkeypatch.setattr(module._legacy, "_verify_inputs", lambda _values: base)
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_transport_runtime_pin",
        lambda *_args, **_kwargs: transport,
    )
    monkeypatch.setattr(module, "verify_images", lambda _runtime: None)
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_snapshot",
        lambda *_args, **_kwargs: expected_snapshot,
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_skill_projection",
        lambda *_args, **_kwargs: skill_run,
    )
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_registration",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_chat_request",
        lambda _snapshot: object(),
    )

    def reject_budget(*_args: object, **_kwargs: object) -> None:
        calls.append("budget")
        raise ValueError("maximum model-token budget exceeded")

    class ForbiddenRuntime:
        def __init__(self, **_kwargs: object) -> None:
            calls.append("model")

    monkeypatch.setattr(
        module,
        "require_local_web_analysis_request_fits_model_budget",
        reject_budget,
    )
    monkeypatch.setattr(module, "LocalModelRuntime", ForbiddenRuntime)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_runtime",
        lambda **_kwargs: calls.append("assembly"),
    )

    with pytest.raises(module.OperationalSkillBoundWebAnalysisError):
        asyncio.run(module.run_operational_skill_bound_web_analysis(values))

    assert calls == ["budget"]


def test_successor_context_mismatch_fails_before_model_start_or_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    base = _base_verified(tmp_path)
    transport = web_analysis_transport_runtime_pin(
        base.plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    values = replace(values, expected_transport_pin_digest=transport.pin_digest)
    registry = built_in_proposal_analysis_skill_registry().reference()
    expected_snapshot = SimpleNamespace(
        selection_policy=SimpleNamespace(registry=registry, policy_digest="8" * 64)
    )
    skill_run = SimpleNamespace(snapshot=expected_snapshot)
    calls: list[str] = []

    monkeypatch.setattr(module._legacy, "_verify_inputs", lambda _values: base)
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_transport_runtime_pin",
        lambda *_args, **_kwargs: transport,
    )
    monkeypatch.setattr(module, "verify_images", lambda _runtime: None)
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_snapshot",
        lambda *_args, **_kwargs: expected_snapshot,
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_skill_projection",
        lambda *_args, **_kwargs: skill_run,
    )
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_registration",
        lambda **_kwargs: object(),
    )
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_chat_request",
        lambda _snapshot: object(),
    )
    monkeypatch.setattr(
        module,
        "require_local_web_analysis_request_fits_model_budget",
        lambda *_args, **_kwargs: calls.append("budget"),
    )

    def reject_context(*_args: object, **_kwargs: object) -> None:
        calls.append("context")
        raise ValueError("pinned model context proof is absent")

    class ForbiddenRuntime:
        def __init__(self, **_kwargs: object) -> None:
            calls.append("model")

    monkeypatch.setattr(
        module,
        "require_local_web_analysis_request_fits_runtime_context",
        reject_context,
    )
    monkeypatch.setattr(module, "LocalModelRuntime", ForbiddenRuntime)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_runtime",
        lambda **_kwargs: calls.append("assembly"),
    )

    with pytest.raises(module.OperationalSkillBoundWebAnalysisError):
        asyncio.run(module.run_operational_skill_bound_web_analysis(values))

    assert calls == ["budget", "context"]


def test_transport_digest_mismatch_fails_before_model_runtime_or_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    base = _base_verified(tmp_path)
    calls: list[str] = []
    monkeypatch.setattr(module._legacy, "_verify_inputs", lambda _values: base)

    def reject_pin(*_args: object, **_kwargs: object) -> object:
        calls.append("pin")
        raise ValueError("independent digest differs")

    class ForbiddenRuntime:
        def __init__(self, **_kwargs: object) -> None:
            calls.append("model")

    monkeypatch.setattr(module, "load_verified_web_analysis_transport_runtime_pin", reject_pin)
    monkeypatch.setattr(module, "LocalModelRuntime", ForbiddenRuntime)
    monkeypatch.setattr(
        module,
        "build_local_web_analysis_provider_runtime",
        lambda **_kwargs: calls.append("assembly"),
    )

    with pytest.raises(module.OperationalSkillBoundWebAnalysisError):
        asyncio.run(module.run_operational_skill_bound_web_analysis(values))

    assert calls == ["pin"]


class _FakeModelRuntime:
    instances: ClassVar[list[_FakeModelRuntime]] = []

    def __init__(self, **kwargs: Any) -> None:
        self.kwargs = kwargs
        self.network_name = _EXTERNAL_NETWORK
        self.lifecycle = Lifecycle(owner="1" * 32)
        self.start_calls = 0
        self.cleanup_calls: list[list[str]] = []
        self.key_path = kwargs["key_file"]
        self.key_value = self.key_path.read_text(encoding="ascii")
        self.instances.append(self)

    def start(self) -> None:
        self.start_calls += 1

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
    def __init__(self, model_runtime: _FakeModelRuntime, base_context: object) -> None:
        self.model_runtime = model_runtime
        self.provider_runtime = SimpleNamespace(
            registration=SimpleNamespace(provider_id="web-analysis-local"),
            execution_context=base_context,
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


def _patch_runner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    failure: bool,
) -> tuple[
    module.OperationalSkillBoundWebAnalysisInputs,
    module.VerifiedOperationalSkillBoundWebAnalysisInputs,
    dict[str, Any],
]:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    values = replace(
        values,
        expected_transport_pin_digest=verified.expected_transport_pin_digest,
    )
    state: dict[str, Any] = {
        "builders": [],
        "binders": [],
        "invocations": [],
        "success_loads": [],
        "failure_loads": [],
    }
    base_context = SimpleNamespace(context_digest="3" * 64)
    successor_context = SimpleNamespace(context_digest="4" * 64)
    analysis_publication = SimpleNamespace(
        run_path=Path("/sealed/analysis"),
        run_id=_ANALYSIS_RUN_ID,
        root_digest=_ANALYSIS_ROOT,
    )
    provider_publication = SimpleNamespace(
        run_path=Path("/sealed/provider"),
        run_id=_PROVIDER_RUN_ID,
        root_digest=_PROVIDER_ROOT,
    )
    _FakeModelRuntime.instances = []
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "LocalModelRuntime", _FakeModelRuntime)
    monkeypatch.setattr(module.secrets, "token_urlsafe", lambda _size: "private-test-key")

    def build(**kwargs: Any) -> _FakeAssembly:
        state["builders"].append(kwargs)
        assembly = _FakeAssembly(kwargs["model_runtime"], base_context)
        state["assembly"] = assembly
        return assembly

    def bind(assembly: _FakeAssembly, **kwargs: Any) -> object:
        state["binders"].append((assembly, kwargs))
        bound = SimpleNamespace(
            base_runtime=assembly.provider_runtime,
            execution_context=successor_context,
            expected_external_network=kwargs["expected_external_network"],
        )
        state["bound"] = bound
        return bound

    class FakeInvocation:
        def __init__(self, *, provider_runtime: object) -> None:
            assert provider_runtime is state["bound"]

        async def invoke(self, **kwargs: Any) -> object:
            state["invocations"].append(kwargs)
            if failure:
                raise SkillBoundWebAnalysisRuntimeError(
                    "fixture terminal failure",
                    publication=analysis_publication,
                    provider_publication=provider_publication,
                )
            return SimpleNamespace(
                publication=analysis_publication,
                provider_publication=provider_publication,
            )

    def success_loader(path: Path, **kwargs: Any) -> object:
        state["success_loads"].append((path, kwargs))
        return SimpleNamespace(
            execution_authority=False,
            graph_admission_authority=False,
            finding_authority=False,
            report_delivery_authority=False,
            target_request_count=0,
            dispatch_count=1,
            semantics="skill-bound-compiled-proposal-not-authority",
            verification=SimpleNamespace(
                run_id=_ANALYSIS_RUN_ID,
                root_digest=_ANALYSIS_ROOT,
            ),
            provider_publication=provider_publication,
            provider_execution_context=successor_context,
            receipt=SimpleNamespace(response_state="skill-bound-draft-compiled-not-admitted"),
        )

    def failure_loader(path: Path, **kwargs: Any) -> object:
        state["failure_loads"].append((path, kwargs))
        return SimpleNamespace(
            execution_authority=False,
            automatic_redispatch_authority=False,
            target_request_count=0,
            dispatch_count=1,
            semantics="terminal-skill-bound-failure-no-redispatch",
            verification=SimpleNamespace(
                run_id=_ANALYSIS_RUN_ID,
                root_digest=_ANALYSIS_ROOT,
            ),
            provider_publication=provider_publication,
            provider_execution_context=successor_context,
            receipt=SimpleNamespace(
                terminal_state="provider-response-rejected",
                graph_admission_authorized=False,
                finding_authorized=False,
                report_delivery_authorized=False,
            ),
        )

    monkeypatch.setattr(module, "build_local_web_analysis_provider_runtime", build)
    monkeypatch.setattr(module, "bind_skill_bound_web_analysis_provider_runtime", bind)
    monkeypatch.setattr(module, "SkillBoundWebAnalysisInvocationRuntime", FakeInvocation)
    monkeypatch.setattr(module, "load_verified_skill_bound_web_analysis_invocation", success_loader)
    monkeypatch.setattr(module, "load_verified_skill_bound_web_analysis_failure", failure_loader)
    return values, verified, state


@pytest.mark.parametrize(
    ("failure", "status", "success_loads", "failure_loads"),
    [
        (False, "skill-proposal-compiled", 1, 0),
        (True, "skill-model-attempt-failed", 0, 1),
    ],
)
def test_runner_propagates_independent_anchors_invokes_once_and_cleans(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: bool,
    status: str,
    success_loads: int,
    failure_loads: int,
) -> None:
    values, verified, state = _patch_runner(tmp_path, monkeypatch, failure=failure)

    result = asyncio.run(module.run_operational_skill_bound_web_analysis(values))

    assert len(state["builders"]) == 1
    builder = state["builders"][0]
    assert builder["transport_pin"] == verified.transport_pin
    assert builder["expected_transport_pin_digest"] == (verified.expected_transport_pin_digest)
    assert len(state["binders"]) == 1
    assert state["binders"][0][1] == {
        "transport_pin": verified.transport_pin,
        "expected_transport_pin_digest": verified.expected_transport_pin_digest,
        "expected_external_network": _EXTERNAL_NETWORK,
    }
    assert len(state["invocations"]) == 1
    invocation = state["invocations"][0]
    assert invocation["source"] is verified.source
    assert invocation["skill_run"] is verified.skill_run
    assert invocation["transport_pin"] == verified.transport_pin
    assert invocation["expected_registry_ref"] == verified.expected_registry_ref
    assert invocation["expected_policy_digest"] == verified.expected_policy_digest
    assert invocation["expected_transport_pin_digest"] == (verified.expected_transport_pin_digest)
    assert len(state["success_loads"]) == success_loads
    assert len(state["failure_loads"]) == failure_loads
    strict_call = (state["success_loads"] or state["failure_loads"])[0]
    assert strict_call[1]["expected_external_network"] == _EXTERNAL_NETWORK
    assert strict_call[1]["expected_transport_pin_digest"] == (
        verified.expected_transport_pin_digest
    )
    runtime = _FakeModelRuntime.instances[0]
    assert runtime.start_calls == 1
    assert runtime.cleanup_calls == [[_EXECUTION_ID]]
    assert state["assembly"].cleanup_calls == 1
    assert result.summary["status"] == status
    assert result.summary["providerDispatchCount"] == 1
    assert result.summary["transportPinDigest"] == verified.expected_transport_pin_digest
    assert result.summary["skillRunId"] == _SKILL_RUN_ID
    assert result.summary["targetRequestsPerformed"] is False
    assert result.summary["externalDeliveryPerformed"] is False
    serialized = json.dumps(result.summary, sort_keys=True)
    assert "private-test-key" not in serialized
    assert str(tmp_path) not in serialized
