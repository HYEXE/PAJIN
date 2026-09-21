from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from test_llm_effectiveness_structured import structured_fixture

import pajin.benchmark.effectiveness.docker as effectiveness_docker
import pajin.web_assessment.analysis_capacity as analysis_capacity
import pajin.web_assessment.analysis_local as analysis_local
import scripts.operational_skill_bound_web_capacity as module
from pajin.runtime.pinned_workspace import active_pinned_workspace_identity
from pajin.skills.catalog import built_in_proposal_analysis_skill_registry
from pajin.web_assessment.analysis_skill_projection import (
    _create_web_analysis_skill_projection_run_with_loader,
)
from pajin.web_assessment.analysis_transport import web_analysis_transport_runtime_pin
from tests.test_web_analysis_proposal import _synthetic_loader, _verified_source

_SOURCE_RUN_ID = "run_20260916T000000Z_90abcdef"
_SOURCE_ROOT = "c" * 64
_PLAN_RUN_ID = "run_20260916T000001Z_89abcdef"
_PLAN_ROOT = "e" * 64
_SKILL_RUN_ID = "run_20260916T000002Z_76543210"
_SKILL_ROOT = "f" * 64
_CAPACITY_RUN_ID = "run_20260921T010101Z_1234abcd"
_CAPACITY_ROOT = "a" * 64


def _inputs(tmp_path: Path) -> module.OperationalSkillBoundWebCapacityInputs:
    return module.OperationalSkillBoundWebCapacityInputs(
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
        output_root=tmp_path / "capacity-output",
    )


def _verified_inputs(
    tmp_path: Path,
) -> module.VerifiedOperationalSkillBoundWebCapacityInputs:
    plan = structured_fixture()
    model = next(item for item in plan.models if item.name == "qwen3-4b")
    transport = web_analysis_transport_runtime_pin(
        plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    registry = built_in_proposal_analysis_skill_registry().reference()
    snapshot = SimpleNamespace(snapshot_digest="8" * 64)
    skill_run = SimpleNamespace(
        snapshot=snapshot,
        verification=SimpleNamespace(run_id=_SKILL_RUN_ID, root_digest=_SKILL_ROOT),
        index=SimpleNamespace(selected_skill_count=4),
    )
    return module.VerifiedOperationalSkillBoundWebCapacityInputs(
        source=cast(Any, SimpleNamespace(run_path=tmp_path / "source-run")),
        plan=plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        skill_run=cast(Any, skill_run),
        expected_registry_ref=registry,
        expected_policy_digest="8" * 64,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
        model=model,
        model_path=tmp_path / "qwen.gguf",
        output_root=tmp_path / "capacity-output",
        compact_projection=SimpleNamespace(projection_digest="1" * 64),
        chat_request=SimpleNamespace(request_digest="2" * 64),
    )


def _capacity_run(tmp_path: Path, *, fits_context: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        run_path=tmp_path / "capacity-output" / "web-analysis-capacity" / _CAPACITY_RUN_ID,
        run_id=_CAPACITY_RUN_ID,
        root_digest=_CAPACITY_ROOT,
        projection_digest="1" * 64,
        pin=SimpleNamespace(
            pin_digest="5" * 64,
            chat_request_digest="2" * 64,
            tokenizer_runtime_digest="3" * 64,
            context_tokens=4096,
            provider_dispatch_authority=False,
            target_request_authority=False,
            execution_authority=False,
            graph_admission_authority=False,
            finding_authority=False,
            report_delivery_authority=False,
        ),
        evidence=SimpleNamespace(evidence_digest="6" * 64),
        proof=SimpleNamespace(
            proof_digest="7" * 64,
            evidence_digest="6" * 64,
            request_digest="2" * 64,
            chat_template_digest="4" * 64,
            prompt_tokens=2048,
            completion_tokens=1024,
            total_tokens=3072,
            remaining_tokens=1024,
            conservative_campaign_prompt_tokens=20_000,
            conservative_campaign_total_tokens=21_024,
            fits=fits_context,
            model_inference_performed=False,
            provider_dispatch=False,
            target_requests=0,
        ),
        index=SimpleNamespace(
            index_digest="8" * 64,
            evidence_digest="6" * 64,
            proof_digest="7" * 64,
            model_inference_performed=False,
            provider_dispatch=False,
            target_requests=0,
        ),
    )


def _capacity_api(
    *,
    create: Any,
    load: Any,
    pin: object | None = None,
) -> module._CapacityApi:
    expected_pin = pin or SimpleNamespace(pin_digest="5" * 64)
    return module._CapacityApi(
        build_pin=lambda **_kwargs: expected_pin,
        tokenizer_backend=lambda **_kwargs: object(),
        create_run=create,
        load_run=load,
        system_sentinel="pajin-compact-skill-bound-system-v1",
        user_sentinel="pajin-compact-skill-bound-user-v1",
    )


class _OfflineTokenizer:
    def start(self, _pin: object) -> None:
        return None

    def get_props(self) -> object:
        return {
            "chat_template": "{{ system }}{{ user }}",
            "default_generation_settings": {"n_ctx": 4096},
        }

    def apply_template(self, messages: object) -> object:
        values = cast(list[dict[str, object]], messages)
        return {"prompt": "".join(cast(str, item["content"]) for item in values)}

    def tokenize(self, _formatted_prompt: str) -> object:
        return {"tokens": list(range(1_505))}

    def cleanup(self) -> None:
        return None

    def verify_absent(self) -> None:
        return None


class _OutputRootSwapTokenizer(_OfflineTokenizer):
    def __init__(self, *, output_root: Path, parked: Path, victim: Path) -> None:
        self.output_root = output_root
        self.parked = parked
        self.victim = victim
        self.cleanup_called = False
        self.absence_checked = False

    def start(self, _pin: object) -> None:
        self.output_root.rename(self.parked)
        self.victim.mkdir()
        self.output_root.symlink_to(self.victim, target_is_directory=True)

    def cleanup(self) -> None:
        self.cleanup_called = True

    def verify_absent(self) -> None:
        self.absence_checked = True


def test_cli_accepts_only_immutable_inputs_and_one_capacity_output() -> None:
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
        "output_root",
    }
    assert not destinations & {
        "target",
        "origin",
        "url",
        "destination",
        "retry",
        "api_key",
        "provider_output_root",
        "analysis_output_root",
    }


def test_preflight_strictly_orders_all_anchors_before_compact_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    plan = structured_fixture()
    model = next(item for item in plan.models if item.name == "qwen3-4b")
    transport = web_analysis_transport_runtime_pin(
        plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    registry = built_in_proposal_analysis_skill_registry().reference()
    policy_digest = "8" * 64
    snapshot = SimpleNamespace(
        selection_policy=SimpleNamespace(registry=registry, policy_digest=policy_digest)
    )
    source = SimpleNamespace(run_path=values.source_run_path)
    skill_run = SimpleNamespace(snapshot=snapshot)
    compact = object()
    request = object()
    calls: list[tuple[str, object]] = []

    monkeypatch.setattr(
        module._legacy,
        "_fresh_output_root",
        lambda path, **kwargs: calls.append(("fresh", (path, kwargs))) or path.absolute(),
    )
    monkeypatch.setattr(
        module,
        "load_verified_authenticated_discovery",
        lambda path, **kwargs: calls.append(("source", (path, kwargs))) or source,
    )
    monkeypatch.setattr(
        module._legacy,
        "_load_verified_comparison_plan_run",
        lambda path, **kwargs: calls.append(("plan", (path, kwargs))) or plan,
    )
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_snapshot",
        lambda loaded, **kwargs: calls.append(("snapshot", (loaded, kwargs))) or snapshot,
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_skill_projection",
        lambda path, **kwargs: calls.append(("skill", (path, kwargs))) or skill_run,
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_transport_runtime_pin",
        lambda path, **kwargs: calls.append(("transport", (path, kwargs))) or transport,
    )
    monkeypatch.setattr(
        module,
        "_require_output_outside_inputs",
        lambda output, **kwargs: calls.append(("overlap", (output, kwargs))),
    )
    monkeypatch.setattr(
        module,
        "verify_images",
        lambda runtime: calls.append(("plan-images", runtime)),
    )
    monkeypatch.setattr(
        module,
        "_verify_transport_images",
        lambda value, **kwargs: calls.append(("transport-images", (value, kwargs))),
    )
    monkeypatch.setattr(
        module._legacy,
        "_qwen_model_pin",
        lambda value: calls.append(("model-pin", value)) or model,
    )
    monkeypatch.setattr(
        module,
        "verify_model",
        lambda path, value: calls.append(("model-file", (path, value))) or path.absolute(),
    )
    monkeypatch.setattr(
        module,
        "_build_compact_projection",
        lambda value: calls.append(("compact", value)) or compact,
    )
    monkeypatch.setattr(
        module,
        "_build_compact_chat_request",
        lambda value: calls.append(("request", value)) or request,
    )

    verified = module._verify_inputs(values)

    assert [name for name, _ in calls] == [
        "fresh",
        "source",
        "plan",
        "snapshot",
        "skill",
        "transport",
        "overlap",
        "plan-images",
        "transport-images",
        "model-pin",
        "model-file",
        "compact",
        "request",
    ]
    skill_kwargs = cast(dict[str, Any], calls[4][1][1])
    assert skill_kwargs["expected_run_id"] == _SKILL_RUN_ID
    assert skill_kwargs["expected_root_digest"] == _SKILL_ROOT
    assert skill_kwargs["expected_registry_ref"] == registry
    assert skill_kwargs["expected_policy_digest"] == policy_digest
    transport_kwargs = cast(dict[str, Any], calls[5][1][1])
    assert transport_kwargs == {
        "runtime": plan.runtime,
        "expected_pin_digest": values.expected_transport_pin_digest,
    }
    assert verified.compact_projection is compact
    assert verified.chat_request is request
    assert calls[-1] == ("request", snapshot)
    assert verified.model_path == values.qwen_model_path.absolute()


@pytest.mark.parametrize("drift", ["source", "plan", "skill", "transport", "model"])
def test_anchor_drift_fails_before_capacity_backend(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    drift: str,
) -> None:
    values = _inputs(tmp_path)
    plan = structured_fixture()
    model = next(item for item in plan.models if item.name == "qwen3-4b")
    transport = web_analysis_transport_runtime_pin(
        plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    registry = built_in_proposal_analysis_skill_registry().reference()
    snapshot = SimpleNamespace(
        selection_policy=SimpleNamespace(registry=registry, policy_digest="8" * 64)
    )
    source = SimpleNamespace(run_path=values.source_run_path)
    skill_run = SimpleNamespace(snapshot=snapshot)
    backend_calls: list[str] = []

    def selected(name: str, value: object) -> object:
        if drift == name:
            raise ValueError(f"{name} anchor drift")
        return value

    monkeypatch.setattr(module._legacy, "_fresh_output_root", lambda path, **_kwargs: path)
    monkeypatch.setattr(
        module,
        "load_verified_authenticated_discovery",
        lambda *_args, **_kwargs: selected("source", source),
    )
    monkeypatch.setattr(
        module._legacy,
        "_load_verified_comparison_plan_run",
        lambda *_args, **_kwargs: selected("plan", plan),
    )
    monkeypatch.setattr(
        module,
        "build_skill_bound_web_analysis_snapshot",
        lambda *_args, **_kwargs: snapshot,
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_skill_projection",
        lambda *_args, **_kwargs: selected("skill", skill_run),
    )
    monkeypatch.setattr(
        module,
        "load_verified_web_analysis_transport_runtime_pin",
        lambda *_args, **_kwargs: selected("transport", transport),
    )
    monkeypatch.setattr(module, "_require_output_outside_inputs", lambda *_a, **_k: None)
    monkeypatch.setattr(module, "verify_images", lambda _runtime: None)
    monkeypatch.setattr(
        module,
        "_verify_transport_images",
        lambda *_args, **_kwargs: None,
    )
    monkeypatch.setattr(module._legacy, "_qwen_model_pin", lambda _plan: model)
    monkeypatch.setattr(
        module,
        "verify_model",
        lambda path, _model: selected("model", path),
    )
    monkeypatch.setattr(module, "_build_compact_projection", lambda _snapshot: object())
    monkeypatch.setattr(module, "_build_compact_chat_request", lambda _projection: object())
    monkeypatch.setattr(
        module,
        "_capacity_api",
        lambda: backend_calls.append("capacity") or (object(), object()),
    )

    with pytest.raises(module.OperationalSkillBoundWebCapacityError):
        module.run_operational_skill_bound_web_capacity(values)

    assert backend_calls == []
    assert not values.output_root.exists()


@pytest.mark.parametrize(
    "input_name",
    [
        "source_run_path",
        "comparison_plan_run_path",
        "skill_run_path",
        "transport_pin_path",
        "qwen_model_path",
    ],
)
def test_output_root_cannot_overlap_any_immutable_input(
    tmp_path: Path,
    input_name: str,
) -> None:
    values = _inputs(tmp_path)
    selected = cast(Path, getattr(values, input_name))

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityError,
        match="outside immutable inputs",
    ):
        module._require_output_outside_inputs(
            selected / "capacity-output",
            source_run_path=values.source_run_path,
            comparison_plan_run_path=values.comparison_plan_run_path,
            skill_run_path=values.skill_run_path,
            transport_pin_path=values.transport_pin_path,
            model_path=values.qwen_model_path,
        )


def test_reservation_race_does_not_remove_foreign_empty_directory(tmp_path: Path) -> None:
    output_root = tmp_path / "capacity-output"
    output_root.mkdir()

    with pytest.raises(module.OperationalSkillBoundWebCapacityError):
        module._reserve_fresh_output_root(output_root)

    assert output_root.is_dir()


def test_success_creates_and_strictly_reloads_secret_free_offline_proof(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    calls: list[tuple[str, dict[str, object]]] = []

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _verified: 20_000)

    def create(output_root: Path, **kwargs: object) -> object:
        assert output_root == Path(".")
        calls.append(("create", kwargs))
        return capacity

    def load(_path: Path, **kwargs: object) -> object:
        calls.append(("load", kwargs))
        return capacity

    monkeypatch.setattr(module, "_capacity_api", lambda: _capacity_api(create=create, load=load))

    result = module.run_operational_skill_bound_web_capacity(values)

    assert result.succeeded is True
    assert [name for name, _ in calls] == ["create", "load"]
    assert calls[0][1]["skill_run"] is verified.skill_run
    assert calls[1][1]["expected_run_id"] == _CAPACITY_RUN_ID
    assert calls[1][1]["expected_root_digest"] == _CAPACITY_ROOT
    assert result.summary["status"] == "compact-request-fits-context"
    assert result.summary["strictCapacityReloaded"] is True
    assert result.summary["offlineTokenizerOnly"] is True
    assert result.summary["modelCompletionsPerformed"] == 0
    assert result.summary["providerDispatchCount"] == 0
    assert result.summary["targetRequestCount"] == 0
    assert result.summary["targetRequestsPerformed"] is False
    assert result.summary["remainingTokenCount"] == 1024
    assert result.summary["conservativeCampaignPromptTokens"] == 20_000
    assert result.summary["conservativeCampaignTotalTokens"] == 21_024
    assert result.summary["executionAuthority"] is False
    assert result.summary["capacityRunId"] == _CAPACITY_RUN_ID
    assert result.summary["capacityRootDigest"] == _CAPACITY_ROOT
    assert result.summary["capacityEvidenceDigest"] == "6" * 64
    assert result.summary["capacityProofDigest"] == "7" * 64
    assert result.summary["capacityIndexDigest"] == "8" * 64
    serialized = json.dumps(result.summary, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "private-test-key" not in serialized


def test_runner_calls_exact_capacity_api_and_strict_loader(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _verified_source()
    skill_run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill-output",
        source_loader=_synthetic_loader(source),
    )
    plan = structured_fixture()
    model = next(item for item in plan.models if item.name == "qwen3-4b")
    transport = web_analysis_transport_runtime_pin(
        plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    verified = module.VerifiedOperationalSkillBoundWebCapacityInputs(
        source=source,
        plan=plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        skill_run=skill_run,
        expected_registry_ref=skill_run.snapshot.selection_policy.registry,
        expected_policy_digest=skill_run.snapshot.selection_policy.policy_digest,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
        model=model,
        model_path=tmp_path / "verified-model.gguf",
        output_root=tmp_path / "capacity-output",
        compact_projection=module._build_compact_projection(skill_run.snapshot),
        chat_request=module._build_compact_chat_request(skill_run.snapshot),
    )
    values = _inputs(tmp_path)
    real_api = module._capacity_api()
    api = module._CapacityApi(
        build_pin=real_api.build_pin,
        tokenizer_backend=lambda **_kwargs: _OfflineTokenizer(),
        create_run=analysis_capacity._create_web_analysis_capacity_run_with_backend,
        load_run=real_api.load_run,
        system_sentinel=real_api.system_sentinel,
        user_sentinel=real_api.user_sentinel,
    )
    conservative_prompt_tokens = module._conservative_campaign_prompt_tokens(verified)
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_capacity_api", lambda: api)
    monkeypatch.setattr(
        module,
        "_conservative_campaign_prompt_tokens",
        lambda _verified: conservative_prompt_tokens,
    )

    result = module.run_operational_skill_bound_web_capacity(values)

    assert result.succeeded is True
    assert result.summary["promptTokenCount"] == 1_505
    assert result.summary["totalTokenCount"] == 2_529
    assert result.summary["remainingTokenCount"] == 1_567
    assert result.summary["conservativeCampaignPromptTokens"] == conservative_prompt_tokens
    assert result.summary["conservativeCampaignTotalTokens"] == (conservative_prompt_tokens + 1_024)
    assert result.summary["strictCapacityReloaded"] is True


def test_output_root_swap_writes_only_to_pinned_inode_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = _verified_source()
    skill_run = _create_web_analysis_skill_projection_run_with_loader(
        source=source,
        expected_source_run_id=source.verification.run_id,
        expected_source_root_digest=source.verification.root_digest,
        output_root=tmp_path / "skill-output",
        source_loader=_synthetic_loader(source),
    )
    plan = structured_fixture()
    model = next(item for item in plan.models if item.name == "qwen3-4b")
    transport = web_analysis_transport_runtime_pin(
        plan.runtime,
        worker_image="sha256:" + "6" * 64,
        proxy_image="sha256:" + "7" * 64,
    )
    output_root = tmp_path / "capacity-output"
    parked = tmp_path / "parked-capacity-output"
    victim = tmp_path / "victim"
    verified = module.VerifiedOperationalSkillBoundWebCapacityInputs(
        source=source,
        plan=plan,
        comparison_plan_run_id=_PLAN_RUN_ID,
        comparison_plan_root_digest=_PLAN_ROOT,
        skill_run=skill_run,
        expected_registry_ref=skill_run.snapshot.selection_policy.registry,
        expected_policy_digest=skill_run.snapshot.selection_policy.policy_digest,
        transport_pin=transport,
        expected_transport_pin_digest=transport.pin_digest,
        model=model,
        model_path=tmp_path / "verified-model.gguf",
        output_root=output_root,
        compact_projection=module._build_compact_projection(skill_run.snapshot),
        chat_request=module._build_compact_chat_request(skill_run.snapshot),
    )
    tokenizer = _OutputRootSwapTokenizer(
        output_root=output_root,
        parked=parked,
        victim=victim,
    )
    real_api = module._capacity_api()
    api = module._CapacityApi(
        build_pin=real_api.build_pin,
        tokenizer_backend=lambda **_kwargs: tokenizer,
        create_run=analysis_capacity._create_web_analysis_capacity_run_with_backend,
        load_run=real_api.load_run,
        system_sentinel=real_api.system_sentinel,
        user_sentinel=real_api.user_sentinel,
    )
    original_cwd = Path.cwd()
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_capacity_api", lambda: api)

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityError,
        match="failed closed",
    ):
        module.run_operational_skill_bound_web_capacity(_inputs(tmp_path))

    assert Path.cwd() == original_cwd
    assert active_pinned_workspace_identity() is None
    assert tokenizer.cleanup_called is True
    assert tokenizer.absence_checked is True
    assert output_root.is_symlink()
    assert list(victim.iterdir()) == []
    runs = tuple((parked / "web-analysis-capacity-proof").iterdir())
    assert len(runs) == 1
    assert (runs[0] / "capacity-index.json").is_file()
    assert (runs[0] / "run-integrity.jsonl").is_file()
    assert os.stat(parked).st_ino != os.stat(victim).st_ino


def test_capacity_boundary_never_calls_provider_completion_or_target_io(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    forbidden_calls: list[str] = []

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _verified: 20_000)
    monkeypatch.setattr(
        analysis_local,
        "build_local_web_analysis_provider_runtime",
        lambda **_kwargs: forbidden_calls.append("provider"),
    )
    monkeypatch.setattr(
        effectiveness_docker,
        "LocalModelRuntime",
        lambda **_kwargs: forbidden_calls.append("completion"),
    )

    def create(_output_root: Path, **kwargs: object) -> object:
        assert "provider_runtime" not in kwargs
        assert "api_key" not in kwargs
        assert "target" not in kwargs
        assert "origin" not in kwargs
        return capacity

    monkeypatch.setattr(
        module,
        "_capacity_api",
        lambda: _capacity_api(create=create, load=lambda *_a, **_k: capacity),
    )

    result = module.run_operational_skill_bound_web_capacity(values)

    assert forbidden_calls == []
    assert result.summary["modelCompletionsPerformed"] == 0
    assert result.summary["providerDispatchCount"] == 0
    assert result.summary["targetRequestCount"] == 0


def test_nonzero_dispatch_or_target_markers_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    capacity.proof.provider_dispatch = True
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _verified: 20_000)
    monkeypatch.setattr(
        module,
        "_capacity_api",
        lambda: _capacity_api(create=lambda *_a, **_k: capacity, load=object()),
    )

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityError,
        match="unexpectedly carries",
    ):
        module.run_operational_skill_bound_web_capacity(values)


def test_main_emits_secret_free_error_without_backend_details(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(module, "_arguments", lambda _argv: cast(Any, object()))

    def fail(_values: object) -> module.OperationalSkillBoundWebCapacityResult:
        raise RuntimeError("private-test-key /private/capacity")

    monkeypatch.setattr(module, "run_operational_skill_bound_web_capacity", fail)

    assert module.main([]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["status"] == "operational-error"
    assert payload["errorType"] == "RuntimeError"
    assert payload["providerDispatchCount"] == 0
    assert "private-test-key" not in json.dumps(payload)
