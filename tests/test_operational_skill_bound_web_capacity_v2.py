from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import scripts.operational_skill_bound_web_capacity_v2 as module
from pajin.runtime.pinned_workspace import active_pinned_workspace_identity
from pajin.web_assessment.analysis_capacity import SubprocessLlamaCppTokenizerBackend
from pajin.web_assessment.analysis_capacity_v2 import (
    build_web_analysis_capacity_v2_pin,
    create_web_analysis_capacity_v2_run,
    load_verified_web_analysis_capacity_v2_run,
)

_SOURCE_RUN_ID = "run_20260916T000000Z_90abcdef"
_SOURCE_ROOT = "c" * 64
_PLAN_RUN_ID = "run_20260916T000001Z_89abcdef"
_PLAN_ROOT = "e" * 64
_SKILL_RUN_ID = "run_20260916T000002Z_76543210"
_SKILL_ROOT = "f" * 64
_CAPACITY_RUN_ID = "run_20260921T010101Z_1234abcd"
_CAPACITY_ROOT = "a" * 64
_PIN_DIGEST = "5" * 64
_EVIDENCE_DIGEST = "6" * 64
_PROOF_DIGEST = "7" * 64
_INDEX_DIGEST = "8" * 64
_ATTESTATION_DIGEST = "b" * 64
_MODEL_SHA256 = "d" * 64
_MODEL_PIN_DIGEST = "4" * 64
_IMAGE_ID = "sha256:" + "3" * 64
_POLICY_DIGEST = "9" * 64
_AUTHORITY_FIELDS = {
    "provider_dispatch_authority": False,
    "target_request_authority": False,
    "scope_expansion_authority": False,
    "tool_request_authority": False,
    "capability_authority": False,
    "permit_authority": False,
    "execution_authority": False,
    "graph_admission_authority": False,
    "finding_authority": False,
    "report_delivery_authority": False,
}


def _inputs(tmp_path: Path) -> module.OperationalSkillBoundWebCapacityV2Inputs:
    return module.OperationalSkillBoundWebCapacityV2Inputs(
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
        expected_transport_pin_digest="2" * 64,
        qwen_model_path=tmp_path / "qwen.gguf",
        output_root=tmp_path / "capacity-v2-output",
    )


def _verified_inputs(
    tmp_path: Path,
) -> module.VerifiedOperationalSkillBoundWebCapacityV2Inputs:
    runtime = SimpleNamespace(
        request_timeout_seconds=180,
        model_cpus=4,
        model_memory_mb=6_144,
        model_pids=128,
    )
    plan = SimpleNamespace(runtime=runtime, commitment="1" * 64)
    skill_run = SimpleNamespace(
        verification=SimpleNamespace(run_id=_SKILL_RUN_ID, root_digest=_SKILL_ROOT)
    )
    model = SimpleNamespace(
        name="qwen3-4b",
        repository="example/qwen",
        revision="revision",
        sha256=_MODEL_SHA256,
        size_bytes=4_280_403_520,
    )
    return cast(
        module.VerifiedOperationalSkillBoundWebCapacityV2Inputs,
        SimpleNamespace(
            source=object(),
            plan=plan,
            comparison_plan_run_id=_PLAN_RUN_ID,
            comparison_plan_root_digest=_PLAN_ROOT,
            skill_run=skill_run,
            expected_registry_ref=object(),
            expected_policy_digest="0" * 64,
            transport_pin=object(),
            expected_transport_pin_digest="2" * 64,
            model=model,
            model_path=tmp_path / "qwen.gguf",
            output_root=tmp_path / "capacity-v2-output",
            compact_projection=SimpleNamespace(projection_digest="1" * 64),
            chat_request=SimpleNamespace(request_digest="0" * 64),
        ),
    )


def _no_authority(**values: object) -> SimpleNamespace:
    return SimpleNamespace(**_AUTHORITY_FIELDS, **values)


def _capacity_run(tmp_path: Path) -> SimpleNamespace:
    attestation = _no_authority(
        attestation_digest=_ATTESTATION_DIGEST,
        model_pin_digest=_MODEL_PIN_DIGEST,
        expected_model_sha256=_MODEL_SHA256,
        expected_model_size_bytes=4_280_403_520,
        staged_model_sha256=_MODEL_SHA256,
        staged_model_size_bytes=4_280_403_520,
        staged_model_uid=10001,
        staged_model_gid=10001,
        staged_model_mode="0400",
        mounted_model_sha256=_MODEL_SHA256,
        mounted_model_size_bytes=4_280_403_520,
        mounted_model_uid=10001,
        mounted_model_gid=10001,
        mounted_model_mode="0400",
        tokenizer_image_id=_IMAGE_ID,
        staging_strategy="descriptor-to-docker-volume",
        materialization_kind="docker-copy",
        mount_type="volume",
        mount_destination="/models",
        read_only=True,
        digest_algorithm="sha256",
        attested_before_tokenizer_endpoints=True,
        runtime_user_read_verified=True,
        cleanup_required=True,
    )
    return SimpleNamespace(
        run_path=(
            tmp_path / "capacity-v2-output" / "web-analysis-capacity-proof" / _CAPACITY_RUN_ID
        ),
        run_id=_CAPACITY_RUN_ID,
        root_digest=_CAPACITY_ROOT,
        projection_digest="1" * 64,
        pin=_no_authority(
            pin_digest=_PIN_DIGEST,
            chat_request_digest="0" * 64,
            tokenizer_runtime_digest="3" * 64,
            context_tokens=4096,
            model_materialization_policy_digest=_POLICY_DIGEST,
            offline=True,
            tokenizer_only=True,
        ),
        evidence=_no_authority(
            evidence_digest=_EVIDENCE_DIGEST,
            model_materialization_attestation=attestation,
        ),
        proof=_no_authority(
            proof_digest=_PROOF_DIGEST,
            evidence_digest=_EVIDENCE_DIGEST,
            request_digest="0" * 64,
            chat_template_digest="4" * 64,
            model_materialization_attestation_digest=_ATTESTATION_DIGEST,
            prompt_tokens=1_460,
            completion_tokens=1_024,
            total_tokens=2_484,
            remaining_tokens=1_612,
            conservative_campaign_prompt_tokens=50_144,
            conservative_campaign_total_tokens=51_168,
            fits=True,
            model_inference_performed=False,
            provider_dispatch=False,
            target_requests=0,
        ),
        index=_no_authority(
            index_digest=_INDEX_DIGEST,
            evidence_digest=_EVIDENCE_DIGEST,
            proof_digest=_PROOF_DIGEST,
            model_materialization_attestation_digest=_ATTESTATION_DIGEST,
            model_inference_performed=False,
            provider_dispatch=False,
            target_requests=0,
        ),
        model_materialization_attestation_digest=_ATTESTATION_DIGEST,
        started_event_hash="a" * 64,
        model_mount_attested_event_hash="c" * 64,
        completed_event_hash="e" * 64,
    )


def _api(
    *,
    create: Any,
    load: Any,
) -> module._CapacityV2Api:
    return module._CapacityV2Api(
        build_pin=lambda **_kwargs: SimpleNamespace(pin_digest=_PIN_DIGEST),
        tokenizer_backend=lambda **_kwargs: object(),
        create_run=create,
        load_run=load,
        system_sentinel="pajin-compact-skill-bound-system-v1",
        user_sentinel="pajin-compact-skill-bound-user-v1",
    )


def test_v2_api_uses_exact_production_backend_and_additive_producer() -> None:
    api = module._capacity_v2_api()

    assert api.build_pin is build_web_analysis_capacity_v2_pin
    assert api.tokenizer_backend is SubprocessLlamaCppTokenizerBackend
    assert api.create_run is create_web_analysis_capacity_v2_run
    assert api.load_run is load_verified_web_analysis_capacity_v2_run


def test_success_strictly_reloads_all_v2_anchors_and_emits_secret_free_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    calls: list[tuple[str, dict[str, object]]] = []
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _value: 50_144)

    def create(output_root: Path, **kwargs: object) -> object:
        assert output_root == Path(".")
        assert "provider_runtime" not in kwargs
        assert "target" not in kwargs
        calls.append(("create", kwargs))
        return capacity

    def load(_run_path: Path, **kwargs: object) -> object:
        calls.append(("load", kwargs))
        return capacity

    monkeypatch.setattr(module, "_capacity_v2_api", lambda: _api(create=create, load=load))

    result = module.run_operational_skill_bound_web_capacity_v2(values)

    assert result.succeeded is True
    assert [name for name, _ in calls] == ["create", "load"]
    assert calls[1][1] == {
        "skill_run": verified.skill_run,
        "expected_run_id": _CAPACITY_RUN_ID,
        "expected_root_digest": _CAPACITY_ROOT,
        "expected_pin_digest": _PIN_DIGEST,
        "expected_transport_pin_digest": verified.expected_transport_pin_digest,
        "expected_proof_digest": _PROOF_DIGEST,
        "expected_model_materialization_attestation_digest": _ATTESTATION_DIGEST,
    }
    assert result.summary["apiVersion"].endswith("/v1alpha2")
    assert result.summary["capacityProofVersion"] == "v2"
    assert result.summary["strictCapacityReloaded"] is True
    assert result.summary["modelMaterializationAttestationVerified"] is True
    assert result.summary["modelMaterializationAttestationDigest"] == _ATTESTATION_DIGEST
    assert result.summary["modelInferencePerformed"] is False
    assert result.summary["modelCompletionsPerformed"] == 0
    assert result.summary["providerDispatchCount"] == 0
    assert result.summary["targetRequestCount"] == 0
    materialization = cast(dict[str, object], result.summary["modelMaterialization"])
    assert materialization["stagingStrategy"] == "descriptor-to-docker-volume"
    assert materialization["mountType"] == "volume"
    assert materialization["readOnly"] is True
    assert materialization["stagedModelUid"] == 10001
    assert materialization["stagedModelGid"] == 10001
    assert materialization["stagedModelMode"] == "0400"
    assert materialization["mountedModelUid"] == 10001
    assert materialization["mountedModelGid"] == 10001
    assert materialization["mountedModelMode"] == "0400"
    assert materialization["runtimeUserReadVerified"] is True
    serialized = json.dumps(result.summary, sort_keys=True)
    assert str(tmp_path) not in serialized
    assert "qwen.gguf" not in serialized


def test_strict_reload_difference_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _verified_inputs(tmp_path)
    created = _capacity_run(tmp_path)
    loaded = _capacity_run(tmp_path)
    loaded.completed_event_hash = "0" * 64
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _value: 50_144)
    monkeypatch.setattr(
        module,
        "_capacity_v2_api",
        lambda: _api(
            create=lambda *_args, **_kwargs: created,
            load=lambda *_args, **_kwargs: loaded,
        ),
    )

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityV2Error,
        match="strictly reloaded",
    ):
        module.run_operational_skill_bound_web_capacity_v2(_inputs(tmp_path))


def test_any_v2_authority_marker_fails_before_strict_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    capacity.evidence.tool_request_authority = True
    load_calls: list[str] = []
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _value: 50_144)
    monkeypatch.setattr(
        module,
        "_capacity_v2_api",
        lambda: _api(
            create=lambda *_args, **_kwargs: capacity,
            load=lambda *_args, **_kwargs: load_calls.append("load"),
        ),
    )

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityV2Error,
        match="unexpectedly carries",
    ):
        module.run_operational_skill_bound_web_capacity_v2(_inputs(tmp_path))

    assert load_calls == []


def test_output_root_swap_writes_only_to_pinned_inode_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    values = _inputs(tmp_path)
    verified = _verified_inputs(tmp_path)
    capacity = _capacity_run(tmp_path)
    parked = tmp_path / "parked-capacity-v2-output"
    victim = tmp_path / "victim"
    original_cwd = Path.cwd()
    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(module, "_conservative_campaign_prompt_tokens", lambda _value: 50_144)

    def create(output_root: Path, **_kwargs: object) -> object:
        assert output_root == Path(".")
        values.output_root.rename(parked)
        victim.mkdir()
        values.output_root.symlink_to(victim, target_is_directory=True)
        Path("sealed-v2-marker.json").write_text("{}\n", encoding="utf-8")
        return capacity

    monkeypatch.setattr(
        module,
        "_capacity_v2_api",
        lambda: _api(create=create, load=lambda *_args, **_kwargs: capacity),
    )

    with pytest.raises(
        module.OperationalSkillBoundWebCapacityV2Error,
        match="failed closed",
    ):
        module.run_operational_skill_bound_web_capacity_v2(values)

    assert Path.cwd() == original_cwd
    assert active_pinned_workspace_identity() is None
    assert values.output_root.is_symlink()
    assert list(victim.iterdir()) == []
    assert (parked / "sealed-v2-marker.json").read_text(encoding="utf-8") == "{}\n"
    assert os.stat(parked).st_ino != os.stat(victim).st_ino


def test_main_emits_secret_free_v2_error(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.setattr(module, "_arguments", lambda _argv: cast(Any, object()))

    def fail(_values: object) -> module.OperationalSkillBoundWebCapacityV2Result:
        raise RuntimeError("private-test-key /private/model.gguf")

    monkeypatch.setattr(module, "run_operational_skill_bound_web_capacity_v2", fail)

    assert module.main([]) == 2
    payload = json.loads(capsys.readouterr().out)
    assert payload["capacityProofVersion"] == "v2"
    assert payload["modelCompletionsPerformed"] == 0
    assert payload["providerDispatchCount"] == 0
    assert payload["targetRequestCount"] == 0
    assert payload["modelMaterializationAttestationVerified"] is False
    assert "private-test-key" not in json.dumps(payload)
