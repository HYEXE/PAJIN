from __future__ import annotations

import ast
import json
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

import pajin.web_assessment.analysis_skill_live_preparation as preparation_module
from pajin.providers.session import PolicyBoundProviderPort
from pajin.runtime.secrets import SecretBroker
from pajin.runtime.store import RunStore, load_verified_run_snapshot
from pajin.runtime.worker import DockerWorkerBackend
from pajin.web_assessment.analysis_capacity import SubprocessLlamaCppTokenizerBackend
from pajin.web_assessment.analysis_capacity_v2 import (
    _create_web_analysis_capacity_v2_run_with_backend,
)
from pajin.web_assessment.analysis_skill_compact import (
    build_compact_skill_bound_web_analysis_chat_request,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    COMPACT_LIVE_PREPARATION_STATUS,
    CompactSkillBoundWebAnalysisLivePreparationError,
    CompactSkillBoundWebAnalysisLiveRequest,
    create_compact_skill_bound_web_analysis_preparation_run,
    load_verified_compact_skill_bound_web_analysis_preparation,
    plan_compact_skill_bound_web_analysis_call,
)
from pajin.web_assessment.analysis_skill_runtime import (
    SkillBoundWebAnalysisInvocationRuntime,
    SkillBoundWebAnalysisProviderRuntime,
)
from tests.test_web_analysis_capacity_v2 import (
    _FakeV2Tokenizer,
    _inputs_v2,
)
from tests.test_web_analysis_capacity_v2 import (
    _reload as _reload_capacity,
)


def _capacity(tmp_path: Path):
    skill_run, projection, request, pin = _inputs_v2(tmp_path)
    capacity = _create_web_analysis_capacity_v2_run_with_backend(
        tmp_path / "capacity-v2",
        skill_run=skill_run,
        projection=projection,
        chat_request=request,
        pin=pin,
        tokenizer_backend=_FakeV2Tokenizer(),
    )
    return skill_run, capacity


def _anchors(skill_run: Any, capacity: Any) -> dict[str, str]:
    return {
        "expected_skill_run_id": skill_run.verification.run_id,
        "expected_skill_root_digest": skill_run.verification.root_digest,
        "expected_capacity_run_id": capacity.run_id,
        "expected_capacity_root_digest": capacity.root_digest,
        "expected_capacity_pin_digest": capacity.pin.pin_digest,
        "expected_capacity_proof_digest": capacity.proof.proof_digest,
        "expected_capacity_model_materialization_attestation_digest": (
            capacity.model_materialization_attestation_digest
        ),
        "expected_transport_pin_digest": capacity.pin.transport_pin_digest,
    }


def _load(verified: Any, *, skill_run: Any, capacity: Any, **overrides: str):
    anchors = {
        "expected_run_id": verified.run_id,
        "expected_root_digest": verified.root_digest,
        **_anchors(skill_run, capacity),
    }
    anchors.update(overrides)
    return load_verified_compact_skill_bound_web_analysis_preparation(
        verified.run_path,
        skill_run=skill_run,
        capacity_run=capacity,
        **anchors,
    )


def _forbidden(*_args: object, **_kwargs: object) -> None:
    raise AssertionError("zero-dispatch preparation crossed a forbidden runtime boundary")


def _patch_forbidden_runtime_boundaries(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(SubprocessLlamaCppTokenizerBackend, "start", _forbidden)
    monkeypatch.setattr(PolicyBoundProviderPort, "chat_bound", _forbidden)
    monkeypatch.setattr(SecretBroker, "materialize", _forbidden)
    monkeypatch.setattr(SkillBoundWebAnalysisProviderRuntime, "__init__", _forbidden)
    monkeypatch.setattr(SkillBoundWebAnalysisInvocationRuntime, "__init__", _forbidden)
    monkeypatch.setattr(DockerWorkerBackend, "__init__", _forbidden)
    monkeypatch.setattr(subprocess, "run", _forbidden)


class _AlwaysEqualDuck:
    def __init__(self, wrapped: object) -> None:
        self._wrapped = wrapped

    def __getattr__(self, name: str) -> object:
        return getattr(self._wrapped, name)

    def __eq__(self, _other: object) -> bool:
        return True


def test_live_preparation_rederives_exact_request_without_runtime_or_dispatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    _patch_forbidden_runtime_boundaries(monkeypatch)

    first = plan_compact_skill_bound_web_analysis_call(
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )
    second = plan_compact_skill_bound_web_analysis_call(
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )

    assert first == second
    assert first.live_request.chat_request == (
        build_compact_skill_bound_web_analysis_chat_request(skill_run.snapshot)
    )
    registration = first.live_request.provider_registration
    assert registration.provider_id == "web-analysis-local"
    assert registration.model == capacity.pin.model_id
    assert registration.secret_ref == "web-analysis/local-provider-api-key"
    assert registration.allow_streaming is False
    assert registration.allowed_function_tools == set()
    assert first.live_request.status == COMPACT_LIVE_PREPARATION_STATUS
    assert first.preparation.status == COMPACT_LIVE_PREPARATION_STATUS
    state = first.preparation.execution_state.model_dump(mode="json", by_alias=True)
    assert state
    assert all(
        value is False if isinstance(value, bool) else value == 0 for value in state.values()
    )
    assert first.preparation.capacity_run_id == capacity.run_id
    assert first.preparation.capacity_run_root_digest == capacity.root_digest
    assert first.preparation.capacity_pin_digest == capacity.pin.pin_digest
    assert first.preparation.capacity_proof_digest == capacity.proof.proof_digest
    assert first.preparation.model_materialization_attestation_digest == (
        capacity.model_materialization_attestation_digest
    )
    assert first.preparation.transport_pin_digest == capacity.pin.transport_pin_digest


def test_live_preparation_seals_exact_zero_dispatch_run_and_strictly_reloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    _patch_forbidden_runtime_boundaries(monkeypatch)

    verified = create_compact_skill_bound_web_analysis_preparation_run(
        tmp_path / "preparation",
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )
    reloaded = _load(verified, skill_run=skill_run, capacity=capacity)
    snapshot = load_verified_run_snapshot(verified.run_path, expected_run_id=verified.run_id)

    assert reloaded == verified
    assert snapshot.verification.artifact_count == 3
    assert snapshot.verification.event_count == 2
    assert snapshot.verification.seal_count == 1
    assert {artifact.path for artifact in snapshot.seals[0].artifacts} == {
        "compact-live-request.json",
        "compact-live-preparation.json",
        "compact-live-preparation-index.json",
    }
    assert tuple(event.event_type for event in snapshot.events) == (
        "web-analysis.compact-live-preparation.started",
        "web-analysis.compact-live-preparation.completed",
    )
    assert "model.call.started" not in {event.event_type for event in snapshot.events}
    assert verified.index.status == COMPACT_LIVE_PREPARATION_STATUS
    assert verified.index.execution_state == verified.preparation.execution_state

    artifact_text = "\n".join(
        (verified.run_path / name).read_text(encoding="utf-8")
        for name in (
            "compact-live-request.json",
            "compact-live-preparation.json",
            "compact-live-preparation-index.json",
        )
    )
    assert str(tmp_path) not in artifact_text
    assert "model.gguf" not in artifact_text
    assert '"apiKey"' not in artifact_text
    assert '"api_key"' not in artifact_text
    assert "prepared-not-authorized-no-dispatch" in artifact_text


@pytest.mark.parametrize("input_name", ("capacity", "skill"))
def test_live_preparation_rejects_output_overlapping_immutable_run_without_mutation(
    tmp_path: Path,
    input_name: str,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    output_root = capacity.run_path if input_name == "capacity" else skill_run.run_path
    before_entries = tuple(sorted(path.name for path in output_root.iterdir()))

    with pytest.raises(
        CompactSkillBoundWebAnalysisLivePreparationError,
        match="output failed closed",
    ):
        create_compact_skill_bound_web_analysis_preparation_run(
            output_root,
            skill_run=skill_run,
            capacity_run=capacity,
            **_anchors(skill_run, capacity),
        )

    assert tuple(sorted(path.name for path in output_root.iterdir())) == before_entries
    assert _reload_capacity(capacity, skill_run=skill_run) == capacity


def test_live_preparation_holds_fresh_output_inode_until_strict_reload(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    output_root = tmp_path / "preparation"
    parked = tmp_path / "parked-preparation"
    victim = tmp_path / "victim"

    def swap_output(_output_root: Path, **_kwargs: object):
        output_root.rename(parked)
        victim.mkdir()
        output_root.symlink_to(victim, target_is_directory=True)
        Path("held-inode-marker.txt").write_text("held", encoding="utf-8")
        return preparation_module.VerifiedCompactSkillBoundWebAnalysisPreparationRun(
            run_id="run_20260921T010101Z_1234abcd",
            run_path=Path("compact-live-preparation/run_20260921T010101Z_1234abcd"),
            root_digest="1" * 64,
            live_request=cast(Any, object()),
            preparation=cast(Any, object()),
            index=cast(Any, object()),
            started_event_hash="2" * 64,
            completed_event_hash="3" * 64,
        )

    monkeypatch.setattr(
        preparation_module,
        "_create_compact_skill_bound_web_analysis_preparation_run_in_workspace",
        swap_output,
    )

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        create_compact_skill_bound_web_analysis_preparation_run(
            output_root,
            skill_run=skill_run,
            capacity_run=capacity,
            **_anchors(skill_run, capacity),
        )

    assert not any(victim.iterdir())
    assert (parked / "held-inode-marker.txt").read_text(encoding="utf-8") == "held"


@pytest.mark.parametrize(
    ("anchor", "value"),
    (
        ("expected_capacity_run_id", "run_20260921T000000Z_deadbeef"),
        ("expected_capacity_root_digest", "4" * 64),
        ("expected_capacity_pin_digest", "5" * 64),
        ("expected_capacity_proof_digest", "6" * 64),
        (
            "expected_capacity_model_materialization_attestation_digest",
            "7" * 64,
        ),
        ("expected_transport_pin_digest", "8" * 64),
    ),
)
def test_live_preparation_rejects_every_independent_capacity_anchor_drift(
    tmp_path: Path,
    anchor: str,
    value: str,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    anchors = _anchors(skill_run, capacity)
    anchors[anchor] = value

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        plan_compact_skill_bound_web_analysis_call(
            skill_run=skill_run,
            capacity_run=capacity,
            **anchors,
        )


def test_live_preparation_rejects_supplied_capacity_object_drift(tmp_path: Path) -> None:
    skill_run, capacity = _capacity(tmp_path)
    forged = capacity.model_copy(update={"root_digest": "9" * 64})

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        plan_compact_skill_bound_web_analysis_call(
            skill_run=skill_run,
            capacity_run=forged,
            **_anchors(skill_run, capacity),
        )


@pytest.mark.parametrize("input_name", ("skill", "capacity"))
def test_live_preparation_rejects_always_equal_non_concrete_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_name: str,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    supplied_skill: object = skill_run
    supplied_capacity: object = capacity
    if input_name == "skill":
        supplied_skill = _AlwaysEqualDuck(skill_run)
    else:
        supplied_capacity = _AlwaysEqualDuck(capacity)
    _patch_forbidden_runtime_boundaries(monkeypatch)

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        plan_compact_skill_bound_web_analysis_call(
            skill_run=cast(Any, supplied_skill),
            capacity_run=cast(Any, supplied_capacity),
            **_anchors(skill_run, capacity),
        )


def test_live_preparation_loader_rejects_sealed_artifact_tamper(tmp_path: Path) -> None:
    skill_run, capacity = _capacity(tmp_path)
    verified = create_compact_skill_bound_web_analysis_preparation_run(
        tmp_path / "preparation",
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )
    request_path = verified.run_path / "compact-live-request.json"
    raw = json.loads(request_path.read_text(encoding="utf-8"))
    raw["executionState"]["providerDispatchCount"] = 1
    request_path.write_text(json.dumps(raw, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        _load(verified, skill_run=skill_run, capacity=capacity)


def test_live_preparation_loader_rejects_missing_required_zero_field_in_new_seal(
    tmp_path: Path,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    verified = create_compact_skill_bound_web_analysis_preparation_run(
        tmp_path / "preparation",
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )
    request = json.loads(
        (verified.run_path / "compact-live-request.json").read_text(encoding="utf-8")
    )
    preparation = json.loads(
        (verified.run_path / "compact-live-preparation.json").read_text(encoding="utf-8")
    )
    index = json.loads(
        (verified.run_path / "compact-live-preparation-index.json").read_text(encoding="utf-8")
    )
    del request["executionState"]["providerDispatchCount"]

    malicious = RunStore.create(tmp_path / "missing-field", "compact-live-preparation")
    malicious.append_event(
        "web-analysis.compact-live-preparation.started",
        {"shape": "otherwise-valid"},
    )
    malicious.write_json_create_only("compact-live-request.json", request)
    malicious.write_json_create_only("compact-live-preparation.json", preparation)
    malicious.write_json_create_only("compact-live-preparation-index.json", index)
    malicious.append_event(
        "web-analysis.compact-live-preparation.completed",
        {"shape": "otherwise-valid"},
    )
    seal = malicious.seal()

    with pytest.raises(CompactSkillBoundWebAnalysisLivePreparationError):
        load_verified_compact_skill_bound_web_analysis_preparation(
            malicious.path,
            skill_run=skill_run,
            capacity_run=capacity,
            expected_run_id=malicious.run_id,
            expected_root_digest=seal.root_digest,
            **_anchors(skill_run, capacity),
        )


def test_live_request_model_rejects_defaulted_or_coercible_zero_dispatch_fields(
    tmp_path: Path,
) -> None:
    skill_run, capacity = _capacity(tmp_path)
    planned = plan_compact_skill_bound_web_analysis_call(
        skill_run=skill_run,
        capacity_run=capacity,
        **_anchors(skill_run, capacity),
    )
    raw = planned.live_request.model_dump(mode="json", by_alias=True)
    del raw["executionState"]["providerDispatchCount"]
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisLiveRequest.model_validate(raw)

    raw = planned.live_request.model_dump(mode="json", by_alias=True)
    raw["executionState"]["providerDispatchCount"] = False
    with pytest.raises(ValidationError):
        CompactSkillBoundWebAnalysisLiveRequest.model_validate(raw)


def test_live_preparation_module_has_no_runtime_dispatch_or_network_imports() -> None:
    source_path = (
        Path(__file__).parents[1]
        / "src"
        / "pajin"
        / "web_assessment"
        / "analysis_skill_live_preparation.py"
    )
    tree = ast.parse(source_path.read_text(encoding="utf-8"))
    imports = {
        node.module
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom) and node.module is not None
    }
    imports.update(
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    )
    forbidden = {
        "httpx",
        "subprocess",
        "pajin.providers.session",
        "pajin.runtime.secrets",
        "pajin.runtime.worker",
        "pajin.tools.gateway",
        "pajin.web_assessment.analysis_runtime",
        "pajin.web_assessment.analysis_skill_runtime",
    }
    assert not {
        module
        for module in imports
        if any(module == item or module.startswith(item + ".") for item in forbidden)
    }


def test_preparation_public_surface_is_exact() -> None:
    assert preparation_module.__all__ == [
        "COMPACT_LIVE_PREPARATION_STATUS",
        "CompactSkillBoundWebAnalysisLivePreparationError",
        "CompactSkillBoundWebAnalysisLiveRequest",
        "CompactSkillBoundWebAnalysisPreparation",
        "CompactSkillBoundWebAnalysisPreparationIndex",
        "CompactSkillBoundWebAnalysisZeroDispatchState",
        "PlannedCompactSkillBoundWebAnalysisCall",
        "VerifiedCompactSkillBoundWebAnalysisPreparationRun",
        "create_compact_skill_bound_web_analysis_preparation_run",
        "load_verified_compact_skill_bound_web_analysis_preparation",
        "plan_compact_skill_bound_web_analysis_call",
    ]
