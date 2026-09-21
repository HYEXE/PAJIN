from __future__ import annotations

import ast
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

import scripts.operational_skill_bound_web_live_preparation as module
from pajin.runtime.pinned_workspace import active_pinned_workspace_identity

_SOURCE_RUN_ID = "run_20260921T000000Z_11223344"
_SOURCE_ROOT = "1" * 64
_SKILL_RUN_ID = "run_20260921T000001Z_22334455"
_SKILL_ROOT = "2" * 64
_CAPACITY_RUN_ID = "run_20260921T000002Z_33445566"
_CAPACITY_ROOT = "3" * 64
_CAPACITY_PIN = "4" * 64
_CAPACITY_PROOF = "5" * 64
_ATTESTATION = "6" * 64
_TRANSPORT = "7" * 64
_PREPARATION_RUN_ID = "run_20260921T000003Z_44556677"
_PREPARATION_ROOT = "8" * 64


class _State:
    def model_dump(self, *, mode: str, by_alias: bool) -> dict[str, object]:
        assert mode == "json"
        assert by_alias is True
        return {
            "modelRuntimeStarted": False,
            "modelRuntimeStartCount": 0,
            "modelInvocationPerformed": False,
            "modelInvocationCount": 0,
            "providerDispatchPerformed": False,
            "providerDispatchCount": 0,
            "targetRequestPerformed": False,
            "targetRequestCount": 0,
            "toolRequestPerformed": False,
            "toolRequestCount": 0,
            "actionPermitIssued": False,
            "actionPermitCount": 0,
            "findingCreated": False,
            "findingCount": 0,
            "graphAdmitted": False,
            "graphAdmissionCount": 0,
            "reportCreated": False,
            "reportCount": 0,
            "externalDeliveryPerformed": False,
            "deliveryCount": 0,
            "futureLiveCallAuthorized": False,
            "executionAuthority": False,
        }


def _inputs(tmp_path: Path) -> module.OperationalSkillBoundWebLivePreparationInputs:
    return module.OperationalSkillBoundWebLivePreparationInputs(
        source_run_path=tmp_path / "source-run",
        source_run_id=_SOURCE_RUN_ID,
        source_root_digest=_SOURCE_ROOT,
        skill_run_path=tmp_path / "skill-run",
        skill_run_id=_SKILL_RUN_ID,
        skill_root_digest=_SKILL_ROOT,
        capacity_run_path=tmp_path / "capacity-run",
        capacity_run_id=_CAPACITY_RUN_ID,
        capacity_root_digest=_CAPACITY_ROOT,
        capacity_pin_digest=_CAPACITY_PIN,
        capacity_proof_digest=_CAPACITY_PROOF,
        capacity_model_materialization_attestation_digest=_ATTESTATION,
        expected_transport_pin_digest=_TRANSPORT,
        output_root=tmp_path / "preparation-output",
    )


def _verified(
    tmp_path: Path,
) -> module.VerifiedOperationalSkillBoundWebLivePreparationInputs:
    values = _inputs(tmp_path)
    skill_run = SimpleNamespace(
        run_path=values.skill_run_path,
        verification=SimpleNamespace(run_id=_SKILL_RUN_ID, root_digest=_SKILL_ROOT),
    )
    capacity_run = SimpleNamespace(
        run_path=values.capacity_run_path,
        run_id=_CAPACITY_RUN_ID,
        root_digest=_CAPACITY_ROOT,
    )
    return module.VerifiedOperationalSkillBoundWebLivePreparationInputs(
        source=cast(Any, SimpleNamespace(run_path=values.source_run_path)),
        skill_run=cast(Any, skill_run),
        capacity_run=cast(Any, capacity_run),
        output_root=values.output_root,
        values=values,
    )


def _preparation_run(run_path: Path, *, index_digest: str = "b" * 64) -> SimpleNamespace:
    state = _State()
    live_request = SimpleNamespace(
        request_digest="9" * 64,
        status="prepared-not-authorized-no-dispatch",
        skill_run_id=_SKILL_RUN_ID,
        skill_run_root_digest=_SKILL_ROOT,
        execution_state=state,
    )
    preparation = SimpleNamespace(
        preparation_digest="a" * 64,
        status="prepared-not-authorized-no-dispatch",
        live_request_digest=live_request.request_digest,
        skill_run_id=_SKILL_RUN_ID,
        skill_run_root_digest=_SKILL_ROOT,
        capacity_run_id=_CAPACITY_RUN_ID,
        capacity_run_root_digest=_CAPACITY_ROOT,
        capacity_pin_digest=_CAPACITY_PIN,
        capacity_proof_digest=_CAPACITY_PROOF,
        model_materialization_attestation_digest=_ATTESTATION,
        transport_pin_digest=_TRANSPORT,
        execution_state=state,
    )
    index = SimpleNamespace(
        index_digest=index_digest,
        status="prepared-not-authorized-no-dispatch",
        request_digest=live_request.request_digest,
        preparation_digest=preparation.preparation_digest,
        capacity_run_id=_CAPACITY_RUN_ID,
        capacity_run_root_digest=_CAPACITY_ROOT,
        capacity_pin_digest=_CAPACITY_PIN,
        capacity_proof_digest=_CAPACITY_PROOF,
        model_materialization_attestation_digest=_ATTESTATION,
        transport_pin_digest=_TRANSPORT,
        execution_state=state,
    )
    return SimpleNamespace(
        run_path=run_path,
        run_id=_PREPARATION_RUN_ID,
        root_digest=_PREPARATION_ROOT,
        live_request=live_request,
        preparation=preparation,
        index=index,
    )


def test_cli_accepts_only_immutable_runs_anchors_and_fresh_output() -> None:
    destinations = {action.dest for action in module._parser()._actions if action.dest != "help"}

    assert destinations == {
        "source_run_path",
        "source_run_id",
        "source_root_digest",
        "skill_run_path",
        "skill_run_id",
        "skill_root_digest",
        "capacity_run_path",
        "capacity_run_id",
        "capacity_root_digest",
        "capacity_pin_digest",
        "capacity_proof_digest",
        "capacity_model_materialization_attestation_digest",
        "expected_transport_pin_digest",
        "output_root",
    }
    assert not any(
        marker in destinations
        for marker in {
            "comparison_plan_run_path",
            "qwen_model_path",
            "provider_endpoint",
            "target_url",
            "credential",
        }
    )


def test_runner_creates_and_strictly_reloads_only_zero_dispatch_preparation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _verified(tmp_path)
    calls: list[object] = []
    planned = object()

    def plan(**kwargs: object) -> object:
        calls.append(("plan", None, active_pinned_workspace_identity(), kwargs))
        return planned

    def create(output_root: Path, **kwargs: object) -> object:
        calls.append(("create", output_root, active_pinned_workspace_identity(), kwargs))
        assert output_root == Path(".")
        assert kwargs == {"plan": planned}
        return _preparation_run(Path.cwd() / "compact-live-preparation" / _PREPARATION_RUN_ID)

    def load(run_path: Path, **kwargs: object) -> object:
        calls.append(("load", run_path, active_pinned_workspace_identity(), kwargs))
        assert kwargs["expected_plan"] is planned
        return _preparation_run(run_path)

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(
        module,
        "_preparation_api",
        lambda: module._PreparationApi(plan=plan, create_run=create, load_run=load),
    )

    result = module.run_operational_skill_bound_web_live_preparation(verified.values)

    assert result.succeeded is True
    assert [entry[0] for entry in calls] == ["plan", "create", "load"]
    assert calls[0][2] is None
    plan_kwargs = cast(dict[str, object], calls[0][3])
    assert plan_kwargs["expected_capacity_pin_digest"] == _CAPACITY_PIN
    assert plan_kwargs["expected_capacity_proof_digest"] == _CAPACITY_PROOF
    assert plan_kwargs["expected_capacity_model_materialization_attestation_digest"] == (
        _ATTESTATION
    )
    assert plan_kwargs["expected_transport_pin_digest"] == _TRANSPORT
    for entry in calls[1:]:
        assert entry[2] is not None
    summary = result.summary
    assert summary["status"] == "prepared-not-authorized-no-dispatch"
    assert summary["strictCapacityV2Reloaded"] is True
    assert summary["strictPreparationReloaded"] is True
    assert summary["modelRuntimeStartCount"] == 0
    assert summary["modelInvocationCount"] == 0
    assert summary["providerDispatchCount"] == 0
    assert summary["targetRequestCount"] == 0
    assert summary["futureLiveCallAuthorized"] is False
    assert summary["executionAuthority"] is False
    assert active_pinned_workspace_identity() is None
    serialized = str(summary)
    assert str(tmp_path) not in serialized
    assert "api-key" not in serialized.lower()


def test_runner_rejects_strict_reload_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _verified(tmp_path)

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(
        module,
        "_preparation_api",
        lambda: module._PreparationApi(
            plan=lambda **_kwargs: object(),
            create_run=lambda _root, **_kwargs: _preparation_run(Path("created")),
            load_run=lambda _path, **_kwargs: _preparation_run(
                Path("created"), index_digest="c" * 64
            ),
        ),
    )

    with pytest.raises(
        module.OperationalSkillBoundWebLivePreparationError,
        match="strictly reloaded preparation differs",
    ):
        module.run_operational_skill_bound_web_live_preparation(verified.values)


def test_runner_holds_output_inode_and_fails_closed_on_path_rebinding(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    verified = _verified(tmp_path)
    output_root = verified.output_root
    parked = tmp_path / "parked-output"
    victim = tmp_path / "victim"

    def create(output: Path, **_kwargs: object) -> object:
        assert output == Path(".")
        output_root.rename(parked)
        victim.mkdir()
        output_root.symlink_to(victim, target_is_directory=True)
        marker = Path("sealed-under-held-inode.txt")
        marker.write_text("held", encoding="utf-8")
        return _preparation_run(Path("compact-live-preparation") / _PREPARATION_RUN_ID)

    monkeypatch.setattr(module, "_verify_inputs", lambda _values: verified)
    monkeypatch.setattr(
        module,
        "_preparation_api",
        lambda: module._PreparationApi(
            plan=lambda **_kwargs: object(),
            create_run=create,
            load_run=lambda path, **_kwargs: _preparation_run(path),
        ),
    )

    with pytest.raises(module.OperationalSkillBoundWebLivePreparationError):
        module.run_operational_skill_bound_web_live_preparation(verified.values)

    assert not any(victim.iterdir())
    assert (parked / "sealed-under-held-inode.txt").read_text(encoding="utf-8") == "held"
    assert active_pinned_workspace_identity() is None


def test_runner_rejects_nonzero_or_true_execution_state(tmp_path: Path) -> None:
    run = _preparation_run(tmp_path / "run")

    class _UnsafeState(_State):
        def model_dump(self, *, mode: str, by_alias: bool) -> dict[str, object]:
            values = super().model_dump(mode=mode, by_alias=by_alias)
            values["providerDispatchCount"] = 1
            return values

    run.preparation.execution_state = _UnsafeState()
    with pytest.raises(module.OperationalSkillBoundWebLivePreparationError):
        module._preparation_view(run)


def test_operational_preparation_module_has_no_runtime_or_dispatch_imports() -> None:
    source_path = Path(module.__file__)
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
        "subprocess",
        "httpx",
        "pajin.providers.session",
        "pajin.runtime.secrets",
        "pajin.runtime.worker",
        "pajin.tools.gateway",
        "pajin.web_assessment.analysis_skill_runtime",
    }
    assert not {
        imported
        for imported in imports
        if any(imported == item or imported.startswith(item + ".") for item in forbidden)
    }
