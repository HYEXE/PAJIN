from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from pajin.runtime.store import AuditEvent, RunStore
from pajin.workflow.web_measured_product_flow import (
    WebMeasuredProductFlowError,
    WebMeasuredProductFlowProjector,
    load_web_measured_product_flow,
)
from tests.test_web_measured_product_flow import (
    _install_source_loader,
    _project,
    _source_material,
)
from tests.web_measured_product_fresh_process import (
    _LOCK_ROOT_NAME,
    _is_lock_mutation,
    _tree_snapshot,
)

pytest_plugins = ("tests.test_web_validation_evaluation",)


def test_ux_009d_audit_allows_only_exact_integrity_lock_mutations(
    tmp_path: Path,
) -> None:
    audit_root = tmp_path / "audit-root"
    temp_root = audit_root / "process" / "TEMP"
    lock_root = temp_root / _LOCK_ROOT_NAME
    lock_root.mkdir(parents=True, mode=0o700)
    lock_path = lock_root / f"{'a' * 64}.lock"
    lock_path.touch(mode=0o600)
    if os.name == "posix":
        lock_root.chmod(0o700)
        lock_path.chmod(0o600)

    snapshot = _tree_snapshot(audit_root, temp_root=temp_root)

    assert all(_LOCK_ROOT_NAME not in entry.relative_path for entry in snapshot)
    assert _is_lock_mutation("os.mkdir", lock_root, temp_root=temp_root)
    assert _is_lock_mutation("os.chmod", lock_root, temp_root=temp_root)
    assert _is_lock_mutation("open", lock_path, temp_root=temp_root)
    assert not _is_lock_mutation("open", lock_root, temp_root=temp_root)
    assert not _is_lock_mutation("os.mkdir", lock_path, temp_root=temp_root)
    assert not _is_lock_mutation(
        "open",
        lock_root / "artifact.json",
        temp_root=temp_root,
    )
    assert not _is_lock_mutation(
        "open",
        lock_root / "nested" / f"{'b' * 64}.lock",
        temp_root=temp_root,
    )

    lock_root.joinpath("artifact.json").write_text("{}", encoding="utf-8")
    with pytest.raises(AssertionError, match="lock root has another entry"):
        _tree_snapshot(audit_root, temp_root=temp_root)


def _rewrite_events_and_reseal(
    *,
    run_id: str,
    run_path: Path,
    events: list[AuditEvent],
) -> None:
    previous_hash: str | None = None
    encoded: list[str] = []
    for sequence, event in enumerate(events, start=1):
        pending = event.model_copy(
            update={
                "sequence": sequence,
                "previous_hash": previous_hash,
                "event_hash": "0" * 64,
            }
        )
        finalized = pending.model_copy(update={"event_hash": pending.computed_hash()})
        encoded.append(finalized.model_dump_json())
        previous_hash = finalized.event_hash
    run_path.joinpath("events.jsonl").write_text(
        "\n".join(encoded) + "\n",
        encoding="utf-8",
    )
    run_path.joinpath("run-integrity.jsonl").unlink()
    RunStore(run_id=run_id, path=run_path).seal()


def test_ux_009d_repeated_publication_has_identical_canonical_bytes_and_digests(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, context = _source_material(web002d_context, tmp_path)
    _install_source_loader(
        monkeypatch,
        state=[authority],
        context=context,
        output_root=tmp_path / "first-product",
    )

    first = WebMeasuredProductFlowProjector(output_root=tmp_path / "first-product").project(
        source, reopen_context=context
    )
    second = WebMeasuredProductFlowProjector(output_root=tmp_path / "second-product").project(
        source, reopen_context=context
    )

    assert first.run_id != second.run_id
    assert first.projection == second.projection
    assert first.projection.flow_id == second.projection.flow_id
    assert first.projection.flow_digest == second.projection.flow_digest
    assert first.projection.source_authority_id == second.projection.source_authority_id
    assert first.projection.source_authority_digest == second.projection.source_authority_digest
    assert (
        first.run_path.joinpath(first.artifact_path).read_bytes()
        == second.run_path.joinpath(second.artifact_path).read_bytes()
    )
    assert load_web_measured_product_flow(first, reopen_context=context) == first.projection
    assert load_web_measured_product_flow(second, reopen_context=context) == second.projection


def test_ux_009d_rejects_rehashed_and_resealed_product_event_equivocation(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _, _, context, _, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    events = [
        AuditEvent.model_validate_json(line)
        for line in outcome.run_path.joinpath("events.jsonl")
        .read_text(encoding="utf-8")
        .splitlines()
    ]
    projected = events[1]
    events[1] = projected.model_copy(
        update={
            "payload": {
                **projected.payload,
                "flowDigest": "0" * 64,
            }
        }
    )
    _rewrite_events_and_reseal(
        run_id=outcome.run_id,
        run_path=outcome.run_path,
        events=events,
    )

    with pytest.raises(WebMeasuredProductFlowError, match="not sealed and reproducible"):
        load_web_measured_product_flow(outcome, reopen_context=context)
