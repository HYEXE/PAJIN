import json
import os
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from typer.testing import CliRunner

import pajin.cli as cli
import pajin.runtime.store as store_module
from pajin.runtime.store import (
    AuditEvent,
    RunIntegrityError,
    RunIntegritySeal,
    RunStore,
    load_verified_run_artifacts,
    load_verified_run_events,
    load_verified_run_snapshot,
    verify_run_integrity,
)


def _sealed_run(tmp_path: Path) -> tuple[RunStore, RunIntegritySeal]:
    store = RunStore.create(tmp_path, "integrity-test")
    store.write_json("campaign.json", {"name": "integrity-test"})
    evidence = store.write_json(
        "evidence/request-1.json",
        {
            "request": {
                "request_id": "request-1",
                "tool_id": "test.probe",
            },
            "workerJob": {"executionId": "execution-1"},
            "result": {"success": True},
        },
    )
    store.append_event("campaign.started", {"campaign": "integrity-test"})
    store.append_event(
        "tool.completed",
        {"requestId": "request-1", "evidence": evidence},
    )
    store.append_event("campaign.completed", {"report": "report.md"})
    store.write_text("report.md", "# Integrity test")
    return store, store.seal()


def test_run_seal_binds_artifacts_events_and_evidence_provenance(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)

    verification = verify_run_integrity(store.path)

    assert verification.valid
    assert verification.run_id == store.run_id
    assert verification.seal_count == 1
    assert verification.artifact_count == 3
    assert verification.event_count == 3
    assert verification.root_digest == seal.root_digest
    evidence = next(item for item in seal.artifacts if item.path == "evidence/request-1.json")
    assert evidence.provenance is not None
    assert evidence.provenance.request_id == "request-1"
    assert evidence.provenance.tool_id == "test.probe"
    assert evidence.provenance.execution_id == "execution-1"
    assert len(evidence.provenance.event_ids) == 1


def test_verified_run_snapshot_returns_exact_bounded_events_and_seals(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)

    snapshot = load_verified_run_artifacts(
        store.path,
        requests={"campaign.json": 1024, "evidence/request-1.json": 4096},
        expected_run_id=store.run_id,
    )

    assert snapshot.run_path == store.path
    assert snapshot.verification.root_digest == seal.root_digest
    assert tuple(event.sequence for event in snapshot.events) == (1, 2, 3)
    assert tuple(item.root_digest for item in snapshot.seals) == (seal.root_digest,)
    assert snapshot.artifact_bytes("campaign.json") == (store.path / "campaign.json").read_bytes()
    assert (
        snapshot.artifact_bytes("evidence/request-1.json")
        == (store.path / "evidence/request-1.json").read_bytes()
    )
    with pytest.raises(TypeError):
        snapshot.artifacts["campaign.json"] = b"substituted"  # type: ignore[index]
    assert load_verified_run_events(store.path) == snapshot.events
    with pytest.raises(RunIntegrityError, match="differs from the expected Run"):
        load_verified_run_snapshot(store.path, expected_run_id="run_foreign")


def test_verified_run_snapshot_serializes_with_cooperative_writer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, original_seal = _sealed_run(tmp_path)
    original_load = store_module._load_events
    reader_entered = threading.Event()
    release_reader = threading.Event()
    writer_finished = threading.Event()
    blocked_once = False

    def block_first_load(
        events_path: Path,
        *,
        expected_run_id: str | None = None,
    ) -> list[AuditEvent]:
        nonlocal blocked_once
        if not blocked_once:
            blocked_once = True
            reader_entered.set()
            if not release_reader.wait(timeout=5):
                raise AssertionError("timed out waiting to release verified Run reader")
        return original_load(events_path, expected_run_id=expected_run_id)

    monkeypatch.setattr(store_module, "_load_events", block_first_load)

    def append_extension() -> None:
        store.append_event("assessment.completed", {})
        store.seal()
        writer_finished.set()

    with ThreadPoolExecutor(max_workers=2) as executor:
        reader = executor.submit(load_verified_run_snapshot, store.path)
        assert reader_entered.wait(timeout=5)
        writer = executor.submit(append_extension)
        try:
            assert not writer_finished.wait(timeout=0.2)
        finally:
            release_reader.set()
        snapshot = reader.result(timeout=5)
        writer.result(timeout=5)

    assert snapshot.verification.root_digest == original_seal.root_digest
    assert verify_run_integrity(store.path).root_digest != original_seal.root_digest


@pytest.mark.parametrize(
    "requests",
    [
        {"events.jsonl": 1024},
        {"../campaign.json": 1024},
        {"campaign.json": 1024, "Campaign.json": 1024},
        {"campaign.json": 64 * 1024 * 1024 + 1},
    ],
)
def test_verified_artifact_snapshot_rejects_unsafe_requests(
    tmp_path: Path,
    requests: dict[str, int],
) -> None:
    store, _ = _sealed_run(tmp_path)

    with pytest.raises(ValueError, match=r"artifact|path|reserved|duplicate|byte limits"):
        load_verified_run_artifacts(store.path, requests=requests)


def test_verified_artifact_snapshot_binds_loaded_bytes_to_final_seal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _ = _sealed_run(tmp_path)
    original_read = store_module.read_bounded_regular_bytes

    def substitute_campaign(
        path: Path,
        *,
        max_bytes: int,
        label: str,
        require_single_link: bool = False,
    ) -> bytes:
        content = original_read(
            path,
            max_bytes=max_bytes,
            label=label,
            require_single_link=require_single_link,
        )
        return content + b" " if path.name == "campaign.json" else content

    monkeypatch.setattr(store_module, "read_bounded_regular_bytes", substitute_campaign)

    with pytest.raises(RunIntegrityError, match="differs from its final seal record"):
        load_verified_run_artifacts(store.path, requests={"campaign.json": 1024})


@pytest.mark.parametrize("hard_link_target", ["artifact", "events"])
def test_run_integrity_rejects_external_hard_links(
    tmp_path: Path,
    hard_link_target: str,
) -> None:
    store = RunStore.create(tmp_path, f"hard-link-{hard_link_target}")
    store.append_event("campaign.started", {})
    artifact = store.path / store.write_text("artifact.txt", "sealed content")
    target = artifact if hard_link_target == "artifact" else store.events_path
    os.link(target, tmp_path / f"outside-{hard_link_target}")

    with pytest.raises(RunIntegrityError, match=r"hard links|single-link"):
        store.seal()


def test_integrity_validation_does_not_materialize_complete_logs_with_read_text(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store, _ = _sealed_run(tmp_path)

    def reject_unbounded_read_text(*_args: object, **_kwargs: object) -> str:
        raise AssertionError("integrity validation must stream bounded log records")

    monkeypatch.setattr(Path, "read_text", reject_unbounded_read_text)

    assert verify_run_integrity(store.path).valid


@pytest.mark.parametrize("log_kind", ["events", "seals"])
def test_integrity_rejects_an_oversized_jsonl_record_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    log_kind: str,
) -> None:
    store = RunStore.create(tmp_path, f"oversized-{log_kind}")
    store.append_event("campaign.started", {})
    if log_kind == "events":
        monkeypatch.setattr(store_module, "_MAX_AUDIT_EVENT_RECORD_BYTES", 64)
        store.events_path.write_bytes(b"x" * 65)
    else:
        monkeypatch.setattr(store_module, "_MAX_INTEGRITY_SEAL_RECORD_BYTES", 64)
        store.integrity_path.write_bytes(b"x" * 65)

    with pytest.raises(RunIntegrityError, match="record exceeds the 64-byte limit"):
        verify_run_integrity(store.path)


@pytest.mark.parametrize("log_kind", ["events", "seals"])
@pytest.mark.parametrize("attack", ["duplicate-key", "non-finite", "deep"])
def test_integrity_strictly_parses_each_jsonl_record_before_model_validation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    log_kind: str,
    attack: str,
) -> None:
    store = RunStore.create(tmp_path, f"strict-jsonl-{log_kind}-{attack}")
    store.append_event("campaign.started", {})
    store.seal()
    path = store.events_path if log_kind == "events" else store.integrity_path
    line = path.read_bytes()
    assert line.startswith(b"{")
    if attack == "duplicate-key":
        injected = b'"run_id":' + json.dumps(store.run_id).encode("utf-8")
    elif attack == "non-finite":
        injected = b'"structural_probe":NaN'
    else:
        injected = b'"structural_probe":' + (b"[" * 70) + b"0" + (b"]" * 70)
    path.write_bytes(b"{" + injected + b"," + line[1:])

    model_type = AuditEvent if log_kind == "events" else RunIntegritySeal

    def unexpected_model_parse(*_args: object, **_kwargs: object) -> object:
        raise AssertionError("unsafe JSON reached Pydantic before strict structural parsing")

    monkeypatch.setattr(model_type, "model_validate", classmethod(unexpected_model_parse))
    monkeypatch.setattr(
        model_type,
        "model_validate_json",
        classmethod(unexpected_model_parse),
    )

    expected = "invalid Audit Event" if log_kind == "events" else "invalid Run seal"
    with pytest.raises(RunIntegrityError, match=expected):
        verify_run_integrity(store.path)


@pytest.mark.parametrize("log_kind", ["events", "seals"])
def test_integrity_rejects_excessive_jsonl_record_counts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    log_kind: str,
) -> None:
    store = RunStore.create(tmp_path, f"record-count-{log_kind}")
    store.append_event("campaign.started", {})
    if log_kind == "events":
        store.append_event("worker.progress", {})
        store.seal()
        monkeypatch.setattr(store_module, "_MAX_AUDIT_EVENT_RECORDS", 1)
    else:
        store.seal()
        store.append_event("worker.progress", {})
        store.seal()
        monkeypatch.setattr(store_module, "_MAX_INTEGRITY_SEAL_RECORDS", 1)

    with pytest.raises(RunIntegrityError, match="exceeds the 1-record limit"):
        verify_run_integrity(store.path)


@pytest.mark.parametrize("log_kind", ["events", "seals"])
def test_integrity_rejects_oversized_jsonl_files_before_parsing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    log_kind: str,
) -> None:
    store = RunStore.create(tmp_path, f"file-size-{log_kind}")
    store.append_event("campaign.started", {})
    if log_kind == "events":
        monkeypatch.setattr(store_module, "_MAX_EVENT_LOG_BYTES", 1)
    else:
        store.seal()
        monkeypatch.setattr(store_module, "_MAX_INTEGRITY_LOG_BYTES", 1)

    with pytest.raises(RunIntegrityError, match="exceeds the 1-byte limit"):
        verify_run_integrity(store.path)


def test_seal_rejects_oversized_evidence_provenance_json_before_loading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore.create(tmp_path, "bounded-provenance")
    store.append_event("campaign.started", {})
    sensitive_source = "sensitive-source-MUST-NOT-PERSIST"
    store.write_json(
        f"evidence/{sensitive_source}.json",
        {"request": {"request_id": "request-1", "padding": "x" * 128}},
    )
    monkeypatch.setattr(store_module, "_MAX_PROVENANCE_JSON_BYTES", 64)

    with pytest.raises(RunIntegrityError) as raised:
        store.seal()
    assert str(raised.value) == "Run evidence provenance source could not be read safely"
    assert sensitive_source not in str(raised.value)
    assert not store.integrity_path.exists()


@pytest.mark.parametrize("attack", ["duplicate-key", "non-finite", "deep"])
def test_seal_does_not_extract_provenance_from_ambiguous_json(
    tmp_path: Path,
    attack: str,
) -> None:
    store = RunStore.create(tmp_path, f"strict-provenance-{attack}")
    if attack == "duplicate-key":
        payload = (
            '{"request":{"request_id":"ambiguous",'
            '"request_id":"last-wins","tool_id":"unsafe.probe"}}'
        )
    elif attack == "non-finite":
        payload = '{"request":{"request_id":"ambiguous","tool_id":"unsafe.probe"},"score":NaN}'
    else:
        nested = "[" * 70 + "0" + "]" * 70
        payload = (
            f'{{"request":{{"request_id":"ambiguous","tool_id":"unsafe.probe"}},"nested":{nested}}}'
        )
    evidence_path = store.write_text("evidence/ambiguous.json", payload)
    store.append_event("campaign.started", {})
    store.append_event("tool.completed", {"evidence": evidence_path})

    seal = store.seal()

    evidence = next(item for item in seal.artifacts if item.path == evidence_path)
    assert evidence.provenance is not None
    assert evidence.provenance.request_id is None
    assert evidence.provenance.tool_id is None
    assert evidence.provenance.execution_id is None
    assert len(evidence.provenance.event_ids) == 1


def test_integrity_rejects_changed_and_missing_sealed_artifacts(tmp_path: Path) -> None:
    changed_store, _ = _sealed_run(tmp_path / "changed")
    campaign = changed_store.path / "campaign.json"
    campaign.write_text('{"name":"tampered"}\n', encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="sealed Run artifact changed"):
        verify_run_integrity(changed_store.path)
    with pytest.raises(RunIntegrityError, match="cannot be overwritten"):
        changed_store.write_json("campaign.json", {"name": "rewritten"})

    missing_store, _ = _sealed_run(tmp_path / "missing")
    (missing_store.path / "report.md").unlink()
    with pytest.raises(RunIntegrityError, match="sealed Run artifact is missing"):
        verify_run_integrity(missing_store.path)


def test_integrity_rejects_unsealed_file_addition(tmp_path: Path) -> None:
    store, _ = _sealed_run(tmp_path)
    (store.path / "unexpected.txt").write_text("not sealed\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="Run contains unsealed artifacts"):
        verify_run_integrity(store.path)


def test_integrity_rejects_audit_event_reordering(tmp_path: Path) -> None:
    store, _ = _sealed_run(tmp_path)
    lines = store.events_path.read_text(encoding="utf-8").splitlines()
    lines[0], lines[1] = lines[1], lines[0]
    store.events_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="event sequence is not contiguous"):
        verify_run_integrity(store.path)


def test_integrity_extension_chains_new_artifacts_to_previous_root(tmp_path: Path) -> None:
    store, first = _sealed_run(tmp_path)
    extension_path = store.write_json("derived/assessment.json", {"status": "complete"})
    store.append_event("assessment.completed", {"assessment": extension_path})

    second = store.seal()
    verification = verify_run_integrity(store.path)

    assert second.sequence == 2
    assert second.previous_root_digest == first.root_digest
    assert [item.path for item in second.artifacts] == ["derived/assessment.json"]
    assert verification.seal_count == 2
    assert verification.artifact_count == 4
    assert verification.event_count == 4
    seals = [
        RunIntegritySeal.model_validate_json(line)
        for line in store.integrity_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [item.root_digest for item in seals] == [first.root_digest, second.root_digest]


def test_run_store_rejects_casefold_and_non_nfc_artifact_aliases(tmp_path: Path) -> None:
    RunStore.create(tmp_path / "campaigns", "Campaign")
    with pytest.raises(RunIntegrityError, match="campaign output path collides"):
        RunStore.create(tmp_path / "campaigns", "campaign")

    open_store = RunStore.create(tmp_path / "open", "canonical-paths")
    open_store.write_text("evidence/ToolA.txt", "first")

    with pytest.raises(RunIntegrityError, match="case-fold normalization"):
        open_store.write_text("evidence/toola.txt", "second")
    with pytest.raises(ValueError, match="NFC Unicode normalization"):
        open_store.write_text("evidence/cafe\N{COMBINING ACUTE ACCENT}.txt", "second")

    sealed_store = RunStore.create(tmp_path / "sealed", "canonical-paths")
    sealed_store.write_text("Report.md", "sealed")
    sealed_store.append_event("campaign.completed", {"report": "Report.md"})
    sealed_store.seal()

    with pytest.raises(
        RunIntegrityError,
        match=r"case-fold normalization|cannot be overwritten",
    ):
        sealed_store.write_text("report.md", "must not overwrite")
    assert (sealed_store.path / "Report.md").read_text(encoding="utf-8") == "sealed\n"
    assert verify_run_integrity(sealed_store.path).valid


@pytest.mark.parametrize(
    "relative_path",
    [
        "evidence/cafe\N{COMBINING ACUTE ACCENT}.json",
        "evidence/bidi\N{RIGHT-TO-LEFT OVERRIDE}.json",
        "evidence/zero\N{ZERO WIDTH SPACE}width.json",
        "evidence/result:.json",
        "evidence/NUL.json",
        "evidence/COM1.log",
        "evidence/CON .txt",
        "evidence/trailing-dot.",
        "evidence/trailing-space ",
    ],
)
def test_run_store_writer_rejects_non_portable_artifact_paths(
    tmp_path: Path,
    relative_path: str,
) -> None:
    store = RunStore.create(tmp_path, "portable-writer")

    with pytest.raises(ValueError, match="artifact path"):
        store.write_text(relative_path, "must not be written")


@pytest.mark.parametrize(
    ("case_name", "relative_path"),
    [
        ("nfd", "evidence/cafe\N{COMBINING ACUTE ACCENT}.json"),
        ("bidi", "evidence/bidi\N{RIGHT-TO-LEFT OVERRIDE}.json"),
        ("zero-width", "evidence/zero\N{ZERO WIDTH SPACE}width.json"),
        ("windows-character", "evidence/result:.json"),
        ("windows-device", "evidence/NUL.json"),
        ("trailing-period", "evidence/trailing-dot."),
        ("trailing-space", "evidence/trailing-space "),
    ],
)
def test_seal_rejects_externally_created_non_portable_artifact_paths(
    tmp_path: Path,
    case_name: str,
    relative_path: str,
) -> None:
    store = RunStore.create(tmp_path / case_name, "portable-seal")
    store.append_event("campaign.started", {})
    (store.path / relative_path).write_text("external\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="artifact path is not portable"):
        store.seal()

    assert not store.integrity_path.exists()


def test_verify_rejects_non_portable_path_in_forged_seal(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)
    forged_artifacts = [
        artifact.model_copy(update={"path": "NUL.json"}) if index == 0 else artifact
        for index, artifact in enumerate(seal.artifacts)
    ]
    forged_artifacts.sort(key=lambda artifact: artifact.path)
    forged = seal.model_copy(
        update={
            "artifacts": forged_artifacts,
            "artifact_root_digest": "0" * 64,
            "root_digest": "0" * 64,
        }
    )
    forged = forged.model_copy(
        update={"artifact_root_digest": forged.computed_artifact_root_digest()}
    )
    forged = forged.model_copy(update={"root_digest": forged.computed_root_digest()})
    store.integrity_path.write_text(forged.model_dump_json() + "\n", encoding="utf-8")

    with pytest.raises(RunIntegrityError, match="non-portable artifact path"):
        verify_run_integrity(store.path)


@pytest.mark.parametrize(
    "second_terminal",
    ["campaign.failed", "campaign.cancelled", "campaign.budget-exhausted"],
)
def test_run_store_rejects_a_second_campaign_terminal_event(
    tmp_path: Path,
    second_terminal: str,
) -> None:
    store = RunStore.create(tmp_path, "single-terminal")
    store.append_event("campaign.started", {})
    store.append_event("campaign.completed", {"report": "report.md"})

    with pytest.raises(RunIntegrityError, match="already contains Campaign terminal"):
        store.append_event(second_terminal, {"errorType": "InjectedFailure"})

    assert len(store.events_path.read_text(encoding="utf-8").splitlines()) == 2


def test_integrity_rejects_externally_forged_multiple_campaign_terminal_events(
    tmp_path: Path,
) -> None:
    store = RunStore.create(tmp_path, "forged-terminal")
    store.append_event("campaign.started", {})
    completed = store.append_event("campaign.completed", {"report": "report.md"})
    forged = AuditEvent(
        run_id=store.run_id,
        sequence=completed.sequence + 1,
        event_type="campaign.failed",
        occurred_at=completed.occurred_at,
        payload={"errorType": "InjectedFailure"},
        previous_hash=completed.event_hash,
        event_hash="0" * 64,
    )
    forged = forged.model_copy(update={"event_hash": forged.computed_hash()})
    with store.events_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(forged.model_dump_json() + "\n")

    with pytest.raises(RunIntegrityError, match="multiple Campaign terminal events"):
        verify_run_integrity(store.path)


def test_run_store_fsyncs_root_after_creating_campaign_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    synced: list[Path] = []
    monkeypatch.setattr(store_module, "_fsync_directory", synced.append)
    root = tmp_path / "runs"

    RunStore.create(root, "durable-campaign")

    assert root.resolve() in synced


def test_write_json_serializes_strictly_before_replacing_existing_artifact(
    tmp_path: Path,
) -> None:
    store = RunStore.create(tmp_path, "strict-json")
    artifact = store.path / store.write_json("state.json", {"old": "complete"})
    original = artifact.read_bytes()

    with pytest.raises(TypeError):
        store.write_json("state.json", {"prefix": "would truncate", "bad": object()})
    with pytest.raises(ValueError, match="JSON compliant"):
        store.write_json("state.json", {"notFinite": float("nan")})

    assert artifact.read_bytes() == original
    assert not list(store.path.glob(".pajin-write.*.tmp"))


def test_write_json_create_only_never_replaces_installed_bytes(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "create-only-json")
    artifact = store.path / store.write_json_create_only(
        "requests/tool_once.json",
        {"winner": "first"},
    )
    original = artifact.read_bytes()

    with pytest.raises(FileExistsError):
        store.write_json_create_only(
            "requests/tool_once.json",
            {"winner": "second"},
        )

    assert artifact.read_bytes() == original
    assert not list((store.path / "requests").glob(".pajin-create.*.create"))


def test_atomic_temp_names_do_not_repeat_long_destination_names(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore.create(tmp_path, "bounded-temp-prefix")
    real_mkstemp = store_module.tempfile.mkstemp
    observed_prefixes: list[str] = []

    def record_prefix(*args: object, **kwargs: object) -> tuple[int, str]:
        prefix = kwargs.get("prefix")
        assert isinstance(prefix, str)
        observed_prefixes.append(prefix)
        return real_mkstemp(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(store_module.tempfile, "mkstemp", record_prefix)
    long_name = f"{'artifact-' * 5}.json"

    store.write_json(long_name, {"replace": True})
    store.write_json_create_only(f"requests/{long_name}", {"create": True})

    assert observed_prefixes == [".pajin-write.", ".pajin-create."]
    assert all(long_name not in prefix for prefix in observed_prefixes)


def test_write_json_create_only_arbitrates_across_processes(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "create-only-processes")
    script = """
import json
import sys
from pathlib import Path
from pajin.runtime.store import RunStore

store = RunStore(sys.argv[1], Path(sys.argv[2]))
try:
    store.write_json_create_only("requests/tool_process.json", {"winner": sys.argv[3]})
except FileExistsError:
    print("duplicate")
else:
    print("created")
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, store.run_id, str(store.path), winner],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for winner in ("first", "second")
    ]
    completed = [process.communicate(timeout=10) for process in processes]

    assert [process.returncode for process in processes] == [0, 0]
    assert sorted(stdout.strip() for stdout, _stderr in completed) == [
        "created",
        "duplicate",
    ]
    payload = json.loads((store.path / "requests/tool_process.json").read_text())
    assert payload["winner"] in {"first", "second"}
    assert not list((store.path / "requests").glob(".pajin-create.*.create"))


def test_cross_instance_append_rebases_stale_event_and_terminal_state(
    tmp_path: Path,
) -> None:
    first = RunStore.create(tmp_path, "cross-instance-events")
    second = RunStore(first.run_id, first.path)

    started = first.append_event("campaign.started", {})
    progress = second.append_event("worker.progress", {"writer": "second"})
    rebased = first.append_event("worker.progress", {"writer": "first"})
    terminal = second.append_event("campaign.completed", {})

    assert [started.sequence, progress.sequence, rebased.sequence, terminal.sequence] == [
        1,
        2,
        3,
        4,
    ]
    assert rebased.previous_hash == progress.event_hash
    with pytest.raises(RunIntegrityError, match="already contains Campaign terminal"):
        first.append_event("campaign.failed", {"errorType": "StaleCache"})

    seal = first.seal()
    verification = verify_run_integrity(first.path)
    events = [
        AuditEvent.model_validate_json(line)
        for line in first.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event.sequence for event in events] == [1, 2, 3, 4]
    assert seal.event_count == 4
    assert verification.event_count == 4
    assert store_module._RUN_MUTATION_LOCK_NAME not in {
        artifact.path for artifact in seal.artifacts
    }


def test_event_appends_are_serialized_across_processes(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "cross-process-events")
    store.append_event("campaign.started", {})
    start_signal = tmp_path / "start-concurrent-appends"
    script = """
import sys
import time
from pathlib import Path
from pajin.runtime.store import RunStore

store = RunStore(sys.argv[1], Path(sys.argv[2]))
start_signal = Path(sys.argv[3])
rebase = getattr(store, "_rebase_event_state", None)
if rebase is None:
    rebase = store._ensure_event_state
rebase()
Path(sys.argv[5]).touch()
while not start_signal.exists():
    time.sleep(0.005)
for ordinal in range(8):
    store.append_event("worker.progress", {"writer": sys.argv[4], "ordinal": ordinal})
"""
    processes = [
        subprocess.Popen(
            [
                sys.executable,
                "-c",
                script,
                store.run_id,
                str(store.path),
                str(start_signal),
                str(writer),
                str(tmp_path / f"append-ready-{writer}"),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for writer in range(4)
    ]
    ready_paths = [tmp_path / f"append-ready-{writer}" for writer in range(4)]
    deadline = time.monotonic() + 10
    while not all(path.exists() for path in ready_paths) and time.monotonic() < deadline:
        time.sleep(0.005)
    assert all(path.exists() for path in ready_paths)
    start_signal.touch()
    completed = [process.communicate(timeout=20) for process in processes]

    assert [process.returncode for process in processes] == [0, 0, 0, 0], completed
    events = [
        AuditEvent.model_validate_json(line)
        for line in store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [event.sequence for event in events] == list(range(1, 34))
    assert all(
        event.previous_hash == (events[index - 1].event_hash if index else None)
        for index, event in enumerate(events)
    )
    store.append_event("campaign.completed", {})
    store.seal()
    assert verify_run_integrity(store.path).event_count == 34


def test_concurrent_seals_append_exactly_one_integrity_extension(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "concurrent-seals")
    store.write_text("report.md", "ready")
    store.append_event("campaign.completed", {"report": "report.md"})
    start_signal = tmp_path / "start-concurrent-seals"
    script = """
import sys
import time
from pathlib import Path
from pajin.runtime.store import RunIntegrityError, RunStore

store = RunStore(sys.argv[1], Path(sys.argv[2]))
start_signal = Path(sys.argv[3])
while not start_signal.exists():
    time.sleep(0.005)
try:
    store.seal()
except RunIntegrityError as exc:
    if "no new artifacts or events" not in str(exc):
        raise
    print("rejected")
else:
    print("sealed")
"""
    processes = [
        subprocess.Popen(
            [sys.executable, "-c", script, store.run_id, str(store.path), str(start_signal)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        for _ in range(2)
    ]
    start_signal.touch()
    completed = [process.communicate(timeout=20) for process in processes]

    assert [process.returncode for process in processes] == [0, 0], completed
    assert sorted(stdout.strip() for stdout, _stderr in completed) == ["rejected", "sealed"]
    assert len(store.integrity_path.read_text(encoding="utf-8").splitlines()) == 1
    assert verify_run_integrity(store.path).valid


def test_seal_serializes_append_and_artifact_write_interleaving(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore.create(tmp_path, "seal-mutation-interleaving")
    store.append_event("campaign.started", {})
    store.write_text("initial.txt", "initial")
    sealer = RunStore(store.run_id, store.path)
    writer = RunStore(store.run_id, store.path)
    overwriter = RunStore(store.run_id, store.path)
    appender = RunStore(store.run_id, store.path)
    seal_is_hashing = threading.Event()
    release_seal = threading.Event()
    writer_started = threading.Event()
    overwriter_started = threading.Event()
    appender_started = threading.Event()
    original_artifact_record = store_module._artifact_record

    def paused_artifact_record(
        root: Path,
        relative_path: str,
        event_index: object,
    ) -> object:
        record = original_artifact_record(
            root,
            relative_path,
            event_index,  # type: ignore[arg-type]
        )
        if relative_path == "initial.txt":
            seal_is_hashing.set()
            assert release_seal.wait(timeout=5)
        return record

    def write_late_artifact() -> str:
        writer_started.set()
        return writer.write_text("late.txt", "late")

    def append_late_event() -> AuditEvent:
        appender_started.set()
        return appender.append_event("worker.progress", {"phase": "late"})

    def overwrite_hashed_artifact() -> str:
        overwriter_started.set()
        return overwriter.write_text("initial.txt", "changed after seal hash")

    monkeypatch.setattr(store_module, "_artifact_record", paused_artifact_record)
    with ThreadPoolExecutor(max_workers=4) as executor:
        seal_future = executor.submit(sealer.seal)
        assert seal_is_hashing.wait(timeout=5)
        write_future = executor.submit(write_late_artifact)
        overwrite_future = executor.submit(overwrite_hashed_artifact)
        append_future = executor.submit(append_late_event)
        assert writer_started.wait(timeout=5)
        assert overwriter_started.wait(timeout=5)
        assert appender_started.wait(timeout=5)
        assert not write_future.done()
        assert not overwrite_future.done()
        assert not append_future.done()
        release_seal.set()
        first_seal = seal_future.result(timeout=5)
        assert write_future.result(timeout=5) == "late.txt"
        with pytest.raises(RunIntegrityError, match="sealed Run artifact cannot be overwritten"):
            overwrite_future.result(timeout=5)
        late_event = append_future.result(timeout=5)

    assert [artifact.path for artifact in first_seal.artifacts] == ["initial.txt"]
    assert first_seal.event_count == 1
    assert late_event.sequence == 2
    with pytest.raises(RunIntegrityError, match="unsealed"):
        verify_run_integrity(store.path)

    second_seal = store.seal()
    assert [artifact.path for artifact in second_seal.artifacts] == ["late.txt"]
    assert second_seal.event_count == 2
    assert verify_run_integrity(store.path).valid


def test_run_mutation_lock_is_private_reserved_and_not_sealed(tmp_path: Path) -> None:
    store = RunStore.create(tmp_path, "private-run-lock")
    lock_path = store_module._run_lock_path(store.path)
    lock_path.write_bytes(b"")
    lock_path.chmod(0o666)

    store.append_event("campaign.completed", {})
    with pytest.raises(ValueError, match="reserved by RunStore"):
        store.write_text(store_module._RUN_MUTATION_LOCK_NAME, "not an artifact")
    seal = store.seal()

    if os.name == "posix":
        assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
    assert store_module._RUN_MUTATION_LOCK_NAME not in {
        artifact.path for artifact in seal.artifacts
    }
    assert verify_run_integrity(store.path).valid


def test_run_mutation_lock_rejects_symlink_and_non_regular_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    symlink_store = RunStore.create(tmp_path / "symlink", "invalid-run-lock")
    external = tmp_path / "external-lock-target"
    external.write_text("must remain untouched", encoding="utf-8")
    symlink_lock = store_module._run_lock_path(symlink_store.path)
    symlink_lock.symlink_to(external)

    with pytest.raises(RunIntegrityError, match=r"regular file|symbolic link"):
        symlink_store.append_event("campaign.started", {})
    assert external.read_text(encoding="utf-8") == "must remain untouched"

    directory_store = RunStore.create(tmp_path / "directory", "invalid-run-lock")
    store_module._run_lock_path(directory_store.path).mkdir()
    with pytest.raises(RunIntegrityError, match="regular file"):
        directory_store.write_text("artifact.txt", "blocked")

    root_store = RunStore.create(tmp_path / "root-symlink", "invalid-run-lock")
    external_root = tmp_path / "external-lock-root"
    external_root.mkdir()
    monkeypatch.setattr(store_module.tempfile, "gettempdir", lambda: str(root_store.path.parent))
    store_module._run_lock_root_path().symlink_to(
        external_root,
        target_is_directory=True,
    )
    with pytest.raises(RunIntegrityError, match="lock root must be a real directory"):
        root_store.append_event("campaign.started", {})


def test_atomic_artifact_replace_failure_preserves_previous_complete_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore.create(tmp_path, "atomic-json")
    artifact = store.path / store.write_json("state.json", {"old": "complete"})
    original = artifact.read_bytes()

    def fail_replace(_source: Path, _destination: Path) -> None:
        raise OSError("simulated atomic replace failure")

    monkeypatch.setattr(store_module.os, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated atomic replace failure"):
        store.write_json("state.json", {"new": "complete"})

    assert artifact.read_bytes() == original
    assert not list(store.path.glob(".pajin-write.*.tmp"))


@pytest.mark.skipif(os.name != "posix", reason="POSIX owner-only mode policy")
def test_run_store_creates_private_directories_and_files_under_permissive_umask(
    tmp_path: Path,
) -> None:
    previous_umask = os.umask(0)
    try:
        store = RunStore.create(tmp_path, "private-run")
        store.append_event("campaign.started", {})
        store.write_json("evidence/result.json", {"sensitive": True})
        store.write_text("derived/report.md", "private")
        store.seal()
    finally:
        os.umask(previous_umask)

    for directory in (
        store.path.parent,
        store.path,
        store.evidence_path,
        store.path / "derived",
    ):
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    for artifact in (
        store.events_path,
        store.integrity_path,
        store.path / "evidence/result.json",
        store.path / "derived/report.md",
    ):
        assert stat.S_IMODE(artifact.stat().st_mode) == 0o600


def test_integrity_indexes_each_event_once_for_many_artifacts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = RunStore.create(tmp_path, "linear-provenance")
    for index in range(40):
        relative = store.write_text(f"artifacts/{index}.txt", str(index))
        store.append_event("artifact.created", {"path": relative})
    store.seal()

    original_add = store_module._EventProvenanceIndex.add
    indexed_events = 0

    def counting_add(
        self: store_module._EventProvenanceIndex,
        event: store_module.AuditEvent,
    ) -> None:
        nonlocal indexed_events
        indexed_events += 1
        original_add(self, event)

    monkeypatch.setattr(store_module._EventProvenanceIndex, "add", counting_add)

    verification = verify_run_integrity(store.path)

    assert verification.event_count == 40
    assert verification.artifact_count == 40
    assert indexed_events == verification.event_count


def test_evidence_verify_cli_reports_root_and_fails_closed_on_tamper(tmp_path: Path) -> None:
    store, seal = _sealed_run(tmp_path)
    runner = CliRunner()

    valid = runner.invoke(cli.app, ["evidence-verify", str(store.path)])

    assert valid.exit_code == 0, valid.output
    assert "VALID" in valid.output
    assert seal.root_digest in valid.output

    events = [
        json.loads(line) for line in store.events_path.read_text(encoding="utf-8").splitlines()
    ]
    events[1]["payload"]["requestId"] = "tampered-request"
    store.events_path.write_text(
        "\n".join(json.dumps(item, separators=(",", ":")) for item in events) + "\n",
        encoding="utf-8",
    )
    invalid = runner.invoke(cli.app, ["evidence-verify", str(store.path)])

    assert invalid.exit_code == 1
    assert "verification failed" in invalid.output
