from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path

import pytest

import pajin.modes.ai_redteam.replay as replay_module
import pajin.modes.ai_redteam.replay_source as replay_source_module
from pajin.modes.ai_redteam.replay_source import SealedRunReader, read_object
from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
)


def _sealed_source(tmp_path: Path, content: str) -> Path:
    store = RunStore.create(tmp_path, "replay-source-test")
    store.write_text("payload.json", content)
    store.append_event("replay.source.test-created", {"artifact": "payload.json"})
    store.seal()
    return store.path


@pytest.mark.parametrize(
    "content",
    [
        '{"identity":"first","identity":"second"}',
        '{"metric":NaN}',
        "[" * 70 + "0" + "]" * 70,
    ],
)
def test_sealed_source_reader_rejects_ambiguous_or_deep_json(
    tmp_path: Path,
    content: str,
) -> None:
    reader = SealedRunReader.open(_sealed_source(tmp_path, content))

    with pytest.raises(ValueError, match="sealed replay source artifact could not be read"):
        read_object(reader, "payload.json")


def test_sealed_source_reader_rejects_snapshot_phase_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reader = SealedRunReader.open(_sealed_source(tmp_path, '{"authority":"stable"}'))

    def substitute_verification(
        run_path: Path,
        *,
        requests: Mapping[str, int],
        expected_run_id: str | None = None,
    ) -> VerifiedRunSnapshot:
        loaded = load_verified_run_artifacts(
            run_path,
            requests=requests,
            expected_run_id=expected_run_id,
        )
        return replace(
            loaded,
            verification=loaded.verification.model_copy(update={"root_digest": "0" * 64}),
        )

    monkeypatch.setattr(
        replay_source_module,
        "load_verified_run_artifacts",
        substitute_verification,
    )

    with pytest.raises(
        ValueError,
        match="sealed replay source artifact could not be read",
    ) as caught:
        read_object(reader, "payload.json")
    assert caught.value.__cause__ is not None
    assert "changed while inputs were loaded" in str(caught.value.__cause__)


def test_replay_module_preserves_private_reader_monkeypatch_seam() -> None:
    assert vars(replay_module)["_SealedRunReader"] is SealedRunReader
