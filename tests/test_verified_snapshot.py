from dataclasses import replace
from pathlib import Path
from types import MappingProxyType

import pytest

from pajin.runtime.store import (
    RunStore,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json


def _sealed_json_snapshot(tmp_path: Path, content: str) -> VerifiedRunSnapshot:
    store = RunStore.create(tmp_path, "verified-snapshot-helper")
    store.write_text("payload.json", content)
    store.append_event("snapshot.test.created", {"artifact": "payload.json"})
    store.seal()
    return load_verified_run_artifacts(
        store.path,
        requests={"payload.json": 1024 * 1024},
    )


@pytest.mark.parametrize(
    "content",
    [
        '{"authority":"first","authority":"second"}',
        '{"metric":NaN}',
        "[" * 70 + "0" + "]" * 70,
    ],
)
def test_strict_snapshot_json_rejects_duplicate_nonfinite_and_deep_inputs(
    tmp_path: Path,
    content: str,
) -> None:
    snapshot = _sealed_json_snapshot(tmp_path, content)

    with pytest.raises(ValueError, match="sealed payload is invalid"):
        strict_json(
            snapshot,
            "payload.json",
            label="sealed payload",
            max_bytes=1024 * 1024,
            missing_or_invalid_message="sealed payload is invalid",
        )


def test_strict_snapshot_json_enforces_the_requested_container_type(tmp_path: Path) -> None:
    snapshot = _sealed_json_snapshot(tmp_path, "[]")

    with pytest.raises(ValueError, match="payload must be an object"):
        strict_json(
            snapshot,
            "payload.json",
            label="sealed payload",
            max_bytes=1024 * 1024,
            expected_type=dict,
            type_message="payload must be an object",
        )


def test_same_authority_allows_phased_subsets_but_rejects_shared_byte_or_path_drift(
    tmp_path: Path,
) -> None:
    full = _sealed_json_snapshot(tmp_path, '{"authority":"stable"}')
    metadata_only = load_verified_run_snapshot(
        full.run_path,
        expected_run_id=full.verification.run_id,
    )

    require_same_authority(metadata_only, full, message="authority changed")
    require_same_authority(full, metadata_only, message="authority changed")

    forged_bytes = replace(
        full,
        artifacts=MappingProxyType({"payload.json": b'{"authority":"forged"}'}),
    )
    with pytest.raises(ValueError, match="authority changed"):
        require_same_authority(full, forged_bytes, message="authority changed")

    foreign_path = replace(metadata_only, run_path=tmp_path / "foreign-run")
    with pytest.raises(ValueError, match="authority changed"):
        require_same_authority(metadata_only, foreign_path, message="authority changed")


def test_same_authority_rejects_each_authoritative_identity_or_history_drift(
    tmp_path: Path,
) -> None:
    snapshot = _sealed_json_snapshot(tmp_path, '{"authority":"stable"}')
    verification = snapshot.verification
    variants = [
        replace(
            snapshot,
            verification=verification.model_copy(update={"run_id": "run_foreign"}),
        ),
        replace(
            snapshot,
            verification=verification.model_copy(update={"root_digest": "0" * 64}),
        ),
        replace(
            snapshot,
            verification=verification.model_copy(
                update={"artifact_count": verification.artifact_count + 1}
            ),
        ),
        replace(
            snapshot,
            events=(snapshot.events[0].model_copy(update={"event_type": "snapshot.test.forged"}),),
        ),
        replace(
            snapshot,
            seals=(snapshot.seals[0].model_copy(update={"seal_id": "seal_forged"}),),
        ),
    ]

    for observed in variants:
        with pytest.raises(ValueError, match="authority changed"):
            require_same_authority(snapshot, observed, message="authority changed")
