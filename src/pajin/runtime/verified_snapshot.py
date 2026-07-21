"""Shared exact-authority and strict-JSON operations for verified Run snapshots."""

from __future__ import annotations

from typing import overload

from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import VerifiedRunSnapshot


def require_same_authority(
    expected: VerifiedRunSnapshot,
    observed: VerifiedRunSnapshot,
    *,
    message: str,
) -> None:
    """Require two phased reads to describe one unchanged sealed Run authority.

    Snapshot phases may intentionally load different artifact subsets. The integrity
    verification, Run/root identities, event stream, and seal chain must still be
    identical, and every artifact loaded by both phases must have identical bytes.
    """

    expected_verification = expected.verification
    observed_verification = observed.verification
    shared_artifact_paths = expected.artifacts.keys() & observed.artifacts.keys()
    if (
        observed.run_path != expected.run_path
        or observed_verification.run_id != expected_verification.run_id
        or observed_verification.root_digest != expected_verification.root_digest
        or observed_verification != expected_verification
        or observed.events != expected.events
        or observed.seals != expected.seals
        or any(
            observed.artifacts[path] != expected.artifacts[path] for path in shared_artifact_paths
        )
    ):
        raise ValueError(message)


@overload
def strict_json[T](
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
    *,
    label: str,
    max_bytes: int,
    expected_type: type[T],
    missing_or_invalid_message: str | None = None,
    type_message: str | None = None,
) -> T: ...


@overload
def strict_json(
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
    *,
    label: str,
    max_bytes: int,
    expected_type: None = None,
    missing_or_invalid_message: str | None = None,
    type_message: str | None = None,
) -> object: ...


def strict_json(
    snapshot: VerifiedRunSnapshot,
    relative_path: str,
    *,
    label: str,
    max_bytes: int,
    expected_type: type[object] | None = None,
    missing_or_invalid_message: str | None = None,
    type_message: str | None = None,
) -> object:
    """Parse one already-pinned artifact with bounded, ambiguity-free JSON rules."""

    try:
        raw = snapshot.artifact_bytes(relative_path)
    except KeyError as exc:
        raise ValueError(missing_or_invalid_message or f"{label} is missing or invalid") from exc
    return strict_json_bytes(
        raw,
        label=label,
        max_bytes=max_bytes,
        expected_type=expected_type,
        missing_or_invalid_message=missing_or_invalid_message,
        type_message=type_message,
    )


def strict_json_bytes(
    raw: bytes,
    *,
    label: str,
    max_bytes: int,
    expected_type: type[object] | None = None,
    missing_or_invalid_message: str | None = None,
    type_message: str | None = None,
) -> object:
    """Parse pinned bytes with the same bounded, ambiguity-free JSON rules."""

    try:
        value = parse_strict_json_bytes(raw, label=label, max_bytes=max_bytes)
    except ValueError as exc:
        raise ValueError(missing_or_invalid_message or f"{label} is missing or invalid") from exc
    if expected_type is not None and not isinstance(value, expected_type):
        if expected_type is dict:
            container_label = "JSON object"
        elif expected_type is list:
            container_label = "JSON array"
        else:
            container_label = expected_type.__name__
        raise ValueError(type_message or f"{label} must contain a {container_label}")
    return value
