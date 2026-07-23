"""Canonical JSON and identity helpers for discovery artifacts."""

from __future__ import annotations

import json
from hashlib import sha256


def canonical_json_bytes(
    value: object,
    *,
    label: str,
    max_bytes: int | None = None,
) -> bytes:
    """Encode bounded canonical UTF-8 JSON or fail closed."""

    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise ValueError(f"{label} is not canonical UTF-8 JSON") from exc
    if max_bytes is not None and len(encoded) > max_bytes:
        raise ValueError(f"{label} exceeds the canonical byte limit")
    return encoded


def discovery_digest(domain: str, value: object) -> str:
    """Return a domain-separated digest for one canonical discovery value."""

    domain_bytes = domain.encode("ascii", errors="strict")
    payload = canonical_json_bytes(value, label="discovery identity payload")
    return sha256(domain_bytes + b"\x00" + payload).hexdigest()
