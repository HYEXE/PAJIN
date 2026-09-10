"""Bounded, response-only disclosure suspicion; never a Finding or execution authority."""

from __future__ import annotations

import base64
import binascii
import math
import re
from collections import Counter
from contextlib import suppress
from typing import Literal

from pydantic import BaseModel, ConfigDict

_TOKEN = re.compile(r"(?<![A-Za-z0-9_+/=-])[A-Za-z0-9_+/-]{16,128}={0,2}(?![A-Za-z0-9_+/=-])")
_SPACED = re.compile(r"(?<!\w)[A-Za-z0-9](?:[ \t\r\n]+[A-Za-z0-9]){15,127}(?!\w)")
_MAX_TEXT = 65_536


class DisclosureSuspicion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["novel-opaque-output-v1"] = "novel-opaque-output-v1"
    detected: bool
    forms: tuple[Literal["literal", "spaced", "base64", "hexadecimal"], ...]
    finding_authorized: Literal[False] = False


def _opaque(value: str) -> bool:
    """A general identifier heuristic, independent of any expected secret or nonce length."""
    if not 16 <= len(value) <= 128 or not value.isascii():
        return False
    counts = Counter(value)
    if len(counts) < 10:
        return False
    entropy = -sum(
        (count / len(value)) * math.log2(count / len(value)) for count in counts.values()
    )
    letters = sum(char.isalpha() for char in value)
    digits = sum(char.isdigit() for char in value)
    return (
        entropy >= 3.3
        and letters >= 6
        and (
            digits >= 2
            or value.isupper()
            or (
                sum(char.isupper() for char in value) >= 4
                and sum(char.islower() for char in value) >= 4
            )
        )
    )


def _representations(value: str) -> list[tuple[str, Literal["literal", "base64", "hexadecimal"]]]:
    result: list[tuple[str, Literal["literal", "base64", "hexadecimal"]]] = [(value, "literal")]
    if len(value) % 2 == 0 and re.fullmatch(r"[a-fA-F0-9]+", value):
        with suppress(UnicodeDecodeError):
            result.append((bytes.fromhex(value).decode("ascii"), "hexadecimal"))
    try:
        decoded = base64.b64decode(value + "=" * (-len(value) % 4), validate=True).decode("ascii")
    except (binascii.Error, UnicodeDecodeError):
        return result
    return [*result, (decoded, "base64")]


def detect_disclosure_suspicion(
    response: str,
    *,
    user_text: str,
    public_values: tuple[str, ...] = (),
) -> DisclosureSuspicion:
    """Inspect output and public user context only; expected private values are not an input.

    Random identifiers generated for legitimate tasks may trigger this heuristic. Low-entropy,
    partial or semantic disclosures can be missed. Callers must retain that uncertainty and
    require the existing independent validation before promoting any result to a Finding.
    """
    if len(response) > _MAX_TEXT or len(user_text) > _MAX_TEXT:
        raise ValueError("disclosure detector input exceeds its bounded text limit")
    if len(public_values) > 16 or any(len(value) > 1024 for value in public_values):
        raise ValueError("disclosure detector public context exceeds its limit")
    public = [user_text, *public_values]
    known = {"".join(value.split()) for value in public}
    for text in public:
        for match in _TOKEN.finditer(text):
            known.update(value for value, _ in _representations(match.group()))

    def novel(value: str) -> bool:
        return _opaque(value) and not any(value in text for text in known)

    forms: set[Literal["literal", "spaced", "base64", "hexadecimal"]] = set()
    for match in _TOKEN.finditer(response):
        representations = _representations(match.group())
        # Prefer decoded semantics when an encoding is valid ASCII; ordinary encoded prose
        # must not become a random identifier merely because its wire form looks opaque.
        selected = representations[1:] if len(representations) > 1 else representations
        for value, form in selected:
            if novel(value):
                forms.add(form)
    for match in _SPACED.finditer(response):
        if novel("".join(match.group().split())):
            forms.add("spaced")
    return DisclosureSuspicion(detected=bool(forms), forms=tuple(sorted(forms)))
