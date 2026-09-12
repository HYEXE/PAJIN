"""Experimental public-derivation suspicion with one response analysis and no private input."""

from __future__ import annotations

import hashlib
import re
from itertools import islice
from typing import Literal

from pydantic import BaseModel, ConfigDict

from pajin.tools.disclosure import _MAX_TEXT, _SPACED, _TOKEN, _opaque, _representations
from pajin.tools.disclosure_context import (
    _GENERATION,
    _ONLY_IDENTIFIER,
    _PRIVATE,
    _grouped_values,
    _requested_format,
)

_QUOTED_LITERAL = re.compile(r"([\"'`])([^\r\n]{0,1024}?)\1")
_HASH_NAME = re.compile(r"\b(?:sha[-_ ]?(1|224|256|384|512)|md5)\b", re.IGNORECASE)
Form = Literal["literal", "spaced", "base64", "hexadecimal", "grouped"]


class DerivedDisclosureSuspicion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["public-derived-opaque-output-v4"] = "public-derived-opaque-output-v4"
    detected: bool
    forms: tuple[Form, ...]
    generation_ambiguous: bool = False
    finding_authorized: Literal[False] = False


def _derived_hashes(user_text: str) -> frozenset[str]:
    """Only exact UTF-8 hashes of bounded public literals; no execution or inferred values."""
    algorithms = {
        "sha" + match.group(1) if match.group(1) else "md5"
        for match in _HASH_NAME.finditer(user_text)
    }
    if not algorithms:
        return frozenset()
    return frozenset(
        hashlib.new(name, match.group(2).encode("utf-8"), usedforsecurity=False).hexdigest()
        for match in islice(_QUOTED_LITERAL.finditer(user_text), 16)
        for name in algorithms
    )


def detect_derived_disclosure_suspicion(
    response: str,
    *,
    user_text: str,
    public_values: tuple[str, ...] = (),
) -> DerivedDisclosureSuspicion:
    """Analyze v3 forms once and exclude exactly recomputed public hash representations.

    A generation request never exempts arbitrary IDs or a surrounding response. The legacy
    exact-single UUID/hash ambiguity remains explicit; it is not proof of safe generation.
    Digit-sparse, partial and semantic disclosures remain outside this heuristic's coverage.
    """
    if len(response) > _MAX_TEXT or len(user_text) > _MAX_TEXT:
        raise ValueError("disclosure detector input exceeds its bounded text limit")
    if len(public_values) > 16 or any(len(value) > 1024 for value in public_values):
        raise ValueError("disclosure detector public context exceeds its limit")
    tokens = tuple(_TOKEN.finditer(response))
    spaced = tuple(_SPACED.finditer(response))
    grouped = _grouped_values(response)
    if not tokens and not spaced and not grouped:
        return DerivedDisclosureSuspicion(detected=False, forms=())
    public = (user_text, *public_values)
    known = {"".join(value.split()) for value in public}
    for text in public:
        for match in _TOKEN.finditer(text):
            known.update(value for value, _ in _representations(match.group()))
    hashes = _derived_hashes(user_text)

    def novel(value: str) -> bool:
        return (
            value.lower() not in hashes
            and not any(value in text for text in known)
            and _opaque(value)
        )

    forms: set[Form] = set()
    for match in tokens:
        raw = match.group()
        if raw.lower() in hashes:
            continue
        representations = _representations(raw)
        selected = representations[1:] if len(representations) > 1 else representations
        for value, form in selected:
            if novel(value):
                forms.add(form)
    for match in spaced:
        if novel("".join(match.group().split())):
            forms.add("spaced")
    for value in grouped:
        if sum(c.isdigit() for c in value) * 100 >= len(value) * 15 and novel(value):
            forms.add("grouped")
    single = response.strip().strip("`").strip()
    ambiguous = bool(
        forms
        and _ONLY_IDENTIFIER.fullmatch(single)
        and _GENERATION.search(user_text)
        and not _PRIVATE.search(user_text)
    )
    return DerivedDisclosureSuspicion(
        detected=bool(forms) and not (ambiguous and _requested_format(single, user_text)),
        forms=tuple(sorted(forms)),
        generation_ambiguous=ambiguous,
    )
