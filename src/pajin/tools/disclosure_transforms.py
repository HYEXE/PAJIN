"""Experimental disclosure suspicion with exact, bounded public hash derivations."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterator
from itertools import islice
from typing import Literal

from pydantic import BaseModel, ConfigDict

from pajin.tools.disclosure import _MAX_TEXT, _SPACED, _TOKEN, _opaque, _representations
from pajin.tools.disclosure_context import (
    _CHUNKS,
    _GENERATION,
    _ONLY_IDENTIFIER,
    _PRIVATE,
    _requested_format,
)
from pajin.tools.disclosure_derived import Form

_HASH_NAME = re.compile(
    r"\b(?:sha[-_ ]?3[-_ ]?(224|256|384|512)|sha[-_ ]?(1|224|256|384|512)|"
    r"(md5|blake2[bs]))\b",
    re.IGNORECASE,
)
_LITERAL = re.compile(
    r'"(?P<json>(?:[^"\\\r\n]|\\[^\r\n]){0,1024})"'
    r"|(?P<quote>['`])(?P<plain>[^\r\n]{0,1024}?)(?P=quote)"
    r"|\u201c(?P<double>[^\u201c\u201d\r\n]{0,1024})\u201d"
    r"|\u2018(?P<single>[^\u2018\u2019\r\n]{0,1024})\u2019"
)


class TransformDisclosureSuspicion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["public-transform-opaque-output-v5"] = "public-transform-opaque-output-v5"
    detected: bool
    forms: tuple[Form, ...]
    generation_ambiguous: bool = False
    finding_authorized: Literal[False] = False


def _public_literals(text: str) -> Iterator[str]:
    for match in islice(_LITERAL.finditer(text), 16):
        if match["json"] is not None:
            # Accept JSON string escapes only. Never evaluate source or instructions.
            try:
                value = json.loads(match.group())
            except ValueError:
                continue
            if isinstance(value, str):
                yield value
        else:
            yield next(
                value
                for name in ("plain", "double", "single")
                if (value := match[name]) is not None
            )


def _public_hashes(text: str) -> frozenset[str]:
    algorithms = {
        f"sha3_{match[1]}" if match[1] else f"sha{match[2]}" if match[2] else match[3].lower()
        for match in _HASH_NAME.finditer(text)
    }
    if not algorithms:
        return frozenset()
    values: set[str] = set()
    for literal in _public_literals(text):
        try:
            content = literal.encode("utf-8")
        except UnicodeEncodeError:
            continue
        values.update(
            hashlib.new(name, content, usedforsecurity=False).hexdigest() for name in algorithms
        )
    return frozenset(values)


def _grouped_values(text: str) -> set[str]:
    """Preserve v4's exact grouping/digit rule without repeatedly splitting each prefix."""
    chunks = tuple(_CHUNKS.finditer(text))
    counts = tuple(sum(c.isdigit() for c in match.group()) for match in chunks)
    values: set[str] = set()
    for i, start in enumerate(chunks):
        value, previous = start.group(), start
        digits, each_has_digit = counts[i], counts[i] > 0
        for j in range(i + 1, min(i + 64, len(chunks))):
            following = chunks[j]
            if not text[previous.end() : following.start()].isspace():
                break
            chunk = following.group()
            if len(value) + len(chunk) > 128:
                break
            value += chunk
            digits += counts[j]
            each_has_digit = each_has_digit and counts[j] > 0
            if (
                len(value) >= 16
                and digits * 100 >= len(value) * 15
                and (each_has_digit or value.isupper())
            ):
                values.add(value)
            previous = following
    return values


def _known_public_values(public: tuple[str, ...]) -> set[str]:
    known = {"".join(value.split()) for value in public}
    for text in public:
        if "\\" in text:
            known.update("".join(value.split()) for value in _public_literals(text))
        for match in _TOKEN.finditer(text):
            known.update(value for value, _ in _representations(match.group()))
    return known


def detect_transform_disclosure_suspicion(
    response: str, *, user_text: str, public_values: tuple[str, ...] = ()
) -> TransformDisclosureSuspicion:
    """Inspect only the response and public context; retain all private-value uncertainty."""
    if len(response) > _MAX_TEXT or len(user_text) > _MAX_TEXT:
        raise ValueError("disclosure detector input exceeds its bounded text limit")
    if len(public_values) > 16 or any(len(value) > 1024 for value in public_values):
        raise ValueError("disclosure detector public context exceeds its limit")
    tokens = tuple(_TOKEN.finditer(response))
    spaced = tuple(_SPACED.finditer(response))
    grouped = _grouped_values(response) if re.search(r"\s", response) else set()
    if not tokens and not spaced and not grouped:
        return TransformDisclosureSuspicion(detected=False, forms=())
    known = _known_public_values((user_text, *public_values))
    hashes = _public_hashes(user_text)
    analyzed: dict[str, bool] = {}

    def novel(value: str) -> bool:
        if value not in analyzed:
            analyzed[value] = (
                value.lower() not in hashes
                and not any(value in text for text in known)
                and _opaque(value)
            )
        return analyzed[value]

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
        if novel(value):
            forms.add("grouped")
    single = response.strip().strip("`").strip()
    ambiguous = bool(
        forms
        and _ONLY_IDENTIFIER.fullmatch(single)
        and _GENERATION.search(user_text)
        and not _PRIVATE.search(user_text)
    )
    return TransformDisclosureSuspicion(
        detected=bool(forms) and not (ambiguous and _requested_format(single, user_text)),
        forms=tuple(sorted(forms)),
        generation_ambiguous=ambiguous,
    )
