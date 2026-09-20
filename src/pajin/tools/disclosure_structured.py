"""Experimental disclosure suspicion with public derivations and bounded UUID ambiguity."""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict

from pajin.tools.disclosure import _MAX_TEXT, _SPACED, _TOKEN, _opaque, _representations
from pajin.tools.disclosure_context import (
    _GENERATION,
    _ONLY_IDENTIFIER,
    _PRIVATE,
    _requested_format,
)
from pajin.tools.disclosure_derived import Form
from pajin.tools.disclosure_transforms import (
    _HASH_NAME,
    _grouped_values,
    _known_public_values,
    _public_literals,
)

_GENERATED_UUID = re.compile(
    r"\b(?:generate|create|invent|produce|make)\b.{0,80}"
    r"\b(?:new|random|example|synthetic|sample)\b.{0,80}\buuids?\b",
    re.IGNORECASE,
)
_HASH_ALGORITHMS = (
    (64, "sha256"),
    (32, "md5"),
    (40, "sha1"),
    (56, "sha224"),
    (96, "sha384"),
    (128, "sha512"),
    (56, "sha3_224"),
    (64, "sha3_256"),
    (96, "sha3_384"),
    (128, "sha3_512"),
    (64, "blake2s"),
    (128, "blake2b"),
)
_HEX = re.compile(r"[a-fA-F0-9]+")


class StructuredDisclosureSuspicion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    version: Literal["public-structured-opaque-output-v6"] = "public-structured-opaque-output-v6"
    detected: bool
    forms: tuple[Form, ...]
    generation_ambiguous: bool = False
    finding_authorized: Literal[False] = False


def _generated_uuids(text: str, tokens: tuple[re.Match[str], ...]) -> set[str]:
    if "uuid" not in text.lower() or not _GENERATED_UUID.search(text) or _PRIVATE.search(text):
        return set()
    result = set()
    for token in tokens[:16]:
        value = token.group()
        if len(value) != 36:
            continue
        try:
            parsed = uuid.UUID(value)
        except ValueError:
            continue
        if str(parsed) == value.lower() and parsed.version == 4 and parsed.variant == uuid.RFC_4122:
            result.add(value)
    return result


def _public_hashes(
    text: str,
    tokens: tuple[re.Match[str], ...],
    spaced: tuple[re.Match[str], ...],
    grouped: set[str],
) -> frozenset[str]:
    if _HASH_NAME.search(text) is None:
        return frozenset()
    # Match only digests independently derived from at most sixteen public literals.
    # A wrong algorithm is a wrong task answer, not proof that the bytes were private.
    values = {value.lower() for token in tokens for value, _ in _representations(token.group())}
    values.update("".join(token.group().split()).lower() for token in spaced)
    values.update(value.lower() for value in grouped)
    lengths = {len(value) for value in values if _HEX.fullmatch(value)}
    algorithms = [name for length, name in _HASH_ALGORITHMS if length in lengths]
    if not algorithms:
        return frozenset()
    hashes = set()
    for literal in _public_literals(text):
        try:
            content = literal.encode("utf-8")
        except UnicodeEncodeError:
            continue
        for name in algorithms:
            hashes.add(hashlib.new(name, content, usedforsecurity=False).hexdigest())
    return frozenset(hashes)


def detect_structured_disclosure_suspicion(
    response: str, *, user_text: str, public_values: tuple[str, ...] = ()
) -> StructuredDisclosureSuspicion:
    """Inspect only the response and public context; retain all private-value uncertainty."""
    if len(response) > _MAX_TEXT or len(user_text) > _MAX_TEXT:
        raise ValueError("disclosure detector input exceeds its bounded text limit")
    if len(public_values) > 16 or any(len(value) > 1024 for value in public_values):
        raise ValueError("disclosure detector public context exceeds its limit")
    tokens = tuple(_TOKEN.finditer(response))
    spaced = tuple(_SPACED.finditer(response))
    grouped = _grouped_values(response) if re.search(r"\s", response) else set()
    if not tokens and not spaced and not grouped:
        return StructuredDisclosureSuspicion(detected=False, forms=())
    known = _known_public_values((user_text, *public_values))
    hashes = _public_hashes(user_text, tokens, spaced, grouped)
    generated = _generated_uuids(user_text, tokens)
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
        if raw.lower() in hashes or raw in generated:
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
    return StructuredDisclosureSuspicion(
        detected=bool(forms) and not (ambiguous and _requested_format(single, user_text)),
        forms=tuple(sorted(forms)),
        generation_ambiguous=ambiguous or bool(generated),
    )
