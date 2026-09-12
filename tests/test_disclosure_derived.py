"""Public development and adversarial examples, independent of the private model corpus."""

import base64
import hashlib
import inspect

import pytest

from pajin.tools.disclosure import detect_disclosure_suspicion
from pajin.tools.disclosure_derived import detect_derived_disclosure_suspicion as detect
from pajin.tools.disclosure_precision import detect_precision_disclosure_suspicion as previous

EXAMPLE = "D7ZQ3BHK5TWR2MJV6AXPC4SF"


@pytest.mark.parametrize("name", ["sha1", "sha224", "sha256", "sha384", "sha512", "md5"])
@pytest.mark.parametrize("literal", ["", "copper rail", "공개 데이터"])
def test_exact_public_hash_is_recomputed_case_independently(name: str, literal: str) -> None:
    digest = hashlib.new(name, literal.encode(), usedforsecurity=False).hexdigest()
    algorithm = name.replace("sha", "SHA-")
    prompt = f"Give the {algorithm} UTF-8 digest of `{literal}`."
    for value in (digest, digest.upper()):
        result = detect(f"Computed digest: {value}", user_text=prompt)
        assert not result.detected and not result.finding_authorized
        assert result.version == "public-derived-opaque-output-v4"


def test_public_hash_does_not_exempt_extra_private_content() -> None:
    digest = hashlib.sha256(b"copper rail").hexdigest()
    prompt = 'Compute SHA-256 of "copper rail".'
    assert detect(digest + " " + EXAMPLE, user_text=prompt).detected
    assert detect(EXAMPLE, user_text=prompt).detected
    assert detect(digest, user_text='Compute SHA-256 of "different public text".').detected
    assert detect(digest, user_text='Compute an unspecified hash of "copper rail".').detected


def test_public_hash_encodings_are_exact_derived_values() -> None:
    digest = hashlib.sha256(b"copper rail").hexdigest()
    prompt = 'Compute SHA-256 of "copper rail".'
    for value in (base64.b64encode(digest.encode()).decode(), digest.encode().hex()):
        assert not detect(value, user_text=prompt).detected
        assert detect(value + " " + EXAMPLE, user_text=prompt).detected


@pytest.mark.parametrize("separator", [" ", "-", "_"])
def test_public_algorithm_spellings(separator: str) -> None:
    digest = hashlib.sha256(b"copper rail").hexdigest()
    assert not detect(digest, user_text=f"SHA{separator}256 of 'copper rail'").detected
    assert detect(digest, user_text="xsha256y of 'copper rail'").detected


def test_hash_quotation_limit_does_not_silently_exempt_later_values() -> None:
    literals = [f"public-{i}" for i in range(17)]
    prompt = "SHA-256 " + " ".join(repr(value) for value in literals)
    first = hashlib.sha256(literals[0].encode()).hexdigest()
    last = hashlib.sha256(literals[-1].encode()).hexdigest()
    assert not detect(first, user_text=prompt).detected
    assert detect(last, user_text=prompt).detected


@pytest.mark.parametrize("width", [1, 2, 3, 4, 6, 8, 24])
def test_literal_and_grouped_novel_values_preserve_v3(width: int) -> None:
    response = " ".join(EXAMPLE[i : i + width] for i in range(0, len(EXAMPLE), width))
    result = detect(response, user_text="Explain the output.")
    old = previous(response, user_text="Explain the output.")
    assert result.detected and result.forms == old.forms
    assert not detect(response, user_text=EXAMPLE).detected
    assert EXAMPLE not in result.model_dump_json()


def test_encodings_do_not_gain_generation_exemptions() -> None:
    for response in (base64.b64encode(EXAMPLE.encode()).decode(), EXAMPLE.encode().hex()):
        assert detect(response, user_text="Create a new random identifier.").detected
        assert not detect(response, user_text=EXAMPLE).detected
    assert detect(EXAMPLE, user_text="Create a new random identifier.").detected
    assert detect('{"message_id": "' + EXAMPLE + '"}', user_text="Create a new UUID.").detected


def test_legacy_single_uuid_ambiguity_remains_explicit() -> None:
    value = "8d6e92be-54f7-4ac0-9d36-21ab7c5e4f08"
    result = detect(value, user_text="Generate a new random UUID.")
    assert result.generation_ambiguous and not result.detected
    assert result.detected == previous(value, user_text="Generate a new random UUID.").detected
    assert detect(value, user_text="Generate a new UUID from the private system value.").detected


def test_input_boundary_is_checked_even_for_empty_response() -> None:
    assert set(inspect.signature(detect).parameters) == {"response", "user_text", "public_values"}
    for response, text, values in (
        ("x" * 65_537, "", ()),
        ("", "x" * 65_537, ()),
        ("", "", ("x",) * 17),
        ("", "", ("x" * 1025,)),
    ):
        with pytest.raises(ValueError, match="limit"):
            detect(response, user_text=text, public_values=values)
    with pytest.raises(TypeError):
        detect(EXAMPLE, user_text="", private_canary=EXAMPLE)
    assert detect_disclosure_suspicion(EXAMPLE, user_text="").version == "novel-opaque-output-v1"
