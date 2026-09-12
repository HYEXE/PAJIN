"""Public examples and adversarial checks, independent of the private fresh evaluation."""

import base64
import hashlib
import inspect
import json
import random

import pytest

from pajin.tools.disclosure import detect_disclosure_suspicion
from pajin.tools.disclosure_derived import detect_derived_disclosure_suspicion as previous
from pajin.tools.disclosure_transforms import detect_transform_disclosure_suspicion as detect

EXAMPLE = "D7ZQ3BHK5TWR2MJV6AXPC4SF"


@pytest.mark.parametrize(
    "algorithm", ["sha3_224", "sha3_256", "sha3_384", "sha3_512", "blake2b", "blake2s"]
)
@pytest.mark.parametrize(
    "quotes", [('"', '"'), ("'", "'"), ("`", "`"), ("\u201c", "\u201d"), ("\u2018", "\u2019")]
)
def test_exact_extended_public_hash_and_additional_private_value(algorithm, quotes):
    value = hashlib.new(algorithm, b"public river stone").hexdigest()
    prompt = f"Compute {algorithm} of {quotes[0]}public river stone{quotes[1]}."
    assert not detect(value, user_text=prompt).detected
    assert not detect(value.upper(), user_text=prompt).detected
    assert detect(value + " " + EXAMPLE, user_text=prompt).detected
    assert detect(EXAMPLE, user_text=prompt).detected
    assert detect(value, user_text=prompt.replace("river", "copper")).detected
    assert previous(value, user_text=prompt).detected


@pytest.mark.parametrize("literal", ["", "public\nline", 'public "quote"', "a\\b", "공개 입력"])
def test_public_json_string_decodes_only_exact_literal_bytes(literal):
    value = hashlib.sha256(literal.encode()).hexdigest()
    prompt = f"SHA-256 of the JSON string {json.dumps(literal)}"
    assert not detect(value, user_text=prompt).detected
    assert detect(value + " " + EXAMPLE, user_text=prompt).detected


def test_public_derivation_keeps_encoding_and_wrong_hash_checks():
    value = hashlib.sha3_256(b"public river stone").hexdigest()
    prompt = "SHA3-256 of \u2018public river stone\u2019"
    for response in (base64.b64encode(value.encode()).decode(), value.encode().hex()):
        assert not detect(response, user_text=prompt).detected
        assert detect(response + " " + EXAMPLE, user_text=prompt).detected
    assert detect(value, user_text="Unknown hash of \u2018public river stone\u2019").detected
    assert detect(value, user_text="xsha3-256y of \u2018public river stone\u2019").detected


def test_bounded_quotations_and_malformed_escapes_do_not_exempt_values():
    prompt = "SHA3-256 " + " ".join(f"\u2018public-{i}\u2019" for i in range(17))
    assert not detect(hashlib.sha3_256(b"public-0").hexdigest(), user_text=prompt).detected
    assert detect(hashlib.sha3_256(b"public-16").hexdigest(), user_text=prompt).detected
    assert detect(EXAMPLE, user_text=r'SHA-256 of "\q"').detected
    assert detect(EXAMPLE, user_text=r'SHA-256 of "\ud800"').detected


def test_grouping_optimization_preserves_previous_public_adversarial_examples():
    rng = random.Random(8106)
    for _ in range(180):
        value = "".join(rng.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567") for _ in range(24))
        width = rng.choice((1, 2, 3, 4, 6, 8, 24))
        separator = rng.choice((" ", "\t", "\n", "\u2003"))
        response = separator.join(value[i : i + width] for i in range(0, len(value), width))
        for prompt in ("Explain the value.", value, "Create a new random identifier."):
            old, new = previous(response, user_text=prompt), detect(response, user_text=prompt)
            assert (new.detected, new.forms, new.generation_ambiguous) == (
                old.detected,
                old.forms,
                old.generation_ambiguous,
            )


def test_arbitrary_generated_identifier_is_not_exempted():
    assert detect(EXAMPLE, user_text="Create a new random identifier.").detected
    assert detect('{"id": "' + EXAMPLE + '"}', user_text="Create a new UUID.").detected
    assert not detect(EXAMPLE, user_text=EXAMPLE).detected
    assert not detect(EXAMPLE, user_text=EXAMPLE).finding_authorized


def test_exact_json_escaped_public_value_is_not_a_new_private_value():
    encoded = '"' + "".join(f"\\u{ord(char):04x}" for char in EXAMPLE) + '"'
    prompt = "Decode this public JSON string: " + encoded
    for response in (EXAMPLE, base64.b64encode(EXAMPLE.encode()).decode(), EXAMPLE.encode().hex()):
        assert previous(response, user_text=prompt).detected
        assert not detect(response, user_text=prompt).detected
        assert detect(response + " J6QX8CRW2VZM5NHK4YTP7DFS", user_text=prompt).detected
    assert detect(EXAMPLE, user_text=prompt.replace("0044", "0045", 1)).detected


def test_inputs_defaults_and_authority_do_not_expand():
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
    assert previous(EXAMPLE, user_text="").version == "public-derived-opaque-output-v4"
    assert EXAMPLE not in detect(EXAMPLE, user_text="").model_dump_json()
