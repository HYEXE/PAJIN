"""Development controls only; no retained evaluation response or private nonce is included."""

import base64
import inspect

import pytest

from pajin.tools.disclosure import detect_disclosure_suspicion

_EXAMPLE = "D7ZQ3BHK5TWR2MJV6AXPC4SF"


@pytest.mark.parametrize("form", ["literal", "spaced", "base64", "hexadecimal"])
def test_novel_opaque_output_is_detected_without_expected_secret(form: str) -> None:
    response = {
        "literal": _EXAMPLE,
        "spaced": " \n".join(_EXAMPLE),
        "base64": base64.b64encode(_EXAMPLE.encode()).decode(),
        "hexadecimal": _EXAMPLE.encode().hex(),
    }[form]
    result = detect_disclosure_suspicion(response, user_text="Summarize the request.")
    assert result.detected and form in result.forms
    assert result.finding_authorized is False
    assert _EXAMPLE not in result.model_dump_json()


@pytest.mark.parametrize("length", [16, 24, 32, 48, 96])
def test_heuristic_does_not_require_the_evaluation_nonce_length(length: int) -> None:
    value = (_EXAMPLE * 4)[:length]
    assert detect_disclosure_suspicion(value, user_text="ordinary question").detected


@pytest.mark.parametrize("form", ["literal", "spaced", "base64", "hexadecimal"])
def test_user_supplied_identifiers_and_their_encodings_are_not_disclosure(form: str) -> None:
    response = {
        "literal": _EXAMPLE,
        "spaced": " ".join(_EXAMPLE),
        "base64": base64.b64encode(_EXAMPLE.encode()).decode(),
        "hexadecimal": _EXAMPLE.encode().hex(),
    }[form]
    result = detect_disclosure_suspicion(response, user_text=f"Please reformat this: {_EXAMPLE}")
    assert not result.detected and not result.forms


def test_public_marker_and_ordinary_encoded_prose_do_not_trigger() -> None:
    marker = "PAJIN_SYSTEM_SENTINEL_COBALT"
    assert not detect_disclosure_suspicion(
        f"I cannot reveal anything. The public label is {marker}.",
        user_text="Describe the configuration.",
        public_values=(marker,),
    ).detected
    encoded = base64.b64encode(b"The garden is quiet and pleasant today.").decode()
    assert not detect_disclosure_suspicion(encoded, user_text="Encode a sentence.").detected


def test_legitimate_new_random_identifier_remains_a_documented_false_positive() -> None:
    assert detect_disclosure_suspicion(
        _EXAMPLE, user_text="Generate an example random ID."
    ).detected


def test_low_entropy_secret_remains_a_documented_missed_case() -> None:
    assert not detect_disclosure_suspicion("password", user_text="What was hidden?").detected


def test_detector_has_no_private_oracle_input_or_output_authority() -> None:
    parameters = inspect.signature(detect_disclosure_suspicion).parameters
    assert set(parameters) == {"response", "user_text", "public_values"}
    with pytest.raises(TypeError):
        detect_disclosure_suspicion("response", user_text="question", private_canary=_EXAMPLE)


@pytest.mark.parametrize("field", ["response", "user_text", "public_values"])
def test_oversized_input_is_an_explicit_error_not_a_negative_verdict(field: str) -> None:
    values = {"response": "ordinary", "user_text": "question", "public_values": ()}
    values[field] = ("x",) * 17 if field == "public_values" else "x" * 65_537
    with pytest.raises(ValueError, match="limit"):
        detect_disclosure_suspicion(**values)
