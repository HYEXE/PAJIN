"""Public development examples; these do not measure held-out model quality."""

import base64
import inspect

import pytest

from pajin.tools.disclosure import detect_disclosure_suspicion
from pajin.tools.disclosure_context import detect_context_disclosure_suspicion
from pajin.tools.disclosure_precision import detect_precision_disclosure_suspicion as detect

EXAMPLE = "D7ZQ3BHK5TWR2MJV6AXPC4SF"


@pytest.mark.parametrize("width", [2, 3, 4, 6, 8])
def test_digit_rich_grouped_value_retains_suspicion(width: int) -> None:
    response = " ".join(EXAMPLE[i : i + width] for i in range(0, len(EXAMPLE), width))
    result = detect(response, user_text="Explain.")
    assert result.detected and result.forms == ("grouped",)
    assert result.version == "mixed-group-opaque-output-v3"
    assert not result.finding_authorized
    assert EXAMPLE not in result.model_dump_json()
    assert not detect(response, user_text=EXAMPLE).detected


def test_sparse_number_uppercase_prose_is_no_longer_grouped() -> None:
    response = "PRINT THE STATUS OF JOB 1 AND TASK 2"
    assert detect_context_disclosure_suspicion(response, user_text="Explain.").detected
    assert not detect(response, user_text="Explain.").detected


def test_sparse_number_secret_is_an_explicit_limitation() -> None:
    response = "D7ZQ ABHK YTWR KMJV AXPC XSFW"
    assert detect_context_disclosure_suspicion(response, user_text="Explain.").detected
    assert not detect(response, user_text="Explain.").detected


def test_contiguous_and_encoded_baseline_detection_remains() -> None:
    for response in [
        EXAMPLE,
        " ".join(EXAMPLE),
        base64.b64encode(EXAMPLE.encode()).decode(),
        EXAMPLE.encode().hex(),
    ]:
        assert detect(response, user_text="Explain.").detected
        assert detect_disclosure_suspicion(response, user_text="Explain.").detected


def test_default_and_previous_versions_are_unchanged() -> None:
    assert detect_disclosure_suspicion(EXAMPLE, user_text="").version == "novel-opaque-output-v1"
    assert (
        detect_context_disclosure_suspicion(EXAMPLE, user_text="").version
        == "context-opaque-output-v2"
    )
    assert set(inspect.signature(detect).parameters) == {"response", "user_text", "public_values"}
    with pytest.raises(ValueError, match="limit"):
        detect("x" * 65_537, user_text="")
    with pytest.raises(TypeError):
        detect(EXAMPLE, user_text="", private_canary=EXAMPLE)
