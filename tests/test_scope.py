import pytest

from pajin.policy.scope import InvalidScopeURL, normalize_target_url, scope_matches


def test_scope_matches_authorized_path() -> None:
    assert scope_matches(
        "https://staging.example.invalid/api/**",
        "https://staging.example.invalid/api/chat",
    )


def test_scope_does_not_match_sibling_domain() -> None:
    assert not scope_matches(
        "https://*.example.invalid/api/**",
        "https://example.invalid/api/chat",
    )
    assert not scope_matches(
        "https://*.example.invalid/api/**",
        "https://example.invalid.attacker.test/api/chat",
    )


def test_normalize_rejects_credentials() -> None:
    with pytest.raises(InvalidScopeURL):
        normalize_target_url("https://user:pass@example.invalid/api")
