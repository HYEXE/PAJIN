import pytest

from pajin.policy.scope import (
    InvalidScopeURL,
    normalize_scope_pattern,
    normalize_target_url,
    scope_matches,
)


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


def test_scope_canonicalizes_idna_and_rooted_dns_names() -> None:
    unicode_target = "https://b\N{LATIN SMALL LETTER U WITH DIAERESIS}cher.example/admin/export"

    assert normalize_target_url(unicode_target) == ("https://xn--bcher-kva.example/admin/export")
    assert scope_matches("https://xn--bcher-kva.example/admin/**", unicode_target)
    assert normalize_target_url("https://example.invalid./api") == ("https://example.invalid/api")
    assert scope_matches(
        "https://example.invalid/admin/**",
        "https://example.invalid./admin/export",
    )


def test_normalize_rejects_credentials() -> None:
    with pytest.raises(InvalidScopeURL):
        normalize_target_url("https://user:pass@example.invalid/api")


@pytest.mark.parametrize(
    "target",
    [
        "https://example.invalid:0/api",
        "https://example.invalid:not-a-port/api",
        "https://example.invalid:65536/api",
        "https://[invalid/api",
        "https://%65xample.invalid/api",
        "https://example.invalid../api",
    ],
)
def test_normalize_rejects_invalid_ports_and_authorities_as_scope_errors(target: str) -> None:
    with pytest.raises(InvalidScopeURL):
        normalize_target_url(target)


@pytest.mark.parametrize(
    "path",
    [
        "/safe/../admin",
        "/safe/..;parameter/admin",
        "/safe/%2e%2e/admin",
        "/safe/%252e%252e/admin",
        "/safe/%2fadmin",
        "/safe/%252fadmin",
        "/safe/%5cadmin",
        "/safe/%255cadmin",
        "/safe\\admin",
        "/safe/\nadmin",
        "/safe/%0aadmin",
        "/safe/%zz/admin",
    ],
)
def test_normalize_rejects_ambiguous_server_specific_paths(path: str) -> None:
    with pytest.raises(InvalidScopeURL):
        normalize_target_url(f"https://example.invalid{path}")


def test_normalize_preserves_unambiguous_percent_encoded_paths() -> None:
    assert (
        normalize_target_url("https://EXAMPLE.invalid/reports/hello%20world/%25")
        == "https://example.invalid/reports/hello%20world/%25"
    )


@pytest.mark.parametrize("encoded", ["%61dmin", "a%64min"])
def test_scope_matching_canonicalizes_encoded_unreserved_path_characters(
    encoded: str,
) -> None:
    target = f"https://example.invalid/{encoded}/secret"

    assert normalize_target_url(target) == "https://example.invalid/admin/secret"
    assert scope_matches("https://example.invalid/admin/**", target)


def test_scope_matching_rejects_nested_encoding_even_when_inner_text_is_unreserved() -> None:
    with pytest.raises(InvalidScopeURL, match="nested percent encoding"):
        normalize_target_url("https://example.invalid/%2561dmin/secret")


def test_scope_matching_canonicalizes_query_unreserved_characters() -> None:
    target = "https://example.invalid/api?role=%61dmin"

    assert normalize_target_url(target) == "https://example.invalid/api?role=admin"
    assert scope_matches("https://example.invalid/api?role=admin", target)


def test_scope_matching_rejects_nested_query_encoding() -> None:
    with pytest.raises(InvalidScopeURL, match="query contains nested percent encoding"):
        normalize_target_url("https://example.invalid/api?role=%2561dmin")


def test_scope_matching_rejects_ambiguous_scope_patterns() -> None:
    with pytest.raises(InvalidScopeURL):
        scope_matches(
            "https://example.invalid/api/%2e%2e/**",
            "https://example.invalid/api/users",
        )


def test_scope_pattern_rejects_port_zero() -> None:
    with pytest.raises(InvalidScopeURL):
        normalize_scope_pattern("https://example.invalid:0/api/**")


@pytest.mark.parametrize("encoded", ["%2A", "%3F", "%5B", "%5D"])
def test_scope_pattern_rejects_percent_encoded_glob_metacharacters(encoded: str) -> None:
    with pytest.raises(InvalidScopeURL, match="percent-encode glob metacharacters"):
        normalize_scope_pattern(f"https://example.invalid/api/{encoded}")


def test_concrete_target_preserves_percent_encoded_literal_asterisk() -> None:
    assert (
        normalize_target_url("https://example.invalid/api/literal%2Avalue")
        == "https://example.invalid/api/literal%2Avalue"
    )
    assert scope_matches(
        "https://example.invalid/api/**",
        "https://example.invalid/api/literal%2Avalue",
    )
