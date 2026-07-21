"""Conservative URL scope matching."""

from fnmatch import fnmatchcase
from re import Match
from re import compile as compile_pattern
from urllib.parse import SplitResult, quote, unquote, unquote_to_bytes, urlsplit, urlunsplit

_VALID_PERCENT_ESCAPE = compile_pattern(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT_ESCAPE = compile_pattern(r"%(?![0-9A-Fa-f]{2})")
_URI_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")


class InvalidScopeURL(ValueError):
    """Raised when a scope or request URL cannot be evaluated safely."""


def _contains_control_characters(value: str) -> bool:
    return any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)


def _validate_path_representation(path: str, *, raw_slash_count: int) -> None:
    if _contains_control_characters(path):
        raise InvalidScopeURL("URL path contains control characters")
    if "\\" in path:
        raise InvalidScopeURL("URL path contains an ambiguous backslash")
    if path.count("/") != raw_slash_count:
        raise InvalidScopeURL("URL path contains an encoded slash")
    if any(segment.partition(";")[0] in {".", ".."} for segment in path.split("/")):
        raise InvalidScopeURL("URL path contains a dot segment")


def _normalize_path(path: str, *, pattern: bool) -> str:
    if _INVALID_PERCENT_ESCAPE.search(path):
        raise InvalidScopeURL("URL path contains a malformed percent escape")
    if pattern and any(
        chr(int(match.group(0)[1:], 16)) in "*?[]" for match in _VALID_PERCENT_ESCAPE.finditer(path)
    ):
        raise InvalidScopeURL("scope path cannot percent-encode glob metacharacters")

    raw_slash_count = path.count("/")
    _validate_path_representation(path, raw_slash_count=raw_slash_count)
    try:
        representation = unquote(path, errors="strict")
    except UnicodeDecodeError as exc:
        raise InvalidScopeURL("URL path contains invalid percent-encoded text") from exc
    _validate_path_representation(representation, raw_slash_count=raw_slash_count)
    if _VALID_PERCENT_ESCAPE.search(representation) is not None:
        raise InvalidScopeURL("URL path contains nested percent encoding")
    # Match the resource representation a conforming server sees after percent
    # decoding, then encode it once in a stable RFC 3986 form. Without this step,
    # a broad allow plus a narrow deny can be bypassed with ``/%61dmin``.
    return quote(
        representation,
        safe="/:@-._~!$&'()*+,;=" if pattern else "/:@-._~!$&'()+,;=",
        encoding="utf-8",
        errors="strict",
    )


def _url_port(parsed: SplitResult) -> int | None:
    try:
        port = parsed.port
    except ValueError as exc:
        raise InvalidScopeURL("URL port is invalid") from exc
    if port == 0:
        raise InvalidScopeURL("URL port 0 is not allowed")
    return port


def _canonical_hostname(hostname: str, *, pattern: bool) -> str:
    if "%" in hostname or hostname.endswith(".."):
        raise InvalidScopeURL("URL hostname contains an ambiguous representation")
    rooted = hostname[:-1] if hostname.endswith(".") else hostname
    wildcard = pattern and rooted.startswith("*.")
    suffix = rooted[2:] if wildcard else rooted
    if not suffix:
        raise InvalidScopeURL("URL hostname is required")
    try:
        canonical = suffix.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise InvalidScopeURL("URL hostname is not valid IDNA text") from exc
    if len(canonical) > 253:
        raise InvalidScopeURL("URL hostname is too long")
    return f"*.{canonical}" if wildcard else canonical


def _normalize_query(query: str) -> str:
    if not query:
        return ""
    if _INVALID_PERCENT_ESCAPE.search(query):
        raise InvalidScopeURL("URL query contains a malformed percent escape")
    decoded_bytes = unquote_to_bytes(query)
    if _VALID_PERCENT_ESCAPE.search(decoded_bytes.decode("latin-1")) is not None:
        raise InvalidScopeURL("URL query contains nested percent encoding")

    def normalize_escape(match: Match[str]) -> str:
        encoded = match.group(0)
        character = chr(int(encoded[1:], 16))
        return character if character in _URI_UNRESERVED else encoded.upper()

    normalized = _VALID_PERCENT_ESCAPE.sub(normalize_escape, query)
    return quote(
        normalized,
        safe="!$&'()*+,;=:@/?-._~%",
        encoding="utf-8",
        errors="strict",
    )


def _parse_url(value: str, *, pattern: bool) -> SplitResult:
    if _contains_control_characters(value):
        raise InvalidScopeURL("URL contains control characters")
    try:
        parsed = urlsplit(value)
    except ValueError as exc:
        raise InvalidScopeURL("URL authority is invalid") from exc
    if parsed.scheme not in {"http", "https"}:
        raise InvalidScopeURL("URL scheme must be HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise InvalidScopeURL("credentials in URL authority are not allowed")
    if not parsed.hostname:
        raise InvalidScopeURL("URL hostname is required")
    if parsed.fragment:
        raise InvalidScopeURL("URL fragments are not part of an enforceable scope")
    hostname = parsed.hostname
    if pattern:
        wildcard_count = hostname.count("*")
        if wildcard_count and (wildcard_count != 1 or not hostname.startswith("*.")):
            raise InvalidScopeURL("only a single leading '*.' hostname wildcard is allowed")
    elif "*" in value:
        raise InvalidScopeURL("requested target URL cannot contain wildcards")
    _canonical_hostname(hostname, pattern=pattern)
    _url_port(parsed)
    normalized_path = _normalize_path(parsed.path or "/", pattern=pattern)
    return parsed._replace(path=normalized_path, query=_normalize_query(parsed.query))


def _authority(hostname: str, port: int | None, default_port: int) -> str:
    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    return host if port in {None, default_port} else f"{host}:{port}"


def normalize_target_url(value: str) -> str:
    """Normalize a concrete URL for policy comparison and audit logging."""

    parsed = _parse_url(value, pattern=False)
    hostname = parsed.hostname
    assert hostname is not None
    hostname = _canonical_hostname(hostname, pattern=False)
    port = _url_port(parsed)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = _authority(hostname, port, default_port)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, authority, path, parsed.query, ""))


def normalize_scope_pattern(value: str) -> str:
    """Normalize a constrained HTTP(S) scope rule without expanding its authority."""

    parsed = _parse_url(value, pattern=True)
    hostname = parsed.hostname
    assert hostname is not None
    hostname = _canonical_hostname(hostname, pattern=True)
    default_port = 443 if parsed.scheme == "https" else 80
    authority = _authority(hostname, _url_port(parsed), default_port)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, authority, path, parsed.query, ""))


def scope_matches(pattern: str, target: str) -> bool:
    """Match a concrete target against a constrained URL scope pattern."""

    scope_url = _parse_url(pattern, pattern=True)
    target_url = _parse_url(normalize_target_url(target), pattern=False)
    if scope_url.scheme != target_url.scheme:
        return False

    scope_hostname = scope_url.hostname
    target_hostname = target_url.hostname
    assert scope_hostname is not None
    assert target_hostname is not None
    scope_host = _canonical_hostname(scope_hostname, pattern=True)
    target_host = _canonical_hostname(target_hostname, pattern=False)
    if scope_host.startswith("*."):
        suffix = scope_host[1:]
        if not target_host.endswith(suffix) or target_host == suffix[1:]:
            return False
    elif scope_host != target_host:
        return False

    scope_port = _url_port(scope_url)
    if scope_port is None:
        scope_port = 443 if scope_url.scheme == "https" else 80
    target_port = _url_port(target_url)
    if target_port is None:
        target_port = 443 if target_url.scheme == "https" else 80
    if scope_port != target_port:
        return False

    scope_path = scope_url.path or "/"
    target_path = target_url.path or "/"
    if not fnmatchcase(target_path, scope_path):
        return False
    return not scope_url.query or scope_url.query == target_url.query
