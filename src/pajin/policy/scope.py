"""Conservative URL scope matching."""

from fnmatch import fnmatchcase
from urllib.parse import SplitResult, urlsplit, urlunsplit


class InvalidScopeURL(ValueError):
    """Raised when a scope or request URL cannot be evaluated safely."""


def _parse_url(value: str, *, pattern: bool) -> SplitResult:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"}:
        raise InvalidScopeURL(f"unsupported URL scheme: {parsed.scheme or '<missing>'}")
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
    return parsed


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
    port = parsed.port
    default_port = 443 if parsed.scheme == "https" else 80
    authority = _authority(hostname, port, default_port)
    path = parsed.path or "/"
    return urlunsplit((parsed.scheme, authority, path, parsed.query, ""))


def normalize_scope_pattern(value: str) -> str:
    """Normalize a constrained HTTP(S) scope rule without expanding its authority."""

    parsed = _parse_url(value, pattern=True)
    hostname = parsed.hostname
    assert hostname is not None
    default_port = 443 if parsed.scheme == "https" else 80
    authority = _authority(hostname, parsed.port, default_port)
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
    scope_host = scope_hostname.lower()
    target_host = target_hostname.lower()
    if scope_host.startswith("*."):
        suffix = scope_host[1:]
        if not target_host.endswith(suffix) or target_host == suffix[1:]:
            return False
    elif scope_host != target_host:
        return False

    scope_port = scope_url.port or (443 if scope_url.scheme == "https" else 80)
    target_port = target_url.port or (443 if target_url.scheme == "https" else 80)
    if scope_port != target_port:
        return False

    scope_path = scope_url.path or "/"
    target_path = target_url.path or "/"
    if not fnmatchcase(target_path, scope_path):
        return False
    return not scope_url.query or scope_url.query == target_url.query
