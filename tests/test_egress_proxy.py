import base64
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


@pytest.fixture
def proxy_module(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    policy = {
        "allow": ["https://example.com/**"],
        "deny": [],
        "allowed_methods": ["GET"],
        "allow_private_networks": False,
    }
    encoded = base64.b64encode(json.dumps(policy).encode()).decode()
    monkeypatch.setenv("PAJIN_EGRESS_POLICY_B64", encoded)
    path = Path("containers/egress-proxy/proxy.py")
    spec = importlib.util.spec_from_file_location("pajin_test_egress_proxy", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_https_connect_requires_host_wide_allow_rule(proxy_module: ModuleType) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/api/**"],
        "deny": [],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed("CONNECT", "https://example.com/", authority_only=True)


def test_https_connect_fails_closed_for_any_authority_deny(proxy_module: ModuleType) -> None:
    proxy_module.POLICY = {
        "allow": ["https://example.com/**"],
        "deny": ["https://example.com/admin/**"],
        "allowed_methods": ["GET"],
    }

    assert not proxy_module.request_allowed("CONNECT", "https://example.com/", authority_only=True)


def test_proxy_audit_target_redacts_query_values(proxy_module: ModuleType) -> None:
    redacted = proxy_module.audit_target("https://example.com/api?token=secret&account=alice")

    assert redacted == "https://example.com/api?<redacted>"
    assert "secret" not in redacted
    assert "alice" not in redacted
