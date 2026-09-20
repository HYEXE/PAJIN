from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
from typing import Any, cast
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import quote, quote_plus

import pytest

from pajin.runtime.store import RunStore
from pajin.web_assessment.browser import (
    BrowserAssessmentError,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.models import BrowserPageEvidence
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import assessment_policy


def _browser_with_page(
    tmp_path: Path,
    *,
    title: str,
    monkeypatch: pytest.MonkeyPatch,
) -> PlaywrightAssessmentBrowser:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    page = MagicMock()
    page.content = AsyncMock(return_value="<html><body>safe metadata fixture</body></html>")
    page.screenshot = AsyncMock(return_value=b"safe-screenshot-bytes")
    page.title = AsyncMock(return_value=title)
    browser = PlaywrightAssessmentBrowser(
        plan=plan,
        network=cast(AssessmentNetwork, object()),
        store=RunStore.create(tmp_path, "web-metadata-redaction"),
        navigation_policy=assessment_policy(plan, max_requests=1),
        xss_policy=assessment_policy(plan, max_requests=1),
    )
    browser._page = cast(Any, page)
    monkeypatch.setattr(browser, "_screenshot_masks", lambda _page: [])
    return browser


@pytest.mark.asyncio
async def test_capture_page_redacts_reflected_route_and_title_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    username = "browser.user+tag@example.test"
    password = 'Pass word/"Token-1234'
    token = "opaque-session-token-987654321"
    overlapping_secret = "abcdefgh"
    jwt = "eyJabcdefghij.abcdefgh1234.signature987"
    encoded_token = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
    title = " | ".join(
        (
            username,
            quote_plus(password, safe=""),
            encoded_token,
            jwt,
        )
    )
    browser = _browser_with_page(tmp_path, title=title, monkeypatch=monkeypatch)
    browser._redactions.update((username, password, token, overlapping_secret))
    observed_url = (
        f"{browser.plan.origin}/post-login/{quote(password, safe='')}"
        f"#session/{quote(username, safe='')}/{token}/{jwt}?ignored=query-secret"
    )

    evidence = await browser._capture_page(
        phase="authenticated-navigation",
        route=browser._redacted_route(observed_url),
        ready_selector="app-navbar",
    )

    assert isinstance(evidence, BrowserPageEvidence)
    serialized = evidence.model_dump_json()
    reflected_variants = {
        username,
        password,
        token,
        quote(username, safe=""),
        quote(password, safe=""),
        quote_plus(password, safe=""),
        encoded_token,
        jwt,
    }
    assert all(variant not in serialized for variant in reflected_variants)
    assert "<redacted-secret>" in evidence.route
    assert "<redacted-secret>" in evidence.title
    assert "<redacted-jwt>" in evidence.route
    assert "<redacted-jwt>" in evidence.title
    assert "ignored=query-secret" not in evidence.route


@pytest.mark.asyncio
async def test_capture_page_redacts_selective_and_nested_encoded_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    username = "browser.user+tag@example.test"
    token = "encoded-session-token-987654321"
    selective_username = username.replace(".", "%2e").replace("+", "%2B").replace("@", "%40")
    deeply_nested_username = selective_username
    for _ in range(3):
        deeply_nested_username = quote(deeply_nested_username, safe="")
    double_token = quote(quote(token, safe=""), safe="")
    encoded_hex = token.encode().hex()
    mixed_case_hex = "".join(
        character.upper() if index % 2 else character.lower()
        for index, character in enumerate(encoded_hex)
    )
    browser = _browser_with_page(
        tmp_path,
        title=f"Account {selective_username} session {mixed_case_hex}",
        monkeypatch=monkeypatch,
    )
    browser._redactions.update((username, token))
    observed_url = (
        f"{browser.plan.origin}/post-login/{double_token}#account/{deeply_nested_username}"
    )

    evidence = await browser._capture_page(
        phase="authenticated-navigation",
        route=browser._redacted_route(observed_url),
        ready_selector="app-navbar",
    )

    serialized = evidence.model_dump_json()
    assert selective_username not in serialized
    assert deeply_nested_username not in serialized
    assert double_token not in serialized
    assert mixed_case_hex not in serialized
    assert username not in serialized
    assert token not in serialized


@pytest.mark.asyncio
async def test_capture_page_avoids_redaction_marker_secret_collision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "<redacted-secret>"
    browser = _browser_with_page(
        tmp_path,
        title=f"Session {secret}",
        monkeypatch=monkeypatch,
    )
    browser._redactions.add(secret)

    evidence = await browser._capture_page(
        phase="authenticated-navigation",
        route=f"/#/session/{secret}",
        ready_selector="app-navbar",
    )

    assert secret not in evidence.route
    assert secret not in evidence.title


@pytest.mark.asyncio
async def test_browser_registers_masked_username_metadata_variant(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    credentials = BrowserCredentials(
        username="browser.user@example.test",
        password="browser-password",
    )
    local, separator, domain = credentials.username.partition("@")
    masked_variant = local[3:] + separator + domain
    browser = _browser_with_page(
        tmp_path,
        title=f"Signed in as ***{masked_variant}",
        monkeypatch=monkeypatch,
    )
    monkeypatch.setattr(
        browser,
        "_start",
        AsyncMock(side_effect=BrowserAssessmentError("stop after credential registration")),
    )
    monkeypatch.setattr(browser, "_close", AsyncMock())

    with pytest.raises(BrowserAssessmentError, match="stop after credential registration"):
        await browser.run(credentials)
    assert credentials.username in browser._redactions
    assert credentials.password in browser._redactions
    assert masked_variant in browser._redactions
    evidence = await browser._capture_page(
        phase="authenticated-navigation",
        route=f"/#/account/{masked_variant}",
        ready_selector="app-navbar",
    )

    assert masked_variant not in evidence.route
    assert masked_variant not in evidence.title
    assert "<redacted-secret>" in evidence.route
    assert "<redacted-secret>" in evidence.title


@pytest.mark.asyncio
async def test_login_registers_response_token_before_metadata_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = "post-login-session-token-123456789"
    encoded_token = base64.urlsafe_b64encode(token.encode()).decode().rstrip("=")
    browser = _browser_with_page(
        tmp_path,
        title=f"Session {encoded_token}",
        monkeypatch=monkeypatch,
    )
    credentials = BrowserCredentials(
        username="login@example.test",
        password="login-password",
    )
    browser._redactions.update((credentials.username, credentials.password))
    page = cast(Any, browser._page)
    page.url = f"{browser.plan.origin}/#/session/{token}"
    page.goto = AsyncMock()
    locators: dict[str, MagicMock] = {}
    for selector in (
        browser.plan.login.username_selector,
        browser.plan.login.password_selector,
        browser.plan.login.submit_selector,
        browser.plan.login.success_activation_selector,
        browser.plan.login.success_selector,
    ):
        assert selector is not None
        locator = MagicMock()
        locator.fill = AsyncMock()
        locator.wait_for = AsyncMock()
        locator.is_enabled = AsyncMock(return_value=True)
        locator.press = AsyncMock()
        locator.click = AsyncMock()
        locators[selector] = locator
    page.locator.side_effect = locators.__getitem__
    page.keyboard.press = AsyncMock()
    response = MagicMock()
    response.body = AsyncMock(
        return_value=json.dumps({"authentication": {"token": token, "bid": 7}}).encode()
    )
    response_value = asyncio.get_running_loop().create_future()
    response_value.set_result(response)
    response_info = MagicMock(value=response_value)
    response_context = MagicMock()
    response_context.__aenter__ = AsyncMock(return_value=response_info)
    response_context.__aexit__ = AsyncMock(return_value=False)
    page.expect_response.return_value = response_context
    monkeypatch.setattr(browser, "_dismiss_login_obstructions", AsyncMock())
    monkeypatch.setattr(browser, "_settle", AsyncMock())

    object_id, evidence = await browser._login(credentials)

    assert object_id == 7
    assert token in browser._redactions
    assert token not in evidence.route
    assert token not in evidence.title
    assert encoded_token not in evidence.title
    assert "<redacted-secret>" in evidence.route
    assert "<redacted-secret>" in evidence.title


@pytest.mark.asyncio
async def test_capture_page_redacts_title_before_truncation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "zqjx-boundary-secret-0123456789"
    browser = _browser_with_page(
        tmp_path,
        title="x" * 295 + secret,
        monkeypatch=monkeypatch,
    )
    browser._redactions.add(secret)

    evidence = await browser._capture_page(
        phase="authenticated-navigation",
        route="/#/safe",
        ready_selector="app-navbar",
    )

    assert len(evidence.title) == 300
    assert secret not in evidence.title
    assert "zqjx-" not in evidence.title
