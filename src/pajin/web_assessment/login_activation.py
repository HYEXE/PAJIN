"""Shared, recipe-bound Playwright login activation."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from time import monotonic
from typing import TYPE_CHECKING

from pajin.web_assessment.models import (
    LoginActivationMode,
    LoginRecipe,
    LoginSuccessActivationMode,
)

if TYPE_CHECKING:
    from playwright.async_api import Locator, Page

_ACTIONABILITY_POLL_SECONDS = 0.05


class LoginActivationError(RuntimeError):
    """A login control was not actionable or was activated more than once."""


@dataclass(slots=True)
class PreparedLoginActivation:
    """One actionability-checked login activation that can be consumed only once."""

    _submit: Locator
    _password: Locator
    _mode: LoginActivationMode
    _timeout_milliseconds: int
    _consumed: bool = False

    async def activate_once(self) -> None:
        if self._consumed:
            raise LoginActivationError("login activation was already consumed")
        self._consumed = True
        try:
            if self._mode == "password-enter":
                await self._password.press("Enter", timeout=self._timeout_milliseconds)
            else:
                await self._submit.click(timeout=self._timeout_milliseconds)
        except Exception as exc:
            raise LoginActivationError("login activation failed") from exc


@dataclass(slots=True)
class PreparedLoginSuccessActivation:
    """One actionability-checked success-control activation, consumed at most once."""

    _control: Locator
    _mode: LoginSuccessActivationMode
    _timeout_milliseconds: int
    _consumed: bool = False

    async def activate_once(self) -> None:
        if self._consumed:
            raise LoginActivationError("login success activation was already consumed")
        self._consumed = True
        try:
            if self._mode == "enter":
                await self._control.press("Enter", timeout=self._timeout_milliseconds)
            else:
                await self._control.click(timeout=self._timeout_milliseconds)
        except Exception as exc:
            raise LoginActivationError("login success activation failed") from exc


async def _wait_until_visible_and_enabled(
    control: Locator,
    *,
    timeout_milliseconds: int,
    error_message: str,
) -> None:
    deadline = monotonic() + (timeout_milliseconds / 1_000)
    try:
        await control.wait_for(state="visible", timeout=timeout_milliseconds)
        while not await control.is_enabled():
            remaining = deadline - monotonic()
            if remaining <= 0:
                raise LoginActivationError(error_message)
            await asyncio.sleep(min(_ACTIONABILITY_POLL_SECONDS, remaining))
    except LoginActivationError:
        raise
    except Exception as exc:
        raise LoginActivationError(error_message) from exc


async def prepare_login_activation(
    page: Page,
    recipe: LoginRecipe,
    *,
    timeout_milliseconds: int,
) -> PreparedLoginActivation:
    """Wait for a visible, enabled form without firing an event, then return one action."""

    submit = page.locator(recipe.submit_selector)
    await _wait_until_visible_and_enabled(
        submit,
        timeout_milliseconds=timeout_milliseconds,
        error_message="login form did not become actionable",
    )
    return PreparedLoginActivation(
        _submit=submit,
        _password=page.locator(recipe.password_selector),
        _mode=recipe.activation_mode or "submit-click",
        _timeout_milliseconds=timeout_milliseconds,
    )


async def prepare_login_success_activation(
    page: Page,
    recipe: LoginRecipe,
    *,
    timeout_milliseconds: int,
) -> PreparedLoginSuccessActivation | None:
    """Prepare the optional post-login control without firing its event."""

    if recipe.success_activation_selector is None:
        return None
    control = page.locator(recipe.success_activation_selector)
    await _wait_until_visible_and_enabled(
        control,
        timeout_milliseconds=timeout_milliseconds,
        error_message="login success control did not become actionable",
    )
    return PreparedLoginSuccessActivation(
        _control=control,
        _mode=recipe.success_activation_mode or "click",
        _timeout_milliseconds=timeout_milliseconds,
    )
