"""Disposable Playwright browser session for one exact local Web assessment."""

from __future__ import annotations

import asyncio
import hashlib
import re
import secrets
from collections.abc import Coroutine
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Literal, Never, SupportsIndex
from urllib.parse import quote, urlsplit

from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.secrets import redact_secret_values
from pajin.runtime.store import RunStore
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    discover_browser_routes_and_forms,
)
from pajin.web_assessment.discovery_evidence import (
    AuthenticatedDiscoveryEvidence,
    authenticated_discovery_evidence,
)
from pajin.web_assessment.login_activation import (
    LoginActivationError,
    prepare_login_activation,
    prepare_login_success_activation,
)
from pajin.web_assessment.models import (
    DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
    BrowserPageEvidence,
    BrowserSessionSummary,
    IssueCheck,
    ProbeTrial,
    WebAssessmentPlan,
    json_at,
)
from pajin.web_assessment.network import (
    AssessmentBoundaryError,
    AssessmentNetwork,
    PassiveMetadataCompletion,
    RequestReservation,
)

if TYPE_CHECKING:
    from playwright.async_api import (
        Browser,
        BrowserContext,
        ConsoleMessage,
        Error,
        Page,
        Playwright,
        Request,
        Response,
        Route,
        WebSocketRoute,
    )

_JWT_PATTERN = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_MAX_DIAGNOSTIC_TEXT = 500
_JUICE_SHOP_DECORATIVE_IMAGE_PREFIXES = (
    "/assets/public/images/products/",
    "/assets/public/images/carousel/",
)
_SPECIALIST_BROWSER_INVOCATION_FACTORY_TOKEN = object()


class BrowserAssessmentError(RuntimeError):
    """Raised when the disposable browser cannot prove the requested session behavior."""


@dataclass(frozen=True, repr=False)
class BrowserCredentials:
    username: str
    password: str


@dataclass(frozen=True)
class BrowserAssessmentObservation:
    object_id: int
    summary: BrowserSessionSummary
    dom_xss_trials: tuple[ProbeTrial, ProbeTrial]
    discovery_evidence: AuthenticatedDiscoveryEvidence | None = None


@dataclass(frozen=True)
class SpecialistBrowserObservation:
    """One exact specialist browser trace without aggregate diagnostic output."""

    diagnostic_steps: tuple[IssueCheck, ...]
    object_id: int
    pages: tuple[BrowserPageEvidence, ...]
    dom_xss_trials: tuple[ProbeTrial, ProbeTrial] | None
    requests_completed: int
    blocked_requests: tuple[tuple[str, int], ...]
    request_failures: tuple[tuple[str, int], ...]
    unexpected_console_error_fingerprints: tuple[str, ...]
    authenticated: Literal[True] = True
    account_creation_performed: Literal[False] = False
    provisioned_account_used: Literal[True] = True
    browser_closed: Literal[True] = True


class _SpecialistBrowserInvocation:
    """Task-local one-use test authority for the otherwise inert specialist browser."""

    __slots__ = ("__browser", "__diagnostic_steps", "__task", "__terminal")
    __browser: PlaywrightSpecialistAssessmentBrowser
    __diagnostic_steps: tuple[IssueCheck, ...]
    __task: asyncio.Task[object]
    __terminal: bool

    def __init_subclass__(cls) -> None:
        raise TypeError("specialist browser invocations cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist browser invocations are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist browser invocations are immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist browser invocations cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist browser invocations cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist browser invocations cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist browser invocations cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist browser invocations cannot be serialized")

    def __init__(
        self,
        *,
        browser: PlaywrightSpecialistAssessmentBrowser,
        diagnostic_steps: tuple[IssueCheck, ...],
        task: asyncio.Task[object],
        _factory_token: object,
    ) -> None:
        if _factory_token is not _SPECIALIST_BROWSER_INVOCATION_FACTORY_TOKEN:
            raise TypeError("specialist browser invocation requires its code-owned factory")
        object.__setattr__(self, "_SpecialistBrowserInvocation__browser", browser)
        object.__setattr__(
            self,
            "_SpecialistBrowserInvocation__diagnostic_steps",
            diagnostic_steps,
        )
        object.__setattr__(self, "_SpecialistBrowserInvocation__task", task)
        object.__setattr__(self, "_SpecialistBrowserInvocation__terminal", False)

    def _consume(
        self,
        *,
        browser: PlaywrightSpecialistAssessmentBrowser,
        diagnostic_steps: tuple[IssueCheck, ...],
    ) -> None:
        task = asyncio.current_task()
        if (
            type(self) is not _SpecialistBrowserInvocation
            or self.__browser is not browser
            or self.__diagnostic_steps != diagnostic_steps
            or task is None
            or self.__task is not task
            or self.__terminal
        ):
            raise BrowserAssessmentError(
                "specialist browser invocation is absent, foreign, or consumed"
            )
        object.__setattr__(self, "_SpecialistBrowserInvocation__terminal", True)


def specialist_browser_navigation_policy(plan: WebAssessmentPlan) -> EgressPolicy:
    """Compile the exact browser-bootstrap policy used only by specialist flows."""

    registration_path = plan.registration.endpoint if plan.registration is not None else None
    sql_impact_path = plan.sql_login.impact_endpoint if plan.sql_login is not None else None
    object_access_path = (
        plan.object_access.endpoint_template.partition("{id}")[0]
        if plan.object_access is not None
        else None
    )
    deny_paths = tuple(
        dict.fromkeys(
            (
                *plan.deny_paths,
                *((registration_path,) if registration_path else ()),
                *((sql_impact_path,) if sql_impact_path else ()),
                *((object_access_path,) if object_access_path else ()),
            )
        )
    )
    return EgressPolicy(
        allow=[plan.origin + "/*"],
        deny=[plan.origin + path.rstrip("/") + "*" for path in deny_paths],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=100,
        max_request_bytes=64_000,
    )


def specialist_browser_xss_policy(plan: WebAssessmentPlan) -> EgressPolicy:
    """Compile an exact GET/HEAD-only policy for the bounded DOM XSS phase."""

    registration_path = plan.registration.endpoint if plan.registration is not None else None
    sql_impact_path = plan.sql_login.impact_endpoint if plan.sql_login is not None else None
    object_access_path = (
        plan.object_access.endpoint_template.partition("{id}")[0]
        if plan.object_access is not None
        else None
    )
    deny_paths = tuple(
        dict.fromkeys(
            (
                *plan.deny_paths,
                *((registration_path,) if registration_path else ()),
                *((sql_impact_path,) if sql_impact_path else ()),
                *((object_access_path,) if object_access_path else ()),
            )
        )
    )
    return EgressPolicy(
        allow=[plan.origin + "/*"],
        deny=[plan.origin + path.rstrip("/") + "*" for path in deny_paths],
        allowed_methods={"GET", "HEAD"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=40,
        max_request_bytes=64_000,
    )


class _PlaywrightAssessmentSession:
    """Navigate, authenticate, and run an inert-effect DOM XSS marker in Chromium.

    The context blocks service workers, WebSockets, downloads, and every HTTP request that does not
    pass the shared exact-origin gate. Credentials and response tokens remain process-local.
    """

    def __init__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        store: RunStore,
        navigation_policy: EgressPolicy,
        xss_policy: EgressPolicy,
        headless: bool = True,
    ) -> None:
        self.plan = plan
        self.network = network
        self.store = store
        self.navigation_policy = navigation_policy
        self.xss_policy = xss_policy
        discovery_policy = navigation_policy.model_dump(mode="json")
        discovery_policy.update(
            {
                "allowed_methods": ["GET"],
                "max_requests": 20,
                "max_request_bytes": 1,
            }
        )
        self.discovery_policy = EgressPolicy.model_validate(discovery_policy)
        self.headless = headless
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._reservations: dict[int, RequestReservation] = {}
        self._passive_completions: dict[str, PassiveMetadataCompletion] = {}
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._background_errors: list[str] = []
        self._console_error_fingerprints: list[str] = []
        self._completed_browser_requests = 0
        self._page_counter = 0
        self._redactions: set[str] = set()
        self._visual_redactions: set[str] = set()

    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        if type(self) is not PlaywrightAssessmentBrowser:
            raise BrowserAssessmentError("aggregate browser flow requires its exact implementation")
        self._register_credential_redactions(credentials)
        pages: list[BrowserPageEvidence] = []
        discovery_plan: BrowserDiscoveryPlan | None = None
        discovery_result: BrowserDiscoveryResult | None = None
        try:
            await self._start()
            self.network.begin_phase("browser-authenticated-navigation", self.navigation_policy)
            object_id, login_page = await self._login(credentials)
            pages.append(login_page)
            pages.extend(await self._explore_routes())
            discovery_plan, discovery_result = await self._discover_routes_and_forms()
            source_trial, source_pages = await self._probe_dom_xss("source")
            pages.extend(source_pages)
            replay_trial, replay_pages = await self._probe_dom_xss("replay")
            pages.extend(replay_pages)
        finally:
            await self._close()
        if self._background_errors:
            raise BrowserAssessmentError(self._background_errors[0])
        discovery_evidence = None
        if discovery_plan is not None and discovery_result is not None:
            completions = tuple(
                sorted(
                    self._passive_completions.values(),
                    key=lambda completion: completion.boundary_receipt.evidence_sequence,
                )
            )
            if not completions:
                raise BrowserAssessmentError(
                    "authenticated passive discovery produced no request Evidence"
                )
            discovery_evidence = authenticated_discovery_evidence(
                discovery_plan=discovery_plan,
                discovery_result=discovery_result,
                request_evidence=tuple(completion.evidence for completion in completions),
                boundary_receipts=tuple(completion.boundary_receipt for completion in completions),
            )
        return BrowserAssessmentObservation(
            object_id=object_id,
            summary=BrowserSessionSummary(
                authenticated=True,
                ephemeral_account_created=True,
                pages=tuple(pages),
                requests_completed=self._completed_browser_requests,
                blocked_requests=dict(sorted(self.network.blocked.items())),
                request_failures=dict(sorted(self.network.failures.items())),
                unexpected_console_error_fingerprints=tuple(self._console_error_fingerprints),
                browser_closed=True,
            ),
            dom_xss_trials=(source_trial, replay_trial),
            discovery_evidence=discovery_evidence,
        )

    def _register_credential_redactions(self, credentials: BrowserCredentials) -> None:
        self._redactions.update((credentials.username, credentials.password))
        local, separator, domain = credentials.username.partition("@")
        if separator and len(local) > 3:
            self._redactions.add(local[3:] + separator + domain)
        self._visual_redactions.update((credentials.username, credentials.password))

    async def _start(self) -> None:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - exercised by base-only installations
            raise BrowserAssessmentError(
                "Playwright is unavailable; install the project browser extra"
            ) from exc
        self._playwright = await async_playwright().start()
        try:
            self._browser = await self._playwright.chromium.launch(
                headless=self.headless,
                args=[
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-default-apps",
                    "--disable-domain-reliability",
                    "--disable-features=MediaRouter,OptimizationHints,Translate",
                    "--disable-quic",
                    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
                    "--host-resolver-rules=MAP * ~NOTFOUND, EXCLUDE 127.0.0.1, EXCLUDE ::1",
                    "--no-first-run",
                ],
            )
            self._context = await self._browser.new_context(
                accept_downloads=False,
                ignore_https_errors=False,
                java_script_enabled=True,
                locale="en-US",
                service_workers="block",
                timezone_id="UTC",
                viewport={"width": 1440, "height": 1000},
            )
            await self._context.route("**/*", self._gate_route)
            await self._context.route_web_socket("**/*", self._block_web_socket)
            self._context.on(
                "response",
                lambda response: self._schedule(self._record_response(response)),
            )
            self._context.on(
                "requestfailed",
                lambda request: self._schedule(self._record_request_failure(request)),
            )
            self._page = await self._new_context_page()
        except (Exception, asyncio.CancelledError):
            await self._close()
            raise

    async def _close(self) -> None:
        if self._context is not None:
            try:
                async with asyncio.timeout(self.plan.request_timeout_seconds):
                    await self._context.close()
            except TimeoutError:
                self._background_errors.append("browser context close timed out")
            finally:
                self._context = None
                self._page = None
            await self._drain_background_tasks()
        if self._browser is not None:
            try:
                async with asyncio.timeout(self.plan.request_timeout_seconds):
                    await self._browser.close()
            except TimeoutError:
                self._background_errors.append("browser process close timed out")
            finally:
                self._browser = None
        if self._playwright is not None:
            try:
                async with asyncio.timeout(self.plan.request_timeout_seconds):
                    await self._playwright.stop()
            except TimeoutError:
                self._background_errors.append("Playwright shutdown timed out")
            finally:
                self._playwright = None

    async def _gate_route(self, route: Route, request: Request) -> None:
        if request.redirected_from is not None:
            self.network.record_block("redirect-disabled")
            await route.abort("blockedbyclient")
            return
        if (
            self.plan.adapter_implementation_id == DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID
            and self.network.phase
            in {"browser-authenticated-navigation", "dom-xss-source", "dom-xss-replay"}
            and request.method == "GET"
            and request.resource_type == "image"
            and "?" not in request.url
            and any(
                request.url.startswith(self.plan.origin + prefix)
                for prefix in _JUICE_SHOP_DECORATIVE_IMAGE_PREFIXES
            )
        ):
            self.network.record_block("decorative-image-disabled")
            await route.abort("blockedbyclient")
            return
        content = request.post_data_buffer or b""
        try:
            reservation = await self.network.reserve(
                request.method,
                request.url,
                content=content,
            )
        except AssessmentBoundaryError as exc:
            reason = self._fixed_boundary_reason(exc)
            self.network.record_block(reason)
            await route.abort("blockedbyclient")
            return
        self._reservations[id(request)] = reservation
        await route.continue_()

    async def _block_web_socket(self, route: WebSocketRoute) -> None:
        self.network.record_block("websocket-disabled")
        await route.close(code=1008, reason="local assessment websocket disabled")

    async def _record_response(self, response: Response) -> None:
        reservation = self._reservations.pop(id(response.request), None)
        if reservation is None:
            return
        try:
            async with asyncio.timeout(self.plan.request_timeout_seconds):
                headers = {
                    key.lower(): value for key, value in (await response.all_headers()).items()
                }
                if reservation.phase == "browser-passive-discovery":
                    sizes = await response.request.sizes()
                    observed_response_bytes = sizes.get("responseBodySize")
                    if type(observed_response_bytes) is not int:
                        raise BrowserAssessmentError(
                            "browser passive discovery response size was unavailable"
                        )
                    completion = await self.network.complete_passive_metadata(
                        reservation,
                        status=response.status,
                        headers=headers,
                        observed_response_bytes=observed_response_bytes,
                        return_boundary_receipt=True,
                    )
                    self._passive_completions[completion.evidence.evidence_id] = completion
                else:
                    body = await response.body()
                    await self.network.complete(
                        reservation,
                        status=response.status,
                        headers=headers,
                        body=body,
                    )
            self._completed_browser_requests += 1
        except (Exception, asyncio.CancelledError):
            await self.network.fail(reservation, reason="browser-response-capture-failure")
            self._background_errors.append("browser response evidence capture failed")

    async def _record_request_failure(self, request: Request) -> None:
        reservation = self._reservations.pop(id(request), None)
        if reservation is not None:
            await self.network.fail(reservation, reason="browser-request-failed")

    def _record_console(self, message: ConsoleMessage) -> None:
        if message.type != "error":
            return
        text = self._redact(message.text)
        if "socket.io" in text or "ERR_BLOCKED_BY_CLIENT" in text:
            return
        self._append_console_error_fingerprint("console", text)

    def _record_page_error(self, error: Error) -> None:
        self._append_console_error_fingerprint("page", self._redact(str(error)))

    def _append_console_error_fingerprint(self, kind: str, value: str) -> None:
        normalized = " ".join(value.split())[:_MAX_DIAGNOSTIC_TEXT]
        if not normalized:
            return
        fingerprint = f"{kind}:sha256:{hashlib.sha256(normalized.encode()).hexdigest()}"
        if (
            fingerprint not in self._console_error_fingerprints
            and len(self._console_error_fingerprints) < 20
        ):
            self._console_error_fingerprints.append(fingerprint)

    def _append_diagnostic(self, destination: list[str], value: str) -> None:
        normalized = " ".join(value.split())[:_MAX_DIAGNOSTIC_TEXT]
        if normalized and normalized not in destination and len(destination) < 20:
            destination.append(normalized)

    def _redact(self, value: str) -> str:
        redacted = _JWT_PATTERN.sub("<redacted-jwt>", value)
        return redact_secret_values(redacted, self._redactions)

    async def _login(self, credentials: BrowserCredentials) -> tuple[int, BrowserPageEvidence]:
        page = self._require_page()
        await page.goto(
            self.plan.origin + self.plan.login.route,
            wait_until="domcontentloaded",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await self._dismiss_login_obstructions()
        await page.locator(self.plan.login.username_selector).fill(credentials.username)
        password = page.locator(self.plan.login.password_selector)
        await password.fill(credentials.password)
        timeout_milliseconds = self.plan.request_timeout_seconds * 1_000
        try:
            activation = await prepare_login_activation(
                page,
                self.plan.login,
                timeout_milliseconds=timeout_milliseconds,
            )
        except LoginActivationError as exc:
            raise BrowserAssessmentError("browser login form did not become valid") from exc
        async with page.expect_response(
            lambda response: (
                response.request.method == "POST"
                and urlsplit(response.url).path == self.plan.login.endpoint
            ),
            timeout=timeout_milliseconds,
        ) as response_info:
            try:
                await activation.activate_once()
            except LoginActivationError as exc:
                raise BrowserAssessmentError("browser login activation failed") from exc
        response = await response_info.value
        body = await response.body()
        decoded = parse_strict_json_bytes(
            body,
            label="browser login response",
            max_bytes=self.plan.max_response_bytes,
            max_depth=32,
            max_nodes=50_000,
        )
        token = json_at(decoded, self.plan.login.token_path)
        object_id = json_at(decoded, self.plan.login.object_id_path)
        if not isinstance(token, str) or not token or type(object_id) is not int:
            raise BrowserAssessmentError(
                "browser login response lacks the expected session identity"
            )
        self._redactions.add(token)
        self._visual_redactions.add(token)
        try:
            success_activation = await prepare_login_success_activation(
                page,
                self.plan.login,
                timeout_milliseconds=timeout_milliseconds,
            )
            if success_activation is not None:
                await success_activation.activate_once()
        except LoginActivationError as exc:
            raise BrowserAssessmentError("browser login success activation failed") from exc
        await page.locator(self.plan.login.success_selector).wait_for(
            state="visible",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await page.keyboard.press("Escape")
        await self._settle()
        return object_id, await self._capture_page(
            phase="authenticated-navigation",
            route=self._redacted_route(page.url),
            ready_selector=self.plan.login.success_activation_selector
            or self.plan.login.success_selector,
        )

    async def _dismiss_login_obstructions(self) -> None:
        page = self._require_page()
        for selector in self.plan.login.dismiss_selectors:
            locator = page.locator(selector).first
            try:
                await locator.click(timeout=3_000)
            except Exception:
                continue
        backdrop = page.locator(".cdk-overlay-backdrop-showing")
        try:
            await backdrop.wait_for(state="hidden", timeout=3_000)
        except Exception:
            await page.keyboard.press("Escape")
        if await backdrop.is_visible():
            raise BrowserAssessmentError("login remained covered by an application dialog")

    async def _explore_routes(self) -> list[BrowserPageEvidence]:
        page = self._require_page()
        captured: list[BrowserPageEvidence] = []
        for route in self.plan.routes[: self.plan.max_pages]:
            target_url = self.plan.origin + route
            if page.url != target_url:
                await page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=self.plan.request_timeout_seconds * 1_000,
                )
            selector = self.plan.route_ready_selectors[route]
            await page.locator(selector).wait_for(
                state="attached",
                timeout=self.plan.request_timeout_seconds * 1_000,
            )
            for navigation_selector in self.plan.navigation_selectors:
                await self._exercise_navigation_control(navigation_selector)
            await self._settle()
            captured.append(
                await self._capture_page(
                    phase="authenticated-navigation",
                    route=route,
                    ready_selector=selector,
                )
            )
        return captured

    async def _discover_routes_and_forms(
        self,
    ) -> tuple[BrowserDiscoveryPlan, BrowserDiscoveryResult]:
        """Passively map value-free structure inside the authenticated browser context."""

        await self._retire_active_document()
        self.network.begin_phase("browser-passive-discovery", self.discovery_policy)
        discovery_plan = BrowserDiscoveryPlan(
            origin=self.plan.origin,
            seed_routes=(self.plan.routes[0],),
            authenticationSentinelSelector=self.plan.login.success_selector,
            authenticationSentinelActivationSelector=(self.plan.login.success_activation_selector),
            authenticationSentinelActivationMode=self.plan.login.success_activation_mode,
            max_routes=4,
            max_depth=1,
            max_links_per_page=40,
            max_forms=20,
            max_fields_per_form=16,
            max_total_fields=64,
            navigation_timeout_milliseconds=self.plan.request_timeout_seconds * 1_000,
            settle_milliseconds=250,
        )
        discovery_result = await discover_browser_routes_and_forms(
            self._require_page(),
            plan=discovery_plan,
        )
        await self._settle()
        await self._retire_active_document()
        return discovery_plan, discovery_result

    async def _exercise_navigation_control(self, selector: str) -> None:
        page = self._require_page()
        locator = page.locator(selector).first
        if not await locator.is_visible():
            return
        try:
            await locator.click(timeout=2_000)
            await page.wait_for_timeout(100)
        except Exception:
            pass
        finally:
            await page.keyboard.press("Escape")
        drawer_backdrop = page.locator(".mat-drawer-backdrop.mat-drawer-shown").first
        try:
            if await drawer_backdrop.is_visible():
                await drawer_backdrop.click(timeout=2_000)
        except Exception:
            pass

    async def _probe_dom_xss(
        self,
        repetition: Literal["source", "replay"],
    ) -> tuple[ProbeTrial, tuple[BrowserPageEvidence, BrowserPageEvidence]]:
        if self.plan.dom_xss is None:
            raise BrowserAssessmentError("DOM XSS recipe is unavailable")
        phase = f"dom-xss-{repetition}"
        self.network.begin_phase(phase, self.xss_policy)
        page = self._require_page()
        marker = secrets.token_hex(12)
        attribute = self.plan.dom_xss.marker_attribute
        await page.evaluate(
            "attribute => document.documentElement.removeAttribute(attribute)",
            attribute,
        )
        control_value = f"pajin-control-{marker}"
        self._redactions.update((marker, control_value))
        self._visual_redactions.update((marker, control_value))
        control_route = self.plan.dom_xss.route_template.format(
            payload=quote(control_value, safe=""),
        )
        await self._goto_xss_route(control_route)
        control_executed = await page.evaluate(
            "([attribute, marker]) => document.documentElement.getAttribute(attribute) === marker",
            [attribute, marker],
        )
        redacted_route = self.plan.dom_xss.route_template.partition("{payload}")[0]
        control_evidence = await self._capture_page(
            phase="dom-xss-control",
            route=redacted_route + "<control-redacted>",
            ready_selector=self.plan.dom_xss.ready_selector,
            marker_executed=bool(control_executed),
        )
        await page.evaluate(
            "attribute => document.documentElement.removeAttribute(attribute)",
            attribute,
        )
        payload = (
            '<img src="data:image/gif;base64,'
            "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw=="
            '" onload="document.documentElement.setAttribute(\''
            + attribute
            + "','"
            + marker
            + "')\">"
        )
        probe_route = self.plan.dom_xss.route_template.format(payload=quote(payload, safe=""))
        await self._goto_xss_route(probe_route)
        await page.wait_for_function(
            "([attribute, marker]) => document.documentElement.getAttribute(attribute) === marker",
            arg=[attribute, marker],
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        marker_executed = await page.evaluate(
            "([attribute, marker]) => document.documentElement.getAttribute(attribute) === marker",
            [attribute, marker],
        )
        probe_evidence = await self._capture_page(
            phase="dom-xss-source" if repetition == "source" else "dom-xss-replay",
            route=redacted_route + "<probe-redacted>",
            ready_selector=self.plan.dom_xss.ready_selector,
            marker_executed=bool(marker_executed),
        )
        trial = ProbeTrial(
            check="dom-xss",
            repetition=repetition,
            reproduced=bool(marker_executed),
            controls_passed=not bool(control_executed),
            evidence_ids=(control_evidence.evidence_id, probe_evidence.evidence_id),
            facts={
                "controlMarkerExecuted": bool(control_executed),
                "probeMarkerExecuted": bool(marker_executed),
                "externalTransmission": False,
            },
        )
        return trial, (control_evidence, probe_evidence)

    async def _goto_xss_route(self, route: str) -> None:
        assert self.plan.dom_xss is not None
        page = self._require_page()
        await page.goto(
            self.plan.origin + route,
            wait_until="domcontentloaded",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await page.locator(self.plan.dom_xss.ready_selector).wait_for(
            state="attached",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await self._settle()

    async def _capture_page(
        self,
        *,
        phase: Literal[
            "authenticated-navigation",
            "dom-xss-control",
            "dom-xss-source",
            "dom-xss-replay",
        ],
        route: str,
        ready_selector: str,
        marker_executed: bool | None = None,
    ) -> BrowserPageEvidence:
        page = self._require_page()
        dom = (await page.content()).encode("utf-8")
        if not 1 <= len(dom) <= 2_000_000:
            raise BrowserAssessmentError("browser DOM evidence exceeded its byte limit")
        screenshot = await page.screenshot(
            full_page=True,
            animations="disabled",
            mask=self._screenshot_masks(page),
            mask_color="#000000",
        )
        if not 1 <= len(screenshot) <= 10_000_000:
            raise BrowserAssessmentError("browser screenshot evidence exceeded its byte limit")
        self._page_counter += 1
        reference = self.store.write_bytes(
            f"evidence/browser-{self._page_counter:02d}.png",
            screenshot,
        )
        return BrowserPageEvidence(
            phase=phase,
            route=self._redact(route),
            title=self._redact(await page.title())[:300],
            ready_selector=ready_selector,
            dom_sha256=hashlib.sha256(dom).hexdigest(),
            dom_bytes=len(dom),
            screenshot_reference=reference,
            screenshot_sha256=hashlib.sha256(screenshot).hexdigest(),
            screenshot_bytes=len(screenshot),
            marker_executed=marker_executed,
            captured_at=datetime.now(UTC),
        )

    def _screenshot_masks(self, page: Page) -> list[Any]:
        """Mask form values and rendered credential variants without persisting the values."""

        masks: list[Any] = [
            page.locator("input, textarea, select, [contenteditable='true']"),
        ]
        needles: set[str] = set()
        for secret in self._visual_redactions:
            if len(secret) >= 8:
                needles.add(secret)
            local, separator, domain = secret.partition("@")
            if separator and len(local) > 3:
                # Juice Shop masks the first three local-part characters but renders the rest.
                needles.add(local[3:] + separator + domain)
        masks.extend(
            page.get_by_text(re.compile(re.escape(needle)), exact=False)
            for needle in sorted(needles, key=len, reverse=True)
        )
        return masks

    async def _settle(self) -> None:
        page = self._require_page()
        await page.wait_for_timeout(250)
        await self._drain_background_tasks()
        if self._background_errors:
            raise BrowserAssessmentError(self._background_errors[0])

    def _schedule(self, operation: Coroutine[Any, Any, None]) -> None:
        task = asyncio.create_task(operation)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_tasks.discard)

    async def _drain_background_tasks(self) -> None:
        deadline = asyncio.get_running_loop().time() + self.plan.request_timeout_seconds
        while self._background_tasks:
            tasks = tuple(self._background_tasks)
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                for task in tasks:
                    task.cancel()
                self._background_errors.append("browser response evidence capture timed out")
                return
            _done, pending = await asyncio.wait(tasks, timeout=remaining)
            if pending:
                for task in pending:
                    task.cancel()
                self._background_errors.append("browser response evidence capture timed out")
                return

    async def _new_context_page(self) -> Page:
        if self._context is None:
            raise BrowserAssessmentError("browser context is not initialized")
        page = await self._context.new_page()
        page.on("console", self._record_console)
        page.on("pageerror", self._record_page_error)
        return page

    async def _retire_active_document(self) -> None:
        """Retire phase-local document timers without exporting page-scoped auth state."""

        page = self._page
        if page is None:
            raise BrowserAssessmentError("authenticated browser page is unavailable")
        try:
            async with asyncio.timeout(self.plan.request_timeout_seconds):
                await page.goto(
                    "about:blank",
                    wait_until="domcontentloaded",
                    timeout=self.plan.request_timeout_seconds * 1_000,
                )
        except TimeoutError as exc:
            raise BrowserAssessmentError("browser phase document retirement timed out") from exc
        except Exception as exc:
            raise BrowserAssessmentError("browser phase document retirement failed") from exc
        await self._drain_background_tasks()
        if self._background_errors:
            raise BrowserAssessmentError(self._background_errors[0])

    def _require_page(self) -> Page:
        if self._page is None:
            raise BrowserAssessmentError("browser page is not initialized")
        return self._page

    @staticmethod
    def _redacted_route(url: str) -> str:
        parsed = urlsplit(url)
        fragment = parsed.fragment.partition("?")[0]
        return parsed.path + (f"#{fragment}" if fragment else "")

    @staticmethod
    def _fixed_boundary_reason(error: AssessmentBoundaryError) -> str:
        reason = str(error)
        allowed = {
            "ambiguous-url",
            "assessment-deadline",
            "authorization-expired",
            "candidate-too-long",
            "denied-path",
            "invalid-url",
            "missing-egress-grant",
            "outside-approved-origin",
            "outside-campaign-scope",
            "phase-has-open-requests",
            "phase-request-budget",
            "numeric-object-route",
            "query-values",
            "redirect-disabled",
            "request-body-disabled",
            "request-byte-limit",
            "sensitive-path",
            "total-request-budget",
            "total-response-budget",
            "unapproved-method",
            "unapproved-post-path",
            "value-bearing-path",
        }
        return reason if reason in allowed else "browser-request-rejected"


class PlaywrightAssessmentBrowser(_PlaywrightAssessmentSession):
    """Legacy aggregate browser flow retained byte-for-byte at its public seam."""


class PlaywrightSpecialistAssessmentBrowser(_PlaywrightAssessmentSession):
    """Run only the browser work required by one closed specialist profile.

    SQL-login diagnostics require no browser session.  Authorization requires
    only an authenticated bootstrap to obtain the disposable account object
    identity.  XSS requires that bootstrap plus the two bounded DOM trials.
    The aggregate ``PlaywrightAssessmentBrowser.run`` path is never invoked.
    """

    _SUPPORTED_BROWSER_CLOSURES = frozenset(
        {
            ("dom-xss",),
            ("sql-login", "object-access"),
        }
    )

    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        del credentials
        raise BrowserAssessmentError(
            "specialist browser cannot invoke the aggregate assessment flow"
        )

    async def run_specialist(
        self,
        credentials: BrowserCredentials,
        *,
        diagnostic_steps: tuple[IssueCheck, ...],
        invocation: _SpecialistBrowserInvocation,
    ) -> SpecialistBrowserObservation:
        if type(invocation) is not _SpecialistBrowserInvocation:
            raise BrowserAssessmentError("specialist browser invocation is invalid")
        invocation._consume(browser=self, diagnostic_steps=diagnostic_steps)
        if type(diagnostic_steps) is not tuple or diagnostic_steps not in (
            self._SUPPORTED_BROWSER_CLOSURES
        ):
            raise BrowserAssessmentError("specialist browser diagnostic closure is unsupported")
        if self.navigation_policy != specialist_browser_navigation_policy(self.plan):
            raise BrowserAssessmentError("specialist browser navigation policy differs")
        if self.xss_policy != specialist_browser_xss_policy(self.plan):
            raise BrowserAssessmentError("specialist browser XSS policy differs")
        self._register_credential_redactions(credentials)
        pages: list[BrowserPageEvidence] = []
        trials: tuple[ProbeTrial, ProbeTrial] | None = None
        try:
            await self._start()
            self.network.begin_phase(
                "browser-authenticated-navigation",
                self.navigation_policy,
            )
            object_id, login_page = await self._login(credentials)
            pages.append(login_page)
            if diagnostic_steps == ("dom-xss",):
                source_trial, source_pages = await self._probe_dom_xss("source")
                pages.extend(source_pages)
                replay_trial, replay_pages = await self._probe_dom_xss("replay")
                pages.extend(replay_pages)
                trials = (source_trial, replay_trial)
        finally:
            await self._close()
        if self._background_errors:
            raise BrowserAssessmentError(self._background_errors[0])
        return SpecialistBrowserObservation(
            diagnostic_steps=diagnostic_steps,
            object_id=object_id,
            pages=tuple(pages),
            dom_xss_trials=trials,
            requests_completed=self._completed_browser_requests,
            blocked_requests=tuple(sorted(self.network.blocked.items())),
            request_failures=tuple(sorted(self.network.failures.items())),
            unexpected_console_error_fingerprints=tuple(self._console_error_fingerprints),
            account_creation_performed=False,
            provisioned_account_used=True,
        )


def _testing_specialist_browser_invocation(
    browser: PlaywrightSpecialistAssessmentBrowser,
    *,
    diagnostic_steps: tuple[IssueCheck, ...],
) -> _SpecialistBrowserInvocation:
    """Mint a test-only invocation; the production factory belongs to AGENTIC-003C."""

    if type(browser) is not PlaywrightSpecialistAssessmentBrowser:
        raise BrowserAssessmentError("specialist browser implementation differs")
    task = asyncio.current_task()
    if task is None:
        raise BrowserAssessmentError("specialist browser invocation requires an async task")
    return _SpecialistBrowserInvocation(
        browser=browser,
        diagnostic_steps=diagnostic_steps,
        task=task,
        _factory_token=_SPECIALIST_BROWSER_INVOCATION_FACTORY_TOKEN,
    )
