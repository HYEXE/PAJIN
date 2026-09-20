"""Authenticated, disposable Playwright runtime for passive browser discovery.

The existing assessment browser intentionally captures page and screenshot evidence.  Passive
discovery has a stricter retention contract, so this runtime owns a separate disposable context
that performs the same exact-origin request mediation and normal login without capture APIs.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Coroutine
from contextlib import suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Literal, Protocol, cast
from urllib.parse import urlsplit

from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPage,
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    browser_discovery_request_path_rejection,
    discover_browser_routes_and_forms,
)
from pajin.web_assessment.login_activation import (
    LoginActivationError,
    prepare_login_activation,
    prepare_login_success_activation,
)
from pajin.web_assessment.models import (
    PassiveDiscoveryBoundaryReceipt,
    RequestEvidence,
    WebAssessmentPlan,
    local_origin,
    request_evidence_sequence,
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
        Page,
        Playwright,
        Request,
        Response,
        Route,
        WebSocketRoute,
    )


class BrowserDiscoveryRuntimeError(RuntimeError):
    """A disposable authenticated discovery session could not be completed safely."""


class PassiveDiscoveryRequestBoundaryError(ValueError):
    """One browser request violated the authoritative passive-discovery boundary."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class GovernedAuthenticatedDiscoveryObservation:
    """Closed-browser discovery output plus exact passive request-boundary evidence."""

    discovery_result: BrowserDiscoveryResult
    request_evidence: tuple[RequestEvidence, ...]
    boundary_receipts: tuple[PassiveDiscoveryBoundaryReceipt, ...]
    browser_closed: Literal[True] = True
    session_implementation: Literal[
        "pajin.web_assessment.discovery_runtime.GovernedPlaywrightAuthenticatedDiscoverySession"
    ] = "pajin.web_assessment.discovery_runtime.GovernedPlaywrightAuthenticatedDiscoverySession"
    network_implementation: Literal["pajin.web_assessment.network.AssessmentNetwork"] = (
        "pajin.web_assessment.network.AssessmentNetwork"
    )


def require_passive_discovery_request(
    *,
    origin: str,
    method: str,
    url: str,
    content: bytes | None,
    redirected: bool,
) -> None:
    """Allow only an exact-origin, query-free, bodyless GET with no redirect lineage."""

    if redirected:
        raise PassiveDiscoveryRequestBoundaryError("redirect-disabled")
    if method.upper() != "GET":
        raise PassiveDiscoveryRequestBoundaryError("unapproved-method")
    try:
        canonical_origin = local_origin(origin)
        parsed = urlsplit(url)
        approved = urlsplit(canonical_origin)
    except ValueError as exc:
        raise PassiveDiscoveryRequestBoundaryError("invalid-url") from exc
    if (
        parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or any(ord(character) <= 32 or character == "\\" for character in url)
    ):
        raise PassiveDiscoveryRequestBoundaryError("invalid-url")
    if (parsed.scheme, parsed.netloc) != (approved.scheme, approved.netloc):
        raise PassiveDiscoveryRequestBoundaryError("outside-approved-origin")
    if "?" in url.partition("#")[0]:
        raise PassiveDiscoveryRequestBoundaryError("query-values")
    if content:
        raise PassiveDiscoveryRequestBoundaryError("request-body-disabled")
    path_rejection = browser_discovery_request_path_rejection(
        origin=canonical_origin,
        url=url,
    )
    if path_rejection is not None:
        raise PassiveDiscoveryRequestBoundaryError(path_rejection)


class AuthenticatedBrowserDiscoverySession(Protocol):
    """Small lifecycle boundary used by the runtime and fake-session tests."""

    async def start(self) -> BrowserDiscoveryPage: ...

    async def authenticate(self, credentials: BrowserCredentials) -> None: ...

    async def close(self) -> None: ...


class BrowserDiscoverySessionFactory(Protocol):
    def __call__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        headless: bool,
    ) -> AuthenticatedBrowserDiscoverySession: ...


class PlaywrightAuthenticatedDiscoverySession:
    """Fresh Chromium context with no screenshot, DOM, cookie, or credential persistence."""

    passive_request_profile: Literal["legacy-get-head", "governed-get-only"] = "legacy-get-head"

    def __init__(
        self,
        *,
        plan: WebAssessmentPlan,
        network: AssessmentNetwork,
        headless: bool = True,
    ) -> None:
        self.plan = plan
        self.network = network
        self.headless = headless
        self._playwright: Playwright | None = None
        self._browser: Browser | None = None
        self._context: BrowserContext | None = None
        self._page: Page | None = None
        self._reservations: dict[int, RequestReservation] = {}
        self._background_tasks: set[asyncio.Task[None]] = set()
        self._background_failed = False
        self._accept_background_tasks = True
        self._request_mode: Literal["authentication", "passive-discovery", "closed"] = (
            "authentication"
        )
        self._observed_response_bytes = 0
        self._response_budget_lock = asyncio.Lock()
        self._passive_completions: dict[int, PassiveMetadataCompletion] = {}
        self._closed_cleanly = False

    async def start(self) -> BrowserDiscoveryPage:
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:  # pragma: no cover - base-only installation
            raise BrowserDiscoveryRuntimeError(
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
            self._page = await self._context.new_page()
            return cast(BrowserDiscoveryPage, self._page)
        except (Exception, asyncio.CancelledError):
            await self.close()
            raise

    async def authenticate(self, credentials: BrowserCredentials) -> None:
        """Perform the code-owned normal login and retain no response or credential material."""

        page = self._require_page()
        await page.goto(
            self.plan.origin + self.plan.login.route,
            wait_until="domcontentloaded",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await self._dismiss_login_obstructions(page)
        await page.locator(self.plan.login.username_selector).fill(credentials.username)
        await page.locator(self.plan.login.password_selector).fill(credentials.password)
        timeout_milliseconds = self.plan.request_timeout_seconds * 1_000
        try:
            activation = await prepare_login_activation(
                page,
                self.plan.login,
                timeout_milliseconds=timeout_milliseconds,
            )
        except LoginActivationError as exc:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery login form did not become valid"
            ) from exc
        async with page.expect_response(
            self._is_login_response,
            timeout=timeout_milliseconds,
        ) as response_info:
            try:
                await activation.activate_once()
            except LoginActivationError as exc:
                raise BrowserDiscoveryRuntimeError(
                    "browser discovery login activation failed"
                ) from exc
        response = await response_info.value
        self._request_mode = "passive-discovery"
        if not 200 <= response.status <= 299:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery login response did not report success"
            )
        try:
            success_activation = await prepare_login_success_activation(
                page,
                self.plan.login,
                timeout_milliseconds=timeout_milliseconds,
            )
            if success_activation is not None:
                await success_activation.activate_once()
        except LoginActivationError as exc:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery login success activation failed"
            ) from exc
        await page.locator(self.plan.login.success_selector).wait_for(
            state="visible",
            timeout=self.plan.request_timeout_seconds * 1_000,
        )
        await page.keyboard.press("Escape")
        await self._prepare_passive_discovery()

    async def _prepare_passive_discovery(self) -> None:
        """Close the login request window and require an idle browser before phase transition."""

        self._require_page()
        self._request_mode = "passive-discovery"
        timeout = min(
            float(self.plan.request_timeout_seconds),
            self.network.deadline - time.monotonic(),
        )
        if timeout <= 0:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery authentication could not settle before the deadline"
            )
        try:
            async with asyncio.timeout(timeout):
                await self._wait_for_request_idle(initial_wait_milliseconds=250)
        except TimeoutError as exc:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery authentication left requests in flight"
            ) from exc
        if self._background_failed:
            raise BrowserDiscoveryRuntimeError("browser discovery response evidence capture failed")
        if self._reservations:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery authentication left requests in flight"
            )

    async def close(self) -> None:
        """Close every owned resource and settle any request reservation without leaking detail."""

        cleanup_failed = False
        self._request_mode = "closed"
        if self._context is not None and self._page is not None:
            timeout = min(
                float(self.plan.request_timeout_seconds),
                self.network.deadline - time.monotonic(),
            )
            if timeout <= 0:
                cleanup_failed = True
            else:
                try:
                    async with asyncio.timeout(timeout):
                        await self._wait_for_request_idle(initial_wait_milliseconds=0)
                except (Exception, asyncio.CancelledError):
                    cleanup_failed = True
        # No response/failure callback may create an unowned task once context teardown starts.
        # Any request that races this transition remains reserved and is failed below.
        self._accept_background_tasks = False
        if self._context is not None:
            try:
                await self._context.close()
            except Exception:
                cleanup_failed = True
            self._context = None
        await self._cancel_background_tasks()
        if self._reservations:
            cleanup_failed = True
        for reservation in tuple(self._reservations.values()):
            await self.network.fail(reservation, reason="browser-context-closed")
        self._reservations.clear()
        self._page = None
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                cleanup_failed = True
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                cleanup_failed = True
            self._playwright = None
        if self._background_failed:
            cleanup_failed = True
        if cleanup_failed:
            raise BrowserDiscoveryRuntimeError(
                "disposable browser discovery session did not close cleanly"
            )
        self._closed_cleanly = True

    def passive_metadata_completions(self) -> tuple[PassiveMetadataCompletion, ...]:
        """Return exact passive completions only after a clean browser shutdown."""

        if not self._closed_cleanly:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery evidence is unavailable before browser closure"
            )
        return tuple(
            self._passive_completions[sequence] for sequence in sorted(self._passive_completions)
        )

    async def _gate_route(self, route: Route, request: Request) -> None:
        content = request.post_data_buffer or b""
        rejection = self._request_rejection(
            request.method,
            request.url,
            content=content,
            redirected=request.redirected_from is not None,
        )
        if rejection is not None:
            self.network.record_block(rejection)
            await route.abort("blockedbyclient")
            return
        try:
            reservation = await self.network.reserve(
                request.method,
                request.url,
                content=content,
            )
        except AssessmentBoundaryError as exc:
            self.network.record_block(self._fixed_boundary_reason(exc))
            await route.abort("blockedbyclient")
            return
        self._reservations[id(request)] = reservation
        try:
            await route.continue_()
        except (Exception, asyncio.CancelledError):
            self._reservations.pop(id(request), None)
            await self.network.fail(reservation, reason="browser-request-start-failed")
            raise

    async def _block_web_socket(self, route: WebSocketRoute) -> None:
        self.network.record_block("websocket-disabled")
        await route.close(code=1008, reason="local assessment websocket disabled")

    async def _record_response(self, response: Response) -> None:
        reservation = self._reservations.pop(id(response.request), None)
        if reservation is None:
            return
        try:
            timeout = min(
                float(self.plan.request_timeout_seconds),
                self.network.deadline - time.monotonic(),
            )
            async with asyncio.timeout(max(0.001, timeout)):
                # Do not call Response.finished(): its target-close watcher is an internal,
                # unowned asyncio Task when normal completion wins the race.  The sizes channel
                # operation waits for Playwright's completed transfer accounting without
                # leaving that watcher behind.
                sizes = await response.request.sizes()
                media_type = await response.header_value("content-type")
                headers = {"content-type": media_type or ""}
            response_bytes = sizes.get("responseBodySize")
            if type(response_bytes) is not int or response_bytes < 0:
                raise BrowserDiscoveryRuntimeError(
                    "browser discovery response size metadata was invalid"
                )
            policy = self.network.policy
            if policy is None:
                raise BrowserDiscoveryRuntimeError(
                    "browser discovery response completed without an egress policy"
                )
            if response_bytes > min(self.plan.max_response_bytes, policy.max_response_bytes):
                await self.network.fail(reservation, reason="response-byte-limit")
                self._background_failed = True
                return
            async with self._response_budget_lock:
                if (
                    self._observed_response_bytes + response_bytes
                    > _MAX_TOTAL_BROWSER_RESPONSE_BYTES
                ):
                    await self.network.fail(reservation, reason="total-response-budget")
                    self._background_failed = True
                    return
                self._observed_response_bytes += response_bytes
            # Passive discovery needs status and media-type evidence, not response content.
            # The empty payload makes the persisted digest and byte count accurately describe
            # the retained body (none); Playwright's size metadata enforces transfer budgets
            # without copying or decompressing the response into this process.
            if reservation.phase == "browser-passive-discovery" and reservation.method == "GET":
                completion = await self.network.complete_passive_metadata(
                    reservation,
                    status=response.status,
                    headers=headers,
                    observed_response_bytes=response_bytes,
                    return_boundary_receipt=True,
                )
                sequence = request_evidence_sequence(completion.evidence)
                if sequence in self._passive_completions:
                    raise BrowserDiscoveryRuntimeError(
                        "browser discovery produced duplicate passive response evidence"
                    )
                self._passive_completions[sequence] = completion
            else:
                await self.network.complete(
                    reservation,
                    status=response.status,
                    headers=headers,
                    body=b"",
                )
        except (Exception, asyncio.CancelledError):
            await self.network.fail(
                reservation,
                reason="browser-response-capture-failure",
            )
            self._background_failed = True

    async def _record_request_failure(self, request: Request) -> None:
        reservation = self._reservations.pop(id(request), None)
        if reservation is not None:
            await self.network.fail(reservation, reason="browser-request-failed")

    async def _dismiss_login_obstructions(self, page: Page) -> None:
        for selector in self.plan.login.dismiss_selectors:
            try:
                await page.locator(selector).first.click(timeout=3_000)
            except Exception:
                continue
        backdrop = page.locator(".cdk-overlay-backdrop-showing")
        try:
            await backdrop.wait_for(state="hidden", timeout=3_000)
        except Exception:
            await page.keyboard.press("Escape")
        if await backdrop.is_visible():
            raise BrowserDiscoveryRuntimeError(
                "browser discovery login remained covered by an application dialog"
            )

    def _is_login_response(self, response: Response) -> bool:
        return self._is_exact_login_request(response.request.method, response.url)

    def _request_rejection(
        self,
        method: str,
        url: str,
        *,
        content: bytes,
        redirected: bool,
    ) -> str | None:
        normalized_method = method.upper()
        if self._request_mode == "closed":
            return "unapproved-method"
        if redirected:
            return "redirect-disabled"
        if self._request_mode == "passive-discovery":
            if self.passive_request_profile == "governed-get-only":
                try:
                    require_passive_discovery_request(
                        origin=self.plan.origin,
                        method=normalized_method,
                        url=url,
                        content=content,
                        redirected=False,
                    )
                except PassiveDiscoveryRequestBoundaryError as exc:
                    return exc.reason
                return None
            return (
                None
                if normalized_method in _LEGACY_PASSIVE_DISCOVERY_METHODS
                else ("unapproved-method")
            )
        if normalized_method in _AUTHENTICATION_NAVIGATION_METHODS and not content:
            return None
        if self._is_exact_login_request(normalized_method, url):
            return None
        return "unapproved-method"

    def _is_exact_login_request(self, method: str, url: str) -> bool:
        parsed = urlsplit(url)
        approved = urlsplit(self.plan.origin)
        return (
            method.upper() == "POST"
            and (parsed.scheme, parsed.netloc) == (approved.scheme, approved.netloc)
            and parsed.path == self.plan.login.endpoint
            and not parsed.query
            and not parsed.fragment
        )

    def _require_page(self) -> Page:
        if self._page is None:
            raise BrowserDiscoveryRuntimeError("browser discovery page is not initialized")
        return self._page

    def _schedule(self, operation: Coroutine[Any, Any, None]) -> None:
        if not self._accept_background_tasks:
            operation.close()
            return
        task = asyncio.create_task(operation)
        self._background_tasks.add(task)
        task.add_done_callback(self._background_task_done)

    def _background_task_done(self, task: asyncio.Task[None]) -> None:
        """Retrieve every result before releasing the final strong task reference."""

        self._background_tasks.discard(task)
        if task.cancelled():
            return
        try:
            task.result()
        except asyncio.CancelledError:
            return
        except Exception:
            self._background_failed = True

    async def _drain_background_tasks(self) -> None:
        while self._background_tasks:
            tasks = tuple(self._background_tasks)
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _wait_for_request_idle(self, *, initial_wait_milliseconds: int) -> None:
        page = self._require_page()
        if initial_wait_milliseconds:
            await page.wait_for_timeout(initial_wait_milliseconds)
        while True:
            await self._drain_background_tasks()
            if not self._reservations and not self._background_tasks:
                # Give Playwright one callback turn to publish a response/failure that completed
                # immediately before the idle observation.
                await asyncio.sleep(0)
                if not self._reservations and not self._background_tasks:
                    return
            await page.wait_for_timeout(25)

    async def _cancel_background_tasks(self) -> None:
        tasks = tuple(self._background_tasks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    @staticmethod
    def _fixed_boundary_reason(error: AssessmentBoundaryError) -> str:
        reason = str(error)
        allowed = {
            "assessment-deadline",
            "ambiguous-url",
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
            "total-request-budget",
            "request-byte-limit",
            "sensitive-path",
            "total-response-budget",
            "unapproved-method",
            "unapproved-post-path",
            "value-bearing-path",
        }
        return reason if reason in allowed else "browser-request-rejected"


class GovernedPlaywrightAuthenticatedDiscoverySession(PlaywrightAuthenticatedDiscoverySession):
    """WEB-005-compatible session with the authoritative bodyless GET-only gate."""

    passive_request_profile: Literal["governed-get-only"] = "governed-get-only"


async def _run_authenticated_browser_discovery(
    *,
    assessment_plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
    network: AssessmentNetwork,
    credentials: BrowserCredentials,
    navigation_policy: EgressPolicy,
    headless: bool,
    session_factory: BrowserDiscoverySessionFactory,
    passive_methods: frozenset[str],
    required_session_type: type[PlaywrightAuthenticatedDiscoverySession] | None,
) -> tuple[BrowserDiscoveryResult, AuthenticatedBrowserDiscoverySession]:
    assessment_plan = WebAssessmentPlan.model_validate(assessment_plan.model_dump(mode="json"))
    discovery_plan = BrowserDiscoveryPlan.model_validate(discovery_plan.model_dump(mode="json"))
    if discovery_plan.origin != assessment_plan.origin:
        raise BrowserDiscoveryRuntimeError(
            "browser discovery Plan differs from the assessment origin"
        )
    if network.plan.plan_digest != assessment_plan.plan_digest:
        raise BrowserDiscoveryRuntimeError(
            "browser discovery network differs from the assessment Plan"
        )
    canonical_navigation_policy = EgressPolicy.model_validate(navigation_policy.model_dump())
    network.begin_phase("browser-authentication", canonical_navigation_policy)
    session = session_factory(
        plan=assessment_plan,
        network=network,
        headless=headless,
    )
    try:
        if required_session_type is not None:
            if type(session) is not required_session_type:
                raise BrowserDiscoveryRuntimeError(
                    "governed browser discovery session lacks the authoritative request gate"
                )
            governed_session = session
            if (
                governed_session.network is not network
                or governed_session.plan.plan_digest != assessment_plan.plan_digest
                or governed_session.plan.origin != assessment_plan.origin
            ):
                raise BrowserDiscoveryRuntimeError(
                    "governed browser discovery session differs from the assessment boundary"
                )
        page = await session.start()
        await session.authenticate(credentials)
        remaining_requests = canonical_navigation_policy.max_requests - network.phase_requests
        if remaining_requests < 1:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery authentication exhausted the request budget"
            )
        granted_passive_methods = canonical_navigation_policy.allowed_methods.intersection(
            passive_methods
        )
        if not granted_passive_methods:
            raise BrowserDiscoveryRuntimeError(
                "browser discovery policy grants no passive navigation methods"
            )
        passive_policy = canonical_navigation_policy.model_copy(
            update={
                "allowed_methods": granted_passive_methods,
                "max_requests": remaining_requests,
            }
        )
        network.begin_phase("browser-passive-discovery", passive_policy)
        result = await discover_browser_routes_and_forms(page, plan=discovery_plan)
    except (Exception, asyncio.CancelledError):
        with suppress(Exception, asyncio.CancelledError):
            await session.close()
        raise
    await session.close()
    return result, session


async def run_authenticated_browser_discovery(
    *,
    assessment_plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
    network: AssessmentNetwork,
    credentials: BrowserCredentials,
    navigation_policy: EgressPolicy,
    headless: bool = True,
    session_factory: BrowserDiscoverySessionFactory = (PlaywrightAuthenticatedDiscoverySession),
) -> BrowserDiscoveryResult:
    """Run the existing WEB-004-compatible GET/HEAD passive discovery profile."""

    result, _session = await _run_authenticated_browser_discovery(
        assessment_plan=assessment_plan,
        discovery_plan=discovery_plan,
        network=network,
        credentials=credentials,
        navigation_policy=navigation_policy,
        headless=headless,
        session_factory=session_factory,
        passive_methods=_LEGACY_PASSIVE_DISCOVERY_METHODS,
        required_session_type=None,
    )
    return result


async def run_governed_authenticated_browser_discovery(
    *,
    assessment_plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
    network: AssessmentNetwork,
    credentials: BrowserCredentials,
    navigation_policy: EgressPolicy,
    headless: bool = True,
) -> BrowserDiscoveryResult:
    """Run proposal-only discovery through the exact bodyless GET request profile."""

    if type(network) is not AssessmentNetwork:
        raise BrowserDiscoveryRuntimeError(
            "governed browser discovery requires the code-owned assessment network"
        )
    result, _session = await _run_authenticated_browser_discovery(
        assessment_plan=assessment_plan,
        discovery_plan=discovery_plan,
        network=network,
        credentials=credentials,
        navigation_policy=navigation_policy,
        headless=headless,
        session_factory=GovernedPlaywrightAuthenticatedDiscoverySession,
        passive_methods=_GOVERNED_PASSIVE_DISCOVERY_METHODS,
        required_session_type=GovernedPlaywrightAuthenticatedDiscoverySession,
    )
    return result


async def run_governed_authenticated_browser_discovery_with_evidence(
    *,
    assessment_plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
    network: AssessmentNetwork,
    credentials: BrowserCredentials,
    navigation_policy: EgressPolicy,
    headless: bool = True,
) -> GovernedAuthenticatedDiscoveryObservation:
    """Return closed-browser discovery plus ordered bodyless passive metadata receipts."""

    if type(network) is not AssessmentNetwork:
        raise BrowserDiscoveryRuntimeError(
            "governed browser discovery requires the code-owned assessment network"
        )
    result, session = await _run_authenticated_browser_discovery(
        assessment_plan=assessment_plan,
        discovery_plan=discovery_plan,
        network=network,
        credentials=credentials,
        navigation_policy=navigation_policy,
        headless=headless,
        session_factory=GovernedPlaywrightAuthenticatedDiscoverySession,
        passive_methods=_GOVERNED_PASSIVE_DISCOVERY_METHODS,
        required_session_type=GovernedPlaywrightAuthenticatedDiscoverySession,
    )
    if type(session) is not GovernedPlaywrightAuthenticatedDiscoverySession:
        raise BrowserDiscoveryRuntimeError("governed browser discovery session provenance differs")
    completions = session.passive_metadata_completions()
    if not completions:
        raise BrowserDiscoveryRuntimeError(
            "governed browser discovery retained no passive response evidence"
        )
    requests = tuple(completion.evidence for completion in completions)
    receipts = tuple(completion.boundary_receipt for completion in completions)
    passive_network_evidence = tuple(
        sorted(
            (
                request
                for request in network.evidence
                if request.phase == "browser-passive-discovery"
            ),
            key=request_evidence_sequence,
        )
    )
    if (
        tuple(request_evidence_sequence(request) for request in requests)
        != tuple(receipt.evidence_sequence for receipt in receipts)
        or requests != passive_network_evidence
    ):
        raise BrowserDiscoveryRuntimeError(
            "governed browser discovery passive evidence order differs"
        )
    return GovernedAuthenticatedDiscoveryObservation(
        discovery_result=BrowserDiscoveryResult.model_validate(
            result.model_dump(mode="json", by_alias=True)
        ),
        request_evidence=tuple(
            RequestEvidence.model_validate(request.model_dump(mode="json", by_alias=True))
            for request in requests
        ),
        boundary_receipts=tuple(
            PassiveDiscoveryBoundaryReceipt.model_validate(
                receipt.model_dump(mode="json", by_alias=True)
            )
            for receipt in receipts
        ),
    )


_AUTHENTICATION_NAVIGATION_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD"})
_LEGACY_PASSIVE_DISCOVERY_METHODS: Final[frozenset[str]] = frozenset({"GET", "HEAD"})
_GOVERNED_PASSIVE_DISCOVERY_METHODS: Final[frozenset[str]] = frozenset({"GET"})
_MAX_TOTAL_BROWSER_RESPONSE_BYTES: Final[int] = 128_000_000


__all__ = [
    "AuthenticatedBrowserDiscoverySession",
    "BrowserDiscoveryRuntimeError",
    "BrowserDiscoverySessionFactory",
    "GovernedAuthenticatedDiscoveryObservation",
    "GovernedPlaywrightAuthenticatedDiscoverySession",
    "PassiveDiscoveryRequestBoundaryError",
    "PlaywrightAuthenticatedDiscoverySession",
    "require_passive_discovery_request",
    "run_authenticated_browser_discovery",
    "run_governed_authenticated_browser_discovery",
    "run_governed_authenticated_browser_discovery_with_evidence",
]
