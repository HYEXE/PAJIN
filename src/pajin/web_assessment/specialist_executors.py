"""Closed least-privilege diagnostic executors for AGENTIC-003B.

This module binds the inert specialist profiles from AGENTIC-003A to three
separate code-owned diagnostic closures.  It deliberately exposes no Campaign,
Capability, Permit, Gateway, Worker, Finding, or Graph authority.  A later
trusted bridge must supply those authorities before this code is reachable from
an agent assignment.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from types import MappingProxyType
from typing import Final, Literal, Never, SupportsIndex, cast

from pajin.agentic.execution_profiles import (
    ResolvedSpecialistExecutionProfile,
    SpecialistExecutionProfileRef,
    SpecialistExecutionProfileSnapshot,
)
from pajin.capabilities.models import capability_definition_digest
from pajin.runtime.safe_files import read_bounded_regular_bytes
from pajin.runtime.store import RunStore, validate_run_artifact_path
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment import diagnostics
from pajin.web_assessment.adapter_catalog import production_adapter_implementation_catalog
from pajin.web_assessment.browser import (
    PlaywrightSpecialistAssessmentBrowser,
    SpecialistBrowserObservation,
)
from pajin.web_assessment.models import (
    AssessmentIssue,
    BrowserPageEvidence,
    IssueCheck,
    ProbeTrial,
    RequestEvidence,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.specialist_profiles import (
    WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
    WEB_SQLI_SPECIALIST_PROFILE_ID,
    WEB_XSS_SPECIALIST_PROFILE_ID,
    production_web_specialist_execution_profile_catalog,
)

_EXECUTOR_CATALOG_DIGEST_DOMAIN: Final = "pajin.web-specialist-executor-catalog/v1"
_EXECUTOR_DIGEST_DOMAIN: Final = "pajin.web-specialist-executor/v1"
_EXECUTOR_VERSION: Final = "1.1.0"
_BROWSER_IMPLEMENTATION_ID: Final = "pajin.web-specialist-browser.playwright"
_BROWSER_IMPLEMENTATION_VERSION: Final = "1.1.0"
_BROWSER_IMPLEMENTATION_DIGEST: Final = capability_definition_digest(
    "pajin.web-specialist-browser/v1",
    {
        "implementationId": _BROWSER_IMPLEMENTATION_ID,
        "implementationVersion": _BROWSER_IMPLEMENTATION_VERSION,
        "aggregateRunnerReused": False,
        "supportedClosures": [
            ["dom-xss"],
            ["sql-login", "object-access"],
        ],
        "accountSemantics": {
            "accountCreationPerformed": False,
            "provisionedAccountUsed": True,
        },
    },
)
_CATALOG_FACTORY_TOKEN: Final = object()
_AUTHORITY_FACTORY_TOKEN: Final = object()
_RUNTIME_PROFILE_PRODUCTION: Final = "production-default-httpx-playwright"
_RUNTIME_PROFILE_TESTING: Final = "testing-injected-transport"

_DIAGNOSE_SQL_LOGIN: Final = diagnostics.diagnose_sql_login
_DIAGNOSE_OBJECT_ACCESS: Final = diagnostics.diagnose_object_access
_DOM_XSS_ISSUE: Final = diagnostics.dom_xss_issue
_SPECIALIST_BROWSER_RUN: Final = PlaywrightSpecialistAssessmentBrowser.run_specialist


class WebSpecialistExecutorError(RuntimeError):
    """Raised when a specialist closure or its runtime provenance differs."""


class WebSpecialistDependencyError(WebSpecialistExecutorError):
    """Raised when an ordered specialist dependency cannot be established."""


@dataclass(frozen=True, slots=True)
class SpecialistDiagnosticPolicies:
    """Code-owned exact policies present only for the selected closure."""

    sql_login: EgressPolicy | None = None
    object_access: EgressPolicy | None = None


def _specialist_deny_rules(plan: WebAssessmentPlan) -> list[str]:
    return [plan.origin + path.rstrip("/") + "*" for path in plan.deny_paths]


def specialist_sql_login_policy(plan: WebAssessmentPlan) -> EgressPolicy:
    """Compile the exact two-endpoint policy used by each SQL-login phase."""

    recipe = plan.sql_login
    if recipe is None:
        raise WebSpecialistExecutorError("SQL login recipe is unavailable")
    return EgressPolicy(
        allow=[
            plan.origin + plan.login.endpoint,
            plan.origin + recipe.impact_endpoint,
        ],
        deny=_specialist_deny_rules(plan),
        allowed_methods={"GET", "POST"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=3,
        max_request_bytes=64_000,
    )


def specialist_object_access_policy(plan: WebAssessmentPlan) -> EgressPolicy:
    """Compile the exact GET-only object endpoint policy used by each phase."""

    recipe = plan.object_access
    if recipe is None:
        raise WebSpecialistExecutorError("object access recipe is unavailable")
    return EgressPolicy(
        allow=[plan.origin + recipe.endpoint_template.replace("{id}", "*")],
        deny=_specialist_deny_rules(plan),
        allowed_methods={"GET"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=3,
        max_request_bytes=64_000,
    )


def _canonical_specialist_policy(
    policy: EgressPolicy,
    *,
    expected: EgressPolicy,
    label: str,
) -> EgressPolicy:
    if type(policy) is not EgressPolicy:
        raise WebSpecialistExecutorError(f"{label} specialist policy is not canonical")
    try:
        canonical = EgressPolicy.model_validate(policy.model_dump(mode="json"))
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutorError(f"{label} specialist policy is invalid") from exc
    if canonical != policy or canonical != expected:
        raise WebSpecialistExecutorError(
            f"{label} specialist policy differs from the exact code-owned boundary"
        )
    return canonical


_SPECIALIST_SQL_LOGIN_POLICY: Final = specialist_sql_login_policy
_SPECIALIST_OBJECT_ACCESS_POLICY: Final = specialist_object_access_policy


@dataclass(frozen=True, slots=True)
class SpecialistExecutorDescriptor:
    """Serializable-by-value executor identity without bearer authority."""

    catalog_digest: str
    profile_registry_digest: str
    profile_ref: SpecialistExecutionProfileRef
    executor_id: str
    executor_version: str
    executor_digest: str
    browser_implementation_id: str | None
    browser_implementation_version: str | None
    browser_implementation_digest: str | None
    diagnostic_steps: tuple[IssueCheck, ...]
    promotable_steps: tuple[IssueCheck, ...]
    scope_authority: Literal[False] = field(default=False, init=False)
    capability_authority: Literal[False] = field(default=False, init=False)
    permit_authority: Literal[False] = field(default=False, init=False)
    gateway_authority: Literal[False] = field(default=False, init=False)
    worker_authority: Literal[False] = field(default=False, init=False)
    finding_authority: Literal[False] = field(default=False, init=False)
    graph_authority: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class SpecialistDiagnosticExecution:
    """Evidence-derived subset output that is not a Finding or Graph authority."""

    descriptor: SpecialistExecutorDescriptor
    run_id: str
    object_id: int | None
    issues: tuple[AssessmentIssue, ...]
    promotable_issues: tuple[AssessmentIssue, ...]
    observed_diagnostic_steps: tuple[IssueCheck, ...]
    independent_validation_performed: Literal[False] = field(default=False, init=False)
    finding_authority: Literal[False] = field(default=False, init=False)
    graph_authority: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class _CodeOwnedSpecialistExecutor:
    profile: SpecialistExecutionProfileSnapshot
    executor_id: str
    executor_version: str
    executor_digest: str
    browser_required: bool


def _executor_material(
    profile: SpecialistExecutionProfileSnapshot,
    *,
    executor_id: str,
    browser_required: bool,
) -> dict[str, object]:
    return {
        "executorId": executor_id,
        "executorVersion": _EXECUTOR_VERSION,
        "profileRef": profile.reference().model_dump(mode="json", by_alias=True),
        "diagnosticSteps": list(profile.diagnostic_steps),
        "promotableSteps": list(profile.promotable_steps),
        "browser": (
            {
                "implementationId": _BROWSER_IMPLEMENTATION_ID,
                "implementationVersion": _BROWSER_IMPLEMENTATION_VERSION,
                "implementationDigest": _BROWSER_IMPLEMENTATION_DIGEST,
            }
            if browser_required
            else None
        ),
        "orderedComponents": [
            ("pajin.web_assessment.browser.PlaywrightSpecialistAssessmentBrowser.run_specialist"),
            "pajin.web_assessment.diagnostics.diagnose_sql_login",
            "pajin.web_assessment.diagnostics.diagnose_object_access",
            "pajin.web_assessment.diagnostics.dom_xss_issue",
            "pajin.web_assessment.specialist_executors.specialist_sql_login_policy",
            "pajin.web_assessment.specialist_executors.specialist_object_access_policy",
        ],
        "diagnosticPolicyBoundaries": {
            "sql-login": {
                "endpointSources": ["login.endpoint", "sqlLogin.impactEndpoint"],
                "allowedMethods": ["GET", "POST"],
                "maxRequestsPerPhase": 3,
            },
            "object-access": {
                "endpointSources": ["objectAccess.endpointTemplate"],
                "allowedMethods": ["GET"],
                "maxRequestsPerPhase": 3,
            },
        },
        "aggregateRunnerReused": False,
        "findingAuthority": False,
        "graphAuthority": False,
    }


def _new_executor(
    profile: SpecialistExecutionProfileSnapshot,
    *,
    executor_id: str,
    browser_required: bool,
) -> _CodeOwnedSpecialistExecutor:
    canonical = SpecialistExecutionProfileSnapshot.model_validate(
        profile.model_dump(mode="json", by_alias=True)
    )
    material = _executor_material(
        canonical,
        executor_id=executor_id,
        browser_required=browser_required,
    )
    return _CodeOwnedSpecialistExecutor(
        profile=canonical,
        executor_id=executor_id,
        executor_version=_EXECUTOR_VERSION,
        executor_digest=capability_definition_digest(_EXECUTOR_DIGEST_DOMAIN, material),
        browser_required=browser_required,
    )


def _code_owned_executors() -> tuple[_CodeOwnedSpecialistExecutor, ...]:
    profiles = production_web_specialist_execution_profile_catalog()
    by_id = {
        reference.profile_id: profiles.resolve(reference).snapshot()
        for reference in profiles.references()
    }
    return tuple(
        sorted(
            (
                _new_executor(
                    by_id[WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID],
                    executor_id="pajin.web-specialist.authorization",
                    browser_required=True,
                ),
                _new_executor(
                    by_id[WEB_SQLI_SPECIALIST_PROFILE_ID],
                    executor_id="pajin.web-specialist.sql-login",
                    browser_required=False,
                ),
                _new_executor(
                    by_id[WEB_XSS_SPECIALIST_PROFILE_ID],
                    executor_id="pajin.web-specialist.dom-xss",
                    browser_required=True,
                ),
            ),
            key=lambda item: item.profile.profile_id,
        )
    )


def _descriptor(
    executor: _CodeOwnedSpecialistExecutor,
    *,
    catalog_digest: str,
    profile_registry_digest: str,
) -> SpecialistExecutorDescriptor:
    return SpecialistExecutorDescriptor(
        catalog_digest=catalog_digest,
        profile_registry_digest=profile_registry_digest,
        profile_ref=executor.profile.reference(),
        executor_id=executor.executor_id,
        executor_version=executor.executor_version,
        executor_digest=executor.executor_digest,
        browser_implementation_id=(
            _BROWSER_IMPLEMENTATION_ID if executor.browser_required else None
        ),
        browser_implementation_version=(
            _BROWSER_IMPLEMENTATION_VERSION if executor.browser_required else None
        ),
        browser_implementation_digest=(
            _BROWSER_IMPLEMENTATION_DIGEST if executor.browser_required else None
        ),
        diagnostic_steps=_typed_steps(executor.profile.diagnostic_steps),
        promotable_steps=_typed_steps(executor.profile.promotable_steps),
    )


def _typed_steps(values: tuple[str, ...]) -> tuple[IssueCheck, ...]:
    if any(value not in {"sql-login", "object-access", "dom-xss"} for value in values):
        raise WebSpecialistExecutorError("specialist profile contains an unknown diagnostic")
    return cast(tuple[IssueCheck, ...], values)


def _is_mapping_proxy(value: object) -> bool:
    return type(value) is type(MappingProxyType({}))


def _catalog_digest(
    executors: tuple[_CodeOwnedSpecialistExecutor, ...],
    *,
    profile_registry_digest: str,
    runtime_profile: str,
) -> str:
    return capability_definition_digest(
        _EXECUTOR_CATALOG_DIGEST_DOMAIN,
        {
            "profileRegistryDigest": profile_registry_digest,
            "runtimeProfile": runtime_profile,
            "executors": [
                {
                    **_executor_material(
                        item.profile,
                        executor_id=item.executor_id,
                        browser_required=item.browser_required,
                    ),
                    "executorDigest": item.executor_digest,
                }
                for item in executors
            ],
        },
    )


def _canonical_page(page: BrowserPageEvidence) -> BrowserPageEvidence:
    if type(page) is not BrowserPageEvidence:
        raise WebSpecialistExecutorError("specialist browser page type is not canonical")
    try:
        canonical = BrowserPageEvidence.model_validate(page.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutorError("specialist browser page is invalid") from exc
    if canonical != page:
        raise WebSpecialistExecutorError("specialist browser page differs after strict reload")
    return canonical


def _canonical_counter_items(
    items: tuple[tuple[str, int], ...],
    *,
    label: str,
) -> tuple[tuple[str, int], ...]:
    if (
        type(items) is not tuple
        or items != tuple(sorted(items))
        or len(items) != len({key for key, _value in items})
        or any(
            type(key) is not str or not key or len(key) > 100 or type(value) is not int or value < 0
            for key, value in items
        )
    ):
        raise WebSpecialistExecutorError(f"specialist browser {label} is not canonical")
    return items


def _canonical_trial(trial: ProbeTrial) -> ProbeTrial:
    if type(trial) is not ProbeTrial:
        raise WebSpecialistExecutorError("specialist browser trial type is not canonical")
    try:
        canonical = ProbeTrial.model_validate(trial.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutorError("specialist browser trial is invalid") from exc
    if canonical != trial:
        raise WebSpecialistExecutorError("specialist browser trial differs after strict reload")
    return canonical


def _require_page_evidence(store: RunStore, pages: tuple[BrowserPageEvidence, ...]) -> None:
    references: set[str] = set()
    for page in pages:
        try:
            reference = validate_run_artifact_path(page.screenshot_reference)
        except ValueError as exc:
            raise WebSpecialistExecutorError(
                "specialist browser screenshot reference is not a Run artifact path"
            ) from exc
        if reference in references:
            raise WebSpecialistExecutorError(
                "specialist browser screenshot reference is duplicated"
            )
        references.add(reference)
        try:
            content = read_bounded_regular_bytes(
                store.path / reference,
                max_bytes=10_000_000,
                label="specialist browser screenshot Evidence",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise WebSpecialistExecutorError(
                "specialist browser screenshot Evidence is absent from the current Run"
            ) from exc
        if (
            len(content) != page.screenshot_bytes
            or sha256(content).hexdigest() != page.screenshot_sha256
        ):
            raise WebSpecialistExecutorError(
                "specialist browser screenshot Evidence differs from the current Run"
            )


def _canonical_browser_observation(  # noqa: C901 - one closed adversarial boundary
    observation: SpecialistBrowserObservation | None,
    *,
    executor: _CodeOwnedSpecialistExecutor,
    plan: WebAssessmentPlan,
    store: RunStore,
) -> SpecialistBrowserObservation | None:
    if not executor.browser_required:
        if observation is not None:
            raise WebSpecialistExecutorError(
                "SQL specialist must not receive a browser observation"
            )
        return None
    if (
        type(observation) is not SpecialistBrowserObservation
        or observation.diagnostic_steps != executor.profile.diagnostic_steps
        or type(observation.object_id) is not int
        or not 0 < observation.object_id <= 2_147_483_647
        or type(observation.pages) is not tuple
        or not observation.pages
        or type(observation.requests_completed) is not int
        or not 1 <= observation.requests_completed <= 500
        or type(observation.unexpected_console_error_fingerprints) is not tuple
        or len(observation.unexpected_console_error_fingerprints) > 20
        or any(
            type(item) is not str or not item or len(item) > 200
            for item in observation.unexpected_console_error_fingerprints
        )
        or observation.authenticated is not True
        or observation.account_creation_performed is not False
        or observation.provisioned_account_used is not True
        or observation.browser_closed is not True
    ):
        raise WebSpecialistExecutorError("specialist browser observation is not canonical")
    pages = tuple(_canonical_page(page) for page in observation.pages)
    _canonical_counter_items(observation.blocked_requests, label="blocked requests")
    _canonical_counter_items(observation.request_failures, label="request failures")
    if executor.profile.diagnostic_steps == ("dom-xss",):
        if type(observation.dom_xss_trials) is not tuple or len(observation.dom_xss_trials) != 2:
            raise WebSpecialistExecutorError("XSS specialist requires two DOM trials")
        trials = tuple(_canonical_trial(trial) for trial in observation.dom_xss_trials)
        if tuple(page.phase for page in pages) != (
            "authenticated-navigation",
            "dom-xss-control",
            "dom-xss-source",
            "dom-xss-control",
            "dom-xss-replay",
        ):
            raise WebSpecialistExecutorError("XSS specialist browser trace is not minimal")
        if plan.dom_xss is None:
            raise WebSpecialistExecutorError("XSS specialist recipe is unavailable")
        pages_by_id = {page.evidence_id: page for page in pages}
        expected_probe_phases = ("dom-xss-source", "dom-xss-replay")
        route_prefix = plan.dom_xss.route_template.partition("{payload}")[0]
        used: list[str] = []
        for trial, probe_phase in zip(trials, expected_probe_phases, strict=True):
            if (
                trial.check != "dom-xss"
                or len(trial.evidence_ids) != 2
                or set(trial.facts)
                != {
                    "controlMarkerExecuted",
                    "probeMarkerExecuted",
                    "externalTransmission",
                }
            ):
                raise WebSpecialistExecutorError("XSS specialist trial shape differs")
            try:
                control = pages_by_id[trial.evidence_ids[0]]
                probe = pages_by_id[trial.evidence_ids[1]]
            except KeyError as exc:
                raise WebSpecialistExecutorError(
                    "XSS specialist trial references unknown page Evidence"
                ) from exc
            if (
                control.phase != "dom-xss-control"
                or probe.phase != probe_phase
                or control.route != route_prefix + "<control-redacted>"
                or probe.route != route_prefix + "<probe-redacted>"
                or control.ready_selector != plan.dom_xss.ready_selector
                or probe.ready_selector != plan.dom_xss.ready_selector
                or type(control.marker_executed) is not bool
                or type(probe.marker_executed) is not bool
                or trial.controls_passed is not (control.marker_executed is False)
                or trial.reproduced is not probe.marker_executed
                or trial.facts["controlMarkerExecuted"] is not control.marker_executed
                or trial.facts["probeMarkerExecuted"] is not probe.marker_executed
                or trial.facts["externalTransmission"] is not False
            ):
                raise WebSpecialistExecutorError(
                    "XSS specialist trial differs from browser Evidence"
                )
            used.extend(trial.evidence_ids)
        if len(used) != len(set(used)):
            raise WebSpecialistExecutorError("XSS specialist trial Evidence is reused")
        canonical_trials: tuple[ProbeTrial, ProbeTrial] | None = (trials[0], trials[1])
    else:
        if executor.profile.diagnostic_steps != ("sql-login", "object-access"):
            raise WebSpecialistExecutorError("specialist browser closure is not installed")
        if observation.dom_xss_trials is not None:
            raise WebSpecialistExecutorError(
                "authorization bootstrap must not contain DOM XSS diagnostics"
            )
        if tuple(page.phase for page in pages) != ("authenticated-navigation",):
            raise WebSpecialistExecutorError(
                "authorization specialist bootstrap trace is not minimal"
            )
        canonical_trials = None
    _require_page_evidence(store, pages)
    return SpecialistBrowserObservation(
        diagnostic_steps=observation.diagnostic_steps,
        object_id=observation.object_id,
        pages=pages,
        dom_xss_trials=canonical_trials,
        requests_completed=observation.requests_completed,
        blocked_requests=observation.blocked_requests,
        request_failures=observation.request_failures,
        unexpected_console_error_fingerprints=(observation.unexpected_console_error_fingerprints),
        account_creation_performed=False,
        provisioned_account_used=True,
    )


def _expected_trace_phases(steps: tuple[IssueCheck, ...]) -> tuple[str, ...]:
    if steps == ("dom-xss",):
        return (
            "browser-authenticated-navigation",
            "dom-xss-source",
            "dom-xss-replay",
        )
    if steps == ("sql-login",):
        return ("sql-login-source", "sql-login-replay")
    if steps == ("sql-login", "object-access"):
        return (
            "browser-authenticated-navigation",
            "sql-login-source",
            "sql-login-replay",
            "object-access-source",
            "object-access-replay",
        )
    raise WebSpecialistExecutorError("specialist trace closure is not installed")


def _expected_bound_phases(steps: tuple[IssueCheck, ...]) -> tuple[str, ...]:
    if steps == ("dom-xss",):
        return _expected_trace_phases(steps)
    if steps == ("sql-login",):
        return ()
    if steps == ("sql-login", "object-access"):
        return ("browser-authenticated-navigation",)
    raise WebSpecialistExecutorError("specialist trace closure is not installed")


def _trace_phase_groups(evidence: list[RequestEvidence]) -> tuple[str, ...]:
    groups: list[str] = []
    for item in evidence:
        if type(item) is not RequestEvidence:
            raise WebSpecialistExecutorError("specialist request Evidence is not canonical")
        if not groups or groups[-1] != item.phase:
            groups.append(item.phase)
    return tuple(groups)


def _require_trace_closure(
    evidence: list[RequestEvidence],
    *,
    steps: tuple[IssueCheck, ...],
    bound_only: bool = False,
) -> tuple[IssueCheck, ...]:
    expected = _expected_bound_phases(steps) if bound_only else _expected_trace_phases(steps)
    observed_phases = _trace_phase_groups(evidence)
    if observed_phases != expected:
        raise WebSpecialistExecutorError(
            "specialist trace phases differ from the exact profile closure"
        )
    return tuple(
        step
        for step in steps
        if f"{step}-source" in observed_phases and f"{step}-replay" in observed_phases
    )


def _canonical_issue(issue: AssessmentIssue) -> AssessmentIssue:
    if type(issue) is not AssessmentIssue:
        raise WebSpecialistExecutorError("specialist issue type is not canonical")
    try:
        canonical = AssessmentIssue.model_validate(issue.model_dump(mode="json", by_alias=True))
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutorError("specialist issue is invalid") from exc
    if canonical != issue:
        raise WebSpecialistExecutorError("specialist issue differs after strict reload")
    return canonical


class _SpecialistExecutionAuthority:
    __slots__ = (
        "__browser_observation",
        "__catalog",
        "__executor",
        "__factory_token",
        "__network",
        "__object_policy",
        "__plan",
        "__run_id",
        "__sql_policy",
        "__task",
        "__terminal",
    )
    __browser_observation: SpecialistBrowserObservation | None
    __catalog: WebSpecialistExecutorCatalog
    __executor: _CodeOwnedSpecialistExecutor
    __factory_token: object
    __network: AssessmentNetwork
    __object_policy: EgressPolicy | None
    __plan: WebAssessmentPlan
    __run_id: str
    __sql_policy: EgressPolicy | None
    __task: asyncio.Task[object]
    __terminal: bool

    def __init_subclass__(cls) -> None:
        raise TypeError("specialist execution authorities cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist execution authorities are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist execution authorities are immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist execution authorities cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist execution authorities cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist execution authorities cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist execution authorities cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist execution authorities cannot be serialized")

    def __init__(
        self,
        *,
        catalog: WebSpecialistExecutorCatalog,
        executor: _CodeOwnedSpecialistExecutor,
        plan: WebAssessmentPlan,
        browser_observation: SpecialistBrowserObservation | None,
        network: AssessmentNetwork,
        sql_policy: EgressPolicy | None,
        object_policy: EgressPolicy | None,
        run_id: str,
        task: asyncio.Task[object],
        _factory_token: object,
    ) -> None:
        if _factory_token is not _AUTHORITY_FACTORY_TOKEN:
            raise TypeError("specialist execution authority requires runner binding")
        prefix = "_SpecialistExecutionAuthority__"
        object.__setattr__(self, prefix + "catalog", catalog)
        object.__setattr__(self, prefix + "executor", executor)
        object.__setattr__(self, prefix + "plan", plan)
        object.__setattr__(self, prefix + "browser_observation", browser_observation)
        object.__setattr__(self, prefix + "network", network)
        object.__setattr__(self, prefix + "sql_policy", sql_policy)
        object.__setattr__(self, prefix + "object_policy", object_policy)
        object.__setattr__(self, prefix + "run_id", run_id)
        object.__setattr__(self, prefix + "task", task)
        object.__setattr__(self, prefix + "factory_token", _factory_token)
        object.__setattr__(self, prefix + "terminal", False)

    def _consume(
        self,
        catalog: WebSpecialistExecutorCatalog,
    ) -> tuple[
        _CodeOwnedSpecialistExecutor,
        WebAssessmentPlan,
        SpecialistBrowserObservation | None,
        AssessmentNetwork,
        EgressPolicy | None,
        EgressPolicy | None,
        str,
    ]:
        task = asyncio.current_task()
        if (
            type(self) is not _SpecialistExecutionAuthority
            or self.__factory_token is not _AUTHORITY_FACTORY_TOKEN
            or self.__catalog is not catalog
            or task is None
            or task is not self.__task
            or self.__terminal
        ):
            raise WebSpecialistExecutorError(
                "specialist execution authority is absent, foreign, or consumed"
            )
        object.__setattr__(self, "_SpecialistExecutionAuthority__terminal", True)
        return (
            self.__executor,
            self.__plan,
            self.__browser_observation,
            self.__network,
            self.__sql_policy,
            self.__object_policy,
            self.__run_id,
        )


class WebSpecialistExecutorCatalog:
    """Closed executor catalog with no dynamic registration or fallback path."""

    __slots__ = (
        "__catalog_digest",
        "__entries",
        "__executors",
        "__profile_registry_digest",
        "__runtime_profile",
    )
    __catalog_digest: str
    __entries: Mapping[tuple[str, str, str], _CodeOwnedSpecialistExecutor]
    __executors: tuple[_CodeOwnedSpecialistExecutor, ...]
    __profile_registry_digest: str
    __runtime_profile: Literal[
        "production-default-httpx-playwright",
        "testing-injected-transport",
    ]

    def __init_subclass__(cls) -> None:
        raise TypeError("specialist executor catalogs cannot be subclassed")

    def __setattr__(self, _name: str, _value: object) -> Never:
        raise AttributeError("specialist executor catalogs are immutable")

    def __delattr__(self, _name: str) -> Never:
        raise AttributeError("specialist executor catalogs are immutable")

    def __copy__(self) -> Never:
        raise TypeError("specialist executor catalogs cannot be copied")

    def __deepcopy__(self, _memo: object) -> Never:
        raise TypeError("specialist executor catalogs cannot be copied")

    def __reduce__(self) -> Never:
        raise TypeError("specialist executor catalogs cannot be serialized")

    def __reduce_ex__(self, _protocol: SupportsIndex) -> Never:
        raise TypeError("specialist executor catalogs cannot be serialized")

    def __getstate__(self) -> Never:
        raise TypeError("specialist executor catalogs cannot be serialized")

    def __init__(
        self,
        *,
        _runtime_profile: Literal[
            "production-default-httpx-playwright",
            "testing-injected-transport",
        ],
        _factory_token: object | None = None,
    ) -> None:
        if (
            type(self) is not WebSpecialistExecutorCatalog
            or _factory_token is not _CATALOG_FACTORY_TOKEN
        ):
            raise TypeError("specialist executor catalog requires its code-owned factory")
        if _runtime_profile not in {
            _RUNTIME_PROFILE_PRODUCTION,
            _RUNTIME_PROFILE_TESTING,
        }:
            raise WebSpecialistExecutorError("specialist runtime profile is not code-owned")
        profile_catalog = production_web_specialist_execution_profile_catalog()
        executors = _code_owned_executors()
        entries = {
            (
                item.profile.profile_id,
                item.profile.profile_version,
                item.profile.profile_digest,
            ): item
            for item in executors
        }
        if len(entries) != 3:
            raise WebSpecialistExecutorError("specialist executor catalog is not complete")
        object.__setattr__(self, "_WebSpecialistExecutorCatalog__executors", executors)
        object.__setattr__(
            self,
            "_WebSpecialistExecutorCatalog__entries",
            MappingProxyType(entries),
        )
        object.__setattr__(
            self,
            "_WebSpecialistExecutorCatalog__profile_registry_digest",
            profile_catalog.registry_digest,
        )
        object.__setattr__(
            self,
            "_WebSpecialistExecutorCatalog__runtime_profile",
            _runtime_profile,
        )
        object.__setattr__(
            self,
            "_WebSpecialistExecutorCatalog__catalog_digest",
            _catalog_digest(
                executors,
                profile_registry_digest=profile_catalog.registry_digest,
                runtime_profile=_runtime_profile,
            ),
        )

    @property
    def catalog_digest(self) -> str:
        self._require_current()
        return self.__catalog_digest

    def descriptors(self) -> tuple[SpecialistExecutorDescriptor, ...]:
        self._require_current()
        return tuple(
            _descriptor(
                executor,
                catalog_digest=self.__catalog_digest,
                profile_registry_digest=self.__profile_registry_digest,
            )
            for executor in self.__executors
        )

    def resolve(
        self,
        profile: ResolvedSpecialistExecutionProfile,
    ) -> SpecialistExecutorDescriptor:
        executor = self._resolve_profile(profile)
        return _descriptor(
            executor,
            catalog_digest=self.__catalog_digest,
            profile_registry_digest=self.__profile_registry_digest,
        )

    def _bind_runner_execution(
        self,
        *,
        profile: ResolvedSpecialistExecutionProfile,
        plan: WebAssessmentPlan,
        browser_observation: SpecialistBrowserObservation | None,
        network: AssessmentNetwork,
        policies: SpecialistDiagnosticPolicies,
        store: RunStore,
        browser_factory: object | None,
        network_factory: object,
    ) -> _SpecialistExecutionAuthority:
        self._require_current()
        if self.__runtime_profile != _RUNTIME_PROFILE_TESTING:
            raise WebSpecialistExecutorError(
                "production specialist execution requires the AGENTIC-003C governed bridge"
            )
        executor = self._resolve_profile(profile)
        canonical_plan = self._canonical_plan(executor, plan)
        if type(store) is not RunStore:
            raise WebSpecialistExecutorError("specialist Run lineage is not canonical")
        canonical_observation = _canonical_browser_observation(
            browser_observation,
            executor=executor,
            plan=canonical_plan,
            store=store,
        )
        if type(network) is not AssessmentNetwork or network.plan != canonical_plan:
            raise WebSpecialistExecutorError("specialist network differs from the exact plan")
        sql_policy, object_policy = self._canonical_policies(
            executor,
            policies,
            canonical_plan,
        )
        self._require_runtime_factories(
            executor=executor,
            browser_factory=browser_factory,
            network_factory=network_factory,
        )
        _require_executor_current(executor)
        _require_trace_closure(
            network.evidence,
            steps=_typed_steps(executor.profile.diagnostic_steps),
            bound_only=True,
        )
        task = asyncio.current_task()
        if task is None:
            raise WebSpecialistExecutorError("specialist execution requires an async Run task")
        return _SpecialistExecutionAuthority(
            catalog=self,
            executor=executor,
            plan=canonical_plan,
            browser_observation=canonical_observation,
            network=network,
            sql_policy=sql_policy,
            object_policy=object_policy,
            run_id=store.run_id,
            task=task,
            _factory_token=_AUTHORITY_FACTORY_TOKEN,
        )

    async def execute(
        self,
        *,
        authority: _SpecialistExecutionAuthority,
    ) -> SpecialistDiagnosticExecution:
        self._require_current()
        if self.__runtime_profile != _RUNTIME_PROFILE_TESTING:
            raise WebSpecialistExecutorError(
                "production specialist execution requires the AGENTIC-003C governed bridge"
            )
        if type(authority) is not _SpecialistExecutionAuthority:
            raise WebSpecialistExecutorError("specialist execution authority is invalid")
        (
            executor,
            plan,
            observation,
            network,
            sql_policy,
            object_policy,
            run_id,
        ) = authority._consume(self)
        self._require_current()
        _require_executor_current(executor)
        issues: list[AssessmentIssue] = []
        sql = None
        if executor.profile.diagnostic_steps == ("dom-xss",):
            if observation is None or observation.dom_xss_trials is None:
                raise WebSpecialistExecutorError("XSS specialist browser Evidence is absent")
            issues.append(_DOM_XSS_ISSUE(observation.dom_xss_trials))
        else:
            if sql_policy is None:
                raise WebSpecialistExecutorError("SQL specialist policy is absent")
            sql = await _DIAGNOSE_SQL_LOGIN(
                network=network,
                plan=plan,
                policy=sql_policy,
            )
            issues.append(sql.issue)
            if executor.profile.diagnostic_steps == ("sql-login", "object-access"):
                if observation is None or object_policy is None:
                    raise WebSpecialistExecutorError(
                        "authorization specialist bootstrap or policy is absent"
                    )
                if (
                    sql.issue.status != "locally-reproduced"
                    or sql.token is None
                    or sql.object_id is None
                ):
                    raise WebSpecialistDependencyError(
                        "authorization specialist SQL session dependency was not reproduced"
                    )
                if sql.object_id == observation.object_id:
                    raise WebSpecialistDependencyError(
                        "authorization specialist requires distinct account objects"
                    )
                issues.append(
                    await _DIAGNOSE_OBJECT_ACCESS(
                        network=network,
                        plan=plan,
                        policy=object_policy,
                        attack_token=sql.token,
                        attack_object_id=sql.object_id,
                        target_object_id=observation.object_id,
                    )
                )
        canonical_issues = tuple(_canonical_issue(issue) for issue in issues)
        if tuple(issue.check for issue in canonical_issues) != executor.profile.diagnostic_steps:
            raise WebSpecialistExecutorError("specialist issue order differs from the profile")
        promotable = tuple(
            issue
            for issue in canonical_issues
            if issue.check in executor.profile.promotable_steps
            and issue.status == "locally-reproduced"
        )
        if any(issue.check not in executor.profile.promotable_steps for issue in promotable):
            raise WebSpecialistExecutorError(
                "specialist promotable issue subset differs from the profile"
            )
        observed_steps = _require_trace_closure(
            network.evidence,
            steps=_typed_steps(executor.profile.diagnostic_steps),
        )
        if observed_steps != executor.profile.diagnostic_steps:
            raise WebSpecialistExecutorError("specialist request trace is incomplete")
        return SpecialistDiagnosticExecution(
            descriptor=_descriptor(
                executor,
                catalog_digest=self.__catalog_digest,
                profile_registry_digest=self.__profile_registry_digest,
            ),
            run_id=run_id,
            object_id=observation.object_id if observation is not None else None,
            issues=canonical_issues,
            promotable_issues=promotable,
            observed_diagnostic_steps=observed_steps,
        )

    def _resolve_profile(
        self,
        profile: ResolvedSpecialistExecutionProfile,
    ) -> _CodeOwnedSpecialistExecutor:
        self._require_current()
        if type(profile) is not ResolvedSpecialistExecutionProfile:
            raise WebSpecialistExecutorError("specialist profile handle is not canonical")
        try:
            reference = profile.reference()
            snapshot = profile.snapshot()
        except (AttributeError, TypeError, ValueError) as exc:
            raise WebSpecialistExecutorError("specialist profile failed strict resolution") from exc
        if profile.registry_digest != self.__profile_registry_digest:
            raise WebSpecialistExecutorError("specialist profile registry differs")
        key = (reference.profile_id, reference.profile_version, reference.profile_digest)
        try:
            executor = self.__entries[key]
        except KeyError as exc:
            raise WebSpecialistExecutorError(
                "specialist profile executor is not installed"
            ) from exc
        if snapshot != executor.profile or reference != executor.profile.reference():
            raise WebSpecialistExecutorError("specialist profile differs from its executor")
        return executor

    def _canonical_plan(
        self,
        executor: _CodeOwnedSpecialistExecutor,
        plan: WebAssessmentPlan,
    ) -> WebAssessmentPlan:
        if type(plan) is not WebAssessmentPlan:
            raise WebSpecialistExecutorError("specialist plan type is not canonical")
        try:
            canonical = WebAssessmentPlan.model_validate(
                plan.model_dump(mode="json", by_alias=True)
            )
            adapter_catalog = production_adapter_implementation_catalog()
            resolved = adapter_catalog.resolve(
                implementation_id=executor.profile.adapter_implementation_id,
                implementation_digest=executor.profile.adapter_implementation_digest,
                origin=canonical.origin,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise WebSpecialistExecutorError(
                "specialist plan cannot be resolved by the code-owned adapter"
            ) from exc
        if (
            canonical != plan
            or resolved.plan != canonical
            or resolved.catalog_digest != executor.profile.adapter_catalog_digest
        ):
            raise WebSpecialistExecutorError("specialist plan or adapter identity differs")
        return canonical

    @staticmethod
    def _canonical_policies(
        executor: _CodeOwnedSpecialistExecutor,
        policies: SpecialistDiagnosticPolicies,
        plan: WebAssessmentPlan,
    ) -> tuple[EgressPolicy | None, EgressPolicy | None]:
        if type(policies) is not SpecialistDiagnosticPolicies:
            raise WebSpecialistExecutorError("specialist policies are not canonical")
        steps = executor.profile.diagnostic_steps
        sql_required = "sql-login" in steps
        object_required = "object-access" in steps
        if sql_required != (policies.sql_login is not None) or object_required != (
            policies.object_access is not None
        ):
            raise WebSpecialistExecutorError("specialist policies differ from the selected closure")
        try:
            sql_policy = (
                _canonical_specialist_policy(
                    policies.sql_login,
                    expected=specialist_sql_login_policy(plan),
                    label="SQL login",
                )
                if policies.sql_login is not None
                else None
            )
            object_policy = (
                _canonical_specialist_policy(
                    policies.object_access,
                    expected=specialist_object_access_policy(plan),
                    label="object access",
                )
                if policies.object_access is not None
                else None
            )
        except (TypeError, ValueError) as exc:
            raise WebSpecialistExecutorError("specialist policy boundary differs") from exc
        return sql_policy, object_policy

    def _require_runtime_factories(
        self,
        *,
        executor: _CodeOwnedSpecialistExecutor,
        browser_factory: object | None,
        network_factory: object,
    ) -> None:
        if executor.browser_required != (browser_factory is not None):
            raise WebSpecialistExecutorError(
                "specialist browser runtime differs from the selected closure"
            )
        if self.__runtime_profile == _RUNTIME_PROFILE_PRODUCTION:
            if (
                (
                    executor.browser_required
                    and browser_factory is not PlaywrightSpecialistAssessmentBrowser
                )
                or (not executor.browser_required and browser_factory is not None)
                or network_factory is not AssessmentNetwork
            ):
                raise WebSpecialistExecutorError(
                    "production specialist requires code-owned browser and network runtimes"
                )
        elif self.__runtime_profile != _RUNTIME_PROFILE_TESTING:
            raise WebSpecialistExecutorError("specialist runtime profile changed")

    def _require_current(self) -> None:
        if type(self) is not WebSpecialistExecutorCatalog:
            raise WebSpecialistExecutorError("specialist executor catalog type changed")
        if (
            not _is_mapping_proxy(self.__entries)
            or type(self.__executors) is not tuple
            or len(self.__entries) != len(self.__executors)
        ):
            raise WebSpecialistExecutorError("specialist executor catalog identity changed")
        expected_entries = {
            (
                item.profile.profile_id,
                item.profile.profile_version,
                item.profile.profile_digest,
            ): item
            for item in self.__executors
        }
        if any(self.__entries.get(key) is not item for key, item in expected_entries.items()):
            raise WebSpecialistExecutorError("specialist executor catalog entries changed")
        expected_digest = _catalog_digest(
            self.__executors,
            profile_registry_digest=self.__profile_registry_digest,
            runtime_profile=self.__runtime_profile,
        )
        if expected_digest != self.__catalog_digest:
            raise WebSpecialistExecutorError("specialist executor catalog digest changed")
        for executor in self.__executors:
            _require_executor_current(executor)


def _require_executor_current(executor: _CodeOwnedSpecialistExecutor) -> None:
    if type(executor) is not _CodeOwnedSpecialistExecutor:
        raise WebSpecialistExecutorError("specialist executor implementation changed")
    expected_digest = capability_definition_digest(
        _EXECUTOR_DIGEST_DOMAIN,
        _executor_material(
            executor.profile,
            executor_id=executor.executor_id,
            browser_required=executor.browser_required,
        ),
    )
    if (
        diagnostics.diagnose_sql_login is not _DIAGNOSE_SQL_LOGIN
        or diagnostics.diagnose_object_access is not _DIAGNOSE_OBJECT_ACCESS
        or diagnostics.dom_xss_issue is not _DOM_XSS_ISSUE
        or specialist_sql_login_policy is not _SPECIALIST_SQL_LOGIN_POLICY
        or specialist_object_access_policy is not _SPECIALIST_OBJECT_ACCESS_POLICY
        or PlaywrightSpecialistAssessmentBrowser.run_specialist is not (_SPECIALIST_BROWSER_RUN)
        or executor.profile.diagnostic_steps
        not in {
            ("dom-xss",),
            ("sql-login",),
            ("sql-login", "object-access"),
        }
        or executor.executor_version != _EXECUTOR_VERSION
        or executor.executor_digest != expected_digest
    ):
        raise WebSpecialistExecutorError("specialist executor implementation changed")


def production_web_specialist_executor_catalog() -> WebSpecialistExecutorCatalog:
    return WebSpecialistExecutorCatalog(
        _runtime_profile=_RUNTIME_PROFILE_PRODUCTION,
        _factory_token=_CATALOG_FACTORY_TOKEN,
    )


def _testing_web_specialist_executor_catalog() -> WebSpecialistExecutorCatalog:
    return WebSpecialistExecutorCatalog(
        _runtime_profile=_RUNTIME_PROFILE_TESTING,
        _factory_token=_CATALOG_FACTORY_TOKEN,
    )


__all__ = [
    "SpecialistDiagnosticExecution",
    "SpecialistDiagnosticPolicies",
    "SpecialistExecutorDescriptor",
    "WebSpecialistDependencyError",
    "WebSpecialistExecutorCatalog",
    "WebSpecialistExecutorError",
    "production_web_specialist_executor_catalog",
    "specialist_object_access_policy",
    "specialist_sql_login_policy",
]
