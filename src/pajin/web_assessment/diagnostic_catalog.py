"""Closed code-owned diagnostic bundles for governed Web assessments.

The catalog binds one exact installed adapter implementation to one fixed
diagnostic order and attack-path shape. The trusted runner binds runtime
evidence and policy; callers cannot provide Python callables, payloads, success
narratives, or graph/Finding authority.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass, field
from hashlib import sha256
from types import MappingProxyType
from typing import Final, Literal

import httpx

from pajin.capabilities.models import capability_definition_digest
from pajin.runtime.safe_files import read_bounded_regular_bytes
from pajin.runtime.store import RunStore, validate_run_artifact_path
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment import adapter_catalog, diagnostics
from pajin.web_assessment.adapter_catalog import AdapterImplementationCatalog
from pajin.web_assessment.browser import (
    BrowserAssessmentObservation,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.models import (
    AssessmentIssue,
    AttackPath,
    BrowserSessionSummary,
    IssueCheck,
    ProbeTrial,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork

_BUNDLE_DIGEST_DOMAIN: Final = "pajin.web-assessment.diagnostic-bundle/v1"
_CATALOG_DIGEST_DOMAIN: Final = "pajin.web-assessment.diagnostic-catalog/v1"
_SHA256_CHARACTERS: Final = frozenset("0123456789abcdef")
_CATALOG_FACTORY_TOKEN: Final = object()

JUICE_SHOP_DIAGNOSTIC_BUNDLE_ID: Final = "pajin.web-diagnostics.juice-shop.v1"
_LOCAL_FIXTURE_DIAGNOSTIC_BUNDLE_ID: Final = "pajin.web-diagnostics.local-fixture.v1"
_EXECUTOR_ID: Final = "pajin.web-diagnostics.sql-object-dom.v1"
_PATH_BUILDER_ID: Final = "pajin.web-diagnostics.fixed-two-paths.v1"
_EXECUTOR_IMPLEMENTATION_VERSION: Final = "1.0.0"
_PATH_BUILDER_IMPLEMENTATION_VERSION: Final = "1.0.0"
_DIAGNOSTIC_ORDER: Final[tuple[IssueCheck, ...]] = (
    "sql-login",
    "object-access",
    "dom-xss",
)
_ATTACK_PATH_ISSUE_SEQUENCES: Final[tuple[tuple[IssueCheck, ...], ...]] = (
    ("sql-login", "object-access"),
    ("dom-xss",),
)
_RUNTIME_PROFILE_PRODUCTION: Final = "production-default-httpx"
_RUNTIME_PROFILE_TESTING: Final = "testing-injected-transport"
_RUNTIME_AUTHORITY_FACTORY_TOKEN: Final = object()

_DIAGNOSE_SQL_LOGIN: Final = diagnostics.diagnose_sql_login
_DIAGNOSE_OBJECT_ACCESS: Final = diagnostics.diagnose_object_access
_DOM_XSS_ISSUE: Final = diagnostics.dom_xss_issue
_BUILD_ATTACK_PATHS: Final = diagnostics.build_attack_paths
_PLAYWRIGHT_BROWSER_RUN: Final = PlaywrightAssessmentBrowser.run


def _executor_implementation_material() -> dict[str, object]:
    return {
        "implementationId": _EXECUTOR_ID,
        "implementationVersion": _EXECUTOR_IMPLEMENTATION_VERSION,
        "orderedComponents": [
            "pajin.web_assessment.diagnostics.diagnose_sql_login",
            "pajin.web_assessment.diagnostics.diagnose_object_access",
            "pajin.web_assessment.diagnostics.dom_xss_issue",
        ],
        "browserEvidenceRole": "validate-preexecuted-dom-control-and-probe",
        "callerExecutableInput": False,
    }


def _path_builder_implementation_material() -> dict[str, object]:
    return {
        "implementationId": _PATH_BUILDER_ID,
        "implementationVersion": _PATH_BUILDER_IMPLEMENTATION_VERSION,
        "component": "pajin.web_assessment.diagnostics.build_attack_paths",
        "orderedIssueSequences": [list(sequence) for sequence in _ATTACK_PATH_ISSUE_SEQUENCES],
        "findingAuthority": False,
        "graphAuthority": False,
    }


EXECUTOR_IMPLEMENTATION_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.diagnostic-executor-implementation/v1",
    _executor_implementation_material(),
)
PATH_BUILDER_IMPLEMENTATION_DIGEST: Final = capability_definition_digest(
    "pajin.web-assessment.attack-path-builder-implementation/v1",
    _path_builder_implementation_material(),
)


class DiagnosticBundleCatalogError(ValueError):
    """Raised when diagnostic authority or execution lineage cannot be proven."""


@dataclass(frozen=True, slots=True)
class DiagnosticBundleDescriptor:
    """Non-executable description of one exact code-owned diagnostic bundle."""

    catalog_digest: str
    bundle_id: str
    bundle_digest: str
    adapter_implementation_id: str
    adapter_implementation_digest: str
    executor_id: str
    executor_implementation_digest: str
    path_builder_id: str
    path_builder_implementation_digest: str
    diagnostic_order: tuple[IssueCheck, ...]
    attack_path_issue_sequences: tuple[tuple[IssueCheck, ...], ...]
    finding_authority: Literal[False] = field(default=False, init=False)
    graph_authority: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class DiagnosticExecutionPolicies:
    """Policies supplied by the trusted coordinator, never by a bundle manifest."""

    sql_login: EgressPolicy
    object_access: EgressPolicy


@dataclass(frozen=True, slots=True)
class DiagnosticBundleExecution:
    """Evidence-derived local issues and paths without promotion authority."""

    descriptor: DiagnosticBundleDescriptor
    run_id: str
    issues: tuple[AssessmentIssue, ...]
    attack_paths: tuple[AttackPath, ...]
    finding_authority: Literal[False] = field(default=False, init=False)
    graph_authority: Literal[False] = field(default=False, init=False)


@dataclass(frozen=True, slots=True)
class _CodeOwnedDiagnosticBundle:
    bundle_id: str
    adapter_implementation_id: str
    adapter_implementation_digest: str
    executor_id: Literal["pajin.web-diagnostics.sql-object-dom.v1"]
    executor_implementation_digest: str
    path_builder_id: Literal["pajin.web-diagnostics.fixed-two-paths.v1"]
    path_builder_implementation_digest: str
    diagnostic_order: tuple[IssueCheck, ...]
    attack_path_issue_sequences: tuple[tuple[IssueCheck, ...], ...]

    @property
    def bundle_digest(self) -> str:
        return _bundle_digest(self)


def _bundle_material(bundle: _CodeOwnedDiagnosticBundle) -> dict[str, object]:
    return {
        "bundleId": bundle.bundle_id,
        "adapterImplementationId": bundle.adapter_implementation_id,
        "adapterImplementationDigest": bundle.adapter_implementation_digest,
        "executorId": bundle.executor_id,
        "executorImplementationDigest": bundle.executor_implementation_digest,
        "pathBuilderId": bundle.path_builder_id,
        "pathBuilderImplementationDigest": bundle.path_builder_implementation_digest,
        "diagnosticOrder": list(bundle.diagnostic_order),
        "attackPathIssueSequences": [
            list(sequence) for sequence in bundle.attack_path_issue_sequences
        ],
        "findingAuthority": False,
        "graphAuthority": False,
    }


def _bundle_digest(bundle: _CodeOwnedDiagnosticBundle) -> str:
    return capability_definition_digest(_BUNDLE_DIGEST_DOMAIN, _bundle_material(bundle))


def _catalog_digest(
    *,
    adapter_catalog_digest: str,
    bundles: tuple[_CodeOwnedDiagnosticBundle, ...],
    runtime_profile: str,
) -> str:
    return capability_definition_digest(
        _CATALOG_DIGEST_DOMAIN,
        {
            "adapterCatalogDigest": adapter_catalog_digest,
            "runtimeProfile": runtime_profile,
            "bundles": [
                {
                    **_bundle_material(bundle),
                    "bundleDigest": bundle.bundle_digest,
                }
                for bundle in sorted(
                    bundles,
                    key=lambda item: (
                        item.adapter_implementation_id,
                        item.adapter_implementation_digest,
                    ),
                )
            ],
        },
    )


_JUICE_SHOP_BUNDLE: Final = _CodeOwnedDiagnosticBundle(
    bundle_id=JUICE_SHOP_DIAGNOSTIC_BUNDLE_ID,
    adapter_implementation_id=adapter_catalog.JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    adapter_implementation_digest=(adapter_catalog.JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
    executor_id=_EXECUTOR_ID,
    executor_implementation_digest=EXECUTOR_IMPLEMENTATION_DIGEST,
    path_builder_id=_PATH_BUILDER_ID,
    path_builder_implementation_digest=PATH_BUILDER_IMPLEMENTATION_DIGEST,
    diagnostic_order=_DIAGNOSTIC_ORDER,
    attack_path_issue_sequences=_ATTACK_PATH_ISSUE_SEQUENCES,
)
_LOCAL_FIXTURE_BUNDLE: Final = _CodeOwnedDiagnosticBundle(
    bundle_id=_LOCAL_FIXTURE_DIAGNOSTIC_BUNDLE_ID,
    adapter_implementation_id=(adapter_catalog._LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID),
    adapter_implementation_digest=(adapter_catalog._LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST),
    executor_id=_EXECUTOR_ID,
    executor_implementation_digest=EXECUTOR_IMPLEMENTATION_DIGEST,
    path_builder_id=_PATH_BUILDER_ID,
    path_builder_implementation_digest=PATH_BUILDER_IMPLEMENTATION_DIGEST,
    diagnostic_order=_DIAGNOSTIC_ORDER,
    attack_path_issue_sequences=_ATTACK_PATH_ISSUE_SEQUENCES,
)
_PRODUCTION_CODE_OWNED_BUNDLES: Final = MappingProxyType(
    {_JUICE_SHOP_BUNDLE.bundle_id: _JUICE_SHOP_BUNDLE}
)
_TESTING_CODE_OWNED_BUNDLES: Final = MappingProxyType(
    {
        _JUICE_SHOP_BUNDLE.bundle_id: _JUICE_SHOP_BUNDLE,
        _LOCAL_FIXTURE_BUNDLE.bundle_id: _LOCAL_FIXTURE_BUNDLE,
    }
)


def _descriptor(
    bundle: _CodeOwnedDiagnosticBundle,
    *,
    catalog_digest: str,
) -> DiagnosticBundleDescriptor:
    return DiagnosticBundleDescriptor(
        catalog_digest=catalog_digest,
        bundle_id=bundle.bundle_id,
        bundle_digest=bundle.bundle_digest,
        adapter_implementation_id=bundle.adapter_implementation_id,
        adapter_implementation_digest=bundle.adapter_implementation_digest,
        executor_id=bundle.executor_id,
        executor_implementation_digest=bundle.executor_implementation_digest,
        path_builder_id=bundle.path_builder_id,
        path_builder_implementation_digest=bundle.path_builder_implementation_digest,
        diagnostic_order=bundle.diagnostic_order,
        attack_path_issue_sequences=bundle.attack_path_issue_sequences,
    )


def _valid_identifier(value: object) -> bool:
    return type(value) is str and bool(value) and value == value.strip() and len(value) <= 200


def _valid_digest(value: object) -> bool:
    return (
        type(value) is str
        and len(value) == 64
        and all(character in _SHA256_CHARACTERS for character in value)
    )


def _canonical_policy(
    policy: EgressPolicy,
    *,
    plan: WebAssessmentPlan,
    label: str,
) -> EgressPolicy:
    if type(policy) is not EgressPolicy:
        raise DiagnosticBundleCatalogError(f"{label} policy is not canonical")
    try:
        canonical = EgressPolicy.model_validate(policy.model_dump(mode="json"))
    except (TypeError, ValueError) as exc:
        raise DiagnosticBundleCatalogError(f"{label} policy is invalid") from exc
    expected_deny = [plan.origin + path + "*" for path in plan.deny_paths]
    if (
        canonical != policy
        or canonical.allow != [plan.origin + "/*"]
        or canonical.deny != expected_deny
        or canonical.allowed_methods != {"GET", "HEAD", "POST"}
        or not canonical.allow_private_networks
        or canonical.max_response_bytes != plan.max_response_bytes
        or canonical.max_request_bytes != 64_000
        or canonical.max_requests != 20
    ):
        raise DiagnosticBundleCatalogError(
            f"{label} policy exceeds or cannot execute the exact plan boundary"
        )
    return canonical


def _canonical_observation(
    observation: BrowserAssessmentObservation,
    *,
    plan: WebAssessmentPlan,
) -> BrowserAssessmentObservation:
    if (
        type(observation) is not BrowserAssessmentObservation
        or type(observation.object_id) is not int
        or not 0 < observation.object_id <= 2_147_483_647
        or type(observation.summary) is not BrowserSessionSummary
        or type(observation.dom_xss_trials) is not tuple
        or len(observation.dom_xss_trials) != 2
        or any(type(trial) is not ProbeTrial for trial in observation.dom_xss_trials)
    ):
        raise DiagnosticBundleCatalogError("browser observation is not canonical")
    try:
        summary = BrowserSessionSummary.model_validate(
            observation.summary.model_dump(mode="json", by_alias=True)
        )
        trials = tuple(
            ProbeTrial.model_validate(trial.model_dump(mode="json", by_alias=True))
            for trial in observation.dom_xss_trials
        )
    except (TypeError, ValueError) as exc:
        raise DiagnosticBundleCatalogError("browser observation is invalid") from exc
    if (
        summary != observation.summary
        or trials != observation.dom_xss_trials
        or tuple(trial.check for trial in trials) != ("dom-xss", "dom-xss")
        or tuple(trial.repetition for trial in trials) != ("source", "replay")
    ):
        raise DiagnosticBundleCatalogError("browser observation lineage differs")
    if plan.dom_xss is None:
        raise DiagnosticBundleCatalogError("browser DOM diagnostic recipe is unavailable")
    pages_by_id = {page.evidence_id: page for page in summary.pages}
    if len(pages_by_id) != len(summary.pages):
        raise DiagnosticBundleCatalogError("browser page Evidence identity is duplicated")
    expected_probe_phases = ("dom-xss-source", "dom-xss-replay")
    redacted_route_prefix = plan.dom_xss.route_template.partition("{payload}")[0]
    expected_fact_keys = {
        "controlMarkerExecuted",
        "probeMarkerExecuted",
        "externalTransmission",
    }
    used_evidence_ids: list[str] = []
    for trial, probe_phase in zip(trials, expected_probe_phases, strict=True):
        if len(trial.evidence_ids) != 2:
            raise DiagnosticBundleCatalogError(
                "browser DOM trial requires one control and one probe Evidence"
            )
        try:
            control = pages_by_id[trial.evidence_ids[0]]
            probe = pages_by_id[trial.evidence_ids[1]]
        except KeyError as exc:
            raise DiagnosticBundleCatalogError(
                "browser DOM trial references unknown page Evidence"
            ) from exc
        if (
            control.phase != "dom-xss-control"
            or probe.phase != probe_phase
            or control.route != redacted_route_prefix + "<control-redacted>"
            or probe.route != redacted_route_prefix + "<probe-redacted>"
            or control.ready_selector != plan.dom_xss.ready_selector
            or probe.ready_selector != plan.dom_xss.ready_selector
            or type(control.marker_executed) is not bool
            or type(probe.marker_executed) is not bool
            or trial.controls_passed is not (control.marker_executed is False)
            or trial.reproduced is not probe.marker_executed
            or trial.facts.get("controlMarkerExecuted") is not control.marker_executed
            or trial.facts.get("probeMarkerExecuted") is not probe.marker_executed
            or trial.facts.get("externalTransmission") is not False
            or set(trial.facts) != expected_fact_keys
        ):
            raise DiagnosticBundleCatalogError(
                "browser DOM trial differs from its control/probe Evidence"
            )
        used_evidence_ids.extend(trial.evidence_ids)
    if len(used_evidence_ids) != len(set(used_evidence_ids)):
        raise DiagnosticBundleCatalogError("browser DOM trial Evidence is reused")
    return BrowserAssessmentObservation(
        object_id=observation.object_id,
        summary=summary,
        dom_xss_trials=(trials[0], trials[1]),
    )


def _canonical_execution_output(
    *,
    bundle: _CodeOwnedDiagnosticBundle,
    issues: tuple[AssessmentIssue, ...],
    attack_paths: tuple[AttackPath, ...],
) -> tuple[tuple[AssessmentIssue, ...], tuple[AttackPath, ...]]:
    try:
        canonical_issues = tuple(
            AssessmentIssue.model_validate(issue.model_dump(mode="json", by_alias=True))
            for issue in issues
        )
        canonical_paths = tuple(
            AttackPath.model_validate(path.model_dump(mode="json", by_alias=True))
            for path in attack_paths
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise DiagnosticBundleCatalogError("diagnostic output is invalid") from exc
    if (
        canonical_issues != issues
        or canonical_paths != attack_paths
        or tuple(issue.check for issue in canonical_issues) != bundle.diagnostic_order
    ):
        raise DiagnosticBundleCatalogError("diagnostic output order or identity differs")
    issues_by_id = {issue.issue_id: issue for issue in canonical_issues}
    path_sequences: list[tuple[IssueCheck, ...]] = []
    for path in canonical_paths:
        sequence: list[IssueCheck] = []
        for stage in path.stages:
            if stage.issue_id is not None:
                try:
                    sequence.append(issues_by_id[stage.issue_id].check)
                except KeyError as exc:
                    raise DiagnosticBundleCatalogError(
                        "diagnostic path references an unknown issue"
                    ) from exc
        path_sequences.append(tuple(sequence))
    if tuple(path_sequences) != bundle.attack_path_issue_sequences:
        raise DiagnosticBundleCatalogError("diagnostic attack-path shape differs")
    return canonical_issues, canonical_paths


def _require_browser_run_evidence(
    *,
    store: RunStore,
    observation: BrowserAssessmentObservation,
) -> None:
    references: set[str] = set()
    for page in observation.summary.pages:
        try:
            reference = validate_run_artifact_path(page.screenshot_reference)
        except ValueError as exc:
            raise DiagnosticBundleCatalogError(
                "browser screenshot reference is not a Run artifact path"
            ) from exc
        if reference in references:
            raise DiagnosticBundleCatalogError("browser screenshot reference is duplicated")
        references.add(reference)
        try:
            content = read_bounded_regular_bytes(
                store.path / reference,
                max_bytes=10_000_000,
                label="browser screenshot Evidence",
                require_single_link=True,
            )
        except (OSError, ValueError) as exc:
            raise DiagnosticBundleCatalogError(
                "browser screenshot Evidence is absent from the current Run"
            ) from exc
        if len(content) != page.screenshot_bytes or sha256(content).hexdigest() != (
            page.screenshot_sha256
        ):
            raise DiagnosticBundleCatalogError(
                "browser screenshot Evidence differs from the current Run"
            )


def _require_executor_current(bundle: _CodeOwnedDiagnosticBundle) -> None:
    if (
        diagnostics.diagnose_sql_login is not _DIAGNOSE_SQL_LOGIN
        or diagnostics.diagnose_object_access is not _DIAGNOSE_OBJECT_ACCESS
        or diagnostics.dom_xss_issue is not _DOM_XSS_ISSUE
        or diagnostics.build_attack_paths is not _BUILD_ATTACK_PATHS
        or PlaywrightAssessmentBrowser.run is not _PLAYWRIGHT_BROWSER_RUN
        or bundle.executor_id != _EXECUTOR_ID
        or bundle.executor_implementation_digest != EXECUTOR_IMPLEMENTATION_DIGEST
        or bundle.path_builder_id != _PATH_BUILDER_ID
        or bundle.path_builder_implementation_digest != PATH_BUILDER_IMPLEMENTATION_DIGEST
        or capability_definition_digest(
            "pajin.web-assessment.diagnostic-executor-implementation/v1",
            _executor_implementation_material(),
        )
        != EXECUTOR_IMPLEMENTATION_DIGEST
        or capability_definition_digest(
            "pajin.web-assessment.attack-path-builder-implementation/v1",
            _path_builder_implementation_material(),
        )
        != PATH_BUILDER_IMPLEMENTATION_DIGEST
    ):
        raise DiagnosticBundleCatalogError("diagnostic executable identity changed")


class _RunnerDiagnosticExecutionAuthority:
    """One-shot runtime lineage minted only by the catalog's runner binding."""

    __slots__ = (
        "__bundle",
        "__catalog",
        "__factory_token",
        "__network",
        "__object_policy",
        "__observation",
        "__plan",
        "__run_id",
        "__sql_policy",
        "__task",
        "__terminal",
    )

    def __init__(
        self,
        *,
        catalog: DiagnosticBundleCatalog,
        bundle: _CodeOwnedDiagnosticBundle,
        plan: WebAssessmentPlan,
        observation: BrowserAssessmentObservation,
        network: AssessmentNetwork,
        sql_policy: EgressPolicy,
        object_policy: EgressPolicy,
        run_id: str,
        task: asyncio.Task[object],
        _factory_token: object,
    ) -> None:
        if _factory_token is not _RUNTIME_AUTHORITY_FACTORY_TOKEN:
            raise TypeError("diagnostic runtime authority requires runner binding")
        self.__catalog = catalog
        self.__bundle = bundle
        self.__plan = plan
        self.__observation = observation
        self.__network = network
        self.__sql_policy = sql_policy
        self.__object_policy = object_policy
        self.__run_id = run_id
        self.__task = task
        self.__factory_token = _factory_token
        self.__terminal = False

    def _consume(
        self,
        catalog: DiagnosticBundleCatalog,
    ) -> tuple[
        _CodeOwnedDiagnosticBundle,
        WebAssessmentPlan,
        BrowserAssessmentObservation,
        AssessmentNetwork,
        EgressPolicy,
        EgressPolicy,
        str,
    ]:
        task = asyncio.current_task()
        if (
            type(self) is not _RunnerDiagnosticExecutionAuthority
            or self.__factory_token is not _RUNTIME_AUTHORITY_FACTORY_TOKEN
            or self.__catalog is not catalog
            or task is None
            or task is not self.__task
            or self.__terminal
        ):
            raise DiagnosticBundleCatalogError(
                "diagnostic runtime authority is absent, foreign, or consumed"
            )
        self.__terminal = True
        return (
            self.__bundle,
            self.__plan,
            self.__observation,
            self.__network,
            self.__sql_policy,
            self.__object_policy,
            self.__run_id,
        )


class DiagnosticBundleCatalog:
    """Immutable catalog and the sole dispatcher for installed diagnostics."""

    __slots__ = (
        "__adapter_catalog",
        "__adapter_catalog_digest",
        "__bundles",
        "__catalog_digest",
        "__entries",
        "__runtime_profile",
    )
    __adapter_catalog: AdapterImplementationCatalog
    __adapter_catalog_digest: str
    __bundles: tuple[_CodeOwnedDiagnosticBundle, ...]
    __catalog_digest: str
    __entries: Mapping[tuple[str, str], _CodeOwnedDiagnosticBundle]
    __runtime_profile: Literal[
        "production-default-httpx",
        "testing-injected-transport",
    ]

    def __init__(
        self,
        *,
        _bundles: tuple[_CodeOwnedDiagnosticBundle, ...],
        _adapter_catalog: AdapterImplementationCatalog,
        _runtime_profile: Literal[
            "production-default-httpx",
            "testing-injected-transport",
        ],
        _factory_token: object | None = None,
    ) -> None:
        if type(self) is not DiagnosticBundleCatalog or _factory_token is not (
            _CATALOG_FACTORY_TOKEN
        ):
            raise TypeError("diagnostic catalog requires its code-owned factory")
        if type(_adapter_catalog) is not AdapterImplementationCatalog:
            raise DiagnosticBundleCatalogError("adapter catalog is not code-owned")
        if not _bundles:
            raise DiagnosticBundleCatalogError("diagnostic catalog is empty")
        if _runtime_profile not in {
            _RUNTIME_PROFILE_PRODUCTION,
            _RUNTIME_PROFILE_TESTING,
        }:
            raise DiagnosticBundleCatalogError("diagnostic runtime profile is not code-owned")
        adapter_catalog_digest = _adapter_catalog.catalog_digest
        adapter_references = set(_adapter_catalog.references())
        bundle_registry = (
            _PRODUCTION_CODE_OWNED_BUNDLES
            if _runtime_profile == _RUNTIME_PROFILE_PRODUCTION
            else _TESTING_CODE_OWNED_BUNDLES
        )
        entries: dict[tuple[str, str], _CodeOwnedDiagnosticBundle] = {}
        bundle_ids: set[str] = set()
        bundle_digests: set[str] = set()
        for bundle in _bundles:
            if (
                type(bundle) is not _CodeOwnedDiagnosticBundle
                or bundle_registry.get(bundle.bundle_id) is not bundle
            ):
                raise DiagnosticBundleCatalogError("diagnostic bundle descriptor is not code-owned")
            key = (
                bundle.adapter_implementation_id,
                bundle.adapter_implementation_digest,
            )
            if key not in adapter_references:
                raise DiagnosticBundleCatalogError("diagnostic bundle adapter is not installed")
            if (
                key in entries
                or bundle.bundle_id in bundle_ids
                or bundle.bundle_digest in bundle_digests
            ):
                raise DiagnosticBundleCatalogError(
                    "diagnostic catalog contains a duplicate identity"
                )
            entries[key] = bundle
            bundle_ids.add(bundle.bundle_id)
            bundle_digests.add(bundle.bundle_digest)
        bundles = tuple(entries[key] for key in sorted(entries))
        catalog_digest = _catalog_digest(
            adapter_catalog_digest=adapter_catalog_digest,
            bundles=bundles,
            runtime_profile=_runtime_profile,
        )
        object.__setattr__(self, "_DiagnosticBundleCatalog__adapter_catalog", _adapter_catalog)
        object.__setattr__(
            self,
            "_DiagnosticBundleCatalog__adapter_catalog_digest",
            adapter_catalog_digest,
        )
        object.__setattr__(self, "_DiagnosticBundleCatalog__bundles", bundles)
        object.__setattr__(
            self,
            "_DiagnosticBundleCatalog__runtime_profile",
            _runtime_profile,
        )
        object.__setattr__(
            self,
            "_DiagnosticBundleCatalog__entries",
            MappingProxyType(entries),
        )
        object.__setattr__(
            self,
            "_DiagnosticBundleCatalog__catalog_digest",
            catalog_digest,
        )

    @property
    def catalog_digest(self) -> str:
        self._require_current()
        return self.__catalog_digest

    def references(self) -> tuple[tuple[str, str], ...]:
        """Return exact installed adapter keys without executable material."""

        self._require_current()
        return tuple(sorted(self.__entries))

    def resolve(
        self,
        *,
        adapter_implementation_id: str,
        adapter_implementation_digest: str,
    ) -> DiagnosticBundleDescriptor:
        """Resolve one exact adapter key without fallback or caller-defined code."""

        self._require_current()
        if not _valid_identifier(adapter_implementation_id) or not _valid_digest(
            adapter_implementation_digest
        ):
            raise DiagnosticBundleCatalogError("diagnostic adapter reference is invalid")
        try:
            bundle = self.__entries[(adapter_implementation_id, adapter_implementation_digest)]
        except KeyError as exc:
            raise DiagnosticBundleCatalogError(
                "diagnostic bundle is not installed for the exact adapter"
            ) from exc
        return _descriptor(bundle, catalog_digest=self.__catalog_digest)

    def require_code_owned_plan(
        self,
        *,
        descriptor: DiagnosticBundleDescriptor,
        plan: WebAssessmentPlan,
    ) -> WebAssessmentPlan:
        """Rebuild and compare the selected plan before any target request."""

        bundle = self._require_descriptor(descriptor)
        return self._require_code_owned_plan(bundle=bundle, plan=plan)

    def _require_runner_runtime_factories(
        self,
        *,
        browser_factory: object,
        network_factory: object,
    ) -> None:
        """Reject non-production factories before the runner performs any I/O."""

        self._require_current()
        if self.__runtime_profile == _RUNTIME_PROFILE_PRODUCTION:
            if (
                browser_factory is not PlaywrightAssessmentBrowser
                or network_factory is not AssessmentNetwork
            ):
                raise DiagnosticBundleCatalogError(
                    "production diagnostics require the code-owned browser and network runtime"
                )
        elif self.__runtime_profile != _RUNTIME_PROFILE_TESTING:
            raise DiagnosticBundleCatalogError("diagnostic runtime profile changed")

    def _bind_runner_execution(
        self,
        *,
        descriptor: DiagnosticBundleDescriptor,
        plan: WebAssessmentPlan,
        observation: BrowserAssessmentObservation,
        network: AssessmentNetwork,
        policies: DiagnosticExecutionPolicies,
        store: RunStore,
        browser_factory: object,
        network_factory: object,
    ) -> _RunnerDiagnosticExecutionAuthority:
        """Bind trusted runner-owned runtime state before diagnostic execution."""

        bundle = self._require_descriptor(descriptor)
        canonical_plan = self._require_code_owned_plan(bundle=bundle, plan=plan)
        canonical_observation = _canonical_observation(
            observation,
            plan=canonical_plan,
        )
        if type(network) is not AssessmentNetwork or network.plan != canonical_plan:
            raise DiagnosticBundleCatalogError(
                "diagnostic network differs from the exact code-owned plan"
            )
        if type(policies) is not DiagnosticExecutionPolicies:
            raise DiagnosticBundleCatalogError("diagnostic policies are not canonical")
        sql_policy = _canonical_policy(
            policies.sql_login,
            plan=canonical_plan,
            label="SQL login",
        )
        object_policy = _canonical_policy(
            policies.object_access,
            plan=canonical_plan,
            label="object access",
        )
        _require_executor_current(bundle)
        if type(store) is not RunStore:
            raise DiagnosticBundleCatalogError("diagnostic Run lineage is not canonical")
        _require_browser_run_evidence(store=store, observation=canonical_observation)
        task = asyncio.current_task()
        if task is None:
            raise DiagnosticBundleCatalogError("diagnostic execution requires an async Run task")
        self._require_runner_runtime_factories(
            browser_factory=browser_factory,
            network_factory=network_factory,
        )
        if self.__runtime_profile == _RUNTIME_PROFILE_PRODUCTION:
            transport = getattr(network.client, "_transport", None)
            if (
                type(network.client) is not httpx.AsyncClient
                or type(transport) is not httpx.AsyncHTTPTransport
            ):
                raise DiagnosticBundleCatalogError(
                    "production diagnostics require the code-owned browser and network runtime"
                )
        return _RunnerDiagnosticExecutionAuthority(
            catalog=self,
            bundle=bundle,
            plan=canonical_plan,
            observation=canonical_observation,
            network=network,
            sql_policy=sql_policy,
            object_policy=object_policy,
            run_id=store.run_id,
            task=task,
            _factory_token=_RUNTIME_AUTHORITY_FACTORY_TOKEN,
        )

    async def execute(
        self,
        *,
        authority: _RunnerDiagnosticExecutionAuthority,
    ) -> DiagnosticBundleExecution:
        """Consume one runner-bound authority and evaluate fixed diagnostics."""

        if type(authority) is not _RunnerDiagnosticExecutionAuthority:
            raise DiagnosticBundleCatalogError("diagnostic runtime authority is invalid")
        (
            bundle,
            canonical_plan,
            canonical_observation,
            network,
            sql_policy,
            object_policy,
            run_id,
        ) = authority._consume(self)
        self._require_current()
        _require_executor_current(bundle)

        sql = await _DIAGNOSE_SQL_LOGIN(
            network=network,
            plan=canonical_plan,
            policy=sql_policy,
        )
        object_issue = await _DIAGNOSE_OBJECT_ACCESS(
            network=network,
            plan=canonical_plan,
            policy=object_policy,
            attack_token=sql.token,
            attack_object_id=sql.object_id,
            target_object_id=canonical_observation.object_id,
        )
        issues = (
            sql.issue,
            object_issue,
            _DOM_XSS_ISSUE(canonical_observation.dom_xss_trials),
        )
        attack_paths = _BUILD_ATTACK_PATHS(issues)
        canonical_issues, canonical_paths = _canonical_execution_output(
            bundle=bundle,
            issues=issues,
            attack_paths=attack_paths,
        )
        return DiagnosticBundleExecution(
            descriptor=_descriptor(bundle, catalog_digest=self.__catalog_digest),
            run_id=run_id,
            issues=canonical_issues,
            attack_paths=canonical_paths,
        )

    def _require_descriptor(
        self,
        descriptor: DiagnosticBundleDescriptor,
    ) -> _CodeOwnedDiagnosticBundle:
        self._require_current()
        if type(descriptor) is not DiagnosticBundleDescriptor:
            raise DiagnosticBundleCatalogError("diagnostic descriptor is not canonical")
        try:
            bundle = self.__entries[
                (
                    descriptor.adapter_implementation_id,
                    descriptor.adapter_implementation_digest,
                )
            ]
        except KeyError as exc:
            raise DiagnosticBundleCatalogError("diagnostic descriptor is not installed") from exc
        if descriptor != _descriptor(bundle, catalog_digest=self.__catalog_digest):
            raise DiagnosticBundleCatalogError("diagnostic descriptor identity changed")
        return bundle

    def _require_code_owned_plan(
        self,
        *,
        bundle: _CodeOwnedDiagnosticBundle,
        plan: WebAssessmentPlan,
    ) -> WebAssessmentPlan:
        if type(plan) is not WebAssessmentPlan:
            raise DiagnosticBundleCatalogError("diagnostic plan is not canonical")
        try:
            canonical = WebAssessmentPlan.model_validate(
                plan.model_dump(mode="json", by_alias=True)
            )
            resolved = self.__adapter_catalog.resolve(
                implementation_id=bundle.adapter_implementation_id,
                implementation_digest=bundle.adapter_implementation_digest,
                origin=canonical.origin,
            )
        except (AttributeError, TypeError, ValueError) as exc:
            raise DiagnosticBundleCatalogError(
                "diagnostic plan cannot be resolved by the code-owned adapter"
            ) from exc
        if canonical != plan or resolved.plan != canonical:
            raise DiagnosticBundleCatalogError("diagnostic plan is not the code-owned adapter plan")
        return canonical

    def _require_current(self) -> None:
        bundles = self.__bundles
        entries = self.__entries
        bundle_registry = (
            _PRODUCTION_CODE_OWNED_BUNDLES
            if self.__runtime_profile == _RUNTIME_PROFILE_PRODUCTION
            else _TESTING_CODE_OWNED_BUNDLES
        )
        try:
            adapter_catalog_digest = self.__adapter_catalog.catalog_digest
        except (AttributeError, TypeError, ValueError) as exc:
            raise DiagnosticBundleCatalogError("diagnostic adapter catalog changed") from exc
        if (
            type(self) is not DiagnosticBundleCatalog
            or type(bundles) is not tuple
            or type(entries) is not MappingProxyType
            or type(_PRODUCTION_CODE_OWNED_BUNDLES) is not MappingProxyType
            or type(_TESTING_CODE_OWNED_BUNDLES) is not MappingProxyType
            or self.__runtime_profile not in {_RUNTIME_PROFILE_PRODUCTION, _RUNTIME_PROFILE_TESTING}
            or adapter_catalog_digest != self.__adapter_catalog_digest
            or len(entries) != len(bundles)
            or any(
                type(bundle) is not _CodeOwnedDiagnosticBundle
                or bundle_registry.get(bundle.bundle_id) is not bundle
                or entries.get(
                    (
                        bundle.adapter_implementation_id,
                        bundle.adapter_implementation_digest,
                    )
                )
                is not bundle
                for bundle in bundles
            )
            or _catalog_digest(
                adapter_catalog_digest=adapter_catalog_digest,
                bundles=bundles,
                runtime_profile=self.__runtime_profile,
            )
            != self.__catalog_digest
        ):
            raise DiagnosticBundleCatalogError("diagnostic catalog identity changed")
        for bundle in bundles:
            _require_executor_current(bundle)


def _new_diagnostic_bundle_catalog(
    *,
    bundles: tuple[_CodeOwnedDiagnosticBundle, ...],
    implementation_catalog: AdapterImplementationCatalog,
    runtime_profile: Literal[
        "production-default-httpx",
        "testing-injected-transport",
    ] = _RUNTIME_PROFILE_TESTING,
) -> DiagnosticBundleCatalog:
    return DiagnosticBundleCatalog(
        _bundles=bundles,
        _adapter_catalog=implementation_catalog,
        _runtime_profile=runtime_profile,
        _factory_token=_CATALOG_FACTORY_TOKEN,
    )


_PRODUCTION_DIAGNOSTIC_BUNDLE_CATALOG: Final = _new_diagnostic_bundle_catalog(
    bundles=(_JUICE_SHOP_BUNDLE,),
    implementation_catalog=adapter_catalog.production_adapter_implementation_catalog(),
    runtime_profile=_RUNTIME_PROFILE_PRODUCTION,
)


def production_diagnostic_bundle_catalog() -> DiagnosticBundleCatalog:
    """Return the closed production catalog; local fixtures are never installed."""

    return _PRODUCTION_DIAGNOSTIC_BUNDLE_CATALOG


def _testing_diagnostic_bundle_catalog() -> DiagnosticBundleCatalog:
    """Return a fresh catalog with the predeclared internal adapter fixture."""

    return _new_diagnostic_bundle_catalog(
        bundles=(_JUICE_SHOP_BUNDLE, _LOCAL_FIXTURE_BUNDLE),
        implementation_catalog=adapter_catalog._testing_adapter_implementation_catalog(),
        runtime_profile=_RUNTIME_PROFILE_TESTING,
    )


__all__ = [
    "EXECUTOR_IMPLEMENTATION_DIGEST",
    "JUICE_SHOP_DIAGNOSTIC_BUNDLE_ID",
    "PATH_BUILDER_IMPLEMENTATION_DIGEST",
    "DiagnosticBundleCatalog",
    "DiagnosticBundleCatalogError",
    "DiagnosticBundleDescriptor",
    "DiagnosticBundleExecution",
    "DiagnosticExecutionPolicies",
    "production_diagnostic_bundle_catalog",
]
