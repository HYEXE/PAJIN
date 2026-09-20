"""Sealed, discovery-only authenticated browser Run artifacts.

This slice performs only normal login and passive structural discovery.  Its output is an inert
proposal aggregate: it carries no diagnostic, ToolRequest, ActionPermit, Finding, Graph, or
external-delivery authority, and persists no credentials, DOM, screenshot, or response body.
"""

from __future__ import annotations

import re
from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, Literal, Self

from pydantic import ConfigDict, Field, ValidationError, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.runtime.store import (
    RunIntegrityError,
    RunIntegrityVerification,
    RunStore,
    SealedArtifact,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
    verify_run_integrity,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    browser_discovery_request_path_rejection,
)
from pajin.web_assessment.discovery_evidence import (
    AuthenticatedDiscoveryEvidence,
    authenticated_discovery_evidence,
)
from pajin.web_assessment.discovery_runtime import (
    GovernedAuthenticatedDiscoveryObservation,
    run_governed_authenticated_browser_discovery_with_evidence,
)
from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    WebAssessmentPlan,
    request_evidence_sequence,
)
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    LocalWebAssessmentError,
    ProvisionedLocalWebAssessmentAccount,
    assessment_policy,
)

AUTHENTICATED_DISCOVERY_RUN_INDEX_API_VERSION: Final[
    Literal["pajin.dev/authenticated-discovery-run-index/v1alpha1"]
] = "pajin.dev/authenticated-discovery-run-index/v1alpha1"

_RUN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")
_PLAN_PATH: Final = "plan.json"
_AUTHORIZATION_PATH: Final = "authorization.json"
_DISCOVERY_PATH: Final = "discovery.json"
_INDEX_PATH: Final = "index.json"
_EXPECTED_ARTIFACTS: Final[frozenset[str]] = frozenset(
    {_PLAN_PATH, _AUTHORIZATION_PATH, _DISCOVERY_PATH, _INDEX_PATH}
)
_MAX_PLAN_BYTES: Final = 1 * 1024 * 1024
_MAX_AUTHORIZATION_BYTES: Final = 256 * 1024
_MAX_DISCOVERY_BYTES: Final = 8 * 1024 * 1024
_MAX_INDEX_BYTES: Final = 256 * 1024
_ARTIFACT_LIMITS: Final[Mapping[str, int]] = {
    _PLAN_PATH: _MAX_PLAN_BYTES,
    _AUTHORIZATION_PATH: _MAX_AUTHORIZATION_BYTES,
    _DISCOVERY_PATH: _MAX_DISCOVERY_BYTES,
    _INDEX_PATH: _MAX_INDEX_BYTES,
}
_SESSION_IMPLEMENTATION: Final = (
    "pajin.web_assessment.discovery_runtime.GovernedPlaywrightAuthenticatedDiscoverySession"
)
_NETWORK_IMPLEMENTATION: Final = "pajin.web_assessment.network.AssessmentNetwork"
_STARTED_EVENT: Final = "authenticated-discovery.started"
_COMPLETED_EVENT: Final = "authenticated-discovery.completed"


class AuthenticatedDiscoveryRunError(RuntimeError):
    """A discovery-only authenticated Run could not be produced safely."""


class AuthenticatedDiscoveryRunIntegrityError(ValueError):
    """A sealed discovery-only Run failed strict, independently anchored loading."""


class AuthenticatedDiscoveryRunIndex(StrictModel):
    """Bounded inventory and explicit non-authority markers for one sealed Run."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)

    api_version: Literal["pajin.dev/authenticated-discovery-run-index/v1alpha1"] = Field(
        default=AUTHENTICATED_DISCOVERY_RUN_INDEX_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["AuthenticatedDiscoveryRunIndex"] = "AuthenticatedDiscoveryRunIndex"
    index_digest: str = Field(default="", alias="indexDigest", max_length=64)
    run_id: str = Field(alias="runId", pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    semantics: Literal["proposal-only"]
    plan_reference: Literal["plan.json"] = Field(alias="planReference")
    plan_digest: str = Field(alias="planDigest", pattern=r"^[a-f0-9]{64}$")
    authorization_reference: Literal["authorization.json"] = Field(
        alias="authorizationReference",
    )
    authorization_id: str = Field(alias="authorizationId", min_length=1, max_length=110)
    account_reference_digest: str = Field(
        alias="accountReferenceDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    account_provisioned_at: datetime = Field(alias="accountProvisionedAt")
    target_version: str = Field(alias="targetVersion", min_length=1, max_length=100)
    discovery_reference: Literal["discovery.json"] = Field(
        alias="discoveryReference",
    )
    discovery_evidence_digest: str = Field(
        alias="discoveryEvidenceDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    discovery_plan_digest: str = Field(
        alias="discoveryPlanDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    discovery_result_digest: str = Field(
        alias="discoveryResultDigest",
        pattern=r"^[a-f0-9]{64}$",
    )
    origin: str
    passive_request_count: int = Field(
        alias="passiveRequestCount",
        strict=True,
        ge=1,
        le=500,
    )
    started_at: datetime = Field(alias="startedAt")
    finished_at: datetime = Field(alias="finishedAt")
    session_implementation: Literal[
        "pajin.web_assessment.discovery_runtime.GovernedPlaywrightAuthenticatedDiscoverySession"
    ] = Field(alias="sessionImplementation")
    network_implementation: Literal["pajin.web_assessment.network.AssessmentNetwork"] = Field(
        alias="networkImplementation"
    )
    browser_closed: Literal[True] = Field(alias="browserClosed")
    credentials_persisted: Literal[False] = Field(alias="credentialsPersisted")
    raw_dom_persisted: Literal[False] = Field(alias="rawDomPersisted")
    screenshots_persisted: Literal[False] = Field(alias="screenshotsPersisted")
    response_bodies_persisted: Literal[False] = Field(
        alias="responseBodiesPersisted",
    )
    diagnostic_invocation_count: Literal[0] = Field(
        alias="diagnosticInvocationCount",
    )
    tool_request_count: Literal[0] = Field(alias="toolRequestCount")
    action_permit_count: Literal[0] = Field(alias="actionPermitCount")
    finding_count: Literal[0] = Field(alias="findingCount")
    graph_mutation_count: Literal[0] = Field(alias="graphMutationCount")
    external_delivery_performed: Literal[False] = Field(
        alias="externalDeliveryPerformed",
    )
    independent_execution_attested: Literal[False] = Field(
        alias="independentExecutionAttested",
    )
    execution_authority: Literal[False] = Field(alias="executionAuthority")
    finding_authority: Literal[False] = Field(alias="findingAuthority")
    graph_admission_authority: Literal[False] = Field(
        alias="graphAdmissionAuthority",
    )

    @field_validator("account_provisioned_at", "started_at", "finished_at")
    @classmethod
    def normalize_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authenticated discovery Run times require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator("target_version")
    @classmethod
    def require_canonical_target_version(cls, value: str) -> str:
        if (
            value != value.strip()
            or not value.isascii()
            or any(ord(character) < 0x20 for character in value)
        ):
            raise ValueError("authenticated discovery target version is not canonical")
        return value

    @field_validator("browser_closed", mode="before")
    @classmethod
    def require_browser_closed(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("authenticated discovery browserClosed must be boolean true")
        return value

    @field_validator(
        "credentials_persisted",
        "raw_dom_persisted",
        "screenshots_persisted",
        "response_bodies_persisted",
        "external_delivery_performed",
        "independent_execution_attested",
        "execution_authority",
        "finding_authority",
        "graph_admission_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError(
                "authenticated discovery retention and authority markers must be false"
            )
        return value

    @field_validator(
        "diagnostic_invocation_count",
        "tool_request_count",
        "action_permit_count",
        "finding_count",
        "graph_mutation_count",
        mode="before",
    )
    @classmethod
    def require_zero_counts(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("authenticated discovery authority call counts must be integer zero")
        return value

    @model_validator(mode="after")
    def bind_index(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("authenticated discovery Run finished before it started")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"index_digest"},
        )
        expected = discovery_digest(
            "pajin.web-assessment.authenticated-discovery-run-index/v1",
            material,
        )
        if self.index_digest and self.index_digest != expected:
            raise ValueError("authenticated discovery Run Index Digest differs")
        object.__setattr__(self, "index_digest", expected)
        return self


@dataclass(frozen=True, slots=True)
class AuthenticatedDiscoveryRunArtifacts:
    """Producer return for one sealed discovery-only Run."""

    run_path: Path
    plan_path: Path
    authorization_path: Path
    discovery_path: Path
    index_path: Path
    root_digest: str
    discovery: AuthenticatedDiscoveryEvidence
    index: AuthenticatedDiscoveryRunIndex


@dataclass(frozen=True, slots=True)
class VerifiedAuthenticatedDiscoveryRun:
    """Strictly loaded inert discovery evidence under independent Run/root anchors."""

    run_path: Path
    verification: RunIntegrityVerification
    plan: WebAssessmentPlan
    authorization: LocalWebAssessmentAuthorization
    discovery: AuthenticatedDiscoveryEvidence
    index: AuthenticatedDiscoveryRunIndex
    semantics: Literal["source-integrity-only"] = "source-integrity-only"
    independent_replay_verified: Literal[False] = False
    execution_authority: Literal[False] = False
    finding_authority: Literal[False] = False
    graph_admission_authority: Literal[False] = False


_DiscoveryExecutor = Callable[
    ...,
    Awaitable[GovernedAuthenticatedDiscoveryObservation],
]


def code_owned_authenticated_discovery_plan(
    plan: WebAssessmentPlan,
) -> BrowserDiscoveryPlan:
    """Build the one fixed authenticated discovery recipe for the code-owned adapter."""

    if type(plan) is not WebAssessmentPlan:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact code-owned assessment Plan type"
        )
    canonical_plan = WebAssessmentPlan.model_validate(plan.model_dump(mode="json", by_alias=True))
    if canonical_plan != juice_shop_plan(canonical_plan.origin):
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact code-owned Juice Shop Plan"
        )
    return BrowserDiscoveryPlan(
        origin=canonical_plan.origin,
        seed_routes=(canonical_plan.routes[0],),
        authenticationSentinelSelector=canonical_plan.login.success_selector,
        authenticationSentinelActivationSelector=(canonical_plan.login.success_activation_selector),
        authenticationSentinelActivationMode=canonical_plan.login.success_activation_mode,
        max_routes=4,
        max_depth=1,
        max_links_per_page=40,
        max_forms=20,
        max_fields_per_form=16,
        max_total_fields=64,
        navigation_timeout_milliseconds=canonical_plan.request_timeout_seconds * 1_000,
        settle_milliseconds=250,
    )


def _account_reference_digest(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    provisioned_at: datetime,
    target_version: str,
) -> str:
    return discovery_digest(
        "pajin.web-assessment.authenticated-discovery-account-reference/v1",
        {
            "adapterImplementationId": plan.adapter_implementation_id,
            "authorizationId": authorization.authorization_id,
            "origin": plan.origin,
            "planDigest": plan.plan_digest,
            "provisionedAt": provisioned_at.astimezone(UTC).isoformat(),
            "targetProduct": plan.target_product,
            "targetVersion": target_version,
        },
    )


def _canonical_inputs(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    discovery_plan: BrowserDiscoveryPlan,
    account: ProvisionedLocalWebAssessmentAccount,
    now: datetime,
) -> tuple[WebAssessmentPlan, LocalWebAssessmentAuthorization, BrowserDiscoveryPlan]:
    if type(plan) is not WebAssessmentPlan:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact code-owned assessment Plan type"
        )
    if type(authorization) is not LocalWebAssessmentAuthorization:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact local authorization type"
        )
    if type(discovery_plan) is not BrowserDiscoveryPlan:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact code-owned discovery Plan type"
        )
    if type(account) is not ProvisionedLocalWebAssessmentAccount:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires an exact pre-provisioned account"
        )
    if type(account.credentials) is not BrowserCredentials:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires process-local browser credentials"
        )
    if (
        type(account.credentials.username) is not str
        or not account.credentials.username
        or type(account.credentials.password) is not str
        or not account.credentials.password
    ):
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires non-empty process-local browser credentials"
        )

    canonical_plan = WebAssessmentPlan.model_validate(plan.model_dump(mode="json", by_alias=True))
    if canonical_plan != juice_shop_plan(canonical_plan.origin):
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery requires the exact code-owned Juice Shop Plan"
        )
    canonical_authorization = LocalWebAssessmentAuthorization.model_validate(
        authorization.model_dump(mode="json", by_alias=True)
    )
    canonical_discovery_plan = BrowserDiscoveryPlan.model_validate(
        discovery_plan.model_dump(mode="json", by_alias=True)
    )
    expected_discovery_plan = code_owned_authenticated_discovery_plan(canonical_plan)
    if canonical_discovery_plan != expected_discovery_plan:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery Plan differs from the exact authenticated route boundary"
        )
    provisioned_at = account.provisioned_at
    if (
        not isinstance(provisioned_at, datetime)
        or provisioned_at.tzinfo is None
        or provisioned_at.utcoffset() is None
        or not canonical_authorization.approved_at <= provisioned_at.astimezone(UTC) <= now
        or type(account.target_version) is not str
        or not account.target_version
        or account.target_version != account.target_version.strip()
        or len(account.target_version) > 100
        or not account.target_version.isascii()
        or any(ord(character) < 0x20 for character in account.target_version)
    ):
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery account provisioning facts are invalid"
        )
    try:
        account.require_current(
            plan=canonical_plan,
            authorization=canonical_authorization,
            now=now,
        )
    except (LocalWebAssessmentError, TypeError, ValueError) as exc:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery account differs from its exact Plan authorization"
        ) from exc
    return canonical_plan, canonical_authorization, canonical_discovery_plan


def _require_observation(
    observation: GovernedAuthenticatedDiscoveryObservation,
    *,
    plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
) -> None:
    if type(observation) is not GovernedAuthenticatedDiscoveryObservation:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery runtime returned an unsupported observation"
        )
    sequences = tuple(request_evidence_sequence(item) for item in observation.request_evidence)
    receipt_sequences = tuple(item.evidence_sequence for item in observation.boundary_receipts)
    if (
        type(observation.browser_closed) is not bool
        or observation.browser_closed is not True
        or observation.session_implementation != _SESSION_IMPLEMENTATION
        or observation.network_implementation != _NETWORK_IMPLEMENTATION
        or observation.discovery_result.plan_digest != discovery_plan.plan_digest
        or observation.discovery_result.origin != plan.origin
        or not sequences
        or sequences != tuple(sorted(sequences))
        or len(sequences) != len(set(sequences))
        or receipt_sequences != sequences
    ):
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery runtime observation differs from its governed boundary"
        )


async def _run_authenticated_discovery_artifact(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    account: ProvisionedLocalWebAssessmentAccount,
    discovery_plan: BrowserDiscoveryPlan,
    output_root: Path,
    headless: bool,
    executor: _DiscoveryExecutor,
) -> AuthenticatedDiscoveryRunArtifacts:
    started_at = datetime.now(UTC)
    canonical_plan, canonical_authorization, canonical_discovery_plan = _canonical_inputs(
        plan=plan,
        authorization=authorization,
        discovery_plan=discovery_plan,
        account=account,
        now=started_at,
    )
    started_payload = {
        "authorizationId": canonical_authorization.authorization_id,
        "discoveryPlanDigest": canonical_discovery_plan.plan_digest,
        "origin": canonical_plan.origin,
        "planDigest": canonical_plan.plan_digest,
        "semantics": "proposal-only",
    }
    network = AssessmentNetwork(canonical_plan)
    if type(network) is not AssessmentNetwork:  # pragma: no cover - constructor is fixed above
        raise AuthenticatedDiscoveryRunError("authenticated discovery network provenance differs")
    network.bind_authorization_deadline(canonical_authorization.expires_at)
    policy: EgressPolicy = assessment_policy(canonical_plan, max_requests=100)
    try:
        observation = await executor(
            assessment_plan=canonical_plan,
            discovery_plan=canonical_discovery_plan,
            network=network,
            credentials=account.credentials,
            navigation_policy=policy,
            headless=headless,
        )
    finally:
        await network.close()

    _require_observation(
        observation,
        plan=canonical_plan,
        discovery_plan=canonical_discovery_plan,
    )
    discovery = authenticated_discovery_evidence(
        discovery_plan=canonical_discovery_plan,
        discovery_result=observation.discovery_result,
        request_evidence=observation.request_evidence,
        boundary_receipts=observation.boundary_receipts,
    )
    finished_at = datetime.now(UTC)
    try:
        canonical_authorization.require_current(plan=canonical_plan, now=finished_at)
    except ValueError as exc:
        raise AuthenticatedDiscoveryRunError(
            "authenticated discovery authorization expired before artifact completion"
        ) from exc
    run_id = RunStore.new_run_id()
    index = AuthenticatedDiscoveryRunIndex(
        runId=run_id,
        semantics="proposal-only",
        planReference=_PLAN_PATH,
        planDigest=canonical_plan.plan_digest,
        authorizationReference=_AUTHORIZATION_PATH,
        authorizationId=canonical_authorization.authorization_id,
        accountReferenceDigest=_account_reference_digest(
            plan=canonical_plan,
            authorization=canonical_authorization,
            provisioned_at=account.provisioned_at,
            target_version=account.target_version,
        ),
        accountProvisionedAt=account.provisioned_at,
        targetVersion=account.target_version,
        discoveryReference=_DISCOVERY_PATH,
        discoveryEvidenceDigest=discovery.evidence_digest,
        discoveryPlanDigest=canonical_discovery_plan.plan_digest,
        discoveryResultDigest=discovery.discovery_result.result_digest,
        origin=canonical_plan.origin,
        passiveRequestCount=len(discovery.request_evidence),
        startedAt=started_at,
        finishedAt=finished_at,
        sessionImplementation=observation.session_implementation,
        networkImplementation=observation.network_implementation,
        browserClosed=True,
        credentialsPersisted=False,
        rawDomPersisted=False,
        screenshotsPersisted=False,
        responseBodiesPersisted=False,
        diagnosticInvocationCount=0,
        toolRequestCount=0,
        actionPermitCount=0,
        findingCount=0,
        graphMutationCount=0,
        externalDeliveryPerformed=False,
        independentExecutionAttested=False,
        executionAuthority=False,
        findingAuthority=False,
        graphAdmissionAuthority=False,
    )

    store = RunStore.create(
        output_root,
        canonical_plan.name + "-authenticated-discovery",
        run_id=run_id,
    )
    store.append_event(_STARTED_EVENT, started_payload, occurred_at=started_at)
    for path, artifact in (
        (_PLAN_PATH, canonical_plan),
        (_AUTHORIZATION_PATH, canonical_authorization),
        (_DISCOVERY_PATH, discovery),
        (_INDEX_PATH, index),
    ):
        store.write_json_create_only(
            path,
            artifact.model_dump(mode="json", by_alias=True, exclude_none=True),
        )
    completed_payload = {
        "browserClosed": True,
        "discoveryEvidenceDigest": discovery.evidence_digest,
        "indexDigest": index.index_digest,
        "passiveRequestCount": len(discovery.request_evidence),
        "semantics": "proposal-only",
    }
    store.append_event(_COMPLETED_EVENT, completed_payload, occurred_at=finished_at)
    seal = store.seal()
    verification = verify_run_integrity(store.path)
    if (
        verification.run_id != store.run_id
        or verification.root_digest != seal.root_digest
        or verification.seal_count != 1
        or verification.event_count != 2
        or verification.artifact_count != len(_EXPECTED_ARTIFACTS)
    ):
        raise AuthenticatedDiscoveryRunError("sealed authenticated discovery verification differs")
    return AuthenticatedDiscoveryRunArtifacts(
        run_path=store.path,
        plan_path=store.path / _PLAN_PATH,
        authorization_path=store.path / _AUTHORIZATION_PATH,
        discovery_path=store.path / _DISCOVERY_PATH,
        index_path=store.path / _INDEX_PATH,
        root_digest=seal.root_digest,
        discovery=discovery,
        index=index,
    )


async def run_sealed_authenticated_discovery(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    account: ProvisionedLocalWebAssessmentAccount,
    discovery_plan: BrowserDiscoveryPlan,
    output_root: Path,
    headless: bool = True,
) -> AuthenticatedDiscoveryRunArtifacts:
    """Run the fixed governed login/passive-discovery implementation and seal its evidence."""

    return await _run_authenticated_discovery_artifact(
        plan=plan,
        authorization=authorization,
        account=account,
        discovery_plan=discovery_plan,
        output_root=output_root,
        headless=headless,
        executor=run_governed_authenticated_browser_discovery_with_evidence,
    )


def _artifact_records(snapshot: VerifiedRunSnapshot) -> dict[str, SealedArtifact]:
    records = {artifact.path: artifact for seal in snapshot.seals for artifact in seal.artifacts}
    if len(records) != sum(len(seal.artifacts) for seal in snapshot.seals):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "authenticated discovery seal contains duplicate artifact paths"
        )
    return records


def _require_run_shape(
    snapshot: VerifiedRunSnapshot,
    *,
    expected_root_digest: str,
) -> None:
    verification = snapshot.verification
    if (
        verification.root_digest != expected_root_digest
        or verification.seal_count != 1
        or len(snapshot.seals) != 1
        or verification.event_count != 2
        or len(snapshot.events) != 2
        or tuple(event.event_type for event in snapshot.events)
        != (_STARTED_EVENT, _COMPLETED_EVENT)
    ):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery Run shape differs"
        )
    records = _artifact_records(snapshot)
    if set(records) != _EXPECTED_ARTIFACTS or verification.artifact_count != len(
        _EXPECTED_ARTIFACTS
    ):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery artifact inventory differs"
        )
    for path, record in records.items():
        if (
            record.media_type != "application/json"
            or record.size_bytes < 1
            or record.size_bytes > _ARTIFACT_LIMITS[path]
        ):
            raise AuthenticatedDiscoveryRunIntegrityError(
                f"sealed authenticated discovery artifact boundary differs: {path}"
            )


def _strict_model[T: StrictModel](
    snapshot: VerifiedRunSnapshot,
    path: str,
    model: type[T],
) -> T:
    raw = strict_json(
        snapshot,
        path,
        label=f"authenticated discovery {path}",
        max_bytes=_ARTIFACT_LIMITS[path],
        expected_type=dict,
    )
    value = model.model_validate(raw)
    if raw != value.model_dump(mode="json", by_alias=True, exclude_none=True):
        raise AuthenticatedDiscoveryRunIntegrityError(
            f"authenticated discovery {path} is not the exact canonical artifact"
        )
    return value


def _require_loaded_bindings(
    *,
    snapshot: VerifiedRunSnapshot,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    discovery: AuthenticatedDiscoveryEvidence,
    index: AuthenticatedDiscoveryRunIndex,
) -> None:
    if plan != juice_shop_plan(plan.origin):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery Plan is not the exact code-owned Plan"
        )
    discovery_plan = discovery.discovery_plan
    try:
        expected_discovery_plan = code_owned_authenticated_discovery_plan(plan)
    except AuthenticatedDiscoveryRunError as exc:  # pragma: no cover - plan equality checked above
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery code-owned Plan could not be reconstructed"
        ) from exc
    if discovery_plan != expected_discovery_plan:
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery route boundary differs from its Plan"
        )
    if any(
        browser_discovery_request_path_rejection(origin=plan.origin, url=plan.origin + request.path)
        is not None
        for request in discovery.request_evidence
    ):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery contains a rejected request path"
        )
    if (
        discovery.discovery_result.plan_digest != discovery_plan.plan_digest
        or discovery.discovery_result.origin != plan.origin
        or discovery.browser_closed is not True
        or discovery.credentials_persisted is not False
        or discovery.redirects_followed is not False
        or discovery.request_payloads_sent is not False
        or discovery.raw_dom_retained is not False
        or discovery.screenshots_retained is not False
        or discovery.form_values_retained is not False
        or discovery.forms_submitted is not False
        or discovery.response_bodies_retained is not False
        or discovery.external_delivery_performed is not False
        or discovery.scope_expansion_authority is not False
        or discovery.action_permit_authority is not False
        or discovery.form_submission_authority is not False
        or discovery.payload_authority is not False
        or discovery.execution_authority is not False
        or discovery.finding_authority is not False
        or discovery.graph_admission_authority is not False
        or index.run_id != snapshot.verification.run_id
        or index.plan_digest != plan.plan_digest
        or index.authorization_id != authorization.authorization_id
        or index.account_reference_digest
        != _account_reference_digest(
            plan=plan,
            authorization=authorization,
            provisioned_at=index.account_provisioned_at,
            target_version=index.target_version,
        )
        or not authorization.approved_at <= index.account_provisioned_at <= index.started_at
        or index.account_provisioned_at >= authorization.expires_at
        or index.discovery_evidence_digest != discovery.evidence_digest
        or index.discovery_plan_digest != discovery_plan.plan_digest
        or index.discovery_result_digest != discovery.discovery_result.result_digest
        or index.origin != plan.origin
        or index.passive_request_count != len(discovery.request_evidence)
        or index.session_implementation != _SESSION_IMPLEMENTATION
        or index.network_implementation != _NETWORK_IMPLEMENTATION
        or index.browser_closed is not True
        or index.credentials_persisted is not False
        or index.raw_dom_persisted is not False
        or index.screenshots_persisted is not False
        or index.response_bodies_persisted is not False
        or index.diagnostic_invocation_count != 0
        or index.tool_request_count != 0
        or index.action_permit_count != 0
        or index.finding_count != 0
        or index.graph_mutation_count != 0
        or index.external_delivery_performed is not False
        or index.independent_execution_attested is not False
        or index.execution_authority is not False
        or index.finding_authority is not False
        or index.graph_admission_authority is not False
    ):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery exact bindings or false authority differ"
        )
    try:
        authorization.require_current(plan=plan, now=index.started_at)
        authorization.require_current(plan=plan, now=index.finished_at)
    except ValueError as exc:
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery authorization or time binding differs"
        ) from exc

    started, completed = snapshot.events
    expected_started = {
        "authorizationId": authorization.authorization_id,
        "discoveryPlanDigest": discovery_plan.plan_digest,
        "origin": plan.origin,
        "planDigest": plan.plan_digest,
        "semantics": "proposal-only",
    }
    expected_completed = {
        "browserClosed": True,
        "discoveryEvidenceDigest": discovery.evidence_digest,
        "indexDigest": index.index_digest,
        "passiveRequestCount": len(discovery.request_evidence),
        "semantics": "proposal-only",
    }
    if (
        started.occurred_at != index.started_at
        or started.payload != expected_started
        or completed.occurred_at != index.finished_at
        or completed.payload != expected_completed
    ):
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery audit events differ from its Index"
        )


def load_verified_authenticated_discovery(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> VerifiedAuthenticatedDiscoveryRun:
    """Strictly load one bounded Run under independently supplied Run and root anchors."""

    if _RUN_ID_PATTERN.fullmatch(expected_run_id) is None:
        raise AuthenticatedDiscoveryRunIntegrityError(
            "expected authenticated discovery Run ID is invalid"
        )
    if _SHA256_PATTERN.fullmatch(expected_root_digest) is None:
        raise AuthenticatedDiscoveryRunIntegrityError(
            "expected authenticated discovery root digest is invalid"
        )
    try:
        initial = load_verified_run_snapshot(run_path, expected_run_id=expected_run_id)
        _require_run_shape(initial, expected_root_digest=expected_root_digest)
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=dict(_ARTIFACT_LIMITS),
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed authenticated discovery changed while artifacts were loaded",
        )
        plan = _strict_model(loaded, _PLAN_PATH, WebAssessmentPlan)
        authorization = _strict_model(
            loaded,
            _AUTHORIZATION_PATH,
            LocalWebAssessmentAuthorization,
        )
        discovery = _strict_model(
            loaded,
            _DISCOVERY_PATH,
            AuthenticatedDiscoveryEvidence,
        )
        index = _strict_model(loaded, _INDEX_PATH, AuthenticatedDiscoveryRunIndex)
        _require_loaded_bindings(
            snapshot=loaded,
            plan=plan,
            authorization=authorization,
            discovery=discovery,
            index=index,
        )
        final = load_verified_run_snapshot(initial.run_path, expected_run_id=expected_run_id)
        require_same_authority(
            initial,
            final,
            message="sealed authenticated discovery changed during strict reload",
        )
        return VerifiedAuthenticatedDiscoveryRun(
            run_path=initial.run_path,
            verification=initial.verification.model_copy(deep=True),
            plan=plan,
            authorization=authorization,
            discovery=discovery,
            index=index,
        )
    except AuthenticatedDiscoveryRunIntegrityError:
        raise
    except (OSError, RunIntegrityError, UnicodeError, ValidationError, ValueError) as exc:
        raise AuthenticatedDiscoveryRunIntegrityError(
            "sealed authenticated discovery failed strict verification"
        ) from exc


__all__ = [
    "AUTHENTICATED_DISCOVERY_RUN_INDEX_API_VERSION",
    "AuthenticatedDiscoveryRunArtifacts",
    "AuthenticatedDiscoveryRunError",
    "AuthenticatedDiscoveryRunIndex",
    "AuthenticatedDiscoveryRunIntegrityError",
    "VerifiedAuthenticatedDiscoveryRun",
    "code_owned_authenticated_discovery_plan",
    "load_verified_authenticated_discovery",
    "run_sealed_authenticated_discovery",
]
