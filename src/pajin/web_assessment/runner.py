"""Authority-bound orchestration for one exact local browser assessment."""

from __future__ import annotations

import asyncio
import secrets
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from pajin.runtime.store import RunStore, verify_run_integrity
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.browser import (
    BrowserAssessmentError,
    BrowserAssessmentObservation,
    BrowserCredentials,
    PlaywrightAssessmentBrowser,
)
from pajin.web_assessment.diagnostic_catalog import (
    DiagnosticBundleCatalog,
    DiagnosticBundleCatalogError,
    DiagnosticExecutionPolicies,
    production_diagnostic_bundle_catalog,
)
from pajin.web_assessment.diagnostics import WebDiagnosticError
from pajin.web_assessment.models import (
    DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
    DEFAULT_WEB_ASSESSMENT_FINGERPRINT_VERSION_PATH,
    DEFAULT_WEB_ASSESSMENT_TARGET_PRODUCT,
    LocalWebAssessmentAuthorization,
    LocalWebAssessmentResult,
    RequestEvidence,
    WebAssessmentPlan,
    json_at,
    request_evidence_sequence,
)
from pajin.web_assessment.network import AssessmentBoundaryError, AssessmentNetwork
from pajin.web_assessment.report import render_local_web_assessment_report


class LocalWebAssessmentError(RuntimeError):
    """Raised when the complete local assessment cannot produce a sealed result."""


class AssessmentBrowser(Protocol):
    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation: ...


BrowserFactory = Callable[..., AssessmentBrowser]
NetworkFactory = Callable[[WebAssessmentPlan], AssessmentNetwork]


@dataclass(frozen=True)
class LocalWebAssessmentArtifacts:
    result: LocalWebAssessmentResult
    run_path: Path
    result_path: Path
    report_path: Path
    root_digest: str
    discovery_evidence_path: Path | None = None


@dataclass(frozen=True, repr=False)
class ProvisionedLocalWebAssessmentAccount:
    """Process-local credentials plus a secret-free account-provisioning receipt."""

    credentials: BrowserCredentials
    plan_digest: str
    authorization_id: str
    origin: str
    target_version: str
    provisioned_at: datetime
    request_evidence: tuple[RequestEvidence, ...]
    target_product: str = DEFAULT_WEB_ASSESSMENT_TARGET_PRODUCT
    fingerprint_version_path: str = DEFAULT_WEB_ASSESSMENT_FINGERPRINT_VERSION_PATH
    adapter_implementation_id: str = DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID

    def require_current(
        self,
        *,
        plan: WebAssessmentPlan,
        authorization: LocalWebAssessmentAuthorization,
        now: datetime,
    ) -> None:
        authorization.require_current(plan=plan, now=now)
        if (
            self.plan_digest != plan.plan_digest
            or self.authorization_id != authorization.authorization_id
            or self.origin != plan.origin
            or self.target_product != plan.target_product
            or self.fingerprint_version_path != plan.fingerprint_version_path
            or self.adapter_implementation_id != plan.adapter_implementation_id
            or not authorization.approved_at <= self.provisioned_at < authorization.expires_at
        ):
            raise LocalWebAssessmentError(
                "pre-provisioned account differs from the selected plan authorization"
            )

    def receipt(self) -> dict[str, object]:
        """Return bounded audit material without credentials or a credential verifier."""

        return {
            "apiVersion": "pajin.dev/local-web-assessment-provisioning/v1alpha1",
            "kind": "LocalWebAssessmentProvisioningReceipt",
            "planDigest": self.plan_digest,
            "authorizationId": self.authorization_id,
            "origin": self.origin,
            "targetProduct": self.target_product,
            "targetVersion": self.target_version,
            "provisionedAt": self.provisioned_at.isoformat(),
            "requests": [item.model_dump(mode="json") for item in self.request_evidence],
            "accountRetainedInLocalLab": True,
            "credentialsPersisted": False,
        }


def issue_local_web_assessment_authorization(
    plan: WebAssessmentPlan,
    *,
    operator_confirmed_authorized_local_lab: bool,
    now: datetime | None = None,
) -> LocalWebAssessmentAuthorization:
    """Issue a short-lived exact-plan assertion only from an explicit CLI confirmation."""

    if (
        type(operator_confirmed_authorized_local_lab) is not bool
        or not operator_confirmed_authorized_local_lab
    ):
        raise LocalWebAssessmentError("an explicit authorized-local-lab confirmation is required")
    approved_at = now or datetime.now(UTC)
    if approved_at.tzinfo is None or approved_at.utcoffset() is None:
        raise LocalWebAssessmentError("authorization time requires an explicit UTC offset")
    approved_at = approved_at.astimezone(UTC)
    return LocalWebAssessmentAuthorization(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        approved_at=approved_at,
        expires_at=approved_at + timedelta(minutes=30),
        operator_attested_authorized=True,
        ephemeral_account_creation_allowed=True,
    )


def assessment_policy(plan: WebAssessmentPlan, *, max_requests: int) -> EgressPolicy:
    """Compile an exact-origin, loopback-enabled policy for one assessment phase."""

    return EgressPolicy(
        allow=[plan.origin + "/*"],
        deny=[plan.origin + path + "*" for path in plan.deny_paths],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=plan.max_response_bytes,
        max_requests=max_requests,
        max_request_bytes=64_000,
    )


def _ephemeral_credentials() -> BrowserCredentials:
    nonce = secrets.token_hex(12)
    return BrowserCredentials(
        username=f"pajin-{nonce}@example.test",
        password=f"Pajin-{secrets.token_hex(16)}!",
    )


async def _fingerprint_target(
    network: AssessmentNetwork,
    plan: WebAssessmentPlan,
    policy: EgressPolicy,
) -> str:
    network.begin_phase("target-fingerprint", policy)
    response = await network.json_request("GET", plan.fingerprint_endpoint)
    version = json_at(response.json(), plan.fingerprint_version_path)
    if response.status != 200 or not isinstance(version, str) or not version[:100].strip():
        raise LocalWebAssessmentError("target fingerprint did not identify the planned product")
    return version[:100]


async def _create_ephemeral_account(
    network: AssessmentNetwork,
    plan: WebAssessmentPlan,
    policy: EgressPolicy,
    credentials: BrowserCredentials,
) -> None:
    recipe = plan.registration
    if recipe is None:
        raise LocalWebAssessmentError("the selected assessment recipe cannot create an account")
    network.begin_phase("ephemeral-account-registration", policy)
    payload: dict[str, object] = dict(recipe.extra_fields)
    payload[recipe.username_field] = credentials.username
    payload[recipe.password_field] = credentials.password
    if recipe.repeat_password_field is not None:
        payload[recipe.repeat_password_field] = credentials.password
    response = await network.json_request("POST", recipe.endpoint, payload=payload)
    if response.status not in {200, 201}:
        raise LocalWebAssessmentError("disposable local assessment account creation failed")


async def provision_local_web_assessment_account(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    network_factory: NetworkFactory = AssessmentNetwork,
) -> ProvisionedLocalWebAssessmentAccount:
    """Create one disposable account under WEB-003 local authority before local execution.

    Account creation is deliberately kept outside the read-only browser Capability. The
    returned credentials are process-local and excluded from the serializable receipt.
    """

    provisioned_at = datetime.now(UTC)
    authorization.require_current(plan=plan, now=provisioned_at)
    policy = assessment_policy(plan, max_requests=10)
    network = network_factory(plan)
    network.bind_authorization_deadline(authorization.expires_at)
    credentials = _ephemeral_credentials()
    try:
        target_version = await _fingerprint_target(network, plan, policy)
        await _create_ephemeral_account(network, plan, policy, credentials)
        return ProvisionedLocalWebAssessmentAccount(
            credentials=credentials,
            plan_digest=plan.plan_digest,
            authorization_id=authorization.authorization_id,
            origin=plan.origin,
            target_version=target_version,
            provisioned_at=provisioned_at,
            request_evidence=tuple(network.evidence),
            target_product=plan.target_product,
            fingerprint_version_path=plan.fingerprint_version_path,
            adapter_implementation_id=plan.adapter_implementation_id,
        )
    finally:
        await network.close()


def _failure_category(error: BaseException) -> str:
    if isinstance(error, asyncio.TimeoutError):
        return "deadline"
    if isinstance(error, AssessmentBoundaryError):
        return "boundary"
    if isinstance(error, BrowserAssessmentError):
        return "browser"
    if isinstance(error, WebDiagnosticError):
        return "diagnostic"
    if isinstance(error, ValueError):
        return "contract"
    return "execution"


async def run_local_web_assessment(
    *,
    plan: WebAssessmentPlan,
    authorization: LocalWebAssessmentAuthorization,
    output_root: Path,
    run_id: str | None = None,
    headless: bool = True,
    browser_factory: BrowserFactory = PlaywrightAssessmentBrowser,
    network_factory: NetworkFactory = AssessmentNetwork,
    provisioned_account: ProvisionedLocalWebAssessmentAccount | None = None,
    adapter_implementation_digest: str | None = None,
    diagnostic_catalog: DiagnosticBundleCatalog | None = None,
) -> LocalWebAssessmentArtifacts:
    """Run registration, browser login/navigation, diagnostics, chaining, and sealing."""

    started_at = datetime.now(UTC)
    bundle_catalog = diagnostic_catalog or production_diagnostic_bundle_catalog()
    try:
        bundle_catalog._require_runner_runtime_factories(
            browser_factory=browser_factory,
            network_factory=network_factory,
        )
    except DiagnosticBundleCatalogError as exc:
        raise LocalWebAssessmentError("code-owned diagnostic runtime provenance failed") from exc
    try:
        selected_digest = adapter_implementation_digest
        if selected_digest is None:
            matches = tuple(
                digest
                for implementation_id, digest in bundle_catalog.references()
                if implementation_id == plan.adapter_implementation_id
            )
            if len(matches) != 1:
                raise DiagnosticBundleCatalogError(
                    "an exact installed adapter implementation digest is required"
                )
            selected_digest = matches[0]
        bundle_descriptor = bundle_catalog.resolve(
            adapter_implementation_id=plan.adapter_implementation_id,
            adapter_implementation_digest=selected_digest,
        )
        bundle_catalog.require_code_owned_plan(
            descriptor=bundle_descriptor,
            plan=plan,
        )
    except DiagnosticBundleCatalogError as exc:
        raise LocalWebAssessmentError("code-owned diagnostic bundle resolution failed") from exc
    authorization.require_current(plan=plan, now=started_at)
    store = RunStore.create(output_root, plan.name, run_id=run_id)
    setup_policy = assessment_policy(plan, max_requests=10)
    navigation_policy = assessment_policy(plan, max_requests=100)
    diagnostic_policy = assessment_policy(plan, max_requests=20)
    xss_policy = assessment_policy(plan, max_requests=40)
    network = network_factory(plan)
    network.bind_authorization_deadline(authorization.expires_at)
    credentials = (
        provisioned_account.credentials
        if provisioned_account is not None
        else _ephemeral_credentials()
    )
    account_created = False
    try:
        store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
        store.write_json_create_only(
            "authorization.json",
            authorization.model_dump(mode="json"),
        )
        store.append_event(
            "web-assessment.started",
            {
                "authorizationId": authorization.authorization_id,
                "origin": plan.origin,
                "planDigest": plan.plan_digest,
            },
            occurred_at=started_at,
        )
        if provisioned_account is None:
            target_version = await _fingerprint_target(network, plan, setup_policy)
            await _create_ephemeral_account(
                network,
                plan,
                setup_policy,
                credentials,
            )
        else:
            provisioned_account.require_current(
                plan=plan,
                authorization=authorization,
                now=started_at,
            )
            target_version = provisioned_account.target_version
            store.write_json_create_only(
                "provisioning-receipt.json",
                provisioned_account.receipt(),
            )
        account_created = True
        browser = browser_factory(
            plan=plan,
            network=network,
            store=store,
            navigation_policy=navigation_policy,
            xss_policy=xss_policy,
            headless=headless,
        )
        observation = await browser.run(credentials)
        if (
            browser_factory is PlaywrightAssessmentBrowser
            and observation.discovery_evidence is None
        ):
            raise LocalWebAssessmentError(
                "code-owned browser omitted authenticated passive discovery Evidence"
            )
        diagnostic_authority = bundle_catalog._bind_runner_execution(
            descriptor=bundle_descriptor,
            plan=plan,
            observation=observation,
            network=network,
            policies=DiagnosticExecutionPolicies(
                sql_login=diagnostic_policy,
                object_access=diagnostic_policy.model_copy(deep=True),
            ),
            store=store,
            browser_factory=browser_factory,
            network_factory=network_factory,
        )
        diagnostic_execution = await bundle_catalog.execute(
            authority=diagnostic_authority,
        )
        issues = diagnostic_execution.issues
        discovery_reference: Literal["discovery-evidence.json"] | None = None
        discovery_digest = None
        if observation.discovery_evidence is not None:
            discovery_evidence = observation.discovery_evidence
            passive_requests = tuple(
                sorted(
                    (
                        request
                        for request in network.evidence
                        if request.phase == "browser-passive-discovery"
                    ),
                    key=request_evidence_sequence,
                )
            )
            if passive_requests != discovery_evidence.request_evidence:
                raise LocalWebAssessmentError(
                    "authenticated passive discovery Evidence differs from the Run requests"
                )
            written_discovery_reference = store.write_json_create_only(
                "discovery-evidence.json",
                discovery_evidence.model_dump(mode="json", by_alias=True),
            )
            if written_discovery_reference != "discovery-evidence.json":
                raise LocalWebAssessmentError(
                    "authenticated passive discovery artifact path differs"
                )
            discovery_reference = "discovery-evidence.json"
            discovery_digest = discovery_evidence.evidence_digest
        result = LocalWebAssessmentResult(
            run_id=store.run_id,
            plan_name=plan.name,
            plan_digest=plan.plan_digest,
            authorization_id=authorization.authorization_id,
            origin=plan.origin,
            target_product=plan.target_product,
            target_version=target_version,
            started_at=started_at,
            finished_at=datetime.now(UTC),
            browser=observation.summary,
            requests=tuple(network.evidence),
            discovery_evidence_reference=discovery_reference,
            discovery_evidence_digest=discovery_digest,
            issues=issues,
            attack_paths=diagnostic_execution.attack_paths,
            account_retained_in_local_lab=True,
            credentials_persisted=False,
            external_delivery_performed=False,
            finding_authority=False,
        )
        result_reference = store.write_json_create_only(
            "result.json",
            result.model_dump(mode="json"),
        )
        report_reference = store.write_text_create_only(
            "report.md",
            render_local_web_assessment_report(
                result,
                discovery_evidence=observation.discovery_evidence,
            ),
        )
        store.append_event(
            "web-assessment.completed",
            {
                "attackPathCount": len(result.attack_paths),
                "issueCount": len(result.issues),
                "resultDigest": result.result_digest,
            },
            occurred_at=result.finished_at,
        )
        seal = store.seal()
        verified = verify_run_integrity(store.path)
        if verified.root_digest != seal.root_digest:
            raise LocalWebAssessmentError("sealed local assessment verification differs")
        return LocalWebAssessmentArtifacts(
            result=result,
            run_path=store.path,
            result_path=store.path / result_reference,
            report_path=store.path / report_reference,
            root_digest=seal.root_digest,
            discovery_evidence_path=(
                store.path / discovery_reference if discovery_reference is not None else None
            ),
        )
    except (Exception, asyncio.CancelledError) as exc:
        try:
            store.write_json_create_only(
                "failure.json",
                {
                    "category": _failure_category(exc),
                    "accountRetainedInLocalLab": account_created,
                    "credentialsPersisted": False,
                    "externalDeliveryPerformed": False,
                    "findingAuthority": False,
                },
            )
            store.append_event(
                "web-assessment.failed",
                {"category": _failure_category(exc)},
            )
            store.seal()
        except Exception:
            pass
        raise
    finally:
        credentials = BrowserCredentials(username="discarded", password="discarded")
        await network.close()
