"""Versioned recipes, authority, and evidence for local web assessments."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from typing import Final, Literal, Self
from urllib.parse import urlsplit, urlunsplit

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel

WEB_ASSESSMENT_API_VERSION: Final[Literal["pajin.dev/local-web-assessment/v1alpha1"]] = (
    "pajin.dev/local-web-assessment/v1alpha1"
)
WEB_ASSESSMENT_AUTHORIZATION_API_VERSION: Final[
    Literal["pajin.dev/local-web-assessment-authorization/v1alpha1"]
] = "pajin.dev/local-web-assessment-authorization/v1alpha1"
WEB_ASSESSMENT_RESULT_API_VERSION: Final[
    Literal["pajin.dev/local-web-assessment-result/v1alpha1"]
] = "pajin.dev/local-web-assessment-result/v1alpha1"
PASSIVE_DISCOVERY_BOUNDARY_RECEIPT_API_VERSION: Final[
    Literal["pajin.dev/passive-discovery-boundary-receipt/v1alpha1"]
] = "pajin.dev/passive-discovery-boundary-receipt/v1alpha1"

DEFAULT_WEB_ASSESSMENT_TARGET_PRODUCT: Final = "OWASP Juice Shop"
DEFAULT_WEB_ASSESSMENT_FINGERPRINT_VERSION_PATH: Final = "version"
DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID: Final = "pajin.web-assessment.juice-shop.v1"

_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_REQUEST_EVIDENCE_ID_PATTERN = r"^http-([1-9][0-9]*)-[a-f0-9]{8}$"
_EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_MEDIA_TYPE_ESSENCE_PATTERN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+/[!#$%&'*+.^_`|~0-9a-z-]+$")

IssueCheck = Literal["sql-login", "object-access", "dom-xss"]
IssueStatus = Literal["locally-reproduced", "not-reproduced", "inconclusive"]
AttackPathStageState = Literal["observed", "locally-reproduced", "potential"]
AttackPathStatus = Literal["locally-validated", "incomplete"]
LoginActivationMode = Literal["submit-click", "password-enter"]
LoginSuccessActivationMode = Literal["click", "enter"]

_ISSUE_OBSERVATIONS: Final[dict[tuple[IssueCheck, IssueStatus], tuple[str, str]]] = {
    ("sql-login", "locally-reproduced"): (
        "SQL injection bypasses the login boundary",
        "The true condition minted an authenticated session and the resulting session read "
        "multiple records from the protected user directory; the false condition did not.",
    ),
    ("sql-login", "not-reproduced"): (
        "SQL login bypass was not reproduced",
        "Across both controlled trials, the true condition did not establish a protected "
        "session while the false controls remained rejected.",
    ),
    ("sql-login", "inconclusive"): (
        "SQL login boundary diagnostic was inconclusive",
        "The source and replay outcomes or their false-condition controls did not support a "
        "stable login-bypass conclusion.",
    ),
    ("object-access", "locally-reproduced"): (
        "Authenticated sessions can read another account's basket",
        "The session obtained through the login injection read the distinct basket container "
        "owned by this run's disposable account. No unrelated account contents were selected.",
    ),
    ("object-access", "not-reproduced"): (
        "Cross-account basket access was not reproduced",
        "Across both controlled trials, the injected session did not return the disposable "
        "account's distinct basket while the own-object and missing-object controls passed.",
    ),
    ("object-access", "inconclusive"): (
        "Cross-account basket diagnostic was inconclusive",
        "The source and replay outcomes or their own-object and missing-object controls did not "
        "support a stable cross-account access conclusion.",
    ),
    ("dom-xss", "locally-reproduced"): (
        "Search input executes script in the application origin",
        "A crafted search route executed a same-origin marker that only set one DOM attribute; "
        "the plain-text control did not execute and no data was transmitted.",
    ),
    ("dom-xss", "not-reproduced"): (
        "Search-route script execution was not reproduced",
        "Across both controlled trials, the plain-text controls remained inert and the probes "
        "did not set the same-origin DOM marker.",
    ),
    ("dom-xss", "inconclusive"): (
        "Search-route script execution diagnostic was inconclusive",
        "The source and replay outcomes or their plain-text controls did not support a stable "
        "same-origin script-execution conclusion.",
    ),
}

_ATTACK_PATH_STAGE_SUMMARIES: Final[dict[tuple[str, AttackPathStageState], str]] = {
    ("unauthenticated-login-input", "observed"): (
        "The public login endpoint was exercised with controlled identity input."
    ),
    ("sql-authentication-bypass", "locally-reproduced"): (
        "A true SQL condition minted a session while the false control failed."
    ),
    ("sql-authentication-bypass", "potential"): (
        "The controlled trials did not reproduce a stable session-minting bypass."
    ),
    ("cross-account-basket-read", "locally-reproduced"): (
        "That injected session read the distinct basket created for the normal browser-login "
        "account."
    ),
    ("cross-account-basket-read", "potential"): (
        "The controlled trials did not reproduce stable access to the browser-login account's "
        "basket."
    ),
    ("crafted-search-route", "observed"): (
        "The SPA search route was exercised with controlled input."
    ),
    ("same-origin-script-execution", "locally-reproduced"): (
        "The probe changed only its dedicated DOM marker without transmission."
    ),
    ("same-origin-script-execution", "potential"): (
        "The controlled trials did not reproduce stable DOM-marker execution."
    ),
}

_ATTACK_PATH_OBSERVATIONS: Final[
    dict[tuple[tuple[str, ...], AttackPathStatus], tuple[str, str]]
] = {
    (
        (
            "unauthenticated-login-input",
            "sql-authentication-bypass",
            "cross-account-basket-read",
        ),
        "locally-validated",
    ): (
        "Unauthenticated login injection to cross-account basket access",
        "The full chain reached another account's basket container in the approved local lab.",
    ),
    (
        (
            "unauthenticated-login-input",
            "sql-authentication-bypass",
            "cross-account-basket-read",
        ),
        "incomplete",
    ): (
        "Login-injection to cross-account basket chain was incomplete",
        "The full chain was not reproduced in both controlled trials.",
    ),
    (
        ("crafted-search-route", "same-origin-script-execution"),
        "locally-validated",
    ): (
        "Crafted search URL to same-origin script execution",
        "Same-origin JavaScript execution was observed in the disposable browser context.",
    ),
    (
        ("crafted-search-route", "same-origin-script-execution"),
        "incomplete",
    ): (
        "Crafted search-route script-execution chain was incomplete",
        "Same-origin execution was not reproduced twice with passing controls.",
    ),
}


def issue_observation(check: IssueCheck, status: IssueStatus) -> tuple[str, str]:
    """Return the status-bound title and observed-impact text for one fixed check."""

    return _ISSUE_OBSERVATIONS[(check, status)]


def attack_path_stage_summary(stage_id: str, state: AttackPathStageState) -> str:
    """Return the state-bound summary for one code-owned attack-path stage."""

    try:
        return _ATTACK_PATH_STAGE_SUMMARIES[(stage_id, state)]
    except KeyError as error:
        raise ValueError("unsupported attack path stage or state") from error


def attack_path_observation(
    stage_ids: tuple[str, ...],
    status: AttackPathStatus,
) -> tuple[str, str]:
    """Return the status-bound title and observed impact for one fixed path shape."""

    try:
        return _ATTACK_PATH_OBSERVATIONS[(stage_ids, status)]
    except KeyError as error:
        raise ValueError("unsupported attack path shape or status") from error


def _require_relative_recipe_path(path: str) -> None:
    if (
        not path.startswith("/")
        or path.startswith("//")
        or "\\" in path
        or any(ord(char) < 32 for char in path)
    ):
        raise ValueError("recipes require origin-relative paths")


def local_origin(value: str) -> str:
    """Accept a literal loopback origin without DNS or implicit scope expansion."""
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "::1"}
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or any(ord(char) <= 32 or char == "\\" for char in value)
    ):
        raise ValueError("WEB-003 requires an exact numeric loopback HTTP(S) origin")
    port = parsed.port
    if port == 0:
        raise ValueError("WEB-003 does not allow origin port zero")
    host = "[::1]" if parsed.hostname == "::1" else "127.0.0.1"
    default_port = 443 if parsed.scheme == "https" else 80
    if port is not None and port != default_port:
        host += f":{port}"
    return urlunsplit((parsed.scheme, host, "", "", ""))


class Recipe(StrictModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class LoginRecipe(Recipe):
    route: str = Field(min_length=1, max_length=500)
    username_selector: str = Field(min_length=1, max_length=300)
    password_selector: str = Field(min_length=1, max_length=300)
    submit_selector: str = Field(min_length=1, max_length=300)
    activation_mode: LoginActivationMode | None = None
    success_selector: str = Field(min_length=1, max_length=300)
    success_activation_selector: str | None = Field(
        default=None,
        min_length=1,
        max_length=300,
    )
    success_activation_mode: LoginSuccessActivationMode | None = None
    endpoint: str = Field(min_length=1, max_length=500)
    username_field: str = "email"
    password_field: str = "password"
    token_path: str = "authentication.token"
    object_id_path: str = "authentication.bid"
    dismiss_selectors: tuple[str, ...] = Field(default=(), max_length=5)

    @model_validator(mode="after")
    def bind_success_activation(self) -> Self:
        if self.success_activation_mode is not None and self.success_activation_selector is None:
            raise ValueError("success activation mode requires a selector")
        return self


class RegistrationRecipe(Recipe):
    endpoint: str
    username_field: str = "email"
    password_field: str = "password"
    repeat_password_field: str | None = "passwordRepeat"
    extra_fields: dict[str, JsonValue] = Field(default_factory=dict, max_length=10)


class ObjectAccessRecipe(Recipe):
    endpoint_template: str = Field(min_length=1, max_length=500)
    object_path: str = "data"
    owner_field: str = "UserId"
    id_field: str = "id"


class SQLLoginRecipe(Recipe):
    true_expression: str = "' OR 1=1--"
    false_expression: str = "' AND 1=2--"
    impact_endpoint: str
    records_path: str = "data"
    record_id_field: str = "id"


class DOMXSSRecipe(Recipe):
    route_template: str = Field(min_length=1, max_length=500)
    ready_selector: str = Field(min_length=1, max_length=300)
    marker_attribute: Literal["data-pajin-xss"] = "data-pajin-xss"


class WebAssessmentPlan(Recipe):
    api_version: Literal["pajin.dev/local-web-assessment/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_API_VERSION,
    )
    name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    origin: str
    target_product: str = Field(
        default=DEFAULT_WEB_ASSESSMENT_TARGET_PRODUCT,
        min_length=1,
        max_length=100,
    )
    fingerprint_version_path: str = Field(
        default=DEFAULT_WEB_ASSESSMENT_FINGERPRINT_VERSION_PATH,
        min_length=1,
        max_length=500,
        pattern=r"^[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*$",
    )
    adapter_implementation_id: str = Field(
        default=DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
        min_length=1,
        max_length=200,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$",
    )
    fingerprint_endpoint: str = Field(default="/rest/admin/application-version", max_length=500)
    login: LoginRecipe
    registration: RegistrationRecipe | None = None
    routes: tuple[str, ...] = Field(min_length=1, max_length=20)
    route_ready_selectors: dict[str, str] = Field(default_factory=dict, max_length=20)
    navigation_selectors: tuple[str, ...] = Field(default=(), max_length=5)
    allowed_post_paths: tuple[str, ...] = Field(min_length=1, max_length=10)
    deny_paths: tuple[str, ...] = Field(default=(), max_length=20)
    sql_login: SQLLoginRecipe | None = None
    object_access: ObjectAccessRecipe | None = None
    dom_xss: DOMXSSRecipe | None = None
    max_pages: int = Field(default=8, ge=1, le=30, strict=True)
    duration_seconds: int = Field(default=300, ge=30, le=1800, strict=True)
    request_timeout_seconds: int = Field(default=12, ge=1, le=30, strict=True)
    max_response_bytes: int = Field(default=8_000_000, ge=1024, le=10_000_000, strict=True)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return local_origin(value)

    @field_validator("target_product")
    @classmethod
    def validate_target_product(cls, value: str) -> str:
        if value != value.strip():
            raise ValueError("target product identity must be canonical")
        return value

    @model_validator(mode="after")
    def validate_routes(self) -> Self:
        if (
            self.registration is None
            or self.sql_login is None
            or self.object_access is None
            or self.dom_xss is None
        ):
            raise ValueError("WEB-003 requires registration and all three bounded diagnostics")
        paths = [
            self.fingerprint_endpoint,
            self.login.route,
            self.login.endpoint,
            *self.routes,
            *self.allowed_post_paths,
            *self.deny_paths,
        ]
        if self.registration:
            paths.append(self.registration.endpoint)
        if self.sql_login:
            paths.append(self.sql_login.impact_endpoint)
        if self.object_access:
            if self.object_access.endpoint_template.count("{id}") != 1:
                raise ValueError("object endpoint requires exactly one {id}")
            paths.append(self.object_access.endpoint_template)
        if self.dom_xss:
            if self.dom_xss.route_template.count("{payload}") != 1:
                raise ValueError("XSS route requires exactly one {payload}")
            paths.append(self.dom_xss.route_template)
        for path in paths:
            _require_relative_recipe_path(path)
        if set(self.route_ready_selectors) != set(self.routes):
            raise ValueError("every navigation route requires exactly one ready selector")
        if any(
            not selector or len(selector) > 300 for selector in self.route_ready_selectors.values()
        ):
            raise ValueError("route ready selectors must contain 1 to 300 characters")
        if len(set(self.routes)) != len(self.routes):
            raise ValueError("navigation routes must be unique")
        if len(set(self.allowed_post_paths)) != len(self.allowed_post_paths):
            raise ValueError("allowed POST paths must be unique")
        required_posts = {self.login.endpoint}
        if self.registration:
            required_posts.add(self.registration.endpoint)
        if required_posts != set(self.allowed_post_paths):
            raise ValueError("only login and registration POST paths are allowed")
        return self

    @property
    def plan_digest(self) -> str:
        material = self.model_dump(mode="json", by_alias=True)
        legacy_defaults = {
            "target_product": DEFAULT_WEB_ASSESSMENT_TARGET_PRODUCT,
            "fingerprint_version_path": DEFAULT_WEB_ASSESSMENT_FINGERPRINT_VERSION_PATH,
            "adapter_implementation_id": DEFAULT_WEB_ASSESSMENT_ADAPTER_IMPLEMENTATION_ID,
        }
        for field, legacy_default in legacy_defaults.items():
            if material.get(field) == legacy_default:
                material.pop(field, None)
        login = material.get("login")
        if isinstance(login, dict):
            if login.get("activation_mode") is None:
                login.pop("activation_mode", None)
            if login.get("success_activation_mode") is None:
                login.pop("success_activation_mode", None)
        return discovery_digest(
            "pajin.web-assessment.plan/v1",
            material,
        )


class LocalWebAssessmentAuthorization(Recipe):
    """One short-lived operator assertion bound to an exact local plan."""

    api_version: Literal["pajin.dev/local-web-assessment-authorization/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_AUTHORIZATION_API_VERSION
    )
    authorization_id: str = Field(default="", max_length=110)
    plan_digest: str = Field(pattern=_SHA256_PATTERN)
    origin: str
    approved_at: datetime
    expires_at: datetime
    approval_method: Literal["explicit-cli-local-lab-confirmation"] = (
        "explicit-cli-local-lab-confirmation"
    )
    operator_attested_authorized: Literal[True] = True
    ephemeral_account_creation_allowed: Literal[True] = True
    checks: tuple[Literal["sql-login", "object-access", "dom-xss"], ...] = (
        "sql-login",
        "object-access",
        "dom-xss",
    )
    execution_authority_scope: Literal["exact-numeric-loopback-origin"] = (
        "exact-numeric-loopback-origin"
    )

    @field_validator("origin")
    @classmethod
    def validate_authorized_origin(cls, value: str) -> str:
        return local_origin(value)

    @field_validator("approved_at", "expires_at")
    @classmethod
    def normalize_authorization_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("assessment authorization timestamps require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "operator_attested_authorized",
        "ephemeral_account_creation_allowed",
        mode="before",
    )
    @classmethod
    def require_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("local assessment authorization markers must be true")
        return value

    @model_validator(mode="after")
    def bind_authorization(self) -> Self:
        if not self.approved_at < self.expires_at <= self.approved_at + timedelta(minutes=30):
            raise ValueError("local assessment authorization lifetime must be at most 30 minutes")
        if tuple(sorted(self.checks)) != ("dom-xss", "object-access", "sql-login"):
            raise ValueError("local assessment authorization must bind the exact three checks")
        material = self.model_dump(
            mode="json",
            by_alias=True,
            exclude={"authorization_id"},
        )
        digest = discovery_digest("pajin.web-assessment.authorization/v1", material)
        expected_id = f"web-assessment-authorization:{digest}"
        if self.authorization_id and self.authorization_id != expected_id:
            raise ValueError("local assessment authorization ID differs")
        object.__setattr__(self, "authorization_id", expected_id)
        return self

    def require_current(self, *, plan: WebAssessmentPlan, now: datetime) -> None:
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("authorization verification time requires an explicit UTC offset")
        if self.plan_digest != plan.plan_digest or self.origin != plan.origin:
            raise ValueError("local assessment authorization differs from the selected plan")
        if not self.approved_at <= now.astimezone(UTC) < self.expires_at:
            raise ValueError("local assessment authorization is not current")


class RequestEvidence(Recipe):
    evidence_id: str = Field(pattern=_REQUEST_EVIDENCE_ID_PATTERN)
    phase: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,79}$")
    method: Literal["GET", "HEAD", "POST"]
    path: str = Field(min_length=1, max_length=2_000)
    request_sha256: str = Field(pattern=_SHA256_PATTERN)
    status: int = Field(strict=True, ge=100, le=599)
    response_sha256: str = Field(pattern=_SHA256_PATTERN)
    response_bytes: int = Field(strict=True, ge=0, le=10_000_000)
    media_type: str = Field(max_length=100)

    @field_validator("path")
    @classmethod
    def validate_evidence_path(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value or "\\" in value:
            raise ValueError("request Evidence stores one origin-relative path without query data")
        return value


def request_evidence_digest(evidence: RequestEvidence) -> str:
    """Content-address one canonical generic request-evidence record."""

    canonical = RequestEvidence.model_validate(evidence.model_dump(mode="json", by_alias=True))
    return discovery_digest(
        "pajin.web-assessment.request-evidence/v1",
        canonical.model_dump(mode="json", by_alias=True),
    )


def request_evidence_sequence(evidence: RequestEvidence) -> int:
    """Return the monotonic reservation sequence encoded in a valid Evidence ID."""

    match = re.fullmatch(_REQUEST_EVIDENCE_ID_PATTERN, evidence.evidence_id)
    if match is None:  # pragma: no cover - RequestEvidence owns the same grammar
        raise ValueError("request Evidence ID is invalid")
    return int(match.group(1))


def passive_media_type_essence(value: str) -> str:
    """Return only a bounded canonical Content-Type essence for passive evidence."""

    essence = value.partition(";")[0].strip().lower()
    if (
        not essence
        or len(essence) > 100
        or not essence.isascii()
        or _MEDIA_TYPE_ESSENCE_PATTERN.fullmatch(essence) is None
    ):
        return ""
    return essence


class PassiveDiscoveryBoundaryReceipt(Recipe):
    """Observed request-boundary facts for one passive discovery response."""

    api_version: Literal["pajin.dev/passive-discovery-boundary-receipt/v1alpha1"] = Field(
        default=PASSIVE_DISCOVERY_BOUNDARY_RECEIPT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["PassiveDiscoveryBoundaryReceipt"] = "PassiveDiscoveryBoundaryReceipt"
    receipt_digest: str = Field(default="", alias="receiptDigest", max_length=64)
    evidence_id: str = Field(alias="evidenceId", pattern=_REQUEST_EVIDENCE_ID_PATTERN)
    request_evidence_digest: str = Field(
        alias="requestEvidenceDigest",
        pattern=_SHA256_PATTERN,
    )
    reservation_sequence: int = Field(
        alias="reservationSequence",
        strict=True,
        ge=1,
        le=500,
    )
    evidence_sequence: int = Field(
        alias="evidenceSequence",
        strict=True,
        ge=1,
        le=500,
    )
    canonical_origin: str = Field(alias="canonicalOrigin", strict=True)
    method: Literal["GET"]
    query_present: Literal[False] = Field(alias="queryPresent")
    request_bytes: int = Field(alias="requestBytes", strict=True, ge=0, le=64_000)
    redirect_hops: int = Field(alias="redirectHops", strict=True, ge=0, le=20)
    path: str = Field(min_length=1, max_length=2_000, strict=True)
    status: int = Field(strict=True, ge=100, le=599)
    observed_response_body_bytes: int = Field(
        alias="observedResponseBodyBytes",
        strict=True,
        ge=0,
        le=10_000_000,
    )
    retained_response_bytes: int = Field(
        alias="retainedResponseBytes",
        strict=True,
        ge=0,
        le=10_000_000,
    )
    retained_response_sha256: str = Field(
        alias="retainedResponseSha256",
        pattern=_SHA256_PATTERN,
    )
    media_type: str = Field(alias="mediaType", max_length=100, strict=True)

    @field_validator("canonical_origin")
    @classmethod
    def require_canonical_origin(cls, value: str) -> str:
        if local_origin(value) != value:
            raise ValueError("passive discovery receipt origin must be canonical")
        return value

    @field_validator("query_present", mode="before")
    @classmethod
    def require_query_absent(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("passive discovery receipt query marker must be boolean false")
        return value

    @field_validator("request_bytes", "redirect_hops", "retained_response_bytes", mode="before")
    @classmethod
    def require_exact_zero(cls, value: object) -> object:
        if type(value) is not int or value != 0:
            raise ValueError("passive discovery receipt boundary counters must be integer zero")
        return value

    @field_validator("path")
    @classmethod
    def require_query_free_path(cls, value: str) -> str:
        if not value.startswith("/") or "?" in value or "#" in value or "\\" in value:
            raise ValueError(
                "passive discovery receipt path must be origin-relative and query-free"
            )
        return value

    @field_validator("media_type")
    @classmethod
    def require_media_type_essence(cls, value: str) -> str:
        if passive_media_type_essence(value) != value:
            raise ValueError(
                "passive discovery receipt media type must be a canonical Content-Type essence"
            )
        return value

    @model_validator(mode="after")
    def bind_receipt(self) -> Self:
        sequence_match = re.fullmatch(
            _REQUEST_EVIDENCE_ID_PATTERN,
            self.evidence_id,
        )
        if sequence_match is None or int(sequence_match.group(1)) != self.evidence_sequence:
            raise ValueError("passive discovery receipt Evidence sequence differs")
        if self.reservation_sequence != self.evidence_sequence:
            raise ValueError("passive discovery receipt reservation sequence differs")
        if self.retained_response_sha256 != _EMPTY_SHA256:
            raise ValueError("passive discovery receipt retained response digest differs")
        material = self.model_dump(mode="json", by_alias=True, exclude={"receipt_digest"})
        expected = discovery_digest(
            "pajin.web-assessment.passive-discovery-boundary-receipt/v1",
            material,
        )
        if self.receipt_digest and self.receipt_digest != expected:
            raise ValueError("passive discovery boundary Receipt Digest differs")
        object.__setattr__(self, "receipt_digest", expected)
        return self


class BrowserPageEvidence(Recipe):
    evidence_id: str = Field(default="", max_length=110)
    phase: Literal[
        "authenticated-navigation",
        "dom-xss-control",
        "dom-xss-source",
        "dom-xss-replay",
    ]
    route: str = Field(min_length=1, max_length=500)
    title: str = Field(min_length=1, max_length=300)
    ready_selector: str = Field(min_length=1, max_length=300)
    dom_sha256: str = Field(pattern=_SHA256_PATTERN)
    dom_bytes: int = Field(strict=True, ge=1, le=2_000_000)
    screenshot_reference: str = Field(min_length=1, max_length=500)
    screenshot_sha256: str = Field(pattern=_SHA256_PATTERN)
    screenshot_bytes: int = Field(strict=True, ge=1, le=10_000_000)
    marker_executed: bool | None = None
    captured_at: datetime

    @field_validator("captured_at")
    @classmethod
    def normalize_capture_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("browser evidence timestamp requires an explicit UTC offset")
        return value.astimezone(UTC)

    @model_validator(mode="after")
    def bind_evidence(self) -> Self:
        material = self.model_dump(mode="json", exclude={"evidence_id"})
        digest = discovery_digest("pajin.web-assessment.browser-page/v1", material)
        expected_id = f"browser-page:{digest}"
        if self.evidence_id and self.evidence_id != expected_id:
            raise ValueError("browser page Evidence ID differs")
        object.__setattr__(self, "evidence_id", expected_id)
        return self


class BrowserSessionSummary(Recipe):
    authenticated: Literal[True]
    ephemeral_account_created: Literal[True]
    pages: tuple[BrowserPageEvidence, ...] = Field(min_length=2, max_length=32)
    requests_completed: int = Field(strict=True, ge=1, le=500)
    blocked_requests: dict[str, int] = Field(default_factory=dict, max_length=20)
    request_failures: dict[str, int] = Field(default_factory=dict, max_length=20)
    unexpected_console_error_fingerprints: tuple[str, ...] = Field(
        default=(),
        max_length=20,
    )
    browser_closed: Literal[True]

    @field_validator("authenticated", "ephemeral_account_created", "browser_closed", mode="before")
    @classmethod
    def require_session_true(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("completed browser session markers must be true")
        return value


class ProbeTrial(Recipe):
    check: IssueCheck
    repetition: Literal["source", "replay"]
    reproduced: bool = Field(strict=True)
    controls_passed: bool = Field(strict=True)
    evidence_ids: tuple[str, ...] = Field(max_length=20)
    facts: dict[str, JsonValue] = Field(max_length=30)


class AssessmentIssue(Recipe):
    issue_id: str = Field(pattern=r"^web-issue:[a-f0-9]{64}$")
    check: IssueCheck
    cwe: str = Field(pattern=r"^CWE-[1-9][0-9]{0,4}$")
    status: IssueStatus
    severity: Literal["high", "medium"]
    title: str
    observed_impact: str
    potential_impact: str
    remediation: str
    trials: tuple[ProbeTrial, ProbeTrial]
    finding_authority: Literal[False] = False

    @field_validator("finding_authority", mode="before")
    @classmethod
    def require_no_finding_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("local Web issues cannot claim confirmed Finding authority")
        return value

    @model_validator(mode="after")
    def validate_trials(self) -> Self:
        if tuple(trial.repetition for trial in self.trials) != ("source", "replay"):
            raise ValueError("local Web issues require ordered source and replay trials")
        if any(trial.check != self.check for trial in self.trials):
            raise ValueError("local Web issue and trial checks differ")
        if all(trial.reproduced and trial.controls_passed for trial in self.trials):
            expected_status = "locally-reproduced"
        elif all(not trial.reproduced and trial.controls_passed for trial in self.trials):
            expected_status = "not-reproduced"
        else:
            expected_status = "inconclusive"
        if self.status != expected_status:
            raise ValueError("local Web issue status differs from its controlled trials")
        expected_title, expected_observed_impact = issue_observation(
            self.check,
            self.status,
        )
        if self.title != expected_title or self.observed_impact != expected_observed_impact:
            raise ValueError("local Web issue narrative differs from its check and status")
        expected_id = "web-issue:" + discovery_digest(
            "pajin.web-assessment.issue/v1",
            {
                "check": self.check,
                "cwe": self.cwe,
                "trials": [trial.model_dump(mode="json") for trial in self.trials],
            },
        )
        if self.issue_id != expected_id:
            raise ValueError("local Web issue ID differs from its controlled trials")
        return self


class AttackPathStage(Recipe):
    ordinal: int = Field(strict=True, ge=1, le=8)
    stage_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,79}$")
    state: AttackPathStageState
    summary: str = Field(min_length=1, max_length=1_000)
    issue_id: str | None = Field(default=None, pattern=r"^web-issue:[a-f0-9]{64}$")
    evidence_ids: tuple[str, ...] = Field(default=(), max_length=20)

    @model_validator(mode="after")
    def bind_stage(self) -> Self:
        if self.state == "observed" and self.issue_id is not None:
            raise ValueError("observed attack path stages cannot claim a local issue")
        if self.state != "observed" and self.issue_id is None:
            raise ValueError("diagnostic attack path stages require a local issue")
        expected_summary = attack_path_stage_summary(self.stage_id, self.state)
        if self.summary != expected_summary:
            raise ValueError("attack path stage summary differs from its state")
        return self


class AttackPath(Recipe):
    path_id: str = Field(default="", max_length=110)
    title: str = Field(min_length=1, max_length=300)
    status: AttackPathStatus
    stages: tuple[AttackPathStage, ...] = Field(min_length=2, max_length=8)
    observed_impact: str = Field(min_length=1, max_length=2_000)
    potential_impact: str = Field(min_length=1, max_length=2_000)
    finding_authority: Literal[False] = False

    @field_validator("finding_authority", mode="before")
    @classmethod
    def require_no_path_finding_authority(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("local attack paths cannot claim confirmed Finding authority")
        return value

    @model_validator(mode="after")
    def bind_path(self) -> Self:
        ordinals = [stage.ordinal for stage in self.stages]
        if ordinals != list(range(1, len(self.stages) + 1)):
            raise ValueError("attack path stages must be consecutive and ordered")
        stage_ids = [stage.stage_id for stage in self.stages]
        if len(stage_ids) != len(set(stage_ids)):
            raise ValueError("attack path stage IDs must be unique")
        diagnostic_stages = [stage for stage in self.stages if stage.issue_id is not None]
        if not diagnostic_stages:
            raise ValueError("attack paths require at least one issue-bound diagnostic stage")
        expected_status: AttackPathStatus = (
            "locally-validated"
            if all(stage.state == "locally-reproduced" for stage in diagnostic_stages)
            else "incomplete"
        )
        if self.status != expected_status:
            raise ValueError("attack path status differs from its stage states")
        expected_title, expected_observed_impact = attack_path_observation(
            tuple(stage.stage_id for stage in self.stages),
            self.status,
        )
        if self.title != expected_title or self.observed_impact != expected_observed_impact:
            raise ValueError("attack path narrative differs from its shape and status")
        material = self.model_dump(mode="json", exclude={"path_id"})
        digest = discovery_digest("pajin.web-assessment.attack-path/v1", material)
        expected_id = f"web-attack-path:{digest}"
        if self.path_id and self.path_id != expected_id:
            raise ValueError("local attack path ID differs")
        object.__setattr__(self, "path_id", expected_id)
        return self


def _validate_attack_path_lineage(
    attack_paths: tuple[AttackPath, ...],
    issues_by_id: dict[str, AssessmentIssue],
    evidence_id_set: set[str],
) -> None:
    issue_ids = set(issues_by_id)
    path_issue_checks: list[tuple[IssueCheck, ...]] = []
    for path in attack_paths:
        referenced_checks: list[IssueCheck] = []
        for stage in path.stages:
            if stage.issue_id is not None and stage.issue_id not in issue_ids:
                raise ValueError("attack path references an unknown local issue")
            if stage.issue_id is not None:
                referenced_issue = issues_by_id[stage.issue_id]
                referenced_checks.append(referenced_issue.check)
                expected_stage_state = (
                    "locally-reproduced"
                    if referenced_issue.status == "locally-reproduced"
                    else "potential"
                )
                if stage.state != expected_stage_state:
                    raise ValueError(
                        "attack path stage state differs from its referenced local issue"
                    )
            if any(item not in evidence_id_set for item in stage.evidence_ids):
                raise ValueError("attack path references unknown Evidence")
        path_issue_checks.append(tuple(referenced_checks))
    if tuple(path_issue_checks) != (
        ("sql-login", "object-access"),
        ("dom-xss",),
    ):
        raise ValueError("attack path issue sequence differs from the fixed diagnostic flow")


class LocalWebAssessmentResult(Recipe):
    api_version: Literal["pajin.dev/local-web-assessment-result/v1alpha1"] = Field(
        default=WEB_ASSESSMENT_RESULT_API_VERSION
    )
    result_digest: str = Field(default="", max_length=64)
    run_id: str = Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    plan_name: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,79}$")
    plan_digest: str = Field(pattern=_SHA256_PATTERN)
    authorization_id: str = Field(min_length=1, max_length=110)
    origin: str
    target_product: str = Field(min_length=1, max_length=100)
    target_version: str = Field(min_length=1, max_length=100)
    started_at: datetime
    finished_at: datetime
    browser: BrowserSessionSummary
    requests: tuple[RequestEvidence, ...] = Field(min_length=1, max_length=500)
    discovery_evidence_reference: Literal["discovery-evidence.json"] | None = None
    discovery_evidence_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    issues: tuple[AssessmentIssue, ...] = Field(min_length=1, max_length=20)
    attack_paths: tuple[AttackPath, ...] = Field(min_length=1, max_length=20)
    account_retained_in_local_lab: Literal[True]
    credentials_persisted: Literal[False] = False
    external_delivery_performed: Literal[False] = False
    finding_authority: Literal[False] = False

    @field_validator("origin")
    @classmethod
    def validate_result_origin(cls, value: str) -> str:
        return local_origin(value)

    @field_validator("started_at", "finished_at")
    @classmethod
    def normalize_result_time(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("assessment result timestamps require an explicit UTC offset")
        return value.astimezone(UTC)

    @field_validator(
        "account_retained_in_local_lab",
        mode="before",
    )
    @classmethod
    def require_retained_account_marker(cls, value: object) -> object:
        if type(value) is not bool or value is not True:
            raise ValueError("completed local assessment must disclose retained test state")
        return value

    @field_validator(
        "credentials_persisted",
        "external_delivery_performed",
        "finding_authority",
        mode="before",
    )
    @classmethod
    def require_false_markers(cls, value: object) -> object:
        if type(value) is not bool or value is not False:
            raise ValueError("local assessment non-authority markers must be false")
        return value

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        if self.finished_at < self.started_at:
            raise ValueError("assessment result time order differs")
        if (self.discovery_evidence_reference is None) != (self.discovery_evidence_digest is None):
            raise ValueError(
                "assessment discovery Evidence reference and digest must be present together"
            )
        has_passive_requests = any(
            request.phase == "browser-passive-discovery" for request in self.requests
        )
        if (self.discovery_evidence_reference is not None) != has_passive_requests:
            raise ValueError(
                "assessment passive requests and discovery Evidence must be present together"
            )
        if tuple(issue.check for issue in self.issues) != (
            "sql-login",
            "object-access",
            "dom-xss",
        ):
            raise ValueError("assessment result requires the three ordered diagnostic checks")
        evidence_ids = [request.evidence_id for request in self.requests]
        evidence_ids.extend(page.evidence_id for page in self.browser.pages)
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("assessment Evidence IDs must be unique")
        evidence_id_set = set(evidence_ids)
        issues_by_id = {issue.issue_id: issue for issue in self.issues}
        issue_ids = set(issues_by_id)
        if len(issue_ids) != len(self.issues):
            raise ValueError("assessment issue IDs must be unique")
        for issue in self.issues:
            if any(
                evidence_id not in evidence_id_set
                for trial in issue.trials
                for evidence_id in trial.evidence_ids
            ):
                raise ValueError("assessment trial references unknown Evidence")
        _validate_attack_path_lineage(self.attack_paths, issues_by_id, evidence_id_set)
        if self.browser.requests_completed > len(self.requests):
            raise ValueError("browser request count exceeds total HTTP Evidence")
        material = self.model_dump(mode="json", by_alias=True, exclude={"result_digest"})
        if self.discovery_evidence_reference is None:
            # Preserve the v1alpha1 digest of historical Runs that predate the optional,
            # content-addressed passive-discovery sidecar.
            material.pop("discovery_evidence_reference", None)
            material.pop("discovery_evidence_digest", None)
        digest = discovery_digest("pajin.web-assessment.result/v1", material)
        if self.result_digest and self.result_digest != digest:
            raise ValueError("local assessment Result Digest differs")
        object.__setattr__(self, "result_digest", digest)
        return self


def json_at(value: object, path: str) -> object:
    current = value
    for key in path.split(".") if path else []:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current
