"""Bounded, passive browser route and form discovery for exact loopback origins.

This module deliberately stops at structural observation. It follows only query-free,
same-origin ``a`` and ``area`` targets through ``page.goto``. An optional code-owned
authentication sentinel activation may open and close a non-submitting UI control; discovered
controls are never activated. The module never submits a form, reads a form value, captures a
screenshot, or retains raw DOM.
"""

from __future__ import annotations

import asyncio
import re
from collections import Counter, deque
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Literal, Protocol, Self, cast
from urllib.parse import unquote, urljoin, urlsplit

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import discovery_digest
from pajin.domain.models import StrictModel
from pajin.web_assessment.models import local_origin

BROWSER_DISCOVERY_PLAN_API_VERSION: Final[
    Literal["pajin.dev/local-web-browser-discovery/v1alpha1"]
] = "pajin.dev/local-web-browser-discovery/v1alpha1"
BROWSER_DISCOVERY_RESULT_API_VERSION: Final[
    Literal["pajin.dev/local-web-browser-discovery-result/v1alpha1"]
] = "pajin.dev/local-web-browser-discovery-result/v1alpha1"

_PERCENT_ESCAPE = re.compile(r"%[0-9A-Fa-f]{2}")
_INVALID_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_ENCODED_AMBIGUOUS_DELIMITER = re.compile(r"%(?:00|23|2f|3f|5c)", re.IGNORECASE)
_SAFE_FIELD_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-\[\]]{0,199}$")
_REJECTION_KEY = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_URI_REFERENCE = re.compile(r"^[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]+$")
_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_EMAIL_PATH_SEGMENT = re.compile(
    r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$"
)
_UUID_PATH_SEGMENT = re.compile(
    r"^[A-Fa-f0-9]{8}-[A-Fa-f0-9]{4}-[A-Fa-f0-9]{4}-"
    r"[A-Fa-f0-9]{4}-[A-Fa-f0-9]{12}$"
)
_JWT_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$")
_OPAQUE_HEX_PATH_SEGMENT = re.compile(r"^[A-Fa-f0-9]{24,}$")
_OPAQUE_URLSAFE_PATH_SEGMENT = re.compile(r"^[A-Za-z0-9_-]{32,}$")

_SENSITIVE_PATH_WORDS: Final[frozenset[str]] = frozenset(
    {
        "account",
        "accounts",
        "admin",
        "administrator",
        "basket",
        "baskets",
        "billing",
        "cart",
        "carts",
        "checkout",
        "delete",
        "destroy",
        "disable",
        "drop",
        "logout",
        "order",
        "orders",
        "password",
        "passwords",
        "passwd",
        "payment",
        "payments",
        "purge",
        "remove",
        "revoke",
        "signout",
        "terminate",
    }
)

_CANDIDATE_REJECTIONS: Final[frozenset[str]] = frozenset(
    {
        "ambiguous-url",
        "candidate-too-long",
        "depth-limit",
        "empty-target",
        "external-origin",
        "field-limit",
        "form-limit",
        "link-limit",
        "numeric-object-route",
        "query-values",
        "route-limit",
        "sensitive-path",
        "unsafe-scheme",
        "url-credentials",
        "value-bearing-path",
    }
)

RouteSource = Literal["anchor", "area", "seed"]
FormActionDisposition = Literal[
    "ambiguous-url",
    "candidate-too-long",
    "external-origin",
    "non-navigation-method",
    "numeric-object-route",
    "query-values",
    "same-origin",
    "sensitive-path",
    "unsafe-scheme",
    "url-credentials",
    "value-bearing-path",
]
ControlTag = Literal["button", "input", "other", "select", "textarea"]
ControlType = Literal[
    "button",
    "checkbox",
    "color",
    "date",
    "datetime-local",
    "email",
    "file",
    "hidden",
    "image",
    "month",
    "number",
    "other",
    "password",
    "radio",
    "range",
    "reset",
    "search",
    "select",
    "submit",
    "tel",
    "text",
    "textarea",
    "time",
    "url",
    "week",
]
AutocompleteRole = Literal[
    "current-password",
    "email",
    "name",
    "new-password",
    "none",
    "off",
    "on",
    "one-time-code",
    "organization",
    "other",
    "tel",
    "username",
]

_CONTROL_TYPES: Final[frozenset[str]] = frozenset(
    {
        "button",
        "checkbox",
        "color",
        "date",
        "datetime-local",
        "email",
        "file",
        "hidden",
        "image",
        "month",
        "number",
        "password",
        "radio",
        "range",
        "reset",
        "search",
        "submit",
        "tel",
        "text",
        "time",
        "url",
        "week",
    }
)
_AUTOCOMPLETE_ROLES: Final[frozenset[str]] = frozenset(
    {
        "current-password",
        "email",
        "name",
        "new-password",
        "off",
        "on",
        "one-time-code",
        "organization",
        "tel",
        "username",
    }
)


class BrowserDiscoveryError(RuntimeError):
    """The passive discovery engine could not produce a safe bounded result."""


class BrowserDiscoveryBoundaryError(BrowserDiscoveryError):
    """A navigation escaped or drifted from the pre-validated exact route."""


class BrowserDiscoveryPage(Protocol):
    """The small Playwright Page surface required by passive discovery."""

    @property
    def url(self) -> str: ...

    async def goto(
        self,
        url: str,
        *,
        wait_until: Literal["domcontentloaded"],
        timeout: float,
    ) -> object | None: ...

    async def wait_for_timeout(self, timeout: float) -> None: ...

    async def evaluate(self, expression: str, arg: object | None = None) -> object: ...


class BrowserDiscoveryLocator(Protocol):
    """The locator operation used only for an optional code-owned auth sentinel."""

    async def wait_for(
        self,
        *,
        state: Literal["attached", "visible"],
        timeout: float,
    ) -> None: ...

    async def click(self, *, timeout: float) -> None: ...

    async def press(self, key: str, *, timeout: float) -> None: ...


class BrowserDiscoveryKeyboard(Protocol):
    """The one dismissal operation allowed after a code-owned sentinel activation."""

    async def press(self, key: Literal["Escape"]) -> None: ...


class BrowserDiscoverySentinelPage(Protocol):
    """Optional Page surface required only by authentication-sentinel plans."""

    def locator(self, selector: str) -> BrowserDiscoveryLocator: ...

    @property
    def keyboard(self) -> BrowserDiscoveryKeyboard: ...


class BrowserDiscoveryModel(StrictModel):
    """Frozen base for the serialized passive-discovery boundary."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True, frozen=True)


class BrowserDiscoveryPlan(BrowserDiscoveryModel):
    """One deterministic passive crawl plan for an exact numeric loopback origin."""

    api_version: Literal["pajin.dev/local-web-browser-discovery/v1alpha1"] = Field(
        default=BROWSER_DISCOVERY_PLAN_API_VERSION
    )
    plan_digest: str = Field(default="", max_length=64)
    origin: str
    seed_routes: tuple[str, ...] = Field(default=("/",), min_length=1, max_length=8)
    authentication_sentinel_selector: str | None = Field(
        default=None,
        alias="authenticationSentinelSelector",
        min_length=1,
        max_length=300,
    )
    authentication_sentinel_activation_selector: str | None = Field(
        default=None,
        alias="authenticationSentinelActivationSelector",
        min_length=1,
        max_length=300,
    )
    authentication_sentinel_activation_mode: Literal["click", "enter"] | None = Field(
        default=None,
        alias="authenticationSentinelActivationMode",
    )
    max_routes: int = Field(default=20, ge=1, le=30, strict=True)
    max_depth: int = Field(default=2, ge=0, le=4, strict=True)
    max_links_per_page: int = Field(default=100, ge=1, le=200, strict=True)
    max_forms: int = Field(default=50, ge=1, le=100, strict=True)
    max_fields_per_form: int = Field(default=32, ge=1, le=64, strict=True)
    max_total_fields: int = Field(default=256, ge=1, le=512, strict=True)
    navigation_timeout_milliseconds: int = Field(default=12_000, ge=1_000, le=30_000, strict=True)
    settle_milliseconds: int = Field(default=250, ge=0, le=2_000, strict=True)

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        try:
            return local_origin(value)
        except ValueError as exc:
            raise ValueError(
                "browser discovery requires an exact numeric loopback HTTP(S) origin"
            ) from exc

    @field_validator(
        "authentication_sentinel_selector",
        "authentication_sentinel_activation_selector",
    )
    @classmethod
    def validate_authentication_selector(cls, value: str | None) -> str | None:
        if value is not None and (
            value != value.strip() or any(ord(character) < 0x20 for character in value)
        ):
            raise ValueError("browser discovery authentication sentinel selector is invalid")
        return value

    @model_validator(mode="after")
    def bind_plan(self) -> Self:
        if (
            self.authentication_sentinel_activation_selector is not None
            and self.authentication_sentinel_selector is None
        ):
            raise ValueError("browser discovery sentinel activation requires a sentinel")
        if (
            self.authentication_sentinel_activation_mode is not None
            and self.authentication_sentinel_activation_selector is None
        ):
            raise ValueError("browser discovery sentinel activation mode requires a selector")
        if self.seed_routes != tuple(sorted(set(self.seed_routes))):
            raise ValueError("browser discovery seed routes must be unique and sorted")
        for route in self.seed_routes:
            decision = _classify_target(route, base_url=self.origin + "/", origin=self.origin)
            if decision.route is None or decision.route != route:
                raise ValueError("browser discovery seed route is unsafe or noncanonical")
        if self.max_total_fields < self.max_fields_per_form:
            raise ValueError("total browser discovery field limit cannot be smaller than one form")
        material = self.model_dump(mode="json", exclude={"plan_digest"})
        for optional_field in (
            "authentication_sentinel_selector",
            "authentication_sentinel_activation_selector",
            "authentication_sentinel_activation_mode",
        ):
            if material.get(optional_field) is None:
                material.pop(optional_field, None)
        expected = discovery_digest("pajin.web-assessment.browser-discovery-plan/v1", material)
        if self.plan_digest and self.plan_digest != expected:
            raise ValueError("browser discovery Plan Digest differs")
        object.__setattr__(self, "plan_digest", expected)
        return self


class DiscoveredBrowserRoute(BrowserDiscoveryModel):
    """One visited query-free route with bounded discovery lineage."""

    route_id: str = Field(default="", max_length=110)
    structure_digest: str = Field(default="", max_length=64)
    route: str = Field(min_length=1, max_length=2_000)
    depth: int = Field(ge=0, le=4, strict=True)
    source: RouteSource
    discovered_from_route_id: str | None = Field(default=None, max_length=110)

    @model_validator(mode="after")
    def bind_route(self) -> Self:
        _require_serialized_route(self.route)
        if self.source == "seed" and self.discovered_from_route_id is not None:
            raise ValueError("seed browser routes cannot name a parent route")
        if self.source != "seed" and self.discovered_from_route_id is None:
            raise ValueError("discovered browser routes require a parent route")
        if (self.source == "seed") != (self.depth == 0):
            raise ValueError("browser route source differs from its discovery depth")
        material = {"route": self.route}
        expected_digest = discovery_digest(
            "pajin.web-assessment.browser-route-structure/v1", material
        )
        expected_id = f"browser-route:{expected_digest}"
        if self.structure_digest and self.structure_digest != expected_digest:
            raise ValueError("browser route Structure Digest differs")
        if self.route_id and self.route_id != expected_id:
            raise ValueError("browser route ID differs")
        object.__setattr__(self, "structure_digest", expected_digest)
        object.__setattr__(self, "route_id", expected_id)
        return self


class DiscoveredFormControl(BrowserDiscoveryModel):
    """Value-free structural metadata for one HTML form-associated control."""

    ordinal: int = Field(ge=0, le=1_000_000, strict=True)
    tag: ControlTag
    control_type: ControlType
    name: str | None = Field(default=None, min_length=1, max_length=200)
    name_omitted: bool = Field(default=False, strict=True)
    autocomplete_role: AutocompleteRole = "none"
    required: bool = Field(strict=True)
    disabled: bool = Field(strict=True)
    read_only: bool = Field(strict=True)
    multiple: bool = Field(strict=True)

    @field_validator("name")
    @classmethod
    def validate_name(cls, value: str | None) -> str | None:
        if value is not None and _SAFE_FIELD_NAME.fullmatch(value) is None:
            raise ValueError("retained browser form field name is not structural")
        return value

    @model_validator(mode="after")
    def bind_name_state(self) -> Self:
        if self.name_omitted != (self.name is None):
            raise ValueError("retained browser form field name omission marker differs")
        return self


class DiscoveredBrowserForm(BrowserDiscoveryModel):
    """One passive, value-free form description. It is never executable authority."""

    form_id: str = Field(default="", max_length=110)
    structure_digest: str = Field(default="", max_length=64)
    route_id: str = Field(pattern=r"^browser-route:[a-f0-9]{64}$")
    document_ordinal: int = Field(ge=0, le=1_000_000, strict=True)
    method: Literal["DIALOG", "GET", "POST", "UNKNOWN"]
    action_route: str | None = Field(default=None, min_length=1, max_length=2_000)
    action_disposition: FormActionDisposition
    encoding: Literal[
        "application/x-www-form-urlencoded", "multipart/form-data", "other", "text/plain"
    ]
    controls: tuple[DiscoveredFormControl, ...] = Field(default=(), max_length=64)
    observed_control_count: int = Field(ge=0, le=1_000_000, strict=True)
    controls_truncated: bool = Field(strict=True)
    submission_performed: Literal[False] = False

    @model_validator(mode="after")
    def bind_form(self) -> Self:
        if self.action_disposition == "same-origin":
            if self.action_route is None:
                raise ValueError("same-origin browser form action requires a route")
            _require_serialized_route(self.action_route)
        elif self.action_route is not None:
            raise ValueError("rejected browser form actions cannot retain a route")
        if self.method == "DIALOG" and self.action_disposition != "non-navigation-method":
            raise ValueError("dialog forms cannot claim a navigable action")
        if self.observed_control_count < len(self.controls):
            raise ValueError("browser form control count is smaller than retained controls")
        if self.controls_truncated != (self.observed_control_count > len(self.controls)):
            raise ValueError("browser form truncation marker differs from its controls")
        ordinals = [control.ordinal for control in self.controls]
        if ordinals != sorted(ordinals) or len(ordinals) != len(set(ordinals)):
            raise ValueError("browser form controls must be uniquely ordered")
        material = self.model_dump(
            mode="json",
            exclude={"form_id", "structure_digest", "submission_performed"},
        )
        expected_digest = discovery_digest(
            "pajin.web-assessment.browser-form-structure/v1", material
        )
        expected_id = f"browser-form:{expected_digest}"
        if self.structure_digest and self.structure_digest != expected_digest:
            raise ValueError("browser form Structure Digest differs")
        if self.form_id and self.form_id != expected_id:
            raise ValueError("browser form ID differs")
        object.__setattr__(self, "structure_digest", expected_digest)
        object.__setattr__(self, "form_id", expected_id)
        return self


class BrowserDiscoveryResult(BrowserDiscoveryModel):
    """Deterministic output from one bounded passive traversal."""

    api_version: Literal["pajin.dev/local-web-browser-discovery-result/v1alpha1"] = Field(
        default=BROWSER_DISCOVERY_RESULT_API_VERSION
    )
    result_digest: str = Field(default="", max_length=64)
    plan_digest: str = Field(pattern=r"^[a-f0-9]{64}$")
    origin: str
    routes: tuple[DiscoveredBrowserRoute, ...] = Field(min_length=1, max_length=30)
    forms: tuple[DiscoveredBrowserForm, ...] = Field(default=(), max_length=100)
    rejected_candidates: dict[str, int] = Field(default_factory=dict, max_length=32)
    route_limit_reached: bool = Field(strict=True)
    form_limit_reached: bool = Field(strict=True)
    field_limit_reached: bool = Field(strict=True)
    raw_dom_retained: Literal[False] = False
    screenshots_retained: Literal[False] = False
    form_values_retained: Literal[False] = False
    forms_submitted: Literal[False] = False
    external_delivery_performed: Literal[False] = False
    graph_admission_authority: Literal[False] = False
    finding_authority: Literal[False] = False
    execution_authority: Literal[False] = False

    @field_validator("origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return local_origin(value)

    @field_validator("rejected_candidates")
    @classmethod
    def validate_rejections(cls, value: dict[str, int]) -> dict[str, int]:
        if list(value) != sorted(value):
            raise ValueError("browser discovery rejection categories must be sorted")
        for key, count in value.items():
            if (
                _REJECTION_KEY.fullmatch(key) is None
                or key not in _CANDIDATE_REJECTIONS
                or type(count) is not int
                or count < 1
            ):
                raise ValueError("browser discovery rejection summary is invalid")
        return value

    @model_validator(mode="after")
    def bind_result(self) -> Self:
        route_order = [(route.depth, route.route) for route in self.routes]
        if route_order != sorted(route_order):
            raise ValueError("browser discovery routes must be in deterministic BFS order")
        route_ids = [route.route_id for route in self.routes]
        if len(route_ids) != len(set(route_ids)):
            raise ValueError("browser discovery route IDs must be unique")
        known_routes = {route.route_id: route for route in self.routes}
        route_positions = {route_id: index for index, route_id in enumerate(route_ids)}
        for index, route in enumerate(self.routes):
            parent_id = route.discovered_from_route_id
            if parent_id is None:
                continue
            parent = known_routes.get(parent_id)
            if (
                parent is None
                or route_positions[parent_id] >= index
                or parent.depth + 1 != route.depth
            ):
                raise ValueError("browser discovery route lineage is invalid")
        form_order = [(form.route_id, form.document_ordinal, form.form_id) for form in self.forms]
        if form_order != sorted(form_order):
            raise ValueError("browser discovery forms must be deterministically ordered")
        form_ids = [form.form_id for form in self.forms]
        if len(form_ids) != len(set(form_ids)):
            raise ValueError("browser discovery form IDs must be unique")
        form_locations = [(form.route_id, form.document_ordinal) for form in self.forms]
        if len(form_locations) != len(set(form_locations)):
            raise ValueError("browser discovery form locations must be unique")
        if any(form.route_id not in known_routes for form in self.forms):
            raise ValueError("browser discovery form references an unknown route")
        if self.route_limit_reached != ("route-limit" in self.rejected_candidates):
            raise ValueError("browser discovery route-limit marker differs")
        if self.form_limit_reached != ("form-limit" in self.rejected_candidates):
            raise ValueError("browser discovery form-limit marker differs")
        if self.field_limit_reached != ("field-limit" in self.rejected_candidates):
            raise ValueError("browser discovery field-limit marker differs")
        material = self.model_dump(mode="json", exclude={"result_digest"})
        expected = discovery_digest("pajin.web-assessment.browser-discovery-result/v1", material)
        if self.result_digest and self.result_digest != expected:
            raise ValueError("browser discovery Result Digest differs")
        object.__setattr__(self, "result_digest", expected)
        return self


class _RawLink(StrictModel):
    kind: Literal["anchor", "area"]
    href: str = Field(max_length=2_001)
    href_truncated: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_truncation(self) -> Self:
        if not self.href_truncated and len(self.href) > 2_000:
            raise ValueError("browser link truncation marker differs")
        return self


class _RawControl(StrictModel):
    ordinal: int = Field(ge=0, le=1_000_000, strict=True)
    tag: str = Field(max_length=20)
    control_type: str = Field(max_length=100)
    name: str | None = Field(default=None, max_length=201)
    name_truncated: bool = Field(strict=True)
    autocomplete: str = Field(max_length=101)
    required: bool = Field(strict=True)
    disabled: bool = Field(strict=True)
    read_only: bool = Field(strict=True)
    multiple: bool = Field(strict=True)

    @model_validator(mode="after")
    def validate_truncation(self) -> Self:
        if not self.name_truncated and self.name is not None and len(self.name) > 200:
            raise ValueError("browser form field-name truncation marker differs")
        return self


class _RawForm(StrictModel):
    document_ordinal: int = Field(ge=0, le=1_000_000, strict=True)
    action: str = Field(max_length=2_001)
    action_truncated: bool = Field(strict=True)
    method: str = Field(max_length=20)
    encoding: str = Field(max_length=100)
    controls: tuple[_RawControl, ...] = Field(default=(), max_length=65)
    observed_control_count: int = Field(ge=0, le=1_000_000, strict=True)

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if not self.action_truncated and len(self.action) > 2_000:
            raise ValueError("browser form action truncation marker differs")
        if self.observed_control_count < len(self.controls):
            raise ValueError("browser form observed control count is invalid")
        if [control.ordinal for control in self.controls] != list(range(len(self.controls))):
            raise ValueError("browser form control ordinals are invalid")
        return self


class _RawSnapshot(StrictModel):
    links: tuple[_RawLink, ...] = Field(default=(), max_length=201)
    observed_link_count: int = Field(ge=0, le=1_000_000, strict=True)
    forms: tuple[_RawForm, ...] = Field(default=(), max_length=101)
    observed_form_count: int = Field(ge=0, le=1_000_000, strict=True)

    @model_validator(mode="after")
    def validate_shape(self) -> Self:
        if self.observed_link_count < len(self.links):
            raise ValueError("browser observed link count is invalid")
        if self.observed_form_count < len(self.forms):
            raise ValueError("browser observed form count is invalid")
        if [form.document_ordinal for form in self.forms] != list(range(len(self.forms))):
            raise ValueError("browser form ordinals are invalid")
        return self


@dataclass(frozen=True, slots=True)
class _TargetDecision:
    route: str | None
    rejection: str | None


@dataclass(frozen=True, slots=True)
class _QueuedRoute:
    route: str
    depth: int
    source: RouteSource
    parent_route_id: str | None


_DISCOVERY_SCRIPT: Final[str] = r"""
({ maxLinks, maxForms, maxFieldsPerForm }) => {
  const links = [];
  const linkNodes = document.links;
  const linkLimit = Math.min(linkNodes.length, maxLinks + 1);
  for (let index = 0; index < linkLimit; index += 1) {
    const element = linkNodes[index];
    const rawHref = element.getAttribute('href') || '';
    links.push({
      kind: element.tagName.toLowerCase() === 'area' ? 'area' : 'anchor',
      href: rawHref.slice(0, 2001),
      href_truncated: rawHref.length > 2000,
    });
  }

  const forms = [];
  const formNodes = document.forms;
  const formLimit = Math.min(formNodes.length, maxForms + 1);
  for (let formIndex = 0; formIndex < formLimit; formIndex += 1) {
    const form = formNodes[formIndex];
    const rawAction = form.getAttribute('action') || '';
    const controls = [];
    const controlLimit = Math.min(form.elements.length, maxFieldsPerForm + 1);
    for (let controlIndex = 0; controlIndex < controlLimit; controlIndex += 1) {
      const control = form.elements[controlIndex];
      const rawName = control.getAttribute && control.getAttribute('name');
      const rawAutocomplete = control.getAttribute && control.getAttribute('autocomplete');
      const rawType = control.getAttribute && control.getAttribute('type');
      controls.push({
        ordinal: controlIndex,
        tag: (control.tagName || '').toLowerCase().slice(0, 20),
        control_type: (rawType || '').toLowerCase().slice(0, 100),
        name: rawName === null ? null : rawName.slice(0, 201),
        name_truncated: rawName !== null && rawName.length > 200,
        autocomplete: (rawAutocomplete || '').toLowerCase().slice(0, 101),
        required: control.required === true,
        disabled: control.disabled === true,
        read_only: control.readOnly === true,
        multiple: control.multiple === true,
      });
    }
    forms.push({
      document_ordinal: formIndex,
      action: rawAction.slice(0, 2001),
      action_truncated: rawAction.length > 2000,
      method: (form.getAttribute('method') || 'get').toLowerCase().slice(0, 20),
      encoding: (form.enctype || 'application/x-www-form-urlencoded').toLowerCase().slice(0, 100),
      controls,
      observed_control_count: Math.min(form.elements.length, 1000000),
    });
  }
  return {
    links,
    observed_link_count: Math.min(linkNodes.length, 1000000),
    forms,
    observed_form_count: Math.min(formNodes.length, 1000000),
  };
}
"""


def _origin_key(value: str) -> tuple[str, str, int]:
    parsed = urlsplit(value)
    if parsed.hostname is None:
        raise ValueError("URL has no host")
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname.lower(), parsed.port or default_port


def _looks_like_value_bearing_path_segment(segment: str) -> bool:
    """Reject identifiers that are likely to contain account or secret material.

    The checks deliberately require a whole-segment structural match. This keeps ordinary
    descriptive routes and human-readable hyphenated slugs usable while excluding common
    bearer-token and object-identifier shapes from both traversal and serialized evidence.
    """

    if (
        _EMAIL_PATH_SEGMENT.fullmatch(segment) is not None
        or _UUID_PATH_SEGMENT.fullmatch(segment) is not None
        or _JWT_PATH_SEGMENT.fullmatch(segment) is not None
        or _OPAQUE_HEX_PATH_SEGMENT.fullmatch(segment) is not None
    ):
        return True
    if _OPAQUE_URLSAFE_PATH_SEGMENT.fullmatch(segment) is None:
        return False
    character_classes = sum(
        (
            any(character.islower() for character in segment),
            any(character.isupper() for character in segment),
            any(character.isdecimal() for character in segment),
        )
    )
    return character_classes >= 2 and len(set(segment)) >= 12


def _unsafe_path_reason(path: str, fragment: str) -> str | None:
    decoded_segments: list[str] = []
    for value in (path, fragment):
        try:
            decoded = unquote(value, errors="strict")
        except (UnicodeDecodeError, ValueError):
            return "ambiguous-url"
        if any(ord(character) < 0x20 or character in {"\\", "?", "#"} for character in decoded):
            return "ambiguous-url"
        if any(character in {"&", ";", "="} for character in decoded):
            return "query-values"
        decoded_segments.extend(segment for segment in re.split(r"[/#]+", decoded) if segment)
    if any(segment in {".", ".."} for segment in decoded_segments):
        return "ambiguous-url"
    if any(segment.isdecimal() for segment in decoded_segments):
        return "numeric-object-route"
    if any(_looks_like_value_bearing_path_segment(segment) for segment in decoded_segments):
        return "value-bearing-path"
    for segment in decoded_segments:
        separated = _CAMEL_BOUNDARY.sub("-", segment)
        words = {word for word in re.split(r"[^a-z0-9]+", separated.lower()) if word}
        if words & _SENSITIVE_PATH_WORDS:
            return "sensitive-path"
    return None


def _raw_target_rejection(raw: str) -> str | None:
    if not raw:
        return "empty-target"
    if len(raw) > 2_000:
        return "candidate-too-long"
    if raw != raw.strip() or raw.startswith("//") or _URI_REFERENCE.fullmatch(raw) is None:
        return "ambiguous-url"
    try:
        raw_parts = urlsplit(raw)
    except ValueError:
        return "ambiguous-url"
    if raw_parts.scheme and raw_parts.scheme.lower() not in {"http", "https"}:
        return "unsafe-scheme"
    if "?" in raw.partition("#")[0]:
        return "query-values"
    if any(segment in {".", ".."} for segment in raw_parts.path.split("/")):
        return "ambiguous-url"
    return None


def _classify_target(raw: str, *, base_url: str, origin: str) -> _TargetDecision:
    raw_rejection = _raw_target_rejection(raw)
    if raw_rejection is not None:
        return _TargetDecision(None, raw_rejection)
    try:
        absolute = urljoin(base_url, raw)
        parsed = urlsplit(absolute)
        parsed_origin = _origin_key(absolute)
        approved_origin = _origin_key(origin)
    except ValueError:
        return _TargetDecision(None, "ambiguous-url")
    if parsed.scheme.lower() not in {"http", "https"}:
        return _TargetDecision(None, "unsafe-scheme")
    if parsed.username is not None or parsed.password is not None:
        return _TargetDecision(None, "url-credentials")
    if parsed_origin != approved_origin:
        return _TargetDecision(None, "external-origin")
    if parsed.query or "?" in parsed.fragment or "=" in parsed.fragment or "&" in parsed.fragment:
        return _TargetDecision(None, "query-values")
    path = parsed.path or "/"
    fragment = parsed.fragment
    if (
        path.startswith("//")
        or _INVALID_PERCENT_ESCAPE.search(path)
        or _INVALID_PERCENT_ESCAPE.search(fragment)
        or _ENCODED_AMBIGUOUS_DELIMITER.search(path)
        or _ENCODED_AMBIGUOUS_DELIMITER.search(fragment)
    ):
        return _TargetDecision(None, "ambiguous-url")
    reason = _unsafe_path_reason(path, fragment)
    if reason is not None:
        return _TargetDecision(None, reason)
    normalized_path = _PERCENT_ESCAPE.sub(lambda match: match.group(0).upper(), path)
    normalized_fragment = _PERCENT_ESCAPE.sub(lambda match: match.group(0).upper(), fragment)
    route = normalized_path + (f"#{normalized_fragment}" if normalized_fragment else "")
    if len(route) > 2_000:
        return _TargetDecision(None, "candidate-too-long")
    return _TargetDecision(route, None)


def browser_discovery_request_path_rejection(*, origin: str, url: str) -> str | None:
    """Return a fixed reason when a browser request path is unsafe to retain.

    This applies the same value-bearing and sensitive-path classifier used for discovered links
    to autonomous subresource requests. Callers may reject such requests before they leave the
    browser; the raw target-controlled path must not be copied into persisted evidence.
    """

    try:
        canonical_origin = local_origin(origin)
    except ValueError:
        return "ambiguous-url"
    decision = _classify_target(
        url,
        base_url=canonical_origin + "/",
        origin=canonical_origin,
    )
    return decision.rejection


def _require_serialized_route(route: str) -> None:
    origin = "http://127.0.0.1"
    decision = _classify_target(route, base_url=origin + "/", origin=origin)
    if decision.route != route:
        raise ValueError("serialized browser route is unsafe or noncanonical")


def _normalize_control(raw: _RawControl) -> DiscoveredFormControl:
    tag_value = raw.tag.lower()
    tag: ControlTag = (
        cast(ControlTag, tag_value)
        if tag_value in {"button", "input", "select", "textarea"}
        else "other"
    )
    if tag == "textarea":
        control_type: ControlType = "textarea"
    elif tag == "select":
        control_type = "select"
    else:
        type_value = raw.control_type.lower() or ("text" if tag == "input" else "other")
        control_type = cast(ControlType, type_value) if type_value in _CONTROL_TYPES else "other"
    name = raw.name
    name_omitted = name is None or raw.name_truncated or _SAFE_FIELD_NAME.fullmatch(name) is None
    if name_omitted:
        name = None
    autocomplete_value = raw.autocomplete.split()[0] if raw.autocomplete.split() else "none"
    autocomplete_role: AutocompleteRole = (
        cast(AutocompleteRole, autocomplete_value)
        if autocomplete_value in _AUTOCOMPLETE_ROLES
        else "other"
    )
    return DiscoveredFormControl(
        ordinal=raw.ordinal,
        tag=tag,
        control_type=control_type,
        name=name,
        name_omitted=name_omitted,
        autocomplete_role=autocomplete_role,
        required=raw.required,
        disabled=raw.disabled,
        read_only=raw.read_only,
        multiple=raw.multiple,
    )


def _normalize_method(value: str) -> Literal["DIALOG", "GET", "POST", "UNKNOWN"]:
    normalized = value.upper()
    return cast(
        Literal["DIALOG", "GET", "POST", "UNKNOWN"],
        normalized if normalized in {"DIALOG", "GET", "POST"} else "UNKNOWN",
    )


def _normalize_encoding(
    value: str,
) -> Literal["application/x-www-form-urlencoded", "multipart/form-data", "other", "text/plain"]:
    normalized = value.lower()
    if normalized in {
        "application/x-www-form-urlencoded",
        "multipart/form-data",
        "text/plain",
    }:
        return cast(
            Literal[
                "application/x-www-form-urlencoded",
                "multipart/form-data",
                "text/plain",
            ],
            normalized,
        )
    return "other"


def _form_action(
    raw: _RawForm,
    *,
    current_url: str,
    origin: str,
) -> tuple[str | None, FormActionDisposition, str | None]:
    method = _normalize_method(raw.method)
    if method == "DIALOG":
        return None, "non-navigation-method", None
    if raw.action_truncated:
        return None, "candidate-too-long", "candidate-too-long"
    target = raw.action or current_url
    decision = _classify_target(target, base_url=current_url, origin=origin)
    if decision.route is not None:
        return decision.route, "same-origin", None
    rejection = decision.rejection or "ambiguous-url"
    disposition = cast(FormActionDisposition, rejection)
    return None, disposition, rejection


def _retained_controls(
    raw: _RawForm,
    *,
    plan: BrowserDiscoveryPlan,
    retained_total: int,
) -> tuple[tuple[DiscoveredFormControl, ...], bool]:
    remaining = max(0, plan.max_total_fields - retained_total)
    keep = min(plan.max_fields_per_form, remaining, len(raw.controls))
    selected = tuple(_normalize_control(control) for control in raw.controls[:keep])
    truncated = raw.observed_control_count > len(selected)
    return selected, truncated


def _normalize_form(
    raw: _RawForm,
    *,
    route: DiscoveredBrowserRoute,
    current_url: str,
    origin: str,
    plan: BrowserDiscoveryPlan,
    retained_total: int,
) -> tuple[DiscoveredBrowserForm, str | None]:
    action_route, disposition, rejection = _form_action(
        raw,
        current_url=current_url,
        origin=origin,
    )
    controls, truncated = _retained_controls(
        raw,
        plan=plan,
        retained_total=retained_total,
    )
    return (
        DiscoveredBrowserForm(
            route_id=route.route_id,
            document_ordinal=raw.document_ordinal,
            method=_normalize_method(raw.method),
            action_route=action_route,
            action_disposition=disposition,
            encoding=_normalize_encoding(raw.encoding),
            controls=controls,
            observed_control_count=raw.observed_control_count,
            controls_truncated=truncated,
            submission_performed=False,
        ),
        rejection,
    )


async def _snapshot(
    page: BrowserDiscoveryPage,
    plan: BrowserDiscoveryPlan,
) -> _RawSnapshot:
    try:
        async with asyncio.timeout(plan.navigation_timeout_milliseconds / 1_000):
            raw = await page.evaluate(
                _DISCOVERY_SCRIPT,
                {
                    "maxLinks": plan.max_links_per_page,
                    "maxForms": plan.max_forms,
                    "maxFieldsPerForm": plan.max_fields_per_form,
                },
            )
        return _RawSnapshot.model_validate(raw)
    except Exception:
        raise BrowserDiscoveryError(
            "browser discovery returned an invalid structural snapshot"
        ) from None


async def _navigate(
    page: BrowserDiscoveryPage,
    *,
    absolute: str,
    expected_route: str,
    plan: BrowserDiscoveryPlan,
) -> None:
    timeout_seconds = (
        plan.navigation_timeout_milliseconds + plan.settle_milliseconds + 1_000
    ) / 1_000
    try:
        async with asyncio.timeout(timeout_seconds):
            await page.goto(
                absolute,
                wait_until="domcontentloaded",
                timeout=float(plan.navigation_timeout_milliseconds),
            )
            if plan.settle_milliseconds:
                await page.wait_for_timeout(float(plan.settle_milliseconds))
            observed_url = page.url
    except Exception:
        raise BrowserDiscoveryError("browser discovery navigation failed") from None
    observed = _classify_target(observed_url, base_url=absolute, origin=plan.origin)
    if observed.route != expected_route:
        raise BrowserDiscoveryBoundaryError("browser discovery navigation route drifted")


async def _require_authentication_sentinel(
    page: BrowserDiscoveryPage,
    *,
    plan: BrowserDiscoveryPlan,
) -> None:
    selector = plan.authentication_sentinel_selector
    if selector is None:
        return
    sentinel_page = cast(BrowserDiscoverySentinelPage, page)
    activation_selector = plan.authentication_sentinel_activation_selector
    activation_performed = False
    try:
        async with asyncio.timeout(plan.navigation_timeout_milliseconds / 1_000):
            if activation_selector is not None:
                activation = sentinel_page.locator(activation_selector)
                await activation.wait_for(
                    state="visible",
                    timeout=float(plan.navigation_timeout_milliseconds),
                )
                activation_mode = plan.authentication_sentinel_activation_mode or "click"
                if activation_mode == "enter":
                    await activation.press(
                        "Enter",
                        timeout=float(plan.navigation_timeout_milliseconds),
                    )
                else:
                    await activation.click(
                        timeout=float(plan.navigation_timeout_milliseconds),
                    )
                activation_performed = True
            await sentinel_page.locator(selector).wait_for(
                state="attached",
                timeout=float(plan.navigation_timeout_milliseconds),
            )
            if activation_performed:
                await sentinel_page.keyboard.press("Escape")
    except Exception:
        raise BrowserDiscoveryBoundaryError(
            "browser discovery authentication sentinel is not attached"
        ) from None


def _record_form_rejections(
    rejections: Counter[str],
    *,
    snapshot: _RawSnapshot,
    retained_forms: int,
    plan: BrowserDiscoveryPlan,
) -> int:
    available = max(0, plan.max_forms - retained_forms)
    omitted = max(0, snapshot.observed_form_count - min(len(snapshot.forms), available))
    if omitted:
        rejections["form-limit"] += omitted
    return available


def _add_forms(
    destination: list[DiscoveredBrowserForm],
    rejections: Counter[str],
    *,
    snapshot: _RawSnapshot,
    route: DiscoveredBrowserRoute,
    current_url: str,
    origin: str,
    plan: BrowserDiscoveryPlan,
) -> None:
    available = _record_form_rejections(
        rejections,
        snapshot=snapshot,
        retained_forms=len(destination),
        plan=plan,
    )
    for raw in sorted(snapshot.forms, key=lambda item: item.document_ordinal)[:available]:
        retained_fields = sum(len(form.controls) for form in destination)
        form, rejection = _normalize_form(
            raw,
            route=route,
            current_url=current_url,
            origin=origin,
            plan=plan,
            retained_total=retained_fields,
        )
        destination.append(form)
        if rejection is not None:
            rejections[rejection] += 1
        if form.controls_truncated:
            rejections["field-limit"] += form.observed_control_count - len(form.controls)


def _link_candidates(
    snapshot: _RawSnapshot,
    *,
    current_url: str,
    origin: str,
    max_links: int,
    rejections: Counter[str],
) -> list[tuple[str, Literal["anchor", "area"]]]:
    if snapshot.observed_link_count > max_links:
        rejections["link-limit"] += snapshot.observed_link_count - max_links
    candidates: dict[str, Literal["anchor", "area"]] = {}
    source_order = {"anchor": 0, "area": 1}
    for raw in sorted(snapshot.links, key=lambda item: (item.href, source_order[item.kind]))[
        :max_links
    ]:
        if raw.href_truncated:
            rejections["candidate-too-long"] += 1
            continue
        decision = _classify_target(raw.href, base_url=current_url, origin=origin)
        if decision.route is None:
            rejections[decision.rejection or "ambiguous-url"] += 1
            continue
        existing = candidates.get(decision.route)
        if existing is None or source_order[raw.kind] < source_order[existing]:
            candidates[decision.route] = raw.kind
    return sorted(candidates.items())


def _enqueue_links(
    queue: deque[_QueuedRoute],
    queued_or_visited: set[str],
    rejections: Counter[str],
    *,
    candidates: list[tuple[str, Literal["anchor", "area"]]],
    current: DiscoveredBrowserRoute,
    plan: BrowserDiscoveryPlan,
) -> None:
    for route, source in candidates:
        if route in queued_or_visited:
            continue
        if current.depth >= plan.max_depth:
            rejections["depth-limit"] += 1
            continue
        queue.append(
            _QueuedRoute(
                route=route,
                depth=current.depth + 1,
                source=source,
                parent_route_id=current.route_id,
            )
        )
        queued_or_visited.add(route)
    ordered = sorted(queue, key=lambda item: (item.depth, item.route))
    queue.clear()
    queue.extend(ordered)


async def discover_browser_routes_and_forms(
    page: BrowserDiscoveryPage,
    *,
    plan: BrowserDiscoveryPlan,
) -> BrowserDiscoveryResult:
    """Passively traverse query-free same-origin links and enumerate value-free forms.

    The caller owns browser/context creation and the exact-origin network gate. A redirect or
    client-side route drift is rejected after navigation as an additional fail-closed check.
    """

    plan = BrowserDiscoveryPlan.model_validate(plan.model_dump(mode="json"))
    queue = deque(
        _QueuedRoute(route=route, depth=0, source="seed", parent_route_id=None)
        for route in plan.seed_routes
    )
    queued_or_visited = set(plan.seed_routes)
    routes: list[DiscoveredBrowserRoute] = []
    forms: list[DiscoveredBrowserForm] = []
    rejections: Counter[str] = Counter()

    while queue and len(routes) < plan.max_routes:
        queued = queue.popleft()
        absolute = plan.origin + queued.route
        await _navigate(
            page,
            absolute=absolute,
            expected_route=queued.route,
            plan=plan,
        )
        await _require_authentication_sentinel(page, plan=plan)
        route = DiscoveredBrowserRoute(
            route=queued.route,
            depth=queued.depth,
            source=queued.source,
            discovered_from_route_id=queued.parent_route_id,
        )
        routes.append(route)
        snapshot = await _snapshot(page, plan)
        _add_forms(
            forms,
            rejections,
            snapshot=snapshot,
            route=route,
            current_url=absolute,
            origin=plan.origin,
            plan=plan,
        )
        candidates = _link_candidates(
            snapshot,
            current_url=absolute,
            origin=plan.origin,
            max_links=plan.max_links_per_page,
            rejections=rejections,
        )
        _enqueue_links(
            queue,
            queued_or_visited,
            rejections,
            candidates=candidates,
            current=route,
            plan=plan,
        )

    if queue:
        rejections["route-limit"] += len(queue)
    ordered_forms = tuple(
        sorted(forms, key=lambda item: (item.route_id, item.document_ordinal, item.form_id))
    )
    rejection_summary = dict(sorted((key, count) for key, count in rejections.items() if count))
    return BrowserDiscoveryResult(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        routes=tuple(routes),
        forms=ordered_forms,
        rejected_candidates=rejection_summary,
        route_limit_reached="route-limit" in rejection_summary,
        form_limit_reached="form-limit" in rejection_summary,
        field_limit_reached="field-limit" in rejection_summary,
        raw_dom_retained=False,
        screenshots_retained=False,
        form_values_retained=False,
        forms_submitted=False,
        external_delivery_performed=False,
        graph_admission_authority=False,
        finding_authority=False,
        execution_authority=False,
    )


def browser_discovery_plan(
    origin: str,
    *,
    seed_routes: tuple[str, ...] = ("/",),
    authentication_sentinel_selector: str | None = None,
    authentication_sentinel_activation_selector: str | None = None,
    authentication_sentinel_activation_mode: Literal["click", "enter"] | None = None,
    limits: Mapping[str, int] | None = None,
) -> BrowserDiscoveryPlan:
    """Build a passive plan with an optional code-owned authentication sentinel."""

    values: dict[str, object] = {
        "origin": origin,
        "seed_routes": seed_routes,
    }
    if authentication_sentinel_selector is not None:
        values["authentication_sentinel_selector"] = authentication_sentinel_selector
    if authentication_sentinel_activation_selector is not None:
        values["authentication_sentinel_activation_selector"] = (
            authentication_sentinel_activation_selector
        )
    if authentication_sentinel_activation_mode is not None:
        values["authentication_sentinel_activation_mode"] = (
            authentication_sentinel_activation_mode
        )
    if limits is not None:
        allowed = {
            "max_routes",
            "max_depth",
            "max_links_per_page",
            "max_forms",
            "max_fields_per_form",
            "max_total_fields",
            "navigation_timeout_milliseconds",
            "settle_milliseconds",
        }
        if set(limits) - allowed:
            raise ValueError("unknown browser discovery limit")
        values.update(limits)
    return BrowserDiscoveryPlan.model_validate(values)


__all__ = [
    "BROWSER_DISCOVERY_PLAN_API_VERSION",
    "BROWSER_DISCOVERY_RESULT_API_VERSION",
    "BrowserDiscoveryBoundaryError",
    "BrowserDiscoveryError",
    "BrowserDiscoveryKeyboard",
    "BrowserDiscoveryLocator",
    "BrowserDiscoveryPage",
    "BrowserDiscoveryPlan",
    "BrowserDiscoveryResult",
    "BrowserDiscoverySentinelPage",
    "DiscoveredBrowserForm",
    "DiscoveredBrowserRoute",
    "DiscoveredFormControl",
    "browser_discovery_plan",
    "browser_discovery_request_path_rejection",
    "discover_browser_routes_and_forms",
]
