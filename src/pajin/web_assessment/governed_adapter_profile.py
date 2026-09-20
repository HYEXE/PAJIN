"""Closed deployment profiles for governed authenticated Web campaigns.

The public coordinator may select only an adapter reference and the exact
numeric-loopback origin installed by this module.  Routes, selectors, payloads,
and Python callables remain owned by :mod:`pajin.web_assessment.adapter_catalog`.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime
from types import MappingProxyType
from typing import Final

from pajin.capabilities.models import capability_definition_digest
from pajin.web_assessment.adapter_catalog import (
    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    AdapterImplementationCatalog,
    AdapterImplementationCatalogError,
    _testing_adapter_implementation_catalog,
    production_adapter_implementation_catalog,
)
from pajin.web_assessment.models import WebAssessmentPlan, local_origin

_PROFILE_DIGEST_DOMAIN: Final = "pajin.web-assessment.governed-adapter-profile/v1"
_REGISTRY_DIGEST_DOMAIN: Final = "pajin.web-assessment.governed-adapter-profile-registry/v1"
_ADAPTER_REFERENCE_PATTERN: Final = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}/v[1-9][0-9]{0,8}$")
_REGISTRY_FACTORY_TOKEN: Final = object()
_RESOLVED_PROFILE_FACTORY_TOKEN: Final = object()

GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE: Final = "juice-shop-local/v1"
GOVERNED_JUICE_SHOP_ORIGIN: Final = "http://127.0.0.1:3000"
GOVERNED_JUICE_SHOP_ADAPTER_ID: Final = "pajin.adapter.juice-shop.local"
GOVERNED_JUICE_SHOP_ADAPTER_VERSION: Final = "1.0.0"
GOVERNED_JUICE_SHOP_PLAN_DIGEST: Final = (
    "3b66877b08648ea82faca13dbda6395d90ac8c13f37db9ca20fd7dea5e57ff96"
)
GOVERNED_WEB_CAMPAIGN_ID: Final = "juice-shop-governed-local"
GOVERNED_WEB_TARGET_ID: Final = "owasp-juice-shop-local"

_JUICE_SHOP_DESCRIPTION: Final = (
    "Governed authenticated assessment of the approved local Juice Shop lab."
)
_JUICE_SHOP_OBJECTIVE: Final = (
    "Execute the code-owned authenticated Juice Shop diagnostics twice and reconcile them."
)
_LOCAL_FIXTURE_ADAPTER_REFERENCE: Final = "local-fixture/v1"
_LOCAL_FIXTURE_ORIGIN: Final = "http://127.0.0.1:3001"


class GovernedWebAdapterProfileError(ValueError):
    """Raised when a deployment profile cannot be resolved exactly."""


@dataclass(frozen=True, slots=True)
class _CodeOwnedDeploymentProfile:
    adapter_reference: str
    origin: str
    adapter_id: str
    adapter_version: str
    implementation_id: str
    implementation_digest: str
    expected_plan_digest: str
    campaign_id: str
    target_id: str
    target_type: str
    target_product: str
    description: str
    objective: str

    def material(self) -> dict[str, str]:
        return {
            "adapterReference": self.adapter_reference,
            "origin": self.origin,
            "adapterId": self.adapter_id,
            "adapterVersion": self.adapter_version,
            "implementationId": self.implementation_id,
            "implementationDigest": self.implementation_digest,
            "expectedPlanDigest": self.expected_plan_digest,
            "campaignId": self.campaign_id,
            "targetId": self.target_id,
            "targetType": self.target_type,
            "targetProduct": self.target_product,
            "description": self.description,
            "objective": self.objective,
        }


def _fixture_plan_digest() -> str:
    catalog = _testing_adapter_implementation_catalog(
        implementation_ids=(_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,)
    )
    return catalog.resolve(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=_LOCAL_FIXTURE_ORIGIN,
    ).plan.plan_digest


_JUICE_SHOP_PROFILE: Final = _CodeOwnedDeploymentProfile(
    adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    origin=GOVERNED_JUICE_SHOP_ORIGIN,
    adapter_id=GOVERNED_JUICE_SHOP_ADAPTER_ID,
    adapter_version=GOVERNED_JUICE_SHOP_ADAPTER_VERSION,
    implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    expected_plan_digest=GOVERNED_JUICE_SHOP_PLAN_DIGEST,
    campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
    target_id=GOVERNED_WEB_TARGET_ID,
    target_type="web-application",
    target_product="OWASP Juice Shop",
    description=_JUICE_SHOP_DESCRIPTION,
    objective=_JUICE_SHOP_OBJECTIVE,
)
_LOCAL_FIXTURE_PROFILE: Final = _CodeOwnedDeploymentProfile(
    adapter_reference=_LOCAL_FIXTURE_ADAPTER_REFERENCE,
    origin=_LOCAL_FIXTURE_ORIGIN,
    adapter_id="pajin.adapter.local-fixture",
    adapter_version="1.0.0",
    implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
    expected_plan_digest=_fixture_plan_digest(),
    campaign_id="local-fixture-governed",
    target_id="code-owned-local-fixture",
    target_type="web-application",
    target_product="OWASP Juice Shop",
    description="Governed authenticated assessment of a code-owned local test fixture.",
    objective="Resolve a second code-owned adapter without caller-authored execution input.",
)
_CODE_OWNED_PROFILES: Final[Mapping[tuple[str, str], _CodeOwnedDeploymentProfile]] = (
    MappingProxyType(
        {
            (
                _JUICE_SHOP_PROFILE.adapter_reference,
                _JUICE_SHOP_PROFILE.origin,
            ): _JUICE_SHOP_PROFILE,
            (
                _LOCAL_FIXTURE_PROFILE.adapter_reference,
                _LOCAL_FIXTURE_PROFILE.origin,
            ): _LOCAL_FIXTURE_PROFILE,
        }
    )
)


def _profile_digest(
    descriptor: _CodeOwnedDeploymentProfile,
    *,
    catalog_digest: str,
    plan_digest: str,
) -> str:
    return capability_definition_digest(
        _PROFILE_DIGEST_DOMAIN,
        {
            **descriptor.material(),
            "catalogDigest": catalog_digest,
            "planDigest": plan_digest,
        },
    )


@dataclass(frozen=True, slots=True)
class _BoundDeploymentProfile:
    descriptor: _CodeOwnedDeploymentProfile
    catalog_digest: str
    profile_digest: str
    plan: WebAssessmentPlan


@dataclass(frozen=True, slots=True)
class ResolvedGovernedWebAdapterProfile:
    """Public-safe immutable metadata for one exact installed deployment."""

    registry_digest: str
    profile_digest: str
    catalog_digest: str
    adapter_reference: str
    origin: str
    adapter_id: str
    adapter_version: str
    implementation_id: str
    implementation_digest: str
    plan_digest: str
    plan: WebAssessmentPlan
    campaign_id: str
    target_id: str
    target_type: str
    target_product: str
    description: str
    objective: str
    _descriptor: _CodeOwnedDeploymentProfile = field(repr=False, compare=False)
    _expected_registry_digest: str = field(repr=False, compare=False)
    _factory_token: object = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        if (
            type(self) is not ResolvedGovernedWebAdapterProfile
            or self._factory_token is not _RESOLVED_PROFILE_FACTORY_TOKEN
        ):
            raise TypeError("governed Web adapter profile requires registry resolution")
        self._require_current()

    @property
    def campaign_description(self) -> str:
        """Return the public-safe campaign description."""

        self._require_current()
        return self.description

    def manifest_input(
        self,
        *,
        issued_at: datetime,
        expires_at: datetime,
    ) -> dict[str, object]:
        """Return secret-free exact kwargs for ``WebAssessmentAdapterManifest``."""

        self._require_current()
        return {
            "adapterId": self.adapter_id,
            "adapterVersion": self.adapter_version,
            "origin": self.origin,
            "implementationId": self.implementation_id,
            "implementationDigest": self.implementation_digest,
            "recipeDigest": self.plan_digest,
            "issuedAt": issued_at,
            "expiresAt": expires_at,
        }

    def public_metadata(self) -> dict[str, str]:
        """Return a detached, JSON-ready campaign and target metadata snapshot."""

        self._require_current()
        return {
            "adapterReference": self.adapter_reference,
            "adapterId": self.adapter_id,
            "adapterVersion": self.adapter_version,
            "origin": self.origin,
            "implementationId": self.implementation_id,
            "implementationDigest": self.implementation_digest,
            "catalogDigest": self.catalog_digest,
            "profileDigest": self.profile_digest,
            "registryDigest": self.registry_digest,
            "planDigest": self.plan_digest,
            "campaignId": self.campaign_id,
            "targetId": self.target_id,
            "targetType": self.target_type,
            "targetProduct": self.target_product,
            "description": self.description,
            "objective": self.objective,
        }

    def _require_current(self) -> None:
        descriptor = self._descriptor
        key = (self.adapter_reference, self.origin)
        if (
            type(descriptor) is not _CodeOwnedDeploymentProfile
            or _CODE_OWNED_PROFILES.get(key) is not descriptor
            or self.adapter_reference != descriptor.adapter_reference
            or self.origin != descriptor.origin
            or self.adapter_id != descriptor.adapter_id
            or self.adapter_version != descriptor.adapter_version
            or self.implementation_id != descriptor.implementation_id
            or self.implementation_digest != descriptor.implementation_digest
            or self.plan_digest != descriptor.expected_plan_digest
            or self.plan.plan_digest != self.plan_digest
            or self.plan.origin != self.origin
            or self.plan.adapter_implementation_id != self.implementation_id
            or self.plan.target_product != self.target_product
            or self.campaign_id != descriptor.campaign_id
            or self.target_id != descriptor.target_id
            or self.target_type != descriptor.target_type
            or self.target_product != descriptor.target_product
            or self.description != descriptor.description
            or self.objective != descriptor.objective
            or self.registry_digest != self._expected_registry_digest
            or self.profile_digest
            != _profile_digest(
                descriptor,
                catalog_digest=self.catalog_digest,
                plan_digest=self.plan_digest,
            )
        ):
            raise GovernedWebAdapterProfileError(
                "resolved governed Web adapter profile identity changed"
            )


def _bind_profile(
    descriptor: _CodeOwnedDeploymentProfile,
    *,
    catalog: AdapterImplementationCatalog,
    catalog_digest: str,
) -> _BoundDeploymentProfile:
    try:
        resolved = catalog.resolve(
            implementation_id=descriptor.implementation_id,
            implementation_digest=descriptor.implementation_digest,
            origin=descriptor.origin,
        )
    except AdapterImplementationCatalogError as exc:
        raise GovernedWebAdapterProfileError(
            "governed Web adapter profile implementation is not installed"
        ) from exc
    plan = resolved.plan
    if (
        resolved.catalog_digest != catalog_digest
        or plan.origin != descriptor.origin
        or plan.adapter_implementation_id != descriptor.implementation_id
        or plan.target_product != descriptor.target_product
        or plan.plan_digest != descriptor.expected_plan_digest
    ):
        raise GovernedWebAdapterProfileError(
            "governed Web adapter profile differs from code authority"
        )
    return _BoundDeploymentProfile(
        descriptor=descriptor,
        catalog_digest=catalog_digest,
        profile_digest=_profile_digest(
            descriptor,
            catalog_digest=catalog_digest,
            plan_digest=plan.plan_digest,
        ),
        plan=WebAssessmentPlan.model_validate(plan.model_dump(mode="json", by_alias=True)),
    )


def _registry_digest(
    *,
    catalog_digest: str,
    profiles: tuple[_BoundDeploymentProfile, ...],
) -> str:
    return capability_definition_digest(
        _REGISTRY_DIGEST_DOMAIN,
        {
            "catalogDigest": catalog_digest,
            "profiles": [
                {
                    "adapterReference": profile.descriptor.adapter_reference,
                    "origin": profile.descriptor.origin,
                    "profileDigest": profile.profile_digest,
                }
                for profile in profiles
            ],
        },
    )


class GovernedWebAdapterProfileRegistry:
    """Immutable exact-key inventory of code-owned deployment profiles."""

    __slots__ = (
        "__catalog",
        "__catalog_digest",
        "__entries",
        "__profiles",
        "__registry_digest",
    )
    __catalog: AdapterImplementationCatalog
    __catalog_digest: str
    __entries: Mapping[tuple[str, str], _BoundDeploymentProfile]
    __profiles: tuple[_BoundDeploymentProfile, ...]
    __registry_digest: str

    def __init__(
        self,
        *,
        _profiles: tuple[_CodeOwnedDeploymentProfile, ...],
        _catalog: AdapterImplementationCatalog,
        _factory_token: object | None = None,
    ) -> None:
        if (
            type(self) is not GovernedWebAdapterProfileRegistry
            or _factory_token is not _REGISTRY_FACTORY_TOKEN
        ):
            raise TypeError("governed Web adapter profile registry requires its code-owned factory")
        if type(_catalog) is not AdapterImplementationCatalog:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile catalog is not code-owned"
            )
        if not _profiles:
            raise GovernedWebAdapterProfileError("governed Web adapter profile registry is empty")
        try:
            catalog_digest = _catalog.catalog_digest
        except AdapterImplementationCatalogError as exc:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile catalog is not current"
            ) from exc
        entries: dict[tuple[str, str], _BoundDeploymentProfile] = {}
        for descriptor in _profiles:
            key = (descriptor.adapter_reference, descriptor.origin)
            if (
                type(descriptor) is not _CodeOwnedDeploymentProfile
                or _CODE_OWNED_PROFILES.get(key) is not descriptor
            ):
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter profile is not code-owned"
                )
            if _ADAPTER_REFERENCE_PATTERN.fullmatch(descriptor.adapter_reference) is None:
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter reference is not CLI-safe"
                )
            try:
                canonical_origin = local_origin(descriptor.origin)
            except (TypeError, ValueError) as exc:
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter profile origin is not exact loopback"
                ) from exc
            if canonical_origin != descriptor.origin:
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter profile origin is not canonical"
                )
            if key in entries:
                raise GovernedWebAdapterProfileError("governed Web adapter profile is duplicated")
            entries[key] = _bind_profile(
                descriptor,
                catalog=_catalog,
                catalog_digest=catalog_digest,
            )
        profiles = tuple(entries[key] for key in sorted(entries))
        object.__setattr__(
            self,
            "_GovernedWebAdapterProfileRegistry__catalog",
            _catalog,
        )
        object.__setattr__(
            self,
            "_GovernedWebAdapterProfileRegistry__catalog_digest",
            catalog_digest,
        )
        object.__setattr__(
            self,
            "_GovernedWebAdapterProfileRegistry__entries",
            MappingProxyType(entries),
        )
        object.__setattr__(
            self,
            "_GovernedWebAdapterProfileRegistry__profiles",
            profiles,
        )
        object.__setattr__(
            self,
            "_GovernedWebAdapterProfileRegistry__registry_digest",
            _registry_digest(catalog_digest=catalog_digest, profiles=profiles),
        )

    @property
    def catalog_digest(self) -> str:
        self._require_current()
        return self.__catalog_digest

    @property
    def registry_digest(self) -> str:
        self._require_current()
        return self.__registry_digest

    def references(self) -> tuple[tuple[str, str], ...]:
        """Return the exact CLI adapter-reference and origin pairs."""

        self._require_current()
        return tuple(sorted(self.__entries))

    def resolve(
        self,
        *,
        adapter_reference: str,
        origin: str,
    ) -> ResolvedGovernedWebAdapterProfile:
        """Resolve one exact installed profile without accepting recipe input."""

        self._require_current()
        if (
            type(adapter_reference) is not str
            or _ADAPTER_REFERENCE_PATTERN.fullmatch(adapter_reference) is None
            or type(origin) is not str
        ):
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile reference is invalid"
            )
        try:
            canonical_origin = local_origin(origin)
        except (TypeError, ValueError) as exc:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile origin is not exact loopback"
            ) from exc
        if canonical_origin != origin:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile origin is not exact loopback"
            )
        try:
            bound = self.__entries[(adapter_reference, canonical_origin)]
        except KeyError as exc:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile is not installed for the exact origin"
            ) from exc
        plan = WebAssessmentPlan.model_validate(bound.plan.model_dump(mode="json", by_alias=True))
        descriptor = bound.descriptor
        return ResolvedGovernedWebAdapterProfile(
            registry_digest=self.__registry_digest,
            profile_digest=bound.profile_digest,
            catalog_digest=bound.catalog_digest,
            adapter_reference=descriptor.adapter_reference,
            origin=descriptor.origin,
            adapter_id=descriptor.adapter_id,
            adapter_version=descriptor.adapter_version,
            implementation_id=descriptor.implementation_id,
            implementation_digest=descriptor.implementation_digest,
            plan_digest=plan.plan_digest,
            plan=plan,
            campaign_id=descriptor.campaign_id,
            target_id=descriptor.target_id,
            target_type=descriptor.target_type,
            target_product=descriptor.target_product,
            description=descriptor.description,
            objective=descriptor.objective,
            _descriptor=descriptor,
            _expected_registry_digest=self.__registry_digest,
            _factory_token=_RESOLVED_PROFILE_FACTORY_TOKEN,
        )

    def _require_current(self) -> None:
        try:
            catalog_digest = self.__catalog.catalog_digest
        except AdapterImplementationCatalogError as exc:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile catalog identity changed"
            ) from exc
        if catalog_digest != self.__catalog_digest:
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile catalog identity changed"
            )
        current: list[_BoundDeploymentProfile] = []
        for profile in self.__profiles:
            descriptor = profile.descriptor
            key = (descriptor.adapter_reference, descriptor.origin)
            if self.__entries.get(key) is not profile:
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter profile registry identity changed"
                )
            rebound = _bind_profile(
                descriptor,
                catalog=self.__catalog,
                catalog_digest=catalog_digest,
            )
            if rebound != profile:
                raise GovernedWebAdapterProfileError(
                    "governed Web adapter profile identity changed"
                )
            current.append(rebound)
        current_profiles = tuple(current)
        if (
            len(self.__entries) != len(current_profiles)
            or _registry_digest(
                catalog_digest=catalog_digest,
                profiles=current_profiles,
            )
            != self.__registry_digest
        ):
            raise GovernedWebAdapterProfileError(
                "governed Web adapter profile registry identity changed"
            )


def _new_profile_registry(
    profiles: tuple[_CodeOwnedDeploymentProfile, ...],
    *,
    catalog: AdapterImplementationCatalog,
) -> GovernedWebAdapterProfileRegistry:
    return GovernedWebAdapterProfileRegistry(
        _profiles=profiles,
        _catalog=catalog,
        _factory_token=_REGISTRY_FACTORY_TOKEN,
    )


_PRODUCTION_GOVERNED_WEB_ADAPTER_PROFILE_REGISTRY: Final = _new_profile_registry(
    (_JUICE_SHOP_PROFILE,),
    catalog=production_adapter_implementation_catalog(),
)


def production_governed_web_adapter_profile_registry() -> GovernedWebAdapterProfileRegistry:
    """Return the production inventory containing only Juice Shop local v1."""

    return _PRODUCTION_GOVERNED_WEB_ADAPTER_PROFILE_REGISTRY


def _testing_governed_web_adapter_profile_registry(
    *,
    adapter_references: tuple[str, ...] = (
        GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        _LOCAL_FIXTURE_ADAPTER_REFERENCE,
    ),
    catalog: AdapterImplementationCatalog | None = None,
) -> GovernedWebAdapterProfileRegistry:
    """Create a private registry from only predeclared test profile references."""

    by_reference = {profile.adapter_reference: profile for profile in _CODE_OWNED_PROFILES.values()}
    selected: list[_CodeOwnedDeploymentProfile] = []
    for adapter_reference in adapter_references:
        if type(adapter_reference) is not str or adapter_reference not in by_reference:
            raise GovernedWebAdapterProfileError(
                "test governed Web adapter profile selection is not code-owned"
            )
        selected.append(by_reference[adapter_reference])
    selected_catalog = _testing_adapter_implementation_catalog() if catalog is None else catalog
    return _new_profile_registry(tuple(selected), catalog=selected_catalog)


__all__ = [
    "GOVERNED_JUICE_SHOP_ADAPTER_ID",
    "GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE",
    "GOVERNED_JUICE_SHOP_ADAPTER_VERSION",
    "GOVERNED_JUICE_SHOP_ORIGIN",
    "GOVERNED_JUICE_SHOP_PLAN_DIGEST",
    "GOVERNED_WEB_CAMPAIGN_ID",
    "GOVERNED_WEB_TARGET_ID",
    "GovernedWebAdapterProfileError",
    "GovernedWebAdapterProfileRegistry",
    "ResolvedGovernedWebAdapterProfile",
    "production_governed_web_adapter_profile_registry",
]
