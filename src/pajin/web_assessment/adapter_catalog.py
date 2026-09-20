"""Closed code-owned implementation selection for governed Web adapters.

Signed adapter manifests may select one exact installed implementation, but they
never supply Python import paths, callables, routes, selectors, or payloads.  The
catalog is the sole bridge from an implementation identity to a plan builder.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final, Literal

from pajin.capabilities.models import capability_definition_digest
from pajin.web_assessment.models import WebAssessmentPlan
from pajin.web_assessment.recipes import juice_shop_plan

_IMPLEMENTATION_DIGEST_DOMAIN: Final = "pajin.web-assessment.implementation/v1"
_CATALOG_DIGEST_DOMAIN: Final = "pajin.web-assessment.adapter-implementation-catalog/v1"
_SHA256_CHARACTERS: Final = frozenset("0123456789abcdef")
_CATALOG_FACTORY_TOKEN: Final = object()

JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID: Final = "pajin.web-assessment.juice-shop.v1"


def _implementation_digest(
    *,
    implementation_type: str,
    implementation_version: str,
    provisioning_mode: str,
) -> str:
    return capability_definition_digest(
        _IMPLEMENTATION_DIGEST_DOMAIN,
        {
            "implementationType": implementation_type,
            "implementationVersion": implementation_version,
            "provisioningMode": provisioning_mode,
        },
    )


JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST: Final = _implementation_digest(
    implementation_type="pajin.web_assessment.recipes.juice_shop_plan",
    implementation_version="1.0.2",
    provisioning_mode="preprovisioned-only",
)
_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID: Final = (
    "pajin.web-assessment.local-fixture.v1"
)


class AdapterImplementationCatalogError(ValueError):
    """Raised when code-owned implementation selection cannot be proven."""


@dataclass(frozen=True, slots=True)
class _CodeOwnedAdapterImplementation:
    implementation_id: str
    implementation_type: str
    implementation_version: str
    provisioning_mode: Literal["preprovisioned-only"]
    builder: Literal["juice-shop", "local-fixture"]

    @property
    def implementation_digest(self) -> str:
        return _implementation_digest(
            implementation_type=self.implementation_type,
            implementation_version=self.implementation_version,
            provisioning_mode=self.provisioning_mode,
        )

    def descriptor(self) -> dict[str, str]:
        return {
            "implementationId": self.implementation_id,
            "implementationDigest": self.implementation_digest,
            "implementationType": self.implementation_type,
            "implementationVersion": self.implementation_version,
            "provisioningMode": self.provisioning_mode,
        }


@dataclass(frozen=True, slots=True)
class ResolvedAdapterImplementation:
    """Non-executable resolved identity paired with its canonical code-owned plan."""

    catalog_digest: str
    implementation_id: str
    implementation_digest: str
    implementation_type: str
    implementation_version: str
    provisioning_mode: Literal["preprovisioned-only"]
    plan: WebAssessmentPlan


def _local_fixture_plan(origin: str) -> WebAssessmentPlan:
    """Second code-owned implementation used only by focused catalog tests."""

    material = juice_shop_plan(origin).model_dump(mode="json")
    material["name"] = "juice-shop-local-fixture-assessment"
    material["adapter_implementation_id"] = _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID
    material["routes"] = ["/#/about"]
    material["route_ready_selectors"] = {"/#/about": "app-about"}
    return WebAssessmentPlan.model_validate(material)


_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST: Final = _implementation_digest(
    implementation_type="pajin.web_assessment.adapter_catalog._local_fixture_plan",
    implementation_version="1.0.0",
    provisioning_mode="preprovisioned-only",
)

_JUICE_SHOP_IMPLEMENTATION: Final = _CodeOwnedAdapterImplementation(
    implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    implementation_type="pajin.web_assessment.recipes.juice_shop_plan",
    implementation_version="1.0.2",
    provisioning_mode="preprovisioned-only",
    builder="juice-shop",
)
_LOCAL_FIXTURE_IMPLEMENTATION: Final = _CodeOwnedAdapterImplementation(
    implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    implementation_type="pajin.web_assessment.adapter_catalog._local_fixture_plan",
    implementation_version="1.0.0",
    provisioning_mode="preprovisioned-only",
    builder="local-fixture",
)
_CODE_OWNED_IMPLEMENTATIONS: Final = MappingProxyType(
    {
        _JUICE_SHOP_IMPLEMENTATION.implementation_id: _JUICE_SHOP_IMPLEMENTATION,
        _LOCAL_FIXTURE_IMPLEMENTATION.implementation_id: _LOCAL_FIXTURE_IMPLEMENTATION,
    }
)


def _catalog_digest(implementations: tuple[_CodeOwnedAdapterImplementation, ...]) -> str:
    return capability_definition_digest(
        _CATALOG_DIGEST_DOMAIN,
        {
            "implementations": [
                implementation.descriptor()
                for implementation in sorted(
                    implementations,
                    key=lambda item: (
                        item.implementation_id,
                        item.implementation_digest,
                    ),
                )
            ]
        },
    )


def _build_code_owned_plan(
    implementation: _CodeOwnedAdapterImplementation,
    origin: str,
) -> WebAssessmentPlan:
    if implementation is _JUICE_SHOP_IMPLEMENTATION and implementation.builder == "juice-shop":
        return juice_shop_plan(origin)
    if (
        implementation is _LOCAL_FIXTURE_IMPLEMENTATION
        and implementation.builder == "local-fixture"
    ):
        return _local_fixture_plan(origin)
    raise AdapterImplementationCatalogError(
        "adapter implementation plan builder is not code-owned"
    )


class AdapterImplementationCatalog:
    """Immutable exact-key catalog created only from module-owned implementations."""

    __slots__ = ("__catalog_digest", "__entries", "__implementations")
    __catalog_digest: str
    __entries: Mapping[tuple[str, str], _CodeOwnedAdapterImplementation]
    __implementations: tuple[_CodeOwnedAdapterImplementation, ...]

    def __init__(
        self,
        *,
        _implementations: tuple[_CodeOwnedAdapterImplementation, ...],
        _factory_token: object | None = None,
    ) -> None:
        if type(self) is not AdapterImplementationCatalog or _factory_token is not (
            _CATALOG_FACTORY_TOKEN
        ):
            raise TypeError("adapter implementation catalog requires its code-owned factory")
        if not _implementations:
            raise AdapterImplementationCatalogError(
                "adapter implementation catalog is empty"
            )
        entries: dict[tuple[str, str], _CodeOwnedAdapterImplementation] = {}
        implementation_ids: set[str] = set()
        implementation_digests: set[str] = set()
        for implementation in _implementations:
            if type(implementation) is not _CodeOwnedAdapterImplementation:
                raise AdapterImplementationCatalogError(
                    "adapter implementation descriptor is not code-owned"
                )
            code_owned = _CODE_OWNED_IMPLEMENTATIONS.get(implementation.implementation_id)
            if code_owned is not implementation:
                raise AdapterImplementationCatalogError(
                    "adapter implementation descriptor is not code-owned"
                )
            key = (implementation.implementation_id, implementation.implementation_digest)
            if (
                key in entries
                or implementation.implementation_id in implementation_ids
                or implementation.implementation_digest in implementation_digests
            ):
                raise AdapterImplementationCatalogError(
                    "adapter implementation catalog contains a duplicate identity"
                )
            entries[key] = implementation
            implementation_ids.add(implementation.implementation_id)
            implementation_digests.add(implementation.implementation_digest)
        implementations = tuple(entries[key] for key in sorted(entries))
        object.__setattr__(self, "_AdapterImplementationCatalog__implementations", implementations)
        object.__setattr__(
            self,
            "_AdapterImplementationCatalog__entries",
            MappingProxyType(entries),
        )
        object.__setattr__(
            self,
            "_AdapterImplementationCatalog__catalog_digest",
            _catalog_digest(implementations),
        )

    @property
    def catalog_digest(self) -> str:
        self._require_current()
        return self.__catalog_digest

    def references(self) -> tuple[tuple[str, str], ...]:
        """Return exact installed implementation keys without construction authority."""

        self._require_current()
        return tuple(sorted(self.__entries))

    def resolve(
        self,
        *,
        implementation_id: str,
        implementation_digest: str,
        origin: str,
    ) -> ResolvedAdapterImplementation:
        """Build one canonical plan from an exact installed implementation key."""

        self._require_current()
        if (
            type(implementation_id) is not str
            or not implementation_id
            or implementation_id != implementation_id.strip()
            or type(implementation_digest) is not str
            or len(implementation_digest) != 64
            or any(character not in _SHA256_CHARACTERS for character in implementation_digest)
            or type(origin) is not str
        ):
            raise AdapterImplementationCatalogError(
                "adapter implementation reference is invalid"
            )
        try:
            implementation = self.__entries[(implementation_id, implementation_digest)]
        except KeyError as exc:
            raise AdapterImplementationCatalogError(
                "adapter implementation is not installed"
            ) from exc
        try:
            plan = _build_code_owned_plan(implementation, origin)
        except AdapterImplementationCatalogError:
            raise
        except Exception as exc:
            raise AdapterImplementationCatalogError(
                "adapter implementation rejected the target origin"
            ) from exc
        if type(plan) is not WebAssessmentPlan:
            raise AdapterImplementationCatalogError(
                "adapter implementation returned an unsupported plan type"
            )
        try:
            canonical_plan = WebAssessmentPlan.model_validate(
                plan.model_dump(mode="json", by_alias=True)
            )
        except (TypeError, ValueError) as exc:
            raise AdapterImplementationCatalogError(
                "adapter implementation returned an invalid plan"
            ) from exc
        if canonical_plan != plan or canonical_plan.origin != origin:
            raise AdapterImplementationCatalogError(
                "adapter implementation plan differs from its exact target origin"
            )
        return ResolvedAdapterImplementation(
            catalog_digest=self.__catalog_digest,
            implementation_id=implementation.implementation_id,
            implementation_digest=implementation.implementation_digest,
            implementation_type=implementation.implementation_type,
            implementation_version=implementation.implementation_version,
            provisioning_mode=implementation.provisioning_mode,
            plan=canonical_plan,
        )

    def _require_current(self) -> None:
        entries = self.__entries
        implementations = self.__implementations
        if (
            type(self) is not AdapterImplementationCatalog
            or len(entries) != len(implementations)
            or any(
                type(implementation) is not _CodeOwnedAdapterImplementation
                or _CODE_OWNED_IMPLEMENTATIONS.get(implementation.implementation_id)
                is not implementation
                or entries.get(
                    (implementation.implementation_id, implementation.implementation_digest)
                )
                is not implementation
                for implementation in implementations
            )
            or _catalog_digest(implementations) != self.__catalog_digest
        ):
            raise AdapterImplementationCatalogError(
                "adapter implementation catalog identity changed"
            )


def _new_adapter_implementation_catalog(
    implementations: tuple[_CodeOwnedAdapterImplementation, ...],
) -> AdapterImplementationCatalog:
    return AdapterImplementationCatalog(
        _implementations=implementations,
        _factory_token=_CATALOG_FACTORY_TOKEN,
    )


_PRODUCTION_ADAPTER_IMPLEMENTATION_CATALOG: Final = _new_adapter_implementation_catalog(
    (_JUICE_SHOP_IMPLEMENTATION,)
)


def production_adapter_implementation_catalog() -> AdapterImplementationCatalog:
    """Return the closed production inventory; local fixtures are never installed."""

    return _PRODUCTION_ADAPTER_IMPLEMENTATION_CATALOG


def _testing_adapter_implementation_catalog(
    *,
    implementation_ids: tuple[str, ...] = (
        JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
    ),
) -> AdapterImplementationCatalog:
    """Build a test catalog by selecting only predeclared module-owned entries."""

    selected: list[_CodeOwnedAdapterImplementation] = []
    for implementation_id in implementation_ids:
        if type(implementation_id) is not str:
            raise AdapterImplementationCatalogError(
                "test catalog implementation ID is invalid"
            )
        implementation = _CODE_OWNED_IMPLEMENTATIONS.get(implementation_id)
        if implementation is None:
            raise AdapterImplementationCatalogError(
                "test catalog selection is not code-owned"
            )
        selected.append(implementation)
    return _new_adapter_implementation_catalog(tuple(selected))


__all__ = [
    "JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST",
    "JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID",
    "AdapterImplementationCatalog",
    "AdapterImplementationCatalogError",
    "ResolvedAdapterImplementation",
    "production_adapter_implementation_catalog",
]
