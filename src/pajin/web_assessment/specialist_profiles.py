"""Exact inert Web diagnostic profiles for AGENTIC specialist assignments.

The profiles bind installed proposal-analysis Skill identities to bounded
diagnostic closures.  They deliberately do not bind the current all-in-one Web
executor because that runtime cannot yet enforce per-specialist least
privilege.
"""

from __future__ import annotations

from typing import Final

from pajin.agentic.execution_profiles import (
    SpecialistExecutionDependency,
    SpecialistExecutionProfileCatalog,
    SpecialistExecutionProfileError,
    SpecialistExecutionProfileSnapshot,
    _new_code_owned_specialist_execution_profile,
    _new_specialist_execution_profile_catalog,
)
from pajin.agentic.models import (
    AnalysisSkillReference,
    ExploitGroupDefinition,
    PentestSpecialization,
)
from pajin.web_assessment.adapter_catalog import (
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    AdapterImplementationCatalogError,
    production_adapter_implementation_catalog,
)

WEB_XSS_SPECIALIST_PROFILE_ID: Final = "pajin.web-specialist.juice-shop.dom-xss-only"
WEB_SQLI_SPECIALIST_PROFILE_ID: Final = "pajin.web-specialist.juice-shop.sql-login-only"
WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID: Final = (
    "pajin.web-specialist.juice-shop.object-access-via-sql-login"
)
WEB_SPECIALIST_PROFILE_VERSION: Final = "1.0.0"
_PROPOSAL_SKILL_VERSION: Final = "1.1.0"
_ASSESS_WEB_OBJECT_ACCESS_SKILL_ID: Final = "pajin.skill.web.assess-object-access"
_ASSESS_WEB_SQLI_SKILL_ID: Final = "pajin.skill.web.assess-sqli"
_ASSESS_WEB_XSS_SKILL_ID: Final = "pajin.skill.web.assess-xss"
_ADAPTER_CATALOG_VALIDATION_ORIGIN: Final = "http://127.0.0.1:3000"


class WebSpecialistExecutionProfileError(SpecialistExecutionProfileError):
    """Raised when the installed Web specialist roster differs from the profiles."""


def _canonical_group(group: ExploitGroupDefinition) -> ExploitGroupDefinition:
    if type(group) is not ExploitGroupDefinition:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile Exploit Group type is not canonical"
        )
    try:
        canonical = ExploitGroupDefinition.model_validate(
            group.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile Exploit Group failed strict reload"
        ) from exc
    if canonical != group:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile Exploit Group differs after strict reload"
        )
    return canonical


def _exact_skill_reference(
    *,
    group: ExploitGroupDefinition,
    specialization: PentestSpecialization,
    threat_class: str,
    expected_skill_id: str,
) -> AnalysisSkillReference:
    specialist = group.specialist_for(specialization, threat_class)
    if specialist is None or len(specialist.skill_refs) != 1:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile requires one exact selection Skill"
        )
    reference = specialist.skill_refs[0]
    if (
        reference.skill_id != expected_skill_id
        or reference.skill_version != _PROPOSAL_SKILL_VERSION
    ):
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile selection Skill differs from the installed roster"
        )
    try:
        canonical = AnalysisSkillReference.model_validate(
            reference.model_dump(mode="json", by_alias=True)
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile selection Skill failed strict reload"
        ) from exc
    if type(reference) is not AnalysisSkillReference or canonical != reference:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile selection Skill differs after strict reload"
        )
    return canonical


def _profile(
    *,
    profile_id: str,
    specialization: PentestSpecialization,
    threat_class: str,
    selection_skill_ref: AnalysisSkillReference,
    adapter_catalog_digest: str,
    supporting_skill_refs: tuple[AnalysisSkillReference, ...] = (),
    diagnostic_steps: tuple[str, ...],
    dependency_edges: tuple[SpecialistExecutionDependency, ...] = (),
    promotable_steps: tuple[str, ...],
    required_capability_categories: tuple[str, ...],
    promotable_finding_categories: tuple[str, ...],
) -> SpecialistExecutionProfileSnapshot:
    return SpecialistExecutionProfileSnapshot(
        profileId=profile_id,
        profileVersion=WEB_SPECIALIST_PROFILE_VERSION,
        specialization=specialization,
        threatClass=threat_class,
        selectionSkillRefs=(selection_skill_ref,),
        supportingSkillRefs=supporting_skill_refs,
        adapterImplementationId=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        adapterImplementationDigest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        adapterCatalogDigest=adapter_catalog_digest,
        diagnosticSteps=diagnostic_steps,
        dependencyEdges=dependency_edges,
        promotableSteps=promotable_steps,
        requiredCapabilityCategories=required_capability_categories,
        promotableFindingCategories=promotable_finding_categories,
    )


def _profiles_from_group(
    group: ExploitGroupDefinition,
    *,
    adapter_catalog_digest: str,
) -> tuple[SpecialistExecutionProfileSnapshot, ...]:
    canonical_group = _canonical_group(group)
    xss_skill = _exact_skill_reference(
        group=canonical_group,
        specialization=PentestSpecialization.XSS,
        threat_class="xss",
        expected_skill_id=_ASSESS_WEB_XSS_SKILL_ID,
    )
    sqli_skill = _exact_skill_reference(
        group=canonical_group,
        specialization=PentestSpecialization.SQL_INJECTION,
        threat_class="sql-injection",
        expected_skill_id=_ASSESS_WEB_SQLI_SKILL_ID,
    )
    authorization_skill = _exact_skill_reference(
        group=canonical_group,
        specialization=PentestSpecialization.AUTHORIZATION,
        threat_class="authorization",
        expected_skill_id=_ASSESS_WEB_OBJECT_ACCESS_SKILL_ID,
    )
    return (
        _profile(
            profile_id=WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID,
            specialization=PentestSpecialization.AUTHORIZATION,
            threat_class="authorization",
            selection_skill_ref=authorization_skill,
            adapter_catalog_digest=adapter_catalog_digest,
            supporting_skill_refs=(sqli_skill,),
            diagnostic_steps=("sql-login", "object-access"),
            dependency_edges=(
                SpecialistExecutionDependency(
                    predecessorStep="sql-login",
                    dependentStep="object-access",
                    purpose="session-acquisition",
                    evidenceType="web.session-and-object-identity",
                ),
            ),
            promotable_steps=("object-access",),
            required_capability_categories=tuple(sorted(("CWE-89", "CWE-639"))),
            promotable_finding_categories=("CWE-639",),
        ),
        _profile(
            profile_id=WEB_SQLI_SPECIALIST_PROFILE_ID,
            specialization=PentestSpecialization.SQL_INJECTION,
            threat_class="sql-injection",
            selection_skill_ref=sqli_skill,
            adapter_catalog_digest=adapter_catalog_digest,
            diagnostic_steps=("sql-login",),
            promotable_steps=("sql-login",),
            required_capability_categories=("CWE-89",),
            promotable_finding_categories=("CWE-89",),
        ),
        _profile(
            profile_id=WEB_XSS_SPECIALIST_PROFILE_ID,
            specialization=PentestSpecialization.XSS,
            threat_class="xss",
            selection_skill_ref=xss_skill,
            adapter_catalog_digest=adapter_catalog_digest,
            diagnostic_steps=("dom-xss",),
            promotable_steps=("dom-xss",),
            required_capability_categories=("CWE-79",),
            promotable_finding_categories=("CWE-79",),
        ),
    )


def production_web_specialist_execution_profile_catalog() -> SpecialistExecutionProfileCatalog:
    """Build the closed inert catalog from the sole installed-roster consumer."""

    from pajin.web_assessment.analysis_skill_projection import (
        registered_web_pentest_exploit_group,
    )

    adapter_catalog = production_adapter_implementation_catalog()
    try:
        installed_adapter = adapter_catalog.resolve(
            implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
            origin=_ADAPTER_CATALOG_VALIDATION_ORIGIN,
        )
    except AdapterImplementationCatalogError as exc:
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile adapter is not installed exactly"
        ) from exc
    if (
        installed_adapter.catalog_digest != adapter_catalog.catalog_digest
        or installed_adapter.implementation_id != JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID
        or installed_adapter.implementation_digest != JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
    ):
        raise WebSpecialistExecutionProfileError(
            "Web specialist profile adapter differs from the production catalog"
        )
    profiles = _profiles_from_group(
        registered_web_pentest_exploit_group(),
        adapter_catalog_digest=adapter_catalog.catalog_digest,
    )
    return _new_specialist_execution_profile_catalog(
        tuple(_new_code_owned_specialist_execution_profile(profile) for profile in profiles)
    )


__all__ = [
    "WEB_AUTHORIZATION_SPECIALIST_PROFILE_ID",
    "WEB_SPECIALIST_PROFILE_VERSION",
    "WEB_SQLI_SPECIALIST_PROFILE_ID",
    "WEB_XSS_SPECIALIST_PROFILE_ID",
    "WebSpecialistExecutionProfileError",
    "production_web_specialist_execution_profile_catalog",
]
