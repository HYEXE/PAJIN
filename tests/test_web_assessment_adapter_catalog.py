from __future__ import annotations

from datetime import UTC, datetime, timedelta
from hashlib import sha256

import pytest
from pydantic import ValidationError

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
from pajin.web_assessment.governed_models import (
    GovernedWebAssessmentModelError,
    SignedWebAssessmentAdapter,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
    WebAssessmentSigningKeyState,
    WebAssessmentSigningRole,
    WebAssessmentVerificationKey,
    sign_web_assessment_adapter,
    web_assessment_public_key_base64url,
)
from pajin.web_assessment.governed_worker import (
    HostLoopbackWebDeploymentContext,
    WebProvisionedAccountMaterial,
)
from pajin.web_assessment.models import RequestEvidence, WebAssessmentPlan
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import issue_local_web_assessment_authorization

_NOW = datetime(2026, 9, 15, 1, tzinfo=UTC)
_ORIGIN = "http://127.0.0.1:3000"


def _seed(label: str) -> bytes:
    return sha256(f"adapter-catalog:{label}".encode()).digest()


def _verification_key() -> WebAssessmentVerificationKey:
    return WebAssessmentVerificationKey(
        keyId="web.adapter-catalog",
        principalId="principal.adapter-catalog",
        role=WebAssessmentSigningRole.ADAPTER_PUBLISHER,
        publicKeyBase64url=web_assessment_public_key_base64url(_seed("publisher")),
        state=WebAssessmentSigningKeyState.ACTIVE,
        notBefore=_NOW - timedelta(days=1),
        notAfter=_NOW + timedelta(days=1),
    )


def _manifest(
    *,
    implementation_id: str = JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
    implementation_digest: str = JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
    recipe_digest: str | None = None,
    issued_at: datetime | None = None,
    expires_at: datetime | None = None,
) -> WebAssessmentAdapterManifest:
    return WebAssessmentAdapterManifest(
        adapterId="pajin.adapter.catalog-test",
        adapterVersion="1.0.0",
        origin=_ORIGIN,
        implementationId=implementation_id,
        implementationDigest=implementation_digest,
        recipeDigest=recipe_digest or juice_shop_plan(_ORIGIN).plan_digest,
        issuedAt=issued_at or _NOW - timedelta(minutes=2),
        expiresAt=expires_at or _NOW + timedelta(hours=1),
    )


def _signed(manifest: WebAssessmentAdapterManifest) -> SignedWebAssessmentAdapter:
    key = _verification_key()
    return sign_web_assessment_adapter(
        manifest,
        key_id=key.key_id,
        private_key=_seed("publisher"),
    )


def _registry(
    signed: SignedWebAssessmentAdapter,
    *,
    catalog: AdapterImplementationCatalog | None = None,
) -> WebAssessmentAdapterRegistry:
    return WebAssessmentAdapterRegistry(
        keys=(_verification_key(),),
        adapters=(signed,),
        catalog=catalog,
        clock=lambda: _NOW,
    )


def _fingerprint_evidence(
    plan: WebAssessmentPlan,
    *,
    evidence_id: str,
) -> RequestEvidence:
    response = b'{"version":"fixture-v1"}'
    return RequestEvidence(
        evidence_id=evidence_id,
        phase="target-fingerprint",
        method="GET",
        path=plan.fingerprint_endpoint,
        request_sha256="8" * 64,
        status=200,
        response_sha256=sha256(response).hexdigest(),
        response_bytes=len(response),
        media_type="application/json",
    )


def test_production_catalog_preserves_exact_juice_shop_identity_and_plan() -> None:
    expected_digest = capability_definition_digest(
        "pajin.web-assessment.implementation/v1",
        {
            "implementationType": "pajin.web_assessment.recipes.juice_shop_plan",
            "implementationVersion": "1.0.2",
            "provisioningMode": "preprovisioned-only",
        },
    )
    catalog = production_adapter_implementation_catalog()

    assert expected_digest == JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
    assert catalog.references() == (
        (JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID, JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
    )
    assert all(
        reference[0] != _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID
        for reference in catalog.references()
    )
    resolved = catalog.resolve(
        implementation_id=JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=_ORIGIN,
    )
    assert resolved.catalog_digest == catalog.catalog_digest
    assert resolved.plan == juice_shop_plan(_ORIGIN)


def test_test_catalog_can_select_only_predeclared_nonproduction_fixture() -> None:
    catalog = _testing_adapter_implementation_catalog()

    assert catalog.references() == tuple(
        sorted(
            (
                (
                    JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
                    JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
                ),
                (
                    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
                    _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
                ),
            )
        )
    )
    resolved = catalog.resolve(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=_ORIGIN,
    )
    assert resolved.plan.name == "juice-shop-local-fixture-assessment"
    assert resolved.plan.plan_digest != juice_shop_plan(_ORIGIN).plan_digest


def test_catalog_construction_is_closed_empty_duplicate_and_injection_safe() -> None:
    with pytest.raises(TypeError, match="code-owned factory"):
        AdapterImplementationCatalog(
            _implementations=(),
            _factory_token=object(),
        )
    with pytest.raises(AdapterImplementationCatalogError, match="empty"):
        _testing_adapter_implementation_catalog(implementation_ids=())
    with pytest.raises(AdapterImplementationCatalogError, match="duplicate identity"):
        _testing_adapter_implementation_catalog(
            implementation_ids=(
                JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
                JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            )
        )
    with pytest.raises(AdapterImplementationCatalogError, match="not code-owned"):
        _testing_adapter_implementation_catalog(
            implementation_ids=("pajin.web-assessment.caller-builder.v1",)
        )
    assert not hasattr(production_adapter_implementation_catalog(), "register")


@pytest.mark.parametrize(
    ("implementation_id", "implementation_digest"),
    (
        (JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID, "9" * 64),
        ("pajin.web-assessment.unknown.v1", JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST),
        (
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_ID,
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
        (
            _LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
            JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST,
        ),
    ),
)
def test_registry_requires_exact_catalog_id_and_digest_without_fallback(
    implementation_id: str,
    implementation_digest: str,
) -> None:
    signed = _signed(
        _manifest(
            implementation_id=implementation_id,
            implementation_digest=implementation_digest,
        )
    )

    with pytest.raises(GovernedWebAssessmentModelError, match="not code-owned"):
        _registry(signed, catalog=_testing_adapter_implementation_catalog())


def test_registry_defaults_to_production_catalog_and_accepts_exact_manifest() -> None:
    manifest = _manifest()
    registry = _registry(_signed(manifest))

    assert registry.resolve(manifest.reference()) == manifest
    assert registry.catalog_digest == production_adapter_implementation_catalog().catalog_digest


def test_registry_accepts_second_code_owned_plan_only_with_its_exact_recipe_digest() -> None:
    catalog = _testing_adapter_implementation_catalog()
    fixture_plan = catalog.resolve(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=_ORIGIN,
    ).plan
    manifest = _manifest(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        recipe_digest=fixture_plan.plan_digest,
    )

    registry = _registry(_signed(manifest), catalog=catalog)
    assert registry.resolve(manifest.reference()) == manifest

    mismatched = _manifest(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="recipe differs"):
        _registry(_signed(mismatched), catalog=catalog)


def test_catalog_fixture_plan_survives_deployment_context_identity_validation() -> None:
    catalog = _testing_adapter_implementation_catalog()
    plan = catalog.resolve(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        origin=_ORIGIN,
    ).plan
    adapter = _manifest(
        implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
        recipe_digest=plan.plan_digest,
    )
    source_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=_NOW - timedelta(minutes=2),
    )
    validation_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=_NOW - timedelta(minutes=1),
    )
    account_receipt_digest = "a" * 64
    source_account = WebProvisionedAccountMaterial(
        accountReceiptDigest=account_receipt_digest,
        planDigest=plan.plan_digest,
        authorizationId=source_authorization.authorization_id,
        origin=plan.origin,
        targetVersion="fixture-v1",
        provisionedAt=_NOW - timedelta(minutes=3),
        requestEvidence=(
            _fingerprint_evidence(plan, evidence_id="http-1-aaaaaaaa"),
        ),
    )
    validation_account = WebProvisionedAccountMaterial(
        accountReceiptDigest=account_receipt_digest,
        planDigest=plan.plan_digest,
        authorizationId=validation_authorization.authorization_id,
        origin=plan.origin,
        targetVersion="fixture-v1",
        provisionedAt=_NOW - timedelta(minutes=3),
        requestEvidence=(
            _fingerprint_evidence(plan, evidence_id="http-1-bbbbbbbb"),
        ),
    )

    context = HostLoopbackWebDeploymentContext(
        accountReceiptDigest=account_receipt_digest,
        adapter=adapter,
        plan=plan,
        sourceAuthorization=source_authorization,
        validationAuthorization=validation_authorization,
        sourceAccount=source_account,
        validationAccount=validation_account,
    )

    assert context.plan.adapter_implementation_id == adapter.implementation_id
    assert context.plan.plan_digest == adapter.recipe_digest


def test_signature_and_lifetime_fail_before_unknown_catalog_resolution() -> None:
    unknown = _manifest(
        implementation_id="pajin.web-assessment.unknown.v1",
        implementation_digest="9" * 64,
    )
    valid_signature = _signed(unknown)
    tampered_signature = SignedWebAssessmentAdapter(
        manifest=unknown,
        keyId=valid_signature.key_id,
        signatureBase64url="A" * 86,
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="signature verification"):
        _registry(tampered_signature, catalog=_testing_adapter_implementation_catalog())

    expired = _manifest(
        implementation_id="pajin.web-assessment.unknown.v1",
        implementation_digest="9" * 64,
        issued_at=_NOW - timedelta(hours=2),
        expires_at=_NOW - timedelta(hours=1),
    )
    with pytest.raises(GovernedWebAssessmentModelError, match="not current"):
        _registry(_signed(expired), catalog=_testing_adapter_implementation_catalog())


@pytest.mark.parametrize(
    "field",
    ("importPath", "module", "payload", "routes", "selectors", "symbol"),
)
def test_manifest_rejects_caller_authored_executable_inputs(field: str) -> None:
    raw = _manifest().model_dump(mode="json", by_alias=True)
    raw[field] = "caller-controlled"

    with pytest.raises(ValidationError):
        WebAssessmentAdapterManifest.model_validate(raw)


def test_catalog_rejects_invalid_origin_without_default_plan_fallback() -> None:
    catalog = _testing_adapter_implementation_catalog()

    with pytest.raises(AdapterImplementationCatalogError, match="rejected the target origin"):
        catalog.resolve(
            implementation_id=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_ID,
            implementation_digest=_LOCAL_FIXTURE_ADAPTER_IMPLEMENTATION_DIGEST,
            origin="http://example.test",
        )
