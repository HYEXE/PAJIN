from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import TypeAdapter, ValidationError

from pajin.discovery import (
    CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA,
    CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE,
    AttackSurface,
    CloudAccountResourceLocatorRegistry,
    CloudAccountResourceSurface,
    CloudAccountResourceSurfaceLocator,
    CloudAccountResourceSurfaceRef,
    CloudAccountSurfaceLocator,
    CloudContainerSurfaceLocator,
    CloudIAMObjectKind,
    CloudIAMSurfaceLocator,
    CloudProjectSurfaceLocator,
    CloudResourceSurfaceLocator,
    CloudSurfaceClass,
    CloudSurfaceRegistryError,
    RegisteredCloudAccountResourceLocator,
    SurfaceLocator,
    cloud_account_surface_locator,
    cloud_container_surface_locator,
    cloud_iam_surface_locator,
    cloud_project_surface_locator,
    cloud_resource_surface_locator,
    registered_cloud_account_resource_locator_registry,
    resolve_cloud_account_resource_locator_registry,
    resolve_registered_cloud_account_resource_locator,
    typed_cloud_account_resource_surface,
)
from pajin.domain.security_domain import SecurityDomain, registered_security_domain_taxonomy
from pajin.graph.domain_semantics import registered_multi_domain_graph_semantics

_CLOUD_LOCATOR_ADAPTER = TypeAdapter(CloudAccountResourceSurfaceLocator)
_DISCOVERY_LOCATOR_ADAPTER = TypeAdapter(SurfaceLocator)
_IMAGE_DIGEST = "sha256:" + "a" * 64

_REGISTRY_FALSE_ALIASES = (
    "discoveryWireChanged",
    "attackSurfaceWireChanged",
    "domainSemanticsRegistryChanged",
    "discoveryAuthorized",
    "inventoryAuthorized",
    "policyReadAuthorized",
    "policyEvaluationAuthorized",
    "credentialLeaseAuthorized",
    "ambientCredentialAuthorized",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "permitIssuanceAuthorized",
    "providerSelectionAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "containerAccessAuthorized",
    "resourceMutationAuthorized",
    "iamMutationAuthorized",
    "graphAdmissionAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)
_SURFACE_FALSE_ALIASES = (
    "discoveryObserved",
    "resourceExistenceVerified",
    "iamPolicyVerified",
    "containerRuntimeVerified",
    "providerRegistrationAsserted",
    "tenantAuthorityAsserted",
    "evidenceSealed",
    "graphAdmitted",
    "scopeExpansionAuthorized",
    "capabilityActivationAuthorized",
    "approvalSatisfied",
    "permitIssuanceAuthorized",
    "providerSelectionAuthorized",
    "inventoryAuthorized",
    "policyReadAuthorized",
    "policyEvaluationAuthorized",
    "credentialLeaseAuthorized",
    "ambientCredentialAuthorized",
    "toolSelectionAuthorized",
    "workerSelectionAuthorized",
    "networkAccessAuthorized",
    "containerAccessAuthorized",
    "resourceMutationAuthorized",
    "iamMutationAuthorized",
    "runtimeSupportAsserted",
    "executionAuthorized",
)


def _account() -> CloudAccountSurfaceLocator:
    return cloud_account_surface_locator(
        provider_id="aws",
        provider_partition="aws",
        account_id="123456789012",
    )


def _project() -> CloudProjectSurfaceLocator:
    return cloud_project_surface_locator(
        account=cloud_account_surface_locator(
            provider_id="gcp",
            provider_partition="public",
            account_id="organization-123",
        ),
        project_id="security-lab-01",
    )


def _resource() -> CloudResourceSurfaceLocator:
    return cloud_resource_surface_locator(
        parent=_account(),
        service_id="s3",
        location_id="ap-northeast-2",
        resource_type="bucket",
        resource_id="pajin-artifacts-123456789012",
    )


def _iam() -> CloudIAMSurfaceLocator:
    return cloud_iam_surface_locator(
        parent=_account(),
        iam_object_kind=CloudIAMObjectKind.ROLE,
        iam_id="role/pajin-prod-tenant-a",
    )


def _container() -> CloudContainerSurfaceLocator:
    return cloud_container_surface_locator(
        parent=_project(),
        orchestrator_id="kubernetes",
        runtime_scope_id="cluster/security-lab-01",
        namespace="security",
        container_id="f47ac10b-58cc-4372-a567-0e02b2c3d479",
        image_digest=_IMAGE_DIGEST,
    )


def _locators() -> tuple[CloudAccountResourceSurfaceLocator, ...]:
    return (_account(), _project(), _resource(), _iam(), _container())


def test_registry_binds_exact_cloud_semantics_and_locator_classes() -> None:
    registry = registered_cloud_account_resource_locator_registry()
    taxonomy = registered_security_domain_taxonomy()
    graph_semantics = registered_multi_domain_graph_semantics()
    cloud_type_set = next(
        item
        for item in graph_semantics.domain_type_sets
        if item.domain_classification.domain is SecurityDomain.CLOUD
    )

    assert registry.security_domain_taxonomy_digest == taxonomy.taxonomy_digest
    assert registry.multi_domain_graph_semantics_digest == graph_semantics.registry_digest
    assert registry.surface_type == CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE
    assert registry.locator_schema == CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA
    assert registry.domain_classification.domain is SecurityDomain.CLOUD
    assert registry.domain_graph_type_set == cloud_type_set.reference()
    assert cloud_type_set.surface_type == CLOUD_ACCOUNT_RESOURCE_SURFACE_TYPE
    assert cloud_type_set.locator_schema == CLOUD_ACCOUNT_RESOURCE_LOCATOR_SCHEMA
    assert tuple(
        (
            item.surface_class.value,
            item.locator_kind,
            item.parent_requirement,
            item.location_required,
            item.iam_object_kind_required,
            item.image_digest_required,
        )
        for item in registry.locators
    ) == (
        ("account", "cloud-account", "none", False, False, False),
        ("project", "cloud-project", "account", False, False, False),
        ("resource", "cloud-resource", "account-or-project", True, False, False),
        ("iam", "cloud-iam", "account-or-project", False, True, False),
        ("container", "cloud-container", "account-or-project", False, False, True),
    )
    assert tuple(item.surface_class for item in registry.locators) == tuple(CloudSurfaceClass)
    assert registry.discovered_surface_initial_state == "registered-not-authorized"
    assert registry.registry_only is True
    assert len(registry.registry_digest) == 64
    assert (
        CloudAccountResourceLocatorRegistry.model_validate(
            registry.model_dump(mode="json", by_alias=True)
        )
        == registry
    )


def test_locator_and_complete_registry_resolution_require_exact_references() -> None:
    registry = registered_cloud_account_resource_locator_registry()

    for source in registry.locators:
        resolved = resolve_registered_cloud_account_resource_locator(source.reference())
        assert resolved == source
        assert resolved is not source

    resolved_registry = resolve_cloud_account_resource_locator_registry(registry.reference())
    assert resolved_registry == registry
    assert resolved_registry is not registry


def test_exact_resolution_rejects_digest_class_and_registry_substitution() -> None:
    registry = registered_cloud_account_resource_locator_registry()
    source = registry.locators[0]

    with pytest.raises(CloudSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_cloud_account_resource_locator(
            source.reference().model_copy(update={"locator_digest": "0" * 64})
        )
    with pytest.raises(CloudSurfaceRegistryError, match="not registered exactly"):
        resolve_registered_cloud_account_resource_locator(
            source.reference().model_copy(update={"surface_class": CloudSurfaceClass.IAM})
        )
    with pytest.raises(CloudSurfaceRegistryError, match="not registered exactly"):
        resolve_cloud_account_resource_locator_registry(
            registry.reference().model_copy(update={"registry_digest": "0" * 64})
        )


def test_account_and_resource_coordinates_canonicalize_without_provider_calls() -> None:
    account = cloud_account_surface_locator(
        provider_id="AWS",
        provider_partition="AWS",
        account_id="123456789012",
    )
    resource = cloud_resource_surface_locator(
        parent=account,
        service_id="S3",
        location_id="AP-NORTHEAST-2",
        resource_type="BUCKET",
        resource_id="Pajin-Artifact-Bucket",
    )

    assert account.provider_id == "aws"
    assert account.provider_partition == "aws"
    assert resource.service_id == "s3"
    assert resource.location_id == "ap-northeast-2"
    assert resource.resource_type == "bucket"
    assert resource.resource_id == "Pajin-Artifact-Bucket"
    assert (
        CloudAccountSurfaceLocator.model_validate(account.model_dump(mode="json", by_alias=True))
        == account
    )
    assert (
        CloudResourceSurfaceLocator.model_validate(resource.model_dump(mode="json", by_alias=True))
        == resource
    )


def test_project_resource_iam_and_container_preserve_exact_parent_identity() -> None:
    project = _project()
    project_resource = cloud_resource_surface_locator(
        parent=project,
        service_id="object-storage",
        location_id="global",
        resource_type="bucket",
        resource_id="security-evidence",
    )
    project_iam = cloud_iam_surface_locator(
        parent=project,
        iam_object_kind=CloudIAMObjectKind.POLICY,
        iam_id="policies/read-only-inventory-v1",
    )
    container = _container()

    assert project.account.provider_id == "gcp"
    assert project_resource.parent == project
    assert project_resource.parent is not project
    assert project_iam.parent == project
    assert container.parent == project
    assert container.orchestrator_id == "kubernetes"
    assert container.image_digest == _IMAGE_DIGEST
    assert (
        CloudProjectSurfaceLocator.model_validate(project.model_dump(mode="json", by_alias=True))
        == project
    )
    assert (
        CloudIAMSurfaceLocator.model_validate(project_iam.model_dump(mode="json", by_alias=True))
        == project_iam
    )
    assert (
        CloudContainerSurfaceLocator.model_validate(
            container.model_dump(mode="json", by_alias=True)
        )
        == container
    )


@pytest.mark.parametrize(
    ("locator", "expected_class"),
    tuple(zip(_locators(), tuple(CloudSurfaceClass), strict=True)),
)
def test_each_locator_becomes_a_stable_inert_typed_cloud_surface(
    locator: CloudAccountResourceSurfaceLocator,
    expected_class: CloudSurfaceClass,
) -> None:
    surface = typed_cloud_account_resource_surface(locator=locator)

    assert surface.locator == locator
    assert surface.locator is not locator
    assert surface.surface_class is expected_class
    assert surface.initial_state == "registered-not-authorized"
    assert surface.typed_surface_only is True
    assert surface.surface_id == f"cloud-account-resource-surface_{surface.surface_digest}"
    assert surface.reference() == CloudAccountResourceSurfaceRef(
        surfaceId=surface.surface_id,
        surfaceDigest=surface.surface_digest,
        surfaceType=surface.surface_type,
        locatorSchema=surface.locator_schema,
        surfaceClass=expected_class,
        locatorKind=locator.kind,
        locatorRegistry=surface.locator_registry,
    )
    assert (
        CloudAccountResourceSurface.model_validate(surface.model_dump(mode="json", by_alias=True))
        == surface
    )
    assert (
        _CLOUD_LOCATOR_ADAPTER.validate_python(locator.model_dump(mode="json", by_alias=True))
        == locator
    )


def test_class_and_parent_substitution_change_content_identity() -> None:
    account = _account()
    project = cloud_project_surface_locator(account=account, project_id="project-a")
    account_resource = cloud_resource_surface_locator(
        parent=account,
        service_id="s3",
        location_id="global",
        resource_type="bucket",
        resource_id="same-local-id",
    )
    project_resource = cloud_resource_surface_locator(
        parent=project,
        service_id="s3",
        location_id="global",
        resource_type="bucket",
        resource_id="same-local-id",
    )

    surface_ids = {
        typed_cloud_account_resource_surface(locator=locator).surface_id
        for locator in (account, project, account_resource, project_resource)
    }

    assert len(surface_ids) == 4


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("providerId", "auto"),
        ("providerPartition", " latest "),
        ("accountId", "latest"),
        ("accountId", "https://example.test/account"),
        ("accountId", "account*"),
    ),
)
def test_account_rejects_mutable_ambiguous_or_url_identity(
    field: str,
    value: str,
) -> None:
    payload = _account().model_dump(mode="json", by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        CloudAccountSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("serviceId", "unknown"),
        ("locationId", "current"),
        ("resourceType", "default"),
        ("resourceId", "https://storage.example.test/bucket"),
        ("resourceId", "bucket?credential=secret"),
        ("resourceId", "bucket*"),
    ),
)
def test_resource_rejects_mutable_or_active_syntax(field: str, value: str) -> None:
    payload = _resource().model_dump(mode="json", by_alias=True)
    payload[field] = value

    with pytest.raises(ValidationError):
        CloudResourceSurfaceLocator.model_validate(payload)


@pytest.mark.parametrize(
    "image_digest",
    (
        "pajin-worker:latest",
        "sha256:" + "A" * 64,
        "sha256:" + "0" * 63,
        "sha512:" + "0" * 64,
    ),
)
def test_container_requires_exact_sha256_image_digest(image_digest: str) -> None:
    payload = _container().model_dump(mode="json", by_alias=True)
    payload["imageDigest"] = image_digest

    with pytest.raises(ValidationError):
        CloudContainerSurfaceLocator.model_validate(payload)


def test_resource_iam_and_container_reject_non_scope_parent_substitution() -> None:
    resource_payload = _resource().model_dump(mode="json", by_alias=True)
    resource_payload["parent"] = resource_payload.copy()
    with pytest.raises(ValidationError):
        CloudResourceSurfaceLocator.model_validate(resource_payload)

    iam_payload = _iam().model_dump(mode="json", by_alias=True)
    iam_payload["parent"] = _resource().model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError):
        CloudIAMSurfaceLocator.model_validate(iam_payload)

    container_payload = _container().model_dump(mode="json", by_alias=True)
    container_payload["parent"] = _iam().model_dump(mode="json", by_alias=True)
    with pytest.raises(ValidationError):
        CloudContainerSurfaceLocator.model_validate(container_payload)


def test_aws_object_storage_coordinates_remain_inert_provider_local_identifiers() -> None:
    account = _account()
    bucket = cloud_resource_surface_locator(
        parent=account,
        service_id="aws-s3",
        location_id="ap-northeast-2",
        resource_type="bucket",
        resource_id="pajin-production-artifacts",
    )
    role = cloud_iam_surface_locator(
        parent=account,
        iam_object_kind=CloudIAMObjectKind.ROLE,
        iam_id="role/pajin-prod-tenant-a",
    )
    kms_key = cloud_resource_surface_locator(
        parent=account,
        service_id="aws-kms",
        location_id="ap-northeast-2",
        resource_type="key",
        resource_id="11111111-2222-3333-4444-555555555555",
    )

    assert bucket.parent == role.parent == kms_key.parent == account
    assert {
        "tenant_id",
        "endpoint_origin",
        "role_arn",
        "credential",
        "credential_lease",
        "provider_registration",
        "policy_document",
    }.isdisjoint(CloudAccountResourceSurface.model_fields)
    assert typed_cloud_account_resource_surface(locator=bucket).inventory_authorized is False
    assert typed_cloud_account_resource_surface(locator=role).credential_lease_authorized is False


def test_cloud_models_do_not_change_existing_discovery_or_attack_surface_wire() -> None:
    registry = registered_cloud_account_resource_locator_registry()

    assert registry.discovery_wire_changed is False
    assert registry.attack_surface_wire_changed is False
    assert registry.domain_semantics_registry_changed is False
    assert "cloud-account" not in str(SurfaceLocator)
    assert "domain_classification" not in CloudAccountSurfaceLocator.model_fields
    assert "surface_type" not in AttackSurface.model_fields
    assert "locator_schema" not in AttackSurface.model_fields

    with pytest.raises(ValidationError):
        _DISCOVERY_LOCATOR_ADAPTER.validate_python(
            _resource().model_dump(mode="json", by_alias=True)
        )


def test_registry_and_surface_carry_explicit_non_authority_markers() -> None:
    registry_payload = registered_cloud_account_resource_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    surface_payload = typed_cloud_account_resource_surface(locator=_iam()).model_dump(
        mode="json",
        by_alias=True,
    )

    assert all(registry_payload[alias] is False for alias in _REGISTRY_FALSE_ALIASES)
    assert all(surface_payload[alias] is False for alias in _SURFACE_FALSE_ALIASES)
    assert {
        "campaign_profile",
        "scope_authority",
        "capability",
        "approval",
        "permit",
        "provider",
        "tool",
        "worker",
        "request",
        "observation",
        "evidence",
        "credential",
        "secret",
        "policy_document",
    }.isdisjoint(CloudAccountResourceSurface.model_fields)


@pytest.mark.parametrize(
    ("path", "value", "match"),
    (
        (("locators", 0, "surfaceClass"), "resource", "code authority"),
        (("locators", 0, "sourceModelId"), "pajin.fake.Account", "code authority"),
        (("locators", 0, "locatorDigest"), "0" * 64, "Digest differs"),
        (("locators",), "reverse", "code authority"),
        (("domainClassification", "domain"), "web", "code authority"),
        (("multiDomainGraphSemanticsDigest",), "0" * 64, "code authority"),
        (("registryDigest",), "0" * 64, "Digest differs"),
    ),
)
def test_registry_rejects_identity_order_domain_and_digest_drift(
    path: tuple[str | int, ...],
    value: str,
    match: str,
) -> None:
    payload = deepcopy(
        registered_cloud_account_resource_locator_registry().model_dump(
            mode="json",
            by_alias=True,
        )
    )
    if path == ("locators",):
        payload["locators"].reverse()
    else:
        target = payload
        for component in path[:-1]:
            target = target[component]
        target[path[-1]] = value

    with pytest.raises(ValidationError, match=match):
        CloudAccountResourceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _REGISTRY_FALSE_ALIASES)
def test_registry_rejects_authority_escalation_and_boolean_coercion(alias: str) -> None:
    payload = registered_cloud_account_resource_locator_registry().model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        CloudAccountResourceLocatorRegistry.model_validate(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        CloudAccountResourceLocatorRegistry.model_validate(payload)


@pytest.mark.parametrize("alias", _SURFACE_FALSE_ALIASES)
def test_typed_surface_rejects_authority_escalation_and_boolean_coercion(
    alias: str,
) -> None:
    payload = typed_cloud_account_resource_surface(locator=_iam()).model_dump(
        mode="json",
        by_alias=True,
    )
    payload[alias] = True
    with pytest.raises(ValidationError):
        CloudAccountResourceSurface.model_validate(payload)

    payload[alias] = "false"
    with pytest.raises(ValidationError, match="must be booleans"):
        CloudAccountResourceSurface.model_validate(payload)


def test_typed_surface_rejects_registry_domain_identity_digest_and_authority_injection() -> None:
    original = typed_cloud_account_resource_surface(locator=_iam()).model_dump(
        mode="json",
        by_alias=True,
    )
    mutations = (
        ("locatorRegistry", "registryDigest", "0" * 64),
        ("domainClassification", "domain", "web"),
        (None, "surfaceClass", "account"),
        (None, "surfaceDigest", "0" * 64),
        (None, "surfaceId", "cloud-account-resource-surface_" + "0" * 64),
        (None, "credentialLease", {"accessKey": "redacted"}),
        (None, "providerSelection", {"adapterDigest": "0" * 64}),
    )

    for parent, key, value in mutations:
        payload = deepcopy(original)
        target = payload if parent is None else payload[parent]
        target[key] = value
        with pytest.raises(ValidationError):
            CloudAccountResourceSurface.model_validate(payload)


def test_locator_definition_rejects_boolean_coercion_and_secret_mapping() -> None:
    definition = registered_cloud_account_resource_locator_registry().locators[0]
    payload = definition.model_dump(mode="json", by_alias=True)
    payload["locationRequired"] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        RegisteredCloudAccountResourceLocator.model_validate(payload)

    payload = definition.model_dump(mode="json", by_alias=True)
    payload["credentialProviderId"] = "ambient"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        RegisteredCloudAccountResourceLocator.model_validate(payload)


@pytest.mark.parametrize("locator", _locators())
@pytest.mark.parametrize("alias", ("secretReferenceEmbedded", "credentialReferenceEmbedded"))
def test_locators_reject_secret_markers_and_credential_field_injection(
    locator: CloudAccountResourceSurfaceLocator,
    alias: str,
) -> None:
    payload = locator.model_dump(mode="json", by_alias=True)
    payload[alias] = True
    with pytest.raises(ValidationError):
        _CLOUD_LOCATOR_ADAPTER.validate_python(payload)

    payload[alias] = 0
    with pytest.raises(ValidationError, match="must be booleans"):
        _CLOUD_LOCATOR_ADAPTER.validate_python(payload)

    payload = locator.model_dump(mode="json", by_alias=True)
    payload["accessToken"] = "redacted"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        _CLOUD_LOCATOR_ADAPTER.validate_python(payload)
