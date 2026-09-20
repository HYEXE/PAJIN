from __future__ import annotations

import socket
import subprocess
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import Any, cast

import httpx
import pytest
from pydantic import ValidationError

from pajin.agentic.models import PentestSpecialization
from pajin.capabilities.activation import (
    capability_normalized_parameters_digest,
    capability_tool_request_digest,
)
from pajin.capabilities.agentic_web_specialist import WebSpecialistAssessmentTool
from pajin.capabilities.agentic_web_specialist_v2 import (
    WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID,
    WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION,
    WEB_SQLI_SPECIALIST_V2_TOOL_ID,
    AgenticWebSpecialistV2CapabilityError,
    WebSQLSpecialistCapabilityActivationSetV2,
    WebSQLSpecialistCapabilityActivationV2,
    WebSQLSpecialistCapabilityBundleV2,
    activate_web_sqli_specialist_capability_v2,
    web_sqli_specialist_capability_bundle_v2,
)
from pajin.capabilities.authorities import (
    CapabilityAuthorityError,
    CapabilityAuthorityRegistry,
    CapabilityAuthorityRole,
    CodeBackedCapability,
    RegisteredCapabilityAuthority,
)
from pajin.capabilities.lifecycle import (
    CapabilityLifecycleKeyRole,
    CapabilityLifecycleKeyState,
    CapabilityLifecyclePolicy,
    CapabilityLifecycleRegistry,
    CapabilityLifecycleSigner,
    CapabilityLifecycleTrustKey,
    CapabilityReleaseBundle,
    CapabilityReleaseRef,
    CapabilityReleaseStatement,
    CapabilityReviewDecision,
    CapabilityReviewStatement,
    CapabilityUseProfile,
    capability_lifecycle_public_key,
)
from pajin.capabilities.models import (
    CapabilityDefinitionRegistry,
    CapabilityMaturity,
    capability_definition_digest,
)
from pajin.domain.models import ToolResult, ToolRiskTier
from pajin.runtime.worker import WorkerResult, WorkerStatus
from tests.test_agentic_web_specialist_capability import (
    SpecialistCapabilityFixture,
    _v2_tool,
)
from tests.test_agentic_web_specialist_capability import (
    _activation as _v1_activation,
)
from tests.test_agentic_web_specialist_capability import (
    _fixture as _specialist_fixture,
)

NOW = datetime(2026, 9, 20, 6, 0, tzinfo=UTC)


def _seed(label: str) -> bytes:
    return sha256(f"agentic-sqli-v2-activation:{label}".encode()).digest()


def _trust_key(
    label: str,
    *,
    principal: str,
    role: CapabilityLifecycleKeyRole,
) -> CapabilityLifecycleTrustKey:
    return CapabilityLifecycleTrustKey(
        keyId=f"agentic.sqli-v2.{label}",
        principalId=principal,
        role=role,
        publicKeyBase64url=capability_lifecycle_public_key(_seed(label)),
        state=CapabilityLifecycleKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=2),
        notAfter=NOW + timedelta(days=2),
    )


def _signed_lifecycle(
    bundle: WebSQLSpecialistCapabilityBundleV2,
) -> tuple[CapabilityLifecycleRegistry, tuple[CapabilityReleaseRef, ...]]:
    policy = CapabilityLifecyclePolicy.reference_policy()
    publisher_key = _trust_key(
        "publisher",
        principal="agentic.sqli-v2.publisher",
        role=CapabilityLifecycleKeyRole.PUBLISHER,
    )
    reviewer_key = _trust_key(
        "reviewer",
        principal="agentic.sqli-v2.reviewer",
        role=CapabilityLifecycleKeyRole.REVIEWER,
    )
    publisher = CapabilityLifecycleSigner.from_private_key_bytes(
        key=publisher_key,
        private_key=_seed("publisher"),
    )
    reviewer = CapabilityLifecycleSigner.from_private_key_bytes(
        key=reviewer_key,
        private_key=_seed("reviewer"),
    )
    capability = bundle.capability().reference()
    review = CapabilityReviewStatement(
        capability=capability,
        targetMaturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewerPrincipalId=reviewer.key.principal_id,
        checklistDigest=sha256(b"sqli-v2-review:1").hexdigest(),
        decision=CapabilityReviewDecision.APPROVED,
        issuedAt=NOW - timedelta(minutes=26),
        expiresAt=NOW + timedelta(hours=1),
    )
    signed_review = reviewer.sign_review(review)
    release = CapabilityReleaseStatement(
        capability=capability,
        maturity=CapabilityMaturity.EXPERIMENTAL,
        sequence=1,
        previousReleaseDigest=None,
        policyDigest=policy.digest,
        reviewDigests=(signed_review.statement.review_digest,),
        publisherPrincipalId=publisher.key.principal_id,
        issuedAt=NOW - timedelta(minutes=25),
    )
    signed_bundle = CapabilityReleaseBundle(
        release=publisher.sign_release(release),
        reviews=(signed_review,),
    )
    lifecycle = CapabilityLifecycleRegistry(
        definitions=bundle.definitions,
        authorities=bundle.authorities,
        policy=policy,
        trust_keys=(publisher_key, reviewer_key),
        releases=(signed_bundle,),
        clock=lambda: NOW,
    )
    return lifecycle, (signed_bundle.release.statement.reference(),)


def _bundle(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[SpecialistCapabilityFixture, WebSQLSpecialistCapabilityBundleV2]:
    fixture = _specialist_fixture(monkeypatch)
    fixture.registry.register(_v2_tool(fixture))
    return fixture, web_sqli_specialist_capability_bundle_v2(fixture.registry)


def _activation(
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    SpecialistCapabilityFixture,
    WebSQLSpecialistCapabilityActivationV2,
    tuple[CapabilityReleaseRef, ...],
]:
    fixture, bundle = _bundle(monkeypatch)
    lifecycle, releases = _signed_lifecycle(bundle)
    activation = activate_web_sqli_specialist_capability_v2(
        bundle=bundle,
        lifecycle=lifecycle,
        release=releases[-1],
    )
    return fixture, activation, releases


def test_v2_bundle_is_one_sqli_definition_with_all_seven_code_backed_roles(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, bundle = _bundle(monkeypatch)
    manifests = bundle.authorities.capabilities()

    assert len(bundle.definitions.definitions()) == 1
    assert len(manifests) == 1
    capability = manifests[0]
    assert isinstance(capability, CodeBackedCapability)
    assert capability.capability == bundle.definition.reference()
    assert bundle.capability() == capability
    assert bundle.definition.capability_id == WEB_SQLI_SPECIALIST_V2_CAPABILITY_ID
    assert bundle.definition.capability_version == WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION
    assert bundle.definition.tool.tool_id == WEB_SQLI_SPECIALIST_V2_TOOL_ID
    assert [binding.role for binding in capability.authorities] == sorted(
        CapabilityAuthorityRole,
        key=lambda role: role.value,
    )
    assert len({binding.authority_digest for binding in capability.authorities}) == 7
    assert (
        capability.reference()
        != cast(Any, fixture.bundle).capability(PentestSpecialization.SQL_INJECTION).reference()
    )
    assert (
        CodeBackedCapability.model_validate(capability.model_dump(mode="json", by_alias=True))
        == capability
    )


def test_signed_range_activation_prepares_only_the_exact_v2_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, activation, releases = _activation(monkeypatch)
    release = releases[-1]
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)

    definition = activation.definition()
    resolved = activation.resolve_for_dispatch(
        activation.activation_set.binding.action_capability.reference()
    )
    first = activation.prepare_action(
        release=release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    second = activation.prepare_action(
        release=release,
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )

    assert activation.activation_set.profile is CapabilityUseProfile.RANGE
    assert definition == activation.bundle.definition
    assert resolved.release == release
    assert resolved.capability.reference() == activation.bundle.capability().reference()
    assert activation.action_registry().resolve(first.capability) == (
        activation.activation_set.binding.action_capability
    )
    assert first == second
    assert first.release == release
    assert first.capability.capability_version == WEB_SQLI_SPECIALIST_V2_CAPABILITY_VERSION
    assert first.request.tool_id == WEB_SQLI_SPECIALIST_V2_TOOL_ID
    assert first.request.request_id.startswith("agentic-specialist-v2-request_")
    assert first.request_digest == capability_tool_request_digest(first.request)
    assert first.normalized_parameters_digest == (
        capability_normalized_parameters_digest(cast(dict[str, Any], first.request.arguments))
    )
    activation.bundle.tool.validate_request(first.request)


def test_activation_identity_is_canonical_and_rejects_tampering(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, activation, _releases = _activation(monkeypatch)
    activation_set = activation.activation_set
    payload = activation_set.model_dump(mode="json", by_alias=True)

    assert WebSQLSpecialistCapabilityActivationSetV2.model_validate(payload) == activation_set
    expected_digest = capability_definition_digest(
        "pajin.capability.agentic-web-sqli-specialist-activation-set/v2",
        activation_set.model_dump(
            mode="json",
            by_alias=True,
            exclude={"activation_set_id", "activation_set_digest"},
        ),
    )
    assert activation_set.activation_set_digest == expected_digest
    assert activation_set.activation_set_id.endswith(expected_digest)

    payload["activationSetDigest"] = "f" * 64
    with pytest.raises(ValidationError, match="activation-set digest differs"):
        WebSQLSpecialistCapabilityActivationSetV2.model_validate(payload)


def test_copied_context_forged_v1_validator_substitution_is_never_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _specialist_fixture(monkeypatch)
    tool = _v2_tool(fixture)
    genuine = WebSpecialistAssessmentTool(
        specialization=PentestSpecialization.SQL_INJECTION,
        preparations=fixture.preparation_registry,
        adapters=tool.adapters,
        account_receipts=tool.account_receipts,
    )

    class ForgedValidator:
        def __init__(self) -> None:
            self.calls = 0

        def stable_execution_context(self) -> dict[str, object]:
            return genuine.stable_execution_context()

        def validate_request(self, *_args: object, **_kwargs: object) -> None:
            self.calls += 1

    forged = ForgedValidator()
    tool._v1_validator = cast(Any, forged)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="Tool identity drifted",
    ):
        tool.compile_request(
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    assert forged.calls == 0


def test_instance_shadowed_predecessor_factory_and_validator_are_never_used(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture = _specialist_fixture(monkeypatch)
    tool = _v2_tool(fixture)
    genuine = WebSpecialistAssessmentTool(
        specialization=PentestSpecialization.SQL_INJECTION,
        preparations=fixture.preparation_registry,
        adapters=tool.adapters,
        account_receipts=tool.account_receipts,
    )
    calls = 0

    def forged_validate(*_args: object, **_kwargs: object) -> None:
        nonlocal calls
        calls += 1

    genuine.validate_request = cast(Any, forged_validate)
    tool._new_validation_predecessor = cast(Any, lambda: genuine)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="Tool identity drifted",
    ):
        tool.compile_request(
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    assert calls == 0


def test_self_consistent_rehashed_action_binding_cannot_replace_code_owned_definition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, activation, _releases = _activation(monkeypatch)
    payload = activation.activation_set.model_dump(mode="json", by_alias=True)
    action = cast(dict[str, Any], payload["binding"]["actionCapability"])
    action["riskTier"] = ToolRiskTier.T1.value
    action["capabilityDigest"] = ""
    payload["activationSetId"] = ""
    payload["activationSetDigest"] = ""
    forged = WebSQLSpecialistCapabilityActivationSetV2.model_validate(payload)

    assert forged.activation_set_digest != activation.activation_set.activation_set_digest
    assert forged.binding.action_capability.risk_tier is ToolRiskTier.T1
    object.__setattr__(activation, "activation_set", forged)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="signed activation drifted",
    ):
        activation.action_registry()


def test_activation_requires_private_factory_and_exact_activation_set_type(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, activation, _releases = _activation(monkeypatch)

    with pytest.raises(TypeError, match="code-owned factory"):
        WebSQLSpecialistCapabilityActivationV2(
            bundle=activation.bundle,
            lifecycle=activation.lifecycle,
            activation_set=activation.activation_set,
            _factory_token=object(),
        )

    forged_activation = object.__new__(WebSQLSpecialistCapabilityActivationV2)
    object.__setattr__(forged_activation, "bundle", activation.bundle)
    object.__setattr__(forged_activation, "lifecycle", activation.lifecycle)
    object.__setattr__(forged_activation, "activation_set", activation.activation_set)
    object.__setattr__(forged_activation, "_factory_token", object())
    binding = activation.activation_set.binding
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="runtime identity drifted",
    ):
        forged_activation.resolve_for_dispatch(binding.action_capability.reference())
    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="runtime identity drifted",
    ):
        forged_activation.authority(CapabilityAuthorityRole.MATERIALIZER)
    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="runtime identity drifted",
    ):
        forged_activation.prepare_action(
            release=binding.release,
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    class ForgedActivationSet(WebSQLSpecialistCapabilityActivationSetV2):
        pass

    forged_set = ForgedActivationSet.model_validate(
        activation.activation_set.model_dump(mode="json", by_alias=True)
    )
    object.__setattr__(activation, "activation_set", forged_set)
    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="runtime identity drifted",
    ):
        activation.definition()


def test_activation_rejects_foreign_and_v1_release_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, bundle = _bundle(monkeypatch)
    lifecycle, releases = _signed_lifecycle(bundle)

    v1 = cast(Any, _v1_activation(fixture, PentestSpecialization.SQL_INJECTION))
    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="activation failed closed",
    ):
        activate_web_sqli_specialist_capability_v2(
            bundle=bundle,
            lifecycle=lifecycle,
            release=v1.activation_set.binding.release,
        )

    current = activate_web_sqli_specialist_capability_v2(
        bundle=bundle,
        lifecycle=lifecycle,
        release=releases[0],
    )
    with pytest.raises(AgenticWebSpecialistV2CapabilityError, match="outside"):
        current.resolve_for_dispatch(v1.activation_set.binding.action_capability.reference())


def test_activation_rechecks_signed_lifecycle_and_fails_on_registry_replacement(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, activation, _releases = _activation(monkeypatch)
    v1 = cast(Any, _v1_activation(fixture, PentestSpecialization.SQL_INJECTION))

    object.__setattr__(activation, "lifecycle", v1.lifecycle)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="current signed release",
    ):
        activation.definition()


def test_activation_rejects_definition_registry_state_and_instance_shadow_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _fixture, activation, _releases = _activation(monkeypatch)
    original = activation.definition()
    forged_calls = 0

    def forged_resolve(_reference: object) -> object:
        nonlocal forged_calls
        forged_calls += 1
        return original

    activation.bundle.definitions._records.clear()
    monkeypatch.setattr(activation.bundle.definitions, "resolve", forged_resolve)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="registry runtime identity drifted",
    ):
        activation.definition()

    assert forged_calls == 0


def test_activation_rejects_authority_registry_state_and_instance_shadow_bypass(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, activation, releases = _activation(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    capability = activation.bundle.capability()
    handles = dict(activation.bundle.authorities._handles)
    forged_calls = 0

    def forged_capabilities() -> tuple[CodeBackedCapability, ...]:
        nonlocal forged_calls
        forged_calls += 1
        return (capability,)

    def forged_resolve(_reference: object) -> CodeBackedCapability:
        nonlocal forged_calls
        forged_calls += 1
        return capability

    def forged_authority(
        _reference: object,
        role: CapabilityAuthorityRole,
    ) -> RegisteredCapabilityAuthority:
        nonlocal forged_calls
        forged_calls += 1
        key = (
            capability.capability.capability_id,
            capability.capability.capability_version,
            capability.capability.capability_digest,
            role,
        )
        return handles[key]

    activation.bundle.authorities._handles.clear()
    activation.bundle.authorities._manifests.clear()
    monkeypatch.setattr(
        activation.bundle.authorities,
        "capabilities",
        forged_capabilities,
    )
    monkeypatch.setattr(activation.bundle.authorities, "resolve", forged_resolve)
    monkeypatch.setattr(activation.bundle.authorities, "authority", forged_authority)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="registry runtime identity drifted",
    ):
        activation.prepare_action(
            release=releases[-1],
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    assert forged_calls == 0


@pytest.mark.parametrize(
    ("owner_type", "method_name"),
    (
        (CapabilityDefinitionRegistry, "resolve"),
        (CapabilityAuthorityRegistry, "resolve"),
        (CapabilityAuthorityRegistry, "authority"),
        (CapabilityAuthorityRegistry, "capabilities"),
        (CapabilityAuthorityRegistry, "_validate_manifest_handles"),
        (RegisteredCapabilityAuthority, "validate_adapter_identity"),
        (RegisteredCapabilityAuthority, "validate_declared_identity"),
        (RegisteredCapabilityAuthority, "materialize"),
        (RegisteredCapabilityAuthority, "compile"),
    ),
)
def test_activation_rejects_registry_and_wrapper_class_replacement(
    monkeypatch: pytest.MonkeyPatch,
    owner_type: type[object],
    method_name: str,
) -> None:
    fixture, activation, releases = _activation(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    forged_calls = 0

    def forged(*_args: object, **_kwargs: object) -> None:
        nonlocal forged_calls
        forged_calls += 1

    monkeypatch.setattr(owner_type, method_name, forged)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="runtime identity drifted",
    ):
        activation.prepare_action(
            release=releases[-1],
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    assert forged_calls == 0


@pytest.mark.parametrize(
    ("role", "method_name"),
    (
        (CapabilityAuthorityRole.MATERIALIZER, "materialize"),
        (CapabilityAuthorityRole.MATERIALIZER, "stable_execution_context"),
        (CapabilityAuthorityRole.ACTION_COMPILER, "compile"),
        (CapabilityAuthorityRole.ACTION_COMPILER, "stable_execution_context"),
    ),
)
def test_activation_rejects_concrete_authority_adapter_replacement(
    monkeypatch: pytest.MonkeyPatch,
    role: CapabilityAuthorityRole,
    method_name: str,
) -> None:
    fixture, activation, releases = _activation(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    handle = activation.authority(role)
    adapter_type = type(handle._adapter)
    forged_calls = 0

    def forged(*_args: object, **_kwargs: object) -> None:
        nonlocal forged_calls
        forged_calls += 1

    monkeypatch.setattr(adapter_type, method_name, forged)

    with pytest.raises(
        AgenticWebSpecialistV2CapabilityError,
        match="authority runtime identity drifted",
    ):
        activation.prepare_action(
            release=releases[-1],
            preparation_id=preparation.preparation_id,
            preparation_digest=preparation.preparation_digest,
            account_receipt_ref=fixture.receipt.reference(),
        )

    assert forged_calls == 0


def test_non_compiler_roles_and_direct_tool_dispatch_fail_closed_with_zero_io(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fixture, activation, releases = _activation(monkeypatch)
    preparation = fixture.preparation(PentestSpecialization.SQL_INJECTION)
    calls: list[str] = []

    def sync_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("sync-io")

    async def async_tripwire(*_args: object, **_kwargs: object) -> None:
        calls.append("async-io")

    monkeypatch.setattr(socket, "create_connection", sync_tripwire)
    monkeypatch.setattr(socket, "socket", sync_tripwire)
    monkeypatch.setattr(subprocess, "Popen", sync_tripwire)
    monkeypatch.setattr(subprocess, "run", sync_tripwire)
    monkeypatch.setattr(subprocess, "call", sync_tripwire)
    monkeypatch.setattr(subprocess, "check_call", sync_tripwire)
    monkeypatch.setattr(subprocess, "check_output", sync_tripwire)
    monkeypatch.setattr(httpx.Client, "request", sync_tripwire)
    monkeypatch.setattr(httpx.AsyncClient, "request", async_tripwire)

    prepared = activation.prepare_action(
        release=releases[-1],
        preparation_id=preparation.preparation_id,
        preparation_digest=preparation.preparation_digest,
        account_receipt_ref=fixture.receipt.reference(),
    )
    materialized = activation.authority(CapabilityAuthorityRole.MATERIALIZER).materialize(
        cast(dict[str, Any], prepared.request.arguments)
    )
    assert (
        activation.authority(CapabilityAuthorityRole.ACTION_COMPILER).compile(
            prepared.request,
            materialized,
        )
        == prepared.request
    )

    worker_result = WorkerResult(
        execution_id="execution-sqli-v2",
        backend="specialist-v2-test",
        status=WorkerStatus.SUCCEEDED,
        exit_code=0,
        started_at=NOW,
        finished_at=NOW,
    )
    tool_result = ToolResult(
        request_id=prepared.request.request_id,
        tool_id=prepared.request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW,
    )
    fail_closed = (
        lambda: activation.authority(CapabilityAuthorityRole.EXECUTOR_ADAPTER).prepare(
            prepared.request
        ),
        lambda: activation.authority(CapabilityAuthorityRole.RESULT_NORMALIZER).normalize(
            prepared.request,
            worker_result,
        ),
        lambda: activation.authority(CapabilityAuthorityRole.SUCCESS_ORACLE).evaluate(
            prepared.request,
            tool_result,
        ),
        lambda: activation.authority(CapabilityAuthorityRole.REPLAY_STRATEGY).plan_replay(
            prepared.request,
            tool_result,
        ),
        lambda: activation.authority(CapabilityAuthorityRole.CLEANUP_HANDLER).plan_cleanup(
            prepared.request,
            tool_result,
        ),
        lambda: activation.bundle.tool.prepare(prepared.request),
        lambda: activation.bundle.tool.interpret(prepared.request, worker_result),
    )
    for invoke in fail_closed:
        with pytest.raises(
            (AgenticWebSpecialistV2CapabilityError, CapabilityAuthorityError),
            match="schema-v6 specialist Gateway",
        ):
            invoke()

    assert calls == []
