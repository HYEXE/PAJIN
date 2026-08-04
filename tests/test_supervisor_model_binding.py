from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignManifest
from pajin.providers import ProviderRegistration
from pajin.supervision import (
    SupervisorModelBinding,
    SupervisorModelBindingError,
    SupervisorModelConfiguration,
    SupervisorShadowProposalDraft,
    bind_supervisor_model,
    verify_supervisor_model_binding,
)


def _provider(
    *,
    provider_id: str = "shadow-provider",
    model: str = "shadow-model",
    allowed_function_tools: set[str] | None = None,
) -> ProviderRegistration:
    return ProviderRegistration.model_validate(
        {
            "provider_id": provider_id,
            "endpoint": f"https://{provider_id}.example/v1/chat/completions",
            "model": model,
            "secret_ref": f"provider/{provider_id}/api-key",
            "allow_streaming": False,
            "allowed_function_tools": allowed_function_tools or set(),
        }
    )


def _binding(campaign: CampaignManifest) -> SupervisorModelBinding:
    return bind_supervisor_model(
        campaign,
        _provider(),
        model_revision="2026-08-04",
        configuration=SupervisorModelConfiguration(),
    )


def test_supervisor_model_binding_is_content_addressed_and_non_invocable(
    sample_campaign: CampaignManifest,
) -> None:
    binding = _binding(sample_campaign)
    raw = binding.model_dump(mode="json", by_alias=True)

    assert SupervisorModelBinding.model_validate(raw) == binding
    assert binding.supervisor_role == "supervisor"
    assert binding.profile_compilation.source_campaign == sample_campaign
    assert binding.profile_digest == binding.profile_compilation.profile.profile_digest
    assert binding.provider_model.model_id == "shadow-model"
    assert binding.provider_model.model_revision == "2026-08-04"
    assert binding.allowed_input_schemas[0].schema_kind == "walking-shadow-input"
    assert binding.allowed_input_schemas[1].schema_kind == "collaboration-snapshot"
    assert binding.output_proposal_schema.schema_kind == "shadow-proposal-draft"
    assert binding.binding_state == "shadow-model-bound-not-invocable"
    assert binding.shadow_mode is True
    assert binding.snapshot_only_input_required is True
    assert binding.model_invocation_authorized is False
    assert binding.capability_granted is False
    assert binding.permit_granted is False
    assert binding.execution_authorized is False
    assert binding.activation_eligible is False
    assert "secretRef" not in raw["providerModel"]
    assert "provider/shadow-provider/api-key" not in str(raw)


def test_supervisor_output_schema_has_no_direct_command_or_tool_authority() -> None:
    fields = SupervisorShadowProposalDraft.model_fields

    assert {
        "command",
        "messages",
        "prompt",
        "tool_request",
        "arguments",
        "capability",
        "permit",
    }.isdisjoint(fields)
    with pytest.raises(ValidationError):
        SupervisorShadowProposalDraft.model_validate(
            {
                "snapshotId": "walking-shadow-snapshot_" + "a" * 64,
                "snapshotDigest": "a" * 64,
                "proposalKind": "stop",
                "rationale": "Stop and request human review.",
                "command": "shell.execute",
            }
        )


def test_provider_registration_digest_is_independent_of_set_insertion_order(
    sample_campaign: CampaignManifest,
) -> None:
    first_tools = {"zeta_tool", "alpha_tool"}
    second_tools = set(reversed(tuple(first_tools)))
    configuration = SupervisorModelConfiguration()

    first = bind_supervisor_model(
        sample_campaign,
        _provider(allowed_function_tools=first_tools),
        model_revision="2026-08-04",
        configuration=configuration,
    )
    second = bind_supervisor_model(
        sample_campaign,
        _provider(allowed_function_tools=second_tools),
        model_revision="2026-08-04",
        configuration=configuration,
    )

    assert first == second


@pytest.mark.parametrize(
    "payload",
    (
        {"seed": True},
        {"maxCompletionTokens": "2048"},
        {"topP": True},
        {"streaming": 0},
        {"promptContentBound": 0},
        {"toolCallsAllowed": 0},
    ),
)
def test_supervisor_model_configuration_rejects_coerced_wire_values(
    payload: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        SupervisorModelConfiguration.model_validate(payload)


def test_supervisor_model_configuration_normalizes_negative_zero() -> None:
    assert (
        SupervisorModelConfiguration(temperature=-0.0)
        == SupervisorModelConfiguration(temperature=0.0)
    )


@pytest.mark.parametrize(
    ("path", "replacement"),
    [
        (("bindingDigest",), "0" * 64),
        (("campaignDigest",), "1" * 64),
        (("profileCompilationDigest",), "2" * 64),
        (("profileDigest",), "3" * 64),
        (("commonEngineContractDigest",), "4" * 64),
        (("supervisorRole",), "specialist"),
        (("providerModelDigest",), "5" * 64),
        (("providerModel", "modelRevision"), "latest"),
        (("providerModel", "providerRegistrationDigest"), "6" * 64),
        (("configurationDigest",), "7" * 64),
        (("configuration", "maxCompletionTokens"), 4_096),
        (("walkingShadowPolicyDigest",), "8" * 64),
        (("allowedInputSchemas",), "reverse"),
        (("allowedInputSchemas", 0, "schemaDigest"), "9" * 64),
        (("outputProposalSchema", "schemaDigest"), "a" * 64),
        (("modelInvocationAuthorized",), True),
        (("capabilityGranted",), True),
        (("permitGranted",), True),
        (("executionAuthorized",), True),
        (("activationEligible",), True),
        (("shadowMode",), 1),
        (("snapshotOnlyInputRequired",), 1),
        (("modelInvocationAuthorized",), 0),
    ],
)
def test_supervisor_model_binding_rejects_forgery_and_escalation(
    sample_campaign: CampaignManifest,
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    raw = deepcopy(_binding(sample_campaign).model_dump(mode="json", by_alias=True))
    if replacement == "reverse":
        replacement = list(reversed(raw["allowedInputSchemas"]))
    target = raw
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        SupervisorModelBinding.model_validate(raw)


def test_supervisor_model_binding_rejects_valid_cross_runtime_substitution(
    sample_campaign: CampaignManifest,
) -> None:
    expected_provider = _provider()
    expected_configuration = SupervisorModelConfiguration()
    expected = bind_supervisor_model(
        sample_campaign,
        expected_provider,
        model_revision="2026-08-04",
        configuration=expected_configuration,
    )
    foreign_campaign = sample_campaign.model_copy(
        update={
            "metadata": sample_campaign.metadata.model_copy(
                update={"name": "foreign-supervisor-campaign"}
            )
        },
        deep=True,
    )
    substitutions = (
        bind_supervisor_model(
            foreign_campaign,
            expected_provider,
            model_revision="2026-08-04",
            configuration=expected_configuration,
        ),
        bind_supervisor_model(
            sample_campaign,
            _provider(provider_id="foreign-provider"),
            model_revision="2026-08-04",
            configuration=expected_configuration,
        ),
        bind_supervisor_model(
            sample_campaign,
            expected_provider,
            model_revision="2026-08-05",
            configuration=expected_configuration,
        ),
        bind_supervisor_model(
            sample_campaign,
            expected_provider,
            model_revision="2026-08-04",
            configuration=SupervisorModelConfiguration(maxCompletionTokens=4_096),
        ),
    )

    assert (
        verify_supervisor_model_binding(
            expected,
            sample_campaign,
            expected_provider,
            model_revision="2026-08-04",
            configuration=expected_configuration,
        )
        == expected
    )
    for substitution in substitutions:
        with pytest.raises(SupervisorModelBindingError):
            verify_supervisor_model_binding(
                substitution,
                sample_campaign,
                expected_provider,
                model_revision="2026-08-04",
                configuration=expected_configuration,
            )
