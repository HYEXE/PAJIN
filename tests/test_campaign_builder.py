from __future__ import annotations

from copy import deepcopy
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.modes.bug_bounty import (
    BugBountyScopeApproval,
    BugBountyScopeService,
    load_bug_bounty_program,
)
from pajin.modes.ctf import CTFChallengeService, load_ctf_challenge
from pajin.workflow.campaign_builder import (
    CampaignBuilderError,
    CampaignBuilderGate,
    CampaignBuilderSourceKind,
    CampaignProfileScopeDraft,
    build_campaign_profile_scope_draft,
)

_EXAMPLES = Path(__file__).parents[1] / "examples"


def test_bug_bounty_builder_binds_existing_scope_input_without_compiling_campaign() -> None:
    program = load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml")
    review = BugBountyScopeService().review(program)

    draft = build_campaign_profile_scope_draft(
        program,
        profile_id="pajin.profile.bug-hunt",
    )

    assert draft.source is not program
    assert draft.source_kind is CampaignBuilderSourceKind.BUG_BOUNTY_PROGRAM
    assert draft.scope_preview.approval_digest == review.scope_digest
    assert draft.source_digest != review.scope_digest
    assert draft.selected_profile.profile_id == "pajin.profile.bug-hunt"
    assert draft.scope_preview.allow == ("http://host.docker.internal:8770/v1/users/lookup",)
    assert draft.scope_preview.deny == ("http://host.docker.internal:8770/admin/**",)
    assert len(draft.scope_preview.target_inputs) == 1
    target = draft.scope_preview.target_inputs[0]
    assert target.source_id == "synthetic-user-lookup"
    assert target.target_type == "bug-bounty-api"
    assert target.compiler_supported is True
    assert target.target_execution_authorized is False
    assert draft.scope_preview.scope_authorized is False
    assert draft.required_gates == (
        CampaignBuilderGate.SCOPE_DIGEST_APPROVAL,
        CampaignBuilderGate.AUTHORIZATION_WINDOW_RECHECK,
    )
    assert draft.campaign_manifest_compiled is False
    assert draft.capability_granted is False
    assert draft.permit_granted is False
    assert draft.execution_authorized is False
    assert "campaign" not in CampaignProfileScopeDraft.model_fields


@pytest.mark.parametrize(
    ("filename", "target_type", "endpoint"),
    (
        (
            "ctf-web-backup-lab.yaml",
            "ctf-web",
            "http://host.docker.internal:8780/backup/config.json.bak",
        ),
        (
            "ctf-crypto-xor-lab.yaml",
            "ctf-crypto",
            (
                "http://artifact.invalid/crypto-xor-lab/"
                "cd63642e4c282f36a73bf4834fbb9587e9b46053823a0b0728e4ccf5904a7880"
            ),
        ),
    ),
)
def test_ctf_builder_projects_exact_existing_target_input(
    filename: str,
    target_type: str,
    endpoint: str,
) -> None:
    challenge = load_ctf_challenge(_EXAMPLES / filename)

    draft = build_campaign_profile_scope_draft(
        challenge,
        profile_id="pajin.profile.ctf",
    )

    assert draft.source_kind is CampaignBuilderSourceKind.CTF_CHALLENGE
    assert draft.selected_profile.profile_id == "pajin.profile.ctf"
    assert draft.scope_preview.allow == (endpoint,)
    assert draft.scope_preview.deny == ()
    assert draft.scope_preview.review_only_source_ids == ()
    assert draft.scope_preview.approval_digest is None
    assert len(draft.scope_preview.target_inputs) == 1
    target = draft.scope_preview.target_inputs[0]
    assert target.source_id == challenge.metadata.name
    assert target.target_type == target_type
    assert target.endpoint == endpoint
    assert target.compiler_supported is True
    assert draft.required_gates == (CampaignBuilderGate.AUTHORIZATION_WINDOW_RECHECK,)
    assert draft.campaign_manifest_compiled is False
    assert draft.execution_authorized is False


def test_builder_draft_is_content_addressed_round_trippable_and_detached() -> None:
    program = load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml")
    first = build_campaign_profile_scope_draft(
        program,
        profile_id="pajin.profile.bug-hunt",
    )
    second = build_campaign_profile_scope_draft(
        program,
        profile_id="pajin.profile.bug-hunt",
    )

    assert first == second
    assert first.draft_id == f"campaign-builder-draft:{first.draft_digest}"
    assert (
        CampaignProfileScopeDraft.model_validate(first.model_dump(mode="json", by_alias=True))
        == first
    )

    program.spec.scope.in_scope[0].entry_points.clear()
    assert first.scope_preview.target_inputs
    assert first.source.spec.scope.in_scope[0].entry_points


@pytest.mark.parametrize(
    ("filename", "profile_id"),
    (
        ("bug-bounty-lab-program.yaml", "pajin.profile.ctf"),
        ("ctf-web-backup-lab.yaml", "pajin.profile.bug-hunt"),
        ("ctf-web-backup-lab.yaml", "pajin.profile.pentest"),
    ),
)
def test_builder_rejects_cross_profile_or_pentest_selection(
    filename: str,
    profile_id: str,
) -> None:
    if filename.startswith("bug-bounty"):
        source = load_bug_bounty_program(_EXAMPLES / filename)
    else:
        source = load_ctf_challenge(_EXAMPLES / filename)

    with pytest.raises(CampaignBuilderError, match="does not match"):
        build_campaign_profile_scope_draft(source, profile_id=profile_id)


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("draftId",), "campaign-builder-draft:" + "0" * 64),
        (("draftDigest",), "1" * 64),
        (("profileCatalogDigest",), "2" * 64),
        (("selectedProfile", "profileId"), "pajin.profile.ctf"),
        (("sourceKind",), "ctf-challenge"),
        (("sourceDigest",), "3" * 64),
        (("scopePreview", "allow"), ["https://outside.invalid/**"]),
        (("scopePreview", "scopeAuthorized"), True),
        (("scopePreview", "targetInputs", 0, "compilerSupported"), False),
        (("scopePreview", "targetInputs", 0, "compilerSupported"), 1),
        (("scopePreview", "targetInputs", 0, "targetExecutionAuthorized"), True),
        (
            ("compilerEntrypoint",),
            "pajin.modes.ctf.service.CTFChallengeService.compile_campaign",
        ),
        (("requiredGates",), ["authorization-window-recheck"]),
        (("campaignManifestCompiled",), True),
        (("capabilityGranted",), True),
        (("permitGranted",), True),
        (("executionAuthorized",), True),
    ),
)
def test_builder_wire_rejects_substitution_or_authority_escalation(
    path: tuple[str | int, ...],
    replacement: object,
) -> None:
    draft = build_campaign_profile_scope_draft(
        load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml"),
        profile_id="pajin.profile.bug-hunt",
    )
    payload = deepcopy(draft.model_dump(mode="json", by_alias=True))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement

    with pytest.raises(ValidationError):
        CampaignProfileScopeDraft.model_validate(payload)


def test_builder_wire_rejects_source_mutation_under_retained_digest() -> None:
    draft = build_campaign_profile_scope_draft(
        load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml"),
        profile_id="pajin.profile.bug-hunt",
    )
    payload = draft.model_dump(mode="json", by_alias=True)
    payload["source"]["spec"]["objectives"].append("Expand testing beyond approved scope.")

    with pytest.raises(ValidationError, match="typed source"):
        CampaignProfileScopeDraft.model_validate(payload)

    reordered = draft.model_dump(mode="json", by_alias=True)
    reordered["source"]["spec"]["objectives"].reverse()
    with pytest.raises(ValidationError, match="typed source"):
        CampaignProfileScopeDraft.model_validate(reordered)


def test_review_only_bug_bounty_input_remains_blocked_by_existing_compiler() -> None:
    program = load_bug_bounty_program(_EXAMPLES / "bug-bounty-program.yaml")
    draft = build_campaign_profile_scope_draft(
        program,
        profile_id="pajin.profile.bug-hunt",
    )
    review = BugBountyScopeService().review(program)
    approval = BugBountyScopeApproval(
        scope_digest=review.scope_digest,
        approved_by="operator",
        approved_at=datetime(2026, 7, 14, tzinfo=UTC),
        expires_at=datetime(2026, 7, 15, tzinfo=UTC),
        evidence="operator-reviewed-program-policy",
    )

    assert draft.scope_preview.review_only_source_ids == (
        "lab-api",
        "lab-web-wildcard",
    )
    assert draft.scope_preview.target_inputs[0].compiler_supported is False
    with pytest.raises(ValueError, match="review-only"):
        BugBountyScopeService().compile_campaign(
            program,
            approval,
            evaluated_at=datetime(2026, 7, 14, 1, tzinfo=UTC),
        )


def test_ctf_builder_does_not_bypass_existing_authorization_window() -> None:
    challenge = load_ctf_challenge(_EXAMPLES / "ctf-web-backup-lab.yaml")
    draft = build_campaign_profile_scope_draft(
        challenge,
        profile_id="pajin.profile.ctf",
    )

    assert draft.draft_state == "input-validated-not-compiled"
    with pytest.raises(ValueError, match="authorization is not active"):
        CTFChallengeService().compile_campaign(
            challenge,
            evaluated_at=datetime(2100, 1, 1, tzinfo=UTC),
        )
