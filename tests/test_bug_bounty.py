import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.manifest import load_manifest
from pajin.domain.models import (
    CampaignMode,
    CapabilityGrant,
    ToolRequest,
    ToolRiskTier,
)
from pajin.modes.bug_bounty import (
    BugBountyProgramManifest,
    BugBountyScopeApproval,
    BugBountyScopeService,
    load_bug_bounty_program,
)
from pajin.policy.engine import PolicyEngine
from pajin.tools.http import HTTPGetTool


def _program() -> BugBountyProgramManifest:
    return load_bug_bounty_program(Path("examples/bug-bounty-program.yaml"))


def _executable_program() -> BugBountyProgramManifest:
    return load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))


def _approval(digest: str) -> BugBountyScopeApproval:
    return BugBountyScopeApproval(
        scope_digest=digest,
        approved_by="program-owner",
        approved_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
        expires_at=datetime(2027, 7, 13, 1, tzinfo=UTC),
        evidence="private-program-authorization-ticket-123",
    )


def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:  # pragma: no cover - depends on Windows developer privileges
        pytest.skip(f"symbolic links are unavailable: {exc}")


def test_review_normalizes_scope_and_binds_raw_policy() -> None:
    program = _program()
    service = BugBountyScopeService()
    review = service.review(program, generated_at=datetime(2026, 7, 13, tzinfo=UTC))

    assert len(review.scope_digest) == 64
    assert len(review.source_sha256) == 64
    assert review.entry_points == ["https://api.example.invalid/v1/health"]
    assert "denial-of-service" in review.prohibited_techniques
    assert "social-engineering" in review.prohibited_techniques
    assert review.allowed_tool_categories == {"active-test", "http"}
    assert review.max_requests_per_minute == 20
    assert review.approval_required
    assert any("wildcard" in warning for warning in review.warnings)
    assert any("automatic retention" in item for item in review.manual_controls)

    changed = program.model_copy(deep=True)
    changed.spec.policy.raw_text += "\nA newly published restriction."
    assert service.review(changed).scope_digest != review.scope_digest

    reordered_payload = program.model_dump(mode="json", by_alias=True)
    reordered_payload["spec"]["rules"]["allowedMethods"].reverse()
    reordered_payload["spec"]["rules"]["allowedToolCategories"].reverse()
    reordered = BugBountyProgramManifest.model_validate(reordered_payload)
    assert service.review(reordered).scope_digest == review.scope_digest


def test_compile_requires_exact_digest_and_maps_enforced_policy() -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    review = service.review(program)

    with pytest.raises(ValueError, match="digest does not match"):
        service.compile_campaign(program, _approval("0" * 64))

    campaign = service.compile_campaign(program, _approval(review.scope_digest))
    rules = campaign.spec.rules_of_engagement
    assert campaign.spec.mode is CampaignMode.BUG_BOUNTY
    assert campaign.spec.targets[0].endpoint == ("http://host.docker.internal:8770/v1/users/lookup")
    assert campaign.spec.scope.allow == sorted(campaign.spec.scope.allow)
    assert "http://host.docker.internal:8770/admin/**" in campaign.spec.scope.deny
    assert rules.max_tool_risk_tier is ToolRiskTier.T2
    assert rules.allowed_methods == {"GET"}
    assert rules.allowed_tool_categories == {
        "active-test",
        "bug-bounty",
        "http",
        "injection",
    }
    assert rules.max_requests_per_minute == 6
    assert len(rules.testing_windows) == 1
    assert f"scope-sha256:{review.scope_digest}" in campaign.spec.authorization.evidence


def test_compiled_campaign_allows_entry_point_and_denies_excluded_path() -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    review = service.review(program)
    campaign = service.compile_campaign(program, _approval(review.scope_digest))
    entry_point = campaign.spec.targets[0].endpoint
    grant = CapabilityGrant(
        subject="agent:planner-local",
        campaign=campaign.metadata.name,
        tools={"http.get"},
        targets={entry_point, "http://host.docker.internal:8770/admin/users"},
        max_risk_tier=ToolRiskTier.T2,
        max_calls=2,
        expires_at=campaign.spec.authorization.expires_at,
        issued_at=datetime(2026, 7, 13, tzinfo=UTC),
    )
    engine = PolicyEngine()

    allowed = engine.evaluate_tool_request(
        campaign,
        grant,
        ToolRequest(
            agent_id=grant.subject,
            tool_id="http.get",
            target=entry_point,
            method="GET",
        ),
        HTTPGetTool.spec,
        used_calls=0,
        now=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )
    denied = engine.evaluate_tool_request(
        campaign,
        grant,
        ToolRequest(
            agent_id=grant.subject,
            tool_id="http.get",
            target="http://host.docker.internal:8770/admin/users",
            method="GET",
        ),
        HTTPGetTool.spec,
        used_calls=0,
        now=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert allowed.allowed
    assert not denied.allowed
    assert denied.policy == "scope-deny"


def test_compile_rejects_approval_older_than_policy_snapshot() -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    review = service.review(program)
    approval = _approval(review.scope_digest).model_copy(
        update={"approved_at": datetime(2026, 7, 12, tzinfo=UTC)}
    )

    with pytest.raises(ValueError, match="predates"):
        service.compile_campaign(program, approval)


def test_policy_snapshot_and_approval_require_timezone_offsets() -> None:
    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["policy"]["retrievedAt"] = "2026-07-13T00:00:00"
    with pytest.raises(ValidationError, match="retrievedAt must include"):
        BugBountyProgramManifest.model_validate(payload)

    with pytest.raises(ValidationError, match="approved_at must include"):
        BugBountyScopeApproval(
            scope_digest="0" * 64,
            approved_by="program-owner",
            approved_at=datetime(2026, 7, 13),
            expires_at=datetime(2026, 7, 14),
            evidence="ticket",
        )


def test_scope_rejects_entry_point_outside_allow_or_inside_deny() -> None:
    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["inScope"][0]["entryPoints"] = [
        "https://outside.example.invalid/v1/health"
    ]
    with pytest.raises(ValidationError, match="does not match asset"):
        BugBountyProgramManifest.model_validate(payload)

    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"]["inScope"][0]["entryPoints"] = [
        "https://api.example.invalid/v1/admin/users"
    ]
    with pytest.raises(ValidationError, match="out-of-scope"):
        BugBountyProgramManifest.model_validate(payload)


def test_program_rejects_high_risk_and_mandatory_prohibition_conflict() -> None:
    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["rules"]["maxToolRiskTier"] = "T3"
    with pytest.raises(ValidationError, match="cannot compile T3 or T4"):
        BugBountyProgramManifest.model_validate(payload)

    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["rules"]["allowedToolCategories"].append("denial-of-service")
    with pytest.raises(ValidationError, match="mandatory prohibitions"):
        BugBountyProgramManifest.model_validate(payload)


def test_review_and_campaign_artifacts_are_reproducible_and_loadable(tmp_path: Path) -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    artifacts = service.write_review(
        program,
        tmp_path / "reviews",
        generated_at=datetime(2026, 7, 13, tzinfo=UTC),
    )
    normalized = json.loads(artifacts.normalized_program_path.read_text(encoding="utf-8"))
    serialized_review = json.loads(artifacts.review_json_path.read_text(encoding="utf-8"))
    assert normalized["spec"]["policy"]["rawText"] == program.spec.policy.raw_text
    assert serialized_review["scope_digest"] == artifacts.review.scope_digest
    assert artifacts.review.scope_digest in artifacts.review_markdown_path.read_text(
        encoding="utf-8"
    )
    artifacts.review_json_path.write_text("stale", encoding="utf-8")
    rewritten = service.write_review(
        program,
        tmp_path / "reviews",
        generated_at=datetime(2026, 7, 13, tzinfo=UTC),
    )
    assert (
        json.loads(rewritten.review_json_path.read_text(encoding="utf-8"))["scope_digest"]
        == artifacts.review.scope_digest
    )

    campaign_path = tmp_path / "campaigns" / "bug-bounty.yaml"
    service.write_campaign(
        program,
        _approval(artifacts.review.scope_digest),
        campaign_path,
    )
    loaded = load_manifest(campaign_path)
    assert loaded.spec.mode is CampaignMode.BUG_BOUNTY
    assert loaded.spec.rules_of_engagement.max_requests_per_minute == 6
    campaign_path.write_text("stale", encoding="utf-8")
    service.write_campaign(
        program,
        _approval(artifacts.review.scope_digest),
        campaign_path,
    )
    assert load_manifest(campaign_path).spec.mode is CampaignMode.BUG_BOUNTY


def test_scope_review_rejects_symlink_leaf_without_touching_its_target(
    tmp_path: Path,
) -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    review = service.review(program)
    directory = tmp_path / "reviews" / program.metadata.name / review.scope_digest[:12]
    directory.mkdir(parents=True)
    victim = tmp_path / "victim.json"
    victim.write_text("keep", encoding="utf-8")
    _symlink_or_skip(directory / "program.normalized.json", victim)

    with pytest.raises(ValueError, match="symbolic link"):
        service.write_review(program, tmp_path / "reviews")

    assert victim.read_text(encoding="utf-8") == "keep"


def test_scope_review_rejects_symlinked_output_parent(tmp_path: Path) -> None:
    program = _executable_program()
    actual = tmp_path / "actual-reviews"
    actual.mkdir()
    linked = tmp_path / "linked-reviews"
    _symlink_or_skip(linked, actual, directory=True)

    with pytest.raises(ValueError, match="parent contains a symbolic link"):
        BugBountyScopeService().write_review(program, linked)

    assert list(actual.iterdir()) == []


def test_campaign_write_rejects_symlink_leaf_and_parent_without_touching_targets(
    tmp_path: Path,
) -> None:
    program = _executable_program()
    service = BugBountyScopeService()
    approval = _approval(service.review(program).scope_digest)
    victim = tmp_path / "victim.yaml"
    victim.write_text("keep", encoding="utf-8")

    output = tmp_path / "campaigns" / "campaign.yaml"
    output.parent.mkdir()
    _symlink_or_skip(output, victim)
    with pytest.raises(ValueError, match="symbolic link"):
        service.write_campaign(program, approval, output)
    assert victim.read_text(encoding="utf-8") == "keep"

    actual = tmp_path / "actual-campaigns"
    actual.mkdir()
    linked = tmp_path / "linked-campaigns"
    _symlink_or_skip(linked, actual, directory=True)
    with pytest.raises(ValueError, match="parent contains a symbolic link"):
        service.write_campaign(program, approval, linked / "campaign.yaml")
    assert list(actual.iterdir()) == []


def test_scope_review_markdown_neutralizes_untrusted_structure_and_surrogates() -> None:
    program = _program()
    service = BugBountyScopeService()
    review = service.review(program).model_copy(
        update={
            "warnings": ["warning\n## injected <script>alert(1)</script>\ud800"],
            "manual_controls": ["control\r\n- injected"],
        }
    )
    program = program.model_copy(
        update={
            "metadata": program.metadata.model_copy(
                update={"display_name": "Program\n# forged heading\ud800"}
            )
        }
    )

    rendered = service.render_review(program, review)

    assert "\n# forged heading" not in rendered
    assert "\n## injected" not in rendered
    assert "<script>" not in rendered
    assert "\ud800" not in rendered
    assert "Program \\# forged heading" in rendered
    assert "warning \\#\\# injected &lt;script&gt;alert" in rendered


def test_private_network_execution_is_restricted_to_the_fixed_local_lab_profile() -> None:
    payload = _program().model_dump(mode="json", by_alias=True)
    payload["spec"]["rules"]["allowPrivateNetworks"] = True
    with pytest.raises(ValidationError, match="platform: local-lab"):
        BugBountyProgramManifest.model_validate(payload)

    lab = load_bug_bounty_program(Path("examples/bug-bounty-lab-program.yaml"))
    service = BugBountyScopeService()
    review = service.review(lab)
    campaign = service.compile_campaign(lab, _approval(review.scope_digest))

    assert campaign.spec.targets[0].type == "bug-bounty-api"
    assert campaign.spec.rules_of_engagement.allow_private_networks
    assert campaign.spec.targets[0].endpoint.startswith("http://host.docker.internal:8770/")
