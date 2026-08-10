from __future__ import annotations

import json
import os
from copy import deepcopy
from pathlib import Path

import pytest
from platform_test_support import symlink_or_skip
from typer.testing import CliRunner

import pajin.cli as cli
from pajin.modes.bug_bounty import BugBountyScopeService, load_bug_bounty_program
from pajin.modes.ctf import CTFChallengeService
from pajin.workflow.campaign_builder import (
    CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME,
    CampaignBuilderArtifactError,
    build_campaign_profile_scope_draft,
    load_campaign_profile_scope_draft,
    write_campaign_profile_scope_draft,
)

_EXAMPLES = Path(__file__).parents[1] / "examples"


def _write_bug_bounty_draft(tmp_path: Path) -> Path:
    draft = build_campaign_profile_scope_draft(
        load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml"),
        profile_id="pajin.profile.bug-hunt",
    )
    return write_campaign_profile_scope_draft(draft, tmp_path / "drafts").path


def test_draft_artifact_uses_content_addressed_path_and_canonical_wire(tmp_path: Path) -> None:
    program = load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml")
    draft = build_campaign_profile_scope_draft(
        program,
        profile_id="pajin.profile.bug-hunt",
    )

    first = write_campaign_profile_scope_draft(draft, tmp_path / "drafts")
    first_content = first.path.read_bytes()
    second = write_campaign_profile_scope_draft(draft, tmp_path / "drafts")
    payload = json.loads(first.path.read_text(encoding="utf-8"))

    assert first.path == (
        tmp_path / "drafts" / draft.draft_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
    )
    assert first == second
    assert second.path.read_bytes() == first_content
    assert first.draft == load_campaign_profile_scope_draft(first.path)
    rules = payload["source"]["spec"]["rules"]
    assert rules["allowedMethods"] == sorted(rules["allowedMethods"])
    assert rules["allowedToolCategories"] == sorted(rules["allowedToolCategories"])
    assert rules["prohibitedTechniques"] == sorted(rules["prohibitedTechniques"])
    assert rules["stopOn"] == sorted(rules["stopOn"])
    assert rules["testingWindows"][0]["days"] == sorted(rules["testingWindows"][0]["days"])
    required_fields = payload["source"]["spec"]["reporting"]["requiredFields"]
    assert required_fields == sorted(required_fields)
    assert payload["campaignManifestCompiled"] is False
    assert payload["executionAuthorized"] is False
    assert "campaign" not in payload


@pytest.mark.parametrize(
    ("path", "replacement"),
    (
        (("executionAuthorized",), True),
        (("executionAuthorized",), 0),
        (("draftDigest",), "0" * 64),
        (
            ("source", "spec", "scope", "inScope", 0, "entryPoints", 0),
            "https://outside.invalid/",
        ),
    ),
)
def test_draft_artifact_loader_rejects_authority_or_source_substitution(
    path: tuple[str | int, ...],
    replacement: object,
    tmp_path: Path,
) -> None:
    artifact_path = _write_bug_bounty_draft(tmp_path)
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    target = payload
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = replacement
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(CampaignBuilderArtifactError, match="artifact is invalid"):
        load_campaign_profile_scope_draft(artifact_path)


def test_draft_artifact_loader_rejects_ambiguous_json(tmp_path: Path) -> None:
    artifact_path = _write_bug_bounty_draft(tmp_path)
    content = artifact_path.read_text(encoding="utf-8")
    artifact_path.write_text(
        content.replace(
            '  "kind": "CampaignProfileScopeDraft",',
            '  "kind": "CampaignProfileScopeDraft",\n  "kind": "CampaignProfileScopeDraft",',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(CampaignBuilderArtifactError, match="artifact is invalid"):
        load_campaign_profile_scope_draft(artifact_path)


def test_draft_artifact_loader_rejects_linked_leaf_or_parent(tmp_path: Path) -> None:
    artifact_path = _write_bug_bounty_draft(tmp_path)
    linked_leaf = tmp_path / "linked-draft.json"
    symlink_or_skip(linked_leaf, artifact_path)
    with pytest.raises(CampaignBuilderArtifactError, match="artifact is invalid"):
        load_campaign_profile_scope_draft(linked_leaf)

    linked_parent = tmp_path / "linked-parent"
    symlink_or_skip(linked_parent, artifact_path.parent, target_is_directory=True)
    with pytest.raises(CampaignBuilderArtifactError, match="artifact is invalid"):
        load_campaign_profile_scope_draft(linked_parent / artifact_path.name)


def test_draft_artifact_loader_rejects_hardlink_alias(tmp_path: Path) -> None:
    artifact_path = _write_bug_bounty_draft(tmp_path)
    alias = tmp_path / "hardlinked-draft.json"
    try:
        os.link(artifact_path, alias)
    except OSError as exc:
        pytest.skip(f"hard links are unavailable: {exc}")

    with pytest.raises(CampaignBuilderArtifactError, match="artifact is invalid"):
        load_campaign_profile_scope_draft(artifact_path)


@pytest.mark.parametrize(
    ("filename", "profile_id"),
    (
        ("bug-bounty-lab-program.yaml", "pajin.profile.bug-hunt"),
        ("ctf-web-backup-lab.yaml", "pajin.profile.ctf"),
    ),
)
def test_campaign_draft_cli_creates_and_inspects_without_compilation(
    filename: str,
    profile_id: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_compile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Campaign compiler must not run while creating or inspecting a draft")

    monkeypatch.setattr(BugBountyScopeService, "compile_campaign", unexpected_compile)
    monkeypatch.setattr(CTFChallengeService, "compile_campaign", unexpected_compile)
    output = tmp_path / "drafts"

    created = CliRunner().invoke(
        cli.app,
        [
            "campaign-draft-create",
            str(_EXAMPLES / filename),
            "--profile-id",
            profile_id,
            "--output",
            str(output),
        ],
    )

    assert created.exit_code == 0, created.output
    assert "Execution authorized" in created.output
    assert "false" in created.output
    assert "No Campaign, approval, Capability, Permit, or execution authority" in created.output
    artifact_paths = list(output.rglob(CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME))
    assert len(artifact_paths) == 1

    inspected = CliRunner().invoke(
        cli.app,
        ["campaign-draft-inspect", str(artifact_paths[0])],
    )

    assert inspected.exit_code == 0, inspected.output
    assert "Execution authorized" in inspected.output
    assert "not a compiler input or execution authorization" in inspected.output
    assert "Traceback" not in inspected.output


def test_campaign_draft_cli_fails_closed_on_tampered_artifact(tmp_path: Path) -> None:
    artifact_path = _write_bug_bounty_draft(tmp_path)
    payload = deepcopy(json.loads(artifact_path.read_text(encoding="utf-8")))
    payload["scopePreview"]["scopeAuthorized"] = True
    artifact_path.write_text(json.dumps(payload), encoding="utf-8")

    result = CliRunner().invoke(
        cli.app,
        ["campaign-draft-inspect", str(artifact_path)],
    )

    assert result.exit_code == 2, result.output
    assert "Cannot inspect Campaign Builder draft" in result.output
    assert "Traceback" not in result.output
    assert "scopeAuthorized" not in result.output
