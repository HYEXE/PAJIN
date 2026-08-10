from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.campaign_drafts import (
    CampaignDraftView,
    ControlPlaneCampaignDraftReader,
)
from pajin.control_plane.errors import ResourceNotFound
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.modes.bug_bounty import BugBountyScopeService, load_bug_bounty_program
from pajin.modes.ctf import CTFChallengeService
from pajin.workflow.campaign_builder import (
    CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME,
    CampaignBuilderDraftArtifact,
    build_campaign_profile_scope_draft,
    write_campaign_profile_scope_draft,
)

_EXAMPLES = Path(__file__).parents[1] / "examples"

_OPERATOR_TOKEN = "campaign-draft-operator-token-00001"
_APPROVER_TOKEN = "campaign-draft-approver-token-00001"
_AUDITOR_TOKEN = "campaign-draft-auditor-token-000001"
_WORKER_TOKEN = "campaign-draft-worker-token-0000001"


def _settings(database_path: Path, *, draft_root: Path | None) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="campaign-draft-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="campaign-draft-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            _AUDITOR_TOKEN: Principal(
                subject="campaign-draft-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="campaign-draft-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"test-v1": b"test-checkpoint-signing-key-32-bytes-minimum"},
        active_checkpoint_key_id="test-v1",
        campaign_draft_root=draft_root,
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _write_bug_bounty_draft(root: Path) -> CampaignBuilderDraftArtifact:
    draft = build_campaign_profile_scope_draft(
        load_bug_bounty_program(_EXAMPLES / "bug-bounty-lab-program.yaml"),
        profile_id="pajin.profile.bug-hunt",
    )
    return write_campaign_profile_scope_draft(draft, root)


def test_operator_reads_only_bounded_verified_campaign_draft_projection(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_compile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Campaign draft lookup must not invoke a Campaign compiler")

    monkeypatch.setattr(BugBountyScopeService, "compile_campaign", unexpected_compile)
    monkeypatch.setattr(CTFChallengeService, "compile_campaign", unexpected_compile)
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    app = create_app(_settings(tmp_path / "read.db", draft_root=root))

    with TestClient(app) as client:
        response = client.get(
            f"/v1/campaign-drafts/{artifact.draft.draft_digest}",
            headers=_auth(_OPERATOR_TOKEN),
        )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    assert response.json() == {
        "apiVersion": "pajin.control-plane/campaign-draft-view/v1alpha1",
        "kind": "CampaignDraftView",
        "draftId": artifact.draft.draft_id,
        "draftDigest": artifact.draft.draft_digest,
        "profileId": "pajin.profile.bug-hunt",
        "profileVersion": "1.0.0",
        "sourceKind": "bug-bounty-program",
        "allowRuleCount": 1,
        "denyRuleCount": 1,
        "targetInputCount": 1,
        "reviewOnlySourceCount": 0,
        "requiredGates": [
            "scope-digest-approval",
            "authorization-window-recheck",
        ],
        "draftState": "input-validated-not-compiled",
        "scopeAuthorized": False,
        "campaignManifestCompiled": False,
        "capabilityGranted": False,
        "permitGranted": False,
        "executionAuthorized": False,
    }
    assert "source" not in response.json()
    assert "scopePreview" not in response.json()
    assert "http://host.docker.internal:8770" not in response.text


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    (
        ({}, 401),
        (_auth(_APPROVER_TOKEN), 403),
        (_auth(_AUDITOR_TOKEN), 403),
        (_auth(_WORKER_TOKEN), 403),
    ),
)
def test_campaign_draft_projection_is_operator_only(
    headers: dict[str, str],
    expected_status: int,
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    app = create_app(_settings(tmp_path / f"role-{expected_status}.db", draft_root=root))

    with TestClient(app) as client:
        response = client.get(
            f"/v1/campaign-drafts/{artifact.draft.draft_digest}",
            headers=headers,
        )

    assert response.status_code == expected_status
    assert "http://host.docker.internal:8770" not in response.text


def test_campaign_draft_lookup_fails_closed_when_root_is_not_configured(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path / "unconfigured.db", draft_root=None))

    with TestClient(app) as client:
        response = client.get(
            f"/v1/campaign-drafts/{'a' * 64}",
            headers=_auth(_OPERATOR_TOKEN),
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Campaign Builder draft root is not configured"}


def test_campaign_draft_lookup_rejects_malformed_or_missing_digest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    app = create_app(_settings(tmp_path / "bad-digest.db", draft_root=root))

    with TestClient(app) as client:
        malformed = [
            client.get(
                f"/v1/campaign-drafts/{candidate}",
                headers=_auth(_OPERATOR_TOKEN),
            )
            for candidate in ("A" * 64, "short")
        ]
        missing = client.get(
            f"/v1/campaign-drafts/{'a' * 64}",
            headers=_auth(_OPERATOR_TOKEN),
        )

    assert [response.status_code for response in malformed] == [422, 422]
    assert missing.status_code == 404
    assert missing.json() == {
        "detail": "Campaign Builder draft was not found or failed verification"
    }
    with pytest.raises(ResourceNotFound, match="not found or failed verification"):
        ControlPlaneCampaignDraftReader(root).get("../" + "a" * 64)


def test_campaign_draft_lookup_rejects_digest_directory_substitution(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    substituted_digest = "b" * 64
    substituted_path = root / substituted_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
    substituted_path.parent.mkdir(parents=True)
    substituted_path.write_bytes(artifact.path.read_bytes())
    app = create_app(_settings(tmp_path / "substitution.db", draft_root=root))

    with TestClient(app) as client:
        response = client.get(
            f"/v1/campaign-drafts/{substituted_digest}",
            headers=_auth(_OPERATOR_TOKEN),
        )

    assert response.status_code == 404
    assert artifact.draft.draft_id not in response.text


def test_campaign_draft_lookup_hides_tampered_source_details(tmp_path: Path) -> None:
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    payload = json.loads(artifact.path.read_text(encoding="utf-8"))
    forged_endpoint = "https://forged-secret.invalid/target"
    payload["source"]["spec"]["scope"]["inScope"][0]["entryPoints"][0] = forged_endpoint
    artifact.path.write_text(json.dumps(payload), encoding="utf-8")
    app = create_app(_settings(tmp_path / "tampered.db", draft_root=root))

    with TestClient(app) as client:
        response = client.get(
            f"/v1/campaign-drafts/{artifact.draft.draft_digest}",
            headers=_auth(_OPERATOR_TOKEN),
        )

    assert response.status_code == 404
    assert forged_endpoint not in response.text
    assert "Traceback" not in response.text


def test_campaign_draft_root_loads_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    root = tmp_path / "configured-drafts"
    monkeypatch.setenv("PAJIN_CP_CAMPAIGN_DRAFT_ROOT", str(root))

    settings = ControlPlaneSettings.from_env()

    assert settings.campaign_draft_root == root


@pytest.mark.parametrize("raw", ["", " ", "\t", "\r\n"])
def test_campaign_draft_root_environment_rejects_blank_values(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "test-checkpoint-signing-key-32-bytes-minimum",
    )
    monkeypatch.setenv("PAJIN_CP_CAMPAIGN_DRAFT_ROOT", raw)

    with pytest.raises(RuntimeError, match="CAMPAIGN_DRAFT_ROOT must not be blank"):
        ControlPlaneSettings.from_env()


def test_campaign_draft_view_rejects_false_numeric_authority_markers(tmp_path: Path) -> None:
    view = ControlPlaneCampaignDraftReader(tmp_path / "drafts")
    artifact = _write_bug_bounty_draft(tmp_path / "drafts")
    payload = view.get(artifact.draft.draft_digest).model_dump(mode="json", by_alias=True)
    payload["executionAuthorized"] = 0

    with pytest.raises(ValidationError, match="authority markers"):
        CampaignDraftView.model_validate(payload)
