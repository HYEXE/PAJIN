from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.campaign_drafts import (
    CampaignDraftCompilationRequest,
    CampaignDraftCompilationView,
    ControlPlaneCampaignDraftCompiler,
    ControlPlaneCampaignDraftReader,
)
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.domain.models import CampaignMode, campaign_manifest_digest
from pajin.modes.bug_bounty import BugBountyScopeService, load_bug_bounty_program
from pajin.modes.ctf import CTFChallengeManifest, CTFChallengeService, load_ctf_challenge
from pajin.workflow.campaign_builder import (
    CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME,
    CampaignBuilderDraftArtifact,
    build_campaign_profile_scope_draft,
    write_campaign_profile_scope_draft,
)

_EXAMPLES = Path(__file__).parents[1] / "examples"

_OPERATOR_TOKEN = "campaign-compile-operator-token-00001"
_APPROVER_TOKEN = "campaign-compile-approver-token-00001"
_AUDITOR_TOKEN = "campaign-compile-auditor-token-000001"
_WORKER_TOKEN = "campaign-compile-worker-token-0000001"


def _settings(database_path: Path, *, draft_root: Path | None) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database_path.as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="campaign-compile-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="campaign-compile-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            _AUDITOR_TOKEN: Principal(
                subject="campaign-compile-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject="campaign-compile-worker",
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


def _write_ctf_draft(root: Path) -> CampaignBuilderDraftArtifact:
    draft = build_campaign_profile_scope_draft(
        load_ctf_challenge(_EXAMPLES / "ctf-web-backup-lab.yaml"),
        profile_id="pajin.profile.ctf",
    )
    return write_campaign_profile_scope_draft(draft, root)


def _scope_approval(
    digest: str,
    *,
    approved_at: str = "2026-07-14T00:00:00Z",
    expires_at: str = "2099-07-14T00:00:00Z",
    evidence: str = "operator-reviewed-exact-scope",
) -> dict[str, str]:
    return {
        "scope_digest": digest,
        "approved_by": "campaign-compile-approver",
        "approved_at": approved_at,
        "expires_at": expires_at,
        "evidence": evidence,
    }


def _compile_path(artifact: CampaignBuilderDraftArtifact) -> str:
    return f"/v1/campaign-drafts/{artifact.draft.draft_digest}/compile"


def test_operator_compiles_verified_bug_bounty_draft_without_persistence_or_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_write(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Campaign draft compilation must not persist a Campaign")

    monkeypatch.setattr(BugBountyScopeService, "write_campaign", unexpected_write)
    monkeypatch.setattr(CTFChallengeService, "write_campaign", unexpected_write)
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    approval_digest = artifact.draft.scope_preview.approval_digest
    assert approval_digest is not None
    app = create_app(_settings(tmp_path / "bug-bounty.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "sourceKind": "bug-bounty-program",
                "scopeApproval": _scope_approval(approval_digest),
            },
        )
        runs = client.get("/v1/runs", headers=_auth(_OPERATOR_TOKEN))

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store, max-age=0"
    payload = response.json()
    assert payload["draftId"] == artifact.draft.draft_id
    assert payload["draftDigest"] == artifact.draft.draft_digest
    assert payload["sourceKind"] == "bug-bounty-program"
    assert payload["campaign"]["spec"]["mode"] == CampaignMode.BUG_BOUNTY
    assert payload["campaignDigest"] == campaign_manifest_digest(
        CampaignDraftCompilationView.model_validate(payload).campaign
    )
    assert payload["campaignManifestCompiled"] is True
    assert payload["campaignPersisted"] is False
    assert payload["capabilityGranted"] is False
    assert payload["permitGranted"] is False
    assert payload["runSubmitted"] is False
    assert payload["executionAuthorized"] is False
    assert runs.status_code == 200
    assert runs.json()["total"] == 0


def test_operator_compiles_ctf_draft_with_embedded_authorization_recheck(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    app = create_app(_settings(tmp_path / "ctf.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == 200
    payload = response.json()
    assert payload["profileId"] == "pajin.profile.ctf"
    assert payload["campaign"]["spec"]["mode"] == CampaignMode.CTF
    assert payload["campaignPersisted"] is False
    assert payload["runSubmitted"] is False


@pytest.mark.parametrize(
    ("headers", "expected_status"),
    (
        ({}, 401),
        (_auth(_APPROVER_TOKEN), 403),
        (_auth(_AUDITOR_TOKEN), 403),
        (_auth(_WORKER_TOKEN), 403),
    ),
)
def test_campaign_draft_compilation_is_operator_only(
    headers: dict[str, str],
    expected_status: int,
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    app = create_app(_settings(tmp_path / f"role-{expected_status}.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=headers,
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == expected_status


@pytest.mark.parametrize(
    "payload",
    (
        {"sourceKind": "bug-bounty-program"},
        {
            "sourceKind": "ctf-challenge",
            "scopeApproval": _scope_approval("a" * 64),
        },
        {
            "sourceKind": "ctf-challenge",
            "evaluatedAt": "2026-07-14T00:00:00Z",
        },
    ),
)
def test_compilation_request_rejects_missing_foreign_or_backdated_authority(
    payload: dict[str, object],
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    app = create_app(_settings(tmp_path / "invalid-request.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json=payload,
        )

    assert response.status_code == 422


def test_source_kind_substitution_fails_before_any_existing_compiler(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def unexpected_compile(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("mismatched source kind must not reach a compiler")

    monkeypatch.setattr(BugBountyScopeService, "compile_campaign", unexpected_compile)
    monkeypatch.setattr(CTFChallengeService, "compile_campaign", unexpected_compile)
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    app = create_app(_settings(tmp_path / "source-kind.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Campaign draft source kind does not match the compiler handoff"
    }


@pytest.mark.parametrize(
    "approval",
    (
        _scope_approval("f" * 64, evidence="foreign-scope-secret"),
        _scope_approval(
            "a" * 64,
            approved_at="2026-07-14T00:00:00Z",
            expires_at="2026-07-15T00:00:00Z",
            evidence="stale-approval-secret",
        ),
    ),
)
def test_forged_or_stale_scope_approval_fails_closed_without_reflection(
    approval: dict[str, str],
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    if approval["scope_digest"] == "a" * 64:
        approval = {**approval, "scope_digest": artifact.draft.scope_preview.approval_digest}
    app = create_app(_settings(tmp_path / "bad-approval.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={
                "sourceKind": "bug-bounty-program",
                "scopeApproval": approval,
            },
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Campaign draft compiler rejected the handoff"}
    assert approval["evidence"] not in response.text


def test_expired_ctf_authorization_is_rechecked_by_existing_compiler(
    tmp_path: Path,
) -> None:
    source = load_ctf_challenge(_EXAMPLES / "ctf-web-backup-lab.yaml")
    payload = source.model_dump(mode="json", by_alias=True)
    payload["spec"]["authorization"]["expiresAt"] = "2026-07-15T00:00:00Z"
    expired = CTFChallengeManifest.model_validate(payload)
    root = tmp_path / "drafts"
    artifact = write_campaign_profile_scope_draft(
        build_campaign_profile_scope_draft(
            expired,
            profile_id="pajin.profile.ctf",
        ),
        root,
    )
    app = create_app(_settings(tmp_path / "expired-ctf.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == 409
    assert response.json() == {"detail": "Campaign draft compiler rejected the handoff"}


def test_invalid_existing_compiler_output_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        CTFChallengeService,
        "compile_campaign",
        lambda *_args, **_kwargs: object(),
    )
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    app = create_app(_settings(tmp_path / "invalid-output.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == 409
    assert response.json() == {
        "detail": "Campaign draft compiler produced an invalid Campaign"
    }


def test_tampered_or_digest_substituted_draft_fails_before_compilation(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_bug_bounty_draft(root)
    substituted_digest = "b" * 64
    substituted_path = root / substituted_digest / CAMPAIGN_BUILDER_DRAFT_ARTIFACT_FILENAME
    substituted_path.parent.mkdir(parents=True)
    substituted_path.write_bytes(artifact.path.read_bytes())

    payload = json.loads(artifact.path.read_text(encoding="utf-8"))
    forged_endpoint = "https://forged-secret.invalid/target"
    payload["source"]["spec"]["scope"]["inScope"][0]["entryPoints"][0] = forged_endpoint
    artifact.path.write_text(json.dumps(payload), encoding="utf-8")
    app = create_app(_settings(tmp_path / "tampered.db", draft_root=root))

    with TestClient(app) as client:
        responses = [
            client.post(
                f"/v1/campaign-drafts/{digest}/compile",
                headers=_auth(_OPERATOR_TOKEN),
                json={
                    "sourceKind": "bug-bounty-program",
                    "scopeApproval": _scope_approval("a" * 64),
                },
            )
            for digest in (artifact.draft.draft_digest, substituted_digest)
        ]

    assert [response.status_code for response in responses] == [404, 404]
    assert all(forged_endpoint not in response.text for response in responses)


def test_compilation_view_rejects_authority_marker_or_campaign_digest_forgery(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    app = create_app(_settings(tmp_path / "view-binding.db", draft_root=root))

    with TestClient(app) as client:
        response = client.post(
            _compile_path(artifact),
            headers=_auth(_OPERATOR_TOKEN),
            json={"sourceKind": "ctf-challenge"},
        )

    assert response.status_code == 200
    payload = response.json()
    for field, replacement in (
        ("campaignManifestCompiled", False),
        ("campaignPersisted", True),
        ("capabilityGranted", True),
        ("permitGranted", True),
        ("runSubmitted", True),
        ("executionAuthorized", True),
        ("campaignDigest", "0" * 64),
    ):
        forged = deepcopy(payload)
        forged[field] = replacement
        with pytest.raises(ValidationError):
            CampaignDraftCompilationView.model_validate(forged)


def test_compiler_rejects_naive_server_clock_before_existing_compiler(
    tmp_path: Path,
) -> None:
    root = tmp_path / "drafts"
    artifact = _write_ctf_draft(root)
    compiler = ControlPlaneCampaignDraftCompiler(
        reader=ControlPlaneCampaignDraftReader(root),
        clock=lambda: datetime(2026, 7, 14),
    )

    with pytest.raises(StateConflict, match="clock is invalid"):
        compiler.compile(
            artifact.draft.draft_digest,
            CampaignDraftCompilationRequest(sourceKind="ctf-challenge"),
        )
