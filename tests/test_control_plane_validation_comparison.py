from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.validation_comparison import (
    VerifiedWalkingControlComparisonReader,
    VerifiedWalkingControlComparisonView,
    WalkingComparisonRunLocator,
    WalkingControlComparisonCoordinate,
    WalkingControlComparisonLane,
)
from pajin.domain.validation_controls import ValidationControlKind

COMPARISON_ID = f"walking-control-comparison_{'1' * 64}"
OPERATOR_TOKEN = "walking-comparison-operator-token-long-enough"
APPROVER_TOKEN = "walking-comparison-approver-token-long-enough"
AUDITOR_TOKEN = "walking-comparison-auditor-token-long-enough"
WORKER_TOKEN = "walking-comparison-worker-token-long-enough"


@pytest.mark.parametrize(
    "relative_path",
    ["../outside", "/absolute", "runs/../outside", "runs\\foreign"],
)
def test_walking_control_comparison_locator_rejects_path_escape(
    relative_path: str,
) -> None:
    with pytest.raises(ValidationError, match="canonical relative path"):
        WalkingComparisonRunLocator(
            runId="walking-run",
            relativePath=relative_path,
            artifactPath="artifacts/authority.json",
        )


def _settings(database: Path, *, evidence_root: Path | None = None) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="walking-comparison-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="walking-comparison-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="walking-comparison-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="walking-comparison-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"walking-comparison-signing-key-32-bytes"},
        validation_evidence_root=evidence_root,
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _coordinate(
    ordinal: int,
    role: str,
    *,
    control_kind: ValidationControlKind | None = None,
) -> WalkingControlComparisonCoordinate:
    return WalkingControlComparisonCoordinate.model_validate(
        {
            "ordinal": ordinal,
            "role": role,
            "controlKind": control_kind,
            "runId": f"redacted-run-{ordinal}",
            "rootDigest": f"{ordinal + 1:x}" * 64,
            "executionDigest": f"{ordinal + 7:x}" * 64,
        }
    )


def _view() -> VerifiedWalkingControlComparisonView:
    coordinates = (
        _coordinate(0, "original-source"),
        _coordinate(1, "primary-replay"),
        _coordinate(2, "additional-replay"),
        _coordinate(3, "baseline-control", control_kind=ValidationControlKind.BASELINE),
        _coordinate(
            4,
            "negative-control",
            control_kind=ValidationControlKind.NEGATIVE_CONTROL,
        ),
        _coordinate(
            5,
            "counterfactual-control",
            control_kind=ValidationControlKind.COUNTERFACTUAL,
        ),
    )
    return VerifiedWalkingControlComparisonView(
        comparisonId=COMPARISON_ID,
        comparisonDigest="1" * 64,
        assessmentDigest="2" * 64,
        campaignDigest="3" * 64,
        claimDigest="4" * 64,
        profileId="pajin.profile.ai-assessment",
        profileVersion="1.0.0",
        achievedDepth="repeated-controlled-validity-replay",
        validationState="profile-floor-satisfied-not-confirmed",
        controlContrast="contrast-observed",
        lanes=(
            WalkingControlComparisonLane(
                stage="original",
                availability="verified-reference",
                authorityRole="sealed-source-execution",
                executionCount=1,
                coordinates=coordinates[0:1],
            ),
            WalkingControlComparisonLane(
                stage="replay",
                availability="verified-reference",
                authorityRole="sealed-repeated-validity-replay",
                executionCount=2,
                coordinates=coordinates[1:3],
            ),
            WalkingControlComparisonLane(
                stage="control",
                availability="verified-reference",
                authorityRole="sealed-baseline-negative-counterfactual",
                executionCount=3,
                coordinates=coordinates[3:6],
            ),
            WalkingControlComparisonLane(
                stage="retest",
                availability="not-in-authority",
                authorityRole="retest-not-bound",
                executionCount=0,
                coordinates=(),
            ),
        ),
    )


def test_walking_control_comparison_view_rejects_authority_escalation() -> None:
    raw = _view().model_dump(mode="json", by_alias=True)
    raw["authorityBoundary"]["retestEvidenceIncluded"] = 0
    with pytest.raises(ValidationError, match="authority markers must be false"):
        VerifiedWalkingControlComparisonView.model_validate(raw)

    raw = _view().model_dump(mode="json", by_alias=True)
    raw["lanes"][2]["coordinates"][1]["controlKind"] = "baseline"
    with pytest.raises(ValidationError, match="Control order differs"):
        VerifiedWalkingControlComparisonView.model_validate(raw)


def test_walking_control_comparison_endpoint_is_operator_only_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    view = _view()

    def read(
        _reader: VerifiedWalkingControlComparisonReader,
        *,
        comparison_id: str,
    ) -> VerifiedWalkingControlComparisonView:
        assert comparison_id == COMPARISON_ID
        return view

    monkeypatch.setattr(VerifiedWalkingControlComparisonReader, "read", read)
    app = create_app(_settings(tmp_path / "control-plane.sqlite3"))
    path = f"/v1/validation-comparisons/walking/{COMPARISON_ID}"

    with TestClient(app) as client:
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))
        assert response.status_code == 200
        body = response.json()
        assert body["apiVersion"] == (
            "pajin.control-plane/verified-walking-control-comparison-view/v1alpha1"
        )
        assert body["comparisonMode"] == (
            "exact-execution-coordinates-with-verified-control-contrast"
        )
        assert [lane["executionCount"] for lane in body["lanes"]] == [1, 2, 3, 0]
        assert body["authorityBoundary"] == {
            "val004cSealedPredecessorsVerified": True,
            "exactExecutionLineageVerified": True,
            "controlContrastVerified": True,
            "identifiersAndContentRedacted": True,
            "retestEvidenceIncluded": False,
            "viewCreatesValidationAssessment": False,
            "viewAttestsProfileSelection": False,
            "viewAttestsRemediation": False,
            "viewConfirmsFinding": False,
            "viewAuthorizesExecution": False,
        }
        assert "sensitive-claim-statement" not in response.text
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        assert client.get(
            "/v1/validation-comparisons/walking/not-a-comparison",
            headers=_auth(OPERATOR_TOKEN),
        ).status_code == 422


def test_walking_control_comparison_endpoint_fails_closed_without_evidence(
    tmp_path: Path,
) -> None:
    unconfigured = create_app(_settings(tmp_path / "unconfigured.sqlite3"))
    path = f"/v1/validation-comparisons/walking/{COMPARISON_ID}"
    with TestClient(unconfigured) as client:
        assert client.get(path, headers=_auth(OPERATOR_TOKEN)).status_code == 503

    configured_root = tmp_path / "evidence"
    configured_root.mkdir()
    configured = create_app(
        _settings(
            tmp_path / "configured.sqlite3",
            evidence_root=configured_root,
        )
    )
    with TestClient(configured) as client:
        assert client.get(path, headers=_auth(OPERATOR_TOKEN)).status_code == 404


def test_walking_control_comparison_evidence_root_loads_from_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "walking-comparison-environment-key-32-bytes",
    )
    root = tmp_path / "evidence"
    monkeypatch.setenv("PAJIN_CP_VALIDATION_EVIDENCE_ROOT", str(root))

    settings = ControlPlaneSettings.from_env()

    assert settings.validation_evidence_root == root


@pytest.mark.parametrize("raw", ["", " ", "\t", "\r\n"])
def test_walking_control_comparison_evidence_root_rejects_blank_environment(
    raw: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "walking-comparison-environment-key-32-bytes",
    )
    monkeypatch.setenv("PAJIN_CP_VALIDATION_EVIDENCE_ROOT", raw)

    with pytest.raises(RuntimeError, match="VALIDATION_EVIDENCE_ROOT must not be blank"):
        ControlPlaneSettings.from_env()
