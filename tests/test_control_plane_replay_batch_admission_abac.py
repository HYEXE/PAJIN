from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from pajin.control_plane.abac import (
    ControlPlaneReplayBatchAdmissionABACPolicy,
    ControlPlaneReplayBatchAdmissionAuthorizer,
    ReplayBatchAdmissionRule,
    parse_replay_batch_admission_abac_policy,
)
from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.errors import AuthorizationDenied
from pajin.control_plane.models import (
    SOURCE_ARTIFACT_MEDIA_TYPE,
    SOURCE_ARTIFACT_SCHEMA_KIND,
    ArtifactLocator,
    ArtifactRef,
    CreateReplayBatchRequest,
    Principal,
    PrincipalRole,
    ReplayBatchState,
    ReplayBatchView,
    replay_batch_admission_authority_digest,
)
from pajin.domain.models import CampaignMode
from pajin.domain.replay import ReplayPurpose

_OPERATOR_TOKEN = "replay-batch-abac-operator-token-that-is-long-and-distinct"
_OTHER_OPERATOR_TOKEN = "replay-batch-abac-other-operator-token-that-is-long-and-distinct"
_APPROVER_TOKEN = "replay-batch-abac-approver-token-that-is-long-and-distinct"
_WORKER_TOKEN = "replay-batch-abac-worker-token-that-is-long-and-distinct"
_OPERATOR_SUBJECT = "replay-batch-abac-operator"
_OTHER_OPERATOR_SUBJECT = "replay-batch-abac-other-operator"


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _locator(identity: str, *, repository_version: int = 1) -> ArtifactLocator:
    return ArtifactLocator(
        artifact_id=f"artifact_{identity * 32}",
        repository_version=repository_version,
    )


def _request(**updates: object) -> CreateReplayBatchRequest:
    values: dict[str, object] = {
        "source": _locator("1"),
        "idempotency_key": "replay-batch-abac-exact",
    }
    values.update(updates)
    return CreateReplayBatchRequest.model_validate(values)


def _policy(
    request: CreateReplayBatchRequest,
    *,
    subject: str = _OPERATOR_SUBJECT,
) -> ControlPlaneReplayBatchAdmissionABACPolicy:
    digest = replay_batch_admission_authority_digest(request, actor=subject)
    return ControlPlaneReplayBatchAdmissionABACPolicy(
        policy_id="replay-batch-admission-policy_0123456789abcdef0123456789abcdef",
        replay_batch_admission_rules=(
            ReplayBatchAdmissionRule(
                principal_subject=subject,
                action="replay.batch.admit",
                replay_batch_admission_authority_digest=digest,
            ),
        ),
    )


def _settings(
    tmp_path: Path,
    policy: ControlPlaneReplayBatchAdmissionABACPolicy | None,
) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject=_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _OTHER_OPERATOR_TOKEN: Principal(
                subject=_OTHER_OPERATOR_SUBJECT,
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="replay-batch-abac-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            _WORKER_TOKEN: Principal(
                subject="replay-batch-abac-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"replay-batch-abac-checkpoint-key-that-is-long-enough"},
        replay_batch_admission_abac_policy=policy,
    )


def _source() -> ArtifactRef:
    return ArtifactRef(
        artifact_id=_locator("1").artifact_id,
        repository_version=1,
        media_type=SOURCE_ARTIFACT_MEDIA_TYPE,
        schema_kind=SOURCE_ARTIFACT_SCHEMA_KIND,
        byte_length=1,
        content_digest="2" * 64,
        producer_run_id=f"run_{'3' * 32}",
        run_id="engine_replay_batch_abac",
        integrity_root_digest="4" * 64,
        created_by=_OPERATOR_SUBJECT,
    )


class _StubReplayIssuance:
    def __init__(self) -> None:
        self.calls: list[tuple[CreateReplayBatchRequest, str]] = []

    def create_replay_batch(
        self,
        request: CreateReplayBatchRequest,
        *,
        actor: str,
    ) -> ReplayBatchView:
        self.calls.append((request, actor))
        now = datetime(2026, 1, 1, tzinfo=UTC)
        return ReplayBatchView(
            batch_id=f"replay-batch_{'5' * 32}",
            campaign_name="replay-batch-abac",
            source=_source(),
            mode=CampaignMode.AI_REDTEAM,
            purpose=ReplayPurpose.CONFIRMATION,
            policy_version="kisa-confirmation-v1",
            state=ReplayBatchState.PLANNED,
            cas_version=1,
            created_by=actor,
            created_at=now,
            updated_at=now,
        )


def test_replay_batch_admission_policy_is_strict_and_exact() -> None:
    request = _request()
    policy = _policy(request)
    exact_rule = policy.replay_batch_admission_rules[0]
    with pytest.raises(ValidationError, match="admission rules must be unique"):
        ControlPlaneReplayBatchAdmissionABACPolicy(
            policy_id="replay-batch-admission-policy_0123456789abcdef0123456789abcdef",
            replay_batch_admission_rules=(exact_rule, exact_rule),
        )
    raw = policy.model_dump(mode="json")
    raw["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        parse_replay_batch_admission_abac_policy(json.dumps(raw).encode("utf-8"))

    authorizer = ControlPlaneReplayBatchAdmissionAuthorizer(policy)
    with pytest.raises(AuthorizationDenied, match="Replay batch admission"):
        authorizer.authorize_replay_batch_admission(
            principal_subject=_OPERATOR_SUBJECT,
            replay_batch_admission_authority_digest="f" * 64,
        )


def test_replay_batch_admission_rules_must_name_authenticated_operators(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="authenticated Operator subjects"):
        _settings(tmp_path, _policy(_request(), subject="unknown-operator"))


def test_environment_loads_replay_batch_admission_policy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _policy(_request())
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_SUBJECT", _OPERATOR_SUBJECT)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "replay-batch-abac-checkpoint-key-that-is-long-enough",
    )
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY",
        policy.model_dump_json(),
    )
    for name in (
        "PAJIN_CP_ABAC_POLICY",
        "PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY",
        "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY",
        "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY",
        "PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY",
        "PAJIN_CP_OIDC_HUMAN_TRUST_POLICY",
        "PAJIN_CP_WORKER_MTLS_TRUST_POLICY",
    ):
        monkeypatch.delenv(name, raising=False)

    settings = ControlPlaneSettings.from_env()

    assert settings.replay_batch_admission_abac_policy == policy


def test_exact_replay_batch_admission_and_idempotent_retry_are_authorized(
    tmp_path: Path,
) -> None:
    request = _request()
    app = create_app(_settings(tmp_path, _policy(request)))
    stub = _StubReplayIssuance()
    with TestClient(app) as client:
        app.state.control_plane._replay_issuance = stub
        first = client.post(
            "/v1/replay/batches",
            headers=_auth(_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )
        repeat = client.post(
            "/v1/replay/batches",
            headers=_auth(_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )
        denied_repeat = client.post(
            "/v1/replay/batches",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )

    assert first.status_code == 200, first.text
    assert repeat.status_code == 200, repeat.text
    assert repeat.json() == first.json()
    assert denied_repeat.status_code == 403
    assert denied_repeat.json() == {"detail": "ABAC policy denied the Replay batch admission"}
    assert stub.calls == [(request, _OPERATOR_SUBJECT), (request, _OPERATOR_SUBJECT)]


@pytest.mark.parametrize(
    ("allowed", "attempted"),
    [
        (_request(), _request(source=_locator("2"))),
        (_request(), _request(source=_locator("1", repository_version=2))),
        (_request(), _request(retest_source=_locator("6"))),
        (
            _request(retest_source=_locator("6")),
            _request(retest_source=_locator("7")),
        ),
        (
            _request(retest_source=_locator("6")),
            _request(retest_source=_locator("6", repository_version=2)),
        ),
        (_request(), _request(claim_projection=True)),
        (
            _request(claim_projection=True),
            _request(claim_projection=True, portable_attestation=True),
        ),
        (
            _request(claim_projection=True, portable_attestation=True),
            _request(
                claim_projection=True,
                portable_attestation=True,
                target_attestation=True,
            ),
        ),
        (_request(), _request(idempotency_key="replay-batch-abac-substituted")),
    ],
    ids=[
        "source-artifact",
        "source-version",
        "retest-presence",
        "retest-artifact",
        "retest-version",
        "claim-projection",
        "portable-attestation",
        "target-attestation",
        "idempotency",
    ],
)
def test_mismatched_replay_batch_authority_denies_before_config_or_delegate(
    tmp_path: Path,
    allowed: CreateReplayBatchRequest,
    attempted: CreateReplayBatchRequest,
) -> None:
    app = create_app(_settings(tmp_path, _policy(allowed)))
    stub = _StubReplayIssuance()
    with TestClient(app) as client:
        app.state.control_plane._replay_issuance = stub
        response = client.post(
            "/v1/replay/batches",
            headers=_auth(_OPERATOR_TOKEN),
            json=attempted.model_dump(mode="json"),
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "ABAC policy denied the Replay batch admission"}
    assert stub.calls == []


def test_policy_omission_preserves_operator_rbac_batch_admission(tmp_path: Path) -> None:
    request = _request()
    app = create_app(_settings(tmp_path, None))
    stub = _StubReplayIssuance()
    with TestClient(app) as client:
        app.state.control_plane._replay_issuance = stub
        response = client.post(
            "/v1/replay/batches",
            headers=_auth(_OTHER_OPERATOR_TOKEN),
            json=request.model_dump(mode="json"),
        )

    assert response.status_code == 200, response.text
    assert stub.calls == [(request, _OTHER_OPERATOR_SUBJECT)]
