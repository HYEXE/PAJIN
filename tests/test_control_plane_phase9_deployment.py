from __future__ import annotations

import pytest

from pajin.control_plane.api import ControlPlaneSettings
from pajin.control_plane.models import PrincipalRole

_OPERATOR_TOKEN = "phase9-deployment-operator-token-that-is-long-enough"
_APPROVER_TOKEN = "phase9-deployment-approver-token-that-is-long-enough"
_WORKER_TOKEN = "phase9-deployment-worker-token-that-is-long-enough"
_REPLAY_WORKER_TOKEN = "phase9-deployment-replay-token-that-is-long-enough"
_REPLAY_WORKER_SUBJECT = "phase9-deployment-replay-worker"

_OPTIONAL_POLICY_ENVIRONMENTS = (
    "PAJIN_CP_OIDC_HUMAN_TRUST_POLICY",
    "PAJIN_CP_WORKER_MTLS_TRUST_POLICY",
    "PAJIN_CP_ABAC_POLICY",
    "PAJIN_CP_RUN_SUBMISSION_ABAC_POLICY",
    "PAJIN_CP_RUN_CANCELLATION_ABAC_POLICY",
    "PAJIN_CP_CHECKPOINT_RESUME_ABAC_POLICY",
    "PAJIN_CP_REPLAY_SOURCE_ARTIFACT_ABAC_POLICY",
    "PAJIN_CP_REPLAY_BATCH_ADMISSION_ABAC_POLICY",
    "PAJIN_CP_MAINTENANCE_ABAC_POLICY",
    "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
    "PAJIN_CP_ADDITIONAL_WORKER_CREDENTIALS",
)


def _set_compatibility_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in (
        *_OPTIONAL_POLICY_ENVIRONMENTS,
        "PAJIN_CP_REPLAY_WORKER_TOKEN",
        "PAJIN_CP_REPLAY_WORKER_SUBJECT",
        "PAJIN_CP_PENTEST_RECON_DEPLOYMENT_PATH",
        "PAJIN_CP_PENTEST_RECON_DEPLOYMENT_SHA256",
        "PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_PATH",
        "PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_SHA256",
        "PAJIN_CP_PENTEST_WORKFLOW_DEPLOYMENT_PATH",
        "PAJIN_CP_PENTEST_WORKFLOW_DEPLOYMENT_SHA256",
        "PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH",
        "PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_SHA256",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", _OPERATOR_TOKEN)
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", _APPROVER_TOKEN)
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", _WORKER_TOKEN)
    monkeypatch.setenv(
        "PAJIN_CP_CHECKPOINT_KEY",
        "phase9-deployment-checkpoint-key-that-is-long-enough",
    )


def test_unset_phase9_opt_ins_preserve_only_the_compatibility_ceiling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_compatibility_environment(monkeypatch)

    settings = ControlPlaneSettings.from_env()

    assert settings.oidc_human_trust_policy is None
    assert settings.worker_mtls_trust_policy is None
    assert settings.abac_policy is None
    assert settings.run_submission_abac_policy is None
    assert settings.run_cancellation_abac_policy is None
    assert settings.checkpoint_resume_abac_policy is None
    assert settings.replay_source_artifact_abac_policy is None
    assert settings.replay_batch_admission_abac_policy is None
    assert settings.maintenance_abac_policy is None
    assert settings.replay_executor_profiles == {}
    assert settings.pentest_replay_deployment_path is None
    assert settings.pentest_replay_deployment_sha256 is None
    assert settings.pentest_recon_deployment_path is None
    assert settings.pentest_recon_deployment_sha256 is None
    assert settings.pentest_workflow_coordination_deployment_path is None
    assert settings.pentest_workflow_coordination_deployment_sha256 is None


@pytest.mark.parametrize("environment_name", _OPTIONAL_POLICY_ENVIRONMENTS)
def test_blank_phase9_opt_ins_fail_startup(
    monkeypatch: pytest.MonkeyPatch,
    environment_name: str,
) -> None:
    _set_compatibility_environment(monkeypatch)
    if environment_name == "PAJIN_CP_REPLAY_EXECUTOR_PROFILES":
        monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", _REPLAY_WORKER_TOKEN)
    monkeypatch.setenv(environment_name, " \t ")

    with pytest.raises(RuntimeError, match=environment_name):
        ControlPlaneSettings.from_env()


def test_replay_worker_token_and_profiles_are_one_deployment_unit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_compatibility_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", _REPLAY_WORKER_TOKEN)

    with pytest.raises(RuntimeError, match="must be configured together"):
        ControlPlaneSettings.from_env()

    monkeypatch.delenv("PAJIN_CP_REPLAY_WORKER_TOKEN")
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", _REPLAY_WORKER_SUBJECT)
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
        f'{{"{_REPLAY_WORKER_SUBJECT}":["kisa-exact-v1"]}}',
    )

    with pytest.raises(RuntimeError, match="must be configured together"):
        ControlPlaneSettings.from_env()


def test_additional_worker_credentials_resolve_indirect_token_environments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_compatibility_environment(monkeypatch)
    monkeypatch.setenv("PAJIN_CONTROL_ONE_TOKEN", "control-one-token-that-is-long-enough")
    monkeypatch.setenv("PAJIN_CONTROL_TWO_TOKEN", "control-two-token-that-is-long-enough")
    monkeypatch.setenv(
        "PAJIN_CP_ADDITIONAL_WORKER_CREDENTIALS",
        '{"pentest-control-one":"PAJIN_CONTROL_ONE_TOKEN",'
        '"pentest-control-two":"PAJIN_CONTROL_TWO_TOKEN"}',
    )

    settings = ControlPlaneSettings.from_env()

    worker_subjects = {
        principal.subject
        for principal in settings.credentials.values()
        if principal.roles == frozenset({PrincipalRole.WORKER})
    }
    assert worker_subjects == {
        "worker-service",
        "pentest-control-one",
        "pentest-control-two",
    }


def test_additional_worker_token_cannot_be_reused_by_replay_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _set_compatibility_environment(monkeypatch)
    shared_token = "control-replay-shared-token-that-is-long-enough"
    monkeypatch.setenv("PAJIN_CONTROL_ONE_TOKEN", shared_token)
    monkeypatch.setenv(
        "PAJIN_CP_ADDITIONAL_WORKER_CREDENTIALS",
        '{"pentest-control-one":"PAJIN_CONTROL_ONE_TOKEN"}',
    )
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_TOKEN", shared_token)
    monkeypatch.setenv("PAJIN_CP_REPLAY_WORKER_SUBJECT", _REPLAY_WORKER_SUBJECT)
    monkeypatch.setenv(
        "PAJIN_CP_REPLAY_EXECUTOR_PROFILES",
        f'{{"{_REPLAY_WORKER_SUBJECT}":["kisa-exact-v1"]}}',
    )

    with pytest.raises(RuntimeError, match="distinct from additional Workers"):
        ControlPlaneSettings.from_env()
