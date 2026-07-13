from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.modes.ctf import (
    CTFChallengeManifest,
    CTFChallengeService,
    load_ctf_challenge,
)


def _challenge() -> CTFChallengeManifest:
    return load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))


def test_ctf_challenge_compiles_to_one_local_policy_bound_target() -> None:
    challenge = _challenge()
    campaign = CTFChallengeService().compile_campaign(
        challenge,
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert campaign.spec.mode is CampaignMode.CTF
    assert campaign.spec.autonomy.value == "lab-autonomous"
    assert len(campaign.spec.targets) == 1
    target = campaign.spec.targets[0]
    assert target.type == "ctf-web"
    assert target.endpoint == "http://host.docker.internal:8780/backup/config.json.bak"
    assert target.simulation["flagSha256"] == challenge.spec.flag.sha256
    assert "candidateFlag" not in target.simulation
    assert campaign.spec.scope.allow == [target.endpoint]
    rules = campaign.spec.rules_of_engagement
    assert rules.max_tool_risk_tier is ToolRiskTier.T1
    assert rules.allowed_methods == {"GET"}
    assert rules.allow_private_networks
    assert campaign.spec.budgets.max_tool_calls == 1
    assert campaign.spec.budgets.max_model_calls == 0


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        (
            "entryPoint",
            "https://example.com/backup/config.json.bak",
            "local HTTP lab",
        ),
        (
            "entryPoint",
            "http://host.docker.internal:9999/backup/config.json.bak",
            "host.docker.internal:8780",
        ),
        (
            "entryPoint",
            "http://host.docker.internal:8780/admin",
            "entry point must be",
        ),
    ],
)
def test_ctf_manifest_rejects_non_lab_or_non_fixed_scope(
    field: str,
    value: str,
    message: str,
) -> None:
    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["scope"][field] = value

    with pytest.raises(ValidationError, match=message):
        CTFChallengeManifest.model_validate(payload)


def test_ctf_manifest_rejects_authority_expansion_and_plaintext_flag() -> None:
    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["budgets"]["maxToolCalls"] = 2
    with pytest.raises(ValidationError, match="exactly one fixed Tool call"):
        CTFChallengeManifest.model_validate(payload)

    payload = _challenge().model_dump(mode="json", by_alias=True)
    payload["spec"]["flag"]["plaintext"] = "PAJIN{must-not-be-in-manifest}"
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CTFChallengeManifest.model_validate(payload)


def test_ctf_compile_rejects_inactive_authorization() -> None:
    challenge = _challenge()

    with pytest.raises(ValueError, match="authorization is not active"):
        CTFChallengeService().compile_campaign(
            challenge,
            evaluated_at=datetime(2100, 1, 1, tzinfo=UTC),
        )
