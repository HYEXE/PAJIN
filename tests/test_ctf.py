from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignMode, ToolRiskTier
from pajin.modes.ctf import (
    CTFChallengeManifest,
    CTFChallengeService,
    load_ctf_challenge,
)


def _challenge() -> CTFChallengeManifest:
    return load_ctf_challenge(Path("examples/ctf-web-backup-lab.yaml"))


def _symlink_or_skip(link: Path, target: Path, *, directory: bool = False) -> None:
    try:
        link.symlink_to(target, target_is_directory=directory)
    except OSError as exc:  # pragma: no cover - depends on Windows developer privileges
        pytest.skip(f"symbolic links are unavailable: {exc}")


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


def test_ctf_campaign_write_roundtrips_and_atomically_replaces_regular_file(
    tmp_path: Path,
) -> None:
    service = CTFChallengeService()
    challenge = _challenge()
    output = tmp_path / "generated" / "ctf-campaign.yaml"

    artifact = service.write_campaign(
        challenge,
        output,
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert artifact.path == output
    assert load_manifest(output) == artifact.campaign

    output.write_text("stale: true\n", encoding="utf-8")
    rewritten = service.write_campaign(
        challenge,
        output,
        evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
    )

    assert load_manifest(output) == rewritten.campaign
    assert "stale: true" not in output.read_text(encoding="utf-8")


def test_ctf_campaign_write_rejects_symlink_leaf_without_touching_target(
    tmp_path: Path,
) -> None:
    victim = tmp_path / "victim.yaml"
    victim.write_text("keep\n", encoding="utf-8")
    output = tmp_path / "generated" / "ctf-campaign.yaml"
    output.parent.mkdir()
    _symlink_or_skip(output, victim)

    with pytest.raises(ValueError, match="symbolic link"):
        CTFChallengeService().write_campaign(
            _challenge(),
            output,
            evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
        )

    assert victim.read_text(encoding="utf-8") == "keep\n"


def test_ctf_campaign_write_rejects_symlinked_parent_without_creating_artifact(
    tmp_path: Path,
) -> None:
    actual = tmp_path / "actual-output"
    actual.mkdir()
    linked = tmp_path / "linked-output"
    _symlink_or_skip(linked, actual, directory=True)

    with pytest.raises(ValueError, match="parent contains a symbolic link"):
        CTFChallengeService().write_campaign(
            _challenge(),
            linked / "ctf-campaign.yaml",
            evaluated_at=datetime(2026, 7, 13, 1, tzinfo=UTC),
        )

    assert list(actual.iterdir()) == []
