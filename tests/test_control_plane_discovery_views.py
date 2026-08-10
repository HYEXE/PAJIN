import asyncio
import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import JsonValue

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.discovery import (
    DeterministicHypothesisCompiler,
    DynamicHypothesisWaveRunner,
    MCPInterfaceSurfaceAdapter,
    RegisteredHypothesisRule,
    RegisteredMCPReconPlanner,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
)
from pajin.domain.models import CampaignManifest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.control import BudgetController
from pajin.runtime.store import RunStore, load_verified_run_events, verify_run_integrity
from pajin.runtime.worker import SimulatedWorkerBackend
from pajin.tools.base import ToolRegistry
from pajin.tools.mcp import RegisteredMCPTool, demo_mcp_tool
from pajin.tools.mock import MockAgentProbe

OPERATOR_TOKEN = "discovery-view-operator-token-is-long-enough"
APPROVER_TOKEN = "discovery-view-approver-token-is-long-enough"
AUDITOR_TOKEN = "discovery-view-auditor-token-is-long-enough"
WORKER_TOKEN = "discovery-view-worker-token-is-long-enough"
_INPUT_SCHEMA_DIGEST = "a" * 64


def _settings(database: Path, *, discovery_root: Path | None) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{database.as_posix()}",
        credentials={
            OPERATOR_TOKEN: Principal(
                subject="discovery-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            APPROVER_TOKEN: Principal(
                subject="discovery-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            AUDITOR_TOKEN: Principal(
                subject="discovery-auditor",
                roles=frozenset({PrincipalRole.AUDITOR}),
            ),
            WORKER_TOKEN: Principal(
                subject="discovery-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"discovery-view-test-signing-key-32-bytes"},
        discovery_run_root=discovery_root,
    )


def _auth(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _a4_campaign(campaign: CampaignManifest) -> CampaignManifest:
    budgets = campaign.spec.budgets.model_copy(update={"max_agents": 4, "max_spawn_depth": 1})
    return CampaignManifest.model_validate(
        campaign.model_copy(
            update={"spec": campaign.spec.model_copy(update={"budgets": budgets})}
        ).model_dump(mode="python", by_alias=True)
    )


def _rule(recon_tool: RegisteredMCPTool) -> RegisteredHypothesisRule:
    registration = recon_tool.registration
    arguments: dict[str, JsonValue] = {"simulation": {"unauthorizedToolCall": True}}
    return RegisteredHypothesisRule(
        ruleId="pajin.test.discovery-view-tool-authorization.v1",
        sourceRegistryId=registration.server_id,
        sourceToolId=registration.remote_tool_name,
        sourceToolVersion=recon_tool.spec.version,
        sourceInputSchemaDigest=_INPUT_SCHEMA_DIGEST,
        threatClass="A02",
        statement="The discovered Tool may accept an unauthorized delegated action.",
        expectedObservable="The target invokes a protected Tool for an untrusted instruction.",
        requiredToolId=MockAgentProbe.spec.tool_id,
        method="POST",
        arguments=arguments,
        estimatedCostUsd=0,
        successCondition="The registered Tool returns one bounded observation.",
    )


def _completed_hypothesis_wave(
    root: Path,
    campaign: CampaignManifest,
):
    tools = ToolRegistry()
    recon_tool = demo_mcp_tool()
    tools.register(recon_tool)
    tools.register(MockAgentProbe())
    adapter = MCPInterfaceSurfaceAdapter(
        tool=recon_tool,
        input_schema_digest=_INPUT_SCHEMA_DIGEST,
    )
    recon_runner = SingleReconWaveRunner(
        planner=RegisteredMCPReconPlanner(
            tool=recon_tool,
            target_id=campaign.spec.targets[0].id,
            arguments={"text": "describe the registered local lab interface"},
        ),
        producer=TrustedSurfaceProducer(tools=tools, adapters=[adapter]),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=root,
    )
    hypothesis_runner = DynamicHypothesisWaveRunner(
        compiler=DeterministicHypothesisCompiler(tools=tools, rules=[_rule(recon_tool)]),
        tools=tools,
        policy=PolicyEngine(),
        worker=SimulatedWorkerBackend(),
        output_root=root,
    )
    budget = BudgetController(campaign.spec.budgets)
    recon = asyncio.run(recon_runner.run(campaign, budget=budget))
    return asyncio.run(hypothesis_runner.run(campaign, recon, budget=budget)), recon


def _endpoint(campaign: str, run_id: str) -> str:
    return f"/v1/discovery/campaigns/{campaign}/hypothesis-runs/{run_id}"


def test_verified_discovery_view_is_operator_only_bounded_and_read_only(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    root = tmp_path / "runs"
    campaign = _a4_campaign(sample_campaign)
    outcome, recon = _completed_hypothesis_wave(root, campaign)
    hypothesis_before = verify_run_integrity(outcome.run_path)
    source_before = verify_run_integrity(recon.source_run_path)
    projection_before = verify_run_integrity(recon.projection_run_path)
    app = create_app(_settings(tmp_path / "control-plane.db", discovery_root=root))
    path = _endpoint(campaign.metadata.name, outcome.run_id)

    with TestClient(app) as client:
        assert client.get(path).status_code == 401
        assert client.get(path, headers=_auth(APPROVER_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(AUDITOR_TOKEN)).status_code == 403
        assert client.get(path, headers=_auth(WORKER_TOKEN)).status_code == 403
        response = client.get(path, headers=_auth(OPERATOR_TOKEN))

    assert response.status_code == 200, response.text
    assert "no-store" in response.headers["cache-control"]
    body = response.json()
    assert body["kind"] == "VerifiedDiscoverySurfaceWaveView"
    assert body["campaign"]["name"] == campaign.metadata.name
    assert body["hypothesisRun"] == {
        "runId": outcome.run_id,
        "rootDigest": hypothesis_before.root_digest,
        "state": "completed",
    }
    assert body["surfaceSnapshot"]["sourceRunId"] == recon.source_run_id
    assert body["surfaceSnapshot"]["projectionRunId"] == recon.publication.projection_run_id
    assert body["surfaceSet"]["surfaceCount"] == 1
    assert body["surfaceSet"]["observationCount"] == 1
    surface = body["surfaceSet"]["surfaces"][0]
    assert set(surface) == {
        "surfaceId",
        "targetId",
        "locator",
        "confidence",
        "observationCount",
        "firstObservedAt",
        "lastObservedAt",
    }
    assert surface["locator"]["kind"] == "tool-interface"
    assert [wave["kind"] for wave in body["waves"]] == ["recon", "hypothesis"]
    assert body["waves"][1]["tasks"][0]["surfaceId"] == surface["surfaceId"]
    assert body["authorityBoundary"] == {
        "surfaceSnapshotVerified": True,
        "canonicalGraphIncluded": False,
        "viewGrantsCapability": False,
        "viewGrantsPermit": False,
        "viewAuthorizesExecution": False,
    }
    serialized = json.dumps(body)
    assert "arguments" not in serialized
    assert "evidence" not in serialized
    assert verify_run_integrity(outcome.run_path) == hypothesis_before
    assert verify_run_integrity(recon.source_run_path) == source_before
    assert verify_run_integrity(recon.projection_run_path) == projection_before


def test_discovery_view_fails_closed_when_unconfigured_or_tampered(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    campaign = _a4_campaign(sample_campaign)
    missing_app = create_app(_settings(tmp_path / "missing.db", discovery_root=None))
    plausible_run_id = "run_20260810T010203Z_1234abcd"
    with TestClient(missing_app) as client:
        unavailable = client.get(
            _endpoint(campaign.metadata.name, plausible_run_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert unavailable.status_code == 503

    root = tmp_path / "runs"
    outcome, recon = _completed_hypothesis_wave(root, campaign)
    artifact = recon.projection_run_path / recon.publication.artifact_path
    artifact.write_bytes(artifact.read_bytes() + b"\n")
    app = create_app(_settings(tmp_path / "tampered.db", discovery_root=root))
    with TestClient(app) as client:
        rejected = client.get(
            _endpoint(campaign.metadata.name, outcome.run_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == ("Discovery Surface/Wave authority is not integrity-valid")


def test_discovery_view_rejects_sealed_event_equivocation(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    root = tmp_path / "runs"
    campaign = _a4_campaign(sample_campaign)
    outcome, _recon = _completed_hypothesis_wave(root, campaign)
    source_events = load_verified_run_events(outcome.run_path)
    forged = RunStore.create(root, campaign.metadata.name)
    for name in (
        "campaign.json",
        "hypothesis-set.json",
        "hypothesis-wave-plan.json",
        "surface-bound-plan.json",
        "hypothesis-results.json",
        "run.json",
    ):
        payload = json.loads((outcome.run_path / name).read_text(encoding="utf-8"))
        if name == "run.json":
            payload["runId"] = forged.run_id
        forged.write_json(name, payload)
    started = next(event for event in source_events if event.event_type == "campaign.started")
    compiled = next(
        event for event in source_events if event.event_type == "discovery.hypothesis-set.compiled"
    )
    completed = next(
        event
        for event in source_events
        if event.event_type == "discovery.hypothesis-wave.completed"
    )
    terminal = next(event for event in source_events if event.event_type == "campaign.completed")
    forged.append_event(started.event_type, started.payload)
    forged.append_event(compiled.event_type, compiled.payload)
    forged.append_event(compiled.event_type, compiled.payload)
    forged.append_event(completed.event_type, completed.payload)
    forged.append_event(terminal.event_type, terminal.payload)
    forged.seal()
    assert verify_run_integrity(forged.path).valid

    app = create_app(_settings(tmp_path / "equivocation.db", discovery_root=root))
    with TestClient(app) as client:
        rejected = client.get(
            _endpoint(campaign.metadata.name, forged.run_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == ("Discovery Surface/Wave authority is not integrity-valid")


def test_discovery_view_rejects_cross_campaign_link_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    root = tmp_path / "runs"
    campaign = _a4_campaign(sample_campaign)
    outcome, _recon = _completed_hypothesis_wave(root, campaign)
    foreign_campaign = "foreign-campaign"
    foreign_path = root / foreign_campaign
    foreign_path.mkdir()
    substituted_run_id = "run_20260810T010203Z_deadbeef"
    link = foreign_path / substituted_run_id
    try:
        os.symlink(outcome.run_path, link, target_is_directory=True)
    except (NotImplementedError, OSError):
        pytest.skip("directory symlinks are unavailable in this environment")

    app = create_app(_settings(tmp_path / "substitution.db", discovery_root=root))
    with TestClient(app) as client:
        rejected = client.get(
            _endpoint(foreign_campaign, substituted_run_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert rejected.status_code == 409


@pytest.mark.parametrize(
    ("campaign", "run_id"),
    [
        ("../escape", "run_20260810T010203Z_1234abcd"),
        ("valid-campaign", "run_bad"),
        ("Valid-Campaign", "run_20260810T010203Z_1234abcd"),
    ],
)
def test_discovery_view_rejects_noncanonical_path_identifiers(
    tmp_path: Path,
    campaign: str,
    run_id: str,
) -> None:
    root = tmp_path / "runs"
    root.mkdir()
    app = create_app(_settings(tmp_path / "paths.db", discovery_root=root))
    with TestClient(app) as client:
        response = client.get(
            _endpoint(campaign, run_id),
            headers=_auth(OPERATOR_TOKEN),
        )
    assert response.status_code in {404, 422}
