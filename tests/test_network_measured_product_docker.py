from __future__ import annotations

import os
from pathlib import Path

import pytest

from pajin.domain.models import CampaignManifest
from pajin.workflow.network_fixture_runtime import (
    NetworkFixtureDockerProvider,
    NetworkFixtureOperationJournal,
    NetworkFixtureTargetLifecycleRunner,
    registered_network_source_image_binding,
)
from pajin.workflow.network_measured_case_authority import (
    registered_network_measured_case_mapping,
)
from pajin.workflow.network_measured_product_flow import (
    NetworkMeasuredProductProjector,
    NetworkMeasuredProductSourceReopenContext,
    load_network_measured_product,
)
from pajin.workflow.network_replay_evaluation import (
    NetworkReplayEvaluationRunner,
    load_network_replay_floor_evaluation,
)
from pajin.workflow.network_source_measurement import NetworkSourceMeasurementRunner
from tests.network_measured_product_fresh_process import (
    FreshNetworkMeasuredProductRecipe,
    run_fresh_network_measured_product_probe,
)
from tests.test_network_source_measurement import _DockerConformanceAuthorizer


@pytest.mark.asyncio
async def test_real_docker_net_002d_exact_commit_product_conformance(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    if os.environ.get("PAJIN_NETWORK_002D_REAL_DOCKER") != "1":
        pytest.skip("set PAJIN_NETWORK_002D_REAL_DOCKER=1 with the three fixed images")

    provider = NetworkFixtureDockerProvider()
    images = registered_network_source_image_binding(provider)
    measured = registered_network_measured_case_mapping()
    lifecycle = NetworkFixtureTargetLifecycleRunner(
        provider=provider,
        journal=NetworkFixtureOperationJournal(tmp_path / "docker-journal.sqlite3"),
    )
    authorizer = _DockerConformanceAuthorizer(tmp_path / "plans", sample_campaign)
    assert provider.managed_resources_absent()

    try:
        source = await NetworkSourceMeasurementRunner(
            measured_cases=measured,
            images=images,
            lifecycle=lifecycle,
            authorizer=authorizer,
            source_runs_root=tmp_path / "source-runs",
            authority_runs_root=tmp_path / "source-authority-runs",
        ).run()
        replay = await NetworkReplayEvaluationRunner(
            source=source,
            measured_cases=measured,
            images=images,
            lifecycle=lifecycle,
            authorizer=authorizer,
            replay_source_runs_root=tmp_path / "replay-runs",
            replay_measurement_runs_root=tmp_path / "replay-authority-runs",
            evaluation_runs_root=tmp_path / "evaluation-runs",
        ).run()
        reopen = NetworkMeasuredProductSourceReopenContext(
            measured_cases=measured,
            provider=provider,
        )
        product = NetworkMeasuredProductProjector(output_root=tmp_path / "product-runs").project(
            replay, reopen_context=reopen
        )
        probe = run_fresh_network_measured_product_probe(
            FreshNetworkMeasuredProductRecipe(
                audit_root=tmp_path,
                process_root=tmp_path / "fresh-product-process",
                outcome=product,
                measured_cases=measured,
                real_docker=True,
            ),
            hash_seed=24002,
            timeout_seconds=300,
        )
    finally:
        lifecycle.reconcile_abandoned()

    evaluation = load_network_replay_floor_evaluation(
        replay,
        measured_cases=measured,
        provider=provider,
    )
    sealed_product = load_network_measured_product(product, reopen_context=reopen)
    assert evaluation == replay.mapping.public_evaluation
    assert sealed_product == product.product
    assert len(source.executions) == 6
    assert len(replay.replay.executions) == 6
    assert len(source.mapping.public_authority.denials) == 5
    assert len(replay.replay.mapping.public_authority.denials) == 5
    assert probe.statuses[-2:] == (200, 200)
    assert probe.source_reload_calls == 2
    assert probe.product_id == product.product.product_id
    assert probe.product_digest == product.product.product_digest
    assert probe.filesystem_unchanged is True
    assert provider.managed_resources_absent()
