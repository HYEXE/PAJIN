from __future__ import annotations

import os
from pathlib import Path

import pytest

from pajin.workflow.ai_fixture_runtime import (
    AIFixtureDockerProvider,
    registered_ai_source_image_binding,
)
from pajin.workflow.ai_measured_case_authority import registered_ai_measured_case_mapping
from pajin.workflow.ai_measured_product_flow import (
    AIMeasuredProductProjector,
    AIMeasuredProductSourceReopenContext,
    load_ai_measured_product,
)
from pajin.workflow.ai_replay_evaluation import (
    AIReplayEvaluationRunner,
    load_ai_replay_floor_evaluation,
)
from pajin.workflow.ai_source_measurement import AISourceMeasurementRunner
from tests.ai_measured_product_fresh_process import (
    FreshAIMeasuredProductRecipe,
    run_fresh_ai_measured_product_probe,
)
from tests.test_ai_source_measurement import (
    _MeasurementAuthorizer,
    _SourceAuthorizer,
)


@pytest.mark.asyncio
async def test_real_docker_ai_002d_exact_commit_product_conformance(
    tmp_path: Path,
) -> None:
    if os.environ.get("PAJIN_AI_002D_REAL_DOCKER") != "1":
        pytest.skip("set PAJIN_AI_002D_REAL_DOCKER=1 with the three fixed images")

    provider = AIFixtureDockerProvider()
    images = registered_ai_source_image_binding(provider)
    measured = registered_ai_measured_case_mapping()
    source_authorizer = _SourceAuthorizer(tmp_path / "source-plans")
    measurement_authorizer = _MeasurementAuthorizer(tmp_path / "measurement-plans")
    assert provider.managed_resources_absent()

    try:
        source = await AISourceMeasurementRunner(
            measured_cases=measured,
            images=images,
            provider=provider,
            authorizer=source_authorizer,
            source_runs_root=tmp_path / "source-runs",
            authority_runs_root=tmp_path / "source-authority-runs",
        ).run()
        replay = await AIReplayEvaluationRunner(
            source=source,
            measured_cases=measured,
            images=images,
            provider=provider,
            authorizer=measurement_authorizer,
            operation_runs_root=tmp_path / "operation-runs",
            evaluation_runs_root=tmp_path / "evaluation-runs",
        ).run()
        reopen = AIMeasuredProductSourceReopenContext(
            measured_cases=measured,
            provider=provider,
        )
        product = AIMeasuredProductProjector(output_root=tmp_path / "product-runs").project(
            replay,
            reopen_context=reopen,
        )
        probe = run_fresh_ai_measured_product_probe(
            FreshAIMeasuredProductRecipe(
                audit_root=tmp_path,
                process_root=tmp_path / "fresh-product-process",
                outcome=product,
                measured_cases=measured,
                real_docker=True,
            ),
            hash_seed=25002,
            timeout_seconds=300,
        )

        evaluation = load_ai_replay_floor_evaluation(
            replay,
            measured_cases=measured,
            provider=provider,
        )
        sealed_product = load_ai_measured_product(product, reopen_context=reopen)
        assert evaluation == replay.mapping.public_evaluation
        assert sealed_product == product.product
        assert source_authorizer.calls == 1
        assert measurement_authorizer.calls == 5
        assert len(replay.executions) == 5
        assert len(replay.mapping.public_evaluation.operations) == 6
        assert len(source.mapping.public_authority.denials) == 8
        assert replay.mapping.public_evaluation.validation_floor_satisfied is True
        assert probe.statuses[-2:] == (200, 200)
        assert probe.source_reload_calls == 2
        assert probe.product_id == product.product.product_id
        assert probe.product_digest == product.product.product_digest
        assert probe.filesystem_unchanged is True
    finally:
        assert provider.managed_resources_absent()
