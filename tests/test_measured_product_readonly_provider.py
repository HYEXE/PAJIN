from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from pajin.benchmark.docker_provider import DockerBenchmarkProviderError
from pajin.benchmark.measurement_registry_distribution import (
    BenchmarkMeasurementRegistryActivationStore,
    BenchmarkMeasurementRegistryDistributionError,
)
from pajin.benchmark.scanner_docker_provider import DockerZAPScannerTargetFactoryAdapter
from pajin.benchmark.target_recovery import BenchmarkTargetOperation
from pajin.workflow.web_controlled_validation_route import (
    WebControlledValidationRouteClaimError,
    WebControlledValidationRouteClaimLedger,
)
from pajin.workflow.web_controlled_validation_runtime import (
    WebControlledValidationRuntimeError,
    _WebControlledValidationWorkerEvidenceStore,
)
from tests.test_benchmark_zap_scanner import _anchor, _run


def test_zap_reopen_needs_no_signer_and_cannot_run_stages(tmp_path: Path) -> None:
    plan, _catalog, _store, _anchor_value, source, original = _run(tmp_path)
    before = {path: path.read_bytes() for path in tmp_path.rglob("*") if path.is_file()}
    reader = DockerZAPScannerTargetFactoryAdapter(
        state_path=tmp_path / "provider.sqlite3",
        profile=original.profile,
        plan=plan,
        registration=original.scanner_registration,
        trust_anchor=_anchor(),
        measurement_private_key=None,
    )
    receipt = source.target.authority.execution_receipt
    assert reader.evidence(receipt) == original.evidence(receipt)
    assert reader.raw_sarif(receipt) == original.raw_sarif(receipt)

    authority = source.target.authority
    operation = BenchmarkTargetOperation(
        attemptId="read-only-test",
        attemptDigest="a" * 64,
        adapterDigest=original.definition.adapter_digest,
        coordinateDigest=authority.coordinate.coordinate_digest,
        fence=1,
        stage="reset",
        ordinal=1,
    )
    with pytest.raises(DockerBenchmarkProviderError, match="cannot run a stage"):
        asyncio.run(reader.reset(authority.coordinate, operation))
    with pytest.raises(DockerBenchmarkProviderError, match="cannot attest"):
        asyncio.run(reader.attest(authority.attestation.statement))
    assert {path: path.read_bytes() for path in before} == before


def test_zap_reopen_rejects_missing_database_without_creating_it(tmp_path: Path) -> None:
    plan, _catalog, _store, _anchor_value, _source, original = _run(tmp_path)
    path = tmp_path / "absent.sqlite3"
    with pytest.raises((OSError, ValueError, DockerBenchmarkProviderError)):
        DockerZAPScannerTargetFactoryAdapter(
            state_path=path,
            profile=original.profile,
            plan=plan,
            registration=original.scanner_registration,
            trust_anchor=_anchor(),
            measurement_private_key=None,
        )
    assert not path.exists()


@pytest.mark.parametrize(
    "store_type",
    [
        BenchmarkMeasurementRegistryActivationStore,
        WebControlledValidationRouteClaimLedger,
        _WebControlledValidationWorkerEvidenceStore,
    ],
)
def test_verification_store_reopen_does_not_create_or_repair_state(
    tmp_path: Path, store_type: Callable[..., object]
) -> None:
    path = tmp_path / "retained.sqlite3"
    errors = (
        sqlite3.Error,
        BenchmarkMeasurementRegistryDistributionError,
        WebControlledValidationRouteClaimError,
        WebControlledValidationRuntimeError,
    )
    with pytest.raises(errors):
        store_type(path, initialize=False)
    assert not path.exists()
    store_type(path)
    before = path.read_bytes()
    store_type(path, initialize=False)
    assert path.read_bytes() == before

    with sqlite3.connect(path) as connection:
        trigger = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'trigger' ORDER BY name LIMIT 1"
        ).fetchone()[0]
        connection.execute('DROP TRIGGER "' + trigger.replace('"', '""') + '"')
    tampered = path.read_bytes()
    with pytest.raises(errors):
        store_type(path, initialize=False)
    assert path.read_bytes() == tampered
    assert set(tmp_path.iterdir()) == {path}
