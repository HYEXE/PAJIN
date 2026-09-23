"""WEB-008's first topology boundary remains inert after a hosted advisory."""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from pajin.agentic.codex_recon_compilation import CodexReconCompilationResult
from pajin.agentic.codex_recon_draft import CodexReconDraft
from pajin.agentic.codex_usage import CodexAdvisoryUsageJournal
from pajin.web_assessment.diagnostic_catalog import production_diagnostic_bundle_catalog
from pajin.web_assessment.discovery_artifact import VerifiedAuthenticatedDiscoveryRun
from pajin.web_assessment.governed_adapter_profile import (
    GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
    production_governed_web_adapter_profile_registry,
)
from pajin.web_assessment.governed_advisory_topology import (
    GovernedWebAdvisoryTopology,
    GovernedWebAdvisoryTopologyError,
    build_governed_web_advisory_topology,
)
from tests import test_agentic_codex_recon_compilation as bridge_fixture


def _inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    VerifiedAuthenticatedDiscoveryRun,
    CodexAdvisoryUsageJournal,
    CodexReconCompilationResult,
    dict[str, str],
]:
    original_draft = bridge_fixture._draft

    def ranked_draft(projection: Any) -> CodexReconDraft:
        original = original_draft(projection)
        payload = original.model_dump(mode="json", by_alias=True)
        ranked = [payload["prioritizedDiagnostics"][index] for index in (2, 0, 1)]
        for rank, item in enumerate(ranked, start=1):
            item["rank"] = rank
        payload["prioritizedDiagnostics"] = ranked
        return CodexReconDraft.model_validate(payload)

    monkeypatch.setattr(bridge_fixture, "_draft", ranked_draft)
    source, journal, attempt_id, receipt_digest = bridge_fixture._setup(tmp_path, monkeypatch)
    compilation = bridge_fixture._compile(source, journal, attempt_id, receipt_digest)
    profile = production_governed_web_adapter_profile_registry().resolve(
        adapter_reference=GOVERNED_JUICE_SHOP_ADAPTER_REFERENCE,
        origin=source.plan.origin,
    )
    descriptor = production_diagnostic_bundle_catalog().resolve(
        adapter_implementation_id=profile.implementation_id,
        adapter_implementation_digest=profile.implementation_digest,
    )
    pins = {
        "attempt_id": attempt_id,
        "expected_source_run_id": source.verification.run_id,
        "expected_source_root_digest": source.verification.root_digest,
        "expected_receipt_digest": receipt_digest,
        "expected_proposal_digest": compilation.proposal.proposal_digest,
        "expected_profile_digest": profile.profile_digest,
        "expected_diagnostic_catalog_digest": descriptor.catalog_digest,
        "expected_diagnostic_bundle_digest": descriptor.bundle_digest,
    }
    return source, journal, compilation, pins


def _topology(
    source: VerifiedAuthenticatedDiscoveryRun,
    journal: CodexAdvisoryUsageJournal,
    compilation: CodexReconCompilationResult,
    pins: dict[str, str],
) -> GovernedWebAdvisoryTopology:
    return build_governed_web_advisory_topology(
        source=source, journal=journal, compilation=compilation, **pins
    )


def test_topology_binds_hosted_bridge_and_keeps_model_rank_inert(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, journal, compilation, pins = _inputs(tmp_path, monkeypatch)
    topology = _topology(source, journal, compilation, pins)

    assert tuple(item.diagnostic_id for item in compilation.proposal.prioritized_diagnostics) == (
        "dom-xss",
        "sql-login",
        "object-access",
    )
    assert topology.diagnostic_order == ("sql-login", "object-access", "dom-xss")
    assert topology.bridge_digest == compilation.record.bridge_digest
    assert topology.receipt_digest == compilation.record.receipt_digest
    assert tuple(slot.role for slot in topology.stage_slots) == ("source", "validation")
    assert topology.stage_slots[0].slot_digest != topology.stage_slots[1].slot_digest
    assert all(slot.plan_digest == topology.plan_digest for slot in topology.stage_slots)
    assert topology.diagnostic_rank_is_execution_order is False
    assert topology.target_request_authorized is False
    assert topology.permit_granted is False
    assert topology.execution_authorized is False
    assert topology.finding_authorized is False
    assert (
        GovernedWebAdvisoryTopology.model_validate(topology.model_dump(mode="json", by_alias=True))
        == topology
    )
    with pytest.raises(ValidationError):
        topology.execution_authorized = True  # type: ignore[misc]


def test_topology_rejects_foreign_pins_and_unknown_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, journal, compilation, pins = _inputs(tmp_path, monkeypatch)
    for key in pins:
        wrong = dict(pins)
        wrong[key] = (
            "run_20260915T020000Z_deadbeef"
            if key == "expected_source_run_id"
            else sha256(key.encode()).hexdigest()
        )
        with pytest.raises(GovernedWebAdvisoryTopologyError):
            _topology(source, journal, compilation, wrong)
    with pytest.raises(GovernedWebAdvisoryTopologyError):
        _topology(
            replace(source, run_path=tmp_path / "unknown-source"),
            journal,
            compilation,
            pins,
        )


def test_topology_rejects_foreign_bridge_and_wire_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, journal, compilation, pins = _inputs(tmp_path, monkeypatch)
    for field in ("receipt_digest", "bridge_digest"):
        forged_record = compilation.record.model_copy(
            update={field: sha256(field.encode()).hexdigest()}
        )
        with pytest.raises(GovernedWebAdvisoryTopologyError):
            _topology(source, journal, replace(compilation, record=forged_record), pins)
    with pytest.raises(GovernedWebAdvisoryTopologyError):
        build_governed_web_advisory_topology(
            source=source,
            journal=journal,
            compilation=compilation.proposal,  # type: ignore[arg-type]
            **pins,
        )

    topology = _topology(source, journal, compilation, pins)
    raw = topology.model_dump(mode="json", by_alias=True)
    raw["diagnosticOrder"] = ["dom-xss", "sql-login", "object-access"]
    with pytest.raises(ValidationError):
        GovernedWebAdvisoryTopology.model_validate(raw)
    raw = topology.model_dump(mode="json", by_alias=True)
    raw["permitGranted"] = 0
    with pytest.raises(ValidationError):
        GovernedWebAdvisoryTopology.model_validate(raw)
