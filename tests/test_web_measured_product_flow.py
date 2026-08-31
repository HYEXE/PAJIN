from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from pydantic import ValidationError

import pajin.workflow.web_measured_product_flow as product_flow_module
from pajin.runtime.store import RunStore
from pajin.workflow.web_controlled_validation_authority import (
    WebControlledValidationAuthority,
    WebControlledValidationAuthorityOutcome,
)
from pajin.workflow.web_measured_product_flow import (
    WEB_MEASURED_PRODUCT_FLOW_PATH,
    WebMeasuredProductFlowError,
    WebMeasuredProductFlowOutcome,
    WebMeasuredProductFlowProjection,
    WebMeasuredProductFlowProjector,
    WebMeasuredProductSourceReopenContext,
    load_web_measured_product_flow,
)
from tests.test_web_validation_evaluation import _evaluate

pytest_plugins = ("tests.test_web_validation_evaluation",)


def _source_material(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
) -> tuple[
    WebControlledValidationAuthorityOutcome,
    WebControlledValidationAuthority,
    WebMeasuredProductSourceReopenContext,
]:
    evaluated = _evaluate(web002d_context)
    digest = "a" * 64
    authority = cast(
        WebControlledValidationAuthority,
        SimpleNamespace(
            authority_id=f"web-controlled-validation:{digest}",
            authority_digest=digest,
            measured_case=web002d_context.source_context.measured_case.reference(),
            source_measurement=web002d_context.source.reference(),
            floor_policy=web002d_context.floor.reference(),
            projection_policy=web002d_context.mapping.public_policy.reference(),
            floor_evaluation=evaluated.evaluation,
            finding=evaluated.finding,
            source_measurement_verified=True,
            policy_denial_control_satisfied=True,
            target_cleanup_verified=True,
            benchmark_validation_floor_satisfied=True,
            bounded_product_finding_confirmed=True,
            private_ground_truth_disclosure_authorized=False,
            raw_sarif_disclosure_authorized=False,
            controlled_query_disclosure_authorized=False,
            scope_expansion_authorized=False,
            graph_mutation_authorized=False,
            reporting_authorized=False,
            external_delivery_authorized=False,
            permit_issuance_authorized=False,
            additional_execution_authorized=False,
            private_marker="private-ground-truth-marker-not-for-product-wire",
            route_marker="route-approval-permit-marker-not-for-product-wire",
            worker_marker="worker-container-network-marker-not-for-product-wire",
            graph_marker="graph-hypothesis-marker-not-for-product-wire",
        ),
    )
    source = WebControlledValidationAuthorityOutcome(
        run_id=RunStore.new_run_id(),
        run_path=tmp_path / "source-run-not-read-by-test-double",
        authority_path="web-controlled-validation-authority.json",
        authority=authority,
    )
    context = WebMeasuredProductSourceReopenContext(
        measured_case_authority=web002d_context.source_context.measured_case,
        private_ground_truth_profile=web002d_context.source_context.private_profile,
        source_reopen_context=cast(Any, object()),
        floor_policy=web002d_context.floor,
        mapping=web002d_context.mapping,
        trust_anchor=cast(Any, object()),
        claim_ledger=cast(Any, object()),
        target_journal=cast(Any, object()),
        provider=cast(Any, object()),
        adapter=cast(Any, object()),
        denial_route_authority=cast(Any, object()),
    )
    return source, authority, context


def _install_source_loader(
    monkeypatch: pytest.MonkeyPatch,
    *,
    state: list[WebControlledValidationAuthority],
    context: WebMeasuredProductSourceReopenContext,
    output_root: Path,
) -> tuple[list[WebControlledValidationAuthorityOutcome], list[bool]]:
    calls: list[WebControlledValidationAuthorityOutcome] = []
    root_states: list[bool] = []

    def fake_loader(
        source: WebControlledValidationAuthorityOutcome,
        **kwargs: object,
    ) -> WebControlledValidationAuthority:
        assert kwargs == {
            "measured_case_authority": context.measured_case_authority,
            "private_ground_truth_profile": context.private_ground_truth_profile,
            "source_reopen_context": context.source_reopen_context,
            "floor_policy": context.floor_policy,
            "mapping": context.mapping,
            "trust_anchor": context.trust_anchor,
            "claim_ledger": context.claim_ledger,
            "target_journal": context.target_journal,
            "provider": context.provider,
            "adapter": context.adapter,
            "denial_route_authority": context.denial_route_authority,
        }
        calls.append(source)
        root_states.append(output_root.exists())
        return state[0]

    monkeypatch.setattr(
        product_flow_module,
        "load_web_controlled_validation_authority",
        fake_loader,
    )
    return calls, root_states


def _project(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[
    WebMeasuredProductFlowOutcome,
    WebControlledValidationAuthorityOutcome,
    WebControlledValidationAuthority,
    WebMeasuredProductSourceReopenContext,
    list[WebControlledValidationAuthority],
    list[WebControlledValidationAuthorityOutcome],
    list[bool],
]:
    source, authority, context = _source_material(web002d_context, tmp_path)
    output_root = tmp_path / "product"
    state = [authority]
    calls, root_states = _install_source_loader(
        monkeypatch,
        state=state,
        context=context,
        output_root=output_root,
    )
    outcome = WebMeasuredProductFlowProjector(output_root=output_root).project(
        source,
        reopen_context=context,
    )
    return outcome, source, authority, context, state, calls, root_states


def test_ux_009a_projects_only_bounded_public_web_authority(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, source, authority, context, _, calls, root_states = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )

    assert calls == [source, source]
    assert root_states == [False, True]
    projection = load_web_measured_product_flow(outcome, reopen_context=context)
    assert calls == [source, source, source]
    assert root_states == [False, True, True]
    assert projection == outcome.projection
    assert outcome.run_id != source.run_id
    assert outcome.artifact_path == WEB_MEASURED_PRODUCT_FLOW_PATH
    assert projection.source_run_id == source.run_id
    assert projection.source_authority_id == authority.authority_id
    assert projection.source_authority_digest == authority.authority_digest
    assert projection.scope.campaign_scope_available is False
    assert projection.scope.scope_expanded is False
    assert projection.scope.profile_inferred is False
    assert projection.evidence.source_evidence_requirement_count == 6
    assert projection.evidence.controlled_validation_evidence_requirement_count == 10
    assert projection.evidence.denial_control_satisfied is True
    assert projection.evidence.target_cleanup_verified is True
    assert projection.evidence.evidence_content_included is False
    assert projection.evidence.filesystem_coordinates_included is False
    assert projection.floor.public_metric_count == 14
    assert projection.floor.required_metric_count == 11
    assert projection.floor.not_applicable_metric_count == 3
    assert projection.floor.metrics == authority.floor_evaluation.observations
    assert projection.finding.claim_ceiling == "benchmark-ground-truth-match"
    assert projection.finding.product_finding_confirmed is True
    assert projection.finding.generic_production_vulnerability_confirmed is False
    assert projection.finding.impact_assurance == "not-evaluated-information-only"
    assert projection.finding.severity_assurance == "not-evaluated-information-only"
    assert projection.report.report_available is False
    assert projection.report.report_creation_authorized is False
    assert projection.report.report_delivery_authorized is False
    assert projection.report.external_delivery_authorized is False
    assert projection.authority_boundary.web_002c_graph_predecessor_required is False
    assert projection.authority_boundary.graph_included is False
    assert projection.authority_boundary.graph_mutation_authorized is False
    assert projection.authority_boundary.additional_execution_authorized is False
    assert projection.authority_boundary.http_entrypoint_available is False
    assert projection.authority_boundary.ui_entrypoint_available is False
    assert (
        WebMeasuredProductFlowProjection.model_validate_json(
            projection.model_dump_json(by_alias=True)
        )
        == projection
    )

    public_wire = json.dumps(
        projection.model_dump(mode="json", by_alias=True),
        ensure_ascii=False,
        sort_keys=True,
    )
    for forbidden in (
        authority.private_marker,
        authority.route_marker,
        authority.worker_marker,
        authority.graph_marker,
        "routeId",
        "approvalId",
        "permitId",
        "requestId",
        "dispatchId",
        "artifactPath",
        "runPath",
        "graphHypothesis",
    ):
        assert forbidden not in public_wire


@pytest.mark.parametrize(
    ("section", "field", "value"),
    (
        ("scope", "campaignScopeAvailable", True),
        ("evidence", "evidenceContentIncluded", True),
        ("finding", "productFindingConfirmed", 1),
        ("finding", "genericProductionVulnerabilityConfirmed", True),
        ("report", "reportAvailable", True),
        ("authorityBoundary", "web002cGraphPredecessorRequired", True),
        ("authorityBoundary", "additionalExecutionAuthorized", True),
        ("authorityBoundary", "additionalExecutionAuthorized", 0),
        ("authorityBoundary", "httpEntrypointAvailable", True),
    ),
)
def test_ux_009a_rejects_authority_escalation_and_boolean_coercion(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    section: str,
    field: str,
    value: object,
) -> None:
    source, authority, _ = _source_material(web002d_context, tmp_path)
    projection = product_flow_module._build_product_flow(source.run_id, authority)
    material = projection.model_dump(mode="python", by_alias=True)
    nested = cast(dict[str, object], material[section])
    nested[field] = value

    with pytest.raises(ValidationError):
        WebMeasuredProductFlowProjection.model_validate(material)


def test_ux_009a_rejects_claim_or_assurance_escalation(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
) -> None:
    source, authority, _ = _source_material(web002d_context, tmp_path)
    projection = product_flow_module._build_product_flow(source.run_id, authority)

    for field, value in (
        ("claimCeiling", "production-vulnerability"),
        ("impactAssurance", "high"),
        ("severityAssurance", "critical"),
    ):
        material = projection.model_dump(mode="python", by_alias=True)
        finding = cast(dict[str, object], material["finding"])
        finding[field] = value
        with pytest.raises(ValidationError):
            WebMeasuredProductFlowProjection.model_validate(material)


def test_ux_009a_loader_rejects_product_and_source_substitution(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, source, authority, context, state, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )

    forged_projection = outcome.projection.model_copy(update={"flow_digest": "0" * 64})
    with pytest.raises(WebMeasuredProductFlowError, match="not sealed and reproducible"):
        load_web_measured_product_flow(
            replace(outcome, projection=forged_projection),
            reopen_context=context,
        )

    foreign_source = replace(source, run_id=RunStore.new_run_id())
    with pytest.raises(WebMeasuredProductFlowError, match="not sealed and reproducible"):
        load_web_measured_product_flow(
            replace(outcome, source=foreign_source),
            reopen_context=context,
        )

    foreign_digest = "b" * 64
    foreign_material = vars(cast(SimpleNamespace, authority)).copy()
    foreign_material["authority_id"] = f"web-controlled-validation:{foreign_digest}"
    foreign_material["authority_digest"] = foreign_digest
    state[0] = cast(WebControlledValidationAuthority, SimpleNamespace(**foreign_material))
    with pytest.raises(WebMeasuredProductFlowError, match="not sealed and reproducible"):
        load_web_measured_product_flow(outcome, reopen_context=context)


@pytest.mark.parametrize("target", ("artifact", "events"))
def test_ux_009a_loader_rejects_post_seal_mutation(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
) -> None:
    outcome, _, _, context, _, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    path = (
        outcome.run_path / outcome.artifact_path
        if target == "artifact"
        else outcome.run_path / "events.jsonl"
    )
    path.write_bytes(path.read_bytes() + b" ")

    with pytest.raises(WebMeasuredProductFlowError, match="not sealed and reproducible"):
        load_web_measured_product_flow(outcome, reopen_context=context)


def test_ux_009a_rejects_product_run_reuse(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source, authority, context = _source_material(web002d_context, tmp_path)
    _install_source_loader(
        monkeypatch,
        state=[authority],
        context=context,
        output_root=tmp_path / "product",
    )
    monkeypatch.setattr(RunStore, "new_run_id", staticmethod(lambda: source.run_id))

    with pytest.raises(WebMeasuredProductFlowError, match="projection failed closed") as error:
        WebMeasuredProductFlowProjector(output_root=tmp_path / "product").project(
            source,
            reopen_context=context,
        )
    assert error.value.__cause__ is not None
    assert "reuses its source Run" in str(error.value.__cause__)
