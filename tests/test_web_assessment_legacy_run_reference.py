"""Historical WEB-005 wire compatibility without changing current Run identities."""

from __future__ import annotations

from copy import deepcopy

import pytest
from pydantic import ValidationError
from test_web_assessment_campaign import _campaign_result, _verified_source

from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.campaign import (
    LocalWebAssessmentCampaignResult,
    LocalWebAssessmentRunReference,
    local_web_assessment_run_reference,
)
from pajin.web_assessment.models import LocalWebAssessmentResult, WebAssessmentPlan

_PLAN_FIELDS = ("target_product", "fingerprint_version_path", "adapter_implementation_id")
_RESULT_FIELDS = ("discovery_evidence_reference", "discovery_evidence_digest")


def _historical_reference_wire(reference: LocalWebAssessmentRunReference) -> dict[str, object]:
    raw = reference.model_dump(mode="json", by_alias=True)
    for field in _PLAN_FIELDS:
        raw["plan"].pop(field, None)
    for field in _RESULT_FIELDS:
        raw["result"].pop(field, None)
    raw["referenceDigest"] = discovery_digest(
        "pajin.web-assessment.run-reference/v1",
        {key: value for key, value in raw.items() if key != "referenceDigest"},
    )
    return raw


def test_legacy_reference_and_reconciliation_preserve_original_wire_and_digest() -> None:
    plan, source_auth, validation_auth, source, validation, reconciled = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )
    source_raw = _historical_reference_wire(source)
    validation_raw = _historical_reference_wire(validation)
    assert source_raw["referenceDigest"] == source.reference_digest

    loaded_source = LocalWebAssessmentRunReference.model_validate(source_raw)
    loaded_validation = LocalWebAssessmentRunReference.model_validate(validation_raw)
    assert loaded_source.model_dump(mode="json", by_alias=True) == source_raw
    assert loaded_validation.model_dump(mode="json", by_alias=True) == validation_raw

    source_from_child = local_web_assessment_run_reference(
        role="source",
        verified_source=_verified_source(
            plan=WebAssessmentPlan.model_validate(source_raw["plan"]),
            authorization=source_auth,
            result=LocalWebAssessmentResult.model_validate(source_raw["result"]),
            index=1,
        ),
    )
    assert source_from_child == loaded_source
    assert source_from_child.model_dump(mode="json", by_alias=True) == source_raw

    reconciliation_raw = reconciled.model_dump(mode="json", by_alias=True)
    for field in _PLAN_FIELDS:
        reconciliation_raw["plan"].pop(field)
    reconciliation_raw["source"] = source_raw
    reconciliation_raw["validation"] = validation_raw
    reconciliation_raw["resultDigest"] = discovery_digest(
        "pajin.web-assessment.campaign-result/v1",
        {key: value for key, value in reconciliation_raw.items() if key != "resultDigest"},
    )
    loaded_reconciliation = LocalWebAssessmentCampaignResult.model_validate(reconciliation_raw)
    assert loaded_reconciliation.model_dump(mode="json", by_alias=True) == reconciliation_raw
    assert loaded_reconciliation.plan == plan
    assert loaded_reconciliation.source.authorization_id == source_auth.authorization_id
    assert loaded_reconciliation.validation.authorization_id == validation_auth.authorization_id


def test_legacy_reference_rejects_tamper_or_partial_new_field_shape() -> None:
    _, _, _, source, _, _ = _campaign_result(
        source_reproduced=True,
        validation_reproduced=True,
    )
    raw = _historical_reference_wire(source)
    tampered = deepcopy(raw)
    tampered["rootDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="reference digest differs"):
        LocalWebAssessmentRunReference.model_validate(tampered)

    partial = deepcopy(raw)
    partial["plan"]["target_product"] = source.plan.target_product
    with pytest.raises(ValidationError, match="reference digest differs"):
        LocalWebAssessmentRunReference.model_validate(partial)

    partial_result = deepcopy(raw)
    partial_result["result"]["discovery_evidence_reference"] = None
    with pytest.raises(ValidationError, match="reference digest differs"):
        LocalWebAssessmentRunReference.model_validate(partial_result)

    assert "plan" not in LocalWebAssessmentRunReference.model_validate(raw).model_dump(
        exclude={"plan", "result"}
    )

    current = deepcopy(raw)
    current["plan"].update(
        target_product=source.plan.target_product,
        fingerprint_version_path=source.plan.fingerprint_version_path,
        adapter_implementation_id=source.plan.adapter_implementation_id,
    )
    current["result"].update(
        discovery_evidence_reference=None,
        discovery_evidence_digest=None,
    )
    current["referenceDigest"] = discovery_digest(
        "pajin.web-assessment.run-reference/v1",
        {key: value for key, value in current.items() if key != "referenceDigest"},
    )
    loaded_current = LocalWebAssessmentRunReference.model_validate(current)
    assert loaded_current.reference_digest != source.reference_digest
    assert loaded_current.model_dump(mode="json", by_alias=True) == current
