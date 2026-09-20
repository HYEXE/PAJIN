from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.discovery.canonicalization import discovery_digest
from pajin.web_assessment.browser import BrowserAssessmentObservation, BrowserCredentials
from pajin.web_assessment.diagnostic_catalog import _testing_diagnostic_bundle_catalog
from pajin.web_assessment.models import AssessmentIssue, WebAssessmentPlan
from pajin.web_assessment.network import AssessmentNetwork
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    issue_local_web_assessment_authorization,
    run_local_web_assessment,
)
from pajin.web_assessment.semantic import (
    WebSemanticError,
    validate_local_web_assessment_semantics,
    validate_web_assessment_issue_semantics,
)
from tests.test_web_assessment import _FakeBrowser, _mock_transport


class _SemanticFakeBrowser(_FakeBrowser):
    async def run(self, credentials: BrowserCredentials) -> BrowserAssessmentObservation:
        observed = await super().run(credentials)
        trials = tuple(
            trial.model_copy(
                update={
                    "facts": {
                        "controlMarkerExecuted": False,
                        "probeMarkerExecuted": True,
                        "externalTransmission": False,
                    }
                }
            )
            for trial in observed.dom_xss_trials
        )
        return replace(observed, dom_xss_trials=(trials[0], trials[1]))


@pytest.mark.asyncio
async def test_semantic_oracle_recomputes_all_three_web_diagnostics(
    tmp_path: Path,
) -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
    )
    transport = _mock_transport(plan, [])
    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=tmp_path,
        browser_factory=_SemanticFakeBrowser,
        network_factory=lambda selected: AssessmentNetwork(
            selected,
            transport=transport,
        ),
        diagnostic_catalog=_testing_diagnostic_bundle_catalog(),
    )

    claims = validate_local_web_assessment_semantics(artifacts.result)

    assert [claim.check for claim in claims.claims] == [
        "sql-login",
        "object-access",
        "dom-xss",
    ]
    assert all(claim.status == "locally-reproduced" for claim in claims.claims)
    assert all(trial.code_owned_oracle_passed for claim in claims.claims for trial in claim.trials)
    assert claims.source_integrity_only is True
    assert claims.independent_execution_attested is False
    assert claims.finding_authority is False
    serialized = json.dumps(claims.model_dump(mode="json", by_alias=True))
    assert "transient-token" not in serialized
    assert "@example.test" not in serialized


@pytest.mark.asyncio
async def test_semantic_oracle_rejects_self_asserted_outcome_and_fact_extension() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    transport = _mock_transport(plan, [])

    async def issue() -> AssessmentIssue:
        from pajin.web_assessment.diagnostics import diagnose_sql_login
        from pajin.web_assessment.runner import assessment_policy

        network = AssessmentNetwork(plan, transport=transport)
        try:
            return (
                await diagnose_sql_login(
                    network=network,
                    plan=plan,
                    policy=assessment_policy(plan, max_requests=20),
                )
            ).issue
        finally:
            await network.close()

    original = await issue()
    tampered = original.model_dump(mode="json")
    tampered["trials"][0]["facts"]["sessionMinted"] = False
    tampered["issue_id"] = "web-issue:" + discovery_digest(
        "pajin.web-assessment.issue/v1",
        {
            "check": tampered["check"],
            "cwe": tampered["cwe"],
            "trials": tampered["trials"],
        },
    )
    self_asserted = AssessmentIssue.model_validate(tampered)
    with pytest.raises(WebSemanticError, match="facts differ"):
        validate_web_assessment_issue_semantics(self_asserted)

    extended = original.model_dump(mode="json")
    extended["trials"][0]["facts"]["callerClaimedFinding"] = True
    extended["issue_id"] = "web-issue:" + discovery_digest(
        "pajin.web-assessment.issue/v1",
        {
            "check": extended["check"],
            "cwe": extended["cwe"],
            "trials": extended["trials"],
        },
    )
    extended_issue = AssessmentIssue.model_validate(extended)
    with pytest.raises(WebSemanticError, match="facts differ"):
        validate_web_assessment_issue_semantics(extended_issue)


@pytest.mark.asyncio
async def test_semantic_models_reject_authority_escalation() -> None:
    plan = juice_shop_plan("http://127.0.0.1:3000")
    original = await _diagnose_sql_issue(plan)
    claim = validate_web_assessment_issue_semantics(original)
    elevated = claim.model_dump(mode="json", by_alias=True)
    elevated["claimDigest"] = ""
    elevated["findingAuthority"] = True
    with pytest.raises(ValidationError, match="cannot assert attestation or Finding authority"):
        type(claim).model_validate(elevated)


async def _diagnose_sql_issue(plan: WebAssessmentPlan) -> AssessmentIssue:
    from pajin.web_assessment.diagnostics import diagnose_sql_login
    from pajin.web_assessment.runner import assessment_policy

    network = AssessmentNetwork(plan, transport=_mock_transport(plan, []))
    try:
        return (
            await diagnose_sql_login(
                network=network,
                plan=plan,
                policy=assessment_policy(plan, max_requests=20),
            )
        ).issue
    finally:
        await network.close()
