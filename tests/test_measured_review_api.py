"""End-to-end human review over independently executed in-process AI fixtures."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import create_app
from pajin.control_plane.database import ControlPlaneRepository
from pajin.control_plane.errors import StateConflict
from pajin.control_plane.measured_reviews.evidence import MeasuredReviewEvidenceReader
from pajin.control_plane.measured_reviews.models import AssessmentRequest, OpenReviewRequest
from pajin.control_plane.measured_reviews.service import MeasuredReviewService
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.workflow.ai_measured_case_authority import AIMeasuredCaseMapping
from pajin.workflow.ai_measured_product_flow import (
    AI_MEASURED_PRODUCT_PATH,
    AIMeasuredProductProjector,
    AIMeasuredProductSourceReopenContext,
)
from pajin.workflow.ai_measured_product_reader import (
    AIMeasuredProductReader,
    AIMeasuredProductReadRegistry,
)
from tests.test_ai_measured_product import _ProductContext, _registration
from tests.test_ai_source_measurement import _run_ai002c_checkpoint
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)
from tests.test_measured_reviews import _assessment

pytest_plugins = ("tests.test_measured_reviews",)
BASE = "/v1/measured-reviews"
EVIDENCE = "/v1/measured-review-evidence/ai"


def _reader(context: _ProductContext) -> AIMeasuredProductReader:
    registration = _registration(context)
    return AIMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=AIMeasuredProductReadRegistry((registration,)),
    )


@pytest.fixture(scope="module")
def second_ai_product(tmp_path_factory: pytest.TempPathFactory) -> Iterator[_ProductContext]:
    root = tmp_path_factory.mktemp("review-retest")
    patch = pytest.MonkeyPatch()
    try:
        source, _authorizer, provider, measured = asyncio.run(_run_ai002c_checkpoint(root, patch))
        assert isinstance(measured, AIMeasuredCaseMapping)
        reopen = AIMeasuredProductSourceReopenContext(measured_cases=measured, provider=provider)
        outcome = AIMeasuredProductProjector(output_root=root / "product-runs").project(
            source,
            reopen_context=reopen,
        )
        yield _ProductContext(root, source, measured, provider, reopen, outcome)
    finally:
        patch.undo()


def test_api_assessment_review_restart_retest_and_report(
    tmp_path: Path,
    ai_product_context: _ProductContext,
    second_ai_product: _ProductContext,
) -> None:
    from pajin.control_plane.measured_reviews.models import ReviewEvidence

    settings = _settings(tmp_path / "review.db")
    operator, approver = _auth(OPERATOR_TOKEN), _auth(APPROVER_TOKEN)
    app = create_app(settings, ai_measured_product_reader=_reader(ai_product_context))
    with TestClient(app) as client:
        assert client.get(BASE, headers=operator).json() == {"items": [], "nextAfter": None}
        response = client.get(EVIDENCE, headers=operator)
        assert response.status_code == 200, response.text
        evidence = ReviewEvidence.model_validate_json(response.text)
        opened_request = {
            "requestKey": "open-1",
            "domain": "ai",
            "evidenceDigest": evidence.evidence_digest,
            "title": "Disclosure review",
        }
        response = client.post(BASE, json=opened_request, headers=operator)
        assert response.status_code == 200, response.text
        opened = response.json()
        url = BASE + "/" + opened["reviewId"]
        assert client.post(BASE, json=opened_request, headers=operator).json() == opened
        assessment = {
            "requestKey": "assess-1",
            "expectedRevision": 1,
            "assessment": _assessment(evidence).model_dump(mode="json", by_alias=True),
        }
        response = client.post(url + "/assessment", json=assessment, headers=operator)
        assert response.status_code == 200, response.text
        assert response.json()["state"] == "awaiting-review"
        decision = {
            "requestKey": "accept-1",
            "expectedRevision": 2,
            "decision": "accept",
            "reason": "The isolated benchmark assessment and plan are supported.",
        }
        assert client.post(url + "/decision", json=decision, headers=operator).status_code == 403
        response = client.post(url + "/decision", json=decision, headers=approver)
        assert response.status_code == 200, response.text
        accepted = response.json()
        assert accepted["state"] == "accepted" and accepted["revision"] == 3
        assert accepted["reviewer"] != accepted["assessmentAuthor"]
        retest = {
            "requestKey": "retest-1",
            "expectedRevision": 3,
            "evidenceDigest": evidence.evidence_digest,
            "changeReference": "change-42",
            "conclusion": "inconclusive",
            "rationale": "A separate run needs comparison.",
        }
        assert client.post(url + "/retest", json=retest, headers=operator).status_code == 409
        assert client.get(url, headers=_auth(AUDITOR_TOKEN)).json() == accepted
        report = client.get(url + "/report.md", headers=operator)
        assert report.status_code == 200 and "Status: ACCEPTED" in report.text
        assert "no-store" in report.headers["cache-control"]
        assert "attachment" in report.headers["content-disposition"]

    # A real restart loads another independently executed and sealed source through its reader.
    app = create_app(settings, ai_measured_product_reader=_reader(second_ai_product))
    with TestClient(app) as client:
        assert client.get(url, headers=operator).json() == accepted
        assert client.post(BASE, json=opened_request, headers=operator).json() == opened
        fresh = client.get(EVIDENCE, headers=operator)
        assert fresh.status_code == 200, fresh.text
        new_evidence = ReviewEvidence.model_validate_json(fresh.text)
        assert new_evidence.source_identity != evidence.source_identity
        assert new_evidence.case_contract_digest == evidence.case_contract_digest
        retest["evidenceDigest"] = new_evidence.evidence_digest
        response = client.post(url + "/retest", json=retest, headers=operator)
        assert response.status_code == 200, response.text
        pending = response.json()
        assert pending["state"] == "awaiting-review" and pending["reviewer"] is None
        assert not pending["retest"]["executionAfterRemediationVerified"]
        assert "Status: DRAFT" in client.get(url + "/report.md", headers=operator).text
        stale = {**decision, "requestKey": "stale-accept"}
        assert client.post(url + "/decision", json=stale, headers=approver).status_code == 409
        response = client.post(
            url + "/decision",
            headers=approver,
            json={**decision, "requestKey": "accept-2", "expectedRevision": 4},
        )
        assert response.status_code == 200, response.text
        final = response.json()
        assert final["state"] == "accepted" and final["revision"] == 5
        assert not final["genericFindingConfirmed"] and not final["sarifAuthorized"]
        assert client.post(url + "/retest", json=retest, headers=operator).json() == pending
        assert client.get(url, headers=operator).json() == final
        history = client.get(url + "/history", headers=approver).json()
        assert [item["revision"] for item in history] == [1, 2, 3, 4, 5]
        assert history[2]["command"]["decision"] == "accept"
        report = client.get(url + "/report.md", headers=_auth(AUDITOR_TOKEN))
        assert "revision: 5" in report.text
        assert evidence.evidence_digest in report.text
        assert new_evidence.evidence_digest in report.text
        assert "Production impact remains unverified" in report.text


@pytest.mark.parametrize("token, expected", [(None, 401), (WORKER_TOKEN, 403)])
def test_unauthenticated_or_worker_cannot_access_review_surfaces(
    tmp_path: Path,
    token: str | None,
    expected: int,
) -> None:
    app = create_app(_settings(tmp_path / "roles.db"))
    headers = {} if token is None else _auth(token)
    review = BASE + "/review_" + "a" * 32
    with TestClient(app) as client:
        for path in (EVIDENCE, BASE, review, review + "/history", review + "/report.md"):
            assert client.get(path, headers=headers).status_code == expected


def test_review_source_selection_and_unconfigured_reader_fail_closed(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "unconfigured.db"))
    with TestClient(app) as client:
        for token in (OPERATOR_TOKEN, APPROVER_TOKEN, AUDITOR_TOKEN):
            for domain in ("web", "network", "ai"):
                path = "/v1/measured-review-evidence/" + domain
                assert client.get(path, headers=_auth(token)).status_code == 503
        assert (
            client.get(EVIDENCE + "?path=source.json", headers=_auth(OPERATOR_TOKEN)).status_code
            == 400
        )
        assert (
            client.request("GET", EVIDENCE, json={}, headers=_auth(OPERATOR_TOKEN)).status_code
            == 400
        )
        for injected in ({"actor": "another"}, {"source": {}}, {"path": "/sealed/source"}):
            response = client.post(
                BASE,
                headers=_auth(OPERATOR_TOKEN),
                json={
                    "requestKey": "forged-open",
                    "domain": "ai",
                    "evidenceDigest": "a" * 64,
                    "title": "forged",
                    **injected,
                },
            )
            assert response.status_code == 422
        assert client.get(BASE, headers=_auth(OPERATOR_TOKEN)).json()["items"] == []


def test_tampered_source_cannot_be_recorded_as_verified_review(
    tmp_path: Path,
    ai_product_context: _ProductContext,
) -> None:
    app = create_app(
        _settings(tmp_path / "tampered.db"), ai_measured_product_reader=_reader(ai_product_context)
    )
    path = ai_product_context.outcome.run_path / AI_MEASURED_PRODUCT_PATH
    original = path.read_bytes()
    with TestClient(app) as client:
        try:
            path.write_bytes(original + b" ")
            response = client.get(EVIDENCE, headers=_auth(OPERATOR_TOKEN))
            assert response.status_code == 409
            assert "integrity-valid" in response.text
            response = client.post(
                BASE,
                headers=_auth(OPERATOR_TOKEN),
                json={
                    "requestKey": "tampered-open",
                    "domain": "ai",
                    "evidenceDigest": "a" * 64,
                    "title": "cannot be verified",
                },
            )
            assert response.status_code == 409
            assert client.get(BASE, headers=_auth(OPERATOR_TOKEN)).json()["items"] == []
        finally:
            path.write_bytes(original)


def test_concurrent_commands_restart_and_key_substitution_are_atomic(
    tmp_path: Path,
    ai_product_context: _ProductContext,
) -> None:
    path = tmp_path / "race.db"
    repositories = [ControlPlaneRepository(f"sqlite:///{path}") for _ in range(2)]
    reader = MeasuredReviewEvidenceReader(ai=_reader(ai_product_context))
    evidence = reader.read("ai")
    principal = Principal(subject="writer", roles=frozenset({PrincipalRole.OPERATOR}))
    services = [MeasuredReviewService(repository, reader) for repository in repositories]
    for repository in repositories:
        repository.initialize()
    payload = OpenReviewRequest(
        requestKey="same-open",
        domain="ai",
        evidenceDigest=evidence.evidence_digest,
        title="Race review",
    )
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(service.submit, payload, principal=principal) for service in services
            ]
            views = [future.result() for future in futures]
        assert views[0] == views[1]
        assert len(services[0].history(views[0].review_id, principal=principal)) == 1
        substitute = payload.model_copy(update={"title": "Different content"})
        with pytest.raises(StateConflict, match="Request key"):
            services[0].submit(substitute, principal=principal)
        requests = [
            AssessmentRequest(
                requestKey=f"race-{index}", expectedRevision=1, assessment=_assessment(evidence)
            )
            for index in range(2)
        ]
        with ThreadPoolExecutor(max_workers=2) as pool:
            futures = [
                pool.submit(
                    service.submit, request, principal=principal, review_id=views[0].review_id
                )
                for service, request in zip(services, requests, strict=True)
            ]
            results = []
            for future in futures:
                try:
                    results.append(future.result())
                except StateConflict:
                    results.append(None)
        assert sum(result is not None for result in results) == 1
        assert len(services[0].history(views[0].review_id, principal=principal)) == 2
    finally:
        for repository in repositories:
            repository.close()
    restarted = ControlPlaneRepository(f"sqlite:///{path}")
    try:
        restarted.initialize()
        service = MeasuredReviewService(restarted, MeasuredReviewEvidenceReader())
        # Exact duplicates return the original receipt even if the deployment source is offline.
        assert service.submit(payload, principal=principal) == views[0]
        assert service.get(views[0].review_id, principal=principal).revision == 2
    finally:
        restarted.close()


def test_incomplete_stale_and_forged_stored_assessments_are_rejected(
    tmp_path: Path,
    ai_product_context: _ProductContext,
) -> None:
    from pajin.control_plane.measured_reviews.models import ReviewEvidence

    settings = _settings(tmp_path / "integrity.db")
    app = create_app(settings, ai_measured_product_reader=_reader(ai_product_context))
    headers = _auth(OPERATOR_TOKEN)
    with TestClient(app) as client:
        evidence = ReviewEvidence.model_validate_json(client.get(EVIDENCE, headers=headers).text)
        request = {
            "requestKey": "integrity-open",
            "domain": "ai",
            "title": "Review",
            "evidenceDigest": evidence.evidence_digest,
        }
        stale = {**request, "evidenceDigest": "0" * 64}
        assert client.post(BASE, headers=headers, json=stale).status_code == 409
        view = client.post(BASE, headers=headers, json=request).json()
        url = BASE + "/" + view["reviewId"]
        assessment = _assessment(evidence).model_dump(mode="json", by_alias=True)
        incomplete = {**assessment, "severityRationale": " "}
        response = client.post(
            url + "/assessment",
            headers=headers,
            json={
                "requestKey": "incomplete",
                "expectedRevision": 1,
                "assessment": incomplete,
            },
        )
        assert response.status_code == 422
        assert client.get(url, headers=headers).json()["revision"] == 1
    repository = ControlPlaneRepository(settings.database_url)
    try:
        repository.initialize()
        with repository.engine.begin() as connection:
            guard = connection.exec_driver_sql(
                "SELECT sql FROM sqlite_master "
                "WHERE name = 'cp_measured_review_revisions_no_update'"
            ).scalar_one()
            original = json.loads(
                connection.exec_driver_sql(
                    "SELECT payload FROM cp_measured_review_revisions"
                ).scalar_one()
            )
            original["command"]["title"] = "Altered outside the application"
            connection.exec_driver_sql("DROP TRIGGER cp_measured_review_revisions_no_update")
            connection.exec_driver_sql(
                "UPDATE cp_measured_review_revisions SET payload = ?", (json.dumps(original),)
            )
            connection.exec_driver_sql(guard)
    finally:
        repository.close()
    with TestClient(create_app(settings)) as client:
        for suffix in ("", "/history", "/report.md"):
            response = client.get(url + suffix, headers=headers)
            assert response.status_code == 409 and "integrity-valid" in response.text
        assert client.post(BASE, headers=headers, json=request).status_code == 409
