"""Domain composition tests; Web retains the existing unit-level source-loader double."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.measured_reviews.models import ReviewEvidence
from pajin.workflow.network_measured_product_reader import (
    NetworkMeasuredProductReader,
    NetworkMeasuredProductReadRegistration,
    NetworkMeasuredProductReadRegistry,
)
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReadRegistry,
)
from tests.test_control_plane_web import APPROVER_TOKEN, OPERATOR_TOKEN, _auth, _settings
from tests.test_measured_reviews import _assessment
from tests.test_network_measured_product import _ProductContext
from tests.test_web_measured_product_flow import _project
from tests.test_web_measured_product_reader import _read_registration

pytest_plugins = ("tests.test_network_measured_product", "tests.test_web_validation_evaluation")


def _exercise(
    settings: ControlPlaneSettings,
    domain: str,
    tmp_path: Path,
    *,
    web: WebMeasuredProductReader | None = None,
    network: NetworkMeasuredProductReader | None = None,
) -> None:
    app = create_app(
        settings, web_measured_product_reader=web, network_measured_product_reader=network
    )
    with TestClient(app) as client:
        response = client.get(
            "/v1/measured-review-evidence/" + domain, headers=_auth(APPROVER_TOKEN)
        )
        assert response.status_code == 200, response.text
        evidence = ReviewEvidence.model_validate_json(response.text)
        assert evidence.domain == domain and evidence.raw_content_included is False
        evidence_path = tmp_path / "public-review-evidence.json"
        evidence_path.write_text(response.text)
        node = shutil.which("node")
        if node is not None:
            module = Path(__file__).resolve().parents[1] / "src/pajin/control_plane/web"
            script = (
                'import fs from "node:fs"; '
                "const review = await import(process.argv[1]); "
                "const protocol = await import(process.argv[2]); "
                "review.validateReviewEvidence(protocol.parseJsonPayload("
                'fs.readFileSync(process.argv[3], "utf8"), 200));'
            )
            result = subprocess.run(
                [
                    node,
                    "--input-type=module",
                    "--eval",
                    script,
                    (module / "measured-reviews.js").as_uri(),
                    (module / "protocol.js").as_uri(),
                    str(evidence_path),
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            assert result.returncode == 0, result.stderr
        response = client.post(
            "/v1/measured-reviews",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "requestKey": "open-domain",
                "domain": domain,
                "title": f"{domain} review",
                "evidenceDigest": evidence.evidence_digest,
            },
        )
        assert response.status_code == 200, response.text
        review_id = response.json()["reviewId"]
        url = "/v1/measured-reviews/" + review_id
        assessment = _assessment(evidence).model_copy(
            update={"impact": "Bounded benchmark assessment"}
        )
        response = client.post(
            url + "/assessment",
            headers=_auth(OPERATOR_TOKEN),
            json={
                "requestKey": "assessment-domain",
                "expectedRevision": 1,
                "assessment": assessment.model_dump(mode="json", by_alias=True),
            },
        )
        assert response.status_code == 200, response.text
        response = client.post(
            url + "/decision",
            headers=_auth(APPROVER_TOKEN),
            json={
                "requestKey": "accept-domain",
                "expectedRevision": 2,
                "decision": "accept",
                "reason": "The report preserves the source limits and actionable remediation.",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["evidence"]["projection"] == evidence.projection.model_dump(
            mode="json",
            by_alias=True,
        )
        report = client.get(url + "/report.md", headers=_auth(APPROVER_TOKEN))
        assert report.status_code == 200
        assert evidence.evidence_digest in report.text and "Status: ACCEPTED" in report.text


def test_network_human_review_uses_exact_registered_product(
    tmp_path: Path,
    network_product_context: _ProductContext,
) -> None:
    context = network_product_context
    registration = NetworkMeasuredProductReadRegistration.from_outcome(
        deployment_id="deployment.network-review",
        outcome=context.outcome,
        reopen_context=context.reopen,
    )
    _exercise(
        _settings(tmp_path / "network-review.db"),
        "network",
        tmp_path,
        network=NetworkMeasuredProductReader(
            deployment_id=registration.deployment_id,
            resolver=NetworkMeasuredProductReadRegistry((registration,)),
        ),
    )


def test_web_human_review_preserves_projection_authority_at_unit_boundary(
    tmp_path: Path,
    web002d_context: SimpleNamespace,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, _, _, context, _, _, _ = _project(web002d_context, tmp_path, monkeypatch)
    registration = _read_registration(outcome=outcome, context=context)
    _exercise(
        _settings(tmp_path / "web-review.db"),
        "web",
        tmp_path,
        web=WebMeasuredProductReader(
            deployment_id=registration.deployment_id,
            resolver=WebMeasuredProductReadRegistry((registration,)),
        ),
    )
