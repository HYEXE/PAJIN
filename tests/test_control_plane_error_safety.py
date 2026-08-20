import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.exceptions import RequestValidationError

from pajin.control_plane.api import _safe_request_validation_detail
from pajin.control_plane.client import (
    ControlPlaneClient,
    ControlPlaneLeaseLost,
    ControlPlaneProtocolError,
    ControlPlaneRunCancelled,
    ControlPlaneTransientError,
)
from pajin.control_plane.models import ControlPlaneConflictCode
from pajin.control_plane.pentest_workflow_coordination import (
    PentestWorkflowCoordinationRequest,
    PentestWorkflowStageActivationBundle,
    PentestWorkflowStageActivationStatement,
)


def test_control_plane_validation_detail_omits_input_messages_and_field_names() -> None:
    secret = "control-plane-secret-MUST-NOT-PERSIST"
    error = RequestValidationError(
        [
            {
                "type": "value_error",
                "loc": ("body", secret, 7),
                "msg": f"Value error, {secret}\nforged status",
                "input": secret,
                "ctx": {"error": ValueError(secret)},
            }
        ]
    )

    detail = _safe_request_validation_detail(error)
    rendered = json.dumps(detail)

    assert detail == [
        {
            "type": "request_validation",
            "loc": ["body", "<field>", 7],
            "msg": "request validation failed",
        }
    ]
    assert secret not in rendered
    assert "forged status" not in rendered


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status_code", "code", "error_type", "safe_message"),
    [
        (
            409,
            ControlPlaneConflictCode.RUN_CANCELLED.value,
            ControlPlaneRunCancelled,
            "run has been cancelled",
        ),
        (
            409,
            ControlPlaneConflictCode.LEASE_LOST.value,
            ControlPlaneLeaseLost,
            "Control Plane lease was rejected or expired",
        ),
        (500, None, ControlPlaneTransientError, "Control Plane server failure"),
        (418, None, ControlPlaneProtocolError, "unexpected Control Plane status 418"),
    ],
)
async def test_control_plane_client_does_not_reflect_remote_error_detail(
    status_code: int,
    code: str | None,
    error_type: type[Exception],
    safe_message: str,
) -> None:
    secret = "remote-control-plane-secret-MUST-NOT-PERSIST"

    async def handler(_request: httpx.Request) -> httpx.Response:
        body: dict[str, object] = {"detail": f"{secret}\nforged daemon status"}
        if code is not None:
            body["code"] = code
        return httpx.Response(status_code, json=body)

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        with pytest.raises(error_type) as raised:
            await client._request("POST", "/v1/test", json={})

    assert str(raised.value) == safe_message
    assert secret not in str(raised.value)
    assert "forged daemon status" not in str(raised.value)


@pytest.mark.asyncio
async def test_pentest_workflow_client_selects_separate_recon_and_replay_routes() -> None:
    paths: list[str] = []

    async def handler(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        payload = json.loads(request.content)
        statement = payload["activation"]["statement"]
        completed = ["source"] if payload["stage"] == "source" else ["source", "replay"]
        return httpx.Response(
            200,
            json={
                "apiVersion": "pajin.dev/pentest-workflow-coordination-view/v1alpha1",
                "kind": "PentestWorkflowCoordinationView",
                "deploymentId": payload["deploymentId"],
                "deploymentDigest": payload["deploymentDigest"],
                "coordinationRunId": statement["coordinationRunId"],
                "completedStages": completed,
                "nextStage": (
                    "replay" if payload["stage"] == "source" else "control-baseline"
                ),
                "workflowPreparationEligible": False,
                "workflowDeploymentId": None,
                "workflowDeploymentDigest": None,
                "workflowDeploymentSha256": None,
                "sealedCoordinationRootDigest": "e" * 64,
                "executionAuthority": False,
                "findingAuthority": False,
            },
        )

    now = datetime(2026, 8, 20, 12, 0, tzinfo=UTC)
    requests = []
    predecessor: str | None = None
    for ordinal, stage in enumerate(("source", "replay"), start=1):
        statement = PentestWorkflowStageActivationStatement(
            issuerId="pajin.pentest-stage-authority",
            issuerVersion="1.0.0",
            issuerDigest="d" * 64,
            coordinationDeploymentId="pentest-coordination-client",
            coordinationDeploymentDigest="a" * 64,
            coordinationRunId="run_20260820T120000Z_1234abcd",
            stage=stage,
            ordinal=ordinal,
            predecessorReceiptDigest=predecessor,
            childDeploymentId=f"deployment:pentest-{stage}",
            childDeploymentDigest=("b" if stage == "source" else "c") * 64,
            workerSubject=f"pentest-{stage}-worker",
            issuedAt=now,
            expiresAt=now + timedelta(minutes=5),
        )
        bundle = PentestWorkflowStageActivationBundle(
            keyId="pentest-stage-key-client",
            statement=statement,
            signatureBase64url="A" * 86,
        )
        requests.append(
            PentestWorkflowCoordinationRequest(
                deploymentId=statement.coordination_deployment_id,
                deploymentDigest=statement.coordination_deployment_digest,
                stage=stage,
                activation=bundle,
            )
        )
        predecessor = "f" * 64

    async with ControlPlaneClient(
        base_url="https://control-plane.invalid",
        bearer_token="worker-client-token-00000000000000000001",
        transport=httpx.MockTransport(handler),
    ) as client:
        for request in requests:
            await client.dispatch_pentest_workflow_stage(request)

    assert paths == [
        "/v1/worker/pentest/workflows/stages/recon/dispatch",
        "/v1/worker/pentest/workflows/stages/replay/dispatch",
    ]
