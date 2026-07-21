import json

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
