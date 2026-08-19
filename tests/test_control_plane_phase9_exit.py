from pathlib import Path

from fastapi.routing import APIRoute

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.models import Principal, PrincipalRole

_NON_SAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_EXPECTED_PUBLIC_NON_SAFE_ROUTES = frozenset(
    {
        ("POST", "/v1/runs"),
        ("POST", "/v1/runs/{run_id}/cancel"),
        ("POST", "/v1/campaign-drafts/{draft_digest}/compile"),
        ("POST", "/v1/replay/source-artifacts"),
        ("POST", "/v1/replay/batches"),
        ("POST", "/v1/worker/jobs/claim"),
        ("POST", "/v1/worker/pentest/recon/dispatch"),
        ("POST", "/v1/worker/pentest/replay/dispatch"),
        ("POST", "/v1/worker/pentest/workflows/stages/recon/dispatch"),
        ("POST", "/v1/worker/pentest/workflows/stages/replay/dispatch"),
        ("POST", "/v1/pentest/workflows/run"),
        ("POST", "/v1/worker/replay/jobs/claim"),
        ("POST", "/v1/worker/replay/jobs/{job_id}/heartbeat"),
        ("POST", "/v1/worker/replay/jobs/{job_id}/tool-permits"),
        ("POST", "/v1/worker/replay/jobs/{job_id}/artifact-upload"),
        ("PUT", "/v1/worker/replay/jobs/{job_id}/artifact-upload/parts"),
        ("POST", "/v1/worker/replay/jobs/{job_id}/finalize"),
        ("POST", "/v1/worker/jobs/{job_id}/heartbeat"),
        ("POST", "/v1/worker/jobs/{job_id}/complete"),
        ("POST", "/v1/worker/jobs/{job_id}/fail"),
        ("POST", "/v1/worker/jobs/{job_id}/checkpoints"),
        ("POST", "/v1/approvals/{approval_id}/decision"),
        ("POST", "/v1/checkpoints/{checkpoint_id}/resume"),
        ("POST", "/v1/maintenance/requeue-expired"),
    }
)


def _settings(tmp_path: Path) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            "phase9-exit-operator-token-that-is-long-and-distinct": Principal(
                subject="phase9-exit-operator",
                roles=frozenset({PrincipalRole.OPERATOR}),
            ),
            "phase9-exit-approver-token-that-is-long-and-distinct": Principal(
                subject="phase9-exit-approver",
                roles=frozenset({PrincipalRole.APPROVER}),
            ),
            "phase9-exit-worker-token-that-is-long-and-distinct": Principal(
                subject="phase9-exit-worker",
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"phase9-exit-checkpoint-key-that-is-long-enough"},
    )


def test_public_non_safe_route_inventory_is_explicit_and_bearer_authenticated(
    tmp_path: Path,
) -> None:
    app = create_app(_settings(tmp_path))
    observed = frozenset(
        (method, route.path)
        for route in app.routes
        if isinstance(route, APIRoute)
        for method in route.methods & _NON_SAFE_METHODS
    )

    assert observed == _EXPECTED_PUBLIC_NON_SAFE_ROUTES

    openapi_paths = app.openapi()["paths"]
    for method, path in observed:
        operation = openapi_paths[path][method.lower()]
        assert operation["security"] == [{"HTTPBearer": []}]
