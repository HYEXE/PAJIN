"""Read-only Operator transport for one deployment-pinned System result."""

import asyncio
from threading import Lock
from typing import TYPE_CHECKING, Annotated

from fastapi import Depends, FastAPI, HTTPException, Request

from pajin.control_plane.models import Principal, PrincipalRole
from pajin.control_plane.system_product import (
    SystemOperatorView,
    SystemProductIntegrityError,
    SystemProductNotFound,
    SystemProductReader,
    SystemProductUnavailable,
)

if TYPE_CHECKING:
    from pajin.control_plane.api_routes import ControlPlaneDependencies


def register_system_product_route(
    app: FastAPI, *, reader: SystemProductReader | None, dependencies: "ControlPlaneDependencies"
) -> None:
    if reader is not None and type(reader) is not SystemProductReader:
        raise TypeError("System product reads require the exact pinned reader")
    lock = Lock()

    def read(campaign: str, principal: Principal) -> SystemOperatorView:
        if reader is None:
            raise SystemProductUnavailable("System result is not configured")
        # Admission precedes filesystem access and waiting for another reader.
        reader.authorize(campaign, principal.subject)
        with lock:
            return reader.read(campaign=campaign, subject=principal.subject)

    @app.get(
        "/v1/campaigns/{campaign}/products/system-os-release",
        response_model=SystemOperatorView,
    )
    async def get_system_product(
        campaign: str,
        request: Request,
        principal: Annotated[
            Principal, Depends(dependencies.require_roles(PrincipalRole.OPERATOR))
        ],
    ) -> SystemOperatorView:
        if request.scope.get("query_string", b"") or await request.body():
            raise HTTPException(400, "System result read accepts no query or request body")
        try:
            return await asyncio.to_thread(read, campaign, principal)
        except SystemProductNotFound:
            raise HTTPException(404, "No System result is visible for this Campaign") from None
        except SystemProductIntegrityError:
            raise HTTPException(409, "System evidence is not integrity-valid") from None
        except SystemProductUnavailable:
            detail = (
                "System result is not configured"
                if reader is None
                else "System evidence could not be read"
            )
            raise HTTPException(503, detail) from None
