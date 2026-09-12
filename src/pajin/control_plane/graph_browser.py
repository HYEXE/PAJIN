"""Deployment-registered Campaign discovery and explicitly historical Graph pages."""

import base64
import sqlite3
from collections.abc import Mapping
from dataclasses import asdict
from pathlib import Path
from re import fullmatch
from types import MappingProxyType
from typing import TYPE_CHECKING, Annotated, Literal

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi import Path as APIPath
from pydantic import Field

from pajin.control_plane.graph_pages import CanonicalGraphPageContent, build_graph_page_content
from pajin.control_plane.graph_views import _validated_graph_database
from pajin.control_plane.models import Principal, PrincipalRole
from pajin.domain.models import StrictModel
from pajin.graph.history import read_snapshot_history
from pajin.graph.sqlite_store import SQLiteGraphStoreError
from pajin.runtime.safe_files import parse_strict_json_bytes

if TYPE_CHECKING:
    from pajin.control_plane.api_routes import ControlPlaneDependencies

CAMPAIGN = r"^[a-z0-9][a-z0-9-]{2,79}$"
SNAPSHOT = r"^graph-snapshot_[a-f0-9]{64}$"
DIGEST = r"^[a-f0-9]{64}$"


def campaign_databases(value: str | None) -> dict[str, Path]:
    if value is None:
        return {}
    decoded = parse_strict_json_bytes(
        value.encode(), label="Graph Campaign registry", max_bytes=65536
    )
    if (
        not isinstance(decoded, dict)
        or len(decoded) > 100
        or any(
            not isinstance(k, str)
            or fullmatch(CAMPAIGN, k) is None
            or not isinstance(v, str)
            or not v
            or len(v) > 4096
            for k, v in decoded.items()
        )
    ):
        raise ValueError(
            "Graph Campaign registry must map at most 100 Campaigns to deployment paths"
        )
    return {k: Path(v) for k, v in decoded.items()}


class HistoricalGraphBoundary(StrictModel):
    canonical_graph_snapshot_verified: Literal[True] = Field(
        default=True, alias="canonicalGraphSnapshotVerified"
    )
    current_snapshot_verified: Literal[False] = Field(
        default=False, alias="currentSnapshotVerified"
    )
    content_redacted: Literal[True] = Field(default=True, alias="contentRedacted")
    view_authorizes_admission: Literal[False] = Field(
        default=False, alias="viewAuthorizesAdmission"
    )
    view_grants_capability: Literal[False] = Field(default=False, alias="viewGrantsCapability")
    view_grants_permit: Literal[False] = Field(default=False, alias="viewGrantsPermit")
    view_authorizes_execution: Literal[False] = Field(
        default=False, alias="viewAuthorizesExecution"
    )


class HistoricalGraphPage(CanonicalGraphPageContent):
    api_version: Literal["pajin.control-plane/historical-graph-page/v1"] = Field(
        default="pajin.control-plane/historical-graph-page/v1", alias="apiVersion"
    )
    kind: Literal["HistoricalGraphPage"] = "HistoricalGraphPage"
    state_digest: str = Field(alias="stateDigest", pattern=DIGEST)
    is_current: bool = Field(alias="isCurrent", strict=True)
    historical_read_only: Literal[True] = Field(default=True, alias="historicalReadOnly")
    authority_boundary: HistoricalGraphBoundary = Field(
        default_factory=HistoricalGraphBoundary, alias="authorityBoundary"
    )


class _HistoryCursor(StrictModel):
    campaign: str = Field(pattern=CAMPAIGN)
    state: str = Field(pattern=DIGEST)
    offset: int = Field(ge=1, strict=True)
    limit: int = Field(ge=1, le=50, strict=True)

    def encode(self) -> str:
        return base64.urlsafe_b64encode(self.model_dump_json().encode()).decode().rstrip("=")

    @classmethod
    def decode(cls, value: str) -> "_HistoryCursor":
        if not value or len(value) > 1024:
            raise ValueError("invalid history cursor")
        content = base64.b64decode(value + "=" * (-len(value) % 4), altchars=b"-_", validate=True)
        result = cls.model_validate(
            parse_strict_json_bytes(content, label="history cursor", max_bytes=1024)
        )
        if result.encode() != value:
            raise ValueError("noncanonical history cursor")
        return result


class GraphCampaignBrowser:
    def __init__(self, databases: Mapping[str, Path]) -> None:
        if len(databases) > 100 or any(fullmatch(CAMPAIGN, k) is None for k in databases):
            raise ValueError("Graph Campaign registry is invalid")
        paths = {k: _validated_graph_database(v) for k, v in databases.items()}
        if len(set(paths.values())) != len(paths):
            raise ValueError("Graph Campaigns require distinct databases")
        self.databases = MappingProxyType(paths)

    def path(self, campaign: str) -> Path:
        if campaign not in self.databases:
            raise HTTPException(status_code=404, detail="Campaign is not registered for browsing")
        return self.databases[campaign]

    def catalog(self, campaign: str, *, limit: int, cursor: str | None) -> dict[str, object]:
        offset, expected = 0, None
        if cursor is not None:
            try:
                decoded = _HistoryCursor.decode(cursor)
                if decoded.campaign != campaign or decoded.limit != limit or decoded.offset % limit:
                    raise ValueError("cursor scope differs")
                offset, expected = decoded.offset, decoded.state
            except ValueError as exc:
                raise HTTPException(status_code=422, detail="History cursor is invalid") from exc
        result = read_snapshot_history(
            self.path(campaign),
            campaign_id=campaign,
            offset=offset,
            limit=limit,
            expected_state=expected,
        )
        return {
            "apiVersion": "pajin.control-plane/graph-history-catalog/v1",
            "campaignId": campaign,
            "stateDigest": result.state_digest,
            "currentSnapshotId": result.current_snapshot_id,
            "total": result.total,
            "offset": offset,
            "limit": limit,
            "items": [asdict(entry) for entry in result.entries],
            "nextCursor": _HistoryCursor(
                campaign=campaign, state=result.state_digest, offset=offset + limit, limit=limit
            ).encode()
            if offset + limit < result.total
            else None,
            "historicalReadOnly": True,
        }

    def page(
        self, campaign: str, snapshot_id: str, *, state: str, limit: int, cursor: str | None
    ) -> HistoricalGraphPage:
        result = read_snapshot_history(
            self.path(campaign), campaign_id=campaign, snapshot_id=snapshot_id, expected_state=state
        )
        if result.snapshot is None:
            raise HTTPException(status_code=404, detail="Historical Snapshot was not found")
        content = build_graph_page_content(result.snapshot, limit=limit, cursor=cursor)
        return HistoricalGraphPage.model_validate(
            {
                **content.model_dump(by_alias=True),
                "stateDigest": result.state_digest,
                "isCurrent": snapshot_id == result.current_snapshot_id,
            }
        )


def register_graph_browser_routes(
    app: FastAPI, *, browser: GraphCampaignBrowser, dependencies: "ControlPlaneDependencies"
) -> None:
    operator = dependencies.require_roles(PrincipalRole.OPERATOR)

    async def read_only(request: Request) -> None:
        pairs = list(request.query_params.multi_items())
        if (
            await request.body()
            or any(k not in {"state", "limit", "cursor"} for k, _ in pairs)
            or len(pairs) != len({k for k, _ in pairs})
        ):
            raise HTTPException(
                status_code=400, detail="Graph browsing accepts only its page parameters"
            )

    @app.get("/v1/graph-browser/campaigns", dependencies=[Depends(read_only)])
    def campaigns(_principal: Annotated[Principal, Depends(operator)]) -> dict[str, object]:
        return {
            "apiVersion": "pajin.control-plane/graph-campaigns/v1",
            "campaigns": sorted(browser.databases),
            "executionAuthorized": False,
        }

    @app.get("/v1/graph-browser/campaigns/{campaign}/snapshots", dependencies=[Depends(read_only)])
    def snapshots(
        campaign: Annotated[str, APIPath(pattern=CAMPAIGN)],
        _principal: Annotated[Principal, Depends(operator)],
        limit: Annotated[int, Query(ge=1, le=50)] = 25,
        cursor: Annotated[str | None, Query(max_length=1024)] = None,
    ) -> dict[str, object]:
        try:
            return browser.catalog(campaign, limit=limit, cursor=cursor)
        except (ValueError, OSError, SQLiteGraphStoreError, sqlite3.Error) as exc:
            raise HTTPException(
                status_code=409,
                detail="Graph history is unavailable or changed; reload the catalog",
            ) from exc

    @app.get(
        "/v1/graph-browser/campaigns/{campaign}/snapshots/{snapshot_id}/pages",
        response_model=HistoricalGraphPage,
        dependencies=[Depends(read_only)],
    )
    def page(
        campaign: Annotated[str, APIPath(pattern=CAMPAIGN)],
        snapshot_id: Annotated[str, APIPath(pattern=SNAPSHOT)],
        _principal: Annotated[Principal, Depends(operator)],
        state: Annotated[str, Query(pattern=DIGEST)],
        limit: Annotated[int, Query(ge=1, le=500)] = 100,
        cursor: Annotated[str | None, Query(max_length=2048)] = None,
    ) -> HistoricalGraphPage:
        try:
            return browser.page(campaign, snapshot_id, state=state, limit=limit, cursor=cursor)
        except (ValueError, OSError, SQLiteGraphStoreError, sqlite3.Error) as exc:
            raise HTTPException(
                status_code=409,
                detail="Graph history is unavailable or changed; reload the catalog",
            ) from exc
