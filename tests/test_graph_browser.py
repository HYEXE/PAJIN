"""Registered Campaign and historical reads retain every Graph verification gate."""

import json
import shutil
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_control_plane_graph_views import (
    APPROVER_TOKEN,
    CAMPAIGN,
    DIGEST_B,
    NOW,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _current_snapshot,
    _settings,
)
from test_graph_snapshot_cache import _tamper

from pajin.control_plane.api import create_app
from pajin.control_plane.graph_browser import GraphCampaignBrowser, campaign_databases
from pajin.graph import GraphSnapshotAuthority, GraphSnapshotReason, SQLiteGraphStore

BASE = "/v1/graph-browser/campaigns"


@pytest.fixture
def browser(tmp_path):
    first = tmp_path / "first.db"
    _store, authority, old = _current_snapshot(first)
    latest = authority.capture(GraphSnapshotReason.REPLAN)
    second = tmp_path / "second.db"
    other = SQLiteGraphStore(second, campaign_id="second-campaign")
    GraphSnapshotAuthority(
        creator_id="reader",
        creator_digest=DIGEST_B,
        projection_store=other.projection_store,
        snapshot_store=other.snapshot_store,
        clock=lambda: NOW,
    ).capture(GraphSnapshotReason.CHECKPOINT)
    settings = replace(
        _settings(tmp_path / "cp.db", graph_database=first),
        graph_campaign_databases={CAMPAIGN: first, "second-campaign": second},
    )
    with TestClient(create_app(settings)) as client:
        yield client, first, authority, old, latest


def test_campaign_catalog_history_and_current_contract_remain_separate(browser):
    client, path, _, old, latest = browser
    auth = _auth(OPERATOR_TOKEN)
    before = path.read_bytes()
    registered = client.get(BASE, headers=auth)
    assert registered.status_code == 200
    assert registered.json()["campaigns"] == [CAMPAIGN, "second-campaign"]
    assert str(path) not in registered.text and registered.json()["executionAuthorized"] is False
    url = f"{BASE}/{CAMPAIGN}/snapshots"
    catalog = client.get(url + "?limit=1", headers=auth).json()
    assert catalog["currentSnapshotId"] == latest.snapshot_id
    assert catalog["items"][0]["snapshot_id"] == latest.snapshot_id
    assert catalog["total"] == 2 and catalog["nextCursor"]
    earlier = client.get(url, params={"limit": 1, "cursor": catalog["nextCursor"]}, headers=auth)
    assert (
        earlier.status_code == 200 and earlier.json()["items"][0]["snapshot_id"] == old.snapshot_id
    )
    page = client.get(
        f"{url}/{old.snapshot_id}/pages",
        params={"state": catalog["stateDigest"], "limit": 1},
        headers=auth,
    )
    assert page.status_code == 200, page.text
    data = page.json()
    assert data["historicalReadOnly"] is True and data["isCurrent"] is False
    assert data["authorityBoundary"]["currentSnapshotVerified"] is False
    assert data["authorityBoundary"]["viewAuthorizesExecution"] is False
    assert data["nodes"] and data["nextCursor"]
    next_page = client.get(
        f"{url}/{old.snapshot_id}/pages",
        params={"state": catalog["stateDigest"], "limit": 1, "cursor": data["nextCursor"]},
        headers=auth,
    )
    assert next_page.status_code == 200 and next_page.json()["pageOffset"] == 1
    assert (
        client.get(
            f"/v1/graphs/campaigns/{CAMPAIGN}/snapshots/{old.snapshot_id}/pages", headers=auth
        ).status_code
        == 409
    )
    assert path.read_bytes() == before


def test_unknown_campaign_role_path_injection_and_stale_page_are_refused(browser):
    client, _, authority, old, _latest = browser
    auth = _auth(OPERATOR_TOKEN)
    url = f"{BASE}/{CAMPAIGN}/snapshots"
    for token, status in ((None, 401), (WORKER_TOKEN, 403), (APPROVER_TOKEN, 403)):
        assert client.get(BASE, headers=_auth(token) if token else {}).status_code == status
    assert client.get(BASE + "/not-enrolled/snapshots", headers=auth).status_code == 404
    assert client.get(url + "?database=/private/state", headers=auth).status_code == 400
    assert client.get(url + "?limit=1&limit=2", headers=auth).status_code == 400
    catalog = client.get(url + "?limit=1", headers=auth).json()
    cursor = catalog["nextCursor"]
    assert (
        client.get(
            BASE + "/second-campaign/snapshots", params={"limit": 1, "cursor": cursor}, headers=auth
        ).status_code
        == 422
    )
    assert client.get(url, params={"limit": 2, "cursor": cursor}, headers=auth).status_code == 422
    authority.capture(GraphSnapshotReason.HANDOFF)
    assert client.get(url, params={"limit": 1, "cursor": cursor}, headers=auth).status_code == 409
    assert (
        client.get(
            f"{url}/{old.snapshot_id}/pages", params={"state": catalog["stateDigest"]}, headers=auth
        ).status_code
        == 409
    )


@pytest.mark.parametrize(
    "table,column",
    [
        ("graph_events", "event_json"),
        ("graph_nodes", "node_json"),
        ("graph_projections", "projection_json"),
        ("graph_snapshots", "snapshot_json"),
    ],
)
def test_unselected_history_corruption_blocks_catalog_and_pages(browser, table, column):
    client, path, _, _, latest = browser
    auth = _auth(OPERATOR_TOKEN)
    url = f"{BASE}/{CAMPAIGN}/snapshots"
    state = client.get(url, headers=auth).json()["stateDigest"]
    _tamper(
        path,
        table,
        f"UPDATE {table} SET {column}=? WHERE rowid=(SELECT min(rowid) FROM {table})",
        (b"{}",),
    )
    for target in (url, f"{url}/{latest.snapshot_id}/pages?state={state}"):
        result = client.get(target, headers=auth)
        assert result.status_code == 409 and str(path) not in result.text


@pytest.mark.parametrize(
    "value",
    ["[]", '{"BAD":"x"}', '{"test-campaign":"a","test-campaign":"b"}', '{"test-campaign":{}}'],
)
def test_registry_rejects_malformed_and_duplicate_deployment_mapping(value):
    with pytest.raises(ValueError):
        campaign_databases(value)


def test_registry_rejects_shared_database_and_misbound_campaign(browser):
    _client, path, _, _, _ = browser
    with pytest.raises(ValueError, match="distinct"):
        GraphCampaignBrowser({"first-campaign": path, "second-campaign": path})
    reader = GraphCampaignBrowser({"wrong-campaign": path})
    with pytest.raises(RuntimeError):
        reader.catalog("wrong-campaign", limit=25, cursor=None)
    assert campaign_databases(json.dumps({CAMPAIGN: str(path)})) == {CAMPAIGN: path}


def test_history_browser_discards_late_results_and_recovers_from_offline(browser, tmp_path):
    client, _, _, _, latest = browser
    node = shutil.which("node")
    assert node is not None, "Node.js is required for browser state verification"
    auth = _auth(OPERATOR_TOKEN)
    first = client.get(f"{BASE}/{CAMPAIGN}/snapshots", headers=auth).json()
    fixture = {
        "campaigns": client.get(BASE, headers=auth).json(),
        "first": first,
        "second": client.get(f"{BASE}/second-campaign/snapshots", headers=auth).json(),
        "page": client.get(
            f"{BASE}/{CAMPAIGN}/snapshots/{latest.snapshot_id}/pages",
            params={"state": first["stateDigest"]},
            headers=auth,
        ).json(),
    }
    source = tmp_path / "ui-fixture.json"
    source.write_text(json.dumps(fixture))
    root = Path(__file__).resolve().parents[1]
    result = subprocess.run(
        [
            node,
            str(root / "tests/js/graph_browser_state.mjs"),
            str(root / "src/pajin/control_plane/web/graph-browser.js"),
            str(source),
        ],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout
