from __future__ import annotations

import json
import shutil
import sqlite3
import subprocess
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier, Lock
from time import sleep
from types import SimpleNamespace
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import create_app
from pajin.runtime.store import RunStore
from pajin.workflow.web_measured_product_flow import WebMeasuredProductFlowProjection
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReadRegistry,
)
from tests.test_control_plane_web import (
    APPROVER_TOKEN,
    AUDITOR_TOKEN,
    OPERATOR_TOKEN,
    WORKER_TOKEN,
    _auth,
    _settings,
)
from tests.test_web_measured_product_flow import _project
from tests.test_web_measured_product_reader import (
    _CountingProductReadResolver,
    _read_registration,
    _run_tree_state,
)

pytest_plugins = ("tests.test_web_validation_evaluation",)

_PRODUCT_PATH = "/v1/products/web-measured-flow"


def _database_state(path: Path) -> tuple[str, ...]:
    with sqlite3.connect(f"file:{path.as_posix()}?mode=ro", uri=True) as connection:
        return tuple(connection.iterdump())


def _assert_non_cacheable(response: Any) -> None:
    assert "no-store" in response.headers["cache-control"]
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["referrer-policy"] == "no-referrer"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "set-cookie" not in response.headers
    assert "access-control-allow-origin" not in response.headers
    assert "etag" not in response.headers


def _assert_browser_protocol_accepts(response: Any, tmp_path: Path) -> None:
    node = shutil.which("node")
    if node is None:
        return
    payload_path = tmp_path / "measured-product-response.json"
    payload_path.write_bytes(response.content)
    root = Path(__file__).resolve().parents[1]
    protocol_url = (root / "src" / "pajin" / "control_plane" / "web" / "protocol.js").as_uri()
    script = (
        'import fs from "node:fs"; '
        "const protocol = await import(process.argv[1]); "
        'const payload = fs.readFileSync(process.argv[2], "utf8"); '
        "protocol.validateWebMeasuredProductProjection("
        "protocol.parseJsonPayload(payload, 2000000));"
    )
    result = subprocess.run(
        [node, "--input-type=module", "--eval", script, protocol_url, str(payload_path)],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, result.stderr or result.stdout


def test_ux_009c_unconfigured_read_fails_closed_after_authorization(tmp_path: Path) -> None:
    app = create_app(_settings(tmp_path / "unconfigured-product.db"))
    with TestClient(app) as client:
        missing = client.get(_PRODUCT_PATH)
        auditor = client.get(_PRODUCT_PATH, headers=_auth(AUDITOR_TOKEN))
        operator = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))

    assert missing.status_code == 401
    assert missing.headers["www-authenticate"] == "Bearer"
    assert auditor.status_code == 403
    assert operator.status_code == 503
    assert operator.json() == {"detail": "Measured Web product read is not configured"}
    for response in (missing, auditor, operator):
        _assert_non_cacheable(response)


def test_ux_009c_rejects_any_reader_other_than_the_exact_ux_009b_type(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match="exact UX-009B reader"):
        create_app(
            _settings(tmp_path / "foreign-product-reader.db"),
            web_measured_product_reader=cast(Any, object()),
        )


def test_ux_009c_operator_only_body_free_exact_projection_read(
    web002d_context: SimpleNamespace,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outcome, source, authority, context, _, _, _ = _project(
        web002d_context,
        tmp_path,
        monkeypatch,
    )
    registration = _read_registration(outcome=outcome, context=context)
    registry = WebMeasuredProductReadRegistry((registration,))
    resolver = _CountingProductReadResolver(registry)
    reader = WebMeasuredProductReader(
        deployment_id=registration.deployment_id,
        resolver=resolver,
    )
    database_path = tmp_path / "measured-product.db"
    app = create_app(
        _settings(database_path),
        web_measured_product_reader=reader,
    )

    def reject_run_creation(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("UX-009C product consumption must not create a Run")

    monkeypatch.setattr(RunStore, "create", reject_run_creation)
    with TestClient(app) as client:
        before_database = _database_state(database_path)
        before_runs = _run_tree_state(outcome.run_path, source.run_path)

        denied = (
            client.get(_PRODUCT_PATH),
            client.get(_PRODUCT_PATH, headers=_auth(APPROVER_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(AUDITOR_TOKEN)),
            client.get(_PRODUCT_PATH, headers=_auth(WORKER_TOKEN)),
        )
        assert [response.status_code for response in denied] == [401, 403, 403, 403]
        assert resolver.calls == []

        query = client.get(f"{_PRODUCT_PATH}?runId=caller-selected", headers=_auth(OPERATOR_TOKEN))
        body = client.request(
            "GET",
            _PRODUCT_PATH,
            headers=_auth(OPERATOR_TOKEN),
            content=b"{}",
        )
        post = client.post(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN), json={})
        head = client.head(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert [query.status_code, body.status_code, post.status_code, head.status_code] == [
            400,
            400,
            405,
            405,
        ]
        assert query.json() == {
            "detail": "Measured Web product read accepts no query or request body"
        }
        assert body.json() == query.json()
        assert resolver.calls == []

        first = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        second = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
        expected = outcome.projection.model_dump(mode="json", by_alias=True)
        assert first.json() == expected
        assert second.json() == expected
        _assert_browser_protocol_accepts(first, tmp_path)
        assert resolver.calls == [registration.deployment_id, registration.deployment_id]

        state_lock = Lock()
        start = Barrier(4)
        active_reads = 0
        maximum_active_reads = 0
        serialized_read_count = 0

        def guarded_read(
            _reader: WebMeasuredProductReader,
        ) -> WebMeasuredProductFlowProjection:
            nonlocal active_reads, maximum_active_reads, serialized_read_count
            with state_lock:
                active_reads += 1
                serialized_read_count += 1
                maximum_active_reads = max(maximum_active_reads, active_reads)
            try:
                sleep(0.05)
                return outcome.projection
            finally:
                with state_lock:
                    active_reads -= 1

        def concurrent_read(_ordinal: int) -> Any:
            start.wait(timeout=5)
            return client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))

        with monkeypatch.context() as concurrency_patch:
            concurrency_patch.setattr(WebMeasuredProductReader, "read", guarded_read)
            with ThreadPoolExecutor(max_workers=4) as pool:
                concurrent = list(pool.map(concurrent_read, range(4)))

        assert [response.status_code for response in concurrent] == [200, 200, 200, 200]
        assert serialized_read_count == 4
        assert maximum_active_reads == 1
        assert _database_state(database_path) == before_database
        assert _run_tree_state(outcome.run_path, source.run_path) == before_runs

        public_wire = json.dumps(first.json(), ensure_ascii=False, sort_keys=True)
        for forbidden in (
            str(outcome.run_path),
            str(source.run_path),
            authority.private_marker,
            authority.route_marker,
            authority.worker_marker,
            authority.graph_marker,
            '"provider":',
            '"adapter":',
            "trustAnchor",
            "claimLedger",
            "targetJournal",
            "privateBinding",
        ):
            assert forbidden not in public_wire

        for response in (*denied, query, body, post, head, first, second):
            _assert_non_cacheable(response)

        outcome.run_path.joinpath(outcome.artifact_path).write_text(
            "{}",
            encoding="utf-8",
        )
        tampered = client.get(_PRODUCT_PATH, headers=_auth(OPERATOR_TOKEN))

    assert tampered.status_code == 409
    assert tampered.json() == {"detail": "Measured Web product authority is not integrity-valid"}
    _assert_non_cacheable(tampered)
    assert resolver.calls == [
        registration.deployment_id,
        registration.deployment_id,
        registration.deployment_id,
    ]
    assert str(outcome.run_path) not in tampered.text
    assert authority.private_marker not in tampered.text
