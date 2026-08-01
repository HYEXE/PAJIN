"""Fixed standard-library Worker for the synthetic Boolean-SQLi Benchmark profile."""

from __future__ import annotations

import base64
import json
import sys
from hashlib import sha256
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, Request, build_opener

_ACTION = "bug-bounty-sqli-probe"
_SCENARIO = "bug-bounty.api.boolean-sqli-lab"
_TARGET = "http://target:8080/v1/users/lookup"
_MAX_INPUT_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 128 * 1024


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        del req, fp, code, msg, headers, newurl
        return None


_OPENER = build_opener(_NoRedirectHandler())


def _read_input() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if not 1 <= len(raw) <= _MAX_INPUT_BYTES:
        raise ValueError("benchmark worker input is missing or too large")
    value = json.loads(raw)
    if not isinstance(value, dict) or set(value) != {"scenarioId", "target"}:
        raise ValueError("benchmark worker input shape differs")
    if value != {"scenarioId": _SCENARIO, "target": _TARGET}:
        raise ValueError("benchmark worker input identity differs")
    return value


def _observation(identifier: str, name: str) -> dict[str, object]:
    url = f"{_TARGET}?{urlencode({'id': identifier})}"
    request = Request(
        url,
        method="GET",
        headers={"Accept": "application/json", "User-Agent": "PAJIN-Benchmark-Worker/1.0"},
    )
    try:
        with _OPENER.open(request, timeout=10) as response:
            status = response.status
            body = response.read(_MAX_RESPONSE_BYTES + 1)
    except HTTPError as exc:
        status = exc.code
        body = exc.read(_MAX_RESPONSE_BYTES + 1)
    if len(body) > _MAX_RESPONSE_BYTES or 300 <= status < 400:
        raise ValueError("benchmark target response is invalid")
    value = json.loads(body)
    if not isinstance(value, dict):
        raise ValueError("benchmark target response is not an object")
    record_count = value.get("recordCount")
    if (
        not isinstance(record_count, int)
        or isinstance(record_count, bool)
        or not 0 <= record_count <= 100
        or value.get("synthetic") is not True
    ):
        raise ValueError("benchmark target response contract differs")
    return {
        "name": name,
        "status": status,
        "recordCount": record_count,
        "synthetic": True,
        "bodySha256": sha256(body).hexdigest(),
        "responseBodyBase64": base64.b64encode(body).decode("ascii"),
    }


def main() -> int:
    if sys.argv[1:] != [_ACTION]:
        print("unsupported benchmark worker action", file=sys.stderr)
        return 64
    try:
        payload = _read_input()
        observations = [
            _observation("1", "baseline"),
            _observation("1' AND '1'='2", "negative-control"),
            _observation("1' OR '1'='1", "boolean-probe"),
        ]
        by_name = {str(item["name"]): item for item in observations}
        checks = {
            "baselineSingleRecord": (
                by_name["baseline"]["status"] == 200 and by_name["baseline"]["recordCount"] == 1
            ),
            "negativeControlEmpty": (
                by_name["negative-control"]["status"] == 200
                and by_name["negative-control"]["recordCount"] == 0
            ),
            "booleanProbeExpanded": (
                by_name["boolean-probe"]["status"] == 200
                and int(by_name["boolean-probe"]["recordCount"]) > 1
            ),
            "syntheticLabOnly": all(item["synthetic"] is True for item in observations),
        }
        result = {
            "target": payload["target"],
            "scenarioId": payload["scenarioId"],
            "vulnerable": all(checks.values()),
            "checks": checks,
            "observations": observations,
            "networkPerformed": True,
        }
        json.dump(result, sys.stdout, separators=(",", ":"), sort_keys=True)
        sys.stdout.write("\n")
        return 0
    except (HTTPError, URLError, OSError, TypeError, ValueError, json.JSONDecodeError):
        print("benchmark worker failed", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
