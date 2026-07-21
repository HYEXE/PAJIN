"""Hermetic Docker CLI double for the Replay Worker process test.

The production ``DockerWorkerBackend`` still builds every command and parses every
result.  This executable replaces only the external Docker daemon boundary so the
daemon entrypoint can run as a real OS process in environments without Docker.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlsplit, urlunsplit

if TYPE_CHECKING:
    from pajin.runtime.worker import WorkerJob

_AI_CHAT_PROXY_RECEIPT_VERSION = "pajin.dev/egress-http-json-receipt/v1"


def _state_root() -> Path:
    raw = os.environ.get("PAJIN_FAKE_DOCKER_STATE")
    if not raw:
        raise RuntimeError("PAJIN_FAKE_DOCKER_STATE is required")
    root = Path(raw)
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    return root


def _canonical_json_digest(value: object) -> str:
    return sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
            allow_nan=False,
        ).encode("utf-8")
    ).hexdigest()


def _proxy_receipt_log(job: WorkerJob, output: dict[str, object]) -> str:
    payload = json.loads(job.stdin)
    probe = payload["probe"]
    if not isinstance(probe, dict):
        raise TypeError("Replay probe payload must be an object")
    turns = probe["turns"]
    observed_turns = output["turns"]
    if not isinstance(turns, list) or not isinstance(observed_turns, list):
        raise TypeError("Replay turns must be arrays")
    parsed_target = urlsplit(payload["target"])
    redacted_target = urlunsplit(
        (
            parsed_target.scheme,
            parsed_target.netloc,
            parsed_target.path,
            "<redacted>" if parsed_target.query else "",
            "",
        )
    )
    events = [json.dumps({"event": "ready", "port": 8080}, separators=(",", ":"))]
    for index, (turn, observed) in enumerate(zip(turns, observed_turns, strict=True)):
        if not isinstance(turn, dict) or not isinstance(observed, dict):
            raise TypeError("Replay turn entries must be objects")
        request_body = {
            "sessionId": probe["session_id"],
            "messages": turn["messages"],
            "metadata": {"scenarioId": probe["scenario_id"], "turn": index},
        }
        response = observed["response"]
        events.append(
            json.dumps(
                {
                    "event": "allow",
                    "receiptVersion": _AI_CHAT_PROXY_RECEIPT_VERSION,
                    "sequence": index + 1,
                    "method": "POST",
                    "target": redacted_target,
                    "targetSha256": sha256(payload["target"].encode("utf-8")).hexdigest(),
                    "address": "172.17.0.1",
                    "status": 200,
                    "requestJsonSha256": _canonical_json_digest(request_body),
                    "responseBodySha256": _canonical_json_digest(response),
                    "responseJsonSha256": _canonical_json_digest(response),
                },
                separators=(",", ":"),
            )
        )
    return "\n".join(events)


def _argument(args: list[str], name: str) -> str:
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError) as exc:
        raise RuntimeError(f"fake Docker invocation is missing {name}") from exc


def _run_proxy(args: list[str], state: Path) -> int:
    proxy_name = _argument(args, "--name")
    (state / "active-proxy").write_text(proxy_name, encoding="utf-8")
    print(f"fake-{proxy_name}")
    return 0


def _run_worker(args: list[str], state: Path) -> int:
    from kisa_control_plane_support import SupportingKISAWorker

    from pajin.runtime.worker import WorkerJob

    label = _argument(args, "--label")
    prefix = "pajin.execution-id="
    if not label.startswith(prefix):
        raise RuntimeError("fake Docker Worker label is invalid")
    raw = sys.stdin.read()
    job = WorkerJob(
        execution_id=label.removeprefix(prefix),
        image="pajin-worker:dev",
        command=["ai-chat-probe"],
        stdin=raw,
    )
    result = asyncio.run(SupportingKISAWorker().run(job))
    output = json.loads(result.stdout)
    proxy_name = (state / "active-proxy").read_text(encoding="utf-8")
    (state / f"{proxy_name}.log").write_text(
        _proxy_receipt_log(job, output),
        encoding="utf-8",
    )
    sys.stdout.write(result.stdout)
    return 0


def main() -> int:
    args = sys.argv[1:]
    if not args:
        print("fake Docker command is required", file=sys.stderr)
        return 64
    try:
        state = _state_root()
        if args[:2] == ["network", "create"]:
            print("fake-network")
            return 0
        if args[:2] in (["network", "connect"], ["network", "rm"]):
            return 0
        if args[0] == "inspect":
            print("healthy")
            return 0
        if args[0] == "logs":
            proxy_name = args[-1]
            sys.stdout.write((state / f"{proxy_name}.log").read_text(encoding="utf-8"))
            return 0
        if args[0] == "rm":
            return 0
        if args[0] == "run" and "--detach" in args:
            return _run_proxy(args, state)
        if args[0] == "run" and "--interactive" in args:
            return _run_worker(args, state)
        raise RuntimeError(f"unsupported fake Docker command: {args[0]}")
    except Exception as exc:
        print(f"fake Docker failure: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
