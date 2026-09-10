"""Fixed APP-002 byte transport, with no command, file path or network input."""

from __future__ import annotations

import base64
import binascii
import importlib.util
import json
import os
import sys
from hashlib import sha256
from pathlib import Path


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate input key")
        value[key] = item
    return value


def observe_runtime() -> dict[str, object]:
    status = dict(
        line.split(":", 1)
        for line in Path("/proc/self/status").read_text().splitlines()
        if ":" in line
    )
    # Kernel-created links can exist but remain administratively down in network=none.
    # IFF_UP is bit 0. Non-root/cap-drop-all cannot activate those links.
    interfaces = [path for path in Path("/sys/class/net").iterdir() if path.is_dir()]
    active = sorted(
        path.name for path in interfaces if int((path / "flags").read_text().strip(), 16) & 1
    )
    ipv4 = Path("/proc/net/route").read_text().splitlines()[1:]
    ipv6 = Path("/proc/net/ipv6_route").read_text().splitlines()
    non_loopback_routes = sum(line.split()[0] != "lo" for line in ipv4 if line.strip())
    non_loopback_routes += sum(line.split()[-1] != "lo" for line in ipv6 if line.strip())
    mounts = {
        parts[1]: set(parts[3].split(","))
        for line in Path("/proc/mounts").read_text().splitlines()
        if len(parts := line.split()) >= 4
    }
    observation = {
        "effectiveCapabilities": int(status["CapEff"].strip(), 16),
        "noNewPrivileges": int(status["NoNewPrivs"].strip()),
        "activeInterfaces": active,
        "inactiveInterfaceCount": len(interfaces) - len(active),
        "nonLoopbackRoutes": non_loopback_routes,
        "rootReadOnly": bool(os.statvfs("/").f_flag & os.ST_RDONLY),
        "workspaceNoExec": "noexec" in mounts.get("/workspace", set()),
        "tmpNoExec": "noexec" in mounts.get("/tmp", set()),
    }
    if (
        observation["effectiveCapabilities"] != 0
        or observation["noNewPrivileges"] != 1
        or active != ["lo"]
        or non_loopback_routes != 0
        or not observation["rootReadOnly"]
        or not observation["workspaceNoExec"]
        or not observation["tmpNoExec"]
    ):
        raise ValueError("Worker confinement observation differs")
    return observation


def main() -> int:
    try:
        if sys.argv[1:] != ["elf-header-read"] or os.getuid() != 65532:
            raise ValueError("Worker action or identity is invalid")
        wire = sys.stdin.buffer.read(360_001)
        if len(wire) > 360_000:
            raise ValueError("Worker input exceeds its byte limit")
        request = json.loads(wire, object_pairs_hook=unique_object)
        if (
            type(request) is not dict
            or set(request) != {"pajinEnvelopeVersion", "payload", "secrets"}
            or type(request["pajinEnvelopeVersion"]) is not int
            or request["pajinEnvelopeVersion"] != 1
            or request["secrets"] != {}
        ):
            raise ValueError("Worker transport is invalid")
        payload = request["payload"]
        if type(payload) is not dict or set(payload) != {"sha256", "bytes", "content"}:
            raise ValueError("Worker payload is invalid")
        if type(payload["bytes"]) is not int or not 64 <= payload["bytes"] <= 262_144:
            raise ValueError("Worker artifact size is invalid")
        if type(payload["content"]) is not str or len(payload["content"]) > 349_528:
            raise ValueError("Worker content is invalid")
        content = base64.b64decode(payload["content"], validate=True)
        if len(content) != payload["bytes"] or sha256(content).hexdigest() != payload["sha256"]:
            raise ValueError("Worker artifact digest or size differs")
        spec = importlib.util.spec_from_file_location("elf_parser", "/app/parser.py")
        if spec is None or spec.loader is None:
            raise RuntimeError("fixed parser is unavailable")
        parser = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(parser)
        header = parser.parse_header(content)
        result = {
            "header": header,
            "parserSha256": sha256(Path("/app/parser.py").read_bytes()).hexdigest(),
            "uid": os.getuid(),
            "runtime": observe_runtime(),
        }
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
        return 0
    except (ValueError, KeyError, TypeError, UnicodeError, binascii.Error):
        # No attacker-controlled input or artifact bytes are reflected in stderr.
        print("APP-002 rejected unsupported or inconsistent artifact input", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
