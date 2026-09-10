"""One fixed mTLS GET through the required host-owned egress proxy."""

from __future__ import annotations

import http.client
import json
import os
import re
import ssl
import sys
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from urllib.parse import urlsplit


def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("duplicate input field")
        result[name] = value
    return result


def execute() -> dict[str, object]:
    if sys.argv[1:] != ["system-os-release"] or os.getuid() != 65532:
        raise ValueError("invalid fixed Worker action")
    wire = sys.stdin.buffer.read(64001)
    if len(wire) > 64000:
        raise ValueError("input exceeds limit")
    envelope = json.loads(wire, object_pairs_hook=unique)
    if (
        set(envelope) != {"pajinEnvelopeVersion", "payload", "secrets"}
        or envelope["pajinEnvelopeVersion"] != 1
        or set(envelope["secrets"]) != {"system-mtls"}
    ):
        raise ValueError("exact credential lease envelope required")
    credentials = json.loads(envelope["secrets"]["system-mtls"], object_pairs_hook=unique)
    if set(credentials) != {"ca", "certificate", "key"}:
        raise ValueError("invalid credential fields")
    payload = envelope["payload"]
    if set(payload) != {"deployment", "requestId"}:
        raise ValueError("invalid payload fields")
    deployment = payload["deployment"]
    value = deployment["value"]
    target = urlsplit(value["target"])
    if (
        target.scheme != "https"
        or not target.hostname
        or target.port is None
        or target.username
        or target.password
        or target.query
        or target.fragment
        or target.path != "/v1/os-release"
        or value["operation"] != "linux-os-release-v1"
        or re.fullmatch(r"tool_[a-f0-9]{32}", payload["requestId"]) is None
    ):
        raise ValueError("invalid System read endpoint or request")
    if sha256(Path(__file__).read_bytes()).hexdigest() != deployment["client_sha256"]:
        raise ValueError("client implementation differs")
    if sha256(credentials["ca"].encode()).hexdigest() != deployment["ca_sha256"]:
        raise ValueError("CA differs")
    client_pin = sha256(ssl.PEM_cert_to_DER_cert(credentials["certificate"])).hexdigest()
    if client_pin != deployment["client_cert_sha256"]:
        raise ValueError("client identity differs")
    proxy = urlsplit(os.environ["HTTPS_PROXY"])
    if (
        proxy.scheme != "http"
        or proxy.hostname != "egress-proxy"
        or proxy.port != 8080
        or proxy.username
        or proxy.password
        or proxy.path
        or proxy.query
        or proxy.fragment
    ):
        raise ValueError("host-owned egress proxy required")
    return read_agent(credentials, deployment, payload["requestId"])


def read_agent(
    credentials: dict[str, str], deployment: dict[str, object], request_id: str
) -> dict[str, object]:
    value = deployment["value"]
    if not isinstance(value, dict):
        raise ValueError("invalid deployment input")
    target = urlsplit(value["target"])
    if target.hostname is None or target.port is None:
        raise ValueError("invalid target authority")
    client_pin = sha256(ssl.PEM_cert_to_DER_cert(credentials["certificate"])).hexdigest()
    with TemporaryDirectory(prefix="sys-002-", dir="/tmp") as directory:
        cert, key = Path(directory) / "client.pem", Path(directory) / "key.pem"
        for path, text in ((cert, credentials["certificate"]), (key, credentials["key"])):
            with path.open("x") as handle:
                path.chmod(0o600)
                handle.write(text)
        context = ssl.create_default_context(cadata=credentials["ca"])
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(cert, key)
        connection = http.client.HTTPSConnection("egress-proxy", 8080, timeout=10, context=context)
        try:
            connection.set_tunnel(target.hostname, target.port)
            connection.connect()
            if connection.sock is None:
                raise ValueError("TLS socket absent")
            peer = connection.sock.getpeercert(binary_form=True)
            if peer is None or sha256(peer).hexdigest() != deployment["server_cert_sha256"]:
                raise ValueError("server identity differs")
            connection.request(
                "GET",
                "/v1/os-release",
                headers={"X-PAJIN-Request-ID": request_id, "Connection": "close"},
            )
            response = connection.getresponse()
            content = response.read(16385)
            if response.status != 200 or len(content) > 16384:
                raise ValueError("agent read failed")
            result = json.loads(content, object_pairs_hook=unique)
            if (
                result["requestId"] != request_id
                or result["instance"] != value["instance"]
                or result["agentSha256"] != deployment["agent_sha256"]
            ):
                raise ValueError("agent receipt identity differs")
            return {
                "schema": "pajin.sys-002.worker-read/v1",
                "agent": result,
                "serverCertSha256": deployment["server_cert_sha256"],
                "clientCertSha256": client_pin,
                "clientSha256": deployment["client_sha256"],
                "uid": os.getuid(),
            }
        finally:
            connection.close()


def main() -> int:
    try:
        result = execute()
    except (KeyError, TypeError, ValueError, OSError, http.client.HTTPException):
        print("System read failed closed", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
