"""Opt-in owned-host transport conformance; no Docker isolation or model quality claim."""

from __future__ import annotations

import asyncio
import base64
import importlib.util
import ipaddress
import json
import os
import ssl
import sys
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from secrets import token_hex

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_supervisor_checkpoint_scheduler import _policy, _provider, _runtime
from test_supervisor_input_transport import large_runtime as large_runtime

from pajin.domain.models import ToolRequest
from pajin.providers import OpenAICompatibleChatTool, ProviderMessage, ProviderRegistration
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.worker import DockerWorkerBackend, EgressPolicy, NetworkMode, WorkerJob
from pajin.supervision import build_supervisor_invocation_request
from pajin.supervision.input_transport import reconstruct_supervisor_input

pytestmark = pytest.mark.skipif(
    os.environ.get("PAJIN_LIVE_SUPERVISOR_INPUT") != "1",
    reason=(
        "set PAJIN_LIVE_SUPERVISOR_INPUT=1 with PAJIN_SUPERVISOR_TEST_BIND_IP for owned transport"
    ),
)


def _test_tls_context(tmp_path: Path, address):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "owned-transport-test")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(address)]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    certificate_path = tmp_path / "transport-cert.pem"
    key_path = tmp_path / "transport-key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate_path, key_path)
    return context, certificate_path


@pytest.mark.parametrize("trust_certificate", [True, False])
def test_large_input_crosses_real_worker_process_and_https_proxy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    large_runtime,
    trust_certificate: bool,
) -> None:
    campaign, graph_store, collaboration, _ = large_runtime
    address = ipaddress.ip_address(os.environ["PAJIN_SUPERVISOR_TEST_BIND_IP"])
    assert address.version == 4 and address.is_private
    assert not (address.is_loopback or address.is_link_local or address.is_unspecified)
    credential = token_hex(32)
    tls_context, certificate_path = _test_tls_context(tmp_path, address)

    async def exercise():
        bodies = []
        receipts = []

        async def upstream(reader, writer):
            try:
                header = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
                lines = header.decode("ascii").split("\r\n")
                assert lines[0] == "POST /v1/chat/completions HTTP/1.1"
                headers = dict(line.split(": ", 1) for line in lines[1:] if line)
                authorization = next(
                    (value for key, value in headers.items() if key.lower() == "authorization"), ""
                )
                if authorization != f"Bearer {credential}":
                    return
                length = int(
                    next(value for key, value in headers.items() if key.lower() == "content-length")
                )
                assert 4_000_000 < length <= 16 * 1024 * 1024
                body = await asyncio.wait_for(reader.readexactly(length), timeout=10)
                bodies.append(body)
                payload = json.loads(body)
                messages = [ProviderMessage.model_validate(value) for value in payload["messages"]]
                assert reconstruct_supervisor_input(messages, binding.input_transport) == snapshot
                response = json.dumps(
                    {
                        "id": "owned-host-response",
                        "model": payload["model"],
                        "choices": [
                            {
                                "index": 0,
                                "message": {
                                    "role": "assistant",
                                    "content": sha256(body).hexdigest(),
                                },
                                "finish_reason": "stop",
                            }
                        ],
                        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                    }
                ).encode()
                response_header = (
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(response)}\r\nConnection: close\r\n\r\n"
                ).encode()
                writer.write(response_header + response)
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        async with await asyncio.start_server(upstream, str(address), 0, ssl=tls_context) as target:
            authority = f"https://{address}:{target.sockets[0].getsockname()[1]}"
            endpoint = authority + "/v1/chat/completions"
            registration = ProviderRegistration.model_validate(
                {
                    **_provider().model_dump(mode="json"),
                    "endpoint": endpoint,
                    "allow_private_networks": True,
                }
            )
            snapshot, model, provider, configuration = _runtime(
                campaign,
                graph_store,
                collaboration,
                provider=registration,
            )
            chat, binding = build_supervisor_invocation_request(
                snapshot,
                model,
                campaign,
                provider,
                configuration,
                _policy(tokens=50_000_000),
                model_revision="shadow-model-revision-2026-08-04",
            )
            tool = OpenAICompatibleChatTool(provider)
            request = ToolRequest(
                agent_id="transport-check",
                tool_id=tool.spec.tool_id,
                target=endpoint,
                method="POST",
                arguments=chat.model_dump(mode="json"),
            )
            prepared = tool.prepare(request)
            policy = EgressPolicy(
                allow=[endpoint, authority + "/**"],
                allowed_methods={"POST"},
                allow_private_networks=True,
                max_request_bytes=prepared.request_byte_limit_override,
            )
            job = WorkerJob.model_validate(
                {
                    **prepared.model_dump(mode="python"),
                    "network": NetworkMode.EGRESS_PROXY,
                    "egress_policy": policy,
                }
            )
            monkeypatch.setenv(
                "PAJIN_EGRESS_POLICY_B64",
                base64.b64encode(
                    json.dumps(
                        {
                            **policy.model_dump(mode="json"),
                            "max_exchange_seconds": job.limits.timeout_seconds,
                        }
                    ).encode(),
                ).decode(),
            )
            spec = importlib.util.spec_from_file_location(
                "owned_large_input_proxy",
                Path("containers/egress-proxy/proxy.py"),
            )
            assert spec is not None and spec.loader is not None
            proxy = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(proxy)
            proxy.log_event = lambda event, **fields: receipts.append({"event": event, **fields})
            async with await asyncio.start_server(proxy.handle_client, "127.0.0.1", 0) as forward:
                proxy_url = f"http://127.0.0.1:{forward.sockets[0].getsockname()[1]}"
                process = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "containers/worker/worker_entry.py",
                    *job.command,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env={
                        "PATH": os.defpath,
                        "HTTP_PROXY": proxy_url,
                        "HTTPS_PROXY": proxy_url,
                        "NO_PROXY": "",
                        "PYTHONDONTWRITEBYTECODE": "1",
                        **({"SSL_CERT_FILE": str(certificate_path)} if trust_certificate else {}),
                    },
                )
                try:
                    wire = DockerWorkerBackend._wire_stdin(
                        job,
                        [
                            SecretMaterial(
                                lease_id="lease_owned_host",
                                binding="provider-api-key",
                                value=credential,
                            )
                        ],
                    )
                    stdout, stderr = await asyncio.wait_for(process.communicate(wire), timeout=40)
                    if trust_certificate:
                        assert process.returncode == 0, {
                            "stderr": stderr.decode(),
                            "receivedBodies": len(bodies),
                            "proxyEvents": receipts,
                        }
                        result = json.loads(stdout)
                        assert len(bodies) == 1
                        assert result["content"] == sha256(bodies[0]).hexdigest()
                    else:
                        assert process.returncode == 65
                        assert not bodies
                        assert not stdout
                finally:
                    if process.returncode is None:
                        process.kill()
                        await process.wait()
            allowed = [receipt for receipt in receipts if receipt["event"] == "allow"]
            assert len(allowed) == 1
            assert allowed[0]["method"] == "CONNECT"
            assert allowed[0]["applicationVisibility"] == "opaque"
            assert proxy.REQUEST_COUNT == 1

    asyncio.run(exercise())
