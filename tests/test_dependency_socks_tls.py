"""Verify actual TLS, CA validation and socket cleanup through a disposable SOCKS peer."""

import asyncio
import os
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpcore2
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _tls_contexts(tmp_path: Path, trusted: bool) -> tuple[ssl.SSLContext, ssl.SSLContext]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.invalid")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder().subject_name(name).issuer_name(name)
        .public_key(key.public_key()).serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(minutes=10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.invalid")]), True)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "cert.pem", tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    with os.fdopen(os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as f:
        f.write(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server.load_cert_chain(cert_path, key_path)
    client = ssl.create_default_context(cafile=str(cert_path) if trusted else None)
    assert client.verify_mode == ssl.CERT_REQUIRED and client.check_hostname
    return server, client


def _receive(stream: socket.socket, length: int) -> bytes:
    data = b""
    while len(data) < length:
        chunk = stream.recv(length - len(data))
        if not chunk:
            raise AssertionError("SOCKS client disconnected early")
        data += chunk
    return data


def _serve_socks(listener: socket.socket, context: ssl.SSLContext, trusted: bool) -> bool:
    peer, _ = listener.accept()
    with peer:
        peer.settimeout(5)
        assert _receive(peer, 3) == b"\x05\x01\x00"
        peer.sendall(b"\x05\x00")
        assert _receive(peer, 4) == b"\x05\x01\x00\x03"
        length = _receive(peer, 1)[0]
        assert _receive(peer, length) == b"fixture.invalid"
        assert _receive(peer, 2) == b"\x01\xbb"
        peer.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x01\xbb")
        # Inspect the real wire before the server performs its TLS handshake.
        assert peer.recv(1, socket.MSG_PEEK) == b"\x16"
        if not trusted:
            with pytest.raises(ssl.SSLError):
                context.wrap_socket(peer, server_side=True)
            return False
        with context.wrap_socket(peer, server_side=True) as tls:
            request = b""
            while b"\r\n\r\n" not in request:
                chunk = tls.recv(4096)
                assert chunk
                request += chunk
                assert len(request) <= 8192
            assert request.startswith(b"GET /probe HTTP/1.1\r\n")
            tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            return True


@pytest.mark.parametrize("asynchronous", [False, True])
@pytest.mark.parametrize("trusted", [False, True])
def test_secure_websocket_socks_route_requires_real_verified_tls(
    tmp_path: Path, asynchronous: bool, trusted: bool,
) -> None:
    server_context, client_context = _tls_contexts(tmp_path, trusted)
    with socket.socket() as listener:
        listener.settimeout(5)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        proxy_url = f"socks5://127.0.0.1:{listener.getsockname()[1]}"

        async def send_async() -> httpcore2.Response:
            async with httpcore2.AsyncSOCKSProxy(proxy_url, ssl_context=client_context) as proxy:
                return await proxy.request("GET", "wss://fixture.invalid/probe")

        def send() -> httpcore2.Response:
            if asynchronous:
                return asyncio.run(send_async())
            with httpcore2.SOCKSProxy(proxy_url, ssl_context=client_context) as proxy:
                return proxy.request("GET", "wss://fixture.invalid/probe")

        with ThreadPoolExecutor(max_workers=1) as executor:
            result = executor.submit(_serve_socks, listener, server_context, trusted)
            try:
                if trusted:
                    response = send()
                    assert response.status == 200 and response.content == b"ok"
                else:
                    with pytest.raises(httpcore2.ConnectError, match="CERTIFICATE_VERIFY_FAILED"):
                        send()
            finally:
                assert result.result(timeout=10) is trusted
