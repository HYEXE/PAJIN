"""Uvicorn adapter that exposes direct TLS peer evidence through ASGI."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from uvicorn.protocols.http.h11_impl import H11Protocol

_TLS_VERSION_CODES = {
    "SSLv3": 0x0300,
    "TLSv1": 0x0301,
    "TLSv1.1": 0x0302,
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}


def _asgi_tls_extension(transport: asyncio.Transport) -> dict[str, object] | None:
    ssl_object = transport.get_extra_info("ssl_object")
    if not isinstance(ssl_object, ssl.SSLObject):
        return None
    peer_certificate_der = ssl_object.getpeercert(binary_form=True)
    client_cert_chain: tuple[str, ...] = ()
    client_cert_name: str | None = None
    if peer_certificate_der:
        certificate = x509.load_der_x509_certificate(peer_certificate_der)
        client_cert_chain = (certificate.public_bytes(serialization.Encoding.PEM).decode("ascii"),)
        client_cert_name = certificate.subject.rfc4514_string()
    tls_version = ssl_object.version()
    return {
        "server_cert": None,
        "client_cert_chain": client_cert_chain,
        "client_cert_name": client_cert_name,
        "client_cert_error": None,
        "tls_version": _TLS_VERSION_CODES.get(tls_version) if tls_version is not None else None,
        "cipher_suite": None,
    }


class WorkerMTLSH11Protocol(H11Protocol):
    """Add the standard ASGI TLS extension before the request task can run."""

    _pajin_tls_extension: dict[str, object] | None = None

    def connection_made(  # type: ignore[override]
        self, transport: asyncio.Transport
    ) -> None:
        super().connection_made(transport)
        self._pajin_tls_extension = _asgi_tls_extension(transport)

    def handle_events(self) -> None:
        previous_scope = self.scope
        super().handle_events()
        if self.scope is previous_scope or self.scope is None or self._pajin_tls_extension is None:
            return
        extensions = self.scope.setdefault("extensions", {})
        typed_extensions: dict[str, Any] = extensions
        typed_extensions["tls"] = self._pajin_tls_extension.copy()
