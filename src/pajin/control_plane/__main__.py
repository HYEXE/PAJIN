"""Run the PAJIN Control Plane API server."""

from __future__ import annotations

import os
import ssl
from dataclasses import dataclass

import uvicorn

from pajin.control_plane.tls_protocol import WorkerMTLSH11Protocol

_DEFAULT_LIMIT_CONCURRENCY = 256


def _limit_concurrency_from_env() -> int:
    raw = os.environ.get("PAJIN_CP_LIMIT_CONCURRENCY", str(_DEFAULT_LIMIT_CONCURRENCY))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError("PAJIN_CP_LIMIT_CONCURRENCY must be an integer") from exc
    if not 1 <= value <= 100_000:
        raise ValueError("PAJIN_CP_LIMIT_CONCURRENCY must be between 1 and 100000")
    return value


@dataclass(frozen=True)
class _ServerTLSSettings:
    certificate_file: str | None
    private_key_file: str | None
    private_key_password: str | None
    worker_ca_file: str | None
    certificate_requirements: ssl.VerifyMode


def _server_tls_settings_from_env() -> _ServerTLSSettings:
    certificate_file = os.environ.get("PAJIN_CP_TLS_CERT_FILE")
    private_key_file = os.environ.get("PAJIN_CP_TLS_KEY_FILE")
    private_key_password = os.environ.get("PAJIN_CP_TLS_KEY_PASSWORD")
    worker_ca_file = os.environ.get("PAJIN_CP_WORKER_MTLS_CA_FILE")
    worker_policy = os.environ.get("PAJIN_CP_WORKER_MTLS_TRUST_POLICY")
    file_settings = {
        "PAJIN_CP_TLS_CERT_FILE": certificate_file,
        "PAJIN_CP_TLS_KEY_FILE": private_key_file,
        "PAJIN_CP_WORKER_MTLS_CA_FILE": worker_ca_file,
    }
    blank = [name for name, value in file_settings.items() if value is not None and not value]
    if blank:
        raise ValueError(f"Control Plane TLS file settings must not be blank: {', '.join(blank)}")
    if (certificate_file is None) != (private_key_file is None):
        raise ValueError(
            "PAJIN_CP_TLS_CERT_FILE and PAJIN_CP_TLS_KEY_FILE must be configured together"
        )
    if private_key_password is not None and private_key_file is None:
        raise ValueError("PAJIN_CP_TLS_KEY_PASSWORD requires PAJIN_CP_TLS_KEY_FILE")
    if (worker_ca_file is None) != (worker_policy is None):
        raise ValueError(
            "PAJIN_CP_WORKER_MTLS_CA_FILE and PAJIN_CP_WORKER_MTLS_TRUST_POLICY "
            "must be configured together"
        )
    if worker_policy is not None and (certificate_file is None or private_key_file is None):
        raise ValueError(
            "PAJIN_CP_WORKER_MTLS_TRUST_POLICY requires direct TLS certificate, key, and Worker CA"
        )
    return _ServerTLSSettings(
        certificate_file=certificate_file,
        private_key_file=private_key_file,
        private_key_password=private_key_password,
        worker_ca_file=worker_ca_file,
        certificate_requirements=(
            ssl.CERT_OPTIONAL if worker_ca_file is not None else ssl.CERT_NONE
        ),
    )


def main() -> None:
    tls = _server_tls_settings_from_env()
    uvicorn.run(
        "pajin.control_plane.api:create_app",
        factory=True,
        host=os.environ.get("PAJIN_CP_HOST", "127.0.0.1"),
        port=int(os.environ.get("PAJIN_CP_PORT", "8090")),
        limit_concurrency=_limit_concurrency_from_env(),
        http=WorkerMTLSH11Protocol,
        proxy_headers=False,
        server_header=False,
        ssl_certfile=tls.certificate_file,
        ssl_keyfile=tls.private_key_file,
        ssl_keyfile_password=tls.private_key_password,
        ssl_ca_certs=tls.worker_ca_file,
        ssl_cert_reqs=tls.certificate_requirements,
    )


if __name__ == "__main__":
    main()
