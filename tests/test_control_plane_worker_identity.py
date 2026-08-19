from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
import threading
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
import uvicorn
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pajin.control_plane.api import ControlPlaneSettings, create_app
from pajin.control_plane.client import (
    ControlPlaneAuthenticationError,
    ControlPlaneClient,
)
from pajin.control_plane.models import ClaimJobRequest, Principal, PrincipalRole
from pajin.control_plane.tls_protocol import WorkerMTLSH11Protocol
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSAdmission,
    WorkerMTLSAuthenticator,
    WorkerMTLSTrustPolicy,
    certificate_spki_sha256,
)

_OPERATOR_TOKEN = "worker-mtls-operator-token-that-is-long-enough"
_APPROVER_TOKEN = "worker-mtls-approver-token-that-is-long-enough"
_WORKER_TOKEN = "worker-mtls-worker-token-that-is-long-enough"
_WORKER_SUBJECT = "worker-mtls-service"


def _issue_ca(tmp_path: Path) -> tuple[rsa.RSAPrivateKey, x509.Certificate, Path]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAJIN test CA")])
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    path = tmp_path / "ca.pem"
    path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return key, certificate, path


def _issue_leaf(
    tmp_path: Path,
    *,
    ca_key: rsa.RSAPrivateKey,
    ca_certificate: x509.Certificate,
    name: str,
    server: bool,
) -> tuple[x509.Certificate, Path, Path]:
    key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_certificate.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=1))
        .not_valid_after(now + timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=True,
        )
    )
    if server:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("localhost"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
    certificate = builder.sign(ca_key, hashes.SHA256())
    certificate_path = tmp_path / f"{name}.cert.pem"
    key_path = tmp_path / f"{name}.key.pem"
    certificate_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return certificate, certificate_path, key_path


def _policy(certificate: x509.Certificate) -> WorkerMTLSTrustPolicy:
    return WorkerMTLSTrustPolicy(
        policy_id="worker-mtls-policy_0123456789abcdef0123456789abcdef",
        bindings=(
            WorkerCertificateBinding(
                principal_subject=_WORKER_SUBJECT,
                certificate_spki_sha256=certificate_spki_sha256(certificate),
            ),
        ),
    )


def _settings(tmp_path: Path, policy: WorkerMTLSTrustPolicy) -> ControlPlaneSettings:
    return ControlPlaneSettings(
        database_url=f"sqlite:///{(tmp_path / 'control-plane.db').as_posix()}",
        credentials={
            _OPERATOR_TOKEN: Principal(
                subject="worker-mtls-operator",
                roles=frozenset({PrincipalRole.OPERATOR, PrincipalRole.AUDITOR}),
            ),
            _APPROVER_TOKEN: Principal(
                subject="worker-mtls-approver",
                roles=frozenset({PrincipalRole.APPROVER, PrincipalRole.AUDITOR}),
            ),
            _WORKER_TOKEN: Principal(
                subject=_WORKER_SUBJECT,
                roles=frozenset({PrincipalRole.WORKER}),
            ),
        },
        checkpoint_keys={"v1": b"worker-mtls-checkpoint-key-that-is-long-enough"},
        worker_mtls_trust_policy=policy,
    )


def _ca_context(ca_path: Path) -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca_path.read_text(encoding="ascii"))
    return context


def _start_tls_server(
    tmp_path: Path,
    *,
    settings: ControlPlaneSettings,
    server_certificate: Path,
    server_key: Path,
    client_ca: Path,
) -> tuple[uvicorn.Server, threading.Thread, str, list[BaseException]]:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    port = listener.getsockname()[1]
    server = uvicorn.Server(
        uvicorn.Config(
            create_app(settings),
            host="127.0.0.1",
            port=port,
            http=WorkerMTLSH11Protocol,
            access_log=False,
            log_level="critical",
            ssl_certfile=str(server_certificate),
            ssl_keyfile=str(server_key),
            ssl_ca_certs=str(client_ca),
            ssl_cert_reqs=ssl.CERT_OPTIONAL,
        )
    )
    errors: list[BaseException] = []

    def serve() -> None:
        try:
            asyncio.run(server.serve(sockets=[listener]))
        except BaseException as exc:  # pragma: no cover - surfaced below
            errors.append(exc)

    thread = threading.Thread(target=serve, name="worker-mtls-control-plane", daemon=True)
    thread.start()
    base_url = f"https://127.0.0.1:{port}"
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        if errors or not thread.is_alive():
            break
        try:
            response = httpx.get(
                f"{base_url}/healthz",
                verify=_ca_context(client_ca),
                timeout=0.5,
                trust_env=False,
            )
            if response.status_code == 200:
                return server, thread, base_url, errors
        except httpx.HTTPError:
            pass
        time.sleep(0.02)
    server.should_exit = True
    thread.join(timeout=5)
    raise AssertionError(f"mTLS Control Plane did not start: {errors!r} at {tmp_path}")


async def _claim(
    *,
    base_url: str,
    ca: Path,
    certificate: Path,
    private_key: Path,
) -> object:
    async with ControlPlaneClient(
        base_url=base_url,
        bearer_token=_WORKER_TOKEN,
        tls_ca_file=str(ca),
        tls_client_cert_file=str(certificate),
        tls_client_key_file=str(private_key),
    ) as client:
        return await client.claim(ClaimJobRequest(worker_id="mtls-worker"))


def test_worker_mtls_policy_must_cover_every_and_only_worker_subject(tmp_path: Path) -> None:
    ca_key, ca_certificate, _ca_path = _issue_ca(tmp_path)
    certificate, _certificate_path, _key_path = _issue_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        name="unmapped-worker",
        server=False,
    )
    policy = WorkerMTLSTrustPolicy(
        policy_id="worker-mtls-policy_abcdef0123456789abcdef0123456789",
        bindings=(
            WorkerCertificateBinding(
                principal_subject="another-worker",
                certificate_spki_sha256=certificate_spki_sha256(certificate),
            ),
        ),
    )

    with pytest.raises(ValueError, match="every and only configured Worker subject"):
        _settings(tmp_path, policy)


def test_worker_mtls_admission_binds_live_bearer_subject_and_leaf_spki(
    tmp_path: Path,
) -> None:
    ca_key, ca_certificate, _ca_path = _issue_ca(tmp_path)
    certificate, _certificate_path, _key_path = _issue_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        name="admitted-worker",
        server=False,
    )
    authenticator = WorkerMTLSAuthenticator(_policy(certificate))
    principal = Principal(
        subject=_WORKER_SUBJECT,
        roles=frozenset({PrincipalRole.WORKER}),
    )
    scope = {
        "scheme": "https",
        "extensions": {
            "tls": {
                "client_cert_error": None,
                "client_cert_chain": [
                    certificate.public_bytes(serialization.Encoding.PEM).decode("ascii")
                ],
            }
        },
    }

    admission = authenticator.authenticate_with_admission(scope, principal)

    assert authenticator.authenticate(scope, principal) == principal
    assert admission.admission_id == f"worker-mtls-admission_{admission.admission_digest}"
    assert admission.policy_id == _policy(certificate).policy_id
    assert admission.principal_subject == _WORKER_SUBJECT
    assert admission.certificate_spki_sha256 == certificate_spki_sha256(certificate)
    assert admission.bearer_authenticated is True
    assert admission.direct_mtls_authenticated is True
    assert admission.execution_authority is False

    changed = admission.model_dump(mode="json")
    changed["certificate_spki_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="digest differs"):
        WorkerMTLSAdmission.model_validate(changed)


def test_direct_mtls_binds_worker_subject_without_requiring_human_certificate(
    tmp_path: Path,
) -> None:
    ca_key, ca_certificate, ca_path = _issue_ca(tmp_path)
    _server_cert, server_cert_path, server_key_path = _issue_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        name="control-plane",
        server=True,
    )
    worker_cert, worker_cert_path, worker_key_path = _issue_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        name="bound-worker",
        server=False,
    )
    _wrong_cert, wrong_cert_path, wrong_key_path = _issue_leaf(
        tmp_path,
        ca_key=ca_key,
        ca_certificate=ca_certificate,
        name="wrong-worker",
        server=False,
    )
    server, thread, base_url, errors = _start_tls_server(
        tmp_path,
        settings=_settings(tmp_path, _policy(worker_cert)),
        server_certificate=server_cert_path,
        server_key=server_key_path,
        client_ca=ca_path,
    )
    try:
        assert (
            asyncio.run(
                _claim(
                    base_url=base_url,
                    ca=ca_path,
                    certificate=worker_cert_path,
                    private_key=worker_key_path,
                )
            )
            is None
        )
        with pytest.raises(ControlPlaneAuthenticationError):
            asyncio.run(
                _claim(
                    base_url=base_url,
                    ca=ca_path,
                    certificate=wrong_cert_path,
                    private_key=wrong_key_path,
                )
            )

        without_certificate = httpx.post(
            f"{base_url}/v1/worker/jobs/claim",
            headers={"Authorization": f"Bearer {_WORKER_TOKEN}"},
            json={"worker_id": "missing-mtls-worker", "kinds": ["campaign"]},
            verify=_ca_context(ca_path),
            timeout=2,
            trust_env=False,
        )
        assert without_certificate.status_code == 401

        human = httpx.get(
            f"{base_url}/v1/session",
            headers={"Authorization": f"Bearer {_OPERATOR_TOKEN}"},
            verify=_ca_context(ca_path),
            timeout=2,
            trust_env=False,
        )
        assert human.status_code == 200
        assert human.json()["subject"] == "worker-mtls-operator"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
    assert not thread.is_alive()
    assert errors == []
