from __future__ import annotations

import ssl
from pathlib import Path

import pytest

import pajin.control_plane.__main__ as control_plane_main
from pajin.control_plane.api import ControlPlaneSettings
from pajin.control_plane.client import ControlPlaneClient, _control_plane_tls_context
from pajin.control_plane.tls_protocol import WorkerMTLSH11Protocol
from pajin.control_plane.worker_identity import (
    WorkerCertificateBinding,
    WorkerMTLSTrustPolicy,
)

_TOKEN_SUFFIX = "-token-that-is-long-enough-for-mtls"
_TLS_ENV_NAMES = (
    "PAJIN_CP_TLS_CERT_FILE",
    "PAJIN_CP_TLS_KEY_FILE",
    "PAJIN_CP_TLS_KEY_PASSWORD",
    "PAJIN_CP_WORKER_MTLS_CA_FILE",
    "PAJIN_CP_WORKER_MTLS_TRUST_POLICY",
)


def _policy() -> WorkerMTLSTrustPolicy:
    return WorkerMTLSTrustPolicy(
        policy_id="worker-mtls-policy_0123456789abcdef0123456789abcdef",
        bindings=(
            WorkerCertificateBinding(
                principal_subject="worker-service",
                certificate_spki_sha256="a" * 64,
            ),
        ),
    )


def _clear_tls_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _TLS_ENV_NAMES:
        monkeypatch.delenv(name, raising=False)


def test_server_worker_mtls_ca_and_policy_must_be_configured_together(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_tls_env(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_MTLS_CA_FILE", "worker-ca.pem")
    with pytest.raises(ValueError, match="must be configured together"):
        control_plane_main._server_tls_settings_from_env()

    _clear_tls_env(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", _policy().model_dump_json())
    with pytest.raises(ValueError, match="must be configured together"):
        control_plane_main._server_tls_settings_from_env()


def test_server_worker_mtls_uses_optional_verified_certificates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_tls_env(monkeypatch)
    monkeypatch.setenv("PAJIN_CP_TLS_CERT_FILE", "server.cert.pem")
    monkeypatch.setenv("PAJIN_CP_TLS_KEY_FILE", "server.key.pem")
    monkeypatch.setenv("PAJIN_CP_WORKER_MTLS_CA_FILE", "worker-ca.pem")
    monkeypatch.setenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", _policy().model_dump_json())

    settings = control_plane_main._server_tls_settings_from_env()

    assert settings.certificate_requirements is ssl.CERT_OPTIONAL
    assert settings.worker_ca_file == "worker-ca.pem"


def test_server_main_wires_the_peer_evidence_protocol(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_tls_env(monkeypatch)
    captured: dict[str, object] = {}

    def fake_run(_app: str, **kwargs: object) -> None:
        captured.update(kwargs)

    monkeypatch.setattr(control_plane_main.uvicorn, "run", fake_run)

    control_plane_main.main()

    assert captured["http"] is WorkerMTLSH11Protocol
    assert captured["proxy_headers"] is False
    assert captured["ssl_cert_reqs"] is ssl.CERT_NONE


def test_control_plane_client_allows_ca_only_but_rejects_partial_or_plaintext_mtls(
    tmp_path: Path,
) -> None:
    token = f"worker{_TOKEN_SUFFIX}"
    system_ca_der = ssl.create_default_context().get_ca_certs(binary_form=True)[0]
    ca_path = tmp_path / "ca.pem"
    ca_path.write_text(ssl.DER_cert_to_PEM_cert(system_ca_der), encoding="ascii")

    context = _control_plane_tls_context(
        base_url="https://control-plane.example.test",
        ca_file=str(ca_path),
        certificate_file=None,
        private_key_file=None,
        private_key_password=None,
        require_client_certificate=False,
    )
    assert isinstance(context, ssl.SSLContext)

    with pytest.raises(ValueError, match="requires CA, client certificate"):
        _control_plane_tls_context(
            base_url="https://control-plane.example.test",
            ca_file=str(ca_path),
            certificate_file=None,
            private_key_file=None,
            private_key_password=None,
            require_client_certificate=True,
        )

    with pytest.raises(ValueError, match="client certificate and private-key"):
        _control_plane_tls_context(
            base_url="https://control-plane.example.test",
            ca_file=str(ca_path),
            certificate_file="worker.cert.pem",
            private_key_file=None,
            private_key_password=None,
            require_client_certificate=True,
        )

    with pytest.raises(ValueError, match="only with HTTPS"):
        ControlPlaneClient(
            base_url="http://127.0.0.1:8090",
            bearer_token=token,
            allow_plaintext_http_for_lab=True,
            tls_ca_file="ca.pem",
            tls_client_cert_file="worker.cert.pem",
            tls_client_key_file="worker.key.pem",
        )


def test_environment_policy_binds_the_configured_worker_subject(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", f"operator{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", f"approver{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", f"worker{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "checkpoint-key-that-is-long-enough-for-mtls")
    monkeypatch.setenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", _policy().model_dump_json())

    settings = ControlPlaneSettings.from_env()

    assert settings.worker_mtls_trust_policy == _policy()


def test_pentest_recon_deployment_requires_digest_and_worker_mtls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", f"operator{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", f"approver{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", f"worker{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "checkpoint-key-that-is-long-enough-for-mtls")
    monkeypatch.setenv("PAJIN_CP_PENTEST_RECON_DEPLOYMENT_PATH", "deployment.json")
    monkeypatch.delenv("PAJIN_CP_PENTEST_RECON_DEPLOYMENT_SHA256", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    with pytest.raises(RuntimeError, match="path and SHA-256"):
        ControlPlaneSettings.from_env()

    monkeypatch.setenv("PAJIN_CP_PENTEST_RECON_DEPLOYMENT_SHA256", "a" * 64)
    with pytest.raises(ValueError, match="requires Worker mTLS policy"):
        ControlPlaneSettings.from_env()


def test_pentest_replay_deployment_requires_digest_and_worker_mtls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("PAJIN_CP_OPERATOR_TOKEN", f"operator{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_APPROVER_TOKEN", f"approver{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_WORKER_TOKEN", f"worker{_TOKEN_SUFFIX}")
    monkeypatch.setenv("PAJIN_CP_CHECKPOINT_KEY", "checkpoint-key-that-is-long-enough-for-mtls")
    monkeypatch.setenv("PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_PATH", "deployment.json")
    monkeypatch.delenv("PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_SHA256", raising=False)
    monkeypatch.delenv("PAJIN_CP_WORKER_MTLS_TRUST_POLICY", raising=False)

    with pytest.raises(RuntimeError, match="path and SHA-256"):
        ControlPlaneSettings.from_env()

    monkeypatch.setenv("PAJIN_CP_PENTEST_REPLAY_DEPLOYMENT_SHA256", "a" * 64)
    with pytest.raises(ValueError, match="requires Worker mTLS policy"):
        ControlPlaneSettings.from_env()
