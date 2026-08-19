from __future__ import annotations

import argparse
import base64
import ipaddress
import json
import os
import secrets
import shlex
import ssl
import subprocess
import tempfile
import threading
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import boto3
import botocore
import httpx
from botocore.config import Config
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pajin.control_plane.artifact_transfer import (
    PortableArtifactManifestFile,
    PortableArtifactMultipartManifest,
    portable_artifact_manifest_sha256,
)
from pajin.control_plane.object_storage_activation import ObjectStorageAuthorityHeadStore
from pajin.control_plane.object_storage_admission import (
    ObjectStorageProviderAdmissionStore,
    compile_object_storage_provider_admission_policy,
    compile_object_storage_selected_provider_evidence,
)
from pajin.control_plane.object_storage_authority import (
    ObjectStorageDeploymentAuthority,
    compile_object_storage_transport_binding,
)
from pajin.control_plane.object_storage_conformance import (
    run_object_storage_provider_conformance,
)
from pajin.control_plane.object_storage_minio import (
    MINIO_S3_BOTO3_VERSION,
    MINIO_S3_BOTOCORE_VERSION,
    MINIO_S3_SERVER_IMAGE,
    MinioS3ObjectStorageAdapter,
    MinioS3ProviderConformanceTarget,
    MinioS3ProviderInventory,
    MinioS3RuntimeSecrets,
)
from pajin.control_plane.object_storage_recovery import ObjectStorageProviderAttemptJournal

_ENDPOINT_ORIGIN = "https://127.0.0.1:9443"
_REDIRECT_PROBE_ORIGIN = "https://127.0.0.1:9444"
_BUCKET_NAME = "pajin-conformance-ux007p2"


class _RedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        self._redirect()

    def do_PUT(self) -> None:
        self._redirect()

    def do_POST(self) -> None:
        self._redirect()

    def do_DELETE(self) -> None:
        self._redirect()

    def _redirect(self) -> None:
        self.send_response(307)
        self.send_header("Location", f"{_ENDPOINT_ORIGIN}/must-not-follow")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def _run_docker(*args: str) -> str:
    result = subprocess.run(
        ("docker", *args),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Docker operation failed; inspect Docker Desktop without logging secrets"
        )
    return result.stdout.strip()


def _generate_tls(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(UTC)
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PAJIN UX-007P2 Test CA")])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=False,
                key_cert_sign=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False,
                crl_sign=True,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )
    server_key = ec.generate_private_key(ec.SECP256R1())
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address("127.0.0.1")), x509.DNSName("localhost")]
            ),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_path = directory.parent / "ca.crt"
    public_path = directory / "public.crt"
    private_path = directory / "private.key"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    public_path.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    private_path.write_bytes(
        server_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(private_path, 0o600)
    return ca_path, public_path, private_path


def _start_redirect_server(public_path: Path, private_path: Path) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("127.0.0.1", 9444), _RedirectHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(public_path, private_path)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def _wait_for_minio(ca_path: Path, *, container_name: str | None) -> None:
    deadline = time.monotonic() + 45
    last_observation = "no HTTP observation"
    while time.monotonic() < deadline:
        if container_name is not None:
            state = _run_docker(
                "inspect",
                "--format",
                "{{.State.Status}} {{.State.ExitCode}}",
                container_name,
            )
            if state.startswith("exited "):
                raise RuntimeError(f"MinIO exited before readiness ({state})")
        try:
            response = httpx.get(
                f"{_ENDPOINT_ORIGIN}/minio/health/live",
                verify=str(ca_path),
                trust_env=False,
                timeout=2.0,
            )
            if response.status_code == 200:
                return
            last_observation = f"HTTP {response.status_code}"
        except httpx.HTTPError as exc:
            last_observation = f"{type(exc).__name__}: {exc}"
        time.sleep(0.5)
    raise RuntimeError(f"MinIO did not become ready inside the bounded wait ({last_observation})")


def _manifest(content: bytes) -> PortableArtifactMultipartManifest:
    files = [
        PortableArtifactManifestFile(
            path="sealed/conformance.bin",
            size=len(content),
            sha256=sha256(content).hexdigest(),
        )
    ]
    return PortableArtifactMultipartManifest(
        files=files,
        file_count=1,
        total_bytes=len(content),
        manifest_sha256=portable_artifact_manifest_sha256(files),
    )


def _write_json_once(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    if path.exists():
        if path.read_bytes() != encoded:
            raise RuntimeError("Content-addressed MinIO evidence path equivocated")
        return
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        stream.write(encoded.decode("utf-8"))


def _tls_self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="pajin-ux007p2-tls-") as raw_directory:
        cert_directory = Path(raw_directory) / "certs"
        cert_directory.mkdir()
        ca_path, public_path, private_path = _generate_tls(cert_directory)
        server = _start_redirect_server(public_path, private_path)
        try:
            response = httpx.put(
                f"{_REDIRECT_PROBE_ORIGIN}/probe",
                verify=str(ca_path),
                follow_redirects=False,
                trust_env=False,
                timeout=5.0,
            )
            return response.status_code
        finally:
            server.shutdown()
            server.server_close()


def _require_sdk_versions() -> None:
    if boto3.__version__ != MINIO_S3_BOTO3_VERSION:
        raise RuntimeError("boto3 version differs from the selected provider inventory")
    if botocore.__version__ != MINIO_S3_BOTOCORE_VERSION:
        raise RuntimeError("botocore version differs from the selected provider inventory")


def _read_runtime_secrets(path: Path) -> MinioS3RuntimeSecrets:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        if set(raw) != {"accessKey", "secretKey", "sseCustomerKeyBase64"}:
            raise ValueError
        return MinioS3RuntimeSecrets(
            access_key=raw["accessKey"],
            secret_key=raw["secretKey"],
            sse_customer_key=base64.b64decode(raw["sseCustomerKeyBase64"], validate=True),
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise RuntimeError("MinIO runtime secret file is invalid") from None


def _execute_attached(runtime_directory: Path, report_directory: Path) -> tuple[Path, ...]:
    _require_sdk_versions()
    runtime_directory = runtime_directory.resolve()
    cert_directory = runtime_directory / "certs"
    ca_path = runtime_directory / "ca.crt"
    state_directory = runtime_directory / "state"
    public_path = cert_directory / "public.crt"
    private_path = cert_directory / "private.key"
    runtime_secrets = _read_runtime_secrets(runtime_directory / "runtime-secrets.json")
    inventory = MinioS3ProviderInventory(
        endpointOrigin=_ENDPOINT_ORIGIN,
        redirectProbeOrigin=_REDIRECT_PROBE_ORIGIN,
        bucketName=_BUCKET_NAME,
        tlsCaSha256=sha256(ca_path.read_bytes()).hexdigest(),
    )
    redirect_server = _start_redirect_server(public_path, private_path)
    try:
        _wait_for_minio(ca_path, container_name=None)
        client = boto3.client(
            "s3",
            endpoint_url=inventory.endpoint_origin,
            region_name=inventory.region,
            aws_access_key_id=runtime_secrets.access_key,
            aws_secret_access_key=runtime_secrets.secret_key,
            verify=str(ca_path),
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                retries={"total_max_attempts": 1, "mode": "standard"},
            ),
        )
        client.create_bucket(Bucket=inventory.bucket_name)
        challenge = secrets.token_bytes(32)
        issued_at = datetime.now(UTC)
        authority = ObjectStorageDeploymentAuthority(
            deploymentId="object-storage:minio-conformance",
            revision=1,
            issuedAt=issued_at - timedelta(seconds=2),
            tenantId="tenant:minio-conformance",
            endpointOrigin=inventory.endpoint_origin,
            objectKeyPrefix="pajin-conformance/tenant",
            uploadTtlSeconds=60,
        )
        head = ObjectStorageAuthorityHeadStore.bootstrap(
            state_directory / "authority.sqlite3",
            authority,
            activated_at=issued_at - timedelta(seconds=1),
        )
        binding = compile_object_storage_transport_binding(
            authority,
            output_staging_id="stage_" + secrets.token_hex(16),
            manifest=_manifest(challenge),
            executor_attestation_digest=sha256(secrets.token_bytes(32)).hexdigest(),
            issued_at=issued_at,
        )
        adapter = MinioS3ObjectStorageAdapter(
            inventory=inventory,
            secrets=runtime_secrets,
            ca_bundle_path=ca_path,
            state_path=state_directory / "adapter.sqlite3",
        )
        journal = ObjectStorageProviderAttemptJournal.bootstrap(
            state_directory / "journal.sqlite3",
            authority_checkpoint=head.checkpoint(),
            adapter=adapter.definition,
            deployment_profile=adapter.deployment_profile,
            activated_at=issued_at - timedelta(milliseconds=500),
        )
        target = MinioS3ProviderConformanceTarget(
            adapter=adapter,
            ca_bundle_path=ca_path,
        )
        report = run_object_storage_provider_conformance(
            authority_store=head,
            journal=journal,
            binding=binding,
            target=target,
            challenge=challenge,
        )
        activation = journal.latest_activation()
        evidence = compile_object_storage_selected_provider_evidence(
            inventory=inventory,
            activation=activation,
            report=report,
        )
        policy = compile_object_storage_provider_admission_policy(
            evidence,
            issued_at=report.finished_at,
        )
        admission_store = ObjectStorageProviderAdmissionStore.bootstrap(
            state_directory / "admission.sqlite3",
            store_id="object-storage-admission:minio-live",
            policy=policy,
            provisioned_at=report.finished_at,
        )
        admission = admission_store.admit(
            evidence,
            inventory=inventory,
            authority_store=head,
            journal=journal,
            expected_checkpoint=admission_store.checkpoint(),
            evaluated_at=report.finished_at,
        )
        admission_checkpoint = admission_store.checkpoint()
        inventory_path = report_directory / f"minio-inventory-{inventory.inventory_digest}.json"
        report_path = report_directory / f"minio-report-{report.report_digest}.json"
        evidence_path = report_directory / f"minio-evidence-{evidence.evidence_digest}.json"
        policy_path = report_directory / f"minio-admission-policy-{policy.policy_digest}.json"
        admission_path = report_directory / f"minio-admission-{admission.admission_digest}.json"
        checkpoint_path = (
            report_directory
            / f"minio-admission-checkpoint-{admission_checkpoint.checkpoint_digest}.json"
        )
        _write_json_once(
            inventory_path,
            inventory.model_dump(mode="json", by_alias=True),
        )
        _write_json_once(
            report_path,
            report.model_dump(mode="json", by_alias=True),
        )
        _write_json_once(
            evidence_path,
            evidence.model_dump(mode="json", by_alias=True),
        )
        _write_json_once(
            policy_path,
            policy.model_dump(mode="json", by_alias=True),
        )
        _write_json_once(
            admission_path,
            admission.model_dump(mode="json", by_alias=True),
        )
        _write_json_once(
            checkpoint_path,
            admission_checkpoint.model_dump(mode="json", by_alias=True),
        )
        return (
            inventory_path,
            report_path,
            evidence_path,
            policy_path,
            admission_path,
            checkpoint_path,
        )
    finally:
        redirect_server.shutdown()
        redirect_server.server_close()


def _windows_path_to_wsl(path: Path) -> str:
    resolved = path.resolve()
    drive = resolved.drive
    if len(drive) != 2 or drive[1] != ":":
        raise RuntimeError("WSL runner requires one absolute Windows drive path")
    suffix = resolved.as_posix()[2:].lstrip("/")
    return f"/mnt/{drive[0].lower()}/{suffix}"


def _run_wsl_attached(runtime_directory: Path, report_directory: Path) -> tuple[str, ...]:
    repository = Path.cwd().resolve()
    try:
        runtime_relative = runtime_directory.resolve().relative_to(repository).as_posix()
        report_relative = report_directory.resolve().relative_to(repository).as_posix()
    except ValueError:
        raise RuntimeError(
            "MinIO WSL runtime and report paths must remain inside the repository"
        ) from None
    command = " ".join(
        (
            "cd",
            shlex.quote(_windows_path_to_wsl(repository)),
            "&&",
            ".pajin/wsl-minio-venv/bin/python",
            "scripts/run-minio-object-storage-conformance.py",
            "--attach-runtime",
            shlex.quote(runtime_relative),
            "--report-directory",
            shlex.quote(report_relative),
        )
    )
    result = subprocess.run(
        ("wsl.exe", "-d", "Ubuntu", "--", "bash", "-lc", command),
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"WSL MinIO conformance failed: {result.stderr.strip()}")
    lines = tuple(line.strip() for line in result.stdout.splitlines() if line.strip())
    if len(lines) != 6:
        raise RuntimeError("WSL MinIO conformance returned an invalid receipt")
    return tuple(line.replace("\\", "/").rsplit("/", 1)[-1] for line in lines)


def _execute(report_directory: Path) -> tuple[Path, ...]:
    _require_sdk_versions()
    runtime_secrets = MinioS3RuntimeSecrets(
        access_key="pajin" + secrets.token_hex(8),
        secret_key=secrets.token_urlsafe(32),
        sse_customer_key=secrets.token_bytes(32),
    )
    container_name = "pajin-ux007p2-" + secrets.token_hex(6)
    volume_name = container_name + "-data"
    private_root = Path(".pajin").resolve()
    private_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix="pajin-ux007p2-",
        dir=private_root,
    ) as raw_directory:
        runtime_directory = Path(raw_directory).resolve()
        cert_directory = runtime_directory / "certs"
        state_directory = runtime_directory / "state"
        cert_directory.mkdir()
        state_directory.mkdir()
        ca_path, _public_path, _private_path = _generate_tls(cert_directory)
        inventory = MinioS3ProviderInventory(
            endpointOrigin=_ENDPOINT_ORIGIN,
            redirectProbeOrigin=_REDIRECT_PROBE_ORIGIN,
            bucketName=_BUCKET_NAME,
            tlsCaSha256=sha256(ca_path.read_bytes()).hexdigest(),
        )
        _write_json_once(
            runtime_directory / "runtime-secrets.json",
            {
                "accessKey": runtime_secrets.access_key,
                "secretKey": runtime_secrets.secret_key,
                "sseCustomerKeyBase64": base64.b64encode(runtime_secrets.sse_customer_key).decode(
                    "ascii"
                ),
            },
        )
        os.chmod(runtime_directory / "runtime-secrets.json", 0o600)
        started = False
        volume_created = False
        try:
            _run_docker("pull", MINIO_S3_SERVER_IMAGE)
            _run_docker("volume", "create", volume_name)
            volume_created = True
            _run_docker(
                "run",
                "--detach",
                "--name",
                container_name,
                "--platform",
                inventory.platform,
                "--publish",
                "127.0.0.1:9443:9000",
                "--volume",
                f"{cert_directory}:/certs:ro",
                "--mount",
                f"type=volume,src={volume_name},dst=/data",
                "--env",
                f"MINIO_ROOT_USER={runtime_secrets.access_key}",
                "--env",
                f"MINIO_ROOT_PASSWORD={runtime_secrets.secret_key}",
                MINIO_S3_SERVER_IMAGE,
                "server",
                "/data",
                "--certs-dir",
                "/certs",
                "--address",
                ":9000",
                "--console-address",
                ":9001",
            )
            started = True
            try:
                evidence_names = _run_wsl_attached(
                    runtime_directory,
                    report_directory,
                )
            except RuntimeError as exc:
                logs = _run_docker("logs", "--tail", "40", container_name)
                state = _run_docker(
                    "inspect",
                    "--format",
                    "{{json .State}} {{json .NetworkSettings.Ports}}",
                    container_name,
                )
                redacted = logs.replace(runtime_secrets.access_key, "<redacted>").replace(
                    runtime_secrets.secret_key,
                    "<redacted>",
                )
                raise RuntimeError(
                    f"{exc}; container state: {state}; sanitized MinIO logs: {redacted}"
                ) from None
            return tuple(report_directory / name for name in evidence_names)
        finally:
            try:
                if started:
                    _run_docker("rm", "--force", container_name)
            finally:
                if volume_created:
                    _run_docker("volume", "rm", "--force", volume_name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run UX-007P2/Q against a pinned disposable MinIO server."
    )
    parser.add_argument(
        "--report-directory",
        type=Path,
        default=Path("reports/object-storage-conformance"),
    )
    parser.add_argument("--tls-self-test", action="store_true")
    parser.add_argument("--attach-runtime", type=Path)
    arguments = parser.parse_args()
    if arguments.tls_self_test:
        print(_tls_self_test())
        return
    if arguments.attach_runtime is not None:
        evidence_paths = _execute_attached(
            arguments.attach_runtime,
            arguments.report_directory.resolve(),
        )
        for path in evidence_paths:
            print(path)
        return
    for path in _execute(arguments.report_directory.resolve()):
        print(path)


if __name__ == "__main__":
    main()
