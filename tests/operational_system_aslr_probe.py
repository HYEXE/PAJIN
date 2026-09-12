"""Opt-in real mTLS agent/Worker fixture, invoked only by the owned System rehearsal."""

from __future__ import annotations

import asyncio
import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pajin.graph.approval import ActionApprovalError
from pajin.graph.authority import ActionPermitError
from pajin.system_aslr.models import AslrDeployment, AslrInput
from pajin.system_aslr.report import (
    AslrReportTrust,
    compare_aslr_runs,
    read_aslr_run,
    seal_aslr_execution,
)
from pajin.system_aslr.runtime import AslrGateway, dispatch_aslr_action
from pajin.system_aslr.tool import AslrReadTool
from tests.sys_004_support import fixture_action, local_fixture_activation


def docker(*arguments):
    return subprocess.run(
        ["docker", *arguments], check=True, capture_output=True, text=True, timeout=30
    ).stdout.strip()


def write(path, value):
    with path.open("x") as handle:
        path.chmod(0o600)
        json.dump(value, handle, indent=2, sort_keys=True)


def certificate(ca=None, ca_key=None, *, addresses=(), server=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = "SYS-004 CA" if ca is None else ("SYS-004 server" if server else "SYS-004 client")
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    now = datetime.now(UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca.subject if ca else name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=ca is None, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key((ca_key or key).public_key()),
            critical=False,
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage(
                [ExtendedKeyUsageOID.SERVER_AUTH if server else ExtendedKeyUsageOID.CLIENT_AUTH]
            ),
            critical=False,
        )
    if addresses:
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                [x509.IPAddress(ipaddress.ip_address(address)) for address in addresses]
            ),
            critical=False,
        )
    cert = builder.sign(ca_key or key, hashes.SHA256())
    return cert, key


def pem_key(key):
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ).decode()


def pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def owned_agent(root, name, *, file_content=None):
    directory = root / name
    directory.mkdir(mode=0o700)
    credentials = directory / "credentials"
    credentials.mkdir(mode=0o755)
    credentials.chmod(0o755)
    args = [
        "create",
        "--label",
        os.environ["PAJIN_SYS004_OWNER"],
        "--read-only",
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user=65532:65532",
        "--pids-limit=32",
        "--memory=128m",
        "--cpus=0.5",
        "--publish=127.0.0.1::8443",
        "--mount",
        f"type=bind,source={credentials},target=/credentials,readonly",
    ]
    if file_content is not None:
        file = directory / "aslr-invalid-fixture"
        file.write_bytes(file_content)
        file.chmod(0o444)
        args += [
            "--mount",
            f"type=bind,source={file},target=/fixtures/aslr-invalid,readonly",
        ]
    # The disposable launcher waits for fresh certificates binding the actual assigned IP.
    launcher = (
        "import pathlib,time,runpy; p=pathlib.Path('/credentials/ready'); "
        "deadline=time.monotonic()+60\n"
        "while not p.exists() and time.monotonic()<deadline: time.sleep(.1)\n"
        "assert p.exists(); runpy.run_path('/app/agent.py',run_name='__main__')"
    )
    if file_content is not None:
        # runc forbids replacing files inside /proc. This negative fixture redirects only
        # the fixed open; the unchanged agent performs the real bounded reads and validation.
        launcher = (
            "import os\n"
            "actual_open=os.open\n"
            "def fixture_open(path, flags, *args, **kwargs):\n"
            " if path == '/proc/sys/kernel/randomize_va_space':\n"
            "  path = '/fixtures/aslr-invalid'\n"
            " return actual_open(path, flags, *args, **kwargs)\n"
            "os.open=fixture_open\n"
        ) + launcher
        write(directory / "fault-injection.json", {
            "method": "test-launcher-fixed-open-redirection",
            "fileSha256": sha256(file_content).hexdigest(),
            "kernelValueModified": False,
            "positiveExecutionEvidence": False,
        })
    identifier = docker(
        *args, "--entrypoint=python", os.environ["PAJIN_SYS004_IMAGE"], "-I", "-c", launcher
    )
    try:
        docker("start", identifier)
    except subprocess.CalledProcessError as exc:
        (directory / "start-error.log").write_text(exc.stderr)
        raise
    address = docker(
        "inspect",
        identifier,
        "--format",
        '{{(index .NetworkSettings.Networks "bridge").IPAddress}}',
    )
    port = int(docker("port", identifier, "8443/tcp").rsplit(":", 1)[1])
    ca, ca_key = certificate()
    server, server_key = certificate(ca, ca_key, addresses=(address, "127.0.0.1"), server=True)
    client, client_key = certificate(ca, ca_key)
    wrong, wrong_key = certificate(ca, ca_key)
    values = {
        "ca.pem": pem_cert(ca),
        "server.pem": pem_cert(server),
        "server-key.pem": pem_key(server_key),
        "client.pem": pem_cert(client),
        "client-key.pem": pem_key(client_key),
    }
    for filename, value in values.items():
        (credentials / filename).write_text(value)
        (credentials / filename).chmod(0o444)
    client_pin = client.fingerprint(hashes.SHA256()).hex()
    (credentials / "agent.json").write_text(
        json.dumps({"instance": name, "client_cert_sha256": client_pin})
    )
    (credentials / "agent.json").chmod(0o444)
    (credentials / "ready").touch(mode=0o444)
    config = AslrDeployment(
        value=AslrInput(target=f"https://{address}:8443/v1/aslr", instance=name),
        image_id=os.environ["PAJIN_SYS004_IMAGE"],
        proxy_image_id=os.environ["PAJIN_SYS004_PROXY"],
        ca_sha256=sha256(values["ca.pem"].encode()).hexdigest(),
        server_cert_sha256=server.fingerprint(hashes.SHA256()).hex(),
        client_cert_sha256=client_pin,
        agent_sha256=sha256(Path("containers/system-aslr/agent.py").read_bytes()).hexdigest(),
        client_sha256=sha256(Path("containers/system-aslr/client.py").read_bytes()).hexdigest(),
    )
    context = ssl.create_default_context(cadata=values["ca.pem"])
    context.load_cert_chain(credentials / "client.pem", credentials / "client-key.pem")
    deadline = time.monotonic() + 45
    while True:
        try:
            with (
                socket.create_connection(("127.0.0.1", port), timeout=2) as stream,
                context.wrap_socket(stream, server_hostname="127.0.0.1"),
            ):
                break
        except OSError as exc:
            if time.monotonic() >= deadline:
                raise RuntimeError("owned System agent did not become TLS-ready") from exc
            time.sleep(0.2)
    secret = json.dumps(
        {
            "ca": values["ca.pem"],
            "certificate": values["client.pem"],
            "key": values["client-key.pem"],
        }
    )
    wrong_secret = json.dumps(
        {"ca": values["ca.pem"], "certificate": pem_cert(wrong), "key": pem_key(wrong_key)}
    )
    return identifier, port, context, config, secret, wrong_secret


async def execute(root, config, secret, *, activation=None, operator=None):
    tool = AslrReadTool(config)
    activation = activation or local_fixture_activation(tool)
    operator = operator or ed25519.Ed25519PrivateKey.generate()
    policy, keys, releases = activation.lifecycle.verification_material()
    trust = AslrReportTrust(
        deployment=config,
        operator_public_key=operator.public_key().public_bytes_raw().hex(),
        operator_id="sys-004-fixture-operator",
        policy=policy,
        keys=keys,
        releases=releases,
        release=activation.release,
    )
    action, authority, graph, store = fixture_action(root, tool, config.value, activation, operator)
    gateway = AslrGateway(tool, store, secret)
    outcome = await dispatch_aslr_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert outcome is not None and outcome.executed
    write(root / (store.run_id + "-outcome.json"), outcome.model_dump(mode="json"))
    assert (
        await dispatch_aslr_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
        is None
    )
    reference = seal_aslr_execution(store, outcome, trust)
    report = read_aslr_run(root / "runs", reference, trust)
    return outcome, reference, report, trust


def direct_get(port, context, request_id, path="/v1/aslr"):
    connection = http.client.HTTPSConnection("127.0.0.1", port, timeout=5, context=context)
    try:
        connection.request("GET", path, headers={"X-PAJIN-Request-ID": request_id})
        response = connection.getresponse()
        response.read()
        return response.status
    finally:
        connection.close()


@pytest.mark.asyncio
async def test_real_authenticated_agent_full_product_flow():
    root = Path(os.environ["PAJIN_SYS004_ROOT"])
    agent, port, context, config, secret, wrong_secret = owned_agent(root, "owned-system")
    tool = AslrReadTool(config)
    activation = local_fixture_activation(tool)
    operator = ed25519.Ed25519PrivateKey.generate()
    source, left, source_report, trust = await execute(
        root, config, secret, activation=activation, operator=operator
    )
    assert source.result.success, source.result.error
    assert source_report["complete"]
    replay, right, replay_report, replay_trust = await execute(
        root, config, secret, activation=activation, operator=operator
    )
    assert replay.result.success and replay_report["complete"] and replay_trust == trust
    comparison = compare_aslr_runs(root / "runs", left, right, trust)
    assert comparison["complete"] and comparison["aslrMatch"]
    # GNU coreutils performs an independent byte read and decimal rendering, without PAJIN code.
    version = docker("exec", agent, "od", "--version").splitlines()[0]
    independent = docker(
        "exec", agent, "od", "-An", "-tu1", "/proc/sys/kernel/randomize_va_space"
    )
    values = [int(value) for value in independent.split()]
    assert len(values) == 2 and values[0] in (48, 49, 50) and values[1] == 10
    observed = source_report["aslr"]["metadata"]
    assert observed == {"randomizeVaSpace": values[0] - 48}
    write(root / "independent-coreutils.json", {
        "metadata": observed, "bytes": values, "implementation": version, "match": True,
        "processAslrVerified": False, "physicalHostVerified": False,
    })
    assert direct_get(port, context, source_report["requestId"]) == 409
    assert direct_get(port, context, "tool_" + uuid4().hex, "/etc/passwd") == 400
    with pytest.raises(ssl.SSLError):
        direct_get(port, ssl.create_default_context(), "tool_" + uuid4().hex)
    # A separately pinned CA-signed client still cannot impersonate the agent's enrolled client.
    wrong = json.loads(wrong_secret)
    wrong_pin = sha256(ssl.PEM_cert_to_DER_cert(wrong["certificate"])).hexdigest()
    bad_config = config.model_copy(update={"client_cert_sha256": wrong_pin})
    failed, _, failed_report, _ = await execute(root, bad_config, wrong_secret)
    assert not failed.result.success and not failed_report["complete"]
    write(root / "trust.json", trust.model_dump(mode="json"))
    write(root / "source-ref.json", left.model_dump())
    write(root / "replay-ref.json", right.model_dump())
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.system_aslr",
            "--root",
            str(root / "runs"),
            "--trust",
            str(root / "trust.json"),
            "--trust-digest",
            trust.commitment,
            "--source-ref",
            str(root / "source-ref.json"),
            "--replay-ref",
            str(root / "replay-ref.json"),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert json.loads(result.stdout) == comparison
    write(root / "fresh-process-report.json", json.loads(result.stdout))
    await denied_authority_without_worker(root, config, secret)
    await malformed_file_failure(root)
    await asyncio.sleep(0)


async def malformed_file_failure(root):
    _, port, context, config, secret, _ = owned_agent(
        root, "owned-malformed", file_content=b"9\n"
    )
    request_id = "tool_" + uuid4().hex
    assert direct_get(port, context, request_id) == 422
    assert direct_get(port, context, request_id) == 409
    outcome, _, report, _ = await execute(root, config, secret)
    assert not outcome.result.success and not report["complete"]


async def denied_authority_without_worker(root, config, secret):
    for mode in ("scope", "signature"):
        tool = AslrReadTool(config)
        action, authority, graph, store = fixture_action(root, tool, config.value)
        if mode == "scope":
            authority.campaign.spec.scope.allow = [config.value.target]
        else:
            authority.signed.signature = "0" * 128
        with pytest.raises((ValueError, ActionApprovalError, ActionPermitError)):
            await dispatch_aslr_action(
                action=action,
                authority=authority,
                graph=graph,
                gateway=AslrGateway(tool, store, secret),
                store=store,
            )
        assert not (store.path / "authorization.json").exists()
        assert not list((store.path / "evidence").glob("*.json"))
