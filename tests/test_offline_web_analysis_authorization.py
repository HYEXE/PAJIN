from __future__ import annotations

import ast
import base64
import json
import os
import stat
import subprocess
import sys
import tomllib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from offline.web_analysis_authorization.src import (
    pajin_web_analysis_authorization_offline as offline_authority,
)
from offline.web_analysis_authorization.src.pajin_web_analysis_authorization_offline import (
    cli as cli_module,
)
from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.web_assessment.analysis_live_authorization import (
    parse_web_analysis_one_call_authorization_trust_anchor,
)
from pajin.web_assessment.analysis_live_authorization_v2 import (
    WebAnalysisOneCallAuthorizationRequestV2,
    WebAnalysisOneCallAuthorizationVerifierV2,
    authorization_statement_signing_bytes_v2,
    parse_signed_web_analysis_one_call_authorization_v2,
)
from tests.test_web_analysis_live_authorization import _statement as _v1_statement
from tests.test_web_analysis_live_authorization_v2 import (
    authorization_v2_context as _authorization_v2_context_fixture,
)

_DIGESTS = tuple(character * 64 for character in "123456789abcdef")


@pytest.fixture(scope="module")  # type: ignore[untyped-decorator]
def main_v2_context(tmp_path_factory: pytest.TempPathFactory) -> SimpleNamespace:
    build_context = cast(Any, _authorization_v2_context_fixture).__wrapped__
    return cast(SimpleNamespace, build_context(tmp_path_factory))


def _owner_dir(path: Path) -> Path:
    path.mkdir(mode=0o700)
    path.chmod(0o700)
    return path


def _write_owner_file(path: Path, content: bytes) -> None:
    path.write_bytes(content)
    path.chmod(0o600)


def _authorization_request() -> WebAnalysisOneCallAuthorizationRequestV2:
    return WebAnalysisOneCallAuthorizationRequestV2(
        admissionId="prepared-compact-web-analysis:test",
        admissionDigest=_DIGESTS[0],
        preparationRunId="run_20260923T010203Z_deadbeef",
        preparationRunRootDigest=_DIGESTS[1],
        preparationIdentity=_DIGESTS[2],
        preparationIndexDigest=_DIGESTS[3],
        liveRequestDigest=_DIGESTS[4],
        providerId="local-openai",
        modelId="qwen3-4b-instruct-2507-q8_0.gguf",
        providerRegistrationDigest=_DIGESTS[5],
        providerChatRequestDigest=_DIGESTS[6],
        compactProjectionDigest=_DIGESTS[7],
        responseSchemaDigest=_DIGESTS[8],
        capacityPinDigest=_DIGESTS[9],
        modelPinDigest=_DIGESTS[10],
        modelSha256=_DIGESTS[11],
        modelSizeBytes=4_000_000_000,
        modelImage="ghcr.io/example/llama.cpp@sha256:" + "a" * 64,
        modelPlatformManifest="sha256:" + "b" * 64,
        lineageTransportPinDigest=_DIGESTS[12],
        lineageTransportVersion="pajin.web-analysis.provider-transport/v2",
        compactRuntimePinDigest=_DIGESTS[13],
        compactTransportPinDigest=_DIGESTS[14],
        compactTransportVersion="pajin.web-analysis.compact-provider-transport/v1",
        workerAction="openai-chat-completion-v3",
        workerImage="sha256:" + "c" * 64,
        proxyImage="sha256:" + "d" * 64,
        contextTokens=4096,
        maximumCompletionTokens=1024,
    )


def _write_request(directory: Path) -> tuple[Path, WebAnalysisOneCallAuthorizationRequestV2]:
    request = _authorization_request()
    path = directory / "request.json"
    _write_owner_file(
        path,
        canonical_json_bytes(
            request.model_dump(mode="json", by_alias=True),
            label="test authorization request",
        )
        + b"\n",
    )
    return path, request


def _provision(directory: Path) -> offline_authority.ProvisionedAuthorizationAuthority:
    now = datetime.now(UTC).replace(microsecond=0)
    return offline_authority.provision_authorization_authority(
        private_key_file=directory / "private.seed",
        trust_anchor_file=directory / "trust-anchor.json",
        trust_anchor_digest_file=directory / "trust-anchor.sha256",
        trust_domain="pajin.web-analysis.live",
        issuer="external-authorizer.invalid",
        key_id="external-key-v1",
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(hours=1),
    )


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + ("=" * (-len(value) % 4)))


def test_provision_and_issue_one_fresh_v2_bundle(tmp_path: Path) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request_path, request = _write_request(request_directory)

    issued = offline_authority.issue_authorization_bundle(
        private_key_file=provisioned.private_key_file,
        trust_anchor_file=provisioned.trust_anchor_file,
        trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
        authorization_request_file=request_path,
        signed_bundle_file=issued_directory / "authorization.json",
        lifetime_seconds=180,
    )

    for path in (
        provisioned.private_key_file,
        provisioned.trust_anchor_file,
        provisioned.trust_anchor_digest_file,
        issued.signed_bundle_file,
    ):
        metadata = path.stat()
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
        assert metadata.st_uid == os.geteuid()
    assert len(provisioned.private_key_file.read_bytes()) == 32
    anchor = parse_web_analysis_one_call_authorization_trust_anchor(
        provisioned.trust_anchor_file.read_bytes()
    )
    assert provisioned.trust_anchor_digest_file.read_text(encoding="ascii") == (
        anchor.digest + "\n"
    )
    bundle_content = issued.signed_bundle_file.read_bytes()
    bundle = parse_signed_web_analysis_one_call_authorization_v2(bundle_content)
    assert bundle_content == (
        canonical_json_bytes(
            bundle.model_dump(mode="json", by_alias=True),
            label="test signed authorization bundle",
        )
        + b"\n"
    )
    assert bundle.statement.request == request
    assert bundle.statement.maximum_dispatch_count == 1
    assert bundle.statement.target_request_authority is False
    assert bundle.statement.finding_authority is False
    assert bundle.statement.graph_admission_authority is False
    assert bundle.statement.retry_authority is False
    assert bundle.digest == issued.bundle_digest
    assert bundle.statement.expires_at - bundle.statement.issued_at == timedelta(seconds=180)
    public_key = Ed25519PublicKey.from_public_bytes(
        _decode_base64url(anchor.keys[0].public_key_base64url)
    )
    public_key.verify(
        _decode_base64url(bundle.signature_base64url),
        authorization_statement_signing_bytes_v2(bundle.statement),
    )
    private_seed = provisioned.private_key_file.read_bytes()
    assert private_seed not in provisioned.trust_anchor_file.read_bytes()
    assert private_seed not in bundle_content


def test_main_v2_verifier_accepts_offline_bundle(
    tmp_path: Path,
    main_v2_context: SimpleNamespace,
) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request_path = request_directory / "request.json"
    _write_owner_file(
        request_path,
        canonical_json_bytes(
            main_v2_context.request.model_dump(mode="json", by_alias=True),
            label="test main v2 authorization request",
        )
        + b"\n",
    )

    issued = offline_authority.issue_authorization_bundle(
        private_key_file=provisioned.private_key_file,
        trust_anchor_file=provisioned.trust_anchor_file,
        trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
        authorization_request_file=request_path,
        signed_bundle_file=issued_directory / "authorization.json",
        lifetime_seconds=120,
    )

    anchor = parse_web_analysis_one_call_authorization_trust_anchor(
        provisioned.trust_anchor_file.read_bytes()
    )
    bundle = parse_signed_web_analysis_one_call_authorization_v2(
        issued.signed_bundle_file.read_bytes()
    )
    verifier = WebAnalysisOneCallAuthorizationVerifierV2(
        trust_anchor=anchor,
        expected_trust_anchor_digest=provisioned.trust_anchor_digest,
        clock=lambda: bundle.statement.issued_at + timedelta(seconds=1),
    )
    verified = verifier.verify(
        bundle,
        admission=main_v2_context.admission,
        live_request=main_v2_context.live_request,
        capacity_pin=main_v2_context.capacity_pin,
        lineage_transport_pin=main_v2_context.transport_pin,
        compact_runtime_pin=main_v2_context.compact_runtime,
        compact_transport_pin=main_v2_context.compact_transport,
    )

    assert verified.authorization_envelope_digest == issued.bundle_digest
    assert verified.statement_sha256 == bundle.statement_sha256
    assert verified.issuer_signature_verified is True
    assert verified.dispatch_ready is False


def test_provision_and_issue_never_replace_existing_outputs(tmp_path: Path) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request_path, _ = _write_request(request_directory)
    bundle_path = issued_directory / "authorization.json"

    with pytest.raises(offline_authority.OfflineAuthorizationError, match="already exists"):
        _provision(authority_directory)
    offline_authority.issue_authorization_bundle(
        private_key_file=provisioned.private_key_file,
        trust_anchor_file=provisioned.trust_anchor_file,
        trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
        authorization_request_file=request_path,
        signed_bundle_file=bundle_path,
        lifetime_seconds=60,
    )
    original = bundle_path.read_bytes()
    with pytest.raises(offline_authority.OfflineAuthorizationError, match="already exists"):
        offline_authority.issue_authorization_bundle(
            private_key_file=provisioned.private_key_file,
            trust_anchor_file=provisioned.trust_anchor_file,
            trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
            authorization_request_file=request_path,
            signed_bundle_file=bundle_path,
            lifetime_seconds=60,
        )
    assert bundle_path.read_bytes() == original


@pytest.mark.parametrize("unsafe_kind", ["mode", "symlink", "hardlink"])
def test_issue_rejects_unsafe_private_key_files(tmp_path: Path, unsafe_kind: str) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request_path, _ = _write_request(request_directory)
    private_key_file = provisioned.private_key_file
    if unsafe_kind == "mode":
        private_key_file.chmod(0o640)
    elif unsafe_kind == "symlink":
        linked = authority_directory / "linked.seed"
        linked.symlink_to(private_key_file)
        private_key_file = linked
    else:
        linked = authority_directory / "linked.seed"
        os.link(private_key_file, linked)
        private_key_file = linked

    with pytest.raises(offline_authority.OfflineAuthorizationError):
        offline_authority.issue_authorization_bundle(
            private_key_file=private_key_file,
            trust_anchor_file=provisioned.trust_anchor_file,
            trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
            authorization_request_file=request_path,
            signed_bundle_file=issued_directory / "authorization.json",
            lifetime_seconds=60,
        )
    assert not (issued_directory / "authorization.json").exists()


def test_issue_rejects_noncanonical_request_and_wrong_retained_digest(tmp_path: Path) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request = _authorization_request()
    request_path = request_directory / "request.json"
    _write_owner_file(
        request_path,
        (json.dumps(request.model_dump(mode="json", by_alias=True), indent=2) + "\n").encode(),
    )
    with pytest.raises(offline_authority.OfflineAuthorizationError, match="exact canonical"):
        offline_authority.issue_authorization_bundle(
            private_key_file=provisioned.private_key_file,
            trust_anchor_file=provisioned.trust_anchor_file,
            trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
            authorization_request_file=request_path,
            signed_bundle_file=issued_directory / "noncanonical.json",
            lifetime_seconds=60,
        )

    _write_owner_file(
        request_path,
        canonical_json_bytes(
            request.model_dump(mode="json", by_alias=True),
            label="test authorization request",
        )
        + b"\n",
    )
    _write_owner_file(provisioned.trust_anchor_digest_file, ("0" * 64 + "\n").encode())
    with pytest.raises(offline_authority.OfflineAuthorizationError, match="digest differs"):
        offline_authority.issue_authorization_bundle(
            private_key_file=provisioned.private_key_file,
            trust_anchor_file=provisioned.trust_anchor_file,
            trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
            authorization_request_file=request_path,
            signed_bundle_file=issued_directory / "wrong-digest.json",
            lifetime_seconds=60,
        )


def test_issue_rejects_v1_statement_and_request_discriminator(
    tmp_path: Path,
    main_v2_context: SimpleNamespace,
) -> None:
    authority_directory = _owner_dir(tmp_path / "authority")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    provisioned = _provision(authority_directory)
    request_path = request_directory / "request.json"
    v1_statement = _v1_statement(main_v2_context)
    v1_request = main_v2_context.request.model_dump(mode="json", by_alias=True)
    v1_request["apiVersion"] = "pajin.dev/web-analysis-one-call-authorization-request/v1alpha1"
    v1_request["kind"] = "WebAnalysisOneCallAuthorizationRequest"

    for output_name, payload in (
        (
            "v1-statement.json",
            v1_statement.model_dump(mode="json", by_alias=True),
        ),
        ("v1-request.json", v1_request),
    ):
        _write_owner_file(
            request_path,
            canonical_json_bytes(payload, label=output_name) + b"\n",
        )
        output_path = issued_directory / output_name
        with pytest.raises(offline_authority.OfflineAuthorizationError, match="request is invalid"):
            offline_authority.issue_authorization_bundle(
                private_key_file=provisioned.private_key_file,
                trust_anchor_file=provisioned.trust_anchor_file,
                trust_anchor_digest_file=provisioned.trust_anchor_digest_file,
                authorization_request_file=request_path,
                signed_bundle_file=output_path,
                lifetime_seconds=60,
            )
        assert not output_path.exists()


def test_issue_rejects_private_key_that_does_not_match_anchor(tmp_path: Path) -> None:
    first_directory = _owner_dir(tmp_path / "first")
    second_directory = _owner_dir(tmp_path / "second")
    request_directory = _owner_dir(tmp_path / "request")
    issued_directory = _owner_dir(tmp_path / "issued")
    first = _provision(first_directory)
    second = _provision(second_directory)
    request_path, _ = _write_request(request_directory)

    assert first.private_key_file.read_bytes() != second.private_key_file.read_bytes()
    with pytest.raises(offline_authority.OfflineAuthorizationError, match="does not match"):
        offline_authority.issue_authorization_bundle(
            private_key_file=first.private_key_file,
            trust_anchor_file=second.trust_anchor_file,
            trust_anchor_digest_file=second.trust_anchor_digest_file,
            authorization_request_file=request_path,
            signed_bundle_file=issued_directory / "authorization.json",
            lifetime_seconds=60,
        )


def test_fresh_interpreter_offline_import_graph_loads_no_pajin_modules(
    tmp_path: Path,
) -> None:
    package_root = (
        Path(__file__).resolve().parents[1] / "offline" / "web_analysis_authorization" / "src"
    )
    script = "\n".join(
        (
            "import importlib",
            "import sys",
            "sys.path.insert(0, sys.argv[1])",
            "package = importlib.import_module('pajin_web_analysis_authorization_offline')",
            "cli = importlib.import_module('pajin_web_analysis_authorization_offline.cli')",
            "importlib.import_module('pajin_web_analysis_authorization_offline.contracts')",
            "cli.build_parser()",
            "forbidden = sorted(name for name in sys.modules "
            "if name == 'pajin' or name.startswith('pajin.'))",
            "if forbidden: raise SystemExit('forbidden imports: ' + ','.join(forbidden))",
            "assert package.__name__ == 'pajin_web_analysis_authorization_offline'",
        )
    )
    completed = subprocess.run(
        [sys.executable, "-I", "-c", script, str(package_root)],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr


def test_offline_distribution_has_no_pajin_dependency_or_secret_input_path() -> None:
    project_root = Path(__file__).resolve().parents[1] / "offline" / "web_analysis_authorization"
    project = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
    dependencies = project["project"]["dependencies"]
    assert all(not dependency.casefold().startswith("pajin") for dependency in dependencies)

    sources = tuple(
        path.read_text(encoding="utf-8") for path in sorted((project_root / "src").rglob("*.py"))
    )
    nodes = tuple(node for source in sources for node in ast.walk(ast.parse(source)))
    imported_modules = {
        imported.name for node in nodes if isinstance(node, ast.Import) for imported in node.names
    } | {
        node.module
        for node in nodes
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module is not None
    }
    assert not any(module == "pajin" or module.startswith("pajin.") for module in imported_modules)
    assert not any(
        isinstance(node, ast.Attribute)
        and isinstance(node.value, ast.Name)
        and (node.value.id, node.attr) in {("os", "environ"), ("sys", "stdin")}
        for node in nodes
    )
    assert not any(
        isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "input"
        for node in nodes
    )
    with pytest.raises(SystemExit):
        cli_module.build_parser().parse_args(["issue", "--private-key", "secret-material"])
