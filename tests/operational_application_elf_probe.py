"""Explicit real-Docker APP-002 fixture suite, run by scripts/operational_application_elf.py."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from pajin.application_elf.models import ELFInput
from pajin.application_elf.report import (
    ELFReportTrust,
    compare_elf_runs,
    read_elf_run,
    seal_elf_execution,
)
from pajin.application_elf.runtime import ELFGateway, SignedELFApproval, dispatch_elf_action
from pajin.application_elf.tool import ELFHeaderTool
from pajin.graph.approval import ActionApprovalError
from pajin.runtime.worker import DockerWorkerBackend
from tests.app_002_support import (
    fixture_action,
    local_fixture_activation,
    private_custody,
    seeded_elf,
)


def write_private(path: Path, value: object) -> None:
    with path.open("x", encoding="utf-8") as handle:
        path.chmod(0o600)
        json.dump(value, handle, indent=2, sort_keys=True)


class TrackedDockerWorker(DockerWorkerBackend):
    """Observe execution IDs; DockerWorkerBackend owns actual execution and cleanup."""

    def __init__(self, image):
        super().__init__(allowed_images={image})
        self.jobs = []

    async def run(self, job, *, secrets=()):
        self.jobs.append(job)
        return await super().run(job, secrets=secrets)


@pytest.fixture(scope="module")
def deployment():
    root = Path(os.environ["PAJIN_APP002_ROOT"])
    image = os.environ["PAJIN_APP002_IMAGE"]
    if not root.is_dir() or not (root / "owned-fixture-suite.json").is_file():
        raise ValueError("real APP-002 suite requires a separately created owned fixture root")
    pin = sha256(Path("src/pajin/application_elf/parser.py").read_bytes()).hexdigest()
    tool = ELFHeaderTool(None, image_id=image, parser_sha256=pin)
    activation = local_fixture_activation(tool)
    operator = Ed25519PrivateKey.generate()
    policy, keys, releases = activation.lifecycle.verification_material()
    trust = ELFReportTrust(
        image_id=image,
        parser_sha256=pin,
        operator_public_key=operator.public_key().public_bytes_raw().hex(),
        operator_id="app-002-fixture-operator",
        policy=policy,
        keys=keys,
        releases=releases,
        release=activation.release,
    )
    write_private(root / "deployment-trust.json", trust.model_dump(mode="json", by_alias=True))
    write_private(root / "deployment-checkpoint.json", {"trustDigest": trust.commitment})
    return root, image, activation, operator, trust


def prepare_case(deployment, name, content):
    root, image, activation, operator, trust = deployment
    case_root = root / name
    custody, value = private_custody(case_root / "custody", content)
    tool = ELFHeaderTool(custody, image_id=image, parser_sha256=trust.parser_sha256)
    action, authority, graph, store = fixture_action(root, tool, value, activation, operator)
    worker = TrackedDockerWorker(image)
    gateway = ELFGateway(tool, store)
    gateway._worker = worker  # Observes IDs while preserving the real Docker run implementation.
    return action, authority, graph, store, worker, gateway, case_root


async def run_case(deployment, name, content):
    action, authority, graph, store, worker, gateway, case_root = prepare_case(
        deployment, name, content
    )
    outcome = await dispatch_elf_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert outcome is not None
    assert len(graph.permit_store.permits()) == len(graph.permit_store.action_approvals()) == 1
    assert (
        await dispatch_elf_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
        is None
    )
    reference = seal_elf_execution(store, outcome, deployment[-1])
    write_private(case_root / "reference.json", reference.model_dump())
    report = read_elf_run(deployment[0] / "runs", reference, deployment[-1])
    write_private(case_root / "report.json", report)
    assert all(
        not subprocess.run(
            [
                "docker",
                "ps",
                "--all",
                "--filter",
                "label=pajin.execution-id=" + job.execution_id,
                "--format",
                "{{.ID}}",
            ],
            capture_output=True,
            check=True,
        ).stdout.strip()
        for job in worker.jobs
    )
    return reference, report


@pytest.mark.asyncio
@pytest.mark.parametrize("architecture", ("x86_64", "aarch64"))
async def test_compiled_elf_source_fresh_reexecution_and_llvm_oracle(deployment, architecture):
    root = deployment[0]
    compiled = root / (architecture + ".o")
    subprocess.run(
        [
            "clang",
            "-target",
            architecture + "-linux-gnu",
            "-x",
            "c",
            "-c",
            "-o",
            str(compiled),
            "-",
        ],
        check=True,
        capture_output=True,
        timeout=30,
        input=b"int app002_fixture(int x) { return x + 3; }\n",
    )
    compiled.chmod(0o600)
    content = compiled.read_bytes()
    llvm = subprocess.run(
        ["objdump", "--file-headers", "--section-headers", str(compiled)],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    ).stdout
    expected_sections = len(re.findall(r"^\s+\d+\s+.*[0-9a-f]{8}\s+[0-9a-f]{16}", llvm, re.M))
    expected_entry = re.search(r"start address: (0x[0-9a-f]{16})", llvm).group(1)
    assert "architecture: " + architecture in llvm and "file format elf64-" in llvm
    source, source_report = await run_case(deployment, architecture + "-source", content)
    replay, replay_report = await run_case(deployment, architecture + "-replay", content)
    comparison = compare_elf_runs(root / "runs", source, replay, deployment[-1])
    assert comparison["complete"] and comparison["headerMatch"]
    header = source_report["header"]
    assert header == replay_report["header"]
    assert header["machine"] == ("x86-64" if architecture == "x86_64" else "aarch64")
    assert header["type"] == "relocatable" and header["class"] == 64
    assert header["sectionHeaderCount"] == expected_sections and expected_sections > 1
    assert header["entryPoint"] == expected_entry
    write_private(
        root / (architecture + "-llvm-oracle.json"),
        {
            "artifactSha256": sha256(content).hexdigest(),
            "artifactBytes": len(content),
            "compiler": "clang -target <architecture>-linux-gnu -c fixed-source",
            "oracle": "LLVM objdump --file-headers --section-headers",
            "observedMachine": architecture,
            "observedEntry": expected_entry,
            "observedSectionCount": expected_sections,
            "independentlyCheckedFields": ["class", "machine", "entryPoint", "sectionHeaderCount"],
            "compilerContractCheckedFields": ["type"],
            "allHeaderFieldsIndependentlyVerified": False,
        },
    )
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pajin.application_elf",
            "--root",
            str(root / "runs"),
            "--trust",
            str(root / "deployment-trust.json"),
            "--trust-digest",
            deployment[-1].commitment,
            "--source-ref",
            str(root / (architecture + "-source") / "reference.json"),
            "--replay-ref",
            str(root / (architecture + "-replay") / "reference.json"),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    fresh = json.loads(result.stdout)
    assert fresh == comparison
    write_private(root / (architecture + "-fresh-report.json"), fresh)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case,content",
    (
        ("bad-magic", bytes(64)),
        ("unsupported-machine", seeded_elf(machine=3)),
        ("bad-table", seeded_elf()[:56] + b"\x01\x00" + seeded_elf()[58:]),
    ),
)
async def test_actual_parser_failure_is_sealed_and_cleaned(deployment, case, content):
    _, report = await run_case(deployment, case, content)
    assert report["workerExecuted"] and not report["complete"]
    assert report["header"] is None and report["cleanup"] == "absent"


@pytest.mark.asyncio
async def test_maximum_input_is_read_without_truncation_or_persistent_resources(deployment):
    _, report = await run_case(deployment, "maximum-input", seeded_elf() + bytes(262_144 - 64))
    assert report["complete"] and report["header"]["artifactBytes"] == 262_144
    assert report["cleanup"] == "absent"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case",
    (
        "signature-denied",
        "scope-denied",
        "replacement-image-denied",
        "replacement-parser-denied",
        "missing-artifact",
        "digest-drift",
    ),
)
async def test_authority_and_custody_denials_never_dispatch_worker(deployment, case):
    action, authority, graph, store, worker, gateway, root = prepare_case(
        deployment, case, seeded_elf()
    )
    if case == "signature-denied":
        authority.signed = SignedELFApproval(
            approval=authority.signed.approval, signature="0" * 128
        )
    elif case == "scope-denied":
        authority.campaign.spec.scope.deny.append(action.request.target)
    elif case in {"replacement-image-denied", "replacement-parser-denied"}:
        replacement = ELFHeaderTool(
            authority.tool.custody,
            image_id="sha256:" + "d" * 64
            if case == "replacement-image-denied"
            else authority.tool.image_id,
            parser_sha256="d" * 64
            if case == "replacement-parser-denied"
            else authority.tool.parser_sha256,
        )
        authority.tool = replacement
        gateway = ELFGateway(replacement, store)
        gateway._worker = worker
    else:
        value = ELFInput.model_validate(action.request.arguments)
        path = authority.tool.custody.directory / (value.artifact_sha256 + ".elf")
        if case == "missing-artifact":
            path.rename(root / "retained-displaced-fixture.elf")
        else:
            path.write_bytes(bytes(64))
    if case.endswith("denied"):
        with pytest.raises((ValueError, ActionApprovalError)):
            await dispatch_elf_action(
                action=action, authority=authority, graph=graph, gateway=gateway, store=store
            )
        assert graph.permit_store.permits() == ()
        store.append_event("app-002.expected-denial", {"case": case, "workerCreated": False})
        store.seal()
    else:
        outcome = await dispatch_elf_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
        assert not outcome.executed and not outcome.result.success
        reference = seal_elf_execution(store, outcome, deployment[-1])
        report = read_elf_run(deployment[0] / "runs", reference, deployment[-1])
        assert not report["complete"] and report["cleanup"] == "not-created"
        write_private(root / "report.json", report)
    assert worker.jobs == []
