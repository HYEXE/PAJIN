from __future__ import annotations

import json
import os
import struct
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path

import pytest

from pajin.application_elf.capability import elf_capability_bundle
from pajin.application_elf.models import ELFHeader, ELFInput
from pajin.application_elf.parser import parse_header
from pajin.application_elf.runtime import (
    ELFGateway,
    SignedELFApproval,
    dispatch_elf_action,
)
from pajin.application_elf.tool import ELFHeaderTool
from pajin.capabilities.authorities import CapabilityAuthorityRole
from pajin.runtime.worker import WorkerResult, WorkerStatus
from tests.app_002_support import fixture_action, private_custody, seeded_elf

IMAGE = "sha256:" + "a" * 64
PARSER = sha256(Path("src/pajin/application_elf/parser.py").read_bytes()).hexdigest()


@pytest.mark.parametrize("machine", (62, 183))
@pytest.mark.parametrize("kind", (1, 2, 3))
def test_real_structural_fields(machine, kind):
    header = ELFHeader.model_validate(parse_header(seeded_elf(machine=machine, kind=kind)))
    assert header.machine == ("x86-64" if machine == 62 else "aarch64")
    assert header.elf_type == {1: "relocatable", 2: "executable", 3: "shared-object"}[kind]
    assert header.entry_point == "0x0000000000401080"


@pytest.mark.parametrize(
    "offset,content",
    (
        (0, b"FAIL"),
        (4, b"\x01"),
        (5, b"\x02"),
        (6, b"\x02"),
        (15, b"\x01"),
        (16, b"\x04\x00"),
        (18, b"\x03\x00"),
        (20, b"\x02"),
        (52, b"\x3f"),
        (56, b"\xff\xff"),
        (62, b"\xff\xff"),
        (40, b"\x40"),
        (32, b"\x40"),
        (56, b"\x01"),
        (60, b"\x01"),
        (62, b"\x01"),
    ),
)
def test_unsupported_and_truncated_formats_fail_closed(offset, content):
    modified = bytearray(seeded_elf())
    modified[offset : offset + len(content)] = content
    with pytest.raises(ValueError, match="ELF"):
        parse_header(bytes(modified))


@pytest.mark.parametrize("content", (b"", seeded_elf()[:63], seeded_elf() + bytes(262145)))
def test_byte_limits(content):
    with pytest.raises(ValueError, match="byte count"):
        parse_header(content)


def test_real_table_bounds_and_full_uint64_entry():
    content = bytearray(seeded_elf(entry=2**64 - 1)) + bytes(56)
    struct.pack_into("<Q", content, 32, 64)
    struct.pack_into("<HH", content, 54, 56, 1)
    result = parse_header(bytes(content))
    assert result["programHeaderCount"] == 1 and result["entryPoint"] == "0xffffffffffffffff"
    with pytest.raises(ValueError, match="outside"):
        parse_header(bytes(content[:-1]))


def test_custody_checks_real_bytes_links_size_and_authorization(tmp_path):
    custody, value = private_custody(tmp_path / "custody", seeded_elf())
    path = custody.directory / (value.artifact_sha256 + ".elf")
    assert custody.read(value) == seeded_elf()
    with pytest.raises(ValueError, match="not authorized"):
        custody.read(ELFInput(artifactSha256="b" * 64, artifactBytes=64))
    path.write_bytes(b"!" + seeded_elf()[1:])
    with pytest.raises(ValueError, match="digest differs"):
        custody.read(value)
    path.write_bytes(seeded_elf()[:-1])
    with pytest.raises(ValueError, match="byte contract"):
        custody.read(value)
    path.write_bytes(seeded_elf())
    path.chmod(0o644)
    with pytest.raises(ValueError, match="byte contract"):
        custody.read(value)
    path.chmod(0o600)
    os.link(path, tmp_path / "extra")
    with pytest.raises(ValueError, match="byte contract"):
        custody.read(value)
    (tmp_path / "extra").unlink()
    path.rename(tmp_path / "original")
    path.symlink_to(tmp_path / "original")
    with pytest.raises(OSError):
        custody.read(value)


def test_complete_capability_roles_and_inert_reader(tmp_path):
    custody, value = private_custody(tmp_path / "custody", seeded_elf())
    tool = ELFHeaderTool(custody, image_id=IMAGE, parser_sha256=PARSER)
    bundle = elf_capability_bundle(tool)
    assert len(bundle.authorities.capabilities()[0].authorities) == len(CapabilityAuthorityRole)
    action, *_ = fixture_action(tmp_path / "action", tool, value)
    inert = ELFHeaderTool(None, image_id=IMAGE, parser_sha256=PARSER)
    assert elf_capability_bundle(inert).reference == bundle.reference
    with pytest.raises(ValueError, match="custody authorization"):
        inert.prepare(action.request)


class FailingWorker:
    """Unit-only failure injection; real-Docker conformance is a separately executed suite."""

    name = "app-unit-failure"

    def __init__(self):
        self.calls = 0

    async def run(self, job, *, secrets=()):
        self.calls += 1
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend=self.name,
            status=WorkerStatus.FAILED,
            exit_code=2,
            stderr="unsupported ELF",
            started_at=now,
            finished_at=now,
        )


def setup_action(tmp_path):
    custody, value = private_custody(tmp_path / "custody", seeded_elf())
    tool = ELFHeaderTool(custody, image_id=IMAGE, parser_sha256=PARSER)
    action, authority, graph, store = fixture_action(tmp_path / "action", tool, value)
    worker = FailingWorker()
    gateway = ELFGateway(tool, store)
    gateway._worker = worker  # Unit-only failure injection, never a live-conformance substitute.
    return action, authority, graph, store, gateway, worker


@pytest.mark.asyncio
async def test_durable_permit_charges_failed_worker_and_prevents_duplicate(tmp_path):
    action, authority, graph, store, gateway, worker = setup_action(tmp_path)
    outcome = await dispatch_elf_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert outcome.executed and not outcome.result.success
    retry = await dispatch_elf_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert retry is None and worker.calls == 1
    assert len(graph.permit_store.permits()) == len(graph.permit_store.action_approvals()) == 1
    assert (store.path / "authorization.json").exists()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case", ("signature", "key", "expired", "scope", "request", "release-code")
)
async def test_authority_denial_precedes_custody_read_or_worker(tmp_path, monkeypatch, case):
    action, authority, graph, store, gateway, worker = setup_action(tmp_path)
    if case == "signature":
        authority.signed = SignedELFApproval(
            approval=authority.signed.approval, signature="0" * 128
        )
    elif case == "key":
        authority.public_key = bytes(32)
    elif case == "expired":
        authority.clock = lambda: datetime.now(UTC) + timedelta(minutes=6)
    elif case == "scope":
        authority.campaign.spec.scope.allow.clear()
    elif case == "request":
        action = replace(action, request=action.request.model_copy(update={"method": "POST"}))
    else:
        authority.tool.parser_sha256 = "c" * 64

    def never_read(*_args):
        pytest.fail("unauthorized custody read")

    monkeypatch.setattr(type(authority.tool.custody), "read", never_read)
    with pytest.raises((ValueError, RuntimeError)):
        await dispatch_elf_action(
            action=action, authority=authority, graph=graph, gateway=gateway, store=store
        )
    assert worker.calls == 0 and graph.permit_store.permits() == ()


@pytest.mark.asyncio
async def test_wrong_custody_digest_is_charged_without_worker(tmp_path):
    action, authority, graph, store, gateway, worker = setup_action(tmp_path)
    value = ELFInput.model_validate(action.request.arguments)
    (authority.tool.custody.directory / (value.artifact_sha256 + ".elf")).write_bytes(bytes(64))
    outcome = await dispatch_elf_action(
        action=action, authority=authority, graph=graph, gateway=gateway, store=store
    )
    assert not outcome.executed and not outcome.result.success and worker.calls == 0
    assert len(graph.permit_store.permits()) == 1


@pytest.mark.parametrize(
    "field,value", (("path", "/tmp/a"), ("command", "sh"), ("artifactBytes", True))
)
def test_no_path_command_or_integer_coercion(field, value):
    raw = {"artifactSha256": "a" * 64, "artifactBytes": 64, field: value}
    with pytest.raises(ValueError):
        ELFInput.model_validate(raw)


def test_worker_payload_does_not_leak_content_into_request(tmp_path):
    action, authority, *_ = setup_action(tmp_path)
    job = authority.tool.prepare(action.request)
    wire = json.loads(job.stdin)
    assert set(wire) == {"pajinEnvelopeVersion", "payload", "secrets"}
    assert wire["pajinEnvelopeVersion"] == 1 and wire["secrets"] == {}
    assert set(wire["payload"]) == {"content", "sha256", "bytes"}
    assert set(action.request.arguments) == {"artifactSha256", "artifactBytes"}
    assert job.network.value == "none" and job.secret_requests == []
    assert job.command == ["elf-header-read"] and job.image == IMAGE
