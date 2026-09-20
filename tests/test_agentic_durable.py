from __future__ import annotations

import os
import shutil
import sqlite3
import subprocess
import sys
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier

import pytest
from pydantic import ValidationError

from pajin.agentic.durable import (
    AgenticCommandAdmissionReceipt,
    AgenticCoordinationBinding,
    AgenticCoordinationError,
    AgenticCoordinationStore,
    AgenticHypothesisInvocationIntent,
    AgenticHypothesisReceiptPublication,
    AgenticHypothesisRequestBinding,
    AgenticModelInvocationState,
    AgenticOutboxState,
    build_agentic_hypothesis_invocation_receipt,
    build_agentic_hypothesis_request_binding,
)
from pajin.agentic.durable_graph import (
    CurrentGraphHeadResolver,
    VerifiedCurrentGraphHead,
)
from pajin.agentic.models import AgentControlCommandKind, AgentEvent, AgentEventKind
from pajin.agentic.runtime import HypothesisExpansionContext, build_hypothesis_model_projection
from pajin.agentic.supervisor import DynamicSupervisor, DynamicSupervisorPolicy
from pajin.discovery.canonicalization import canonical_json_bytes, discovery_digest
from pajin.graph import (
    GraphAdmissionAuthority,
    GraphProducerRegistration,
    GraphProducerRegistry,
    GraphProjectionCoordinator,
    GraphProposalKind,
    GraphProposalLineage,
    GraphSnapshot,
    GraphSnapshotAuthority,
    GraphSnapshotReason,
    SQLiteGraphStore,
    SurfaceProposal,
    TrustedGraphLineageRegistry,
    graph_snapshot_ref,
)
from pajin.graph.models import HypothesisProposal as GraphHypothesisProposal
from pajin.runtime.store import RunStore
from tests.test_agentic_campaign import (
    CAMPAIGN,
    ROOT_EDGES,
    ROOT_SURFACE,
    ROOT_XSS,
    TARGET,
    _candidate,
    _expansion_context,
    _exploit_group,
)

SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64
SHA_D = "d" * 64
SHA_E = "e" * 64
SHA_F = "f" * 64
SHA_G = "0" * 64
NOW = datetime(2026, 9, 18, 1, 0, tzinfo=UTC)
PLANNED_RUN_ID = "run_20260918T010000Z_01234567"
PLANNED_RUN_PATH = Path("/private/tmp/pajin-agentic-planned") / PLANNED_RUN_ID


@dataclass(frozen=True, slots=True)
class DurableHarness:
    store: AgenticCoordinationStore
    binding: AgenticCoordinationBinding
    supervisor: DynamicSupervisor
    initial_head: object
    cycle: object
    snapshot: GraphSnapshot
    resolver: CurrentGraphHeadResolver
    graph_head: VerifiedCurrentGraphHead


def _lineage(tag: str, *, producer_digest: str) -> GraphProposalLineage:
    digest = discovery_digest("pajin.agentic.durable-test-lineage/v1", {"tag": tag})
    return GraphProposalLineage(
        campaignId=CAMPAIGN,
        runId=f"run:agentic-durable:{tag}",
        agentId="agent:agentic-durable-fixture",
        taskId=f"task:agentic-durable:{tag}",
        requestId=f"agentic_durable_{tag}",
        requestDigest=digest,
        capabilityGrantId=f"grant:agentic-durable:{tag}",
        capabilityGrantDigest=producer_digest,
        capabilityId="capability:agentic-durable-graph-fixture",
        capabilityVersion="1.0.0",
        capabilityDigest=SHA_C,
        sourceRootDigest=SHA_D,
        evidence=[
            {
                "reference": f"evidence/agentic-durable-{tag}.json",
                "sha256": digest,
            }
        ],
        producedAt=NOW,
    )


def _seed_current_graph(path: Path) -> GraphSnapshot:
    surface_producer_id = "pajin.agentic.durable-surface-fixture"
    surface_producer_digest = SHA_F
    surface = SurfaceProposal(
        proposalId="proposal:agentic-durable:surface",
        producerId=surface_producer_id,
        producerVersion="1.0.0",
        producerDigest=surface_producer_digest,
        lineage=_lineage("surface", producer_digest=surface_producer_digest),
        surface=ROOT_SURFACE,
    )
    hypothesis = GraphHypothesisProposal(
        proposalId="proposal:agentic-durable:hypothesis",
        producerId=ROOT_XSS.producer_id,
        producerVersion=ROOT_XSS.producer_version,
        producerDigest=ROOT_XSS.producer_digest,
        lineage=_lineage("hypothesis", producer_digest=ROOT_XSS.producer_digest),
        hypothesis=ROOT_XSS,
        edges=[ROOT_EDGES[0]],
    )
    store = SQLiteGraphStore(path, campaign_id=CAMPAIGN)
    admission = GraphAdmissionAuthority(
        campaign_id=CAMPAIGN,
        authority_id="pajin.agentic.durable-test-admission",
        authority_digest=SHA_A,
        producers=GraphProducerRegistry(
            (
                GraphProducerRegistration(
                    producerId=surface_producer_id,
                    producerVersion="1.0.0",
                    producerDigest=surface_producer_digest,
                    allowedProposalKinds=(GraphProposalKind.SURFACE,),
                ),
                GraphProducerRegistration(
                    producerId=ROOT_XSS.producer_id,
                    producerVersion=ROOT_XSS.producer_version,
                    producerDigest=ROOT_XSS.producer_digest,
                    allowedProposalKinds=(GraphProposalKind.HYPOTHESIS,),
                ),
            )
        ),
        lineage_verifier=TrustedGraphLineageRegistry((surface.lineage, hypothesis.lineage)),
        event_log=store.event_log,
        clock=lambda: NOW + timedelta(seconds=1),
    )
    admission.submit(surface)
    admission.submit(hypothesis)
    GraphProjectionCoordinator(
        event_log=store.event_log,
        projection_store=store.projection_store,
    ).refresh()
    authority = GraphSnapshotAuthority(
        creator_id="pajin.agentic.durable-test-snapshot",
        creator_digest=SHA_B,
        projection_store=store.projection_store,
        snapshot_store=store.snapshot_store,
        clock=lambda: NOW + timedelta(seconds=2),
    )
    return authority.capture(GraphSnapshotReason.CHECKPOINT)


def _context(snapshot: GraphSnapshot) -> HypothesisExpansionContext:
    wire = _expansion_context().model_dump(mode="json", by_alias=True)
    wire.pop("contextId")
    wire.pop("contextDigest")
    wire["sourceSnapshotId"] = snapshot.snapshot_id
    wire["sourceSnapshotDigest"] = snapshot.snapshot_digest
    return HypothesisExpansionContext.model_validate(wire)


def _request_binding(
    snapshot: GraphSnapshot,
    *,
    planned_run_id: str = PLANNED_RUN_ID,
    planned_run_path: Path = PLANNED_RUN_PATH,
) -> AgenticHypothesisRequestBinding:
    projection = build_hypothesis_model_projection(_context(snapshot), source_snapshot=snapshot)
    return build_agentic_hypothesis_request_binding(
        projection,
        provider_id="local-test",
        model_id="test-model-v1",
        provider_model_digest=SHA_A,
        model_configuration_digest=SHA_B,
        provider_runtime_digest=SHA_C,
        capability_grant_digest=SHA_D,
        campaign_budget_policy_digest=SHA_E,
        campaign_budget_state_digest=SHA_F,
        dedicated_budget_policy_digest=SHA_G,
        max_completion_tokens=1024,
        planned_provider_run_id=planned_run_id,
        planned_provider_run_path=planned_run_path,
    )


def _make_harness(tmp_path: Path, name: str) -> DurableHarness:
    graph_path = tmp_path / f"{name}-graph" / "canonical.sqlite3"
    snapshot = _seed_current_graph(graph_path)
    resolver = CurrentGraphHeadResolver(graph_path, campaign_id=CAMPAIGN)
    graph_head = resolver.resolve(graph_snapshot_ref(snapshot))
    policy = DynamicSupervisorPolicy(beamWidth=1, minScoreBps=0)
    supervisor = DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id="agent:dynamic-supervisor",
        source_snapshot=snapshot,
        allowed_target_ids=(TARGET,),
        exploit_group=_exploit_group(),
        policy=policy,
    )
    initial = supervisor.checkpoint()
    cycle = supervisor.plan_cycle(
        (
            _candidate(
                name,
                snapshot_id=snapshot.snapshot_id,
                snapshot_digest=snapshot.snapshot_digest,
            ),
        )
    )
    binding = AgenticCoordinationBinding.from_checkpoint(
        initial,
        control_plane_run_id=f"agentic-control-plane:{name}",
        campaign_manifest_digest=SHA_A,
        deployment_digest=SHA_B,
        exploit_group=supervisor.exploit_group,
        supervisor_policy=supervisor.policy,
        scoring_policy=supervisor.scorer.policy,
    )
    store_id = sha256(name.encode()).hexdigest()[:32]
    store = AgenticCoordinationStore(
        tmp_path / f"{name}-coordination.sqlite3",
        binding=binding,
        graph_resolver=resolver,
        graph_head=graph_head,
        clock=lambda: NOW + timedelta(seconds=10),
        store_id_factory=lambda: f"agentic-store:{store_id}",
    )
    initial_head = store.initialize_head(initial, graph_resolver=resolver, graph_head=graph_head)
    return DurableHarness(
        store, binding, supervisor, initial_head, cycle, snapshot, resolver, graph_head
    )


@pytest.fixture
def harness_factory(tmp_path: Path) -> Iterator[Callable[[str], DurableHarness]]:
    if sys.platform != "linux":
        pytest.skip("authoritative durable coordination requires Linux /proc descriptors")
    resolvers: list[CurrentGraphHeadResolver] = []

    def factory(name: str) -> DurableHarness:
        harness = _make_harness(tmp_path, name)
        resolvers.append(harness.resolver)
        return harness

    yield factory
    for resolver in resolvers:
        resolver.close()


@pytest.mark.skipif(sys.platform == "linux", reason="unsupported-platform contract only")
def test_unsupported_platform_fails_before_coordination_filesystem_mutation(
    tmp_path: Path,
) -> None:
    parent = tmp_path / "must-not-exist"
    with pytest.raises(AgenticCoordinationError, match="Linux descriptor"):
        AgenticCoordinationStore(
            parent / "coordination.sqlite3",
            binding=None,  # type: ignore[arg-type]
            graph_resolver=None,  # type: ignore[arg-type]
            graph_head=None,  # type: ignore[arg-type]
        )
    assert not parent.exists()


def _graph_args(harness: DurableHarness) -> dict[str, object]:
    return {"graph_resolver": harness.resolver, "graph_head": harness.graph_head}


def _publish_cycle(harness: DurableHarness):
    return harness.store.publish_cycle(harness.initial_head, harness.cycle, **_graph_args(harness))


def _admit_and_ack(harness: DurableHarness, claim):
    admission = harness.store.admit_delivery(claim, **_graph_args(harness))
    return admission, harness.store.acknowledge_delivery(claim, admission, **_graph_args(harness))


def _leave_true_hot_journal(path: Path) -> Path:
    script = (
        "import os,sqlite3,sys;"
        "c=sqlite3.connect(sys.argv[1]);"
        "c.execute('PRAGMA journal_mode=DELETE');"
        "c.execute('PRAGMA cache_size=1');"
        "c.execute('PRAGMA cache_spill=ON');"
        "c.execute('BEGIN IMMEDIATE');"
        "c.execute('CREATE TABLE crash_probe(value BLOB)');"
        "c.executemany('INSERT INTO crash_probe(value) VALUES (?)',"
        "((b'x'*4096,) for _ in range(128)));"
        "os._exit(0)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    journal = Path(f"{path}-journal")
    assert journal.is_file()
    assert journal.stat().st_size > 512
    assert journal.read_bytes()[:8] == bytes.fromhex("d9d505f920a163d7")
    return journal


def test_reopen_binding_and_allow_create_false_are_exact_and_non_mutating(
    harness_factory: Callable[[str], DurableHarness], tmp_path: Path
) -> None:
    harness = harness_factory("reopen")
    publication = _publish_cycle(harness)
    before_store = harness.store.path.stat()
    with pytest.raises(AgenticCoordinationError, match="expected store ID"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
        )
    with pytest.raises(AgenticCoordinationError, match="store ID differs"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
            expected_store_id="agentic-store:" + "f" * 32,
        )
    reopened = AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=harness.store.store_id,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    after_store = harness.store.path.stat()
    assert (
        after_store.st_mode,
        after_store.st_ino,
        after_store.st_mtime_ns,
    ) == (
        before_store.st_mode,
        before_store.st_ino,
        before_store.st_mtime_ns,
    )
    assert reopened.store_id == harness.store.store_id
    assert reopened.current_head(**_graph_args(harness)).checkpoint == publication.head.checkpoint
    foreign = AgenticCoordinationBinding.from_checkpoint(
        harness.initial_head.checkpoint,
        control_plane_run_id="agentic-control-plane:reopen",
        campaign_manifest_digest=SHA_A,
        deployment_digest=SHA_C,
        exploit_group=harness.supervisor.exploit_group,
        supervisor_policy=harness.supervisor.policy,
        scoring_policy=harness.supervisor.scorer.policy,
    )
    with pytest.raises(AgenticCoordinationError, match="binding"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=foreign,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
            expected_store_id=harness.store.store_id,
        )

    parent = tmp_path / "already-private"
    parent.mkdir(mode=0o700)
    before = parent.stat()
    with pytest.raises(AgenticCoordinationError, match="missing"):
        AgenticCoordinationStore(
            parent / "missing.sqlite3",
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
            expected_store_id="agentic-store:" + "0" * 32,
        )
    after = parent.stat()
    assert (after.st_mode, after.st_ino, after.st_mtime_ns) == (
        before.st_mode,
        before.st_ino,
        before.st_mtime_ns,
    )


def test_reopen_rejects_wal_mode_and_idle_sidecars(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    wal = harness_factory("wal-reopen")
    connection = sqlite3.connect(wal.store.path)
    try:
        mode = connection.execute("PRAGMA journal_mode = WAL").fetchone()
        assert mode is not None and mode[0] == "wal"
    finally:
        connection.close()
    with pytest.raises(
        AgenticCoordinationError,
        match=r"DELETE|sidecar|pinned database inode|descriptor set changed before attestation",
    ):
        AgenticCoordinationStore(
            wal.store.path,
            binding=wal.binding,
            graph_resolver=wal.resolver,
            graph_head=wal.graph_head,
            allow_create=False,
            expected_store_id=wal.store.store_id,
        )

    sidecar = harness_factory("idle-sidecar")
    unexpected = Path(f"{sidecar.store.path}-wal")
    unexpected.write_bytes(b"not a SQLite WAL")
    unexpected.chmod(0o600)
    with pytest.raises(AgenticCoordinationError, match="sidecar"):
        AgenticCoordinationStore(
            sidecar.store.path,
            binding=sidecar.binding,
            graph_resolver=sidecar.resolver,
            graph_head=sidecar.graph_head,
            allow_create=False,
            expected_store_id=sidecar.store.store_id,
        )


@pytest.mark.parametrize("operation", ("read", "write"))
def test_linux_sqlite_connection_rejects_leaf_swap_back_before_io(
    harness_factory: Callable[[str], DurableHarness],
    monkeypatch: pytest.MonkeyPatch,
    operation: str,
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory(f"leaf-swap-{operation}")
    parent_fd = harness.store._database.parent_fd
    leaf = harness.store.path.name
    parked = f"{leaf}.parked"
    replacement = f"{leaf}.replacement"
    replacement_path = harness.store.path.with_name(replacement)
    shutil.copy2(harness.store.path, replacement_path)
    replacement_path.chmod(0o600)
    replacement_before = replacement_path.read_bytes()
    real_connect = durable_module.sqlite3.connect

    def swapped_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        os.rename(leaf, parked, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.rename(replacement, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        try:
            return real_connect(*args, **kwargs)
        finally:
            os.rename(leaf, replacement, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.rename(parked, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)

    with monkeypatch.context() as scoped:
        scoped.setattr(durable_module.sqlite3, "connect", swapped_connect)
        with pytest.raises(AgenticCoordinationError, match="pinned database inode"):
            if operation == "read":
                harness.store.current_head(**_graph_args(harness))
            else:
                _publish_cycle(harness)
    assert replacement_path.read_bytes() == replacement_before
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_linux_sqlite_connection_rejects_swap_back_with_pinned_inode_decoy(
    harness_factory: Callable[[str], DurableHarness],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("leaf-swap-decoy")
    parent_fd = harness.store._database.parent_fd
    leaf = harness.store.path.name
    parked = f"{leaf}.parked"
    replacement = f"{leaf}.replacement"
    replacement_path = harness.store.path.with_name(replacement)
    shutil.copy2(harness.store.path, replacement_path)
    replacement_path.chmod(0o600)
    real_connect = durable_module.sqlite3.connect
    decoy_descriptors: list[int] = []

    def swapped_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        os.rename(leaf, parked, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.rename(replacement, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        try:
            connection = real_connect(*args, **kwargs)
        finally:
            os.rename(leaf, replacement, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
            os.rename(parked, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        decoy_descriptors.append(
            os.open(
                leaf,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
                dir_fd=parent_fd,
            )
        )
        return connection

    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(durable_module.sqlite3, "connect", swapped_connect)
            with pytest.raises(AgenticCoordinationError, match="pinned database inode"):
                harness.store.current_head(**_graph_args(harness))
    finally:
        for descriptor in decoy_descriptors:
            os.close(descriptor)
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_linux_pinned_leaf_rejects_persistent_replacement(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("persistent-leaf-replacement")
    parent_fd = harness.store._database.parent_fd
    leaf = harness.store.path.name
    parked = f"{leaf}.parked"
    replacement = f"{leaf}.replacement"
    replacement_path = harness.store.path.with_name(replacement)
    shutil.copy2(harness.store.path, replacement_path)
    replacement_path.chmod(0o600)
    os.rename(leaf, parked, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    os.rename(replacement, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    try:
        with pytest.raises(AgenticCoordinationError, match="identity changed"):
            harness.store.current_head(**_graph_args(harness))
    finally:
        os.rename(leaf, replacement, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
        os.rename(parked, leaf, src_dir_fd=parent_fd, dst_dir_fd=parent_fd)
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_linux_pinned_parent_rejects_namespace_replacement(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("persistent-parent-replacement")
    parent = harness.store.path.parent
    parked = parent.with_name(f"{parent.name}-parked")
    os.rename(parent, parked)
    parent.mkdir(mode=0o700)
    try:
        with pytest.raises(AgenticCoordinationError, match="identity changed"):
            harness.store._database.require_idle_exact()
    finally:
        parent.rmdir()
        os.rename(parked, parent)
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_linux_pinned_parent_allows_unrelated_sibling_directory_lifecycle(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("parent-sibling-lifecycle")
    sibling = harness.store.path.parent / "unrelated-sibling"
    sibling.mkdir(mode=0o700)
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )
    sibling.rmdir()
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_closed_and_forked_descriptor_authority_cannot_be_consumed(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    closed = harness_factory("closed-authority")
    closed.store.close()
    with pytest.raises(AgenticCoordinationError, match="closed"):
        closed.store.current_head(**_graph_args(closed))
    closed.store.close()

    concurrently_closed = harness_factory("concurrently-closed-authority")
    close_barrier = Barrier(2)

    def close_store(_: int) -> None:
        close_barrier.wait()
        concurrently_closed.store.close()

    with ThreadPoolExecutor(max_workers=2) as executor:
        tuple(executor.map(close_store, range(2)))
    with pytest.raises(AgenticCoordinationError, match="closed"):
        concurrently_closed.store.current_head(**_graph_args(concurrently_closed))

    inherited = harness_factory("forked-authority")
    read_fd, write_fd = os.pipe()
    child = os.fork()
    if child == 0:
        os.close(read_fd)
        try:
            inherited.store._database.require_open()
        except AgenticCoordinationError as exc:
            payload = b"rejected" if "process fork" in str(exc) else b"wrong-error"
        except BaseException:
            payload = b"unexpected-error"
        else:
            payload = b"accepted"
        os.write(write_fd, payload)
        os.close(write_fd)
        os._exit(0)
    os.close(write_fd)
    try:
        payload = os.read(read_fd, 64)
    finally:
        os.close(read_fd)
    waited, status = os.waitpid(child, 0)
    assert waited == child and os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
    assert payload == b"rejected"


def test_hot_journal_recovers_once_only_during_reopen(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("hot-journal-recovery")
    store_id = harness.store.store_id
    journal = _leave_true_hot_journal(harness.store.path)
    with pytest.raises(AgenticCoordinationError, match="sidecar"):
        harness.store.current_head(**_graph_args(harness))

    harness.store.close()
    reopened = AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=store_id,
    )
    assert not journal.exists()
    assert reopened.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )

    journal.write_bytes(b"injected journal")
    journal.chmod(0o600)
    with pytest.raises(AgenticCoordinationError, match="sidecar"):
        reopened.current_head(**_graph_args(harness))


def test_swap_back_rejection_cannot_consume_pinned_hot_journal(
    harness_factory: Callable[[str], DurableHarness],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("hot-journal-swap-back")
    store_id = harness.store.store_id
    leaf = harness.store.path.name
    parked = f"{leaf}.parked"
    replacement = f"{leaf}.replacement"
    parked_path = harness.store.path.with_name(parked)
    replacement_path = harness.store.path.with_name(replacement)
    shutil.copy2(harness.store.path, replacement_path)
    replacement_path.chmod(0o600)
    replacement_before = replacement_path.read_bytes()
    journal = _leave_true_hot_journal(harness.store.path)
    journal_before = journal.read_bytes()
    harness.store.close()
    real_connect = durable_module.sqlite3.connect

    def swapped_connect(*args: object, **kwargs: object) -> sqlite3.Connection:
        os.rename(harness.store.path, parked_path)
        os.rename(replacement_path, harness.store.path)
        try:
            return real_connect(*args, **kwargs)
        finally:
            os.rename(harness.store.path, replacement_path)
            os.rename(parked_path, harness.store.path)

    with monkeypatch.context() as scoped:
        scoped.setattr(durable_module.sqlite3, "connect", swapped_connect)
        with pytest.raises(AgenticCoordinationError, match="pinned database inode"):
            AgenticCoordinationStore(
                harness.store.path,
                binding=harness.binding,
                graph_resolver=harness.resolver,
                graph_head=harness.graph_head,
                allow_create=False,
                expected_store_id=store_id,
            )
    assert journal.read_bytes() == journal_before
    assert replacement_path.read_bytes() == replacement_before

    recovered = AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=store_id,
    )
    assert not journal.exists()
    assert recovered.current_head(**_graph_args(harness)).checkpoint == (
        harness.initial_head.checkpoint
    )


def test_reopen_rejects_cold_journal_without_deleting_it(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("cold-journal-rejection")
    store_id = harness.store.store_id
    script = (
        "import os,sqlite3,sys;"
        "c=sqlite3.connect(sys.argv[1]);"
        "c.execute('PRAGMA journal_mode=DELETE');"
        "c.execute('BEGIN IMMEDIATE');"
        "c.execute('CREATE TABLE crash_probe(value TEXT)');"
        "os._exit(0)"
    )
    completed = subprocess.run(
        [sys.executable, "-c", script, str(harness.store.path)],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    journal = Path(f"{harness.store.path}-journal")
    assert journal.is_file()
    assert journal.read_bytes()[:8] == b"\x00" * 8
    harness.store.close()

    with pytest.raises(AgenticCoordinationError, match="sidecar"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
            expected_store_id=store_id,
        )
    assert journal.is_file()


def test_concurrent_delivery_claims_share_one_pinned_authority(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("concurrent-delivery")
    _publish_cycle(harness)

    def claim(_: int):
        return harness.store.claim_next_delivery(**_graph_args(harness))

    with ThreadPoolExecutor(max_workers=2) as executor:
        claims = tuple(executor.map(claim, range(2)))
    delivered = tuple(claim for claim in claims if claim is not None)
    assert len(delivered) == 1
    assert delivered[0].command.command is AgentControlCommandKind.SPAWN


def test_cycle_cas_outbox_stale_cross_store_and_crash_rollback(
    harness_factory: Callable[[str], DurableHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    harness = harness_factory("cycle")
    publication = _publish_cycle(harness)
    replay = harness.store.publish_cycle(
        harness.initial_head, harness.cycle, **_graph_args(harness)
    )
    assert replay == publication
    assert tuple(item.command for item in publication.outbox_entries) == harness.cycle.commands
    assert all(item.state is AgenticOutboxState.PENDING for item in publication.outbox_entries)
    assert publication.head.checkpoint.restart_resume_supported is False
    assert publication.head.checkpoint.durable_head_published is False

    divergent = DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id="agent:dynamic-supervisor",
        source_snapshot=harness.snapshot,
        allowed_target_ids=(TARGET,),
        exploit_group=harness.supervisor.exploit_group,
        policy=harness.supervisor.policy,
    ).plan_cycle(
        (
            _candidate(
                "divergent",
                snapshot_id=harness.snapshot.snapshot_id,
                snapshot_digest=harness.snapshot.snapshot_digest,
            ),
        )
    )
    with pytest.raises(AgenticCoordinationError, match="stale"):
        harness.store.publish_cycle(harness.initial_head, divergent, **_graph_args(harness))
    second = harness_factory("cycle-second")
    with pytest.raises(AgenticCoordinationError, match="another store"):
        harness.store.publish_cycle(second.initial_head, harness.cycle, **_graph_args(harness))

    from pajin.agentic import durable as durable_module

    crashing = harness_factory("cycle-crash")

    def crash(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("simulated failure before transaction commit")

    monkeypatch.setattr(durable_module, "_insert_cycle_outbox", crash)
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        _publish_cycle(crashing)
    assert crashing.store.current_head(**_graph_args(crashing)).checkpoint == (
        crashing.initial_head.checkpoint
    )
    assert crashing.store.recovery_snapshot(**_graph_args(crashing)).pending_outbox == ()


def test_initialize_rejects_revision_zero_with_non_initial_supervisor_state(
    harness_factory: Callable[[str], DurableHarness], tmp_path: Path
) -> None:
    harness = harness_factory("forged-initial")
    wire = harness.cycle.resulting_checkpoint.model_dump(mode="json", by_alias=True)
    wire["checkpointId"] = ""
    wire["checkpointDigest"] = ""
    wire["revision"] = 0
    forged = type(harness.cycle.resulting_checkpoint).model_validate(wire)
    fresh = AgenticCoordinationStore(
        tmp_path / "forged-initial-fresh-coordination.sqlite3",
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
    )
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        fresh.initialize_head(forged, **_graph_args(harness))


def test_raw_foreign_genesis_never_becomes_durable_authority(
    harness_factory: Callable[[str], DurableHarness], tmp_path: Path
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("raw-foreign-genesis-source")
    fresh = AgenticCoordinationStore(
        tmp_path / "raw-foreign-genesis.sqlite3",
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        store_id_factory=lambda: "agentic-store:" + "e" * 32,
    )
    foreign = DynamicSupervisor(
        campaign_id=CAMPAIGN,
        supervisor_agent_id="agent:foreign-supervisor",
        source_snapshot=harness.snapshot,
        allowed_target_ids=(TARGET,),
        exploit_group=harness.supervisor.exploit_group,
        policy=harness.supervisor.policy,
        scoring_policy=harness.supervisor.scorer.policy,
    ).checkpoint()
    connection = sqlite3.connect(fresh.path)
    try:
        durable_module._insert_checkpoint(
            connection,
            foreign,
            predecessor_digest=None,
            recorded_at=NOW + timedelta(seconds=20),
        )
        connection.execute(
            """
            INSERT INTO agentic_checkpoint_head(slot, checkpoint_digest, revision)
            VALUES (1, ?, 0)
            """,
            (foreign.checkpoint_digest,),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="genesis differs"):
        fresh.current_head(**_graph_args(harness))


def test_delivery_inbox_fences_later_session_commands(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("delivery")
    _publish_cycle(harness)
    first = harness.store.claim_next_delivery(**_graph_args(harness))
    assert first is not None and first.command.command is AgentControlCommandKind.SPAWN
    assert harness.store.claim_next_delivery(**_graph_args(harness)) is None
    reopened = AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=harness.store.store_id,
        clock=lambda: NOW + timedelta(seconds=20),
    )
    recovery = reopened.recovery_snapshot(**_graph_args(harness))
    assert tuple(item.command for item in recovery.unknown_outbox) == (first.command,)
    assert len(recovery.pending_outbox) == 1
    admission = reopened.admit_delivery(first, **_graph_args(harness))
    assert admission.receiver_durable_admission is True
    assert admission.command_consumed is False and admission.task_completed is False
    acknowledged = reopened.acknowledge_delivery(first, admission, **_graph_args(harness))
    assert acknowledged.state is AgenticOutboxState.ACKNOWLEDGED
    assert reopened.acknowledge_delivery(first, admission, **_graph_args(harness)) == acknowledged
    second = reopened.claim_next_delivery(**_graph_args(harness))
    assert second is not None and second.command.command is AgentControlCommandKind.ASSIGN
    assert reopened.claim_next_delivery(**_graph_args(harness)) is None
    forged = admission.model_copy(update={"receipt_digest": SHA_A})
    with pytest.raises((AgenticCoordinationError, ValidationError)):
        reopened.acknowledge_delivery(first, forged, **_graph_args(harness))


def test_delivery_chronology_failure_rolls_back_without_releasing_state(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("delivery-chronology")
    _publish_cycle(harness)
    claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert claim is not None
    harness.store._clock = lambda: claim.claimed_at - timedelta(seconds=1)
    with pytest.raises(AgenticCoordinationError, match="predates delivery claim"):
        harness.store.admit_delivery(claim, **_graph_args(harness))
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert len(recovery.unknown_outbox) == 1
    assert recovery.acknowledged_outbox == ()

    harness.store._clock = lambda: claim.claimed_at + timedelta(seconds=1)
    admission = harness.store.admit_delivery(claim, **_graph_args(harness))
    harness.store._clock = lambda: claim.claimed_at
    with pytest.raises(AgenticCoordinationError, match="predates receiver admission"):
        harness.store.acknowledge_delivery(
            claim,
            admission,
            **_graph_args(harness),
        )
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert len(recovery.unknown_outbox) == 1
    assert recovery.acknowledged_outbox == ()


def test_typed_event_cas_recovery_restore_and_historical_checkpoint(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("events")
    cycle_publication = _publish_cycle(harness)
    spawn_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert spawn_claim is not None
    _admit_and_ack(harness, spawn_claim)
    spawn_event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn_claim.command.target_agent_id,
        commandId=spawn_claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn command durably admitted.",
    )
    spawn_publication = harness.store.publish_event(
        cycle_publication.head, spawn_event, **_graph_args(harness)
    )
    assert (
        harness.store.publish_event(cycle_publication.head, spawn_event, **_graph_args(harness))
        == spawn_publication
    )
    assignment_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert assignment_claim is not None
    _admit_and_ack(harness, assignment_claim)
    terminal = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment_claim.command.target_agent_id,
        commandId=assignment_claim.command.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment_claim.command.task_id,
        candidateId=assignment_claim.command.candidate_id,
        summary="Bounded specialist task completed.",
    )
    terminal_publication = harness.store.publish_event(
        spawn_publication.head, terminal, **_graph_args(harness)
    )
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert recovery.head.checkpoint == terminal_publication.head.checkpoint
    restored = harness.store.restore_supervisor(terminal_publication.head, **_graph_args(harness))
    assert restored.checkpoint() == terminal_publication.head.checkpoint
    historical = harness.store.verified_checkpoint(
        terminal_publication.head,
        checkpoint_id=harness.initial_head.checkpoint.checkpoint_id,
        checkpoint_digest=harness.initial_head.checkpoint.checkpoint_digest,
        **_graph_args(harness),
    )
    assert historical.checkpoint == harness.initial_head.checkpoint
    assert historical.current_head_digest == terminal_publication.head.checkpoint.checkpoint_digest


def test_event_transaction_failure_rolls_back_checkpoint(
    harness_factory: Callable[[str], DurableHarness], monkeypatch: pytest.MonkeyPatch
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("event-crash")
    publication = _publish_cycle(harness)
    claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert claim is not None
    _admit_and_ack(harness, claim)
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=claim.command.target_agent_id,
        commandId=claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn command durably admitted.",
    )

    def crash(_event: AgentEvent) -> bytes:
        raise RuntimeError("simulated crash after checkpoint insert")

    monkeypatch.setattr(durable_module, "_agent_event_bytes", crash)
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        harness.store.publish_event(publication.head, event, **_graph_args(harness))
    assert harness.store.current_head(**_graph_args(harness)).checkpoint == (
        publication.head.checkpoint
    )
    assert harness.store.recovery_snapshot(**_graph_args(harness)).head.checkpoint == (
        publication.head.checkpoint
    )


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("provider_id", "other-provider"),
        ("model_id", "other-model"),
        ("provider_model_digest", SHA_B),
        ("model_configuration_digest", SHA_C),
        ("provider_runtime_digest", SHA_D),
        ("capability_grant_digest", SHA_E),
        ("campaign_budget_policy_digest", SHA_F),
        ("campaign_budget_state_digest", SHA_G),
        ("dedicated_budget_policy_digest", SHA_A),
        ("request_schema_digest", SHA_B),
        ("response_schema_digest", SHA_C),
        ("provider_chat_request_digest", SHA_D),
        ("max_completion_tokens", 2048),
        ("planned_provider_run_id", "run:other"),
    ),
)
def test_request_binding_rejects_stale_identity_after_pin_mutation(
    harness_factory: Callable[[str], DurableHarness], field: str, replacement: object
) -> None:
    harness = harness_factory(f"pin-{field.replace('_', '-')}")
    binding = _request_binding(harness.snapshot)
    forged = binding.model_copy(update={field: replacement})
    with pytest.raises(ValidationError):
        AgenticHypothesisRequestBinding.model_validate(
            forged.model_dump(mode="json", by_alias=True)
        )


@pytest.mark.parametrize(
    ("alias", "replacement"),
    (
        ("providerId", "other-provider"),
        ("modelId", "other-model"),
        ("providerModelDigest", SHA_B),
        ("modelConfigurationDigest", SHA_C),
        ("providerRuntimeDigest", SHA_D),
        ("capabilityGrantDigest", SHA_E),
        ("campaignBudgetPolicyDigest", SHA_F),
        ("campaignBudgetStateDigest", SHA_G),
        ("dedicatedBudgetPolicyDigest", SHA_A),
        ("maxCompletionTokens", 2048),
        ("plannedProviderRunId", "run_20260918T010001Z_89abcdef"),
        (
            "plannedProviderRunPath",
            f"/private/tmp/pajin-agentic-other/{PLANNED_RUN_ID}",
        ),
    ),
)
def test_logical_invocation_slot_cannot_rebind_any_valid_request_pin(
    harness_factory: Callable[[str], DurableHarness], alias: str, replacement: object
) -> None:
    harness = harness_factory(f"slot-{alias.lower()}")
    context = _context(harness.snapshot)
    request = _request_binding(harness.snapshot)
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    wire = request.model_dump(mode="json", by_alias=True)
    wire["requestBindingId"] = ""
    wire["requestBindingDigest"] = ""
    wire[alias] = replacement
    if alias == "maxCompletionTokens":
        wire["chat"]["max_completion_tokens"] = replacement
        wire["providerChatRequestDigest"] = discovery_digest(
            "pajin.provider.chat-request/v1", wire["chat"]
        )
    elif alias == "plannedProviderRunId":
        wire["plannedProviderRunPath"] = f"/private/tmp/pajin-agentic-planned/{replacement}"
    rebound = AgenticHypothesisRequestBinding.model_validate(wire)
    with pytest.raises(AgenticCoordinationError, match="equivocated"):
        harness.store.claim_hypothesis_invocation(
            harness.initial_head,
            context,
            request.projection,
            request_binding=rebound,
            **_graph_args(harness),
        )
    started = harness.store.begin_hypothesis_dispatch(claimed, **_graph_args(harness))
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert recovery.unknown_invocations == (started,)


@pytest.mark.parametrize(
    "forged_parent",
    ("hypothesis:invented-not-in-graph", ROOT_SURFACE.node_id),
)
def test_invocation_claim_rejects_context_parent_without_current_graph_lineage(
    harness_factory: Callable[[str], DurableHarness], forged_parent: str
) -> None:
    harness = harness_factory(f"context-{sha256(forged_parent.encode()).hexdigest()[:8]}")
    context = _context(harness.snapshot)
    wire = context.model_dump(mode="json", by_alias=True)
    wire["contextId"] = ""
    wire["contextDigest"] = ""
    wire["parentHypothesisId"] = forged_parent
    wire["ancestorHypothesisIds"] = [forged_parent]
    forged = HypothesisExpansionContext.model_validate(wire)
    request = _request_binding(harness.snapshot)
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        harness.store.claim_hypothesis_invocation(
            harness.initial_head,
            forged,
            request.projection,
            request_binding=request,
            **_graph_args(harness),
        )
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert recovery.claimed_invocations == ()
    assert recovery.unknown_invocations == ()


def _seal_receipt(
    started,
    *,
    run_root: Path | None = None,
    campaign_name: str | None = None,
    run_id: str | None = None,
    recorded_at: datetime = NOW + timedelta(seconds=11),
) -> AgenticHypothesisReceiptPublication:
    receipt = build_agentic_hypothesis_invocation_receipt(
        started,
        succeeded=True,
        outcome_digest=SHA_D,
        recorded_at=recorded_at,
    )
    binding = started.intent.request_binding
    planned = Path(binding.planned_provider_run_path)
    selected_run_id = run_id or binding.planned_provider_run_id
    selected_campaign = campaign_name or planned.parent.name
    selected_root = run_root or planned.parent.parent
    store = RunStore.create(
        selected_root,
        selected_campaign,
        run_id=selected_run_id,
    )
    raw = canonical_json_bytes(
        receipt.model_dump(mode="json", by_alias=True), label="test invocation receipt"
    )
    path = "agentic/hypothesis-invocation-receipt.json"
    store.write_bytes(path, raw)
    store.append_event(
        "agentic.hypothesis-invocation-terminal",
        {
            "artifactPath": path,
            "receiptDigest": receipt.receipt_digest,
            "receiptId": receipt.receipt_id,
        },
    )
    seal = store.seal()
    return AgenticHypothesisReceiptPublication(
        store.path,
        store.run_id,
        seal.root_digest,
        path,
        sha256(raw).hexdigest(),
        receipt,
    )


def test_invocation_unknown_recovery_and_sealed_terminal_receipt(
    harness_factory: Callable[[str], DurableHarness], tmp_path: Path
) -> None:
    harness = harness_factory("invocation")
    context = _context(harness.snapshot)
    planned_run_id = RunStore.new_run_id()
    planned_run_path = (tmp_path / "receipt-runs" / "agentic-terminal" / planned_run_id).absolute()
    request = _request_binding(
        harness.snapshot,
        planned_run_id=planned_run_id,
        planned_run_path=planned_run_path,
    )
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    assert (
        harness.store.claim_hypothesis_invocation(
            harness.initial_head,
            context,
            request.projection,
            request_binding=request,
            **_graph_args(harness),
        )
        == claimed
    )
    started = harness.store.begin_hypothesis_dispatch(claimed, **_graph_args(harness))
    assert started.state is AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN
    reopened = AgenticCoordinationStore(
        harness.store.path,
        binding=harness.binding,
        graph_resolver=harness.resolver,
        graph_head=harness.graph_head,
        allow_create=False,
        expected_store_id=harness.store.store_id,
        clock=lambda: NOW + timedelta(seconds=12),
    )
    assert reopened.recovery_snapshot(**_graph_args(harness)).unknown_invocations == (started,)
    with pytest.raises(AgenticCoordinationError, match="redispatch"):
        reopened.begin_hypothesis_dispatch(started, **_graph_args(harness))
    publication = _seal_receipt(started)
    terminal = reopened.finalize_hypothesis_invocation(
        started, publication=publication, **_graph_args(harness)
    )
    assert terminal.state is AgenticModelInvocationState.TERMINAL_SUCCESS
    assert reopened.recovery_snapshot(**_graph_args(harness)).terminal_invocations == (terminal,)
    foreign_run_id = RunStore.new_run_id()
    foreign = _seal_receipt(
        started,
        run_root=tmp_path / "foreign-receipt-runs",
        campaign_name="foreign-terminal",
        run_id=foreign_run_id,
    )
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        reopened.finalize_hypothesis_invocation(
            started,
            publication=foreign,
            **_graph_args(harness),
        )

    class AlternatingPath(os.PathLike[str]):
        def __init__(self, first: Path, second: Path) -> None:
            self._paths = (str(first), str(second))
            self.calls = 0

        def __fspath__(self) -> str:
            result = self._paths[self.calls % 2]
            self.calls += 1
            return result

    alternating = AlternatingPath(publication.run_path, foreign.run_path)
    stateful_path = AgenticHypothesisReceiptPublication(
        alternating,  # type: ignore[arg-type]
        publication.run_id,
        publication.root_digest,
        publication.artifact_path,
        publication.artifact_sha256,
        publication.receipt,
    )
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        reopened.finalize_hypothesis_invocation(
            terminal,
            publication=stateful_path,
            **_graph_args(harness),
        )
    assert alternating.calls == 0

    forged = AgenticHypothesisReceiptPublication(
        publication.run_path,
        publication.run_id,
        SHA_A,
        publication.artifact_path,
        publication.artifact_sha256,
        publication.receipt,
    )
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        reopened.finalize_hypothesis_invocation(
            terminal, publication=forged, **_graph_args(harness)
        )


def test_invocation_rejects_receipt_that_postdates_terminal_publication(
    harness_factory: Callable[[str], DurableHarness], tmp_path: Path
) -> None:
    harness = harness_factory("future-receipt")
    context = _context(harness.snapshot)
    planned_run_id = RunStore.new_run_id()
    planned_run_path = (
        tmp_path / "future-receipt-runs" / "agentic-terminal" / planned_run_id
    ).absolute()
    request = _request_binding(
        harness.snapshot,
        planned_run_id=planned_run_id,
        planned_run_path=planned_run_path,
    )
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    started = harness.store.begin_hypothesis_dispatch(claimed, **_graph_args(harness))
    future = _seal_receipt(started, recorded_at=NOW + timedelta(days=1))
    with pytest.raises(AgenticCoordinationError, match="postdates"):
        harness.store.finalize_hypothesis_invocation(
            started,
            publication=future,
            **_graph_args(harness),
        )
    assert harness.store.recovery_snapshot(**_graph_args(harness)).unknown_invocations == (started,)


def test_dispatch_clock_rollback_preserves_claimed_invocation(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("dispatch-clock-rollback")
    context = _context(harness.snapshot)
    request = _request_binding(harness.snapshot)
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    harness.store._clock = lambda: claimed.intent.claimed_at - timedelta(seconds=1)
    with pytest.raises(AgenticCoordinationError, match="predates its durable claim"):
        harness.store.begin_hypothesis_dispatch(claimed, **_graph_args(harness))
    recovery = harness.store.recovery_snapshot(**_graph_args(harness))
    assert recovery.claimed_invocations == (claimed,)
    assert recovery.unknown_invocations == ()


def test_raw_dispatch_before_claim_fails_full_history_validation(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("raw-dispatch-before-claim")
    context = _context(harness.snapshot)
    request = _request_binding(harness.snapshot)
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    started_at = claimed.intent.claimed_at - timedelta(seconds=1)
    state_digest = durable_module._invocation_state_digest(
        intent_digest=claimed.intent.intent_digest,
        state=AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN,
        dispatch_started_at=started_at,
        terminal_at=None,
        outcome_digest=None,
        receipt_reference=None,
        receipt_digest=None,
        receipt_run_path=None,
        receipt_run_id=None,
        receipt_root_digest=None,
        receipt_artifact_path=None,
        receipt_artifact_sha256=None,
    )
    connection = sqlite3.connect(harness.store.path)
    try:
        connection.execute(
            """
            UPDATE agentic_model_invocations
            SET state = ?, dispatch_started_at = ?, state_digest = ?
            WHERE intent_id = ?
            """,
            (
                AgenticModelInvocationState.DISPATCH_STARTED_OUTCOME_UNKNOWN.value,
                durable_module._format_timestamp(started_at),
                state_digest,
                claimed.intent.intent_id,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="failed closed"):
        harness.store.recovery_snapshot(**_graph_args(harness))


def test_invocation_state_cannot_rewind_after_dispatch_started(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("invocation-rewind")
    context = _context(harness.snapshot)
    request = _request_binding(harness.snapshot)
    claimed = harness.store.claim_hypothesis_invocation(
        harness.initial_head,
        context,
        request.projection,
        request_binding=request,
        **_graph_args(harness),
    )
    started = harness.store.begin_hypothesis_dispatch(claimed, **_graph_args(harness))
    connection = sqlite3.connect(harness.store.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="advance exactly once"):
            connection.execute(
                """
                UPDATE agentic_model_invocations
                SET state = 'claimed', dispatch_started_at = NULL
                WHERE intent_id = ?
                """,
                (started.intent.intent_id,),
            )
    finally:
        connection.close()
    assert harness.store.recovery_snapshot(**_graph_args(harness)).unknown_invocations == (started,)


@pytest.mark.parametrize("mutation", ("stable-slot", "checkpoint-id"))
def test_raw_invocation_insert_cannot_forge_checkpoint_slot(
    harness_factory: Callable[[str], DurableHarness], mutation: str
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory(f"raw-invocation-{mutation}")
    context = _context(harness.snapshot)
    request = _request_binding(harness.snapshot)
    expected_stable = durable_module._stable_hypothesis_request_id(
        binding_digest=harness.binding.binding_digest,
        source_checkpoint_digest=harness.initial_head.checkpoint.checkpoint_digest,
    )
    stable = "hypothesis-request_" + SHA_A if mutation == "stable-slot" else expected_stable
    assert mutation != "stable-slot" or stable != expected_stable
    source_checkpoint_id = (
        "agentic-checkpoint_" + SHA_A
        if mutation == "checkpoint-id"
        else harness.initial_head.checkpoint.checkpoint_id
    )
    assert mutation != "checkpoint-id" or source_checkpoint_id != (
        harness.initial_head.checkpoint.checkpoint_id
    )
    intent = AgenticHypothesisInvocationIntent(
        stableRequestId=stable,
        storeId=harness.store.store_id,
        coordinationBindingId=harness.binding.binding_id,
        coordinationBindingDigest=harness.binding.binding_digest,
        sourceCheckpointId=source_checkpoint_id,
        sourceCheckpointDigest=harness.initial_head.checkpoint.checkpoint_digest,
        contextId=context.context_id,
        contextDigest=context.context_digest,
        context=context,
        projectionId=request.projection.projection_id,
        projectionDigest=request.projection.projection_digest,
        requestBindingId=request.request_binding_id,
        requestBindingDigest=request.request_binding_digest,
        requestBinding=request,
        providerRunId=request.planned_provider_run_id,
        claimedAt=(NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
    )
    state_digest = durable_module._invocation_state_digest(
        intent_digest=intent.intent_digest,
        state=AgenticModelInvocationState.CLAIMED,
        dispatch_started_at=None,
        terminal_at=None,
        outcome_digest=None,
        receipt_reference=None,
        receipt_digest=None,
        receipt_run_path=None,
        receipt_run_id=None,
        receipt_root_digest=None,
        receipt_artifact_path=None,
        receipt_artifact_sha256=None,
    )
    connection = sqlite3.connect(harness.store.path)
    try:
        connection.execute(
            """
            INSERT INTO agentic_model_invocations(
                intent_id, intent_digest, stable_request_id, provider_run_id,
                source_checkpoint_digest, context_digest, projection_digest,
                request_binding_digest, canonical_intent, state,
                dispatch_started_at, terminal_at, outcome_digest,
                receipt_reference, receipt_digest, receipt_run_path,
                receipt_run_id, receipt_root_digest, receipt_artifact_path,
                receipt_artifact_sha256, state_digest
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'claimed', NULL, NULL, NULL,
                      NULL, NULL, NULL, NULL, NULL, NULL, NULL, ?)
            """,
            (
                intent.intent_id,
                intent.intent_digest,
                intent.stable_request_id,
                intent.provider_run_id,
                intent.source_checkpoint_digest,
                intent.context_digest,
                intent.projection_digest,
                intent.request_binding_digest,
                sqlite3.Binary(durable_module._intent_bytes(intent)),
                state_digest,
            ),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="checkpoint and Graph slot"):
        harness.store.current_head(**_graph_args(harness))


def test_cross_store_and_in_place_state_tamper_fail_closed(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    first = harness_factory("cross-first")
    second = harness_factory("cross-second")
    _publish_cycle(first)
    _publish_cycle(second)
    claim = first.store.claim_next_delivery(**_graph_args(first))
    assert claim is not None
    with pytest.raises(AgenticCoordinationError, match="another store"):
        second.store.admit_delivery(claim, **_graph_args(second))
    connection = sqlite3.connect(first.store.path)
    try:
        with pytest.raises(sqlite3.IntegrityError, match="advance exactly once"):
            connection.execute(
                "UPDATE agentic_command_outbox SET state_digest = ? WHERE command_id = ?",
                (SHA_A, claim.command.command_id),
            )
    finally:
        connection.close()
    reopened = AgenticCoordinationStore(
        first.store.path,
        binding=first.binding,
        graph_resolver=first.resolver,
        graph_head=first.graph_head,
        allow_create=False,
        expected_store_id=first.store.store_id,
    )
    unknown = reopened.recovery_snapshot(**_graph_args(first)).unknown_outbox
    assert len(unknown) == 1
    assert unknown[0].command == claim.command
    assert unknown[0].claim_id == claim.claim_id
    assert unknown[0].claim_digest == claim.claim_digest


def test_raw_graph_and_stale_head_never_cross_restore_boundary(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("raw-boundary")
    publication = _publish_cycle(harness)
    with pytest.raises(AgenticCoordinationError):
        harness.store.restore_supervisor(
            publication.head,
            graph_resolver=harness.resolver,
            graph_head=harness.snapshot,  # type: ignore[arg-type]
        )
    with pytest.raises(AgenticCoordinationError, match="stale"):
        harness.store.restore_supervisor(harness.initial_head, **_graph_args(harness))


def test_unadmitted_command_cannot_publish_event(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    harness = harness_factory("event-without-inbox")
    publication = _publish_cycle(harness)
    spawn = next(
        command
        for command in harness.cycle.commands
        if command.command is AgentControlCommandKind.SPAWN
    )
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn.target_agent_id,
        commandId=spawn.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Forged acknowledgement without receiver admission.",
    )
    with pytest.raises(AgenticCoordinationError, match="admission"):
        harness.store.publish_event(publication.head, event, **_graph_args(harness))


def test_raw_semantic_event_without_acknowledged_inbox_never_releases_head(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("raw-event-without-inbox")
    publication = _publish_cycle(harness)
    spawn = next(
        command
        for command in harness.cycle.commands
        if command.command is AgentControlCommandKind.SPAWN
    )
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn.target_agent_id,
        commandId=spawn.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Raw-appended event without receiver admission.",
    )
    resulting = harness.supervisor.accept_event(event)
    connection = sqlite3.connect(harness.store.path)
    try:
        durable_module._insert_checkpoint(
            connection,
            resulting,
            predecessor_digest=publication.head.checkpoint.checkpoint_digest,
            recorded_at=NOW + timedelta(seconds=20),
        )
        connection.execute(
            """
            INSERT INTO agentic_events(
                event_id, event_digest, command_id, agent_id, event_sequence,
                source_checkpoint_digest, resulting_checkpoint_digest,
                canonical_event, recorded_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                durable_module._agent_event_digest(event),
                event.command_id,
                event.agent_id,
                event.sequence,
                publication.head.checkpoint.checkpoint_digest,
                resulting.checkpoint_digest,
                sqlite3.Binary(durable_module._agent_event_bytes(event)),
                durable_module._format_timestamp(NOW + timedelta(seconds=20)),
            ),
        )
        connection.execute(
            """
            UPDATE agentic_checkpoint_head
            SET checkpoint_digest = ?, revision = ?
            WHERE slot = 1
            """,
            (resulting.checkpoint_digest, resulting.revision),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="acknowledged receiver admission"):
        harness.store.current_head(**_graph_args(harness))


@pytest.mark.parametrize(
    "mutation",
    ("store", "binding", "receiver", "admission-time"),
)
def test_foreign_or_ill_timed_inbox_receipt_never_releases_durable_state(
    harness_factory: Callable[[str], DurableHarness], mutation: str
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory(f"foreign-inbox-{mutation}")
    publication = _publish_cycle(harness)
    claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert claim is not None
    receipt = AgenticCommandAdmissionReceipt(
        storeId=("agentic-store:" + "f" * 32 if mutation == "store" else harness.store.store_id),
        coordinationBindingDigest=(
            SHA_A if mutation == "binding" else harness.binding.binding_digest
        ),
        claimId=claim.claim_id,
        claimDigest=claim.claim_digest,
        commandId=claim.command.command_id,
        commandDigest=claim.command_digest,
        receiverAgentId=(
            "agent:foreign-receiver" if mutation == "receiver" else claim.command.target_agent_id
        ),
        admittedAt=(
            claim.claimed_at - timedelta(seconds=1)
            if mutation == "admission-time"
            else claim.claimed_at + timedelta(seconds=1)
        )
        .isoformat()
        .replace("+00:00", "Z"),
    )
    raw = canonical_json_bytes(
        receipt.model_dump(mode="json", by_alias=True),
        label="foreign durable admission fixture",
    )
    connection = sqlite3.connect(harness.store.path)
    try:
        connection.execute(
            """
            INSERT INTO agentic_command_inbox(
                receipt_id, receipt_digest, command_id, claim_id, claim_digest,
                receiver_agent_id, canonical_receipt, admitted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                receipt.receipt_id,
                receipt.receipt_digest,
                receipt.command_id,
                receipt.claim_id,
                receipt.claim_digest,
                receipt.receiver_agent_id,
                sqlite3.Binary(raw),
                durable_module._format_timestamp(receipt.admitted_at),
            ),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="receiver inbox differs"):
        harness.store.recovery_snapshot(**_graph_args(harness))
    event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=claim.command.target_agent_id,
        commandId=claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="This event must not cross a foreign inbox boundary.",
    )
    with pytest.raises(AgenticCoordinationError, match="receiver inbox differs"):
        harness.store.publish_event(publication.head, event, **_graph_args(harness))


def test_semantically_counterfeit_event_chain_never_issues_authority(
    harness_factory: Callable[[str], DurableHarness],
) -> None:
    from pajin.agentic import durable as durable_module

    harness = harness_factory("counterfeit-event")
    cycle = _publish_cycle(harness)
    spawn_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert spawn_claim is not None
    _admit_and_ack(harness, spawn_claim)
    spawn_event = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=spawn_claim.command.target_agent_id,
        commandId=spawn_claim.command.command_id,
        event=AgentEventKind.ACKNOWLEDGED,
        summary="Spawn admitted.",
    )
    spawn = harness.store.publish_event(cycle.head, spawn_event, **_graph_args(harness))
    assignment_claim = harness.store.claim_next_delivery(**_graph_args(harness))
    assert assignment_claim is not None
    _admit_and_ack(harness, assignment_claim)
    final = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment_claim.command.target_agent_id,
        commandId=assignment_claim.command.command_id,
        event=AgentEventKind.FINAL,
        taskId=assignment_claim.command.task_id,
        candidateId=assignment_claim.command.candidate_id,
        summary="Completed.",
    )
    terminal = harness.store.publish_event(spawn.head, final, **_graph_args(harness))
    counterfeit = AgentEvent(
        campaignId=CAMPAIGN,
        sequence=1,
        agentId=assignment_claim.command.target_agent_id,
        commandId=assignment_claim.command.command_id,
        event=AgentEventKind.FAILED,
        taskId=assignment_claim.command.task_id,
        candidateId=assignment_claim.command.candidate_id,
        summary="Counterfeit failure.",
    )
    connection = sqlite3.connect(harness.store.path)
    try:
        connection.execute("DROP TRIGGER agentic_events_immutable")
        connection.execute(
            """
            UPDATE agentic_events
            SET event_id = ?, event_digest = ?, canonical_event = ?
            WHERE event_id = ?
            """,
            (
                counterfeit.event_id,
                durable_module._agent_event_digest(counterfeit),
                sqlite3.Binary(durable_module._agent_event_bytes(counterfeit)),
                final.event_id,
            ),
        )
        connection.execute(durable_module._EVENTS_IMMUTABLE_SQL)
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(AgenticCoordinationError, match="semantic replay differs"):
        harness.store.current_head(**_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match="semantic replay differs"):
        harness.store.restore_supervisor(terminal.head, **_graph_args(harness))
    with pytest.raises(AgenticCoordinationError, match="semantic replay differs"):
        AgenticCoordinationStore(
            harness.store.path,
            binding=harness.binding,
            graph_resolver=harness.resolver,
            graph_head=harness.graph_head,
            allow_create=False,
            expected_store_id=harness.store.store_id,
        )


def test_admission_receipt_cannot_claim_command_consumption() -> None:
    with pytest.raises(ValidationError):
        AgenticCommandAdmissionReceipt(
            storeId="agentic-store:" + "1" * 32,
            coordinationBindingDigest=SHA_A,
            claimId="agentic-delivery-claim_" + SHA_B,
            claimDigest=SHA_B,
            commandId="agent-command_" + SHA_C,
            commandDigest=SHA_D,
            receiverAgentId="agent:receiver",
            admittedAt=NOW,
            commandConsumed=True,
        )
