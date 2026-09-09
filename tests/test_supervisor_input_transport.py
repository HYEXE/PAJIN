from __future__ import annotations

import asyncio
import io
import json
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError
from test_provider import _worker_entry
from test_supervisor_checkpoint_scheduler import (
    _campaign,
    _graph,
    _invocation_environment,
    _policy,
    _runtime,
    _schedule,
)

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.manifest import load_manifest
from pajin.domain.models import CampaignManifest
from pajin.providers.models import ProviderMessage
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.store import load_verified_run_artifacts
from pajin.runtime.worker import (
    LARGE_PROVIDER_ACTION,
    DockerWorkerBackend,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.supervision import (
    SupervisorCheckpointScheduler,
    SupervisorInvocationPlanError,
    SupervisorInvocationRequestBinding,
    build_supervisor_invocation_request,
)
from pajin.supervision.input_transport import (
    MAX_INPUT_BYTES,
    SupervisorInputTransport,
    build_supervisor_input_messages,
    reconstruct_supervisor_input,
)
from pajin.supervision.snapshot_input import SupervisorSnapshotInput, SupervisorSnapshotInputError
from pajin.tools.ai import ChatRole


@pytest.fixture(scope="module")
def large_runtime():
    raw = _campaign(load_manifest(Path("examples/ai-redteam.yaml"))).model_dump(
        mode="json",
        by_alias=True,
    )
    raw["spec"]["budgets"]["maxModelTokens"] = 50_000_000
    campaign = CampaignManifest.model_validate(raw)
    store, _, _, collaboration = _graph(campaign, fact_count=247, statement="😀" * 4_000)
    return campaign, store, collaboration, _runtime(campaign, store, collaboration)


def test_near_four_mib_input_is_lossless_and_bound_to_every_message(large_runtime) -> None:
    campaign, _, _, runtime = large_runtime
    snapshot, binding, provider, configuration = runtime
    chat, request = build_supervisor_invocation_request(
        snapshot,
        binding,
        campaign,
        provider,
        configuration,
        _policy(tokens=50_000_000),
        model_revision="shadow-model-revision-2026-08-04",
    )
    transport = request.input_transport
    assert transport is not None
    assert MAX_INPUT_BYTES - 16_384 < transport.content_bytes <= MAX_INPUT_BYTES
    assert 2 < len(chat.messages) <= 100
    assert all(len(message.content or "") <= 65_536 for message in chat.messages)
    assert reconstruct_supervisor_input(chat.messages, transport) == snapshot
    assert request.api_version.endswith("/v1alpha2")
    assert (
        SupervisorInvocationRequestBinding.model_validate_json(
            request.model_dump_json(by_alias=True),
        )
        == request
    )
    for message, bound in zip(chat.messages, request.messages, strict=True):
        content = (message.content or "").encode("utf-8")
        assert bound.content_digest == sha256(content).hexdigest()
        assert bound.content_bytes == len(content)
    assert request.usage_bound.prompt_tokens > transport.content_bytes * 4
    assert request.model_invocation_authorized is False


@pytest.mark.parametrize(
    "mutation",
    ["missing", "duplicate", "reordered", "mixed", "edited", "header", "role", "noncanonical"],
)
def test_reconstruction_rejects_incomplete_or_substituted_input(
    sample_campaign: CampaignManifest,
    mutation: str,
) -> None:
    campaign = _campaign(sample_campaign)
    store, _, _, collaboration = _graph(campaign, fact_count=17, statement="x" * 4_000)
    snapshot, *_ = _runtime(campaign, store, collaboration)
    messages, transport = build_supervisor_input_messages(snapshot)
    assert transport is not None
    if mutation == "missing":
        messages.pop()
    elif mutation == "duplicate":
        messages.append(messages[-1])
    elif mutation == "reordered":
        messages[1], messages[2] = messages[2], messages[1]
    elif mutation == "role":
        messages[1] = messages[1].model_copy(update={"role": ChatRole.DEVELOPER})
    else:
        content = messages[1].content
        assert content is not None
        prefix, _, part = content.partition("\n")
        header = json.loads(prefix)
        if mutation == "mixed":
            header["inputDigest"] = "a" * 64
            header["inputId"] = "supervisor-snapshot-input:" + "a" * 64
        elif mutation == "edited":
            part = part[:-1] + ("y" if part[-1] != "y" else "x")
        elif mutation == "header":
            header["chunkIndex"] = True
        elif mutation == "noncanonical":
            prefix += " "
        if mutation != "noncanonical":
            prefix = canonical_json_bytes(header, label="test header").decode()
        messages[1] = messages[1].model_copy(update={"content": prefix + "\n" + part})
    with pytest.raises(ValueError):
        reconstruct_supervisor_input(messages, transport)


def test_chunking_preserves_json_escapes_unicode_and_taint(sample_campaign) -> None:
    campaign = _campaign(sample_campaign)
    statement = ('\\"한😀' * 1_000)[:4_000]
    store, _, _, collaboration = _graph(campaign, fact_count=17, statement=statement)
    snapshot, *_ = _runtime(campaign, store, collaboration)
    messages, transport = build_supervisor_input_messages(snapshot)
    assert transport is not None
    rebuilt = reconstruct_supervisor_input(messages, transport)
    assert rebuilt == snapshot
    assert all(
        text.text == statement and not text.instruction_authorized
        for text in rebuilt.model_visible_text
    )


def test_chunk_transport_cannot_be_downgraded_or_expand_budget(large_runtime) -> None:
    campaign, _, _, runtime = large_runtime
    snapshot, binding, provider, configuration = runtime
    with pytest.raises(SupervisorInvocationPlanError, match="dedicated budget"):
        build_supervisor_invocation_request(
            snapshot,
            binding,
            campaign,
            provider,
            configuration,
            _policy(tokens=1_000_000),
            model_revision="shadow-model-revision-2026-08-04",
        )
    _, request = build_supervisor_invocation_request(
        snapshot,
        binding,
        campaign,
        provider,
        configuration,
        _policy(tokens=50_000_000),
        model_revision="shadow-model-revision-2026-08-04",
    )
    raw = request.model_dump(mode="json", by_alias=True)
    raw["apiVersion"] = "pajin.dev/supervisor-invocation-request/v1alpha1"
    raw["requestBindingId"] = raw["requestBindingDigest"] = ""
    with pytest.raises(ValidationError):
        SupervisorInvocationRequestBinding.model_validate(raw)


def test_input_above_original_four_mib_ceiling_still_fails(large_runtime) -> None:
    campaign, _, _, _ = large_runtime
    store, _, _, collaboration = _graph(campaign, fact_count=248, statement="😀" * 4_000)
    with pytest.raises(SupervisorSnapshotInputError):
        _runtime(campaign, store, collaboration)


class _TransportWorker:
    """Exercise real Worker envelope, HTTP serializer, and response parser without a paid model."""

    def __init__(self, snapshot: SupervisorSnapshotInput, transport: SupervisorInputTransport):
        self.snapshot = snapshot
        self.transport = transport
        self.calls = 0
        self.module = _worker_entry()
        self.module._open_http = self._open_http

    def stable_execution_context(self):
        return {"fixture": "supervisor-transport-worker/v1"}

    def _open_http(self, request, *, timeout):
        assert timeout == 30
        body = request.data
        assert body is not None and len(body) > 1_100_000
        payload = json.loads(body)
        messages = [ProviderMessage.model_validate(message) for message in payload["messages"]]
        assert reconstruct_supervisor_input(messages, self.transport) == self.snapshot
        draft = {
            "apiVersion": "pajin.dev/supervisor-shadow-proposal-draft/v1alpha1",
            "kind": "SupervisorShadowProposalDraft",
            "snapshotId": self.snapshot.source_snapshot_id,
            "snapshotDigest": self.snapshot.source_snapshot_digest,
            "proposalKind": "replan",
            "rationale": "Review the complete supplied Snapshot.",
            "proposalState": "untrusted-model-output-not-authorized",
            "capabilityGranted": False,
            "permitGranted": False,
            "executionAuthorized": False,
        }
        return io.BytesIO(
            json.dumps(
                {
                    "id": "transport-response",
                    "model": payload["model"],
                    "choices": [
                        {
                            "index": 0,
                            "message": {"role": "assistant", "content": json.dumps(draft)},
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20},
                }
            ).encode()
        )

    async def run(self, job: WorkerJob, *, secrets: list[SecretMaterial] | None = None):
        assert job.command == [LARGE_PROVIDER_ACTION]
        assert job.egress_policy is not None
        assert job.egress_policy.max_request_bytes == job.stdin_byte_limit
        wire = DockerWorkerBackend._wire_stdin(job, secrets or [])
        payload, bindings = self.module._unwrap_worker_envelope(
            self.module._read_worker_input(
                io.StringIO(wire.decode()),
                large_provider=True,
            )
        )
        result = self.module._dispatch_action(job.command[0], payload, bindings)
        self.calls += 1
        now = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="transport-contract",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(result),
            started_at=now,
            finished_at=now,
        )


def test_large_input_runs_once_with_two_seals_and_conservative_budgets(
    tmp_path: Path,
    large_runtime,
) -> None:
    campaign, graph_store, collaboration, runtime = large_runtime
    snapshot, binding, provider, configuration = runtime
    policy = _policy(tokens=50_000_000)
    scheduled = _schedule(
        SupervisorCheckpointScheduler(output_root=tmp_path / "schedules", budget_policy=policy),
        runtime,
        campaign,
        collaboration,
        graph_store,
    )
    transport = scheduled.schedule.request_binding.input_transport
    assert transport is not None
    worker = _TransportWorker(snapshot, transport)
    invoker, journal, authorities, _, campaign_budget, dedicated_budget = _invocation_environment(
        tmp_path,
        campaign,
        provider,
        policy,
        snapshot,
        binding,
        configuration,
        collaboration,
        graph_store,
        worker_backend=worker,
    )
    first = asyncio.run(invoker.invoke(scheduled, authorities))
    second = asyncio.run(invoker.invoke(scheduled, authorities))
    assert first == second
    assert worker.calls == 1
    entry = journal.inspect(first.publication.journal_entry.intent.intent_id)
    assert entry.state == "terminal-success"
    sealed = load_verified_run_artifacts(
        first.publication.run_path,
        requests={},
        expected_run_id=first.publication.receipt.provider_run_id,
    )
    assert sealed.verification.seal_count == 2
    assert campaign_budget.model_calls == dedicated_budget.model_calls == 1
    assert campaign_budget.model_prompt_tokens > transport.content_bytes * 4
    assert campaign_budget.snapshot()["modelTokens"] == dedicated_budget.snapshot()["modelTokens"]
    assert first.proposal.execution_authorized is False
