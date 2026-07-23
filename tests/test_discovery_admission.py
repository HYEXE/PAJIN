from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from pajin.discovery import (
    SurfaceAdmissionError,
    SurfaceCandidate,
    SurfaceProjectionConflict,
    TrustedSurfaceAdmission,
    TrustedSurfaceProducer,
    http_surface_locator,
    publish_surface_projection,
)
from pajin.domain.models import (
    CampaignManifest,
    ToolRequest,
    ToolResult,
    ToolRiskTier,
)
from pajin.policy.engine import PolicyDecision
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import RunStore, load_verified_run_snapshot, verify_run_integrity
from pajin.runtime.worker import WorkerJob, WorkerResult
from pajin.tools.base import Tool, ToolRegistry, ToolSpec

NOW = datetime(2026, 7, 23, 1, 0, tzinfo=UTC)
EVIDENCE_REFERENCE = "evidence/tool_recon_1.json"


class _HTTPReconTool(Tool):
    spec = ToolSpec(
        tool_id="test.http-recon",
        version="1.0.0",
        description="Deterministic HTTP discovery contract used by admission tests",
        risk_tier=ToolRiskTier.T1,
        categories=frozenset({"recon"}),
    )

    def prepare(self, request: ToolRequest) -> WorkerJob:  # pragma: no cover - not executed
        raise NotImplementedError

    def interpret(
        self,
        request: ToolRequest,
        result: WorkerResult,
    ) -> ToolResult:  # pragma: no cover - not executed
        raise NotImplementedError


class _HTTPReconAdapter:
    producer_id = "trusted-core:test-http-recon-v1"
    tool_id = _HTTPReconTool.spec.tool_id

    def extract_surfaces(
        self,
        request: ToolRequest,
        result: ToolResult,
    ) -> list[SurfaceCandidate]:
        del request
        if set(result.data) != {"discoveredUrl", "method", "confidence"}:
            raise ValueError("unexpected Recon result fields")
        url = result.data["discoveredUrl"]
        method = result.data["method"]
        confidence = result.data["confidence"]
        if not isinstance(url, str) or not isinstance(method, str):
            raise ValueError("invalid Recon locator")
        if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
            raise ValueError("invalid Recon confidence")
        return [
            SurfaceCandidate(
                locator=http_surface_locator(url=url, method=method),
                confidence=float(confidence),
            )
        ]


class _UnknownToolAdapter(_HTTPReconAdapter):
    tool_id = "test.unregistered-recon"


def _producer() -> TrustedSurfaceProducer:
    registry = ToolRegistry()
    registry.register(_HTTPReconTool())
    return TrustedSurfaceProducer(tools=registry, adapters=[_HTTPReconAdapter()])


def _sealed_source_run(
    tmp_path: Path,
    campaign: CampaignManifest,
    *,
    discovered_url: str = "https://staging.example.invalid/api/discovered",
    discovered_method: str = "GET",
    confidence: float = 0.85,
    policy_allowed: bool = True,
    result_request_id: str = "tool_recon_1",
) -> tuple[RunStore, ToolRequest, ToolResult]:
    store = RunStore.create(tmp_path / "source", campaign.metadata.name)
    request = ToolRequest(
        request_id="tool_recon_1",
        agent_id="agent:recon",
        tool_id=_HTTPReconTool.spec.tool_id,
        target=campaign.spec.targets[0].endpoint,
        method="GET",
    )
    result = ToolResult(
        request_id=result_request_id,
        tool_id=request.tool_id,
        success=True,
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
        data={
            "discoveredUrl": discovered_url,
            "method": discovered_method,
            "confidence": confidence,
        },
    )
    decision = PolicyDecision(
        allowed=policy_allowed,
        reason="all policy checks passed" if policy_allowed else "denied by fixture",
        policy="allow" if policy_allowed else "scope-deny",
    )
    store.append_event(
        "campaign.started",
        {"campaign": campaign.metadata.name, "mode": campaign.spec.mode.value},
        occurred_at=NOW - timedelta(seconds=2),
    )
    store.write_json("campaign.json", campaign.model_dump(mode="json", by_alias=True))
    store.append_event(
        "tool.policy_evaluated",
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "allowed": decision.allowed,
            "policy": decision.policy,
            "reason": decision.reason,
        },
        occurred_at=NOW - timedelta(seconds=1),
    )
    store.write_json_create_only(
        EVIDENCE_REFERENCE,
        {
            "request": request.model_dump(mode="json"),
            "policyDecision": decision.model_dump(mode="json"),
            "result": result.model_dump(mode="json"),
            "networkLogTrusted": True,
        },
    )
    store.append_event(
        "tool.completed",
        {
            "requestId": request.request_id,
            "toolId": request.tool_id,
            "success": True,
            "evidence": EVIDENCE_REFERENCE,
        },
        occurred_at=NOW + timedelta(seconds=1),
    )
    store.seal()
    return store, request, result


def _admit(
    producer: TrustedSurfaceProducer,
    store: RunStore,
    *,
    admitted_at: datetime = NOW + timedelta(minutes=1),
) -> TrustedSurfaceAdmission:
    return producer.produce_from_run(
        store.path,
        evidence_reference=EVIDENCE_REFERENCE,
        expected_run_id=store.run_id,
        admitted_at=admitted_at,
    )


def test_trusted_producer_binds_sealed_campaign_request_result_evidence_and_root(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, request, result = _sealed_source_run(tmp_path, sample_campaign)
    verification = verify_run_integrity(source.path)
    snapshot = load_verified_run_snapshot(source.path)

    admission = _admit(_producer(), source)
    surface_set = admission.surface_set

    assert admission.producer_id == _HTTPReconAdapter.producer_id
    assert admission.source_verification == verification
    assert surface_set.campaign == sample_campaign.metadata.name
    assert surface_set.run_id == source.run_id
    assert surface_set.source_root_digest == verification.root_digest
    assert len(surface_set.observations) == len(surface_set.surfaces) == 1
    observation = surface_set.observations[0]
    surface = surface_set.surfaces[0]
    assert observation.target_id == sample_campaign.spec.targets[0].id
    assert observation.request_id == request.request_id
    assert observation.tool_id == request.tool_id
    assert observation.observed_at == result.finished_at
    assert observation.locator.url == "https://staging.example.invalid/api/discovered"
    assert observation.locator.method == "GET"
    assert observation.evidence[0].reference == EVIDENCE_REFERENCE
    assert observation.evidence[0].sha256 == next(
        artifact.sha256
        for seal in snapshot.seals
        for artifact in seal.artifacts
        if artifact.path == EVIDENCE_REFERENCE
    )
    assert surface.observation_ids == [observation.observation_id]
    assert surface.confidence == 0.85


@pytest.mark.parametrize(
    ("url", "message"),
    [
        ("https://outside.example.invalid/api/discovered", "outside the Campaign allow scope"),
        (
            "https://staging.example.invalid/api/admin/delete",
            "matches an explicit deny rule",
        ),
    ],
)
def test_admission_rejects_out_of_scope_or_explicitly_denied_surfaces(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    url: str,
    message: str,
) -> None:
    source, _, _ = _sealed_source_run(tmp_path, sample_campaign, discovered_url=url)

    with pytest.raises(SurfaceAdmissionError, match=message):
        _admit(_producer(), source)


def test_admission_rejects_discovered_methods_outside_campaign_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, _ = _sealed_source_run(
        tmp_path,
        sample_campaign,
        discovered_method="DELETE",
    )

    with pytest.raises(SurfaceAdmissionError, match="method exceeds Campaign authority"):
        _admit(_producer(), source)


def test_admission_revalidates_authorization_and_tool_risk(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    expired = sample_campaign.model_copy(
        deep=True,
        update={
            "spec": sample_campaign.spec.model_copy(
                deep=True,
                update={
                    "authorization": sample_campaign.spec.authorization.model_copy(
                        update={"expires_at": NOW - timedelta(seconds=1)}
                    )
                },
            )
        },
    )
    expired_source, _, _ = _sealed_source_run(tmp_path / "expired", expired)
    with pytest.raises(SurfaceAdmissionError, match="authorization was inactive"):
        _admit(_producer(), expired_source)

    low_risk = sample_campaign.model_copy(
        deep=True,
        update={
            "spec": sample_campaign.spec.model_copy(
                deep=True,
                update={
                    "rules_of_engagement": sample_campaign.spec.rules_of_engagement.model_copy(
                        update={"max_tool_risk_tier": ToolRiskTier.T0}
                    )
                },
            )
        },
    )
    risk_source, _, _ = _sealed_source_run(tmp_path / "risk", low_risk)
    with pytest.raises(SurfaceAdmissionError, match="risk exceeds Campaign authority"):
        _admit(_producer(), risk_source)


def test_admission_rejects_denied_or_mismatched_gateway_lineage(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    denied_source, _, _ = _sealed_source_run(
        tmp_path / "denied",
        sample_campaign,
        policy_allowed=False,
    )
    with pytest.raises(SurfaceAdmissionError, match="policy or completion was not allowed"):
        _admit(_producer(), denied_source)

    mismatched_source, _, _ = _sealed_source_run(
        tmp_path / "mismatch",
        sample_campaign,
        result_request_id="tool_other_request",
    )
    with pytest.raises(SurfaceAdmissionError, match="result differs from its source request"):
        _admit(_producer(), mismatched_source)


def test_producer_requires_code_registered_tool_adapter() -> None:
    registry = ToolRegistry()
    registry.register(_HTTPReconTool())

    with pytest.raises(ValueError, match="requires a registered Tool"):
        TrustedSurfaceProducer(tools=registry, adapters=[_UnknownToolAdapter()])


def test_projection_is_append_only_and_preserves_the_source_run(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, _ = _sealed_source_run(tmp_path, sample_campaign)
    producer = _producer()
    first_admission = _admit(producer, source)
    source_before = verify_run_integrity(source.path)
    projection = RunStore.create(tmp_path / "projection", sample_campaign.metadata.name)

    first = publish_surface_projection(projection, first_admission)
    first_bytes = (projection.path / first.artifact_path).read_bytes()
    assert verify_run_integrity(source.path) == source_before
    assert first.source_run_id == source.run_id
    assert first.source_root_digest == source_before.root_digest
    assert first.surface_set_id == first_admission.surface_set.surface_set_id
    assert verify_run_integrity(projection.path).root_digest == first.projection_root_digest

    second_admission = _admit(
        producer,
        source,
        admitted_at=NOW + timedelta(minutes=2),
    )
    second = publish_surface_projection(projection, second_admission)
    projection_verification = verify_run_integrity(projection.path)
    assert second.surface_set_id != first.surface_set_id
    assert second.artifact_path != first.artifact_path
    assert projection_verification.seal_count == 2
    assert (projection.path / first.artifact_path).read_bytes() == first_bytes
    assert verify_run_integrity(source.path) == source_before

    first_payload = parse_strict_json_bytes(first_bytes, label="published Surface Set")
    assert first_payload == first_admission.surface_set.model_dump(mode="json", by_alias=True)


def test_projection_rejects_duplicate_forged_mutated_or_source_run_authority(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, _ = _sealed_source_run(tmp_path, sample_campaign)
    admission = _admit(_producer(), source)
    projection = RunStore.create(tmp_path / "projection", sample_campaign.metadata.name)
    publish_surface_projection(projection, admission)
    projection_before = verify_run_integrity(projection.path)

    with pytest.raises(SurfaceProjectionConflict, match="already exists"):
        publish_surface_projection(projection, admission)
    assert verify_run_integrity(projection.path) == projection_before

    with pytest.raises(SurfaceAdmissionError, match="trusted admission authority"):
        publish_surface_projection(projection, admission.surface_set)  # type: ignore[arg-type]

    forged = TrustedSurfaceAdmission(
        producer_id=admission.producer_id,
        source_tool_spec=admission.source_tool_spec,
        source_run_path=admission.source_run_path,
        source_verification=admission.source_verification,
        evidence_reference=admission.evidence_reference,
        surface_set=admission.surface_set,
        authority_digest=admission.authority_digest,
        _authority=object(),
    )
    with pytest.raises(SurfaceAdmissionError, match="trusted admission authority"):
        publish_surface_projection(projection, forged)

    mutated = _admit(
        _producer(),
        source,
        admitted_at=NOW + timedelta(minutes=3),
    )
    mutated.surface_set.generated_at = NOW + timedelta(minutes=4)
    with pytest.raises(SurfaceAdmissionError, match="authority was mutated"):
        publish_surface_projection(projection, mutated)

    with pytest.raises(SurfaceAdmissionError, match="separate from its source Run"):
        publish_surface_projection(source, admission)


def test_projection_rejects_source_run_extension_after_admission(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    source, _, _ = _sealed_source_run(tmp_path, sample_campaign)
    admission = _admit(_producer(), source)
    projection = RunStore.create(tmp_path / "projection", sample_campaign.metadata.name)
    source.append_event("source.extended", {"reason": "new immutable fact"})
    source.seal()

    with pytest.raises(SurfaceAdmissionError, match="changed after admission"):
        publish_surface_projection(projection, admission)


def test_empty_trusted_result_produces_a_versioned_empty_admission(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
) -> None:
    class _EmptyAdapter(_HTTPReconAdapter):
        producer_id = "trusted-core:test-empty-recon-v1"

        def extract_surfaces(
            self,
            request: ToolRequest,
            result: ToolResult,
        ) -> list[SurfaceCandidate]:
            del request, result
            return []

    source, _, _ = _sealed_source_run(tmp_path, sample_campaign)
    registry = ToolRegistry()
    registry.register(_HTTPReconTool())
    producer = TrustedSurfaceProducer(tools=registry, adapters=[_EmptyAdapter()])

    admission = _admit(producer, source)

    assert admission.surface_set.observations == []
    assert admission.surface_set.surfaces == []
