from __future__ import annotations

import asyncio
import json
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path

import pytest
from pydantic import ValidationError

from pajin.discovery import (
    DiscoveryAdapterRegistry,
    HTTPAndOpenAPIRAGSurfaceAdapter,
    HTTPAuthenticationSurfaceLocator,
    HTTPRAGInjectionReconPlanner,
    HTTPRAGSurfaceLocator,
    ModeNeutralAttackChainAuthority,
    ModeNeutralAttackChainError,
    ReconWaveOutcome,
    SingleReconWaveRunner,
    TrustedSurfaceProducer,
    compile_auth_bypass_ai_admin_chain,
    registered_auth_bypass_ai_admin_chain_contract,
    verify_auth_bypass_ai_admin_chain,
)
from pajin.domain.models import CampaignManifest, CampaignMode
from pajin.policy.engine import PolicyEngine
from pajin.runtime.secrets import SecretMaterial
from pajin.runtime.worker import (
    DockerWorkerBackend,
    NetworkMode,
    WorkerJob,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.base import (
    EGRESS_HTTP_RECEIPT_VERSION,
    ToolRegistry,
    audit_http_target,
    http_target_sha256,
)
from pajin.tools.http import HTTPGetTool

TARGET = "https://staging.example.invalid/api/openapi.json"


def _campaign(sample_campaign: CampaignManifest, mode: CampaignMode) -> CampaignManifest:
    payload = sample_campaign.model_dump(mode="json", by_alias=True)
    payload["spec"]["mode"] = mode.value
    payload["spec"]["targets"][0]["endpoint"] = TARGET
    return CampaignManifest.model_validate(payload)


def _openapi_document(*, allows_anonymous: bool = False) -> dict[str, object]:
    security: list[dict[str, list[str]]] = [{"BearerAuth": []}]
    if allows_anonymous:
        security.append({})
    return {
        "openapi": "3.1.0",
        "servers": [{"url": "/api"}],
        "components": {
            "securitySchemes": {
                "BearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
        "security": security,
        "paths": {
            "/documents": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "corpus-ingest",
                        "corpusIds": ["knowledge-base"],
                        "indexIds": [],
                    },
                    "requestBody": {
                        "required": True,
                        "content": {
                            "multipart/form-data": {
                                "schema": {
                                    "type": "object",
                                    "required": ["document"],
                                    "properties": {
                                        "document": {"type": "string", "format": "binary"}
                                    },
                                }
                            }
                        },
                    },
                    "responses": {"202": {"description": "accepted"}},
                }
            },
            "/indexes/{index_id}": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "index-management",
                        "corpusIds": ["knowledge-base"],
                        "indexIds": ["primary-index"],
                    },
                    "responses": {"204": {"description": "updated"}},
                }
            },
            "/search": {
                "post": {
                    "x-pajin-rag": {
                        "version": "1",
                        "boundary": "retrieval",
                        "corpusIds": ["knowledge-base"],
                        "indexIds": ["primary-index"],
                    },
                    "responses": {"200": {"description": "results"}},
                }
            },
        },
    }


def _docker_backend(
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> DockerWorkerBackend:
    body = json.dumps(document, separators=(",", ":")).encode("utf-8")
    body_digest = sha256(body).hexdigest()

    async def run(
        self: DockerWorkerBackend,
        job: WorkerJob,
        *,
        secrets: list[SecretMaterial] | None = None,
    ) -> WorkerResult:
        del self
        assert not secrets
        assert job.network is NetworkMode.EGRESS_PROXY
        occurred_at = datetime.now(UTC)
        return WorkerResult(
            execution_id=job.execution_id,
            backend="docker",
            status=WorkerStatus.SUCCEEDED,
            exit_code=0,
            stdout=json.dumps(
                {
                    "target": TARGET,
                    "status": 200,
                    "contentType": "application/json",
                    "bodyPreview": body.decode("utf-8"),
                    "bodySha256": body_digest,
                    "responseBodyBase64": b64encode(body).decode("ascii"),
                },
                separators=(",", ":"),
            ),
            network_log="\n".join(
                [
                    json.dumps({"event": "ready", "port": 8080}),
                    json.dumps(
                        {
                            "event": "allow",
                            "receiptVersion": EGRESS_HTTP_RECEIPT_VERSION,
                            "sequence": 1,
                            "method": "GET",
                            "target": audit_http_target(TARGET),
                            "targetSha256": http_target_sha256(TARGET),
                            "address": "203.0.113.10",
                            "status": 200,
                            "responseBodySha256": body_digest,
                        }
                    ),
                ]
            ),
            started_at=occurred_at,
            finished_at=occurred_at,
        )

    monkeypatch.setattr(DockerWorkerBackend, "run", run)
    return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})


def _recon(
    tmp_path: Path,
    campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    document: dict[str, object],
) -> ReconWaveOutcome:
    tools = ToolRegistry()
    tool = HTTPGetTool()
    tools.register(tool)
    adapter = HTTPAndOpenAPIRAGSurfaceAdapter(
        tool=tool,
        allowed_methods=("GET", "POST"),
    )
    registry = DiscoveryAdapterRegistry(tools=tools, adapters=[adapter])
    reference = registry.definitions()[0].reference()
    producer = TrustedSurfaceProducer.from_adapter_registry(
        tools=tools,
        registry=registry,
        adapter_references=[reference],
    )
    runner = SingleReconWaveRunner(
        planner=HTTPRAGInjectionReconPlanner(
            tool=tool,
            target_id=campaign.spec.targets[0].id,
            adapter_reference=reference,
        ),
        producer=producer,
        tools=tools,
        policy=PolicyEngine(),
        worker=_docker_backend(monkeypatch, document),
        output_root=tmp_path,
    )
    return asyncio.run(runner.run(campaign))


def _surface_ids(recon: ReconWaveOutcome, path: str, boundary: str) -> tuple[str, str]:
    surface_set = recon.surface_set
    authentication = [
        surface
        for surface in surface_set.surfaces
        if isinstance(surface.locator, HTTPAuthenticationSurfaceLocator)
        and surface.locator.route.path_template == path
    ]
    rag = [
        surface
        for surface in surface_set.surfaces
        if isinstance(surface.locator, HTTPRAGSurfaceLocator)
        and surface.locator.route.path_template == path
        and surface.locator.boundary == boundary
    ]
    assert len(authentication) == len(rag) == 1
    return authentication[0].surface_id, rag[0].surface_id


def test_chain001_contract_is_deterministic_mode_neutral_and_non_executable() -> None:
    first = registered_auth_bypass_ai_admin_chain_contract()
    second = registered_auth_bypass_ai_admin_chain_contract()

    assert first == second
    assert first.chain_id == "chain-001:auth-bypass-to-ai-admin-surface"
    assert first.campaign_mode_constraint == "none"
    assert first.chain_state == "hypothesized-not-validated"
    assert first.capability_granted is False
    assert first.execution_authorized is False
    assert first.claim_replay_authorized is False
    assert first.finding_confirmed is False


@pytest.mark.parametrize("mode", list(CampaignMode))
def test_chain001_compiles_the_same_contract_for_every_campaign_mode(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
    mode: CampaignMode,
) -> None:
    campaign = _campaign(sample_campaign, mode)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    source_id, target_id = _surface_ids(recon, "/indexes/{index_id}", "index-management")

    first = compile_auth_bypass_ai_admin_chain(
        campaign,
        recon,
        source_surface_id=source_id,
        target_surface_id=target_id,
    )
    second = compile_auth_bypass_ai_admin_chain(
        campaign.model_copy(deep=True),
        recon,
        source_surface_id=source_id,
        target_surface_id=target_id,
    )

    assert first == second
    assert first.contract == registered_auth_bypass_ai_admin_chain_contract()
    assert first.campaign_mode_constraint == "none"
    assert first.source_surface.target_id == first.target_surface.target_id
    assert first.source_surface.locator_kind == "http-authentication"
    assert first.target_surface.locator_kind == "http-rag"
    assert first.surface_snapshot.surface_set_id == recon.surface_set.surface_set_id
    assert verify_auth_bypass_ai_admin_chain(first, campaign, recon) == first


def test_chain001_rejects_cross_route_and_non_admin_surface_substitution(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    source_documents, _ = _surface_ids(recon, "/documents", "corpus-ingest")
    source_search, target_search = _surface_ids(recon, "/search", "retrieval")
    _, target_admin = _surface_ids(recon, "/indexes/{index_id}", "index-management")

    with pytest.raises(ModeNeutralAttackChainError, match="sealed Surface authority"):
        compile_auth_bypass_ai_admin_chain(
            campaign,
            recon,
            source_surface_id=source_documents,
            target_surface_id=target_admin,
        )
    with pytest.raises(ModeNeutralAttackChainError, match="sealed Surface authority"):
        compile_auth_bypass_ai_admin_chain(
            campaign,
            recon,
            source_surface_id=source_search,
            target_surface_id=target_search,
        )


def test_chain001_rejects_anonymous_authentication_boundary(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.BUG_BOUNTY)
    recon = _recon(
        tmp_path,
        campaign,
        monkeypatch,
        _openapi_document(allows_anonymous=True),
    )
    source_id, target_id = _surface_ids(recon, "/indexes/{index_id}", "index-management")

    with pytest.raises(ModeNeutralAttackChainError, match="sealed Surface authority"):
        compile_auth_bypass_ai_admin_chain(
            campaign,
            recon,
            source_surface_id=source_id,
            target_surface_id=target_id,
        )


def test_chain001_rejects_authority_forgery_cross_target_and_stale_recon(
    tmp_path: Path,
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    campaign = _campaign(sample_campaign, CampaignMode.AI_REDTEAM)
    first_recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    source_id, target_id = _surface_ids(
        first_recon,
        "/indexes/{index_id}",
        "index-management",
    )
    authority = compile_auth_bypass_ai_admin_chain(
        campaign,
        first_recon,
        source_surface_id=source_id,
        target_surface_id=target_id,
    )

    raw = authority.model_dump(mode="json", by_alias=True)
    raw["executionAuthorized"] = True
    with pytest.raises(ValidationError, match="must be boolean false"):
        ModeNeutralAttackChainAuthority.model_validate(raw)

    raw = authority.model_dump(mode="json", by_alias=True)
    raw["authorityId"] = ""
    raw["authorityDigest"] = ""
    raw["targetSurface"]["targetId"] = "target:foreign"
    with pytest.raises(ValidationError, match="target binding"):
        ModeNeutralAttackChainAuthority.model_validate(raw)

    raw = authority.model_dump(mode="json", by_alias=True)
    raw["authorityId"] = ""
    raw["authorityDigest"] = ""
    raw["routeDigest"] = "0" * 64
    with pytest.raises(ValidationError, match="route Digest"):
        ModeNeutralAttackChainAuthority.model_validate(raw)

    forged = replace(
        first_recon,
        surface_set=first_recon.surface_set.model_copy(
            update={"campaign": "forged-campaign"},
            deep=True,
        ),
    )
    with pytest.raises(ModeNeutralAttackChainError, match="sealed Surface authority"):
        compile_auth_bypass_ai_admin_chain(
            campaign,
            forged,
            source_surface_id=source_id,
            target_surface_id=target_id,
        )

    second_recon = _recon(tmp_path, campaign, monkeypatch, _openapi_document())
    with pytest.raises(ModeNeutralAttackChainError, match="verified"):
        verify_auth_bypass_ai_admin_chain(authority, campaign, second_recon)
