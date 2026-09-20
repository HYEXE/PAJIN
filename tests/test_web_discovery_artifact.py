from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from inspect import signature
from pathlib import Path

import pytest

from pajin.runtime.store import RunStore
from pajin.runtime.worker import EgressPolicy
from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.discovery import (
    BrowserDiscoveryPlan,
    BrowserDiscoveryResult,
    DiscoveredBrowserRoute,
)
from pajin.web_assessment.discovery_artifact import (
    AuthenticatedDiscoveryRunArtifacts,
    AuthenticatedDiscoveryRunError,
    AuthenticatedDiscoveryRunIntegrityError,
    _run_authenticated_discovery_artifact,
    code_owned_authenticated_discovery_plan,
    load_verified_authenticated_discovery,
    run_sealed_authenticated_discovery,
)
from pajin.web_assessment.discovery_runtime import (
    GovernedAuthenticatedDiscoveryObservation,
)
from pajin.web_assessment.models import (
    LocalWebAssessmentAuthorization,
    WebAssessmentPlan,
)
from pajin.web_assessment.network import AssessmentNetwork, PassiveMetadataCompletion
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import ProvisionedLocalWebAssessmentAccount

_ORIGIN = "http://127.0.0.1:4317"
_USERNAME = "artifact-only-user@example.test"
_PASSWORD = "Artifact-Only-Password-Unique!"
_FORBIDDEN_BODY = b"unique-response-body-that-must-never-be-persisted"
_FORBIDDEN_DOM = b'<main data-private="unique-raw-dom-marker">'
_FORBIDDEN_SCREENSHOT = b"unique-png-screenshot-marker"


def _inputs() -> tuple[
    WebAssessmentPlan,
    LocalWebAssessmentAuthorization,
    ProvisionedLocalWebAssessmentAccount,
    BrowserDiscoveryPlan,
]:
    plan = juice_shop_plan(_ORIGIN)
    approved_at = datetime.now(UTC) - timedelta(seconds=5)
    authorization = LocalWebAssessmentAuthorization(
        plan_digest=plan.plan_digest,
        origin=plan.origin,
        approved_at=approved_at,
        expires_at=approved_at + timedelta(minutes=30),
    )
    account = ProvisionedLocalWebAssessmentAccount(
        credentials=BrowserCredentials(_USERNAME, _PASSWORD),
        plan_digest=plan.plan_digest,
        authorization_id=authorization.authorization_id,
        origin=plan.origin,
        target_version="synthetic-test-version",
        provisioned_at=approved_at + timedelta(seconds=1),
        request_evidence=(),
        target_product=plan.target_product,
        fingerprint_version_path=plan.fingerprint_version_path,
        adapter_implementation_id=plan.adapter_implementation_id,
    )
    discovery_plan = code_owned_authenticated_discovery_plan(plan)
    return plan, authorization, account, discovery_plan


def _result(discovery_plan: BrowserDiscoveryPlan) -> BrowserDiscoveryResult:
    return BrowserDiscoveryResult(
        plan_digest=discovery_plan.plan_digest,
        origin=discovery_plan.origin,
        routes=(
            DiscoveredBrowserRoute(
                route=discovery_plan.seed_routes[0],
                depth=0,
                source="seed",
            ),
        ),
        route_limit_reached=False,
        form_limit_reached=False,
        field_limit_reached=False,
    )


async def _fake_executor(
    *,
    assessment_plan: WebAssessmentPlan,
    discovery_plan: BrowserDiscoveryPlan,
    network: AssessmentNetwork,
    credentials: BrowserCredentials,
    navigation_policy: EgressPolicy,
    headless: bool,
) -> GovernedAuthenticatedDiscoveryObservation:
    assert type(network) is AssessmentNetwork
    assert network.phase == "uninitialized"
    assert credentials == BrowserCredentials(_USERNAME, _PASSWORD)
    assert headless is True
    passive_policy = navigation_policy.model_copy(update={"allowed_methods": {"GET"}})
    network.begin_phase("browser-passive-discovery", passive_policy)
    completions: list[PassiveMetadataCompletion] = []
    for path, observed_bytes, media_type in (
        ("/assets/runtime.js", len(_FORBIDDEN_BODY), "application/javascript; charset=utf-8"),
        ("/assets/theme.css", 2_048, "text/css; charset=utf-8"),
    ):
        reservation = await network.reserve("GET", assessment_plan.origin + path)
        completion = await network.complete_passive_metadata(
            reservation,
            status=200,
            headers={"content-type": media_type},
            observed_response_bytes=observed_bytes,
            return_boundary_receipt=True,
        )
        completions.append(completion)
    return GovernedAuthenticatedDiscoveryObservation(
        discovery_result=_result(discovery_plan),
        request_evidence=tuple(item.evidence for item in completions),
        boundary_receipts=tuple(item.boundary_receipt for item in completions),
    )


async def _run_fake(
    output_root: Path,
    *,
    executor: Callable[..., Awaitable[GovernedAuthenticatedDiscoveryObservation]] = (
        _fake_executor
    ),
) -> AuthenticatedDiscoveryRunArtifacts:
    plan, authorization, account, discovery_plan = _inputs()
    return await _run_authenticated_discovery_artifact(
        plan=plan,
        authorization=authorization,
        account=account,
        discovery_plan=discovery_plan,
        output_root=output_root,
        headless=True,
        executor=executor,
    )


@pytest.mark.asyncio
async def test_discovery_only_run_retains_ordered_bodyless_receipts_and_no_secrets(
    tmp_path: Path,
) -> None:
    artifacts = await _run_fake(tmp_path)

    verified = load_verified_authenticated_discovery(
        artifacts.run_path,
        expected_run_id=artifacts.index.run_id,
        expected_root_digest=artifacts.root_digest,
    )

    assert tuple(item.path for item in verified.discovery.request_evidence) == (
        "/assets/runtime.js",
        "/assets/theme.css",
    )
    assert tuple(item.evidence_id for item in verified.discovery.boundary_receipts) == tuple(
        item.evidence_id for item in verified.discovery.request_evidence
    )
    assert tuple(
        item.observed_response_body_bytes for item in verified.discovery.boundary_receipts
    ) == (len(_FORBIDDEN_BODY), 2_048)
    assert all(item.response_bytes == 0 for item in verified.discovery.request_evidence)
    assert verified.discovery.browser_closed is True
    assert verified.index.browser_closed is True
    assert verified.index.diagnostic_invocation_count == 0
    assert verified.index.tool_request_count == 0
    assert verified.index.action_permit_count == 0
    assert verified.index.finding_count == 0
    assert verified.index.graph_mutation_count == 0

    retained = b"\n".join(
        path.read_bytes() for path in artifacts.run_path.rglob("*") if path.is_file()
    )
    for forbidden in (
        _USERNAME.encode(),
        _PASSWORD.encode(),
        _FORBIDDEN_BODY,
        _FORBIDDEN_DOM,
        _FORBIDDEN_SCREENSHOT,
    ):
        assert forbidden not in retained


@pytest.mark.asyncio
async def test_discovery_only_run_uses_create_only_artifact_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    writes: list[str] = []
    original = RunStore.write_json_create_only

    def record_create_only(self: RunStore, path: str, data: object) -> str:
        writes.append(path)
        return original(self, path, data)

    def reject_replaceable_write(
        _self: RunStore,
        _path: str,
        _data: object,
    ) -> str:
        raise AssertionError("discovery-only artifacts must use create-only writes")

    monkeypatch.setattr(RunStore, "write_json_create_only", record_create_only)
    monkeypatch.setattr(RunStore, "write_json", reject_replaceable_write)

    artifacts = await _run_fake(tmp_path)

    assert writes == ["plan.json", "authorization.json", "discovery.json", "index.json"]
    assert artifacts.run_path.joinpath("run-integrity.jsonl").read_text().count("\n") == 1


@pytest.mark.asyncio
async def test_public_runner_has_no_replaceable_executor_or_network_seam() -> None:
    parameters = signature(run_sealed_authenticated_discovery).parameters

    assert "executor" not in parameters
    assert "network" not in parameters
    assert "session_factory" not in parameters


@pytest.mark.asyncio
async def test_loader_rejects_tampered_sealed_artifact(tmp_path: Path) -> None:
    artifacts = await _run_fake(tmp_path)
    raw = json.loads(artifacts.index_path.read_text())
    raw["diagnosticInvocationCount"] = 1
    artifacts.index_path.write_text(json.dumps(raw))

    with pytest.raises(
        AuthenticatedDiscoveryRunIntegrityError,
        match="strict verification",
    ):
        load_verified_authenticated_discovery(
            artifacts.run_path,
            expected_run_id=artifacts.index.run_id,
            expected_root_digest=artifacts.root_digest,
        )


@pytest.mark.asyncio
async def test_loader_rejects_wrong_independent_anchors(tmp_path: Path) -> None:
    artifacts = await _run_fake(tmp_path)
    wrong_run_id = "run_20000101T000000Z_00000000"

    with pytest.raises(AuthenticatedDiscoveryRunIntegrityError):
        load_verified_authenticated_discovery(
            artifacts.run_path,
            expected_run_id=wrong_run_id,
            expected_root_digest=artifacts.root_digest,
        )
    with pytest.raises(AuthenticatedDiscoveryRunIntegrityError, match="Run shape differs"):
        load_verified_authenticated_discovery(
            artifacts.run_path,
            expected_run_id=artifacts.index.run_id,
            expected_root_digest="0" * 64,
        )


@pytest.mark.asyncio
async def test_runner_rejects_false_browser_closed_before_persistence(tmp_path: Path) -> None:
    async def unclosed_executor(
        **kwargs: object,
    ) -> GovernedAuthenticatedDiscoveryObservation:
        observation = await _fake_executor(**kwargs)  # type: ignore[arg-type]
        return GovernedAuthenticatedDiscoveryObservation(
            discovery_result=observation.discovery_result,
            request_evidence=observation.request_evidence,
            boundary_receipts=observation.boundary_receipts,
            browser_closed=False,  # type: ignore[arg-type]
        )

    with pytest.raises(RuntimeError, match="governed boundary"):
        await _run_fake(tmp_path, executor=unclosed_executor)

    assert not tuple(tmp_path.rglob("*.json"))


@pytest.mark.asyncio
async def test_runner_rejects_caller_modified_discovery_plan_before_executor(
    tmp_path: Path,
) -> None:
    plan, authorization, account, discovery_plan = _inputs()
    raw = discovery_plan.model_dump(mode="json", by_alias=True, exclude={"plan_digest"})
    raw["max_routes"] = discovery_plan.max_routes + 1
    modified = BrowserDiscoveryPlan.model_validate(raw)
    called = False

    async def unexpected_executor(
        **_kwargs: object,
    ) -> GovernedAuthenticatedDiscoveryObservation:
        nonlocal called
        called = True
        raise AssertionError("modified discovery plan reached executor")

    with pytest.raises(AuthenticatedDiscoveryRunError, match="exact authenticated route"):
        await _run_authenticated_discovery_artifact(
            plan=plan,
            authorization=authorization,
            account=account,
            discovery_plan=modified,
            output_root=tmp_path,
            headless=True,
            executor=unexpected_executor,
        )

    assert called is False
    assert list(tmp_path.iterdir()) == []


@pytest.mark.asyncio
async def test_executor_failure_leaves_no_unsealed_partial_run(tmp_path: Path) -> None:
    async def failing_executor(
        **_kwargs: object,
    ) -> GovernedAuthenticatedDiscoveryObservation:
        raise RuntimeError("synthetic executor failure")

    with pytest.raises(RuntimeError, match="synthetic executor failure"):
        await _run_fake(tmp_path, executor=failing_executor)

    assert list(tmp_path.iterdir()) == []
