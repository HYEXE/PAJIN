from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import textwrap
import time
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import httpx
import pytest

from pajin.capabilities.web_authenticated_assessment import WebAuthenticatedAssessmentTool
from pajin.domain.models import ToolRequest
from pajin.policy.engine import PolicyEngine
from pajin.runtime.pinned_workspace import PinnedOutputRoot, PinnedWorkspaceError
from pajin.runtime.secrets import SecretBroker, SecretMaterial
from pajin.runtime.worker import EgressPolicy, NetworkMode, WorkerJob, WorkerStatus
from pajin.tools.base import ToolRegistry
from pajin.tools.gateway import RequestRateLimitLedger
from pajin.web_assessment import governed_worker as governed_worker_module
from pajin.web_assessment import runner as runner_module
from pajin.web_assessment import worker_process
from pajin.web_assessment.adapter_catalog import JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
from pajin.web_assessment.governed_gateway import (
    HostLoopbackWebAssessmentGateway,
    WebGatewayCompletedActionAuthority,
    WebGatewayCompletionReceipt,
)
from pajin.web_assessment.governed_models import (
    ProvisionedWebAccountReceipt,
    ProvisionedWebAccountReceiptRegistry,
    WebAssessmentAdapterManifest,
    WebAssessmentAdapterRegistry,
    WebAssessmentDispatchBinding,
)
from pajin.web_assessment.governed_worker import (
    WEB_ACCOUNT_NAME_BINDING,
    WEB_ACCOUNT_PROOF_BINDING,
    WEB_ASSESSMENT_EXECUTOR_COMMAND,
    WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
    WEB_WORKER_OS_ENV_ALLOWLIST,
    WEB_WORKER_SIGNING_KEY_BINDING,
    AsyncioWebWorkerSubprocessRunner,
    HostLoopbackBrowserWorkerBackend,
    HostLoopbackWebAssessmentJobCompiler,
    HostLoopbackWebAssessmentOutputVerifier,
    HostLoopbackWebDeploymentContext,
    SignedWebExecutionAttestation,
    SignedWebTargetIdentity,
    SignedWebWorkerActionEvidence,
    WebExecutionStatement,
    WebIndependentWorkerEvidence,
    WebProvisionedAccountMaterial,
    WebSubprocessCapture,
    WebTargetIdentityStatement,
    WebWorkerAttestor,
    WebWorkerAuthorityBinding,
    WebWorkerCompletedActionAuthority,
    WebWorkerJobSpec,
    WebWorkerKeyState,
    WebWorkerProcessInput,
    WebWorkerRole,
    WebWorkerTrustRegistry,
    WebWorkerVerificationKey,
    _activate_governed_coordinator_worker_group,
    _create_governed_coordinator_worker_group_authority,
    _web_worker_starts_new_session,
    canonical_web_worker_json,
    verify_independent_web_worker_evidence,
    verify_signed_web_target_identity,
    web_target_fingerprint_digest,
    web_worker_private_key_base64url,
    web_worker_public_key_base64url,
)
from pajin.web_assessment.models import RequestEvidence, WebAssessmentPlan
from pajin.web_assessment.recipes import juice_shop_plan
from pajin.web_assessment.runner import (
    issue_local_web_assessment_authorization,
    run_local_web_assessment,
)
from pajin.web_assessment.worker_process import WebTargetFingerprintProbe

NOW = datetime(2026, 9, 14, 8, 0, tzinfo=UTC)
ORIGIN = "http://127.0.0.1:3000"
VERSION = "19.2.1"
DEFAULT_PLAN = juice_shop_plan(ORIGIN)
TARGET_PRODUCT = DEFAULT_PLAN.target_product
ADAPTER_IMPLEMENTATION_ID = DEFAULT_PLAN.adapter_implementation_id
FINGERPRINT_ENDPOINT = DEFAULT_PLAN.fingerprint_endpoint
FINGERPRINT_BODY = canonical_web_worker_json({"version": VERSION})
FINGERPRINT_RESPONSE_SHA256 = sha256(FINGERPRINT_BODY).hexdigest()
ADAPTER_IMPLEMENTATION_DIGEST = JUICE_SHOP_ADAPTER_IMPLEMENTATION_DIGEST
RECIPE_DIGEST = DEFAULT_PLAN.plan_digest
SOURCE_RUN_ID = "run_20260914T080001Z_11111111"
VALIDATION_RUN_ID = "run_20260914T080002Z_22222222"


class _FrozenWebWorkerClock:
    @staticmethod
    def now(tz: object = None) -> datetime:
        verified_at = NOW + timedelta(seconds=5)
        return verified_at if tz is not None else verified_at.replace(tzinfo=None)


@pytest.fixture(autouse=True)
def _freeze_governed_worker_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(governed_worker_module, "datetime", _FrozenWebWorkerClock)


def _key_bytes(role: WebWorkerRole) -> bytes:
    return bytes([list(WebWorkerRole).index(role) + 1]) * 32


def _registry() -> WebWorkerTrustRegistry:
    keys = [
        WebWorkerVerificationKey(
            keyId=f"key:{role.value}",
            role=role,
            publicKeyBase64url=web_worker_public_key_base64url(_key_bytes(role)),
            state=WebWorkerKeyState.ACTIVE,
            notBefore=NOW - timedelta(days=1),
            notAfter=NOW + timedelta(days=1),
        )
        for role in WebWorkerRole
    ]
    return WebWorkerTrustRegistry(
        trustDomain="pajin.web.local-test",
        issuer="deployment:test",
        keys=tuple(sorted(keys, key=lambda item: (item.role.value, item.key_id))),
    )


def _authority(*, role: str) -> WebWorkerAuthorityBinding:
    marker = "a" if role == "source" else "b"
    return WebWorkerAuthorityBinding(
        campaignId="campaign:web-test",
        campaignDigest="1" * 64,
        capabilityId="pajin.bug-bounty.web-authenticated-read-only-assessment",
        capabilityVersion="1.0.0",
        capabilityDigest="2" * 64,
        capabilityGrantId=f"grant:{role}",
        capabilityGrantDigest=("0" if role == "source" else "1") * 64,
        capabilityGrantConsumptionReceiptId=f"grant-consumption:{role}",
        capabilityGrantConsumptionReceiptDigest=("8" if role == "source" else "9") * 64,
        adapterDigest="3" * 64,
        adapterImplementationDigest=ADAPTER_IMPLEMENTATION_DIGEST,
        recipeDigest=RECIPE_DIGEST,
        accountReceiptDigest="4" * 64,
        targetOrigin=ORIGIN,
        targetProduct=TARGET_PRODUCT,
        targetVersion=VERSION,
        targetFingerprintEndpoint=FINGERPRINT_ENDPOINT,
        expectedTargetResponseSha256=FINGERPRINT_RESPONSE_SHA256,
        expectedTargetFingerprintDigest=web_target_fingerprint_digest(
            origin=ORIGIN,
            product=TARGET_PRODUCT,
            version=VERSION,
            fingerprint_endpoint=FINGERPRINT_ENDPOINT,
            response_sha256=FINGERPRINT_RESPONSE_SHA256,
            adapter_implementation_digest=ADAPTER_IMPLEMENTATION_DIGEST,
            recipe_digest=RECIPE_DIGEST,
        ),
        requestId=f"tool_web_{role}",
        requestDigest=marker * 64,
        actionPermitId=f"permit:{role}",
        actionPermitDigest=("c" if role == "source" else "d") * 64,
        approvalId=f"approval:{role}",
        approvalDigest=("e" if role == "source" else "f") * 64,
        approvalReceiptId=f"approval-receipt:{role}",
        approvalReceiptDigest=("6" if role == "source" else "7") * 64,
        dispatchBindingDigest=("5" if role == "source" else "6") * 64,
        expectedRunId=SOURCE_RUN_ID if role == "source" else VALIDATION_RUN_ID,
    )


def _attestor(role: WebWorkerRole) -> WebWorkerAttestor:
    return WebWorkerAttestor.from_private_key_base64url(
        key_id=f"key:{role.value}",
        role=role,
        trust_domain="pajin.web.local-test",
        issuer="deployment:test",
        private_key_base64url=web_worker_private_key_base64url(_key_bytes(role)),
    )


def _target(
    *,
    role: WebWorkerRole,
    authority: WebWorkerAuthorityBinding,
    execution_id: str,
    process_id: int,
    response_body: bytes = FINGERPRINT_BODY,
) -> SignedWebTargetIdentity:
    statement = WebTargetIdentityStatement(
        trustDomain="pajin.web.local-test",
        issuer="deployment:test",
        authority=authority,
        role=role,
        executionId=execution_id,
        targetProduct=authority.target_product,
        targetVersion=authority.target_version,
        fingerprintEndpoint=authority.target_fingerprint_endpoint,
        observedTargetFingerprintDigest=authority.expected_target_fingerprint_digest,
        responseSha256=authority.expected_target_response_sha256,
        responseBytes=len(response_body),
        processId=process_id,
        startedAt=NOW,
        finishedAt=NOW + timedelta(seconds=1),
        issuedAt=NOW + timedelta(seconds=1),
    )
    return _attestor(role).sign_target(statement)


def _execution(
    *,
    role: WebWorkerRole,
    authority: WebWorkerAuthorityBinding,
    execution_id: str,
    process_id: int,
    target: SignedWebTargetIdentity,
    run_suffix: str,
) -> SignedWebExecutionAttestation:
    statement = WebExecutionStatement(
        trustDomain="pajin.web.local-test",
        issuer="deployment:test",
        authority=authority,
        role=role,
        executionId=execution_id,
        targetIdentityAttestationDigest=target.digest,
        runId=SOURCE_RUN_ID if run_suffix == "1" else VALIDATION_RUN_ID,
        runRootDigest=run_suffix * 64,
        resultDigest=("8" if run_suffix == "1" else "9") * 64,
        processId=process_id,
        startedAt=NOW + timedelta(seconds=2),
        finishedAt=NOW + timedelta(seconds=3),
        issuedAt=NOW + timedelta(seconds=3),
    )
    return _attestor(role).sign_execution(statement)


def test_four_way_independence_requires_two_target_observations() -> None:
    source_authority = _authority(role="source")
    validation_authority = _authority(role="validation")
    source_target = _target(
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        authority=source_authority,
        execution_id="exec:source-target",
        process_id=101,
    )
    source = _execution(
        role=WebWorkerRole.SOURCE_EXECUTOR,
        authority=source_authority,
        execution_id="exec:source",
        process_id=102,
        target=source_target,
        run_suffix="1",
    )
    validation_target = _target(
        role=WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        authority=validation_authority,
        execution_id="exec:validation-target",
        process_id=103,
    )
    validation = _execution(
        role=WebWorkerRole.VALIDATION_EXECUTOR,
        authority=validation_authority,
        execution_id="exec:validation",
        process_id=104,
        target=validation_target,
        run_suffix="2",
    )

    verified = verify_independent_web_worker_evidence(
        source_target=source_target,
        source=source,
        validation_target=validation_target,
        validation=validation,
        registry=_registry(),
    )

    assert isinstance(verified, WebIndependentWorkerEvidence)
    assert verified.process_ids == (101, 102, 103, 104)
    assert len(set(verified.key_ids)) == 4
    with pytest.raises(ValueError, match="outside key validity"):
        verify_independent_web_worker_evidence(
            source_target=source_target,
            source=source,
            validation_target=validation_target,
            validation=validation,
            registry=_registry(),
            verification_time=NOW + timedelta(days=2),
        )
    with pytest.raises(ValueError, match=r"target identity binding|observer role"):
        verify_independent_web_worker_evidence(
            source_target=source_target,
            source=source,
            validation_target=source_target,
            validation=validation,
            registry=_registry(),
        )


def test_trust_registry_rejects_distinct_key_ids_with_reused_public_key() -> None:
    reused_role = WebWorkerRole.SOURCE_TARGET_OBSERVER
    keys = [
        WebWorkerVerificationKey(
            keyId=f"key:{role.value}",
            role=role,
            publicKeyBase64url=web_worker_public_key_base64url(
                _key_bytes(reused_role if role is WebWorkerRole.VALIDATION_EXECUTOR else role)
            ),
            state=WebWorkerKeyState.ACTIVE,
            notBefore=NOW - timedelta(hours=1),
            notAfter=NOW + timedelta(hours=1),
        )
        for role in WebWorkerRole
    ]

    with pytest.raises(ValueError, match="distinct active public keys"):
        WebWorkerTrustRegistry(
            trustDomain="pajin.web.local-test",
            issuer="deployment:test",
            keys=tuple(sorted(keys, key=lambda item: (item.role.value, item.key_id))),
        )


def test_live_verifier_rejects_backdated_attestation_from_retired_key() -> None:
    retired_private_key = b"\x09" * 32
    retired_key = WebWorkerVerificationKey(
        keyId="key:source-target-observer:retired",
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        publicKeyBase64url=web_worker_public_key_base64url(retired_private_key),
        state=WebWorkerKeyState.RETIRED,
        notBefore=NOW - timedelta(days=3),
        notAfter=NOW - timedelta(days=1),
    )
    active_registry = _registry()
    registry = WebWorkerTrustRegistry(
        trustDomain=active_registry.trust_domain,
        issuer=active_registry.issuer,
        keys=tuple(
            sorted(
                (*active_registry.keys, retired_key),
                key=lambda item: (item.role.value, item.key_id),
            )
        ),
    )
    issued_at = NOW - timedelta(days=2)
    statement = WebTargetIdentityStatement(
        trustDomain=registry.trust_domain,
        issuer=registry.issuer,
        authority=_authority(role="source"),
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        executionId="exec:retired-source-target",
        targetProduct=TARGET_PRODUCT,
        targetVersion=VERSION,
        fingerprintEndpoint=FINGERPRINT_ENDPOINT,
        observedTargetFingerprintDigest=_authority(
            role="source"
        ).expected_target_fingerprint_digest,
        responseSha256=FINGERPRINT_RESPONSE_SHA256,
        responseBytes=len(FINGERPRINT_BODY),
        processId=202,
        startedAt=issued_at - timedelta(seconds=2),
        finishedAt=issued_at - timedelta(seconds=1),
        issuedAt=issued_at,
    )
    attestation = WebWorkerAttestor.from_private_key_base64url(
        key_id=retired_key.key_id,
        role=retired_key.role,
        trust_domain=registry.trust_domain,
        issuer=registry.issuer,
        private_key_base64url=web_worker_private_key_base64url(retired_private_key),
    ).sign_target(statement)

    with pytest.raises(ValueError, match="current ACTIVE role key"):
        verify_signed_web_target_identity(
            attestation,
            registry,
            verification_time=NOW,
        )

    expired_active_key = WebWorkerVerificationKey(
        keyId=f"key:{WebWorkerRole.SOURCE_TARGET_OBSERVER.value}",
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        publicKeyBase64url=web_worker_public_key_base64url(
            _key_bytes(WebWorkerRole.SOURCE_TARGET_OBSERVER)
        ),
        state=WebWorkerKeyState.ACTIVE,
        notBefore=NOW - timedelta(days=3),
        notAfter=NOW - timedelta(days=1),
    )
    expired_registry = WebWorkerTrustRegistry(
        trustDomain=active_registry.trust_domain,
        issuer=active_registry.issuer,
        keys=tuple(
            sorted(
                (
                    expired_active_key,
                    *(
                        key
                        for key in active_registry.keys
                        if key.role is not WebWorkerRole.SOURCE_TARGET_OBSERVER
                    ),
                ),
                key=lambda item: (item.role.value, item.key_id),
            )
        ),
    )
    expired_attestation = _attestor(WebWorkerRole.SOURCE_TARGET_OBSERVER).sign_target(statement)
    with pytest.raises(ValueError, match="outside key validity"):
        verify_signed_web_target_identity(
            expired_attestation,
            expired_registry,
            verification_time=NOW,
        )


def test_signature_tamper_fails_closed() -> None:
    target = _target(
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        authority=_authority(role="source"),
        execution_id="exec:source-target",
        process_id=201,
    )
    tampered = target.model_copy(update={"signature_base64url": "A" * 86})
    with pytest.raises(ValueError, match="signature verification failed"):
        verify_signed_web_target_identity(tampered, _registry())


def test_execution_statement_rejects_non_preallocated_run_id() -> None:
    authority = _authority(role="source")
    target = _target(
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        authority=authority,
        execution_id="exec:source-target",
        process_id=211,
    )

    with pytest.raises(ValueError, match="Run ID differs from preallocated authority"):
        WebExecutionStatement(
            trustDomain="pajin.web.local-test",
            issuer="deployment:test",
            authority=authority,
            role=WebWorkerRole.SOURCE_EXECUTOR,
            executionId="exec:source",
            targetIdentityAttestationDigest=target.digest,
            runId=VALIDATION_RUN_ID,
            runRootDigest="1" * 64,
            resultDigest="8" * 64,
            processId=212,
            startedAt=NOW + timedelta(seconds=2),
            finishedAt=NOW + timedelta(seconds=3),
            issuedAt=NOW + timedelta(seconds=3),
        )


@pytest.mark.asyncio
async def test_runner_default_run_id_remains_generated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = juice_shop_plan(ORIGIN)
    authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=datetime.now(UTC),
    )
    observed_run_id: list[str | None] = []

    def capture_create(
        _root: Path,
        _campaign_name: str,
        *,
        run_id: str | None = None,
    ) -> object:
        observed_run_id.append(run_id)
        raise RuntimeError("stop after RunStore.create")

    monkeypatch.setattr(runner_module.RunStore, "create", capture_create)

    with pytest.raises(RuntimeError, match=r"stop after RunStore\.create"):
        await run_local_web_assessment(
            plan=plan,
            authorization=authorization,
            output_root=tmp_path,
        )

    assert observed_run_id == [None]


class _FakeRunner:
    def __init__(self) -> None:
        self.invocations: list[
            tuple[tuple[str, ...], WebWorkerProcessInput, Mapping[str, str]]
        ] = []

    async def run(
        self,
        command: tuple[str, ...],
        *,
        stdin: bytes,
        env: Mapping[str, str],
        timeout_seconds: float,
        stdout_limit_bytes: int,
        stderr_limit_bytes: int,
    ) -> WebSubprocessCapture:
        del timeout_seconds, stdout_limit_bytes, stderr_limit_bytes
        payload = WebWorkerProcessInput.model_validate(json.loads(stdin))
        self.invocations.append((command, payload, env))
        pid = 301 + len(self.invocations)
        if payload.job.role in {
            WebWorkerRole.SOURCE_TARGET_OBSERVER,
            WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        }:
            output: SignedWebTargetIdentity | SignedWebExecutionAttestation = _target(
                role=payload.job.role,
                authority=payload.job.authority,
                execution_id=payload.job.execution_id,
                process_id=pid,
            )
        else:
            assert payload.job.target_identity is not None
            output = _execution(
                role=payload.job.role,
                authority=payload.job.authority,
                execution_id=payload.job.execution_id,
                process_id=pid,
                target=payload.job.target_identity,
                run_suffix="1",
            )
        return WebSubprocessCapture(
            pid=pid,
            exit_code=0,
            stdout=canonical_web_worker_json(output.model_dump(mode="json", by_alias=True)),
            stderr=b"",
            started_at=NOW - timedelta(seconds=1),
            finished_at=NOW + timedelta(seconds=4),
        )


class _TestBackend(HostLoopbackBrowserWorkerBackend):
    def _verify_sealed_execution(
        self,
        spec: object,
        attestation: SignedWebExecutionAttestation,
    ) -> None:
        del spec, attestation


def _fingerprint_evidence(
    suffix: str,
    *,
    plan: WebAssessmentPlan = DEFAULT_PLAN,
    response_body: bytes = FINGERPRINT_BODY,
) -> RequestEvidence:
    return RequestEvidence(
        evidence_id=f"http-1-{suffix * 8}",
        phase="target-fingerprint",
        method="GET",
        path=plan.fingerprint_endpoint,
        request_sha256=("8" if suffix == "a" else "9") * 64,
        status=200,
        response_sha256=sha256(response_body).hexdigest(),
        response_bytes=len(response_body),
        media_type="application/json",
    )


def _alternate_worker_plan() -> WebAssessmentPlan:
    raw = DEFAULT_PLAN.model_dump(mode="json")
    raw.update(
        {
            "name": "synthetic-shop-web-assessment",
            "target_product": "Synthetic Shop",
            "fingerprint_version_path": "metadata.release.version",
            "adapter_implementation_id": "pajin.web-assessment.synthetic-shop.v1",
        }
    )
    return WebAssessmentPlan.model_validate(raw)


def _deployment_models(
    *,
    plan: WebAssessmentPlan = DEFAULT_PLAN,
    fingerprint_body: bytes = FINGERPRINT_BODY,
) -> tuple[
    WebAssessmentAdapterManifest,
    ProvisionedWebAccountReceipt,
    WebAssessmentDispatchBinding,
    HostLoopbackWebDeploymentContext,
    ToolRequest,
]:
    source_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=NOW - timedelta(minutes=2),
    )
    validation_authorization = issue_local_web_assessment_authorization(
        plan,
        operator_confirmed_authorized_local_lab=True,
        now=NOW - timedelta(minutes=1),
    )
    adapter = WebAssessmentAdapterManifest(
        adapterId="juice-shop-local",
        adapterVersion="1.0.0",
        origin=plan.origin,
        implementationId=plan.adapter_implementation_id,
        implementationDigest=ADAPTER_IMPLEMENTATION_DIGEST,
        recipeDigest=plan.plan_digest,
        issuedAt=NOW - timedelta(days=1),
        expiresAt=NOW + timedelta(days=1),
    )
    target_digest = web_target_fingerprint_digest(
        origin=plan.origin,
        product=plan.target_product,
        version=VERSION,
        fingerprint_endpoint=plan.fingerprint_endpoint,
        response_sha256=sha256(fingerprint_body).hexdigest(),
        adapter_implementation_digest=adapter.implementation_digest,
        recipe_digest=adapter.recipe_digest,
    )
    receipt = ProvisionedWebAccountReceipt(
        adapter=adapter.reference(),
        origin=plan.origin,
        accountReferenceDigest="b" * 64,
        provisioningEvidenceDigest="c" * 64,
        targetFingerprintResponseSha256=sha256(fingerprint_body).hexdigest(),
        targetIdentityDigest=target_digest,
        authorizationIds=tuple(
            sorted(
                (
                    source_authorization.authorization_id,
                    validation_authorization.authorization_id,
                )
            )
        ),
        identityMaterialRef="secret:web-account-name",
        proofMaterialRef="secret:web-account-proof",
        issuedAt=NOW - timedelta(minutes=1),
        expiresAt=NOW + timedelta(minutes=20),
    )
    source_account = WebProvisionedAccountMaterial(
        accountReceiptDigest=receipt.receipt_digest,
        planDigest=plan.plan_digest,
        authorizationId=source_authorization.authorization_id,
        origin=plan.origin,
        targetVersion=VERSION,
        provisionedAt=NOW - timedelta(seconds=30),
        requestEvidence=(_fingerprint_evidence("a", plan=plan, response_body=fingerprint_body),),
    )
    validation_account = WebProvisionedAccountMaterial(
        accountReceiptDigest=receipt.receipt_digest,
        planDigest=plan.plan_digest,
        authorizationId=validation_authorization.authorization_id,
        origin=plan.origin,
        targetVersion=VERSION,
        provisionedAt=NOW - timedelta(seconds=30),
        requestEvidence=(_fingerprint_evidence("b", plan=plan, response_body=fingerprint_body),),
    )
    context = HostLoopbackWebDeploymentContext(
        accountReceiptDigest=receipt.receipt_digest,
        adapter=adapter,
        plan=plan,
        sourceAuthorization=source_authorization,
        validationAuthorization=validation_authorization,
        sourceAccount=source_account,
        validationAccount=validation_account,
    )
    request = ToolRequest(
        request_id="tool_web_source",
        agent_id="agent:web-test",
        tool_id="web.authenticated-read-only-assessment",
        target=plan.origin,
        method="POST",
        arguments={
            "adapter": adapter.reference().model_dump(mode="json", by_alias=True),
            "accountReceipt": receipt.reference().model_dump(mode="json", by_alias=True),
        },
    )
    dispatch = WebAssessmentDispatchBinding(
        requestId=request.request_id,
        expectedRunId=SOURCE_RUN_ID,
        role="source",
        workerExecutionId="exec:web-source",
        targetObserverExecutionId="exec:web-source-target",
        requestDigest="d" * 64,
        campaignId="campaign:web-test",
        campaignDigest="e" * 64,
        capabilityId="pajin.bug-bounty.web-authenticated-read-only-assessment",
        capabilityVersion="1.0.0",
        capabilityDigest="f" * 64,
        capabilityGrantId="grant:web-source",
        capabilityGrantDigest="0" * 64,
        capabilityGrantConsumptionReceiptId="grant-consumption:web-source",
        capabilityGrantConsumptionReceiptDigest="8" * 64,
        adapter=adapter.reference(),
        accountReceipt=receipt.reference(),
        approvalId="approval:web-source",
        approvalDigest="1" * 64,
        approvalReceiptId="approval-receipt:web-source",
        approvalReceiptDigest="3" * 64,
        permitId="permit:web-source",
        permitDigest="2" * 64,
        outputRootReference="web-governed-runs",
        workerSigningMaterialRef="secret:web-source-executor-key",
        targetObserverSigningMaterialRef="secret:web-source-observer-key",
    )
    return adapter, receipt, dispatch, context, request


def _production_gateway_fixture(
    tmp_path: Path,
) -> tuple[
    HostLoopbackBrowserWorkerBackend,
    WebAuthenticatedAssessmentTool,
    ToolRegistry,
    SecretBroker,
    RequestRateLimitLedger,
]:
    from tests import test_web_authenticated_assessment_capability as capability_fixtures

    graph_store = capability_fixtures._graph_store(tmp_path / "gateway-graph.sqlite3")
    base_tool, _manifest, _receipt = capability_fixtures._tool(
        graph_store,
        grant_store_path=tmp_path / "gateway-grants.sqlite3",
    )
    adapters = WebAssessmentAdapterRegistry(
        keys=tuple(base_tool.adapters._keys.values()),
        adapters=tuple(base_tool.adapters._adapters.values()),
    )
    account_receipts = ProvisionedWebAccountReceiptRegistry(
        keys=tuple(base_tool.account_receipts._keys.values()),
        receipts=tuple(base_tool.account_receipts._receipts.values()),
    )
    adapter, _account_receipt, _dispatch, context, _request = _deployment_models()
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path / "worker",
        trust_registry=_registry(),
    )
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=adapter.implementation_id,
        implementation_digest=adapter.implementation_digest,
    )
    verifier = HostLoopbackWebAssessmentOutputVerifier(
        output_root=tmp_path / "worker",
        output_root_reference="web-governed-runs",
        trust_registry=_registry(),
        contexts=(context,),
    )
    tool = WebAuthenticatedAssessmentTool(
        adapters=adapters,
        account_receipts=account_receipts,
        dispatch_bindings=base_tool.dispatch_bindings,
        job_compiler=compiler,
        output_verifier=verifier,
    )
    tools = ToolRegistry()
    tools.register(tool)
    return (
        backend,
        tool,
        tools,
        SecretBroker(),
        RequestRateLimitLedger(),
    )


def _worker_process_inputs(
    tmp_path: Path,
    *,
    plan: WebAssessmentPlan = DEFAULT_PLAN,
    fingerprint_body: bytes = FINGERPRINT_BODY,
) -> tuple[WebWorkerProcessInput, WebWorkerProcessInput]:
    adapter, receipt, dispatch, context, request = _deployment_models(
        plan=plan,
        fingerprint_body=fingerprint_body,
    )
    backend = _TestBackend(
        output_root=tmp_path,
        trust_registry=_registry(),
        runner=_FakeRunner(),
    )
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=adapter.implementation_id,
        implementation_digest=adapter.implementation_digest,
    )
    executor_spec = WebWorkerJobSpec.model_validate_json(
        compiler.compile_job(
            request=request,
            adapter=adapter,
            account_receipt=receipt,
            dispatch=dispatch,
        ).stdin
    )
    observer_role = WebWorkerRole.SOURCE_TARGET_OBSERVER
    observer_raw = executor_spec.model_dump(mode="json", by_alias=True)
    observer_raw.update(
        {
            "role": observer_role.value,
            "executionId": dispatch.target_observer_execution_id,
            "signingKeyId": _registry().active_key(observer_role).key_id,
            "observerExecutionId": None,
            "observerSigningKeyId": None,
            "targetIdentity": None,
        }
    )
    observer_spec = WebWorkerJobSpec.model_validate(observer_raw)
    target = _target(
        role=observer_role,
        authority=executor_spec.authority,
        execution_id=dispatch.target_observer_execution_id,
        process_id=901,
        response_body=fingerprint_body,
    )
    executor_raw = executor_spec.model_dump(mode="json", by_alias=True)
    executor_raw["targetIdentity"] = target.model_dump(mode="json", by_alias=True)
    bound_executor_spec = WebWorkerJobSpec.model_validate(executor_raw)
    observer_input = WebWorkerProcessInput(
        job=observer_spec,
        outputRoot=str(tmp_path),
        trustDomain=_registry().trust_domain,
        issuer=_registry().issuer,
        secrets={
            "signingPrivateKeyBase64url": web_worker_private_key_base64url(
                _key_bytes(observer_role)
            ),
            "accountName": None,
            "accountProof": None,
        },
    )
    executor_input = WebWorkerProcessInput(
        job=bound_executor_spec,
        outputRoot=str(tmp_path),
        trustDomain=_registry().trust_domain,
        issuer=_registry().issuer,
        secrets={
            "signingPrivateKeyBase64url": web_worker_private_key_base64url(
                _key_bytes(WebWorkerRole.SOURCE_EXECUTOR)
            ),
            "accountName": "user@example.test",
            "accountProof": "Example-password-123!",
        },
    )
    return observer_input, executor_input


def _isolated_worker_environment() -> dict[str, str]:
    environment = {
        "PAJIN_WEB_WORKER_HOST_SUBPROCESS": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
    }
    if sys.platform == "darwin":
        environment["__CF_USER_TEXT_ENCODING"] = f"0x{os.getuid():X}:0x3:0x33"
    return environment


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group containment")
def test_coordinator_worker_group_requires_both_pinned_authority_and_marker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = "PAJIN_GOVERNED_WEB_COORDINATOR_HOST_SUBPROCESS"
    monkeypatch.setenv(marker, "1")

    assert _web_worker_starts_new_session() is True
    with pytest.raises(ValueError, match="marked pinned child"):
        _create_governed_coordinator_worker_group_authority()

    with (
        PinnedOutputRoot.create(tmp_path / "coordinator-output") as pinned,
        pinned.activate(),
    ):
        assert _web_worker_starts_new_session() is True
        process_id = os.getpid()
        monkeypatch.setattr(os, "getpgrp", lambda: process_id + 1)
        with pytest.raises(ValueError, match="dedicated process group and session"):
            _create_governed_coordinator_worker_group_authority()
        monkeypatch.setattr(os, "getpgrp", lambda: process_id)
        monkeypatch.setattr(os, "getsid", lambda _pid: process_id)
        authority = _create_governed_coordinator_worker_group_authority()
        with _activate_governed_coordinator_worker_group(authority):
            assert _web_worker_starts_new_session() is False
            assert marker not in HostLoopbackBrowserWorkerBackend._sanitized_environment()
            monkeypatch.setattr(os, "getpgrp", lambda: process_id + 1)
            with pytest.raises(ValueError, match="no longer exact"):
                _web_worker_starts_new_session()
            monkeypatch.setattr(os, "getpgrp", lambda: process_id)
        assert _web_worker_starts_new_session() is True


@pytest.mark.skipif(os.name != "posix", reason="POSIX process-group containment")
def test_coordinator_group_termination_reaps_nested_worker_tree_without_late_write(
    tmp_path: Path,
) -> None:
    output = tmp_path / "coordinator-output"
    ready_path = output / "nested-ready.txt"
    late_path = output / "late-write.txt"
    late_source = textwrap.dedent(
        """
        import sys
        import time
        from pathlib import Path

        time.sleep(1.0)
        Path(sys.argv[1]).write_text("late\\n", encoding="utf-8")
        time.sleep(60)
        """
    )
    worker_source = textwrap.dedent(
        f"""
        import os
        import subprocess
        import sys
        import time
        from pathlib import Path

        child = subprocess.Popen(
            [sys.executable, "-c", {late_source!r}, sys.argv[2]]
        )
        Path(sys.argv[1]).write_text(
            f"{{os.getpid()}} {{child.pid}} {{os.getpgrp()}}\\n",
            encoding="utf-8",
        )
        time.sleep(60)
        """
    )
    coordinator_source = textwrap.dedent(
        f"""
        import asyncio
        import os
        import sys
        from pathlib import Path

        from pajin.runtime.pinned_workspace import PinnedOutputRoot
        from pajin.web_assessment.governed_worker import (
            AsyncioWebWorkerSubprocessRunner,
            _activate_governed_coordinator_worker_group,
            _create_governed_coordinator_worker_group_authority,
        )

        async def main():
            os.environ["PAJIN_GOVERNED_WEB_COORDINATOR_HOST_SUBPROCESS"] = "1"
            with PinnedOutputRoot.create(Path(sys.argv[1])) as pinned, pinned.activate():
                authority = _create_governed_coordinator_worker_group_authority()
                with _activate_governed_coordinator_worker_group(authority):
                    await AsyncioWebWorkerSubprocessRunner().run(
                        (sys.executable, "-c", {worker_source!r}, sys.argv[2], sys.argv[3]),
                        stdin=b"",
                        env={{}},
                        timeout_seconds=60,
                        stdout_limit_bytes=1024,
                        stderr_limit_bytes=1024,
                    )

        asyncio.run(main())
        """
    )
    coordinator = subprocess.Popen(
        [
            sys.executable,
            "-c",
            coordinator_source,
            str(output),
            str(ready_path),
            str(late_path),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        text=True,
    )
    deadline = time.monotonic() + 10
    while not ready_path.is_file() and coordinator.poll() is None:
        if time.monotonic() >= deadline:
            break
        time.sleep(0.02)
    if not ready_path.is_file():
        stdout, stderr = coordinator.communicate(timeout=5)
        pytest.fail(f"nested Worker did not start: stdout={stdout!r} stderr={stderr!r}")

    worker_pid, grandchild_pid, worker_group = (
        int(value) for value in ready_path.read_text(encoding="utf-8").split()
    )
    assert os.getpgid(coordinator.pid) == coordinator.pid
    assert worker_group == coordinator.pid
    os.killpg(coordinator.pid, signal.SIGTERM)
    coordinator.wait(timeout=5)
    assert coordinator.returncode == -signal.SIGTERM

    time.sleep(1.3)
    assert not late_path.exists()
    for process_id in (worker_pid, grandchild_pid):
        with pytest.raises(ProcessLookupError):
            os.kill(process_id, 0)


@pytest.mark.skipif(os.name != "posix", reason="POSIX pinned CWD capability")
@pytest.mark.asyncio
async def test_backend_binds_pinned_cwd_identity_into_worker_process_input(
    tmp_path: Path,
) -> None:
    observer_input, _executor_input = _worker_process_inputs(tmp_path)
    output = tmp_path / "pinned-output"
    parked = tmp_path / "parked-output"
    victim = tmp_path / "victim-output"
    victim.mkdir()
    fake = _FakeRunner()

    with PinnedOutputRoot.create(output) as pinned, pinned.activate():
        output.rename(parked)
        output.symlink_to(victim, target_is_directory=True)
        backend = _TestBackend(
            output_root=Path("worker-runs"),
            trust_registry=_registry(),
            runner=fake,
        )
        await backend._invoke_process(
            observer_input.job,
            {
                WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING: (
                    web_worker_private_key_base64url(
                        _key_bytes(WebWorkerRole.SOURCE_TARGET_OBSERVER)
                    )
                )
            },
            signing_binding=WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
            timeout_seconds=5,
            job=WorkerJob(
                execution_id=observer_input.job.execution_id,
                image="pajin-test-worker",
                command=["observe"],
            ),
        )

        _command, launched, _environment = fake.invocations[0]
        assert launched.output_root == "worker-runs"
        assert launched.pinned_workspace_identity == pinned.identity
        assert backend.output_root == Path("worker-runs")
        assert tuple(victim.iterdir()) == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX pinned CWD capability")
@pytest.mark.asyncio
async def test_worker_process_writes_only_below_inherited_pinned_cwd_after_path_swap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer_input, _executor_input = _worker_process_inputs(tmp_path)
    output = tmp_path / "pinned-output"
    parked = tmp_path / "parked-output"
    victim = tmp_path / "victim-output"
    victim.mkdir()

    with PinnedOutputRoot.create(output) as pinned:
        raw = observer_input.model_dump(mode="json", by_alias=True)
        raw.update(
            {
                "outputRoot": "worker-runs",
                "pinnedWorkspaceDevice": pinned.identity.device,
                "pinnedWorkspaceInode": pinned.identity.inode,
                "pinnedWorkspaceUid": pinned.identity.uid,
                "pinnedWorkspaceMode": pinned.identity.mode,
            }
        )
        payload = WebWorkerProcessInput.model_validate(raw)
        previous_cwd = os.open(".", os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fchdir(pinned.fd)
            output.rename(parked)
            output.symlink_to(victim, target_is_directory=True)

            async def write_probe(
                process_input: WebWorkerProcessInput,
            ) -> SignedWebTargetIdentity:
                destination = Path(process_input.output_root)
                destination.mkdir(parents=True)
                (destination / "worker-probe.txt").write_text("parked only\n", encoding="utf-8")
                assert process_input.pinned_workspace_identity == pinned.identity
                return _target(
                    role=process_input.job.role,
                    authority=process_input.job.authority,
                    execution_id=process_input.job.execution_id,
                    process_id=os.getpid(),
                )

            with monkeypatch.context() as patcher:
                patcher.setattr(worker_process.os, "environ", _isolated_worker_environment())
                patcher.setattr(worker_process, "_observe_target", write_probe)
                result = await worker_process.run_process_input(
                    payload,
                    argv_role=payload.job.role.value,
                )
        finally:
            os.fchdir(previous_cwd)
            os.close(previous_cwd)

    assert isinstance(result, SignedWebTargetIdentity)
    assert (parked / "worker-runs/worker-probe.txt").read_text(encoding="utf-8") == (
        "parked only\n"
    )
    assert tuple(victim.iterdir()) == ()


@pytest.mark.skipif(os.name != "posix", reason="POSIX pinned CWD capability")
@pytest.mark.asyncio
async def test_worker_process_rejects_mismatched_pinned_cwd_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer_input, _executor_input = _worker_process_inputs(tmp_path)
    cwd = os.stat(".")
    raw = observer_input.model_dump(mode="json", by_alias=True)
    raw.update(
        {
            "outputRoot": "worker-runs",
            "pinnedWorkspaceDevice": cwd.st_dev,
            "pinnedWorkspaceInode": cwd.st_ino + 1,
            "pinnedWorkspaceUid": cwd.st_uid,
            "pinnedWorkspaceMode": cwd.st_mode,
        }
    )
    payload = WebWorkerProcessInput.model_validate(raw)

    with monkeypatch.context() as patcher:
        patcher.setattr(worker_process.os, "environ", _isolated_worker_environment())
        with pytest.raises(PinnedWorkspaceError, match="current directory differs"):
            await worker_process.run_process_input(
                payload,
                argv_role=payload.job.role.value,
            )


def test_worker_process_normal_mode_keeps_absolute_output_requirement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer_input, _executor_input = _worker_process_inputs(tmp_path)

    with monkeypatch.context() as patcher:
        patcher.setattr(worker_process.os, "environ", _isolated_worker_environment())
        worker_process._require_process_boundary(
            observer_input,
            observer_input.job.role.value,
        )
        relative = observer_input.model_copy(update={"output_root": "worker-runs"})
        with pytest.raises(ValueError, match="must be absolute"):
            worker_process._require_process_boundary(
                relative,
                relative.job.role.value,
            )


@pytest.mark.asyncio
async def test_observer_rejects_same_version_different_fingerprint_body(
    tmp_path: Path,
) -> None:
    observer_input, _executor_input = _worker_process_inputs(tmp_path)
    changed_body = canonical_web_worker_json({"build": "substituted", "version": VERSION})
    changed_probe = WebTargetFingerprintProbe(
        version=VERSION,
        response_sha256=sha256(changed_body).hexdigest(),
        response_bytes=len(changed_body),
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=1),
    )

    async def fetch_changed(
        _payload: WebWorkerProcessInput,
    ) -> WebTargetFingerprintProbe:
        return changed_probe

    with pytest.raises(ValueError, match="approved provisioning baseline"):
        await worker_process._observe_target(
            observer_input,
            fingerprint_fetcher=fetch_changed,
            clock=lambda: NOW + timedelta(seconds=2),
        )


@pytest.mark.asyncio
async def test_executor_rejects_observer_to_executor_target_swap_before_browser(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _observer_input, executor_input = _worker_process_inputs(tmp_path)
    changed_body = canonical_web_worker_json({"instance": "swapped", "version": VERSION})

    async def fetch_swapped(
        _payload: WebWorkerProcessInput,
    ) -> WebTargetFingerprintProbe:
        return WebTargetFingerprintProbe(
            version=VERSION,
            response_sha256=sha256(changed_body).hexdigest(),
            response_bytes=len(changed_body),
            started_at=NOW,
            finished_at=NOW + timedelta(seconds=1),
        )

    assessment_started = False

    async def forbidden_assessment(**_kwargs: object) -> object:
        nonlocal assessment_started
        assessment_started = True
        raise AssertionError("browser assessment must not start after target swap")

    monkeypatch.setattr(
        worker_process,
        "run_local_web_assessment",
        forbidden_assessment,
    )

    with pytest.raises(ValueError, match="changed between observer and executor"):
        await worker_process._execute_assessment(
            executor_input,
            fingerprint_fetcher=fetch_swapped,
            clock=lambda: NOW,
        )
    assert assessment_started is False


@pytest.mark.asyncio
async def test_executor_rejects_postflight_target_swap_without_attestation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _observer_input, executor_input = _worker_process_inputs(tmp_path)
    changed_body = canonical_web_worker_json({"instance": "postflight-swap", "version": VERSION})
    calls = 0

    async def fetch_before_and_after(
        _payload: WebWorkerProcessInput,
    ) -> WebTargetFingerprintProbe:
        nonlocal calls
        calls += 1
        body = FINGERPRINT_BODY if calls == 1 else changed_body
        return WebTargetFingerprintProbe(
            version=VERSION,
            response_sha256=sha256(body).hexdigest(),
            response_bytes=len(body),
            started_at=NOW,
            finished_at=NOW + timedelta(seconds=1),
        )

    assessment_kwargs: dict[str, object] = {}

    async def completed_assessment(**kwargs: object) -> object:
        assessment_kwargs.update(kwargs)
        return object()

    monkeypatch.setattr(worker_process, "run_local_web_assessment", completed_assessment)

    with pytest.raises(ValueError, match="changed during Web assessment execution"):
        await worker_process._execute_assessment(
            executor_input,
            fingerprint_fetcher=fetch_before_and_after,
            clock=lambda: NOW,
        )

    assert calls == 2
    assert assessment_kwargs["run_id"] == SOURCE_RUN_ID
    assert assessment_kwargs["adapter_implementation_digest"] == (
        executor_input.job.authority.adapter_implementation_digest
    )


@pytest.mark.asyncio
async def test_compiler_backend_runs_distinct_observer_and_executor_without_secret_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inherited_canaries = {
        "PAJIN_SECRET_CANARY": "must-not-cross-process-boundary",
        "PYTHONPATH": "/tmp/pajin-attacker-pythonpath",
        "PYTHONHOME": "/tmp/pajin-attacker-pythonhome",
        "PYTHONSTARTUP": "/tmp/pajin-attacker-startup.py",
        "PYTHONINSPECT": "1",
        "HTTPS_PROXY": "http://proxy.invalid:8080",
    }
    for key, value in inherited_canaries.items():
        monkeypatch.setenv(key, value)
    adapter, receipt, dispatch, context, request = _deployment_models()
    fake = _FakeRunner()
    backend = _TestBackend(output_root=tmp_path, trust_registry=_registry(), runner=fake)
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=ADAPTER_IMPLEMENTATION_DIGEST,
    )
    prepared = compiler.compile_job(
        request=request,
        adapter=adapter,
        account_receipt=receipt,
        dispatch=dispatch,
    )
    policy = EgressPolicy(
        allow=[ORIGIN + "/**"],
        deny=[ORIGIN + path + "*" for path in context.plan.deny_paths],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=8_000_000,
        max_requests=100,
    )
    job = WorkerJob.model_validate(
        prepared.model_copy(
            update={"network": NetworkMode.EGRESS_PROXY, "egress_policy": policy}
        ).model_dump(mode="python")
    )
    materials = [
        SecretMaterial("lease-1", WEB_ACCOUNT_NAME_BINDING, "user@example.test"),
        SecretMaterial("lease-2", WEB_ACCOUNT_PROOF_BINDING, "Example-password-123!"),
        SecretMaterial(
            "lease-3",
            WEB_TARGET_OBSERVER_SIGNING_KEY_BINDING,
            web_worker_private_key_base64url(_key_bytes(WebWorkerRole.SOURCE_TARGET_OBSERVER)),
        ),
        SecretMaterial(
            "lease-4",
            WEB_WORKER_SIGNING_KEY_BINDING,
            web_worker_private_key_base64url(_key_bytes(WebWorkerRole.SOURCE_EXECUTOR)),
        ),
    ]

    result = await backend.run(job, secrets=materials)

    assert result.status is WorkerStatus.SUCCEEDED
    evidence = SignedWebWorkerActionEvidence.model_validate_json(result.stdout)
    verified = SimpleNamespace(
        plan=context.plan,
        authorization=context.source_authorization,
        result=SimpleNamespace(
            result_digest=evidence.execution_attestation.statement.result_digest,
            browser=SimpleNamespace(authenticated=True, browser_closed=True),
            credentials_persisted=False,
        ),
    )

    def load_verified(
        path: Path,
        *,
        expected_run_id: str,
        expected_root_digest: str,
    ) -> SimpleNamespace:
        assert path == tmp_path / context.plan.name / SOURCE_RUN_ID
        assert expected_run_id == SOURCE_RUN_ID
        assert expected_root_digest == evidence.execution_attestation.statement.run_root_digest
        return verified

    monkeypatch.setattr(
        "pajin.web_assessment.governed_worker.load_verified_local_web_assessment_source_integrity",
        load_verified,
    )
    verifier = HostLoopbackWebAssessmentOutputVerifier(
        output_root=tmp_path,
        output_root_reference="web-governed-runs",
        trust_registry=_registry(),
        contexts=(context,),
    )
    output = verifier.verify_output(
        request=request,
        dispatch=dispatch,
        worker_result=result,
    )

    assert output.attestation_digest == evidence.digest
    assert output.attestation_digest != evidence.execution_attestation.digest
    assert evidence.target_identity.statement.process_id != (
        evidence.execution_attestation.statement.process_id
    )
    assert [entry[1].job.role for entry in fake.invocations] == [
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.SOURCE_EXECUTOR,
    ]
    explicit_environment = {
        "PAJIN_WEB_WORKER_HOST_SUBPROCESS",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
    }
    for _, _, environment in fake.invocations:
        assert set(environment) <= WEB_WORKER_OS_ENV_ALLOWLIST | explicit_environment
        assert inherited_canaries.keys().isdisjoint(environment)
        assert environment["PAJIN_WEB_WORKER_HOST_SUBPROCESS"] == "1"
        assert environment["PYTHONDONTWRITEBYTECODE"] == "1"
        assert environment["PYTHONNOUSERSITE"] == "1"
        assert environment["PYTHONSAFEPATH"] == "1"
    for material in materials:
        assert material.value not in result.stdout
    assert backend.stable_execution_context()["containerIsolation"] is False
    with pytest.raises(ValueError, match="production subprocess profile"):
        backend.completed_action_authority(
            request_id=dispatch.request_id,
            execution_id=dispatch.worker_execution_id,
            dispatch_binding_digest=dispatch.binding_digest,
        )


def test_production_completion_profile_rejects_never_run_and_serialized_handles(
    tmp_path: Path,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )

    assert backend.stable_execution_context()["productionAuthorityEligible"] is True
    with pytest.raises(ValueError, match="no completed-action authority"):
        backend.completed_action_authority(
            request_id="tool_web_source",
            execution_id="exec:web-source",
            dispatch_binding_digest="5" * 64,
        )
    serialized = cast(WebWorkerCompletedActionAuthority, {})
    with pytest.raises(TypeError, match="opaque authorities"):
        backend.consume_completed_action_authorities(
            source=serialized,
            validation=serialized,
        )


@pytest.mark.asyncio
async def test_production_backend_rejects_direct_call_before_process(
    tmp_path: Path,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )
    job = WorkerJob(
        execution_id="exec:web-source",
        image="pajin/web-assessment-host-subprocess@sha256:" + "0" * 64,
        command=list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
        stdin="{}",
    )

    with pytest.raises(ValueError, match="requires a governed ToolGateway launch"):
        await backend.run(job)
    with pytest.raises(ValueError, match="requires a Gateway launch"):
        await backend._run_authorized(
            job,
            secrets=None,
            gateway_authority=None,
        )

    assert list(tmp_path.iterdir()) == []


def test_production_gateways_pin_system_clocks_and_distinct_audit_stores(
    tmp_path: Path,
) -> None:
    backend, _tool, tools, secrets, rate_limits = _production_gateway_fixture(tmp_path)
    source = HostLoopbackWebAssessmentGateway.production(
        backend=backend,
        role="source",
        audit_output_root=tmp_path / "gateway-audit",
        policy=PolicyEngine(),
        tools=tools,
        secrets=secrets,
        rate_limits=rate_limits,
    )
    validation = HostLoopbackWebAssessmentGateway.production(
        backend=backend,
        role="validation",
        audit_output_root=tmp_path / "gateway-audit",
        policy=PolicyEngine(),
        tools=tools,
        secrets=secrets,
        rate_limits=rate_limits,
    )

    assert source.stable_execution_context()["productionAuthorityEligible"] is True
    assert validation.stable_execution_context()["productionAuthorityEligible"] is True
    assert source.store is not validation.store
    assert source.store.run_id != validation.store.run_id
    assert source.store.path != validation.store.path
    assert source.store.run_id != SOURCE_RUN_ID
    assert validation.store.run_id != VALIDATION_RUN_ID


def test_production_gateway_rejects_clock_map_tool_and_state_shadows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend, tool, tools, secrets, rate_limits = _production_gateway_fixture(tmp_path)
    gateway = HostLoopbackWebAssessmentGateway.production(
        backend=backend,
        role="source",
        audit_output_root=tmp_path / "gateway-audit",
        policy=PolicyEngine(),
        tools=tools,
        secrets=secrets,
        rate_limits=rate_limits,
    )

    mutations = (
        (tool.adapters, "_clock", lambda: NOW - timedelta(days=365)),
        (tool.adapters, "_adapters", dict(tool.adapters._adapters)),
        (tool, "prepare", lambda _request: None),
        (tool.job_compiler, "compile_job", lambda **_kwargs: None),
        (gateway, "_attempted", False),
    )
    for target, name, value in mutations:
        attributes = getattr(target, "__dict__", {})
        had_instance_attribute = name in attributes
        with monkeypatch.context() as patcher:
            patcher.setattr(target, name, value, raising=False)
            assert gateway.stable_execution_context()["productionAuthorityEligible"] is False
            with pytest.raises(ValueError, match="runtime differs"):
                gateway._require_authoritative_profile()
        if not had_instance_attribute:
            getattr(target, "__dict__", {}).pop(name, None)
        assert gateway.stable_execution_context()["productionAuthorityEligible"] is True

    assert not any(gateway.store.path.rglob("*.json"))
    with pytest.raises(ValueError, match="no completed-action authority"):
        backend.completed_action_authority(
            request_id="tool_web_source",
            execution_id="exec:web-source",
            dispatch_binding_digest="5" * 64,
        )


def test_production_gateway_rejects_spoofed_backdated_clock_before_audit(
    tmp_path: Path,
) -> None:
    backend, tool, tools, secrets, rate_limits = _production_gateway_fixture(tmp_path)

    def spoofed_clock() -> datetime:
        return NOW - timedelta(days=365)

    spoofed_clock.__module__ = WebAssessmentAdapterRegistry.__module__
    spoofed_clock.__qualname__ = (
        f"{WebAssessmentAdapterRegistry.__qualname__}.__init__.<locals>.<lambda>"
    )
    tool.adapters._clock = spoofed_clock
    audit_root = tmp_path / "rejected-gateway-audit"

    with pytest.raises(ValueError, match="system UTC dependency clocks"):
        HostLoopbackWebAssessmentGateway.production(
            backend=backend,
            role="source",
            audit_output_root=audit_root,
            policy=PolicyEngine(),
            tools=tools,
            secrets=secrets,
            rate_limits=rate_limits,
        )

    assert not audit_root.exists()
    with pytest.raises(ValueError, match="no completed-action authority"):
        backend.completed_action_authority(
            request_id="tool_web_source",
            execution_id="exec:web-source",
            dispatch_binding_digest="5" * 64,
        )


def test_custom_runner_and_foreign_interpreter_are_not_authoritative(tmp_path: Path) -> None:
    custom_runner = HostLoopbackBrowserWorkerBackend(
        output_root=tmp_path,
        trust_registry=_registry(),
        runner=_FakeRunner(),
    )
    foreign_interpreter = HostLoopbackBrowserWorkerBackend(
        output_root=tmp_path,
        trust_registry=_registry(),
        python_executable="/foreign/python",
    )

    for backend in (custom_runner, foreign_interpreter):
        assert backend.stable_execution_context()["productionAuthorityEligible"] is False
        with pytest.raises(ValueError, match="production subprocess profile"):
            backend.require_authoritative_completion_profile()


def test_production_backend_rejects_subclass_factory(tmp_path: Path) -> None:
    class ForeignBackend(HostLoopbackBrowserWorkerBackend):
        pass

    with pytest.raises(TypeError, match="rejects subclasses"):
        ForeignBackend.production(output_root=tmp_path, trust_registry=_registry())


def test_production_backend_pins_venv_entrypoint_target_and_prefix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_target = Path(sys.executable).resolve()
    virtual_environment = tmp_path / "venv"
    entrypoint = virtual_environment / "bin" / "python"
    entrypoint.parent.mkdir(parents=True)
    entrypoint.symlink_to(original_target)
    base_prefix = tmp_path / "base-python"
    base_prefix.mkdir()

    with monkeypatch.context() as patcher:
        patcher.setattr(sys, "executable", str(entrypoint))
        patcher.setattr(sys, "prefix", str(virtual_environment))
        patcher.setattr(sys, "exec_prefix", str(virtual_environment))
        patcher.setattr(sys, "base_prefix", str(base_prefix))
        patcher.setattr(sys, "base_exec_prefix", str(base_prefix))
        backend = HostLoopbackBrowserWorkerBackend.production(
            output_root=tmp_path / "worker",
            trust_registry=_registry(),
        )

        assert backend.stable_execution_context()["pythonExecutable"] == str(entrypoint)
        assert backend.stable_execution_context()["productionAuthorityEligible"] is True

        entrypoint.unlink()
        replacement = tmp_path / "replacement-python"
        replacement.write_bytes(b"foreign executable")
        entrypoint.symlink_to(replacement)

        assert backend.stable_execution_context()["productionAuthorityEligible"] is False
        with pytest.raises(ValueError, match="production subprocess profile"):
            backend.require_authoritative_completion_profile()


def test_production_backend_rejects_prefix_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )

    monkeypatch.setattr(
        sys,
        "prefix",
        str(tmp_path / "substituted-venv"),
    )

    assert backend.stable_execution_context()["productionAuthorityEligible"] is False
    with pytest.raises(ValueError, match="production subprocess profile"):
        backend.require_authoritative_completion_profile()


def test_production_backend_rejects_macos_text_encoding_substitution(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    marker = f"0x{os.getuid():X}:0x3:0x33"
    with monkeypatch.context() as patcher:
        patcher.setattr(sys, "platform", "darwin")
        patcher.setenv("__CF_USER_TEXT_ENCODING", marker)
        backend = HostLoopbackBrowserWorkerBackend.production(
            output_root=tmp_path,
            trust_registry=_registry(),
        )
        assert backend.stable_execution_context()["productionAuthorityEligible"] is True

        patcher.setenv("__CF_USER_TEXT_ENCODING", f"0x{os.getuid():X}:0x3:0x34")
        assert backend.stable_execution_context()["productionAuthorityEligible"] is False
        with pytest.raises(ValueError, match="production subprocess profile"):
            backend.require_authoritative_completion_profile()


def test_worker_process_accepts_only_canonical_darwin_injected_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observer_input, _ = _worker_process_inputs(tmp_path)
    marker = f"0x{os.getuid():X}:0x3:0x33"
    process_environment = {
        "PAJIN_WEB_WORKER_HOST_SUBPROCESS": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONNOUSERSITE": "1",
        "PYTHONSAFEPATH": "1",
        "__CF_USER_TEXT_ENCODING": marker,
    }
    with monkeypatch.context() as patcher:
        patcher.setattr(sys, "platform", "darwin")
        patcher.setattr(worker_process.os, "environ", process_environment)
        worker_process._require_process_boundary(
            observer_input,
            observer_input.job.role.value,
        )

        for foreign in (
            f"0x{os.getuid() + 1:X}:0x3:0x33",
            f"0x{os.getuid():x}:0x3:0x33",
            f"0x{os.getuid():X}:03:0x33",
            marker + ":0x1",
        ):
            process_environment["__CF_USER_TEXT_ENCODING"] = foreign
            with pytest.raises(ValueError, match="macOS Web Worker text encoding marker"):
                worker_process._require_process_boundary(
                    observer_input,
                    observer_input.job.role.value,
                )


def test_gateway_completion_authority_pins_copy_safe_audit_run_path(tmp_path: Path) -> None:
    gateway_parent = tmp_path / "gateway-runs" / "web-source-gateway"
    gateway_parent.mkdir(parents=True)
    gateway_run = gateway_parent / VALIDATION_RUN_ID
    gateway_run.mkdir()
    worker_authority = _authority(role="source")
    receipt = WebGatewayCompletionReceipt(
        role="source",
        authority=worker_authority,
        dispatchBindingDigest=worker_authority.dispatch_binding_digest,
        requestId=worker_authority.request_id,
        workerExecutionId="exec:web-source",
        gatewayLaunchId="launch:web-source",
        gatewayAuditRunId=VALIDATION_RUN_ID,
        gatewayAuditRootDigest="1" * 64,
        gatewayEventHeadDigest="2" * 64,
        gatewayEvidenceReference="evidence/tool_web_source.json",
        gatewayEvidenceDigest="3" * 64,
        gatewayRequestReservationReference="requests/tool_web_source.json",
        gatewayRequestReservationDigest="4" * 64,
        backendCompletionDigest="5" * 64,
        workerResultDigest="6" * 64,
        toolResultDigest="7" * 64,
        policyDecisionDigest="8" * 64,
        gatewayOutcomeDigest="9" * 64,
        completedAt=NOW,
    )

    class CompletionStub:
        completion_digest = "5" * 64

    completion = WebGatewayCompletedActionAuthority(
        gateway=object(),
        token=object(),
        receipt=receipt,
        receipt_reference=f"gateway-completions/{receipt.receipt_digest}.json",
        backend_completion=cast(WebWorkerCompletedActionAuthority, CompletionStub()),
        final_root_digest="a" * 64,
        final_event_head="b" * 64,
        run_path=gateway_run,
    )

    first_copy = completion.run_path
    second_copy = completion.run_path
    assert first_copy == gateway_run
    assert second_copy == gateway_run

    displaced = tmp_path / "displaced-gateway-run"
    gateway_run.rename(displaced)
    gateway_run.mkdir()
    with pytest.raises(ValueError, match="identity changed"):
        _ = completion.run_path


@pytest.mark.asyncio
async def test_production_backend_rejects_runner_instance_shadow_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )
    fake_calls = 0

    async def fake_run(*_args: object, **_kwargs: object) -> WebSubprocessCapture:
        nonlocal fake_calls
        fake_calls += 1
        raise AssertionError("shadow runner must never be called")

    job = WorkerJob(
        execution_id="exec:web-source",
        image="pajin/web-assessment-host-subprocess@sha256:" + "0" * 64,
        command=list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
        stdin="{}",
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(backend._runner, "run", fake_run)
        assert backend.stable_execution_context()["productionAuthorityEligible"] is False
        with pytest.raises(ValueError, match="production subprocess profile"):
            await backend.run(job)

    assert fake_calls == 0
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError, match="production subprocess profile"):
        backend.completed_action_authority(
            request_id="tool_web_source",
            execution_id="exec:web-source",
            dispatch_binding_digest="5" * 64,
        )


@pytest.mark.asyncio
async def test_production_backend_rejects_runner_class_monkeypatch_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )
    fake_calls = 0

    async def fake_run(*_args: object, **_kwargs: object) -> WebSubprocessCapture:
        nonlocal fake_calls
        fake_calls += 1
        raise AssertionError("monkeypatched runner must never be called")

    job = WorkerJob(
        execution_id="exec:web-source",
        image="pajin/web-assessment-host-subprocess@sha256:" + "0" * 64,
        command=list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
        stdin="{}",
    )
    with monkeypatch.context() as patcher:
        patcher.setattr(AsyncioWebWorkerSubprocessRunner, "run", fake_run)
        assert backend.stable_execution_context()["productionAuthorityEligible"] is False
        with pytest.raises(ValueError, match="production subprocess profile"):
            await backend.run(job)

    assert fake_calls == 0
    assert list(tmp_path.iterdir()) == []
    with pytest.raises(ValueError, match="no completed-action authority"):
        backend.completed_action_authority(
            request_id="tool_web_source",
            execution_id="exec:web-source",
            dispatch_binding_digest="5" * 64,
        )


@pytest.mark.asyncio
async def test_production_backend_rejects_validation_helper_shadow_before_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = HostLoopbackBrowserWorkerBackend.production(
        output_root=tmp_path,
        trust_registry=_registry(),
    )

    monkeypatch.setattr(backend, "_validate_secrets", lambda *_args, **_kwargs: {})
    assert backend.stable_execution_context()["productionAuthorityEligible"] is False
    with pytest.raises(ValueError, match="production subprocess profile"):
        await backend.run(
            WorkerJob(
                execution_id="exec:web-source",
                image="pajin/web-assessment-host-subprocess@sha256:" + "0" * 64,
                command=list(WEB_ASSESSMENT_EXECUTOR_COMMAND),
                stdin="{}",
            )
        )

    assert list(tmp_path.iterdir()) == []


def test_compiler_stdin_contains_no_secret_material_references(tmp_path: Path) -> None:
    adapter, receipt, dispatch, context, request = _deployment_models()
    backend = _TestBackend(output_root=tmp_path, trust_registry=_registry(), runner=_FakeRunner())
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=ADAPTER_IMPLEMENTATION_DIGEST,
        headless=False,
    )
    job = compiler.compile_job(
        request=request,
        adapter=adapter,
        account_receipt=receipt,
        dispatch=dispatch,
    )

    assert tuple(job.command) == WEB_ASSESSMENT_EXECUTOR_COMMAND
    assert compiler.stable_execution_context()["headless"] is False
    compiled = WebWorkerJobSpec.model_validate_json(job.stdin)
    assert compiled.headless is False
    assert compiled.expected_run_id == dispatch.expected_run_id
    assert compiled.authority.expected_run_id == dispatch.expected_run_id
    assert compiled.authority.capability_grant_id == dispatch.capability_grant_id
    assert compiled.authority.capability_grant_digest == dispatch.capability_grant_digest
    assert (
        compiled.authority.capability_grant_consumption_receipt_id
        == dispatch.capability_grant_consumption_receipt_id
    )
    assert (
        compiled.authority.capability_grant_consumption_receipt_digest
        == dispatch.capability_grant_consumption_receipt_digest
    )
    assert compiled.authority.approval_receipt_id == dispatch.approval_receipt_id
    assert compiled.authority.approval_receipt_digest == dispatch.approval_receipt_digest
    legacy_raw = compiled.model_dump(mode="json", by_alias=True)
    legacy_raw["adapterImplementation"] = "pajin.web-assessment.juice-shop/v1"
    assert (
        WebWorkerJobSpec.model_validate(legacy_raw).adapter_implementation
        == DEFAULT_PLAN.adapter_implementation_id
    )
    for secret_ref in (
        receipt.identity_material_ref,
        receipt.proof_material_ref,
        dispatch.worker_signing_material_ref,
        dispatch.target_observer_signing_material_ref,
    ):
        assert secret_ref not in job.stdin

    with pytest.raises(TypeError, match="literal boolean"):
        HostLoopbackWebAssessmentJobCompiler(
            backend=backend,
            output_root_reference="web-governed-runs",
            contexts=(context,),
            implementation_id=ADAPTER_IMPLEMENTATION_ID,
            implementation_digest="a" * 64,
            headless=cast(bool, 1),
        )


def test_compiler_binds_alternate_product_profile_and_adapter_identity(tmp_path: Path) -> None:
    plan = _alternate_worker_plan()
    fingerprint_body = canonical_web_worker_json({"metadata": {"release": {"version": VERSION}}})
    adapter, receipt, dispatch, context, request = _deployment_models(
        plan=plan,
        fingerprint_body=fingerprint_body,
    )
    backend = _TestBackend(output_root=tmp_path, trust_registry=_registry(), runner=_FakeRunner())
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=adapter.implementation_id,
        implementation_digest=adapter.implementation_digest,
    )

    compiled = WebWorkerJobSpec.model_validate_json(
        compiler.compile_job(
            request=request,
            adapter=adapter,
            account_receipt=receipt,
            dispatch=dispatch,
        ).stdin
    )

    assert compiled.adapter_implementation == plan.adapter_implementation_id
    assert compiled.authority.target_product == plan.target_product
    assert compiled.authority.target_fingerprint_endpoint == plan.fingerprint_endpoint
    assert compiled.plan.fingerprint_version_path == plan.fingerprint_version_path

    tampered_job = compiled.model_dump(mode="json", by_alias=True)
    tampered_job["adapterImplementation"] = "pajin.web-assessment.substituted.v1"
    with pytest.raises(ValueError, match="plan, authorization, account, and authority differ"):
        WebWorkerJobSpec.model_validate(tampered_job)

    substituted_adapter = context.adapter.model_dump(mode="json", by_alias=True)
    substituted_adapter["adapterDigest"] = ""
    substituted_adapter["implementationId"] = "pajin.web-assessment.substituted.v1"
    tampered_context = context.model_dump(mode="json", by_alias=True)
    tampered_context["adapter"] = substituted_adapter
    with pytest.raises(ValueError, match="adapter context differs from its plan"):
        HostLoopbackWebDeploymentContext.model_validate(tampered_context)


@pytest.mark.asyncio
async def test_worker_fingerprint_parser_uses_alternate_plan_json_path(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    plan = _alternate_worker_plan()
    fingerprint_body = canonical_web_worker_json({"metadata": {"release": {"version": VERSION}}})
    observer_input, _executor_input = _worker_process_inputs(
        tmp_path,
        plan=plan,
        fingerprint_body=fingerprint_body,
    )
    requested: dict[str, object] = {}

    class FingerprintResponse:
        status_code = 200

        async def __aenter__(self) -> FingerprintResponse:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        async def aiter_bytes(self) -> AsyncIterator[bytes]:
            yield fingerprint_body

    class FingerprintClient:
        def __init__(self, **_kwargs: object) -> None:
            pass

        async def __aenter__(self) -> FingerprintClient:
            return self

        async def __aexit__(self, *_args: object) -> None:
            return None

        def stream(self, method: str, url: str, **_kwargs: object) -> FingerprintResponse:
            requested.update({"method": method, "url": url})
            return FingerprintResponse()

    monkeypatch.setattr(httpx, "AsyncClient", FingerprintClient)

    probe = await worker_process.fetch_web_target_fingerprint(observer_input)

    assert requested == {
        "method": "GET",
        "url": plan.origin + plan.fingerprint_endpoint,
    }
    assert probe.version == VERSION
    assert probe.response_sha256 == sha256(fingerprint_body).hexdigest()


def test_grant_consumption_receipt_tamper_fails_signed_verifier() -> None:
    original_authority = _authority(role="source")
    tampered_raw = original_authority.model_dump(mode="json", by_alias=True)
    tampered_raw["capabilityGrantConsumptionReceiptDigest"] = "0" * 64
    tampered_authority = WebWorkerAuthorityBinding.model_validate(tampered_raw)
    tampered_target = _target(
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        authority=tampered_authority,
        execution_id="exec:tampered-grant-receipt-target",
        process_id=925,
    )

    with pytest.raises(ValueError, match="authority binding differs"):
        verify_signed_web_target_identity(
            tampered_target,
            _registry(),
            expected_authority=original_authority,
            verification_time=NOW + timedelta(seconds=10),
        )


@pytest.mark.asyncio
async def test_approval_receipt_tamper_fails_before_process_and_in_signed_verifier(
    tmp_path: Path,
) -> None:
    adapter, receipt, dispatch, context, request = _deployment_models()
    fake = _FakeRunner()
    backend = _TestBackend(output_root=tmp_path, trust_registry=_registry(), runner=fake)
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=adapter.implementation_id,
        implementation_digest=adapter.implementation_digest,
    )
    prepared = compiler.compile_job(
        request=request,
        adapter=adapter,
        account_receipt=receipt,
        dispatch=dispatch,
    )
    compiled_raw = json.loads(prepared.stdin)
    compiled_raw["authority"]["approvalReceiptDigest"] = "4" * 64
    policy = EgressPolicy(
        allow=[ORIGIN + "/**"],
        deny=[ORIGIN + path + "*" for path in context.plan.deny_paths],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=8_000_000,
        max_requests=100,
    )
    tampered_job = WorkerJob.model_validate(
        prepared.model_copy(
            update={
                "stdin": canonical_web_worker_json(compiled_raw).decode("utf-8"),
                "network": NetworkMode.EGRESS_PROXY,
                "egress_policy": policy,
            }
        ).model_dump(mode="python")
    )

    rejected = await backend.run(tampered_job, secrets=[])

    assert rejected.status is WorkerStatus.FAILED
    assert fake.invocations == []

    original_authority = WebWorkerJobSpec.model_validate_json(prepared.stdin).authority
    tampered_authority_raw = original_authority.model_dump(mode="json", by_alias=True)
    tampered_authority_raw["approvalReceiptDigest"] = "4" * 64
    tampered_authority = WebWorkerAuthorityBinding.model_validate(tampered_authority_raw)
    original_target = _target(
        role=WebWorkerRole.SOURCE_TARGET_OBSERVER,
        authority=original_authority,
        execution_id=dispatch.target_observer_execution_id,
        process_id=902,
    )
    tampered_statement_raw = original_target.statement.model_dump(mode="json", by_alias=True)
    tampered_statement_raw["authority"] = tampered_authority.model_dump(
        mode="json",
        by_alias=True,
    )
    tampered_statement = WebTargetIdentityStatement.model_validate(tampered_statement_raw)
    validly_signed_tamper = _attestor(WebWorkerRole.SOURCE_TARGET_OBSERVER).sign_target(
        tampered_statement
    )

    with pytest.raises(ValueError, match="authority binding differs"):
        verify_signed_web_target_identity(
            validly_signed_tamper,
            _registry(),
            expected_authority=original_authority,
            verification_time=NOW + timedelta(seconds=10),
        )


@pytest.mark.asyncio
async def test_backend_rejects_egress_policy_drift_before_process_launch(
    tmp_path: Path,
) -> None:
    adapter, receipt, dispatch, context, request = _deployment_models()
    fake = _FakeRunner()
    backend = _TestBackend(output_root=tmp_path, trust_registry=_registry(), runner=fake)
    compiler = HostLoopbackWebAssessmentJobCompiler(
        backend=backend,
        output_root_reference="web-governed-runs",
        contexts=(context,),
        implementation_id=ADAPTER_IMPLEMENTATION_ID,
        implementation_digest=ADAPTER_IMPLEMENTATION_DIGEST,
    )
    prepared = compiler.compile_job(
        request=request,
        adapter=adapter,
        account_receipt=receipt,
        dispatch=dispatch,
    )
    drifted_policy = EgressPolicy(
        allow=["http://127.0.0.1:3001/**"],
        deny=[],
        allowed_methods={"GET", "HEAD", "POST"},
        allow_private_networks=True,
        max_response_bytes=8_000_000,
        max_requests=100,
    )
    job = WorkerJob.model_validate(
        prepared.model_copy(
            update={"network": NetworkMode.EGRESS_PROXY, "egress_policy": drifted_policy}
        ).model_dump(mode="python")
    )

    result = await backend.run(job, secrets=[])

    assert result.status is WorkerStatus.FAILED
    assert fake.invocations == []
    assert "secret" not in result.stderr.lower()
