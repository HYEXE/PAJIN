"""Pipe-only entrypoint for the governed local Web assessment subprocess.

The parent backend chooses the role on argv and sends the complete ephemeral
input on stdin.  This module never writes credentials or the signing key to an
artifact, stdout, stderr, command-line argument, or inherited environment.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

from pajin.runtime.pinned_workspace import (
    activate_inherited_pinned_workspace,
    pinned_workspace_relative_path,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.web_assessment.adapter_catalog import (
    AdapterImplementationCatalogError,
    production_adapter_implementation_catalog,
)
from pajin.web_assessment.browser import BrowserCredentials
from pajin.web_assessment.governed_worker import (
    WEB_WORKER_OS_ENV_ALLOWLIST,
    SignedWebExecutionAttestation,
    SignedWebTargetIdentity,
    WebExecutionStatement,
    WebTargetIdentityStatement,
    WebWorkerAttestor,
    WebWorkerProcessInput,
    WebWorkerRole,
    _canonical_macos_user_text_encoding,
    canonical_web_worker_json,
    web_target_fingerprint_digest,
)
from pajin.web_assessment.models import WebAssessmentPlan, json_at
from pajin.web_assessment.runner import (
    ProvisionedLocalWebAssessmentAccount,
    run_local_web_assessment,
)

_MAX_INPUT_BYTES = 1_000_000
_MAX_FINGERPRINT_BYTES = 10_000_000


@dataclass(frozen=True, slots=True)
class WebTargetFingerprintProbe:
    """One byte-exact, bounded response observed inside a Worker subprocess."""

    version: str
    response_sha256: str
    response_bytes: int
    started_at: datetime
    finished_at: datetime


WebTargetFingerprintFetcher = Callable[
    [WebWorkerProcessInput], Awaitable[WebTargetFingerprintProbe]
]


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_process_boundary(payload: WebWorkerProcessInput, argv_role: str) -> None:
    if os.environ.get("PAJIN_WEB_WORKER_HOST_SUBPROCESS") != "1":
        raise ValueError("Web Worker process is missing its host-subprocess marker")
    if any(key.lower().endswith("_proxy") for key in os.environ):
        raise ValueError("Web Worker process inherited a proxy setting")
    explicit = {
        "PAJIN_WEB_WORKER_HOST_SUBPROCESS",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONNOUSERSITE",
        "PYTHONSAFEPATH",
    }
    macos_text_encoding = os.environ.get("__CF_USER_TEXT_ENCODING")
    if sys.platform == "darwin":
        if macos_text_encoding is None:
            raise ValueError("Web Worker process is missing the macOS text encoding marker")
        _canonical_macos_user_text_encoding(macos_text_encoding)
        explicit.add("__CF_USER_TEXT_ENCODING")
    elif macos_text_encoding is not None:
        raise ValueError("Web Worker process inherited a foreign macOS environment setting")
    unexpected = {
        key
        for key in os.environ
        if key.upper() not in WEB_WORKER_OS_ENV_ALLOWLIST and key not in explicit
    }
    if unexpected:
        raise ValueError("Web Worker process inherited an unapproved environment setting")
    if (
        os.environ.get("PYTHONDONTWRITEBYTECODE") != "1"
        or os.environ.get("PYTHONNOUSERSITE") != "1"
        or os.environ.get("PYTHONSAFEPATH") != "1"
    ):
        raise ValueError("Web Worker Python isolation settings differ")
    if argv_role != payload.job.role.value:
        raise ValueError("Web Worker argv role differs from its signed job role")
    output_root = Path(payload.output_root)
    pinned_workspace = payload.pinned_workspace_identity
    if pinned_workspace is None:
        if not output_root.is_absolute():
            raise ValueError("Web Worker output root must be absolute")
    elif (
        output_root.is_absolute()
        or ".." in output_root.parts
        or str(output_root) != payload.output_root
    ):
        raise ValueError("pinned Web Worker output root must be normalized and relative")
    if payload.job.signing_key_id == "":  # defensive; the model already rejects this
        raise ValueError("Web Worker signing key ID is required")


def _attestor(payload: WebWorkerProcessInput) -> WebWorkerAttestor:
    return WebWorkerAttestor.from_private_key_base64url(
        key_id=payload.job.signing_key_id,
        role=payload.job.role,
        trust_domain=payload.trust_domain,
        issuer=payload.issuer,
        private_key_base64url=payload.secrets.signing_private_key_base64url,
    )


def require_code_owned_worker_plan(
    *,
    plan: WebAssessmentPlan,
    implementation_id: str,
    implementation_digest: str,
    origin: str,
) -> None:
    """Re-resolve executable recipe authority inside the Worker process.

    The controller-provided serialized Plan remains evidence, not code-selection
    authority.  A fresh process must obtain the same canonical Plan from its
    own deployment catalog before any target request is issued.
    """

    try:
        resolved = production_adapter_implementation_catalog().resolve(
            implementation_id=implementation_id,
            implementation_digest=implementation_digest,
            origin=origin,
        )
    except AdapterImplementationCatalogError as exc:
        raise ValueError("Web Worker adapter implementation is not installed") from exc
    if resolved.plan != plan:
        raise ValueError("Web Worker serialized Plan differs from code-owned authority")


async def fetch_web_target_fingerprint(
    payload: WebWorkerProcessInput,
) -> WebTargetFingerprintProbe:
    """Fetch the exact signed fingerprint endpoint without proxy or redirects."""

    try:
        import httpx
    except ImportError as exc:  # pragma: no cover - base-only installation
        raise RuntimeError("httpx is unavailable for the Web target observer") from exc

    plan = payload.job.plan
    started_at = _utc_now()
    url = payload.job.authority.target_origin + (payload.job.authority.target_fingerprint_endpoint)
    body = bytearray()
    timeout = httpx.Timeout(plan.request_timeout_seconds)
    async with (
        httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            timeout=timeout,
        ) as client,
        client.stream(
            "GET",
            url,
            headers={"accept": "application/json", "accept-encoding": "identity"},
        ) as response,
    ):
        if response.status_code != 200:
            raise RuntimeError("target fingerprint endpoint did not return success")
        async for chunk in response.aiter_bytes():
            if len(body) + len(chunk) > min(
                plan.max_response_bytes,
                _MAX_FINGERPRINT_BYTES,
            ):
                raise RuntimeError("target fingerprint response exceeded its byte limit")
            body.extend(chunk)
    decoded = parse_strict_json_bytes(
        bytes(body),
        label="Web target fingerprint response",
        max_bytes=min(plan.max_response_bytes, _MAX_FINGERPRINT_BYTES),
        max_depth=16,
        max_nodes=10_000,
    )
    target_version = json_at(decoded, plan.fingerprint_version_path)
    if not isinstance(target_version, str) or not target_version[:100].strip():
        raise RuntimeError("target fingerprint response did not identify a version")
    target_version = target_version[:100]
    return WebTargetFingerprintProbe(
        version=target_version,
        response_sha256=sha256(bytes(body)).hexdigest(),
        response_bytes=len(body),
        started_at=started_at,
        finished_at=_utc_now(),
    )


def _require_approved_fingerprint(
    payload: WebWorkerProcessInput,
    probe: WebTargetFingerprintProbe,
) -> None:
    authority = payload.job.authority
    plan = payload.job.plan
    provisioning = payload.job.provisioned_account.target_fingerprint_evidence(plan)
    observed_digest = web_target_fingerprint_digest(
        origin=authority.target_origin,
        product=authority.target_product,
        version=probe.version,
        fingerprint_endpoint=authority.target_fingerprint_endpoint,
        response_sha256=probe.response_sha256,
        adapter_implementation_digest=authority.adapter_implementation_digest,
        recipe_digest=authority.recipe_digest,
    )
    if (
        authority.recipe_digest != plan.plan_digest
        or authority.target_product != plan.target_product
        or authority.target_fingerprint_endpoint != plan.fingerprint_endpoint
        or payload.job.adapter_implementation != plan.adapter_implementation_id
        or probe.version != authority.target_version
        or probe.response_sha256 != authority.expected_target_response_sha256
        or probe.response_sha256 != provisioning.response_sha256
        or probe.response_bytes != provisioning.response_bytes
        or observed_digest != authority.expected_target_fingerprint_digest
    ):
        raise ValueError("live target fingerprint differs from the approved provisioning baseline")


async def _observe_target(
    payload: WebWorkerProcessInput,
    *,
    fingerprint_fetcher: WebTargetFingerprintFetcher = fetch_web_target_fingerprint,
    clock: Callable[[], datetime] = _utc_now,
) -> SignedWebTargetIdentity:
    if payload.job.role not in {
        WebWorkerRole.SOURCE_TARGET_OBSERVER,
        WebWorkerRole.VALIDATION_TARGET_OBSERVER,
    }:
        raise ValueError("target observation requires the target-observer role")
    probe = await fingerprint_fetcher(payload)
    _require_approved_fingerprint(payload, probe)
    observer_role = cast(
        Literal[
            WebWorkerRole.SOURCE_TARGET_OBSERVER,
            WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        ],
        payload.job.role,
    )
    statement = WebTargetIdentityStatement(
        trustDomain=payload.trust_domain,
        issuer=payload.issuer,
        authority=payload.job.authority,
        role=observer_role,
        executionId=payload.job.execution_id,
        targetProduct=payload.job.authority.target_product,
        targetVersion=probe.version,
        fingerprintEndpoint=payload.job.authority.target_fingerprint_endpoint,
        observedTargetFingerprintDigest=(payload.job.authority.expected_target_fingerprint_digest),
        responseSha256=probe.response_sha256,
        responseBytes=probe.response_bytes,
        responseStatus=200,
        processId=os.getpid(),
        startedAt=probe.started_at,
        finishedAt=probe.finished_at,
        issuedAt=clock(),
    )
    return _attestor(payload).sign_target(statement)


async def _execute_assessment(
    payload: WebWorkerProcessInput,
    *,
    fingerprint_fetcher: WebTargetFingerprintFetcher = fetch_web_target_fingerprint,
    clock: Callable[[], datetime] = _utc_now,
) -> SignedWebExecutionAttestation:
    if payload.job.role not in {
        WebWorkerRole.SOURCE_EXECUTOR,
        WebWorkerRole.VALIDATION_EXECUTOR,
    }:
        raise ValueError("Web assessment execution requires an executor role")
    if payload.job.target_identity is None:
        raise ValueError("Web assessment execution requires target identity evidence")
    if payload.secrets.account_name is None or payload.secrets.account_proof is None:
        raise ValueError("Web assessment executor did not receive account secret leases")

    plan = payload.job.plan
    authorization = payload.job.authorization
    authorization.require_current(plan=plan, now=clock())
    live_fingerprint = await fingerprint_fetcher(payload)
    observer_fingerprint = payload.job.target_identity.statement
    if (
        live_fingerprint.version != observer_fingerprint.target_version
        or live_fingerprint.response_sha256 != observer_fingerprint.response_sha256
        or live_fingerprint.response_bytes != observer_fingerprint.response_bytes
    ):
        raise ValueError("target fingerprint changed between observer and executor")
    _require_approved_fingerprint(payload, live_fingerprint)
    account_material = payload.job.provisioned_account
    provisioned_account = ProvisionedLocalWebAssessmentAccount(
        credentials=BrowserCredentials(
            username=payload.secrets.account_name,
            password=payload.secrets.account_proof,
        ),
        plan_digest=account_material.plan_digest,
        authorization_id=account_material.authorization_id,
        origin=account_material.origin,
        target_version=account_material.target_version,
        provisioned_at=account_material.provisioned_at,
        request_evidence=account_material.request_evidence,
        target_product=plan.target_product,
        fingerprint_version_path=plan.fingerprint_version_path,
        adapter_implementation_id=plan.adapter_implementation_id,
    )
    artifacts = await run_local_web_assessment(
        plan=plan,
        authorization=authorization,
        output_root=Path(payload.output_root),
        run_id=payload.job.expected_run_id,
        headless=payload.job.headless,
        provisioned_account=provisioned_account,
        adapter_implementation_digest=(payload.job.authority.adapter_implementation_digest),
    )
    postflight_fingerprint = await fingerprint_fetcher(payload)
    if (
        postflight_fingerprint.version != live_fingerprint.version
        or postflight_fingerprint.response_sha256 != live_fingerprint.response_sha256
        or postflight_fingerprint.response_bytes != live_fingerprint.response_bytes
        or postflight_fingerprint.version != observer_fingerprint.target_version
        or postflight_fingerprint.response_sha256 != observer_fingerprint.response_sha256
        or postflight_fingerprint.response_bytes != observer_fingerprint.response_bytes
    ):
        raise ValueError("target fingerprint changed during Web assessment execution")
    _require_approved_fingerprint(payload, postflight_fingerprint)
    result = artifacts.result
    role = cast(
        Literal[WebWorkerRole.SOURCE_EXECUTOR, WebWorkerRole.VALIDATION_EXECUTOR],
        payload.job.role,
    )
    statement = WebExecutionStatement(
        trustDomain=payload.trust_domain,
        issuer=payload.issuer,
        authority=payload.job.authority,
        role=role,
        executionId=payload.job.execution_id,
        targetIdentityAttestationDigest=payload.job.target_identity.digest,
        runId=result.run_id,
        runRootDigest=artifacts.root_digest,
        resultDigest=result.result_digest,
        processId=os.getpid(),
        startedAt=result.started_at,
        finishedAt=result.finished_at,
        issuedAt=clock(),
    )
    return _attestor(payload).sign_execution(statement)


async def run_process_input(
    payload: WebWorkerProcessInput,
    *,
    argv_role: str,
) -> SignedWebTargetIdentity | SignedWebExecutionAttestation:
    """Execute one already-parsed pipe input; kept public for focused contract tests."""

    _require_process_boundary(payload, argv_role)
    require_code_owned_worker_plan(
        plan=payload.job.plan,
        implementation_id=payload.job.adapter_implementation,
        implementation_digest=payload.job.authority.adapter_implementation_digest,
        origin=payload.job.authority.target_origin,
    )

    async def execute() -> SignedWebTargetIdentity | SignedWebExecutionAttestation:
        if payload.job.role in {
            WebWorkerRole.SOURCE_TARGET_OBSERVER,
            WebWorkerRole.VALIDATION_TARGET_OBSERVER,
        }:
            return await _observe_target(payload)
        return await _execute_assessment(payload)

    pinned_workspace = payload.pinned_workspace_identity
    if pinned_workspace is None:
        return await execute()
    with activate_inherited_pinned_workspace(pinned_workspace):
        if (
            pinned_workspace_relative_path(
                Path(payload.output_root),
                label="Web Worker output root",
            )
            is None
        ):
            raise ValueError("Web Worker failed to activate its pinned output workspace")
        return await execute()


async def _async_main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in {role.value for role in WebWorkerRole}:
        raise ValueError("Web Worker requires exactly one supported role argument")
    content = sys.stdin.buffer.read(_MAX_INPUT_BYTES + 1)
    if len(content) > _MAX_INPUT_BYTES:
        raise ValueError("Web Worker stdin exceeded its byte limit")
    decoded = parse_strict_json_bytes(
        content,
        label="Web Worker process input",
        max_bytes=_MAX_INPUT_BYTES,
        max_depth=64,
        max_nodes=100_000,
    )
    payload = WebWorkerProcessInput.model_validate(decoded)
    result = await run_process_input(payload, argv_role=argv[1])
    output = canonical_web_worker_json(result.model_dump(mode="json", by_alias=True))
    for secret in (
        payload.secrets.signing_private_key_base64url,
        payload.secrets.account_name,
        payload.secrets.account_proof,
    ):
        if secret is not None and secret.encode("utf-8") in output:
            raise RuntimeError("Web Worker output contained pipe-only secret material")
    sys.stdout.buffer.write(output)
    sys.stdout.buffer.flush()
    return 0


def main() -> int:
    try:
        return asyncio.run(_async_main(sys.argv))
    except (Exception, asyncio.CancelledError) as exc:
        # Never serialize exception details: a dependency could include request
        # bodies, credentials, local paths, or tokens in its message.
        category = type(exc).__name__
        sys.stderr.write(f"governed Web Worker failed ({category})")
        sys.stderr.flush()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
