"""Packaged one-shot operator for the compact WEB-007 live successor.

The commands in this module deliberately separate durable-state provisioning,
signer-neutral request preparation, zero-side-effect preflight, and the single
execution attempt.  This package contains verification-only authorization code;
private-key provisioning and signing remain in the physically separate offline
issuer package.
"""

from __future__ import annotations

import argparse
import asyncio
import inspect
import os
import re
import secrets
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from hmac import compare_digest
from pathlib import Path
from typing import Annotated, Final, Literal, Protocol, Self, cast

from pydantic import ConfigDict, Field, field_validator, model_validator

from pajin.discovery.canonicalization import canonical_json_bytes
from pajin.domain.models import StrictModel
from pajin.runtime.safe_files import (
    load_bounded_strict_json,
    parse_strict_json_bytes,
    read_bounded_regular_bytes,
)
from pajin.runtime.secrets import SecretBroker
from pajin.skills.models import SkillRegistryRef
from pajin.web_assessment.analysis_capacity_v2 import (
    SubprocessLlamaCppLiveMaterialization,
    VerifiedWebAnalysisCapacityV2Run,
    load_verified_web_analysis_capacity_v2_run,
)
from pajin.web_assessment.analysis_compact_live_pins import (
    CompactWebAnalysisRuntimePin,
    CompactWebAnalysisTransportPin,
    load_verified_compact_web_analysis_runtime_pin,
    load_verified_compact_web_analysis_transport_pin,
)
from pajin.web_assessment.analysis_live_authorization import (
    WebAnalysisOneCallAuthorizationTrustAnchor,
    parse_web_analysis_one_call_authorization_trust_anchor,
)
from pajin.web_assessment.analysis_live_authorization_v2 import (
    SignedWebAnalysisOneCallAuthorizationV2,
    VerifiedWebAnalysisOneCallAuthorizationV2,
    WebAnalysisOneCallAuthorizationRequestV2,
    WebAnalysisOneCallAuthorizationVerifierV2,
    build_web_analysis_one_call_authorization_request_v2,
    parse_signed_web_analysis_one_call_authorization_v2,
)
from pajin.web_assessment.analysis_live_claim_journal import (
    WebAnalysisLiveClaimJournal,
    WebAnalysisLiveClaimTerminalDisposition,
)
from pajin.web_assessment.analysis_skill_invocation import (
    CompiledSkillBoundWebAnalysisProposal,
)
from pajin.web_assessment.analysis_skill_live_invocation import (
    PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope,
    plan_prepared_compact_skill_bound_web_analysis_admission,
    verify_planned_prepared_compact_skill_bound_web_analysis_admission,
)
from pajin.web_assessment.analysis_skill_live_preparation import (
    VerifiedCompactSkillBoundWebAnalysisPreparationRun,
    load_verified_compact_skill_bound_web_analysis_preparation,
)
from pajin.web_assessment.analysis_skill_projection import (
    VerifiedWebAnalysisSkillProjectionRun,
    load_verified_web_analysis_skill_projection,
)
from pajin.web_assessment.analysis_transport import WebAnalysisTransportRuntimePin
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

COMPACT_LIVE_OPERATOR_MANIFEST_API_VERSION: Final = (
    "pajin.dev/compact-live-operator-manifest/v1alpha1"
)
COMPACT_LIVE_PROVISIONED_STATE_API_VERSION: Final = (
    "pajin.dev/compact-live-provisioned-state/v1alpha1"
)
COMPACT_LIVE_PREFLIGHT_API_VERSION: Final = "pajin.dev/compact-live-preflight/v1alpha1"

_MANIFEST_MAX_BYTES: Final = 256 * 1024
_ADMISSION_MAX_BYTES: Final = 512 * 1024
_LINEAGE_PIN_MAX_BYTES: Final = 64 * 1024
_TRUST_ANCHOR_MAX_BYTES: Final = 128 * 1024
_SIGNED_AUTHORIZATION_MAX_BYTES: Final = 768 * 1024
_AUTHORIZATION_DIGEST_BYTES: Final = 65
_JOURNAL_FILENAME: Final = "live-claims.sqlite3"
_TERMINAL_OUTPUT_DIRECTORY: Final = "terminal-output"
_SHA256_PATTERN: Final = re.compile(r"^[a-f0-9]{64}$")
_RUN_ID_PATTERN: Final = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_Sha256 = Annotated[str, Field(pattern=r"^[a-f0-9]{64}$")]


class CompactLiveOperatorError(RuntimeError):
    """Raised when one operator phase fails closed."""


class _FrozenOperatorModel(StrictModel):
    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        validate_default=True,
        strict=True,
        allow_inf_nan=False,
    )


class CompactLiveOperatorManifest(_FrozenOperatorModel):
    """All immutable inputs and independently retained anchors for one call."""

    api_version: Literal["pajin.dev/compact-live-operator-manifest/v1alpha1"] = Field(
        default=COMPACT_LIVE_OPERATOR_MANIFEST_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactLiveOperatorManifest"] = "CompactLiveOperatorManifest"

    source_run_path: Path = Field(alias="sourceRunPath")
    source_run_id: str = Field(alias="sourceRunId", pattern=_RUN_ID_PATTERN.pattern)
    source_run_root_digest: _Sha256 = Field(alias="sourceRunRootDigest")

    skill_run_path: Path = Field(alias="skillRunPath")
    skill_run_id: str = Field(alias="skillRunId", pattern=_RUN_ID_PATTERN.pattern)
    skill_run_root_digest: _Sha256 = Field(alias="skillRunRootDigest")
    registry: SkillRegistryRef
    selection_policy_digest: _Sha256 = Field(alias="selectionPolicyDigest")

    capacity_run_path: Path = Field(alias="capacityRunPath")
    capacity_run_id: str = Field(alias="capacityRunId", pattern=_RUN_ID_PATTERN.pattern)
    capacity_run_root_digest: _Sha256 = Field(alias="capacityRunRootDigest")
    capacity_pin_digest: _Sha256 = Field(alias="capacityPinDigest")
    capacity_proof_digest: _Sha256 = Field(alias="capacityProofDigest")
    capacity_model_materialization_attestation_digest: _Sha256 = Field(
        alias="capacityModelMaterializationAttestationDigest"
    )

    lineage_transport_pin_path: Path = Field(alias="lineageTransportPinPath")
    lineage_transport_pin_digest: _Sha256 = Field(alias="lineageTransportPinDigest")

    preparation_run_path: Path = Field(alias="preparationRunPath")
    preparation_run_id: str = Field(alias="preparationRunId", pattern=_RUN_ID_PATTERN.pattern)
    preparation_run_root_digest: _Sha256 = Field(alias="preparationRunRootDigest")
    preparation_digest: _Sha256 = Field(alias="preparationDigest")
    preparation_index_digest: _Sha256 = Field(alias="preparationIndexDigest")
    live_request_digest: _Sha256 = Field(alias="liveRequestDigest")

    admission_path: Path = Field(alias="admissionPath")
    admission_id: str = Field(
        alias="admissionId",
        pattern=r"^prepared-compact-web-analysis:.+",
        max_length=110,
    )
    admission_digest: _Sha256 = Field(alias="admissionDigest")

    compact_runtime_pin_path: Path = Field(alias="compactRuntimePinPath")
    compact_runtime_pin_digest: _Sha256 = Field(alias="compactRuntimePinDigest")
    compact_transport_pin_path: Path = Field(alias="compactTransportPinPath")
    compact_transport_pin_digest: _Sha256 = Field(alias="compactTransportPinDigest")
    model_path: Path = Field(alias="modelPath")

    @field_validator(
        "source_run_path",
        "skill_run_path",
        "capacity_run_path",
        "lineage_transport_pin_path",
        "preparation_run_path",
        "admission_path",
        "compact_runtime_pin_path",
        "compact_transport_pin_path",
        "model_path",
    )
    @classmethod
    def require_canonical_absolute_path(cls, value: Path) -> Path:
        if not isinstance(value, Path):
            raise ValueError("Compact live operator paths must be Path values")
        rendered = os.fspath(value)
        if "\x00" in rendered or not value.is_absolute():
            raise ValueError("Compact live operator paths must be absolute")
        canonical = Path(os.path.abspath(rendered))
        if canonical != value:
            raise ValueError("Compact live operator paths must be lexically canonical")
        return canonical

    @model_validator(mode="after")
    def require_independent_paths_and_lineage(self) -> Self:
        run_paths = (
            self.source_run_path,
            self.skill_run_path,
            self.capacity_run_path,
            self.preparation_run_path,
        )
        artifacts = (
            self.lineage_transport_pin_path,
            self.admission_path,
            self.compact_runtime_pin_path,
            self.compact_transport_pin_path,
        )
        if len(set(run_paths)) != len(run_paths):
            raise ValueError("Compact live sealed Run paths must be distinct")
        if len(set(artifacts)) != len(artifacts):
            raise ValueError("Compact live standalone artifact paths must be distinct")
        if any(path in set(run_paths) for path in artifacts):
            raise ValueError("Compact live Run and standalone artifact paths must be distinct")
        return self


class CompactLiveProvisionedState(_FrozenOperatorModel):
    """Public, secret-free result of one durable-state provisioning operation."""

    api_version: Literal["pajin.dev/compact-live-provisioned-state/v1alpha1"] = Field(
        default=COMPACT_LIVE_PROVISIONED_STATE_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactLiveProvisionedState"] = "CompactLiveProvisionedState"
    state_root: Path = Field(alias="stateRoot")
    claim_journal_path: Path = Field(alias="claimJournalPath")
    terminal_output_root: Path = Field(alias="terminalOutputRoot")
    claim_store_id: _Sha256 = Field(alias="claimStoreId")
    execution_authority: Literal[False] = Field(default=False, alias="executionAuthority")


class CompactLivePreflightResult(_FrozenOperatorModel):
    """Secret-free evidence returned after the pure verification phase."""

    api_version: Literal["pajin.dev/compact-live-preflight/v1alpha1"] = Field(
        default=COMPACT_LIVE_PREFLIGHT_API_VERSION,
        alias="apiVersion",
    )
    kind: Literal["CompactLivePreflightResult"] = "CompactLivePreflightResult"
    status: Literal["verified-not-claimed-no-dispatch"] = "verified-not-claimed-no-dispatch"
    admission_id: str = Field(alias="admissionId")
    admission_digest: _Sha256 = Field(alias="admissionDigest")
    authorization_request_digest: _Sha256 = Field(alias="authorizationRequestDigest")
    authorization_envelope_digest: _Sha256 = Field(alias="authorizationEnvelopeDigest")
    authorization_verification_digest: _Sha256 = Field(alias="authorizationVerificationDigest")
    compact_runtime_pin_digest: _Sha256 = Field(alias="compactRuntimePinDigest")
    compact_transport_pin_digest: _Sha256 = Field(alias="compactTransportPinDigest")
    claim_performed: Literal[False] = Field(default=False, alias="claimPerformed")
    credential_issued: Literal[False] = Field(default=False, alias="credentialIssued")
    materialization_performed: Literal[False] = Field(
        default=False,
        alias="materializationPerformed",
    )
    provider_dispatch_count: Literal[0] = Field(default=0, alias="providerDispatchCount")
    target_request_count: Literal[0] = Field(default=0, alias="targetRequestCount")


@dataclass(frozen=True, slots=True)
class _VerifiedImmutableInputs:
    manifest: CompactLiveOperatorManifest
    source: VerifiedAuthenticatedDiscoveryRun
    skill_run: VerifiedWebAnalysisSkillProjectionRun
    capacity_run: VerifiedWebAnalysisCapacityV2Run
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun
    planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission
    lineage_transport_pin: WebAnalysisTransportRuntimePin
    compact_runtime_pin: CompactWebAnalysisRuntimePin
    compact_transport_pin: CompactWebAnalysisTransportPin


@dataclass(frozen=True, slots=True)
class VerifiedCompactLiveInputs:
    """All strictly reloaded values used by one execution construction."""

    immutable: _VerifiedImmutableInputs
    trust_anchor: WebAnalysisOneCallAuthorizationTrustAnchor
    signed_authorization: SignedWebAnalysisOneCallAuthorizationV2
    authorization_verifier: WebAnalysisOneCallAuthorizationVerifierV2
    verified_authorization: VerifiedWebAnalysisOneCallAuthorizationV2

    @property
    def result(self) -> CompactLivePreflightResult:
        planned = self.immutable.planned
        verification = self.verified_authorization
        return CompactLivePreflightResult(
            admissionId=planned.admission.admission_id,
            admissionDigest=planned.admission.admission_digest,
            authorizationRequestDigest=self.signed_authorization.statement.request.request_digest,
            authorizationEnvelopeDigest=self.signed_authorization.digest,
            authorizationVerificationDigest=verification.verification_digest,
            compactRuntimePinDigest=self.immutable.compact_runtime_pin.pin_digest,
            compactTransportPinDigest=self.immutable.compact_transport_pin.pin_digest,
        )


class _OneShotRuntime(Protocol):
    async def invoke(self) -> object: ...


def load_compact_live_operator_manifest(path: Path) -> CompactLiveOperatorManifest:
    """Strict-load one bounded manifest without following its leaf symlink."""

    try:
        content = read_bounded_regular_bytes(
            path,
            max_bytes=_MANIFEST_MAX_BYTES,
            label="compact live operator manifest",
            require_single_link=True,
        )
        decoded = parse_strict_json_bytes(
            content,
            label="compact live operator manifest",
            max_bytes=_MANIFEST_MAX_BYTES,
            max_depth=16,
            max_nodes=4_000,
        )
        if type(decoded) is not dict:
            raise TypeError("Compact live operator manifest must be an object")
        canonical = canonical_json_bytes(
            decoded,
            label="compact live operator manifest",
            max_bytes=_MANIFEST_MAX_BYTES,
        )
        manifest = CompactLiveOperatorManifest.model_validate_json(canonical)
        exact = canonical_json_bytes(
            manifest.model_dump(mode="json", by_alias=True),
            label="compact live operator manifest",
            max_bytes=_MANIFEST_MAX_BYTES,
        )
        if canonical != exact or content != exact + b"\n":
            raise ValueError(
                "Compact live operator manifest must be exact canonical JSON plus one line feed"
            )
        return manifest
    except CompactLiveOperatorError:
        raise
    except Exception as exc:
        raise CompactLiveOperatorError("Compact live operator manifest failed closed") from exc


def provision_state(state_root: Path) -> CompactLiveProvisionedState:
    """Create one new owner-only journal/output root and return its store identity."""

    root = _canonical_absolute_path(state_root, label="compact live state root")
    try:
        _require_no_symlink_components(root.parent, label="compact live state parent")
        root.mkdir(mode=0o700, parents=False, exist_ok=False)
        if os.name == "posix":
            root.chmod(0o700)
        _require_owner_directory(root, label="compact live state root")
        terminal_root = root / _TERMINAL_OUTPUT_DIRECTORY
        terminal_root.mkdir(mode=0o700, parents=False, exist_ok=False)
        if os.name == "posix":
            terminal_root.chmod(0o700)
        _require_owner_directory(terminal_root, label="compact live terminal output root")
        journal_path = root / _JOURNAL_FILENAME
        journal = WebAnalysisLiveClaimJournal(journal_path, allow_create=True)
        _require_owner_regular_file(journal_path, label="compact live claim journal")
        return CompactLiveProvisionedState(
            stateRoot=root,
            claimJournalPath=journal_path,
            terminalOutputRoot=terminal_root,
            claimStoreId=journal.store_id,
        )
    except CompactLiveOperatorError:
        raise
    except Exception as exc:
        raise CompactLiveOperatorError("Compact live state provisioning failed closed") from exc


def prepare_authorization_request(
    manifest: CompactLiveOperatorManifest | Path,
    output_path: Path,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    """Strict-reload immutable inputs and emit one signer-neutral v2 request."""

    try:
        verified = _strict_load_immutable_inputs(_coerce_manifest(manifest))
        request = build_web_analysis_one_call_authorization_request_v2(
            admission=verified.planned.admission,
            live_request=verified.preparation_run.live_request,
            capacity_pin=verified.capacity_run.pin,
            lineage_transport_pin=verified.lineage_transport_pin,
            compact_runtime_pin=verified.compact_runtime_pin,
            compact_transport_pin=verified.compact_transport_pin,
        )
        payload = _canonical_model_bytes(
            request,
            label="compact live authorization request v2",
            max_bytes=_SIGNED_AUTHORIZATION_MAX_BYTES,
        )
        _exclusive_owner_write(output_path, payload, label="authorization request")
        return request
    except CompactLiveOperatorError:
        raise
    except Exception as exc:
        raise CompactLiveOperatorError(
            "Compact live authorization request preparation failed closed"
        ) from exc


def preflight(
    manifest: CompactLiveOperatorManifest | Path,
    *,
    trust_anchor_path: Path,
    trust_anchor_digest_path: Path,
    signed_authorization_path: Path,
) -> VerifiedCompactLiveInputs:
    """Verify all immutable/public authorization inputs with zero live side effects."""

    try:
        exact_manifest = _coerce_manifest(manifest)
        immutable = _strict_load_immutable_inputs(exact_manifest)
        authorization_paths = (
            _canonical_absolute_path(trust_anchor_path, label="trust anchor path"),
            _canonical_absolute_path(
                trust_anchor_digest_path,
                label="trust anchor digest path",
            ),
            _canonical_absolute_path(
                signed_authorization_path,
                label="signed authorization path",
            ),
        )
        if len(set(authorization_paths)) != len(authorization_paths):
            raise ValueError("Authorization input paths must be distinct")
        immutable_paths = {
            exact_manifest.admission_path,
            exact_manifest.lineage_transport_pin_path,
            exact_manifest.compact_runtime_pin_path,
            exact_manifest.compact_transport_pin_path,
            exact_manifest.model_path,
        }
        if any(path in immutable_paths for path in authorization_paths):
            raise ValueError("Authorization inputs must be independent artifacts")

        trust_anchor_bytes = _read_owner_only_file(
            authorization_paths[0],
            max_bytes=_TRUST_ANCHOR_MAX_BYTES,
            label="authorization trust anchor",
        )
        trust_anchor = parse_web_analysis_one_call_authorization_trust_anchor(trust_anchor_bytes)
        if trust_anchor_bytes != _canonical_model_bytes(
            trust_anchor,
            label="authorization trust anchor",
            max_bytes=_TRUST_ANCHOR_MAX_BYTES,
        ):
            raise ValueError("Authorization trust anchor is not canonical JSON plus one line feed")

        digest_bytes = _read_owner_only_file(
            authorization_paths[1],
            max_bytes=_AUTHORIZATION_DIGEST_BYTES,
            label="authorization trust anchor digest",
        )
        if (
            len(digest_bytes) != _AUTHORIZATION_DIGEST_BYTES
            or digest_bytes[-1:] != b"\n"
            or _SHA256_PATTERN.fullmatch(digest_bytes[:-1].decode("ascii", errors="strict")) is None
        ):
            raise ValueError("Authorization trust anchor digest artifact is not exact")
        expected_trust_anchor_digest = digest_bytes[:-1].decode("ascii")
        if not compare_digest(trust_anchor.digest, expected_trust_anchor_digest):
            raise ValueError("Authorization trust anchor differs from its retained digest")

        signed_bytes = _read_owner_only_file(
            authorization_paths[2],
            max_bytes=_SIGNED_AUTHORIZATION_MAX_BYTES,
            label="signed authorization v2",
        )
        signed = parse_signed_web_analysis_one_call_authorization_v2(signed_bytes)
        if signed_bytes != _canonical_model_bytes(
            signed,
            label="signed authorization v2",
            max_bytes=_SIGNED_AUTHORIZATION_MAX_BYTES,
        ):
            raise ValueError("Signed authorization v2 is not canonical JSON plus one line feed")

        verifier = WebAnalysisOneCallAuthorizationVerifierV2(
            trust_anchor=trust_anchor,
            expected_trust_anchor_digest=expected_trust_anchor_digest,
        )
        verified_authorization = verifier.verify(
            signed,
            admission=immutable.planned.admission,
            live_request=immutable.preparation_run.live_request,
            capacity_pin=immutable.capacity_run.pin,
            lineage_transport_pin=immutable.lineage_transport_pin,
            compact_runtime_pin=immutable.compact_runtime_pin,
            compact_transport_pin=immutable.compact_transport_pin,
        )
        return VerifiedCompactLiveInputs(
            immutable=immutable,
            trust_anchor=trust_anchor,
            signed_authorization=signed,
            authorization_verifier=verifier,
            verified_authorization=verified_authorization,
        )
    except CompactLiveOperatorError:
        raise
    except Exception as exc:
        raise CompactLiveOperatorError("Compact live preflight failed closed") from exc


async def execute(
    manifest: CompactLiveOperatorManifest | Path,
    *,
    trust_anchor_path: Path,
    trust_anchor_digest_path: Path,
    signed_authorization_path: Path,
    state_root: Path,
    expected_store_id: str,
    docker_executable: str = "docker",
) -> object:
    """Repeat preflight, open the exact existing store, and invoke exactly once."""

    verified = preflight(
        manifest,
        trust_anchor_path=trust_anchor_path,
        trust_anchor_digest_path=trust_anchor_digest_path,
        signed_authorization_path=signed_authorization_path,
    )
    try:
        if (
            type(expected_store_id) is not str
            or _SHA256_PATTERN.fullmatch(expected_store_id) is None
        ):
            raise ValueError("Expected claim store identity must be a SHA-256 digest")
        if type(docker_executable) is not str or not docker_executable:
            raise ValueError("Docker executable must be a non-empty string")
        root = _canonical_absolute_path(state_root, label="compact live state root")
        _require_owner_directory(root, label="compact live state root")
        terminal_root = root / _TERMINAL_OUTPUT_DIRECTORY
        _require_owner_directory(terminal_root, label="compact live terminal output root")
        journal_path = root / _JOURNAL_FILENAME
        _require_owner_regular_file(journal_path, label="compact live claim journal")
        journal = WebAnalysisLiveClaimJournal(
            journal_path,
            expected_store_id=expected_store_id,
            allow_create=False,
        )
        if not compare_digest(journal.store_id, expected_store_id):
            raise ValueError("Compact live claim store identity differs after open")

        broker = SecretBroker()
        secret_ref = (
            verified.immutable.preparation_run.live_request.provider_registration.secret_ref
        )
        broker.register(secret_ref, secrets.token_urlsafe(48))
        runtime = _build_live_runtime(
            verified,
            journal=journal,
            broker=broker,
            terminal_output_root=terminal_root,
            docker_executable=docker_executable,
        )
        return await runtime.invoke()
    except CompactLiveOperatorError:
        raise
    except BaseException as exc:
        if isinstance(exc, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        raise CompactLiveOperatorError("Compact live execution failed closed") from exc


def prepare_compact_live_authorization_request(
    manifest: CompactLiveOperatorManifest | Path,
    output_path: Path,
) -> WebAnalysisOneCallAuthorizationRequestV2:
    """Named API alias matching the compact-live contract."""

    return prepare_authorization_request(manifest, output_path)


def preflight_compact_live(
    manifest: CompactLiveOperatorManifest | Path,
    *,
    trust_anchor_path: Path,
    trust_anchor_digest_path: Path,
    signed_authorization_path: Path,
) -> VerifiedCompactLiveInputs:
    """Named API alias matching the compact-live contract."""

    return preflight(
        manifest,
        trust_anchor_path=trust_anchor_path,
        trust_anchor_digest_path=trust_anchor_digest_path,
        signed_authorization_path=signed_authorization_path,
    )


async def execute_compact_live(
    manifest: CompactLiveOperatorManifest | Path,
    *,
    trust_anchor_path: Path,
    trust_anchor_digest_path: Path,
    signed_authorization_path: Path,
    state_root: Path,
    expected_store_id: str,
    docker_executable: str = "docker",
) -> object:
    """Named API alias matching the compact-live contract."""

    return await execute(
        manifest,
        trust_anchor_path=trust_anchor_path,
        trust_anchor_digest_path=trust_anchor_digest_path,
        signed_authorization_path=signed_authorization_path,
        state_root=state_root,
        expected_store_id=expected_store_id,
        docker_executable=docker_executable,
    )


def _strict_load_immutable_inputs(
    manifest: CompactLiveOperatorManifest,
) -> _VerifiedImmutableInputs:
    source = load_verified_authenticated_discovery(
        manifest.source_run_path,
        expected_run_id=manifest.source_run_id,
        expected_root_digest=manifest.source_run_root_digest,
    )
    skill_run = load_verified_web_analysis_skill_projection(
        manifest.skill_run_path,
        source=source,
        expected_run_id=manifest.skill_run_id,
        expected_root_digest=manifest.skill_run_root_digest,
        expected_source_run_id=manifest.source_run_id,
        expected_source_root_digest=manifest.source_run_root_digest,
        expected_registry_ref=manifest.registry,
        expected_policy_digest=manifest.selection_policy_digest,
    )
    capacity_run = load_verified_web_analysis_capacity_v2_run(
        manifest.capacity_run_path,
        skill_run=skill_run,
        expected_run_id=manifest.capacity_run_id,
        expected_root_digest=manifest.capacity_run_root_digest,
        expected_pin_digest=manifest.capacity_pin_digest,
        expected_transport_pin_digest=manifest.lineage_transport_pin_digest,
        expected_proof_digest=manifest.capacity_proof_digest,
        expected_model_materialization_attestation_digest=(
            manifest.capacity_model_materialization_attestation_digest
        ),
    )
    preparation_run = load_verified_compact_skill_bound_web_analysis_preparation(
        manifest.preparation_run_path,
        skill_run=skill_run,
        capacity_run=capacity_run,
        expected_run_id=manifest.preparation_run_id,
        expected_root_digest=manifest.preparation_run_root_digest,
        expected_skill_run_id=manifest.skill_run_id,
        expected_skill_root_digest=manifest.skill_run_root_digest,
        expected_capacity_run_id=manifest.capacity_run_id,
        expected_capacity_root_digest=manifest.capacity_run_root_digest,
        expected_capacity_pin_digest=manifest.capacity_pin_digest,
        expected_capacity_proof_digest=manifest.capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            manifest.capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=manifest.lineage_transport_pin_digest,
    )
    planned = _plan_admission(
        manifest,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
    )
    planned = _verify_admission(
        manifest,
        planned,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
    )
    supplied_admission = _load_exact_admission(manifest.admission_path)
    if (
        supplied_admission != planned.admission
        or supplied_admission.admission_id != manifest.admission_id
        or supplied_admission.admission_digest != manifest.admission_digest
    ):
        raise ValueError("Prepared compact admission differs from its exact plan or anchors")

    lineage_transport_pin = _load_lineage_transport_pin(
        manifest.lineage_transport_pin_path,
        expected_digest=manifest.lineage_transport_pin_digest,
    )
    compact_runtime_pin = load_verified_compact_web_analysis_runtime_pin(
        manifest.compact_runtime_pin_path,
        capacity=capacity_run,
        live_request=preparation_run.live_request,
        lineage_transport_pin=lineage_transport_pin,
        expected_pin_digest=manifest.compact_runtime_pin_digest,
    )
    compact_transport_pin = load_verified_compact_web_analysis_transport_pin(
        manifest.compact_transport_pin_path,
        runtime_pin=compact_runtime_pin,
        lineage_transport_pin=lineage_transport_pin,
        expected_pin_digest=manifest.compact_transport_pin_digest,
    )
    return _VerifiedImmutableInputs(
        manifest=manifest,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        planned=planned,
        lineage_transport_pin=lineage_transport_pin,
        compact_runtime_pin=compact_runtime_pin,
        compact_transport_pin=compact_transport_pin,
    )


def _plan_admission(
    manifest: CompactLiveOperatorManifest,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
) -> PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
    return plan_prepared_compact_skill_bound_web_analysis_admission(
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        expected_source_run_id=manifest.source_run_id,
        expected_source_root_digest=manifest.source_run_root_digest,
        expected_skill_run_id=manifest.skill_run_id,
        expected_skill_root_digest=manifest.skill_run_root_digest,
        expected_registry_ref=manifest.registry,
        expected_policy_digest=manifest.selection_policy_digest,
        expected_capacity_run_id=manifest.capacity_run_id,
        expected_capacity_root_digest=manifest.capacity_run_root_digest,
        expected_capacity_pin_digest=manifest.capacity_pin_digest,
        expected_capacity_proof_digest=manifest.capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            manifest.capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=manifest.lineage_transport_pin_digest,
        expected_preparation_run_id=manifest.preparation_run_id,
        expected_preparation_root_digest=manifest.preparation_run_root_digest,
        expected_preparation_digest=manifest.preparation_digest,
        expected_preparation_index_digest=manifest.preparation_index_digest,
        expected_live_request_digest=manifest.live_request_digest,
    )


def _verify_admission(
    manifest: CompactLiveOperatorManifest,
    planned: PlannedPreparedCompactSkillBoundWebAnalysisAdmission,
    *,
    source: VerifiedAuthenticatedDiscoveryRun,
    skill_run: VerifiedWebAnalysisSkillProjectionRun,
    capacity_run: VerifiedWebAnalysisCapacityV2Run,
    preparation_run: VerifiedCompactSkillBoundWebAnalysisPreparationRun,
) -> PlannedPreparedCompactSkillBoundWebAnalysisAdmission:
    return verify_planned_prepared_compact_skill_bound_web_analysis_admission(
        planned,
        source=source,
        skill_run=skill_run,
        capacity_run=capacity_run,
        preparation_run=preparation_run,
        expected_source_run_id=manifest.source_run_id,
        expected_source_root_digest=manifest.source_run_root_digest,
        expected_skill_run_id=manifest.skill_run_id,
        expected_skill_root_digest=manifest.skill_run_root_digest,
        expected_registry_ref=manifest.registry,
        expected_policy_digest=manifest.selection_policy_digest,
        expected_capacity_run_id=manifest.capacity_run_id,
        expected_capacity_root_digest=manifest.capacity_run_root_digest,
        expected_capacity_pin_digest=manifest.capacity_pin_digest,
        expected_capacity_proof_digest=manifest.capacity_proof_digest,
        expected_capacity_model_materialization_attestation_digest=(
            manifest.capacity_model_materialization_attestation_digest
        ),
        expected_transport_pin_digest=manifest.lineage_transport_pin_digest,
        expected_preparation_run_id=manifest.preparation_run_id,
        expected_preparation_root_digest=manifest.preparation_run_root_digest,
        expected_preparation_digest=manifest.preparation_digest,
        expected_preparation_index_digest=manifest.preparation_index_digest,
        expected_live_request_digest=manifest.live_request_digest,
    )


def _load_exact_admission(path: Path) -> PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope:
    content = read_bounded_regular_bytes(
        path,
        max_bytes=_ADMISSION_MAX_BYTES,
        label="prepared compact admission",
        require_single_link=True,
    )
    decoded = parse_strict_json_bytes(
        content,
        label="prepared compact admission",
        max_bytes=_ADMISSION_MAX_BYTES,
        max_depth=20,
        max_nodes=20_000,
    )
    canonical = canonical_json_bytes(
        decoded,
        label="prepared compact admission",
        max_bytes=_ADMISSION_MAX_BYTES,
    )
    admission = PreparedCompactSkillBoundWebAnalysisAdmissionEnvelope.model_validate_json(canonical)
    if content not in (canonical, canonical + b"\n"):
        raise ValueError("Prepared compact admission must be canonical JSON")
    exact = canonical_json_bytes(
        admission.model_dump(mode="json", by_alias=True),
        label="prepared compact admission",
        max_bytes=_ADMISSION_MAX_BYTES,
    )
    if canonical != exact:
        raise ValueError("Prepared compact admission omits or changes canonical fields")
    return admission


def _load_lineage_transport_pin(
    path: Path,
    *,
    expected_digest: str,
) -> WebAnalysisTransportRuntimePin:
    decoded = load_bounded_strict_json(
        path,
        max_bytes=_LINEAGE_PIN_MAX_BYTES,
        label="lineage Web analysis transport Pin",
        require_single_link=True,
        max_depth=16,
        max_nodes=5_000,
    )
    if type(decoded) is not dict:
        raise TypeError("Lineage Web analysis transport Pin must be an object")
    canonical = canonical_json_bytes(
        decoded,
        label="lineage Web analysis transport Pin",
        max_bytes=_LINEAGE_PIN_MAX_BYTES,
    )
    pin = WebAnalysisTransportRuntimePin.model_validate_json(canonical)
    exact = canonical_json_bytes(
        pin.model_dump(mode="json", by_alias=True),
        label="lineage Web analysis transport Pin",
        max_bytes=_LINEAGE_PIN_MAX_BYTES,
    )
    if canonical != exact or not compare_digest(pin.pin_digest, expected_digest):
        raise ValueError("Lineage Web analysis transport Pin differs from its anchor")
    return pin


def _build_live_runtime(
    verified: VerifiedCompactLiveInputs,
    *,
    journal: WebAnalysisLiveClaimJournal,
    broker: SecretBroker,
    terminal_output_root: Path,
    docker_executable: str,
) -> _OneShotRuntime:
    """Construct the exact compact Gate-D runtime after the durable store opens.

    The compact runtime constructor is deliberately resolved here so importing
    the preflight/provisioning surface cannot construct runtime components.
    """

    # The runtime is being migrated in the same Gate-D checkpoint.  Resolve its
    # final compact-Pin/v2 signature at execution time and fail closed if any
    # historical constructor is still installed.
    from pajin.web_assessment import analysis_skill_compact_live_runtime as live_runtime

    immutable = verified.immutable
    adapter_type = live_runtime.DockerCompactSkillBoundWebAnalysisDispatchAdapter
    runtime_type = live_runtime.CompactSkillBoundWebAnalysisLiveRuntime
    adapter_parameters = inspect.signature(adapter_type).parameters
    runtime_parameters = inspect.signature(runtime_type).parameters
    required_adapter = {
        "capacity_pin",
        "live_request",
        "lineage_transport_pin",
        "compact_runtime_pin",
        "compact_transport_pin",
        "expected_capacity_pin_digest",
        "expected_lineage_transport_pin_digest",
        "expected_compact_runtime_pin_digest",
        "expected_compact_transport_pin_digest",
        "secrets",
        "docker_executable",
    }
    required_runtime = {
        "source",
        "skill_run",
        "capacity_run",
        "preparation_run",
        "admission",
        "lineage_transport_pin",
        "compact_runtime_pin",
        "compact_transport_pin",
        "signed_authorization",
        "trust_anchor",
        "authorization_verifier",
        "journal",
        "materializer_factory",
        "dispatch_adapter",
        "terminal_output_root",
        "anchors",
    }
    if not required_adapter.issubset(adapter_parameters) or not required_runtime.issubset(
        runtime_parameters
    ):
        raise CompactLiveOperatorError(
            "Installed compact live runtime does not expose the v2 one-shot constructor"
        )

    adapter = adapter_type(
        capacity_pin=immutable.capacity_run.pin,
        live_request=immutable.preparation_run.live_request,
        lineage_transport_pin=immutable.lineage_transport_pin,
        compact_runtime_pin=immutable.compact_runtime_pin,
        compact_transport_pin=immutable.compact_transport_pin,
        expected_capacity_pin_digest=immutable.manifest.capacity_pin_digest,
        expected_lineage_transport_pin_digest=immutable.manifest.lineage_transport_pin_digest,
        expected_compact_runtime_pin_digest=immutable.manifest.compact_runtime_pin_digest,
        expected_compact_transport_pin_digest=immutable.manifest.compact_transport_pin_digest,
        secrets=broker,
        docker_executable=docker_executable,
    )
    anchors = live_runtime.CompactSkillBoundWebAnalysisLiveAnchors(
        source_run_id=immutable.manifest.source_run_id,
        source_root_digest=immutable.manifest.source_run_root_digest,
        skill_run_id=immutable.manifest.skill_run_id,
        skill_root_digest=immutable.manifest.skill_run_root_digest,
        registry_ref=immutable.manifest.registry,
        policy_digest=immutable.manifest.selection_policy_digest,
        capacity_run_id=immutable.manifest.capacity_run_id,
        capacity_root_digest=immutable.manifest.capacity_run_root_digest,
        capacity_pin_digest=immutable.manifest.capacity_pin_digest,
        capacity_proof_digest=immutable.manifest.capacity_proof_digest,
        capacity_materialization_attestation_digest=(
            immutable.manifest.capacity_model_materialization_attestation_digest
        ),
        lineage_transport_pin_digest=immutable.manifest.lineage_transport_pin_digest,
        compact_runtime_pin_digest=immutable.manifest.compact_runtime_pin_digest,
        compact_transport_pin_digest=immutable.manifest.compact_transport_pin_digest,
        preparation_run_id=immutable.manifest.preparation_run_id,
        preparation_root_digest=immutable.manifest.preparation_run_root_digest,
        preparation_digest=immutable.manifest.preparation_digest,
        preparation_index_digest=immutable.manifest.preparation_index_digest,
        live_request_digest=immutable.manifest.live_request_digest,
        trust_anchor_digest=verified.trust_anchor.digest,
        claim_store_id=journal.store_id,
    )

    def materializer_factory(resource_owner: str) -> SubprocessLlamaCppLiveMaterialization:
        return SubprocessLlamaCppLiveMaterialization(
            model_path=immutable.manifest.model_path,
            docker_binary=docker_executable,
            cpus=immutable.compact_runtime_pin.model_cpus,
            memory_mb=immutable.compact_runtime_pin.model_memory_mb,
            pids_limit=immutable.compact_runtime_pin.model_pids,
            resource_owner=resource_owner,
            provider_network_alias="host.docker.internal",
        )

    runtime = runtime_type(
        source=immutable.source,
        skill_run=immutable.skill_run,
        capacity_run=immutable.capacity_run,
        preparation_run=immutable.preparation_run,
        admission=immutable.planned.admission,
        lineage_transport_pin=immutable.lineage_transport_pin,
        compact_runtime_pin=immutable.compact_runtime_pin,
        compact_transport_pin=immutable.compact_transport_pin,
        signed_authorization=verified.signed_authorization,
        trust_anchor=verified.trust_anchor,
        authorization_verifier=verified.authorization_verifier,
        journal=journal,
        materializer_factory=materializer_factory,
        dispatch_adapter=adapter,
        terminal_output_root=terminal_output_root,
        anchors=anchors,
    )
    return cast(_OneShotRuntime, runtime)


def _coerce_manifest(
    manifest: CompactLiveOperatorManifest | Path,
) -> CompactLiveOperatorManifest:
    if type(manifest) is CompactLiveOperatorManifest:
        return manifest
    if isinstance(manifest, Path):
        return load_compact_live_operator_manifest(manifest)
    raise TypeError("Compact live operator requires a manifest or manifest Path")


def _canonical_model_bytes(model: object, *, label: str, max_bytes: int) -> bytes:
    dump = getattr(model, "model_dump", None)
    if not callable(dump):
        raise TypeError(f"{label} is not a serializable strict model")
    value = dump(mode="json", by_alias=True)
    return canonical_json_bytes(value, label=label, max_bytes=max_bytes) + b"\n"


def _canonical_absolute_path(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise TypeError(f"{label} must be a Path")
    rendered = os.fspath(path)
    if "\x00" in rendered or not path.is_absolute():
        raise ValueError(f"{label} must be absolute")
    canonical = Path(os.path.abspath(rendered))
    if canonical != path:
        raise ValueError(f"{label} must be lexically canonical")
    return canonical


def _require_no_symlink_components(path: Path, *, label: str) -> None:
    absolute = _canonical_absolute_path(path, label=label)
    current = Path(absolute.anchor)
    for component in absolute.parts[1:]:
        current /= component
        metadata = os.lstat(current)
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError(f"{label} contains a symbolic-link component")


def _require_owner_directory(path: Path, *, label: str) -> None:
    absolute = _canonical_absolute_path(path, label=label)
    _require_no_symlink_components(absolute, label=label)
    metadata = os.lstat(absolute)
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"{label} must be a directory")
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise ValueError(f"{label} must be owner-owned with mode 0700")


def _require_owner_regular_file(path: Path, *, label: str) -> None:
    absolute = _canonical_absolute_path(path, label=label)
    _require_no_symlink_components(absolute.parent, label=f"{label} parent")
    metadata = os.lstat(absolute)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError(f"{label} must be a single-link regular file")
    if os.name == "posix" and (
        metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ValueError(f"{label} must be owner-owned with mode 0600")


def _read_owner_only_file(path: Path, *, max_bytes: int, label: str) -> bytes:
    absolute = _canonical_absolute_path(path, label=f"{label} path")
    _require_owner_directory(absolute.parent, label=f"{label} parent")
    _require_owner_regular_file(absolute, label=label)
    content = read_bounded_regular_bytes(
        absolute,
        max_bytes=max_bytes,
        label=label,
        require_single_link=True,
    )
    _require_owner_regular_file(absolute, label=label)
    return content


def _exclusive_owner_write(path: Path, content: bytes, *, label: str) -> None:
    destination = _canonical_absolute_path(path, label=f"{label} output path")
    if not isinstance(content, bytes):
        raise TypeError(f"{label} output must be bytes")
    _require_owner_directory(destination.parent, label=f"{label} output parent")
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(destination, flags, 0o600)
        if os.name == "posix":
            os.fchmod(descriptor, 0o600)
        view = memoryview(content)
        written = 0
        while written < len(view):
            count = os.write(descriptor, view[written:])
            if count < 1:
                raise OSError(f"{label} output write made no progress")
            written += count
        os.fsync(descriptor)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    _require_owner_regular_file(destination, label=f"{label} output")
    observed = read_bounded_regular_bytes(
        destination,
        max_bytes=max(len(content), 1),
        label=f"{label} output",
        require_single_link=True,
    )
    if observed != content:
        raise ValueError(f"{label} output differs after write")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pajin-compact-live",
        description="Provision, preflight, or execute one compact WEB-007 live completion",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    provision = commands.add_parser("provision-state")
    provision.add_argument("--state-root", type=Path, required=True)

    prepare = commands.add_parser("prepare-authorization-request")
    prepare.add_argument("--manifest", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    for name in ("preflight", "execute"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--trust-anchor", type=Path, required=True)
        command.add_argument("--trust-anchor-digest", type=Path, required=True)
        command.add_argument("--signed-authorization", type=Path, required=True)
        if name == "execute":
            command.add_argument("--state-root", type=Path, required=True)
            command.add_argument("--expected-store-id", required=True)
            command.add_argument("--docker-executable", default="docker")
    return parser


def _stdout_model(model: object) -> None:
    sys.stdout.buffer.write(
        _canonical_model_bytes(
            model,
            label="compact live operator output",
            max_bytes=2 * 1024 * 1024,
        )
    )


def _require_literal_false_fields(
    value: object,
    *,
    label: str,
    fields: tuple[str, ...],
) -> None:
    for field in fields:
        marker = getattr(value, field)
        if type(marker) is not bool or marker is not False:
            raise ValueError(f"{label} {field} must be literal false")


def _successful_proposal_for_output(
    outcome: object,
) -> CompiledSkillBoundWebAnalysisProposal:
    """Extract only a fully cross-linked, zero-authority terminal success proposal."""

    try:
        from pajin.web_assessment import analysis_skill_compact_live_runtime as live_runtime

        if type(outcome) is not live_runtime.CompactSkillBoundWebAnalysisLiveCompletion:
            raise TypeError("Compact live execution returned an unexpected outcome type")
        proposal = outcome.proposal
        if type(proposal) is not CompiledSkillBoundWebAnalysisProposal:
            raise TypeError("Compact live execution did not return an exact compiled proposal")
        if type(outcome.dispatch_count) is not int or outcome.dispatch_count != 1:
            raise ValueError("Compact live success must retain exactly one dispatch")

        _require_literal_false_fields(
            proposal,
            label="compiled Skill-bound proposal",
            fields=(
                "model_output_authoritative",
                "scope_expansion_authorized",
                "tool_request_compiled",
                "capability_granted",
                "permit_granted",
                "execution_authorized",
                "graph_admission_authorized",
                "finding_authorized",
                "report_delivery_authorized",
            ),
        )
        _require_literal_false_fields(
            proposal.compiled_proposal,
            label="nested compiled proposal",
            fields=(
                "model_output_authoritative",
                "diagnostic_selection_authoritative",
                "path_assessment_authoritative",
                "scope_expansion_authorized",
                "tool_request_compiled",
                "capability_granted",
                "permit_granted",
                "execution_authorized",
                "graph_admission_authorized",
                "finding_authorized",
                "report_delivery_authorized",
            ),
        )
        completion_false_fields = (
            "target_request_authority",
            "tool_request_authority",
            "finding_authority",
            "graph_admission_authority",
            "report_authority",
            "retry_authority",
            "automatic_redispatch_authority",
        )
        _require_literal_false_fields(
            outcome,
            label="compact live completion",
            fields=completion_false_fields,
        )

        terminal_run = outcome.terminal_run
        terminal_proposal = terminal_run.proposal
        receipt = terminal_run.receipt
        receipt_proposal = receipt.compiled_proposal
        if (
            type(terminal_proposal) is not CompiledSkillBoundWebAnalysisProposal
            or type(receipt_proposal) is not CompiledSkillBoundWebAnalysisProposal
            or terminal_proposal != proposal
            or receipt_proposal != proposal
        ):
            raise ValueError("Compact live terminal proposal cross-links differ")
        _require_literal_false_fields(
            terminal_run,
            label="compact live terminal Run",
            fields=completion_false_fields,
        )
        _require_literal_false_fields(
            receipt,
            label="compact live terminal receipt",
            fields=(
                "target_request_authority",
                "tool_request_authority",
                "capability_authority",
                "permit_authority",
                "finding_authority",
                "graph_admission_authority",
                "report_authority",
                "delivery_authority",
                "retry_authority",
                "automatic_redispatch_authority",
            ),
        )
        terminal_claim = terminal_run.terminal_claim
        pending_claim = receipt.pending_claim
        if (
            type(terminal_claim.dispatch_count) is not int
            or terminal_claim.dispatch_count != 1
            or type(pending_claim.dispatch_count) is not int
            or pending_claim.dispatch_count != 1
        ):
            raise ValueError("Compact live terminal evidence must retain one dispatch")
        if (
            terminal_claim.terminal_disposition
            is not WebAnalysisLiveClaimTerminalDisposition.SUCCESS
        ):
            raise ValueError("Compact live terminal claim is not successful")
        return proposal
    except CompactLiveOperatorError:
        raise
    except Exception as exc:
        raise CompactLiveOperatorError(
            "Compact live execution outcome failed success validation"
        ) from exc


def main(argv: Sequence[str] | None = None) -> int:
    """Run one explicit operator phase; there is no retry or recovery command."""

    arguments = _parser().parse_args(argv)
    try:
        if arguments.command == "provision-state":
            _stdout_model(provision_state(arguments.state_root))
        elif arguments.command == "prepare-authorization-request":
            request = prepare_authorization_request(arguments.manifest, arguments.output)
            _stdout_model(request)
        elif arguments.command == "preflight":
            verified = preflight(
                arguments.manifest,
                trust_anchor_path=arguments.trust_anchor,
                trust_anchor_digest_path=arguments.trust_anchor_digest,
                signed_authorization_path=arguments.signed_authorization,
            )
            _stdout_model(verified.result)
        elif arguments.command == "execute":
            outcome = asyncio.run(
                execute(
                    arguments.manifest,
                    trust_anchor_path=arguments.trust_anchor,
                    trust_anchor_digest_path=arguments.trust_anchor_digest,
                    signed_authorization_path=arguments.signed_authorization,
                    state_root=arguments.state_root,
                    expected_store_id=arguments.expected_store_id,
                    docker_executable=arguments.docker_executable,
                )
            )
            _stdout_model(_successful_proposal_for_output(outcome))
        else:  # pragma: no cover - argparse requires one known command
            raise CompactLiveOperatorError("Unknown compact live operator command")
    except BaseException as exc:
        if isinstance(exc, (KeyboardInterrupt, SystemExit)):
            raise
        sys.stderr.write(f"compact live operator failed: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover - console entrypoint owns invocation
    raise SystemExit(main())
