"""Isolated parent/child coordinator for one governed local Web campaign.

The public process boundary owns the newly-created output-root descriptor and
does not trust a child exit code as completion evidence.  The child blocks at
every sealed parent checkpoint until this process reloads that exact signed
Run below the pinned output inode and acknowledges the canonical progress
record.  Success returns a strictly reloaded completed historical receipt;
failure may expose only the last independently verified and acknowledged
incomplete receipt.  Live signers, stores, and other execution authorities
remain in the child process.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import selectors
import signal
import stat
import subprocess
import sys
import threading
import time
from contextlib import suppress
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Final, Literal, cast

from pajin.graph.sqlite_store import (
    _MAX_GRAPH_BYTES,
)
from pajin.graph.sqlite_store import (
    _SCHEMA_DIGEST as _GRAPH_SCHEMA_DIGEST,
)
from pajin.runtime.pinned_sqlite import load_verified_pinned_sqlite_checkpoint_chain
from pajin.runtime.pinned_workspace import (
    PinnedOutputRoot,
    PinnedWorkspaceIdentity,
    activate_inherited_pinned_workspace,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.web_assessment.governed_campaign_evidence import (
    GOVERNED_WEB_ADAPTER_REF,
    GOVERNED_WEB_CAMPAIGN_ID,
    GOVERNED_WEB_CAMPAIGN_STAGE_ORDER,
    GOVERNED_WEB_ORIGIN,
    GovernedWebCampaignHistoricalResult,
    VerifiedGovernedWebCompletedCampaign,
    VerifiedGovernedWebIncompleteCampaign,
    load_verified_governed_web_campaign_terminal,
    load_verified_governed_web_completed_campaign_evidence,
)
from pajin.web_assessment.governed_models import (
    _WEB_GRANT_CONSUMPTION_MAX_BYTES,
    _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST,
)
from pajin.web_assessment.governed_worker import (
    WEB_WORKER_OS_ENV_ALLOWLIST,
    _activate_governed_coordinator_worker_group,
    _create_governed_coordinator_worker_group_authority,
    _current_macos_user_text_encoding,
    _current_python_runtime_identity,
)

_PROGRESS_API_VERSION: Final = "pajin.dev/governed-web-process-progress/v1alpha1"
_PROGRESS_KIND: Final = "GovernedWebCampaignProcessProgress"
_ACK_API_VERSION: Final = "pajin.dev/governed-web-process-ack/v1alpha1"
_ACK_KIND: Final = "GovernedWebCampaignProcessAck"
_PROGRESS_DIGEST_DOMAIN: Final = b"pajin.web.governed-process-progress/v1\0"
_COORDINATOR_MARKER: Final = "PAJIN_GOVERNED_WEB_COORDINATOR_HOST_SUBPROCESS"
_WORKER_MARKER: Final = "PAJIN_WEB_WORKER_HOST_SUBPROCESS"
_MAX_PROGRESS_RECORDS: Final = 32
_MAX_PROGRESS_RECORD_BYTES: Final = 4 * 1024
_MAX_PROGRESS_BYTES: Final = 128 * 1024
_MAX_CAPTURE_BYTES: Final = 64 * 1024
_PROCESS_TIMEOUT_SECONDS: Final = 15 * 60.0
_ACK_TIMEOUT_SECONDS: Final = 60.0
_POLL_SECONDS: Final = 0.10
_TERMINATION_GRACE_SECONDS: Final = 1.0
_RUN_ID = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256 = re.compile(r"^[a-f0-9]{64}$")

_ProgressStage = Literal[
    "initial",
    "provisioning",
    "source-gateway",
    "validation-gateway",
    "graph-admission",
    "poc-publication",
    "export-publication",
    "parent-evidence",
]
_ProgressStatus = Literal[
    "prepared",
    "started",
    "completed",
    "database-checkpoint",
    "failed",
]
_DatabaseStoreKind = Literal["governed-web-graph", "governed-web-grant"]

_PROGRESS_FIELDS: Final = frozenset(
    {
        "apiVersion",
        "kind",
        "sequence",
        "previousRecordDigest",
        "recordDigest",
        "parentRunId",
        "campaignPlanDigest",
        "deploymentTrustAnchorDigest",
        "previousParentRootDigest",
        "parentRootDigest",
        "stage",
        "status",
        "terminal",
        "databaseStoreKind",
        "databaseCheckpointOrdinal",
        "databaseManifestDigest",
        "databaseSha256",
        "databaseCheckpointDigest",
    }
)
_ACK_FIELDS: Final = frozenset(
    {
        "apiVersion",
        "kind",
        "sequence",
        "recordDigest",
        "parentRootDigest",
    }
)


class GovernedWebCampaignProcessError(RuntimeError):
    """The isolated coordinator failed closed before verified completion."""

    def __init__(
        self,
        message: str,
        *,
        incomplete_receipt: GovernedWebCampaignIncompleteReceipt | None = None,
    ) -> None:
        super().__init__(message)
        self.incomplete_receipt = incomplete_receipt


class GovernedWebCampaignProcessCancelled(asyncio.CancelledError):
    """Cancellation after cleanup, carrying only independently retained progress."""

    def __init__(
        self,
        *,
        incomplete_receipt: GovernedWebCampaignIncompleteReceipt | None,
    ) -> None:
        super().__init__("governed WEB campaign process was cancelled")
        self.incomplete_receipt = incomplete_receipt


@dataclass(frozen=True, slots=True)
class GovernedWebCampaignIncompleteReceipt:
    """Secret-free last progress independently verified and ACKed by the parent."""

    output_root: Path
    parent_run_path: Path
    parent_run_id: str
    initial_parent_root_digest: str
    parent_root_digest: str
    campaign_plan_digest: str
    deployment_trust_anchor_digest: str
    last_verified_sequence: int
    last_record_digest: str
    last_stage: _ProgressStage
    last_status: _ProgressStatus
    terminal_progress_observed: bool
    campaign_completed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class GovernedWebCampaignProcessReceipt:
    """Authority-free receipt reconstructed by the supervising parent."""

    output_root: Path
    parent_run_path: Path
    parent_run_id: str
    initial_parent_root_digest: str
    parent_root_digest: str
    campaign_plan_digest: str
    deployment_trust_anchor_digest: str
    result: GovernedWebCampaignHistoricalResult

    @property
    def graph_path(self) -> Path:
        return self.output_root / "authority" / "governed-web.sqlite3"

    @property
    def grant_path(self) -> Path:
        return self.output_root / "authority" / "capability-grant-consumptions.sqlite3"

    @property
    def validation_run_path(self) -> Path:
        return (
            self.output_root
            / "validation-runs"
            / "governed-web-validation"
            / self.result.validation_projection_run_id
        )

    @property
    def report_path(self) -> Path:
        return self.output_root / self.result.report_reference

    @property
    def poc_bundle_path(self) -> Path:
        return self.output_root / "poc-bundle"

    @property
    def poc_manifest_path(self) -> Path:
        return self.output_root / self.result.poc_manifest_reference

    @property
    def sarif_path(self) -> Path:
        return self.output_root / self.result.sarif_reference

    @property
    def delivery_readiness_path(self) -> Path:
        return self.output_root / self.result.delivery_readiness_reference


@dataclass(frozen=True, slots=True)
class _ProgressRecord:
    sequence: int
    previous_record_digest: str | None
    record_digest: str
    parent_run_id: str
    campaign_plan_digest: str
    deployment_trust_anchor_digest: str
    previous_parent_root_digest: str | None
    parent_root_digest: str
    stage: _ProgressStage
    status: _ProgressStatus
    terminal: bool
    database_store_kind: _DatabaseStoreKind | None
    database_checkpoint_ordinal: int | None
    database_manifest_digest: str | None
    database_sha256: str | None
    database_checkpoint_digest: str | None


class _SupervisorProgressState:
    """Thread-safe custody for the last parent-verified progress receipt."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._incomplete_receipt: GovernedWebCampaignIncompleteReceipt | None = None
        self._last_verified_sequence = 0

    @property
    def incomplete_receipt(self) -> GovernedWebCampaignIncompleteReceipt | None:
        with self._lock:
            return self._incomplete_receipt

    def require_next_verified_ack(
        self,
        *,
        sequence: int,
        incomplete_receipt: GovernedWebCampaignIncompleteReceipt | None,
    ) -> None:
        with self._lock:
            if sequence != self._last_verified_sequence + 1:
                raise GovernedWebCampaignProcessError(
                    "governed WEB verified progress ACK is not contiguous"
                )
            if (
                incomplete_receipt is not None
                and incomplete_receipt.last_verified_sequence != sequence
            ):
                raise GovernedWebCampaignProcessError(
                    "governed WEB incomplete receipt differs from its verified ACK"
                )

    def commit_verified_ack(
        self,
        *,
        sequence: int,
        incomplete_receipt: GovernedWebCampaignIncompleteReceipt | None,
    ) -> None:
        """Commit an already-validated ACK transition without a post-ACK failure path."""

        with self._lock:
            self._last_verified_sequence = sequence
            self._incomplete_receipt = incomplete_receipt


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _progress_digest(material: dict[str, object]) -> str:
    return sha256(_PROGRESS_DIGEST_DOMAIN + _canonical_json(material)).hexdigest()


def _digest_or_none(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise GovernedWebCampaignProcessError(f"{label} is not a canonical SHA-256 digest")
    return value


def _parse_progress_record(content: bytes) -> _ProgressRecord:
    if not content or len(content) > _MAX_PROGRESS_RECORD_BYTES:
        raise GovernedWebCampaignProcessError("governed WEB progress record exceeds its limit")
    try:
        decoded = parse_strict_json_bytes(
            content,
            label="governed WEB process progress",
            max_bytes=_MAX_PROGRESS_RECORD_BYTES,
            max_depth=8,
            max_nodes=64,
        )
    except ValueError as exc:
        raise GovernedWebCampaignProcessError(
            "governed WEB process emitted invalid progress JSON"
        ) from exc
    if type(decoded) is not dict or frozenset(decoded) != _PROGRESS_FIELDS:
        raise GovernedWebCampaignProcessError("governed WEB progress schema is not exact")
    raw = cast(dict[str, object], decoded)
    if content != _canonical_json(raw):
        raise GovernedWebCampaignProcessError("governed WEB progress JSON is not canonical")
    if raw["apiVersion"] != _PROGRESS_API_VERSION or raw["kind"] != _PROGRESS_KIND:
        raise GovernedWebCampaignProcessError("governed WEB progress version is unsupported")
    sequence = raw["sequence"]
    terminal = raw["terminal"]
    parent_run_id = raw["parentRunId"]
    stage = raw["stage"]
    status = raw["status"]
    if type(sequence) is not int or not 1 <= sequence <= _MAX_PROGRESS_RECORDS:
        raise GovernedWebCampaignProcessError("governed WEB progress sequence is invalid")
    if type(terminal) is not bool:
        raise GovernedWebCampaignProcessError("governed WEB progress terminal flag is invalid")
    if type(parent_run_id) is not str or _RUN_ID.fullmatch(parent_run_id) is None:
        raise GovernedWebCampaignProcessError("governed WEB progress Run ID is invalid")
    stages = {"initial", *GOVERNED_WEB_CAMPAIGN_STAGE_ORDER}
    statuses = {"prepared", "started", "completed", "database-checkpoint", "failed"}
    if stage not in stages or status not in statuses:
        raise GovernedWebCampaignProcessError("governed WEB progress state is invalid")
    if (stage == "initial") is not (status == "prepared") or (status == "prepared" and terminal):
        raise GovernedWebCampaignProcessError("governed WEB prepared progress is invalid")
    campaign_plan_digest = _digest_or_none(
        raw["campaignPlanDigest"], label="governed WEB Campaign Plan digest"
    )
    anchor_digest = _digest_or_none(
        raw["deploymentTrustAnchorDigest"],
        label="governed WEB deployment trust-anchor digest",
    )
    parent_root_digest = _digest_or_none(
        raw["parentRootDigest"], label="governed WEB parent root digest"
    )
    record_digest = _digest_or_none(
        raw["recordDigest"], label="governed WEB progress record digest"
    )
    assert campaign_plan_digest is not None
    assert anchor_digest is not None
    assert parent_root_digest is not None
    assert record_digest is not None
    previous_record = _digest_or_none(
        raw["previousRecordDigest"], label="governed WEB previous progress digest"
    )
    previous_parent = _digest_or_none(
        raw["previousParentRootDigest"], label="governed WEB previous parent root digest"
    )
    store_kind = raw["databaseStoreKind"]
    ordinal = raw["databaseCheckpointOrdinal"]
    manifest_digest = _digest_or_none(
        raw["databaseManifestDigest"],
        label="governed WEB database manifest digest",
    )
    database_sha256 = _digest_or_none(
        raw["databaseSha256"],
        label="governed WEB database SHA-256",
    )
    checkpoint_digest = _digest_or_none(
        raw["databaseCheckpointDigest"],
        label="governed WEB database checkpoint digest",
    )
    if status == "database-checkpoint":
        if (
            store_kind not in {"governed-web-graph", "governed-web-grant"}
            or type(ordinal) is not int
            or not 1 <= ordinal <= 4096
            or manifest_digest is None
            or database_sha256 is None
            or checkpoint_digest is None
            or stage == "initial"
            or terminal
        ):
            raise GovernedWebCampaignProcessError(
                "governed WEB database-checkpoint progress is invalid"
            )
        validated_ordinal: int | None = ordinal
    elif any(
        value is not None
        for value in (
            store_kind,
            ordinal,
            manifest_digest,
            database_sha256,
            checkpoint_digest,
        )
    ):
        raise GovernedWebCampaignProcessError(
            "governed WEB non-database progress contains database fields"
        )
    else:
        validated_ordinal = None
    material = dict(raw)
    material.pop("recordDigest")
    if _progress_digest(material) != record_digest:
        raise GovernedWebCampaignProcessError("governed WEB progress digest differs")
    return _ProgressRecord(
        sequence=sequence,
        previous_record_digest=previous_record,
        record_digest=record_digest,
        parent_run_id=parent_run_id,
        campaign_plan_digest=campaign_plan_digest,
        deployment_trust_anchor_digest=anchor_digest,
        previous_parent_root_digest=previous_parent,
        parent_root_digest=parent_root_digest,
        stage=cast(_ProgressStage, stage),
        status=cast(_ProgressStatus, status),
        terminal=terminal,
        database_store_kind=cast(_DatabaseStoreKind | None, store_kind),
        database_checkpoint_ordinal=validated_ordinal,
        database_manifest_digest=manifest_digest,
        database_sha256=database_sha256,
        database_checkpoint_digest=checkpoint_digest,
    )


def _validate_progress_chain(
    records: list[_ProgressRecord],
    record: _ProgressRecord,
) -> None:
    if len(records) >= _MAX_PROGRESS_RECORDS:
        raise GovernedWebCampaignProcessError("governed WEB progress record limit was exceeded")
    if records and records[-1].terminal:
        raise GovernedWebCampaignProcessError(
            "governed WEB process emitted progress after terminal"
        )
    expected_sequence = len(records) + 1
    expected_record = records[-1].record_digest if records else None
    expected_parent = records[-1].parent_root_digest if records else None
    if (
        record.sequence != expected_sequence
        or record.previous_record_digest != expected_record
        or record.previous_parent_root_digest != expected_parent
    ):
        raise GovernedWebCampaignProcessError("governed WEB progress chain is not contiguous")
    if records:
        first = records[0]
        if (
            record.parent_run_id != first.parent_run_id
            or record.campaign_plan_digest != first.campaign_plan_digest
            or record.deployment_trust_anchor_digest != first.deployment_trust_anchor_digest
        ):
            raise GovernedWebCampaignProcessError("governed WEB progress authority changed")
    elif not (
        record.stage == "initial"
        and record.status == "prepared"
        and not record.terminal
        and record.previous_record_digest is None
        and record.previous_parent_root_digest is None
    ):
        raise GovernedWebCampaignProcessError("governed WEB initial progress is invalid")


def _validate_loaded_progress(
    loaded: VerifiedGovernedWebCompletedCampaign | VerifiedGovernedWebIncompleteCampaign,
    record: _ProgressRecord,
) -> None:
    if (
        loaded.parent_run_id != record.parent_run_id
        or loaded.parent_root_digest != record.parent_root_digest
        or loaded.plan.campaign_plan_digest != record.campaign_plan_digest
        or loaded.deployment_trust_anchor_digest != record.deployment_trust_anchor_digest
        or not loaded.seals
        or loaded.seals[-1].root_digest != record.parent_root_digest
        or loaded.seals[-1].previous_root_digest != record.previous_parent_root_digest
    ):
        raise GovernedWebCampaignProcessError("governed WEB reloaded progress differs")
    if isinstance(loaded, VerifiedGovernedWebCompletedCampaign):
        if not (
            record.stage == "parent-evidence"
            and record.status == "completed"
            and record.terminal
            and loaded.events
            and loaded.events[-1].event_type == "campaign.completed"
        ):
            raise GovernedWebCampaignProcessError(
                "governed WEB completed parent has nonterminal progress"
            )
        return
    incomplete = loaded
    _validate_incomplete_progress(incomplete, record)


def _validate_incomplete_progress(
    incomplete: VerifiedGovernedWebIncompleteCampaign,
    record: _ProgressRecord,
) -> None:
    if incomplete.has_unsealed_tail:
        raise GovernedWebCampaignProcessError("governed WEB progress parent has an unsealed tail")
    if record.status == "failed":
        if not (
            record.terminal
            and incomplete.terminal == "failed"
            and incomplete.incomplete.failure_stage == record.stage
            and incomplete.events
            and incomplete.events[-1].event_type == "campaign.failed"
        ):
            raise GovernedWebCampaignProcessError("governed WEB failed progress differs")
        return
    if record.terminal or incomplete.terminal != "interrupted":
        raise GovernedWebCampaignProcessError("governed WEB nonterminal progress differs")
    if record.status == "started":
        if (
            incomplete.active_stage != record.stage
            or not incomplete.events
            or incomplete.events[-1].event_type != "web.governed.stage.started"
            or incomplete.events[-1].payload.get("stage") != record.stage
        ):
            raise GovernedWebCampaignProcessError("governed WEB active stage differs")
    elif record.status == "prepared":
        if (
            record.stage == "initial"
            and incomplete.active_stage is None
            and not incomplete.completed_stages
            and incomplete.events
            and incomplete.events[-1].event_type == "campaign.started"
        ):
            return
        raise GovernedWebCampaignProcessError("governed WEB initial parent differs")
    elif record.status == "completed":
        if (
            incomplete.active_stage is not None
            or not incomplete.completed_stages
            or incomplete.completed_stages[-1] != record.stage
            or not incomplete.events
            or incomplete.events[-1].event_type != "web.governed.stage.completed"
            or incomplete.events[-1].payload.get("stage") != record.stage
        ):
            raise GovernedWebCampaignProcessError("governed WEB completed stage differs")
    elif record.status == "database-checkpoint":
        event = incomplete.events[-1] if incomplete.events else None
        payload = event.payload if event is not None else None
        if (
            incomplete.active_stage != record.stage
            or event is None
            or event.event_type != "web.governed.database-checkpoint"
            or type(payload) is not dict
            or payload.get("stage") != record.stage
            or payload.get("storeKind") != record.database_store_kind
            or payload.get("ordinal") != record.database_checkpoint_ordinal
            or payload.get("manifestDigest") != record.database_manifest_digest
            or payload.get("databaseSha256") != record.database_sha256
            or payload.get("checkpointDigest") != record.database_checkpoint_digest
        ):
            raise GovernedWebCampaignProcessError(
                "governed WEB database-checkpoint progress differs"
            )
    else:
        raise GovernedWebCampaignProcessError("governed WEB progress status is unsupported")


def _ack_bytes(record: _ProgressRecord) -> bytes:
    return (
        _canonical_json(
            {
                "apiVersion": _ACK_API_VERSION,
                "kind": _ACK_KIND,
                "sequence": record.sequence,
                "recordDigest": record.record_digest,
                "parentRootDigest": record.parent_root_digest,
            }
        )
        + b"\n"
    )


def _write_all(descriptor: int, content: bytes) -> None:
    view = memoryview(content)
    while view:
        written = os.write(descriptor, view)
        if written <= 0:
            raise BrokenPipeError("governed WEB process pipe was closed")
        view = view[written:]


def _read_one_line(descriptor: int, *, timeout_seconds: float, max_bytes: int) -> bytes:
    selector = selectors.DefaultSelector()
    buffer = bytearray()
    try:
        selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("governed WEB process ACK timed out")
            if not selector.select(min(remaining, _POLL_SECONDS)):
                continue
            chunk = os.read(descriptor, max_bytes + 1 - len(buffer))
            if not chunk:
                raise BrokenPipeError("governed WEB process ACK pipe closed")
            buffer.extend(chunk)
            newline = buffer.find(b"\n")
            if newline >= 0:
                if newline != len(buffer) - 1:
                    raise ValueError("governed WEB process ACK contains a trailing record")
                return bytes(buffer[:newline])
            if len(buffer) > max_bytes:
                raise ValueError("governed WEB process ACK exceeds its limit")
    finally:
        selector.close()


class _ChildProgressSink:
    def __init__(self, *, progress_fd: int, ack_fd: int) -> None:
        self._progress_fd = progress_fd
        self._ack_fd = ack_fd
        self._sequence = 0
        self._previous_record_digest: str | None = None
        self._previous_parent_root_digest: str | None = None

    def __call__(self, item: object) -> None:
        self._sequence += 1
        if self._sequence > _MAX_PROGRESS_RECORDS:
            raise ValueError("governed WEB process progress limit was exceeded")
        previous_parent = getattr(item, "previous_parent_root_digest", None)
        if previous_parent != self._previous_parent_root_digest:
            raise ValueError("governed WEB child progress parent chain changed")
        stage = getattr(item, "stage", None)
        status = getattr(item, "status", None)
        store_kind = getattr(item, "database_store_kind", None)
        ordinal = getattr(item, "database_checkpoint_ordinal", None)
        checkpoint_digest = getattr(item, "database_checkpoint_digest", None)
        manifest_digest = getattr(item, "database_manifest_digest", None)
        database_sha256 = getattr(item, "database_sha256", None)
        material: dict[str, object] = {
            "apiVersion": _PROGRESS_API_VERSION,
            "kind": _PROGRESS_KIND,
            "sequence": self._sequence,
            "previousRecordDigest": self._previous_record_digest,
            "parentRunId": getattr(item, "parent_run_id", None),
            "campaignPlanDigest": getattr(item, "campaign_plan_digest", None),
            "deploymentTrustAnchorDigest": getattr(item, "deployment_trust_anchor_digest", None),
            "previousParentRootDigest": previous_parent,
            "parentRootDigest": getattr(item, "parent_root_digest", None),
            "stage": stage,
            "status": status,
            "terminal": getattr(item, "terminal", None),
            "databaseStoreKind": store_kind,
            "databaseCheckpointOrdinal": ordinal,
            "databaseManifestDigest": manifest_digest,
            "databaseSha256": database_sha256,
            "databaseCheckpointDigest": checkpoint_digest,
        }
        record_digest = _progress_digest(material)
        record = {**material, "recordDigest": record_digest}
        encoded = _canonical_json(record)
        if len(encoded) > _MAX_PROGRESS_RECORD_BYTES:
            raise ValueError("governed WEB child progress record exceeds its limit")
        _write_all(self._progress_fd, encoded + b"\n")
        acknowledgement = _read_one_line(
            self._ack_fd,
            timeout_seconds=_ACK_TIMEOUT_SECONDS,
            max_bytes=_MAX_PROGRESS_RECORD_BYTES,
        )
        decoded = parse_strict_json_bytes(
            acknowledgement,
            label="governed WEB process ACK",
            max_bytes=_MAX_PROGRESS_RECORD_BYTES,
            max_depth=4,
            max_nodes=16,
        )
        expected = {
            "apiVersion": _ACK_API_VERSION,
            "kind": _ACK_KIND,
            "sequence": self._sequence,
            "recordDigest": record_digest,
            "parentRootDigest": material["parentRootDigest"],
        }
        if (
            type(decoded) is not dict
            or frozenset(decoded) != _ACK_FIELDS
            or decoded != expected
            or acknowledgement != _canonical_json(expected)
        ):
            raise ValueError("governed WEB process ACK differs from progress")
        self._previous_record_digest = record_digest
        self._previous_parent_root_digest = cast(str, material["parentRootDigest"])


def _coordinator_environment() -> dict[str, str]:
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in WEB_WORKER_OS_ENV_ALLOWLIST
    }
    text_encoding = _current_macos_user_text_encoding()
    if text_encoding is not None:
        environment["__CF_USER_TEXT_ENCODING"] = text_encoding
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["PYTHONNOUSERSITE"] = "1"
    environment["PYTHONSAFEPATH"] = "1"
    environment[_COORDINATOR_MARKER] = "1"
    environment.pop(_WORKER_MARKER, None)
    return environment


def _child_command(
    *,
    python_entrypoint: str,
    workspace_fd: int,
    progress_fd: int,
    ack_fd: int,
    identity: PinnedWorkspaceIdentity,
    headless: bool,
) -> tuple[str, ...]:
    return (
        python_entrypoint,
        "-m",
        "pajin.web_assessment.governed_process",
        "--child",
        str(workspace_fd),
        str(progress_fd),
        str(ack_fd),
        str(identity.device),
        str(identity.inode),
        str(identity.uid),
        str(identity.mode),
        GOVERNED_WEB_ORIGIN,
        GOVERNED_WEB_ADAPTER_REF,
        "1" if headless else "0",
    )


def _process_group_exists(process_group_id: int) -> bool:
    try:
        os.killpg(process_group_id, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if os.name != "posix":
        if process.poll() is None:
            process.kill()
        process.wait(timeout=_TERMINATION_GRACE_SECONDS)
        return
    for sent_signal in (signal.SIGTERM, signal.SIGKILL):
        with suppress(ProcessLookupError):
            os.killpg(process.pid, sent_signal)
        deadline = time.monotonic() + _TERMINATION_GRACE_SECONDS
        while _process_group_exists(process.pid) and time.monotonic() < deadline:
            time.sleep(0.02)
        if not _process_group_exists(process.pid):
            break
    if process.poll() is None:
        try:
            process.wait(timeout=_TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=_TERMINATION_GRACE_SECONDS)


def _append_bounded(target: bytearray, chunk: bytes) -> bool:
    remaining = max(0, _MAX_CAPTURE_BYTES - len(target))
    target.extend(chunk[:remaining])
    return len(chunk) > remaining


class _ParentProcessMonitor:
    """Bounded selector state for one already-started coordinator child."""

    def __init__(
        self,
        *,
        process: subprocess.Popen[bytes],
        pinned: PinnedOutputRoot,
        progress_read: int,
        ack_write: int,
        cancellation: threading.Event,
        progress_state: _SupervisorProgressState,
    ) -> None:
        assert process.stdout is not None
        assert process.stderr is not None
        self.process = process
        self.pinned = pinned
        self.progress_read = progress_read
        self.ack_write = ack_write
        self.cancellation = cancellation
        self.progress_state = progress_state
        self.selector = selectors.DefaultSelector()
        self.progress_buffer = bytearray()
        self.progress_bytes = 0
        self.records: list[_ProgressRecord] = []
        self.stdout = bytearray()
        self.stderr = bytearray()
        self.capture_overflow = False
        self.deadline = time.monotonic() + _PROCESS_TIMEOUT_SECONDS
        stdout_fd = process.stdout.fileno()
        stderr_fd = process.stderr.fileno()
        for descriptor, label in (
            (progress_read, "progress"),
            (stdout_fd, "stdout"),
            (stderr_fd, "stderr"),
        ):
            os.set_blocking(descriptor, False)
            self.selector.register(descriptor, selectors.EVENT_READ, label)

    def close(self) -> None:
        self.selector.close()

    def run(self) -> list[_ProgressRecord]:
        while self.selector.get_map():
            if self.cancellation.is_set():
                raise asyncio.CancelledError
            if time.monotonic() >= self.deadline:
                raise TimeoutError("governed WEB coordinator process timed out")
            for key, _mask in self.selector.select(_POLL_SECONDS):
                self._consume_ready(key)
            self.process.poll()
        if self.progress_buffer:
            raise GovernedWebCampaignProcessError(
                "governed WEB progress stream ended with a partial record"
            )
        return self.records

    def _consume_ready(self, key: selectors.SelectorKey) -> None:
        try:
            chunk = os.read(key.fd, 64 * 1024)
        except BlockingIOError:
            return
        if not chunk:
            self.selector.unregister(key.fd)
            return
        if key.data == "stdout":
            self.capture_overflow = _append_bounded(self.stdout, chunk) or self.capture_overflow
        elif key.data == "stderr":
            self.capture_overflow = _append_bounded(self.stderr, chunk) or self.capture_overflow
        else:
            self._consume_progress(chunk)
        if self.capture_overflow:
            raise GovernedWebCampaignProcessError(
                "governed WEB child exceeded its stdout or stderr limit"
            )

    def _consume_progress(self, chunk: bytes) -> None:
        self.progress_bytes += len(chunk)
        if self.progress_bytes > _MAX_PROGRESS_BYTES:
            raise GovernedWebCampaignProcessError(
                "governed WEB progress stream exceeds its total limit"
            )
        self.progress_buffer.extend(chunk)
        while True:
            newline = self.progress_buffer.find(b"\n")
            if newline < 0:
                break
            line = bytes(self.progress_buffer[:newline])
            del self.progress_buffer[: newline + 1]
            record = _parse_progress_record(line)
            if not self.records:
                try:
                    process_group_id = os.getpgid(self.process.pid)
                    session_id = os.getsid(self.process.pid)
                except ProcessLookupError as exc:
                    raise GovernedWebCampaignProcessError(
                        "governed WEB child exited before its first ACK"
                    ) from exc
                if process_group_id != self.process.pid or session_id != self.process.pid:
                    raise GovernedWebCampaignProcessError(
                        "governed WEB child lacks its dedicated process group"
                    )
            _verified_progress(self.pinned, self.records, record)
            next_records = [*self.records, record]
            incomplete_receipt = _candidate_incomplete_receipt(
                self.pinned,
                next_records,
            )
            self.progress_state.require_next_verified_ack(
                sequence=record.sequence,
                incomplete_receipt=incomplete_receipt,
            )
            _write_all(self.ack_write, _ack_bytes(record))
            self.records = next_records
            self.progress_state.commit_verified_ack(
                sequence=record.sequence,
                incomplete_receipt=incomplete_receipt,
            )
        if len(self.progress_buffer) > _MAX_PROGRESS_RECORD_BYTES:
            raise GovernedWebCampaignProcessError("governed WEB progress record is unterminated")

    def require_clean_exit(self) -> None:
        exit_code = self.process.wait(timeout=_TERMINATION_GRACE_SECONDS)
        if self.capture_overflow:
            raise GovernedWebCampaignProcessError(
                "governed WEB child exceeded its stdout or stderr limit"
            )
        if self.stdout or self.stderr:
            raise GovernedWebCampaignProcessError(
                "governed WEB child emitted unexpected stdout or stderr"
            )
        if exit_code != 0:
            raise GovernedWebCampaignProcessError(
                "governed WEB child exited before verified completion"
            )
        if _process_group_exists(self.process.pid):
            raise GovernedWebCampaignProcessError(
                "governed WEB child left a process-group descendant"
            )


def _parent_run_path(output_root: Path, parent_run_id: str) -> Path:
    return output_root / "campaign-runs" / GOVERNED_WEB_CAMPAIGN_ID / parent_run_id


def _incomplete_receipt(
    pinned: PinnedOutputRoot,
    records: list[_ProgressRecord],
) -> GovernedWebCampaignIncompleteReceipt | None:
    if not records:
        return None
    initial = records[0]
    latest = records[-1]
    return GovernedWebCampaignIncompleteReceipt(
        output_root=pinned.path,
        parent_run_path=_parent_run_path(pinned.path, latest.parent_run_id),
        parent_run_id=latest.parent_run_id,
        initial_parent_root_digest=initial.parent_root_digest,
        parent_root_digest=latest.parent_root_digest,
        campaign_plan_digest=latest.campaign_plan_digest,
        deployment_trust_anchor_digest=latest.deployment_trust_anchor_digest,
        last_verified_sequence=latest.sequence,
        last_record_digest=latest.record_digest,
        last_stage=latest.stage,
        last_status=latest.status,
        terminal_progress_observed=latest.terminal,
    )


def _candidate_incomplete_receipt(
    pinned: PinnedOutputRoot,
    records: list[_ProgressRecord],
) -> GovernedWebCampaignIncompleteReceipt | None:
    record = records[-1]
    if record.stage == "parent-evidence" and record.status == "completed" and record.terminal:
        return None
    receipt = _incomplete_receipt(pinned, records)
    if receipt is None:
        raise GovernedWebCampaignProcessError(
            "governed WEB verified progress receipt is unavailable"
        )
    return receipt


def _verified_progress(
    pinned: PinnedOutputRoot,
    records: list[_ProgressRecord],
    record: _ProgressRecord,
) -> VerifiedGovernedWebCompletedCampaign | VerifiedGovernedWebIncompleteCampaign:
    _validate_progress_chain(records, record)
    pinned.require_original_path_identity()
    path = _parent_run_path(pinned.path, record.parent_run_id)
    try:
        loaded = load_verified_governed_web_campaign_terminal(
            path,
            expected_parent_run_id=record.parent_run_id,
            expected_parent_root_digest=record.parent_root_digest,
            expected_campaign_plan_digest=record.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=(record.deployment_trust_anchor_digest),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignProcessError(
            "governed WEB progress failed strict parent reload"
        ) from exc
    _validate_loaded_progress(loaded, record)
    if record.status == "database-checkpoint":
        _validate_database_checkpoint(pinned.path, loaded, record)
    pinned.require_original_path_identity()
    return loaded


def _validate_database_checkpoint(
    output_root: Path,
    loaded: VerifiedGovernedWebCompletedCampaign | VerifiedGovernedWebIncompleteCampaign,
    record: _ProgressRecord,
) -> None:
    if not loaded.events or record.database_store_kind is None:
        raise GovernedWebCampaignProcessError(
            "governed WEB database checkpoint lacks its parent event"
        )
    payload = loaded.events[-1].payload
    manifest_reference = payload.get("manifestReference")
    if type(manifest_reference) is not str:
        raise GovernedWebCampaignProcessError(
            "governed WEB database checkpoint manifest reference is invalid"
        )
    if record.database_store_kind == "governed-web-graph":
        final_reference = "authority/governed-web.sqlite3"
        schema_digest = _GRAPH_SCHEMA_DIGEST
        max_bytes = _MAX_GRAPH_BYTES
    else:
        final_reference = "authority/capability-grant-consumptions.sqlite3"
        schema_digest = _WEB_GRANT_CONSUMPTION_SCHEMA_DIGEST
        max_bytes = _WEB_GRANT_CONSUMPTION_MAX_BYTES
    assert record.database_manifest_digest is not None
    assert record.database_checkpoint_ordinal is not None
    assert record.database_sha256 is not None
    try:
        verified = load_verified_pinned_sqlite_checkpoint_chain(
            output_root,
            final_database_reference=final_reference,
            expected_store_kind=record.database_store_kind,
            expected_campaign_id=GOVERNED_WEB_CAMPAIGN_ID,
            expected_schema_digest=schema_digest,
            expected_latest_manifest_reference=manifest_reference,
            expected_latest_manifest_digest=record.database_manifest_digest,
            expected_latest_ordinal=record.database_checkpoint_ordinal,
            expected_latest_database_sha256=record.database_sha256,
            max_database_bytes=max_bytes,
        )
    except (OSError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignProcessError(
            "governed WEB database checkpoint failed strict reload"
        ) from exc
    checkpoint = verified.latest_checkpoint
    if (
        checkpoint.manifest_digest != record.database_manifest_digest
        or checkpoint.database_sha256 != record.database_sha256
        or checkpoint.ordinal != record.database_checkpoint_ordinal
        or checkpoint.state_digest != payload.get("stateDigest")
    ):
        raise GovernedWebCampaignProcessError("governed WEB database checkpoint proof differs")


def _receipt(
    *,
    pinned: PinnedOutputRoot,
    records: list[_ProgressRecord],
) -> GovernedWebCampaignProcessReceipt:
    if not records or not records[-1].terminal:
        raise GovernedWebCampaignProcessError("governed WEB process lacks terminal progress")
    first = records[0]
    final = records[-1]
    parent_path = _parent_run_path(pinned.path, final.parent_run_id)
    pinned.require_original_path_identity()
    try:
        verified = load_verified_governed_web_completed_campaign_evidence(
            parent_path,
            expected_parent_run_id=final.parent_run_id,
            expected_parent_root_digest=final.parent_root_digest,
            expected_campaign_plan_digest=final.campaign_plan_digest,
            expected_deployment_trust_anchor_digest=(final.deployment_trust_anchor_digest),
        )
    except (OSError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignProcessError(
            "governed WEB process did not produce strict completed evidence"
        ) from exc
    pinned.require_original_path_identity()
    result = verified.result.model_copy(deep=True)
    output = pinned.path
    return GovernedWebCampaignProcessReceipt(
        output_root=output,
        parent_run_path=parent_path,
        parent_run_id=final.parent_run_id,
        initial_parent_root_digest=first.parent_root_digest,
        parent_root_digest=final.parent_root_digest,
        campaign_plan_digest=final.campaign_plan_digest,
        deployment_trust_anchor_digest=final.deployment_trust_anchor_digest,
        result=result,
    )


def _run_parent_process(
    *,
    output_root: Path,
    headless: bool,
    cancellation: threading.Event,
    progress_state: _SupervisorProgressState | None = None,
) -> GovernedWebCampaignProcessReceipt:
    if os.name != "posix":
        raise GovernedWebCampaignProcessError(
            "governed WEB process coordination requires POSIX process groups"
        )
    process: subprocess.Popen[bytes] | None = None
    progress_read = progress_write = ack_read = ack_write = -1
    monitor: _ParentProcessMonitor | None = None
    normal_completion = False
    retained_state = progress_state or _SupervisorProgressState()
    try:
        with PinnedOutputRoot.create(output_root) as pinned:
            python_runtime = _current_python_runtime_identity()
            progress_read, progress_write = os.pipe()
            ack_read, ack_write = os.pipe()
            command = _child_command(
                python_entrypoint=python_runtime.entrypoint,
                workspace_fd=pinned.fd,
                progress_fd=progress_write,
                ack_fd=ack_read,
                identity=pinned.identity,
                headless=headless,
            )
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_coordinator_environment(),
                close_fds=True,
                pass_fds=(pinned.fd, progress_write, ack_read),
                start_new_session=True,
            )
            os.close(progress_write)
            progress_write = -1
            os.close(ack_read)
            ack_read = -1
            monitor = _ParentProcessMonitor(
                process=process,
                pinned=pinned,
                progress_read=progress_read,
                ack_write=ack_write,
                cancellation=cancellation,
                progress_state=retained_state,
            )
            records = monitor.run()
            monitor.require_clean_exit()
            receipt = _receipt(pinned=pinned, records=records)
            if _current_python_runtime_identity() != python_runtime:
                raise GovernedWebCampaignProcessError(
                    "governed WEB Python runtime changed during execution"
                )
            normal_completion = True
            return receipt
    except asyncio.CancelledError:
        raise
    except GovernedWebCampaignProcessError as exc:
        if exc.incomplete_receipt is not None:
            raise
        raise GovernedWebCampaignProcessError(
            str(exc),
            incomplete_receipt=retained_state.incomplete_receipt,
        ) from exc
    except (OSError, subprocess.SubprocessError, TimeoutError, TypeError, ValueError) as exc:
        raise GovernedWebCampaignProcessError(
            "governed WEB isolated coordinator failed closed",
            incomplete_receipt=retained_state.incomplete_receipt,
        ) from exc
    finally:
        if monitor is not None:
            monitor.close()
        for descriptor in (progress_read, progress_write, ack_read, ack_write):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)
        if process is not None and not normal_completion:
            _terminate_process_group(process)


async def _run_governed_local_web_campaign_process(
    *,
    origin: str,
    output_root: Path,
    authorized_local_lab: bool,
    selected_adapter_ref: Literal["juice-shop-local/v1"],
    headless: bool,
) -> GovernedWebCampaignProcessReceipt:
    """Run the exact campaign in one supervised, killable child process."""

    if type(authorized_local_lab) is not bool or authorized_local_lab is not True:
        raise GovernedWebCampaignProcessError(
            "governed WEB process requires explicit local-lab authorization"
        )
    if type(origin) is not str or origin != GOVERNED_WEB_ORIGIN:
        raise GovernedWebCampaignProcessError("governed WEB process origin is not exact")
    if type(selected_adapter_ref) is not str or selected_adapter_ref != GOVERNED_WEB_ADAPTER_REF:
        raise GovernedWebCampaignProcessError("governed WEB process adapter is not installed")
    if type(output_root) is not type(Path()):
        raise TypeError("governed WEB process output_root must be a Path")
    if type(headless) is not bool:
        raise TypeError("governed WEB process headless must be a literal boolean")
    cancellation = threading.Event()
    progress_state = _SupervisorProgressState()
    task = asyncio.create_task(
        asyncio.to_thread(
            _run_parent_process,
            output_root=output_root,
            headless=headless,
            cancellation=cancellation,
            progress_state=progress_state,
        )
    )
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError as exc:
        cancellation.set()
        with suppress(BaseException, asyncio.CancelledError):
            await asyncio.shield(task)
        raise GovernedWebCampaignProcessCancelled(
            incomplete_receipt=progress_state.incomplete_receipt,
        ) from exc


def _canonical_nonnegative_integer(value: str, *, label: str, positive: bool) -> int:
    if not value or not value.isascii() or not value.isdecimal():
        raise ValueError(f"{label} is invalid")
    parsed = int(value)
    if value != str(parsed) or parsed < (1 if positive else 0):
        raise ValueError(f"{label} is not canonical")
    return parsed


def _require_child_pipe(descriptor: int, *, writable: bool, label: str) -> None:
    if os.name != "posix":
        raise ValueError(f"{label} requires POSIX")
    import fcntl

    status = os.fstat(descriptor)
    access_mode = fcntl.fcntl(descriptor, fcntl.F_GETFL) & os.O_ACCMODE
    expected_mode = os.O_WRONLY if writable else os.O_RDONLY
    if not stat.S_ISFIFO(status.st_mode) or access_mode != expected_mode:
        raise ValueError(f"{label} is not the expected pipe end")
    os.set_inheritable(descriptor, False)


def _child_main_exact(arguments: list[str]) -> int:
    if len(arguments) != 11 or arguments[0] != "--child":
        return 64
    workspace_fd = progress_fd = ack_fd = -1
    try:
        workspace_fd = _canonical_nonnegative_integer(
            arguments[1], label="workspace fd", positive=True
        )
        progress_fd = _canonical_nonnegative_integer(
            arguments[2], label="progress fd", positive=True
        )
        ack_fd = _canonical_nonnegative_integer(arguments[3], label="ACK fd", positive=True)
        if len({workspace_fd, progress_fd, ack_fd}) != 3:
            raise ValueError("governed WEB process descriptors must be distinct")
        identity = PinnedWorkspaceIdentity(
            device=_canonical_nonnegative_integer(
                arguments[4], label="workspace device", positive=False
            ),
            inode=_canonical_nonnegative_integer(
                arguments[5], label="workspace inode", positive=True
            ),
            uid=_canonical_nonnegative_integer(arguments[6], label="workspace uid", positive=False),
            mode=_canonical_nonnegative_integer(
                arguments[7], label="workspace mode", positive=True
            ),
        )
        origin = arguments[8]
        adapter_ref = arguments[9]
        if arguments[10] not in {"0", "1"}:
            raise ValueError("governed WEB process headless flag is invalid")
        headless = arguments[10] == "1"
        if (
            os.environ.get(_COORDINATOR_MARKER) != "1"
            or origin != GOVERNED_WEB_ORIGIN
            or adapter_ref != GOVERNED_WEB_ADAPTER_REF
            or PinnedWorkspaceIdentity.from_stat(os.fstat(workspace_fd)) != identity
        ):
            raise ValueError("governed WEB child authority is not exact")
        _require_child_pipe(progress_fd, writable=True, label="progress fd")
        _require_child_pipe(ack_fd, writable=False, label="ACK fd")
        os.set_inheritable(workspace_fd, False)
        os.fchdir(workspace_fd)
        with activate_inherited_pinned_workspace(identity):
            authority = _create_governed_coordinator_worker_group_authority()
            sink = _ChildProgressSink(progress_fd=progress_fd, ack_fd=ack_fd)
            from pajin.web_assessment import governed

            with (
                _activate_governed_coordinator_worker_group(authority),
                governed._activate_governed_web_campaign_progress_sink(sink),
            ):
                asyncio.run(
                    governed._run_governed_local_web_campaign_in_pinned_workspace(
                        origin=origin,
                        selected_adapter_ref=cast(Literal["juice-shop-local/v1"], adapter_ref),
                        headless=headless,
                    )
                )
        return 0
    except BaseException:
        return 1
    finally:
        for descriptor in (progress_fd, ack_fd, workspace_fd):
            if descriptor >= 0:
                with suppress(OSError):
                    os.close(descriptor)


def main() -> int:
    """Process-only entrypoint; direct malformed calls remain silent and inert."""

    return _child_main_exact(sys.argv[1:])


if __name__ == "__main__":  # pragma: no cover - exercised by the real subprocess boundary
    raise SystemExit(main())


__all__ = [
    "GovernedWebCampaignIncompleteReceipt",
    "GovernedWebCampaignProcessCancelled",
    "GovernedWebCampaignProcessError",
    "GovernedWebCampaignProcessReceipt",
]
