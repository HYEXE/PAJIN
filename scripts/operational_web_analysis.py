"""Run one local-only WEB-007 analysis turn over sealed discovery evidence."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import secrets
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Final

from pydantic import ValidationError

from pajin.benchmark.effectiveness.docker import (
    LocalModelRuntime,
    verify_images,
    verify_model,
)
from pajin.benchmark.effectiveness.evidence import Lifecycle
from pajin.benchmark.effectiveness.suite import ModelPin
from pajin.benchmark.effectiveness_structured.plan import ComparisonPlan
from pajin.runtime.store import (
    RunIntegrityError,
    VerifiedRunSnapshot,
    load_verified_run_artifacts,
    load_verified_run_snapshot,
)
from pajin.runtime.verified_snapshot import require_same_authority, strict_json
from pajin.web_assessment.analysis_local import (
    LocalWebAnalysisProviderAssembly,
    LocalWebAnalysisProviderCleanup,
    build_local_web_analysis_provider_runtime,
)
from pajin.web_assessment.analysis_proposal import (
    WebAnalysisSnapshot,
    build_web_analysis_snapshot,
)
from pajin.web_assessment.analysis_runtime import (
    VerifiedWebAnalysisFailureRun,
    VerifiedWebAnalysisInvocationRun,
    WebAnalysisCancelledError,
    WebAnalysisInvocationError,
    WebAnalysisInvocationPublication,
    WebAnalysisInvocationRuntime,
    WebAnalysisProviderRunPublication,
    load_verified_web_analysis_failure,
    load_verified_web_analysis_invocation,
)
from pajin.web_assessment.discovery_artifact import (
    VerifiedAuthenticatedDiscoveryRun,
    load_verified_authenticated_discovery,
)

_MAX_COMPARISON_PLAN_BYTES: Final[int] = 4 * 1024 * 1024
_MAX_COMPARISON_MANIFEST_BYTES: Final[int] = 4 * 1024 * 1024
_QWEN_MODEL_NAME: Final[str] = "qwen3-4b"
_SUMMARY_API_VERSION: Final[str] = "pajin.dev/operational-web-analysis-conformance/v1alpha1"
_COMPARISON_PLAN_CAMPAIGN: Final[str] = "effect-001-plan"
_COMPARISON_PLAN_PATH: Final[str] = "plan.json"
_COMPARISON_MANIFEST_PATH: Final[str] = "public-manifest.json"
_COMPARISON_EVENT: Final[str] = "comparison.preregistered"
_COMPARISON_ARTIFACT_LIMITS: Final[dict[str, int]] = {
    _COMPARISON_PLAN_PATH: _MAX_COMPARISON_PLAN_BYTES,
    _COMPARISON_MANIFEST_PATH: _MAX_COMPARISON_MANIFEST_BYTES,
}
_RUN_ID_PATTERN: Final[re.Pattern[str]] = re.compile(r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
_SHA256_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[a-f0-9]{64}$")


class OperationalWebAnalysisError(ValueError):
    """Raised when the local WEB-007 conformance boundary fails closed."""


@dataclass(frozen=True, slots=True)
class OperationalWebAnalysisResult:
    """Secret-free terminal summary plus its process-success classification."""

    summary: dict[str, object]
    succeeded: bool


@dataclass(frozen=True, slots=True)
class OperationalWebAnalysisInputs:
    """Caller-supplied paths and independent evidence anchors."""

    source_run_path: Path
    source_run_id: str
    source_root_digest: str
    comparison_plan_run_path: Path
    comparison_plan_run_id: str
    comparison_plan_root_digest: str
    qwen_model_path: Path
    provider_output_root: Path
    analysis_output_root: Path


@dataclass(frozen=True, slots=True)
class VerifiedOperationalWebAnalysisInputs:
    """Strictly reloaded immutable inputs before any local model resource starts."""

    source: VerifiedAuthenticatedDiscoveryRun
    plan: ComparisonPlan
    comparison_plan_run_id: str
    comparison_plan_root_digest: str
    model: ModelPin
    model_path: Path
    provider_output_root: Path
    analysis_output_root: Path


@dataclass(frozen=True, slots=True)
class _TerminalEvidence:
    status: str
    semantics: str
    analysis_run_id: str
    analysis_root_digest: str
    provider_run_id: str
    provider_root_digest: str
    provider_execution_context_digest: str
    terminal_state: str
    failure_class: str | None


@dataclass(frozen=True, slots=True)
class _ReservedOutputRoot:
    path: Path
    device: int
    inode: int


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-run-path", required=True, type=Path)
    parser.add_argument("--source-run-id", required=True)
    parser.add_argument("--source-root-digest", required=True)
    parser.add_argument("--comparison-plan-run-path", required=True, type=Path)
    parser.add_argument("--comparison-plan-run-id", required=True)
    parser.add_argument("--comparison-plan-root-digest", required=True)
    parser.add_argument("--qwen-model-path", required=True, type=Path)
    parser.add_argument("--provider-output-root", required=True, type=Path)
    parser.add_argument("--analysis-output-root", required=True, type=Path)
    return parser


def _arguments(argv: Sequence[str] | None = None) -> OperationalWebAnalysisInputs:
    args = _parser().parse_args(argv)
    return OperationalWebAnalysisInputs(
        source_run_path=args.source_run_path,
        source_run_id=args.source_run_id,
        source_root_digest=args.source_root_digest,
        comparison_plan_run_path=args.comparison_plan_run_path,
        comparison_plan_run_id=args.comparison_plan_run_id,
        comparison_plan_root_digest=args.comparison_plan_root_digest,
        qwen_model_path=args.qwen_model_path,
        provider_output_root=args.provider_output_root,
        analysis_output_root=args.analysis_output_root,
    )


def _verify_inputs(
    values: OperationalWebAnalysisInputs,
) -> VerifiedOperationalWebAnalysisInputs:
    try:
        provider_root = _fresh_output_root(
            values.provider_output_root,
            label="Provider output root",
        )
        analysis_root = _fresh_output_root(
            values.analysis_output_root,
            label="analysis output root",
        )
        _require_disjoint_roots(provider_root, analysis_root)
        source = load_verified_authenticated_discovery(
            values.source_run_path,
            expected_run_id=values.source_run_id,
            expected_root_digest=values.source_root_digest,
        )
        plan = _load_verified_comparison_plan_run(
            values.comparison_plan_run_path,
            expected_run_id=values.comparison_plan_run_id,
            expected_root_digest=values.comparison_plan_root_digest,
        )
        _require_outputs_outside_inputs(
            provider_root,
            analysis_root,
            source_run_path=source.run_path,
            comparison_plan_run_path=values.comparison_plan_run_path,
            model_path=values.qwen_model_path,
        )
        verify_images(plan.runtime)
        model = _qwen_model_pin(plan)
        model_path = verify_model(values.qwen_model_path, model)
        return VerifiedOperationalWebAnalysisInputs(
            source=source,
            plan=plan,
            comparison_plan_run_id=values.comparison_plan_run_id,
            comparison_plan_root_digest=values.comparison_plan_root_digest,
            model=model,
            model_path=model_path,
            provider_output_root=provider_root,
            analysis_output_root=analysis_root,
        )
    except OperationalWebAnalysisError:
        raise
    except Exception as exc:
        raise OperationalWebAnalysisError(
            "WEB-007 operational inputs failed strict verification"
        ) from exc


def _load_verified_comparison_plan_run(
    run_path: Path,
    *,
    expected_run_id: str,
    expected_root_digest: str,
) -> ComparisonPlan:
    """Load one frozen EFFECT plan from an independently anchored sealed Run."""

    if not isinstance(run_path, Path):
        raise OperationalWebAnalysisError(
            "EFFECT-007 ComparisonPlan Run path must be an exact Path"
        )
    if _RUN_ID_PATTERN.fullmatch(expected_run_id) is None:
        raise OperationalWebAnalysisError("expected EFFECT-007 ComparisonPlan Run ID is invalid")
    if _SHA256_PATTERN.fullmatch(expected_root_digest) is None:
        raise OperationalWebAnalysisError(
            "expected EFFECT-007 ComparisonPlan root digest is invalid"
        )
    candidate = Path(os.path.abspath(run_path))
    if any(part.is_symlink() for part in (candidate, *candidate.parents)):
        raise OperationalWebAnalysisError(
            "EFFECT-007 ComparisonPlan Run path cannot traverse symbolic links"
        )
    try:
        initial = load_verified_run_snapshot(
            candidate,
            expected_run_id=expected_run_id,
        )
        _require_comparison_plan_run_shape(
            initial,
            expected_root_digest=expected_root_digest,
        )
        loaded = load_verified_run_artifacts(
            initial.run_path,
            requests=_COMPARISON_ARTIFACT_LIMITS,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            loaded,
            message="sealed EFFECT-007 ComparisonPlan changed while artifacts were loaded",
        )
        raw_plan = strict_json(
            loaded,
            _COMPARISON_PLAN_PATH,
            label="EFFECT-007 ComparisonPlan",
            max_bytes=_MAX_COMPARISON_PLAN_BYTES,
            expected_type=dict,
        )
        plan = ComparisonPlan.model_validate_json(loaded.artifact_bytes(_COMPARISON_PLAN_PATH))
        if raw_plan != plan.model_dump(mode="json"):
            raise OperationalWebAnalysisError(
                "EFFECT-007 ComparisonPlan is not the exact canonical artifact"
            )
        public_manifest = strict_json(
            loaded,
            _COMPARISON_MANIFEST_PATH,
            label="EFFECT-007 public manifest",
            max_bytes=_MAX_COMPARISON_MANIFEST_BYTES,
            expected_type=dict,
        )
        if public_manifest != plan.public_manifest():
            raise OperationalWebAnalysisError(
                "EFFECT-007 public manifest differs from its sealed ComparisonPlan"
            )
        if loaded.events[0].payload != {"commitment": plan.commitment}:
            raise OperationalWebAnalysisError(
                "EFFECT-007 preregistration commitment differs from its sealed ComparisonPlan"
            )
        final = load_verified_run_snapshot(
            initial.run_path,
            expected_run_id=expected_run_id,
        )
        require_same_authority(
            initial,
            final,
            message="sealed EFFECT-007 ComparisonPlan changed during strict reload",
        )
        return plan
    except OperationalWebAnalysisError:
        raise
    except (OSError, RunIntegrityError, UnicodeError, ValidationError, ValueError) as exc:
        raise OperationalWebAnalysisError(
            "sealed EFFECT-007 ComparisonPlan failed strict verification"
        ) from exc


def _require_comparison_plan_run_shape(
    snapshot: VerifiedRunSnapshot,
    *,
    expected_root_digest: str,
) -> None:
    verification = snapshot.verification
    if snapshot.run_path.parent.name != _COMPARISON_PLAN_CAMPAIGN:
        raise OperationalWebAnalysisError("sealed EFFECT-007 ComparisonPlan campaign path differs")
    if (
        verification.root_digest != expected_root_digest
        or verification.seal_count != 1
        or len(snapshot.seals) != 1
        or verification.event_count != 1
        or len(snapshot.events) != 1
        or snapshot.events[0].event_type != _COMPARISON_EVENT
    ):
        raise OperationalWebAnalysisError("sealed EFFECT-007 ComparisonPlan Run shape differs")
    records = {artifact.path: artifact for artifact in snapshot.seals[0].artifacts}
    if set(records) != set(_COMPARISON_ARTIFACT_LIMITS) or verification.artifact_count != len(
        _COMPARISON_ARTIFACT_LIMITS
    ):
        raise OperationalWebAnalysisError(
            "sealed EFFECT-007 ComparisonPlan artifact inventory differs"
        )
    for path, record in records.items():
        if (
            record.media_type != "application/json"
            or record.size_bytes < 1
            or record.size_bytes > _COMPARISON_ARTIFACT_LIMITS[path]
        ):
            raise OperationalWebAnalysisError(
                f"sealed EFFECT-007 ComparisonPlan artifact boundary differs: {path}"
            )


def _qwen_model_pin(plan: ComparisonPlan) -> ModelPin:
    matches = tuple(model for model in plan.models if model.name == _QWEN_MODEL_NAME)
    if len(matches) != 1:
        raise OperationalWebAnalysisError(
            "EFFECT-007 ComparisonPlan does not contain the exact Qwen model pin"
        )
    return matches[0]


def _fresh_output_root(path: Path, *, label: str) -> Path:
    if not isinstance(path, Path):
        raise OperationalWebAnalysisError(f"{label} must be an exact Path")
    candidate = Path(os.path.abspath(path))
    if candidate.exists() or candidate.is_symlink():
        raise OperationalWebAnalysisError(f"{label} must not already exist")
    parent = candidate.parent
    try:
        resolved_parent = parent.resolve(strict=True)
    except OSError as exc:
        raise OperationalWebAnalysisError(f"{label} parent must be an existing directory") from exc
    if resolved_parent != parent or not parent.is_dir():
        raise OperationalWebAnalysisError(f"{label} parent cannot traverse symbolic links")
    return candidate


def _require_disjoint_roots(provider_root: Path, analysis_root: Path) -> None:
    if (
        provider_root == analysis_root
        or provider_root in analysis_root.parents
        or analysis_root in provider_root.parents
    ):
        raise OperationalWebAnalysisError("Provider and analysis output roots must be disjoint")


def _reserve_fresh_output_roots(
    provider_root: Path,
    analysis_root: Path,
) -> tuple[_ReservedOutputRoot, _ReservedOutputRoot]:
    reserved: list[_ReservedOutputRoot] = []
    try:
        for path in (provider_root, analysis_root):
            path.mkdir(mode=0o700, exist_ok=False)
            created = path.lstat()
            item = _ReservedOutputRoot(
                path=path,
                device=created.st_dev,
                inode=created.st_ino,
            )
            reserved.append(item)
            descriptor = _open_directory(path)
            try:
                os.fchmod(descriptor, 0o700)
                observed = os.fstat(descriptor)
                current = path.lstat()
            finally:
                os.close(descriptor)
            if (
                observed.st_dev != item.device
                or observed.st_ino != item.inode
                or current.st_dev != item.device
                or current.st_ino != item.inode
                or not stat.S_ISDIR(observed.st_mode)
                or not stat.S_ISDIR(current.st_mode)
                or stat.S_IMODE(observed.st_mode) != 0o700
                or observed.st_nlink < 1
            ):
                raise OperationalWebAnalysisError("WEB-007 output root reservation differs")
    except Exception as exc:
        rollback_failed = False
        for item in reversed(reserved):
            try:
                current = item.path.lstat()
                if (
                    current.st_dev != item.device
                    or current.st_ino != item.inode
                    or not stat.S_ISDIR(current.st_mode)
                ):
                    rollback_failed = True
                    continue
                item.path.rmdir()
            except OSError:
                rollback_failed = True
        message = (
            "WEB-007 fresh output root reservation rollback failed"
            if rollback_failed
            else "WEB-007 fresh output roots could not be reserved"
        )
        raise OperationalWebAnalysisError(message) from exc
    return reserved[0], reserved[1]


def _require_reserved_output_roots(
    roots: tuple[_ReservedOutputRoot, _ReservedOutputRoot],
) -> None:
    for item in roots:
        try:
            descriptor = _open_directory(item.path)
            try:
                current = os.fstat(descriptor)
                empty = not os.listdir(descriptor)
                path_entry = item.path.lstat()
            finally:
                os.close(descriptor)
        except OSError as exc:
            raise OperationalWebAnalysisError(
                "WEB-007 reserved output root cannot be rechecked"
            ) from exc
        if (
            current.st_dev != item.device
            or current.st_ino != item.inode
            or path_entry.st_dev != item.device
            or path_entry.st_ino != item.inode
            or not stat.S_ISDIR(current.st_mode)
            or not stat.S_ISDIR(path_entry.st_mode)
            or stat.S_IMODE(current.st_mode) != 0o700
            or not empty
        ):
            raise OperationalWebAnalysisError(
                "WEB-007 reserved output root changed before runtime assembly"
            )


def _open_directory(path: Path) -> int:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    return os.open(path, flags)


def _require_outputs_outside_inputs(
    provider_root: Path,
    analysis_root: Path,
    *,
    source_run_path: Path,
    comparison_plan_run_path: Path,
    model_path: Path,
) -> None:
    inputs = (
        Path(os.path.abspath(source_run_path)),
        Path(os.path.abspath(comparison_plan_run_path)),
        Path(os.path.abspath(model_path)),
    )
    for output in (provider_root, analysis_root):
        if any(
            output == value or value in output.parents or output in value.parents
            for value in inputs
        ):
            raise OperationalWebAnalysisError(
                "WEB-007 output roots must be outside immutable inputs"
            )


async def run_operational_web_analysis(
    values: OperationalWebAnalysisInputs,
) -> OperationalWebAnalysisResult:
    """Perform one local-only WEB-007 invocation and strictly reload its terminal Run."""

    verified = _verify_inputs(values)
    model_runtime: LocalModelRuntime | None = None
    assembly: LocalWebAnalysisProviderAssembly | None = None
    cleanup: LocalWebAnalysisProviderCleanup | None = None
    terminal: _TerminalEvidence | None = None
    pending_error: BaseException | None = None
    with TemporaryDirectory(
        prefix="pajin-web-007-key-",
        dir=verified.provider_output_root.parent,
    ) as private_directory:
        private_root = Path(private_directory)
        private_root.chmod(0o700)
        key_path = private_root / "model-api-key"
        api_key = secrets.token_urlsafe(32)
        _write_private_key(key_path, api_key)
        model_runtime = LocalModelRuntime(
            runtime=verified.plan.runtime,
            model=verified.model,
            model_path=verified.model_path,
            key_file=key_path,
        )
        try:
            try:
                model_runtime.start()
                reserved_roots = _reserve_fresh_output_roots(
                    verified.provider_output_root,
                    verified.analysis_output_root,
                )
                _require_reserved_output_roots(reserved_roots)
                assembly = build_local_web_analysis_provider_runtime(
                    source=verified.source,
                    expected_run_id=values.source_run_id,
                    expected_root_digest=values.source_root_digest,
                    model_runtime=model_runtime,
                    api_key=api_key,
                    provider_store_root=verified.provider_output_root,
                    analysis_output_root=verified.analysis_output_root,
                )
                snapshot = build_web_analysis_snapshot(
                    verified.source,
                    expected_run_id=values.source_run_id,
                    expected_root_digest=values.source_root_digest,
                )
                invocation = WebAnalysisInvocationRuntime(
                    provider_runtime=assembly.provider_runtime
                )
                terminal = await _invoke_once_and_reload(
                    invocation=invocation,
                    assembly=assembly,
                    verified=verified,
                    source_run_id=values.source_run_id,
                    source_root_digest=values.source_root_digest,
                    snapshot=snapshot,
                )
            except BaseException as exc:
                pending_error = exc
        finally:
            try:
                cleanup = _cleanup_owned_runtime(
                    model_runtime=model_runtime,
                    assembly=assembly,
                )
            except Exception as exc:
                if pending_error is not None:
                    if isinstance(pending_error, WebAnalysisCancelledError):
                        pending_error.__dict__["_operational_cleanup_verified"] = False
                    pending_error.add_note(
                        f"WEB-007 owned cleanup also failed: {type(exc).__name__}"
                    )
                    raise pending_error from exc
                raise

    try:
        if cleanup is None:
            raise OperationalWebAnalysisError("WEB-007 cleanup evidence is unavailable")
        expected_execution_ids = assembly.execution_ids if assembly is not None else ()
        _require_clean_cleanup(
            cleanup,
            expected_execution_ids=expected_execution_ids,
        )
        if isinstance(pending_error, WebAnalysisCancelledError):
            pending_error.__dict__["_operational_cleanup_verified"] = True
    except Exception as exc:
        if pending_error is not None:
            if isinstance(pending_error, WebAnalysisCancelledError):
                pending_error.__dict__["_operational_cleanup_verified"] = False
            pending_error.add_note(
                f"WEB-007 owned cleanup verification also failed: {type(exc).__name__}"
            )
            raise pending_error from exc
        raise

    if pending_error is not None:
        raise pending_error

    if terminal is None or assembly is None:
        raise OperationalWebAnalysisError(
            "WEB-007 did not produce strictly reloaded terminal evidence"
        )
    summary = _secret_free_summary(
        verified=verified,
        terminal=terminal,
        cleanup=cleanup,
    )
    return OperationalWebAnalysisResult(
        summary=summary,
        succeeded=terminal.status == "proposal-compiled",
    )


async def _invoke_once_and_reload(
    *,
    invocation: WebAnalysisInvocationRuntime,
    assembly: LocalWebAnalysisProviderAssembly,
    verified: VerifiedOperationalWebAnalysisInputs,
    source_run_id: str,
    source_root_digest: str,
    snapshot: WebAnalysisSnapshot,
) -> _TerminalEvidence:
    try:
        completion = await invocation.invoke(
            source=verified.source,
            snapshot=snapshot,
            expected_source_run_id=source_run_id,
            expected_source_root_digest=source_root_digest,
        )
    except WebAnalysisCancelledError as exc:
        try:
            _reload_failure(
                publication=exc.publication,
                provider_publication=exc.provider_publication,
                assembly=assembly,
                verified=verified,
                source_run_id=source_run_id,
                source_root_digest=source_root_digest,
            )
            exc.__dict__["_operational_terminal_reloaded"] = True
        except Exception as verification_error:
            exc.__dict__["_operational_terminal_reloaded"] = False
            exc.add_note(
                "WEB-007 cancelled failure Run reload also failed: "
                f"{type(verification_error).__name__}"
            )
            raise exc from verification_error
        raise
    except WebAnalysisInvocationError as exc:
        if exc.publication is None or exc.provider_publication is None:
            raise OperationalWebAnalysisError(
                "WEB-007 invocation failed before a strict terminal Run was published"
            ) from exc
        failed = _reload_failure(
            publication=exc.publication,
            provider_publication=exc.provider_publication,
            assembly=assembly,
            verified=verified,
            source_run_id=source_run_id,
            source_root_digest=source_root_digest,
        )
        return _failed_terminal(failed)

    loaded = load_verified_web_analysis_invocation(
        completion.publication.run_path,
        expected_run_id=completion.publication.run_id,
        expected_root_digest=completion.publication.root_digest,
        source=verified.source,
        expected_source_run_id=source_run_id,
        expected_source_root_digest=source_root_digest,
        registration=assembly.provider_runtime.registration,
        provider_run_path=completion.provider_publication.run_path,
        expected_provider_run_id=completion.provider_publication.run_id,
        expected_provider_root_digest=completion.provider_publication.root_digest,
        expected_provider_execution_context=assembly.provider_runtime.execution_context,
    )
    return _successful_terminal(loaded)


def _reload_failure(
    *,
    publication: WebAnalysisInvocationPublication,
    provider_publication: WebAnalysisProviderRunPublication,
    assembly: LocalWebAnalysisProviderAssembly,
    verified: VerifiedOperationalWebAnalysisInputs,
    source_run_id: str,
    source_root_digest: str,
) -> VerifiedWebAnalysisFailureRun:
    return load_verified_web_analysis_failure(
        publication.run_path,
        expected_run_id=publication.run_id,
        expected_root_digest=publication.root_digest,
        source=verified.source,
        expected_source_run_id=source_run_id,
        expected_source_root_digest=source_root_digest,
        registration=assembly.provider_runtime.registration,
        provider_run_path=provider_publication.run_path,
        expected_provider_run_id=provider_publication.run_id,
        expected_provider_root_digest=provider_publication.root_digest,
        expected_provider_execution_context=assembly.provider_runtime.execution_context,
    )


def _successful_terminal(run: VerifiedWebAnalysisInvocationRun) -> _TerminalEvidence:
    if run.execution_authority or run.graph_admission_authority or run.finding_authority:
        raise OperationalWebAnalysisError(
            "WEB-007 strict success reload unexpectedly carries authority"
        )
    return _TerminalEvidence(
        status="proposal-compiled",
        semantics=run.semantics,
        analysis_run_id=run.verification.run_id,
        analysis_root_digest=run.verification.root_digest,
        provider_run_id=run.provider_publication.run_id,
        provider_root_digest=run.provider_publication.root_digest,
        provider_execution_context_digest=(
            run.provider_publication.execution_context.context_digest
        ),
        terminal_state=run.receipt.response_state,
        failure_class=None,
    )


def _failed_terminal(run: VerifiedWebAnalysisFailureRun) -> _TerminalEvidence:
    if (
        run.execution_authority
        or run.receipt.automatic_redispatch_authorized
        or run.receipt.graph_admission_authorized
        or run.receipt.finding_authorized
    ):
        raise OperationalWebAnalysisError(
            "WEB-007 strict failure reload unexpectedly carries authority"
        )
    return _TerminalEvidence(
        status="model-attempt-failed",
        semantics=run.semantics,
        analysis_run_id=run.verification.run_id,
        analysis_root_digest=run.verification.root_digest,
        provider_run_id=run.provider_publication.run_id,
        provider_root_digest=run.provider_publication.root_digest,
        provider_execution_context_digest=(
            run.provider_publication.execution_context.context_digest
        ),
        terminal_state=run.receipt.terminal_state,
        failure_class=run.receipt.failure_class,
    )


def _write_private_key(path: Path, api_key: str) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = api_key.encode("ascii", errors="strict")
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OperationalWebAnalysisError(
                    "WEB-007 private Provider key could not be written completely"
                )
            offset += written
        os.fsync(descriptor)
        observed = os.fstat(descriptor)
        if not stat.S_ISREG(observed.st_mode) or stat.S_IMODE(observed.st_mode) != 0o600:
            raise OperationalWebAnalysisError("WEB-007 private Provider key permissions differ")
    finally:
        os.close(descriptor)


def _cleanup_owned_runtime(
    *,
    model_runtime: LocalModelRuntime,
    assembly: LocalWebAnalysisProviderAssembly | None,
) -> LocalWebAnalysisProviderCleanup:
    if assembly is not None:
        return assembly.cleanup()
    model_runtime.cleanup([])
    return LocalWebAnalysisProviderCleanup(
        execution_ids=(),
        lifecycle=Lifecycle.model_validate(model_runtime.lifecycle.model_dump(mode="json")),
    )


def _require_clean_cleanup(
    cleanup: LocalWebAnalysisProviderCleanup,
    *,
    expected_execution_ids: tuple[str, ...],
) -> None:
    if (
        not cleanup.lifecycle.cleanup_observed
        or not cleanup.lifecycle.clean
        or cleanup.lifecycle.execution_ids != cleanup.execution_ids
        or cleanup.execution_ids != expected_execution_ids
    ):
        raise OperationalWebAnalysisError("WEB-007 exact owned-resource cleanup evidence differs")


def _secret_free_summary(
    *,
    verified: VerifiedOperationalWebAnalysisInputs,
    terminal: _TerminalEvidence,
    cleanup: LocalWebAnalysisProviderCleanup,
) -> dict[str, object]:
    summary: dict[str, object] = {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalWebAnalysisConformance",
        "status": terminal.status,
        "semantics": terminal.semantics,
        "terminalState": terminal.terminal_state,
        "strictSourceReloaded": True,
        "comparisonPlanVerified": True,
        "comparisonPlanRunId": verified.comparison_plan_run_id,
        "comparisonPlanRootDigest": verified.comparison_plan_root_digest,
        "comparisonPlanCommitment": verified.plan.commitment,
        "imagesVerified": True,
        "modelVerified": True,
        "model": {
            "name": verified.model.name,
            "repository": verified.model.repository,
            "revision": verified.model.revision,
            "sha256": verified.model.sha256,
            "sizeBytes": verified.model.size_bytes,
        },
        "invocationAttempts": 1,
        "analysisRunId": terminal.analysis_run_id,
        "analysisRootDigest": terminal.analysis_root_digest,
        "providerRunId": terminal.provider_run_id,
        "providerRootDigest": terminal.provider_root_digest,
        "providerExecutionContextDigest": (terminal.provider_execution_context_digest),
        "strictTerminalReloaded": True,
        "proposalCompiled": terminal.status == "proposal-compiled",
        "ownedExecutionCount": len(cleanup.execution_ids),
        "cleanupObserved": True,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
    }
    if terminal.failure_class is not None:
        summary["failureClass"] = terminal.failure_class
    return summary


def _error_summary(exc: BaseException) -> dict[str, object]:
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalWebAnalysisConformance",
        "status": "operational-error",
        "errorType": type(exc).__name__,
        "complete": False,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
    }


def _cancelled_summary(exc: WebAnalysisCancelledError) -> dict[str, object]:
    terminal_reloaded = bool(exc.__dict__.get("_operational_terminal_reloaded", False))
    cleanup_verified = bool(exc.__dict__.get("_operational_cleanup_verified", False))
    return {
        "apiVersion": _SUMMARY_API_VERSION,
        "kind": "OperationalWebAnalysisConformance",
        "status": "cancelled",
        "errorType": type(exc).__name__,
        "invocationAttempts": 1,
        "analysisRunId": exc.publication.run_id,
        "analysisRootDigest": exc.publication.root_digest,
        "providerRunId": exc.provider_publication.run_id,
        "providerRootDigest": exc.provider_publication.root_digest,
        "strictTerminalReloaded": terminal_reloaded,
        "cleanupObserved": cleanup_verified,
        "complete": False,
        "targetRequestsPerformed": False,
        "externalDeliveryPerformed": False,
        "automaticRedispatchAuthorized": False,
        "executionAuthority": False,
        "graphAdmissionAuthority": False,
        "findingAuthority": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    try:
        result = asyncio.run(run_operational_web_analysis(_arguments(argv)))
    except WebAnalysisCancelledError as exc:
        print(json.dumps(_cancelled_summary(exc), sort_keys=True))
        return 130
    except asyncio.CancelledError as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 130
    except (Exception, KeyboardInterrupt) as exc:
        print(json.dumps(_error_summary(exc), sort_keys=True))
        return 2
    print(json.dumps(result.summary, sort_keys=True))
    return 0 if result.succeeded else 1


if __name__ == "__main__":
    raise SystemExit(main())
