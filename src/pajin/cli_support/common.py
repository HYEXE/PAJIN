"""Shared parsing, rendering, Run-integrity, and backend helpers for the CLI."""

from __future__ import annotations

import json
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table
from rich.text import Text

from pajin.domain.validation import FindingDisposition, FindingValidationSet
from pajin.runtime.error_safety import audit_safe_exception_diagnostic
from pajin.runtime.execution_context import (
    SIMULATED_EVIDENCE_LABEL,
    worker_execution_context,
)
from pajin.runtime.safe_files import parse_strict_json_bytes
from pajin.runtime.store import load_verified_run_artifacts, load_verified_run_snapshot
from pajin.runtime.worker import DockerWorkerBackend, SimulatedWorkerBackend, WorkerBackend
from pajin.tools.ai import AIChatProbeTool, AIChatRegressionTool
from pajin.tools.base import ToolRegistry
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import ApprovalCheckTool, MockAgentProbe

MAX_CLI_RUN_ARTIFACT_BYTES = 64 * 1024 * 1024
_MAX_CLI_VALUE_CHARS = 4_000
_MAX_CLI_SECRET_SCAN_BYTES = 256 * 1024 * 1024
_SAFE_CLI_ERROR_MESSAGES = frozenset(
    {
        "Local KISA replay requires mode: ai-redteam",
        "KISA Mode Pack requires mode: ai-redteam",
        "KISA retest requires mode: ai-redteam",
        "durable replay ticket ledger does not exist",
        "durable replay ticket schema version is unsupported",
        "file is not a database",
        "finalized replay ticket does not match the sealed receipt",
        "replay Run directory does not exist",
        "replay ticket ledger initialization failed",
        "sealed replay receipt does not match its canonical artifacts",
        "this command accepts only the web CTF category",
        "'unknown replay execution ticket'",
    }
)
_SAFE_CLI_REQUIRED_CALL_PREFIXES = (
    "maxToolCalls must reserve the Local KISA source plan and every replay attempt "
    "(requires at least ",
    "maxToolCalls must reserve the original KISA plan and every automatic replay attempt "
    "(requires at least ",
    "maxToolCalls must reserve the original KISA plan and every automatic replay attempt and "
    "opted-in validation Control (requires at least ",
    "maxToolCalls must reserve every normal-function probe retry and baseline-bound negative "
    "replay attempt (requires at least ",
)

console = Console()


def safe_cli_value(value: object, *, max_chars: int = _MAX_CLI_VALUE_CHARS) -> str:
    try:
        detail = str(value)
    except BaseException:
        detail = f"{type(value).__name__} could not be rendered"
    detail = detail.encode("utf-8", errors="replace").decode("utf-8")
    detail = "".join(character if character.isprintable() else " " for character in detail)
    return detail[:max_chars]


def safe_cli_error(exc: BaseException) -> str:
    """Classify a CLI failure without rendering its potentially secret message."""

    detail = safe_cli_value(exc)
    if detail in _SAFE_CLI_ERROR_MESSAGES:
        return detail
    for prefix in _SAFE_CLI_REQUIRED_CALL_PREFIXES:
        if detail.startswith(prefix) and detail.endswith(")"):
            required_calls = detail[len(prefix) : -1]
            if required_calls.isascii() and required_calls.isdecimal():
                return detail
    return audit_safe_exception_diagnostic(exc, stage="cli-command")


def plain_cli_value(value: object) -> Text:
    return Text(safe_cli_value(value))


def print_cli_field(label: str, value: object, *, label_style: str | None = None) -> None:
    console.print(
        Text.assemble(
            (f"{label}:", label_style) if label_style else f"{label}:",
            " ",
            safe_cli_value(value),
        )
    )


def print_cli_error(label: str, exc: BaseException) -> None:
    console.print(
        Text.assemble(
            (f"{label}:", "bold red"),
            " ",
            safe_cli_error(exc),
        )
    )


def print_cli_status_failure(label: str, detail: str) -> None:
    """Print a trusted, locally constructed status failure."""

    console.print(
        Text.assemble(
            (f"{label}:", "bold red"),
            " ",
            safe_cli_value(detail),
        )
    )


@contextmanager
def cli_error_boundary(label: str, *, exit_code: int) -> Iterator[None]:
    """Translate command failures into a stable non-zero CLI result."""

    try:
        yield
    except typer.Exit:
        raise
    except Exception as exc:
        print_cli_error(label, exc)
        raise typer.Exit(code=exit_code) from exc


def print_check_table(title: str, checks: dict[str, bool]) -> None:
    table = Table(title=title)
    table.add_column("Control")
    table.add_column("Status")
    for control, passed in checks.items():
        table.add_row(control, "PASS" if passed else "FAIL")
    console.print(table)


def disposition_count(
    validation: FindingValidationSet,
    disposition: FindingDisposition,
) -> int:
    return sum(decision.disposition is disposition for decision in validation.decisions)


def verified_cli_json_artifacts(
    run_path: Path,
    run_id: str,
    *relative_paths: str,
) -> dict[str, object]:
    snapshot = load_verified_run_artifacts(
        run_path,
        requests={path: MAX_CLI_RUN_ARTIFACT_BYTES for path in relative_paths},
        expected_run_id=run_id,
    )
    return {
        path: parse_strict_json_bytes(
            snapshot.artifact_bytes(path),
            label=f"CLI Run artifact {path}",
            max_bytes=MAX_CLI_RUN_ARTIFACT_BYTES,
        )
        for path in relative_paths
    }


def cli_json_object(value: object, *, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    return value


def cli_json_object_list(value: object, *, label: str) -> list[dict[str, object]]:
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise ValueError(f"{label} must be a JSON array of objects")
    return value


def cli_json_integer(value: object, *, label: str) -> int:
    if type(value) is not int:
        raise ValueError(f"{label} must be a JSON integer")
    return value


def verified_cli_event_types(run_path: Path, run_id: str) -> list[str]:
    snapshot = load_verified_run_snapshot(run_path, expected_run_id=run_id)
    return [event.event_type for event in snapshot.events]


def _json_value_contains_text(value: object, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    if isinstance(value, list):
        return any(_json_value_contains_text(item, needle) for item in value)
    if isinstance(value, dict):
        return any(
            needle in key or _json_value_contains_text(item, needle) for key, item in value.items()
        )
    return False


def verified_cli_run_contains_secret(run_path: Path, run_id: str, secret: str) -> bool:
    """Scan one exact sealed Run snapshot without following injected filesystem entries."""

    if not secret:
        raise ValueError("CLI secret scan requires a non-empty secret")
    initial = load_verified_run_snapshot(run_path, expected_run_id=run_id)
    records = [artifact for seal in initial.seals for artifact in seal.artifacts]
    total_bytes = sum(record.size_bytes for record in records)
    if total_bytes > _MAX_CLI_SECRET_SCAN_BYTES:
        raise ValueError("CLI secret scan exceeds its aggregate byte limit")
    requests: dict[str, int] = {}
    for record in records:
        if record.size_bytes > MAX_CLI_RUN_ARTIFACT_BYTES:
            raise ValueError(f"CLI secret scan artifact is too large: {record.path}")
        if record.path in requests:
            raise ValueError(f"CLI secret scan found duplicate sealed path: {record.path}")
        requests[record.path] = max(record.size_bytes, 1)
    snapshot = load_verified_run_artifacts(
        run_path,
        requests=requests,
        expected_run_id=run_id,
    )
    if snapshot.verification.root_digest != initial.verification.root_digest:
        raise ValueError("sealed Run changed while the CLI secret scan was prepared")

    secret_bytes = secret.encode("utf-8")
    escaped_secret_bytes = json.dumps(secret, ensure_ascii=False)[1:-1].encode("utf-8")
    variants = {secret_bytes, escaped_secret_bytes}
    if any(
        any(variant in content for variant in variants) for content in snapshot.artifacts.values()
    ):
        return True
    if any(secret in path for path in snapshot.artifacts):
        return True
    return any(
        _json_value_contains_text(event.model_dump(mode="json"), secret)
        for event in snapshot.events
    )


def tool_registry() -> ToolRegistry:
    registry = ToolRegistry()
    registry.register(MockAgentProbe())
    registry.register(ApprovalCheckTool())
    registry.register(AIChatProbeTool())
    registry.register(AIChatRegressionTool())
    registry.register(BooleanSQLiProbeTool())
    registry.register(CTFWebBackupProbeTool())
    registry.register(CTFCryptoXORTool())
    registry.register(HTTPGetTool())
    registry.register(demo_mcp_tool())
    return registry


def worker_backend(worker: str) -> WorkerBackend:
    if worker == "simulated":
        return SimulatedWorkerBackend()
    if worker == "docker":
        return DockerWorkerBackend(allowed_images={"pajin-worker:dev"})
    raise ValueError("use 'simulated' or 'docker'")


def parse_aware_datetime(value: str, *, option: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{option} must be an ISO 8601 datetime") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{option} must include a UTC offset or Z")
    return parsed


def print_worker_execution_context(backend: object) -> None:
    execution_context = worker_execution_context(backend)
    print_cli_field("Worker backend", execution_context.backend)
    if execution_context.simulated:
        console.print(Text(SIMULATED_EVIDENCE_LABEL, style="bold yellow"))
        console.print(Text(execution_context.warning or "Development-only simulated execution."))
