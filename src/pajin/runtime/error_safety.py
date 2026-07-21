"""Secret-free diagnostics for exceptions crossing audit boundaries."""

from __future__ import annotations

_SAFE_AUDIT_STAGES = frozenset(
    {
        "deterministic-worker-input",
        "docker-cleanup",
        "docker-cli-start",
        "docker-worker-input",
        "egress-proxy-setup",
        "cli-command",
        "provider-output-validation",
        "provider-planner-fallback",
        "provider-validator-fallback",
        "process-entrypoint",
        "replay-worker-control-plane-lease",
        "replay-worker-control-plane-protocol",
        "replay-worker-control-plane-transport",
        "secret-lease",
        "simulated-worker-input",
        "run-terminalization",
        "tool-interpretation",
        "tool-preparation",
        "tool-request-validation",
        "trusted-execution-validation",
        "worker-backend",
        "worker-control-plane-lease",
        "worker-control-plane-protocol",
        "worker-control-plane-transport",
    }
)
_SAFE_BUILTIN_EXCEPTION_TYPES = frozenset(
    {
        "AssertionError",
        "AttributeError",
        "ConnectionError",
        "EOFError",
        "FileExistsError",
        "FileNotFoundError",
        "KeyError",
        "LookupError",
        "OSError",
        "OverflowError",
        "PermissionError",
        "RuntimeError",
        "TimeoutError",
        "TypeError",
        "UnicodeError",
        "ValueError",
    }
)
_SAFE_PAJIN_EXCEPTION_TYPES = frozenset(
    {
        "BudgetExceeded",
        "CapabilityError",
        "CheckpointIntegrityError",
        "ControlPlaneAuthenticationError",
        "ControlPlaneLeaseLost",
        "ControlPlaneLocalLeaseDeadlineExceeded",
        "ControlPlaneProtocolError",
        "ControlPlaneRunCancelled",
        "ControlPlaneTransientError",
        "ModelCallFailure",
        "PermanentExecutionError",
        "ReplayWorkerQuiescenceError",
        "TransientExecutionError",
        "WorkerCleanupError",
        "WorkerQuiescenceError",
    }
)
_SAFE_EXTERNAL_EXCEPTION_TYPES = frozenset(
    {
        ("asyncio.exceptions", "CancelledError"),
        ("json.decoder", "JSONDecodeError"),
        ("pydantic_core._pydantic_core", "ValidationError"),
    }
)


def audit_safe_exception_type(error: BaseException) -> str:
    """Return a bounded allowlisted type name without consulting ``str(error)``."""

    try:
        error_type = type(error)
        module = error_type.__module__
        name = error_type.__name__
    except BaseException:
        return "Exception"
    if not isinstance(module, str) or not isinstance(name, str):
        return "Exception"
    if module == "builtins" and name in _SAFE_BUILTIN_EXCEPTION_TYPES:
        return name
    if module.startswith("pajin.") and name in _SAFE_PAJIN_EXCEPTION_TYPES:
        return name
    if (module, name) in _SAFE_EXTERNAL_EXCEPTION_TYPES:
        return name
    return "Exception"


def audit_safe_exception_diagnostic(
    error: BaseException,
    *,
    stage: str,
) -> str:
    """Classify a failure while deliberately omitting its untrusted message."""

    safe_stage = stage if isinstance(stage, str) and stage in _SAFE_AUDIT_STAGES else "unknown"
    return f"exception_type={audit_safe_exception_type(error)}; stage={safe_stage}; detail=omitted"
