"""Dependency-aware console entrypoints for optional PAJIN processes."""

from __future__ import annotations

import argparse
import sys
from importlib import import_module
from importlib.util import find_spec
from typing import Protocol, cast

_CONTROL_PLANE_IMPORTS = ("fastapi", "sqlalchemy", "uvicorn")
_WORKER_IMPORTS = ("httpx",)
_CONTROL_PLANE_INSTALL = "python -m pip install 'pajin[control-plane]'"


class _RunnableModule(Protocol):
    def main(self) -> None: ...


def _parse_daemon_arguments(*, program: str, description: str) -> None:
    parser = argparse.ArgumentParser(prog=program, description=description)
    parser.parse_args()


def _safe_error(exc: BaseException) -> str:
    """Classify startup failure without rendering its potentially secret message."""

    # Keep optional daemon ``--help`` entrypoints importable from a clean wheel
    # without eagerly importing the runtime package and its base dependencies.
    from pajin.runtime.error_safety import audit_safe_exception_diagnostic

    return audit_safe_exception_diagnostic(exc, stage="process-entrypoint")


def _load_optional_module(
    module_name: str,
    *,
    required_imports: tuple[str, ...],
) -> _RunnableModule:
    missing = [name for name in required_imports if find_spec(name) is None]
    if missing:
        sys.stderr.write(
            "PAJIN Control Plane dependencies are not installed "
            f"(missing: {', '.join(missing)}).\n"
            f"Install the optional dependencies with:\n  {_CONTROL_PLANE_INSTALL}\n"
        )
        raise SystemExit(1)
    module = cast(_RunnableModule, import_module(module_name))
    if not callable(getattr(module, "main", None)):
        raise RuntimeError(f"optional process module has no callable main(): {module_name}")
    return module


def _run_daemon(
    *,
    program: str,
    description: str,
    module_name: str,
    required_imports: tuple[str, ...],
) -> None:
    _parse_daemon_arguments(program=program, description=description)
    try:
        module = _load_optional_module(
            module_name,
            required_imports=required_imports,
        )
        module.main()
    except SystemExit:
        raise
    except Exception as exc:
        sys.stderr.write(f"{program} failed: {_safe_error(exc)}\n")
        raise SystemExit(1) from exc


def control_plane_main() -> None:
    """Run the optional Control Plane server after checking its dependency extra."""

    _run_daemon(
        program="pajin-control-plane",
        description="Run the PAJIN Control Plane API server.",
        module_name="pajin.control_plane.__main__",
        required_imports=_CONTROL_PLANE_IMPORTS,
    )


def worker_daemon_main() -> None:
    """Run the optional Worker daemon after checking its dependency extra."""

    _run_daemon(
        program="pajin-worker-daemon",
        description="Run the PAJIN Control Plane Worker daemon.",
        module_name="pajin.control_plane.worker_main",
        required_imports=_WORKER_IMPORTS,
    )


def replay_worker_daemon_main() -> None:
    """Run the optional dedicated Replay Worker daemon."""

    _run_daemon(
        program="pajin-replay-worker-daemon",
        description="Run the PAJIN dedicated Replay Worker daemon.",
        module_name="pajin.control_plane.replay_worker_main",
        required_imports=_WORKER_IMPORTS,
    )
