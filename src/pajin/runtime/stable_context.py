"""Explicit, canonical context contracts for resumable execution components."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Protocol, runtime_checkable


@runtime_checkable
class StableExecutionContextProvider(Protocol):
    """Expose every trusted instance setting that can change resumed execution."""

    def stable_execution_context(self) -> Mapping[str, object]:
        """Return canonicalizable, non-secret configuration for integrity binding."""


def stable_execution_context(value: object, *, component: str) -> dict[str, object]:
    """Load an explicitly implemented context without inspecting arbitrary object state."""

    implementation = type(value).__dict__.get("stable_execution_context")
    if implementation is None or not isinstance(value, StableExecutionContextProvider):
        raise TypeError(
            f"{component} {_qualified_type(value)} must explicitly implement "
            "stable_execution_context() before it can be used by a resumable workflow"
        )
    context = value.stable_execution_context()
    if not isinstance(context, Mapping) or any(not isinstance(key, str) for key in context):
        raise TypeError(f"{component} stable execution context must be a string-keyed mapping")
    return {
        "type": _qualified_type(value),
        "context": dict(context),
    }


def _qualified_type(value: object) -> str:
    value_type = type(value)
    return f"{value_type.__module__}.{value_type.__qualname__}"
