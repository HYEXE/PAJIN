"""Shared process-boundary parsing and health checks for leased daemons."""

from __future__ import annotations

import asyncio
import math
import os
import re
import signal
from datetime import UTC, datetime, timedelta


def required_env(name: str, *, owner: str) -> str:
    """Load a non-empty, whitespace-exact required setting."""

    value = os.environ.get(name)
    if value is None or not value or value != value.strip():
        raise RuntimeError(f"missing or invalid required {owner} setting: {name}")
    return value


def env(name: str, default: str, *, owner: str) -> str:
    """Load a non-empty, whitespace-exact optional setting."""

    value = os.environ.get(name, default)
    if not value or value != value.strip():
        raise RuntimeError(f"invalid {owner} setting: {name}")
    return value


def integer_env(name: str, default: int, *, owner: str) -> int:
    """Accept only canonical unsigned decimal integers."""

    raw = env(name, str(default), owner=owner)
    if re.fullmatch(r"0|[1-9][0-9]*", raw) is None:
        raise RuntimeError(f"{owner} setting must be a canonical integer: {name}")
    return int(raw)


def float_env(name: str, default: float, *, owner: str) -> float:
    """Load a finite floating-point setting."""

    raw = env(name, str(default), owner=owner)
    try:
        value = float(raw)
    except ValueError as exc:
        raise RuntimeError(f"{owner} setting must be numeric: {name}") from exc
    if not math.isfinite(value):
        raise RuntimeError(f"{owner} setting must be finite: {name}")
    return value


def literal_bool_env(name: str, *, owner: str, default: bool = False) -> bool:
    """Parse an opt-in boolean without truthy aliases or whitespace coercion."""

    raw = os.environ.get(name, "true" if default else "false")
    if raw not in {"true", "false"}:
        raise RuntimeError(f"{owner} setting must be the literal true or false: {name}")
    return raw == "true"


def install_stop_event() -> asyncio.Event:
    """Install portable SIGINT/SIGTERM handlers for the current event loop."""

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for selected_signal in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(selected_signal, stop.set)
        except (NotImplementedError, RuntimeError):
            signal.signal(
                selected_signal,
                lambda _signum, _frame: loop.call_soon_threadsafe(stop.set),
            )
    return stop


def validate_health_timestamp(
    last_contact: datetime,
    *,
    owner: str,
    max_age: timedelta,
    max_future_skew: timedelta = timedelta(seconds=5),
) -> None:
    """Reject timezone-naive, future, and stale daemon status timestamps."""

    if last_contact.tzinfo is None or last_contact.utcoffset() is None:
        raise SystemExit(f"{owner} status timestamp is timezone-naive")
    age = datetime.now(UTC) - last_contact.astimezone(UTC)
    if age < -max_future_skew:
        raise SystemExit(f"{owner} status timestamp is in the future")
    if age > max_age:
        raise SystemExit(f"{owner} status is stale")
