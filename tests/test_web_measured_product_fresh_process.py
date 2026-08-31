import multiprocessing
from pathlib import Path
from typing import Any

import pytest

from pajin.runtime.store import RunStore
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReaderError,
    WebMeasuredProductReadRegistry,
)
from tests.web_measured_product_fresh_process import (
    _fresh_child_stage,
    _mark_fresh_child_stage,
    _start_call_monitoring,
    _stop_call_monitoring,
)


def _mark_first_read_in_spawn(progress: Any) -> None:
    _mark_fresh_child_stage(progress, "first-product-read-complete")


def test_fresh_product_monitor_is_code_local_and_restores_the_tool(
    tmp_path: Path,
) -> None:
    counters: dict[str, int] = {}
    resolver_calls: list[str] = []
    blocked_root = tmp_path / "blocked"

    session = _start_call_monitoring(counters, resolver_calls=resolver_calls)
    try:
        with pytest.raises(WebMeasuredProductReaderError):
            WebMeasuredProductReader.read(object())  # type: ignore[arg-type]
        with pytest.raises(AttributeError):
            WebMeasuredProductReadRegistry.resolve_for_product_read(
                object(),  # type: ignore[arg-type]
                deployment_id="deployment-monitor-test",
            )
        with pytest.raises(
            AssertionError,
            match=r"fresh WEB product invoked forbidden:RunStore\.create",
        ):
            RunStore.create(blocked_root, "blocked-monitor-test")
    finally:
        _stop_call_monitoring(session)

    assert counters == {
        "reader": 1,
        "resolver": 1,
        "forbidden:RunStore.create": 1,
    }
    assert resolver_calls == ["deployment-monitor-test"]
    assert not blocked_root.exists()

    allowed = RunStore.create(tmp_path / "allowed", "allowed-monitor-test")
    assert allowed.path.exists()


def test_fresh_product_progress_reports_the_last_completed_stage() -> None:
    class Progress:
        value = 0

    progress = Progress()

    _mark_fresh_child_stage(progress, "first-product-read-complete")

    assert _fresh_child_stage(progress) == "first-product-read-complete"

    progress.value = 999
    assert _fresh_child_stage(progress) == "unknown-999"


def test_fresh_product_progress_crosses_the_spawn_boundary() -> None:
    context = multiprocessing.get_context("spawn")
    progress = context.RawValue("i", 0)
    process = context.Process(target=_mark_first_read_in_spawn, args=(progress,))

    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)

    assert process.exitcode == 0
    assert _fresh_child_stage(progress) == "first-product-read-complete"
