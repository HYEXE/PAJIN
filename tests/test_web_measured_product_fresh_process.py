from pathlib import Path

import pytest

from pajin.runtime.store import RunStore
from pajin.workflow.web_measured_product_reader import (
    WebMeasuredProductReader,
    WebMeasuredProductReaderError,
    WebMeasuredProductReadRegistry,
)
from tests.web_measured_product_fresh_process import (
    _start_call_monitoring,
    _stop_call_monitoring,
)


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
