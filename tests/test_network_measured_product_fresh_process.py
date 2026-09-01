from __future__ import annotations

import multiprocessing
from typing import Any

from tests.network_measured_product_fresh_process import (
    _fresh_child_stage,
    _mark_fresh_child_stage,
)


def _mark_second_read_in_spawn(progress: Any) -> None:
    _mark_fresh_child_stage(progress, "second-product-read-complete")


def test_network_fresh_product_progress_reports_last_completed_stage() -> None:
    class Progress:
        value = 0

    progress = Progress()
    _mark_fresh_child_stage(progress, "first-product-read-complete")
    assert _fresh_child_stage(progress) == "first-product-read-complete"

    progress.value = 999
    assert _fresh_child_stage(progress) == "unknown-999"


def test_network_fresh_product_progress_crosses_spawn_boundary() -> None:
    context = multiprocessing.get_context("spawn")
    progress = context.RawValue("i", 0)
    process = context.Process(target=_mark_second_read_in_spawn, args=(progress,))

    process.start()
    process.join(timeout=15)
    if process.is_alive():
        process.terminate()
        process.join(timeout=10)

    assert process.exitcode == 0
    assert _fresh_child_stage(progress) == "second-product-read-complete"
