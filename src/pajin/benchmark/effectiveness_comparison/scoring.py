"""Paired, bounded detector input and measured local execution; oracle is a separate caller."""

from __future__ import annotations

from time import perf_counter, process_time

from pydantic import Field

from pajin.benchmark.effectiveness.suite import (
    MARKER,
    Digest,
    FrozenModel,
    detector_verdict,
    digest,
)
from pajin.tools.disclosure import detect_disclosure_suspicion


class DetectorInput(FrozenModel):
    response: str = Field(max_length=65_536)
    user_text: str = Field(max_length=65_536)


class PairedDetection(FrozenModel):
    input_digest: Digest
    baseline: bool
    candidate: bool
    baseline_wall_seconds: float = Field(ge=0)
    candidate_wall_seconds: float = Field(ge=0)
    baseline_cpu_seconds: float = Field(ge=0)
    candidate_cpu_seconds: float = Field(ge=0)


def candidate_verdict(value: DetectorInput) -> bool:
    return detect_disclosure_suspicion(
        value.response,
        user_text=value.user_text,
        public_values=(MARKER,),
    ).detected


def measure_pair(value: DetectorInput, *, candidate_first: bool) -> PairedDetection:
    """No system message, case label, canary, oracle result or model setting is accepted."""
    functions = {
        "baseline": lambda: detector_verdict(value.response),
        "candidate": lambda: candidate_verdict(value),
    }
    result: dict[str, object] = {"input_digest": digest(value.model_dump(mode="json"))}
    for name in ("candidate", "baseline") if candidate_first else ("baseline", "candidate"):
        wall, cpu = perf_counter(), process_time()
        verdict = functions[name]()
        result[name + "_cpu_seconds"] = process_time() - cpu
        result[name + "_wall_seconds"] = perf_counter() - wall
        result[name] = verdict
    return PairedDetection.model_validate(result)


def verify_pair(value: DetectorInput, recorded: PairedDetection) -> None:
    if (
        recorded.input_digest != digest(value.model_dump(mode="json"))
        or recorded.baseline != detector_verdict(value.response)
        or recorded.candidate != candidate_verdict(value)
    ):
        raise ValueError("paired detector result differs from the retained response")
