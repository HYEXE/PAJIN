"""Authoritative worker-backend identity for sealed local Run artifacts."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from pajin.runtime.worker import DockerWorkerBackend, SimulatedWorkerBackend

SIMULATED_EVIDENCE_LABEL = "SIMULATED / NOT REAL TARGET EVIDENCE"
SIMULATED_EVIDENCE_WARNING = (
    "The deterministic simulated Worker is for development and unit tests only; "
    "its observations do not establish behavior of a real target."
)


class WorkerEvidenceScope(StrEnum):
    WORKER_OBSERVED = "worker-observed-execution"
    SIMULATED_DEVELOPMENT = "simulated-development-only"
    CUSTOM_UNCLASSIFIED = "custom-backend-unclassified"


class WorkerExecutionContext(BaseModel):
    """Typed identity copied into every authoritative local execution projection."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    backend: Literal["docker", "simulated", "custom"]
    implementation: str = Field(min_length=1, max_length=500)
    simulated: bool
    evidence_scope: WorkerEvidenceScope = Field(alias="evidenceScope")
    warning: str | None = Field(default=None, max_length=1_000)

    @model_validator(mode="after")
    def require_consistent_simulation_scope(self) -> WorkerExecutionContext:
        if self.backend == "simulated" and (
            not self.simulated
            or self.evidence_scope is not WorkerEvidenceScope.SIMULATED_DEVELOPMENT
            or self.warning is None
        ):
            raise ValueError("simulated Worker context requires its development-only warning")
        if self.backend != "simulated" and self.simulated:
            raise ValueError("only the simulated Worker context can be marked simulated")
        return self

    def run_summary(self) -> dict[str, object]:
        """Return the stable fields duplicated into ``run.json``."""

        return {
            "executionContext": "execution-context.json",
            "workerBackend": self.backend,
            "simulated": self.simulated,
            "evidenceScope": self.evidence_scope.value,
        }


def worker_execution_context(worker: object) -> WorkerExecutionContext:
    """Derive backend identity from the actual backend instance, not Worker output."""

    implementation_type = type(worker)
    implementation = f"{implementation_type.__module__}.{implementation_type.__qualname__}"
    if isinstance(worker, SimulatedWorkerBackend):
        return WorkerExecutionContext(
            backend="simulated",
            implementation=implementation,
            simulated=True,
            evidenceScope=WorkerEvidenceScope.SIMULATED_DEVELOPMENT,
            warning=SIMULATED_EVIDENCE_WARNING,
        )
    if isinstance(worker, DockerWorkerBackend):
        return WorkerExecutionContext(
            backend="docker",
            implementation=implementation,
            simulated=False,
            evidenceScope=WorkerEvidenceScope.WORKER_OBSERVED,
        )
    return WorkerExecutionContext(
        backend="custom",
        implementation=implementation,
        simulated=False,
        evidenceScope=WorkerEvidenceScope.CUSTOM_UNCLASSIFIED,
    )
