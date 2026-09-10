"""Sealed local-host evaluation evidence, with recomputed metrics and Provider bindings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Literal, Protocol, Self, cast

from pydantic import Field, model_validator

from pajin.benchmark.effectiveness.scoring import (
    ScoredResponse,
    confusion,
    distribution,
    repetition_distributions,
)
from pajin.benchmark.effectiveness.suite import (
    Case,
    Coordinate,
    Digest,
    FrozenModel,
    ModelPin,
    PrivateSuite,
    RuntimePin,
    SourcePin,
    chat_for,
    detector_verdict,
    digest,
    implementation_pins,
    matrix,
    model_pins,
    oracle_verdict,
)
from pajin.domain.models import CapabilityGrant, ToolRequest, ToolResult
from pajin.providers.models import ProviderChatRequest, ProviderChatResult, ProviderRegistration
from pajin.providers.receipts import ProviderBoundChatOutcome, verify_provider_bound_chat_outcome
from pajin.runtime.store import RunStore, load_verified_run_artifacts
from pajin.runtime.worker import WorkerResult
from pajin.tools.gateway import GatewayOutcome


class EvaluationCorpus(Protocol):
    @property
    def cases(self) -> tuple[Case, ...]: ...


class EvaluationExecutionPlan(Protocol):
    """Shared source-verification inputs; each version owns its corpus and scoring contract."""

    @property
    def suite(self) -> EvaluationCorpus: ...

    @property
    def runtime(self) -> RuntimePin: ...

    @property
    def models(self) -> tuple[ModelPin, ...]: ...

    @property
    def coordinates(self) -> tuple[Coordinate, ...]: ...

    @property
    def commitment(self) -> str: ...


class EvaluationPlan(FrozenModel):
    version: Literal["effect-001-v1"] = "effect-001-v1"
    suite: PrivateSuite
    runtime: RuntimePin
    models: tuple[ModelPin, ...]
    implementation: tuple[SourcePin, ...]
    coordinates: tuple[Coordinate, ...]

    @model_validator(mode="after")
    def require_complete_matrix(self) -> Self:
        if self.models != model_pins() or self.coordinates != matrix():
            raise ValueError("evaluation must freeze both registered models and all 24 coordinates")
        if not self.implementation or len({s.name for s in self.implementation}) != len(
            self.implementation
        ):
            raise ValueError("implementation identities must be present and unique")
        return self

    @property
    def commitment(self) -> str:
        return digest(self.model_dump(mode="json"))

    def public_manifest(self) -> dict[str, object]:
        return {
            "version": self.version,
            "plan_commitment": self.commitment,
            "suite_commitment": digest(self.suite.model_dump(mode="json")),
            "models": [m.model_dump(mode="json") for m in self.models],
            "runtime": self.runtime.model_dump(mode="json"),
            "implementation": [s.model_dump(mode="json") for s in self.implementation],
            "coordinates": [c.model_dump(mode="json") for c in self.coordinates],
            "cases": [
                {
                    "id": c.case_id,
                    "split": c.split,
                    "category": c.category,
                    "commitment": digest(c.model_dump(mode="json")),
                }
                for c in self.suite.cases
            ],
            "model_training_decontamination": "unknown",
            "claim": "local-private-canary-detector-effectiveness-only",
        }


class RunReference(FrozenModel):
    campaign: Literal["effect-001-plan", "effect-001-run", "effect-001-report"]
    run_id: str = Field(pattern=r"^run_[0-9]{8}T[0-9]{6}Z_[a-f0-9]{8}$")
    root_digest: Digest

    def path(self, root: Path) -> Path:
        candidate = root / self.campaign / self.run_id
        if candidate.is_symlink() or (root / self.campaign).is_symlink():
            raise ValueError("evaluation Run path must not be a symbolic link")
        return candidate


def seal_reference(store: RunStore, campaign: str) -> RunReference:
    seal = store.seal()
    return RunReference.model_validate(
        {"campaign": campaign, "run_id": store.run_id, "root_digest": seal.root_digest}
    )


def read_artifact(root: Path, reference: RunReference, name: str) -> bytes:
    snapshot = load_verified_run_artifacts(
        reference.path(root),
        requests={name: 32 * 1024 * 1024},
        expected_run_id=reference.run_id,
    )
    if snapshot.verification.root_digest != reference.root_digest:
        raise ValueError("evaluation Run differs from pinned integrity root")
    return snapshot.artifact_bytes(name)


class Trial(FrozenModel):
    case_id: str
    elapsed_seconds: float = Field(ge=0)
    error_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,100}$")
    chat: ProviderChatRequest
    grant: CapabilityGrant
    request: ToolRequest | None = None
    gateway: GatewayOutcome | None = None
    result: ProviderChatResult | None = None
    receipt: ProviderBoundChatOutcome | None = None

    @model_validator(mode="after")
    def require_explicit_outcome(self) -> Self:
        if self.error_type is None:
            if any(v is None for v in (self.request, self.gateway, self.result, self.receipt)):
                raise ValueError("successful trial is missing its bound Provider sources")
        elif self.receipt is not None or self.result is not None:
            raise ValueError("failed trial cannot carry a successful result")
        return self


class Lifecycle(FrozenModel):
    owner: str = Field(pattern=r"^[a-f0-9]{32}$")
    container_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    network_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{64}$")
    healthy: bool = False
    startup_seconds: float = Field(default=0, ge=0)
    execution_ids: tuple[str, ...] = ()
    remaining_containers: tuple[str, ...] = ()
    remaining_networks: tuple[str, ...] = ()
    cleanup_observed: bool = False
    model_image_id: str | None = None
    internal_network: bool = False
    published_ports: bool = False
    read_only: bool = False
    memory_bytes: int = 0
    nano_cpus: int = 0
    pids_limit: int = 0

    @property
    def clean(self) -> bool:
        return (
            self.cleanup_observed and not self.remaining_containers and not self.remaining_networks
        )


class RunRecord(FrozenModel):
    version: Literal["effect-001-v1"] = "effect-001-v1"
    mode: Literal["live-local", "development"]
    plan_commitment: Digest
    coordinate: Coordinate
    registration: ProviderRegistration
    lifecycle: Lifecycle
    trials: tuple[Trial, ...] = Field(max_length=16)
    error_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,100}$")
    elapsed_seconds: float = Field(ge=0)


class EvaluationIndex(FrozenModel):
    plan: RunReference
    runs: tuple[RunReference, ...] = Field(max_length=24)
    elapsed_seconds: float = Field(ge=0)
    error_type: str | None = Field(default=None, pattern=r"^[A-Za-z][A-Za-z0-9_]{0,100}$")


def verify_trial(
    plan: EvaluationExecutionPlan, run: RunRecord, trial: Trial,
) -> ScoredResponse | None:
    cases = {c.case_id: c for c in plan.suite.cases}
    case = cases.get(trial.case_id)
    if case is None or case.split != "held-out" or trial.chat != chat_for(case, run.coordinate):
        raise ValueError("trial differs from the frozen held-out request")
    if trial.error_type is not None:
        return None
    assert trial.request is not None and trial.gateway is not None
    assert trial.result is not None and trial.receipt is not None
    verified = verify_provider_bound_chat_outcome(
        trial.receipt,
        registration=run.registration,
        grant=trial.grant,
        chat=trial.chat,
        request=trial.request,
        result=trial.result,
        gateway_outcome=trial.gateway,
        charged_usage=trial.receipt.charged_usage,
        expected_budget_scope="campaign",
    )
    worker = trial.gateway.worker_result
    if (
        not verified.network_log_trusted
        or worker is None
        or worker.backend != "docker"
        or worker.execution_id not in run.lifecycle.execution_ids
    ):
        raise ValueError(
            "live trial requires a tracked Docker Worker with trusted network evidence"
        )
    if trial.result.content is None:
        return None
    return ScoredResponse(
        detected=detector_verdict(trial.result.content),
        exposed=oracle_verdict(trial.result.content, case.private_canary) is not None,
    )


def verify_run(plan: EvaluationExecutionPlan, run: RunRecord) -> list[ScoredResponse]:
    from pajin.benchmark.effectiveness.runtime import registration_for

    if (
        run.plan_commitment != plan.commitment
        or run.mode != "live-local"
        or run.coordinate not in plan.coordinates
        or run.registration != registration_for(run.coordinate)
    ):
        raise ValueError("run identity differs from the frozen evaluation")
    expected = [c.case_id for c in plan.suite.cases if c.split == "held-out"]
    actual = [t.case_id for t in run.trials]
    if actual != expected[: len(actual)]:
        raise ValueError("trial coordinates are duplicated, missing or reordered")
    execution_ids = run.lifecycle.execution_ids
    if len(set(execution_ids)) != len(execution_ids):
        raise ValueError("Worker execution identities are duplicated")
    requests = [t.request.request_id for t in run.trials if t.request is not None]
    if len(set(requests)) != len(requests):
        raise ValueError("Provider source request identities are duplicated")
    observed = run.lifecycle
    if observed.healthy and (
        observed.model_image_id != plan.runtime.model_image.split("@", 1)[1]
        or not observed.internal_network
        or observed.published_ports
        or not observed.read_only
        or observed.memory_bytes != plan.runtime.model_memory_mb * 1024 * 1024
        or observed.nano_cpus != plan.runtime.model_cpus * 1_000_000_000
        or observed.pids_limit != plan.runtime.model_pids
    ):
        raise ValueError("observed model runtime differs from the frozen resource boundary")
    return [scored for t in run.trials if (scored := verify_trial(plan, run, t)) is not None]


def verify_retained_sources(
    root: Path, reference: RunReference, plan: EvaluationExecutionPlan, run: RunRecord
) -> None:
    paths = {f"trials/{trial.case_id}.json": 2 * 1024 * 1024 for trial in run.trials}
    for trial in run.trials:
        if trial.receipt is not None:
            paths.update({p: 2 * 1024 * 1024 for p in trial.receipt.evidence_references})
    if not paths:
        return
    snapshot = load_verified_run_artifacts(
        reference.path(root), requests=paths, expected_run_id=reference.run_id
    )
    if snapshot.verification.root_digest != reference.root_digest:
        raise ValueError("Provider source Run root differs")
    for trial in run.trials:
        saved = Trial.model_validate_json(snapshot.artifact_bytes(f"trials/{trial.case_id}.json"))
        if saved != trial:
            raise ValueError("trial summary differs from the retained source")
        if trial.receipt is None:
            continue
        assert trial.request is not None and trial.gateway is not None
        payload = json.loads(snapshot.artifact_bytes(trial.receipt.evidence_references[0]))
        if not isinstance(payload, dict):
            raise ValueError("Provider evidence must be an object")
        source = cast(dict[str, object], payload)
        expected_result = trial.gateway.result.model_copy(update={"evidence": []})
        job = source.get("workerJob")
        if (
            ToolRequest.model_validate(source.get("request")) != trial.request
            or ToolResult.model_validate(source.get("result")) != expected_result
            or WorkerResult.model_validate(source.get("workerResult"))
            != trial.gateway.worker_result
            or source.get("policyDecision") != trial.gateway.decision.model_dump(mode="json")
            or source.get("networkLogTrusted") is not True
            or not isinstance(job, dict)
            or job.get("image") != plan.runtime.worker_image
            or job.get("command") != ["openai-chat-completion"]
            or not isinstance(job.get("limits"), dict)
            or job["limits"].get("timeout_seconds") != plan.runtime.request_timeout_seconds
        ):
            raise ValueError("Provider receipt sources differ from retained Gateway evidence")


def require_unique_lifecycles(records: list[RunRecord]) -> None:
    for identities in (
        [r.lifecycle.owner for r in records],
        [r.lifecycle.container_id for r in records if r.lifecycle.container_id],
        [r.lifecycle.network_id for r in records if r.lifecycle.network_id],
        [execution for r in records for execution in r.lifecycle.execution_ids],
    ):
        if len(identities) != len(set(identities)):
            raise ValueError("evaluation reused a target or Worker lifecycle")


def recompute_report(root: Path, reference: RunReference) -> dict[str, object]:
    if reference.campaign != "effect-001-report":
        raise ValueError("reader requires a pinned report Run")
    index = EvaluationIndex.model_validate_json(read_artifact(root, reference, "index.json"))
    if index.plan.campaign != "effect-001-plan" or any(
        r.campaign != "effect-001-run" for r in index.runs
    ):
        raise ValueError("evaluation source Run kind differs")
    plan = EvaluationPlan.model_validate_json(read_artifact(root, index.plan, "plan.json"))
    scoring_names = {"suite.py", "scoring.py", "pajin.tools.ai"}
    expected_scoring = tuple(p for p in implementation_pins() if p.name in scoring_names)
    if tuple(p for p in plan.implementation if p.name in scoring_names) != expected_scoring:
        raise ValueError("detector or oracle implementation differs from preregistration")
    if len({r.run_id for r in index.runs}) != len(index.runs):
        raise ValueError("duplicate source Runs in evaluation index")
    records = [
        RunRecord.model_validate_json(read_artifact(root, r, "run.json")) for r in index.runs
    ]
    coordinates = [r.coordinate for r in records]
    require_unique_lifecycles(records)
    if coordinates != list(plan.coordinates[: len(coordinates)]):
        raise ValueError("run matrix coordinates are missing, duplicated or reordered")
    all_rows: list[ScoredResponse] = []
    groups: dict[str, list[ScoredResponse]] = {}
    repeats: dict[str, list[list[ScoredResponse]]] = {}
    per_run = []
    for run_reference, run in zip(index.runs, records, strict=True):
        verify_retained_sources(root, run_reference, plan, run)
        rows = verify_run(plan, run)
        all_rows.extend(rows)
        cell = run.coordinate.key.rsplit("-s", 1)[0]
        groups.setdefault(cell, []).extend(rows)
        repeats.setdefault(cell, []).append(rows)
        per_run.append(
            {
                "coordinate": run.coordinate.model_dump(mode="json"),
                "counts": confusion(rows),
                "attempted": len(run.trials),
                "failed": sum(t.error_type is not None for t in run.trials),
                "startup_seconds": run.lifecycle.startup_seconds,
                "elapsed_seconds": run.elapsed_seconds,
                "cleanup": run.lifecycle.clean,
                "error_type": run.error_type,
            }
        )
    trials = [t for r in records for t in r.trials]
    usages = [t.receipt.reported_usage for t in trials if t.receipt is not None]
    complete = (
        len(records) == 24
        and len(all_rows) == 384
        and index.error_type is None
        and all(
            r.error_type is None
            and r.lifecycle.healthy
            and r.lifecycle.clean
            and r.lifecycle.container_id
            and r.lifecycle.network_id
            for r in records
        )
    )
    return {
        "version": "effect-001-v1",
        "complete": bool(complete),
        "plan": plan.public_manifest(),
        "expected_requests": 384,
        "attempted": len(trials),
        "responded": sum(t.result is not None for t in trials),
        "failed": sum(t.error_type is not None for t in trials),
        "unscored": len(trials) - len(all_rows),
        "not_attempted": 384 - len(trials),
        "counts": confusion(all_rows),
        "runs": per_run,
        "cells": [
            {
                "cell": key,
                "counts": confusion(rows),
                "repetitions": repetition_distributions(repeats.get(key, [])),
            }
            for key, rows in sorted(groups.items())
        ],
        "elapsed_seconds": index.elapsed_seconds,
        "request_latency_seconds": distribution([t.elapsed_seconds for t in trials]),
        "source_runs": [r.model_dump(mode="json") for r in index.runs],
        "token_usage_missing_requests": sum(t.receipt is None for t in trials),
        "provider_reported_tokens": {
            "prompt": sum(u.prompt_tokens for u in usages),
            "completion": sum(u.completion_tokens for u in usages),
        },
        "marginal_token_cost_usd": sum(u.cost_usd for u in usages),
        "unmeasured_costs": ["hardware", "electricity", "storage"],
        "cost_scope": "local-marginal-token-price-only; provider usage is untrusted",
        "trust_scope": "pinned-host-local-RunStore; not independent measurement attestation",
        "comparison_eligible": bool(complete),
        "finding_authorized": False,
        "error_type": index.error_type,
    }


def require_output_outside_runs(root: Path, destination: Path) -> None:
    """Keep standalone outputs out of all managed immutable evidence subtrees."""
    output = destination.resolve()
    for campaign in ("effect-001-plan", "effect-001-run", "effect-001-report"):
        if output.is_relative_to((root / campaign).resolve()):
            raise ValueError("evaluation output must be outside sealed Run storage")


def export_report(root: Path, reference: RunReference, destination: Path) -> bool:
    require_output_outside_runs(root, destination)
    report = recompute_report(root, reference)
    with destination.open("x", encoding="utf-8") as output:
        json.dump(report, output, ensure_ascii=False, indent=2, allow_nan=False)
        output.write("\n")
    return report["complete"] is True
