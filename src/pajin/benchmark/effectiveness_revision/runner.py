"""Reuse governed local execution; consume a corpus once and seal a paired comparison."""

from __future__ import annotations

import os
import sqlite3
from contextlib import closing
from pathlib import Path
from time import monotonic

from pajin.benchmark.effectiveness.docker import verify_images, verify_model
from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    RunReference,
    read_artifact,
    seal_reference,
)
from pajin.benchmark.effectiveness.runner import execute_run
from pajin.benchmark.effectiveness.runtime import local_campaign
from pajin.benchmark.effectiveness.suite import (
    ENDPOINT,
    RuntimePin,
    digest,
    matrix,
    model_pins,
    normalized_prompt,
)
from pajin.benchmark.effectiveness_comparison.evidence import (
    ComparisonIndex as ComparisonIndexSource,
)
from pajin.benchmark.effectiveness_comparison.evidence import (
    recompute_comparison as prior_report,
)
from pajin.benchmark.effectiveness_comparison.plan import ComparisonPlan as PriorPlan
from pajin.benchmark.effectiveness_revision.evidence import ComparisonIndex
from pajin.benchmark.effectiveness_revision.plan import (
    ComparisonPlan,
    ComparisonSuite,
    comparison_pins,
)
from pajin.benchmark.effectiveness_revision.scoring import (
    DetectorInput,
    PairedDetection,
    measure_pair,
)
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.control import BudgetController
from pajin.runtime.store import RunStore


def freeze_comparison(
    root: Path,
    runtime: RuntimePin,
    suite: ComparisonSuite,
    *,
    development_root: Path,
    development_reference: RunReference,
) -> RunReference:
    if prior_report(development_root, development_reference)["complete"] is not True:
        raise ValueError("development reference must be the verified previous evaluation")
    previous = ComparisonIndexSource.model_validate_json(
        read_artifact(development_root, development_reference, "comparison.json")
    )
    previous_plan = PriorPlan.model_validate_json(
        read_artifact(development_root, previous.source.plan, "plan.json")
    )
    expected = tuple(digest(normalized_prompt(case.prompt)) for case in previous_plan.suite.cases)
    if suite.prior_prompt_digests != expected:
        raise ValueError("prior corpus commitments differ from the verified development evidence")
    verify_images(runtime)
    plan = ComparisonPlan(
        suite=suite,
        runtime=runtime,
        models=model_pins(),
        coordinates=matrix(),
        implementation=comparison_pins(),
        development_report_root=development_reference.root_digest,
    )
    store = RunStore.create(root, "effect-001-plan")
    store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
    store.write_json_create_only("public-manifest.json", plan.public_manifest())
    store.append_event("comparison.preregistered", {"commitment": plan.commitment})
    return seal_reference(store, "effect-001-plan")


def consume_corpus(root: Path, plan: ComparisonPlan) -> None:
    root.mkdir(parents=True, exist_ok=True)
    marker = root / ".effect-003-consumed.sqlite3"
    with closing(sqlite3.connect(marker)) as connection, connection:
        os.chmod(marker, 0o600)
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "CREATE TABLE IF NOT EXISTS prompts (digest TEXT PRIMARY KEY, plan TEXT NOT NULL)"
        )
        try:
            connection.executemany(
                "INSERT INTO prompts VALUES (?, ?)",
                [
                    (digest(normalized_prompt(case.prompt)), plan.commitment)
                    for case in plan.suite.cases[2:]
                ],
            )
        except sqlite3.IntegrityError as exc:
            raise ValueError("held-out prompt already consumed in this evaluation root") from exc


async def run_comparison(
    *,
    root: Path,
    reference: RunReference,
    model_paths: dict[str, Path],
    development: bool = False,
) -> RunReference:
    started = monotonic()
    if reference.campaign != "effect-001-plan":
        raise ValueError("comparison requires a pinned plan Run")
    plan = ComparisonPlan.model_validate_json(read_artifact(root, reference, "plan.json"))
    if plan.implementation != comparison_pins():
        raise ValueError("source changed after preregistration; freeze an unused comparison")
    verify_images(plan.runtime)
    paths = {pin.name: verify_model(model_paths[pin.name], pin) for pin in plan.models}
    if not development:
        consume_corpus(root, plan)
    campaign = local_campaign()
    budget = BudgetController(campaign.spec.budgets)
    ledger = CapabilityLedger(max_depth=1)
    grant = ledger.issue_root(
        campaign,
        subject="agent:effect-001",
        tools={"provider.effect-001.chat"},
        targets={ENDPOINT},
    )
    coordinates = (
        tuple(
            c
            for c in plan.coordinates
            if c.policy == "protected" and c.temperature == 0 and c.seed == 17
        )
        if development
        else plan.coordinates
    )
    references = []
    detections: list[PairedDetection | None] = []
    error_type = None
    cases = {case.case_id: case for case in plan.suite.cases}
    for coordinate in coordinates:
        run_ref, run = await execute_run(
            plan=plan,
            coordinate=coordinate,
            model_path=paths[coordinate.model],
            root=root,
            campaign=campaign,
            budget=budget,
            ledger=ledger,
            grant=grant,
            development=development,
        )
        references.append(run_ref)
        if not development:
            for trial in run.trials:
                if trial.result is None or trial.result.content is None:
                    continue
                try:
                    value = DetectorInput(
                        response=trial.result.content, user_text=cases[trial.case_id].prompt
                    )
                    detections.append(measure_pair(value, candidate_first=len(detections) % 2 == 1))
                except ValueError:
                    detections.append(None)
                    error_type = "DetectorValueError"
        if run.error_type or not run.lifecycle.clean:
            error_type = run.error_type or "CleanupIncomplete"
            break
    source = EvaluationIndex(
        plan=reference,
        runs=tuple(references),
        error_type=error_type,
        elapsed_seconds=monotonic() - started,
    )
    store = RunStore.create(root, "effect-001-report")
    store.write_json_create_only("index.json", source.model_dump(mode="json"))
    store.write_json_create_only(
        "comparison.json",
        ComparisonIndex(
            source=source,
            detections=tuple(detections),
        ).model_dump(mode="json"),
    )
    store.append_event("comparison.indexed", {"development": development})
    return seal_reference(store, "effect-001-report")
