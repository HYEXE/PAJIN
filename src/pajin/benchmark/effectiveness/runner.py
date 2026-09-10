"""Sequential, preregistered local-model evaluation with durable failure and cleanup evidence."""

from __future__ import annotations

import asyncio
import json
import os
import secrets
from pathlib import Path
from tempfile import TemporaryDirectory
from time import monotonic
from typing import Literal

from pajin.benchmark.effectiveness.docker import LocalModelRuntime, verify_images, verify_model
from pajin.benchmark.effectiveness.evidence import (
    EvaluationExecutionPlan,
    EvaluationIndex,
    EvaluationPlan,
    RunRecord,
    RunReference,
    Trial,
    read_artifact,
    seal_reference,
)
from pajin.benchmark.effectiveness.runtime import (
    execute_trial,
    local_campaign,
    provider_port,
    registration_for,
)
from pajin.benchmark.effectiveness.suite import (
    ENDPOINT,
    Coordinate,
    RuntimePin,
    chat_for,
    implementation_pins,
    matrix,
    model_pins,
    new_suite,
)
from pajin.domain.models import CampaignManifest, CapabilityGrant
from pajin.policy.capability import CapabilityLedger
from pajin.runtime.control import BudgetController
from pajin.runtime.store import RunStore


def freeze_plan(root: Path, runtime: RuntimePin) -> RunReference:
    verify_images(runtime)
    plan = EvaluationPlan(
        suite=new_suite(),
        runtime=runtime,
        models=model_pins(),
        implementation=implementation_pins(),
        coordinates=matrix(),
    )
    store = RunStore.create(root, "effect-001-plan")
    store.write_json_create_only("plan.json", plan.model_dump(mode="json"))
    store.write_json_create_only("public-manifest.json", plan.public_manifest())
    store.append_event("effectiveness.preregistered", {"commitment": plan.commitment})
    return seal_reference(store, "effect-001-plan")


async def execute_run(
    *,
    plan: EvaluationExecutionPlan,
    coordinate: Coordinate,
    model_path: Path,
    root: Path,
    campaign: CampaignManifest,
    budget: BudgetController,
    ledger: CapabilityLedger,
    grant: CapabilityGrant,
    development: bool = False,
) -> tuple[RunReference, RunRecord]:
    started = monotonic()
    store = RunStore.create(root, "effect-001-run")
    model = next(m for m in plan.models if m.name == coordinate.model)
    mode: Literal["development", "live-local"] = "development" if development else "live-local"
    store.write_json_create_only(
        "start.json",
        {
            "mode": mode,
            "plan_commitment": plan.commitment,
            "coordinate": coordinate.model_dump(mode="json"),
            "campaign": campaign.model_dump(mode="json", by_alias=True),
        },
    )
    trials: list[Trial] = []
    execution_ids: list[str] = []
    error_type = None
    with TemporaryDirectory(prefix="effect-001-key-", dir=root) as private:
        os.chmod(private, 0o700)
        key_path = Path(private) / "api-key"
        key = secrets.token_urlsafe(32)
        with key_path.open("x", encoding="ascii") as handle:
            os.chmod(key_path, 0o600)
            handle.write(key)
        target = LocalModelRuntime(
            runtime=plan.runtime, model=model, model_path=model_path, key_file=key_path
        )
        store.write_json_create_only(
            "lifecycle-intent.json",
            {
                "owner": target.owner,
                "network": target.network_name,
                "container": target.container_name,
                "plan_commitment": plan.commitment,
            },
        )
        try:
            budget.check_duration()
            verify_model(model_path, model)
            target.start()
            store.write_json_create_only("lifecycle-start.json", target.lifecycle.model_dump())
            port, gateway, tool, child = provider_port(
                coordinate=coordinate,
                runtime=plan.runtime,
                network=target.network_name,
                key=key,
                campaign=campaign,
                budget=budget,
                ledger=ledger,
                root_grant=grant,
                store=store,
            )
            execution_ids = tool.execution_ids
            split = "development" if development else "held-out"
            for case in (c for c in plan.suite.cases if c.split == split):
                budget.check_duration()
                trial = await execute_trial(
                    port=port,
                    gateway=gateway,
                    grant=child,
                    case_id=case.case_id,
                    chat=chat_for(case, coordinate),
                    run_id=store.run_id,
                )
                trials.append(trial)
                store.write_json_create_only(
                    f"trials/{case.case_id}.json", trial.model_dump(mode="json")
                )
                print(
                    json.dumps(
                        {
                            "coordinate": coordinate.key,
                            "case": case.case_id,
                            "status": "failed" if trial.error_type else "responded",
                            "seconds": round(trial.elapsed_seconds, 2),
                        }
                    ),
                    flush=True,
                )
            verify_model(model_path, model)
        except (Exception, KeyboardInterrupt, asyncio.CancelledError) as exc:
            error_type = type(exc).__name__
        finally:
            try:
                target.cleanup(execution_ids)
            except Exception as exc:
                error_type = f"Cleanup{type(exc).__name__}"
        record = RunRecord(
            mode=mode,
            plan_commitment=plan.commitment,
            coordinate=coordinate,
            registration=registration_for(coordinate),
            lifecycle=target.lifecycle,
            trials=tuple(trials),
            error_type=error_type,
            elapsed_seconds=monotonic() - started,
        )
        store.write_json_create_only("run.json", record.model_dump(mode="json"))
        store.write_json_create_only("budget.json", budget.snapshot())
        store.append_event(
            "effectiveness.completed",
            {
                "mode": mode,
                "attempted": len(trials),
                "error_type": error_type,
                "cleanup": target.lifecycle.clean,
            },
        )
        reference = seal_reference(store, "effect-001-run")
    return reference, record


async def run_evaluation(
    *,
    root: Path,
    plan_reference: RunReference,
    model_paths: dict[str, Path],
    development: bool = False,
) -> RunReference:
    started = monotonic()
    if plan_reference.campaign != "effect-001-plan":
        raise ValueError("evaluation requires a pinned plan Run")
    plan = EvaluationPlan.model_validate_json(read_artifact(root, plan_reference, "plan.json"))
    if plan.implementation != implementation_pins():
        raise ValueError("source changed after preregistration; freeze a new evaluation version")
    verify_images(plan.runtime)
    models = {m.name: verify_model(model_paths[m.name], m) for m in plan.models}
    if not development:
        # A crashed attempt consumes this host-local plan too. Never silently rerun an
        # already observed corpus and select the more favorable attempt.
        marker = root / f".effect-001-started-{plan.commitment}"
        with marker.open("x", encoding="ascii") as handle:
            os.chmod(marker, 0o600)
            handle.write(plan_reference.model_dump_json() + "\n")
    campaign = local_campaign()
    budget = BudgetController(campaign.spec.budgets)
    ledger = CapabilityLedger(max_depth=1)
    grant = ledger.issue_root(
        campaign, subject="agent:effect-001", tools={"provider.effect-001.chat"}, targets={ENDPOINT}
    )
    references = []
    error_type = None
    selected = (
        plan.coordinates
        if not development
        else tuple(
            c
            for c in plan.coordinates
            if c.policy == "protected" and c.temperature == 0 and c.seed == 17
        )
    )
    for coordinate in selected:
        reference, record = await execute_run(
            plan=plan,
            coordinate=coordinate,
            model_path=models[coordinate.model],
            root=root,
            campaign=campaign,
            budget=budget,
            ledger=ledger,
            grant=grant,
            development=development,
        )
        references.append(reference)
        if record.error_type or not record.lifecycle.clean:
            error_type = record.error_type or "CleanupIncomplete"
            break
    index = EvaluationIndex(
        plan=plan_reference,
        runs=tuple(references),
        elapsed_seconds=monotonic() - started,
        error_type=error_type,
    )
    store = RunStore.create(root, "effect-001-report")
    store.write_json_create_only("index.json", index.model_dump(mode="json"))
    store.append_event("effectiveness.indexed", {"development": development})
    return seal_reference(store, "effect-001-report")
