"""Local operator entry point: freeze, smoke, run, and verify a pinned report."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    EvaluationPlan,
    RunRecord,
    RunReference,
    export_report,
    read_artifact,
    recompute_report,
    require_output_outside_runs,
    verify_retained_sources,
)
from pajin.benchmark.effectiveness.runner import freeze_plan, run_evaluation
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin


def smoke_succeeded(root: Path, reference: RunReference) -> bool:
    index = EvaluationIndex.model_validate_json(read_artifact(root, reference, "index.json"))
    plan = EvaluationPlan.model_validate_json(read_artifact(root, index.plan, "plan.json"))
    if index.error_type is not None or len(index.runs) != 2:
        return False
    for run_ref in index.runs:
        run = RunRecord.model_validate_json(read_artifact(root, run_ref, "run.json"))
        verify_retained_sources(root, run_ref, plan, run)
        if (
            run.mode != "development"
            or run.error_type is not None
            or not run.lifecycle.healthy
            or not run.lifecycle.clean
            or len(run.trials) != 2
            or any(t.error_type is not None or t.receipt is None for t in run.trials)
        ):
            return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("freeze", "smoke", "run", "report"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--platform", choices=tuple(PLATFORM_MANIFESTS), default="linux/arm64")
    parser.add_argument("--worker-image")
    parser.add_argument("--proxy-image")
    parser.add_argument("--qwen-model", type=Path)
    parser.add_argument("--smol-model", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists; choose a fresh destination")
    try:
        require_output_outside_runs(args.root, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    if args.operation == "freeze":
        if not args.worker_image or not args.proxy_image:
            parser.error("freeze requires immutable Worker and proxy image IDs")
        runtime = RuntimePin.model_validate(
            {
                "platform": args.platform,
                "platform_manifest": PLATFORM_MANIFESTS[args.platform],
                "worker_image": args.worker_image,
                "proxy_image": args.proxy_image,
            }
        )
        reference = freeze_plan(args.root, runtime)
    else:
        if args.reference is None:
            parser.error("operation requires a pinned Run reference")
        reference = RunReference.model_validate_json(args.reference.read_bytes())
        if args.operation == "report":
            if not export_report(args.root, reference, args.output):
                raise SystemExit(2)
            return
        if args.qwen_model is None or args.smol_model is None:
            parser.error("run and smoke require both pinned regular model files")
        reference = asyncio.run(
            run_evaluation(
                root=args.root,
                plan_reference=reference,
                model_paths={"qwen3-4b": args.qwen_model, "smollm2-1.7b": args.smol_model},
                development=args.operation == "smoke",
            )
        )
    with args.output.open("x", encoding="utf-8") as output:
        output.write(reference.model_dump_json(indent=2) + "\n")
    print(reference.model_dump_json())
    if args.operation == "smoke" and not smoke_succeeded(args.root, reference):
        raise SystemExit(2)
    if args.operation == "run" and recompute_report(args.root, reference)["complete"] is not True:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
