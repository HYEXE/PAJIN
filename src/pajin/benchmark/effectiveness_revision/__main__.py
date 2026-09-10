"""Freeze private EFFECT-003 input, run the fixed local matrix, or verify a paired report."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from pajin.benchmark.effectiveness.evidence import (
    EvaluationIndex,
    RunRecord,
    RunReference,
    read_artifact,
    require_output_outside_runs,
    verify_retained_sources,
)
from pajin.benchmark.effectiveness.suite import PLATFORM_MANIFESTS, RuntimePin
from pajin.benchmark.effectiveness_revision.evidence import (
    export_comparison,
    recompute_comparison,
)
from pajin.benchmark.effectiveness_revision.plan import ComparisonPlan, ComparisonSuite
from pajin.benchmark.effectiveness_revision.runner import freeze_comparison, run_comparison


def smoke_succeeded(root: Path, reference: RunReference) -> bool:
    index = EvaluationIndex.model_validate_json(read_artifact(root, reference, "index.json"))
    plan = ComparisonPlan.model_validate_json(read_artifact(root, index.plan, "plan.json"))
    expected = [
        coordinate
        for coordinate in plan.coordinates
        if coordinate.policy == "protected"
        and coordinate.temperature == 0
        and coordinate.seed == 17
    ]
    if index.error_type or len(index.runs) != len(expected):
        return False
    for ref, coordinate in zip(index.runs, expected, strict=True):
        run = RunRecord.model_validate_json(read_artifact(root, ref, "run.json"))
        verify_retained_sources(root, ref, plan, run)
        if (
            run.mode != "development"
            or run.coordinate != coordinate
            or run.error_type
            or not run.lifecycle.healthy
            or not run.lifecycle.clean
            or len(run.trials) != 2
            or any(trial.error_type or trial.receipt is None for trial in run.trials)
        ):
            return False
    return True


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("freeze", "smoke", "run", "report"))
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--reference", type=Path)
    parser.add_argument("--corpus", type=Path)
    parser.add_argument("--development-root", type=Path)
    parser.add_argument("--development-reference", type=Path)
    parser.add_argument("--platform", choices=tuple(PLATFORM_MANIFESTS), default="linux/arm64")
    parser.add_argument("--worker-image")
    parser.add_argument("--proxy-image")
    parser.add_argument("--qwen-model", type=Path)
    parser.add_argument("--smol-model", type=Path)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("output already exists")
    try:
        require_output_outside_runs(args.root, args.output)
    except ValueError as exc:
        parser.error(str(exc))
    if args.operation == "freeze":
        if not all(
            (
                args.corpus,
                args.development_root,
                args.development_reference,
                args.worker_image,
                args.proxy_image,
            )
        ):
            parser.error("freeze requires private corpus, development reference/root and image IDs")
        reference = freeze_comparison(
            args.root,
            RuntimePin.model_validate(
                {
                    "platform": args.platform,
                    "platform_manifest": PLATFORM_MANIFESTS[args.platform],
                    "worker_image": args.worker_image,
                    "proxy_image": args.proxy_image,
                }
            ),
            ComparisonSuite.model_validate_json(args.corpus.read_bytes()),
            development_root=args.development_root,
            development_reference=RunReference.model_validate_json(
                args.development_reference.read_bytes()
            ),
        )
    else:
        if args.reference is None:
            parser.error("operation requires a pinned reference")
        reference = RunReference.model_validate_json(args.reference.read_bytes())
        if args.operation == "report":
            if not export_comparison(args.root, reference, args.output):
                raise SystemExit(2)
            return
        if args.qwen_model is None or args.smol_model is None:
            parser.error("run and smoke require both pinned local model files")
        reference = asyncio.run(
            run_comparison(
                root=args.root,
                reference=reference,
                model_paths={"qwen3-4b": args.qwen_model, "smollm2-1.7b": args.smol_model},
                development=args.operation == "smoke",
            )
        )
    with args.output.open("x", encoding="utf-8") as stream:
        stream.write(reference.model_dump_json(indent=2) + "\n")
    print(reference.model_dump_json())
    if args.operation == "smoke" and not smoke_succeeded(args.root, reference):
        raise SystemExit(2)
    if (
        args.operation == "run"
        and recompute_comparison(args.root, reference)["complete"] is not True
    ):
        raise SystemExit(2)


if __name__ == "__main__":
    main()
