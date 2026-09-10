"""Read sealed SYS-002 results with an independently pinned deployment trust document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pajin.runtime.safe_files import load_bounded_strict_json
from pajin.system_read.models import SystemRunReference
from pajin.system_read.report import SystemReportTrust, compare_system_runs, read_system_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--trust-digest", required=True)
    parser.add_argument("--source-ref", required=True, type=Path)
    parser.add_argument("--replay-ref", type=Path)
    args = parser.parse_args()
    trust = SystemReportTrust.model_validate(
        load_bounded_strict_json(
            args.trust, max_bytes=1024 * 1024, label="SYS-002 independent deployment trust"
        )
    )
    if trust.commitment != args.trust_digest:
        raise ValueError("SYS-002 deployment trust differs from its independent digest")
    source = SystemRunReference.model_validate(
        load_bounded_strict_json(
            args.source_ref, max_bytes=2048, label="SYS-002 source Run reference"
        )
    )
    if args.replay_ref is not None:
        replay = SystemRunReference.model_validate(
            load_bounded_strict_json(
                args.replay_ref, max_bytes=2048, label="SYS-002 replay Run reference"
            )
        )
        result = compare_system_runs(args.root, source, replay, trust)
    else:
        result = read_system_run(args.root, source, trust)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
