"""Read sealed SYS-004 results with an independently pinned deployment trust document."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from pajin.runtime.safe_files import load_bounded_strict_json
from pajin.system_aslr.models import AslrRunReference
from pajin.system_aslr.report import AslrReportTrust, compare_aslr_runs, read_aslr_run


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--trust", required=True, type=Path)
    parser.add_argument("--trust-digest", required=True)
    parser.add_argument("--source-ref", required=True, type=Path)
    parser.add_argument("--replay-ref", type=Path)
    args = parser.parse_args()
    trust = AslrReportTrust.model_validate(
        load_bounded_strict_json(
            args.trust, max_bytes=1024 * 1024, label="SYS-004 independent deployment trust"
        )
    )
    if trust.commitment != args.trust_digest:
        raise ValueError("SYS-004 deployment trust differs from its independent digest")
    source = AslrRunReference.model_validate(
        load_bounded_strict_json(
            args.source_ref, max_bytes=2048, label="SYS-004 source Run reference"
        )
    )
    if args.replay_ref is not None:
        replay = AslrRunReference.model_validate(
            load_bounded_strict_json(
                args.replay_ref, max_bytes=2048, label="SYS-004 replay Run reference"
            )
        )
        result = compare_aslr_runs(args.root, source, replay, trust)
    else:
        result = read_aslr_run(args.root, source, trust)
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
