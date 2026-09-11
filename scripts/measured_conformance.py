"""Report measured Docker rerun requirements; never dispatch or certify a workflow."""

from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

DOMAINS = ("web", "network", "ai")
WORKFLOWS = {domain: f".github/workflows/{domain}-002d-conformance.yml" for domain in DOMAINS}
OPERATIONAL_WORKFLOWS = {
    "ops": ".github/workflows/ops-003-conformance.yml",
    "sys": ".github/workflows/sys-002-conformance.yml",
}
TARGET_CONTEXTS = {
    "containers/bug-bounty-target/": "web",
    "containers/benchmark-worker/": "web",
    "containers/network-banner-emitter/": "network",
    "containers/ai-target/": "ai",
}
ROOT_DOCUMENTS = {
    "AGENTS.md",
    "PLAN.md",
    "HANDOFF.md",
    "DECISIONS.md",
    "KNOWN_ISSUES.md",
    "README.md",
    "LICENSE",
}


def required_domains(paths: list[str], *, complete_comparison: bool) -> tuple[str, ...]:
    """Narrow only known container contexts or a domain's own workflow."""
    if not complete_comparison:
        return DOMAINS
    required: set[str] = set()
    for path in paths:
        if path in ROOT_DOCUMENTS or (path.startswith("docs/") and path.endswith(".md")):
            continue
        workflow_domain = next(
            (domain for domain, workflow in WORKFLOWS.items() if path == workflow), None
        )
        target_domain = next(
            (domain for prefix, domain in TARGET_CONTEXTS.items() if path.startswith(prefix)),
            None,
        )
        if domain := workflow_domain or target_domain:
            required.add(domain)
        else:
            required.update(DOMAINS)
    return tuple(domain for domain in DOMAINS if domain in required)


def required_operational_boundaries(
    paths: list[str],
    *,
    complete_comparison: bool,
) -> tuple[str, ...]:
    """Add OPS/SYS gates without changing the legacy domain report or its requirements."""
    if not complete_comparison:
        return tuple(OPERATIONAL_WORKFLOWS)
    required: set[str] = set()
    for path in paths:
        if path in ROOT_DOCUMENTS or (path.startswith("docs/") and path.endswith(".md")):
            continue
        selected = next(
            (name for name, workflow in OPERATIONAL_WORKFLOWS.items() if path == workflow),
            None,
        )
        if selected is not None:
            required.add(selected)
        elif path not in WORKFLOWS.values() and not any(
            path.startswith(prefix) for prefix in TARGET_CONTEXTS
        ):
            required.update(OPERATIONAL_WORKFLOWS)
    return tuple(name for name in OPERATIONAL_WORKFLOWS if name in required)


def _git(root: Path, *arguments: str) -> bytes:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        capture_output=True,
        timeout=30,
    ).stdout


def _commit(root: Path, reference: str) -> str:
    return (
        _git(root, "rev-parse", "--verify", "--end-of-options", f"{reference}^{{commit}}")
        .decode()
        .strip()
    )


def _paths(raw: bytes) -> list[str]:
    return [item.decode("utf-8", errors="surrogateescape") for item in raw.split(b"\0") if item]


def build_plan(
    root: Path, *, base: str | None, head: str, include_working_tree: bool
) -> dict[str, object]:
    head_commit = _commit(root, head)
    current_commit = _commit(root, "HEAD")
    if include_working_tree and current_commit != head_commit:
        raise ValueError("working-tree comparison requires the current HEAD")
    base_commit = None
    if base:
        try:
            base_commit = _commit(root, base)
        except subprocess.CalledProcessError:
            base_commit = None
    paths: list[str] = []
    if base_commit is not None:
        paths.extend(
            _paths(
                _git(
                    root,
                    "diff",
                    "--no-renames",
                    "--name-only",
                    "-z",
                    base_commit,
                    head_commit,
                    "--",
                )
            )
        )
    if include_working_tree:
        paths.extend(
            _paths(_git(root, "diff", "--no-renames", "--name-only", "-z", head_commit, "--"))
        )
        paths.extend(_paths(_git(root, "ls-files", "--others", "--exclude-standard", "-z")))
    paths = sorted(set(paths))
    domains = required_domains(paths, complete_comparison=base_commit is not None)
    operational = required_operational_boundaries(
        paths,
        complete_comparison=base_commit is not None,
    )
    return {
        "schemaVersion": 1,
        "kind": "MeasuredConformanceRequirements",
        "baseCommit": base_commit,
        "headCommit": head_commit,
        "comparison": "complete" if base_commit is not None else "baseline-unavailable",
        "workingTreeIncluded": include_working_tree,
        "workingTreeClean": not _git(root, "status", "--porcelain=v1", "--untracked-files=all"),
        "changedPaths": paths,
        "requiredDomains": list(domains),
        "requiredWorkflows": [WORKFLOWS[domain] for domain in domains],
        "requiredOperationalBoundaries": list(operational),
        "requiredOperationalWorkflows": [OPERATIONAL_WORKFLOWS[name] for name in operational],
        "verificationStatus": "not-executed",
        "dispatchAuthorized": False,
    }


def _summary(plan: dict[str, object]) -> str:
    lines = [
        "### Measured Docker conformance requirements",
        "",
        f"Commit: `{plan['headCommit']}`. Comparison: `{plan['comparison']}`.",
        f"Working tree included: `{plan['workingTreeIncluded']}`; "
        f"clean: `{plan['workingTreeClean']}`.",
        "",
    ]
    domains = plan["requiredDomains"]
    assert isinstance(domains, list)
    if domains:
        lines.extend(f"- `{WORKFLOWS[domain]}`" for domain in domains)
    else:
        lines.append("No measured Docker rerun required by this path comparison.")
    operational = plan["requiredOperationalWorkflows"]
    assert isinstance(operational, list)
    lines.extend(f"- `{workflow}`" for workflow in operational)
    lines.extend(
        [
            "",
            "This is a requirements report, not conformance evidence or dispatch authorization.",
            "Required workflows must pass for this exact clean commit, including residue checks.",
        ]
    )
    if plan["workingTreeIncluded"] and not plan["workingTreeClean"]:
        lines.append(
            "Commit these changes and recompute requirements before exact-commit validation."
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base", help="Last compared commit; unavailable baseline requires all domains"
    )
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--include-working-tree", action="store_true")
    parser.add_argument("--format", choices=("json", "summary"), default="json")
    args = parser.parse_args()
    try:
        root = Path(_git(Path.cwd(), "rev-parse", "--show-toplevel").decode().strip())
        plan = build_plan(
            root, base=args.base, head=args.head, include_working_tree=args.include_working_tree
        )
    except (OSError, subprocess.SubprocessError, ValueError):
        parser.exit(2, "Cannot determine conformance requirements from the requested Git state.\n")
    print(_summary(plan) if args.format == "summary" else json.dumps(plan, indent=2))


if __name__ == "__main__":
    main()
