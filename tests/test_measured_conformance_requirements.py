from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/measured_conformance.py"
spec = importlib.util.spec_from_file_location("measured_conformance", SCRIPT)
assert spec is not None and spec.loader is not None
selector = importlib.util.module_from_spec(spec)
spec.loader.exec_module(selector)


@pytest.mark.parametrize(
    ("paths", "expected"),
    [
        (["docs/adr/0260-example.md", "README.md"], ()),
        (["containers/ai-target/requirements.lock"], ("ai",)),
        (["containers/network-banner-emitter/banner_emitter.py"], ("network",)),
        (["containers/bug-bounty-target/target.py"], ("web",)),
        (["containers/benchmark-worker/worker_entry.py"], ("web",)),
        ([".github/workflows/ai-002d-conformance.yml"], ("ai",)),
        (["containers/worker/worker_entry.py"], ("web", "network", "ai")),
        (["containers/egress-proxy/proxy.py"], ("web", "network", "ai")),
        (["src/pajin/workflow/ai_measured_product_reader.py"], ("web", "network", "ai")),
        (["uv.lock"], ("web", "network", "ai")),
        (["unknown/new-verifier.yaml"], ("web", "network", "ai")),
        (["docs/contracts/new-contract.json"], ("web", "network", "ai")),
    ],
)
def test_change_requirements_preserve_common_boundary(
    paths: list[str], expected: tuple[str, ...]
) -> None:
    assert selector.required_domains(paths, complete_comparison=True) == expected


def test_missing_comparison_never_removes_required_domains() -> None:
    assert selector.required_domains([], complete_comparison=False) == ("web", "network", "ai")


def test_working_tree_includes_deletions_and_untracked_files(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def commit(_root: Path, ref: str) -> str:
        return "b" * 40 if ref == "base" else "a" * 40

    def git(_root: Path, *arguments: str) -> bytes:
        if arguments[0] == "diff":
            assert "--no-renames" in arguments
            return b"containers/ai-target/target.py\0containers/network-banner-emitter/old.py\0"
        if arguments[0] == "ls-files":
            assert arguments == ("ls-files", "--others", "--exclude-standard", "-z")
            return b"docs/new.md\0"
        assert arguments == ("status", "--porcelain=v1", "--untracked-files=all")
        return b" M containers/ai-target/target.py\n"

    monkeypatch.setattr(selector, "_commit", commit)
    monkeypatch.setattr(selector, "_git", git)
    plan = selector.build_plan(ROOT, base="base", head="HEAD", include_working_tree=True)
    assert plan["requiredDomains"] == ["network", "ai"]
    assert plan["changedPaths"] == [
        "containers/ai-target/target.py", "containers/network-banner-emitter/old.py", "docs/new.md"
    ]
    assert plan["workingTreeIncluded"] is True
    assert plan["workingTreeClean"] is False
    assert plan["verificationStatus"] == "not-executed"
    assert plan["dispatchAuthorized"] is False
    assert "Commit these changes" in selector._summary(plan)


def test_read_only_cli_distinguishes_missing_baseline_from_invalid_head() -> None:
    command = [sys.executable, str(SCRIPT), "--base", "0" * 40]
    result = subprocess.run(
        command, cwd=ROOT, capture_output=True, text=True, timeout=30, check=False
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["comparison"] == "baseline-unavailable"
    assert report["requiredDomains"] == ["web", "network", "ai"]
    assert report["verificationStatus"] == "not-executed"
    invalid = subprocess.run(
        [*command, "--head", "0" * 40],
        cwd=ROOT, capture_output=True, text=True, timeout=30, check=False,
    )
    assert invalid.returncode == 2
    assert not invalid.stdout
