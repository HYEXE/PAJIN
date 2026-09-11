"""Test CI ownership gates and evidence projection without claiming Linux probe execution."""

import json
from pathlib import Path

import pytest
import yaml

from scripts import linux_boundary_conformance as ci
from scripts import measured_conformance as selector


@pytest.mark.parametrize("setting", ["local", "self-hosted", "wrong-sha"])
def test_ci_gate_never_admits_local_or_mismatched_runner(monkeypatch, setting):
    monkeypatch.setattr(ci.platform, "system", lambda: "Linux")
    monkeypatch.setenv("GITHUB_ACTIONS", "false" if setting == "local" else "true")
    monkeypatch.setenv(
        "RUNNER_ENVIRONMENT", "self-hosted" if setting == "self-hosted" else "github-hosted"
    )
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    calls = []
    monkeypatch.setattr(ci, "command", lambda *args: calls.append(args) or "b" * 40)
    with pytest.raises(ValueError):
        ci.require_host()
    assert all(args == ("git", "rev-parse", "HEAD") for args in calls)


def test_preexisting_resources_deny_cleanup_admission(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "require_host", lambda: "a" * 40)
    monkeypatch.setattr(ci, "command", lambda *args: "")
    monkeypatch.setattr(ci, "residue", lambda family: {"container": ["existing-service"]})
    state = tmp_path / "ci"
    with pytest.raises(ValueError, match="cleanup is not authorized"):
        ci.preflight("ops", state)
    assert not state.exists()
    assert ci.cleanup("ops", state, audit_only=False) == 0


def test_cleanup_continues_after_one_failure_and_does_not_report_success(tmp_path, monkeypatch):
    (tmp_path / "preflight.json").write_text("{}")
    monkeypatch.setattr(ci, "admitted", lambda *args: {})
    before = {"container": ["container-a", "container-b"], "network": ["network-a"], "volume": []}
    observations = iter([before, {kind: [] for kind in ci.KINDS}])
    monkeypatch.setattr(ci, "residue", lambda family: next(observations))
    removed = []

    def command(*args):
        removed.append(args)
        if args[-1] == "container-a":
            raise RuntimeError("private diagnostic")
        return ""

    monkeypatch.setattr(ci, "command", command)
    assert ci.cleanup("ops", tmp_path, audit_only=False) == 1
    assert [args[-1] for args in removed] == ["container-a", "container-b", "network-a"]
    public = (tmp_path / "public-cleanup.json").read_text()
    assert "private diagnostic" not in public and "container-a" not in public
    assert not json.loads(public)["complete"]


def test_independent_audit_never_removes_resources(tmp_path, monkeypatch):
    (tmp_path / "preflight.json").write_text("{}")
    monkeypatch.setattr(ci, "admitted", lambda *args: {})
    monkeypatch.setattr(
        ci, "residue", lambda family: {"container": ["still-alive"], "network": [], "volume": []}
    )
    removed = []
    monkeypatch.setattr(ci, "command", lambda *args: removed.append(args) or "")
    assert ci.cleanup("sys", tmp_path, audit_only=True) == 1
    assert removed == []
    assert not json.loads((tmp_path / "public-residue.json").read_text())["complete"]


def test_removed_fallback_residue_still_fails_conformance(tmp_path, monkeypatch):
    (tmp_path / "preflight.json").write_text("{}")
    monkeypatch.setattr(ci, "admitted", lambda *args: {})
    observations = iter(
        [
            {"container": ["owned"], "network": [], "volume": []},
            {kind: [] for kind in ci.KINDS},
        ]
    )
    monkeypatch.setattr(ci, "residue", lambda family: next(observations))
    monkeypatch.setattr(ci, "command", lambda *args: "")
    assert ci.cleanup("sys", tmp_path, audit_only=False) == 1
    public = json.loads((tmp_path / "public-cleanup.json").read_text())
    assert public["resources_absent"] is True and public["complete"] is False
    assert public["fallback_needed"] is True


def test_repeated_execution_cannot_reuse_admitted_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "admitted", lambda *args: {})
    (tmp_path / "private-runner.log").touch()
    with pytest.raises(ValueError, match="fresh workflow"):
        ci.run("sys", tmp_path, "a" * 64, "b" * 64)


@pytest.mark.parametrize(
    "report", [[], None, {"complete": True, "checks": [{}]}, {"complete": True, "cleanup": None}]
)
@pytest.mark.parametrize("boundary", ["ops", "sys"])
def test_malformed_reports_remain_bounded_failures(tmp_path, report, boundary):
    (tmp_path / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="incomplete"):
        ci.verify_probe(boundary, tmp_path)


def test_cleanup_marker_is_bound_to_the_current_attempt(tmp_path, monkeypatch):
    monkeypatch.setattr(ci, "require_host", lambda: "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    (tmp_path / "preflight.json").write_text(
        json.dumps(
            dict(version=1, boundary="ops", head="a" * 40, empty=True, run_id="42", attempt="1")
        )
    )
    with pytest.raises(ValueError, match="attempt"):
        ci.admitted("ops", tmp_path)


def test_ops_summary_requires_all_actual_checks_and_omits_private_fields(tmp_path):
    report = dict(
        complete=True,
        checks_passed=True,
        cleanup="observed-absent",
        checks=sorted(ci.OPS_CHECKS),
        private_key="PRIVATE-NEVER-EXPORT",
    )
    (tmp_path / "report.json").write_text(json.dumps(report))
    summary = ci.verify_probe("ops", tmp_path)
    assert summary == dict(actual_checks=11, cleanup_observed=True)
    report["checks"].pop()
    (tmp_path / "report.json").write_text(json.dumps(report))
    with pytest.raises(ValueError, match="incomplete"):
        ci.verify_probe("ops", tmp_path)


@pytest.mark.parametrize("log", ["1 skipped in 0.01s\n", "1 passed, 1 failed in 0.01s\n", ""])
def test_sys_cannot_promote_skipped_missing_or_failed_pytest(tmp_path, log):
    (tmp_path / "report.json").write_text(
        json.dumps(
            dict(
                complete=True,
                exitCode=0,
                sourceUnchanged=True,
                cleanup=dict(
                    ownedAgentContainersAbsent=True,
                    workerAndProxyResourcesAbsent=True,
                    independentObserver=True,
                    observedWorkerExecutions=4,
                ),
            )
        )
    )
    (tmp_path / "pytest.log").write_text(log)
    with pytest.raises(ValueError, match="pytest"):
        ci.verify_probe("sys", tmp_path)
    (tmp_path / "pytest.log").write_text("1 passed in 32.19s\n")
    assert ci.verify_probe("sys", tmp_path)["actual_tests_passed"] == 1


@pytest.mark.parametrize("family,number", [("ops", "003"), ("sys", "002")])
def test_workflows_bind_commit_and_always_cleanup_without_exporting_raw_runs(family, number):
    path = Path(f".github/workflows/{family}-{number}-conformance.yml")
    workflow = yaml.safe_load(path.read_text())
    dispatch = workflow[True]["workflow_dispatch"]["inputs"]
    assert dispatch[f"confirm_{family}_{number}_conformance"]["default"] is False
    assert dispatch["expected_commit"]["required"] is True
    assert workflow["permissions"] == {"contents": "read"}
    job = workflow["jobs"]["conformance"]
    assert job["runs-on"] == "ubuntu-24.04"
    steps = job["steps"]
    for step in steps:
        if step["name"] in {
            "Clean admitted owned resources even after failure",
            "Independently require zero residue",
        }:
            assert step["if"] == "${{ always() }}"
        if "uses" in step:
            assert len(step["uses"].split("@")[-1]) == 40
    assert 'test "$GITHUB_SHA" = "$EXPECTED_COMMIT"' in steps[0]["run"]
    artifact = steps[-1]["with"]
    assert artifact["path"].splitlines() == [
        f".pajin/ci-{family}/public-{kind}.json" for kind in ("summary", "cleanup", "residue")
    ]


@pytest.mark.parametrize(
    "paths,expected",
    [
        (["PLAN.md"], ()),
        (["containers/ai-target/server.py"], ()),
        (["src/pajin/operations/hybrid.py"], ("ops", "sys")),
        (["scripts/linux_boundary_conformance.py"], ("ops", "sys")),
        ([".github/workflows/ops-003-conformance.yml"], ("ops",)),
        ([".github/workflows/sys-002-conformance.yml"], ("sys",)),
    ],
)
def test_operational_workflows_are_additive_to_existing_domain_requirements(paths, expected):
    assert selector.required_operational_boundaries(paths, complete_comparison=True) == expected
    if expected:
        assert selector.required_domains(paths, complete_comparison=True) == (
            "web",
            "network",
            "ai",
        )
    assert selector.required_operational_boundaries([], complete_comparison=False) == ("ops", "sys")
