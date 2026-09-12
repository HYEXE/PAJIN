"""Test CI ownership gates and evidence projection without claiming Linux probe execution."""

import json
import subprocess
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


@pytest.mark.parametrize("change", [None, "phase", "checks", "version", "oversize"])
def test_failed_ops_diagnostics_publish_only_observed_phase_and_count(tmp_path, change):
    report = dict(
        version="ops003-linux-rehearsal-v1",
        phase="source-postgres",
        checks=[],
        stderr="PRIVATE-CREDENTIAL-NEVER-PUBLISH",
    )
    if change == "oversize":
        report["stderr"] *= 5000
    elif change is not None:
        report[change] = "PRIVATE-CREDENTIAL-NEVER-PUBLISH"
    (tmp_path / "report.json").write_text(json.dumps(report))
    result = ci.failed_probe_observation("ops", tmp_path)
    assert result == (
        dict(observed_phase="source-postgres", completed_checks=0)
        if change is None
        else dict(observed_phase="unknown", completed_checks=None)
    )
    assert "PRIVATE" not in json.dumps(result)
    assert ci.failed_probe_observation("sys", tmp_path)["observed_phase"] == "unknown"


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


@pytest.mark.parametrize("incomplete", [False, True])
def test_ops004_requires_every_new_check_and_keeps_limits_explicit(tmp_path, incomplete):
    checks = sorted(ci.OPS004_CHECKS)
    if incomplete:
        checks.pop()
    report = dict(
        version="ops004-linux-rehearsal-v1",
        complete=True,
        checks_passed=True,
        cleanup="observed-absent",
        checks=checks,
        physical_separate_host_verified=False,
        anchor_volume_rollback_detected=False,
    )
    (tmp_path / "report.json").write_text(json.dumps(report))
    if incomplete:
        with pytest.raises(ValueError, match="incomplete"):
            ci.verify_probe("ops", tmp_path, extended=True)
    else:
        assert ci.verify_probe("ops", tmp_path, extended=True) == {
            "actual_checks": 15,
            "cleanup_observed": True,
        }
        report["physical_separate_host_verified"] = True
        (tmp_path / "report.json").write_text(json.dumps(report))
        with pytest.raises(ValueError, match="claims"):
            ci.verify_probe("ops", tmp_path, extended=True)


@pytest.mark.parametrize("second_exit", [0, 1])
def test_original_success_alone_cannot_complete_the_extended_workflow(
    tmp_path, monkeypatch, second_exit
):
    marker = {"head": "a" * 40, "source_sha256": "b" * 64}
    monkeypatch.setattr(ci, "admitted", lambda *args: marker)
    monkeypatch.setattr(ci, "source_digest", lambda: marker["source_sha256"])
    monkeypatch.setattr(ci, "image_record", lambda value: {"id": value, "platform": "linux/amd64"})
    monkeypatch.setattr(ci, "command", lambda *args: "sha256:" + "c" * 64)
    calls, verified = [], []

    def probe(args, **kwargs):
        calls.append(args)
        return subprocess.CompletedProcess(args, 0 if len(calls) == 1 else second_exit)

    def verify(boundary, private, *, extended=False):
        verified.append(extended)
        return {"actual_checks": 15 if extended else 11, "cleanup_observed": True}

    monkeypatch.setattr(ci.subprocess, "run", probe)
    monkeypatch.setattr(ci, "verify_probe", verify)
    monkeypatch.setattr(ci, "verify_witness_probe", lambda private: {"actual_checks": 21})
    assert ci.run("ops", tmp_path, "sha256:" + "d" * 64, "sha256:" + "e" * 64) == second_exit
    assert len(calls) == (3 if second_exit == 0 else 2)
    if second_exit == 0:
        assert "scripts.witness_checkpoint_rehearsal" in calls[2]
    assert "scripts.hybrid_operations_rehearsal" in calls[0]
    assert "scripts.independent_checkpoint_rehearsal" in calls[1]
    result = json.loads((tmp_path / "public-summary.json").read_text())
    assert result["complete"] is (second_exit == 0)
    assert verified == ([False, True] if second_exit == 0 else [False])


@pytest.mark.parametrize(
    "mutation",
    [
        None,
        "missing-check",
        "power-loss",
        "darwin",
        "cycles",
        "no-crash",
        "report-list",
        "probe-list",
    ],
)
def test_ops005_requires_observed_linux_crash_and_all_witness_checks(tmp_path, mutation):
    report = dict(
        version="ops005-linux-rehearsal-v1",
        complete=True,
        checks_passed=True,
        cleanup="observed-absent",
        checks=sorted(ci.OPS005_CHECKS),
        anchor_volume_rollback_detected=True,
        physical_separate_host_verified=False,
        simultaneous_store_rollback_detected=False,
        power_loss_verified=False,
        production_failover_verified=False,
    )
    probe = dict(
        version="ops005-process-crash-v1",
        complete=True,
        system="Linux",
        cycles=32,
        sigkill_after_witness_fsync=True,
        stale_head_denied=True,
        original_retained=True,
        physical_host_failure_verified=False,
        power_loss_verified=False,
    )
    if mutation == "missing-check":
        report["checks"].pop()
    elif mutation == "power-loss":
        report["power_loss_verified"] = True
    elif mutation == "darwin":
        probe["system"] = "Darwin"
    elif mutation == "cycles":
        probe["cycles"] = True
    elif mutation == "no-crash":
        probe["sigkill_after_witness_fsync"] = False
    (tmp_path / "report.json").write_text(json.dumps([] if mutation == "report-list" else report))
    (tmp_path / "process-crash.json").write_text(
        json.dumps([] if mutation == "probe-list" else probe)
    )
    if mutation is None:
        assert ci.verify_witness_probe(tmp_path) == {
            "actual_checks": 21,
            "process_restart_cycles": 32,
            "cleanup_observed": True,
        }
    else:
        with pytest.raises(ValueError, match="OPS-005"):
            ci.verify_witness_probe(tmp_path)


@pytest.mark.parametrize("mutation", [None, "mismatch", "missing", "process-claim", "boolean"])
def test_sys004_requires_independent_coreutils_agreement(tmp_path, mutation):
    metadata = {"randomizeVaSpace": 2}
    evidence = dict(
        metadata=metadata,
        bytes=[50, 10],
        implementation="od (GNU coreutils) 9.7",
        match=True,
        physicalHostVerified=False,
        processAslrVerified=False,
    )
    comparison = dict(
        version="pajin.sys-004.reexecution-report/v1",
        complete=True,
        aslrMatch=True,
        source={"aslr": {"metadata": metadata}},
        replay={"aslr": {"metadata": metadata}},
    )
    if mutation == "mismatch":
        comparison["replay"]["aslr"]["metadata"] = {"randomizeVaSpace": 1}
    elif mutation == "missing":
        del comparison["source"]
    elif mutation == "process-claim":
        evidence["processAslrVerified"] = True
    elif mutation == "boolean":
        evidence["metadata"] = {"randomizeVaSpace": True}
    (tmp_path / "independent-coreutils.json").write_text(json.dumps(evidence))
    (tmp_path / "fresh-process-report.json").write_text(json.dumps(comparison))
    if mutation is None:
        ci._verify_aslr_independent(tmp_path)
    else:
        with pytest.raises(ValueError):
            ci._verify_aslr_independent(tmp_path)


def test_sys004_image_and_residue_are_required_by_the_saved_workflow():
    workflow = yaml.safe_load(Path(".github/workflows/sys-002-conformance.yml").read_text())
    scripts = "\n".join(step.get("run", "") for step in workflow["jobs"]["conformance"]["steps"])
    assert "containers/system-aslr/Dockerfile" in scripts
    assert '--additional-image "$additional_image"' in scripts
    assert "pajin.sys004-owner" in ci.LABELS["sys"]
