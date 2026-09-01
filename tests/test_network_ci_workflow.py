from pathlib import Path

import yaml

_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "network-002d-conformance.yml"


def _workflow() -> dict[str, object]:
    value = yaml.load(_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return value


def test_network_002d_conformance_is_manual_exact_commit_and_opt_in() -> None:
    workflow = _workflow()
    triggers = workflow["on"]
    assert isinstance(triggers, dict)
    assert set(triggers) == {"workflow_dispatch"}
    dispatch = triggers["workflow_dispatch"]
    assert isinstance(dispatch, dict)
    inputs = dispatch["inputs"]
    assert isinstance(inputs, dict)
    conformance_input = inputs["confirm_network_002d_conformance"]
    assert isinstance(conformance_input, dict)
    assert conformance_input == {
        "description": "Run the exact NET-002D real-Docker conformance",
        "required": "true",
        "default": "false",
        "type": "boolean",
    }
    assert workflow["permissions"] == {"contents": "read"}
    assert workflow["concurrency"] == {
        "group": "network-002d-conformance-${{ github.ref }}",
        "cancel-in-progress": "false",
    }

    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["conformance"]
    assert isinstance(job, dict)
    assert job["runs-on"] == "ubuntu-24.04"
    assert job["timeout-minutes"] == "60"
    assert "if" not in job
    steps = job["steps"]
    assert isinstance(steps, list)
    named_steps = {
        step["name"]: step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }
    exact = named_steps["Require exact clean commit"]["run"]
    assert isinstance(exact, str)
    assert 'test "$(git rev-parse HEAD)" = "$GITHUB_SHA"' in exact
    assert "git status --porcelain=v1 --untracked-files=all" in exact


def test_network_002d_conformance_builds_runs_and_audits_exact_boundary() -> None:
    workflow = _workflow()
    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["conformance"]
    assert isinstance(job, dict)
    steps = job["steps"]
    assert isinstance(steps, list)
    named_steps = {
        step["name"]: step
        for step in steps
        if isinstance(step, dict) and isinstance(step.get("name"), str)
    }

    confirmation = named_steps["Require explicit confirmation"]
    assert confirmation["env"] == {
        "CONFIRM_NETWORK_002D_CONFORMANCE": ("${{ inputs.confirm_network_002d_conformance }}")
    }
    assert confirmation["run"] == 'test "$CONFIRM_NETWORK_002D_CONFORMANCE" = "true"'
    assert named_steps["Check out repository"]["uses"] == (
        "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    )
    assert named_steps["Set up Python"]["uses"] == (
        "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    )
    assert named_steps["Set up uv"]["uses"] == (
        "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990"
    )

    build = named_steps["Build exact repository images"]["run"]
    assert isinstance(build, str)
    assert build.count("docker build --pull --platform linux/amd64") == 3
    for image, context in (
        ("pajin-network-banner-emitter:dev", "containers/network-banner-emitter"),
        ("pajin-worker:dev", "containers/worker"),
        ("pajin-egress-proxy:dev", "containers/egress-proxy"),
    ):
        assert f"--tag {image} {context}" in build

    identities = named_steps["Record exact image identities"]["run"]
    assert isinstance(identities, str)
    assert identities.count("Id={{.Id}}") == 3
    assert identities.count("RepoDigests={{json .RepoDigests}}") == 3
    assert identities.count("Platform={{.Os}}/{{.Architecture}}") == 3

    conformance = named_steps["Run NET-002D conformance"]
    assert conformance["env"] == {"PAJIN_NETWORK_002D_REAL_DOCKER": "1"}
    assert (
        "tests/test_network_measured_product_docker.py::"
        "test_real_docker_net_002d_exact_commit_product_conformance" in conformance["run"]
    )

    residue = named_steps["Require zero PAJIN Network Docker residue"]
    assert residue["if"] == "${{ always() }}"
    residue_run = residue["run"]
    assert isinstance(residue_run, str)
    assert "set -euo pipefail" in residue_run
    assert residue_run.count('="$(docker ') == 8
    for query in (
        "label=pajin.network-fixture.managed=true",
        "label=pajin.execution-id",
        "name=^/pajin-net-target-",
        "name=^pajin-net-target-net-",
        "name=^/pajin-proxy-",
        "name=^pajin-egress-",
    ):
        assert query in residue_run
    assert 'if [[ -n "$residue" ]]; then' in residue_run
    assert "exit 1" in residue_run
