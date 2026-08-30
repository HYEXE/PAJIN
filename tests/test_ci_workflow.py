from pathlib import Path

import yaml

_WORKFLOW = Path(__file__).parents[1] / ".github" / "workflows" / "web-002d-conformance.yml"


def _ci_workflow() -> dict[str, object]:
    value = yaml.load(_WORKFLOW.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict)
    return value


def test_web_002d_conformance_is_manual_and_opt_in() -> None:
    workflow = _ci_workflow()
    triggers = workflow["on"]
    assert isinstance(triggers, dict)
    dispatch = triggers["workflow_dispatch"]
    assert isinstance(dispatch, dict)
    inputs = dispatch["inputs"]
    assert isinstance(inputs, dict)
    assert set(triggers) == {"workflow_dispatch"}
    conformance_input = inputs["confirm_web_002d_conformance"]
    assert isinstance(conformance_input, dict)
    assert conformance_input["default"] == "false"
    assert conformance_input["required"] == "true"
    assert conformance_input["type"] == "boolean"

    assert workflow["permissions"] == {"contents": "read"}
    concurrency = workflow["concurrency"]
    assert isinstance(concurrency, dict)
    assert concurrency == {
        "group": "web-002d-conformance-${{ github.ref }}",
        "cancel-in-progress": "false",
    }

    jobs = workflow["jobs"]
    assert isinstance(jobs, dict)
    job = jobs["conformance"]
    assert isinstance(job, dict)
    assert "if" not in job
    assert job["timeout-minutes"] == "60"
    assert job["runs-on"] == "ubuntu-24.04"


def test_web_002d_conformance_builds_and_runs_the_exact_boundary() -> None:
    workflow = _ci_workflow()
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
        "CONFIRM_WEB_002D_CONFORMANCE": "${{ inputs.confirm_web_002d_conformance }}"
    }
    assert confirmation["run"] == 'test "$CONFIRM_WEB_002D_CONFORMANCE" = "true"'

    checkout = named_steps["Check out repository"]
    assert checkout["uses"] == "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
    assert checkout["with"] == {"persist-credentials": "false"}
    setup_python = named_steps["Set up Python"]
    assert setup_python["uses"] == "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97"
    setup_uv = named_steps["Set up uv"]
    assert setup_uv["uses"] == "astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990"
    runtime_context = named_steps["Record runtime context"]["run"]
    assert isinstance(runtime_context, str)
    assert "git rev-parse HEAD" in runtime_context
    assert "python --version" in runtime_context
    assert "docker version" in runtime_context
    assert "runner_image_version" in runtime_context

    build = named_steps["Build exact repository images"]["run"]
    assert isinstance(build, str)
    assert build.count("--platform linux/amd64") == 4
    assert build.count("docker build --pull") == 4
    for image, context in (
        ("pajin-bug-bounty-target:dev", "containers/bug-bounty-target"),
        ("pajin-benchmark-worker:dev", "containers/benchmark-worker"),
        ("pajin-worker:dev", "containers/worker"),
        ("pajin-egress-proxy:dev", "containers/egress-proxy"),
    ):
        assert f"--tag {image} {context}" in build

    job_env = job["env"]
    assert isinstance(job_env, dict)
    zap_digest = job_env["ZAP_REGISTRY_DIGEST"]
    assert zap_digest == ("sha256:71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa")
    pull = named_steps["Pull the digest-pinned ZAP image"]["run"]
    assert isinstance(pull, str)
    expected_pull = (
        'docker pull --platform linux/amd64 "ghcr.io/zaproxy/zaproxy@${ZAP_REGISTRY_DIGEST}"'
    )
    assert expected_pull in pull
    assert 'docker tag "$zap_image_id" ghcr.io/zaproxy/zaproxy:stable' in pull

    identities = named_steps["Record exact image identities"]["run"]
    assert isinstance(identities, str)
    assert identities.count("Id={{.Id}}") == 5
    assert identities.count("RepoDigests={{json .RepoDigests}}") == 5
    assert identities.count("Platform={{.Os}}/{{.Architecture}}") == 5

    conformance = named_steps["Run WEB-002D conformance"]
    assert conformance["env"] == {"PAJIN_TEST_DOCKER_WEB_002D": "1"}
    assert (
        "tests/test_web_controlled_validation_docker.py::"
        "test_real_docker_web_002d_controlled_validation_conformance" in conformance["run"]
    )

    residue = named_steps["Require zero PAJIN Docker residue"]
    assert residue["if"] == "${{ always() }}"
    residue_run = residue["run"]
    assert isinstance(residue_run, str)
    assert "set -euo pipefail" in residue_run
    assert residue_run.count('="$(docker ') == 6
    expected_queries = {
        "benchmark_containers": (
            "container ls --all --quiet --filter label=pajin.benchmark.managed=true"
        ),
        "benchmark_networks": ("network ls --quiet --filter label=pajin.benchmark.managed=true"),
        "execution_containers": ("container ls --all --quiet --filter label=pajin.execution-id"),
        "execution_networks": "network ls --quiet --filter label=pajin.execution-id",
        "named_containers": ("container ls --all --quiet --filter name=^/pajin-bench-"),
        "named_networks": "network ls --quiet --filter name=^pajin-bench-",
    }
    for variable, arguments in expected_queries.items():
        assert f'{variable}="$(docker {arguments})"' in residue_run
    assert (
        'residue="${benchmark_containers}${benchmark_networks}${execution_containers}"'
        in residue_run
    )
    assert 'residue+="${execution_networks}${named_containers}${named_networks}"' in residue_run
    assert 'if [[ -n "$residue" ]]; then' in residue_run
    assert "exit 1" in residue_run
