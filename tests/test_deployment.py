import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest


def _compose_service_block(compose: str, service: str) -> str:
    pattern = (
        rf"(?ms)^  {re.escape(service)}:\n(?P<body>.*?)"
        r"(?=^(?:  [a-z0-9][a-z0-9-]*:|[a-z][a-z0-9-]*:)\n|\Z)"
    )
    match = re.search(
        pattern,
        compose,
    )
    assert match is not None, f"missing Compose service: {service}"
    return match.group("body")


def test_control_plane_image_installs_only_hash_locked_dependencies() -> None:
    dockerfile = Path("containers/control-plane/Dockerfile").read_text(encoding="utf-8")
    lock = Path("containers/control-plane/requirements.lock").read_text(encoding="utf-8")

    assert (
        "pip install --require-hashes --only-binary=:all: -r /tmp/pajin-requirements.lock"
    ) in dockerfile
    assert 'pip install ".[control-plane]"' not in dockerfile
    assert "--hash=sha256:" in lock
    assert "fastapi==" in lock
    assert "sqlalchemy==" in lock
    assert "uvicorn==" in lock


def test_control_plane_dependency_export_matches_the_root_lock(tmp_path: Path) -> None:
    uv = Path(sys.executable).with_name("uv")
    assert uv.is_file(), "the development environment must include the locked uv executable"
    completed = subprocess.run(
        [
            str(uv),
            "export",
            "--cache-dir",
            str(tmp_path / "uv-cache"),
            "--frozen",
            "--no-dev",
            "--extra",
            "control-plane",
            "--no-emit-project",
            "--no-header",
            "--no-annotate",
            "--format",
            "requirements.txt",
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    expected = Path("containers/control-plane/requirements.lock").read_text(encoding="utf-8")
    assert completed.stdout == expected


def test_control_plane_commands_do_not_depend_on_unlocked_console_script_builds() -> None:
    dockerfile = Path("containers/control-plane/Dockerfile").read_text(encoding="utf-8")
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")

    assert 'CMD ["python", "-m", "pajin.control_plane"]' in dockerfile
    assert 'command: ["python", "-m", "pajin.control_plane.worker_main"]' in compose


def test_compose_separates_generic_and_replay_worker_credentials() -> None:
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    api = _compose_service_block(compose, "control-plane")
    generic_worker = _compose_service_block(compose, "worker-daemon")
    replay_worker = _compose_service_block(compose, "replay-worker")

    generic_token = re.search(r"^      PAJIN_CP_WORKER_TOKEN: (\S+)$", api, re.MULTILINE)
    replay_token = re.search(
        r"^      PAJIN_CP_REPLAY_WORKER_TOKEN: (\S+)$",
        api,
        re.MULTILINE,
    )
    assert generic_token is not None
    assert replay_token is not None
    assert generic_token.group(1) != replay_token.group(1)
    assert "PAJIN_CP_WORKER_SUBJECT: worker-service" in api
    assert "PAJIN_CP_REPLAY_WORKER_SUBJECT: replay-worker-service" in api
    assert (
        'PAJIN_CP_REPLAY_EXECUTOR_PROFILES: \'{"replay-worker-service":["kisa-exact-v1"]}\''
    ) in api
    assert '"worker-service":["kisa-exact-v1"]' not in api

    assert "PAJIN_CP_WORKER_TOKEN:" in generic_worker
    assert "PAJIN_CP_REPLAY_WORKER_TOKEN:" not in generic_worker
    assert "PAJIN_CP_REPLAY_WORKER_TOKEN:" in replay_worker
    assert "PAJIN_CP_WORKER_TOKEN:" not in replay_worker


def test_compose_marks_plaintext_control_plane_transport_as_lab_only() -> None:
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    generic_worker = _compose_service_block(compose, "worker-daemon")
    replay_worker = _compose_service_block(compose, "replay-worker")

    for worker in (generic_worker, replay_worker):
        assert "PAJIN_CP_URL: http://control-plane:8090" in worker
        assert 'PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB: "true"' in worker
    assert compose.count("Local Compose lab only; production PAJIN_CP_URL must use HTTPS.") == 2


def test_compose_status_paths_are_inside_private_worker_tmpfs() -> None:
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    generic_worker = _compose_service_block(compose, "worker-daemon")
    replay_worker = _compose_service_block(compose, "replay-worker")

    assert "PAJIN_DAEMON_STATUS_PATH: /tmp/pajin-worker-status.json" in generic_worker
    assert "PAJIN_REPLAY_STATUS_PATH: /tmp/pajin-replay-worker-status.json" in replay_worker
    for worker in (generic_worker, replay_worker):
        assert "- /tmp:uid=10001,gid=10001,mode=0750" in worker
        assert 'user: "10001:10001"' in worker


def test_compose_wires_the_dedicated_replay_process_and_staging_boundary() -> None:
    dockerfile = Path("containers/control-plane/Dockerfile").read_text(encoding="utf-8")
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    api = _compose_service_block(compose, "control-plane")
    replay_worker = _compose_service_block(compose, "replay-worker")
    replay_preflight = _compose_service_block(compose, "replay-runtime-preflight")

    assert "FROM runtime AS replay-worker" in dockerfile
    assert "COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker" in dockerfile
    assert (
        "COPY containers/control-plane/replay_runtime_preflight.py /app/replay_runtime_preflight.py"
    ) in dockerfile
    assert 'CMD ["python", "-m", "pajin.control_plane.replay_worker_main"]' in dockerfile
    assert "target: replay-worker" in replay_worker
    assert 'command: ["python", "-m", "pajin.control_plane.replay_worker_main"]' in replay_worker
    assert "PAJIN_REPLAY_EXECUTOR_PROFILE: kisa-exact-v1" in replay_worker
    assert "PAJIN_REPLAY_STAGING_ROOT: /var/lib/pajin/artifact-staging" in replay_worker
    assert "PAJIN_REPLAY_STATUS_PATH: /tmp/pajin-replay-worker-status.json" in replay_worker
    assert (
        'test: ["CMD", "python", "-m", "pajin.control_plane.replay_worker_health"]' in replay_worker
    )
    assert "- artifact-staging:/var/lib/pajin/artifact-staging" in replay_worker
    assert "- /var/run/docker.sock:/var/run/docker.sock:rw" in replay_worker
    assert "artifact-repository" not in replay_worker
    assert "- artifact-repository:/var/lib/pajin/artifact-repository" in api
    assert "replay-runtime-preflight:" in replay_worker
    assert 'command: ["python", "/app/replay_runtime_preflight.py"]' in replay_preflight
    assert "network_mode: none" in replay_preflight
    assert "- /var/run/docker.sock:/var/run/docker.sock:rw" in replay_preflight


def test_worker_image_builds_from_its_hash_lock_without_an_ignored_vendor_tree() -> None:
    dockerfile = Path("containers/worker/Dockerfile").read_text(encoding="utf-8")
    lock = Path("containers/worker/requirements.lock").read_text(encoding="utf-8")
    preparation = Path("scripts/prepare-worker-dependencies.ps1").read_text(encoding="utf-8")

    assert "COPY vendor/" not in dockerfile
    assert "PIP_NO_CACHE_DIR=1" in dockerfile
    assert "COPY requirements.lock /tmp/pajin-worker-requirements.lock" in dockerfile
    assert "--require-hashes" in dockerfile
    assert "--only-binary=:all:" in dockerfile
    assert "--hash=sha256:" in lock
    assert "pyjwt==2.13.0" in lock
    assert "pyjwt==2.12.1" not in lock
    assert "--universal" in preparation
    assert "--python-platform" not in preparation
    assert "x86_64-manylinux" not in preparation
    assert "sys_platform == 'win32'" in lock


def test_container_base_images_are_pinned_to_immutable_manifest_digests() -> None:
    dockerfiles = sorted(Path("containers").glob("*/Dockerfile"))
    assert dockerfiles
    for dockerfile in dockerfiles:
        declared_stages: set[str] = set()
        base_instructions = [
            line.strip()
            for line in dockerfile.read_text(encoding="utf-8").splitlines()
            if line.strip().startswith("FROM ")
        ]
        assert base_instructions
        for instruction in base_instructions:
            parts = instruction.split()
            assert len(parts) in {2, 4}, dockerfile
            base = parts[1]
            assert base in declared_stages or re.fullmatch(
                r"[^\s@]+@sha256:[a-f0-9]{64}",
                base,
            ), dockerfile
            if len(parts) == 4:
                assert parts[2] == "AS", dockerfile
                declared_stages.add(parts[3])

    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    assert re.search(
        r"image: postgres:17\.10-alpine@sha256:[a-f0-9]{64}",
        compose,
    )


def test_lab_compose_projects_are_isolated_and_use_init() -> None:
    compose_paths = [
        Path("containers/compose.ai-lab.yaml"),
        Path("containers/compose.bug-bounty-lab.yaml"),
        Path("containers/compose.ctf-web-lab.yaml"),
    ]
    project_names: set[str] = set()
    for path in compose_paths:
        compose = path.read_text(encoding="utf-8")
        name = re.search(r"^name: ([a-z0-9-]+)$", compose, re.MULTILINE)
        assert name is not None
        project_names.add(name.group(1))
        assert "    init: true" in compose
        assert "    driver: bridge" in compose
        assert '      - "127.0.0.1:' in compose
    assert len(project_names) == len(compose_paths)


def test_long_running_container_healthchecks_do_not_spawn_a_shell() -> None:
    healthchecked_images = [
        Path("containers/ai-target/Dockerfile"),
        Path("containers/bug-bounty-target/Dockerfile"),
        Path("containers/ctf-web-target/Dockerfile"),
        Path("containers/egress-proxy/Dockerfile"),
    ]
    for path in healthchecked_images:
        dockerfile = path.read_text(encoding="utf-8")
        assert "HEALTHCHECK --interval=5s" in dockerfile
        assert '  CMD ["python", "-c",' in dockerfile
        assert "CMD python -c" not in dockerfile


def test_control_plane_compose_separates_networks_and_bounds_postgres() -> None:
    compose = Path("containers/compose.control-plane.yaml").read_text(encoding="utf-8")
    postgres = _compose_service_block(compose, "postgres")
    api = _compose_service_block(compose, "control-plane")
    generic_worker = _compose_service_block(compose, "worker-daemon")
    replay_worker = _compose_service_block(compose, "replay-worker")
    proxy_image = _compose_service_block(compose, "replay-egress-proxy-image")
    replay_preflight = _compose_service_block(compose, "replay-runtime-preflight")
    initializer = _compose_service_block(compose, "artifact-storage-init")

    assert 'test: ["CMD", "pg_isready"' in postgres
    assert "pids_limit: 128" in postgres
    assert "mem_limit: 256m" in postgres
    assert "- database-host" in postgres
    assert "- database" in postgres
    assert "- api-host" in api
    assert "- control" in api
    assert "- database" in api
    assert "- database" not in generic_worker
    assert "- database" not in replay_worker
    assert "DAC_OVERRIDE" not in initializer
    assert "- replay-uplink" in proxy_image
    assert "network_mode: none" in replay_preflight
    assert 'user: "10001:10001"' in replay_preflight
    assert "pids_limit: 32" in replay_preflight
    assert "mem_limit: 64m" in replay_preflight
    assert (
        "PAJIN_REPLAY_EXTERNAL_NETWORK: ${PAJIN_REPLAY_EXTERNAL_NETWORK:-pajin-replay-uplink-lab}"
        in replay_worker
    )


def test_control_plane_build_context_is_allowlisted() -> None:
    ignore = Path("containers/control-plane/Dockerfile.dockerignore").read_text(encoding="utf-8")

    assert ignore.splitlines()[0] == "**"
    assert "!src/**" in ignore
    assert "!containers/control-plane/requirements.lock" in ignore
    assert "!containers/control-plane/replay_runtime_preflight.py" in ignore
    assert "tests" not in ignore
    assert "examples" not in ignore


def test_storage_initializer_does_not_reflect_paths_or_os_errors() -> None:
    initializer_path = Path("containers/control-plane/init_storage.py")
    spec = importlib.util.spec_from_file_location(
        "pajin_storage_initializer_test",
        initializer_path,
    )
    assert spec is not None
    assert spec.loader is not None
    initializer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(initializer)
    secret = "pajin-secret-path-value\nforged-log-record"

    with pytest.raises(SystemExit) as failure:
        initializer._initialize_private_root(Path("/missing") / secret)

    diagnostic = str(failure.value)
    assert diagnostic == "cannot initialize private artifact root"
    assert secret not in diagnostic
    assert "\n" not in diagnostic


def test_replay_runtime_preflight_rejects_unsafe_config_without_reflection(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    preflight_path = Path("containers/control-plane/replay_runtime_preflight.py")
    spec = importlib.util.spec_from_file_location("pajin_replay_preflight_test", preflight_path)
    assert spec is not None
    assert spec.loader is not None
    preflight = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(preflight)
    secret = "--network=host\nforged-log-record"
    monkeypatch.setenv("PAJIN_REPLAY_WORKER_IMAGE", "pajin-worker:dev")
    monkeypatch.setenv("PAJIN_REPLAY_EGRESS_PROXY_IMAGE", "pajin-egress-proxy:dev")
    monkeypatch.setenv("PAJIN_REPLAY_EXTERNAL_NETWORK", secret)

    assert preflight.main() == 2

    diagnostic = capsys.readouterr().err
    assert diagnostic == "Replay Docker preflight configuration is invalid\n"
    assert secret not in diagnostic


def test_multilingual_docs_state_the_https_proxy_boundary_truthfully() -> None:
    docs = [
        Path("README.md"),
        Path("README.en.md"),
        Path("README.ko.md"),
        Path("docs/adr/0003-egress-proxy-and-mcp-boundary.md"),
        Path("docs/adr/0003-egress-proxy-and-mcp-boundary.en.md"),
        Path("docs/adr/0003-egress-proxy-and-mcp-boundary.ko.md"),
    ]
    for path in docs:
        text = path.read_text(encoding="utf-8")
        assert "receiptEligible=false" in text
        assert "methodEnforcement=trusted-worker-only" in text
        assert "pathEnforcement=authority-only" in text
        assert "8 MiB" in text

    for path in docs[3:]:
        text = path.read_text(encoding="utf-8")
        assert "offline build" in text


def test_multilingual_docs_do_not_present_host_bridges_as_outbound_denial() -> None:
    english_docs = [
        Path("README.md"),
        Path("README.en.md"),
        Path("docs/adr/0029-control-plane-replay-orchestration.en.md"),
    ]
    for path in english_docs:
        text = path.read_text(encoding="utf-8")
        assert "ordinary Docker bridge" in text
        assert "outbound-deny boundary" in text or (
            "do not deny" in text and "container outbound traffic" in text
        )

    korean_docs = [
        Path("README.ko.md"),
        Path("docs/adr/0029-control-plane-replay-orchestration.md"),
        Path("docs/adr/0029-control-plane-replay-orchestration.ko.md"),
    ]
    for path in korean_docs:
        text = path.read_text(encoding="utf-8")
        assert "일반 Docker bridge" in text
        assert "outbound deny 경계는 아니" in text or (
            "container outbound traffic을" in text and "차단하지" in text
        )
