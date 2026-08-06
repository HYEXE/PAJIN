import os
import shutil
import subprocess
import sys
import tarfile
import zipfile
from email.parser import BytesParser
from importlib import import_module
from importlib import util as importlib_util
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from pajin import __version__ as package_version
from pajin import cli as cli_module
from pajin import entrypoints
from pajin.runtime.store import verify_run_integrity

_BUILD_BACKEND_PATH = Path(__file__).resolve().parents[1] / "build_backend.py"
_BUILD_BACKEND_SPEC = importlib_util.spec_from_file_location(
    "pajin_test_build_backend",
    _BUILD_BACKEND_PATH,
)
if _BUILD_BACKEND_SPEC is None or _BUILD_BACKEND_SPEC.loader is None:
    raise RuntimeError("project build backend could not be loaded")
build_backend = importlib_util.module_from_spec(_BUILD_BACKEND_SPEC)
_BUILD_BACKEND_SPEC.loader.exec_module(build_backend)


def test_package_main_module_is_safe_to_import() -> None:
    """Module discovery must not invoke Typer merely by importing ``pajin.__main__``."""

    assert import_module("pajin.__main__").app is cli_module.app


@pytest.mark.parametrize(
    ("entrypoint", "module_name"),
    [
        (entrypoints.control_plane_main, "pajin.control_plane.__main__"),
        (
            entrypoints.replay_worker_daemon_main,
            "pajin.control_plane.replay_worker_main",
        ),
        (entrypoints.worker_daemon_main, "pajin.control_plane.worker_main"),
    ],
)
def test_optional_entrypoints_delegate_when_dependencies_are_installed(
    entrypoint: object,
    module_name: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called: list[str] = []
    monkeypatch.setattr(sys, "argv", ["pajin-daemon"])
    monkeypatch.setattr(entrypoints, "find_spec", lambda _name: object())
    monkeypatch.setattr(
        entrypoints,
        "import_module",
        lambda selected: SimpleNamespace(main=lambda: called.append(selected)),
    )

    assert callable(entrypoint)
    entrypoint()

    assert called == [module_name]


@pytest.mark.parametrize(
    ("entrypoint", "required_imports"),
    [
        (entrypoints.control_plane_main, {"fastapi", "sqlalchemy", "uvicorn"}),
        (entrypoints.worker_daemon_main, {"httpx"}),
        (entrypoints.replay_worker_daemon_main, {"httpx"}),
    ],
)
def test_optional_entrypoints_check_only_the_selected_process_dependencies(
    entrypoint: object,
    required_imports: set[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    checked: list[str] = []
    monkeypatch.setattr(sys, "argv", ["pajin-daemon"])

    def find(name: str) -> object:
        checked.append(name)
        return object()

    monkeypatch.setattr(entrypoints, "find_spec", find)
    monkeypatch.setattr(
        entrypoints,
        "import_module",
        lambda _selected: SimpleNamespace(main=lambda: None),
    )

    assert callable(entrypoint)
    entrypoint()

    assert set(checked) == required_imports


def test_optional_entrypoint_reports_startup_failure_without_traceback(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["pajin-worker-daemon"])
    monkeypatch.setattr(entrypoints, "find_spec", lambda _name: object())
    secret = "invalid-setting-secret"

    def fail() -> None:
        raise RuntimeError(f"invalid setting {secret}\nforged status\ud800")

    monkeypatch.setattr(
        entrypoints,
        "import_module",
        lambda _selected: SimpleNamespace(main=fail),
    )

    with pytest.raises(SystemExit) as raised:
        entrypoints.worker_daemon_main()

    assert raised.value.code == 1
    error = capsys.readouterr().err
    assert (
        "pajin-worker-daemon failed: "
        "exception_type=RuntimeError; stage=process-entrypoint; detail=omitted"
    ) in error
    assert secret not in error
    assert "Traceback" not in error


def test_worker_entrypoint_does_not_require_server_only_dependencies(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "argv", ["pajin-worker-daemon"])
    monkeypatch.setattr(
        entrypoints,
        "find_spec",
        lambda name: None if name == "httpx" else object(),
    )
    monkeypatch.setattr(
        entrypoints,
        "import_module",
        lambda _selected: (_ for _ in ()).throw(AssertionError("must not import")),
    )

    with pytest.raises(SystemExit) as raised:
        entrypoints.worker_daemon_main()

    assert raised.value.code == 1
    error = capsys.readouterr().err
    assert "missing: httpx" in error
    assert "fastapi" not in error
    assert "psycopg" not in error


def test_distribution_artifacts_work_in_a_clean_no_dependency_install(tmp_path: Path) -> None:
    uv = Path(sys.executable).with_name("uv.exe" if os.name == "nt" else "uv")
    assert uv.is_file(), "the development environment must include the locked uv executable"
    uv_environment = {**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    source = tmp_path / "source"
    source.mkdir()
    for filename in ("pyproject.toml", "build_backend.py", "MANIFEST.in", "README.md"):
        shutil.copy2(filename, source / filename)
    shutil.copytree(
        "src/pajin",
        source / "src/pajin",
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
    )
    dist = tmp_path / "dist"
    build = subprocess.run(
        [
            str(uv),
            "build",
            "--no-build-isolation",
            "--offline",
            "--no-index",
            "--python",
            sys.executable,
            "--out-dir",
            str(dist),
            "--no-progress",
            str(source),
        ],
        check=False,
        capture_output=True,
        env=uv_environment,
        text=True,
    )
    assert build.returncode == 0, build.stdout + build.stderr
    wheel = next(dist.glob("pajin-*.whl"))
    sdist = next(dist.glob("pajin-*.tar.gz"))
    with zipfile.ZipFile(wheel) as archive:
        wheel_members = archive.namelist()
        entry_points_path = next(
            member for member in wheel_members if member.endswith(".dist-info/entry_points.txt")
        )
        entry_points = archive.read(entry_points_path).decode("utf-8")
        metadata_path = next(
            member for member in wheel_members if member.endswith(".dist-info/METADATA")
        )
        metadata = BytesParser().parsebytes(archive.read(metadata_path), headersonly=True)
    assert "pajin/py.typed" in wheel_members
    assert "pajin/control_plane/replay_worker_main.py" in wheel_members
    assert "pajin/control_plane/web/index.html" in wheel_members
    assert "pajin/control_plane/web/app.css" in wheel_members
    assert "pajin/control_plane/web/app.js" in wheel_members
    assert "pajin/control_plane/web/protocol.js" in wheel_members
    assert "pajin/control_plane/web/render.js" in wheel_members
    expected_python_modules = {
        path.relative_to("src").as_posix() for path in Path("src/pajin").rglob("*.py")
    }
    packaged_python_modules = {
        member for member in wheel_members if member.startswith("pajin/") and member.endswith(".py")
    }
    assert packaged_python_modules == expected_python_modules
    assert not any("/__pycache__/" in member or member.endswith(".pyc") for member in wheel_members)
    assert metadata["Version"] == package_version
    assert "pajin = pajin.cli:app" in entry_points
    assert "pajin-control-plane = pajin.entrypoints:control_plane_main" in entry_points
    assert (
        "pajin-replay-worker-daemon = pajin.entrypoints:replay_worker_daemon_main" in entry_points
    )
    assert "pajin-worker-daemon = pajin.entrypoints:worker_daemon_main" in entry_points
    with tarfile.open(sdist, mode="r:gz") as archive:
        members = archive.getnames()
    assert any(member.endswith("/build_backend.py") for member in members)
    assert not any("/tests/" in member for member in members)
    assert not any("/.pajin/" in member for member in members)
    assert any(member.endswith("/src/pajin/py.typed") for member in members)

    environment = tmp_path / "wheel-install"
    created = subprocess.run(
        [
            str(uv),
            "venv",
            "--offline",
            "--no-index",
            "--no-project",
            "--python",
            sys.executable,
            str(environment),
        ],
        check=False,
        capture_output=True,
        env=uv_environment,
        text=True,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    installed = subprocess.run(
        [
            str(uv),
            "pip",
            "install",
            "--offline",
            "--no-index",
            "--no-deps",
            "--python",
            str(python),
            str(wheel),
        ],
        check=False,
        capture_output=True,
        env=uv_environment,
        text=True,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr
    imported = subprocess.run(
        [
            str(python),
            "-c",
            (
                "import importlib.metadata as metadata, pajin, pathlib, sys; "
                "module = pathlib.Path(pajin.__file__).resolve(); "
                "prefix = pathlib.Path(sys.prefix).resolve(); "
                "print(pajin.__version__); print(metadata.version('pajin')); "
                "print(module.is_relative_to(prefix))"
            ),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert imported.returncode == 0, imported.stdout + imported.stderr
    assert imported.stdout.splitlines() == [package_version, package_version, "True"]
    scripts = environment / ("Scripts" if os.name == "nt" else "bin")
    suffix = ".exe" if os.name == "nt" else ""

    for command in (
        "pajin-control-plane",
        "pajin-replay-worker-daemon",
        "pajin-worker-daemon",
    ):
        executable = scripts / f"{command}{suffix}"
        help_result = subprocess.run(
            [str(executable), "--help"],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert help_result.returncode == 0
        assert "usage:" in help_result.stdout.lower()
        assert "pajin[control-plane]" not in help_result.stderr

        invalid_result = subprocess.run(
            [str(executable), "--not-a-real-option"],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert invalid_result.returncode == 2
        assert "unrecognized arguments" in invalid_result.stderr
        assert "pajin[control-plane]" not in invalid_result.stderr

        completed = subprocess.run(
            [str(executable)],
            cwd=tmp_path,
            check=False,
            capture_output=True,
            text=True,
        )
        assert completed.returncode == 1
        assert "pajin[control-plane]" in completed.stderr
        assert "Traceback" not in completed.stderr

    consumer = tmp_path / "consumer.py"
    consumer.write_text(
        "from pajin.domain.models import CampaignManifest\nreveal_type(CampaignManifest)\n",
        encoding="utf-8",
    )
    mypy = Path(sys.executable).with_name("mypy.exe" if os.name == "nt" else "mypy")
    completed = subprocess.run(
        [
            str(mypy),
            "--ignore-missing-imports",
            "--python-executable",
            str(python),
            str(consumer),
        ],
        cwd=tmp_path,
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert "missing library stubs or py.typed marker" not in completed.stdout
    assert 'Revealed type is "Any"' not in completed.stdout
    assert "pajin.domain.models.CampaignManifest" in completed.stdout


def test_root_lock_matches_project_metadata_offline(tmp_path: Path) -> None:
    uv = Path(sys.executable).with_name("uv.exe" if os.name == "nt" else "uv")
    assert uv.is_file(), "the development environment must include the locked uv executable"
    completed = subprocess.run(
        [str(uv), "lock", "--check", "--offline", "--no-progress"],
        check=False,
        capture_output=True,
        env={**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")},
        text=True,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_source_distribution_is_reproducible_with_source_date_epoch(tmp_path: Path) -> None:
    uv = Path(sys.executable).with_name("uv.exe" if os.name == "nt" else "uv")
    assert uv.is_file(), "the development environment must include the locked uv executable"
    epoch = 1_704_067_200
    environment = {
        **os.environ,
        "SOURCE_DATE_EPOCH": str(epoch),
        "UV_CACHE_DIR": str(tmp_path / "uv-cache"),
    }
    artifacts: list[tuple[Path, Path]] = []
    for name in ("first", "second"):
        output = tmp_path / name
        completed = subprocess.run(
            [
                str(uv),
                "build",
                "--no-build-isolation",
                "--offline",
                "--no-index",
                "--python",
                sys.executable,
                "--out-dir",
                str(output),
                "--no-progress",
                ".",
            ],
            check=False,
            capture_output=True,
            env=environment,
            text=True,
        )
        assert completed.returncode == 0, completed.stdout + completed.stderr
        artifacts.append(
            (
                next(output.glob("pajin-*.tar.gz")),
                next(output.glob("pajin-*.whl")),
            )
        )

    assert artifacts[0][0].read_bytes() == artifacts[1][0].read_bytes()
    assert artifacts[0][1].read_bytes() == artifacts[1][1].read_bytes()
    with tarfile.open(artifacts[0][0], mode="r:gz") as archive:
        members = archive.getmembers()
    assert members
    assert all(member.mtime == epoch for member in members)
    assert all(member.uid == 0 and member.gid == 0 for member in members)
    assert all(member.uname == "" and member.gname == "" for member in members)
    assert all("atime" not in member.pax_headers for member in members)
    assert all("ctime" not in member.pax_headers for member in members)


def test_custom_backend_delegates_sdist_when_source_date_epoch_is_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, object]] = []
    config = {"--global-option": ["value"]}
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    monkeypatch.setattr(
        build_backend._setuptools_backend,
        "build_sdist",
        lambda directory, settings: calls.append((directory, settings)) or "pajin.tar.gz",
    )
    monkeypatch.setattr(
        build_backend,
        "_normalize_sdist",
        lambda *_args, **_kwargs: pytest.fail("unset SOURCE_DATE_EPOCH must not normalize"),
    )

    assert build_backend.build_sdist("dist", config) == "pajin.tar.gz"
    assert calls == [("dist", config)]


def test_sdist_normalization_uses_random_exclusive_temp_and_cleans_failures(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "pajin-0.1.0.tar.gz"
    payload = tmp_path / "payload.txt"
    payload.write_text("package payload", encoding="utf-8")
    with tarfile.open(archive, mode="w:gz") as generated:
        generated.add(payload, arcname="pajin-0.1.0/payload.txt")

    victim = tmp_path / "victim.txt"
    victim.write_text("must remain unchanged", encoding="utf-8")
    legacy_predictable_temp = archive.with_name(f".{archive.name}.reproducible.tmp")
    try:
        legacy_predictable_temp.symlink_to(victim)
        legacy_is_symlink = True
    except OSError:
        legacy_predictable_temp.write_text("preclaimed temp", encoding="utf-8")
        legacy_is_symlink = False

    build_backend._normalize_sdist(archive, epoch=1_704_067_200)

    assert victim.read_text(encoding="utf-8") == "must remain unchanged"
    if legacy_is_symlink:
        assert legacy_predictable_temp.is_symlink()
    else:
        assert legacy_predictable_temp.read_text(encoding="utf-8") == "preclaimed temp"
    assert set(tmp_path.glob(f".{archive.name}.*.tmp")) == {legacy_predictable_temp}

    broken = tmp_path / "broken.tar.gz"
    broken.write_bytes(b"not a source distribution")
    before = set(tmp_path.iterdir())
    with pytest.raises(tarfile.ReadError):
        build_backend._normalize_sdist(broken, epoch=1_704_067_200)
    assert set(tmp_path.iterdir()) == before


def test_custom_backend_preserves_editable_install_support(tmp_path: Path) -> None:
    uv = Path(sys.executable).with_name("uv.exe" if os.name == "nt" else "uv")
    assert uv.is_file(), "the development environment must include the locked uv executable"
    uv_environment = {**os.environ, "UV_CACHE_DIR": str(tmp_path / "uv-cache")}
    environment = tmp_path / "editable-install"
    created = subprocess.run(
        [
            str(uv),
            "venv",
            "--offline",
            "--no-index",
            "--no-project",
            "--python",
            sys.executable,
            str(environment),
        ],
        check=False,
        capture_output=True,
        env=uv_environment,
        text=True,
    )
    assert created.returncode == 0, created.stdout + created.stderr
    python = environment / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    editable_dist = tmp_path / "editable-dist"
    editable_dist.mkdir()
    editable_wheel = editable_dist / build_backend.build_editable(str(editable_dist))
    installed = subprocess.run(
        [
            str(uv),
            "pip",
            "install",
            "--offline",
            "--no-index",
            "--no-deps",
            "--python",
            str(python),
            str(editable_wheel),
        ],
        check=False,
        capture_output=True,
        env=uv_environment,
        text=True,
    )
    assert installed.returncode == 0, installed.stdout + installed.stderr
    imported = subprocess.run(
        [str(python), "-c", "import pajin; print(pajin.__version__)"],
        check=False,
        capture_output=True,
        cwd=tmp_path,
        text=True,
    )
    assert imported.returncode == 0, imported.stdout + imported.stderr
    assert imported.stdout.strip() == "0.1.0"


def test_worker_lock_refresh_does_not_create_or_delete_a_vendor_tree() -> None:
    script = Path("scripts/prepare-worker-dependencies.ps1").read_text(encoding="utf-8")
    dockerignore = Path("containers/worker/.dockerignore").read_text(encoding="utf-8")
    lock = Path("containers/worker/requirements.lock").read_text(encoding="utf-8")

    assert "pip compile" in script
    assert '--custom-compile-command "scripts/prepare-worker-dependencies.ps1"' in script
    assert "pip install" not in script
    assert "Remove-Item" not in script
    assert "$Vendor" not in script
    assert "vendor/" in dockerignore.splitlines()
    assert "#    scripts/prepare-worker-dependencies.ps1" in lock


def test_multi_cancel_check_accepts_explicit_paths_outside_the_repository(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    manifest = Path("examples/multi-agent-cancel.yaml").resolve()
    output = tmp_path / "runs"
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        cli_module.app,
        [
            "multi-cancel-check",
            str(manifest),
            "--worker",
            "simulated",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    assert "SIMULATED / NOT REAL TARGET EVIDENCE" in result.output
    assert "cancellation propagated into terminal Run" in result.output
    assert "owned engine cleanup receipt sealed" in result.output
    assert "owned executor stack quiescence sealed" in result.output
    assert "Physical resource cleanup: NOT ATTESTED" in result.output
    run_paths = [path.parent for path in output.glob("multi-agent-cancellation-check/*/report.md")]
    assert len(run_paths) == 1
    run_path = run_paths[0]
    assert (run_path / "cancellation.json").is_file()
    assert (run_path / "quiescence.json").is_file()
    assert verify_run_integrity(run_path).seal_count == 2
