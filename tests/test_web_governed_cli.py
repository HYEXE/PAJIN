from __future__ import annotations

import inspect
from pathlib import Path

from click.utils import strip_ansi
from typer.testing import CliRunner

from pajin.cli import app, run_governed_local_web_campaign_command


def test_governed_web_cli_exposes_only_bounded_operator_options() -> None:
    result = CliRunner().invoke(
        app,
        ["web-campaign-run-governed-local", "--help"],
        color=True,
        env={"CI": "true", "TERM": "xterm-256color", "FORCE_COLOR": "1", "COLUMNS": "80"},
    )

    assert result.exit_code == 0
    help_text = strip_ansi(result.output)
    for option in (
        "--origin",
        "--adapter-ref",
        "--output",
        "--authorized-local-lab",
        "--headless",
        "--headed",
    ):
        assert option in help_text
    for forbidden in (
        "--credential",
        "--password",
        "--token",
        "--private-key",
        "--destination",
        "--clock",
        "--runner",
        "--store",
        "--route",
        "--payload",
    ):
        assert forbidden not in help_text


def test_governed_web_cli_requires_explicit_local_lab_confirmation(tmp_path: Path) -> None:
    output = tmp_path / "governed-output"

    result = CliRunner().invoke(
        app,
        [
            "web-campaign-run-governed-local",
            "--origin",
            "http://127.0.0.1:3000",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 2
    assert "Governed local Web campaign failed" in result.output
    assert "stage=cli-command" in result.output
    assert not output.exists()


def test_governed_web_cli_uses_the_verified_poc_manifest_path() -> None:
    source = inspect.getsource(run_governed_local_web_campaign_command)

    assert "artifacts.poc_manifest_path.resolve()" in source
    assert "artifacts.poc_bundle_path / result.poc_manifest_reference" not in source
