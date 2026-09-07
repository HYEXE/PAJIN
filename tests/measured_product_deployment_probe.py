"""Fresh-process UX-010 API probe. Docker simulation is test-owned and explicit."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import replace
from hashlib import sha256
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pajin.control_plane.api import create_app
from pajin.workflow.ai_fixture_runtime import SubprocessAIDockerCommandRunner
from pajin.workflow.network_fixture_runtime import SubprocessNetworkDockerCommandRunner
from tests.test_control_plane_web import OPERATOR_TOKEN, _auth, _settings


def probe_fresh_deployment(
    path: Path,
    digest: str,
    domain: str,
    expected_digest: str,
    process_root: Path,
    *,
    simulate_docker: bool = False,
) -> None:
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "tests.measured_product_deployment_probe",
            str(path),
            digest,
            str(process_root),
            domain,
            *(["--simulate-docker"] if simulate_docker else []),
        ],
        cwd=Path(__file__).resolve().parents[1],
        env={**os.environ, "PYTHONHASHSEED": "71"},
        capture_output=True,
        text=True,
        timeout=240,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["status"] == 200
    assert report["digest"] == expected_digest


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("inventory", type=Path)
    parser.add_argument("digest")
    parser.add_argument("process_root", type=Path)
    parser.add_argument("domain", choices=("web", "network", "ai"))
    parser.add_argument("--simulate-docker", action="store_true")
    args = parser.parse_args()
    args.process_root.mkdir(parents=True, exist_ok=False)
    with pytest.MonkeyPatch.context() as patch:
        if args.simulate_docker:
            from tests.ai_measured_product_fresh_process import _FakeAIDockerRunner
            from tests.test_network_fixture_runtime import _FakeDocker

            ai_docker = _FakeAIDockerRunner()
            network_docker = _FakeDocker()
            patch.setattr(
                SubprocessAIDockerCommandRunner, "run", lambda _self, argv: ai_docker.run(argv)
            )
            patch.setattr(
                SubprocessNetworkDockerCommandRunner,
                "run",
                lambda _self, argv: network_docker.run(argv),
            )
        settings = replace(
            _settings(args.process_root / "control-plane.sqlite3"),
            measured_product_deployment_path=args.inventory,
            measured_product_deployment_sha256=args.digest,
        )
        endpoint = {
            "web": "/v1/products/web-measured-flow",
            "network": "/v1/products/network-measured-service-identification",
            "ai": "/v1/products/ai-measured-system-prompt-disclosure",
        }[args.domain]
        with TestClient(create_app(settings)) as client:
            assert client.get(endpoint).status_code == 401
            response = client.get(endpoint, headers=_auth(OPERATOR_TOKEN))
            assert response.status_code == 200, response.text
            assert response.headers["cache-control"].startswith("no-store")
            payload = response.json()
            print(
                json.dumps(
                    {
                        "status": response.status_code,
                        "digest": payload[
                            "flowDigest" if args.domain == "web" else "productDigest"
                        ],
                        "responseSha256": sha256(response.content).hexdigest(),
                    }
                )
            )


if __name__ == "__main__":
    main()
