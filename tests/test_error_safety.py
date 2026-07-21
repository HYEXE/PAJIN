from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from email.message import Message
from io import BytesIO, StringIO
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.error import HTTPError

import pytest

import pajin.policy.engine as policy_module
import pajin.runtime.store as store_module
from pajin.domain.models import CampaignManifest, ToolRequest
from pajin.domain.yaml_loader import load_yaml_mapping
from pajin.policy.engine import PolicyEngine
from pajin.policy.scope import InvalidScopeURL
from pajin.providers.models import ProviderRegistration
from pajin.providers.openai_compatible import OpenAICompatibleChatTool
from pajin.runtime.error_safety import (
    audit_safe_exception_diagnostic,
    audit_safe_exception_type,
)
from pajin.runtime.store import RunIntegrityError
from pajin.runtime.worker import (
    WorkerFailureCode,
    WorkerResult,
    WorkerStatus,
)
from pajin.tools.ai import AIChatProbeTool
from pajin.tools.base import Tool
from pajin.tools.bug_bounty import BooleanSQLiProbeTool
from pajin.tools.ctf import CTFCryptoXORTool, CTFWebBackupProbeTool
from pajin.tools.http import HTTPGetTool
from pajin.tools.mcp import demo_mcp_tool
from pajin.tools.mock import MockAgentProbe, SleepCheckTool
from pajin.workflow.local import _add_terminalization_failure_note

_SECRET = "adapter-secret-MUST-NOT-PERSIST"


def _provider_tool() -> OpenAICompatibleChatTool:
    return OpenAICompatibleChatTool(
        ProviderRegistration(
            provider_id="error-safety",
            endpoint="https://provider.example.invalid/v1/chat/completions",
            model="fixed-model",
            secret_ref="provider/error-safety/api-key",
        )
    )


_WORKER_BACKED_TOOLS: tuple[Tool, ...] = (
    AIChatProbeTool(),
    BooleanSQLiProbeTool(),
    CTFWebBackupProbeTool(),
    CTFCryptoXORTool(),
    HTTPGetTool(),
    demo_mcp_tool(),
    MockAgentProbe(),
    SleepCheckTool(),
    _provider_tool(),
)


def _worker_result(
    *,
    status: WorkerStatus,
    stdout: str = "",
    stderr: str = "",
    failure_code: WorkerFailureCode | None = None,
) -> WorkerResult:
    now = datetime.now(UTC)
    return WorkerResult(
        execution_id="exec_error_safety",
        backend="error-safety",
        status=status,
        failure_code=failure_code,
        exit_code=0 if status is WorkerStatus.SUCCEEDED else 1,
        stdout=stdout,
        stderr=stderr,
        started_at=now,
        finished_at=now,
    )


def _request(tool: Tool, *, target: str = "https://target.example.invalid/probe") -> ToolRequest:
    return ToolRequest(
        agent_id="agent:error-safety",
        tool_id=tool.spec.tool_id,
        target=target,
        method="POST",
    )


def _load_module(relative_path: str, name: str) -> ModuleType:
    path = Path(__file__).parents[1] / relative_path
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_exception_diagnostic_omits_messages_and_untrusted_custom_type_names() -> None:
    secret = "exception-secret-MUST-NOT-PERSIST"
    custom_error_type = type(f"Leaky{secret}", (RuntimeError,), {})
    error = custom_error_type(secret)

    diagnostic = audit_safe_exception_diagnostic(error, stage="worker-backend")

    assert secret not in diagnostic
    assert audit_safe_exception_type(error) == "Exception"
    assert diagnostic == ("exception_type=Exception; stage=worker-backend; detail=omitted")


def test_exception_diagnostic_preserves_allowlisted_builtin_failure_class() -> None:
    diagnostic = audit_safe_exception_diagnostic(
        ValueError("provider-controlled detail"),
        stage="tool-interpretation",
    )

    assert diagnostic == ("exception_type=ValueError; stage=tool-interpretation; detail=omitted")


def test_exception_diagnostic_does_not_reflect_an_unrecognized_stage() -> None:
    secret = "stage-secret-MUST-NOT-PERSIST"

    diagnostic = audit_safe_exception_diagnostic(
        RuntimeError("fixed"),
        stage=secret,
    )

    assert secret not in diagnostic
    assert diagnostic == "exception_type=RuntimeError; stage=unknown; detail=omitted"


def test_exception_type_tolerates_malformed_runtime_type_metadata() -> None:
    error_type = type("MalformedMetadataError", (RuntimeError,), {})
    error_type.__module__ = 7  # type: ignore[assignment]

    assert audit_safe_exception_type(error_type("fixed")) == "Exception"


@pytest.mark.parametrize(
    "tool",
    _WORKER_BACKED_TOOLS,
    ids=lambda tool: tool.spec.tool_id,
)
def test_tool_adapters_never_copy_failed_worker_stderr(tool: Tool) -> None:
    worker_result = _worker_result(
        status=WorkerStatus.FAILED,
        stderr=f"{_SECRET}\n\x1b]8;;https://forged.invalid\x07forged status",
        failure_code=WorkerFailureCode.TARGET_UNAVAILABLE,
    )

    outcome = tool.interpret(_request(tool), worker_result)

    assert not outcome.success
    assert outcome.error == (
        "Worker execution did not succeed (status=failed, failureCode=target-unavailable)"
    )
    assert _SECRET not in outcome.error
    assert "forged status" not in outcome.error
    assert "\x1b" not in outcome.error


def test_http_adapter_does_not_reflect_worker_validation_input_or_error_detail() -> None:
    tool = HTTPGetTool()
    request = _request(tool)
    validation_failure = tool.interpret(
        request,
        _worker_result(
            status=WorkerStatus.SUCCEEDED,
            stdout=json.dumps({"target": request.target, "status": _SECRET}),
        ),
    )
    target_failure = tool.interpret(
        request,
        _worker_result(
            status=WorkerStatus.SUCCEEDED,
            stdout=json.dumps(
                {
                    "target": request.target,
                    "status": 0,
                    "error": f"{_SECRET}\nforged status",
                }
            ),
        ),
    )

    assert not validation_failure.success
    assert validation_failure.error is not None
    assert _SECRET not in validation_failure.error
    assert not target_failure.success
    assert target_failure.error == "HTTP target was unavailable"
    assert target_failure.data["error"] == "HTTP target was unavailable"
    assert _SECRET not in json.dumps(target_failure.model_dump(mode="json"))


def test_run_store_does_not_reflect_low_level_file_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> bytes:
        raise OSError(f"{_SECRET}\nforged status")

    monkeypatch.setattr(store_module, "read_bounded_regular_bytes", fail)

    with pytest.raises(RunIntegrityError) as raised:
        store_module._read_bounded_regular_file(
            Path("ignored"),
            label="sealed artifact",
            max_bytes=1,
        )

    assert str(raised.value) == "sealed artifact could not be read safely"
    assert _SECRET not in str(raised.value)


def test_policy_decision_does_not_reflect_scope_exception_detail(
    sample_campaign: CampaignManifest,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail(*_args: object, **_kwargs: object) -> bool:
        raise InvalidScopeURL(f"{_SECRET}\nforged policy")

    monkeypatch.setattr(policy_module, "scope_matches", fail)
    request = ToolRequest(
        agent_id="agent:error-safety",
        tool_id="mock.agent-probe",
        target=sample_campaign.spec.targets[0].endpoint,
        method="POST",
    )

    decision = PolicyEngine()._scope_decision(sample_campaign, request)

    assert decision is not None
    assert decision.reason == "scope could not be evaluated safely"
    assert _SECRET not in decision.reason
    assert "forged policy" not in decision.reason


def test_yaml_parse_failure_does_not_reflect_source_text(tmp_path: Path) -> None:
    path = tmp_path / "secret.yaml"
    path.write_text(f"value: [\n  {_SECRET}\n", encoding="utf-8")

    with pytest.raises(ValueError) as raised:
        load_yaml_mapping(path, label="test manifest")

    assert str(raised.value) == (
        "test manifest is not valid bounded YAML: syntax or value violation"
    )
    assert _SECRET not in str(raised.value)


def test_local_terminalization_note_does_not_reflect_secondary_failure() -> None:
    original = RuntimeError("original failure")

    _add_terminalization_failure_note(
        original,
        RuntimeError(f"{_SECRET}\nforged terminal status"),
    )

    notes = getattr(original, "__notes__", [])
    assert notes == [
        "local Run terminalization failed: "
        "exception_type=RuntimeError; stage=run-terminalization; detail=omitted"
    ]
    assert _SECRET not in " ".join(notes)
    assert "forged terminal status" not in " ".join(notes)


def test_worker_main_omits_validation_exception_messages(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _load_module("containers/worker/worker_entry.py", "error_safety_worker")

    def fail(*_args: object, **_kwargs: object) -> dict[str, object]:
        raise ValueError(f"{_SECRET}\n\x1b[32mforged success")

    monkeypatch.setattr(worker, "_dispatch_action", fail)
    monkeypatch.setattr(worker.sys, "argv", ["worker_entry.py", "mock-agent-probe"])
    monkeypatch.setattr(worker.sys, "stdin", StringIO("{}"))

    assert worker.main() == 65
    error = capsys.readouterr().err
    assert error == "invalid worker input or response\n"
    assert _SECRET not in error
    assert "\x1b" not in error


def test_worker_network_failures_do_not_reflect_response_bodies(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _load_module("containers/worker/worker_entry.py", "network_error_safety_worker")

    def fail_open(request: Any, *, timeout: int) -> None:
        del timeout
        target = request.full_url
        raise HTTPError(
            target,
            502,
            "Bad Gateway",
            Message(),
            BytesIO(_SECRET.encode("utf-8")),
        )

    monkeypatch.setattr(worker, "_open_http", fail_open)

    with pytest.raises(ValueError) as ai_failure:
        worker._post_ai_turn(
            "https://ai.example.invalid/v1/chat",
            {"sessionId": "safe-session", "messages": []},
        )
    with pytest.raises(ValueError) as provider_failure:
        worker.openai_chat_completion(
            {
                "providerId": "error-safety",
                "target": "https://provider.example.invalid/v1/chat/completions",
                "request": {
                    "model": "fixed-model",
                    "messages": [{"role": "user", "content": "hello"}],
                    "stream": False,
                },
            },
            {"provider-api-key": "fixed-test-credential"},
        )

    assert str(ai_failure.value) == "AI target returned HTTP 502"
    assert str(provider_failure.value) == "provider returned HTTP 502"
    assert _SECRET not in str(ai_failure.value)
    assert _SECRET not in str(provider_failure.value)


def test_worker_mcp_success_does_not_forward_child_stderr(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    worker = _load_module("containers/worker/worker_entry.py", "mcp_error_safety_worker")
    completed = worker._BoundedChildResult(
        returncode=0,
        stdout=b"{}",
        stderr=_SECRET.encode("utf-8"),
        stdout_truncated=False,
        stderr_truncated=False,
    )
    monkeypatch.setattr(worker, "_run_bounded_child", lambda *_args, **_kwargs: completed)

    assert worker.mcp_call({}) == {}
    captured = capsys.readouterr()
    assert captured.err == ""
    assert _SECRET not in captured.out


def test_synthetic_target_handlers_do_not_reflect_internal_failures(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret_error = ValueError(f"{_SECRET}\nforged status")

    ai_target = _load_module("containers/ai-target/target.py", "error_safety_ai_target")
    ai_responses: list[tuple[int, dict[str, object]]] = []
    ai_handler = ai_target.Handler.__new__(ai_target.Handler)
    ai_handler.path = "/v1/chat"
    ai_handler._request_json = lambda: {"sessionId": "safe", "messages": []}
    ai_handler._json = lambda status, payload: ai_responses.append((status, payload))
    monkeypatch.setattr(
        ai_target, "respond", lambda *_args, **_kwargs: (_ for _ in ()).throw(secret_error)
    )
    ai_handler.do_POST()

    bug_target = _load_module(
        "containers/bug-bounty-target/target.py",
        "error_safety_bug_target",
    )
    bug_responses: list[tuple[int, dict[str, object]]] = []
    bug_handler = bug_target.Handler.__new__(bug_target.Handler)
    bug_handler.path = "/v1/users/lookup?id=1"
    bug_handler._json = lambda status, payload: bug_responses.append((status, payload))
    monkeypatch.setattr(
        bug_target, "lookup", lambda *_args, **_kwargs: (_ for _ in ()).throw(secret_error)
    )
    bug_handler.do_GET()

    ctf_target = _load_module(
        "containers/ctf-web-target/target.py",
        "error_safety_ctf_target",
    )
    ctf_responses: list[tuple[int, dict[str, object]]] = []
    ctf_handler = ctf_target.Handler.__new__(ctf_target.Handler)
    ctf_handler.path = ctf_target.BACKUP_PATH
    ctf_handler._json = lambda status, payload: ctf_responses.append((status, payload))
    monkeypatch.setattr(
        ctf_target,
        "read_backup",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(secret_error),
    )
    ctf_handler.do_GET()

    rendered = json.dumps([ai_responses, bug_responses, ctf_responses])
    assert _SECRET not in rendered
    assert "forged status" not in rendered
    assert ai_responses[0][1]["error"] == "invalid request"
    assert bug_responses[0][1]["error"] == "lab configuration is invalid"
    assert ctf_responses[0][1]["error"] == "lab configuration is invalid"
