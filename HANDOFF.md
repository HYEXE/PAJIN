# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `69809fa04b707ba4b3e6691cc4aa397e6762bf69`
- 현재 구현 체크포인트: `P0-E3B1` local llama.cpp·Qwen registration과 raw trace
- 다음 구현: `P0-E3B2` fresh P0-D1 lifecycle·invocation receipt·completed Result

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 정상 delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

P0-E3B1은 P0-E3A의 generic contract를 다음 exact local runtime에 결박했다.

- agent: 기존 `pajin.workflow.policy-tool-loop@model-tool-trace-v1`; deterministic fallback 없음
- runtime: `ghcr.io/ggml-org/llama.cpp:server-cuda13-b9445`의 고정 OCI digest와 관찰 image ID
- model: `Qwen/Qwen3-4B-Instruct-2507`, exact Q8_0 GGUF revision·filename·SHA-256
- Provider: local OpenAI-compatible endpoint, registered secret-ref, private-network opt-in, marginal token
  price USD 0
- prompt·Tool: exact developer/objective bundle과 고정 `bug-bounty.boolean-sqli-probe`; 모델 작성 payload 없음
- sampling: temperature 0, top-p 1, coordinate seed, 두 turn, retry 0

`ProviderChatRequest`의 optional sampling 값은 기존 caller에서 생략되며, 등록 Provider Tool을 통해 실제
요청으로 전달된다. opt-in traced Tool Loop는 `pajin-model-tool-trace-jsonl/v1` canonical JSONL을 봉인한다.
strict reader는 identity, 두 model request/result/usage, 정확히 한 번의 Tool request/trusted receipt/result,
strict final finding과 zero-active-lease cleanup을 exact sequence로 다시 검증한다. llama.cpp가 tool-call
content를 빈 문자열로 반환하는 실제 호환성은 assistant tool-call 메시지에서만 canonical `None`으로
정규화하며 Tool call 검증은 완화하지 않는다.

핵심 구현 위치:

- `src/pajin/benchmark/single_agent_runtime.py`
- `src/pajin/workflow/model_tool_trace.py`
- `src/pajin/workflow/tool_loop.py`
- `src/pajin/providers/models.py`
- `src/pajin/providers/openai_compatible.py`
- `tests/test_benchmark_single_agent_runtime.py`
- `tests/test_tool_loop.py`
- `docs/benchmark/P0-E3B-local-single-agent-runtime.md`
- `docs/adr/0099-select-local-llama-cpp-single-agent-baseline.md`

## 실제 적합성 근거

- Docker Desktop 4.78.0 / Engine 29.5.3, NVIDIA RTX 3090에서 실행
- llama.cpp image ID:
  `sha256:f92150249e1913ef96e744b5d78f6291f0e4399a7925ffc7b1d0680d82506551`
- GGUF SHA-256:
  `ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1`
- local conformance Run: `run_20260802T085303Z_30585cd9`
- raw trace SHA-256: `a5f0a7635b59ac1759c4032e7882a424e2bb0652e948cac1c60aa0d3a7e741f6`
- normalized trace digest: `b6591dfd82fa36019e31730c91a360fb889d0c8036d0067f2d6f1bddd1c0763e`
- Provider usage: prompt 1,374 + completion 62 = total 1,436 tokens
- 결과: status completed, 정확히 1회 fixed SQLi Tool, trusted host receipts, cleanup succeeded

실행 중 로컬 `pajin-worker:dev`와 `pajin-egress-proxy:dev`가 현재 증거 계약보다 오래된 것이 확인돼
현재 저장소 소스로 재빌드했다. 전체 dependency 재빌드는 container 내부 pip CA 검증 실패로 중단됐고,
기존 hash-locked dependency layer 위에 현재 `worker_entry.py`만 올려 local worker를 복구했다. 이는
로컬 이미지 상태이며 커밋 대상이 아니다. 임시 llama·Target container와 전용 network는 제거했고 GGUF와
ignore된 conformance Run은 재검증을 위해 유지했다.

## 마지막 검증

- 새 runtime/raw trace 집중 테스트: 5 passed
- Provider·Tool Loop·baseline·문서 집중 회귀: 88 passed, 1 deselected
- 빈 tool-call content와 Tool message 치환 회귀 포함
- Ruff 전체 통과
- Linux 대상 strict mypy: 214 source files 통과
- 전체 `pytest -x -q`: 327 passed, 7 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단
- 실제 local llama.cpp/Qwen conformance: completed, strict trace reader 통과
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_single_agent_runtime.py tests\test_tool_loop.py tests\test_provider.py tests\test_benchmark_single_agent_baseline.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_single_agent_runtime.py tests\test_benchmark_single_agent_baseline.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`P0-E3B2`의 가장 작은 수직 슬라이스를 구현한다.

1. exact P0-E3B1 registration과 P0-E3A coordinate를 fresh P0-D1 Target operation에 결박한다.
2. Provider call은 host-local llama.cpp route, fixed SQLi Tool은 P0-D1 internal network route를 사용하되
   동일 exact `DockerWorkerBackend`의 host-observed receipt 신뢰 경계를 유지한다.
3. Target operation·cleanup receipt와 Tool Loop Run/root/raw trace SHA를 상호 결박한 invocation authority를
   봉인하고 substitution·replay·partial cleanup을 fail closed한다.
4. registry-governed Harness·Target source·invocation trace를 재개방해 각 좌표의 normalized Observation을
   만들고 전체 좌표의 completed `BenchmarkResult`를 봉인한다.
5. deterministic fallback이나 PAJIN fixed probe 결과를 agent output으로 가장하지 않는다.

## 알려진 경계

- P0-E3B1 conformance는 fresh P0-D1 measurement lifecycle이 아니며 baseline Result가 아니다.
- local Provider의 USD 0 가격은 marginal token 가격만 의미하며 GPU 전력·감가상각 비용은 제외한다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.
- Docker daemon과 ignore된 local model·Run은 다른 host에서 자동 복원되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 commit·push하고
다음 개발로 계속 진행하는 것을 승인했지만, 비용·credential·외부 데이터 전송 결정은 별도 권한이다.
