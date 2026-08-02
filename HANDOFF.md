# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `a374ed86d862654230200cabc182e12469dec546` (`P0-E2B`)
- 현재 구현 체크포인트: `P0-E3A` Single-agent baseline measurement plan
- 다음 구현: `P0-E3B` 실제 single-agent provider·raw trace·measurement authority

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

P0-E3A는 기존 실행 경계를 single-agent 실측으로 오인하지 않도록 먼저 identity·trace·coordinate
계약을 닫는 contract-first 슬라이스다.

- 기존 `ProviderAgentRuntime`은 Planner·Specialist·Validator·Reporter를 분리하는 multi-role 경계다.
- `PydanticAIAgentRuntime`은 exact deterministic `TestModel`만 허용하고, Provider 테스트 Worker는 응답을
  합성하므로 실제 single-agent provider가 아니다.
- `GenericSingleAgentAdapterContract`은 agent implementation ID/version/digest, Provider registration
  digest, model revision, prompt bundle, tool catalog와 runtime configuration digest를 요구한다.
- model access는 registered Provider Gateway만, Target access는 fresh isolation의 approved Tool만
  허용하고 deterministic fallback을 금지한다.
- raw evidence는 secret-free `pajin-model-tool-trace-jsonl/v1`이며 model request/result, Tool
  request/receipt/result, Provider usage와 cleanup을 요구한다.
- exact P0-D1 catalog selection과 전체 seed/repetition 좌표를 canonical plan에 결박한다.
- 기존 `deterministic-baseline` arm은 non-adaptive baseline 분류로 사용하며 model output determinism을
  주장하지 않는다. future Result는 repetitions와 variance를 유지해야 한다.
- concrete agent·Provider·model·prompt·tool·runtime, invocation, raw trace, Result, comparison과
  Supervisor activation은 모두 literal false다.

핵심 구현 위치:

- `src/pajin/benchmark/single_agent_baseline.py`
- `src/pajin/benchmark/__init__.py`
- `tests/test_benchmark_single_agent_baseline.py`
- `docs/benchmark/P0-E3A-single-agent-baseline-plan.md`
- `docs/adr/0098-bind-single-agent-identity-before-measurement.md`

## 마지막 검증

- P0-E3A 단독 테스트: 20 passed
- P0-E3A·Scanner·Target catalog·BENCH-001·문서 집중 회귀: 57 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 212 source files 통과
- 전체 `pytest -x -q`: 322 passed, 7 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_single_agent_baseline.py tests\test_benchmark_scanner_baseline.py tests\test_benchmark_zap_scanner.py tests\test_benchmark_contract.py tests\test_benchmark_target_catalog.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`P0-E3B`는 다음 외부 실행 결정을 명시적으로 받은 뒤 진행한다.

1. concrete single-agent implementation과 배포 가능한 executable/image identity
2. 실제 Provider endpoint·model revision과 credential secret-ref 이름
3. benchmark 전용 prompt bundle·Tool catalog·sampling/retry/no-fallback configuration
4. trusted input/output token 가격과 허용 비용·호출 한도
5. Provider 데이터 보존·전송 정책을 포함한 외부 실행 승인

선택 뒤에는 P0-E3A plan과 exact registration을 결박하고, fresh P0-D1 lifecycle에서 model/tool trace,
usage/cost, receipt, cleanup과 registry-governed source를 봉인하는 최소 provider/measurement reader를
구현한다. 현재 권한으로 비용 발생 Provider나 credential을 임의 선택·호출하지 않는다.

## 알려진 경계

- P0-E3A는 measurement plan이며 single-agent 성능 측정 결과가 아니다.
- P0-E2B는 local ZAP 실측이지만 P0-E3A의 Provider/model 결정을 대신하지 않는다.
- P0-E1/P0-E2B와 비교할 single-agent Result는 아직 없다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 commit·push하고
다음 개발로 계속 진행하는 것을 승인했지만, 비용·credential·외부 데이터 전송 결정은 별도 권한이다.
