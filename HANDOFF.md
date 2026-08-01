# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 마지막 완료 기능 커밋: `a94df3094990545b0ab67a9f6fce3190ea1a8286`
- 마지막 완료 기능: `WALK-003` MCP Tool Authorization Hypothesis
- 다음 구현: `WALK-004` Observation Graph·Replan

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `a94df30`이었고, 저장소 상태 관리
마이그레이션을 시작하기 전 worktree는 clean이었다. 마이그레이션이 아직 커밋되지 않았다면
예상 변경은 `AGENTS.md`, `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`, ADR-0070,
문서 정책·인덱스·README·RFC와 대응 문서 테스트로 한정된다. 이미 커밋됐다면 worktree가
clean이고 HEAD에 ADR-0070이 포함됐는지 확인한다. 진행 중인 merge, rebase, cherry-pick,
서버 또는 background helper는 없어야 한다.

## 현재 구현 상태

`WALK-001`~`WALK-003`이 구현됐다. WALK-003은 다음을 보장한다.

- 봉인된 WALK-002 H-17 Run root, artifact SHA-256, publication event를 재검증한다.
- 별도의 정확한 DISC-003D MCP Recon Snapshot을 독립적으로 재검증한다.
- MCP server/tool Surface와 input schema를 immutable Capability Definition, live registered
  ToolSpec digest, remote identity, T1 risk, independent user approval에 결박한다.
- 별도 sealed Run에 content-addressed `registered-not-authorized` Hypothesis를 생성한다.
- Activation, CapabilityGrant, ActionPermit, ToolRequest, MCP argument, Worker dispatch를 만들지
  않는다.

핵심 구현 위치:

- `src/pajin/discovery/walking_mcp.py`
- `src/pajin/discovery/recon.py`
- `tests/test_walking_mcp_authorization.py`
- `docs/orchestration/WALK-003-mcp-tool-authorization-hypothesis.md`
- `docs/adr/0069-snapshot-bound-mcp-tool-authorization-hypothesis.md`

## 마지막 검증

`main@a94df30` 기준:

- Ruff 전체 통과
- Linux 대상 strict mypy 185 source files 통과
- WALK/Discovery/Orchestration 집중 회귀 49 passed
- 전체 `pytest -x -q`는 150 passed, 3 skipped 이후 `KNOWN_ISSUES.md`에 기록된 Windows
  symlink 권한 오류에서 중단

저장소 상태 관리 마이그레이션은 문서 중심 변경이다. 다음 명령으로 검증한다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
git diff --check
```

## 다음 개발의 첫 작업

WALK-004 구현 전 다음 파일을 확인한다.

- `src/pajin/discovery/walking_mcp.py`
- `src/pajin/discovery/replanning.py`
- `src/pajin/workflow/discovery.py`
- `tests/test_walking_mcp_authorization.py`
- `tests/test_discovery_replanning.py`
- `docs/orchestration/ORCH-002-deterministic-multi-wave-baseline.md`
- `docs/orchestration/WALK-003-mcp-tool-authorization-hypothesis.md`

ORCH-002가 이미 제공하는 부분과 Walking Chain 통합에서 실제로 빠진 부분을 구분한다.
증거에 결박된 WALK-003 Observation이 다른 Plan으로 이어지되 두 Snapshot과 기존 Rule,
Capability, 승인, Tool binding 전체를 보존하는 가장 작은 additive authority를 설계한다.
별도 계약과 명시적 승인이 없다면 WALK-004에서 등록 MCP Capability를 활성화하거나
dispatch하지 않는다.

## 외부 상태

기존 Notion 로드맵은 `main@a94df30`에서 마지막으로 대조했다. Cutover 시 `PLAN.md`와
`HANDOFF.md`를 가리키는 안내를 한 번 추가할 수 있으며, 이후에는 읽기 전용 역사적
스냅샷으로 취급한다. 저장소 문서가 권위이며 두 개의 활성 로드맵을 유지하지 않는다.

커밋과 push에는 사용자의 명시적 승인이 필요하다.
