# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `c82c036724a34f19656b7f4cbe71445212522fc4`
- 현재 구현 체크포인트: `ENG-002B2A` exact runtime coordinate·독립 sealed dual-run source
- 다음 구현: `ENG-002B2B` Capability·receipt·Outcome·Mode 후처리 normalized parity admission

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

ENG-002B2A는 B1 Planner parity 뒤에서 전체 behavioral parity를 선언하기 전에 두 개의 fresh sealed
source Run을 만드는 async direct-call 측정 경계다.

- B1 authority와 arm별 exact Planner constructor를 다시 검증한다.
- Mode별 exact Validator, AI deterministic delegate·KISA candidate producer,
  `MultiAgentCampaignRunner`를 결박한다.
- complete ToolSpec과 해당 Tool 구현의 stable execution context를 하나의 binding으로 묶는다.
  Tool Registry는 B1 Plan의 ToolRequest 집합과 정확히 같아야 한다.
- Policy와 Worker의 stable execution context, Worker evidence scope와 semantic output role을 결박한다.
  stable context의 mapping·sequence·set을 deterministic JSON으로 정규화하며 비 JSON 값은 거부한다.
- legacy-direct와 Profile-adapter arm을 별도 output root에서 실행한다. 두 좌표의 의미 digest는 같고
  path별 coordinate digest는 달라야 한다.
- 각 결과는 completed Run, sealed root integrity, exact B1 runtime Plan, unique request·evidence를
  요구한다. 두 arm의 Run·request·evidence identity는 서로 겹칠 수 없다.
- 성공한 dual execution은 비교 원천일 뿐이다. Capability·receipt·Outcome·Mode 후처리 parity,
  MissionEnvelope와 Common execution eligibility는 모두 false다.
- 기존 CLI/API, Mode runtime, artifact wire shape와 reader는 변경하지 않았다.

핵심 구현 위치:

- `src/pajin/workflow/engine_runtime_parity.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_engine_runtime_parity.py`
- `docs/orchestration/ENG-002B2A-common-engine-dual-runtime-fixture.md`
- `docs/adr/0106-seal-dual-runtime-sources-before-behavioral-parity.md`

## 마지막 검증

- ENG-002B2A·B1·ENG-002A·PROF-002·PROF-001·ENG-001 집중 회귀: 151 passed
- Mode별 runtime 회귀: 75 passed, 5 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 222 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_runtime_parity.py tests\test_engine_planner_parity.py tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002B2B`의 가장 작은 parity admission 수직 슬라이스를 구현한다.

1. B2A authority와 양쪽 sealed Run tree를 fresh reader에서 다시 검증하고, Plan ordinal을 기준으로
   Run·agent·grant·request·execution·evidence identity 대응표를 만든다.
2. 생성 시각·fresh ID처럼 명시된 필드만 ordinal로 정규화한다. Scope, attenuation 제약, Policy,
   Tool/Worker payload와 receipt, evidence content는 그대로 비교한다.
3. `MultiAgentRunOutcome`의 agents, TaskGraph, ToolResult, Finding, atomic validation과 Mode별 AI
   candidate, Bug Hunt report, CTF result/writeup을 typed normalized projection으로 만든다.
4. complete equality일 때만 Scope·Capability·ToolRequest·Outcome fixture parity를 증명한다.
   incomplete/different evidence, cross-Mode/source 치환, 누락된 후처리는 fail closed하고
   MissionEnvelope/Common execution eligibility는 계속 false로 유지한다.

## 알려진 경계

- B2A는 runtime을 실제 실행하지만 behavioral parity를 판정하지 않는다. sealed root와 외부 coordinate의
  결박은 code-generated content address이며 외부 서명이나 binary/runtime attestation이 아니다.
- 양쪽 output root는 물리적으로 달라야 하며 권위에는 동일 semantic output role만 포함된다.
- 전체 pytest 중단은 코드 회귀가 아니라 현재 Windows 계정의 symlink 생성 권한 제약이다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
