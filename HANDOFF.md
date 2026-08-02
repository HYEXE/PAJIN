# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `e5bfa6f75488178ffaa4b215a4eabaa3c7b8d860`
- 현재 구현 체크포인트: `ENG-002B2B` sealed behavioral parity admission 검증 완료
- 다음 구현: `ENG-002C1` PROF-002·B2B 교집합 비확장 MissionEnvelope compiler

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

ENG-002B2B는 ENG-002B2A가 만든 legacy-direct와 Profile-adapter의 독립 sealed Run을 기존 Mode
processor로 각각 확장하고, complete semantic behavior가 같은 경우에만 parity를 승인한다.

- 각 Run의 현재 root가 B2A에 기록된 source root와 정확히 같아야 시작한다.
- AI는 B1 KISA threshold와 complete code-owned catalog, Bug Hunt는 exact Program manifest,
  CTF는 exact Challenge manifest를 Mode source로 결박한다.
- Plan 순서와 typed lineage로 Run·Agent·Grant·Task·request·Worker execution·evidence·validation·event
  identity를 fixture ordinal에 대응한다.
- 구조화 JSON은 등록된 fresh identity 전체와 정확히 같은 key/value만 치환한다. Mode-owned UTF-8
  report/writeup만 포함 identity 치환을 허용한다.
- 실행 timestamp와 스키마상 unordered set만 명시적 allowlist로 정규화하며 다른 list 순서와
  payload는 그대로 비교한다.
- Scope, Capability attenuation, ToolRequest, Policy decision, Worker job/result, trusted network log,
  ToolResult, complete Outcome, AI·Bug Hunt·CTF 후처리 artifact를 모두 비교한다.
- B2A source root 뒤에 추가된 sealed artifact inventory와 semantic audit-event suffix도 비교한다.
  서로 다른 source root를 상속하는 chain hash는 reader가 독립 검증하고, 상대 순서·type·payload를
  비교한다. 필수 artifact 외의 추가 산출물도 drift로 거부한다.
- receipt 필드나 Mode 역할이 양쪽에서 같이 빠져도 parity로 인정하지 않는다.
- 성공 authority도 exact fixture의 Profile-adapter parity만 승인한다. MissionEnvelope와 Common
  execution authorization은 false다.
- 첫 arm 처리 뒤 둘째 arm이 실패하면 첫 Run은 확장된 채 남고 parity authority는 없다. 재시도는
  fresh B2A pair를 사용한다.

핵심 구현 위치:

- `src/pajin/workflow/engine_behavioral_parity.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_engine_behavioral_parity.py`
- `docs/orchestration/ENG-002B2B-common-engine-behavioral-parity.md`
- `docs/adr/0107-admit-parity-only-from-sealed-semantic-behavior.md`

## 마지막 검증

- ENG-002B2B와 전임 Common Engine/Profile 계약 집중 회귀: 158 passed
- Mode별 runtime 회귀: 75 passed, 5 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 223 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check`: 커밋 전 재실행 대상

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_behavioral_parity.py tests\test_engine_runtime_parity.py tests\test_engine_planner_parity.py tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002C1`의 가장 작은 비실행 compiler bridge를 구현한다.

1. 기존 `MissionEnvelope`와 compiler 계약, ADR-0047, GRAPH-006, PROF-002·B2B authority를 먼저
   대조해 이미 존재하는 authority 필드를 재사용한다.
2. source Campaign, Profile identity, compiler identity, Capability·target·budget·time ceiling을
   PROF-002 compilation과 B2B evidence의 교집합으로만 계산한다.
3. ROE default 적용, 새 target/tool/capability 추가, ActionPermit 발급, Common runtime dispatch를
   금지한다.
4. stale·foreign·cross-Mode parity, Campaign/Profile/digest substitution, scope·budget 확대와 flag
   forgery를 fail closed하는 additive wire authority와 reader를 만든다.

## 알려진 경계

- B2B content address는 외부 서명이나 binary/runtime attestation이 아니다.
- B2B는 existing Mode processor를 실제 호출해 두 fixture Run을 확장하므로 read-only 검사가 아니다.
- 전체 pytest 중단은 코드 회귀가 아니라 현재 Windows 계정의 symlink 생성 권한 제약이다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
