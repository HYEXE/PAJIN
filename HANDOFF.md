# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `1f037e48e66bc0809fb03e5499a946450907f219`
- 현재 구현 체크포인트: `ENG-002B1` 동일 constructor Planner·ToolRequest parity
- 다음 구현: `ENG-002B2` Capability·receipt·Outcome·Mode 후처리 parity와 opt-in 실행 gate

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

ENG-002B1은 세 legacy Mode의 Planner behavior를 ENG-002A-selected Profile adapter Planner와
동일 fixture에서 비교하는 async direct-call 측정 경계다.

- complete PROF-002 Campaign과 exact Planner class, typed constructor input을 양쪽 경로에 동일하게
  전달한다.
- AI는 전체 KISA threshold를 결박하고 Bug Hunt·CTF는 현재 빈 constructor configuration을
  결박한다. non-AI Mode에 AI threshold를 전달하면 거부한다.
- 양쪽 Planner는 독립적으로 호출한다. 매 호출마다 달라야 하는 `step_id`와 `request_id`만 ordered
  `fixture-step-N`, `fixture-request-N`으로 정규화한다.
- 정규화 payload를 기존 `AgentPlan`으로 다시 검증하고 나머지 summary·순서·Tool·target·method·
  arguments·scenario·threat·surface·persona를 exact 비교한다.
- Scope와 ToolRequest Planner behavior만 measured/proven이다. Capability와 Outcome은 unmeasured이며
  full fixture parity, MissionEnvelope, Common runtime, Worker invocation, Common execution은 false다.
- public workflow import 시 Mode package를 불러 순환 import하지 않도록 KISA threshold는 독립 typed
  contract이며 실제 KISA 모델 변환은 명시적 측정 호출 시점에만 수행한다.
- 기존 CLI/API, Mode runtime, Tool execution, artifact와 reader는 변경하지 않았다.

핵심 구현 위치:

- `src/pajin/workflow/engine_planner_parity.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_engine_planner_parity.py`
- `docs/orchestration/ENG-002B1-common-engine-planner-fixture-parity.md`
- `docs/adr/0105-measure-planner-parity-before-runtime-parity.md`

## 마지막 검증

- ENG-002B1·ENG-002A·PROF-002·PROF-001·ENG-001 집중 회귀: 145 passed
- Mode별 runtime 회귀: 75 passed, 5 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 221 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --cached --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_planner_parity.py tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002B2`의 가장 작은 실행 parity 수직 슬라이스를 설계한다.

1. Tool Registry contents, Policy configuration, Worker implementation/configuration, output role와
   Mode별 validator/candidate/post-processing constructor를 typed fixture coordinate로 결박한다.
2. legacy-direct와 Profile adapter 경로가 같은 fixture semantics를 사용하되 Run·request·receipt ID는
   독립적으로 fresh하도록 두 bounded 실행을 만든다.
3. Capability attenuation, Tool receipt, normalized Validator Outcome과 AI candidate, Bug Hunt
   triage/report, CTF result/writeup의 exact parity를 content-addressed evidence로 비교한다.
4. 좌표 drift, receipt/Outcome 차이, 후처리 누락, cross-Mode replay, incomplete evidence에서 full
   fixture parity와 MissionEnvelope/Common execution eligibility가 fail closed하도록 한다.

## 알려진 경계

- ENG-002B1은 Planner 행동만 측정하며 runner/scheduler/Worker/Validator 행동을 증명하지 않는다.
- fresh ID 두 종류 외의 필드는 정규화하지 않는다. runtime timestamp·receipt·Run identity 정규화는
  B2에서 별도 의미 계약이 필요하다.
- content-addressed parity record는 외부 서명이나 runtime attestation이 아니다.
- Windows symlink와 POSIX directory mode 검사는 현재 세션 권한/파일시스템 의미 차이로 전체 검증을
  끝까지 진행하지 못할 수 있다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
