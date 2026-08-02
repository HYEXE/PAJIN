# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `a0d06f28c2f5179a88f9dd74ce5f571de1b81059`
- 현재 구현 체크포인트: `ENG-002A` exact implementation adapter와 structural-only parity authority
- 다음 구현: `ENG-002B` 동일 fixture behavioral parity와 opt-in 실행 gate

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

ENG-002A는 PROF-002 compilation 결과에 기존 Mode 구현 identity를 결박하는 direct-call 비실행
adapter selection authority다.

- `ai-redteam`은 `KISAPlannerRuntime`, `KISAValidatorRuntime`, `KISACandidateProducer`에 결박한다.
- `bug-bounty`는 `BugBountyPlannerRuntime`, `BugBountyValidatorRuntime`에 결박한다.
- `ctf`는 `CTFTriagePlannerRuntime`, `CTFFlagValidatorRuntime`에 결박한다.
- 세 Mode 모두 기존 `MultiAgentCampaignRunner`, `MultiAgentExecutionScheduler`,
  `MultiAgentResultProjector`의 exact module-qualified identity를 공유한다.
- catalog는 exact ENG-001 contract와 PROF-002 compiler, 세 adapter의 canonical set을 결박하며
  pentest legacy adapter를 등록하지 않는다.
- Scope·Capability·ToolRequest·Outcome 네 dimension은 structural evidence로 모두 기록하지만
  `fixtureMeasured=false`, `parityProven=false`, `fixtureParityProven=false`다.
- runtime construction, Tool Registry, Policy, Worker, output path, MissionEnvelope, Common execution
  권한은 모두 false다. 기존 CLI/API와 Mode runtime은 변경하지 않았다.

핵심 구현 위치:

- `src/pajin/workflow/engine_adapter.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_engine_adapter.py`
- `docs/orchestration/ENG-002A-common-engine-implementation-adapter.md`
- `docs/adr/0104-register-implementation-identity-before-runtime-parity.md`

## 마지막 검증

- ENG-002A·PROF-002·PROF-001·ENG-001·Campaign 집중 회귀: 126 passed
- Mode별 runtime 회귀: 75 passed, 5 skipped
- Mode-first import와 adapter catalog 지연 class 해석 회귀: 통과
- Ruff 전체 통과
- Linux 대상 strict mypy: 220 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --cached --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002B`의 가장 작은 수직 슬라이스를 구현한다.

1. 각 Mode runtime constructor와 Mode별 실행·후처리 경로를 대조해 동일 fixture 비교에 필요한
   입력과 관찰 출력을 정확히 고정한다.
2. legacy direct path와 별도 opt-in adapter path를 같은 Campaign·Tool Registry·Policy·Worker·output
   좌표에서 실행하되, 기존 기본 경로를 바꾸지 않는다.
3. Scope·Capability·ToolRequest·receipt·Outcome과 AI candidate, Bug Hunt triage, CTF result/writeup을
   content-addressed parity evidence로 비교한다.
4. constructor drift, request/receipt/outcome 차이, 후처리 누락, cross-Mode replay와 미완전 evidence에서
   parity·MissionEnvelope·Common execution eligibility가 fail closed하도록 한다.

## 알려진 경계

- class identity 일치는 행동 parity나 source/binary attestation이 아니다.
- ENG-002A는 runtime input, 실행 receipt, Outcome과 Mode별 후처리를 아직 결박하지 않는다.
- Windows symlink와 POSIX directory mode 검사는 현재 세션 권한/파일시스템 의미 차이로 전체 검증을
  끝까지 진행하지 못할 수 있다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
