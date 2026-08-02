# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `e3f77047f8d40d0fbf002a996f107da9f2cf6783`
- 현재 구현 체크포인트: `PROF-002` deterministic legacy Mode Profile compatibility
- 다음 구현: `ENG-002` 현재 Planner, Scheduler, Validation 경로 Adapter

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

PROF-002는 current legacy Campaign을 수정하지 않고 PROF-001 semantic Profile에 deterministic하게
투영하는 direct-call compatibility compiler다.

- `ai-redteam → pajin.profile.ai-assessment@1.0.0`,
  `bug-bounty → pajin.profile.bug-hunt@1.0.0`, `ctf → pajin.profile.ctf@1.0.0`만 등록한다.
- legacy Mode가 없는 `pajin.profile.pentest`는 자동 선택할 수 없다.
- `LegacyModeProfileCompiler`는 exact compiler ID/version/digest, PROF-001 catalog, 세 mapping digest,
  accepted Campaign API `pajin.dev/v1alpha1`을 결박한다.
- `LegacyCampaignProfileCompilationAuthority`는 complete detached Campaign과 input digest, source Mode,
  compiler, catalog, Profile, semantic projection과 output digest를 모두 결박한다.
- entry function과 wire reload validator가 모두 미지원 Campaign API version을 거부한다.
- projection은 Campaign digest·Mode·Profile·compiler·catalog identity만 포함하며 Campaign mutation,
  ROE 적용, MissionEnvelope, 실행 authority를 만들지 않는다.
- persisted audit event나 sealed Run은 생성하지 않는다. authority 자체가 후속 runtime integration에서
  기록할 portable audit payload다.
- 기존 CampaignMode·manifest·CLI·API·planner·validator·artifact·reader와 기본 경로는 변경하지
  않았다.

핵심 구현 위치:

- `src/pajin/workflow/profile_compatibility.py`
- `src/pajin/workflow/campaign_profile.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_profile_compatibility.py`
- `docs/orchestration/PROF-002-legacy-mode-profile-compatibility.md`
- `docs/adr/0103-compile-legacy-modes-to-profile-semantics-only.md`

## 마지막 검증

- PROF-002·PROF-001·ENG-001·Campaign·MissionEnvelope 집중 회귀: 101 passed
- Mode별 compatibility 회귀: 75 passed, 5 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 219 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002`의 가장 작은 수직 슬라이스를 설계한다.

1. 기존 Mode별 planner·validator와 공통 `MultiAgentCampaignRunner`/scheduler/projection 경계를 다시
   대조해 adapter가 선택할 exact implementation identity를 등록한다.
2. 동일 Campaign fixture에 대해 legacy direct selection과 PROF-002 selection이 같은 planner,
   validator, scheduler boundary와 unchanged Campaign digest를 산출하는 비실행 parity authority를
   먼저 만든다.
3. Tool registry, Policy, Worker, output path나 execution을 adapter가 생성하지 않게 하고
   Scope·Capability·ToolRequest·Outcome parity evidence가 모두 생기기 전 실행 authority를 false로
   유지한다.
4. cross-Mode implementation substitution, Campaign/compiler/Profile mutation, incomplete parity,
   pentest path, adapter drift와 authority flag escalation을 음성 테스트로 고정한다.

## 알려진 경계

- PROF-002는 semantic compatibility compiler이며 runtime adapter, persisted event, MissionEnvelope,
  Common Engine execution이 아니다.
- Windows symlink와 POSIX directory mode 검사는 현재 세션 권한/파일시스템 의미 차이로 전체 검증을
  끝까지 진행하지 못한다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
