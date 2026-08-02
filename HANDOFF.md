# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `2d3f8cb84a1496275f1881dd6dd5322b97d7a62e`
- 현재 구현 체크포인트: `PROF-001` code-owned Campaign Profile authority
- 다음 구현: `PROF-002` 기존 CampaignMode Compatibility Adapter

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

PROF-001은 ENG-001 비실행 Common Engine contract 위에 네 Mode 중립 Profile의 semantic authority만
등록한다.

- Profile ID는 `pajin.profile.pentest`, `pajin.profile.bug-hunt`, `pajin.profile.ctf`,
  `pajin.profile.ai-assessment`이며 version은 각각 `1.0.0`이다.
- 각 Profile은 reporting semantics, benchmark expectation, 현재 제품 경계에서 확인한 세 operating
  control, 공통 authority constraint, ENG-001 contract ID/digest를 content digest에 결박한다.
- 모든 Profile은 Campaign authorization window·budget·risk ceiling·Scope intersection·registered
  Capability subset을 요구하고 `roeDefaultsPolicy=campaign-authority-only`다.
- `CampaignProfileCatalog`는 canonical full four-Profile set과 complete ENG-001 contract를 하나의
  catalog digest에 결박한다.
- exact resolver는 ID/version으로 등록 Profile만 반환하며 Campaign 선택이나 Mode 컴파일을 하지
  않는다.
- legacy adapter, MissionEnvelope compiler, benchmark measurement, external submission, Profile/Common
  Engine execution 권한은 모두 false다.
- 기존 CampaignMode·manifest·CLI·API·planner·validator·artifact·reader는 변경하지 않았다.

핵심 구현 위치:

- `src/pajin/workflow/campaign_profile.py`
- `src/pajin/workflow/common_engine.py`
- `src/pajin/workflow/__init__.py`
- `tests/test_campaign_profile.py`
- `docs/orchestration/PROF-001-campaign-profile-authority.md`
- `docs/adr/0102-separate-profile-semantics-from-campaign-compilation.md`

## 마지막 검증

- PROF-001·ENG-001·Campaign·MissionEnvelope 집중 회귀: 75 passed
- Mode별 Profile 의미 호환 회귀: 75 passed, 5 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 218 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_manifest.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_bug_bounty.py tests\test_bug_bounty_runtime.py tests\test_ctf.py tests\test_ctf_runtime.py tests\test_ctf_suite.py tests\test_kisa_mode.py tests\test_ai_chat_mode.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`PROF-002`의 가장 작은 수직 슬라이스를 설계한다.

1. 기존 `CampaignMode` 세 값을 PROF-001의 `ai-assessment`, `bug-hunt`, `ctf` exact Profile에만
   deterministic하게 mapping한다. 아직 legacy Mode가 없는 `pentest`는 자동 선택하지 않는다.
2. compiler ID/version/digest, source Mode, complete Campaign input digest, Profile ID/version/digest,
   output digest를 하나의 비실행 compilation authority에 결박한다.
3. compiler는 Campaign을 수정하거나 ROE default를 적용하지 않으며 Profile semantic projection만
   출력한다. `MissionEnvelope`와 Common Engine 실행은 계속 false다.
4. unknown Mode/Profile/version, cross-Mode Profile substitution, Campaign mutation, compiler drift,
   pentest 자동 선택과 authority flag escalation을 음성 테스트로 고정한다.

## 알려진 경계

- PROF-001 Profile은 semantic registry record이며 Campaign 선택, Mode adapter, ROE 적용,
  MissionEnvelope, 실행 권한이 아니다.
- Windows symlink와 POSIX directory mode 검사는 현재 세션 권한/파일시스템 의미 차이로 전체 검증을
  끝까지 진행하지 못한다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
