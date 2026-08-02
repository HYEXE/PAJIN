# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `80a3adddd48f6f2262f23c3763cff4c0efc7bfb4`
- 현재 구현 체크포인트: `ENG-001` 공통 Campaign Execution Engine 비실행 계약
- 다음 구현: `PROF-001` Pentest, Bug Hunt, CTF, AI Assessment Profile

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

ENG-001은 기존 `MultiAgentCampaignRunner`를 새 실행기로 복제하지 않고, 세 legacy Mode가 이미
공유하는 실행 경계를 content-addressed migration contract로 고정한다.

- `CommonCampaignEngineContract`는 `ai-redteam`, `bug-bounty`, `ctf`와 Campaign snapshot,
  budget/rate-limit, Capability/Policy, Worker dispatch, Candidate validation, sealed Run audit의
  여섯 경계를 정확한 순서로 고정한다.
- `CommonCampaignExecutionPlanAuthority`는 complete detached Campaign, canonical Campaign digest,
  source Mode, registered engine contract를 하나의 authority digest에 결박한다.
- `campaign_manifest_digest()`는 기존 Capability Graph Campaign digest와 동일한 wire identity를
  유지한다. 기존 `capability_graph_campaign_digest()` 이름과 결과도 유지된다.
- Plan은 `profile-required-not-executable`이며 Profile compilation, MissionEnvelope, parity
  evidence, Common Engine execution이 모두 false다.
- 기존 Mode manifest·CLI·API·planner·validator·Run artifact·reader와 기본 실행 경로는 변경하지
  않았다.

핵심 구현 위치:

- `src/pajin/workflow/common_engine.py`
- `src/pajin/domain/models.py`
- `src/pajin/control_plane/capability_deployment.py`
- `tests/test_common_engine_contract.py`
- `docs/orchestration/ENG-001-common-campaign-engine-contract.md`
- `docs/adr/0101-register-common-engine-boundary-before-profile-activation.md`

## 마지막 검증

- ENG-001·Campaign digest·Capability Graph·MissionEnvelope 집중 회귀: 77 passed
- Mode별 shared runner 경로: 83 passed, Windows POSIX mode 환경 실패 1건
- 해당 POSIX mode 단일 테스트: Windows에서 `0700`을 `0777`로 보고해 동일하게 실패
- Ruff 전체 통과
- Linux 대상 strict mypy: 217 source files 통과
- 전체 `pytest -x -q`: 333 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_common_engine_contract.py tests\test_manifest.py tests\test_existing_capability_rollout.py tests\test_graph_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_orchestration.py tests\test_bug_bounty_runtime.py tests\test_ctf_runtime.py tests\test_ai_chat_mode.py tests\test_workflow_integrity_regressions.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`PROF-001`의 가장 작은 수직 슬라이스를 설계한다.

1. ADR-0046, ADR-0047, ENG-001, `CampaignManifest`, `MissionEnvelope`를 대조해 Profile이 표현할
   운영 의미와 절대 확대할 수 없는 Campaign 권한을 구분한다.
2. `pentest`, `bug-hunt`, `ctf`, `ai-assessment`의 code-owned Profile ID/version/digest와
   reporting·benchmark·compatibility 의미를 Mode 중립 계약으로 정의한다.
3. PROF-001은 legacy Mode adapter를 구현하지 않는다. source `CampaignMode` 컴파일과 audit event는
   `PROF-002`에 남기고, Profile 자체가 Grant·Permit·ToolRequest를 생성하지 못하게 한다.
4. Profile substitution, unknown version, duplicate/unsorted semantics, authority flag escalation을
   음성 테스트로 고정한다.

## 알려진 경계

- ENG-001은 실행기 활성화가 아니라 migration authority다. Profile·MissionEnvelope·parity가 없으면
  공통 경로를 실행할 수 없다.
- Windows symlink와 POSIX directory mode 검사는 현재 세션 권한/파일시스템 의미 차이로 전체 검증을
  끝까지 진행하지 못한다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
