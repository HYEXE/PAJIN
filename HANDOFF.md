# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `300dfd3c360f8cf76f670167ce7a380ff5560f06`
- 현재 구현 체크포인트: `ENG-002C1` parity-bound 비확장 MissionEnvelope compiler 검증 완료
- 다음 구현: `ENG-002C2` explicit opt-in Common execution gate

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

ENG-002C1은 exact PROF-002 compilation과 ENG-002B2B behavioral parity를 별도 입력으로 받아, B2B가
실제로 측정한 compilation과 exact equality일 때만 기존 GRAPH-006 MissionEnvelope를 컴파일한다.

- B2B normalized Plan의 각 ToolRequest는 검증된 CAP-005 activation에서 정확히 하나의 signed release와
  CAP-002 materialization에 대응해야 한다.
- request ordinal·complete ToolRequest·request/parameter/target digest, activation set, signed release bundle,
  Capability definition·GRAPH reference·request-unit cost·release/review time window를 하나의 binding으로
  결박한다.
- Campaign method, Tool category/prohibit, risk, allow/deny Scope와 성공·Policy-allowed·Worker-succeeded·
  network-trusted receipt를 다시 검증한다.
- Envelope Capability·target은 측정 Plan subset이고, call·request-unit·rate·risk·time은 Campaign 및 signed
  release/review 상한과 교집합이다. 제한되거나 혼합된 weekly testing window는 Envelope에서 보존할 수
  없어 fail closed한다.
- request ID는 fixture 문자열 규칙에 결합하지 않고 Plan ordinal과 exact request equality로 검증한다.
- `missionEnvelopeCompiled=true`지만 `actionPermitIssued`, `commonRuntimeDispatched`,
  `commonExecutionAuthorized`는 모두 false다.
- `pajin.workflow` eager export는 Capability AI replay import cycle을 만들므로 공개 경로는
  `pajin.workflow.engine_mission_envelope`로 한정한다.

핵심 구현 위치:

- `src/pajin/workflow/engine_mission_envelope.py`
- `tests/test_engine_mission_envelope.py`
- `docs/orchestration/ENG-002C1-parity-bound-mission-envelope-compilation.md`
- `docs/adr/0108-compile-mission-authority-by-predecessor-intersection.md`

## 마지막 검증

- ENG-002C1·B2B·B2A·B1·Profile·Common·GRAPH-006·CAP-005 집중 회귀: 176 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 224 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check` 통과

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_mission_envelope.py tests\test_engine_behavioral_parity.py tests\test_engine_runtime_parity.py tests\test_engine_planner_parity.py tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_graph_action_permit.py tests\test_existing_capability_rollout.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-002C2`의 가장 작은 명시적 opt-in Common execution gate를 구현한다.

1. C1 authority를 현재 verified activation과 다시 대조하고 release head·review validity를 dispatch
   직전까지 재검증한다.
2. C1의 exact planned request·normalized parameter digest를 기존 GRAPH-006 ActionProposal,
   latest Snapshot·GraphDecision, registered Capability와 교차 결박한다.
3. 기존 single-use ActionPermit 원자 발급·소비와 Gateway dispatcher를 재사용하되, 명시적 opt-in
   호출 외에는 Common path를 선택하지 않는다.
4. stale Graph, foreign Envelope/Run, request·parameter·target·Capability 치환, release drift, duplicate
   dispatch와 legacy default-path 전환을 fail closed한다.

## 알려진 경계

- C1 authority reader는 signed bundle의 구조와 content identity를 재구성하지만 현재 lifecycle Trust
  Registry를 대체하지 않는다. C2는 verified activation을 다시 요구해야 한다.
- MissionEnvelope 자체는 exact request parameter를 담지 않으므로 C1 binding을 Proposal/Permit에 반드시
  연결해야 한다.
- C1은 fresh Run ID의 fixture 재사용만 차단하며 실제 RunStore 생성·비어 있음·Graph 최신성은 C2의
  실행 전 검증 책임이다.
- 전체 pytest 중단은 코드 회귀가 아니라 현재 Windows 계정의 symlink 생성 권한 제약이다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
