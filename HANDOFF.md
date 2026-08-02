# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `13e24d2245b1f6a3847ba600b348bc6ca911b177`
- 현재 구현 체크포인트: `ENG-002C2` explicit opt-in Common execution gate 검증 완료
- 다음 구현: `MEM-001` CampaignFact Proposal·Record

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

ENG-002C2는 C1 비실행 compiler를 실행 compiler로 오인하지 않고 별도 C2 compiler와 activation
authority를 만든다. C2 Envelope는 compiler identity 외 모든 권한 필드가 C1 Envelope와 정확히 같다.

- gate authority 생성 시 C1 activation set의 모든 signed release를 current verified CAP-005 activation에서
  다시 resolve한다. reader는 C1·activation set·source/new Envelope를 재구성한다.
- action intent는 C1/C2 authority, binding, release, Capability, measured request digest, execution request,
  parameter·target digest와 micro-USD reservation을 결박한다.
- B2B fixture request ID는 C1 Run·binding digest로 fresh deterministic ID를 파생한다. agent·Tool·target·
  method·arguments는 measured request와 exact equality다.
- exact intent digest와 latest Graph Snapshot을 가진 `action-proposal` Decision만 허용한다. Campaign,
  audit Run, actor, Grant subject·Tool·target·risk·call·time도 Permit 전에 검증한다.
- 기존 `GraphActionPermitAuthority`의 durable latest-Snapshot·budget·rate·single-use claim과
  `ExistingModeCapabilityGatewayDispatcher`의 release revalidation·claimed/terminal audit를 그대로 쓴다.
- gate instance는 한 C2 authority와 한 Permit writer에 고정된다. exact retry는 같은 Proposal/Permit을
  반환하고 `dispatched=false`이며 Worker는 한 번만 호출된다.
- legacy Mode 기본 경로, CLI/API, package eager export는 바뀌지 않는다.

핵심 구현 위치:

- `src/pajin/workflow/engine_execution_gate.py`
- `tests/test_engine_execution_gate.py`
- `docs/orchestration/ENG-002C2-explicit-common-execution-gate.md`
- `docs/adr/0109-activate-common-execution-with-a-separate-compiler.md`

## 마지막 검증

- ENG-002C2·C1·B2B·B2A·B1·Profile·Common·GRAPH-006·CAP-005 집중 회귀: 180 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 225 source files 통과
- 전체 `pytest -x -q`: 360 passed, 8 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check` 통과

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_engine_execution_gate.py tests\test_engine_mission_envelope.py tests\test_engine_behavioral_parity.py tests\test_engine_runtime_parity.py tests\test_engine_planner_parity.py tests\test_engine_adapter.py tests\test_profile_compatibility.py tests\test_campaign_profile.py tests\test_common_engine_contract.py tests\test_graph_action_permit.py tests\test_existing_capability_rollout.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`MEM-001`의 가장 작은 CampaignFact Proposal·Record 수직 슬라이스를 구현한다.

1. 기존 Graph Event·Snapshot·Observation·Finding·Claim과 협업·handoff 관련 계약을 대조해 Fact와
   중복되는 authority를 먼저 구분한다.
2. Agent가 제안하는 비권위 `CampaignFactProposal`과 admission 뒤의 immutable `CampaignFactRecord`를
   Campaign·source Run/root·producer·evidence digest에 결박한다.
3. 직접 Agent 명령, prompt relay, execution Capability, Scope 확대를 금지하고 receiver가 최소 Snapshot만
   읽을 수 있는 후속 MEM-002/003 경계를 미리 침범하지 않는다.
4. forged evidence, cross-Campaign/Run substitution, stale source, duplicate/equivocal Fact와 authority flag
   forgery를 fail closed하는 additive reader·집중 테스트를 만든다.

## 알려진 경계

- C2는 current activation, Graph store, RunStore, Gateway와 Grant를 caller가 명시적으로 공급하는
  direct-call opt-in 경계다. organization-wide registry fetch나 default wiring이 아니다.
- micro-USD reservation은 intent/Decision에 결박된 caller 선언이며 provider billing 측정값이 아니다.
- 첫 실제 C2 dispatch 회귀는 CTF Profile 경로다. gate는 Mode 분기가 없고 C1 all-three-mode binding을
  소비하지만 AI/Bug Hunt Common dispatch의 별도 end-to-end 증명은 아직 없다.
- Permit claim 뒤 Gateway 실패·불확실 결과는 기존 안전 우선 계약대로 consumed terminal이며 자동
  redispatch하지 않는다.
- 전체 pytest 중단은 코드 회귀가 아니라 현재 Windows 계정의 symlink 생성 권한 제약이다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
