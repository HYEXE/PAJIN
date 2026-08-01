# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 현재 Git 기준: `2d4046001f3c2c227afa22273ab014ad304991dc`
- 현재 구현 체크포인트: `WALK-005A` 승인·Permit 기반 Candidate Admission 구현, 커밋 전
- 다음 구현: `WALK-005B` MCP Claim-bound Restricted Replay

## 재개 전 확인

다음 명령을 실행하고 결과가 이 문서와 다르면 실제 저장소를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

이 문서를 작성할 때 `main`, HEAD, 로컬 `origin/main`은 `2d40460`였다. WALK-004는 이미
커밋·push됐고 WALK-005A 변경이 worktree에 존재한다. 예상 변경 범위:

- `src/pajin/discovery/walking_validation.py`
- `src/pajin/capabilities/activation.py`, `src/pajin/capabilities/reconciliation.py`
- `src/pajin/discovery/__init__.py`
- `tests/test_walking_mcp_authorization.py`
- `tests/test_existing_capability_rollout.py`
- `docs/orchestration/WALK-005-approved-execution-candidate-admission.md`
- `docs/adr/0072-approved-permitted-walking-candidate-admission.md`
- `README.md`, `docs/rfc/0001-pajin-architecture-v2.md`
- `PLAN.md`, `HANDOFF.md`, `DECISIONS.md`

이 범위 밖의 변경이 보이면 사용자 변경으로 간주하고 먼저 원인을 확인한다. 진행 중인
merge, rebase, cherry-pick, 서버 또는 background helper는 없다.

## 현재 구현 상태

`WALK-001`~`WALK-004`와 `WALK-005A`가 구현됐다. 새 WALK-005A 경계는 다음을 보장한다.

- 봉인된 WALK-004 authority와 별도의 봉인 Capability 실행 Run을 다시 검증한다.
- 명시적 approval receipt가 exact Plan·Tool intent·request·canonical CapabilityGrant digest에
  결박되고 Permit dispatch claim보다 먼저 동일 Run에 기록돼야 한다.
- claimed·terminal Gateway audit event가 같은 Grant digest를 기록해야 하며, 기존 Grant 없는
  event는 계속 읽을 수 있지만 WALK-005A 실행 증거로는 사용할 수 없다.
- consumed ActionPermit, request/parameter digest, Capability·Tool·target, Policy, Worker,
  Gateway outcome digest와 기존 crash reconciliation을 exact equality로 검증한다.
- 대상 결과가 RAG 유래 MCP 인자, 독립 승인 제어 부재, 내부 데이터 접근을 명시적으로
  관찰한 경우에만 미확정 A02 Candidate를 생성한다.
- Candidate와 validity·impact·severity Atomic Claims는 실행 증거에서 결정론적으로 만들며
  caller-authored 치환을 거부한다.
- 상태는 `candidate-admitted-not-confirmed`이며 semantic decision, ReplayOutcome, confirmed
  Finding, report eligibility, Retest 결과를 만들지 않는다.
- 기본 demo MCP inspector는 승인 실패·내부 데이터 접근을 입력에서 합성하지 않으므로
  WALK-005A Candidate를 만들지 못한다.

핵심 구현 위치:

- `src/pajin/discovery/walking_validation.py`
- `src/pajin/capabilities/activation.py`, `src/pajin/capabilities/reconciliation.py`
- `tests/test_walking_mcp_authorization.py`
- `tests/test_existing_capability_rollout.py`
- `docs/orchestration/WALK-005-approved-execution-candidate-admission.md`
- `docs/adr/0072-approved-permitted-walking-candidate-admission.md`

## 마지막 검증

현재 WALK-005A worktree 기준:

- WALK/Capability/Replanning/문서 집중 회귀: 66 passed
- WALK/MCP/Adapter 집중 회귀: 50 passed
- Grant 없는 legacy dispatch event reader와 실제 Gateway Grant digest 기록 회귀 포함: 통과
- WALK-005A 양성 경로 5회 반복 결정성 검증: 매회 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 187 source files 통과
- 전체 `pytest -x -q`: 150 passed, 3 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_mcp_authorization.py tests\test_discovery_replanning.py tests\test_existing_capability_rollout.py tests\test_documentation.py
.\.venv\Scripts\ruff.exe check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 pytest 중단은 WALK-004 회귀가 아니라 `KNOWN_ISSUES.md`에 기록된 Windows 환경
제약이다.

## 다음 조치

현재 변경은 사용자 승인에 따라 다음 순서로 자동 진행한다.

1. 관련 파일만 stage하고 staged diff와 민감정보 포함 여부를 확인한다.
2. 한국어 Conventional Commit으로 WALK-005A 체크포인트를 생성한다.
3. `git -c http.sslBackend=schannel push origin main`으로 push한다.
4. local HEAD, tracking `origin/main`, 실제 원격 SHA와 clean worktree를 검증한다.

WALK-005A를 사전 커밋 검토·검증·push한 뒤 `WALK-005B`를 시작한다. 기존 KISA 전용 Replay를
MCP Candidate에 재사용하지 않고, fresh request·Capability·approval·Permit·Gateway execution과
exact Claim/observable을 결박하는 최소 MCP Restricted Replay 계약부터 구현한다.

## 외부 상태

기존 Notion 로드맵은 읽기 전용 역사 스냅샷이다. 활성 계획과 인수인계 권위는 각각
`PLAN.md`와 이 문서이며 Notion을 병렬 갱신하지 않는다.

현재 사용자는 기능별 사전 검토 후 자동 커밋·push와 다음 개발 진행을 승인했다.
