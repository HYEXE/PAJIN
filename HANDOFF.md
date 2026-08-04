# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `0556391108d10f06fbd1187813fa0a1e22929f6a`
- 현재 구현 체크포인트: `HANDOFF-003` bounded UrgentObservation Fast Gate 검증·사전 리뷰 완료
- 다음 구현: `HANDOFF-004` capability-scoped reader

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

HANDOFF-003은 새 Observation store·message bus·replanner 없이 HANDOFF-002 result와 같은 current
MEM-003 Snapshot의 existing Canonical `GraphObservation`을 ref로 resolve하는 bounded decision
authority다.

- code-owned urgent type은 `credential-material-exposure`, `scope-boundary-violation`,
  `unsafe-side-effect` 세 가지뿐이다.
- origin은 `operator|trusted-core`, confidence는 exact `1.0`만 허용한다.
- exact Graph Action `produces` edge와 result Evidence `supported-by` edge를 각각 하나 요구한다.
- Observation value digest와 HANDOFF-002 sealed result Artifact SHA-256이 같아야 한다.
- handoff당 1 Observation·1 decision·1 local budget unit이며 predecessor가 없어 cycle을 표현할 수 없다.
- 유일한 disposition은 `stop-and-escalate`, 상태는 `admitted-not-applied`다.
- Observation summary/result content/prompt를 wire에 넣지 않고 replan·Scope·Capability·Permit·execution
  authority를 모두 false로 고정한다.

핵심 위치: `src/pajin/collaboration/urgent_observation.py`,
`src/pajin/collaboration/terminal_result.py`,
`tests/test_collaboration_urgent_observation.py`,
`docs/orchestration/HANDOFF-003-bounded-urgent-observation-fast-gate.md`,
`docs/adr/0115-admit-urgent-observations-as-bounded-stop-decisions.md`.

## 마지막 검증

- HANDOFF/Collaboration/Graph 집중 회귀: 57 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 232 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_urgent_observation.py tests\test_collaboration_handoff.py tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py tests\test_graph_admission.py tests\test_graph_projection.py tests\test_graph_consistency.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 사전 허상·버그 검토 결과

- target/Agent text가 fast decision을 직접 선택하지 못하도록 safe `GraphNodeRef`만 caller 입력으로 받고
  current Graph에서 trusted-core|operator Observation을 resolve한다.
- Observation type만 보지 않고 exact Action production, result Evidence support, sealed Artifact hash를 함께
  요구해 unrelated Observation/result 결합을 차단한다.
- terminal result Snapshot이 더 이상 current가 아니면 gate 전 Graph head 재검증에서 거부한다.
- fixed integer bound에 `True`가 `1`처럼 들어오지 않도록 strict pre-validation을 추가했다.
- exact retry의 시간만 무시하고 다른 Observation·result·Snapshot·policy는 equivocation으로 거부한다.
- `stop-and-escalate`는 admission record이지 실제 stop·Permit revoke·human notification 완료 증거가 아니다.

## 다음 조치

`HANDOFF-004`에서 기존 MEM-002 sealed Artifact와 HANDOFF-001 receiver, HANDOFF-002 terminal result,
HANDOFF-003 stop decision을 조사해 capability-scoped reader의 최소 경계를 설계한다. reader는 exact
receiver Agent·Capability Grant·Artifact·Snapshot에 결박하고 TTL·누적 byte limit·single-use 또는 bounded
read count를 강제해야 한다. stale/foreign/cross-Campaign receiver, expired/replayed Grant, Artifact mutation,
prompt interpretation, Scope·Permit·execution 확대를 fail closed하고 raw filesystem path를 노출하지 않는다.
HANDOFF-003의 admitted stop decision이 있는 경우 content read 허용 여부를 명시적으로 결정해야 하며,
이를 암묵적으로 무시하지 않는다.

## 알려진 경계

- HANDOFF authorities와 records 및 fast-gate local budget은 process-local이고 비영속이다.
- fast decision은 runtime Budget reservation이 아니며 기존 Permit을 revoke하거나 실제 실행을 중단하지 않는다.
- Graph와 Run store 사이에 분산 transaction이나 cross-host fence는 없다.
- receiver-bound content reader는 아직 없으며 HANDOFF-004 범위다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
