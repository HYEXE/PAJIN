# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `0b7f1a0552590b52a222327c1b81999c19f38466`
- 현재 구현 체크포인트: `HANDOFF-001` Supervisor-mediated AgentHandoff 검증·사전 리뷰 완료
- 다음 구현: `HANDOFF-002` terminal result handoff

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

HANDOFF-001은 새 Agent registry·TaskGraph·message bus 없이 기존 AgentNode·TaskNode와 exact current
MEM-003 CollaborationSnapshot을 process-local Supervisor가 중재하는 non-executable handoff다.

- sender completed/source Task succeeded, receiver spawned|running/destination Task waiting을 요구한다.
- destination Task가 source Task에 의존하고 각 Task assignment와 Agent가 exact 일치해야 한다.
- 양 Agent의 parentAgentId가 admitting Supervisor와 같고 self/Supervisor handoff를 금지한다.
- complete Agent/Task model digest, enum purpose, Snapshot ID/digest만 wire에 포함한다.
- Proposal당 최초 admission 하나만 유지하며 retry의 다른 admittedAt은 새 record를 만들지 않는다.
- content read, prompt interpretation, Scope, Capability, Permit, execution authority는 모두 false다.

핵심 위치: `src/pajin/collaboration/handoff.py`, `tests/test_collaboration_handoff.py`,
`docs/orchestration/HANDOFF-001-supervisor-mediated-agent-handoff.md`,
`docs/adr/0113-mediate-handoffs-with-existing-agent-task-lineage.md`.

## 마지막 검증

- Collaboration/Graph 집중 회귀: 36 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 230 source files 통과
- 직전 MEM-003 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark fixture 만료
- 직전 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_handoff.py tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py tests\test_graph_projection.py tests\test_graph_consistency.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`HANDOFF-002`에서 HANDOFF-001 admitted record와 destination Task의 terminal result를 exact Agent·Task·
CollaborationSnapshot·result artifact digest에 결박한다. 성공/실패/취소를 구분하고 result content를
복제하지 않으며 stale/foreign/duplicate/equivocal result와 authority 확대를 fail closed한다.

## 알려진 경계

- Supervisor authority와 record는 process-local이며 서명·영속 store가 없다.
- handoff admission은 destination Task를 schedule하거나 Capability/Permit를 발급하지 않는다.
- receiver-bound content reader는 HANDOFF-004 범위다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
