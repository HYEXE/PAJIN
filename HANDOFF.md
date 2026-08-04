# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `367958d045547af3b614fcf1cfc8043346588b52`
- 현재 구현 체크포인트: `SUP-002` Snapshot-only input·Target Taint 검증·사전 리뷰 완료
- 다음 구현: `SUP-003` Task·Replan·Stop·Escalation Proposal

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

`SUP-002`는 exact current MEM-003 `CollaborationSnapshot`을 model-visible input으로 투영하지만 모델은
호출하지 않는다.

- expected Campaign·Provider registration·model revision·configuration으로 SUP-001 binding을 재검증한다.
- existing MEM-003 verifier와 Graph Snapshot store로 current head와 exact Fact membership을 재검증한다.
- 모든 admitted CampaignFact statement를 node/value/text digest, `GraphContentOrigin`, Target Taint와
  함께 투영한다.
- `agent-derived`와 `target-derived`는 모두 `target-tainted-untrusted`로 유지해 Agent summary를 통한
  target content laundering을 차단한다.
- operator와 trusted-core text는 `trusted-metadata`지만 instruction authority는 없다.
- 모든 Fact와 Shared Artifact membership을 content-free safe reference로 보존하며 Artifact bytes는 읽지
  않는다. Evidence에는 content origin이 없으므로 Artifact ref는 보수적으로 target-tainted다.
- complete sorted membership과 Fact text/reference provenance, Artifact digest를 envelope 내부에서
  상호 결박하고 external verifier가 Graph-backed text/value를 전체 재구성한다.
- prompt message/role, model call, output draft, proposal, Capability, Permit, execution authority는 없다.

핵심 위치: `src/pajin/supervision/snapshot_input.py`,
`tests/test_supervisor_snapshot_input.py`,
`docs/orchestration/SUP-002-snapshot-only-target-taint-input.md`,
`docs/adr/0118-preserve-target-taint-in-supervisor-snapshot-input.md`.

## 마지막 검증

- SUP-002/SUP-001/Collaboration/Graph 집중 회귀: 65 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 236 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- SUP-001 직전 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_snapshot_input.py tests\test_supervisor_model_binding.py tests\test_collaboration_snapshots.py tests\test_graph_campaign_fact.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

- MEM-003 safe ref만 복사하면 model-visible Fact text의 taint를 증명할 수 없어, 기존 Graph authority에서
  exact admitted Fact만 다시 resolve하는 projection으로 제한했다.
- agent-derived content도 target input을 요약했을 수 있으므로 trusted로 승격하지 않고 target-tainted로
  보수 처리한다.
- Artifact content는 HANDOFF-004 reader 뒤에 유지하고 SUP-002는 bytes/path를 포함하지 않는다.
- Pydantic nested model instance 재검증에서 serialization shape가 달라질 수 있음을 집중 테스트에서 발견해,
  verified predecessor를 canonical JSON form으로 다시 입력한 뒤 envelope를 구성한다.
- Fact reference digest/origin/taint와 visible text, Artifact reference digest와 source Snapshot을 standalone
  validator에서도 상호 대조한다.
- omission, taint downgrade, schema substitution, cross-runtime binding, stale Snapshot, boolean coercion과
  authority escalation 음성 회귀를 추가했다.

## 다음 조치

`SUP-003`에서 verified `SupervisorSnapshotInput`과 SUP-001 `SupervisorShadowProposalDraft`를 입력으로 받되,
모델 rationale을 authority로 사용하지 않는 deterministic compiler를 설계한다. `task|replan|stop|escalate`
각 kind를 typed non-executable proposal로 변환하고 exact Snapshot/binding/taint digest를 결박한다. tainted text가
ToolRequest·arguments·Scope·Capability·Permit로 복사되거나, output kind가 current policy/state에서 허용되지
않는 경우 fail closed해야 한다. 실행 적용과 scheduler는 여전히 SUP-004 이후 범위다.

## 알려진 경계

- SUP-002 v1은 current Collaboration Snapshot projection만 materialize한다. SUP-001에 등록된 WALK-006
  Snapshot schema의 actual materialization은 별도 후속이 필요하다.
- operator/trusted-core origin은 Graph admission provenance를 신뢰하며 content semantics를 독립 attestation하지
  않는다.
- Artifact reference는 content origin을 세분할 수 없어 보수적으로 target-tainted다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
