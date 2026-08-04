# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `b0f740078edc45b96fa24d74ad4d0eccdc1f852a`
- 현재 구현 체크포인트: Phase 5 adversarial collaboration regression 완료
- 다음 구현: `SUP-001` SupervisorModelBinding

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

Phase 5는 MEM-001~003과 HANDOFF-001~004를 하나의 실제 Graph Snapshot chain으로 조합하는
adversarial regression까지 완료했다.

- empty genesis 뒤 admitted prompt-shaped CampaignFact가 포함된 current MEM-003 Snapshot을 만든다.
- HANDOFF-001은 statement가 아닌 safe Fact ref와 Agent/Task lineage만 중재한다.
- 같은 Graph chain의 후속 Snapshot에 exact Action·Observation·Evidence·sealed result Artifact를 추가한다.
- HANDOFF-002/003은 terminal result와 bounded stop decision을 content 없이 결박한다.
- HANDOFF-004는 exact receiver의 delegated single-use Grant로만 opaque bytes를 반환한다.
- prompt-shaped Fact statement와 Artifact payload는 Snapshot·Handoff·decision·receipt의 command/prompt가
  되지 않고 authority marker는 false로 유지된다.
- 서로 독립적으로 정상인 다른 Run/Campaign Snapshot·source와 다른 CapabilityLedger Grant의 조합은
  consume/content delivery 전에 fail closed한다.
- required urgent authority omission은 reader construction에서 fail closed한다.

핵심 위치: `tests/test_collaboration_urgent_observation.py`,
`src/pajin/collaboration/reader.py`, `PLAN.md`,
`docs/orchestration/HANDOFF-004-capability-scoped-artifact-reader.md`,
`docs/rfc/0001-pajin-architecture-v2.md`.

## 마지막 검증

- Phase 5 Collaboration/Graph/Capability 집중 회귀: 92 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 233 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_urgent_observation.py tests\test_collaboration_handoff.py tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py tests\test_graph_campaign_fact.py tests\test_graph_admission.py tests\test_graph_projection.py tests\test_graph_consistency.py tests\test_capability.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 사전 허상·버그 검토 결과

- 기존 per-authority 음성 테스트를 단순 집계하지 않고 하나의 append-only Graph chain에서 admitted Fact가
  receiver Snapshot과 terminal result까지 이어지는지 증명했다.
- prompt-shaped content는 authorized reader outcome의 opaque bytes에만 존재하고 저장 가능한 receipt나
  orchestration wire에서 명령·ToolRequest·Capability로 재해석되지 않는다.
- same-Campaign cross-Run과 cross-Campaign substitution, foreign live Grant를 각각 구성해 모든 부품이
  독립적으로 valid여도 authority 조합이 exact하지 않으면 거부됨을 확인했다.
- urgent authority를 `None`으로 생략할 수 없도록 reader dependency를 runtime에서 검증한다.
- 통합 검증을 위해 기존 제품 wire나 authority를 완화하거나 새 저장소를 만들지 않았다.

## 다음 조치

`SUP-001`에서 기존 WALK-006 `RegisteredWalkingShadowPolicy`/`WalkingShadowSupervisorAuthority`,
AgentRole.SUPERVISOR, Campaign Profile/Common Engine과 Phase 5 Snapshot/Handoff 경계를 조사해
SupervisorModelBinding의 실제 미구현 부분을 구분한다. 모델 이름이나 prompt text를 authority로 삼지
말고 provider/model immutable identity, version/config digest, allowed input Snapshot schema, output proposal
schema, shadow-only 상태를 content-addressed binding으로 고정한다. 기존 deterministic baseline을 변경하거나
Capability·Permit·execution authority를 부여하지 않는 최소 vertical slice로 시작한다.

## 알려진 경계

- Phase 5 Handoff/reader authorities와 CapabilityLedger는 process-local이고 비영속이다.
- reader caller는 trusted in-process delivery adapter이며 remote receiver 인증은 제공하지 않는다.
- urgent stop/Graph head final check 뒤 변화와 content 반환 사이에 distributed transaction은 없다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
