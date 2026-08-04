# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `d9d0a6d4237fe4e771c11fcf0bf25aeb1abd2ba1`
- 현재 구현 체크포인트: `HANDOFF-004` capability-scoped reader 검증·사전 리뷰 완료
- 다음 구현: Phase 5 adversarial collaboration regression

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

HANDOFF-004는 새 Artifact store나 Grant ledger 없이 existing CapabilityLedger와 sealed Run loader를
사용해 HANDOFF receiver에게 한 번만 bytes를 반환하는 in-process reader다.

- delegated `maxCalls=1` Grant가 terminal receiver, Campaign, `collaboration.artifact.read`, exact Shared
  Artifact ID를 포함하고 live ledger record와 같아야 한다.
- reader-owned clock 기준 terminal completion부터 60초와 Grant expiry의 교집합만 허용한다.
- handoff·Artifact·receiver tuple당 1 attempt/read, 최대 65,536 cumulative bytes다.
- Capability consume이 모든 ancestor budget을 함께 차감하므로 fresh reader instance도 같은 Grant를
  replay할 수 없다.
- current MEM-003 Snapshot과 MEM-002 source를 재검증하고 sealed loader 뒤 size·SHA-256을 재확인한다.
- HANDOFF-003 urgent stop과 Graph head를 consume 전·bytes 반환 전에 재확인한다.
- outcome만 immutable bytes를 가지며 receipt는 content/path 없이 같은 reader에서만 resolve된다.
- receipt는 prompt·Scope·Capability·Permit·execution authority를 모두 false로 고정한다.

핵심 위치: `src/pajin/collaboration/reader.py`,
`src/pajin/collaboration/urgent_observation.py`,
`tests/test_collaboration_urgent_observation.py`,
`docs/orchestration/HANDOFF-004-capability-scoped-artifact-reader.md`,
`docs/adr/0116-read-shared-artifacts-through-single-use-receiver-grants.md`.

## 마지막 검증

- HANDOFF/Collaboration/Graph/Capability 집중 회귀: 81 passed, 1 skipped
- Ruff 전체 통과
- Linux 대상 strict mypy: 233 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_urgent_observation.py tests\test_collaboration_handoff.py tests\test_collaboration_snapshots.py tests\test_collaboration_artifacts.py tests\test_graph_admission.py tests\test_graph_projection.py tests\test_graph_consistency.py tests\test_capability.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 사전 허상·버그 검토 결과

- caller-provided time은 과거 timestamp replay를 허용할 수 있어 reader-owned clock으로 교체했다.
- reader-local read count만으로는 새 instance replay가 가능해 existing delegated Grant 자체를
  `maxCalls=1`로 요구하고 Capability lineage를 consume한다.
- standalone receipt를 권위로 오인하지 않도록 동일 reader의 stored receipt exact resolve를 요구한다.
- bytes 반환 전후에 current Graph head와 urgent stop을 재확인하며 stop이 있으면 Grant를 consume하지 않는다.
- attempt 시작 뒤 실패는 attempt와 이미 consume된 Grant를 복구하지 않아 partial delivery의 모호한 retry를
  차단한다.
- receipt에 result content, normalized relative path, absolute filesystem path, prompt/Tool arguments를 넣지
  않았다.

## 다음 조치

Phase 5 Exit Gate를 닫기 위해 MEM-001~003과 HANDOFF-001~004를 하나의 adversarial collaboration
regression으로 연결한다. memory poisoning, prompt relay, confused deputy, cross-Campaign substitution을
각 authority 경계에서 조합해 fail closed하는지 검증하고, 직접 Agent command가 wire나 reader output으로
승격되지 않는지 확인한다. 기존 unit coverage를 단순 반복하지 말고 여러 정상 authority를 섞은
cross-boundary replay와 omission 공격을 우선한다. 새로운 product authority가 필요하지 않다면 통합
테스트와 계약 정합화만 수행한다.

## 알려진 경계

- Handoff, urgent decision, reader attempts/receipts와 CapabilityLedger는 process-local이고 비영속이다.
- reader caller는 trusted in-process delivery adapter이며 remote receiver 인증은 제공하지 않는다.
- urgent stop/Graph head final check 뒤 발생하는 변화와 content 반환 사이에 distributed transaction은 없다.
- 실패 뒤 consumed Grant call은 refund되지 않고 burned attempt도 재개되지 않는다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
