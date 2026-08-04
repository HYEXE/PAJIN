# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `4e4a3c7ba3b62e3bbbee5868968655d85623f4ea`
- 현재 구현 체크포인트: `MEM-002` bounded SharedArtifactRef 검증·사전 리뷰 완료
- 다음 구현: `MEM-003` CollaborationSnapshot

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

MEM-002는 새 blob·manifest·reader 권위를 만들지 않고 기존 `GraphEvidence` identity와 기존
RunStore `SealedArtifact` record를 연결하는 metadata-only `SharedArtifactRef`를 추가했다.

- `pajin.dev/shared-artifact-ref/v1alpha1`의 전체 wire를 content-addressed ID·digest에 결박한다.
- Campaign, Evidence-kind GraphNodeRef, source Run/current root, normalized relative path, SHA-256,
  media type, size를 하나의 reference에 결박한다.
- 최대 1 MiB artifact와 1 MiB `campaign.json`만 기존 symlink-safe bounded snapshot reader로 읽는다.
- `campaign.json` 자체, traversal, missing/unsealed/mutated/symlink/oversized artifact, metadata 변조,
  cross-Campaign/Run, stale root, identity equivocation을 fail closed한다.
- verifier는 canonical reference만 반환하며 artifact bytes나 filesystem path를 반환하지 않는다.
- Graph admission, content embedding, prompt relay, receiver authority, Scope expansion, Capability,
  execution authority는 모두 부여하지 않는다.

핵심 구현 위치:

- `src/pajin/collaboration/artifacts.py`
- `tests/test_collaboration_artifacts.py`
- `docs/graph/MEM-002-bounded-shared-artifact-reference.md`
- `docs/adr/0111-reference-shared-artifacts-through-existing-authorities.md`

## 마지막 검증

- MEM-002 집중 테스트: 9 passed, 1 skipped
- MEM-002·Graph·RunStore 인접 회귀: 122 passed, 2 skipped, 4 existing Windows failures
  - 비이식 Windows 파일명 정규화 3건
  - 테스트 심볼릭 링크 생성 권한 `WinError 1314` 1건
- Ruff 전체 통과
- Linux 대상 strict mypy: 228 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark Harness 고정 fixture 만료로 중단
- 만료된 두 fixture 파일 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_artifacts.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_collaboration_artifacts.py tests\test_graph_campaign_fact.py tests\test_graph_models.py tests\test_graph_admission.py tests\test_graph_projection.py tests\test_integrity.py tests\test_verified_snapshot.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 다음 조치

`MEM-003`의 가장 작은 `CollaborationSnapshot` 수직 슬라이스를 설계한다.

1. 기존 `GraphSnapshot`/`GraphSnapshotRef`와 admission event reader를 재사용해 새 Graph store나
   snapshot authority를 만들지 않는다.
2. exact Campaign·Graph Snapshot identity와 admitted CampaignFact·GraphEvidence membership을
   deterministic, unique, sorted 집합으로 결박한다.
3. MEM-002 `SharedArtifactRef`는 exact admitted Evidence membership과 일치할 때만 Snapshot에 넣되
   artifact content는 읽거나 포함하지 않는다.
4. forged/unadmitted Fact·Evidence, duplicate/equivocal member, cross-Campaign/Snapshot/Run,
   stale Graph Snapshot, target-derived prompt relay, Scope·Capability·execution 확대를 fail closed한다.

## 알려진 경계

- `SharedArtifactRef`는 exact Evidence identity와 sealed source metadata만 증명한다. Graph admission은
  MEM-003이 기존 Graph Snapshot authority를 통해 별도로 증명해야 한다.
- MEM-002 verifier의 내부 바이트 검증은 content access API가 아니다. receiver·Capability·TTL·byte
  limit에 결박된 실제 reader는 HANDOFF-004 범위다.
- Fact statement와 artifact content는 실행되지 않는 tainted data다. prompt-safe receiver와 semantic
  corroboration·contestation·invalidation은 아직 없다.
- 전체 pytest는 기존 Benchmark fixture 만료와 Windows symlink 권한 제약으로 완주하지 못했다.
  인접 무결성 회귀의 Windows 비이식 파일명 정규화 3건도 코드 회귀와 구분해 `KNOWN_ISSUES.md`에
  기록했다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
