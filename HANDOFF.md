# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `c9317359991b6da8f539c2fe124a99a4f371aa92`
- 현재 구현 체크포인트: `MEM-001` sealed CampaignFact admission 검증·사전 리뷰 완료
- 다음 구현: `MEM-002` SharedArtifactRef

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

MEM-001은 기존 `CampaignFactProposal`, `GraphAdmissionAuthority`, `GraphAdmissionEvent`,
`GraphCampaignFact`를 중복하지 않는 sealed source adapter를 추가했다.

- Proposal을 authority 진입 전에 canonical wire로 다시 파싱한다.
- 최대 64개, 각 1 MiB의 evidence와 1 MiB `campaign.json`만 하나의 verified Run snapshot으로 읽는다.
- exact Run ID, Campaign manifest와 단일 `campaign.started`, 현재 root, 모든 evidence SHA-256을 검증한다.
- producer와 전체 Agent·Task·request·Grant·Capability·Permit lineage는 기존 registry/verifier가 별도로
  판정하며 adapter가 caller lineage를 trusted로 등록하지 않는다.
- exact retry와 same-ID equivocation은 기존 GRAPH-002 Event Log 의미를 유지한다.
- admitted Fact node는 `validationState=admitted`를 authority만 부여하며 command, prompt, Scope,
  ToolRequest, Grant, Permit, execution flag가 없다.

핵심 구현 위치:

- `src/pajin/graph/campaign_fact.py`
- `tests/test_graph_campaign_fact.py`
- `docs/graph/MEM-001-sealed-campaign-fact-admission.md`
- `docs/adr/0110-reuse-canonical-graph-for-campaign-facts.md`

## 마지막 검증

- MEM-001·GRAPH-001/002/003 집중 회귀: 44 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 226 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark Harness 고정 fixture 만료로 중단
- 만료된 두 fixture 파일 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- `git diff --check` 통과

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_graph_campaign_fact.py tests\test_graph_models.py tests\test_graph_admission.py tests\test_graph_projection.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 다음 조치

`MEM-002`의 가장 작은 `SharedArtifactRef` 수직 슬라이스를 설계한다.

1. 기존 Graph Evidence, RunStore sealed artifact, portable Artifact transport와 Snapshot reference를 대조해
   중복되는 blob·manifest·reader 권위를 만들지 않는다.
2. Campaign·source Run/root·relative path·SHA-256·media type·size를 결박한 bounded reference만 허용한다.
3. reference 생성이 artifact 내용을 복제하거나 prompt를 relay하거나 receiver 권한·Scope·Capability를
   확대하지 않도록 한다.
4. path traversal, symlink, digest/size/media-type 변조, cross-Campaign/Run replay, stale root와 oversized
   artifact를 fail closed하는 최소 reader와 테스트를 만든다.

## 알려진 경계

- MEM-001은 sealed source 경계만 검증한다. producer와 full lineage는 기존 Graph registry/verifier가
  독립적으로 trusted source를 공급해야 하며 adapter가 이를 대신하지 않는다.
- Fact statement는 `origin`을 보존하는 비실행 데이터다. prompt 안전한 최소 receiver는 MEM-003 이후
  별도 Snapshot/reader 계약으로 구현해야 한다.
- semantic corroboration·contestation·invalidation과 Human correction authority는 후속 범위다.
- 전체 pytest는 기존 Benchmark Harness 고정 fixture 만료와 Windows symlink 권한 제약으로 완주하지
  못했다. 두 실패의 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 기록했다.
- 자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이
  문서이며 기존 Notion은 역사 자료로만 유지한다.
