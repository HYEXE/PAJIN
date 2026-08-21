# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-21
- 작업 체크아웃: `/Users/hyeonexcel/Workspace/HYEXEN/PAJIN`
- 브랜치: `main`
- 직전 HEAD: `adc43c3c9f6b7d55641cdd2cdbc29f773c1bfb3c`
- 최종 원격 확인: GitHub `origin/main == 75f6eb08c9534cfd27a5cd0516f15dde8b76e8a4`
- 현재 ahead/behind: 이 체크포인트 커밋 후 local `main`이 `origin/main`보다 `3/0`
  ahead/behind
- 완료된 runtime 단계: `PENTEST-004C2B2`, `REDTEAM-001A`, `REDTEAM-001B`,
  `REDTEAM-001C`, `REDTEAM-001D`, `REDTEAM-002`
- 현재 우선순위: `UX-008` initial Scope·Evidence·Finding·report product flow
- 다음 우선순위: `DOMAIN-001` code-owned Security Domain taxonomy
- 로컬 커밋: `cff412a7e0091dbb477cfa39bed8f1520717c4b3`
  (`feat(redteam): 초기 실행 Capability 부트스트랩 완성`)
- 로컬 커밋: `adc43c3c9f6b7d55641cdd2cdbc29f773c1bfb3c`
  (`fix(workflow): Planner 위협 분류 정규화 순서 고정`)
- 현재 체크포인트: 이 문서를 포함한 REDTEAM-002 contract·ADR·sealed measurement
  source/aggregate runtime·tests와 상태 문서 로컬 커밋
- push·Pull Request·merge·배포: 수행하지 않음

이 문서는 로컬 REDTEAM-001C/D·Planner 정규화 수정 커밋과 이 문서를 포함한 REDTEAM-002
체크포인트 커밋을 기록한다. 실제 Git과 파일시스템이 다르면 실제 상태를 우선한다.

## 구현 상태

### implemented

- REDTEAM-001C: 기존 Boolean SQLi Capability를 사용하는 `redteam-web-v1@1.0.0` exact
  three-request synthetic Web profile
- REDTEAM-001D: `pajin.ai.mcp.instruction-hijacking-inspection@1.0.0`과
  `redteam-mcp-v1@1.0.0` exact registered MCP profile
- 기존 CAP-005 `v1alpha1` seven-release inventory와 digest를 보존하는 opt-in MCP
  release/activation `v1alpha2` 및 eight-release Worker deployment `v1alpha3`
- exact `mcp.demo-security.inspect-text@1.0.0` / `demo-security:inspect_text`, 고정 target과
  synthetic input, POST, T0, read-only, network-none, no-cleanup, non-parallel, one request unit,
  approval-required 경계
- MissionEnvelope, signed release/activation, Campaign target·ROE, Proposal reservation,
  deployment-pinned approval, ActionPermit, Gateway, Worker, normalized result, CAP-002 Oracle와
  exact retry no-redispatch 재사용
- 다른 Tool·method·target·input·server registration, request-unit 증감, Campaign target 확장·필수
  category 누락, generic envelope와 legacy deployment relabel, missing approval을 Permit 전에 거부
- REDTEAM-002: exact Profile·CAP-002·CAP-003·CAP-006 denominator, sealed raw source recorder와
  four-profile aggregate runner/report
- detection recall, false-positive, precision, Replay success, request units, Tool calls, cost,
  evidence completeness와 policy-denial correctness의 exact numerator/denominator
- REDTEAM-001이 만들지 않는 valid Finding·cleanup과 미등록 MCP negative/Replay path는 0이 아닌
  explicit `not-applicable`; report의 execution/Finding/Scope authority marker는 false

### contract/scaffold only

- HTTP/OpenAPI/auth/file-upload, RAG/MCP/tenant/internal API discovery와 walking-chain은 Graph
  knowledge와 비실행 Hypothesis contract를 제공하지만 일반 domain execution authority가 아니다.
- ARCH-002와 ADR-0204~0206은 accepted multi-domain architecture decision이며 runtime Security
  Domain registry나 domain-aware Worker registry 구현이 아니다.
- REDTEAM-002 reference tests는 versioned contract·aggregation·tamper rejection을 검증하지만 실제
  외부 Target이나 production benchmark score가 아니다.

### planned

- `UX-008`
- `DOMAIN-001~006` taxonomy, Graph semantics, Capability projection, Worker boundary,
  cross-domain admission과 benchmark extension
- 일반 Network, System, Application, Mobile, Cloud, Cryptography와 Forensics vertical slice

## 이번 체크포인트 변경 파일

- `src/pajin/benchmark/redteam.py`, `src/pajin/benchmark/__init__.py`
  - REDTEAM-002 exact profile denominator, raw Observation, sealed recorder, aggregate report와
    verified loader
- `tests/test_benchmark_redteam.py`
  - exact inventory/applicability, metric aggregation, missing coverage, authority drift,
    Finding-claim과 post-seal mutation rejection
- `docs/benchmark/REDTEAM-002-initial-profile-benchmark.md`
- `docs/adr/0209-measure-redteam-profiles-without-finding-authority.md`
- `PLAN.md`, `README.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`, `HANDOFF.md`
  - 완료 상태, 다음 우선순위, measurement/non-authority 제한과 문서 탐색 동기화

기존 BENCH-001, CAP-003, CAP-006, REDTEAM-001A~D, PENTEST와 Capability/Permit/Gateway/Worker
wire는 유지한다. REDTEAM-002는 Profile이나 Security Domain으로 권위를 추론하지 않으며 report
자체도 Finding·Scope·execution authority가 아니다.

## 검증 결과

- REDTEAM-002 집중 회귀:
  - `.venv/bin/python -m pytest -q tests/test_benchmark_redteam.py`
  - `5 passed`
- BENCH-001·CAP-006·REDTEAM 인접 회귀:
  - `.venv/bin/python -m pytest -q tests/test_benchmark_redteam.py
    tests/test_walking_benchmark_measurement.py tests/test_capability_metrics.py
    tests/test_existing_capability_rollout.py -k 'redteam or benchmark or metric or replay_support'`
  - `54 passed, 47 deselected`
- 문서 정책:
  - `.venv/bin/python -m pytest -q tests/test_documentation.py`
  - `2 passed`
- 정적 검증:
  - `.venv/bin/ruff check src tests containers scripts`: 통과
  - `.venv/bin/python -m mypy --strict src/pajin`:
    `Success: no issues found in 316 source files`
  - `.venv/bin/python -m compileall -q src`: 통과
  - `git diff --check`: 통과
- 전체 회귀:
  - `.venv/bin/python -m pytest -q
    --deselect=tests/test_control_plane_worker_identity.py::test_direct_mtls_binds_worker_subject_without_requiring_human_certificate
    --deselect=tests/test_replay_worker_process.py::test_replay_worker_entrypoint_process_executes_one_exact_replay`
  - `4168 passed, 67 skipped, 2 deselected`
- sandbox loopback bind가 필요한 제외 2건을 별도 권한 경계에서 실행:
  - `2 passed`

Linux CI는 현재 REDTEAM-002 체크포인트 커밋에 대해 실행되지 않았다. 위 검증은 macOS project
`.venv`에서 수행했다.

## 알려진 제한

- REDTEAM-001D는 fixed local stdio demo MCP server와 synthetic input 하나만 지원한다. 외부 MCP
  server, discovery-selected Tool, arbitrary arguments, network/resource/prompt/credential access를
  허용하지 않는다.
- REDTEAM-001C는 단일 synthetic local Web endpoint만 지원하며 arbitrary Web target, scanner,
  crawler, browser나 production Web conformance를 제공하지 않는다.
- fixture-backed Worker 결과는 실제 외부 Target 운영 증거가 아니다.
- REDTEAM-002 reference report는 deterministic measurement-adapter fixture이며 production score가
  아니다. adapter가 원 source lineage와 raw fact의 진실성을 책임진다.
- 성공한 Tool/Oracle 결과는 독립 Replay, validation-floor 만족, Finding, impact, severity,
  report, Scope 확장이나 후속 실행 권위가 아니다.
- cross-host Worker fence와 domain-aware Worker registry는 구현되지 않았다.
- 일반 multi-domain runtime은 planned 상태다.

## Git 재개 확인

```bash
git fetch --prune origin
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count origin/main...HEAD
git diff --check
.venv/bin/python -m pytest -q tests/test_documentation.py
```

REDTEAM-002 변경은 이 문서를 포함한 현재 로컬 커밋으로 보존한다. local `main`의
REDTEAM-001C/D, Planner 정규화 수정과 REDTEAM-002 커밋은 push되지 않았다. 재개 시
merge/rebase/cherry-pick/revert/bisect 진행 상태와 staged/unstaged/untracked 파일을 다시
확인한다.

## 다음 한 단계

`UX-008`에서 현재 REDTEAM-001 Observation과 REDTEAM-002 metric을 Scope·Evidence·Finding·report
product flow에 투영하되, valid Finding이 없는 Profile result를 confirmed Finding처럼 표시하지 않는다.
기존 Operator view, VAL-003 Profile floor, sealed Evidence loader와 Finding projection을 먼저 감사하고
read-only projection부터 닫는다.
