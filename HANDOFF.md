# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-20
- 작업 체크아웃: `/Users/hyeonexcel/Workspace/HYEXEN/PAJIN`
- 브랜치: `main`
- 기준 HEAD: `75f6eb08c9534cfd27a5cd0516f15dde8b76e8a4`
- 최종 원격 확인: GitHub `origin/main == 75f6eb08c9534cfd27a5cd0516f15dde8b76e8a4`
- 현재 ahead/behind: `0/0`; 작업 시작 시 working tree: clean
- 완료된 runtime 단계: `PENTEST-004C2B2`, `REDTEAM-001A`, `REDTEAM-001B`,
  `REDTEAM-001C`, `REDTEAM-001D`
- 현재 우선순위: `REDTEAM-002` initial detection·false-positive·replay·cost benchmark
- 다음 우선순위: `UX-008` initial Scope·Evidence·Finding·report product flow
- 이번 working tree: REDTEAM-001C/D contract·ADR·runtime·positive/adversarial tests와 상태 문서
- commit·push·Pull Request·merge·배포: 수행하지 않음

이 문서는 현재 미커밋 working tree를 기록한다. 실제 Git과 파일시스템이 다르면 실제 상태를
우선한다.

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

### contract/scaffold only

- HTTP/OpenAPI/auth/file-upload, RAG/MCP/tenant/internal API discovery와 walking-chain은 Graph
  knowledge와 비실행 Hypothesis contract를 제공하지만 일반 domain execution authority가 아니다.
- MCP benchmark mapping은 등록돼 있지만 실제 detection·precision·replay·cost 측정 결과가 아니다.
- ARCH-002와 ADR-0204~0206은 accepted multi-domain architecture decision이며 runtime Security
  Domain registry나 domain-aware Worker registry 구현이 아니다.

### planned

- `REDTEAM-002`, `UX-008`
- `DOMAIN-001~006` taxonomy, Graph semantics, Capability projection, Worker boundary,
  cross-domain admission과 benchmark extension
- 일반 Network, System, Application, Mobile, Cloud, Cryptography와 Forensics vertical slice

## 변경 파일

- `src/pajin/tools/mcp.py`
  - REDTEAM-001D exact typed input과 normalized output contract
- `src/pajin/capabilities/existing.py`, `rollout.py`, `activation.py`, `__init__.py`
  - opt-in MCP CAP-001/002 bundle, host Oracle, benchmark mapping, additive release/activation wire
- `src/pajin/control_plane/capability_deployment.py`
  - eight-release `v1alpha3` loader와 closed registered MCP Tool inventory
- `src/pajin/control_plane/redteam_profiles.py`, `executors.py`
  - REDTEAM Web/MCP profile digest, product validator, Job/result routing
- `tests/test_existing_capability_adapters.py`, `tests/test_existing_capability_rollout.py`
  - base digest preservation, exact MCP success/retry/Worker payload와 adversarial authority tests
- `docs/orchestration/REDTEAM-001C-bounded-web-capability-profile.md`,
  `docs/orchestration/REDTEAM-001D-registered-mcp-capability-profile.md`
- `docs/adr/0207-compose-bounded-web-redteam-profile.md`,
  `docs/adr/0208-register-mcp-capability-without-discovery-authority.md`
- `docs/capability/CAP-005-existing-mode-tool-replay-adapters.md`
  - unchanged base inventory와 additive MCP extension 동기화
- `PLAN.md`, `README.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`,
  `docs/orchestration/REDTEAM-001B-multi-turn-llm-rag-profile.md`
  - 실제 완료 상태, 다음 우선순위, 제한과 문서 탐색 동기화

기존 seven-release CAP-005 `v1alpha1`, activation `v1alpha1`, Worker deployment `v1alpha1/2`,
REDTEAM-001A/B/C, PENTEST와 benchmark wire는 유지한다. legacy
`CapabilityDefinition.domain=ai-redteam`는 signed identity로만 검사하며 Security Domain이나
실행 권위로 해석하지 않는다.

## 검증 결과

- REDTEAM-001D 핵심·적대 회귀:
  - `.venv/bin/python -m pytest -q tests/test_existing_capability_adapters.py
    tests/test_existing_capability_rollout.py -k 'registered_mcp or redteam_mcp or mcp_deployment'`
  - `16 passed, 81 deselected`
- MCP·Capability·walking 인접 회귀:
  - `.venv/bin/python -m pytest -q tests/test_mcp.py tests/test_walking_mcp_authorization.py
    tests/test_existing_capability_adapters.py tests/test_existing_capability_rollout.py`
  - `187 passed`
- 문서 정책:
  - `.venv/bin/python -m pytest -q tests/test_documentation.py`
  - `2 passed`
- 정적 검증:
  - `.venv/bin/ruff check src tests containers scripts`: 통과
  - `.venv/bin/python -m mypy --strict src/pajin`:
    `Success: no issues found in 315 source files`
  - `.venv/bin/python -m compileall -q src`: 통과
  - `git diff --check`: 통과
- 전체 회귀:
  - `.venv/bin/python -m pytest -q
    --deselect=tests/test_control_plane_worker_identity.py::test_direct_mtls_binds_worker_subject_without_requiring_human_certificate
    --deselect=tests/test_replay_worker_process.py::test_replay_worker_entrypoint_process_executes_one_exact_replay`
  - `4163 passed, 67 skipped, 2 deselected`
- sandbox loopback bind가 필요한 제외 2건을 별도 권한 경계에서 실행:
  - `2 passed`

Linux CI는 미커밋 working tree에 대해 실행되지 않았다. 위 검증은 macOS project `.venv`에서
수행했다.

## 알려진 제한

- REDTEAM-001D는 fixed local stdio demo MCP server와 synthetic input 하나만 지원한다. 외부 MCP
  server, discovery-selected Tool, arbitrary arguments, network/resource/prompt/credential access를
  허용하지 않는다.
- REDTEAM-001C는 단일 synthetic local Web endpoint만 지원하며 arbitrary Web target, scanner,
  crawler, browser나 production Web conformance를 제공하지 않는다.
- fixture-backed Worker 결과는 실제 외부 Target 운영 증거가 아니다.
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

현재 변경은 staged가 아니며 commit되지 않았다. 재개 시 merge/rebase/cherry-pick/revert/bisect
진행 상태와 staged/unstaged/untracked 파일을 다시 확인한다.

## 다음 한 단계

`REDTEAM-002`를 시작할 때 기존 BENCH-001, CAP-003 mapping, Target Factory와 REDTEAM-001A~D의
sealed Observation/Oracle/Replay 경계를 먼저 감사한다. `Capability가 등록됐다`와 실제 detection
recall·false positive/precision·replay success·time-to-first-valid-finding·request/tool cost를 분리하고,
현재 fixed fixtures에서 정직하게 측정 가능한 공통 metric과 Profile별 metric을 versioned contract로
고정한다. 측정 결과나 validation floor를 구현 전에 추정하지 않는다.
