# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-23
- 작업 체크아웃: `/Users/hyeonexcel/Workspace/HYEXEN/PAJIN`
- 브랜치: `main`
- 감사 시작 기준: `8d764be778ec76794e61496dbc9ddce348de0dfb`
- 구현 체크포인트: `cde01b4` (`feat(security): 멀티 도메인 분석 기반 구현`)
- 완료된 단계: `PENTEST-004C2B2`, `REDTEAM-001A~D`, `REDTEAM-002`, `UX-008`,
  `DOMAIN-001~006`, `WEB-001A~D`, `AI-001A`
- 현재 우선순위: `AI-001B` exact provider/model/tool-bound read-only analysis Capability
- 다음 우선순위: `AI-001C` cross-Surface Observation/Evidence admission without Tool authority

이 문서 자체를 동기화하는 커밋이 구현 체크포인트 뒤에 이어지므로 정확한 현재 HEAD와 원격 상태는
아래 Git 명령으로 확인한다. 문서와 Git이 다르면 Git과 파일시스템을 우선한다.

## 구현 상태

### implemented

- `UX-008`
  - verified REDTEAM-002 aggregate/source Run에서 content-addressed product-flow projection을 발행한다.
  - source identity, completeness와 no-Finding 상태만 투영하며 Campaign Scope, validation floor,
    Finding 또는 execution authority를 만들지 않는다.
- `DOMAIN-001`
  - Web, Network, System, Application, Mobile, Cloud, AI, Cryptography, Forensics의 exact taxonomy와
    classification registry를 제공한다.
  - Domain은 Profile과 직교하는 metadata이며 Scope, Capability, Permit, Tool, Worker 또는 실행 권위가 아니다.
- `DOMAIN-002`
  - 9개 Domain의 Surface/Hypothesis/Observation semantic type-set을 기존 Canonical Graph의 6개 node,
    8개 relation과 single admission writer에 결박한다.
  - 별도 domain ledger나 authority model을 만들지 않는다.
- `DOMAIN-003`
  - 기존 CAP-001/CAP-002 registry의 exact identity를 Web, AI, Cryptography classification에 투영한다.
  - legacy domain 문자열이나 Tool metadata에서 권위를 추론하지 않는다.
- `DOMAIN-004`
  - 9개 Domain의 최소 Worker trust-boundary profile과 exact deployment binding registry를 제공한다.
  - profile은 Worker 선택, current activation, Permit 또는 conformance 증거가 아니다.
- `DOMAIN-005`
  - admitted AI Observation에서 Web Surface/Hypothesis knowledge를 만드는 bounded AI→Web producer를
    기존 `GraphAdmissionAuthority`에 결박한다.
  - 새 knowledge는 `registered-not-authorized`이며 discovery가 Scope나 실행 권위를 확장하지 않는다.
- `DOMAIN-006`
  - common/domain-specific metric, applicability와 Replay 또는 deterministic re-analysis plan registry를
    제공한다.
  - metric은 measurement vocabulary이며 Finding, validation-floor 충족 또는 실행 권위가 아니다.
- `WEB-001A`
  - concrete HTTP endpoint와 URI-template API route를 위한 typed locator/Surface registry를 제공한다.
- `WEB-001B`
  - concrete GET Surface를 기존 signed `pajin.pentest.http-get-recon@1.0.0` CAP-002와 Web Worker profile에
    결박해 `PreparedCapabilityAction`까지만 만든다. 준비 단계는 egress·Worker job·Permit을 만들지 않는다.
- `WEB-001C`
  - prior approved PENTEST-002A execution의 sealed Observation/Evidence를 재검증해 neutral Action,
    Observation, Evidence를 기존 Graph writer로 admission한다.
- `WEB-001D`
  - WEB-001C knowledge와 PENTEST-002B independent Replay comparison을 결박한다.
  - P0-D1 private SQLi Ground Truth는 `registered-ground-truth-not-measured`로 유지한다.
- `AI-001A`
  - model, RAG, agent, MCP, Tool의 5개 class와 10개 locator kind를 secret-free typed Surface registry로
    분류한다.
  - provider/model alias, credential, Tool discovery 또는 Domain metadata를 실행 권위로 바꾸지 않는다.
- Pentest Recon CAP-002 authority-set identity는 unordered Tool categories/evidence types를 정렬해
  Python hash seed와 무관하게 기존 digest를 재현한다.

모든 새 public loader와 workflow boundary는 canonical identity·digest·order·type을 재검증하고,
authority marker 주입, boolean/integer coercion, relabel 또는 substitution을 fail closed 한다.

### contract/scaffold only

- UX-008은 direct-call projection이다. Control Plane HTTP endpoint와 rendered Web Console panel은 없다.
- DOMAIN-001~006은 공통 taxonomy, semantic registry, inventory projection, Worker boundary registry,
  한 bounded cross-domain producer와 metric contract까지다. 일반 multi-domain runtime은 없다.
- DOMAIN-004 profile/binding은 concrete Worker conformance, deployment signing 또는 Gateway 소비를 구현하지 않는다.
- DOMAIN-005는 AI→Web knowledge chain 1개만 지원하며 arbitrary extraction이나 target execution은 없다.
- DOMAIN-006은 numeric measurement, concrete per-domain replay, validation-floor evaluation을 구현하지 않는다.
- WEB-001A~D는 typed Surface, read-only preparation, sealed neutral admission, independent Replay와 private
  Ground Truth registration까지다. 일반 scanner, measured benchmark와 Finding 확정은 없다.
- AI-001A는 classification-only다. provider/model invocation, RAG query, agent 실행, MCP/Tool 선택,
  credential lease, Observation/Evidence, Graph admission과 executable AI support는 없다.

### planned

- `AI-001B`: exact provider/model/tool-bound read-only analysis Capability
- `AI-001C`: cross-Surface Observation/Evidence admission without Tool authority
- `AI-001D`: deterministic replay and AI benchmark Ground Truth
- 이후 Network, Cloud/Container, System, Application/Binary, Mobile, Cryptography, Forensics vertical slice

## 핵심 변경 위치

- Domain과 Graph: `src/pajin/domain/security_domain.py`, `src/pajin/graph/domain_semantics.py`,
  `src/pajin/graph/cross_domain_admission.py`
- Capability와 Worker boundary: `src/pajin/capabilities/domain_projection.py`,
  `src/pajin/capabilities/web_discovery.py`, `src/pajin/control_plane/domain_worker_boundaries.py`
- Surface classification: `src/pajin/discovery/web_surfaces.py`, `src/pajin/discovery/ai_surfaces.py`
- Workflow: `src/pajin/workflow/redteam_product_flow.py`,
  `src/pajin/workflow/web_discovery_admission.py`, `src/pajin/workflow/web_replay_benchmark.py`
- Benchmark: `src/pajin/benchmark/domain_metrics.py`
- 권위 문서: `docs/rfc/0002-multi-domain-security-analysis-architecture.md`, ADR-0210~0216,
  UX-008, DOMAIN-001~006, WEB-001A~D, AI-001A 버전형 계약

## 최신 검증

- 누적 집중 positive/adversarial 회귀:
  - `.venv/bin/pytest -q tests/test_benchmark_redteam.py tests/test_security_domain_taxonomy.py
    tests/test_multi_domain_graph_semantics.py tests/test_capability_domain_projection.py
    tests/test_domain_worker_boundaries.py tests/test_cross_domain_graph_admission.py
    tests/test_domain_benchmark_metrics.py tests/test_web_http_operation_surfaces.py
    tests/test_web_read_only_discovery.py tests/test_pentest_recon_dispatch.py
    tests/test_ai_surface_classification.py tests/test_documentation.py`
  - `627 passed`
- 전체 정적 검증:
  - `.venv/bin/ruff check src tests containers scripts`: 통과
  - `.venv/bin/mypy --strict --platform linux src/pajin`: `328 source files` 통과
  - `.venv/bin/python -m compileall -q src`: 통과
  - `git diff --check`: 통과
- 전체 회귀:
  - sandbox loopback 2건을 제외한 전체 pytest: `4756 passed, 67 skipped, 2 deselected`
  - 제외한 direct-mTLS와 Replay Worker process 2건은 loopback 권한 경계에서 `2 passed`
- Codex Security working-tree diff 감사:
  - changed production source 18개와 authority boundary 11개 surface 검토
  - reportable finding `0`, coverage `complete`
- Linux CI는 실행하지 않았다. 위 결과는 macOS project `.venv` 기준이다.

## 알려진 제한

- 성공한 detection, Oracle, Replay 또는 benchmark metric은 Finding이나 negative security conclusion이 아니다.
- discovered Surface와 cross-domain Observation은 knowledge만 확장하며 Scope나 execution authority를 확장하지 않는다.
- Tool과 MCP는 integration mechanism이며 registered Capability, current authority, ActionPermit와 Gateway를
  우회할 수 없다.
- Forensics는 read-only analysis가 기본이며 발견된 credential material을 별도 Capability·Permit 없이 사용할 수 없다.
- 일반 multi-domain runtime, production benchmark score, cross-host Worker fence와 Linux CI 증거는 없다.
- test source 전체를 strict mypy 대상으로 확장한 탐색 검증의 기존 helper annotation 7건은
  `KNOWN_ISSUES.md`에 기록되어 있다. 공식 Linux CI 범위인 `src/pajin`은 통과한다.

## Git 재개 확인

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git rev-list --left-right --count origin/main...HEAD
git log -5 --oneline --decorate
git diff --check
```

작업 재개 시 working tree가 clean인지, `HEAD == origin/main`인지, 진행 중인 merge/rebase/cherry-pick이
없는지 실제 Git에서 다시 확인한다.

## 다음 한 단계

`AI-001B`에서 AI-001A exact provider/model/Tool identity를 기존 REDTEAM-001A/B/D와 CAP-002 lifecycle에
결박하는 최소 read-only analysis Capability를 설계한다. Domain metadata, Profile 이름, MCP/Tool discovery,
provider registration digest만으로 Scope, approval, Permit, Worker, network, credential 또는 execution authority를
만들지 않는다.
