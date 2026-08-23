# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-24
- 작업 체크아웃: `C:\Workspace\HYEXE\PAJIN`
- 브랜치: `main`
- 기준 HEAD: `923965e` (`security(deps): cryptography 취약 버전 범위 제거`)
- 작업 트리 체크포인트: 기준 HEAD 위의 미커밋 `AI-001B~D` 구현·테스트·계약 문서
- 완료된 단계: `PENTEST-004C2B2`, `REDTEAM-001A~D`, `REDTEAM-002`, `UX-008`,
  `DOMAIN-001~006`, `WEB-001A~D`, `AI-001A~D`
- 현재 우선순위: `NET-001A` host/service/protocol/port Surface model
- 다음 우선순위: `NET-001B` read-only service-identification Capability and scoped Network Worker

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
- `AI-001B`
  - REDTEAM-001A M03/M06, REDTEAM-001B A04, REDTEAM-001D MCP의 exact Profile·CAP-002·Tool identity를
    typed model/RAG/MCP/Tool Surface, request/token/cost ceiling과 minimum AI Worker profile에 결박한다.
  - current Provider registration과 signed lifecycle release를 재검증해 `PreparedCapabilityAction`까지만
    만들며 Profile·Scope·approval·Permit·budget·credential·Worker·Gateway·Graph·execution 권위는 만들지 않는다.
- `AI-001C`
  - AI-001B exact preparation과 기존 REDTEAM LLM/RAG/MCP Capability Graph Run의 seal, consumed Permit,
    dispatch reconciliation, request reservation, Tool/Worker Evidence와 Gateway outcome digest를 재검증한다.
  - exact model/Tool, model/RAG/Tool, MCP/Tool Surface reference를 DOMAIN-002 AI semantic에 결박하고 기존
    Graph single writer에 Action 1·neutral Observation 1·Evidence 2만 admission한다.
  - Surface/Profile/Domain/MCP/Tool metadata와 source Permit은 추가 Scope·Tool·Worker·network·credential·Replay·
    Finding·execution 권위가 아니며 exact retry는 Tool을 재실행하지 않는다.
- `AI-001D`
  - AI-001C sealed source/admission과 별도 KISA source의 두 fresh-session Replay·세 Control을 다시 열어
    exact target·Tool·scenario·threat class·turn·check 및 disjoint session/request identity를 검증한다.
  - exact REDTEAM-002 Profile·Capability·CAP-003 mapping·CAP-006 Replay contract와 DOMAIN-006 AI plan을
    content-addressed projection에 결박하되 concrete Ground Truth case나 numeric measurement는 만들지 않는다.
  - 독립 KISA lane의 Profile floor는 충족하지만 AI Observation confirmation·Finding으로 전환하지 않으며
    source Graph/Permit/Profile/Domain/Tool metadata에서 Replay·Permit·Worker·network·credential·execution 권위를 만들지 않는다.
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
- AI-001A~D는 typed registry, preparation, neutral admission과 direct-call Replay/Control/benchmark-contract
  binding까지다. MCP Replay, concrete AI Ground Truth·numeric measurement, AI Observation confirmation·Finding,
  arbitrary provider·agent·MCP·Tool execution과 일반 AI discovery/runtime은 없다.

### planned

- Network, Cloud/Container, System, Application/Binary, Mobile, Cryptography, Forensics vertical slice

## 핵심 변경 위치

- Domain과 Graph: `src/pajin/domain/security_domain.py`, `src/pajin/graph/domain_semantics.py`,
  `src/pajin/graph/cross_domain_admission.py`
- Capability와 Worker boundary: `src/pajin/capabilities/domain_projection.py`,
  `src/pajin/capabilities/web_discovery.py`, `src/pajin/capabilities/ai_analysis.py`,
  `src/pajin/control_plane/domain_worker_boundaries.py`
- Surface classification: `src/pajin/discovery/web_surfaces.py`, `src/pajin/discovery/ai_surfaces.py`
- Workflow: `src/pajin/workflow/redteam_product_flow.py`,
  `src/pajin/workflow/web_discovery_admission.py`, `src/pajin/workflow/web_replay_benchmark.py`,
  `src/pajin/workflow/ai_analysis_admission.py`, `src/pajin/workflow/ai_replay_benchmark.py`
- Benchmark: `src/pajin/benchmark/domain_metrics.py`
- 권위 문서: `docs/rfc/0002-multi-domain-security-analysis-architecture.md`, ADR-0210~0219,
  UX-008, DOMAIN-001~006, WEB-001A~D, AI-001A~D 버전형 계약

## 최신 검증

- AI-001D 집중 positive/adversarial 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_ai_replay_benchmark.py`
  - `1 passed`
- AI-001D와 KISA Replay·Control·Profile evidence, REDTEAM benchmark, AI-001B/C,
  CAP-002 lifecycle·adapter, VAL-004C 조회 분류, Control Plane dependency export와 문서 인접 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_ai_replay_benchmark.py
    tests\test_ai_analysis_admission.py tests\test_ai_read_only_analysis.py
    tests\test_profile_validation_evidence.py tests\test_validation_controls.py
    tests\test_kisa_replay.py tests\test_benchmark_redteam.py
    tests\test_domain_benchmark_metrics.py tests\test_existing_capability_adapters.py
    tests\test_existing_capability_rollout.py tests\test_documentation.py
    tests\test_control_plane_validation_comparison.py
    tests\test_deployment.py::test_control_plane_dependency_export_matches_the_root_lock`
  - `273 passed`
- 전체 정적 검증:
  - `.venv\Scripts\ruff.exe check src tests containers scripts`: 통과
  - `.venv\Scripts\mypy.exe --strict --platform linux src\pajin`: `331 source files` 통과
  - `.venv\Scripts\python.exe -m compileall -q src`: 통과
  - `git diff --check`: 통과
- Windows 전체 pytest는 `4564 passed, 115 skipped, 187 failed`였다. 실패 중 VAL-004C missing lookup의
  404/409 오분류와 Control Plane `cryptography` export lock 불일치는 수정 후 위 집중 회귀가 통과했다.
  나머지는 POSIX directory `fsync`·secure `dirfd`, Windows 파일명·symlink 제약 184건과 현재 venv에
  optional `boto3` extra가 없는 MinIO inventory 1건이다. Linux 전체 pytest는 실행하지 않았다.

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

`NET-001A`에서 DOMAIN-001 Network classification과 DOMAIN-002 Network semantics를 재검증하고
host/service/protocol/port를 secret-free typed Surface와 locator registry로 결박한다. discovery 결과나
port/protocol metadata를 Scope, scanner, raw-socket, credential, Worker, network 또는 execution authority로
전환하지 않는다.
