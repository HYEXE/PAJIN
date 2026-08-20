# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-20
- 작업 체크아웃: `/Users/hyeonexcel/Workspace/HYEXEN/PAJIN`
- 브랜치: `main`
- 시작 HEAD: `c429a1b5bf76aa6d9cbe6d6218e951fd6a343f5c`
- fetch 후 upstream: `origin/main == c429a1b5bf76aa6d9cbe6d6218e951fd6a343f5c`
- 시작 ahead/behind: `0/0`
- 시작 working tree: clean
- 완료된 runtime 단계: `PENTEST-004C2B2`, `REDTEAM-001A`, `REDTEAM-001B`
- 현재 우선순위: `REDTEAM-001C` bounded Web Capability profile
- 다음 우선순위: `REDTEAM-001D` registered MCP Capability profile
- 이번 작업: multi-domain repository audit와 architecture/roadmap 문서 재정렬
- commit·push·Pull Request·merge·배포: 수행하지 않음

기존 HANDOFF의 “기능 commit은 local이고 push하지 않았다”는 문구는 실제 Git과 달랐다.
`git fetch --prune origin` 뒤 local `main`, `origin/main`, GitHub 기준 commit이 모두
`c429a1b`임을 확인하고 이 문서를 동기화했다.

## 실제 구현 상태

### 구현됨

- ARCH-001의 공통 Campaign Engine, code-owned Campaign Profile과 legacy Mode compatibility
- 6개 node·8개 relation Canonical Graph, single writer, append-only Event/Projection/Snapshot,
  stale Decision guard와 atomic one-use ActionPermit dispatch
- CAP-001 exact Definition/Tool binding과 CAP-002 seven-role code-backed authority set
- Policy/Approval, Tool Gateway, Worker, trusted receipt, sealed Evidence, Replay, validation depth,
  Profile assurance floor와 Retest 경계
- provider-neutral Benchmark/Target Factory와 제한된 local Web·AI benchmark provider
- PENTEST-004C2B2 server-owned child registry와 concrete 004B/004C2A adapters
- REDTEAM-001A exact single-turn M03/M06 LLM profile
- REDTEAM-001B exact two-turn A04 LLM/RAG profile

### contract/scaffold only

- Web/RAG/MCP/tenant/internal API discovery와 walking-chain 일부는 Graph knowledge와 비실행
  Hypothesis contract를 제공하지만 일반 domain execution authority가 아니다.
- Campaign Profile catalog는 code-owned지만 일부 기존 runtime은 legacy `CampaignMode` branch를
  compatibility path로 유지한다.
- ARCH-002와 ADR-0204~0206은 accepted architecture decision이며 multi-domain runtime 구현이 아니다.

### planned

- REDTEAM-001C bounded Web와 REDTEAM-001D exact registered MCP product profile
- DOMAIN-001~006 taxonomy, Graph semantics, Capability projection, Worker boundary, cross-domain
  admission과 benchmark extension
- 일반 Network, System, Application, Mobile, Cloud, Cryptography와 Forensics vertical slice

## 감사 결과

### 재사용 가능한 abstraction

- `src/pajin/graph/models.py`: domain-neutral Graph node와 relation vocabulary
- `src/pajin/graph/admission.py`: producer/lineage/single-writer/retry/equivocation gate
- `src/pajin/capabilities/models.py`: immutable exact-version Capability Definition Registry
- `src/pajin/capabilities/authorities.py`: CAP-002 seven-role authority set와 identity-checking wrapper
- `src/pajin/graph/authority.py`: MissionEnvelope, Proposal reservation과 single-use ActionPermit
- `src/pajin/tools/gateway.py`: Campaign/Scope/risk/rate/secret/Worker/receipt policy re-entry
- `src/pajin/workflow/campaign_profile.py`: `pentest`, `bug-hunt`, `ctf`, `ai-assessment`
  operating semantics
- `src/pajin/discovery/models.py`: current HTTP/RAG/MCP-oriented Surface locators와 sealed lineage
- `src/pajin/discovery/validation_depth.py`, `src/pajin/workflow/profile_assurance.py`: mode-neutral
  Replay/validation requirement와 Profile floor
- `src/pajin/benchmark/models.py`, `src/pajin/benchmark/target_factory.py`: Ground Truth, Result,
  reset/isolation/execution/cleanup과 measurement attestation

### 주요 blocker

- first-class Security Domain taxonomy가 없고 `CapabilityDefinition.domain`이
  `ai-redteam/bug-bounty/ctf/pentest` legacy namespace를 혼합한다.
- Domain과 Profile의 orthogonality를 표현하는 exact non-authoritative projection이 없다.
- 새 domain Surface/locator, Capability, Worker boundary, Replay와 benchmark ground truth가 없다.
- Worker isolation은 Pentest, Replay, Docker benchmark, Provider 등 기존 slice별로 강하지만
  domain-aware boundary registry로 일반화되지 않았다.
- BENCH-001 v1 metric 12개는 attack/finding 중심의 fixed set이므로 Forensics parsing accuracy와
  provenance preservation 같은 metric을 additive하게 표현할 contract가 없다.
- `registered-not-authorized`가 WALK/MCP 등 특정 계약에 존재하지만 모든 cross-domain Surface에
  적용되는 일반 admission projection은 없다.

## 이번 문서 변경

- `docs/rfc/0002-multi-domain-security-analysis-architecture.md`
  - 장기 제품 정의, 실제 baseline, taxonomy, one Graph, Worker boundary와 9-domain gap table
- `docs/adr/0204-separate-security-domain-from-profile-and-authority.md`
  - Security Domain은 Profile/authority root가 아니며 legacy Capability digest를 변경하지 않음
- `docs/adr/0205-admit-cross-domain-knowledge-without-scope-expansion.md`
  - cross-domain Graph admission은 knowledge만 확장하고 Scope/Permit을 확장하지 않음
- `docs/adr/0206-bind-domain-workers-to-existing-authority-path.md`
  - domain-specific isolation을 기존 Policy/Permit/Gateway/Worker 경로에 결박
- `PLAN.md`
  - Phase 11 유지, Phase 12 DOMAIN-001~006과 domain별 Phase 13~21 추가
- `README.md`
  - milestone history를 제거하고 product overview, 실제 지원 범위와 장기 방향으로 축약
- `DECISIONS.md`, `docs/README.md`, `KNOWN_ISSUES.md`
  - 새 architecture navigation과 contract-only 제한 반영

모든 새 multi-domain runtime 항목은 `planned`다. 기존 REDTEAM/PENTEST ID와 wire를 rename하거나
구현된 것처럼 확장하지 않았다.

## 검증 상태

- audit focused baseline:
  - `.venv/bin/python -m pytest -q tests/test_graph_models.py tests/test_graph_admission.py
    tests/test_capability_definition.py tests/test_capability_authorities.py
    tests/test_campaign_profile.py tests/test_existing_capability_adapters.py
    tests/test_benchmark_contract.py tests/test_benchmark_target_factory.py`
  - 결과: `99 passed`
- 문서·packaging 및 배포 경계 검증:
  - `.venv/bin/python -m pytest -q
    tests/test_deployment.py::test_canonical_docs_state_the_https_proxy_boundary_truthfully
    tests/test_deployment.py::test_canonical_docs_do_not_present_host_bridges_as_outbound_denial
    tests/test_documentation.py tests/test_packaging_entrypoints.py`
  - 결과: `21 passed`
- 정적 검증:
  - `.venv/bin/ruff check src tests containers scripts`: 통과
  - `.venv/bin/python -m mypy src`: `Success: no issues found in 315 source files`
  - `.venv/bin/python -m compileall -q src`: 통과
- 전체 회귀:
  - `.venv/bin/python -m pytest -q
    --deselect=tests/test_control_plane_worker_identity.py::test_direct_mtls_binds_worker_subject_without_requiring_human_certificate
    --deselect=tests/test_replay_worker_process.py::test_replay_worker_entrypoint_process_executes_one_exact_replay`
  - 결과: `4136 passed, 67 skipped, 2 deselected`
- loopback bind가 필요한 제외 2건은 샌드박스 밖에서 별도 실행했고 `2 passed`였다.

첫 전체 실행은 새 README에서 기존 HTTPS proxy/Docker bridge 경계 문구가 빠진 문서 회귀
2건과 샌드박스의 `127.0.0.1` bind 거부 2건을 드러냈다. README 경계를 복원했고 문서 테스트와
loopback 테스트를 위와 같이 각각 재검증했다. 남은 코드 회귀는 없다.

## 알려진 제한과 미결정 사항

- ARCH-002는 architecture와 roadmap이며 runtime schema, registry 또는 execution path가 아니다.
- DOMAIN-003 classification projection schema와 lifecycle은 아직 결정하지 않았다.
- Worker boundary signing/conformance authority와 domain-specific benchmark wire는 후속 ADR이 필요하다.
- REDTEAM-001C 후보는 기존 fixed synthetic Boolean SQLi Capability를 exact T2/GET/3-request
  product ceiling으로 재사용하는 방향이지만 아직 계약·코드·테스트가 없다.
- Linux CI는 이번 working tree에 대해 실행하지 않았다.

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

실제 Git과 파일시스템이 이 문서와 다르면 실제 상태를 우선한다. staged 변경과 진행 중인
merge/rebase/cherry-pick/revert/bisect가 없어야 한다.

## 다음 한 단계

`REDTEAM-001C` versioned contract와 ADR을 먼저 작성하고 다음 exact boundary를 고정한다.

- `pajin.bug-bounty.boolean-sqli-lab@1.0.0`
- `bug-bounty.boolean-sqli-probe@1.0.0`
- fixed synthetic local endpoint와 exact scenario
- GET, T2, three request units, read-only, no cleanup
- deployment-pinned approval, exact Campaign target와 trusted three-request receipts
- Permit 전 product-profile validation과 exact retry no-redispatch
- arbitrary payload, arbitrary endpoint, scanner, domain-label inference와 Finding authority 거부

계약 검토 뒤에만 runtime code와 positive/adversarial tests를 구현한다. REDTEAM-001D와
DOMAIN-001~006은 이 slice를 중단하거나 기존 계약을 rename하는 선행 refactor가 아니다.
