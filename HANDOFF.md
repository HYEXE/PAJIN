# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-24
- 작업 체크아웃: `C:\Workspace\HYEXE\PAJIN`
- 브랜치: `main`
- 기준 체크포인트: `928e224` (`feat(cloud): 읽기 전용 분석 수직 슬라이스 추가`)
- 직전 구현 체크포인트: `431b27c` (`feat(network): 네트워크 분석 수직 슬라이스 추가`)
- 구현 상태: `NET-001A~D`, `CLOUD-001A~D` 구현·검증·커밋 완료
- 선행 감사 수정: `8b84983` Control Plane dependency lock, `1046cfe` VAL-004C 조회 상태
- 작업 트리 체크포인트: 구현 변경은 위 두 커밋으로 보존했고 이 문서는 그 직후 상태를 동기화함
- Git 참고: `KNOWN_ISSUES.md`는 worktree metadata 때문에 `M`으로 보이지만 `git diff`가 비어 있고
  worktree blob hash가 `HEAD:KNOWN_ISSUES.md`와 같아 실제 내용 변경은 없음
- 완료된 단계: `PENTEST-004C2B2`, `REDTEAM-001A~D`, `REDTEAM-002`, `UX-008`,
  `DOMAIN-001~006`, `WEB-001A~D`, `AI-001A~D`, `NET-001A~D`, `CLOUD-001A~D`
- 현재 우선순위: `SYS-001A` host/process/filesystem/service/configuration Surface model
- 다음 우선순위: `SYS-001B` read-only inspection Capability and authenticated non-root Worker

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
- `CLOUD-001A`
  - provider-partition account, nested project, provider-local resource, IAM object와 immutable
    container/image identity를 exact Cloud Domain과 `cloud.account-resource` semantics에 결박한다.
  - typed Surface는 `registered-not-authorized`이며 provider selection, tenant/credential authority,
    inventory/policy read, container access, Scope, Capability, Permit, Worker, network, Graph, mutation 또는
    execution 권위를 만들지 않는다.
- `CLOUD-001B`
  - exact CLOUD-001A Surface를 complete signed CAP-002, local Cloud Domain classification, DOMAIN-004 minimum
    Cloud Worker profile과 current Campaign의 exact non-routable Surface token·provider GET target Scope 및
    private-network authority에 결박한다.
  - `inventory-read`는 locator 5종, `policy-read`는 exact IAM Surface만 허용하며 explicit provider/partition,
    canonical HTTPS origin과 unique Surface/operation GET route, TTL/runtime/response budget을 고정한다.
  - `allowPrivateNetworks`는 literal boolean만 허용한다. false이면 exact allow와 별개로 non-global IP literal,
    `localhost`와 fixed Docker host를 거부하고 DNS/connect-time enforcement는 deployment runtime에 남긴다.
  - `SecretBroker.inspect`로 현재 broker-owned snapshot을 소비 없이 재조회하고 exact Campaign scope·audience·
    binding·active single-use·최대 60초 TTL을 재검증한 뒤 raw lease ID·secret reference·material 없이
    fingerprint-only credential reference를 준비한다.
  - provider adapter는 secret-free request description만 만들고 provider client·WorkerJob·network request·
    result normalization을 제공하지 않는다. Tool runtime은 fail-closed, Oracle은 inconclusive다.
  - preparation은 `PreparedCapabilityAction`에서 멈추며 credential materialization/use·provider invocation·
    mutation·approval·Permit·Worker·egress·Observation·Evidence·Graph admission·execution 권위를 만들지 않는다.
- `CLOUD-001C`
  - current Cloud activation·Campaign Scope·CLOUD-001B preparation·Graph Decision/Proposal/Grant와 exactly one
    consumed Permit·durable approval-consumption receipt를 기존 권위 저장소에서 다시 결박한다.
  - admission gate에 고정된 deployment-configured trust anchor에서 exact Capability/release·Cloud Worker profile·direct mTLS subject/SPKI·provider
    adapter·credential audience·Ed25519 key lifecycle를 검증하고 deployment-produced signed execution statement와
    detached raw-body-free response receipt의 signature·file/content digest·timing·one-GET/zero-write budget을 재검증한다.
  - signed credential-use receipt는 broker recheck·single-use materialization/consumption·discard를 나타내는
    historical provenance일 뿐이며 CLOUD-001C는 bearer lease ID·secret reference·credential material을 받거나
    broker/provider/Worker/network를 호출하지 않는다.
  - 기존 Graph single writer에 succeeded Action 1·neutral `cloud.api-observation` 1·digest-only Evidence 2와
    `produces` 1·`supported-by` 2만 admission한다. raw response/header·resource/policy field·target coordinate는
    Graph prose에 들어가지 않고 HTTP success/body digest에서 existence·ownership·policy effect·effective
    permission·Hypothesis·Finding·Replay·후속 action authority를 추론하지 않는다.
- `CLOUD-001D`
  - 두 separately admitted CLOUD-001C policy-read source를 같은 deployment-configured trust anchor와 각자의
    SQLite Graph authority store로 다시 열고 exact stored admission까지 재검증한다.
  - Surface·Campaign Scope·Capability/release·provider adapter/route·credential audience/binding/scope와
    secret-reference fingerprint·exact query는 같고 Run·preparation·request·Decision·Proposal·approval·Permit·
    dispatch·single-use lease fingerprint·signed statement·external execution·source root·admission·policy artifact
    identity는 모두 다른 경우에만 fresh-credential Replay로 결박한다.
  - CLOUD-001C response digest 자체를 policy input으로 취급하지 않는다. exact C admission/execution/receipt/body/
    trust digest에 결박된 deployment-derived sanitized artifact를 별도 Ed25519 signature domain으로 검증하고,
    wildcard 없는 exact principal/action/resource rule을 deny-overrides allow evaluator로 결정론적으로 평가한다.
  - input+decision match, input changed+decision match, decision changed를 neutral state로만 투영하며 provider
    semantics·effective permission·resource existence·Finding·Profile floor 또는 후속 Replay/execution을 확인하지 않는다.
  - exact allow, explicit deny override, implicit-deny negative Control 3개 private Ground Truth와 per-case disposable
    account/emulator·fresh credential·cleanup evidence 요구를 등록한다. Target/credential provision, provider/emulator
    실행, cleanup, live evidence binding, numeric measurement는 수행하지 않는다.
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
- `NET-001A`
  - unresolved DNS/IP host, exact TCP/UDP port와 explicit service name을 host/port/service 3-class locator
    registry와 `registered-not-authorized` typed Surface에 결박한다.
  - DNS는 network call 없이 IDNA canonicalize하고 IPv4/IPv6는 explicit address family와 대조한다.
  - unknown service는 port locator로 유지하며 well-known port에서 service를 추론하지 않는다.
  - 기존 discovery/AttackSurface wire를 바꾸지 않고 Scope·scanner·raw socket·credential·Worker·network·
    Graph admission·execution 권위를 모두 false로 유지한다.
- `NET-001B`
  - exact IPv4/IPv6 literal·TCP·단일 port Surface를 externally signed current Range CAP-002 release,
    current Campaign Scope, fixed passive-banner protocol budget과 DOMAIN-004 minimum Network Worker profile에 결박한다.
  - complete 7-role code-backed Capability와 local resolvable Network Domain classification을 등록하되 기존
    global DOMAIN-003 inventory identity를 변경하거나 Domain metadata를 activation·Worker 권위로 바꾸지 않는다.
  - preparation은 exact host-wide CONNECT allow, same-authority deny 부재, CONNECT RoE와 non-global IP의
    private-network authority를 재검증한 뒤 `PreparedCapabilityAction`에서 멈춘다.
  - Tool/Worker/Gateway adapter 경계는 proxy-mediated CONNECT 한 번, Target application write 0 bytes, passive
    banner 최대 1,024 bytes와 host-observed exact CONNECT receipt를 강제한다. 준비 자체는 Worker·egress·network·
    Observation·Evidence·Graph·approval·Permit·execution 권위를 만들지 않는다.
- `NET-001C`
  - current NET-001B activation·Campaign Scope에서 preparation을 재구성하고 approved sealed source Run의
    exactly consumed Permit·durable approval receipt·completed dispatch reconciliation·Gateway/Worker Evidence·
    exact egress metadata·host-observed CONNECT receipt를 함께 재검증한다.
  - 기존 Graph single writer를 통해 succeeded Action, neutral `network.protocol-observation`과 2개 Evidence를
    admission하며 raw banner·target coordinate·product/version·Worker transcript를 Graph prose에 복제하지 않는다.
  - bounded classifier label이 있을 때만 별도 승인된 fresh passive handshake를 요구하는 confidence `0.5` open
    `network.exposure` Hypothesis를 admission하고 unknown label에는 Hypothesis나 negative conclusion을 만들지 않는다.
  - exact retry는 기존 semantic attempt를 반환하고 redispatch하지 않으며 service label·Graph membership·source
    approval/Permit은 service confirmation이나 Surface·Scope·Capability·Tool·Worker·network·Replay·Finding·execution
    권위를 만들지 않는다.
- `NET-001D`
  - NET-001C source/admission과 separately authorized sealed passive TCP execution을 각각 current NET-001B
    activation·Campaign Scope·approval receipt·consumed Permit·Docker Worker·trusted CONNECT evidence까지 재검증한다.
  - Surface·Scope·Capability·release·protocol budget·Tool semantics는 같고 Run root·request·envelope·Decision·
    Proposal·approval receipt·Permit·dispatch·Worker execution·artifact·terminal·reconciliation identity는 모두
    다른 경우에만 fresh execution Replay를 인정한다.
  - source/replay label은 match/change/unresolved의 neutral state로만 투영하고 banner digest equality를 별도
    기록한다. 어떤 상태도 service Observation confirmation·Ground Truth binding·Profile floor·Finding·후속
    Replay 또는 execution authority가 아니다.
  - ftp/imap/pop3/smtp/ssh known-positive와 unknown negative Control의 synthetic banner Ground Truth 6건을
    disposable loopback-container-per-case requirement로 등록하고 current standalone Worker classifier와 대조한다.
    profile은 Target selection·factory/provider/fixture execution·live Replay binding·numeric measurement를 만들지 않는다.
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
- NET-001A는 typed host/port/service knowledge, NET-001B는 IP-literal TCP 단일 port의 수동 banner 식별,
  NET-001C는 그 한 sealed result의 neutral Graph admission과 optional open Hypothesis, NET-001D는 별도 승인된
  sealed execution의 neutral comparison과 미측정 synthetic fixture registration까지만 지원한다. DNS
  resolution, UDP, port enumeration, active application handshake, credential use, raw socket, 일반 scanner와
  arbitrary Network runtime은 없다.
- NET-001B preparation은 실행이 아니며 실제 dispatch에는 기존 Policy/Approval, ActionPermit, Gateway,
  deployment-owned Worker direct mTLS와 trusted host-observed CONNECT receipt가 모두 필요하다. NET-001C는 이미
  생성된 sealed Evidence와 durable Graph authority만 재검증하며 live mTLS를 재인증하거나 새 dispatcher를
  구성하지 않는다. NET-001D도 실행을 예약하지 않고 supplied sealed source만 비교하며 distinct physical
  Worker/container/certificate를 증명하지 않는다. admitted service label과 Hypothesis도 확인·Finding·후속 실행
  권위가 아니다.
- CLOUD-001B는 signed preparation과 request adaptation만 구현하며 persisted lease reference는 bearer lease
  ID가 없는 fingerprint-only metadata다. CLOUD-001C는 deployment-owned runtime이 별도 승인·consumed Permit·
  direct mTLS·signed credential-use provenance로 만든 sealed execution과 raw-body-free response receipt만
  재검증한다. 저장소 안에는 실제 Cloud provider client/runtime, live broker materialization, raw response custody,
  provider-specific resource/policy field interpreter 또는 effective-permission Oracle이 없다. CLOUD-001D는
  별도 서명된 sanitized exact-rule artifact와 deterministic evaluator만 제공하며 provider semantics를 확인하지
  않는다. disposable account/emulator profile도 provision·execute·cleanup·measure되지 않았다. admitted
  Observation과 Replay comparison은 Hypothesis·Finding·후속 execution authority가 아니다.

### planned

- System, Application/Binary, Mobile, Cryptography, Forensics vertical slice

## 핵심 변경 위치

- Domain과 Graph: `src/pajin/domain/security_domain.py`, `src/pajin/graph/domain_semantics.py`,
  `src/pajin/graph/cross_domain_admission.py`
- Capability와 Worker boundary: `src/pajin/capabilities/domain_projection.py`,
  `src/pajin/capabilities/web_discovery.py`, `src/pajin/capabilities/ai_analysis.py`,
  `src/pajin/capabilities/network_service.py`, `src/pajin/capabilities/cloud_inventory.py`,
  `src/pajin/control_plane/domain_worker_boundaries.py`
- Surface classification: `src/pajin/discovery/web_surfaces.py`, `src/pajin/discovery/ai_surfaces.py`,
  `src/pajin/discovery/network_surfaces.py`, `src/pajin/discovery/cloud_surfaces.py`
- Network Tool/Worker/Gateway: `src/pajin/tools/network.py`, `src/pajin/tools/gateway.py`,
  `containers/worker/worker_entry.py`
- Workflow: `src/pajin/workflow/redteam_product_flow.py`,
  `src/pajin/workflow/web_discovery_admission.py`, `src/pajin/workflow/web_replay_benchmark.py`,
  `src/pajin/workflow/ai_analysis_admission.py`, `src/pajin/workflow/ai_replay_benchmark.py`,
  `src/pajin/workflow/network_service_admission.py`, `src/pajin/workflow/network_replay_benchmark.py`,
  `src/pajin/workflow/cloud_provider_admission.py`, `src/pajin/workflow/cloud_policy_replay_benchmark.py`
- Benchmark: `src/pajin/benchmark/domain_metrics.py`
- 권위 문서: `docs/rfc/0002-multi-domain-security-analysis-architecture.md`, ADR-0210~0227,
  UX-008, DOMAIN-001~006, WEB-001A~D, AI-001A~D, NET-001A~D, CLOUD-001A~D 버전형 계약

## 최신 검증

- 최종 커밋 전 fixed-snapshot 검토:
  - 변경 Python source 15개를 보안 diff-scan으로 전수 검토해 CLOUD-001B가
    `allowPrivateNetworks=false`에서도 exact private provider route를 준비하는 P3 경계 누락 1건을 재현했다.
  - Campaign projection·CLOUD-001C 재검증에 literal private-network authority를 결박하고 non-global IP,
    `localhost`, fixed Docker host를 fail-closed 처리했다.
  - 인접 Campaign parser의 `allowPrivateNetworks=1` → `True` coercion도 재현해 literal boolean만 허용하도록
    수정했다. scan 결과의 나머지 Network/Cloud source surface에서는 reportable issue가 없었다.
- Network/Cloud A~D와 Campaign·SecretBroker·Graph·Gateway·Worker·Tool·문서 통합 회귀:
  - `.venv\Scripts\python.exe -m pytest -q`로 관련 테스트 파일 19개를 명시 실행
  - `802 passed, 2 skipped` (Windows에서 비이식인 POSIX link/symlink semantics)
- private-network fix 집중 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_manifest.py
    tests\test_cloud_read_only_inventory_policy.py tests\test_network_service_identification.py`
  - `120 passed`
- CLOUD-001D signed sanitized artifact·fresh-credential Replay·deterministic evaluator·fixture Ground Truth와
  CLOUD-001C predecessor 집중 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_policy_replay_benchmark.py
    tests\test_cloud_provider_admission.py`
  - `22 passed`
- CLOUD-001D 대상 정적 검증:
  - `.venv\Scripts\python.exe -m ruff check src\pajin\workflow\cloud_policy_replay_benchmark.py
    tests\test_cloud_policy_replay_benchmark.py`: 통과
  - `.venv\Scripts\python.exe -m mypy --strict --platform linux
    src\pajin\workflow\cloud_policy_replay_benchmark.py`: 통과
  - `.venv\Scripts\python.exe -m ruff format --check
    src\pajin\workflow\cloud_policy_replay_benchmark.py tests\test_cloud_policy_replay_benchmark.py`: 통과
- CLOUD-001C 집중 signed source·Permit/approval·trust anchor·neutral Graph admission·non-authority adversarial 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_provider_admission.py`
  - `15 passed`
- CLOUD-001A~D, DOMAIN-006, Graph single writer·SQLite authority, Domain semantics·Worker boundary와
  documentation 통합 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_policy_replay_benchmark.py
    tests\test_cloud_provider_admission.py
    tests\test_cloud_read_only_inventory_policy.py tests\test_cloud_account_resource_surfaces.py
    tests\test_domain_benchmark_metrics.py tests\test_graph_admission.py tests\test_graph_sqlite_store.py
    tests\test_multi_domain_graph_semantics.py tests\test_domain_worker_boundaries.py
    tests\test_documentation.py`
  - `430 passed, 2 skipped` (Windows에서 비이식인 POSIX link/symlink semantics)
- CLOUD-001C 대상 정적·포맷 검증:
  - `.venv\Scripts\python.exe -m ruff check src\pajin\workflow\cloud_provider_admission.py
    tests\test_cloud_provider_admission.py`: 통과
  - `.venv\Scripts\python.exe -m mypy --strict --platform linux
    src\pajin\workflow\cloud_provider_admission.py`: 통과
  - `.venv\Scripts\python.exe -m ruff format --check src\pajin\workflow\cloud_provider_admission.py
    tests\test_cloud_provider_admission.py`: 통과
- CLOUD-001B 집중 Capability·Scope·adapter·trusted lease·non-authority adversarial 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_secrets.py
    tests\test_cloud_read_only_inventory_policy.py`
  - `73 passed`
- CLOUD-001B 대상 정적 검증:
  - `.venv\Scripts\ruff.exe check src/pajin/runtime/secrets.py
    src/pajin/capabilities/cloud_inventory.py tests/test_secrets.py
    tests/test_cloud_read_only_inventory_policy.py`: 통과
  - `.venv\Scripts\mypy.exe --strict --platform linux src/pajin/runtime/secrets.py
    src/pajin/capabilities/cloud_inventory.py`: 통과
- CLOUD-001A/B와 Worker·CAP-002 lifecycle/scaffold 인접 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_account_resource_surfaces.py
    tests\test_domain_worker_boundaries.py tests\test_capability_authorities.py
    tests\test_capability_lifecycle.py tests\test_capability_scaffold.py tests\test_secrets.py
    tests\test_cloud_read_only_inventory_policy.py`
  - `274 passed`
- CLOUD-001A/B, Domain semantics, Capability lifecycle/scaffold, object-storage provider, Docker와 documentation
  최종 통합 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_account_resource_surfaces.py
    tests\test_cloud_read_only_inventory_policy.py tests\test_secrets.py
    tests\test_security_domain_taxonomy.py tests\test_multi_domain_graph_semantics.py
    tests\test_domain_worker_boundaries.py tests\test_discovery_models.py
    tests\test_capability_authorities.py tests\test_capability_lifecycle.py
    tests\test_capability_scaffold.py tests\test_control_plane_object_storage_provider.py
    tests\test_control_plane_object_storage_production.py tests\test_benchmark_docker_provider.py
    tests\test_documentation.py`
  - `514 passed, 3 skipped` (durable managed import POSIX 한정 1건과 real Docker opt-in 2건)
- CLOUD-001A 집중 canonical/parent-substitution/secret-authority adversarial 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_account_resource_surfaces.py`
  - `97 passed`
- CLOUD-001A 대상 정적 검증:
  - `.venv\Scripts\ruff.exe check src/pajin/discovery/cloud_surfaces.py
    src/pajin/discovery/__init__.py tests/test_cloud_account_resource_surfaces.py`: 통과
  - `.venv\Scripts\mypy.exe --strict --platform linux src/pajin/discovery/cloud_surfaces.py`: 통과
- CLOUD-001A와 Domain semantics·Worker boundary·discovery wire·object-storage·Docker·documentation 인접 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_cloud_account_resource_surfaces.py
    tests\test_security_domain_taxonomy.py tests\test_multi_domain_graph_semantics.py
    tests\test_domain_worker_boundaries.py tests\test_discovery_models.py
    tests\test_control_plane_object_storage_provider.py tests\test_control_plane_object_storage_production.py
    tests\test_benchmark_docker_provider.py tests\test_documentation.py`
  - `419 passed, 3 skipped` (durable managed import의 POSIX 한정 1건과 real Docker opt-in 2건)
- NET-001D 집중 positive/adversarial 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_network_replay_benchmark.py`
  - `4 passed`
- NET-001A~D, DOMAIN-006와 documentation 통합 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_network_replay_benchmark.py
    tests\test_network_service_admission.py tests\test_network_service_identification.py
    tests\test_network_host_service_surfaces.py tests\test_domain_benchmark_metrics.py
    tests\test_documentation.py`
  - `171 passed`
- Graph single writer·SQLite authority·Gateway·AI sealed-admission 인접 회귀:
  - `.venv\Scripts\python.exe -m pytest -q tests\test_graph_admission.py tests\test_graph_sqlite_store.py
    tests\test_gateway.py tests\test_ai_analysis_admission.py`
  - `84 passed, 2 skipped` (Windows에서 비이식인 POSIX link/symlink semantics)
- 현재 working tree 전체 정적 검증:
  - `.venv\Scripts\python.exe -m ruff check src tests containers scripts`: 통과
  - `.venv\Scripts\python.exe -m mypy --strict --platform linux src\pajin`: `340 source files` 통과
  - `.venv\Scripts\python.exe -m compileall -q src tests containers scripts`: 통과
  - `git diff --check`: 통과
- 이번 체크포인트의 Windows 전체 pytest는 약 20%에서 알려진 환경 실패로 중단했다. `-x` 재현은
  `1122 passed, 12 skipped, 1 failed`였고 첫 실패는 managed Artifact import가 POSIX directory `fsync`를
  요구해 `tests/test_control_plane_artifact_admission.py`의 예상 후속 오류보다 먼저 닫힌 항목이다.
  `KNOWN_ISSUES.md`의 기존 Windows managed Artifact 제약과 일치한다. Linux 전체 pytest 증거는 없다.
- 전체 `ruff format --check src tests containers scripts`는 이번 변경 밖의 기존 201개 파일을
  재포맷 대상으로 보고해 실패했다. 이번 변경 Python 26개 파일의 대상 포맷 검사는
  `26 files already formatted`로 통과했으며 관련 없는 파일은 수정하지 않았다.

## 알려진 제한

- 성공한 detection, Oracle, Replay 또는 benchmark metric은 Finding이나 negative security conclusion이 아니다.
- discovered Surface와 cross-domain Observation은 knowledge만 확장하며 Scope나 execution authority를 확장하지 않는다.
- Tool과 MCP는 integration mechanism이며 registered Capability, current authority, ActionPermit와 Gateway를
  우회할 수 없다.
- Forensics는 read-only analysis가 기본이며 발견된 credential material을 별도 Capability·Permit 없이 사용할 수 없다.
- 일반 multi-domain runtime, production benchmark score, cross-host Worker fence와 Linux CI 증거는 없다.
- CLOUD-001A의 provider/account/project/resource/IAM/container 값은 provider support, live inventory,
  effective policy, credential/tenant authority, current container runtime 또는 실행 가능성의 증거가 아니다.
- CLOUD-001B의 explicit GET adapter와 active lease fingerprint도 provider runtime, credential use, live
  inventory/policy result 또는 실행 가능성의 증거가 아니다. CLOUD-001C source는 external deployment가 만든
  signed historical provenance이며 저장소 안에 실제 Worker/provider runtime은 없다. admitted response receipt도
  resource existence/ownership, policy effect, effective permission, Finding 또는 후속 실행의 증거가 아니다.
- CLOUD-001D sanitized artifact signature는 deployment provenance와 source binding을 증명하지만 provider-specific
  translation completeness나 effective permission을 증명하지 않는다. `fresh credential`은 서로 다른 signed
  single-use lease provenance를 뜻하며 D가 credential을 새로 획득·사용했다는 의미가 아니다. fixture profile은
  disposable account/emulator, cleanup과 Ground Truth 요구 등록일 뿐 실제 provision·cleanup·측정 증거가 아니다.
- NET-001A의 TCP/UDP vocabulary와 service name은 runtime 지원이나 실제 service 식별 증거가 아니다.
- NET-001C의 admitted protocol Observation과 optional open Hypothesis는 service confirmation, product/version
  typing, Finding, Replay, Ground Truth, benchmark measurement 또는 negative conclusion이 아니다.
- NET-001D의 `fresh Worker`는 distinct sealed Docker Worker execution identity를 뜻하며 서로 다른 물리 host,
  container instance, certificate 또는 live mTLS subject를 증명하지 않는다.
- NET-001D fixture profile은 synthetic Ground Truth registration일 뿐 isolated container provision, live Replay,
  service-identification accuracy 측정이나 validation-floor 충족 증거가 아니다.
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

`SYS-001A`에서 DOMAIN-001 System classification과 DOMAIN-002 `system.host-resource` semantics를 먼저
재검증하고 host/process/filesystem/service/configuration의 secret-free exact locator와 parent lineage를
content-addressed `registered-not-authorized` Surface registry로 정의한다. 기존 Docker/Worker host metadata나
로컬 경로를 live host access, process inspection, filesystem read, service control, credential/root authority로
승격하지 않는다. mutable PID·path alias·service display name과 host-local absolute path의 portability/privacy
경계를 명시하고, Scope·Capability·approval·Permit·authenticated host Worker·Graph·network·mutation·execution
authority는 후속 `SYS-001B/C`까지 false로 유지한다.
