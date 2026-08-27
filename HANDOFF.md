# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-27
- 작업 체크아웃: `C:\Workspace\HYEXE\PAJIN`
- 브랜치: `main`
- 기준 체크포인트: `654dc28` (`docs(roadmap): 분석 도메인 로드맵과 계약 색인 동기화`)
- 직전 구현 체크포인트: `3d40207` (`feat(benchmark): 도메인 Replay와 재분석 경계 추가`)
- 구현 상태: `NET-001A~D`, `CLOUD-001A~D`, `SYS-001A~D`, `APP-001A~D`,
  `MOBILE-001A~D` 구현·검증·로컬 커밋 완료
- 선행 감사 수정: `8b84983` Control Plane dependency lock, `1046cfe` VAL-004C 조회 상태
- 로컬 커밋: `2aeb064` Discovery A, `40d6874` Capability B, `ef280c9` Graph C,
  `3d40207` Replay/benchmark D, `654dc28` roadmap/contract index
- 작업 트리 체크포인트: 이 `HANDOFF.md`와 `KNOWN_ISSUES.md` 동기화만 남았으며 이 문서의
  체크포인트 커밋이 뒤따른다. `origin/main`은 `2870a9e`이고 push는 수행하지 않았다.
- 완료된 단계: `PENTEST-004C2B2`, `REDTEAM-001A~D`, `REDTEAM-002`, `UX-008`,
  `DOMAIN-001~006`, `WEB-001A~D`, `AI-001A~D`, `NET-001A~D`, `CLOUD-001A~D`, `SYS-001A~D`,
  `APP-001A~D`, `MOBILE-001A~D`
- 현재 우선순위: `CRYPTO-001A` protocol/key-usage/ciphertext/configuration Surface model
- 다음 우선순위: `CRYPTO-001B` offline cryptographic misuse analysis Capability

정확한 현재 HEAD와 원격 상태는 아래 Git 명령으로 확인한다. 문서와 Git이 다르면 Git과
파일시스템을 우선한다.

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
- `SYS-001A`
  - pseudonymous host와 exact parent를 포함하는 process, logical-mount-relative filesystem,
    manager-qualified service, sanitized configuration locator 5종을 System Domain과
    `system.host-resource` semantics에 결박한다.
  - PID, absolute/ambiguous path, symlink, service display name, raw configuration value, secret·credential·
    privilege metadata를 거부하고 child identity에 parent와 sanitized content digest를 포함한다.
  - typed Surface는 content-addressed `registered-not-authorized` knowledge이며 host existence/state, Scope,
    Capability, approval, Permit, authenticated host agent, Tool/Worker, network, Graph admission, credential/root,
    host mutation 또는 execution 권위를 만들지 않는다.
- `SYS-001B`
  - exact SYS-001A Surface를 complete signed read-only CAP-002, local System Domain classification과
    DOMAIN-004 deployment-scoped·bounded-host-read·deployment-authentication·authenticated-non-root-agent
    minimum profile에 결박한다.
  - host/process/filesystem/service/configuration에 class별 metadata-only operation 5종을 exact mapping하고
    request 1회, artifact bytes·runtime ceiling, filesystem content/configuration value read·process signal·
    service control·host write 0을 강제한다.
  - explicit content-addressed host-agent deployment는 exact opaque host, complete public Worker mTLS policy와
    selected subject/SPKI, executable digest, non-root run-as identity, attenuated operation set을 결박한다.
    serialized binding도 policy digest와 certificate membership을 다시 검증한다.
  - 기존 Worker가 mTLS로 Control Plane에 연결해 claim하는 구조에 맞춰 별도 routable agent endpoint를 만들지
    않는다. network-disabled Capability는 current Campaign의 exact non-routable Surface token과 GET만 요구하고
    `PreparedCapabilityAction`에서 멈춘다. private-network RoE는 투영되지만 host-access authority가 아니다.
  - live bearer/direct-mTLS authentication, non-root runtime attestation, agent session, host connection/read,
    budget reservation, Worker·network, Observation/Evidence, Graph, approval, Permit, root·privilege escalation,
    mutation 또는 execution 권위를 만들지 않는다.
- `SYS-001C`
  - current activation·Campaign Scope·exact SYS-001B preparation과 approved job, exactly one consumed
    ActionPermit·durable approval receipt를 existing SQLite authority store에서 다시 결박한다.
  - deployment-configured Ed25519 trust anchor는 exact host-agent deployment·Capability/release를 고정하고
    current Campaign·Grant·request·Tool spec으로 Gateway policy를 재계산한 sanitized outcome,
    `WorkerMTLSAdmission`, declared non-root runtime identity/confinement과 detached raw-result-free receipt의
    file/content digest·timing·artifact/runtime ceiling을 검증한다.
  - existing Graph single writer에 succeeded Action 1, neutral `system.host-observation` 1, restricted Evidence 2,
    `produces` 1과 `supported-by` 2를 admission한다. fixed configuration/service review signal에만 confidence
    `0.5` open `system.security-configuration` Hypothesis와 `enables` 1을 추가하고 no-signal에는 결론을 만들지 않는다.
  - raw host content·path·service/configuration value를 Graph prose에 복제하지 않으며 source provenance에서
    Surface·Scope·Capability·approval·Permit·host access·agent/Worker·network·credential·root·privilege escalation·
    service control·mutation·Replay·Finding·후속 execution authority를 만들지 않는다.
- `SYS-001D`
  - SYS-001C signed receipt에 explicit live-host 또는 immutable-snapshot input provenance를 추가하고 snapshot
    mode에만 exact snapshot SHA-256을 요구해 Replay mode를 unsigned label이나 output digest로 추론하지 않는다.
  - one stored SYS-001C admission과 separately authorized sealed execution을 current C verifier·same deployment
    trust anchor로 다시 열고 Capability/release·Surface/operation·deployment·Scope·budget·normalized request
    semantics를 exact 결박하며 모든 Run/request/Decision/Permit/approval/execution/evidence identity 재사용을
    거부하고 replay signed start가 source signed finish보다 이후인지 검증한다.
  - trusted wire reload는 bare Pydantic parse를 검증으로 취급하지 않고 deployment trust anchor, 양쪽 source
    inputs/evidence context와 exact Graph store로 expected projection을 재구성해 전체 일치를 요구한다. embedded
    trust anchor, unstored 또는 recomputed Graph admission은 structural parse만 통과하며 trusted loader에서는 거부한다.
  - same immutable snapshot re-analysis와 fresh authenticated inspection을 구분해 body digest·bounded signal의
    neutral match/change/unresolved만 투영하고 equal body digest에는 exact signed result byte-count equality를
    요구한다. fresh mode는 DOMAIN-006 immutable-snapshot strategy를 satisfied로 표시하지 않으며 Graph write나
    Replay scheduling을 수행하지 않는다.
  - 5개 Surface 전체를 covering하는 known-positive 2·negative Control 2·filesystem privilege-denial Control 1과
    disposable non-root container/VM, result-or-denial·cleanup evidence completeness 요구를 content-addressed
    fixture profile로 등록한다. Ground Truth requirement registration은 true지만 private verification은 false다.
  - host-agent provision·execution·cleanup, raw host value, measurement·Profile floor·host state/Finding,
    root·privilege escalation·service control·mutation·Replay·후속 execution authority를 만들지 않는다.
- `APP-001A`
  - caller-supplied lowercase artifact SHA-256 binary와 exact binary-parent configuration/runtime,
    exact binary-or-runtime-parent library locator 4종을 Application Domain 및
    `application.artifact-runtime` semantics에 결박한다.
  - child locator가 complete parent를 내장해 binary/runtime substitution이 typed Surface identity를 바꾸며,
    coordinate는 case-fold하고 path·URL·query·fragment·wildcard·mutable alias·floating/range version을 거부한다.
  - typed Surface는 content-addressed `registered-not-authorized` knowledge이고 artifact resolve/read·bytes/format·
    configuration/runtime/dependency verification·Scope·Capability·approval·Permit·sandbox/Worker·network·debugger·
    Graph·Finding·mutation·runtime support·execution authority를 만들지 않는다.
- `APP-001B`
  - exact APP-001A Surface를 current signed read-only CAP-002 release, exact non-routable Campaign Surface-token Scope,
    deployment-supplied opaque custody authority/object/authorization digest reference와 결박한다.
  - Surface class별 operation/parser를 exact mapping하고 parser executable·sandbox image digest, explicit non-root
    identity, read-only root와 fixed no-exec artifact mount, disabled network, no-new-privileges 및
    artifact/output/runtime/memory/process ceiling을 content-addressed configuration-only sandbox로 결박한다.
  - preparation은 secret-free request와 `PreparedCapabilityAction`까지만 만들며 authorization verification,
    artifact resolve/read, mount, sandbox/Worker selection·attestation·execution, network, dynamic execution,
    debugger, Observation/Evidence, Graph, Finding 또는 execution authority를 만들지 않는다.
- `APP-001C`
  - current activation·Campaign Scope·exact APP-001B preparation과 approved job, exactly one consumed
    ActionPermit·durable approval receipt를 existing SQLite authority store에서 다시 결박한다.
  - deployment-configured Ed25519 trust anchor와 signed execution에서 exact custody/artifact digest,
    operation/parser, executable/image, non-root network-disabled read-only/no-exec sandbox requirement,
    recomputed Gateway decision, causal budget과 detached digest-only result receipt를 검증한다.
  - existing Graph single writer에 succeeded Action 1, neutral `application.analysis-observation` 1,
    restricted Evidence 2, `produces` 1과 `supported-by` 2를 admission한다. fixed class-bound review signal에만
    confidence `0.5` open `application.vulnerability` Hypothesis와 `enables` 1을 추가하고 no-signal에는
    결론을 만들지 않는다.
  - raw artifact/output, format·configuration·runtime·dependency·vulnerability truth, Scope·Capability·approval·
    Permit·artifact access·custody authority·sandbox/Worker·network·dynamic execution·debugger·mutation·Replay·
    Finding·후속 execution authority를 만들지 않는다.
- `APP-001D`
  - stored APP-001C admission과 separately authorized sealed re-analysis를 current APP-001C verifier와 같은
    deployment trust anchor로 다시 열고 source Observation·optional Hypothesis가 exact source Graph store에
    저장됐는지 확인한다. re-analysis는 Graph에 자동 admission하지 않는다.
  - trusted wire reload는 bare Pydantic parse를 검증으로 취급하지 않고 deployment trust anchor, 양쪽 source
    inputs/evidence root와 exact Graph store로 expected projection을 재구성해 전체 일치를 요구한다. unstored
    self-consistent Graph event, recomputed attestation/source-root digest와 foreign valid trust anchor를 거부한다.
  - exact immutable artifact/Surface/operation·custody/sandbox·parser executable/image·output schema·Scope·release·
    activation·normalized request semantics·budget을 요구하고 Run/source-root/request/envelope/proposal/Decision/
    Permit/dispatch/approval/execution/attestation/result-receipt identity 재사용과 non-causal start를 거부한다.
  - equal opaque body digest에는 exact signed result byte-count equality를 요구하고 digest·byte-count·bounded
    class review signal만으로 match/change/unresolved를 투영한다. changed는 security regression이 아니고
    unresolved는 negative conclusion이 아니다. Graph write·artifact read·parser/sandbox 실행·Replay scheduling이나
    format/configuration/runtime/dependency/vulnerability/Hypothesis/Finding authority가 없다.
  - binary/configuration/runtime/library 각각 known-positive와 negative Control 총 8건에 disposable offline
    non-root sandbox, read-only noexec mount, execution/runtime/result/cleanup evidence를 요구하되 fixture를
    materialize·provision·execute·cleanup·measure하지 않는다. Ground Truth requirement registration과 실제
    verification을 분리하고 provider/fixture execution authority도 false로 유지한다.
- `MOBILE-001A`
  - APP-001A exact binary를 부모로 재사용하는 APK/IPA package와 exact application, declared runtime,
    logical storage, sanitized deeplink, TLS policy, authentication flow locator 8종을 Mobile Domain 및
    `mobile.application-runtime` semantics에 결박한다.
  - binary→package→application complete lineage와 Android/iOS application ID·runtime·link·TLS kind 일치를
    identity에 포함하고 runtime은 canonical numeric/dotted version, deeplink는 canonical scheme·optional strict
    IDNA host·host-dependent optional integer port·logical route ID·sanitized declaration digest만 허용한다.
  - raw package/manifest/security config·signing material·secret·credential·storage value·full URI/path·device
    state/path와 mutable/range/wildcard/authority extra field를 거부한다. public builder와 typed Surface는
    preconstructed Pydantic parent/child도 alias JSON으로 dump한 뒤 재검증한다.
  - typed Surface는 content-addressed `registered-not-authorized` knowledge이며 package resolve/read·format/
    manifest/signing verification, static/dynamic analysis, sandbox/emulator/device/Tool/Worker selection·access·
    instrumentation, storage/network/TLS/auth/credential use, Scope·Capability·approval·Permit·Graph·Finding·
    mutation·runtime support·execution authority를 만들지 않는다.
- `MOBILE-001B`
  - exact MOBILE-001A selected Surface와 canonical root APK/IPA package Surface, APP binary digest,
    exact byte count 및 deployment-owned opaque custody/object/authorization digest reference를 함께 결박한다.
    custody/sandbox public reference는 운반하는 모든 가변 claim으로 원 binding digest를 재계산해 동일
    ID/digest 아래 authorization·Surface lineage·parser/image·deployment·resource/archive ceiling 치환을 거부한다.
  - 8개 Surface class별 operation을 완전 열거하고 parser family는 filename·extension·caller platform이 아니라
    canonical root package lineage에서만 Android APK 또는 iOS IPA로 도출해 substitution을 거부한다.
  - parser executable·sandbox image digest, explicit non-root identity, network/DNS-disabled read-only root와
    read-only/noexec package mount, no-new-privileges 및 archive entry/uncompressed-size/path/nesting/
    compression-ratio ceiling과 traversal/symlink/duplicate-name 거부를 configuration-only 요구로 결박한다.
  - selected Surface와 root package의 non-routable token 둘 다 exact current Campaign allow를 요구하고 deny를
    우선한다. current signed T2 read-only CAP-002의 7개 역할을 등록하되 `PreparedCapabilityAction`에서 멈춘다.
  - current DOMAIN-004 Mobile minimum profile은 device-bound이므로 Application profile이나 placeholder device
    identity를 쓰지 않고 `domainWorkerProfileBound=false`, profile binding deferred, WorkerJob unavailable을 유지한다.
    package resolve/read/mount/parser·sandbox 실행, emulator/device, install/launch/instrumentation, storage/network/
    TLS/auth/credential, Observation/Evidence·Graph·Hypothesis·Finding·mutation·Replay·execution authority가 없다.
- `MOBILE-001C`
  - current activation·Campaign의 selected/root exact Scope·MOBILE-001B preparation·approved job을 다시 만들고
    existing SQLite authority store의 exactly one consumed ActionPermit과 durable approval-consumption receipt를
    exact current authority로 결박한다.
  - deployment-configured Ed25519 trust anchor와 signed external static-sandbox execution에서 selected Surface와
    root APK/IPA Surface, package digest/bytes·custody authorization digest·operation·lineage parser·executable/image·
    non-root identity·recomputed Gateway outcome·causal timing·zero live-channel budget과 detached digest-only
    result receipt를 검증한다.
  - signed runtime receipt가 MOBILE-001B package/output/runtime/memory/process 및 archive entry/uncompressed-size/
    path/nesting/compression-ratio ceiling, observed archive maxima와 traversal/symlink/duplicate-name rejection을
    exact 결박한다. 이는 configured deployment assertion이며 repository-owned parser·sandbox 또는 live runtime
    conformance 증거가 아니다.
  - existing Graph single writer에 succeeded Action 1, neutral `mobile.analysis-observation` 1, restricted Evidence 2,
    `produces` 1과 `supported-by` 2를 admission한다. 8개 class/operation-bound review signal에만 confidence `0.5`
    open `mobile.security-property` Hypothesis와 `enables` 1을 허용하고 no-signal에는 부정적 결론을 만들지 않는다.
  - raw package/parser output·manifest/signing/device/credential 데이터를 Graph에 넣지 않고 package/manifest/
    application/runtime/storage/deeplink/TLS/auth truth·Scope·Capability·approval·Permit·custody/package/sandbox access·
    Worker/profile/job·network/DNS·device/emulator·install/launch/instrumentation·credential·mutation·Replay·Finding·
    후속 execution authority를 만들지 않는다.
  - current DOMAIN-004 Mobile profile은 계속 device-bound이므로 `domainWorkerProfileBindingDeferred=true`,
    `domainWorkerProfileBound=false`, `deviceBoundRuntimeProfileApplied=false`, WorkerJob unavailable을 유지한다.
- `MOBILE-001D`
  - stored MOBILE-001C source admission과 separately authorized sealed exact-package re-analysis를 current C
    verifier, deployment-configured trust anchor 및 양쪽 exact Graph store로 다시 열고 trusted wire reload도 같은
    evidence context를 요구한다. bare model parse와 embedded trust anchor/Graph event는 verification이 아니다.
  - selected/root Surface·complete platform/root lineage·package digest/bytes·operation·custody/sandbox·parser/
    executable/image·output schema·selected/root Scope·release·resource/archive ceiling 및 6개 observed archive
    값을 exact 결박한다. drift는 changed result가 아니라 incomparable input으로 fail closed 한다.
  - source/re-analysis의 Run/source-root/request/envelope/proposal/Decision/Permit/dispatch/approval/execution/
    runtime receipt/attestation/result-receipt identity 재사용을 거부하고 re-analysis signed start가 source signed
    finish보다 strictly later인지 검증한다. equal result-body digest에 다른 signed result byte count도 거부한다.
  - digest·byte-count·bounded review signal의 neutral match/change/unresolved만 투영하고 DOMAIN-006
    `deterministic-package-reanalysis` strategy를 결박한다. comparison과 bytes equality는 package·manifest·
    runtime·security-property·Hypothesis·Finding truth가 아니다.
  - APK/Android, IPA/iOS와 6개 child class의 양 플랫폼을 포함한 14개 valid lineage마다 known-positive와
    no-signal negative Control을 둔 exact 28-case seeded profile을 등록한다. disposable network/DNS-disabled
    non-root static sandbox·read-only/noexec mount·archive safety·execution/runtime/result/cleanup evidence는
    requirement일 뿐 fixture/package materialization·provider/fixture execution·cleanup·measurement 증거가 아니다.
  - current device-bound Mobile profile, profile conformance, WorkerJob, emulator/device, install/launch/
    instrumentation, storage/network/TLS/auth/credential use, Graph write, mutation, Replay scheduling, Finding 및
    후속 action authority를 계속 false로 유지한다.
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
- SYS-001A는 locally supplied typed identity와 exact registry resolution만 구현한다. SYS-001B는 signed
  metadata-only request preparation과 deployment trust configuration만 구현한다. SYS-001C는 external deployment가
  이미 만든 signed Gateway/mTLS/non-root execution statement와 raw-result-free receipt를 재검증하지만 repository에는
  live bearer/direct-mTLS host-agent connector, process/filesystem/service/configuration reader, raw result custody,
  root conformance Oracle 또는 executable System runtime이 없다. SYS-001D도 supplied sealed executions를
  비교하고 future fixture requirement를 등록할 뿐 snapshot/host를 열거나 agent·container·VM을 provision·execute·
  cleanup·measure하지 않는다. fresh comparison은 DOMAIN-006 immutable-snapshot strategy 충족 증거가 아니다.
- APP-001A는 locally supplied digest와 declared coordinate를 content-addressed typed identity로만 만든다.
  APP-001B는 signed preparation, opaque custody/authorization reference와 sandbox configuration만 만든다.
  APP-001C는 external deployment의 signed runtime assertion과 detached receipt를 재검증하지만 repository에는
  generic artifact resolver/reader, custody authorization verifier, parser implementation, image/executable admission,
  mount materializer, live sandbox/Worker runtime, raw result interpreter 또는 executable Application analysis runtime이 없다.
  APP-001D도 supplied sealed executions만 비교하고 future seeded fixture requirements를 등록할 뿐 artifact/sandbox를
  materialize·execute·cleanup·measure하지 않는다.
- MOBILE-001A는 locally supplied APP binary/package/application/declaration coordinate를 typed identity로만
  만든다. APK/IPA class는 package format 증거가 아니고 app/runtime/storage/deeplink/TLS/auth locator도 manifest,
  signing, live device, storage value, route reachability, TLS enforcement 또는 authentication safety 증거가 아니다.
  MOBILE-001B가 Tool identity와 request adaptation을 추가하고 MOBILE-001C가 external deployment의 signed
  static-sandbox assertion과 detached receipt를 재검증하지만 저장소에는 package resolver/parser runtime,
  admitted parser/image/sandbox, Mobile Worker profile conformance, WorkerJob, emulator/device runtime, bridge,
  installer, instrumentation, storage/network/TLS/auth client, raw result interpreter 또는 executable Mobile
  analysis path가 없다. C의 admitted Observation과 optional open Hypothesis도 package·runtime·security-property
  truth, Finding 또는 후속 action authority가 아니다. MOBILE-001D도 supplied sealed executions만 비교하고
  future 28-case seeded fixture requirement를 등록할 뿐 package/sandbox를 materialize·execute·cleanup·measure하거나
  device/profile/Worker authority를 추가하지 않는다.

### planned

- remaining Cryptography와 Forensics vertical slices

## 핵심 변경 위치

- Domain과 Graph: `src/pajin/domain/security_domain.py`, `src/pajin/graph/domain_semantics.py`,
  `src/pajin/graph/cross_domain_admission.py`
- Capability와 Worker boundary: `src/pajin/capabilities/domain_projection.py`,
  `src/pajin/capabilities/web_discovery.py`, `src/pajin/capabilities/ai_analysis.py`,
  `src/pajin/capabilities/network_service.py`, `src/pajin/capabilities/cloud_inventory.py`,
  `src/pajin/capabilities/system_inspection.py`, `src/pajin/capabilities/application_static_analysis.py`,
  `src/pajin/capabilities/mobile_package_analysis.py`,
  `src/pajin/control_plane/domain_worker_boundaries.py`
- Surface classification: `src/pajin/discovery/web_surfaces.py`, `src/pajin/discovery/ai_surfaces.py`,
  `src/pajin/discovery/network_surfaces.py`, `src/pajin/discovery/cloud_surfaces.py`,
  `src/pajin/discovery/system_surfaces.py`, `src/pajin/discovery/application_surfaces.py`,
  `src/pajin/discovery/mobile_surfaces.py`
- Network Tool/Worker/Gateway: `src/pajin/tools/network.py`, `src/pajin/tools/gateway.py`,
  `containers/worker/worker_entry.py`
- Workflow: `src/pajin/workflow/redteam_product_flow.py`,
  `src/pajin/workflow/web_discovery_admission.py`, `src/pajin/workflow/web_replay_benchmark.py`,
  `src/pajin/workflow/ai_analysis_admission.py`, `src/pajin/workflow/ai_replay_benchmark.py`,
  `src/pajin/workflow/network_service_admission.py`, `src/pajin/workflow/network_replay_benchmark.py`,
  `src/pajin/workflow/cloud_provider_admission.py`, `src/pajin/workflow/cloud_policy_replay_benchmark.py`,
  `src/pajin/workflow/system_inspection_admission.py`, `src/pajin/workflow/system_replay_benchmark.py`,
  `src/pajin/workflow/application_static_analysis_admission.py`,
  `src/pajin/workflow/application_reanalysis_benchmark.py`,
  `src/pajin/workflow/mobile_package_analysis_admission.py`,
  `src/pajin/workflow/mobile_package_reanalysis_benchmark.py`
- Benchmark: `src/pajin/benchmark/domain_metrics.py`
- 권위 문서: `docs/rfc/0002-multi-domain-security-analysis-architecture.md`, ADR-0210~0239,
  UX-008, DOMAIN-001~006, WEB-001A~D, AI-001A~D, NET-001A~D, CLOUD-001A~D, SYS-001A~D,
  APP-001A~D, MOBILE-001A~D 버전형 계약

## 최신 검증

### 2026-08-27 최종 통합 검증

- System/Application/Mobile A·B 6개 모듈 전체: `1015 passed in 849.14s`.
- 최종 리뷰 수정 회귀:
  - SYS candidate/Permit snapshot provenance와 contextful loader: `2 passed in 39.23s`.
  - SYS exact Graph-store subtype 거부와 contextful loader: `2 passed in 41.05s`.
  - APP exact Graph-store subtype 거부와 contextful loader: `2 passed in 61.25s`.
  - APP/SYS contextful wire에서 `verification.valid=1`은 exact-boolean validator로 거부됨.
- 전체 Python 정적 검증:
  - `.venv\Scripts\ruff.exe check .`: 통과.
  - 변경 Python 24개 `.venv\Scripts\ruff.exe format --check`: `24 files already formatted`.
  - `.venv\Scripts\mypy.exe --strict --platform linux src\pajin`: `352 source files` 통과.
  - bundled Python `-m compileall -q src\pajin`과 변경 test 12개: 통과.
- 문서·패키지·수집:
  - bundled Python `-m pytest -q tests\test_documentation.py tests\test_secrets.py`:
    `14 passed in 0.12s`.
  - `.venv\Scripts\uv.exe lock --check --offline --no-cache`: `Resolved 71 packages in 1ms`.
  - 변경 test 12개 전체 `--collect-only`: `1144 tests collected in 3.12s`.
  - Markdown 상대 링크, 언어 정책, trailing whitespace와 `git diff --check`: 통과.
- 변경 전체 보안 diff scan과 두 차례 독립 C·D 최종 검토를 수행했다. 발견된 SYS embedded-anchor/
  self-certified Graph low finding, SYS snapshot provenance, APP/SYS exact boolean, APP/SYS Graph-store subtype,
  activation action metadata·authority-set 치환, APP/SYS equal-digest byte-count 문제를 수정했고 최종 검토에는
  남은 concrete 코드·보안·문서 blocker가 없었다.
- 12개 변경 test 모듈 1144건 전체를 연속 실행하지는 않았다. deep C/D Graph/evidence E2E가 건당 수분에서
  20분 이상 걸리므로 A·B 전체, C·D 대표/공격 회귀, 전체 수집과 정적 검증으로 범위를 나눴다.

### 단계별 선행 검증 참고

- MOBILE-001D deterministic package re-analysis·28-case fixture·wire security 경계:
  - bundled Codex Python으로 `tests/test_mobile_package_reanalysis_benchmark.py --collect-only`:
    `27 tests collected in 2.46s`
  - exact 28-lineage fixture와 raw-content 8개 marker·zero-counter 15개 coercion:
    `1 passed in 5.26s`
  - APK/Android 및 RUNTIME/iOS exact-package match: `2 passed in 914.81s`
  - digest·signal·result byte-count가 다른 changed와 fresh runtime/confinement provenance 허용:
    `1 passed in 405.89s`
  - no-signal opaque digest 차이의 unresolved: `1 passed in 405.30s`
  - contextful wire reload와 self-consistent forged Graph, recomputed attestation/source-root,
    foreign deployment trust anchor 거부: `1 passed in 1256.53s`
  - 전체 27개 모듈은 한 번에 실행하지 않았다. deep C evidence/Graph 재검증 E2E가 건당 약
    6분 45초~20분 56초이므로 대표 6개를 실행했고 모두 통과했으며 독립 코드·보안 리뷰에도 blocker가 없었다.
- MOBILE-001D 포함 현재 working-tree 정적·문서·비밀정보 검증:
  - `.venv\Scripts\ruff.exe check .`: 통과
  - `.venv\Scripts\mypy.exe --strict --platform linux src\pajin`: `352 source files` 통과
  - bundled Python `-m compileall -q src\pajin tests\test_mobile_package_reanalysis_benchmark.py`: 통과
  - bundled Python `-m pytest -q tests\test_documentation.py tests\test_secrets.py`: `14 passed in 0.20s`
  - MOBILE-001D source/test Ruff format·check 및 strict mypy: 통과
  - 신규 계약·ADR 링크, 영어 문서 언어, trailing whitespace와 `git diff --check`: 통과
- MOBILE-001C selected/root package·platform/parser·custody/archive/profile/Worker·Graph authority 경계:
  - bundled Codex Python으로 `tests/test_mobile_package_analysis_admission.py --collect-only`:
    `30 tests collected`; APK/IPA와 6개 child Surface의 Android/iOS 조합을 포함한 유효 계보 14개
  - trust-anchor false-marker coercion `1 passed in 73.37s`, archive/profile 경계
    `1 passed in 33.99s`, authority/model-copy unknown-state `1 passed in 224.77s`
  - signal-free APK 종단 간 admission `1 passed in 158.67s`, APPLICATION/iOS 종단 간 admission
    `1 passed in 197.03s`, exact retry 멱등성 `1 passed in 285.42s`, 서명 변조 거부
    `1 passed in 93.14s`
  - 전체 30개를 한 번에 연속 실행하지는 않았다. 각 deep Pydantic/Graph 케이스가 약 1.5~5분이므로
    남은 검증 위험은 미선택 조합의 연속 실행 범위이며, 실행된 대표 7개에서는 기능 실패가 없었다.
- MOBILE-001C 포함 현재 working-tree 정적·문서·비밀정보 검증:
  - `.venv\Scripts\ruff.exe check .`: 통과
  - `.venv\Scripts\mypy.exe --strict --platform linux src\pajin`: `351 source files` 통과
  - bundled Python `-m compileall -q src\pajin tests\test_mobile_package_analysis_admission.py`: 통과
  - bundled Python `-m pytest -q tests\test_documentation.py tests\test_secrets.py`: `14 passed`
  - MOBILE-001C source/test Ruff format·check 및 strict mypy: 통과
  - MOBILE-001C 보안 경계 독립 검토와 `git diff --check`: blocker 없이 통과

- MOBILE-001B exact Surface/root-package Scope, custody/sandbox reference identity, archive ceiling,
  false-authority marker와 CAP-002 fail-closed 집중 회귀:
  - bundled Codex Python에 repository `.venv\Lib\site-packages`와 `src`를 연결해
    `python -m pytest -q tests/test_mobile_package_analysis.py`
  - reference digest identity 수정과 request/materializer 회귀 포함 `170 passed in 604.58s`
  - 이후 보강한 request false-marker 전체 sweep와 Replay/Cleanup direct-call 집중 검증:
    `2 passed in 55.58s`
- MOBILE-001A~B 현재 통합 회귀:
  - 같은 bundled Python으로 `tests/test_mobile_application_runtime_surfaces.py
    tests/test_mobile_package_analysis.py`
  - 최종 현재 파일 기준 `528 passed in 767.59s`
- MOBILE-001A 8-class registry, parent/platform identity, strict IDNA, reference/Pydantic-forgery,
  authority false와 legacy wire 집중 회귀:
  - bundled Codex Python에 repository `.venv\Lib\site-packages`와 `src`를 연결해
    `python -m pytest -q tests/test_mobile_application_runtime_surfaces.py`
  - `357 passed in 35.33s`
- MOBILE-001A, APP-001A, DOMAIN-001/002/004, discovery wire와 documentation 통합 회귀:
  - 같은 bundled Python으로 `tests/test_mobile_application_runtime_surfaces.py
    tests/test_application_artifact_runtime_surfaces.py tests/test_security_domain_taxonomy.py
    tests/test_multi_domain_graph_semantics.py tests/test_domain_worker_boundaries.py
    tests/test_discovery_models.py tests/test_documentation.py`
  - `761 passed in 59.60s`
- 현재 working-tree 정적·패키지·보안 검증:
  - `.venv\Scripts\ruff check .`: 통과
  - `.venv\Scripts\mypy --strict --platform linux src/pajin`: `352 source files` 통과
  - bundled Python `-m compileall -q src/pajin tests/test_mobile_package_reanalysis_benchmark.py`: 통과
  - 임시 writable cache를 사용한 `.venv\Scripts\uv.exe lock --check --offline`:
    `Resolved 71 packages`
  - MOBILE-001D source/test `.venv\Scripts\ruff format --check`: 통과
  - bundled Python `-m pytest -q tests/test_documentation.py tests/test_secrets.py`: `14 passed`
  - repository-wide `ruff format --check .`는 기존 formatting baseline 193개 파일로 미통과하며,
    Mobile 변경 Python 5개에는 해당하지 않음
- 같은 미커밋 체크포인트에서 Mobile 추가 전 실행한 선행 slice 회귀:
  - SYS-001A~D 통합: `477 passed, 2 skipped`
  - APP-001A~D 통합: `508 passed, 2 skipped`
- 현재 project `.venv\Scripts\python.exe`는 Windows Application Control이 `_overlapped` DLL
  로딩을 차단해 pytest 초기화가 불가능하다. 최신 pytest/compileall은
  `C:\Users\hyeon\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe`와
  project site-packages를 사용했고, Ruff/mypy/uv console script는 정상 실행했다.

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
- SYS-001A host/process/filesystem/service/configuration 값은 locally supplied identity knowledge일 뿐 host
  existence, running process, file content, service state, configuration truth, agent authentication, credential/root
  privilege 또는 실행 가능성의 증거가 아니다. logical mount와 relative path도 live host path로 resolve되지 않는다.
- SYS-001B deployment binding의 public mTLS policy, subject/SPKI, executable digest와 non-root run-as identity는
  deployment configuration일 뿐 live authentication, UID/SID/group/capability confinement 또는 host read 성공
  증거가 아니다. 별도 agent endpoint도 정의하지 않았으며 repository에는 authenticated host-agent
  runtime이 없다.
- SYS-001C의 trust anchor와 signed execution/non-root/result receipt는 external deployment provenance를 검증할
  뿐 repository가 live host authentication, non-root/root conformance, raw result interpretation 또는 host state
  Oracle을 수행했다는 증거가 아니다. admitted Observation과 optional open Hypothesis는 host existence,
  process/file/service/configuration truth, Finding, Replay, benchmark measurement 또는 후속 실행 권위가 아니다.
- SYS-001D의 same-snapshot/fresh-inspection 구분은 signed input provenance, distinct authority와 causal execution
  window를 검증한 comparison mode일 뿐 실제 snapshot immutability, live host state, physical Worker freshness 또는
  분석 정확성을 독립 확인하지 않는다. match/change/unresolved는 Finding이나 negative conclusion이 아니며 fixture profile도
  disposable host provision·cleanup, privilege denial, evidence completeness 또는 numeric coverage의 측정 증거가 아니다.
- APP-001A artifact SHA-256과 version/parent coordinate는 caller-supplied identity일 뿐 bytes custody·digest
  recomputation, binary format, configuration semantics, installed/runtime support, dependency relation, vulnerability,
  analysis result 또는 실행 가능성의 증거가 아니다.
- APP-001B custody authority/object/authorization digest와 declared byte count는 deployment-supplied configuration일
  뿐 issuer/signature/freshness, object existence, bytes·digest 또는 read authority 검증 증거가 아니다. parser/image/
  executable digest, run-as identity와 sandbox requirement도 live runtime conformance나 분석 성공 증거가 아니다.
- APP-001C trust anchor와 signed sandbox/runtime/result receipt는 configured external deployment provenance를 검증할
  뿐 repository가 live custody authorization, artifact bytes, image/executable, mount/network namespace, non-root runtime,
  parser compatibility 또는 result-body semantics를 독립 확인했다는 증거가 아니다. admitted Observation과 optional
  open Hypothesis는 format·configuration·runtime·dependency·vulnerability truth, Finding, Replay, benchmark measurement
  또는 후속 실행 권위가 아니다.
- APP-001D의 exact-artifact comparison은 두 deployment-signed execution의 same-artifact/parser/image/Scope/budget
  provenance와 distinct action/evidence identity를 검증할 뿐 artifact bytes, parser determinism, physical sandbox
  freshness 또는 analysis correctness를 독립 확인하지 않는다. match/change/unresolved는 vulnerability·Hypothesis·
  Finding이나 negative conclusion이 아니며 seeded fixture profile도 artifact materialization, sandbox provision·cleanup,
  artifact-analysis coverage, detection quality 또는 Profile-floor 측정 증거가 아니다.
- MOBILE-001D의 exact-package comparison은 두 deployment-signed execution의 selected/root/platform/package/
  custody/parser/image/Scope/budget/archive-observation provenance와 distinct action/evidence identity를 검증할 뿐
  package bytes, format, manifest/signing, parser determinism, live sandbox/profile/Worker/device conformance 또는 분석
  정확성을 독립 확인하지 않는다. match/change/unresolved와 result byte-count equality는 security conclusion이
  아니며 28-case fixture profile도 package materialization, sandbox provision·cleanup, Ground Truth verification,
  manifest-component coverage, detection quality, Profile-floor 또는 numeric measurement 증거가 아니다.
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

`CRYPTO-001A`에서 protocol, key-usage, ciphertext artifact 및 cryptographic configuration의 exact parent lineage와
secret-free content-addressed Surface vocabulary를 정의한다. typed identity는 실제 key material, plaintext,
credential use, decryption, signing, protocol negotiation, Oracle/recomputation, Scope, Capability, approval, Permit,
Worker, network, Graph, Finding, mutation 또는 execution authority로 전환하지 않는다. 기존 CTF single-byte XOR
Capability는 재사용 가능한 분류 자산일 뿐 일반 Cryptography Surface 지원 완료 증거로 취급하지 않는다.
