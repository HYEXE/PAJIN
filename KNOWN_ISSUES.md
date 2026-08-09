# PAJIN 알려진 문제

재현된 미해결 제약만 기록한다. 비밀정보의 실제 값과 추측성 백로그는 기록하지 않는다.
로드맵 작업은 `PLAN.md`에서 관리한다.

## CHAIN-002 WALK Hypothesis-only chain 경계

- 상태: File Upload → RAG Injection → Tool Abuse의 mode-neutral ordered chain 계약은 구현됐고 실제 upload·retrieval·Tool abuse·validation은 닫힘
- 현재 보장: sealed WALK-003 Run·artifact·publication과 그 안의 exact WALK-002 Run root·artifact SHA-256·
  Surface Snapshot·RAG Hypothesis를 다시 결박한다. 3개 stage와 2개 edge의 누락·재정렬, Campaign·Target·
  Snapshot·Surface·Run·Hypothesis 치환은 fail closed한다. P0-D2B는 profile identity 의미 대조만 기록하며
  fixture evidence admission, Capability·execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: CHAIN-002가 WALK-002의 원본 Run 경로를 별도로 소유하거나 다시 실행하지는 않는다. WALK-003가
  봉인할 때 검증해 포함한 nested root·artifact authority를 신뢰하며, 실제 문서 업로드·검색·MCP argument
  influence·승인 누락·내부 데이터 접근을 관찰하지 않는다. P0-D2B의 synthetic confirmed Finding은 다른
  Campaign에 일반화되지 않는다.
- 영향: CHAIN-002는 coverage hypothesis로만 사용할 수 있고 Capability Grant, Permit, dispatch, Report,
  benchmark completion 또는 validated Finding의 근거가 될 수 없다.
- 해소 조건: validation 상태를 올리려면 VAL-001 이후 exact Claim, fresh independent execution, negative
  control과 Replay authority를 CHAIN-002 Campaign·WALK Run·Snapshot lineage에 결박한다.

## CHAIN-001 Surface-only AI admin 해석 경계

- 상태: Auth Bypass → AI Admin Surface의 mode-neutral 비실행 계약은 구현됐고 실제 bypass·access·validation은 닫힘
- 현재 보장: exact sealed Recon과 ORCH-001 Surface Snapshot을 다시 검증하고, non-anonymous
  `http-authentication`과 같은 Campaign Target·exact route의 명시적 `http-rag/index-management`만
  content-addressed chain authority로 결박한다. Campaign mode에 따라 분기하지 않지만 exact Campaign digest는
  보존한다. 익명 대안, 다른 route·Target, 비관리 RAG, forged contract·digest, in-memory Recon 변경과 다른
  publication 재생은 fail closed한다. Capability·execution·Claim Replay·Finding confirmation은 모두 false다.
- 제한: DISC-003C의 target-declared `x-pajin-rag` 의미와 sealed discovery producer를 신뢰하며 실제 인증 우회나
  관리 기능 접근을 관찰하지 않는다. UI-only admin, MCP admin, provider console과 일반 HTTP admin은 typed AI
  admin Surface가 아니며 URL·설명·이름으로 추론하지 않는다. mode-neutral은 Campaign authority 제거가 아니고
  cross-Campaign replay를 허용하지 않는다.
- 영향: CHAIN-001은 coverage hypothesis로만 사용할 수 있고 Finding, Report, Replay 성공 또는 실행 승인 근거가
  될 수 없다.
- 해소 조건: 다른 AI admin family는 별도 bounded typed locator와 trusted admission을 먼저 추가한다. validation
  상태를 올리려면 VAL-001 이후 exact Claim, fresh independent execution, negative control과 Replay authority를
  chain·Snapshot lineage에 결박한다.

## SUP-008 approved profile의 verifier TCB·network·pricing 경계

- 상태: approval-free T0/T1 `general-attack-v1`과 deployment-approved T2 no-write
  `general-attack-approved-v1`은 구현됐고 T3+·write·network·priced action은 닫힘
- 현재 보장: SHA-256-pinned Capability Graph deployment가 Campaign·Envelope·activation·Graph store,
  managed Run root·Tool registry·Worker와 exact Approval inventory를 소유한다. executor는 strict Job source에서
  Proposal과 intent를 다시 만들고 Job approval을 deployment inventory와 exact-match한 뒤 기존 verifier를
  재사용한다. APPROVAL-001A가 Approval·GRAPH Permit·non-reusable receipt를 원자 소비하고 PERMIT-004A가 durable
  receipt를 authenticated outcome에 결박한다. exact retry, callback 실패와 cancellation은 Worker를 자동
  재호출하지 않는다. missing·forged·expired·cross-authority approval, 비표준 Run ID, T3+, write,
  cleanup-required, networked와 non-zero-cost action은 Permit 또는 Worker 전에 fail closed한다.
- 제한: leased Job admission, Envelope·Decision actor provenance, Grant의 출처, approval verifier code pin과
  deployment-selected Tool/Policy/Worker는 process-local Control Plane/deployment TCB다. durable Approval·receipt가
  future process의 verifier 동일성을 증명하지 않는다. `costMicrousd=0`은 Campaign max cost가 0이고 Definition이
  network를 금지한 profile에서만 사용한다. production inventory는 no-write이고 reversible-write product
  composition, trusted pricing·egress observation과 cross-host fencing은 활성화하지 않았다.
- 영향: Job이 Campaign·Envelope·Run root·activation·Gateway·verifier code를 선택하거나 approval digest만으로
  issuer 권위를 주장할 수 없고 exact retry로 Worker를 재호출할 수 없다. 반대로 운영 deployment가 Job
  admission·Decision·Grant provenance 또는 verifier code를 잘못 신뢰하면 이 profile이 별도 서명 권위를 만들어
  보정한다고 주장할 수 없다.
- 해소 조건: network 또는 priced action을 열기 전에 trusted fixed-point pricing과 egress observation authority를
  deployment 계약으로 고정한다. write를 열기 전에는 production Capability·cleanup Grant/mapping·restored-state
  verifier와 운영 복구 계약을 제품 surface에 결박한다. cross-host 재개에는 durable verifier pin과 fencing이
  필요하며 T3+는 별도 정책 승인 전까지 닫는다.

## APPROVAL-001C3 이후 process-local verifier·host-local journal 제한

- 상태: single no-write, bounded General Attack reversible-write, 2~8개 no-write/reversible async
  coordinator와 명시적 General Attack/Control Plane opt-in runtime은 구현됐고 cross-process verifier pin,
  Control Plane write와 cross-host coordination은 닫힘
- 현재 보장: deployment-pinned full Capability policy registry와 issuer input authority를 approval claim
  전후 검증하고, path-specific writer 아래 approval·ActionPermit·non-reusable receipt를 schema v4 SQLite
  transaction 하나에서 원자적으로 소비한다. General Attack T2 reversible-write는 기존 cleanup input
  authority도 함께 pin·검증하고 approval·ActionPermit·receipt·cleanup reservation을 한 transaction에서
  all-or-nothing 소비한다. General Attack outcome과 Control Plane no-write completion은 durable receipt를
  다시 결박하며 exact retry는 Worker를 재호출하지 않는다. C1은 기존 no-write 단일 승인 2~8개를 별도
  host-local journal에 ordered batch로 결박하고 claim-started와 dispatch-started/unknown을 구분한다. pending
  subset cancellation과 authenticated terminal/manual reconciliation만 허용하며 모든 상태의 redispatch
  authority는 false다. C2는 reversible 항목마다 기존 combined approval·cleanup authority를 재사용해 exact
  cleanup reservation을 callback 전에 결박하고 authenticated restored-state evidence 없이는 terminal을
  허용하지 않는다. C3 General Attack은 별도 batch 메서드에서 current approval·cleanup request를 재구성하고,
  Control Plane은 deployment v1alpha2와 `capability-graph-batch-v1`에서만 no-write batch를 실행한다. Control
  Plane completion은 sealed Gateway audit와 outcome digest를 다시 검증한다. journal local backup/restore는
  전체 logical state를 재검증하며 pending·unknown은 retention deletion 적격으로 판정하지 않는다.
- 제한: policy registry, writer token과 verifier 구현은 process-local deployment TCB다. 동일 DB를 새
  `SQLiteGraphStore`로 열 때 verifier code 자체는 DB에 영속 pin되지 않으므로 trusted deployment가 같은
  verifier와 complete policy inventory를 다시 주입해야 한다. 공격자가 재시작 runtime code를 선택할 수 있는
  환경에 대한 durable verifier identity·anti-rollback 보장은 없다. production inventory에는 실제
  reversible-write Capability가 없고 `capability-graph-v1`, Common Engine, legacy write는 cleanup authority
  composition이 없어 닫혀 있다. journal은 Graph DB와 하나의 transaction이 아니므로 Graph claim 전후
  crash는 보수적으로 manual review가 필요하다. backup manifest는 local integrity wire이며 서명·암호화된
  remote retention이나 anti-rollback 저장소가 아니다. journal 삭제는 구현하지 않았고 cross-host fencing,
  기본 batch workflow와 T3+도 계속 닫혀 있다.
- 영향: 신뢰된 deployment composition 밖에서 DB만 재사용해 승인 issuer를 인증했다고 주장할 수 없다.
  지원되지 않는 실행 형태는 Permit·Worker 전에 fail closed하고 unknown batch item은 자동 재호출할 수 없다.
- 해소 조건: Control Plane 등 다른 runtime에서 write를 열려면 current signed Definition, code-owned cleanup
  mapping, authenticated outcome, CleanupPermit과 restored-state verifier를 같은 수준으로 composition해야
  한다. cross-process verifier pin이나 remote retention이 필요하면 signed deployment inventory 또는
  host-attested activation, encryption과 anti-rollback repository를 별도 계약·ADR로 구현한다.

## PERMIT-004B2 production cleanup composition과 hold recovery 경계

- 상태: authenticated cleanup 경로는 구현됐지만 기본 제품 활성화는 의도적으로 닫힘
- 현재 보장: PERMIT-004A sealed-result authentication core가 managed Run·anchor·Grant·terminal
  lifecycle·Gateway·Worker·evidence와 current CAP-002 role을 Oracle·Handler 호출 전에 exact-rebuild한다.
  `reversible-write + cleanupRequired=true` source만 pre-action ActionPermit+cleanup hold를 원자적으로 확보한
  뒤 실행할 수 있다. code-owned mapping, distinct current cleanup release, current Handler의 단일 typed plan,
  cleanup Executor, fresh ToolRequest·Grant와 hold를 교차 결박하고, 별도 CleanupPermit·audit·reconciliation으로
  기존 Gateway·Worker를 정확히 한 번 호출한다. source identity는 immutable source-evidence seal root를 사용하며,
  deployment-owned Gateway·managed Run·verifier를 gate에 고정하고 stored CleanupPermit과 exact-match한다. sealed
  cleanup success 뒤에도 독립 verifier가 actual target-state digest를 관찰해야 restored로 판정한다.
- 제한: current CAP-005 production inventory에는 reversible-write Capability가 없으며 positive path는 격리된
  synthetic state fixture다. Envelope·Decision provenance, fixed-point pricing, managed Run/Grant, code-owned
  mapping, cleanup Grant와 restored-state verifier의 deployment composition은 명시적 TCB로 남는다. SUP-007A는
  no-write direct-call만 열며 B2 write 경로를 활성화하지 않는다. schema v3 생성 뒤 v2 code로 direct downgrade할
  수 없고 expired·abandoned hold를 자동 release하지 않으며, failed·unknown cleanup도 자동 retry하지 않는다.
- 해소 조건: 실제 reversible-write Capability를 활성화할 때 deployment authority 등록·운영 절차와 Target별
  restored-state verifier를 계약화한다. hold release나 unknown-outcome recovery가 필요하면 restored state를
  추정하지 않는 별도 v3-aware recovery authority, 감사 기록과 export/restore 절차를 정의한다.

## PERMIT-003 외부 Envelope·Decision·비용 권위 경계

- 상태: 기존 Permit bridge는 유지되며 SUP-007A가 별도 direct-call T0/T1 no-write 제품 조합으로 연결
- 현재 보장: complete PERMIT-001/002·ORCH·CAP-001/002 source를 exact-rebuild하고 current signed CAP-005
  activation에서 request를 다시 prepare한다. 외부 authority가 공급한 기존 run-level MissionEnvelope,
  current Graph Decision과 strict-integer cost도 current Campaign authorization/testing window, Envelope
  duration·autonomy·risk·Tool-call·cost·rate ceiling에 감쇠한다. request-unit은 activated Definition에서 직접
  파생하고 외부 호출 뒤 signed activation을 재검증한 다음 exact Capability·Target·Decision payload·Envelope
  budget에 교차 검증해 기존 GRAPH-006 SQLite atomic Permit과 first-consumption dispatcher만 사용한다.
  provider에는 canonical deep-detached predecessor copy만 전달해 gate-owned request·Campaign 변조를 막는다.
  exact retry는 consumer를 한 번만 호출하고 stale Graph는 final transaction에서 거부된다. Campaign-aware
  final claim clock은 provider 지연 중 authorization 또는 testing window가 닫힌 경우도 SQLite consumption
  전에 거부한다. synchronous callback과 외부 authority 운영 실패는 Permit claim 전에 typed fail-closed
  오류로 거부된다.
- 제한: 일반 공격용 verified Envelope producer, Graph Decision actor/provenance registry와 generic trusted
  micro-USD pricing service가 아직 없다. 따라서 `GeneralAttackActionPermitInputAuthority`와 SUP-007A execution
  input authority는 deployment가 공급하는 code-owned 또는 외부-backed TCB이며 그 구현의 잘못된 인증을
  gate가 암호학적으로 보정한다고 주장하지 않는다. SUP-007A는 명시적 direct-call에서만 Gateway, Worker,
  Grant·Run audit과 Success Oracle을 연결하며 default workflow와 cleanup write는 닫혀 있다. Permit callback
  실패는 consumed terminal이고 자동 redispatch하지 않는다.
- 해소 조건: `general-attack-v1` 밖의 profile을 열기 전에 조직이 승인한 Envelope·Decision provenance와
  pricing provider를 고정한다. T2는 기존 approval authority를 필수로 하고 write는 production cleanup
  Capability와 복구 운영 절차가 생기기 전까지 분리한다.

## SUP-004A model input 크기 경계

- 상태: SUP-004B actual invocation 전에 versioned input transport가 필요한 활성 계약 경계
- 현재 보장: complete canonical `SupervisorSnapshotInput`을 하나의 user message로 결박하되 기존
  `ProviderMessage`의 65,536-character 한도를 넘으면 schedule publication 전에 fail closed한다.
- 제한: SUP-002가 허용하는 최대 4 MiB projection은 유효하더라도 SUP-004A의 단일 메시지 request로
  계획할 수 없다. SUP-004A는 shared Provider wire 한도를 조용히 넓히거나 부분 입력을 전송하지 않는다.
- 해소 조건: versioned chunked 또는 content-addressed input envelope를 도입하고 모든 chunk와 순서를 stable
  Worker request ID, reservation, Gateway outcome, Provider result에 결박한 뒤 consumer-side에서 complete
  input을 재구성·검증한다.

## SUP-004B3 host-local journal과 process-local budget 경계

- 상태: 의도적으로 제한된 첫 durable Supervisor invocation 경계
- 현재 보장: 하나의 canonical SQLite journal이 exact SUP-004A checkpoint, deterministic stable request ID와
  preplanned Provider Run을 dispatch 전에 claim한다. started 상태는 자동 재호출 권위를 반환하지 않으며,
  complete two-seal Run이 있을 때만 terminal로 복구한다. consumer는 journal·seal·artifact·event와 Gateway
  evidence, B2 outcome, strict draft, dual budget scope를 재구성한 뒤에만 SUP-003 compiler를 호출한다.
- 제한: alternate journal 파일, database 복제·교체, cross-host dispatcher와 distributed exactly-once는
  보장하지 않는다. SUP-004B1 ledger는 process-local이므로 restart 뒤 receipt가 증명하는 것은 호출 당시의
  conservative charge projection이지 현재 in-memory 잔액이 아니다. final receipt 없는 started 상태는
  수동 검토가 필요하고, Graph current-view 검증과 journal 전이는 별도 transaction이다. 봉인된 Gateway
  evidence도 complete tainted request를 포함하는 민감 artifact다.
- 해소 조건: 다중 host 운영이 필요할 때 하나의 외부 consensus/fencing authority, durable distributed budget
  ledger와 독립 journal checkpoint/backup을 추가한다. 민감 evidence의 원격 보관은 별도 encryption과 access
  control 정책을 적용한다.

## SUP-005B2 host-local Shadow 측정과 proposal 비적용 경계

- 상태: 의도적으로 제한된 첫 model-backed Shadow 수치 비교
- 현재 보장: Target execution 구간 안의 exact B3 completion과 원시 Target evidence를 typed relation digest로
  묶고, 기존 execution receipt와 외부 measurement attestation이 관계를 서명한다. 모든 좌표는 동일한 signed
  registry activation, fresh Harness·Target·Observation, baseline model call 0회와 candidate 1회를 증명한 뒤
  기존 BENCH-003B1 Result·Comparison 계산에만 전달된다. caller aggregate와 generic Observation recorder는
  이 경계의 입력이 아니다.
- 제한: 외부 measurement signer와 host-local registry activation을 신뢰하며 distributed exactly-once를
  증명하지 않는다. proposal은 Shadow sidecar로 Target 동작에 적용되지 않으므로 numeric delta가 proposal
  내용의 causal improvement를 뜻하지 않는다. B3 charged cost는 conservative upper bound, Observation cost는
  externally adjudicated coordinate-total이라 동일값이나 합계로 추론할 수 없다. threshold와 activation은
  계속 false다.
- 해소 조건: production 활성화가 필요하면 SUP-006 adversarial regression 이후에도 별도 threshold,
  Permit·Approval authority를 통과해야 한다. 분산 실행에는 외부 fencing·durable budget·registry
  checkpoint를 추가한다. proposal 적용은 Phase 7 Permit·Approval 경계 밖에서 허용하지 않는다.

## SUP-006 adversarial corpus와 fake Provider 검증 경계

- 상태: 의도적으로 제한된 authority-containment 회귀
- 마지막 재현: 2026-08-05
- 현재 보장: system/developer 역할 위장, taint downgrade, Scope·Plan·TaskGraph mutation, ToolRequest,
  Capability, Permit, execution, threshold, activation과 draft schema escape를 SUP-002~SUP-005B2 경로에서
  검증한다. schema-valid 악성 rationale도 typed proposal과 final measurement lineage에서 digest-only이고,
  invalid output은 outcome-unknown·manual review·no-redispatch로 고정된다.
- 제한: deterministic fake Provider와 fake external measurement adapter를 사용하며 실제 production 모델이
  공격을 무시한다고 증명하지 않는다. corpus는 대표 공격 클래스의 authority containment를 고정하지만
  모든 언어·인코딩·Provider별 prompt injection 표현을 열거하지 않는다.
- 해소 조건: 새 Provider/model revision 또는 input/output schema가 추가될 때 corpus를 확장하고 real-provider
  opt-in conformance를 별도 환경에서 실행한다. 모델 품질과 activation 판단은 별도 threshold authority가
  소유해야 한다.

## SUP-005A/B1/B2/SUP-006 테스트 fixture 결합과 단일 좌표 집중 검증

- 상태: 활성 테스트 유지보수 제약
- 마지막 재현: 2026-08-05
- 현재 보장: SUP-005A/B1/B2/SUP-006 집중 테스트와 BENCH-003·P0-C·SUP-004B3 인접 회귀를 함께 실행한다. B1은 complete
  tuple equality, 누락·추가·재정렬, context equivocation, post-hoc legacy request, cross-Plan, foreign
  invoker·schedule·source와 권위 boolean을 직접 거부한다.
- 제한: 네 신규 테스트가 Supervisor invocation과 Walking benchmark source 생성을 위해 기존 대형 테스트
  모듈의 비공개 helper를 import한다. B2/SUP-006은 실제 외부 Ed25519 attestation·registry Harness·B3 호출을
  통과하지만 seed 1개·repetition 1개다. 다중 좌표 canonical ordering, schedule 전단사와 stable request
  uniqueness는 모델 invariant로 구현됐지만 별도 다중 좌표 실행 테스트가 아직 없다.
- 해소 조건: 최소 typed builder를 `tests/support/`에 추출하고 다중 seed/repetition에서 schedule·Harness 입력
  재정렬, 누락·중복, cross-coordinate receipt/relation 거부를 직접 검증한다.

## MEM-001/002/003 협업 source·reference·Snapshot 경계

- 상태: 의도적으로 제한된 source adapter, metadata-only reference와 receiver-neutral Snapshot 경계
- 현재 보장: 기존 CampaignFact Proposal을 다시 파싱하고 exact sealed Campaign·Run·현재 root와
  bounded evidence digest를 검증한 뒤에만 기존 Graph Admission Authority로 전달한다. MEM-002는
  기존 GraphEvidence identity와 exact current sealed artifact metadata만 content-addressed reference로
  연결하며 bytes나 filesystem path를 반환하지 않는다. MEM-003은 exact current Graph Snapshot에서
  admitted Fact 전체와 exact admitted Evidence에 대응하는 reference membership만 파생한다.
- 제한: filesystem seal은 producer·Agent·Task·request·Grant·Capability의 의미적 권위를 증명하지
  않는다. 이 전체 lineage는 caller가 구성한 기존 `GraphLineageVerifier`와 producer registry가 별도로
  공급해야 한다. SharedArtifactRef 자체도 Graph admission이나 receiver read authority를 증명하지
  않는다. CollaborationSnapshot도 sender·receiver·purpose나 content read authority를 증명하지
  않는다. Fact statement와 artifact content를 위한 최소·taint-aware receiver는 아직 없다.
- 해소 조건: HANDOFF-001에서 Supervisor-mediated sender·receiver binding을 추가하고 HANDOFF-004에서
  Capability·TTL·byte limit·receiver에 결박된 reader를 추가하되 기존 Graph/Event Log와 RunStore를
  새 저장소로 복제하지 않는다.

## MEM-003 cross-store current-view atomicity

- 상태: 의도적으로 제한된 cooperative in-process 경계
- 현재 보장: Graph Snapshot head를 exact resolve 전후와 각 bounded Run artifact 검증 뒤에 재확인해
  컴파일 중 협력적 Graph 변경을 fail closed한다. 이후 검증에서는 다시 current head와 모든 source를
  재구성한다.
- 제한: Graph Snapshot store와 여러 RunStore 사이에 하나의 분산 transaction이나 cross-host fence는
  없다. 마지막 head 확인 직후 새 Graph Snapshot이 publish될 수 있으며, 기존 CollaborationSnapshot은
  다음 검증 시 stale로 거부된다.
- 해소 조건: 저장소 경계가 cross-process 또는 cross-host로 확장될 때 signed checkpoint/fence나
  transaction coordinator를 별도 ADR과 contract로 정의한다.

## HANDOFF-001/002/003/004 process-local Handoff authorities

- 상태: 의도적으로 제한된 비영속 authority 경계
- 현재 보장: 단일 authority instance가 exact current CollaborationSnapshot과 기존 Agent/Task lineage,
  양쪽 parent Supervisor를 검증하고 Proposal당 하나의 non-executable record만 admission한다.
  terminal result authority는 이 역사적 admission, 같은 Graph store의 연속 후속 current Snapshot,
  destination Agent/Task terminal 상태와 exact sealed result Artifact를 결박하고 handoff당 한 semantic
  result만 admission한다. urgent fast gate는 같은 result Snapshot의 trusted-core|operator Observation과
  Action·Evidence lineage를 검증하고 handoff당 한 `stop-and-escalate` decision만 admission한다.
  reader는 existing delegated single-use Grant를 consume하고 exact receiver·Artifact·Snapshot을 60초·
  65,536 bytes·1회로 제한하며 urgent stop과 Graph head를 반환 전후에 확인한다.
- 제한: Supervisor와 result authority identity 및 admitted records는 서명되거나 process restart 뒤
  영속되지 않는다. fast-gate 1 unit은 local bound이며 runtime Budget reservation이 아니다. decision은
  `admitted-not-applied`이므로 기존 Permit을 revoke하거나 실행을 실제 중단하거나 사람에게 통지하지
  않는다. Graph와 Run store 사이에 분산 transaction은 없다. reader의 receiver 인증, attempt·receipt,
  CapabilityLedger와 urgent decision 확인은 같은 process의 trusted delivery adapter에 한정된다.
- 해소 조건: 외부/다중 process handoff가 필요할 때 signed Supervisor registry와 append-only record
  store/fence를 별도 계약으로 구현한다. 첫 downstream enforcement point는 urgent stop decision을
  명시적으로 소비해야 한다. remote content delivery가 필요하면 signed receiver authentication과
  durable single-use receipt/fence를 별도 계약으로 구현한다.

## Windows 비이식 파일명 정규화

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-04
- 명령: MEM-002 인접 회귀에 `tests\test_integrity.py` 전체를 포함한 pytest 실행
- 결과: Windows가 `evidence/result:.json`, 후행 점, 후행 공백 경로를 생성 시 정규화해
  `test_seal_rejects_externally_created_non_portable_artifact_paths`의 세 case가 예상 파일명을
  실제 디렉터리에서 관찰하지 못했다.
- 영향: 비이식 경로를 사전에 거부하는 코드 경계의 Linux 동작을 이 Windows 파일시스템에서
  같은 fixture로 증명할 수 없다. MEM-002의 normalized path validator와 새 집중 테스트는 통과했다.
- 해소 조건: Linux CI에서 해당 parameterized test를 실행한다.

## Windows 심볼릭 링크 테스트 권한

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-06
- 현재 결과: 공통 `tests/platform_test_support.py::symlink_or_skip`을 사용해 권한 없는 Windows에서
  `WinError 1314`를 명시적 skip으로 분류한다. 관련 CLI·artifact·control·CTF·safe-files 묶음은
  기능 테스트를 계속 실행하고 symlink 생성이 필요한 음성 사례만 skip한다.
- 영향: 심볼릭 링크 생성 권한이 없는 Windows 세션에서도 나머지 테스트는 진행되지만, link substitution
  자체의 fail-closed 동작은 이 환경에서 증명할 수 없다. 이는 PAJIN 코드 회귀의 증거가 아니다.
- 해소 조건: Linux CI 또는 심볼릭 링크 권한이 있는 Windows 환경에서 전체 테스트를
  실행한다.

## Benchmark Harness 고정 fixture 만료

- 상태: 2026-08-06 해소
- 원인: distribution fixture가 고정된 과거 `issued_at/expires_at`을 사용해 실제 activation 시각에
  만료됐다.
- 조치: distribution fixture의 `issued_at`을 현재 시각 기준으로 만들되 registry 발급 시각보다
  앞서지 않도록 하고, 만료 음성 테스트의 고정 시각 계약은 유지했다.
- 검증: deterministic baseline·single-agent·ZAP 관련 묶음 17 passed, 2 skipped.

## Windows POSIX 파일·디렉터리 mode 검사

- 상태: 테스트 플랫폼 분리 완료, POSIX 보안 검증은 Linux 필요
- 마지막 재현: 2026-08-06
- 명령:
  `.\.venv\Scripts\python.exe -m pytest -q tests\test_workflow_integrity_regressions.py::test_confirmation_projection_keeps_private_permissions_and_escapes_markdown`
- 추가 명령:
  `.\.venv\Scripts\python.exe -m pytest -q tests\test_tool_loop.py::test_high_risk_tool_waits_for_exact_approval_and_resumes_in_new_run`
- 결과: 기능·escaping·approval 재개 검증은 Windows에서도 실행하고 `0700/0600` mode assertion만
  POSIX에서 실행하도록 분리했다. Tool Loop 37 passed, workflow integrity 20 passed.
- 영향: POSIX private mode 자체는 Windows에서 증명할 수 없으며 Linux CI가 필요하다.

## PROF-001 Profile semantic authority 경계

- 상태: 의도적으로 제한된 registry 경계
- 현재 보장: 네 Profile의 exact identity·semantics·restrictive controls와 ENG-001 contract를
  content-addressed catalog에 결박하고 unknown version·unregistered substitution·authority flag
  escalation을 차단한다.
- 제한: Profile 자체는 Campaign이나 source Mode를 포함하지 않으며 ROE default 적용,
  MissionEnvelope compiler, benchmark measurement, external submission, execution 권한이 모두 false다.
  PROF-002 compatibility compiler는 별도 authority로 존재한다.
- 해소 조건: `ENG-002`에서 Campaign attenuation·parity가 증명된 opt-in Envelope/execution
  adapter를 별도로 구현한다.

## PROF-002 legacy compatibility compiler 비실행 경계

- 상태: 의도적으로 제한된 direct-call compiler
- 현재 보장: current v1alpha1 Campaign과 source Mode를 exact PROF-001 Profile, compiler, catalog,
  input/output digest에 결박하며 factory와 wire reload에서 substitution을 차단한다.
- 제한: legacy runtime에 연결되지 않았고 persisted audit event·sealed Run·ROE 적용·pentest 자동 선택·
  MissionEnvelope·execution authority가 없다.
- 해소 조건: `ENG-002`에서 exact implementation adapter와 동일 fixture parity authority를 먼저
  구현하고, 모든 parity dimension이 증명된 별도 opt-in 경로에서만 Envelope compilation을 검토한다.

## ENG-001 Common Engine 비실행 경계

- 상태: 의도적으로 제한된 migration 경계
- 현재 보장: 세 legacy Mode와 기존 `MultiAgentCampaignRunner`의 공유 경계를 code-owned contract로
  고정하고 complete Campaign·Mode·contract를 content-addressed Plan에 결박한다.
- 제한: `MissionEnvelope`, legacy/common parity evidence가 아직 없으며
  `commonExecutionAuthorized=false`다. PROF-002 compiler는 semantic projection만 만든다.
- 해소 조건: `ENG-002`에서 동일 fixture parity와 opt-in execution adapter를 별도 수직 슬라이스로
  구현한다.

## ENG-002A implementation adapter의 structural-only parity 경계

- 상태: 의도적으로 제한된 비실행 adapter selection 경계
- 현재 보장: PROF-002 compilation을 exact Mode별 Planner·Validator, AI candidate producer와 공통
  runner·scheduler·projector class identity에 결박하고, cross-Mode substitution·digest drift·parity
  dimension 누락·authority flag escalation을 wire reload에서 차단한다.
- 제한: module-qualified class identity는 source/binary attestation이 아니며 constructor configuration,
  Tool Registry, Policy, Worker, output path, generated ToolRequest, receipt, Outcome과 Mode별 후처리를
  결박하지 않는다. 네 parity dimension은 구조적으로만 존재하고 모두 측정·증명되지 않았다.
- 해소 조건: `ENG-002B`에서 동일 fixture를 legacy direct path와 별도 opt-in adapter path로 실행해
  전체 runtime input·request·receipt·outcome·post-processing의 exact parity를 봉인하고, 모든 음성
  경계를 통과한 별도 gate에서만 실행 eligibility 변경을 검토한다.

## ENG-002C2 Common execution gate의 explicit local 경계

- 상태: 명시적 direct-call CTF 수직 슬라이스에서 실행 가능하지만 default·분산 운영이 아닌 migration 경계
- 현재 보장: C1 false 권한을 보존한 별도 C2 compiler/Envelope, fresh request intent, exact latest
  GraphDecision, current signed activation, Capability Grant를 교차 검증하고 기존 GRAPH-006 원자 Permit과
  CAP-005 Gateway dispatcher만 사용한다. exact retry·request collision·stale Graph·authority/flag 치환은
  fail closed하며 Worker는 durable first consumption에서 한 번만 호출된다.
- 제한: caller가 current activation, local Graph store, matching RunStore, Gateway dependency와 Grant를
  공급한다. organization registry fetch·remote HA·default runtime wiring이 아니며 첫 실제 dispatch 회귀는
  CTF Profile이다. micro-USD reservation은 caller 선언이지 measured billing evidence가 아니다. Permit claim
  뒤 Gateway 실패·불확실 결과는 consumed terminal이고 자동 redispatch하지 않는다.
- 해소 조건: production 활성화 전 organization-issued activation distribution, durable registry/remote
  Graph authority, explicit operator selection과 AI/Bug Hunt end-to-end dispatch 증거를 별도 계약으로
  구현한다. 비용이 권한 결정에 쓰이면 trusted provider price/usage evidence를 reservation에 결박한다.

## P0-C2B2B provider fence의 host-local 범위

- 상태: 활성 분산 운영 공백
- 현재 보장: local Docker adapter는 별도 SQLite provider state에 fence를 side effect 전에
  영속하고 stale 호출을 Docker 전에 차단한다. 별도 SQLite operation lock이 같은 host의 live
  mutation과 higher-fence cleanup을 직렬화하며, receipt-bound evidence와 실제 Docker
  conformance가 이를 검증한다.
- 영향: 이 강제 경계는 하나의 host와 provider state 경로에 한정된다. 서로 다른 host나 원격
  Docker/cloud control plane이 같은 Target을 공유하면 local SQLite만으로 stale writer를 차단할
  수 없다.
- 해소 조건: 원격 provider의 원자적 compare-and-set fence 또는 lease authority와 독립 provider
  evidence를 구현하고 cross-host stale-call 음성 검증을 수행한다.

## P0-D1 Target catalog 배포 권위와 sealed Harness 연결

- 상태: 의도적으로 남긴 catalog 운영 경계
- 현재 보장: public registration/catalog, private Ground Truth binding, selection authority는
  domain-separated content digest로 exact equality를 증명한다. catalog wrapper는 provider 호출 전
  Manifest·adapter·Docker profile·catalog·private Ground Truth를 검증하고 실행 뒤 receipt-bound
  evidence와 등록된 count를 대조한다. selection은 `providerExecutionAuthorized=false`다.
- 영향: exact Docker image ID는 trusted provisioning input이다. catalog 자체를 누가 승인했는지,
  이전 revision으로 rollback하지 않았는지, 최종 registry-governed Harness authority가 어느 catalog
  selection을 사용했는지는 아직 외부 서명·durable activation·sealed source binding으로 증명하지
  않는다.
- 해소 조건: 별도 catalog distribution Trust Anchor와 contiguous durable activation을 추가하고,
  exact catalog selection Run/root/artifact를 governed Harness authority와 reader에 결박한다.

## P0-D2 fixture와 P0-D2B runnable provider의 분리 범위

- 상태: 의도적으로 분리된 선행 fixture와 host-local runnable provider
- 현재 보장: WALK-002/003/005A/005B2/005C1의 exact API version, 실제 state·target observation,
  private seeded Ground Truth를 content-addressed profile과 catalog selection에 결박한다. selection은
  adapter digest가 없고 `providerExecutionAuthorized=false`, `measurementAdmissionEligible=false`다.
- 영향: P0-D2 fixture는 계속 adapter digest가 없고 `networkLogTrusted=false`이므로 실제 Benchmark
  Run이나 metric 근거로 사용할 수 없다. P0-D2B는 별도 profile·Factory·catalog·Docker matcher로
  runnable 경계를 제공하지만 host-local single-container, deterministic no-model lab이다. MCP endpoint는
  Target 내부에 있어 별도 MCP service/process 격리를 증명하지 않는다.
- 해소 조건: fixture는 non-runnable 상태로 보존한다. production 범위가 필요하면 separate MCP service,
  model-backed RAG, external provider trust와 cross-host fence를 새 profile·ADR로 구현한다.

## P0-D3 Hybrid composition의 non-runnable 범위

- 상태: 의도적으로 실행·측정을 금지한 structural composition
- 현재 보장: exact P0-D1/P0-D2B selection, component order와 distinct identity, private Ground Truth,
  code-owned bridge를 content-addressed authority로 결박하고 substitution·repetition·scope expansion을
  차단한다.
- 영향: bridge는 `declared-not-executed`이며 combined Target Factory·Manifest·operation journal·transfer
  artifact·receipt·Observation이 없다. 독립 component Run 두 개를 Hybrid chain completion이나 metric으로
  합산할 수 없다.
- 해소 조건: 별도 Hybrid Factory/Manifest identity, coordinated network·fence·cleanup, exact transfer
  artifact와 bridge execution receipt, combined matcher와 measurement authority를 실제 provider 및
  partial-failure conformance로 검증한다.

## P0-D3B2 Hybrid provider의 host-local 합성 범위

- 상태: 실행 가능하지만 local Docker·deterministic no-model 합성 lab
- 현재 보장: 세 exact image, 한 internal network·coordinate·fence, causal source response→transfer artifact
  →upload→RAG/MCP receipt, Hybrid matcher와 reverse cleanup을 fake provider와 real Docker에서 검증한다.
- 영향: MCP endpoint는 AI Target process 내부 protocol boundary이며 별도 service 격리가 아니다. provider
  fence는 host-local SQLite에 의존하고, catalog distribution·anti-rollback activation과 production model
  behavior는 증명하지 않는다.
- 해소 조건: 필요 시 별도 MCP/model services, 외부 provider compare-and-set fence, signed catalog
  distribution과 governed Harness source binding을 별도 profile·ADR로 구현한다.

## P0-D4 Holdout authority의 비실행·비밀 저장 범위

- 상태: 의도적으로 non-runnable인 계약 경계
- 현재 보장: exact active Target selection과 별도 Holdout Factory·private suite·public commitment를
  결박하며 공개 artifact에서 case·Finding·matcher·evaluation seed를 제외한다. seeded/holdout replay,
  seed 재사용, catalog 확대와 cross-profile·binding 치환을 차단한다.
- 영향: deterministic private suite가 저장소 코드에 등록되어 있으므로 production 비밀 저장소나 blind
  evaluation을 증명하지 않는다. provider 실행·measurement admission·content disclosure는 false다.
- 해소 조건: access-controlled external evaluator, high-entropy one-time seed, signed bounded adjudication
  projection, leakage-safe log policy와 isolated provider lifecycle을 별도 authority로 구현한다.

## P0-D5 Mutation authority의 비실행 materialization 범위

- 상태: 의도적으로 non-runnable인 계약 경계
- 현재 보장: exact base Target selection, code-owned mutation seed·state·ordered operations, derived
  Manifest와 declared reset plan을 content-addressed authority로 결박한다. base catalog의 빈 mutation
  allowlist는 유지하고 scope expansion·cross-profile replay·순서·seed·state 치환을 차단한다.
- 영향: 실제 Target state를 restore·mutate·verify하지 않으며 reset receipt도 없다. 이 authority를
  Benchmark Result나 measurement admission 근거로 사용할 수 없다.
- 해소 조건: provider-specific materializer, observed base/expected-state evidence, fenced cleanup/recovery와
  registry-governed Harness admission을 새 runnable authority로 구현한다.

## P0-E1 측정의 local deterministic Target 범위

- 상태: 의도적으로 제한된 첫 실측 baseline
- 현재 보장: exact P0-D1 catalog selection, registry-governed Harness, sealed Target Run, execution
  receipt-bound Docker evidence와 private Ground Truth matcher를 다시 검증한 뒤 전체 seed/repetition raw
  Observation에서 12개 BENCH-001 metric을 계산한다.
- 영향: 결과는 고정된 local Docker SQLi lab의 deterministic PAJIN baseline이다. production Web/API
  conformance, 일반 Scanner·single-agent 성능, cross-host provider fence 또는 signed catalog distribution을
  증명하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: 별도 Scanner·single-agent measurement authority, signed catalog distribution과 필요한 외부
  provider trust 경계를 구현하고 동일 benchmark 좌표의 sealed Result를 비교한다.

## P0-E2B Scanner 측정의 local ZAP 범위

- 상태: 의도적으로 제한된 첫 일반 Scanner 실측 baseline
- 현재 보장: OWASP ZAP 2.17.0의 exact runtime image ID, code-owned automation plan, hardened Scanner
  container, internal P0-D1 network, receipt-bound raw SARIF와 strict normalization을 registry-governed
  Harness source 및 completed Result에 결박한다. 실행은 immutable image ID를 사용하고 종료 뒤 관리
  대상 container와 network 부재를 증명한다.
- 영향: 결과는 고정된 local Docker SQLi lab과 한 ZAP version/configuration에 한정된다. image ID의
  trusted provisioning, 일반 Web Scanner 성능, production 공급망, single-agent 성능, cross-host fence를
  증명하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: P0-E3 single-agent authority와 필요한 signed catalog distribution·외부 provider trust를
  별도 구현하고, 동일 좌표에서 모든 비교 metric이 measured인 sealed Result끼리만 비교한다.

## P0-E3B2 Single-agent 측정의 host-local 범위

- 상태: 제한된 local Docker·GPU baseline 측정 완료
- 현재 보장: digest-pinned llama.cpp CUDA image, exact Qwen GGUF, Policy Tool Loop implementation,
  Provider registration, prompt·Tool catalog, sampling·no-fallback configuration을 fresh P0-D1 Target
  coordinate에 결박한다. Provider와 fixed SQLi Tool의 action별 network route, exact Worker/proxy image ID,
  Target operation·cleanup receipt, Tool Loop Run/root, raw trace SHA-256와 normalization을 다시 검증한 뒤
  registry-governed source에서 completed `BenchmarkResult`를 봉인한다.
- 영향: 결과는 고정 local Docker SQLi lab, 한 llama.cpp/Qwen build, 한 seed·repetition 좌표에 한정된다.
  Docker image ID는 trusted provisioning input이며 cross-host fence, remote Provider trust, 일반 single-agent
  성능 또는 통계적 비교를 증명하지 않는다. local token 가격 USD 0은 marginal Provider 가격만 뜻하며
  GPU 전력·감가상각 비용을 포함하지 않는다. candidate comparison과 Supervisor activation은 false다.
- 해소 조건: 비교가 필요하면 동일 Manifest·좌표·measurement authority의 sealed Scanner와 single-agent
  Result에서 모든 필수 비교 metric의 측정 가능성을 먼저 검증한다. production 범위는 signed catalog
  distribution, 외부 Provider trust와 cross-host fence를 별도 authority로 구현한다.

## P0-C2A recovery seal과 journal terminal 전이 사이 중복 감사

- 상태: 활성 보수적 중복 가능성
- 조건: Recovery Authority Run을 seal한 직후 journal attempt를 `reconciled`로 바꾸기 전에
  프로세스가 종료된다.
- 영향: 다음 시작은 이미 journaled된 성공 cleanup receipt를 재사용해 provider를 다시
  호출하지 않지만 동일 attempt에 대한 새 Recovery Authority Run을 하나 더 봉인할 수 있다.
  측정 Admission은 두 Run 모두 false라 안전성이나 metric에는 영향을 주지 않는다.
- 해소 조건: sealed Run ID를 journal terminal transition과 연결하는 재개 가능한 publication
  marker를 추가하고 동일 authority의 재봉인을 제거한다.

## P0-C2B2A1 activation store의 외부 복구 권위

- 상태: 활성 운영 복구 공백
- 현재 보장: registry distribution origin은 별도 Ed25519 key로 검증되고, intact host-local SQLite
  store는 마지막 accepted bundle을 append-only로 유지해 restart rollback·gap·equivocation을
  차단한다.
- 영향: activation database 전체가 삭제되거나 신뢰 경계 밖에서 교체되면 remembered head도 함께
  사라진다. local store만으로는 오래된 revision 1을 새 bootstrap처럼 복원한 상황을 구분할 수 없다.
  distribution Trust Anchor rotation과 remote HTTPS fetch도 아직 없다.
- 해소 조건: 운영 백업 또는 독립 transparency/checkpoint anchor와 명시적 distribution Trust
  Anchor rotation authority를 추가한다.

## Windows 애플리케이션 제어에 의한 임시 console-script 차단

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-06
- 명령:
  `.\.venv\Scripts\python.exe -m pytest -q tests\test_packaging_entrypoints.py::test_distribution_artifacts_work_in_a_clean_no_dependency_install`
- 결과: clean source에서 wheel·sdist build, wheel install, isolated import와 metadata 검증까지 통과한 뒤
  임시 venv의 `pajin-control-plane.exe` 또는 후속 console-script 실행이 `WinError 4551`로 차단됐다.
  비샌드박스 실행과 저장소 내부 전용 basetemp에서도 동일했다.
- 영향: 설치된 console-wrapper의 실제 `--help`·invalid option·missing extra 동작 한 건을 이 Windows
  정책에서 완료할 수 없다. 해당 smoke를 제외한 packaging/entrypoint 16건은 통과했다.
- 해소 조건: Linux CI 또는 조직 AppControl이 빌드 산출물 실행을 허용하는 서명된 환경에서 같은
  테스트를 실행한다. 테스트 assertion이나 애플리케이션 제어 정책을 우회하지 않는다.

## Windows 애플리케이션 제어에 의한 mypy 네이티브 모듈 차단

- 상태: 현재 재현되지 않음, 재발 가능 환경 제약
- 마지막 확인: 2026-08-06
- 명령: `.\.venv\Scripts\python.exe -m mypy --platform linux --cache-dir <writable-cache> src\pajin`
- 현재 결과: 256 source files 통과
- 과거 증상: import 단계에서 Windows 애플리케이션 제어가 네이티브 `librt.base64` 모듈을
  차단했다.
- 재발 시 조치: Linux CI를 사용하거나 조직의 애플리케이션 제어 정책에서 서명된 네이티브
  모듈을 허용한다. mypy 실행을 위해 정책을 비활성화하지 않는다.

## Git OpenSSL CA 경로

- 상태: 활성 로컬 전송 제약
- 마지막 재현: 2026-08-01
- 증상: 기본 Git OpenSSL backend가 GitHub 원격에 대해
  `unable to get local issuer certificate`를 보고할 수 있다.
- 검증된 대안: TLS 검증을 끄지 않고 Windows 인증서 검증을 사용한다.
  - `git -c http.sslBackend=schannel push origin main`
  - `git -c http.sslBackend=schannel ls-remote origin refs/heads/main`
- 해소 조건: 로컬 Git CA bundle을 복구하거나 schannel override를 계속 사용한다.

## Docker daemon 가용성

- 상태: 현재 가용, 세션 의존 환경 제약
- 마지막 관찰: 2026-08-02
- 현재 결과: Docker Desktop 4.78.0 / Engine 29.5.3에서 P0-C2B2B SQLi, P0-D2B AI/RAG/MCP,
  P0-D3B2 Hybrid, P0-E2B ZAP와 P0-E3B2 local llama.cpp/Qwen governed measurement가 통과했고 종료 뒤
  관리 대상 container와 network가 남지 않았다.
- 영향: Docker Desktop이 다음 세션에 자동으로 가용하다는 보장은 없다. daemon이 꺼져 있으면
  opt-in live test는 실행할 수 있지만 일반 fake-provider 검증은 계속 가능하다.
- 필요한 조치: 실제 컨테이너 증거가 필요한 작업 전에 daemon 상태와 exact image ID를 다시
  확인한다. 실행하지 않은 live 검증을 성공으로 보고하지 않는다.
