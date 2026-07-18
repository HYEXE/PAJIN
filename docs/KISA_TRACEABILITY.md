# KISA AI 보안 레드티밍 가이드 추적성

## 1. 목적과 기준선

이 문서는 KISA 「AI 보안 레드티밍 가이드」(2026.07)의 요구사항을 PAJIN의 코드, 실행
통제, 증적, 결과 산출물에 연결한다. 페이지는 첨부 PDF의 물리 페이지를 기준으로 한다.

> 최종 최신화: 2026-07-18. Candidate admission, 원 증거 심사, 제한 재현 계약, Replay
> Compiler·단일 사용 ticket·Restricted Reproducer와 M03·M06·A04용 trusted fresh-session
> materializer·live KISA transcript Oracle·runner coordinator, receipt 재로딩 공통 Gate와
> append-only `validation/v1alpha1` Confirmed 투영을 구현했다. flat `findings.json`은 봉인된
> 원 snapshot으로 보존하며 제품 소비자는 versioned 투영을 사용한다. M6-05는 이 투영의
> reproduction-backed baseline에 결박된 negative ReplayOutcome과 별도 정상 기능 회귀를
> hardened `kisa-retest` 경로에 연결했다. M6-06은 로컬 KISA positive/negative ticket을 stable
> SQLite 원장에 영속화하고 프로세스 재시작 뒤 read-only verifier와 CLI로 receipt 결박을 다시
> 검증하는 경계를 추가했다. M6-07A는 일반 Local Campaign에도 명시적
> `pajin run ... --kisa-replay --repetitions 2` opt-in을 추가해 exact M03·M06·A04 Candidate를
> 같은 SQLite replay와 공통 Gate에 연결했다. flag가 없는 기본 Local 실행은 자동 replay를
> 수행하지 않는다. M6-07B-2A는 Control Plane sealed-source 기반을 추가했다. 소유자 통제 managed
> filesystem Artifact repository, immutable `cp_artifacts` metadata, schema v3와 producer Control
> Plane/sealed Run identity를 따로 보존하는 server-owned admission을 구현했다. consumer는 exact
> opaque `(artifact_id, repository_version)` locator만 사용하고 resolution은 content와 seal을 다시
> 검증한다. M6-07B-2B는 batch input을 그 locator와 idempotency key로 한정한다. Control Plane은
> managed sealed AI Red Team source를 다시 읽어 eligible exact M03·M06·A04 confirmation Candidate와
> contract를 파생하고 trusted Replay Compiler를 실행한 뒤 canonical `ReplayCompilation`과
> `ReplayCapabilityGrant`를 append-only planned/pending, non-dispatchable PostgreSQL derivation
> record이자 proof로 저장한다. 2026-07-18에는 M6-07B-2C durable issuance도 구현했다. 내부 멱등
> `ControlPlaneService.issue_replay_batch(batch_id, actor=...)` 서비스는 managed source를 다시
> resolve·재검증하고 schema v5 durable budget account/reservation과 보수적인 sealed-rate
> account/reservation을 사용해 첫 시도 전체를 예약한다. pending item마다 fresh Replay Run identity와
> 5분 Grant로 다시 compile해 새 canonical compilation을 append하고, 정확한 `compilation_id`,
> `budget_reservation_id`, `rate_reservation_id`, attempt, Replay Run, compilation digest, Grant
> digest에 결박된 내부 Job과 `issued` ticket을 하나씩 원자적으로 만든다. 최초 planned row는
> non-dispatchable 상태로 남고 재사용하지 않는다. M6-07B-2D는 schema v6 append-only
> `cp_replay_tool_permits` 원장과 내부 서비스 전용 호출별 permit 발급을 구현했다. strict request는
> executor profile, lease token, ticket ID, fencing value와 1-based call ordinal만 받는다. 서버는 exact
> active authority graph와 counter를 다시 검증하고 rolling-window rate 재수용을 수행한 뒤 canonical
> Tool/target/method 및 신뢰된 unit 비용에 결박된 일회성 permit을 발급한다. ticket/ordinal 고유성과 저장된 permit digest/request ID로
> 응답 유실 중복 호출은 같은 row를 돌려주며, 최초 발급만 예약량을 consumed로 옮기고 event를 append한다.
> 실행 여부가 불확실해도 발급된 permit은 consumed로 남는다. public Replay/admission API, HTTP transport,
> executor/redeem 집행, 새 identity retry 발행, typed finalization/Gate와 negative Control Plane retest가
> 후속이며 M6-07B 전체는 미완료다.

이 매핑은 기술 평가를 일관되게 수행하고 누락을 드러내기 위한 추적성 자료다. 조직의
법률·윤리·인력·교육·비즈니스 영향·운영 절차를 자동으로 증명하지 않으며, 규정 준수
인증을 의미하지 않는다.

## 2. 가이드에서 PAJIN까지의 흐름

```mermaid
flowchart LR
    G["KISA 가이드<br/>위협·절차·평가·기록"] --> C["KISA Catalog<br/>19개 위협·52개 체크리스트"]
    C --> S["Scenario Selection<br/>대상 유형·요청 위협"]
    S --> P["Planner<br/>반복 가능한 Task Graph"]
    P --> X["Specialists<br/>Tool Gateway·Docker Worker"]
    X --> CP["Trusted Candidate Producer<br/>구현"]
    CP --> V["Semantic Validator<br/>증거 심사·구현"]
    S -. "explicit Local opt-in" .-> LO
    LO["Explicit Local KISA Orchestrator<br/>단일 process·writer"] -. "opt-in sequencing" .-> P
    LO -. "sealed source → replay → Gate" .-> CG
    V --> RC["Versioned Replay Contracts<br/>스키마 구현"]
    RC --> RG["Deterministic Compiler + Replay Grant<br/>구현"]
    RG --> TL["SQLite Ticket Ledger<br/>원자 상태 전이·event journal"]
    TL --> RR["Restricted Reproducer<br/>새 요청·새 증적·이중 seal 구현"]
    RR --> KD["KISA Fresh-session Driver<br/>M03·M06·A04 구현"]
    KD --> O["Live KISA Transcript Oracle<br/>원문 재판정 구현"]
    O --> RI["Replay Index<br/>원본·재현 증적 분리"]
    RI --> DV["Read-only Ticket Verifier<br/>재시작 후 finalization 대조"]
    TL --> DV
    DV --> CG["Common Confirmed Gate<br/>receipt 재검증·구현"]
    CG --> VP["validation/v1alpha1<br/>Decision·Finding·Report"]
    VP --> BR["Baseline-bound Retest<br/>exact Candidate·receipt 결박"]
    BR --> NR["Restricted Negative Replay<br/>별도 공격 Run"]
    NR --> NO["Trusted Negative Oracle<br/>전체 반복 CONTRADICTS"]
    RT["Normal Parent Retest<br/>정상 기능 probe"] --> NREG["Regression<br/>독립 평가"]
    NO --> KG["KISA Retest Gate<br/>fixed·still-vulnerable·inconclusive"]
    NREG --> KG
    V --> N["Candidate·Decision Ledger<br/>needs-review"]
    O --> E["Evaluation<br/>지표·커버리지·체크리스트"]
    VP --> E
    KG --> E
    N --> E
    E --> R["KISA Artifacts<br/>Markdown·JSON"]
```

## 3. 요구사항 매핑

| 가이드 기준 | PDF 페이지 | PAJIN 구현 | 실행 증적·산출물 | 상태 |
| --- | ---: | --- | --- | --- |
| AI 시스템 계층과 공격 표면 | 10-12, 28-29 | `SystemLayer`, Scenario `attack_surface` | `kisa-test-plan.json`의 `scenarioDefinitions` | 구현 |
| 19개 위협 분류 D01-D03, M01-M08, A01-A04, S01-S04 | 13-14 | `KISAThreatDefinition`, `KISA_CATALOG` | `kisa-results.json`의 요청·실행·미실행 위협 | 전체 카탈로그 구현 |
| 평가 기준과 측정 지표 | 26 | `EvaluationThresholds`, `KISAMetricResult`, replay index, 공통 Confirmed Gate | 공격 성공률, 차단·거부율, 반복 관찰률, 민감정보 노출, 지연, 커버리지, replay Oracle support, versioned Confirmed ID | 부분 구현: 기술 지표와 canonical Confirmed 연결 구현, 비즈니스 영향 지표 후속 |
| 위험 등급 | 27 | Candidate/Finding `severity`, 공통 Confirmed Gate, 체크리스트 판정 | `candidate-findings.json`, `validation/v1alpha1/findings.json`, `kisa-results.json` | 부분 구현: reproduction-backed 기술 등급 생성, 조직별 비즈니스 우선순위는 미완료 |
| 공격 표면·페르소나 | 28-29 | `KISAPersona`, Scenario 대상 유형·표면 | `kisa-test-plan.json` | 구현 |
| 시나리오 필수 항목(표 17) | 30 | `KISAScenarioDefinition` | `scenarioDefinitions`에 조건·절차·판정·영향·증적 포함 | 구현 |
| 시나리오 기반 반복 공격 | 35-36 | `KISAPlannerRuntime`, `repetitions` | `plan.json`, `task-graph.json`, `events.jsonl` | 구현 |
| 결과 판정과 영향 분석 | 37-38 | Candidate Producer, Semantic Validator, fresh-session Restricted Reproducer, live KISA transcript Oracle, SQLite ticket finalization verifier, Multi-Agent 및 명시적 Local coordinator, Control Plane trusted KISA 파생·durable 첫 시도 발행·내부 호출별 permit 발급, 공통 Confirmed Gate, baseline-bound Retest Gate | 원 Run, 별도 replay Runs, replay ticket 원장, Control Plane planned proof와 fresh compilation, budget/rate reservation, 내부 Job/issued ticket, append-only per-call permit ledger, `kisa-replay-index.json`, `validation/v1alpha1/`, `kisa-retest.json` | 지원 KISA positive/negative replay 계약, 명시적 Local orchestration, 재시작 후 receipt 검증, Control Plane exact M03·M06·A04 파생, 내부 첫 시도 발행과 일회성 호출별 permit 원장/발급 구현; public Replay API·HTTP transport, executor/redeem, retry, finalization/Gate와 조직 영향 분석은 후속 |
| 로그와 부인 방지 증적 | 39 | Tool Gateway·Worker 증적, 해시, 감사 이벤트, SQLite ticket event journal | `evidence/`, `events.jsonl`, `kisa-execution-log.json`, `replay-tickets.sqlite3` | 로컬 DB/OS 신뢰 경계 구현; portable 서명 proof 후속 |
| 결과 분석·보고 | 41-44 | `KISAModePack` 보고 생성 | `kisa-report.md`, `kisa-results.json` | 구현 |
| 수행 체크리스트(부록 1) | 49-51 | 52개 `ChecklistDefinition`과 4상태 판정 | `kisa-checklist.json` | 구현 |
| 테스트 계획(표 28) | 64 | `_test_plan` | `kisa-test-plan.json` | 구현 |
| 테스트 완료 보고(표 29) | 64-65 | `_completion_report` | `kisa-completion-report.json` | 구현 |
| 테스트 실행 기록(표 30) | 65 | `_execution_log` | `kisa-execution-log.json` | 구현 |
| 완화·재검증·회귀 확인 | 43-44, 51 | `KISARetestService`, baseline-bound Restricted Reproducer, trusted negative Oracle | `remediation-plan.json`, `kisa-retest.json`, `kisa-retest-index.json`, replay receipt lineage, `kisa-checklist-overlay.json` | 지원 KISA 계약 구현: verified `contradicts`만 fixed, 정상 기능 regression 별도 |

## 4. 위협 카탈로그와 실행 커버리지

| 위협군 | 코드 | 현재 상태 |
| --- | --- | --- |
| 데이터 | D01, D02, D03 | 분류·추적 가능, 실행 시나리오 추가 필요 |
| 모델 | M01-M08 | M03·M06 실행 가능, 나머지 시나리오 추가 필요 |
| 에이전트 | A01-A04 | A01·A02·A04 실행 가능, A03 시나리오 추가 필요 |
| 공급망 | S01-S04 | 분류·추적 가능, 실행 시나리오 추가 필요 |

첫 수직 시나리오 `kisa.agent.indirect-tool-hijacking`은 `mock-agent`를 대상으로 간접
프롬프트 인젝션과 비인가 도구 호출을 반복 실행하며 A01·A02를 검증한다. Campaign이 A04를
함께 요청하면 이를 성공으로 간주하지 않고 `untested`와 사유로 기록한다. 따라서 카탈로그
수록과 실제 동적 테스트 커버리지를 구분할 수 있다.

공급자 중립 `ai-chat-api` 대상에는 다음 세 시나리오가 추가로 연결된다.

- `kisa.model.system-prompt-disclosure`: M03 시스템 프롬프트 전용 표식 노출
- `kisa.model.jailbreak-policy-bypass`: M06 제한 동작 승인 표식을 통한 정책 우회
- `kisa.agent.memory-poisoning-persistence`: A04 동일 세션 후속 턴의 오염 표식 지속

각 시나리오는 실제 Docker Worker에서 egress proxy를 거쳐 고정된 Chat API 계약만
호출한다. Tool, Trusted Candidate Producer와 결정론적 Semantic Validator는 동일한 strict
`AIChatProbeOutput` 계약을 파싱하고 Tool이 제공한 `vulnerable`·`matched` 값을 신뢰하지 않은
채 계획에 기록된 판정 마커를 원문 대화 응답에서 다시 확인한다. 이는 원 실행의 증거
심사이며, 새 요청과 증적 계보를 만드는 독립 재현은 아니다.

## 5. 체크리스트 판정 원칙

| 상태 | 의미 | 예시 |
| --- | --- | --- |
| `yes` | 같은 Run의 구조화 증적으로 확인됨 | Scope, 교전 규칙, 반복 실행, 로그, 독립 판정 |
| `no` | 필요한 활동 또는 산출물이 수행되지 않음 | 완화 과제, 재검증, 정상 기능·회귀 테스트 |
| `not-applicable` | 해당 Run에 판정 대상이 없음 | Finding이 없을 때 취약점별 설명·완화 |
| `needs-review` | 기술 실행만으로 확인할 수 없음 | 법률 검토, 교육, HITL, 비즈니스 영향 |

`yes`에는 증적 경로와 자동 판정 여부가 포함된다. 증적이 없거나 조직 맥락이 필요한 항목을
관행적으로 통과시키지 않는다. Docker 실행이 실제 증적에서 관찰된 경우에만 격리 환경
항목을 `yes`로 판정한다.

## 6. 캠페인 실행 재현 명령과 기대 결과

이 절의 명령은 개발자가 전체 Campaign을 다시 실행하는 방법이다. Candidate별 Restricted
ReplayOutcome을 생성하는 Validator 독립 재현 단계와는 구분한다.

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
```

현재 예제의 기대 결과는 다음과 같다.

- Supervisor, Planner, 반복별 Specialist, Candidate Producer, Semantic Validator, Reporter가
  분리된 역할 또는 신뢰 경계로 실행된다.
- A01·A02는 실행되고 A04는 대상 연결 시나리오 부재로 커버리지 갭에 남는다.
- 두 번의 공격 성공 증적은 하나의 Candidate와 legacy validation Finding으로 중복 제거된다.
- Candidate와 legacy Finding은 두 개의 Docker Worker 증적을 참조한다.
- 공격 성공률과 차단·거부율 임계값은 실패하고 민감정보 노출과 지연 임계값은 통과한다.
- 표 28-30 대응 JSON, 전체 체크리스트 JSON, 평가 JSON, Markdown 보고서가 생성된다.

공급자 중립 AI Chat Lab Campaign은 다음 명령으로 별도 실행한다.

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml down
```

같은 exact KISA Chat 계약은 일반 Local runner에서도 명시적으로 선택할 수 있다.

```powershell
.venv\Scripts\pajin run examples\kisa-ai-chat-lab.yaml --worker docker `
  --kisa-replay --repetitions 2
```

`--kisa-replay`가 없으면 `pajin run`은 기존 Local 원 실행만 수행하고 replay ticket이나 공통
Confirmed Gate를 자동으로 시작하지 않는다. opt-in은 AI Red Team Campaign의 exact M03·M06·A04
`ai.chat-probe` allowlist에만 적용한다. Candidate 부재, Validator semantic support 누락 또는
미등록 Scenario를 구조적으로 비슷하다는 이유로 replay하지 않는다.

이 Campaign은 M03·M06·A04에 대해 원 실행 6개 Task와 Candidate별 2회 fresh-session replay를
기대한다. 봉인된 원 Run 뒤에는 trusted Candidate 중 `independent-reproduction-missing` 상태인
항목만 별도 replay Run에서 실행한다. 반복마다 원 실행 및 다른 반복과 구별되는 session ID를
materialize하고, Oracle은 Worker 판정 플래그 대신 원문 transcript에서 카탈로그 check를 다시
계산한다. 취약 프로필에서는 3개 replay record가 Oracle support를 가질 수 있지만
공통 Gate가 영수증을 다시 검증하면 `confirmationMutationApplied`는 `true`가 된다. 원
Candidate·Decision·flat `findings.json`은 덮어쓰지 않고 `validation/v1alpha1`에 최종 Decision과
Finding을 새 seal로 추가하므로, 취약 fixture의 제품 수준 Confirmed 기대 건수는 3건이다.

positive replay ticket은 개별 sealed replay Run 밖의
`<output>/replay/replay-tickets.sqlite3`에 저장된다. 이 원장은 canonical compilation, source
root, replay Run과 Campaign·Tool·Scenario issuance context digest를 결박하고
`issued → claimed → finalized` 상태 전이와 event journal을 원자적으로 기록한다. 실행
프로세스가 종료된 뒤에는 다음 명령이 DB를 `mode=ro`로 열어 receipt ticket, artifact digest와
최종 seal root를 다시 검증한다.

```powershell
.venv\Scripts\pajin replay-verify <replay-run-directory> `
  --ledger <output>\replay\replay-tickets.sqlite3
```

명령은 누락된 ledger를 생성하거나 ticket 상태를 변경하지 않는다. 미완료 ticket이나
compilation·source/replay 계보·digest·seal 불일치는 fail closed다.

명시적 Local 경로의 stable ledger는 `<output>/local-replay/replay-tickets.sqlite3`다. Local
coordinator는 원 Run을 먼저 완결·봉인하고, 같은 live Campaign budget·request-rate ledger·취소
문맥으로 Candidate replay를 실행한 뒤 batch coverage와 canonical receipt를 다시 확인해 공통
Gate를 적용한다. verified replay가 없으면 Gate를 적용하지 않는다. flat `findings.json`은
pre-replay snapshot으로 보존되고 reproduction-backed Confirmed는 append-only
`validation/v1alpha1`에만 기록된다. 이 순서는 단일 프로세스·단일 writer 전제이며 분산 lock이나
Control Plane lease를 제공하지 않는다.

## 7. 완화 및 재검증 폐루프

완화 계획과 취약점 상태 재검증은 기준 Run의 reproduction-backed Finding만 대상으로 한다.
따라서 Restricted Replay 이전의 새 Run에서는 Candidate가 보존되더라도 완화 action은 비어 있고,
retest가 `fixed` 또는 `still-vulnerable`을 주장하지 않는다. 정상 기능 회귀는 별도로 측정하며,
`improve.retest`는 제품 Confirmed 기준선이 생길 때까지 `needs-review`로 남는다.

baseline loader는 봉인된 `validation/v1alpha1`의 Confirmed Decision/Finding과 receipt lineage를
검증한다. legacy flat `findings.json`, semantic-only Candidate, 재현 없는 historical confirmation은
재검증 기준으로 거부한다. 허용된 각 baseline Finding은 Candidate, source Decision, Finding,
remediation action, baseline/retest Run과 seal root, original/replay request, scenario, threat, Tool,
target에 정확히 결박된다. fingerprint는 표시 보조일 뿐 lifecycle 권한 결박이나 신규 Finding
판정에 사용하지 않는다.

```powershell
.venv\Scripts\pajin kisa-plan-remediation <baseline-run-directory>
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml up --detach --force-recreate
.venv\Scripts\pajin kisa-retest <baseline-run-directory> `
  examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
```

재검증 판정은 다음 보수적 규칙을 적용한다.

| 판정 | 조건 |
| --- | --- |
| `fixed` | 기준 Candidate에 결박된 모든 기대 반복이 성공하고 canonical receipt의 trusted negative Oracle이 명시적으로 `ReplayOracleVerdict.CONTRADICTS`를 반환함 |
| `still-vulnerable` | 기준 Candidate에 결박된 verified ReplayOutcome의 trusted Oracle이 `ReplayOracleVerdict.SUPPORTS`를 반환함 |
| `inconclusive` | support/contradiction 혼합, 실행 실패·취소·timeout·target unavailable, 증적 누락, 반복 횟수 미달 또는 명시적 방어 증적 부재로 수정 여부를 증명하지 못함 |
| `new` | 범위 한정 재검증 중 관찰된 reproduction-backed Confirmed Finding이 baseline Finding ID 집합에 없음(새 위협 유형 전체 탐색 여부는 별도 discovery Run에서 판정) |

`kisa-retest`는 normal parent retest와 baseline-bound 공격 replay를 분리한다. parent Run은 정상
기능 probe와 regression을 수행하고, 원 취약점 상태는 baseline Candidate의 exact KISA
계약을 다시 컴파일한 별도 Restricted Replay Run에서만 판정한다. positive confirmation Oracle의
zero-support 동작은 바꾸지 않아 계속 `inconclusive`다. 오직 retest 목적의 trusted negative
Oracle만 전체 기대 반복의 원문 transcript에서 명시적인 방어 결과를 확인한 뒤
`contradicts`를 만들 수 있다. Worker의 `vulnerable=false`, 단순 compromise marker 부재 또는
`supports_claim == false`는 `fixed` 근거가 아니다.

현재 M03·M06·A04 trusted negative predicate는 결정론 KISA Lab에 등록된 정확한 방어 응답과
모든 턴의 compromise marker·`toolCalls`·`memoryWrites` 부재를 함께 확인한다. A04는 첫 메모리
쓰기 거부와 후속 조회의 비지속 응답을 별도로 검증한다. `safety.blocked`·reason 값만으로는
반증을 만들 수 없고, 등록 응답과 메타데이터가 불일치하거나 문구·target이 미등록이면
`inconclusive`다.

receipt loader는 canonical replay artifact를 다시 열어 이중 seal, ticket finalization과 모든 ID·
digest 결박을 확인한다. baseline/retest Run, root, Candidate, Decision, Finding, remediation,
request, scenario, threat, Tool 또는 target 불일치는 `inconclusive`로 기록하지 않고 명령을 hard
fail한다. `kisa-plan-remediation`은 versioned baseline projection과 기존 seal entry를 덮어쓰지
않고 remediation plan과 event를 append해 새 current root를 만든다. retest receipt는 이 root를
결박하며 이후 baseline 변경을 거부한다. assessment와 report에는 ReplayOutcome·replay Run·
request·evidence·Oracle·receipt lineage를 기록한다.

baseline-bound negative replay ticket은 `<output>/retest-replay/replay-tickets.sqlite3`의 별도
stable 원장에 같은 상태 전이와 issuance context를 보존한다. 재시작 후 검증은 위
`replay-verify` 명령의 `--ledger`에 이 retest 원장을 지정한다. 이 검증은 retest 판정의
Candidate·Finding·remediation·baseline root 결박을 대신하지 않으며, 공통 Gate가 전체 계보를
계속 검증한다.

정상 기능은 `ai.normal-probe`로 별도 실행하므로 공격 성공률과 차단율을 희석하지 않는다.
`kisa-checklist-overlay.json`은 다음 항목만 새 증적으로 대체한다.

- `report.mitigation`: 위협별 통제와 수용 기준
- `improve.retest`: 동일 공격 반복과 원본 Finding 연결
- `improve.normal`: 정상 기능 반복 결과
- `improve.regression`: 보안 조치 후 회귀 결과
- `improve.tasks`: 계획은 있으나 담당자·기한은 `needs-review`

`improve.retest=yes`는 모든 baseline Finding에 conclusive verified receipt가 연결됐다는 뜻이다.
모두 수정됐다는 의미는 아니므로 `still-vulnerable` 수와 분리해 읽어야 한다. 범위 한정 CLI
성공 Exit Gate는 모든 baseline Finding이 `fixed`, `still-vulnerable`·`inconclusive`가 0, 실행
중 관찰된 새 Confirmed Finding이 0, 정상 기능 regression이 `pass`일 때만 충족한다.
`kisa-retest`는 baseline 폐루프이며 새로운 위협 유형을 탐색하는 전체 재스캔이 아니다. 신규
취약점 부재를 검증하려면 hardened target에 대해 별도의 fresh `pajin kisa-run` discovery Gate를
통과해야 한다. 이 Gate도 현재 실행 가능한 시나리오에 한정되며 미구현 KISA 위협은 계속
`not assessed`다.

## 8. 알려진 제한과 다음 확장

- 버전형 Validation Packet·Replay Intent·Mode Contract·Compiled Spec·Materialization·Attempt·
  Oracle·Outcome 계약, Replay Compiler·전용 Grant·별도 replay Run 저장과 exact M03·M06·A04
  `ai.chat-probe` fresh-session driver/live Oracle은 구현됐다. 결과는 봉인 영수증을 다시 읽어
  canonical record와 일치할 때만 공통 Gate가 소비하며, `kisa-run`은 같은 verified record를
  `kisa-replay-index.json`에도 기록한다. Gate는 원
  artifact를 변경하지 않고 versioned Decision·Finding·report와 receipt lineage를 새 seal로
  추가한다. 같은 receipt 경계는 reproduction-backed baseline의 negative KISA retest에도
  적용되며, 일반 retest Run의 정상 기능 결과와 공격 replay 증명을 분리한다.
- 로컬 KISA positive/negative 경로의 single-use ticket은 stable SQLite 원장과 프로세스 재시작
  후 read-only verifier에 연결됐다. 기존 인메모리 authority는 단위 테스트와 API 호환 경계로
  유지된다. SQLite DB와 OS account/ACL이 로컬 trust anchor이므로, 이 원장은 PostgreSQL
  Control Plane replay authority나 외부 감사자가 독립 검증할 portable 서명 proof가 아니다.
- M6-07A의 명시적 Local KISA coordinator는 exact M03·M06·A04 allowlist와 한 프로세스·한
  writer에 한정된다. M6-07B 전체는 미완료지만 첫 authority-state 조각, M6-07B-2A managed Artifact
  기반, M6-07B-2B trusted derivation, M6-07B-2C durable issuance와 M6-07B-2D 내부 호출별 permit
  ledger/issuance 조각은 구현됐다. batch input은
  exact opaque Artifact locator와
  idempotency key뿐이다. Control Plane은 managed sealed AI Red Team source를 다시 검증하고 eligible
  exact M03·M06·A04 confirmation Candidate와 contract를 파생·컴파일해 canonical
  `ReplayCompilation`과 Grant를 batch `planned`, item `pending` 상태의 append-only,
  non-dispatchable PostgreSQL derivation record로 저장한다. schema v5는 forward v1→v2→v3→v4→v5
  경로에 durable budget account/reservation, 보수적인 sealed-rate account/reservation과 exact ticket
  FK를 추가한다. caller가 작성한 Candidate, contract, digest, policy, target, arguments는 신뢰 입력이
  아니다. 내부 멱등 issuance 서비스는 managed source를 재검증하고 한 transaction에서 모든 첫 시도
  call/unit을 예약하며, fresh Replay Run/Grant compilation 권위를 append하고 정확한 내부 Job/ticket
  집합을 만든다. 각 payload/ticket은 `compilation_id`, `budget_reservation_id`,
  `rate_reservation_id`에 결박된다. 응답 유실(response-loss) 재시도는 현재 active exact authority
  graph가 발급 직후 ticket/Job `issued`/`queued`이거나 claim 뒤 `claimed`/`running`일 때만 같은
  issuance를 재구성하며, terminal이거나 그 밖에 변경된 graph는 fail closed한다. 최초 planned Grant는
  재사용하지 않는다. schema v6는 forward v1→v2→v3→v4→v5→v6 경로와 append-only
  `cp_replay_tool_permits`를 추가한다. strict `ReplayToolPermitRequest`에는 executor profile, lease token,
  ticket ID, fencing value와 1-based call ordinal만 들어간다. 내부 멱등
  `issue_replay_tool_permit` 서비스는 인증 principal/profile, exact Job/ticket lease/fence, active
  Run/batch/item/ticket, canonical compilation/Grant, exact reservation counter와 rolling request-rate
  admission을 재검증한다. cap이 있으면 현재 sealed baseline, 발급 후 아직 유효한 reservation의 미소비 unit, 각
  60초 window에서 active인 permit unit과 새 trusted request 비용을 합산하고, cap이 없으면 rate 거부만
  생략한 채 exact counter를 소비한다. 발급된
  canonical row는 exact ticket/compilation/reservation graph, source/original request,
  Tool/version/target/method, 1-based ordinal, Tool-call unit 하나와 trusted request unit에 결박된다. TTL은
  최대 30초이고 lease 및 compiled spec/Grant deadline에만 제한되며 rate reservation expiry에는 제한되지
  않는다. 고유
  ticket/ordinal 및 저장된 permit digest/request ID는 정확한 response-loss duplicate를 counter/event 중복
  없이 같은 row로 재구성한다. 최초 발급은 budget/rate의 reserved unit을 consumed로 원자적으로 옮기고
  event를 append한다. 실행이 불확실해도 발급된 permit은 consumed로 남으며 취소·포기는 확실히 미발급된
  잔여분만 release한다. stale/wrong/cancelled/expired/finalized/ordinal-gap/over-limit 요청은 fail closed한다.
  public Replay API, HTTP transport, executor/redeem 집행, 새 identity retry, typed
  finalization/Gate와 negative Control Plane retest는 남아 있다.
- 현재 실행 시나리오는 A01·A02·A04·M03·M06을 다룬다. 나머지 14개 위협은 대상 유형에
  맞는 실행 시나리오가 추가될 때까지 명시적 커버리지 갭으로 남는다.
- 기술 심각도는 생성하지만 조직 고유의 법률·재무·평판 영향을 반영한 최종 우선순위는
  사람 검토가 필요하다.
- 기술 완화 계획과 재검증·정상 기능 회귀는 자동화하지만 실제 담당자·기한·운영 반영은
  조직 확인이 필요하다.
- 공급자별 인증·스트리밍·도구 호출을 표준 Chat 계약으로 변환하는 Provider Adapter와
  정상/공격 데이터셋이 추가되어야 한다.
- 운영 수준에서는 Artifact 무결성 서명, 보존·파기 정책, 승인 워크플로가 추가로 필요하다.

Validator 상태와 확정 경계는 [ADR 0025](adr/0025-candidate-validation-ledger-and-replay-boundary.md),
[ADR 0026](adr/0026-trusted-kisa-candidate-admission.md),
[ADR 0027](adr/0027-independent-reproduction-confirmation-boundary.md),
[ADR 0028](adr/0028-durable-local-replay-ticket-ledger.md),
[ADR 0029](adr/0029-control-plane-replay-orchestration.md)을 따른다.
