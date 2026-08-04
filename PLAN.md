# PAJIN 구현 계획

- 상태 권위: 이 파일
- 기존 Notion 로드맵 최종 대조: 2026-08-01, `main@a94df30`
- 현재 단계: Phase 5 — 구조화된 협업과 Handoff
- 현재 우선순위: Phase 5 adversarial collaboration regression

## 제품 목표

PAJIN은 자신의 권한을 확대하지 않으면서 공격표면을 발견하고 연결하며, 자신이 발견한
취약점을 증거에 결박된 독립 Replay 없이 확정할 수 없는 정책 통제형 공격 발견·독립 검증
시스템을 지향한다.

첫 번째 end-to-end Hybrid Chain은 다음과 같다.

```text
File Upload
-> RAG Indirect Prompt Injection
-> MCP Tool Authorization Failure
-> Internal Data Access
```

## 현재 마일스톤: Phase 4

- [x] `WALK-001` 정확한 File Upload Surface 발견
- [x] `WALK-002` Snapshot-bound RAG Injection Hypothesis 생성
- [x] `WALK-003` 실행을 활성화하지 않고 H-17 의존성을 정확한 등록 MCP Tool Authorization
  Hypothesis에 결박
- [x] `WALK-004` Observation을 Graph에 Admission하고 bounded replan 생성
- [x] `WALK-005` Candidate·Atomic Validation·Replay·Report·Retest 폐루프 완성
  - [x] `WALK-005A` 승인·Permit·봉인 Gateway 실행 기반 Candidate·Atomic Claim Admission
  - [x] `WALK-005B` MCP Claim-bound Restricted Replay·검증 projection
    - [x] `WALK-005B1` validity Claim-bound 비실행 Replay Plan authority
    - [x] `WALK-005B2` Plan-bound fresh 실행·Claim 검증 projection
  - [x] `WALK-005C` Report·Remediation Retest 폐루프
    - [x] `WALK-005C1` MCP 확인 정책·Report·비실행 Remediation baseline
    - [x] `WALK-005C2` baseline-bound fresh Retest·보수적 lifecycle 판정
- [x] `WALK-006` Shadow Supervisor가 선택했을 Task와 Stop Decision 기록

Phase 4 Exit Gate: 하나의 Cross-surface Chain이 Recon부터 Retest까지 닫히고, 동일
Benchmark에서 결정론적 Baseline과 Shadow Decision을 비교할 수 있어야 한다.

### WALK-004 완료 결과

- [x] `pajin.dev/walking-observation-replan/v1alpha1` content-addressed authority를 추가했다.
- [x] 봉인된 WALK-003 `registered-not-authorized` 상태만 Observation으로 Admission한다.
- [x] admitted Observation이 baseline과 다른 `request-independent-approval` Plan을 선택한다.
- [x] Graph에 `supports`, `enables`, `depends-on` 관계를 기록하고 `contradicts` 어휘를
  예약했다. 불일치 증거는 Graph 생성 전에 거부한다.
- [x] forged evidence, Run·Hypothesis 치환, stale·repeated·cyclic state 및
  Scope·Snapshot·Capability 확대를 fail closed한다.
- [x] 봉인된 artifact와 exact audit event에서 전체 권위를 재구성하는 reader를 제공한다.
- [x] 실행 상태는 `proposed-not-authorized`이며 Grant, Permit, ToolRequest, MCP argument,
  Worker dispatch를 생성하지 않는다.
- [x] 기존 A4/A5, ORCH-001/002, WALK-001/002/003 wire shape과 reader를 변경하지 않았다.

### WALK-005 목표

WALK-004의 비실행 승인 요청 Plan 뒤에 별도로 승인되고 허가된 실행 결과만 Candidate로
Admission하며, 기존 Atomic Validation·Restricted Replay·Report·Retest 권위를 재사용해 첫
Hybrid Chain의 검증 폐루프를 닫는다.

먼저 기존 Candidate, Claim, Replay, Report, Retest 계약과 WALK-004 사이에서 이미 충족된
부분과 실제 누락된 연결을 조사한다. 승인 receipt, CapabilityGrant, ActionPermit, Gateway,
Budget, Policy 경계를 새 Plan이 우회하거나 암묵적으로 생성하지 않도록 최소 additive
bridge를 설계한다.

`WALK-005A`는 완료됐다. WALK-004 authority와 별도 실행 Run을 다시 열고, 정확한 승인
receipt가 canonical CapabilityGrant digest에 결박된 채 consumed ActionPermit dispatch보다 먼저
봉인됐으며 claimed·terminal event가 같은 Grant와 기존 reconciliation의 성공한 Gateway
lifecycle을 증명할 때만 미확정 A02 Candidate와 validity·impact·severity Atomic Claim을 생성한다.
의심 입력만으로 승인 실패나 내부 데이터 접근을 합성하지 않으며, 기본 demo MCP
inspector는 해당 대상 관찰값을 내지 않으므로 이 Candidate를 만들 수 없다.

`WALK-005B1`은 기존 KISA M03/M06/A04 Replay를 이름만 바꾸지 않고, WALK-005A의 exact
validity Claim과 원 실행·요청·Tool·target·parameter digest를 content-addressed 비실행 Plan에
결박한다. replay Run·request·approval·Grant·Permit·dispatch·Worker identity는 모두 fresh해야
한다. 다음 `WALK-005B2`가 이 Plan digest를 dispatch 전에 봉인하고 별도 Gateway 실행과 Claim
검증 projection을 만들기 전까지 Candidate는 `candidate-admitted-not-confirmed`를 벗어나지 않는다.

`WALK-005B2`는 B1 Plan/Claim digest와 exact approval·request·Grant를 replay receipt에 결박해
Permit claim 전에 봉인하고, 기존 WALK-005A verifier로 별도 Gateway 실행을 재검증한다. 원 실행
대비 Run·request·approval·Grant·Permit·dispatch·Worker ID가 모두 fresh하고 요청 의미와 새 validity
Claim statement가 exact equality일 때만 `reproduced / confirmationEligible=false` projection을
봉인한다. 다음 `WALK-005C`에서 확인 정책, 보고서, remediation Retest 폐루프를 연결한다.

`WALK-005C1`은 B2 authority를 다시 열어 Plan-bound fresh validity replay만 MCP 전용 제품 확인
근거로 채택한다. impact·severity는 replay됐다고 확장하지 않고 `source-bound-information-only`로
고정한다. validated Finding, typed Report와 exact Markdown, `planned-not-applied` Remediation
Plan을 하나의 content-addressed authority와 봉인 Run으로 묶는다. 다음 `WALK-005C2`는 이
baseline과 별도의 fresh B2 실행을 결박해 양성 재현을 `still-vulnerable`로 판정한다. 음성·실패
실행은 성공한 lifecycle 결과로 바꾸지 않고 fail closed하며, 독립적인 수정 증명 없이는 `fixed`를
금지한다.

`WALK-005C2`는 C1 confirmation publication 뒤에 승인·실행된 별도 B2 authority만 Retest로
받아들인다. B1 Plan·Candidate·Finding·validity Claim은 exact equality여야 하고, baseline
replay와 Run·request·approval·Grant·Permit·dispatch·Worker ID가 모두 달라야 한다. B2가 양성
재현만 나타내므로 현재 lifecycle 결과는 `still-vulnerable`로 제한한다. `fixedEligible=false`,
`remediationAppliedAttested=false`, regression `not-measured`를 고정하고, 음성·실패·불완전
실행을 `fixed`로 해석하지 않는다. 이로써 첫 Walking chain은 Retest까지 닫혔으며 다음 구현은
`WALK-006` Shadow Supervisor Decision 기록이다.

`WALK-006`은 봉인된 C2 `still-vulnerable` lifecycle만 snapshot-only 입력으로 받아 code-registered
Shadow policy가 선택했을 human remediation-review Task와 자율 실행 Stop·escalation Decision을
content-addressed authority로 기록한다. Task는 Capability가 없고 `proposed-not-authorized`, Stop은
`executionAllowed=false`, 전체 결과는 `recorded-not-applied`다. 기존 TaskGraph·Campaign·source
Run을 변경하거나 모델·Tool을 호출하지 않는다. 다음 `BENCH-003`은 동일 benchmark 좌표에서
이 Shadow record와 deterministic baseline을 실제 비교하는 측정 경계를 구현한다.

`BENCH-003A`는 baseline-only BENCH-001 Manifest와 WALK-006 sealed authority를 결박해
deterministic terminal Decision과 Shadow Task·Stop Decision의 구조 차이만 기록한다. 12개 필수
metric 이름은 보존하지만 값과 delta는 비워 두고, `not-measured-no-benchmark-results`,
`benchmarkComparisonEligible=false`, `supervisorActivationEligible=false`로 고정한다. 다음
`BENCH-003B`는 동일 seed·repetition·reset·isolation·cleanup 좌표의 실제 baseline/candidate
`BenchmarkResult`를 생성한 뒤에만 기존 numeric `BenchmarkComparison`을 허용한다.

`BENCH-003B1`은 동일 measurement authority가 봉인한 두 arm의 전체 좌표별 raw count·시간·비용·
Replay·정책·human·cleanup 관찰만 Admission하고, 12개 metric을 코드로 집계해 두 completed Result와
canonical Comparison을 함께 봉인한다. 외부 측정 authority의 의미적 진실성은 별도 trust root이며
Supervisor activation은 false다. 다음 `BENCH-003B2`는 candidate implementation/version/configuration을
exact WALK-006 Shadow policy와 sealed BENCH-003A source publication에 결박한다.

`BENCH-003B2`는 B1 numeric output을 다시 계산하지 않고 sealed A/B1 source를 함께 연다.
measured Manifest의 전체 envelope와 baseline arm은 A와 exact equality이고, candidate
implementation ID/version/configuration digest는 WALK-006 code-owned policy와 같아야 한다. 양쪽
source Run/root/artifact SHA를 content-addressed authority에 결박하며 activation eligibility는 false다.
BENCH-003 Harness는 닫혔지만 fixture가 운영 증거라는 뜻은 아니다. 다음 `P0-C`는 실제 Target
Factory reset·isolation·execution·observation·cleanup과 measurement authority attestation을 구현한다.

`P0-C1`은 provider-neutral async adapter와 좌표별 reset→isolation→execution→cleanup receipt를
정의한다. 다음 provider 호출 전에 각 authority를 검증하고, 유효한 isolation 이후 execution이
실패하거나 foreign raw Observation을 반환해도 cleanup을 먼저 시도한다. 네 receipt와 final B1
Observation은 외부 Ed25519 measurement key로 서명되며 public Trust Anchor로 검증된 뒤 같은 Run에
봉인된다. deterministic 테스트 adapter는 계약만 증명하며 실제 provider가 아니다. 다음 `P0-C2`는
real Docker/external provider implementation, evidence retrieval, network policy, key registry/rotation,
cleanup recovery를 연결한다.

`P0-C2A`는 P0-C1 앞에 recoverable provider 계층을 추가했다. 각 호출의 idempotency operation
ID와 단조 fence를 provider 계약에 전달하고 intent-before-call·validated-result journal을 SQLite
트랜잭션으로 남긴다. 새 실행 전 open attempt를 더 높은 fence로 회수하고 cleanup을 bounded retry한
뒤, 성공 여부를 `measurementAdmissionEligible=false`인 별도 sealed Recovery Authority로 기록한다.
실제 spawn process가 execution intent 직후 `os._exit(23)`으로 종료되는 회귀에서도 다음 시작이
cleanup을 복구하기 전 새 reset을 실행하지 않는다. measurement key registry/rotation과 signed
activation은 후속 로컬 슬라이스에서 구현됐고, 실제 Docker/provider evidence·network policy는
daemon 가용성을 전제로 하는 `P0-C2B2B`로 남긴다.

`P0-C2B1`은 P0-C1 Trust Anchor를 보존한 별도 measurement key registry와
active·retired·revoked lifecycle을 추가했다. 새 측정은 provider reset 전에 active key를 exact
adapter definition과 대조하고, retired key는 bounded historical verification만 허용하며 revoked key는
과거 증거도 거부한다. revision 2부터 exact predecessor registry를 sealed Admission Authority에
포함해 rollback·gap·key substitution·resurrection을 차단한다. P0-C1/P0-C2A가 공통 runner Protocol을
노출하므로 lifecycle을 중복 구현하지 않는다. registry distribution signature·durable latest revision은
P0-C2B2A1, BENCH-003B mandatory admission은 P0-C2B2A2에서 구현됐고 실제 provider
evidence·network policy는 `P0-C2B2B`로 남긴다.

`P0-C2B2A1`은 measurement registry를 별도 Ed25519 distribution key로 서명하고, 7일 이하의
bounded bundle에 현재·직전 registry와 이전 bundle digest를 함께 결박한다. host-local SQLite
activation store는 revision 1만 bootstrap하고 이후 contiguous revision만 append-only로 수용해
restart 뒤 rollback·gap·equivocation·predecessor substitution을 차단한다. verified activation의
mandatory sealed Harness 결박은 P0-C2B2A2에서 구현됐고, 실제 Docker/provider evidence와 network
policy는 `P0-C2B2B`로 남긴다.

`P0-C2B2A2`는 signed activation을 provider reset 전에 필수화하고, 실행 뒤 exact Target Run,
P0-C2B1 Admission Run, durable activation을 하나의 sealed Harness Authority로 결박한다. 전용
reader는 세 Run과 exact accepted revision, 현재 out-of-band distribution Trust Anchor를 모두
재검증한 뒤에만 registry-governed Observation을 반환한다. 실행 중 rotation은 publication을
차단하고, 정상 완료 뒤 measurement registry rotation은 historical exact revision으로 보존하며,
distribution signing-key revocation은 과거 결과에도 적용한다. 실제 provider 경계는 `P0-C2B2B`다.

`P0-C2B2B`는 고정 synthetic Boolean-SQLi lab의 실제 local Docker provider를 구현했다. exact
Target·Worker image ID, provider-owned durable fence·stage order·idempotency 결과, 별도 SQLite
operation lock, `--internal` network, 무포트·non-root·read-only container policy, real Worker probe,
receipt-bound provider evidence, higher-fence cleanup을 하나의 recoverable adapter로 결박한다. fake
Docker 음성 경계와 Docker Desktop 4.78.0 / Engine 29.5.3 live conformance가 통과했다. 이 경계는
host-local 단일 profile이며 cross-host·일반 Target catalog를 주장하지 않는다. 다음 `P0-D1`은 이
구체 구현을 임의 image 실행기로 넓히지 않고 Traditional Web/API Target catalog와 ground-truth
profile 계약부터 분리한다.

`P0-D1`은 첫 Traditional Web/API profile을 public catalog와 private Ground Truth binding으로
분리했다. public registration은 exact Docker profile·Target Factory·빈 mutation allowlist·internal
network policy·Ground Truth digest만 결박하고 case와 matcher 원문은 노출하지 않는다. additive
wrapper는 provider 호출 전에 Manifest·adapter·profile·catalog·private binding을 exact equality로
검증하고, 실행 뒤 receipt-bound Docker evidence와 등록된 Surface·Finding·chain count가 일치할
때만 Observation을 반환한다. selection 자체는 `providerExecutionAuthorized=false`이며 기존
measurement registry와 sealed Harness 권위를 대체하지 않는다. 다음 `P0-D2`는 기존 WALK-002/003
RAG·MCP chain과 실제 실행 provider의 현재 범위를 먼저 대조해, 실행할 수 없는 기능을 catalog가
허가하는 허상을 만들지 않는 AI/RAG/MCP profile 최소 슬라이스를 정의한다.

`P0-D2`는 기존 WALK-002~WALK-005C1 chain을 두 번째 `ai-rag-mcp` catalog와 private seeded
Ground Truth profile로 등록했다. 실제 P0-C Target lifecycle이 없고 WALK 실행 증거의
`networkLogTrusted=false`이므로 profile은 `fixture-contract-only`, selection은
`registered-fixture-not-runnable`, `providerExecutionAuthorized=false`,
`measurementAdmissionEligible=false`로 고정한다. selection에는 adapter digest가 없으며 Benchmark
runner나 governed Harness 입력이 될 수 없다. shared catalog는 기존 P0-D1 wire 값을 바꾸지 않고
두 code-owned catalog ID와 family의 exact 대응만 허용한다. 다음 `P0-D2B`는 reset·seed·isolation·
execution·receipt-bound evidence·cleanup을 실제로 수행하는 local AI/RAG/MCP provider를 구현한 뒤에만
catalog를 runnable 상태로 승격하는 별도 수직 슬라이스다.

`P0-D2B`는 contract-only fixture를 변경하지 않고 별도 Docker profile·Factory·adapter·catalog로
실행 경계를 추가했다. 고정 Worker가 내부 전용 bridge에서 document upload -> deterministic RAG query
-> Target 내부 MCP HTTP endpoint -> synthetic internal marker chain을 실제 수행한다. 공통 Docker
lifecycle은 기존 durable fence·hardening·receipt evidence·cleanup을 재사용하고, AI 전용 parser는
성공 flag뿐 아니라 bounded Base64 body, SHA-256, decoded response 전체를 exact 검증한다. Walking
fixture의 `networkLogTrusted=false` matcher를 재사용하지 않고 Docker profile/evidence와 실제 응답을
묶는 별도 matcher digest를 사용한다. model call과 외부 서비스는 없고 MCP endpoint도 별도
deployment가 아니라 Target container 내부 protocol boundary다. 다음 `P0-D3`는 P0-D1과 P0-D2B의
서로 다른 Factory authority를 하나의 Hybrid Target/chain으로 결합할 때 필요한 composition identity,
lifecycle 순서, Ground Truth 및 음성 경계를 먼저 정의한다.

`P0-D3`는 두 runnable component를 실행 결과로 합치지 않고 exact selection·순서·private Ground
Truth와 `declared-not-executed` bridge를 별도 content-addressed authority로 묶는다. 기존
`BenchmarkManifest`가 Factory 하나만 표현하므로 Hybrid Factory·Manifest·receipt·Observation·metric은
만들지 않으며 execution·measurement·Manifest eligibility를 모두 false로 고정한다. component
reversal·repetition·누락, catalog/profile/factory/provider policy 변경, private registration·Surface
치환과 cross-composition replay가 fail closed한다. 다음 `P0-D3B`는 하나의 Hybrid Factory/Manifest
identity 아래 coordinated isolation, cross-provider fence·cleanup order, exact transfer artifact와 bridge
receipt를 구현하고 partial lifecycle 음성 경계를 통과한 뒤에만 runnable 상태를 허용한다.

`P0-D3B1`은 runnable 구현 전에 기존 component 사이의 실제 데이터 불연속과 single-target lifecycle
가정을 명시적으로 고정한다. 새 Hybrid Factory·adapter identity, 두 Target·한 Worker의 shared internal
network, 단일 coordinate·fence, startup·bridge·reverse-cleanup order와 canonical transfer artifact schema를
P0-D3 selection에 결박한다. 현재 SQLi 응답에는 필요한 `documentContent`가 없으므로 image binding,
adapter registration, Manifest·execution·measurement eligibility와 bridge observation은 모두 false다.
다음 `P0-D3B2`가 Hybrid 전용 seeded source와 AI ingestion, 실제 multi-container adapter·receipt를
구현하고 partial failure와 higher-fence recovery를 증명해야 한다.

`P0-D3B2`는 새 Hybrid Factory·catalog·Ground Truth matcher와 세 Docker image를 구현했다. 하나의
coordinate·fence·internal network에서 SQLi expanded response의 `documentContent`를 canonical transfer
artifact로 seal하고, exact upload·RAG·MCP 결과와 ordered bridge receipt를 evidence에 결박한다. 성공
flag만 맞춘 body 치환, image·catalog·matcher 치환, partial start, stale fence와 cleanup 순서 변경은 fail
closed한다. fake provider와 real Docker에서 causal bridge와 reverse cleanup을 검증했다.

`P0-D4`는 기존 Traditional Web/API active selection을 다시 검증한 뒤 별도 Holdout Factory identity,
private suite·binding, public commitment registration과 non-runnable selection을 결박한다. 공개 artifact에는
case·Finding·matcher·evaluation seed가 없으며 seeded/holdout replay, seed 재사용, active catalog 확대,
cross-profile·private binding 치환을 fail closed한다. 실제 Holdout provider와 measurement admission은 계속
false다. 다음 `P0-D5`는 기존 빈 mutation allowlist를 임의 입력으로 넓히지 않고, code-registered Mutation
profile·base Target binding·reset provenance·비실행 selection authority부터 정의한다.

`P0-D5`는 기존 P0-D1 catalog와 빈 mutation allowlist를 그대로 보존하면서 별도 Mutation profile,
registration, derived Manifest, reset plan과 non-runnable selection을 추가했다. base selector를 다시 실행하고
derived Manifest는 `mutationProfileId` 하나만 달라야 한다. mutation seed·base/expected state·세 operation의
순서와 state chain, benchmark seed와 reset provenance를 content-addressed authority로 결박한다. reset receipt,
materialization, execution, measurement admission은 모두 false다. 이로써 P0-D contract-first Target family 축을
완료하고, 다음 `P0-E1`에서 기존 registry-governed Harness와 runnable deterministic Target을 실제 baseline
measurement authority로 연결한다.

`P0-E1`은 P0-D1 runnable catalog와 P0-C2B2A2 registry-governed Harness를 실제 측정 경계에서
결합한다. 각 Harness·Target Run을 다시 열고 execution receipt로 provider evidence를 재조회한 뒤 private
Ground Truth matcher를 다시 실행한다. Manifest의 baseline seed/repetition 전체 좌표가 한 번씩 존재할 때만
sealed raw Observation에서 12개 BENCH-001 metric을 재계산하고 Result와 source binding을 별도 authority로
봉인한다. candidate comparison과 Supervisor activation은 false다. 다음 `P0-E2`는 이 PAJIN 전용 실행
경계를 일반 Scanner baseline에 그대로 오인 적용하지 않고, scanner identity·invocation·output evidence와
동일 Target 좌표를 결박하는 별도 최소 authority를 설계한다.

저장소에는 Scanner runtime·parser·binary/image identity가 없었으므로 `P0-E2A`는 특정 제품이나 synthetic
output을 실측으로 가장하지 않는다. code-owned generic Scanner contract가 scanner ID/version, executable
SHA-256, configuration digest와 SARIF 2.1.0 parser contract를 요구하고, exact P0-D1 selection과 전체
seed/repetition 좌표를 비실행 measurement plan에 결박한다. identity·invocation receipt·raw output·Result·
comparison·Supervisor activation은 모두 false다. `P0-E2B`는 구체 Scanner artifact와 provider 경계를
명시적으로 선택한 뒤 fresh Target isolation·recovery·cleanup·registry admission을 실제로 증명해야 한다.

`P0-E2B`는 OWASP ZAP 2.17.0의 exact image ID와 code-owned Automation Framework plan을 별도
registration에 결박한다. 기존 fenced P0-D1 lifecycle 안에서 hardened Scanner container를 실행하고 raw
SARIF bytes와 strict normalization을 receipt-bound provider evidence로 보존한다. registry-governed Harness·
Target Run·catalog selection을 다시 연 뒤 전체 좌표의 completed Result를 봉인하되, 실제 분모가 없는
metric만 명시적 `not-applicable`로 기록한다. comparison과 Supervisor activation은 false다. 다음 `P0-E3`는
이 Scanner authority를 이름만 바꾸지 않고, code/model/tool identity와 bounded single-agent execution을
별도 plan·provider·raw trace·measurement authority로 결박해야 한다.

기존 ProviderAgentRuntime은 안전한 multi-role 경계이고 PydanticAI TestModel과 test Provider worker는 실제
single-agent provider가 아니다. `P0-E3A`는 허상 실측을 차단하기 위해 agent implementation, Provider
registration, exact model revision, prompt bundle, tool catalog, runtime configuration과 secret-free raw
model/tool trace를 요구하는 generic contract를 추가했다. P0-D1 selection과 전체 좌표를 non-runnable plan에
결박하고 no-fallback·Gateway-only access를 고정하며 identity·execution·Result·comparison·activation은 모두
false다. 다음 `P0-E3B`가 구체 Provider/model, trusted pricing, prompts/tools/runtime과 fresh Target 실행·raw
trace·usage·cleanup·registry admission을 실제로 증명해야 한다.

`P0-E3B1`은 local llama.cpp CUDA server와 exact Qwen3-4B-Instruct-2507 Q8_0 GGUF를 선택하고,
OCI image ID·GGUF SHA-256·Provider registration·prompt·Tool catalog·sampling·no-fallback policy를 하나의
registration에 결박했다. 기존 Policy Tool Loop는 opt-in으로 secret-free canonical model/tool JSONL trace를
봉인하며, strict reader는 두 model call·정확히 한 번의 고정 SQLi Tool 실행·trusted receipt·usage·cleanup을
모두 재구성한다. `P0-E3B2`는 동일 registration과 coordinate seed를 registry-governed fresh P0-D1
Target lifecycle 안에서 실행하고, action별 Docker network route를 Worker execution context에 결박했다.
Provider evidence는 Target operation, Tool Loop Run/root, raw trace와 exact Worker/proxy image ID를
결박하고, measurement authority는 completed Target lifecycle과 cleanup을 전체 좌표의 Observation·
`BenchmarkResult`에 결박한다. 실제 Docker·GPU 적합성은 이 전체 B2 경계를 통과했다.

`ENG-001`은 이미 존재하는 `MultiAgentCampaignRunner`를 중복 구현하지 않고, 세 legacy Mode가
공유하는 Campaign snapshot·budget/rate-limit·Capability/Policy·Worker·validation·sealed audit
경계를 code-owned contract로 고정했다. 각 legacy Campaign은 exact Mode·canonical Campaign
digest·registered contract에 결박된 비실행 Plan으로만 투영된다. Profile compilation,
MissionEnvelope, parity evidence, Common Engine execution은 모두 false이며 기존 실행 경로가
계속 기본값이다. `PROF-001`은 이 계약을 권한 루트로 오인하지 않고 Mode 중립 Profile
authority를 별도로 정의한다.

`PROF-001`은 `pentest`, `bug-hunt`, `ctf`, `ai-assessment` 네 Profile의 exact
ID/version/digest와 reporting·benchmark expectation·restrictive operating control을 code-owned
catalog에 등록했다. 모든 Profile은 ENG-001 contract에 결박되고
`roeDefaultsPolicy=campaign-authority-only`이며 adapter·MissionEnvelope·measurement·submission·
execution 권한은 false다. exact resolver는 Profile을 Campaign에 선택하지 않는다. 다음
`PROF-002`가 legacy Mode, compiler identity, input/output digest를 exact Profile에 결박한다.

`PROF-002`는 current `pajin.dev/v1alpha1` Campaign의 `ai-redteam`, `bug-bounty`, `ctf`를 각각
PROF-001 `ai-assessment`, `bug-hunt`, `ctf` Profile에 mapping하는 code-owned compiler를 추가했다.
complete Campaign input digest, compiler·catalog·Profile identity와 semantic projection output
digest가 하나의 비실행 compilation authority에 결박된다. Campaign mutation, ROE 적용, pentest
자동 선택, MissionEnvelope와 Common Engine 실행은 false다.

`ENG-002A`는 이 compilation authority를 기존 Mode별 Planner·Validator와 공통 runner·scheduler·
projector의 exact module-qualified class identity에 결박하는 code-owned adapter catalog를 추가했다.
Scope·Capability·ToolRequest·Outcome 네 parity dimension은 모두 존재하지만 현재 evidence는 structural
identity뿐이며 `fixtureMeasured=false`, `parityProven=false`다. runtime construction, Tool Registry,
Policy, Worker, output path, MissionEnvelope와 Common execution은 계속 false다. 다음 `ENG-002B`는
동일 fixture의 legacy direct path와 별도 opt-in adapter path를 실제로 실행해 constructor input,
ToolRequest, receipt, Outcome과 Mode별 후처리를 비교한 뒤에만 behavioral parity를 증명한다.

`ENG-002B1`은 세 Mode의 legacy-direct Planner와 ENG-002A-selected Planner를 같은 complete
Campaign과 typed constructor input으로 각각 호출했다. 매 호출마다 fresh해야 하는 step/request ID만
ordered fixture ordinal로 정규화하고 나머지 complete `AgentPlan`을 exact 비교한다. Scope와
ToolRequest Planner behavior는 측정·증명됐지만 Capability와 Outcome은 미측정이며 Worker,
MissionEnvelope, Common runtime·execution은 false다.

`ENG-002B2A`는 B1 authority를 입력으로 exact ToolSpec·Tool 구현 context, Policy, Worker,
Validator, AI delegate·candidate producer, runner와 semantic output role을 하나의 runtime fixture
coordinate에 결박했다. legacy-direct와 Profile-adapter arm을 서로 다른 output root에서 실행하고,
completed sealed Run·B1과 같은 runtime Plan·fresh Run/request/evidence identity를 검증한 dual-runtime
source authority를 만든다. 아직 Capability·receipt·Outcome·Mode 후처리를 비교하지 않으며 fixture
parity, MissionEnvelope와 Common execution은 false다. 다음 `ENG-002B2B`가 두 sealed source를 다시
검증하고 명시적으로 허용된 fresh identity·timestamp만 정규화해 전체 behavioral parity admission을
판정한다.

`ENG-002B2B`는 두 B2A source root를 다시 검증한 뒤 기존 AI·Bug Hunt·CTF Mode processor로 각각
Run을 확장한다. Plan ordinal과 typed lineage로 확인된 fresh identity, 실행 timestamp, 스키마상
set만 정규화하고 Scope, Capability attenuation, ToolRequest, Policy·Worker receipt, complete Outcome와
Mode artifact를 exact 비교한다. incomplete·different·cross-Mode evidence는 parity authority를 만들지
못한다. 세 legacy Mode의 Profile-adapter behavioral parity는 exact fixture에서 증명됐지만
MissionEnvelope와 Common execution은 계속 false다. 다음 `ENG-002C1`은 PROF-002 compilation과 이
complete parity authority의 교집합에서만 기존 MissionEnvelope를 비확장으로 컴파일하는 비실행
bridge를 만든다.

`ENG-002C1`은 B2B에 내장된 exact PROF-002 compilation, 성공하고 network-trusted인 측정 receipt,
검증된 CAP-005 activation과 source Campaign 권한의 교집합만 기존 GRAPH-006 MissionEnvelope로
컴파일한다. 측정 Plan의 각 요청은 정확히 하나의 signed Capability release에 materialize돼야 하며,
Capability·target 집합과 call·request-unit·rate·risk·time 상한은 측정값과 Campaign 상한보다 넓어질
수 없다. MissionEnvelope가 표현할 수 없는 제한·혼합 weekly testing window는 거부한다. 결과는
content-addressed audit authority이지만 ActionPermit 발급, Common runtime dispatch, 실행 권한은 모두
false다. 다음 `ENG-002C2`는 이 authority만으로 실행을 허용하지 않고 current activation, exact planned
request·parameter, Graph Snapshot·Decision과 기존 GRAPH-006 single-use Permit 대수를 다시 교차 검증하는
명시적 opt-in gate를 구현한다.

`ENG-002C2`는 C1 compiler의 Permit·dispatch 권한 false를 바꾸지 않고 별도 code-owned execution-gate
compiler와 authority를 추가한다. 새 MissionEnvelope는 compiler identity 외의 Campaign·Run·Profile·
Capability·target·risk·budget·rate·autonomy·time 필드가 C1과 정확히 같다. C1 Run과 binding digest로
fresh execution request ID를 파생하고 나머지 measured request semantics를 보존한 intent를 latest
GraphDecision에 결박한다. current signed activation과 Capability Grant를 다시 검증한 뒤 기존 GRAPH-006
원자 Permit과 CAP-005 Gateway dispatcher를 재사용하며 exact retry는 Worker를 다시 호출하지 않는다.
legacy default path는 바뀌지 않는다. 이로써 Phase 1 ENG-002를 닫고 다음 구현은 `MEM-001` CampaignFact
Proposal·Record다.

## 이전 기반 작업

Phase 2 Capability Authoring(`CAP-001`~`CAP-006`)과 구조적 Phase 3 Graph, Discovery,
Deterministic Multi-wave(`GRAPH-001`~`GRAPH-006`, `DISC-001`~`DISC-003D`, `ORCH-001/002`)는
구현됐다. 실제 provider-backed immutable retention, 독립 anchor/KMS, 다른 host restore drill,
organization-issued release 및 실제 isolated Web + AI Campaign은 운영 공백으로 남아 있다.

기존 로드맵에서는 Phase 0 Benchmark/Target Factory와 Phase 1 Common Engine/Profile
Compatibility 항목이 완료 표시되지 않았다. 이 작업을 선택하기 전에 실제 코드와 다시
대조하며, 과거 체크리스트만 보고 완료를 추정하거나 작업을 재시작하지 않는다.

대조가 필요한 Phase 0/1 항목:

- `ARCH-001` Architecture v2 RFC와 기존 ADR-0046/0047/0048 결정 정합성
- 기존 Mode, API, Artifact 호환·Deprecation 정책
- `BENCH-001` Metric·Ground Truth·Run Protocol
- `BENCH-002` Result Schema·Artifact Format
- [x] `BENCH-003` Deterministic Baseline·Adaptive Candidate 비교
  - [x] `BENCH-003A` Walking Baseline·Shadow Decision structural-only comparison
  - [x] `BENCH-003B` 동일 좌표 sealed Result Harness·numeric comparison
    - [x] `BENCH-003B1` sealed raw Observation admission·두 Result·numeric comparison
    - [x] `BENCH-003B2` exact WALK-006 policy/configuration·source publication binding
- [x] `P0-C` reset, seed, isolation, cleanup, measurement, adjudication, sealed Benchmark Harness
  - [x] `P0-C1` provider-neutral lifecycle·sealed Observation·external measurement signature
  - [x] `P0-C2A` durable operation journal·idempotency/fencing·startup cleanup recovery
  - [x] `P0-C2B1` measurement Trust Registry·rotation·retirement·revocation admission
  - [x] `P0-C2B2A1` signed registry distribution·durable anti-rollback activation
  - [x] `P0-C2B2A2` mandatory sealed registry-governed Harness admission
  - [x] `P0-C2B2B` real Docker/provider adapter·evidence·network policy
- [x] `P0-D` Traditional Web/API, AI/RAG/MCP, Hybrid, Holdout, Mutation Target Factory
  - [x] `P0-D1` Traditional Web/API Target Factory catalog·ground-truth profile
  - [x] `P0-D2` AI/RAG/MCP non-runnable fixture catalog·ground-truth profile
  - [x] `P0-D2B` local AI/RAG/MCP provider·별도 runnable catalog
  - [x] `P0-D3` Traditional Web/API + AI/RAG/MCP non-runnable composition authority
  - [x] `P0-D3B` runnable Hybrid multi-provider lifecycle·bridge evidence
    - [x] `P0-D3B1` Hybrid provider topology·transfer artifact schema authority
    - [x] `P0-D3B2` runnable multi-container adapter·bridge receipt·recovery evidence
  - [x] `P0-D4` Holdout Target Factory authority
  - [x] `P0-D5` Mutation Target Factory authority
- [x] Baseline 측정
  - [x] `P0-E1` Deterministic PAJIN baseline measurement authority
  - [x] `P0-E2` 일반 Scanner baseline measurement authority
    - [x] `P0-E2A` Scanner identity·parser·좌표 결박 비실행 measurement plan
    - [x] `P0-E2B` 실제 Scanner provider·raw output·measurement authority
  - [x] `P0-E3` Single-agent baseline measurement authority
    - [x] `P0-E3A` agent·Provider·model·prompt·tool·trace 결박 비실행 measurement plan
    - [x] `P0-E3B1` local llama.cpp·Qwen registration·secret-free raw trace·live conformance
    - [x] `P0-E3B2` fresh P0-D1 lifecycle·invocation receipt·completed Result
- [x] `ENG-001` 공통 Campaign Execution Engine 계약
- [x] `PROF-001` Pentest, Bug Hunt, CTF, AI Assessment Profile
- [x] `PROF-002` 기존 CampaignMode Compatibility Adapter
- [x] `ENG-002` 현재 Planner, Scheduler, Validation 경로 Adapter
  - [x] `ENG-002A` exact implementation adapter·structural-only parity authority
  - [x] `ENG-002B` 동일 fixture behavioral parity authority
    - [x] `ENG-002B1` 동일 constructor Planner·ToolRequest parity
    - [x] `ENG-002B2` Capability·receipt·Outcome·Mode 후처리 parity
      - [x] `ENG-002B2A` exact runtime coordinate·독립 completed sealed dual-run source authority
      - [x] `ENG-002B2B` Capability·receipt·Outcome·Mode 후처리 normalized parity admission
  - [x] `ENG-002C` parity-bound MissionEnvelope·opt-in Common execution gate
    - [x] `ENG-002C1` PROF-002·B2B 교집합 비확장 MissionEnvelope compiler
    - [x] `ENG-002C2` explicit opt-in Common execution gate

## 후속 마일스톤

### Phase 5 — 구조화된 협업과 Handoff

- [x] `MEM-001` CampaignFact Proposal·Record
- [x] `MEM-002` SharedArtifactRef
- [x] `MEM-003` CollaborationSnapshot
- [x] `HANDOFF-001` Supervisor-mediated AgentHandoff
- [x] `HANDOFF-002` terminal result handoff
- [x] `HANDOFF-003` bounded UrgentObservation Fast Gate
- [x] `HANDOFF-004` capability-scoped reader, TTL, byte limit, receiver binding
- [ ] memory poisoning, prompt relay, confused deputy, cross-Campaign 테스트

Exit Gate: Agent A의 admitted Fact가 Agent B의 최소 Snapshot에 결박되고 Agent 간 직접 명령은
불가능해야 한다.

`MEM-001`은 새 Fact 원장이나 `CampaignFactRecord`를 만들지 않고 기존 GRAPH-001 Proposal과
GRAPH-002 Admission Event·CampaignFact를 그대로 사용한다. additive adapter는 기존 Proposal을
다시 파싱하고 하나의 bounded sealed-Run snapshot에서 exact Campaign·Run·현재 root·evidence SHA-256을
검증한 뒤에만 기존 Admission Authority로 전달한다. producer와 전체 request·Grant·Capability lineage는
기존 registry/verifier의 독립 gate로 남고 Fact node에는 명령·prompt·Scope·실행 권한 필드가 없다.
`MEM-002`는 기존 `GraphEvidence` identity와 기존 RunStore seal record를 Campaign·source
Run·현재 root·normalized path·SHA-256·media type·size에 결박하는 bounded `SharedArtifactRef`를
추가했다. reference는 artifact bytes나 filesystem path를 반환하지 않고 Graph admission,
prompt relay, receiver 권한, Scope·Capability·execution authority를 주장하지 않는다.
`MEM-003`은 exact Graph Snapshot에서 admitted Fact와 이 reference의 unique membership만
구성하는 최소 `CollaborationSnapshot`이다. 기존 Graph Snapshot store의 current head를 resolve
전후와 artifact 검증 뒤에 재확인하고 admitted CampaignFact 전체와 exact admitted GraphEvidence에
대응하는 MEM-002 reference만 deterministic하게 결박한다. Fact·artifact content, receiver,
prompt relay, Scope·Capability·execution authority는 포함하지 않는다. 다음 `HANDOFF-001`은
Supervisor가 sender·receiver·purpose와 이 exact Snapshot을 중재하는 비실행 handoff 계약이다.
기존 AgentNode·TaskNode 전체 digest와 completed source → dependent waiting destination 관계를
검증하고 양쪽 parentAgentId가 단일 process-local Supervisor와 같을 때 Proposal당 한 Record만
admission한다. 자유문 command·prompt·content와 read·Scope·Capability·Permit·execution 권위는 없다.
`HANDOFF-002`는 HANDOFF-001 당시의 Snapshot을 역사적 기준점으로 resolve하고, 같은 Graph store의
연속 후속 head인 current MEM-003 Snapshot과 그 안의 exact MEM-002 sealed Artifact reference에
destination Agent·Task terminal lifecycle을 결박한다. 성공·실패·취소는 기존 lifecycle 상태에서만
파생하며 result content, prompt relay, Scope·Capability·Permit·execution authority는 포함하지 않는다.
`HANDOFF-003`은 이 결과와 같은 current Snapshot의 existing GraphObservation ref를 resolve하고 exact
Action `produces`·result Evidence `supported-by`·sealed Artifact value digest를 검증한다. code-owned
긴급 type, operator|trusted-core origin, confidence 1.0만 handoff당 1 Observation·1 decision·1 local
budget unit의 `stop-and-escalate`로 admission한다. decision은 `admitted-not-applied`이며 content,
replan, Scope·Capability·Permit·execution authority가 없다.
`HANDOFF-004`는 existing CapabilityLedger의 delegated `maxCalls=1` Grant를 exact terminal receiver,
Campaign, `collaboration.artifact.read`, Shared Artifact ID에 결박하고 Grant lineage를 consume한 뒤 기존
sealed Run loader로만 bytes를 반환한다. terminal completion부터 60초, 65,536 cumulative bytes, 1회
attempt/read로 제한하며 HANDOFF-003 stop decision과 Graph head를 반환 전후에 재확인한다. receipt에는
content/path가 없고 prompt·Scope·Capability·Permit·execution authority를 부여하지 않는다. 다음 단계는
Phase 5 전체 memory poisoning·prompt relay·confused deputy·cross-Campaign adversarial regression이다.

### Phase 6 — Supervisor Shadow Mode

- [ ] `SUP-001` SupervisorModelBinding
- [ ] `SUP-002` Snapshot-only input·Target Taint
- [ ] `SUP-003` Task·Replan·Stop·Escalation Proposal
- [ ] `SUP-004` Checkpoint Scheduler·전용 Budget
- [ ] `SUP-005` Deterministic Baseline 비교
- [ ] `SUP-006` Adversarial Prompt Injection Regression

활성화하려면 Confirmed Finding Yield 또는 Chain Completion이 개선되고, Policy Violation은
증가하지 않으며, 비용·지연·Variance·Human Overturn 기준을 충족해야 한다.

### Phase 7 — 제한된 Supervisor 활성화

- [ ] `PERMIT-001` 일반 공격 ActionProposal
- [ ] `PERMIT-002` Deterministic Action Compiler
- [ ] `PERMIT-003` Exact Single-use ActionPermit
- [ ] `PERMIT-004` Side-effect·Data-flow·Cleanup Gate
- [ ] `APPROVAL-001` T2 ApprovalEnvelope와 Batch·Async 승인
- [ ] `SUP-007` opt-in T0/T1 실행
- [ ] T2는 사전 승인 Envelope를 요구하고 T3+는 기본 거부

Exit Gate: Supervisor가 권한을 확대할 수 없고 모든 실행이 정확한 Permit, Receipt, Evidence를
남겨야 한다.

### Phase 8 — Coverage·Validation 일반화

- [ ] `CHAIN-001` Auth Bypass → AI Admin Surface
- [ ] `CHAIN-002` File Upload → RAG Injection → Tool Abuse
- [ ] `CHAIN-003` Prompt Injection → URL Tool Control → Internal API
- [ ] `CHAIN-004` Cross-tenant Retrieval → Data Exposure
- [ ] `CHAIN-005` MCP Authorization Failure → Privileged Action
- [ ] `VAL-001` Mode-neutral Claim Replay
- [ ] `VAL-002` ValidationDepthPolicy
- [ ] `VAL-003` Profile별 Assurance Floor
- [ ] `VAL-004` Baseline·Negative Control·Counterfactual·N-run Replay

### Phase 9 — Product UX·Operations

- [ ] Campaign·Profile·Scope Builder
- [ ] Attack Surface·Graph·Wave Timeline UI
- [ ] Hypothesis Ranking·Decision Audit
- [ ] Original·Replay·Control·Retest Diff
- [ ] Human Review·Approval·Kill Switch Queue
- [ ] SARIF·Issue Tracker·SIEM/SOAR Export
- [ ] OIDC·MFA·ABAC·Worker Identity·mTLS
- [ ] Object Storage·Distributed Worker·KMS/HSM
- [ ] TLS 1.3 Exporter·Registry Refresh·External Transparency Anchor

## 미결정 제품 사항

다음 항목을 구현 중 암묵적으로 결정하지 않는다. 먼저 새 ADR 또는 Profile Policy를
작성한다.

- 외부 Profile 명칭과 `ai-redteam` Deprecation 기간
- 첫 Benchmark Target을 현재 저장소에 둘지 별도 저장소에 둘지
- Supervisor Primary/Review Provider 조합
- T2 ApprovalEnvelope의 Action·누적 변경·TTL 기본값
- CampaignFact Retention·Human Correction Authority
- Bug Hunting Program별 A1/A2 Confirmation Floor
- Capability Signing·Review Authority와 외부 기여 모델
- 첫 Graph Event Store를 RunStore로 유지할지 별도 Component로 만들지

## 완료 기준

각 Vertical Slice는 관련 Task ID, Threat Model, 변경되는 Trust Boundary, Schema/API Version,
Backward Compatibility, Migration·Rollback, Positive·Adversarial Test, Audit Artifact/Event,
Benchmark 영향, 버전형 문서를 포함한다. Ruff, Linux 대상 strict mypy, 집중 pytest, 가능한
범위의 전체 pytest 및 가능한 Linux CI를 실행한다. 환경 때문에 실행하지 못한 검증은
`HANDOFF.md`와 `KNOWN_ISSUES.md`에 정확히 기록한다.
