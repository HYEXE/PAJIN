> Languages: [English](README.en.md) | [한국어](README.ko.md)

# PAJIN

## Architecture v2 방향

PAJIN은 하나의 정책 통제형 공통 공격 엔진, Campaign Profile, 버전이 고정된 등록형
Capability와 Minimum Canonical Graph로 점진적으로 전환합니다. AI는 제품 전체를 정의하는
Mode가 아니라 first-class 보안 표면으로 유지합니다. 기존 `ai-redteam`, `bug-bounty`,
`ctf` 입력과 정책·증거·검증·Replay 경계는 strangler migration 동안 호환됩니다.

Adaptive Supervisor는 Graph와 benchmark 계약이 준비될 때까지 의도적으로 보류합니다.
도입 후에도 immutable snapshot을 읽고 proposal만 만들며, deterministic code가 single-use
실행 permit을 컴파일하고 Scope·risk·budget·Capability를 계속 집행합니다. 자세한 계약은
[ARCH-001](docs/rfc/0001-pajin-architecture-v2.ko.md),
[ADR-0046](docs/adr/0046-common-engine-and-campaign-profiles.ko.md),
[ADR-0047](docs/adr/0047-mission-envelope-and-action-permit-algebra.ko.md),
[ADR-0048](docs/adr/0048-minimum-graph-and-admission-consistency.ko.md)을 참조하십시오.

검증된 구현 기준선은 계속 `main@a4d0582`입니다. 로컬 Architecture v2 작업에는
[BENCH-001 manifest·ground-truth·result·comparison 계약](docs/benchmark/BENCH-001-benchmark-contract.ko.md)까지
포함됐습니다. [GRAPH-001의 6개 Node·8개 relation·3개 Proposal 계약](docs/graph/GRAPH-001-minimum-canonical-graph-model.ko.md)도
로컬에 구현했습니다. [GRAPH-002 단일 Admission Authority와 append-only Event Log reference
spike](docs/graph/GRAPH-002-single-admission-event-log.ko.md)는 단일 writer capability, 등록
producer와 exact lineage 검증, 멱등 retry/equivocation, canonical materialization,
hash-chained in-memory Event Log를 추가했습니다. 다음 구현 단위는 GRAPH-003 projection,
revision, immutable Snapshot입니다. 이 변경과 아래 B2.8g는 커밋·CI 검증 전까지 로컬 WIP입니다.

## B2.8g 재개 가능한 multipart portable Artifact 전송

기존 2 MiB 인라인 상한을 넘는 Replay Run은 이제 bytes가 없는 manifest와 multipart
전송을 사용합니다. 첫 조각은 전체 64 MiB, 파일당 16 MiB, 256 files, depth 24, 고정
1 MiB part로 제한됩니다. Control Plane은 live lease, exact Replay authority, executor
서명과 manifest를 먼저 검증한 뒤 owner-private local object-store namespace에 bytes를
받습니다.

upload begin과 part PUT은 exact retry에 멱등이며 같은 part를 다른 bytes로 바꿀 수 없습니다.
최종화는 모든 파일 digest와 canonical manifest를 다시 계산하고 staging tree를 원자적으로
발행한 뒤 기존 managed Artifact, sealed Run, receipt와 projection 검증을 재사용합니다. 작은
Run은 기존 inline v1 전송을 유지합니다. 외부 S3 호환 저장소, pre-signed URL, upload
expiry·garbage collection, encryption과 tenant isolation은 후속입니다. 자세한 경계는
[ADR-0045](docs/adr/0045-resumable-multipart-portable-artifact-transport.ko.md)를 참조하십시오.

## B2.8f Target 서명 TLS session binding

signed Target registry v4는 HTTPS exact URL마다 `tls-unique-sha256` session binding을
요구할 수 있습니다. 제한된 TLS 1.2 lab profile에서 Target은 receipt statement v2에 자신의
channel-binding digest를 서명하고, Executor는 Worker가 관찰한 digest·leaf SPKI·CONNECT
route를 TLS binding v3로 별도 서명합니다. Control Plane은 digest·type·version·pin의 exact
일치를 요구하며 receipt v1, binding v1/v2 downgrade와 cross-session proof 조합을 거부합니다.

Python 3.12 표준 API는 RFC 9266 `tls-exporter`를 노출하지 않으므로 이 조각은 TLS 1.3 지원을
과장하지 않고 TLS 1.2 `tls-unique` profile로 제한합니다. registry v1~v3와 기존 receipt·binding
버전의 동작은 유지합니다. 운영 TLS 1.3 exporter, 전체 handshake 정책과 mTLS는 후속입니다.
자세한 경계는 [ADR-0044](docs/adr/0044-target-signed-tls-session-binding.ko.md)를 참조하십시오.

## B2.8e 서명된 Target registry 배포

registry v3는 별도 Ed25519 배포 trust anchor가 서명한 번들 안에서만 사용할 수 있습니다.
번들은 1부터 연속 증가하는 sequence, 이전 번들 digest, 최대 7일의 유효기간과 exact-URL
registry 전체를 결박합니다. schema v14 append-only
`cp_target_attestation_registry_versions`는 재시작·다중 replica에서도 rollback, sequence
gap, predecessor 불일치와 동일 sequence equivocation을 거부합니다. HTTPS entry는 이전
SPKI pin 하나를 최대 24시간만 중첩할 수 있고 Target receipt 발행 시각으로 허용 여부를
결정합니다.

Control Plane은 inline 번들 또는 redirect 없는 absolute HTTPS URL에서 최대 512 KiB를
시작 시 한 번 읽습니다. 배포 trust anchor는 out-of-band 공개 설정입니다. runtime refresh,
TLS 1.3 exporter binding, CT·revocation, DB와 백업 소실 뒤 anti-rollback 복구는 아직
증명하지 않습니다. 자세한 경계는
[ADR-0043](docs/adr/0043-signed-target-registry-distribution-and-rotation.ko.md)을 참조하십시오.

PAJIN은 정책 통제를 받는 멀티 에이전트 AI 레드팀 및 보안 검증 플랫폼입니다.

현재 구현은 MVP에 가까워진 CLI 우선 백엔드입니다. 타입이 지정된 Campaign 및 Mode Pack
매니페스트를 검증하고, 제한된 Supervisor/Planner/Specialist/Semantic Validator/Reporter 팀을
동적으로 구성하며, 모든 Tool 요청을 Tool Gateway에서 평가합니다. 등록된 mock, HTTP 또는 MCP
Tool은 simulated Worker나 격리된 Docker Worker에서 실행하고, Candidate를 받아들인 뒤 의미론적
증거 Gate와 객관적 증거 Gate에서 각각 검토하며, 감사 증거와 구조화된 JSON 및 Markdown 보고서를
작성합니다. 선택 사항인 FastAPI/PostgreSQL Control Plane과 lease-aware Worker daemon은 로컬
CLI를 대체하지 않으면서 최초의 지속성 있는 실행 경로를 제공합니다.

## 현재 구현 상태

2026-07-24 기준 구현 범위는 다음과 같습니다.

| 영역 | 현재 범위 |
| --- | --- |
| Core engine | 타입이 지정된 Campaign, 정책 및 Capability 집행, 동적 Specialist, 예산, 재시도, 취소, Candidate 수용, Candidate-aware Provider 검토, 결정론적 validity·impact·severity Atomic Claim, metadata-minimized Blind Evidence 검토와 결정론적 reconciliation, 선택적 별도 Provider/model Blind Review와 제안 등급을 숨긴 독립 severity 도출, opt-in 코드 등록형 M03·M06·A04 fresh-capability Baseline·Negative Control·Counterfactual Control Executor, 의미론적 증거 검토, 버전이 지정된 replay 계약, 결정론적 Replay Compiler, 일회용 실행 ticket, 로컬 SQLite replay-ticket 원장, 무상태 및 등록된 fresh-session Restricted Reproducer 경로, receipt 재로딩 confirmation/retest Gate, 변조 탐지 증거 seal |
| Discovery 계약 | 버전형 `SurfaceObservation`, `AttackSurface`, `AttackSurfaceSet` artifact, canonical HTTP operation과 schema-bound Tool interface locator, 도메인 분리 결정론 identity, exact request/result/evidence/root 계보, bounded canonical JSON, ordering·uniqueness·lineage fail-closed 검증을 구현했습니다. 코드에 등록된 Trusted Surface Producer는 무결성이 검증된 Campaign·Gateway 증적만 받아 Scope·Authorization·method·Tool risk를 재검증하고 별도 append-only projection Run으로 발행합니다. A3는 명시적 opt-in 단일 MCP Recon wave, A4는 봉인된 projection 재검증·코드 등록 가설 컴파일·fresh-Capability Specialist wave를 제공합니다. A5는 별도 명시적 opt-in의 bounded replanning Control Run을 추가합니다. 봉인된 A4 wave를 다시 검증하고 exact 등록 결과 필드를 append-only `ObservationGraphSnapshot`으로 승격하며, `supports`·`contradicts`·`enables`·`depends-on`·`new-surface` 관계 계약을 기록합니다. 신규성이 임계값을 넘는 코드 등록 transition만 두 번째 fresh-Capability wave를 한 번 실행할 수 있고 Campaign의 Agent·Tool call·비용·시간·rate limit은 계속 공유됩니다. 동일 상태나 임계값 미만 Plan은 실행 전에 중단되며 기존 one-time Planner는 바꾸지 않습니다. |
| AI Red Team | 19개 위협 분류와 52개 체크리스트 항목의 KISA 카탈로그, 실행 가능한 A01, A02, A04, M03, M06 시나리오, `kisa-run` 및 명시적 Local 경로를 통한 exact M03·M06·A04 validity·impact·severity Claim별 fresh-session Replay 권위, Candidate마다 fresh single-call Capability 세 개와 등록 materializer identity·별도 request/evidence/receipt 계보를 사용하는 opt-in 정보 전용 validation Control, Claim replay projection, 외부 remediation attestation 없이는 inconclusive로 남는 baseline-bound negative replay |
| Bug Bounty | 프로그램 정책 검토, canonical scope 컴파일, 보수적 중복 triage, 로컬 보고서 초안, 고정된 Boolean SQL injection lab 한 개 |
| CTF | 타입이 지정된 로컬 Web backup 및 오프라인 single-byte XOR challenge와 제한된 Web + Crypto Suite |
| Control Plane | 선택적 인증 FastAPI API, PostgreSQL Job queue, 승인 checkpoint, fenced cooperative 취소, lease와 crash 복구, same-origin Web Console preview, owner-controlled managed Artifact, opaque Operator Replay source/batch admission과 역할 기반 조회, durable exact-KISA Replay finalization, fresh-identity retry 발행, 전용 `kisa-exact-v1` Replay Worker. Schema v11은 multi-item projection을, schema v12는 baseline-bound Retest를, schema v13은 exact Claim binding을, schema v14는 signed Target registry anti-rollback 원장을 추가합니다. 추가 opt-in은 Ed25519 Claim receipt, 인라인 또는 재개 가능한 64 MiB local-object-store multipart executor-attested portable Artifact, Target-issued receipt와 HTTPS CONNECT 증명, exact endpoint SPKI, 제한된 old/new pin overlap과 Target 서명 application exchange의 Worker 관찰 TLS 1.2 channel 결박을 제공합니다. validity만 confirmation을 구동하고 impact·severity는 정보 전용입니다. |
| 주요 공백 | 등록된 KISA 세 시나리오 밖의 Validation Control과 Claim별 Replay, live registry refresh와 외부 transparency/federation anchor, TLS 1.3 RFC 9266 exporter 지원, 64 MiB local 조각을 넘는 외부 object-store/pre-signed multipart 전송과 expiry·encryption·tenant isolation, 검증 가능한 운영 Provider 다양성, severity calibration과 다수 Reviewer/Human 합의, HTTP·RAG·Admin 추가 discovery adapter와 Hypothesis·Observation rule, 후속 관찰의 trusted new-Surface admission, ranking·정보가치 평가, 병렬 안전성과 3개 이상 wave 실행, Finding/보고서 검토 UI, 분산 Worker, 외부 연동, 독립적으로 앵커링된 운영 증거 |

주요 운영자 인터페이스는 계속 CLI + YAML입니다. 일반 공개 대상 공격 자동화, 외부 Bug Bounty
또는 CTF 제출, 운영용 멀티테넌트 배포는 구현되어 있지 않습니다.

> **검증 상태:** PAJIN은 현재 신뢰된 Candidate 수용, 의미론적 검토, Finding을 다시 쓰지 않고
> 정확한 Candidate·Atomic Claim digest를 판정하는 Candidate-aware Provider 계약, 결정론적
> validity·impact·severity Claim 분해, 객관적 증거 Gate, 봉인된 Decision snapshot과 별도의
> Blind Evidence Reviewer를 구현합니다. Blind 역할에는 opaque validity/impact Claim identity,
> statement와 허용 목록 evidence만 전달하며 Candidate identity·disposition·severity·기존 Decision은
> 전달하지 않습니다. 결정론적 reconciliation은 Candidate 상태나 confirmation eligibility를 바꾸지
> 않은 채 `corroborated`·`contested`·`inconclusive`를 기록합니다. 선택형 diverse-review
> 등록은 Blind Review와 독립 Severity Derivation을 별도 Agent·Provider Tool·endpoint·model·
> Capability 예산·Secret Lease에 둡니다. severity Packet은 제안 등급, Candidate identity와
> 기존 판정 문맥을 제외하며 reconciliation은 정보 전용이라 Candidate severity를 덮어쓸 수
> 없습니다. opt-in M03·M06·A04
> Control Executor는 코드 등록 materializer만 resolve하고 그 ID·version·scenario digest를
> Plan v1alpha2에 봉인합니다. 고유 session 세 개와 fresh non-delegable single-call Capability
> 세 개, 별도 request/evidence/receipt 계보로 Baseline·Negative Control·Counterfactual 관찰을
> validity Claim에 결박합니다. 그 결정론적 reconciliation은 정보 전용이며 disposition·severity·confirmation
> eligibility를 바꿀 수 없습니다. 버전이 지정된
> `ValidationPacket`, `ReplayIntent`, `ModeReplayContract`,
> `CompiledReplaySpec`, `ReplayAttempt`, `ReplayOracleResult`, `ReplayOutcome` 계약을 구현합니다.
> 순수 결정론적 compiler는 원래 Plan, 결박된 Tool 요청, Specialist grant, 증거 digest, Scope,
> authorization, cancellation, budget을 확인한 다음, 위임할 수 없고 유효 기간이 5분인
> `ReplayCapabilityGrant`와 일회용 실행 ticket만 발급합니다. 별도의 Restricted Reproducer는
> ticket 하나를 claim하고 기존 Tool Gateway와 Worker에서 컴파일된 operation을 실행하여 새로운
> request/evidence lineage를 만듭니다. 또한 Tool이 작성한 Secret Lease 요청을 금지하고, async
> Mode Oracle에 Campaign deadline과 cancellation을 적용하며, 검증된 disk loader가 있는 이중
> seal receipt를 반환합니다. 정확한 KISA `ai.chat-probe` 계약은 이제 신뢰된 fresh-session
> materializer와 raw-transcript Mode Oracle을 사용합니다. 완료된 source Run이 봉인되면
> `kisa-run`과 명시적으로 선택한 Local `pajin run ... --kisa-replay` 경로는 각 시도마다 새
> session을 사용하면서 동일한 공유 Campaign budget과 rate limit 안에서 서로 다른 replay
> Run의 Candidate-bound replay를 조정합니다. 일반 `pajin run` 경로는 replay를 암시적으로 켜지
> 않습니다. Worker가 작성한 `vulnerable` 및 `matched` 필드는 신뢰하지 않습니다. session을
> 포함하는 다른 계약은 등록된 신뢰 materializer가 없으면 계속 fail closed됩니다. M6 공통
> Gate는 이제 모든 KISA replay Run을 다시 열어 두 seal과 ticket finalization을 검증하고, 공유
> reason matrix를 적용한 다음 봉인된 source snapshot을 다시 쓰지 않고
> `validation/v1alpha1/`을 append합니다. [ADR 0027](docs/adr/0027-independent-reproduction-confirmation-boundary.ko.md)이
> 이 artifact는 Candidate 결박, 내부 일관성, receipt lineage를 증명하지만 Worker trust domain과
> 독립된 target 실행 사실은 증명하지 않습니다. 현재 Local·CLI·Control Plane Worker-only 경로는
> `verified-replay-evidence` projection을 작성하고, supporting claim을
> `independent-execution-attestation-missing` 사유의 `needs-review`로 유지합니다. 따라서 제품 수준
> Confirmed Finding을 만들지 않습니다. M6-05 retest는 이전에 독립적으로 attested된 Confirmed
> baseline만 받을 수 있습니다. 공개 deterministic-lab tuple을 포함한 negative target response는
> 별도로 검증 가능한 remediation authority가 생길 때까지 `inconclusive`입니다. positive 관찰은
> 이미 신뢰된 baseline이 `still-vulnerable`임을 보이는 데 사용할 수 있습니다. 로컬 KISA 경로는
> Run 밖의 안정된 SQLite 원장에 ticket 발급 context와 `issued → claimed → finalized` 전이 및
> event journal을 원자적으로 기록합니다. `mode=ro` verifier는 process를 다시 시작한 뒤에도
> compilation, source root, replay Run, artifact digest와 최종 seal root를 대조합니다. 자세한
> 신뢰 경계는 [ADR 0028](docs/adr/0028-durable-local-replay-ticket-ledger.ko.md)을 따릅니다.

## 현재 안전 경계

- Network access는 기본적으로 거부되며 Tool Adapter가 허용할 수 없습니다.
- network-enabled Tool은 Campaign에서 파생된 egress policy를 Tool Gateway에서만 받습니다.
- 각 network 실행에는 private internal Docker network와 전용 allowlist proxy가 제공됩니다.
- 기본 대상은 공개 주소이며 loopback, link-local, private, reserved, multicast, unspecified 주소는
  거부됩니다. private-network Mode Pack 예외는 고정된 synthetic lab으로 제한됩니다. Bug Bounty는
  `local-lab` profile을 사용하고, CTF Web slice는
  `host.docker.internal:8780/backup/config.json.bak`만 허용합니다.
- CTF Crypto slice에는 egress policy가 없습니다. 최대 4 KiB의 content-addressed inline artifact만
  받아들이고, no-network Worker 안에서 정확히 256개의 single-byte XOR key를 평가합니다.
- MCP process command는 Worker catalog에 보관됩니다. Agent는 등록된 server ID, Tool 이름,
  타입이 지정된 인자만 제출할 수 있습니다.
- Planner가 제공한 Agent identity는 무시합니다. Supervisor가 각 요청을 배정된 Specialist에
  결박하고 축소된 task-specific Capability Grant를 발급합니다.
- 자식 Tool 호출은 자신의 grant와 모든 상위 grant를 함께 소비하므로 형제 Agent가 Campaign
  call budget을 늘릴 수 없습니다.
- Agent 수, spawn depth, Tool call, elapsed time, cost, low-risk retry, cancellation은 model
  instruction이 아니라 PAJIN runtime이 제어합니다.
- 명시적 deny scope는 allow scope보다 우선합니다.
- 실행 전에 authorization, Capability, risk tier, method, call budget을 확인합니다.
- 선택적 Tool category allowlist, 반복되는 IANA-timezone testing window, Campaign별 request
  rate는 Policy Engine과 Tool Gateway가 집행합니다.
- 등록되지 않은 Tool은 Worker dispatch 전에 거부됩니다.
- Provider endpoint, model ID, function-tool allowlist, credential reference는 신뢰된 등록으로
  고정되며 Agent가 chat 요청에서 재정의할 수 없습니다.
- Provider credential은 audience-bound 일회용 Secret Lease를 통해 materialize되고 stdin
  envelope로만 Worker에 들어갑니다. Docker argument, environment variable, Job metadata,
  event, evidence에는 절대 들어가지 않습니다.
- Docker image는 allowlist로 제한되며 Campaign 중 암시적으로 pull되지 않습니다.
- 제품 수준 confirmation에는 objective Gate, Candidate-bound replay, 독립적으로 검증 가능한
  execution/target attestation이 모두 필요합니다. 현재 저장소에는 마지막 authority가 없으므로
  Worker-only 증거는 `needs-review`를 넘을 수 없습니다.
- KISA `fixed`에는 독립적으로 검증 가능한 remediation attestation도 필요합니다. 정확한 결박,
  성공한 반복, negative transcript, Worker flag, 로컬 receipt는 일관성 확인에는 필요하지만
  충분한 proof가 아니며, 현재 negative replay는 `inconclusive`로 남습니다.
- `ReplayIntent`는 엄격한 non-executable schema입니다. raw Tool request, command, 임의 URL,
  Capability Grant, 선언되지 않은 executable field는 거부됩니다. 버전 지정 replay artifact가
  Candidate, Run, original/replay request, Mode, scenario, Tool, target, threat identity를 결박한
  뒤에야 결정론적 compiler가 candidate-bound, non-delegable replay Grant와 opaque 일회용 실행
  ticket을 발급할 수 있습니다. Restricted Reproducer는 Mode Oracle이 claim을 지지하기 전에
  Campaign, Tool, scenario fingerprint, 공유 budget/rate ledger, fresh evidence JSON, 봉인된
  artifact digest, finalized ticket receipt를 다시 확인합니다. replay dispatch와 Oracle 평가는
  deadline/cancellation 경계를 공유하며 Tool Adapter는 새 Secret Lease를 요청할 수 없습니다.
  정확한 KISA M03, M06, A04 `ai.chat-probe` 계약은 시도별 fresh `session_id`만 materialize할 수
  있고, 다른 모든 catalog argument는 compiler-bound 상태로 유지됩니다. 등록되지 않은
  session-bearing 계약은 fail closed됩니다.
- Local KISA replay ticket 상태는 봉인된 replay Run 외부의 안정된 SQLite 원장에 저장됩니다.
  원장은 원자적 일회용 상태 전이와 read-only verifier를 사용하지만 host OS account/ACL 경계
  아래의 로컬 데이터베이스로 신뢰됩니다. 이 원장은 portable signed proof, off-host attestation,
  PostgreSQL Control Plane replay authority가 아니며 제품 수준 Confirmed/FIXED authority도 아닙니다.
- 명시적 Local KISA coordinator는 한 process와 한 writer로 제한되며, 정확한 M03, M06, A04
  `ai.chat-probe` 계약만 allowlist에 포함됩니다. generic structural replay predicate나
  distributed lock이 아닙니다. 승인된 ADR 0029는 Control Plane replay의 artifact handoff, lease
  fencing, PostgreSQL ticket/batch/item state, durable budget/rate state를 규정합니다. 구현된
  M6-07B-2B 기반은 버전형 Replay 집합체와 burn-on-claim 수명주기, 소유자가 통제하는 managed
  filesystem repository, immutable `cp_artifacts` metadata, 완료·봉인된 source의 server-owned
  admission을 포함합니다. producer Control Plane Run ID와 sealed Run ID는 별도로 보존합니다.
  consumer는 opaque한 정확한 `(artifact_id, repository_version)` locator만 제공하며, 서버가 이를
  resolve해 content와 seal을 다시 검증합니다. 2026-07-18부터 batch 생성은 그 locator와
  idempotency key만 받습니다. Control Plane은 managed sealed AI Red Team source를 다시 읽고,
  eligible exact M03·M06·A04 confirmation Candidate와 contract를 파생해 trusted Replay Compiler를
  실행한 뒤 canonical `ReplayCompilation`과 `ReplayCapabilityGrant`를 append-only planned/pending,
  non-dispatchable PostgreSQL derivation record이자 proof로 저장합니다. caller가 작성한 Candidate,
  contract, policy, digest, target,
  arguments는 authority input이 아닙니다. schema v4는 canonical, non-dispatchable compilation
  derivation record를 추가해 forward v1→v2→v3→v4 경로를 지원합니다. 각 append-only row는 고유한
  `compilation_id`, Replay Run identity, compilation digest와 Grant digest를 소유합니다. `item_id`는
  고유하지 않고 Candidate/contract plan identity FK에 결박되므로 같은 item에 후속 attempt/version
  row를 추가할 수 있습니다. 2026-07-18에는 M6-07B-2C durable issuance도 구현했습니다. 내부 멱등
  `ControlPlaneService.issue_replay_batch(batch_id, actor=...)` 경로는 managed source를 다시
  resolve하고 재검증한 뒤 schema v5의 `cp_replay_budget_accounts`,
  `cp_replay_budget_reservations`, `cp_replay_rate_accounts`, `cp_replay_rate_reservations` 권위를
  사용합니다. sealed budget과 request-rate snapshot을 보수적으로 결박하고 첫 시도 전체의 Tool-call 및
  request-unit 요구량을 예약한 다음, pending item마다 fresh Replay Run identity와 5분 Grant로 다시
  compile해 새 canonical `ReplayCompilation`을 append하고 내부 Job과 `issued` ticket을 정확히 하나씩
  원자적으로 만듭니다. Job payload와 ticket은 FK 및 strict model을 통해 정확한
  `compilation_id`, `budget_reservation_id`, `rate_reservation_id`, attempt, Replay Run,
  compilation digest, Grant digest에 결박됩니다. 최초 planned compilation은 non-dispatchable proof로
  남으며 승격하거나 재사용하지 않습니다. 응답 유실(response-loss) 재시도는 현재 active exact
  authority graph가 발급 직후 ticket/Job `issued`/`queued`이거나 claim 뒤 `claimed`/`running`일 때만
  같은 issuance를 재구성합니다. terminal이거나 그 밖에 변경된 graph는 fail closed됩니다.
  2026-07-18에는 M6-07B-2D 내부 서비스 전용 호출별 permit 원장과 발급도 구현했습니다. schema v6는
  append-only `cp_replay_tool_permits`를 추가해 forward v1→v2→v3→v4→v5→v6 경로를 지원합니다. strict
  `ReplayToolPermitRequest`는 executor profile, lease token, ticket ID, fencing value와 1부터 시작하는
  call ordinal만 받습니다. 멱등
  `ControlPlaneService.issue_replay_tool_permit(job_id, request, actor=...)` 서비스는 인증 principal과 등록된
  executor profile, 정확한 Job/ticket lease token과 fence, active Run·batch·item·ticket 상태, canonical
  compilation과 Grant, exact reservation counter 및 rolling request-rate admission을 다시 검증합니다. cap이
  있으면 현재 sealed baseline, 발급 후 아직 유효한 reservation의 미소비 unit, 각 60초 window에서 active인 permit
  unit과 새 trusted request 비용을 합산합니다. cap이 없으면 rate 거부만 생략하고 exact reservation
  counter는 계속 소비합니다. canonical permit은 그 authority graph, source와 original request, Tool과
  version, target, method, 1-based ordinal, Tool-call unit 하나와 신뢰된 request-unit 비용에 결박됩니다.
  TTL은 최대 30초이며 lease, compiled spec 또는 Grant deadline을 넘지 않습니다. rate reservation 만료는
  permit TTL cap이 아닙니다. 고유 ticket/ordinal key와 저장된 permit digest 및 request
  ID 덕분에 정확한 응답 유실 중복 호출은 counter를 다시 소비하거나 event를 두 번 append하지 않고 같은
  row를 돌려줍니다. 최초 발급은 예약된 budget/rate unit을 consumed로 원자적으로 옮기고 audit event를
  append합니다. 실행 여부가 불확실해도 발급된 permit은 consumed로 남고, 취소·포기는 확실히 미발급된
  잔여분만 release합니다. stale, mismatch, cancelled, expired, finalized, ordinal gap, over-limit 요청은
  fail closed됩니다. M6-07B-2E는 이 기존 서비스 권위만 Replay claim, heartbeat, Tool-permit 발급 전용
  WORKER-role HTTP endpoint와 대응 async client method로 노출합니다. strict JSON
  `PAJIN_CP_REPLAY_EXECUTOR_PROFILES` subject→profile-array allowlist는 인증된 Worker subject만 받으며,
  설정이 없으면 빈 allowlist로 fail closed합니다. 예를 들어
  `{"replay-worker-service":["kisa-exact-v1"]}`는 별도로 인증된 Replay Worker subject에만 해당
  profile 하나를 허용합니다. Route 권한도 대칭입니다. 이 Replay subject는 모든 일반 Worker
  route에서 거부되고, 일반 Worker와 그 밖의 non-allowlisted subject는 모든 Replay route에서
  거부됩니다. claim과
  heartbeat는 정확한 서버 검증 canonical `ReplayCompilation`을 담은
  `ReplayExecutionClaimView`를 반환하고, envelope는 canonical compilation, Candidate, contract, Grant,
  Campaign, Mode, Candidate Run, Replay Run 결박을 다시 확인합니다. permit은 발급 시 durable unit을 이미
  소비한 non-bearer proof이며 M6-07B-2E는 별도 redeem mutation을 추가하지 않습니다. M6-07B-2F는
  발급 시 fresh compilation마다 append-only schema v7 `cp_replay_execution_contexts` row를 하나씩
  만듭니다. canonical `ReplayExecutionContext`는 정확한 typed Campaign, exact KISA Scenario와
  canonical `AIChatProbeTool.spec`를 결박하고 각 component와 전체 context의 digest를 저장합니다.
  `required_executor_profile`은 `kisa-exact-v1`로 고정되고 Secret Lease는 금지되며, Worker path 대신
  opaque한 `stage_<uuid>` output slot만 할당합니다. Job payload는 context ID/digest를 반복하고,
  claim·heartbeat는 서버가 검증한 같은 context를 반환하며, profile 검사와 모든 permit 발급은
  compilation/context/ticket의 전이적 결박을 다시 검증합니다. v6→v7 migration은
  non-dispatchable v6 상태만 context table이 빈 채로 전진시키며, 정확한 과거 context byte를 backfill할 수
  없으므로 ticket, permit, 내부 Replay Job, durable reservation 또는 진행된 batch/item 상태가 있으면
  fail closed합니다. 이제 전용 `kisa-exact-v1` daemon은 그 profile만 claim하고 fenced lease를
  heartbeat하며, 실제 Tool dispatch 직전에 매번 durable server permit 하나를 발급받아 정확한 opaque
  staging slot에 output을 seal합니다. Worker는 path, ArtifactRef, result, digest 또는 verdict를 제출하지
  않습니다. Schema v9 finalization은 그 slot을 서버 소유 repository로 import한 뒤 seal을 독립적으로
  다시 열고, compilation/ticket/source/permit lineage를 검증하며, 공통 Gate 결정을 파생하고 output
  Artifact, ticket, Job, item, batch, Run과 audit state를 원자적으로 finalize합니다. 이때 permit
  발급에서 budget/rate unit을 이미 소비한 authority를 다시 검증합니다.
  Permit이 하나라도 존재한 뒤 실행이 실패하면 terminal이며 같은 ticket의 자동 dispatch retry는
  금지됩니다. 동일한 ordinal-bound permit 요청과 동일한 서버 finalization 요청의 정확한
  response-loss retry는 모두 멱등이며 어느 쪽도 Tool dispatch를 재시도하지 않습니다. Opaque public
  source/batch admission과 역할 기반 상태 조회 API도 구현됐습니다. Replay claim polling에서 발급된
  Job이 없을 때 Control Plane은 immutable source 재로딩, Candidate/contract plan 불변, permit 0개,
  budget/rate reservation 완전 반환, 이전 staging capability가 존재하고 비어 있음, 최대 시도 횟수
  미만을 모두 검증한 경우에만 pending retry를 발행합니다. abandoned Job/ticket/Run은 이력으로
  보존하고 fresh Replay Run, compilation, execution context, reservation, one-shot Job, ticket, staging
  capability, attempt와 fence를 append합니다. Permit, staged output, 누락 capability, authority 불일치
  또는 시도 소진이 하나라도 있으면 fail closed하며 같은 Job이나 ticket을 다시 dispatch하지
  않습니다. Schema v11/v12 aggregate projection과 dual-source negative Control Plane retest,
  schema v13 exact Claim별 projection, Ed25519 portable Claim receipt, executor-attested portable
  Artifact, Target-issued exact exchange, HTTPS CONNECT·leaf SPKI, signed registry v3 anti-rollback·
  제한된 pin rotation과 registry v4 TLS 1.2 양측 session binding까지 구현됐습니다. TLS 1.3
  RFC 9266 exporter와 대형 object-store/multipart 전송은 아직 남아 있습니다.
- Audit Event는 순서를 확인하는 SHA-256 chain을 구성하고, 완료된 Run artifact는 append-only
  integrity seal에 담깁니다. Mode Pack output은 이전 root를 덮어쓰지 않고 확장합니다.

## 개발 환경 설정

Python 3.12 이상을 지원합니다. 저장소의 `.python-version`은 이식 가능한 contributor 및 CI
baseline으로 Python 3.12를 선택합니다.

저장소 루트의 `uv.lock`은 application, development Tool, 선택적 Control Plane을 위한 canonical
dependency lock입니다. clean clone에서 다음 명령으로 정확한 환경을 만듭니다.

```powershell
uv sync --locked --extra dev --extra control-plane
```

의도적으로 dependency constraint를 변경한 뒤에는 `uv lock`을 사용하고 생성된 lockfile diff를
검토합니다. 모든 package를 암시적으로 새로 고치지 말고, 특정 package upgrade에는
`uv lock --upgrade-package <package>`를 사용합니다. Docker Worker는 계속 별도의 실행 경계이며
`containers/worker/requirements.lock`을 사용합니다.

`uv`를 사용할 수 없는 환경에서는 editable pip install도 지원되는 bootstrap 경로입니다. 다만
선언된 version range 안에서 resolve하므로 재현 가능한 quality-gate 환경은 아닙니다.

```powershell
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
```

## 지원 명령 범위

| 그룹 | 명령 |
| --- | --- |
| Core | `validate`, `run`, `multi-run`, `multi-cancel-check` |
| Provider 및 Agent loop | `provider-check`, `provider-agent-run`, `tool-loop-run`, `tool-loop-approval-check` |
| KISA AI Red Team | `kisa-run`, `kisa-plan-remediation`, `kisa-retest` |
| Bug Bounty | `bug-bounty-review`, `bug-bounty-compile`, `bug-bounty-report`, `bug-bounty-run` |
| CTF | `ctf-run`, `ctf-web-run`(호환 alias), `ctf-suite-run` |
| 증거 및 인프라 | `evidence-verify`, `replay-verify`, `worker-check`, `egress-check`, `mcp-check` |

선택적 server process는 `pajin-control-plane`, `pajin-worker-daemon`,
`pajin-replay-worker-daemon`으로 설치됩니다. 정확한
option 목록은 `pajin --help` 또는 `pajin <command> --help`로 확인합니다.

## 수직 슬라이스 실행

```powershell
.venv\Scripts\pajin validate examples\ai-redteam.yaml
.venv\Scripts\pajin run examples\ai-redteam.yaml

# 명시적인 개발/테스트 전용 실행
.venv\Scripts\pajin run examples\ai-redteam.yaml --worker simulated
```

`run`과 `multi-run`의 기본값은 Docker Worker입니다. simulated backend는 명시적으로 선택해야
하며 결정론적 개발과 unit test에만 사용됩니다. 이는 격리 경계가 아니고 실제 target evidence를
만들지 않습니다. 모든 Local/Multi-Agent Run은 실제 backend identity를
`execution-context.json`에 봉인하고 `run.json`과 start event에 반복 기록하며 report에도
표시합니다. simulated CLI 출력과 report에는 `SIMULATED / NOT REAL TARGET EVIDENCE` 경고가
명시됩니다.

## Bug Bounty 범위 파서

Bug Bounty 실행은 Agent가 free-form scope를 해석한 결과가 아니라 타입이 지정된 program-policy
snapshot에서 시작합니다. 첫 명령은 원본 정책을 normalize하고 `program.normalized.json`,
`scope-review.json`, 운영자용 `scope-review.md`를 생성합니다.

```powershell
.venv\Scripts\pajin bug-bounty-review examples\bug-bounty-program.yaml
```

검토 결과에는 원래 정책 text를 포함한 canonical policy JSON의 SHA-256 scope digest가
출력됩니다. 검토 내용을 공식 program page와 비교한 다음 정확히 그 digest만 컴파일합니다.

```powershell
.venv\Scripts\pajin bug-bounty-compile examples\bug-bounty-program.yaml `
  --scope-digest <digest-from-review> `
  --approved-by <program-owner> `
  --approved-at 2026-07-13T10:00:00+09:00 `
  --expires-at 2026-07-20T10:00:00+09:00 `
  --evidence <authorization-ticket>
.venv\Scripts\pajin validate .pajin\campaigns\example-bug-bounty-lab.yaml
```

raw policy, asset, method, Tool category, limit, time window 중 하나라도 바뀌면 digest는 무효가
됩니다. compiler는 이 MVP를 T2로 제한하고 denial of service, social engineering, persistence,
credential stuffing, real-user-data access, exfiltration에 대한 필수 금지를 삽입합니다. 또한 deny
rule에는 맞지 않으면서 allow rule에는 맞는 구체적 entry point를 요구합니다. runtime은 Worker
dispatch 전에 allow/deny scope, method 및 category allowlist, 주간 test window, sliding 1분
request limit을 집행합니다.

컴파일 시점에 승인도 활성 상태여야 합니다. 구체적 entry point가 있더라도 `generic-http`
profile인 asset은 PAJIN에 제한된 probe profile이 구현될 때까지 review-only이며, 이런 target이
섞인 manifest는 해당 target을 조용히 건너뛰지 않고 전체 컴파일에 실패합니다. review와 Campaign
artifact는 destination이 없거나 regular file일 때만 atomic replace하며, parent나 leaf가 symbolic
link이면 거부합니다.

Evidence retention은 계속 명시적인 수동 제어입니다. duplicate triage는 타입이 지정된 로컬
snapshot을 사용할 수 있지만, 이 snapshot을 platform 또는 issue tracker와 동기화하는 작업은
수동입니다.

### Finding triage와 제출 초안

완료된 Bug Bounty Campaign에 봉인된 validation snapshot이 있으면 보고 가능한 Candidate와
Finding을 program-specific known-finding index와 비교하여 로컬 검토 초안을 만듭니다.

```powershell
.venv\Scripts\pajin bug-bounty-report `
  examples\bug-bounty-program.yaml `
  <completed-run-directory> `
  --known-findings examples\bug-bounty-known-findings.yaml
```

Reporter는 완전한 versioned projection이 존재하면 이를 포함하여 정확히 봉인된
Candidate/Decision snapshot을 로드합니다. Run이 현재 program digest와 정확히 컴파일된 scope
policy를 사용했는지 다시 확인하고 선언된 target만 받아들입니다. 인용한 모든 evidence file은
해당 Run의 `evidence/` directory 아래에 봉인되어 있어야 합니다. 일부만 존재하거나 대체되었거나
authority가 일치하지 않는 snapshot은 fail-closed로 거부합니다. immutable-input 보고서 묶음은
다음 위치에 작성됩니다.

```text
bug-bounty-reports/<triage-id>/
  bug-bounty-triage.json
  bug-bounty-report.md
  submissions/<finding-id>.md
```

정확한 fingerprint는 program, normalize된 target path와 query-parameter 이름, vulnerability
class, affected component, normalize된 root cause를 사용합니다. 미해결 known Finding 또는 같은
Run과 정확히 일치할 때만 자동으로 억제합니다. 해결된 known Finding이나 다른 endpoint의 같은
원인은 `needs-review`가 되어 가능한 regression과 multi-endpoint impact를 보존합니다. impact,
remediation, component, root-cause data가 빠지면 자동 제출 대신 명시적 TODO가 있는 초안을
만듭니다.

program이 `duplicateCheckRequired: true`를 선언한 경우 `--known-findings` 생략을 권위 있는 빈
index로 취급하지 않습니다. 해당 item에는 `duplicate-check-not-performed`가 기록되고
`needs-review`와 submission-ineligible 상태로 남습니다. `findings: []`인 타입 지정 index를
제공해야 “검사를 수행했지만 알려진 일치 항목이 없음”을 뜻합니다. 구체 target이
`eligibleForBounty: false` asset에만 속한 Finding도 나머지 field와 관계없이 `needs-review`로
남습니다.

정확한 Decision에 objective check와 semantic check 성공이 기록되었지만 독립 재현이 없는
Candidate는 `semantic-review-only`로 보존됩니다. 이 item에는
`independent-reproduction-not-confirmed`가 기록되고 `needs-review`,
`submissionEligible: false` 상태로 남으며, 운영자 검토 전용임을 명시한 초안을 만들 수 있습니다.
지원되지 않거나 inconclusive/rejected 상태이거나 authority가 일치하지 않는 Candidate 주장은
초안으로 승격되지 않습니다. 봉인된 `verified-independent-replay` projection에서 가져온 Finding만
`ready` 및 제출 가능 상태가 될 수 있습니다. 독립적으로 검증 가능한 target-execution attestation이
없는 Worker-only replay evidence는 계속 검토 전용입니다.

생성된 Markdown은 로컬 초안일 뿐입니다. PAJIN은 Bug Bounty platform에 제출하지 않으며 로컬
evidence에 production-grade 외부 attestation이 있다고 주장하지 않습니다.

### 자동화된 로컬 Bug Bounty lab

실행 가능한 Bug Bounty slice는 의도적으로 일반 scope parser보다 좁습니다. synthetic
loopback-bound target에 컴파일된 `boolean-sqli-lab` profile만 실행합니다. Planner는
`bug-bounty.boolean-sqli-probe`만 선택할 수 있고, Tool은 Agent가 작성한 attack payload를 받지
않습니다. 신뢰된 Worker는 정확히 baseline 한 번, negative control 한 번, boolean comparison 한
번을 수행합니다. Validator는 Worker가 주장한 결론을 무시하고 제한된 세 observation에서 signal을
다시 계산합니다. 이는 evidence-review 경계를 보호하지만 원래 실행을 재사용하므로 독립 재현은
아닙니다. Tool 호출 한 번은 request-rate unit 세 개를 예약합니다.

Worker와 egress proxy를 build한 다음 취약한 lab을 시작합니다.

```powershell
docker build --tag pajin-worker:dev containers\worker
docker build --tag pajin-egress-proxy:dev containers\egress-proxy
docker compose -f containers\compose.bug-bounty-lab.yaml up --build --detach

.venv\Scripts\pajin bug-bounty-review `
  examples\bug-bounty-lab-program.yaml `
  --output .pajin\bug-bounty-lab-review
```

생성된 검토 결과를 확인하고 출력된 digest를 승인 명령에 복사합니다.

```powershell
.venv\Scripts\pajin bug-bounty-compile `
  examples\bug-bounty-lab-program.yaml `
  --scope-digest <reviewed-digest> `
  --approved-by <local-lab-owner> `
  --approved-at <offset-aware-approval-time> `
  --expires-at <offset-aware-expiry-time> `
  --evidence <local-authorization-record> `
  --output .pajin\campaigns

.venv\Scripts\pajin bug-bounty-run `
  examples\bug-bounty-lab-program.yaml `
  .pajin\campaigns\local-bug-bounty-sqli-lab.yaml
```

현재 vulnerable profile은 legacy validation 초안 하나를 생성합니다. hardened override로 target을
다시 만들고 동일한 digest-approved Campaign을 실행하면 수정된 probe에서는 Finding이 0개여야
합니다.

```powershell
docker compose `
  -f containers\compose.bug-bounty-lab.yaml `
  -f containers\compose.bug-bounty-lab.hardened.yaml `
  up --build --detach --force-recreate

.venv\Scripts\pajin bug-bounty-run `
  examples\bug-bounty-lab-program.yaml `
  .pajin\campaigns\local-bug-bounty-sqli-lab.yaml

docker compose -f containers\compose.bug-bounty-lab.yaml down
```

`bug-bounty-run`은 항상 Docker Worker를 사용하고 로컬 evidence와 triage 초안을 만들며 외부에
보고서를 제출하지 않습니다. 일반 공개 Bug Bounty asset은 계속 검토할 수 있지만, 별도로 제한된
실행용 probe profile이 구현되기 전에는 compiler가 명시적으로 거부합니다.

## 로컬 CTF Mode

CTF Mode는 타입이 지정된 `CTFChallenge` 매니페스트를 받아 기존 5개 역할 팀을 Supervisor 아래의
Triage Planner, category Specialist, 독립 flag Validator, Reporter로 실행합니다. 현재 Triage
Planner는 별도로 제한된 두 시나리오를 인식합니다.

- `web.exposed-backup-config`는 고정 Web Specialist로 route됩니다.
- `crypto.single-byte-xor`는 no-network Crypto Specialist로 route됩니다.

두 매니페스트 모두 expected flag를 plaintext가 아닌 SHA-256으로 보관하며 Docker image, command,
executable, scoreboard destination을 선택할 수 없습니다. `ctf-run`은 category-aware entry
point이고, `ctf-web-run`은 Web 외 매니페스트를 거부하는 backward-compatible alias입니다.

### Web 챌린지

Worker와 egress proxy를 build한 다음 취약한 loopback-bound challenge target을 시작합니다.

```powershell
docker build --tag pajin-worker:dev containers\worker
docker build --tag pajin-egress-proxy:dev containers\egress-proxy
docker compose -f containers\compose.ctf-web-lab.yaml up --build --detach

.venv\Scripts\pajin ctf-run examples\ctf-web-backup-lab.yaml
```

Triage Planner는 `ctf.web-backup-probe` step 하나만 만들 수 있습니다. Tool과 신뢰된 Worker는
모두 `http://host.docker.internal:8780/backup/config.json.bak`에 대한 GET 한 번만 허용하고,
Gateway는 컴파일된 Campaign의 private-network egress policy를 주입합니다. Specialist는 expected
digest를 절대 받지 않습니다. Mode-specific digest Validator는 Candidate를 hash하고 constant-time
digest match일 때만 검증된 solve 결과를 만듭니다.

vulnerable profile은 `solved`, `ctf-result.json`, `ctf-writeup.md`를 생성해야 합니다. 같은 target을
hardened override로 다시 만들어 backup artifact가 없고 명령이 non-zero `unsolved` 결과를
반환하는지 확인합니다.

```powershell
docker compose `
  -f containers\compose.ctf-web-lab.yaml `
  -f containers\compose.ctf-web-lab.hardened.yaml `
  up --build --detach --force-recreate

.venv\Scripts\pajin ctf-run examples\ctf-web-backup-lab.yaml

docker compose -f containers\compose.ctf-web-lab.yaml down
```

### Crypto 챌린지

Crypto 매니페스트는 제한된 inline artifact 한 개를 lowercase hex로 담고 decoded byte의 SHA-256도
포함합니다. compiler는 논리적 `artifact.invalid` content address를 파생하고, 매니페스트는 network
target이나 filesystem path를 제공하지 않습니다. Tool은 Worker Job을 만들기 전에 digest를 다시
확인하고, Worker는 256개의 single-byte XOR key를 모두 평가하기 전에 다시 확인합니다. Tool은
T0 risk를 선언하고 egress policy를 받지 않으며 외부 process를 호출하지 않고 최대 한 개의
`PAJIN{...}` Candidate를 반환합니다.

target service를 시작하지 않고 updated Worker를 build하여 synthetic artifact를 실행합니다.

```powershell
docker build --tag pajin-worker:dev containers\worker
.venv\Scripts\pajin ctf-run examples\ctf-crypto-xor-lab.yaml
```

Crypto Specialist는 expected flag digest를 절대 받지 않습니다. Mode-specific digest Validator는
Candidate를 same-run evidence에 결박하고 SHA-256을 봉인된 Campaign 값과 비교합니다. write-up에는
category routing, offline analysis, 최종 digest decision이 기록됩니다.

Core 실행은 첫 evidence-integrity seal을 만들고, CTF result와 write-up finalization은 그 root를
검증한 뒤 두 번째 seal을 append합니다. `ctf-run`은 Docker 전용이며 scoreboard credential, API
client, 외부 제출 경로가 없습니다. category를 추가하려면 별도의 typed scenario, Tool grammar,
isolated fixture, independent verification rule, safety review가 필요합니다.

### Web + Crypto Suite

`ctf-suite-run`은 정확히 Web 매니페스트 한 개와 Crypto 매니페스트 한 개를 하나의 Campaign으로
컴파일합니다. 두 매니페스트는 서로 다른 challenge ID, 같은 approving authority, 겹치는
authorization window를 가져야 합니다. 컴파일된 Campaign은 두 approval window의 교집합만
사용하고, 두 member contract를 authorization evidence에 결박하며, 6-Agent budget을 파생하고,
정확히 두 번의 Tool call을 허용합니다.

로컬 Web fixture를 시작한 다음 타입이 지정된 두 challenge를 함께 실행합니다.

```powershell
docker compose -f containers\compose.ctf-web-lab.yaml up --build --detach

.venv\Scripts\pajin ctf-suite-run `
  web-crypto-suite `
  examples\ctf-web-backup-lab.yaml `
  examples\ctf-crypto-xor-lab.yaml

docker compose -f containers\compose.ctf-web-lab.yaml down
```

결정론적 Triage Planner는 `ctf-web-specialist`와 `ctf-crypto-specialist`를 각각 하나씩 만듭니다.
각각 자신의 target과 Tool로 제한된 별도 Capability Grant를 받습니다. 고정 Tool 두 개 모두
`parallelSafe`를 선택하므로 generic runner가 같은 제한된 local wave에서 실행하고 결과를 결정론적
plan 순서로 복원합니다. aggregate `ctf-suite-result.json`은 각 challenge의 `solved`, `unsolved`,
`invalid-flag`를 보존하고, `ctf-suite-writeup.md`는 독립적으로 digest 검증된 flag만 기록합니다.
하나라도 solved가 아니면 전체 aggregate evidence를 봉인한 뒤 CLI가 non-zero를 반환합니다.
scoreboard 제출 기능은 없습니다.

## KISA AI Red Team Mode Pack

KISA 기준의 indirect prompt-injection 및 unauthorized tool-use 시나리오를 독립적으로 두 번
반복해 실행합니다.

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker simulated --repetitions 2
.venv\Scripts\pajin kisa-run examples\kisa-ai-redteam.yaml --worker docker --repetitions 2
```

정확한 KISA AI Chat 계약에서는 일반 Local runner가 같은 Candidate-to-replay-to-Gate 경계를
명시적으로 선택할 수 있습니다.

```powershell
.venv\Scripts\pajin run examples\kisa-ai-chat-lab.yaml --worker docker --kisa-replay --repetitions 2
```

`--kisa-replay`가 없으면 `pajin run`은 일반 Local 실행 경로로 유지되고 replay ticket을 만들거나
confirmation Gate를 호출하지 않습니다. opt-in 경로는 AI Red Team Campaign과 정확한 M03, M06,
A04 allowlist로 제한됩니다. 지원되지 않거나 누락된 계약은 generic predicate로 선택되지 않고
unconfirmed 상태로 남습니다.

Mode Pack은 KISA AI Security Red Teaming Guide의 19개 위협 분류를 typed catalog에 매핑하고,
target-compatible 시나리오를 선택하며, 각 시나리오를 별도 Specialist Agent에서 실행합니다.
그런 다음 same-Run evidence 확인 후 Candidate와 legacy validation Finding의 중복을 제거합니다.
M03·M06·A04의 trusted Candidate는 별도 replay Run과 공통 Gate를 거쳐 봉인된
`verified-replay-evidence` projection을 받을 수 있지만, 독립 실행 attestation 없이는
`needs-review`로 남습니다. 그 밖의 요청 위협은 실행 가능한 target-linked
scenario와 명시적인 replay 계약이 추가될 때까지 coverage gap 또는 `needs-review`로 남습니다.

`kisa-run`은 표준 Run artifact 외에도 다음 파일을 작성합니다.

```text
kisa-results.json
kisa-checklist.json
kisa-test-plan.json
kisa-completion-report.json
kisa-execution-log.json
kisa-report.md
```

체크리스트 값은 `yes`, `no`, `not-applicable`, `needs-review`를 구분합니다. 법률, 윤리, 인력,
business impact, remediation, lifecycle governance 항목은 기술 실행 증거에서 추론하지 않습니다.
생성된 보고서는 평가를 지원하지만 compliance certification은 아닙니다.

### Provider-neutral AI Chat/RAG 실습 환경

PAJIN은 승인된 AI application target을 위해 고정된 provider-neutral chat contract를 정의합니다.
등록된 `ai.chat-probe` Tool은 KISA scenario catalog에서 선택된 제한된 POST conversation만 보낼
수 있습니다. 임의 process command를 삽입하거나 스스로 network access를 부여할 수 없습니다.
Tool Gateway는 Campaign Scope에서 egress를 파생하고, Semantic Validator는 Tool의 vulnerability
flag를 신뢰하지 않고 raw transcript를 다시 확인합니다. 이는 원래 실행에 대한 의미론적·결정론적
evidence review이며 두 번째 reproduction request가 아닙니다.

의도적으로 취약한 로컬 target을 build하고 시작한 다음 M03, M06, A04 Campaign을 실행합니다.

```powershell
docker build --tag pajin-worker:dev containers/worker
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml down
```

B2.2의 등록형 M03·M06·A04 Control 조각은 명시적으로 실행합니다.

```powershell
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-controls-lab.yaml `
  --worker docker --repetitions 2 --validation-controls
```

Replay 뒤에 적격 Candidate마다 정보 전용 호출 세 개가 추가됩니다.
Baseline·Negative Control·Counterfactual은 각각 fresh one-call Capability와 고유
request·session·evidence·receipt를 받습니다. M03·M06은 benign `READY` Counterfactual을
사용하고, A04는 두 번째 memory query를 유지한 채 첫 poison write만 바꿉니다. 이 결과는
Candidate를 confirm하거나 변경할 수 없습니다. 세 시나리오 예제는 source 6회, Candidate별
validity·impact·severity Claim Replay 18회, Control 9회로 정확히 33회를 예약합니다.

6개의 Specialist Task는 고유한 session ID를 사용하며 system-prompt disclosure, jailbreak policy
bypass, persistent memory poisoning을 다룹니다. lab은 `127.0.0.1:8765`에만 bind되고, read-only
filesystem과 Linux Capability가 없는 non-root user로 실행되며, production AI service가 아닙니다.

완료된 `kisa-run`은 적격한 신뢰 M03, M06, A04 Candidate를 별도 replay Run에서 추가로 재현합니다.
정확한 validity·impact·severity Atomic Claim마다 별도 compiled 실행 권위, single-use ticket,
fresh session, evidence, Oracle과 receipt를 부여합니다. live KISA Oracle은 Mode 소유 Claim
statement를 확인하고 raw transcript에서 정확한 catalog check를 다시 계산합니다. 제품
confirmation에는 validity만 사용되며 impact·severity assessment는 정보 전용입니다.
source/replay link는
`kisa-replay-index.json`에 기록됩니다. 현재 Worker-only 경로의
`confirmationMutationApplied`는 `false`로 유지됩니다. 공통 Gate는 receipt를 다시 불러와
`verified-replay-evidence` 의미의 봉인된 `validation/v1alpha1`
Decision/evidence/report projection을 append합니다. 원래 flat artifact는 변경 불가능한
pre-replay snapshot으로 유지되고 제품 Finding은 추가되지 않습니다.

로컬 positive replay ticket 원장은 선택한 output root의
`<output>/replay/replay-tickets.sqlite3`에 저장됩니다. 발급된 compilation과 source root, replay
Run, 최종 artifact digest 및 receipt seal root는 실행 process가 종료된 뒤 새 read-only
verifier로 다시 확인할 수 있습니다.

명시적 Local `pajin run --kisa-replay` 경로는 이와 분리된
`<output>/local-replay/replay-tickets.sqlite3`를 사용합니다. source Run, Candidate, SQLite
ticket과 별도 replay Run을 같은 process의 single writer가 순서대로 만든 뒤 공통 Gate가
canonical receipt를 다시 읽습니다. Gate는 flat `findings.json`을 변경하지 않고
`validation/v1alpha1/` projection에 Candidate-bound evidence와
`independent-execution-attestation-missing` 사유만 추가합니다.

```powershell
.venv\Scripts\pajin replay-verify <replay-run-directory> `
  --ledger <output>\replay\replay-tickets.sqlite3

.venv\Scripts\pajin replay-verify <local-replay-run-directory> `
  --ledger <output>\local-replay\replay-tickets.sqlite3
```

`replay-verify`는 ledger를 생성하거나 ticket 상태를 변경하지 않습니다. 파일 누락, 미완료
ticket, context·digest·Run·seal 불일치는 fail closed로 종료됩니다.

### Remediation 및 retest loop

변경 사항을 적용하기 전에 완료된 vulnerable baseline에서 remediation plan을 만듭니다.

```powershell
.venv\Scripts\pajin kisa-plan-remediation <baseline-run-directory>
```

담당자가 계획된 control을 적용한 뒤 hardened profile로 lab을 다시 만들고, 같은 공격과 두 개의
normal-function check를 실행합니다.

```powershell
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml up --detach --force-recreate
.venv\Scripts\pajin kisa-retest <baseline-run-directory> `
  examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml down
```

`kisa-retest`는 독립 attestation을 거쳐 봉인된 `validation/v1alpha1` Confirmed projection에
기록된 baseline Finding만 소비합니다. 현재 Worker-only baseline은 이 조건을 충족하지 않습니다.
legacy flat Finding, semantic-only Candidate, 미확정 baseline은 재검증
기준으로 받아들이지 않습니다. 일반 parent retest Run은 정상 기능 probe와 regression을
수행하고, baseline-bound Restricted Replay는 각 기준 Candidate의 원 request·scenario·threat·
Tool·target을 그대로 컴파일해 별도 공격 replay Run에서 실행합니다. 두 경로의 결과는 구분해
기록하되 호출은 같은 Campaign budget·rate limit·cancellation 경계를 소비합니다.

재검증 Gate는 canonical receipt를 디스크에서 다시 열어 Candidate, source Decision, versioned
Finding, remediation action, baseline/retest Run과 seal root, original/replay request, scenario,
threat, Tool, target 결박을 확인합니다. 이 확인만으로 remediation이 의도한 target에서 실행됐음을
독립적으로 증명할 수는 없습니다. 따라서 모든 반복이 deterministic-lab response와 일치해도
negative Worker transcript는 `inconclusive`로 남습니다. 검증된
`ReplayOracleVerdict.SUPPORTS`는 기존 신뢰 baseline을 `still-vulnerable`로 판정합니다. support가
섞였거나 반복 부족·실행 실패·취소·timeout·target unavailable·명시적인 방어 증적 부재가 있으면
`inconclusive`입니다. 기존 positive Oracle은 zero support를
계속 `inconclusive`로 처리하며, Worker의 `vulnerable=false`나 단순 신호 부재만으로 `fixed`를
주장하지 않습니다. 결박 또는 무결성 불일치는 상태로 축소하지 않고 명령을 fail closed로
종료합니다.

결정론 KISA Lab에 등록된 정확한 방어 응답은 공개 test fixture이지 trusted remediation
predicate가 아닙니다. 해당 문자열, model metadata, `safety.blocked`, compromise marker·
`toolCalls`·`memoryWrites` 부재가 모두 일치해도 lab 또는 일반 target을 `fixed`로 만들 수 없으며,
외부 attestation 없이는 모두 `inconclusive`입니다.

정상 기능 regression은 Finding 상태와 독립적으로 평가됩니다. `kisa-retest`의 범위 한정 Exit
Gate는 모든 baseline Finding이 `fixed`, `still-vulnerable`·`inconclusive`가 0, 실행 중 관찰된
새 Confirmed Finding이 0, regression이 `pass`일 때만 열립니다. 그 밖의 결과는 artifact를 봉인한
뒤 non-zero로 종료됩니다. 현재 Worker-only 구현은 `fixed` 선행 조건을 충족할 수 없으므로 외부
attestation 경로가 구현될 때까지 Gate는 닫힌 상태입니다. 이 명령은 baseline closed loop이지
새로운 위협 유형을 찾는 전체
rescan이 아닙니다. 신규 취약점 부재까지 주장하려면 별도의 fresh `pajin kisa-run` discovery
Gate를 실행해야 합니다. 이 discovery도 현재 실행 가능한 시나리오 범위만 다루며, 나머지 KISA
위협은 아직 `not assessed`입니다.

`kisa-plan-remediation`은 versioned baseline projection과 기존 seal entry를 덮어쓰지 않고
`remediation-plan.json`과 event를 append한 뒤 새 current root를 만듭니다. `kisa-retest`는 이
확정된 root를 모든 baseline-bound receipt에 결박하며, 이후 baseline 변경은 hard fail됩니다.
retest Run은 `remediation-plan.json`, `kisa-retest.json`, `kisa-retest-index.json`,
`kisa-checklist-overlay.json`, `kisa-retest-report.md`와 baseline-bound replay/receipt lineage를
append-only seal로 보호합니다. overlay는 증거로 확인한 5개 KISA 항목만 supersede하고, 담당자,
기한, 운영 반영은 계속 사람의 검토가 필요한 항목으로 남깁니다.

negative replay ticket은 `<output>/retest-replay/replay-tickets.sqlite3` 원장에 같은 원자적
상태 전이와 발급 context를 기록합니다. 재시작 후 검증 명령은 위와 동일하며 `--ledger`에 이
retest 원장 path를 지정합니다. 이 로컬 원장은 기존 in-memory API의 unit-test compatibility
경계를 대체하지 않으며, PostgreSQL Control Plane replay나 외부에서 검증 가능한 signed proof를
제공하지 않습니다.

## OpenAI-compatible Provider Gateway

PAJIN은 Agent 경계에서 provider-neutral message/result contract를 사용합니다. 신뢰된
`ProviderRegistration`은 Chat Completions endpoint, model, credential reference, streaming
permission, 허용된 function 이름을 고정합니다. Worker는 이 계약을 OpenAI-compatible
`POST /chat/completions` 요청으로 변환하고 JSON response 또는 data-only SSE stream을
normalize합니다. function-call argument fragment는 조립되어 JSON으로 parse되지만 Provider
Gateway는 요청된 function을 실행하지 않습니다. 실행하려면 별도로 등록된 PAJIN Tool과 Capability
Grant가 필요합니다.

인증된 로컬 validation target과 4-Specialist Campaign을 실행합니다.

```powershell
docker build --tag pajin-worker:dev containers/worker
docker build --tag pajin-egress-proxy:dev containers/egress-proxy
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin provider-check examples\provider-openai-compatible-lab.yaml --worker docker
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

`provider-check`는 authentication, non-streaming text, SSE text, streamed function call, credential
redaction, Lease 발급/폐기, 모든 Run artifact에 raw credential이 없는지를 검증합니다. 실제
Provider에서는 credential을 선택한 environment variable에만 두고 Campaign 매니페스트나 Provider
등록 파일에 추가하지 마십시오. 현재 in-memory broker는 로컬 runtime 경계이지 production secret
manager가 아닙니다. 배포 환경에서는 platform vault에서 값을 가져오고 그에 맞게 Supervisor
process를 격리해야 합니다.

### Provider-backed Planner, Validator들 및 Reporter

`provider-agent-run`은 기본 네 번의 reasoning 호출에 공격 실행 권한을 주지 않고 등록된 Provider Gateway와
연결합니다. 각 role은 서로 다른 developer prompt, 엄격한 JSON Schema, 정확한 Provider Tool과
endpoint만 포함하는 축소된 Capability를 받습니다. Campaign, plan, result, Finding data는 신뢰할
수 없는 user content로 제공됩니다. Supervisor는 Specialist를 만들기 전에 model이 만든 plan을
다시 검증하고 선언되지 않은 target, Provider control-plane Tool, 미등록 Tool, 미등록 method를
거부합니다.

완전한 model-driven M03 lab을 실행합니다.

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --worker docker --allow-private-provider
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

Blind Review와 독립 Severity Derivation을 별도 Provider/model 경계에 두려면 네 review 설정을
모두 함께 등록합니다.

```powershell
$env:PAJIN_PROVIDER_API_KEY='<primary-provider-secret>'
$env:PAJIN_REVIEW_PROVIDER_API_KEY='<review-provider-secret>'
.venv\Scripts\pajin provider-agent-run examples\provider-agent-lab.yaml `
  --review-provider-endpoint https://review-provider.example/v1 `
  --review-provider-id independent-review `
  --review-model review-model-v1 `
  --review-secret-env PAJIN_REVIEW_PROVIDER_API_KEY
```

Review Provider ID·endpoint·model은 Primary 등록과 모두 달라야 하며, 하나라도 같으면 실행 전에
fail-closed 합니다.

구현된 flow는 Provider Planner → 격리된 `ai.chat-probe` Specialist → 신뢰된 Candidate Producer →
Candidate-aware Provider Semantic Validator → Blind Evidence Reviewer → 결정론적 reconciliation →
objective Gate → Provider Reporter입니다. Validator는
불변 Candidate ID·digest와 결정론적 `validity`·`impact`·`severity` Atomic Claim을 받고, Finding을
다시 만들지 않은 채 Claim마다 `supports`·`contradicts`·`insufficient`와 Candidate 소유 evidence만
반환합니다. validity Decision만 기존 Candidate 의미 Gate에 전달되고 impact·severity 판정은 별도로
봉인되며 Candidate를 변경할 수 없습니다. 두 번째 역할에는 opaque validity/impact Claim identity,
statement와 허용 목록 evidence만 전달합니다. Candidate identity·disposition·severity·첫 판정은
볼 수 없으며 결과는 `corroborated`·`contested`·`inconclusive`로 조정됩니다. Blind 검토 실패는
insufficient로 봉인되고, Blind 검토와 reconciliation 어느 것도 disposition을 바꾸거나 Finding을
confirm할 수 없습니다. 제품 수준 confirmation은 계속 Restricted Reproducer와 독립 실행
attestation을 요구합니다. Reporter output은 `model-narrative.json`에 별도로 저장되어
명확히 하위 섹션으로 append되며 canonical Finding이나 실행 상태를 변경할 수 없습니다.

diverse review를 켜면 Blind Reviewer와 Severity Deriver는 Primary Provider Tool 권한이 없는 전용
Reviewer Agent와 review Provider Capability를 공유합니다. Severity Derivation은 opaque severity
Claim ID와 이미 최소화된 validity·선택적 impact Packet만 받으며 Candidate, 제안 severity,
disposition, Primary Decision과 보고서 문맥은 받지 않습니다. 그 결과의
`corroborated`·`contested`·`inconclusive` 비교는 `validator-output.json` v1alpha2에 정보 전용
신호로 봉인됩니다. 이 로컬 Provider/model 구분은 설정 assertion이며 별도 법인·인프라를
암호학적으로 증명하지는 않습니다.

정확한 Claim identity·evidence·fallback·Blind 검토·Control·confirmation 경계는
[ADR 0030](docs/adr/0030-candidate-aware-atomic-claim-validation.ko.md)과
[ADR 0031](docs/adr/0031-blind-evidence-review-boundary.ko.md),
[ADR 0032](docs/adr/0032-fresh-capability-validation-controls.ko.md),
[ADR 0033](docs/adr/0033-registered-validation-control-materializers.ko.md),
[ADR 0034](docs/adr/0034-diverse-independent-severity-review.ko.md)에 기록했습니다. Claim projection과
별도 Claim 실행 권위는 [ADR 0035](docs/adr/0035-claim-replay-public-state-projection.ko.md)와
[ADR 0036](docs/adr/0036-claim-bound-replay-execution-authority.ko.md)에 기록했습니다.

`maxModelCalls`와 `maxModelTokens`는 Campaign 내부 model 사용량을 각각 제한하며, `maxCostUsd`는
등록 시 제공된 100만 token당 rate를 같은 보수적 예약량에 적용합니다. Provider가 보고한 token
usage와 그 값으로 계산한 reported cost는 비신뢰 감사 관찰값으로만 보존됩니다. 이 값은 Campaign
집행 차감을 줄이지 않으며 외부 Provider 청구서를 정산하는 근거도 아닙니다. PAJIN은 dispatch 전에
canonical request의 UTF-8 byte마다 token 4개를 예약하고 base, message별, tool별, assistant tool
call별, response-format별 framing 상한을 명시적으로 더합니다. 요청에 선언된
`max_completion_tokens`와 그 최대 비용도 함께 예약합니다. dispatch가 증명된 뒤에는 성공, 실패,
취소, usage 누락·불일치 또는 예약 상한을 넘는 보고와 관계없이 보수적 예약량 전체를 확정
소비합니다. 명백한 미실행만 예약을 해제합니다. 따라서 Campaign의 `maxModelTokens`는 적어도 한
번의 완전한 in-flight 예약을 수용해야 합니다. 이는 Campaign 내부 보호 장치이며 외부 과금
정산이 아닙니다.

Provider failure, refusal, schema error는 결정론적 fallback 전에 최대 두 번 재시도합니다.
duration, Capability, token, cost가 소진되면 fallback을 활성화하지 않고 Campaign을 종료합니다.
Bearer 인증을 사용하는 public Provider endpoint에는 HTTPS가 필수입니다. 평문 HTTP는 고정된
loopback/local-lab host와 명시적 private-network opt-in이 모두 있을 때만 허용됩니다.
`--allow-private-provider`를 명시하지 않으면 private Provider destination은 거부됩니다. 과금
Provider에서는 신뢰된 Provider pricing
configuration에 따라 `--input-cost-per-million`과 `--output-cost-per-million`을 설정합니다.

### 정책 통제를 받는 반복형 Tool Loop

`tool-loop-run`은 엄격한 function definition을 Provider에 노출하지만 반환된 모든 call을 신뢰할
수 없는 intent로 취급합니다. parallel call은 비활성화됩니다. Supervisor는 function 이름을 고정
PAJIN Tool, target, method, JSON Schema 하나에 매핑하고 unknown, invalid, parallel, duplicate call을
거부한 뒤 one-call Capability가 있는 새 Specialist를 만듭니다. Specialist 결과만 원래 call ID가
포함된 `tool` message로 돌아갑니다. 그 후 Provider는 최종 response를 반환하거나 제한된 turn을
한 번 더 요청할 수 있습니다.

2-turn 로컬 loop를 실행합니다.

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1' # public local fixture only
.venv\Scripts\pajin tool-loop-run examples\tool-loop-lab.yaml `
  --worker docker --allow-private-provider
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

모든 transition은 conversation state, call fingerprint, pending intent, Tool result, 누적 budget
사용량을 포함하되 credential은 없는 versioned checkpoint를 작성합니다. resume은 연결된
continuation Run을 만들고 Agent, Tool, Model, token, cost, elapsed-time 사용량을 복원합니다.

T3 및 T4 intent는 call fingerprint, Tool ID, target에 결박된 정확하고 활성 상태인 승인이 없으면
Worker를 dispatch하지 않습니다. 로컬 approval check는 먼저 T3 intent가 Tool result 0개인 채
pause되었음을 증명한 다음 명시적 승인을 제공하고 해당 checkpoint에서 resume합니다.

```powershell
docker compose -f containers/compose.ai-lab.yaml up --detach
$env:PAJIN_PROVIDER_API_KEY='pajin-local-credential-v1'
.venv\Scripts\pajin tool-loop-approval-check examples\tool-loop-approval-lab.yaml `
  --worker docker --allow-private-provider --approved-by local-security-owner
Remove-Item Env:PAJIN_PROVIDER_API_KEY
docker compose -f containers/compose.ai-lab.yaml down
```

`mock.approval-probe`는 안전한 mock operation만 수행하지만 approval control을 검증하기 위해 T3로
분류됩니다. 운영 승인은 인증된 외부 Control Plane에서 와야 합니다. lab CLI identity는 검증
data일 뿐 production authentication이 아닙니다.

## 지속성 있는 Control Plane

선택적 Control Plane은 기존 file-backed CLI를 대체하지 않고 인증된 FastAPI endpoint와 PostgreSQL
durable Job queue를 추가합니다. Run 제출은 idempotent하고, Worker claim은 제한된 lease와
heartbeat를 사용하며, 중단된 lease는 queue에 다시 들어가고, 모든 transition은 audit event를
append합니다. PostgreSQL은 event table의 update 또는 delete 시도를 거부합니다.

schema v10은 SQLite와 PostgreSQL 모두에서 제출 및 lease 권위를 영속화합니다. canonical digest는
인증 actor, Campaign, input, idempotency key, Job kind와 retry limit을 결박합니다. 정확히 같은
재시도만 기존 Run을 반환하고 필드 하나라도 바뀌면 fail closed합니다. v9→v10 forward migration은
정확한 public submission graph만 재구성하며 모호한 legacy Run은 non-replayable로 표시합니다.
별도의 Job digest는 Job/Run ID, kind, payload, retry limit과 idempotency key를 결박하며 migration,
startup validation과 claim에서 이 결박을 다시 계산합니다. database guard는 migration 뒤 늦게
재개된 v9 insert, core row delete/replace와 identity 변경, 허용되지 않은 lifecycle transition,
terminal history 변경, 잘못된 JSON authority와 lease deadline 연장을 거부합니다. 각 lease에는
claim 뒤 최대 24시간인 절대 server deadline이 있고 heartbeat는 이를 연장할 수 없습니다. lease
갱신은 계속 영속화하되 audit heartbeat event는 60초당 최대 하나로 coalesce합니다.

mutation endpoint는 authentication 또는 parsing 전에 4 MiB를 넘는 request body를 거부합니다.
그 뒤 submit input, completion result와 checkpoint state에는 operation별 canonical JSON 한도
(UTF-8 최대 1,000,000 bytes 및 제한된 depth, node, key, key 길이, string 길이)를 적용합니다.
escaped 표기가 decode된 뒤 같은 이름이 되는 경우를 포함해 모든 depth의 duplicate object key는
422로 거부하고 wire-size 위반은 413입니다. 저장된 input, result와 checkpoint state는 소유권이
분리된 snapshot이므로 caller mutation이 저장 권위, digest 또는 signature를 바꿀 수 없습니다.

T3/T4 checkpoint 생성은 정확한 call fingerprint, Tool, target, tier, expiry를 기록합니다.
checkpoint payload는 database 외부에 보관된 key로 서명됩니다. Approver credential만 요청을
결정할 수 있고 Operator만 승인된 결정을 소비할 수 있습니다. resume은 checkpoint를 원자적으로
claim하고 continuation Job 하나를 만들기 전에 저장된 payload와 signature를 검증합니다.

선택적 server dependency를 설치하고 SQLite로 로컬 실행합니다.

```powershell
.venv\Scripts\python -m pip install -e ".[dev,control-plane]"
$env:PAJIN_CP_DATABASE_URL='sqlite:///./.pajin/control-plane.db'
$env:PAJIN_CP_OPERATOR_TOKEN='<distinct-random-operator-token>'
$env:PAJIN_CP_APPROVER_TOKEN='<distinct-random-approver-token>'
$env:PAJIN_CP_WORKER_TOKEN='<distinct-random-worker-token>'
$env:PAJIN_CP_WORKER_SUBJECT='worker-service'
$env:PAJIN_CP_REPLAY_WORKER_TOKEN='<distinct-random-replay-worker-token>'
$env:PAJIN_CP_REPLAY_WORKER_SUBJECT='replay-worker-service'
$env:PAJIN_CP_REPLAY_EXECUTOR_PROFILES='{"replay-worker-service":["kisa-exact-v1"]}'
$env:PAJIN_CP_CHECKPOINT_KEY='<random-signing-key-at-least-32-bytes>'
# portable_attestation batch에서만 세 값을 모두 함께 설정합니다.
$env:PAJIN_CP_REPLAY_ATTESTATION_KEY_ID='<active-key-id>'
$env:PAJIN_CP_REPLAY_ATTESTATION_PRIVATE_KEY='<base64url-raw-32-byte-ed25519-seed>'
$env:PAJIN_CP_REPLAY_ATTESTATION_TRUST_ANCHOR='<one-line-trust-anchor-json>'
# 선택적 B2.8a executor transport이며 Control Plane에는 공개 trust만 설정합니다.
$env:PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR='<one-line-executor-trust-anchor-json>'
$env:PAJIN_CP_ARTIFACT_STAGING_ROOT='C:\private\pajin-artifact-staging'
$env:PAJIN_CP_ARTIFACT_REPOSITORY_ROOT='C:\private\pajin-artifact-repository'
.venv\Scripts\pajin-control-plane
```

Artifact root 두 개는 선택 사항이지만 둘을 함께 설정하거나 둘 다 생략해야 합니다. 두 directory는
Control Plane service account만 접근할 수 있게 하고 Worker 또는 사용자가 통제하는 tree 밖에
두십시오. staging은 명시적인 handoff 경계이며 repository object path는 서버가 소유하므로 Artifact
consumer에게서 입력받지 않습니다. 두 값을 생략하면 managed Artifact admission과 Replay-batch
source resolution은 사용할 수 없으며 fail closed합니다. 현재 durable admission은 directory
`fsync`를 지원하는 POSIX filesystem/runtime도 필요하며, 미지원 환경에서는 fail closed합니다.

executor signer와 Control Plane 공개 anchor를 설정하면 Replay finalization은 shared staging
volume에 의존하는 대신 content-addressed bundle을 운반합니다. 첫 transport 상한은 raw 전체
2 MiB, file당 1 MiB, 256 files, depth 24입니다. Control Plane은 bytes를 복사하기 전에 외부
서명을 검증하고 기존 Run·receipt·seal을 다시 검증합니다. 이는 executor 관찰 증거이지
target-issued receipt가 아니므로 `needs-review` confirmation 상한을 해제하지 않습니다.

Operator credential은 다음 공개 Replay admission API를 사용할 수 있습니다.

- `POST /v1/replay/source-artifacts`: opaque staging ID와 완료된 producer Run/Job ID만 받아
  서버가 봉인된 source를 managed Artifact로 반입합니다. 신뢰된 producer가 봉인 Run을 설정된
  server-controlled staging handoff에 먼저 배치해야 하며, 이 endpoint는 파일 upload나 path import
  API가 아닙니다.
- `POST /v1/replay/batches`: confirmed baseline의 정확한 `(artifact_id, repository_version)` locator,
  선택적인 부모 Retest locator와 idempotency key만 받습니다. 부모 Retest를 생략하면 confirmation,
  제공하면 baseline-bound `remediation-retest` Candidate/contract/Replay compilation을 서버가
  `planned` 상태로 파생합니다. Confirmation에서만 명시적 `claim_projection: true`를 사용하면
  exact KISA M03·M06·A04의 validity·impact·severity item을 각각 파생하고 v3 Claim별 projection
  authority와 `claim-replays.json`을 발행합니다. 부모 Retest locator와 함께 사용할 수 없습니다.
  `portable_attestation: true`를 추가하면 `pajin.kisa-claim-attestation:v3` 정책을 선택하고 전체
  Claim receipt authority에 대한 Ed25519 bundle을 봉인합니다. 세 attestation 설정이 모두 있고
  서로 일치하지 않으면 fail closed합니다.

`GET /v1/replay/batches/{batch_id}`, `/items/{item_id}`, `/tickets/{ticket_id}`,
`/tickets/{ticket_id}/finalization`, `/batches/{batch_id}/projection`,
`/batches/{batch_id}/attestation` 및 `/v1/replay/attestation/trust-anchor` 조회는 Operator, Approver,
Auditor가 사용할 수 있습니다.
응답에는 staging ID, repository storage key, lease token이 포함되지 않습니다. 이 공개 표면은 raw
path/URL, caller-authored Candidate·contract·Capability·Tool request·verdict 또는 내부 Replay Job kind를
받지 않습니다. 첫 시도 Job/ticket 발행은 계속 신뢰된 내부 service operation이며 공개 admission이
암시적으로 Tool을 dispatch하지 않습니다.

trust-anchor endpoint는 공개 material을 운반할 뿐 신뢰를 설정하지 않습니다. 별도 운영 채널로
anchor를 export·pin한 뒤 내려받은 bundle을 다른 host에서 검증합니다.

```powershell
.venv\Scripts\pajin replay-attestation-verify .\bundle.json `
  --trust-anchor .\pinned-trust-anchor.json
```

회전 시 이전 공개키는 `retired`, 새 key 하나만 `active`로 둡니다. `retired` key는 유효 기간 안의
과거 bundle을 검증할 수 있고 `revoked` key는 항상 fail closed합니다. 이 proof는 선택한 Control
Plane trust domain이 exact Claim receipts에 서명했다는 뜻이며, 별도 조직·Worker·target이
실행하거나 attest했다는 뜻은 아닙니다.

SQLite는 로컬 compatibility store이며 production multi-Worker queue가 아닙니다. SQLite 변경
transaction은 즉시 writer reservation을 획득해 프로세스 간 claim 및 completion state machine을
직렬화하고, 순수 get/list 작업은 rollback-only snapshot read를 사용해 해당 writer reservation을
획득하지 않습니다. 대신 loopback에서 PostgreSQL lab을 실행합니다.

```powershell
docker compose -f containers/compose.control-plane.yaml up --build --detach --wait
$env:PAJIN_TEST_POSTGRES_URL=`
  'postgresql+psycopg://pajin:pajin-control-plane-lab-password@127.0.0.1:55432/pajin_test'
.venv\Scripts\pytest -q tests/test_control_plane_postgres.py
Remove-Item Env:PAJIN_TEST_POSTGRES_URL
docker compose -f containers/compose.control-plane.yaml down --volumes
```

Compose credential은 격리된 로컬 lab용 공개 fixture입니다. 운영 배포에는 secret manager, TLS
termination, network isolation, 서로 다른 role credential, 별도로 보관한 signing key, database
backup, 관리되는 schema migration이 필요합니다. 상태 및 위협 경계의 자세한 내용은
[`ADR 0011`](docs/adr/0011-durable-control-plane.ko.md)을 참고하십시오.

### Web Console preview

Control Plane은 `http://127.0.0.1:8090/ui`에서 dependency가 없는 same-origin 운영자 shell을
제공합니다. shell 자체에는 Run data가 없고 공개되어 있어 URL이나 cookie에 credential을 넣지
않고도 browser가 불러올 수 있습니다. 모든 `/v1` data call에는 기존 Bearer role check가 계속
필요합니다. 위 server를 시작한 뒤 URL을 열고 Operator, Approver, Auditor credential 중 하나를
입력합니다.

첫 Console slice는 다음 기능을 지원합니다.

- 인증된 session-role 탐색
- 등록된 `campaign` 또는 `tool-loop` Job kind의 Operator 전용 idempotent Run 제출
- state filtering과 stable pagination이 있는 제한된 Run 목록
- 선택한 Run input 및 append-only event 확인
- checkpoint 실행 상태를 노출하지 않는 최소화된 current-approval intent 검토
- Approver 전용 승인 또는 거부. 거부하면 Run이 `cancelled`로 종료됨
- Operator 전용 일회성 checkpoint resume 및 idempotent Run cancellation
- WebSocket 또는 SSE state가 없는 선택적 5초 polling

Run 목록은 summary DTO를 반환하며 제출된 input을 bulk-load하거나 노출하지 않습니다. 선택한 Run
detail은 계속 authorization을 적용하며 해당 input을 포함합니다. browser credential은 JavaScript
memory에만 존재합니다. cookie, local/session storage, IndexedDB, credential URL, 외부 asset을
사용하지 않습니다. lock, refresh, tab close, HTTP 401은 in-memory 값을 지웁니다. 제한적인 CSP,
no-store cache policy, no-referrer policy, same-origin isolation header, text-only DOM rendering은
browser attack surface를 줄입니다.

cancellation은 queue에 있거나 lease된 Job을 원자적으로 fence하고 active lease material을 지우며
pending 또는 approved decision을 revoke하고 제한된 actor/reason event를 기록합니다. executor가
활성 상태일 때 다음 heartbeat가 거부되면 first-write-wins cancellation context가 활성화됩니다.
Worker는 강제 async task cancellation 전에 executor에 제한된 cooperative cleanup grace period를
줍니다. 내장 Local Campaign 및 Tool Loop runner는 engine cleanup 뒤 `cancellation.json`을
봉인하고, 신뢰된 Job executor는 소유한 execution stack이 unwind된 뒤 `quiescence.json`을
append합니다. engine이 이미 반환했다면 completion, failure, checkpoint conflict가 즉시 결과를
fence하고 원인을 daemon status에 기록합니다. runner를 다시 열거나 cancellation receipt를
합성하지 않습니다. 어느 receipt도 Control Plane acknowledgement가 아닙니다. 외부 side effect를
rollback하거나 해당 로컬 process 외부의 physical quiescence를 증명하지 않습니다.

이 기능은 로컬 single-tenant preview이며 production identity 경계가 아닙니다. 원격 사용 전에
HTTPS가 API 앞에서 terminate되어야 합니다. 보고서 download, Agent Graph, user account, tenant
isolation, fleet-wide approval queue는 아직 구현되지 않았습니다. 자세한 내용은
[`ADR 0022`](docs/adr/0022-same-origin-control-plane-web-console.ko.md),
[`ADR 0023`](docs/adr/0023-fenced-control-plane-actions.ko.md),
[`ADR 0024`](docs/adr/0024-cooperative-execution-cancellation.ko.md)를 참고하십시오.

### Lease-aware Worker daemon

`pajin-worker-daemon`은 queue의 Control Plane Job을 기존 PAJIN engine Run으로 변환합니다. 제한된
async HTTP connection pool 하나를 유지하고, 설정된 Job kind만 claim하며, 실행 및 finalization
전반에 heartbeat를 보내고, 일시적 completion call을 재시도합니다. executor가 활성 상태인 동안
Run cancellation, lease loss, heartbeat unavailable, daemon shutdown은 typed cancellation
context에 signal을 보냅니다. 실행이 반환된 뒤에는 finalization conflict가 새 cooperative
runner-cleanup phase가 아니라 즉시 적용되는 result fence입니다. authentication 거부는 fatal입니다.
SIGTERM은 새 claim을 멈추고 active executor에 제한된 cooperative cleanup grace period를 준 다음
fallback으로 forced task cancellation을 사용합니다.

초기 신뢰 registry에는 다음 항목이 있습니다.

- `campaign`: strict embedded Campaign manifest → deterministic `LocalCampaignRunner`
- `tool-loop`: strict embedded Campaign and prompt → real `PolicyToolLoopRunner`

어떤 Job field도 command, Python module, class, executable, 임의 매니페스트 path를 지정할 수
없습니다. unknown kind와 invalid payload는 fail closed됩니다. Docker Tool Loop는 no-network
결정론적 Provider fixture와 안전한 T3 mock Tool을 사용하면서 Provider Gateway, Secret Lease,
Capability, policy, checkpoint, approval 동작을 유지합니다. cancellation source 선택은
first-write-wins이므로 이후 shutdown이나 transport failure가 원래 원인을 다시 명명할 수 없습니다.
cleanup이 완료되면 local runner receipt가 Run evidence와 함께 봉인됩니다. receipt가 없다는 사실이
cleanup 성공을 뜻하지는 않습니다.

이 내장 Adapter는 실제 target 또는 Provider 실행이 아니라 명시적인 검증 profile입니다. 완료된
Job result에는 `executionProfile`과 canonical `executionContext`가 포함되고, 같은 context가
`execution-context.json`으로 봉인되어 completion 수락 전에 `run.json`과 결박됩니다. 따라서 기본
profile은 `simulated: true`, `evidenceScope: simulated-development-only`를 보고합니다. Docker-backed
Adapter는 `worker-observed-execution`을 보고하고, 그 밖의 custom backend는 실제 target 증거로
승격되지 않고 `custom-backend-unclassified`로 남습니다.

| Worker 설정 | 기본값 및 허용 범위 | 경계 |
| --- | --- | --- |
| `PAJIN_CP_URL` | HTTPS origin URL | Bearer 인증 transport는 기본적으로 HTTPS만 허용하며 credential, path, query, fragment, 잘못된 authority, HTTP(S) 이외 scheme을 거부 |
| `PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB` | `false`; 번들 Compose lab에서만 literal `true` | loopback 또는 `control-plane` Compose service 이름에만 HTTP를 명시적으로 허용하며 원격·production transport에서는 절대 활성화하지 않음 |
| `PAJIN_DAEMON_CANCELLATION_GRACE_SECONDS` | 2초; 0.05-30 | daemon이 `task.cancel()`을 호출하기 전 cooperative return |
| `PAJIN_DAEMON_CANCELLATION_FORCE_SECONDS` | 5초; 0.05-30 | forced task cancellation 이후 및 각 final drain의 제한된 wait |
| `PAJIN_DAEMON_STATUS_PATH` | `~/.pajin/status/worker-status.json` | Host 기본값은 shared가 아닌 사용자 home 아래에 있고 custom parent는 daemon 소유이며 group/other 쓰기가 불가해야 함 |

서버 lease timestamp는 보수적으로 local monotonic request-start 시점에 고정됩니다. 멈춘
heartbeat가 authority를 연장할 수 없도록 local deadline에서 두 daemon 모두 heartbeat I/O를
취소하고 grace 지연 없이 executor를 강제 quiesce하며 stale finalization을 거부합니다. 상태 갱신은
공통 dirfd 기반 exclusive random temp, fsync, atomic replace writer를 사용합니다.
status writer와 Tool Loop continuation-checkpoint writer에는 POSIX dirfd/`O_NOFOLLOW` 의미 체계가
필요합니다. native Windows daemon은 어느 write도 시작하기 전에 fail closed하며 Linux container
또는 WSL에서 실행해야 합니다. PowerShell 기반 Compose는 계속 지원됩니다.

daemon은 아직 pending인 task를 drain하기 위해 grace window 한 번, forced window 한 번, 추가
forced window 한 번을 사용할 수 있습니다. 따라서 process supervisor는
`grace + (2 * force)`에 scheduling margin을 더한 것보다 긴 시간을 허용해야 합니다. Compose
lab은 이 기본값을 고정하고 12초 daemon 경계를 넘는 15초 `stop_grace_period`를 사용합니다. 이는
asyncio deadline으로, process와 event loop가 실행될 때만 시간이 흐르고 synchronous blocking
code를 선점할 수 없습니다. `SIGKILL`, host loss, process isolation failure는 in-process cleanup을
완전히 우회합니다.

backend 자체의 cancellation cleanup도 daemon window 안에 들어와야 합니다. 독립 실행형
`DockerWorkerBackend`의 internal cleanup 제한은 20초입니다. 이 backend를 내장한 Adapter에는 기본
5초 forced window가 충분하지 않습니다. 현재 Control Plane Compose Adapter는 결정론적 in-process
profile이며 이를 내장하지 않습니다. 사용자 지정 Docker-backed Adapter는 20초보다 긴 forced
window를 사용하고 Supervisor 허용 시간을 그에 맞게 늘려야 합니다. 예를 들어 `grace=2`,
`force=25`, stop grace는 최소 60초로 설정합니다.

Control Plane Compose stack은 PostgreSQL, API, 일반 non-root Worker daemon 하나와 다음
절에서 설명하는 전용 Replay daemon을 함께 시작합니다.

```powershell
docker compose -f containers/compose.control-plane.yaml up --detach --no-build --wait
$env:PAJIN_TEST_CONTROL_PLANE_URL='http://127.0.0.1:18090'
.venv\Scripts\pytest -q tests/test_worker_daemon_live.py
Remove-Item Env:PAJIN_TEST_CONTROL_PLANE_URL
docker compose -f containers/compose.control-plane.yaml down --volumes
```

live test는 Tool Loop Job을 제출하고 daemon이 T3 checkpoint를 upload할 때까지 기다린 뒤 승인하고
resume하여 continuation Job이 실제 Tool Loop Adapter에서 완료되었는지 검증합니다. opt-in crash
test는 격리된 lab Worker container만 추가로 종료하고 PostgreSQL lease recovery를 검증합니다.

```powershell
$env:PAJIN_TEST_CONTROL_PLANE_URL='http://127.0.0.1:18090'
$env:PAJIN_TEST_WORKER_CRASH_CONTAINER='pajin-control-plane-lab-worker-daemon-1'
.venv\Scripts\pytest -q tests/test_worker_daemon_crash_live.py
Remove-Item Env:PAJIN_TEST_WORKER_CRASH_CONTAINER
Remove-Item Env:PAJIN_TEST_CONTROL_PLANE_URL
```

Job delivery는 at least once입니다. 외부 Tool side effect 뒤 durable completion 전의 crash는 해당
Tool을 replay할 수 있습니다. 따라서 production Adapter는 destination idempotency key를 전달하거나
replay risk를 명시적인 policy/approval 결정으로 만들어야 합니다. 일반 daemon의 Compose Run
output은 tmpfs를 사용하며 durable evidence store가 아닙니다.
[`ADR 0012`](docs/adr/0012-lease-aware-worker-daemon.ko.md)를 참고하십시오.

### 전용 Control Plane Replay Worker

`pajin-replay-worker-daemon`은
`python -m pajin.control_plane.replay_worker_main`과 같은 전용 single-Job daemon입니다. 일반
Campaign 또는 Tool Loop executor를 등록하지 않습니다. 권위 흐름은 다음과 같이 제한됩니다.

1. 인증된 Worker subject에 정확히 `kisa-exact-v1`이 allowlist된 서버 발행 `replay` Job만
   claim하고 ticket-bound lease와 fence를 heartbeat합니다.
2. canonical claim에서 정확한 KISA Campaign/Scenario/Tool context를 복원하고, 각 Gateway
   dispatch 직전에 ordinal-bound durable Tool permit을 발급받습니다.
3. 서버가 예약한 opaque staging slot 안에만 Replay Run을 쓰고 두 번 seal합니다.
4. profile, lease token, ticket, fence와 staging ID만 finalize합니다. Control Plane은 해당 slot을
   import하고 immutable copy를 다시 열어 두 seal과 모든 permit/request 결박을 검증하며, 공통
   confirmation Gate를 파생하고 Artifact와 schema-v9 append-only finalization을
   commit합니다. Finalized item은 batch 전체가 준비될 때까지 `verified`에 머뭅니다. 이후 서버는
   managed source를 수정하지 않고 복사해 전체 Replay Artifact를 다시 열고 봉인된
   `validation/v1alpha1` projection을 만든 뒤, source root·batch CAS·정렬된 finalization 집합이
   그대로일 때만 schema-v11 projection authority와 item/batch의 `gated`/`completed` 전이를
   commit합니다. 이때 permit 발급에서 budget/rate unit을 이미 소비한 authority를 다시 검증합니다.

Worker는 filesystem path, `ArtifactRef`, result, digest, Oracle verdict 또는 `confirmed`
disposition을 제출할 수 없습니다. Permit은 dispatch 전에 durable하게 소비되는 non-bearer
proof입니다. Permit이 하나라도 생긴 뒤 실행이 실패하면 해당 시도는 terminal이며 같은 Job/ticket을
자동으로 다시 dispatch하지 않습니다. 외부 destination은 여전히 exactly-once 또는 rollback을
제공하지 않습니다. 동일한 ordinal-bound permit 요청과 서버 finalize 요청의 정확한 response-loss
retry는 모두 멱등이며 어느 경로도 Tool을 다시 dispatch하지 않습니다. 현재 executor는
명시적인 M03, M06, A04 `ai.chat-probe` confirmation 계약만 지원하고 Secret Lease를 금지하며, 한
host의 Docker daemon을 사용합니다. 기존 경로는 shared POSIX staging을 사용하지만, 별도 executor
workload key를 설정한 bounded portable 경로는 Worker-local staging에서 sealed Run bytes와 exact
permit set을 서명해 다른 Control Plane host로 전달할 수 있습니다. 이 경로도 target이 직접 발행한
응답 증명은 아니며 Generic Replay executor, negative retest Worker 또는 대형 object-store 전송이
아닙니다.

Compose lab은 고정 Tool Worker 및 egress-proxy image를 build하고 owner-only volume initializer,
API, 일반 daemon, 전용 Replay daemon을 시작합니다. API와 Replay daemon은 모두 `10001:10001`로
실행되며 `/var/lib/pajin/artifact-staging`만 공유합니다. Managed repository volume은 API에만
mount됩니다. Initializer는 두 root를 해당 identity 소유, mode `0700`으로 만들고 symlink 또는 invalid
root에서는 fail closed합니다. Docker의 fresh named-volume root는 root-owned이므로 이 one-shot
initializer만 root와 `CHOWN` capability로 실행합니다. 각 고정 mount path를 no-follow 방식으로
root에 handoff한 뒤 같은 inode를 열어 검증하고, 해당 descriptor로 private mode와 최종 소유권을
적용한 다음 fsync하고 API 시작 전에 종료합니다. 모든 long-running PAJIN service는
계속 `10001:10001`입니다. Named Artifact volume은 일반 restart 뒤에도 남지만 local-lab storage일
뿐이며 `down --volumes`가 제거합니다.

Replay daemon에는 Docker CLI와 `/var/run/docker.sock`의 read/write bind mount가 필요합니다. Host가
socket을 group 0에 노출하지 않으면 socket group을 설정합니다.

```bash
export PAJIN_DOCKER_SOCKET_GID="$(stat -c '%g' /var/run/docker.sock)"
docker compose -f containers/compose.control-plane.yaml up --build --detach --wait
```

Replay daemon 시작 전에는 동일 UID, socket mount, supplemental group을 쓰는 networkless one-shot
preflight가 Docker server 접근, 고정 image 두 개, configured proxy uplink를 검사합니다. 하나라도
실패하면 Compose가 daemon 시작을 막습니다. 이 검사는 현재 lab wiring만 확인하며 Docker socket의
권위를 줄이지는 않습니다.

Docker Desktop lab 기본값인 supplemental group 0은 보통 VM socket과 일치합니다. Docker socket은
사실상 host-root 권위입니다. Docker API client가 시작하거나 mount할 수 있는 대상은 non-root UID,
dropped capability, read-only root filesystem, `no-new-privileges`로 제한되지 않습니다. 이 daemon을
untrusted code 또는 인증되지 않은 remote daemon에 노출하지 마십시오. Production에서는 전용 Docker
host 또는 별도 설계한 restricted broker가 필요합니다. 번들 Compose는 전용
`pajin-replay-uplink-lab` network를 생성하며, 다른 `PAJIN_REPLAY_EXTERNAL_NETWORK` override는
미리 존재해야 합니다. Proxy image preflight와 실행별 egress proxy만 이 uplink에 연결되고 실행
Worker는 호출별 internal network에 남습니다.

| Replay Worker 설정 | Compose 값 | 경계 |
| --- | --- | --- |
| `PAJIN_CP_URL`, `PAJIN_CP_REPLAY_WORKER_TOKEN` | HTTPS API origin, 별도 Replay Worker secret | 필수 인증 Replay transport이며 token은 Operator, Approver, 일반 Worker credential과 달라야 하고 Replay/일반 Worker route는 서로의 subject를 거부하며 production에서는 managed secret 필요 |
| `PAJIN_CP_ALLOW_PLAINTEXT_HTTP_FOR_LAB` | 번들 Compose에서만 `true`; 기본 `false` | `http://control-plane:8090`을 위한 좁은 local-lab 예외이며 원격 HTTP는 계속 거부되고 production은 HTTPS를 사용해야 함 |
| `PAJIN_REPLAY_WORKER_ID` | `pajin-compose-replay-worker-1` | Status identity일 뿐이고 Bearer principal이 authorization identity |
| `PAJIN_REPLAY_EXECUTOR_PROFILE` | `kisa-exact-v1` | Literal-only이며 `PAJIN_CP_REPLAY_EXECUTOR_PROFILES`와 일치해야 함 |
| `PAJIN_REPLAY_STAGING_ROOT` | `/var/lib/pajin/artifact-staging` | Owner-only root이며 legacy 경로는 공유하고 portable executor attestation 설정 시 Worker-local로 사용할 수 있으며 claim에는 opaque `stage_<uuid>`만 포함 |
| `PAJIN_REPLAY_EXECUTOR_ATTESTATION_KEY_ID`, `PAJIN_REPLAY_EXECUTOR_ATTESTATION_PRIVATE_KEY`, `PAJIN_REPLAY_EXECUTOR_ATTESTATION_TRUST_ANCHOR`, `PAJIN_CP_EXECUTOR_ATTESTATION_TRUST_ANCHOR` | unset | bounded portable transport에서는 Worker 세 값을 모두 함께 설정하고 Control Plane에는 공개 anchor만 설정하며 private seed를 노출하지 않은 채 서로 일치해야 함 |
| `PAJIN_REPLAY_LEASE_SECONDS`, `PAJIN_REPLAY_HEARTBEAT_SECONDS`, `PAJIN_REPLAY_LONG_POLL_SECONDS` | 30, 5, 10 | Lease 범위는 5-300초, heartbeat는 lease 절반 미만, long poll은 최대 20초 |
| `PAJIN_REPLAY_IDLE_DELAY_SECONDS` | 0.2 | 빈 queue long poll 사이의 polling 제한 |
| `PAJIN_REPLAY_RETRY_BASE_SECONDS`, `PAJIN_REPLAY_RETRY_MAX_SECONDS` | 0.25, 5 | 동일한 permit/finalize response-loss 요청의 제한된 backoff이며 Tool redispatch 권위가 아님 |
| `PAJIN_REPLAY_FINALIZE_ATTEMPTS` | 3 | 정확한 finalize 호출만 재시도하며 다른 권위는 conflict |
| `PAJIN_REPLAY_CANCELLATION_GRACE_SECONDS`, `PAJIN_REPLAY_CANCELLATION_FORCE_SECONDS` | 2, 25 | Cooperative/forced drain이며 25초는 Docker backend 20초 cleanup cap보다 큼 |
| `PAJIN_REPLAY_STATUS_PATH`, `PAJIN_REPLAY_HEALTH_MAX_AGE_SECONDS` | `~/.pajin/status/replay-worker-status.json`, 30 | Host 기본값은 private parent를 사용하고 Compose는 UID 소유 mode-0750 tmpfs를 명시하며 health input은 64 KiB로 제한되고 target 성공이나 physical quiescence를 attest하지 않음 |
| `PAJIN_REPLAY_DOCKER_EXECUTABLE`, `PAJIN_REPLAY_WORKER_IMAGE`, `PAJIN_REPLAY_EGRESS_PROXY_IMAGE`, `PAJIN_REPLAY_EXTERNAL_NETWORK` | pinned CLI path, 고정 `:dev` image 두 개, `pajin-replay-uplink-lab` | Image는 allowlist되며 암묵적으로 pull하지 않고, 번들 Compose는 전용 proxy uplink를 생성하며 override는 미리 생성해야 함 |

Compose `stop_grace_period` 65초는 설정된 `grace + (2 * force)` drain bound와 scheduling margin을
넘습니다. `SIGKILL`, Docker-daemon loss, host loss 또는 blocking kernel operation은 in-process
cleanup을 우회할 수 있으며, 이 경우 lease fencing과 보수적인 permit 소비가 권위 경계로 남습니다.
[`ADR 0029`](docs/adr/0029-control-plane-replay-orchestration.ko.md)를 참고하십시오.

## 동적 멀티 에이전트 engine

기본 Docker Worker에서 결정론적 5개 역할 팀을 실행합니다. simulated Worker는 명시적인
개발 또는 unit-test exercise에서만 선택합니다.

```powershell
.venv\Scripts\pajin multi-run examples\multi-agent.yaml

# 명시적인 개발/테스트 전용 실행
.venv\Scripts\pajin multi-run examples\multi-agent.yaml --worker simulated
```

Supervisor는 계획된 step마다 Specialist 하나를 만듭니다. 결정론적 Planner, Validator, Reporter
role에는 Tool call 권한이 없고, Provider-backed role은 등록된 Provider Tool과 endpoint만 받습니다.
Task는 명시적인 dependency graph를 구성합니다. T0/T1 Specialist failure는 retry slot이 배정된
경우에만 같은 grant 안에서 한 번 재시도할 수 있습니다. planning 후 Supervisor는 먼저
model-backed Validator와 Reporter role에 필요한 최대 downstream call을 예약한 다음 모든
Specialist에 하나씩 예약합니다. 남은 call은 plan 순서대로 각 T0/T1 Task에 최대 한 번의
재시도로 배정됩니다. 모든 Specialist의 첫 시도에 자금을 댈 수 없는 plan은 일부 fan-out 전에
실패합니다. Semantic Validator는 target이 선언되어 있고 인용한 모든 artifact가 같은 Run의
Specialist가 만든 경우에만 Candidate를 지지할 수 있습니다. catalog에 있는 KISA
`ai.chat-probe` 시나리오에서는 Tool이 없는 신뢰 Candidate Producer가 validation 전에 raw
transcript check를 독립적으로 다시 계산합니다. Tool, Candidate Producer, 결정론적 Validator는
같은 엄격한 `AIChatProbeOutput` 계약을 parse하며 Worker가 작성한 `matched` 또는 `vulnerable`
verdict field를 신뢰하지 않습니다. 정확한 Validator Agent/Task identity, Finding 및 Candidate에
결박된 assessment는 같은 봉인 Run snapshot의 `validator-output.json`에 보존됩니다. 영속 Control
Plane derivation은 이 artifact를 다시 읽어 Gate를 replay하며 Candidate 자체에서 semantic support를
재구성하지 않습니다. 이 semantic authority 결박 자체는 독립 재현, 제품 confirmation 또는
remediation을 입증하지 않습니다. 따라서 Finding을 반환하지 않는 Semantic Validator는
observation을 삭제하지 않고 `needs-review` Candidate로 남깁니다. semantic support가 일치하고
공통 objective Gate를 통과하더라도 `independent-reproduction-missing`인 `needs-review`로 남으며,
fresh Restricted Reproducer 결과가 생기기 전에는 confirmed compatibility projection에 들어갈 수
없습니다. Producer의 request 또는 target/threat authority 안에 있는 Validator-only claim은 review
Candidate로 남고, cancellation이나 Validator failure가 발생하면 이미 관찰 가능한 Candidate를
`inconclusive`로 보존합니다.

Specialist concurrency는 Tool 계약의 opt-in 항목입니다. 기본값은 `parallelSafe: false`입니다.
opt-in하지 않은 Tool은 plan 순서에서 single-task barrier로 실행됩니다. 연속된 opt-in Task는 기본
limit이 4인 제한된 local wave에서 실행되고, validation과 reporting 전에 결과가 plan 순서로
복원됩니다. Kill Switch를 활성화하면 실행 중인 sibling Worker가 취소됩니다. 이 로컬 cooperative
scheduler는 distributed 또는 crash-durable reservation을 제공하지 않습니다.

실행 중인 Worker에 live Kill Switch가 전달되는지 검증합니다.

```powershell
.venv\Scripts\pajin multi-cancel-check examples\multi-agent-cancel.yaml --worker docker
```

운영자가 시작한 Run에서는 `multi-run`이 `--kill-file <path>`도 받습니다. 이 파일을 만들면 단방향
Kill Switch가 활성화되어 실행 중인 operation을 취소하고 pending graph Task를 cancelled로 표시하며
전체 Capability lineage를 revoke하고 이유를 기록합니다. Docker cancellation은 실행 중인
container와 실행별 egress resource를 강제로 제거합니다.

## Docker Worker

체크인된 hash lock만으로 개발 image 두 개를 직접 build합니다.

```powershell
docker build --tag pajin-worker:dev containers/worker
docker build --tag pajin-egress-proxy:dev containers/egress-proxy
```

`containers/worker/requirements.lock`은 distribution hash로 MCP v1 SDK와 모든 transitive
dependency를 고정합니다. Worker Dockerfile은 이 lock을 `--require-hashes`와 `--only-binary`로
직접 설치하므로 생성되거나 Git에서 무시되는 `vendor/` tree가 필요하지 않습니다. 체크인된 모든
Dockerfile은 base image도 multi-platform manifest digest로 고정합니다. Build는 선택된 binary
wheel이 cache에 없으면 설정된 package index에서 내려받습니다. Hash lock은 재현성을 제공하지만
offline build를 뜻하지는 않습니다.

`containers/worker/requirements.in`을 의도적으로 변경한 뒤에는 체크인된 lock을 갱신합니다.

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File scripts/prepare-worker-dependencies.ps1
```

이 스크립트는 환경 marker를 보존하는 universal resolution을 수행합니다. Linux Docker build는
비-Linux 분기를 무시하고 amd64와 arm64는 같은 체크인 hash lock을 사용합니다. 스크립트는
lock만 갱신하며 vendor tree를 만들지 않습니다.

container 안에서 실제 적용된 isolation control을 검증합니다.

```powershell
.venv\Scripts\pajin worker-check
```

Docker Worker에서 Campaign을 실행합니다.

```powershell
.venv\Scripts\pajin run examples\ai-redteam.yaml --worker docker
```

Docker backend는 다음 고정 profile을 적용합니다.

- image allowlist 및 `--pull never`
- Tool Gateway가 egress policy를 주입하지 않으면 network namespace를 `none`으로 설정
- read-only root filesystem
- 모든 Linux Capability 제거
- `no-new-privileges`
- non-root UID/GID `65532`
- 제한된 writable tmpfs workspace
- CPU, memory, PID, execution-time, stdout, stderr 제한
- timeout, cancellation, 예상치 못한 base exception 뒤 제한된 forced-container 및 실행별
  egress-cleanup 시도

## Egress proxy

실제 public HTTP 예제를 실행하여 허용된 traffic, 거부된 traffic, direct-socket 우회 차단을
검증합니다.

```powershell
.venv\Scripts\pajin run examples\egress-proxy.yaml --worker docker
.venv\Scripts\pajin egress-check
```

target lab과 host-facing Control Plane/PostgreSQL network는 loopback published port를 유지하기 위한
일반 Docker bridge입니다. service attachment는 분리하지만 container outbound traffic을 차단하지는
않습니다. Production에서는 PAJIN의 실행별 proxy 경계와 별도로 host firewall 또는 동등한 egress
control이 필요합니다.

Worker는 실행별 `--internal` network에만 연결됩니다. 전용 proxy는 이 network와 external Docker
bridge에 연결되고 DNS resolution 뒤 destination을 다시 검증하며 allow/deny decision을 실행
evidence에 기록합니다. 평문 HTTP path와 method는 직접 집행됩니다. HTTPS는 CONNECT를 사용하므로
proxy는 authority-wide rule만 집행합니다. host-wide allow rule만 받아들이고 해당 authority에
deny rule이 하나라도 있으면 전체 tunnel을 거부합니다. 암호화된 정확한 method와 path는 proxy
inspection이 아니라 Gateway가 선택한 고정 Worker action에 결박됩니다. CONNECT event는
`receiptEligible=false`, `methodEnforcement=trusted-worker-only`,
`pathEnforcement=authority-only`를 명시하므로 HTTP request/response receipt가 아닙니다. Policy
input과 response buffering은 제한되며, 고정 64 MiB proxy는 OOM에 의존하지 않고 8 MiB를 넘는
response limit 설정을 실행 전에 거부합니다.

## 등록된 MCP Tool

demo는 격리된 Worker 안에서만 stdio를 통해 공식 MCP Python SDK를 사용합니다.

```powershell
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker simulated
.venv\Scripts\pajin run examples\mcp-tool.yaml --worker docker
.venv\Scripts\pajin mcp-check
```

bridge는 MCP session을 초기화하고 server가 알린 Tool 목록을 검증하며 Worker의 고정 catalog에 있는
Tool만 호출합니다. Agent와 host-side Adapter 모두 executable path나 임의 process argument를
제공할 수 없습니다. `mcp-check`는 unknown server 및 Tool ID가 실제 Worker에서 fail closed됨도
증명합니다.

Worker Job standard input은 audit metadata에서 byte length와 SHA-256 digest로 표현됩니다. raw
Worker stdout, stderr, egress decision log는 재현을 위해 보호된 evidence artifact에 보관됩니다.
query 값은 proxy log에서 redact됩니다.

Run artifact는 `.pajin/runs/<campaign>/<run-id>/` 아래에 작성됩니다.

```text
campaign.json
run.json
events.jsonl
plan.json
candidate-findings.json
validation-decisions.json
validation-index.json
findings.json
report.md
evidence/
run-integrity.jsonl
agents.json
task-graph.json
capabilities.json
budget.json
rate-limits.json
control.json
kisa-replay-index.json  # kisa-run only
validation/v1alpha1/    # verified replay Decision/Finding/report projection, when applied
  claim-replays.json    # exact validity/impact/severity Claim ↔ replay lineage and outcome
```

Restricted Reproducer는 별도 replay Run을 사용합니다. `replay/` directory에는 Validation Packet,
Mode contract, non-executable intent, compiled spec, dedicated grant, attempt, Oracle result,
aggregate outcome, verification receipt가 저장됩니다. 첫 integrity seal은 outcome과 전체 artifact
set을 결박하고, receipt는 검증된 root를 기록하며, 두 번째 seal은 receipt를 결박합니다.
`kisa-run`과 명시적 Local `run --kisa-replay` 경로는 source Run을 봉인한 뒤 정확한 M03, M06, A04
Candidate에 이 경계를 조정합니다. 그런 다음 replay Run path를 공통 Gate에 전달하고, Gate는
변경 가능한 in-memory record를 신뢰하는 대신 canonical receipt를 다시 불러옵니다. Local 경로는
one-process/one-writer 오케스트레이션이며 Control Plane lease, cross-process Gate locking,
PostgreSQL replay authority를 제공하지 않습니다.

`kisa-retest`도 같은 receipt loader와 Restricted Reproducer 경계를 사용하지만 확인 목적은
분리합니다. parent retest Run의 정상 기능 결과를 negative proof로 재해석하지 않고, 봉인된
baseline Candidate에 결박된 별도 replay Run만 `fixed`·`still-vulnerable` 판정에 사용합니다.
retest assessment에는 baseline과 remediation lineage, replay Run/Outcome/request/evidence ID,
Oracle verdict와 receipt seal lineage가 포함됩니다. versioned projection과 기존 baseline seal
entry는 immutable하며, remediation plan append 후 확정된 current root가 retest receipt에
결박됩니다.

Candidate 및 Decision snapshot은 legacy Validator가 반환한 모든 Finding과 활성화된 신뢰 Candidate
Producer가 수용한 모든 observation을 결정론적 disposition과 함께 보존합니다.
`validation-index.json`은 ID-only status view이고 legacy flat `findings.json`은 변경 불가능한
pre-replay compatibility snapshot으로 유지됩니다. 새 consumer는 봉인된
`validation/v1alpha1/index.json`을 우선합니다. 이 파일의 Decision, Finding, Markdown artifact에는
confirmation basis, superseded source Decision, replay Run/Outcome, request ID, artifact digest,
receipt-seal lineage가 포함됩니다. 과거 flat confirmation은 legacy로 읽히며 reproduction-backed
projection으로 승격되지 않습니다. 새 projection은 정확한 validity·impact·severity Claim과
각각의 Replay Run·Outcome·request·evidence·Oracle·receipt 계보를 `claim-replays.json`에 별도로
봉인합니다. KISA 경로는 일부 Claim 누락이나 다른 Claim receipt 치환을 거부합니다. 내부
confirmation Decision은 validity만 구동하며 impact·severity는 정보 전용입니다. 현재 신뢰
Producer는 정확한 KISA AI chat catalog 계약으로
제한됩니다. generic `vulnerable` field를 신뢰하지 않고 Semantic Validator에 attack 또는 replay
Tool을 주지 않습니다. 원자적 생산 과정은 request 및 target/threat confirmation 공간도 예약하므로
Validator가 legacy Adapter를 통해 Candidate 0개 결과를 우회할 수 없습니다.

Mode Pack extension은 연결된 integrity seal을 append하기 전에 `ctf-result.json`,
`ctf-writeup.md`, KISA assessment file, Bug Bounty triage 초안 같은 artifact를 추가할 수 있습니다.

## Evidence integrity 검증

완료된 모든 로컬 Run은 `run-integrity.jsonl`을 작성합니다. store 초기화 뒤 cancellation을 관찰한
내장 Local Campaign 또는 Tool Loop Run은 `cancellation.json`을 봉인합니다. 신뢰된 Control Plane
executor는 두 번째 integrity extension에 `quiescence.json`을 append할 수 있습니다. 각 seal은 새
artifact path, byte size, media type, SHA-256 digest, 사용 가능한 request/Tool/Worker provenance,
현재 Audit Event chain head, 이전 seal root를 결박합니다. Core 실행이 첫 seal을 만들고, KISA
assessment, remediation/retest, Bug Bounty triage, direct Tool Loop checkpoint claim은 현재 root를
검증한 뒤 extension seal을 append합니다.

evidence를 소비하거나 전송하기 전에 Run을 검증합니다.

```powershell
.venv\Scripts\pajin evidence-verify <run-directory>
```

봉인된 파일의 변경 또는 누락, 봉인되지 않은 파일 추가, Audit Event 순서 변경 또는 편집, 잘못된
seal link, 일치하는 extension seal 없는 event append가 있으면 검증에 실패합니다. 봉인된 artifact는
`RunStore`로 덮어쓸 수 없습니다.

root digest는 결정론적 로컬 변조 탐지를 제공하지만 signer identity나 Run 및 외부에 anchor되지
않은 모든 digest를 교체할 수 있는 privileged actor에 대한 보호는 제공하지 않습니다. 운영
배포에서는 표시된 root를 독립적으로 서명된 transparency 또는 object-store record에 게시해야
합니다.

## Test 및 lint

```powershell
.venv\Scripts\python -m pytest
.venv\Scripts\ruff check src tests containers
.venv\Scripts\mypy src
```

SHA로 고정한 [Linux CI workflow](.github/workflows/ci.yml)는 모든 pull request와 `main` push에서
Ubuntu 24.04와 Python 3.12를 사용해 잠금 dependency 설치, Ruff, mypy, 전체 기본 pytest suite를
실행합니다.

기본 suite는 live infrastructure test를 environment-gated 상태로 유지합니다. Control Plane 및
Worker-daemon live test에는 `PAJIN_TEST_CONTROL_PLANE_URL`을, 격리된 PostgreSQL integration
test에는 `PAJIN_TEST_POSTGRES_URL`을 설정합니다. Worker crash-recovery test에는 격리된 test
container 이름을 지정하는 `PAJIN_TEST_WORKER_CRASH_CONTAINER`도 필요합니다. Docker smoke check와
Mode Pack lab에는 실행 중인 Docker daemon과 문서에 설명된 로컬 image 또는 Compose fixture가
필요합니다.

## 아키텍처 규칙

`ProviderAgentRuntime`은 network-backed planning 및 validation을 위한 유일한 운영 경로입니다.
모든 model call은 `PolicyBoundProviderPort`, Tool Gateway, Campaign budget, run-scoped Secret
Lease에 결박됩니다. `PydanticAIAgentRuntime`은 결정론적 test를 위한 PydanticAI의 정확한 로컬
`TestModel`만 허용하며, model name, 일반 model 및 subclass는 Agent 생성 전에 거부합니다. 모든
MCP, CLI, browser, sandbox 및 network-backed model call은 PAJIN 정책 경계를 통과해야 합니다.

[제품 계획](docs/PAJIN_PRODUCT_PLAN.ko.md), [KISA 추적성 매트릭스](docs/KISA_TRACEABILITY.ko.md),
전체 [ADR 결정 기록](docs/adr/)을 참고하십시오. 최신 구현 결정은
[ADR-0019](docs/adr/0019-bounded-ctf-suite-orchestration.ko.md),
[ADR-0020](docs/adr/0020-specialist-call-budget-allocation.ko.md),
[ADR-0021](docs/adr/0021-opt-in-specialist-concurrency.ko.md),
[ADR-0022](docs/adr/0022-same-origin-control-plane-web-console.ko.md),
[ADR-0023](docs/adr/0023-fenced-control-plane-actions.ko.md),
[ADR-0024](docs/adr/0024-cooperative-execution-cancellation.ko.md),
[ADR-0025](docs/adr/0025-candidate-validation-ledger-and-replay-boundary.ko.md),
[ADR-0026](docs/adr/0026-trusted-kisa-candidate-admission.ko.md),
[ADR-0027](docs/adr/0027-independent-reproduction-confirmation-boundary.ko.md),
[ADR-0028](docs/adr/0028-durable-local-replay-ticket-ledger.ko.md), 그리고
[ADR-0029](docs/adr/0029-control-plane-replay-orchestration.ko.md)입니다.
