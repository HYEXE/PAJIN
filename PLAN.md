# PAJIN 구현 계획

이전 8개 개선에 이어 2026-09-09 요청의 새로운 5개 개선도 아래 범위의 구현·검증을 완료했다. 구현·권한 경계는 코드와
버전형 계약, 결정 근거는 채택된 ADR, 실행 결과와 Git 상태는 `HANDOFF.md`에서 확인한다.
과거 Phase의 상세 구현 이력은 각 계약을 참조하며 이 파일에 누적하지 않는다.

## 현재 순차 후속 목표 (2026-09-11)

이번 요청의 다섯 과제를 새 goal로 관리하며 토큰 예산은 지정하지 않는다. 시작 기준은
`main`의 `a599818c7df10e738dd044fe886eb1a6a423fc36`이다. upstream·실제 원격은
`3c66c2e3824d86c0a38bb82fbe69e8cb52ce320a`이고 로컬 문서 커밋 하나가 앞서 있다.
시작 worktree 하나는 깨끗하며 진행 중 Git 작업은 없다. 기존 커밋을 보존한다.

1. [ ] **DOCS-FINAL-002 상태 불일치 수정** — SYS-002/GRAPH-PERF-002/OPS-003 계약의
   로컬 실증과 기존 원격 CI/Web/Network/AI 범위를 대조한다. 문서 검사·diff 검토 후
   추가 문서 commit과 기존 `a599818`을 포함한 push를 별도 승인받고 새 일반 CI를 확인한다.
2. [ ] **EFFECT-004 실패 진단·탐지 정밀도** — 관측한 단계/범주만 공개 가능한 고정 값으로
   분류하고 unknown·보수적 차감·재시도/환불 금지·기존 wire/reader를 유지한다. 정상·거부·실패·
   비노출 회귀 후 새 후보/독립 정답/미사용 과제/모델/seed/반복/성공 규칙/지문을 고정한다.
   동일 실제 응답으로 baseline과 비교하고 표본·실패·혼동행렬·정밀도/재현율·편차·시간/토큰/비용을
   기록한다. 개선 미확인은 그대로 보고하며 기존 기본값과 false Finding authority를 유지한다.
3. [ ] **GRAPH-PERF-003 메모리·동시 조회** — 같은 환경/데이터/반복의 지연·CPU·peak RSS·
   live/retained allocation·I/O·동시 reader를 먼저 측정한다. 측정 병목만 최소 수정하고 동일 조건으로
   비교한다. 모든 과거 증거 검증·cursor/current head·권한·변조 거부·무효화/크기/fallback을 유지한다.
   실험 메모리 예산과 부하의 근거를 명시하며 운영 SLO·최대 규모 보장으로 확대하지 않는다.
4. [ ] **OPS/SYS 전용 Linux CI** — 기존 두 실제 probe를 독립 workflow에 연결한다. 잠금 의존성·
   정확한 clean commit·현지 빌드 이미지·PG17/TLS/mTLS·실제 실행·항상 실행되는 cleanup과 독립
   잔여 자원 검사를 요구한다. 공개 artifact는 비밀정보 없는 요약만 포함한다. 로컬 경계 검증 후
   commit/push/실행을 별도 승인받고 동일 신규 커밋의 CI/Web/Network/AI/OPS/SYS 결과를 확인한다.
5. [ ] **SYS-003 Operator API·Console 조회** — 배포자가 고정한 증거/trust/Run만 기존 독립 reader로
   조회한다. 인증/역할/Campaign 경계·false Finding/general-System authority를 유지한다. 정상·
   미구성·빈 결과·권한 거부·Campaign 혼합·변조·조회 실패와 기존 CLI/API를 검증한다.
   실제 봉인 결과/독립 reader 일치, HTTP 브라우저·키보드·반응형을 확인한다. 조회는 실행을 만들지 않는다.

①→②→③→④→⑤ 순서로 진행하며 승인이나 필수 외부 조건이 필요한 부분만 대기한다.
독립적인 로컬 구현은 계속한다. main에서 작업하고 새 branch/worktree/subagent는 만들지 않는다.
각 변경의 집중 pytest, 전체 Ruff, Linux strict mypy와 새 namespace scripts 별도 타입 검사,
필요한 모델/DB/Docker/API/CLI/packaging/브라우저, 최종 회귀 및 diff를 검증한다.
새 commit·push·workflow 실행·배포는 기존 승인을 재사용하지 않고 구체적 검토안으로 승인받는다.

## 이전 목표의 완료 상태

이전 모든 goal은 완료 상태를 유지한다. 가장 최근 문서 반영·EFFECT-003·OPS-003·GRAPH-PERF-002·
SYS-002는 정해진 범위에서 완료했다. EFFECT-003의 384시도/382응답/2실패 및 정밀도 하락은
기록된 실험 결과이며 이전 goal을 미완료로 돌리는 사유가 아니다. 기본 탐지기는
`novel-opaque-output-v1`이다. 소비된 EFFECT-002/003 평가군은 개발 자료로만 사용한다.

제품 기준 `3c66c2e`의 로컬/원격 pytest는 각각 8,342 passed·기존 76 skipped이고 원격
Quality·24 shard·Web/Network/AI가 첫 시도에 통과했다. OPS-003/SYS-002 자체의 실제 Linux
검증은 로컬 결과이며 전용 원격 workflow는 아직 없다. `a599818`은 최종 원격 결과의 운영 문서
세 개만 담은 승인된 로컬 커밋이다. 이 기록은 새 소스의 CI 또는 새 실행 승인이 아니다.

## 제품 목표와 현재 지원 범위

PAJIN은 9개 Security Domain을 하나의 Canonical Graph와 Capability authority model로 다루는
정책 기반 보안 분석·검증 플랫폼을 지향한다. 도메인 등록, 준비 모델, 외부 서명 증거의 검증,
실제 실행과 분석 효과를 각각 구분한다. 등록된 도메인 수는 지원 완료나 탐지 성능 지표가 아니다.

| 영역 | 현재 구현 범위 | 남은 제품 경계와 계약 |
| --- | --- | --- |
| 공통 엔진·Capability·Graph | CAP-001~006, GRAPH-001~006, legacy Profile 호환과 명시적 실행 gate | 기본·분산 실행으로 자동 확대하지 않음. [Capability](docs/capability/), [Graph](docs/graph/) |
| Hybrid·협업·Supervisor | 제한된 WALK/CHAIN, MEM/HANDOFF, 검증된 proposal·invocation·approval·Permit | model output·metadata 자체는 실행·Finding 권위가 아님. [오케스트레이션 계약](docs/orchestration/) |
| Pentest·Red Team | 승인된 GET Recon/Replay/Controls, 기존 KISA LLM/RAG와 고정 Web/MCP lab | 임의 대상·일반 보안 진단 전체 지원 아님. [Pentest adapter](docs/orchestration/PENTEST-004C2B2-concrete-child-deployment-adapters.md) |
| Web/API | typed discovery/admission와 고정 SQLi 측정·Replay·Controls·product read | 일반 Web 취약점 탐지·운영 영향 확정 아님. [WEB-002D](docs/benchmark/WEB-002D-independent-controlled-validation-floor-and-finding-projection.md) |
| Network | 서비스 Surface·준비·증거 admission와 합성 6-case 측정 | raw socket·일반 스캔·서비스 취약점 확정 아님. [NET-002D](docs/orchestration/NET-002D-bounded-network-measurement-product-read-and-conformance.md) |
| AI | 고정 M03 source·독립 Replay 2개·Controls 3개·product read, 별도 실제 모델 효과 평가 | 임의 모델·agent 안전성이나 일반 Finding으로 확장하지 않음. [AI-002D](docs/orchestration/AI-002D-bounded-ai-measurement-product-read-and-conformance.md) |
| Cloud | CLOUD-001A~D의 준비·서명 증거 admission·정책 비교·fixture 요구 | 실제 provider·credential 사용 runtime, 정책 translator·live benchmark 필요. [CLOUD-001D](docs/benchmark/CLOUD-001D-fresh-credential-policy-replay-disposable-fixtures.md) |
| System | SYS-001A~D 계약과 SYS-002의 실제 mTLS OS-release 읽기·재실행·독립 확인·제품 보고 | SYS-002는 격리 container userspace 한 기능이다. 일반 host 실행과 [SYS-001D](docs/benchmark/SYS-001D-system-replay-disposable-host-fixtures.md) 전체 conformance는 별도다. |
| Application | APP-001A~D 준비·admission과 APP-002의 승인된 offline ELF64 헤더 실행·재실행·보고 | APP-002는 POSIX custody·Linux Docker의 한 읽기 기능만 지원; 일반 parser/동적 실행은 닫힘. [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md) |
| Mobile | MOBILE-001A~D의 package/static 분석 준비·증거 admission·비교 | 실제 parser·emulator/device·device-bound profile conformance 필요. [MOBILE-001D](docs/benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md) |
| Cryptography | CRYPTO-001A~D의 준비·서명된 재계산 증거 검증·중립 비교 | 실제 분석·semantic Oracle·수치 측정 필요. [CRYPTO-001D](docs/benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md) |
| Forensics | FORENSICS-001A~D의 provenance·증거 admission·parser 비교·요구 등록 | 실제 source/parser·custody·semantic 정확도·측정 필요. [FORENSICS-001D](docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md) |

DOMAIN-001~006의 분류·Graph semantics·Capability projection·Worker profile·cross-domain admission·
metric registry는 구현됐다. 각 registry의 false authority와 `required`/`not-applicable` 구분을
유지한다. Phase 0~25는 위 제한된 계약들의 완료 이력이며, 새로운 일반 도메인 실행 승인이 아니다.

## 다음 제품 작업의 선정 기준

이번 5개 개선의 검증 범위와 남은 제약을 기준으로 다음 독립 slice를 선정한다. 아래 항목은 이번 목표의 완료 범위를
암묵적으로 확대하지 않으며, 새로운 실행·비용·운영 권한이 필요하면 별도로 정한다.

- EFFECT-003의 정밀도 하락·2개 실행 실패를 분석하되 소비한 평가군은 개발 자료로만 사용한다.
  다음 후보는 새 버전과 별도 미사용 평가군을 요구한다.
- OPS-003의 제한된 복원·승인 재개 이후 물리 host/storage 장애와 실제 운영 환경의 복구 계약.
- GRAPH-PERF-002 이후 긴 이력의 Snapshot 검증 비용, 증가한 RSS, 미측정 크기·실제 운영 부하를 별도 선정한다.
- SYS-002 한 기능 이후 Cloud provider 또는 추가 System 기능의 인증·격리·독립 검증 범위를 별도 선정한다.
- 단일 호스트 밖의 verifier·store fence·독립 checkpoint·credential custody와 운영 복구 계약.

도메인 기본 우선순위는 Web·AI, Network·Cloud·System, Application·Mobile, Cryptography·Forensics다.
기존 자산 재사용, 독립 Ground Truth, read-only first slice와 검증 가능한 isolation을 기준으로
재평가한다. 하나의 변경에 독립 도메인 runtime을 혼합하지 않는다.

## 미결정 사항

- legacy `CapabilityDefinition.domain` deprecation과 code-owned projection의 review/version 절차
- Surface locator registry의 publisher/review 권위와 Worker profile의 배포 서명·conformance 권위
- 도메인별 수치 artifact·aggregator·Ground Truth admission과 실제 provider/custodian 선정
- Network raw-socket, System privilege, Mobile device, Forensics custody의 최초 운영 범위
- production Graph Event Store, cross-host fence와 independently anchored evidence
- [UX-007R1](docs/orchestration/UX-007R1-aws-s3-production-custody-selection.md) 이후 production pilot

## 변경별 완료 기준

각 slice는 Task ID, 변경되는 Trust Boundary, schema/API version, 호환성, migration·rollback,
positive/adversarial test, audit/evidence lineage와 benchmark 영향을 명시한다.

- Discovery·model output·Domain metadata로 Scope·Capability·Permit을 확장하지 않는다.
- 기존 Policy/Approval → ActionPermit → Gateway/Worker → Evidence → Graph 경로를 유지한다.
- exact retry는 소비된 Action을 재실행하지 않으며 불확실한 결과는 보수적으로 남긴다.
- Finding은 Profile별 독립 Replay·validation floor를 충족하고 사람 판단과 구분한다.
- 관련 pytest, Ruff, Linux strict mypy, 필요한 packaging·실제 사용자 경로를 검증한다.
- 최종 통합은 같은 소스의 전체 회귀와 변경 경로별 conformance를 확인한다.
- 미실행 검증·환경 제한·미커밋 변경을 `HANDOFF.md`와 `KNOWN_ISSUES.md`에 정확히 남긴다.
