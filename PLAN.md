# PAJIN 구현 계획

현재 우선순위는 사용자가 요청한 8개 개선의 최종 통합 검증이다. 구현·권한 경계는 코드와
버전형 계약, 결정 근거는 채택된 ADR, 실행 결과와 Git 상태는 `HANDOFF.md`에서 확인한다.
과거 Phase의 상세 구현 이력은 각 계약을 참조하며 이 파일에 누적하지 않는다.

## 순차 개선 목표

2026-09-07 검토에서 정한 순서를 유지한다. `[x]`는 아래 명시한 범위의 구현·검증 완료를 뜻한다.
로컬 검증, 실제 모델 평가, 특정 커밋의 Docker conformance와 배포 완료는 서로 구분한다.

1. [x] 기본 Control Plane의 Web/Network/AI reader 구성, `--check-config`, Network/AI Console.
   [UX-010](docs/orchestration/UX-010-measured-product-deployment-and-console.md)의 배포자 선택·digest pin·
   재검증과 기존 Operator 인증을 유지한다. `a60395b`에 반영했다.
2. [x] AI 실제 Docker 검증과 공통 코드 변경 시 Web/Network/AI 재검증 기준.
   `3b9aaa0`의 일반 CI·세 Ubuntu Docker workflow·잔여 자원 검사가 통과했다.
   이후 변경은 [재검증 정책](docs/orchestration/MEASURED-CONFORMANCE.md)에 따라 다시 확인한다.
3. [x] [EFFECT-001](docs/benchmark/EFFECT-001-local-llm-effectiveness.md) 실제 LLM 효과 평가.
   개발과 분리한 사례, 두 모델·두 정책·두 temperature·세 seed의 384개 응답을 측정하고
   오탐·미탐·반복 편차·시간·토큰·비용 범위를 봉인했다. 탐지기를 평가 결과로 조정하지 않았다.
4. [x] [UX-011](docs/orchestration/UX-011-human-review-and-remediation-report.md) 사람 검토·보고.
   검증된 공개 근거, 영향·심각도·수정 권고, 별도 사람의 승인, 재검증 연결·재승인·보고서를
   CP v15 이력·기본 API·Console로 연결했다. 새 Finding·SARIF·실행 권위를 만들지 않는다.
5. [x] [OPS-001](docs/orchestration/OPS-001-single-host-recovery-and-urgent-stop.md) 단일 호스트 복구·긴급 중단.
   CP v16 키 연속성, 보수적 예산, v3 첫 사용 등록·원래 CP 입력/source 검증, 활동 배제,
   암호화 checkpoint·독립 pin 복원, CP 취소·Worker 관측·Console 알림을 장애 시나리오로 검증했다.
   범위는 POSIX local SQLite다. 자동 배포 이전·재활성화와 분산 운영은 포함하지 않는다.
6. [x] [Graph 페이지](docs/orchestration/UX-002B-current-canonical-graph-view.md)와
   [Supervisor 입력 전송](docs/orchestration/SUP-004A-checkpoint-invocation-plan.md).
   Snapshot cursor·Console, 4 MiB 입력의 분할·재구성과 버전형 Worker 전송을 구현했다.
   기존 작은 입력 wire·한 호출·이중 예산을 유지하며 실제 브라우저·HTTPS 경로를 검증했다.
7. [x] 프로파일 기반 테스트 비용 개선. code-owned taxonomy/Graph template만 캐시하고 반환값을
   격리했다. 실측 시간 기반 CI 배치·기록과 8,171개 사례의 초기 profile을 검증했다.
   같은 로컬 cProfile 사례는 592.67초에서 43.17초로 줄었다. 실제 CI 개선 수치는 아직 없다.
8. [ ] 운영 문서 정합성과 최종 통합 검증. 현재 문서·체크포인트를 정리하고 전체 로컬 실행에서
   발견한 실패를 관련 모듈 재검증으로 해소했다. 새 커밋의 일반 CI·세 Docker conformance는
   승인된 commit·push 이후 확인해야 하므로 전체 목표는 아직 완료 처리하지 않는다.
   현재 goal은 활성 상태이며 같은 범위의 최종 원격 검증을 진행한다.

3~7단계 제품·테스트·CI 변경은 논리 커밋으로 보존했으며 식별자는 `HANDOFF.md`에서 확인한다.
새 체크포인트의 원격 검증은 승인받아 진행 중이다. 기존 커밋의 성공을 새 코드의 CI나 Docker
검증으로 사용하지 않는다. commit·push·원격 실행의 실제 승인 범위는 `AGENTS.md`와 사용자 지시를 따른다.

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
| System | SYS-001A~D의 host metadata 준비·서명 증거 검증·재검사 비교 | 실제 host-agent·read·isolation conformance 필요. [SYS-001D](docs/benchmark/SYS-001D-system-replay-disposable-host-fixtures.md) |
| Application | APP-001A~D의 artifact·sandbox 준비·증거 admission·재분석 비교 | 실제 custody·parser/sandbox·측정 필요, dynamic 실행 닫힘. [APP-001D](docs/benchmark/APP-001D-application-reanalysis-seeded-artifact-fixtures.md) |
| Mobile | MOBILE-001A~D의 package/static 분석 준비·증거 admission·비교 | 실제 parser·emulator/device·device-bound profile conformance 필요. [MOBILE-001D](docs/benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md) |
| Cryptography | CRYPTO-001A~D의 준비·서명된 재계산 증거 검증·중립 비교 | 실제 분석·semantic Oracle·수치 측정 필요. [CRYPTO-001D](docs/benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md) |
| Forensics | FORENSICS-001A~D의 provenance·증거 admission·parser 비교·요구 등록 | 실제 source/parser·custody·semantic 정확도·측정 필요. [FORENSICS-001D](docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md) |

DOMAIN-001~006의 분류·Graph semantics·Capability projection·Worker profile·cross-domain admission·
metric registry는 구현됐다. 각 registry의 false authority와 `required`/`not-applicable` 구분을
유지한다. Phase 0~25는 위 제한된 계약들의 완료 이력이며, 새로운 일반 도메인 실행 승인이 아니다.

## 다음 제품 작업의 선정 기준

현재 8개 개선을 검증한 뒤 다음 독립 slice를 선정한다. 아래 항목은 이번 목표의 완료 범위를
암묵적으로 확대하지 않으며, 새로운 실행·비용·운영 권한이 필요하면 별도로 정한다.

- EFFECT-001이 확인한 marker 탐지의 오탐·미탐을 줄이는 탐지기와 새 미사용 평가군.
- 배포에 사용할 정확한 SQLite 또는 PostgreSQL 환경의 live 복구·동시성 검증.
- Graph 전체 이력 재검증 비용과 shared fixture 비용을 새 프로파일로 측정한 후 같은 권한 경계에서 분리.
- Cloud/System/Application/Mobile/Cryptography/Forensics의 실제 provider·parser·sandbox와 독립 측정.
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
