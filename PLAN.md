# PAJIN 구현 계획

2026-09-12 사용자는 이전 세 축의 구현을 바탕으로 아래 네 후속 항목을 순서대로 진행하도록 승인했다.
시작 main/upstream/실제 원격은 `b2fe5cb2413cf3c4aa25e50e58ecd4e641aebee7`이다.
기존 미커밋 구현 987개 비문서 입력은 마지막 검증 inventory와 일치했다.

## 현재 순차 구현 목표

1. [ ] **완료분 원격 검증** — OPS-005 검증 정책을 맞추고 승인된 논리적 commit/push 후
   같은 SHA에서 일반 CI의 quality·24 shard와 Web·Network·AI·OPS·SYS 실증/독립 cleanup을 확인한다.
2. [ ] **EFFECT-007 오탐 감소** — 소비된 EFFECT-006의 오탐을 개발 자료로 분석하고 새 후보를 구현한다.
   새 미사용 평가군·성공 기준을 동결한 뒤 같은 실제 응답에서 정밀도·재현율·CPU를 비교한다.
3. [ ] **GRAPH-PERF-006 메모리·과거 조회 비용** — 전체 무결성 검증을 보존하며 과거 Snapshot의
   최초/반복 조회와 여러 독립 reader의 동시 전체 RSS를 같은 Linux 조건에서 전후 측정·개선한다.
4. [ ] **UX-014 검토 업무 필터·이력 후속 처리** — 담당자·미확인·상태 필터를 API와 Console에
   연결하고, 200회 한도에서 기존 감사 기록을 보존하는 명시적 후속 처리·호환성 계약을 검증한다.

## 직전 구현 체크포인트

1. [x] **EFFECT-006 후보·독립 평가 구현** — 새 v5·미사용 평가군·성공 기준을 호출 전에
   동결하고 동일한 실제 384응답의 정밀도·재현율·CPU를 비교했다. **오탐 감소 목표는 미달**이다.
   v4/v5 모두 FP 62/FN 0, 기본값 v1 유지, 소비한 평가군은 재사용하지 않는다.
2. [x] **GRAPH-PERF-005 조회 비용** — 전체 이력·원본 bytes·schema·chain/head·변조 검증을
   유지하며 중복 직렬화를 줄였다. Linux 독립 process의 전후 최초/반복 조회·CPU·RSS를 측정했고
   큰 이력 최초 지연은 약 19~21% 줄었다. RSS·반복 지연의 일관된 개선은 확인하지 못했다.
3. [x] **OPS-005 독립 복구 증명** — enrollment·서명·witness-first publication·중단 후 차단·
   한쪽 rollback 거부·원본 보존 재구성을 구현했다. 최신 source/image가 일치하는 격리 Linux에서
   21개 검사와 실제 SIGKILL 뒤 32회 새 process 검증을 통과했다. 물리 host 실증은 남는다.
4. [x] **UX-012 Campaign·Graph 이력 탐색** — 등록된 여러 Campaign과 검증된 과거 Snapshot의
   API·Console을 연결하고 실제 브라우저에서 탐색·인증 전환·오프라인 복구를 검증했다.
   과거 결과에는 실행·현재 권위를 부여하지 않고 기존 단일 Campaign API를 유지했다.
5. [x] **UX-013 검토 배정·내부 알림** — 명시적 담당자·변경 이력·개인별 알림·확인을 구현하고
   실제 배정→수신→확인과 역할·용량·동시성 회귀를 검증했다. 기존 승인·Finding 경계를 유지했다.

체크 표시는 각 slice의 코드·검증 작업 완료다. EFFECT-006의 품질 기준 실패와 물리 운영 실증,
Graph 메모리/반복 비용, 일반 queue·외부 알림은 별도로 남아 있다.

별도 Linux 물리 호스트는 아직 준비되지 않았다는 기존 선택을 유지한다. 실제 cross-host 장애
전환·운영 배포·장기 운영 보증은 해당 환경과 별도 승인 후 검증한다. 이번 격리 검증을 그 증명으로
표시하지 않는다. 네 항목의 구현·테스트·문서와 기존 완료분 commit/push·원격 검증은 승인됐다.
운영 배포·merge·tag·외부 알림 전송은 승인 범위에 포함하지 않는다.
main에서 직접 작업하고 branch/worktree/subagent를 만들지 않는다.

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
| System | SYS-001A~D 계약, SYS-002의 실제 mTLS OS-release 읽기·재실행·독립 확인과 SYS-003 Operator API/Console의 고정 결과 조회, SYS-004의 승인된 커널 ASLR 고정 읽기·독립 CLI 조회 | SYS-002는 격리 container userspace, SYS-004는 guest kernel 설정 한 값이다. 일반 host 실행과 [SYS-001D](docs/benchmark/SYS-001D-system-replay-disposable-host-fixtures.md) 전체 conformance는 별도다. |
| Application | APP-001A~D 준비·admission과 APP-002의 승인된 offline ELF64 헤더 실행·재실행·보고 | APP-002는 POSIX custody·Linux Docker의 한 읽기 기능만 지원; 일반 parser/동적 실행은 닫힘. [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md) |
| Mobile | MOBILE-001A~D의 package/static 분석 준비·증거 admission·비교 | 실제 parser·emulator/device·device-bound profile conformance 필요. [MOBILE-001D](docs/benchmark/MOBILE-001D-package-reanalysis-seeded-mobile-fixtures.md) |
| Cryptography | CRYPTO-001A~D의 준비·서명된 재계산 증거 검증·중립 비교 | 실제 분석·semantic Oracle·수치 측정 필요. [CRYPTO-001D](docs/benchmark/CRYPTO-001D-independent-implementation-replay-seeded-vector-requirements.md) |
| Forensics | FORENSICS-001A~D의 provenance·증거 admission·parser 비교·요구 등록 | 실제 source/parser·custody·semantic 정확도·측정 필요. [FORENSICS-001D](docs/benchmark/FORENSICS-001D-independent-parser-comparison-seeded-evidence-requirements.md) |

DOMAIN-001~006의 분류·Graph semantics·Capability projection·Worker profile·cross-domain admission·
metric registry는 구현됐다. 각 registry의 false authority와 `required`/`not-applicable` 구분을
유지한다. Phase 0~25는 위 제한된 계약들의 완료 이력이며, 새로운 일반 도메인 실행 승인이 아니다.

## 후속 범위의 선정 기준

이번 목표 밖의 일반 도메인 확장·운영 배포·물리 장애 실증은 별도 선정한다. 도메인 기본
우선순위는 Web·AI, Network·Cloud·System, Application·Mobile, Cryptography·Forensics다.
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

## 현재 실행 체크포인트

- 기준 Git과 원격 CI 34670400044의 첫 시도 성공을 다시 확인했다.
- 다섯 slice의 코드·집중 회귀·계약을 구현했다. 새 모델 평가에서 오탐은 줄지 않았고 기본 v1을 유지한다.
- Graph 전후 Linux 측정과 Console 실제 사용 경로를 검증했다. 큰 이력 최초 조회는 약 19~21%
  빨라졌지만 RSS는 거의 같고 반복 조회는 혼재한다.
- 전체 8,747개 ID의 회귀에서 목록 누락 두 실패를 수정했다. 최종 고유 8,671 passed·기존 76 skipped이며
  마지막 네 파일 수정 뒤 관련 121개·Ruff·strict mypy·설치 패키지를 검증했다. Linux 복구는 강제 종료
  probe의 총 예산을 보정하고 최신 이미지에서 OPS-005 21개·32회 새 process와 OPS-003 11개 검사를 통과했다.
- 실제 Console·Linux 복구·모델·Graph 측정과 최종 독립 cleanup 근거를 보존했다.
  기존 구현은 다섯 로컬 커밋으로 보존했고 새 원격 CI·push·배포는 아직 실행하지 않았다.
- 이전 코드의 CI 8,566 passed·기존 76 skipped와 Web/Network/AI/OPS/SYS 실증은 기준점이다.
- private 작업 근거는 `.pajin/continuation-three-20260912/`에 보존한다.
