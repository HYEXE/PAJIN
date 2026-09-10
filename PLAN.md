# PAJIN 구현 계획

이전 8개 개선에 이어 2026-09-09 요청의 새로운 5개 개선도 아래 범위의 구현·검증을 완료했다. 구현·권한 경계는 코드와
버전형 계약, 결정 근거는 채택된 ADR, 실행 결과와 Git 상태는 `HANDOFF.md`에서 확인한다.
과거 Phase의 상세 구현 이력은 각 계약을 참조하며 이 파일에 누적하지 않는다.

## 현재 순차 개선 목표

새 goal은 아래 다섯 단계의 코드·테스트·계약과 실제 검증을 포함한다. 토큰 예산은 지정하지 않는다.
시작 기준은 `main`의 `b359c3c782f9afa39f31a6d0aba9a9a8ace1dbd7`이다. HEAD·upstream·실제 원격
main이 일치하고 staged/unstaged/untracked 변경 및 진행 중인 Git 작업이 없음을 확인했다.
별도 브랜치·서브에이전트를 만들지 않는다. 이전 commit·push·원격 workflow 승인은 이 목표에 적용하지 않는다.
2026-09-10 이번 변경의 여섯 commit·`origin/main` push·동일 커밋의 일반 CI와 Web/Network/AI Docker
workflow 실행을 새로 승인받았다. `72bdbd9`의 원격 반영·일반 CI·세 Docker 검증을 완료했다.
2026-09-10 사용자가 Linux 단일 호스트·PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal
구성을 선택하고 격리 검증을 승인했다. ③의 선택 대기는 해소됐고 실제 Linux 검증은 통과했다.
추가 변경 14개 파일은 승인받은 한 commit `215d4fc`로 저장하고 `origin/main`에 반영했다.
동일 커밋의 Quality·24 shard(8,260 passed·기존 76 skipped)와 Web/Network/AI Docker 검증이
모두 첫 시도에 통과했다. 최종 결과를 반영한 운영 문서 4개는 로컬 변경으로 보존했다.

1. [x] **SEC-001 의존성 보안 경고 해소** — 로컬 회귀·설치/packaging·원격 경고 해소·동일 커밋 conformance 완료.
   원격 기존 6건은 모두 fixed, 열린 경고는 0건이다. 최종 `215d4fc`에서도 해당 상태와 CI/세 Docker 검증을 확인했다.
   최신 Dependabot/공식 advisory, 설치·잠금 의존 경로와 제품 도달 가능성을 확인한다.
   최소 보안 하한을 패키지 설치 metadata와 관련 lock에 반영하고 설치·wheel/sdist·Provider·HTTP 회귀,
   취약 동작의 재현/거부와 정상 동작을 검증한다. 로컬 취약 버전 제거와 원격 경고 해소는 별도 상태다.
2. [x] **EFFECT-002 탐지 품질 개선** — 고정한 새 384개 응답의 실제 비교·독립 process 검증 완료.
   정밀도 51.72%→80.38%, 재현율 46.51%→98.45%; 남은 FP 31/FN 2와 조건별 편차를 기록했다.
   EFFECT-001을 개발 자료로만 분석한다. 새 미사용 평가군·정답 규칙·탐지기·모델·비교 계획을
   실행 전에 고정하고 비공개 정답을 detector에 전달하지 않는다. 실제 동일 응답에 기존/개선 탐지를
   비교해 TP/TN/FP/FN, 정밀도·재현율, 표본·반복 편차·시간·토큰·비용을 봉인·보고한다.
   점수 개선이 없으면 그대로 기록하며 원문·canary·모델은 비공개로 유지한다.
3. [x] **OPS-002 배포 구성의 실제 운영 검증** — 선정 Linux 구성의 로컬 실증·동일 커밋 원격 검증 완료.
   Linux PG/journal 84개 검사, mTLS API·Worker 중단·crash 재시작·PG/SQLite/RunStore 독립 복원을 통과했다.
   관련 회귀 125개·Ruff·mypy와 최종 커밋의 CI/세 Docker conformance 정책을 충족했다.
   선정 구성은 Linux 단일 호스트·PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal·
   host-local RunStore다. Linux에서 실제 CP/Worker와 검증된 TLS API 연결을 실행하고, 참여 writer를
   정지·확인한 수동 cold checkpoint로 DB/Graph/journal/RunStore를 함께 보존한다. 독립 pin과 원래
   verifier로 새 격리 대상에 복원하고 기존 이력·보수적 예산·재실행 거부를 확인해야 완료다.
   물리 호스트 장애·외부 자원 rollback·자동 복원/재활성화는 이 검증으로 추정하지 않는다. 격리된 폐기 가능 환경에서
   실제 DB migration·기존 데이터·경합/중복/충돌·재시작/보수적 예산·키 교체/verifier·독립 checkpoint
   backup/restore·실행 중 중단/Worker 관측/알림/cleanup을 검증한다. PostgreSQL은 실제 서버를 요구한다.
   운영 데이터·서비스는 변경하지 않으며 관측하지 못한 외부 복구는 unknown으로 보존한다.
4. [x] **GRAPH-PERF-001 대규모 Graph 비용 개선** — 실제 동일 DB 비교·변조/경합/권한 회귀 완료.
   5,002 node / 10,000 edge에서 반복 page 평균 11.54초→0.186초; 최초 조회·크기 제한은 별도 기록.
   대표 크기별 지연·CPU·메모리·반복 검증을 먼저 측정하고 프로파일에 근거한 최소 변경을 한다.
   Snapshot/cursor·current head·변조 거부·권한 경계, 동시 변경·stale cursor·무효화·키/설정 변경을
   회귀 검증하고 동일 조건의 전후 측정과 한계를 남긴다. mutable authority의 무조건 캐시는 금지한다.
5. [x] **DOMAIN-RUN-001 추가 도메인 실제 읽기 기능** — Application ELF64 헤더 읽기·재실행·보고 완료.
   단위 63개와 실제 Docker 12개 검사가 통과했다. 두 architecture의 독립 LLVM 비교와 최대 256 KiB,
   거부·실패·cleanup을 확인했다. 서버 기본 활성화나 일반 Application 지원을 뜻하지 않는다.
   Cloud/System의 credential·인증 agent runtime이 준비되지 않은 현재 환경과 기존 offline Docker·LLVM
   독립 파서 자산을 비교해 선정했다. [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md)의
   최대 256 KiB·x86-64/AArch64 little-endian 헤더만 지원하며 일반 Application 지원과 구분한다.
   Cloud/System을 먼저 검토해 자산·isolation·독립 정답·실행 환경에 맞는 하나를 선정하고 범위를 기록한다.
   허가된 입력/Scope → Capability/Policy/Approval/Permit → 실제 provider/parser/Worker → evidence/seal
   → 독립 재실행/검증 → 제품 조회/보고를 연결한다. 정상·거부·실패·cleanup을 실제 격리 fixture로 검증한다.
   credential·운영 호스트·유료 자원은 구체적 범위 승인 전 사용하지 않으며 도메인 전체 지원과 구분한다.

각 단계는 독립 검증 가능한 기능 흐름/신뢰 경계 단위로 진행한다. 필수 결정·권한 때문에 미완료인
부분을 명시하고, 그 결정에 의존하지 않는 다음 작업은 계속한다. 좁은 pytest부터 Ruff·Linux strict
mypy·packaging·필요한 통합/실제 실행·전체 회귀로 확장한다. 변경 경로별 Web/Network/AI conformance는
[정책](docs/orchestration/MEASURED-CONFORMANCE.md)을 따른다. 새로운 코드 변경에는 그 커밋의 검증을 적용한다.
각 체크포인트에서 `HANDOFF.md`·`KNOWN_ISSUES.md`를 현재 상태로 갱신하고 비자명한 결정은 새 ADR로 남긴다.

## 이전 완료 범위

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
   같은 로컬 cProfile 사례는 592.67초에서 43.17초로 줄었다. 새 CI의 전체 job 실행 구간은 477초였다.
   CI 시간 기록 24개가 동일 SHA·clean tree·exit 0과 8,171개 사례의 중복 없는 처리를 보존했다.
8. [x] 운영 문서 정합성과 최종 통합 검증. 현재 문서·체크포인트를 정리하고 로컬 실패를 해소했다.
   `e7c8243`의 Quality·24 shard(8,095 passed·76 opt-in skipped)와 Web/Network/AI Docker conformance가
   모두 첫 시도에 통과했다. 실제 clean commit·이미지 ID·잔여 자원 검사까지 확인했다.

3~7단계 제품·테스트·CI 변경은 논리 커밋으로 보존했으며 식별자는 `HANDOFF.md`에서 확인한다.
새 체크포인트의 원격 검증은 사용자 승인을 받아 완료했다. 기존 커밋의 성공을 새 코드의 CI나 Docker
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

- EFFECT-002의 남은 오탐 31개·미탐 2개와 표현 범위 밖 사례를 다루는 별도 탐지 개선·새 미사용 평가군.
- 선정 Linux hybrid 구성의 물리 host/storage 장애, 복원 후 활성화와 실제 운영 환경의 복구 계약.
- Graph의 최초 조회 비용과 128 MiB cache 범위 밖 크기를 새 프로파일로 측정한 뒤 같은 권한 경계에서 개선.
- APP-002 한 기능 이후 Cloud/System 등 다음 도메인의 실제 provider·parser·sandbox와 독립 측정.
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
