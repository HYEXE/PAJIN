# PAJIN 구현 계획

이전 8개 개선에 이어 2026-09-09 요청의 새로운 5개 개선도 아래 범위의 구현·검증을 완료했다. 구현·권한 경계는 코드와
버전형 계약, 결정 근거는 채택된 ADR, 실행 결과와 Git 상태는 `HANDOFF.md`에서 확인한다.
과거 Phase의 상세 구현 이력은 각 계약을 참조하며 이 파일에 누적하지 않는다.

## 현재 순차 후속 목표 (2026-09-10)

이전 8개 및 2026-09-09의 5개 개선 goal에 이어 아래 후속 5개의 구현·검증과 승인된 원격 작업을
완료했다. 토큰 예산은 지정하지 않았다. 시작 기준은 `main`의
`215d4fc03e1385c64ccc1e4e7fe70efd0ea4add2`이며 시작 시 HEAD·upstream·실제 원격이 일치했다.
기존 완료 기록 4개 문서의 diff와 bytes를 private `.pajin/followup-five-20260910/step1-docs/`에
보존·검토했다. 여섯 commit·일반 `origin/main` push·동일 신규 커밋 CI/Web/Network/AI 실행은
명시적으로 승인받아 실행했다. 최종 `3c66c2e`의 Quality·24 shard(8,342 passed·기존 76 skipped)와
Web/Network/AI Docker 검증은 모두 첫 시도에 통과했다. HEAD·upstream·실제 원격이 일치했고
push 직후 worktree는 깨끗했다. 최종 결과 운영 문서 3개는 별도 승인받은 로컬 문서 커밋으로
관리하며 해당 문서 커밋의 push는 승인·실행하지 않았다.
배포·운영 서비스 변경은 승인 범위 밖이다.

1. [x] **DOCS-FINAL-001 이전 최종 결과 반영** — 기존 4개 문서 검토·문서 검사 4개·diff 검사 통과.
   원본 CI/24 shard artifact/세 Docker 근거를 대조했고 정확한 기존 diff만 `625e53b`에 저장했다.
   `625e53b`를 포함한 여섯 commit의 원격 반영과 HEAD·upstream·실제 원격·작업 트리 확인을 완료했다.
2. [x] **EFFECT-003 탐지 품질 2차 개선** — `novel-opaque-output-v1`을 기본 baseline으로 유지한다.
   EFFECT-002를 개발 자료로만 사용하고 정상 ID/hash·묶음 분리·표현 범위 밖 사례를 구분한다.
   후보·독립 정답·모델/반복·새 미사용 과제·제외/성공 규칙을 실행 전에 고정한다. 동일 실제 응답의
   TP/TN/FP/FN·정밀도/재현율·반복 편차·시간/토큰/비용을 봉인·재검증했다. 384 시도/382 응답/2 실패,
   baseline 129/201/45/7 → 후보 135/195/51/1이다. 비교 완전성과 정밀도 기준 실패로 개선 미확인·기존 기본값 유지다.
3. [x] **OPS-003 운영 복구 명령 제품화** — 선정 Linux 단일 호스트·PG17 CP·SQLite Graph/journal·
   host-local RunStore를 유지한다. 제한된 사전 점검·writer 정지·전체 checkpoint·독립 pin/검증키/
   예산/Graph/Run 검증·별도 대상 복원·결과 확인·별도 승인/현재 권한 기반 재개를 연결한다.
   버전/호환성/rollback 계약과 폐기 가능한 Linux의 정상·거부·중간 실패·재시도·불확실 호출·cleanup
   실증이 완료 기준이다. 운영 배포·물리 장애·live backup·분산 failover·미확인 외부 rollback은 제외한다.
   새 운영자 명령·계약·ADR-0279·관련 회귀와 실제 Linux 복구/별도 승인 재개를 로컬 검증했다.
4. [x] **GRAPH-PERF-002 최초·변경·큰 데이터 비용** — 동일 대표 데이터·환경·반복으로 최초,
   이력 변경 직후, 128 MiB 초과의 wall/CPU/메모리/I/O/반복 검증을 측정하고 실제 병목만 개선한다.
   snapshot cursor·current head·변조/권한 경계와 동시 변경·stale cursor·무효화·키/설정·크기/fallback
   회귀를 유지하며 전후 결과를 분리한다. 18개 fresh process의 동일 DB 비교에서 큰 Graph 최초
   13.48→8.13초, 이력 변경 직후 15.65→9.20초, 128 MiB 초과 반복 20.80→0.304초를 확인했다.
   작은 DB 반복 지연과 큰 이력 RSS 증가도 기록했다. 관련 90개 회귀 통과; 최대 크기·운영 SLO는 미측정이다.
5. [x] **DOMAIN-RUN-002 Cloud 또는 System 실제 읽기 한 기능** — 실제 자산·인증·격리·독립 정답을
   마련할 수 있는 도메인 하나를 선정한다. Scope→Capability/Policy/Approval/Permit→실제 provider 또는
   인증 agent/Worker→봉인→독립 재검증→제품 조회/보고와 정상·거부·실패·cleanup을 실제 실행한다.
   SYS-002의 실제 mTLS OS-release 읽기·별도 승인 재실행·독립 표준 parser·제품 CLI·거부/실패·cleanup을 검증했다.
   APP-002 반복이나 일반 System 지원이 아니다. 운영 호스트·Cloud credential·유료 자원을 사용하지 않았다.

필수 승인·결정에 의존하는 부분만 대기하고 독립적인 다음 작업은 계속한다. 각 단계는 별도 검증 가능한
기능 흐름/신뢰 경계이며 기존 public API/reader와 false Finding authority를 보존한다. 좁은 pytest부터
전체 Ruff·Linux strict mypy(새 scripts 포함)·필요한 실제 모델/DB/Docker·packaging·최종 회귀로 확장한다.
새 소스의 승인된 원격 CI/conformance는 같은 커밋의 실제 결과로 충족했다. run·artifact·이미지·cleanup
근거는 `HANDOFF.md`에 연결한다. 최종 결과 문서만의 추가 변경은 별도 문서 검사를 적용한다.

## 이전 목표의 완료 상태

이전 두 goal은 완료 상태를 유지하며 이번 목표에서 다시 구현하지 않는다.

- 이전 8개 개선: 기본 measured reader/Console, AI Docker conformance 정책, EFFECT-001,
  사람 검토·보고, OPS-001, Graph 페이지/Supervisor 입력, 테스트 비용, 통합 문서·검증을 완료했다.
  각 버전형 계약과 기존 Git 이력이 상세 범위의 근거다.
- 직전 5개 개선: SEC-001 의존성 수정, EFFECT-002의 새 384응답 비교, OPS-002의 선정 Linux hybrid
  수동 cold 복원, GRAPH-PERF-001 반복 조회, APP-002 offline ELF 헤더 읽기·재실행·보고를 완료했다.
- 최종 기준 `215d4fc`의 Quality·24 shard는 8,260 passed·기존 76 skipped이고 Web/Network/AI
  Docker 검증도 통과했다. 상세 run/로그·완료 기록은 `HANDOFF.md`의 이전 근거 위치와 각 계약을 따른다.
- 위 성공·승인은 해당 기존 커밋에만 적용한다. 이번 소스의 원격 검증이나 배포 완료로 재사용하지 않는다.

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
