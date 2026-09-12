# PAJIN 구현 계획

현재 다섯 후속 목표의 구현·로컬 실증·회귀와 코드 SHA의 원격 검증을 완료했다. 구현·권한 경계는 코드와
버전형 계약, 결정 근거는 채택된 ADR, 실행 결과와 Git 상태는 `HANDOFF.md`에서 확인한다.
과거 Phase의 상세 구현 이력은 각 계약을 참조하며 이 파일에 누적하지 않는다.

## 현재 순차 후속 목표 (2026-09-11, 두 번째 묶음)

사용자가 선정한 다섯 항목의 구현·실증을 완료했다. 시작 HEAD·upstream·실제 원격은
`51aeb02721f4d914e17fc8f028f02a31a0fa21ee`이며 결과 Markdown 8개만 미커밋이었다.
이번 진행 지시에는 준비된 문서 8개의 한 commit·일반 push·일반 CI 확인이 포함된다.
제품 변경의 commit 6개·일반 push·다섯 원격 conformance는 검토한 diff와 실행안을 기준으로 승인받았다.
main에서 직접 작업하며 branch/worktree/subagent를 만들지 않는다. 토큰 예산은 지정하지 않는다.

1. [x] **DOCS-FINAL-003 결과 기록 반영** — 기존 검토 bytes의 문서 8개를 `20f0ec5`로
   commit/push했다. 새 CI 34571193983의 첫 시도 Quality·24 shard, 8,441 passed·기존 76 skipped,
   정확한 clean SHA의 8,517개 중복 없는 ID와 기존 skip 목록을 대조했다. Markdown-only 변경은 추가 Docker workflow를 선택하지 않는다.
2. [x] **EFFECT-005 오탐·탐지 비용** — 새 실험 버전으로 공개 입력에서 독립 계산 가능한
   ID/hash를 구분하고 중복 분석 비용을 줄인다. 생성 의도만으로 실제 유출을 정상으로 바꾸지 않는다.
   후보·독립 정답·이전 prompt 제외·새 미사용 평가군·모델·좌표·성공 기준을 호출 전에 동결하고,
   동일 응답의 혼동행렬·정밀도·재현율·CPU·실패·시간·토큰을 비교한다. 개선 미확인은 그대로
   보고하며 기본 v1과 false Finding authority를 유지한다. 소비된 EFFECT-002/003/004는 개발 전용이다.
3. [x] **GRAPH-PERF-004 최초 조회·프로세스 부하** — 현재 소스의 병목을 먼저 측정하고
   모든 이력·권한·변조·head·cursor 검증을 유지하는 최소 수정을 한다. 동일 데이터·반복의
   전후 지연/CPU/RSS와 별도 프로세스 동시 조회를 측정하고 디스크 캐시 조건을 명시한다.
   cache eviction을 관찰하지 못한 실행을 cold-disk 실증으로 표시하지 않는다.
4. [x] **OPS-004 독립 checkpoint·복원 보호** — 독립 보관한 단조 checkpoint를 통한
   오래된 상태 복원 거부와 별도 대상 복원을 구현하고 실제 격리 Linux 환경에서 검증한다.
   사용자는 별도 Linux 호스트가 아직 없어 구현·격리 검증을 먼저 진행하도록 선택했다.
   물리적으로 다른 호스트·storage 장애·운영 failover 검증은 환경 준비 후 별도 범위다.
5. [x] **SYS-004 추가 고정 읽기** — 사용자가 추가 System 읽기를 선택했다. 재사용 가능한
   mTLS·Capability·승인·Permit·Worker·봉인 증거·독립 확인·조회 경계 안에서 읽기 기능 하나를
   선정하고 정상·거부·변조·재실행·cleanup을 실제 검증한다. 임의 경로·명령이나 host 권한을 열지 않는다.

순서대로 구현·검증하되 원격 대기 중에는 다음 단계의 읽기 조사와 독립 준비를 진행한다.
각 단계는 집중 pytest·Ruff·Linux strict mypy·필요한 실제 실행·문서를 검증하고 최종 통합에서
같은 소스의 전체 회귀와 경로별 conformance를 확인한다. 승인이 필요한 Git 작업은 구현을
완성하고 정확한 diff·메시지·검증안을 준비한 뒤 요청한다.

## 이전 목표의 완료 상태

이전 목표는 모두 완료 상태로 유지한다. 최근 다섯 과제의 구현은 `51aeb02`에서
CI 8,441 passed·기존 76 skipped, Web/Network/AI/OPS/SYS 첫 시도 성공을 확인했다.
EFFECT-004는 새 384응답/0실패에서 6개 grouped 미탐을 회복했지만 오탐 51개는 남았으며
기본 v1을 유지했다. GRAPH-PERF-003은 큰 이력 단일 reader RSS를 1,424.56→769.73 MiB로
줄였으나 변경 직후 최초 조회는 10.9536→11.1738초였다. 앞선 원격 OPS 실패의 정확한 내부
원인은 여전히 미확인이다. 과거 실험·CI는 새로운 변경의 검증으로 대체하지 않는다.

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

초기 문서 `20f0ec5`의 CI 34571193983은 완료했다. 새 코드·테스트·CI 5개 commit의
HEAD `1fd37d16d05887f9ff7956ccea4986b77cd4fe6c`를 push했고 원격 여섯 workflow가 첫 시도에 통과했다.

- EFFECT-005의 새 384응답/0실패에서 오탐 76→64, 정밀도 64.49→68.32%, 재현율 100%,
  평균 CPU 27.09→20.96μs를 확인했다. 동결 source/설치 wheel의 보고서가 같고 평가군은 소비됐다.
- GRAPH-PERF-004의 전후 각각 24그룹·36독립 reader에서 모든 최초 조회 그룹 평균이 개선됐다.
  큰 이력 cold guest page 단일 reader는 12.6702→9.5380초, 두 reader 완료는 13.4525→10.0194초다.
- OPS-003 기존 11개와 OPS-004 새 15개 실제 격리 검사가 통과했다. 별도 물리 host는 미검증이다.
- SYS-002 기존 실행과 SYS-004 새 실행이 각각 Worker 4회를 포함해 통과했다. 새 정상 결과는
  실제 kernel/GNU 도구와 같고 malformed 값은 명시적인 시험용 open redirection으로 거부 검증했다.
- Ruff 전체·Linux strict mypy 490+13+2개, 별도 설치 wheel의 두 System 결과 재구성이 통과했다.
  최초 전체 회귀의 시간 만료 관련 25개 실패/오류는 소스·기준을 유지한 별도 검사에서 모두 통과했다.
  전체 실행+집중 재검증은 8,566 unique passed·기존 76 skipped이며 최초 실패 로그도 보존한다.
  967개 비문서 source가 같고 이전 8,517개 테스트를 보존했다. 문서·diff 검사와 최종 검토를 마쳤다.
  승인된 마지막 문서 commit은 실제 원격 검증 결과를 기록한다.

같은 clean 코드 SHA의 CI는 8,566 passed·기존 76 skipped, 8,642개 ID·이전 8,517개 보존이다.
Web·Network·AI·OPS·SYS 모두 첫 시도 성공이고 실제 image/source·독립 residue를 확인했다.
OPS는 기존 11개+신규 15개, SYS는 두 프로필 각각 Worker 4회다. 결과와 링크는 `HANDOFF.md`에 있다.
후속 결과 문서는 Markdown-only이며 해당 문서 SHA의 일반 CI를 별도로 확인한다.
