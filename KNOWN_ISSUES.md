# PAJIN 알려진 문제

현재 구현의 미해결 제약과 검증 공백을 기록한다. 제품 우선순위는 `PLAN.md`, 실제 실행 결과와
Git 상태는 `HANDOFF.md`, 상세 요구와 권한 경계는 각 버전형 계약이 권위다.

## 현재 후속 목표의 한계와 남은 검증

- 이번 세 축의 변경은 기준 `b2fe5cb` 위의 다섯 로컬 구현 커밋으로 보존했다. `dd039ef`를 push했고 OPS의 원격 재개 단계 실패를 보완 중이다.
  전체 로컬 회귀와 수정 후 관련 검증은
  최종 고유 8,671 passed·기존 76 skipped다. 첫 전체 실행의 목록 누락 두 실패를 보완한 뒤 관련
  121개를 통과했으며 전체를 두 번째 실행하지 않았다. 마지막 Linux 복구 재검증도 통과했다.
  같은 SHA의 일반 CI는 첫 시도 8,671 passed·76 skipped이며 Web·Network·AI·SYS도 통과했다.
  OPS는 기존 11·추가 15 검사를 통과했지만 witness 15/21 뒤 target-resume에서 실패했다.
  private 명령 상세가 없어 원격 내부 원인은 미확정이고 독립 cleanup은 성공했다.
  별도 재현에서 독립 스트레스가 승인 유효기간을 소모하는 문제를 확인해 실행 순서를 수정 중이다.
  이전 코드의 성공은 수정된 코드의 검증으로 재사용하지 않는다. 배포는 실행하지 않았다.
- [EFFECT-006](docs/benchmark/EFFECT-006-public-text-transforms-and-disclosure.md)의 새 384응답은
  실패 없이 완료했지만 오탐은 v4/v5 모두 62건, 미탐 0건이며 개별 판정도 모두 같았다.
  정밀도 68.37%·재현율 100%는 동일하다. 평균 CPU는 29.73→27.52μs지만 중앙값은
  20.72→22.52μs로 증가했다. 사전 선언한 품질 개선 기준은 실패했고 기본 탐지기는 v1을 유지한다.
  생성 23·공개 대조 21·encoded 6·grouped 2·oracle 범위 밖 10건의 오탐이 남는다.
  이 응답과 모든 선행 평가군은 소비됐으며 개선 확인을 위한 미사용 평가군으로 재사용할 수 없다.
- [GRAPH-PERF-005](docs/benchmark/GRAPH-PERF-005-canonical-serialization-cost.md)는 별도 Linux
  process 1/2개·두 DB·guest file pages cold/warm·전후 24그룹씩에서 최초 지연을 줄였다.
  큰 이력 cold 최초 단일 9.8673→7.9494초, 두 reader 완료 10.9121→8.7437초다.
  peak RSS는 약 556 MiB로 거의 같고 반복 조회는 일부 느려졌다. 전체 검증·hash·copy 비용,
  host/SSD cold·동시 aggregate RSS·최대 크기·운영 SLO와 새 이력 탐색 경로의 성능은 남은 과제다.
- [OPS-005](docs/orchestration/OPS-005-separately-retained-recovery-witness.md)는 별도 witness가 최신이면
  anchor 한쪽 rollback·유효 suffix 삭제를 거부하고 새 빈 anchor에 명시적으로 재구성한다.
  첫 Linux 실증의 21개 검사·실제 SIGKILL·32회 새 process 검증이 통과했다. 마지막 UI 경계 수정까지
  포함한 이미지 재검증은 전체 회귀와 동시에 실행되던 강제 종료 probe에서 180초를 넘겼다.
  해당 실행은 미완료로 보존했고 소유 자원 부재를 별도로 확인했다. 35개 하위 process 각각의
  30초 제한은 유지하고 총 한도를 1,200초로 보정했다. 최신 source/image의 단독 재검증은 21개 검사·
  32회 새 process 검증과 기존 OPS-003 11개 검사를 모두 통과했고 별도 cleanup 관찰도 완료했다.
  anchor와 witness가 함께 rollback된 경우, 별도 물리 host·power loss·운영 failover는 미검증이다.
- [UX-012](docs/orchestration/UX-012-registered-campaign-and-snapshot-history.md)의 여러 Campaign·과거
  Snapshot 조회는 배포자가 등록한 local DB에 한정된다. 매 요청 전체 이력을 검증하며 과거 결과는
  실행·현재 승인 권위를 갖지 않는다. [UX-013](docs/orchestration/UX-013-review-assignment-and-internal-notifications.md)의
  배정·알림은 측정 결과에 대한 사람 검토에 한정되고 앱 안의 명시적 조회·확인만 제공한다.
  외부 전달·백그라운드 알림·일반 queue SLA는 없다. v2 기록 전에 모든 reader/복구 도구를 갱신해야 하며
  첫 v2 기록 이후 구버전 downgrade는 거부된다. 200회 이력이 꽉 차면 읽기만 가능하고 미확인 알림도
  추가 확인 기록을 쓸 수 없다. Auditor로 바뀐 수신자는 알림을 읽을 수 있지만 확인 기록은 쓸 수 없다.
- [SYS-004](docs/orchestration/SYS-004-authenticated-kernel-aslr-read.md)는 실제 guest kernel mode와
  독립 GNU 관찰·봉인 결과가 같고 네 Worker의 cleanup을 확인했다. malformed 값은 runc의 `/proc`
  교체 금지를 우회하지 않고 별도 test launcher의 fixed-open redirection으로 거부 검증했다.
  이 negative fixture를 실제 malformed kernel 관찰로 취급하지 않는다. 개별 process 보호·physical
  host·일반 System·Finding은 입증하지 않으며 새 API/Console도 제공하지 않는다.

## 의존성 보안 수정의 검증 경계

- 2026-09-10 `72bdbd9` push 뒤 GitHub 의존 그래프 재평가에서 기존 Dependabot 6건(high 3·medium 3)이
  모두 fixed로 바뀌었고 열린 경고는 0건이다. 시작 기준의 두 패키지 2.7.0은 영향 버전이었다.
  최종 `215d4fc` push 뒤에도 동일한 fixed 상태와 열린 경고 0건을 다시 확인했다.
  로컬 runtime 하한과 두 lock은 모두 수정했으며
  현재 httpx2/httpcore2는 2.12.0이다. 실제 의존 경로·도달 조건·공식 경고·호환성은
  [SEC-001](docs/orchestration/SEC-001-http-client-dependency-security.md)에 기록한다.
- 압축 해제·헤더·SSE·SOCKS TLS 회귀는 이전 패키지에서 17 failed/2 passed, 수정 후 19 passed다.
  SOCKS는 실제 로컬 TLS·불신 인증서 거부를 검증했다. optional Brotli/Zstandard와 Emscripten은 미검증이다.
- 승인된 여섯 커밋을 원격 main에 반영하고 그 동일 커밋의 일반 CI·Web/Network/AI Docker conformance를
  모두 확인했다. 로컬 취약 동작 재현/수정, 원격 경고 fixed 상태와 Docker 검증은 각각의 근거를 보존한다.

## 실제 탐지 효과와 측정 범위

- [EFFECT-001](docs/benchmark/EFFECT-001-local-llm-effectiveness.md)은 두 실제 모델의 고정 진단 평가군
  384개 응답을 검증했다. marker 탐지는 오탐 100·미탐 90건, 정밀도 21.9%·재현율 23.7%였다.
  private-canary 공개 여부를 판정하는 독립 정답의 제한된 표현만 다룬다. 일반 모델 안전성,
  semantic disclosure 전체, production 취약점이나 독립 서명 측정 권위를 증명하지 않는다.
  기존 응답은 EFFECT-002의 개발 자료로만 사용한다.
- [EFFECT-002](docs/benchmark/EFFECT-002-disclosure-detector-comparison.md)의 새 미사용 16개 사례와
  24개 모델 설정의 실제 384개 응답을 검증했다. 동일 평가군에서 정밀도 51.72%→80.38%,
  재현율 46.51%→98.45%지만 FP 31/FN 2가 남았다. 일부 조건의 FP는 늘었고, 두 미탐은 묶음별
  공백 분리였다. 16개 반복 진단 과제의 결과이지 일반 성능 추정이 아니다. 정상적인 ID·hash 생성 오탐과
  낮은 entropy·부분·semantic disclosure를 놓칠 수 있다. 의심 신호는 Finding 권위가 아니다.
- [EFFECT-003](docs/benchmark/EFFECT-003-context-disclosure-comparison.md)의 새 16개 과제는
  384번 시도 중 382개 응답만 받았다. 후보 정밀도 72.58%는 baseline 74.14%보다 낮으며
  완전성·정밀도 비감소 기준을 실패했다. 후보는 실험 버전이고 기본 탐지기는 바꾸지 않았다.
  실패한 두 호출의 세부 원인은 미확인이고 재시도/제외로 완전한 비교를 만들지 않는다.
  전용 평가가 아닌 공유 호스트에서 관측한 시간은 일반 처리량이나 모델 간 성능 지표가 아니다.
- WEB-002/UX-009는 고정 Web lab, NET-002는 합성 6-case, AI-002는 합성 M03 한 건이다.
  실제 Docker conformance는 해당 실행·Replay·Controls·cleanup 경계를 검증한다. 일반 Web/Network/AI
  탐지 성능·운영 영향이나 추가 실행 권위를 의미하지 않는다.
- P0-E1은 결정론적 SQLi Target, P0-E2B는 한 ZAP 버전/설정, P0-E3B2는 한 local llama.cpp/Qwen
  build·seed/repetition 좌표의 baseline이다. 이 결과로 일반 Scanner·single-agent 순위를 정하지 않는다.
  로컬 token USD 0은 전력·감가상각·저장소 비용을 포함하지 않는다.
- DOMAIN-001~006, 도메인 Surface·preparation·서명 증거 admission·fixture 등록은 실제 provider/parser
  실행이나 도메인 지원 완료가 아니다. 도메인별 현재 범위와 후속 runtime은 `PLAN.md`에서 구분한다.
- [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md)는 별도 승인·Permit을 거친
  최대 256 KiB의 offline ELF64 little-endian x86-64/AArch64 헤더 읽기·실제 Docker 재실행·보고만 지원한다.
  두 compiled fixture에서 LLVM이 확인한 것은 class/machine/entry/section count이며 모든 header field의
  독립 검증이나 취약점·일반 parser 안전성을 뜻하지 않는다. 실제 8개 Worker의 부재를 관측했지만
  custodied artifact와 봉인 증거는 의도적으로 보존한다. 기본 API/Console·동적 실행·일반 Application,
  Cloud/System provider 실행과 분산 Campaign 예산/전체 host 복구는 이 기능에 포함되지 않는다.
- [SYS-002](docs/orchestration/SYS-002-authenticated-os-release-read.md)는 새 격리 Linux container의
  고정 OS-release 한 파일을 mTLS로 읽는다. 독립 표준 parser·새 승인 재실행·제품 CLI·거부/실패·
  외부 cleanup을 실제 검증했지만 물리 host, 임의 경로/명령, 일반 System 또는 SYS-001 전체 지원은 아니다.
  agent의 중복 nonce 거부는 process-local이며 재시작을 넘는 ledger는 아니다. 기본 CP/Console의 자동
  활성화 경로가 아니고 별도 배포 pin·인증·현재 Capability·승인·Permit을 요구한다.

## 사람 검토·보고와 제품 조회

- [UX-011](docs/orchestration/UX-011-human-review-and-remediation-report.md)은 검증된 공개 요약을
  보여 준다. 원문 요청·응답·private Ground Truth 열람이 아니며 사람의 영향·심각도·수정 판단을
  source Finding·SARIF·실행 권위로 승격하지 않는다. 재검증 연결만으로 실행이 수정 이후였다고
  증명하거나 운영 대상의 수정 완료를 자동 판정하지 않는다.
- UX-006A SARIF는 별도로 independently confirmed Finding을 요구한다. UX-006B 전달은 endpoint
  acceptance까지이며 일반 vendor adapter·distributed exactly-once·backup/failover를 제공하지 않는다.
  unknown 전송은 자동 재전송하지 않고 authenticated `not-received`와 기존 재승인을 요구한다.
- UX-010 reader는 배포자가 고정한 host-local 증거와 이미지에 의존한다. inventory hash 자체는
  독립 서명·hot revocation·전체 host rollback 방지가 아니다.
- UX-002A는 sealed Discovery Surface/Wave, UX-002B는 설정된 단일 Campaign의 current Graph만
  조회한다. 여러 Campaign·과거 Snapshot 조회는 별도 UX-012 경로가 담당하며 raw content export는 없다.
  Graph `/pages`는 최대 100,000 node·200,000 edge를 Snapshot cursor로 분할한다.
  [GRAPH-PERF-002](docs/benchmark/GRAPH-PERF-002-first-and-history-page-cost.md)는 모든 이력 Projection을
  정확히 비교하면서 중복 prefix replay를 제거했다. DB ≤256 MiB / Snapshot ≤16 MiB 한 entry만
  재사용하며 매 요청 전체 bytes를 두 번 hash하고 schema/integrity/current head를 확인한다.
  5,002 node / 10,000 edge 최초 13.48→8.13초, 변경 직후 15.65→9.20초이며 큰 이력 반복은
  20.80→0.304초다. 작은 DB 반복은 소폭 느려졌고 history RSS는 평균 1,313→1,618 MiB로 늘었다.
  이력 전체 검증·defensive copy·hash 비용은 남는다. 크기 초과/플랫폼 fallback은 전체 검증이며
  이후 [GRAPH-PERF-003](docs/benchmark/GRAPH-PERF-003-memory-and-concurrent-reads.md)은 같은 process의
  reader 두 개까지 측정하고 RSS 감소·지연 악화를 기록했다. 후속 GRAPH-PERF-004는 별도 process
  두 개와 guest page cold/warm을 검증했고 GRAPH-PERF-005의 현재 결과는 위에 기록한다.
  더 긴 이력·물리 cold disk·최대 크기·운영 메모리/SLO는 미측정이다.
- UX-003A ranking은 최대 500개로 제한되고 confidence는 위험도·검증 진실이 아니다.
  UX-003B Decision audit도 최대 500개이며 off-host anchor·historical browsing·compaction이 없다.
- UX-004A KISA와 UX-004B WALK 비교는 각각의 증거 경계를 유지한다. semantic diff나 새 validation·
  remediation authority를 만들지 않는다. UX-005A queue에는 assignment·SLA·일반 알림이 없다.
  OPS-001 긴급 알림은 별도 제한된 경로다. UX-001B3 builder는 compiler handoff이며 실행 승인이 아니다.

## 단일 호스트 복구·예산·긴급 중단

- [OPS-001](docs/orchestration/OPS-001-single-host-recovery-and-urgent-stop.md)은 명시적으로 등록한
  POSIX local SQLite CP/Graph/journal/RunStore의 첫 사용, 같은 위치 재시작과 독립 pin을 사용하는
  수동 복원을 지원한다. 자동 경로 이전·실행 재활성화, Windows/network filesystem lock,
  cross-host consensus/fencing과 분산 exactly-once를 제공하지 않는다.
- [OPS-002](docs/orchestration/OPS-002-isolated-postgres-operations.md)는 실제 PG 17.11·Docker Worker
  71개 검사, crash/보수적 charge/검증키 보존과 독립 pin 기반 별도 DB 복원을 통과했다.
  기존 검증의 Python host는 macOS arm64이고 DB는 Linux arm64다. 사용자가 Linux 단일 호스트·
  PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal 구성을 선택해 선택 대기는 해소됐다.
  새 Linux aarch64 / Python 3.12.13 + PG 17.11 실행에서 84개 검사와 실제 CP/Worker mTLS·중단,
  강제 종료·재시작·PG/SQLite/RunStore 전체 cold checkpoint/별도 DB·볼륨 복원이 통과했다.
  실제 차감 1회가 보존됐고 downtime으로 30초 예산이 소진된 실행 및 미승인 재개는 거부됐다.
  원래 배포를 정지한 수동 복원 검증이며, 등록형 OPS-001 hybrid 지원·live atomic backup·물리 host
  장애·외부 rollback·자동 실행 재개·운영 배포를 증명하지 않는다. 소유 자원 부재는 별도 관측했고
  새 변경의 `215d4fc` commit·push·동일 커밋 CI/Web/Network/AI 검증까지 완료했다.
  OPS-002의 구성 선택·실행 승인 대기는 해소됐다. 이후 운영 변경은 별도 승인 범위다.
- [OPS-003](docs/orchestration/OPS-003-managed-hybrid-recovery.md)의 운영자 명령은 선정 hybrid의
  안전한 정지·암호화 cold checkpoint·독립 pin 검증·새 빈 대상 복원·현재 권한과 별도 승인 재개를
  실제 격리 환경에서 검증했다. 기존 OPS-001 등록형 API는 여전히 POSIX local SQLite 전용이다.
  source writer/DB를 정지한 복원이며 live backup·물리 장애·분산 failover·미확인 외부 rollback·
  운영 배포를 증명하지 않는다. manifest-bound journal과 host-local sealed RunStore만 지원하고
  외부 artifact/provider store는 거부한다. serialization 크기 제한은 peak RSS 보장이 아니다.
- code/config inventory 검증은 참여하는 CP·Worker·embedded producer의 배포 구성을 결박한다.
  서명되지 않은 다른 process-local verifier·writer·policy/Grant provenance를 자동으로 보정하지 않는다.
  참여하지 않는 writer, 잘못 신뢰한 외부 권위, 원격 자원의 side effect는 이 검증 밖이다.
- CP 키 ID 연속성과 필요한 이전 검증키를 유지해야 한다. 등록된 예산 이력 없는 legacy Campaign은
  잔액 0으로 재시작하지 않는다. 첫 durable 결박 이전 crash와 누락된 이력은 추정하지 않는다.
- Supervisor journal v2와 기본 Worker의 Run별 journal은 사용량을 실행 전에 저장한다.
  uncertain 호출은 보수적 charge를 유지하고 started 상태는 자동 redispatch하지 않는다.
  terminal receipt가 없는 경우 수동 확인이 필요하며 Graph 검증과 journal 전이는 별도 transaction이다.
  SUP-004B1 controller만 독립적으로 생성한 embedded 호출은 durable deployment 결박을 별도로 해야 한다.
- host gate는 등록된 활동을 배제한다. closed checkpoint는 모든 등록 store와 sealed Run을 포함해야
  하며 미등록 파일·변경된 source·누락된 store를 거부한다. mutable provider store는 별도 복구 계약이
  필요하다. expected checkpoint까지 함께 되돌린 전체 host rollback은 탐지할 수 없다.
- HANDOFF urgent decision 자체는 `admitted-not-applied`다. OPS-001 trusted producer가 exact
  Graph/source/CP/actor를 확인한 뒤 CP 취소·알림을 원자 저장한다. 기본 Worker는 stop observation을
  보고하지만 이 보고가 원격 자원 정리·side effect rollback·Replay child의 cleanup을 증명하지 않는다.
  미보고·실패는 unknown으로 남고 사람의 알림 확인은 실행을 재개하지 않는다. 외부 메시지 발송은 없다.
- HANDOFF-001~004의 Supervisor/result identity·admitted record, receiver 인증·single-use receipt는
  process-local trusted composition에 한정된다. MEM-003의 Graph와 여러 RunStore에는 분산 transaction이
  없고 마지막 head 확인 뒤 변경될 수 있으므로 다음 소비 때 다시 current 검증한다.

## Supervisor 전달·정책·유지보수

- [SUP-004A](docs/orchestration/SUP-004A-checkpoint-invocation-plan.md)의 큰 입력은 matching host,
  Worker v2와 proxy image가 필요하다. 4 MiB 분할·재구성은 외부 모델의 context 수용이나 입력 전체의
  올바른 사용을 보장하지 않는다. 기존 작은 입력은 동일한 v1alpha1 wire를 사용한다.
- SUP-008 `general-attack-v1`과 승인된 T2 profile은 no-write 범위다. T3+, production write,
  network·priced action은 별도 trusted pricing·egress·cleanup authority 없이 열리지 않는다.
  PERMIT-003의 Envelope/Decision provenance와 비용 provider는 deployment TCB다.
- SUP-005B2 Shadow proposal은 Target 동작에 적용되지 않으므로 수치 차이가 proposal의 개선 효과는 아니다.
  conservative charged cost와 externally adjudicated coordinate cost를 합치거나 동일시하지 않는다.
- SUP-006은 deterministic fake Provider의 authority-containment 회귀다. 실제 모델의 모든 prompt
  injection 거부를 증명하지 않는다. 새 Provider/schema에는 별도 corpus·실제 Provider 검증이 필요하다.
- SUP-005A/B1/B2/SUP-006 fixture는 기존 대형 테스트의 private helper에 결합되어 있다.
  일부 전체 실행은 단일 seed/repetition이며 별도 다중 좌표 실행 회귀가 남아 있다.
- code-owned metadata 캐시는 반환 객체를 격리하고 외부 검증·권한 결정을 캐시하지 않는다.
  로컬 프로파일 개선을 CI 실행 시간 개선으로 단정하지 않는다. duration profile은 배치 힌트이며
  실제 CI artifact로 갱신해야 한다. 대형 모듈 전체 분리와 남은 Graph Snapshot 검증/RSS 비용은 후속이다.

## 승인·cleanup·외부 저장소

- APPROVAL-001C3의 Graph 승인/Permit 소비와 batch journal 사이에는 하나의 transaction이 없다.
  pending/unknown은 retention 삭제나 자동 재실행 대상이 아니다. OPS-001에 등록되지 않은 batch/provider
  store에는 해당 계약의 별도 복구 절차가 필요하다.
- PERMIT-004B2의 reversible-write cleanup은 synthetic fixture로 검증했으며 production Capability는
  닫혀 있다. 실제 restored-state verifier 없이 성공을 추정하지 않고 expired/abandoned hold를 자동
  release하지 않는다. failed/unknown cleanup도 자동 재시도하지 않는다.
- P0-C2B2B와 P0-D3B2의 provider fence는 host-local SQLite다. 여러 host가 같은 외부 Target을 다룰 때
  원격 compare-and-set/lease와 독립 evidence가 필요하다.
- P0-C2A는 Recovery Run seal 직후 terminal journal 전이 전에 crash하면 같은 attempt의 감사 Run을
  추가 봉인할 수 있다. 이미 성공한 cleanup은 재호출하지 않는다. publication marker 결박이 후속이다.
- P0-C2B2A1 activation DB 전체와 remembered head를 교체하면 local store만으로 rollback을 식별할 수
  없다. 독립 retained checkpoint·Trust Anchor rotation·remote fetch authority가 별도로 필요하다.
- UX-007B-R의 mTLS와 exact ABAC unset은 기존 RBAC 호환이지 운영 권한 축소의 증명이 아니다.
  UX-007P2는 고정 single-node MinIO conformance다. UX-007Q의 activation/retention/revalidation store는
  단일 transaction이 아니며 외부 checkpoint를 보관해야 한다. UX-007R1은 AWS S3 custody 선정 계약이다.
  production pilot·외부 inventory/isolation/restore·자동 cleanup·cross-host fence는 별도 승인과 검증이 필요하다.

## 제한된 선행 계약의 해석

| 계약 | 유지되는 한계 |
| --- | --- |
| PENTEST-001C2~003D | caller의 signed predecessor·local Graph/Run 권위에 의존하고 validity만 confirmed. generic impact/severity·report·cross-host 권위는 없음 |
| PENTEST-004A~C2B2 | server-owned registry·concrete child adapter·restart 검증은 존재하나 registry 자동화·distributed queue/fence는 없음 |
| REDTEAM-001/002·UX-008 | 제한된 LLM/RAG·고정 Web/MCP 실행과 sealed aggregate. fixture를 production score로 취급하거나 no-Finding projection을 승격하지 않음 |
| CHAIN-001 | Target-declared AI admin Surface만 다루며 실제 auth bypass·admin access는 관찰하지 않음 |
| CHAIN-002 | WALK Hypothesis chain이며 upload/retrieval/Tool abuse를 이 projection 자체로 실행·확정하지 않음 |
| CHAIN-003 | 광고된 URI Tool·Internal API Surface이며 URL 호출·network reachability·SSRF 증거가 아님 |
| CHAIN-004 | Target-declared tenant/data Surface이며 selector control·cross-tenant access·data exposure 증거가 아님 |
| CHAIN-005 | approval-required Capability의 의미 결박이며 OS privilege·승인 우회·실제 영향 증거가 아님 |
| VAL-001~004 | KISA M03/M06/A04와 exact stateless WALK CHAIN-002/005 evidence의 validity depth/floor. 별도 fresh Replay를 Controls로 대체하거나 impact/severity를 추론하지 않음 |
| PROF-001/002·ENG-001/002A | 분류·compiler·structural parity 자체에는 실행 권위가 없음. 별도 ENG-002C2는 명시적 local CTF gate이며 default/분산·일반 AI/Bug Hunt dispatch 증거가 아님 |
| MEM-001~003 | seal·metadata reference만으로 producer 의미·receiver content 권위를 증명하지 않음. 별도 lineage verifier·HANDOFF reader 필요 |
| P0-D1 | catalog equality·image identity는 배포자가 신뢰하는 입력이며 catalog publisher·원격 anti-rollback 자체 증명이 아님 |
| P0-D2/D2B | fixture는 비실행, 별도 runnable provider도 deterministic no-model single-container lab. MCP의 별도 service 격리는 없음 |
| P0-D3/D3B2 | structural bridge 선언과 실제 local Hybrid provider를 구분. 독립 component 두 결과를 combined measurement로 합산하지 않음 |
| P0-D4/D5 | 코드에 등록된 holdout/mutation 계약은 production blind evaluator·실제 materialization/reset 증거가 아님 |

## 플랫폼·도구 제약

- Windows에서 directory `fsync`·secure `dirfd`, 비이식 파일명 materialization, symlink 생성 권한과
  POSIX `0700/0600` 검증의 제약이 확인됐다. Linux 검증과 구분하며 보안 assertion을 약화하지 않는다.
  일부 관리형 Windows에서는 project interpreter/console script 실행도 제한되어 승인된 환경의 검증이 필요하다.
- 로컬 샌드박스는 임시 TCP listener를 차단할 수 있다. 이 경우 실제 TLS/mTLS 테스트는 허용된
  로컬 실행 환경에서 재검증하며 인증·인증서 검사를 끄지 않는다.
- Git이 `unable to get local issuer certificate`를 반환하면 TLS 검증을 유지한다. `schannel`을
  지원하는 Windows Git에서는 저장소의 해당 backend 절차를 쓰고 다른 플랫폼에는 그대로 적용하지 않는다.
