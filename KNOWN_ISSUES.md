# PAJIN 알려진 문제

현재 구현의 미해결 제약과 검증 공백을 기록한다. 제품 우선순위는 `PLAN.md`, 실제 실행 결과와
Git 상태는 `HANDOFF.md`, 상세 요구와 권한 경계는 각 버전형 계약이 권위다.

## 현재 통합 검증

- `e7c8243`의 일반 CI와 Web/Network/AI exact-clean Ubuntu Docker 검증이 모두 통과했다.
  8,095 passed·76 opt-in skipped와 세 실제 Docker 검증의 cleanup·zero residue를 확인했다.
  이후 변경은 [MEASURED-CONFORMANCE](docs/orchestration/MEASURED-CONFORMANCE.md)에 따라 재검증한다.
- 로컬 Docker daemon은 마지막 조회에서 부재했다. 새 이미지의 Ubuntu 검증은 원격에서 완료했으며
  로컬 재실행 가능 여부와 구분한다. HTTPS 단위 경로만으로 Docker 격리·cleanup을 대신하지 않는다.
- 새 CP v15/v16·복구·중단 경로는 SQLite로 검증했다. PostgreSQL SQL·제약 검사는 존재하지만
  실제 PostgreSQL migration·경합·재시작 검증은 남아 있다.
- 전체 로컬 pytest의 최종 결과와 환경별 재실행은 `HANDOFF.md`에 기록한다.

## 의존성 후속 보완

- 2026-09-09 원격 dependency graph 갱신 후 열린 Dependabot 경고 6건(high 3·medium 3)을 확인했다.
  현재 `uv.lock`은 `httpx2==2.7.0`, `httpcore2==2.7.0`이며 경고의 영향 버전에 해당한다.
- `httpx2`의 압축 응답 메모리 증폭은 [GHSA-8xx6-hgc6-gc2m](https://github.com/advisories/GHSA-8xx6-hgc6-gc2m),
  두 패키지의 SOCKS 경유 WebSocket TLS 문제는 [GHSA-7mj9-2mp8-4m2p](https://github.com/advisories/GHSA-7mj9-2mp8-4m2p)에
  기록되어 있다. 나머지는 요청 헤더 조합·multipart 헤더·SSE buffering 경고다.
  모든 경고를 포함하는 수정 버전의 하한은 httpx2 2.12.0, httpcore2 2.10.0이다.
- 이 잠금 버전은 이번 변경 전부터 존재했다. 영향받는 제품 경로의 도달 가능성 평가는 아직 하지 않았다.
  의존성 호환성과 Provider/HTTP 회귀를 검증하는 별도 갱신이 필요하며 CI 통과를 이 경고의 해소로 보지 않는다.

## 실제 탐지 효과와 측정 범위

- [EFFECT-001](docs/benchmark/EFFECT-001-local-llm-effectiveness.md)은 두 실제 모델의 고정 진단 평가군
  384개 응답을 검증했다. marker 탐지는 오탐 100·미탐 90건, 정밀도 21.9%·재현율 23.7%였다.
  private-canary 공개 여부를 판정하는 독립 정답의 제한된 표현만 다룬다. 일반 모델 안전성,
  semantic disclosure 전체, production 취약점이나 독립 서명 측정 권위를 증명하지 않는다.
  탐지기 개선에는 이번 응답으로 튜닝하지 않은 새 미사용 평가군이 필요하다.
- WEB-002/UX-009는 고정 Web lab, NET-002는 합성 6-case, AI-002는 합성 M03 한 건이다.
  실제 Docker conformance는 해당 실행·Replay·Controls·cleanup 경계를 검증한다. 일반 Web/Network/AI
  탐지 성능·운영 영향이나 추가 실행 권위를 의미하지 않는다.
- P0-E1은 결정론적 SQLi Target, P0-E2B는 한 ZAP 버전/설정, P0-E3B2는 한 local llama.cpp/Qwen
  build·seed/repetition 좌표의 baseline이다. 이 결과로 일반 Scanner·single-agent 순위를 정하지 않는다.
  로컬 token USD 0은 전력·감가상각·저장소 비용을 포함하지 않는다.
- DOMAIN-001~006, 도메인 Surface·preparation·서명 증거 admission·fixture 등록은 실제 provider/parser
  실행이나 도메인 지원 완료가 아니다. 도메인별 현재 범위와 후속 runtime은 `PLAN.md`에서 구분한다.

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
  조회한다. historical browsing·snapshot listing·multi-Campaign routing·raw content export는 없다.
  Graph `/pages`는 최대 100,000 node·200,000 edge를 Snapshot cursor로 분할하지만 매 페이지 전체
  이력을 다시 검증한다. 응답·DOM 크기를 줄인 것이며 서버 검증 비용은 데이터 크기에 비례한다.
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
  실제 CI artifact로 갱신해야 한다. 대형 모듈 전체 분리와 Graph 검증 비용 최적화는 후속이다.

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
