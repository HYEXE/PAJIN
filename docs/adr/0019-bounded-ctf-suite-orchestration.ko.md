> Languages: [English](0019-bounded-ctf-suite-orchestration.en.md) | [한국어](0019-bounded-ctf-suite-orchestration.ko.md)

# ADR 0019: 경계가 제한된 CTF Suite 오케스트레이션

- 상태: Accepted
- 날짜: 2026-07-13

## 맥락

Web 및 Crypto CTF Mode Pack은 각각 역할이 다섯 개인 Campaign 하나를 실행할 수 있다. 이들을
따로 실행하면 단일 Campaign 안에서 범주를 인식하는 동적 Specialist 생성을 입증할 수 없고,
운영자가 두 증거 루트를 수동으로 연계해야 한다. Suite는 형식이 지정된 두 챌린지를 개방형
대상 목록으로 바꾸는 대신 각 구성원의 더 강한 경계를 유지해야 한다.

## 결정

PAJIN은 정확히 두 개의 `CTFChallenge` 매니페스트, 즉 `web.exposed-backup-config` 구성원 하나와
`crypto.single-byte-xor` 구성원 하나를 위한 `ctf-suite-run`을 추가한다. 챌린지 ID는 고유해야
하며 두 매니페스트가 같은 승인 권한자를 명시해야 한다. 각 권한 부여 기간은 겹쳐야 한다.
Suite 권한 부여는 더 늦은 승인 시각에 시작하고 더 이른 만료 시각에 끝난다. Suite 권한 부여
증거의 정규 다이제스트는 구성원의 신원과 범주, 구성원 권한 부여 전체, 예상 플래그 다이제스트를
결속한다.

컴파일러는 재현성을 위해 대상을 Web, Crypto 순으로 정렬하고 다음 고정 예산을 도출한다.

- 에이전트 여섯 개: Supervisor, Planner, Specialist 두 개, Validator, Reporter
- 생성 깊이 1
- Tool 호출 두 번 및 모델 공급자 호출 0번
- 외부 서비스 비용 0
- 이미 경계가 제한된 두 구성원의 실행 시간에 해당하는 기간

Campaign 수준의 범위, 허용 메서드, Tool 범주, 금지 사항, 중지 조건은 두 구성원 프로필에
필요한 합집합으로 정한다. Web 프로브가 T1이므로 최대 위험 등급은 T1이며 Web 요청 상한은
그대로 Campaign의 상한이 된다. 이 합집합은 어느 Specialist에게도 다른 구성원의 권한을
부여하지 않는다. 결정론적 계획은 대상마다 단계 하나를 만들고, 오케스트레이터는 해당 단계의
Tool과 대상만 담은 별도의 Capability Grant를 위임한다. Crypto Worker는 계속
`NetworkMode.NONE`을 받고, Web Worker는 루프백에 바인딩된 픽스처를 위한 고정 송신 정책만
받는다.

다중 에이전트 러너의 호출 예산 할당기는 재시도 슬롯을 배정하기 전에 각 Specialist의 첫 번째
시도 하나를 예약한다. 따라서 정확히 두 번 호출할 수 있는 Suite 루트 예산은 Web과 Crypto에
각각 한 번씩 배정된다. 고정된 두 Tool 모두 별도의 `parallelSafe` 계약을 선언하므로 로컬
스케줄러는 계획 순서의 결과를 유지하면서 하나의 제한된 웨이브에서 이들을 실행한다. 어느
구성원도 다른 구성원이 시작하기 전에 소진할 수 있는 재시도 슬롯을 받지 않는다.

마무리 단계에서는 먼저 핵심 Run 봉인을 검증하고 형식이 지정된 원본 매니페스트에서 정확한
Suite Campaign을 재구성한다. 그런 다음 각 Tool 결과를 해당 계획 요청, 대상, 범주 Tool,
동일 Run의 증거, Mode별 다이제스트 검증 완료 풀이 관측과 결속한다. 각 구성원은 독립적으로
`solved`, `unsolved`, `invalid-flag` 중 하나로 분류된다. 집계된 `ctf-suite-result.json`과
`ctf-suite-writeup.md`를 추가한 뒤 두 번째로 봉인한다. 점수판 제출을 위한 자격 증명, 클라이언트,
라우트는 존재하지 않는다.

## 결과

이제 하나의 Campaign이 범주를 인식하는 Specialist 생성을 입증하고 검증 가능한 단일 Suite
증거 체인을 생성한다. CLI 매니페스트 순서를 뒤집어도 컴파일된 계약은 바뀌지 않는다. 승인
불일치, 겹치지 않는 기간, 중복 신원, 중복 범주, Campaign 드리프트, 누락된 검증, 설명되지 않은
발견 사항이 있으면 폐쇄적으로 실패한다.

MVP는 의도적으로 범용 CTF 재생 목록이 아니다. 세 번째 구성원, 반복 범주, 분산 스케줄링,
새 챌린지 유형, 외부 아티팩트 또는 점수판 통합을 추가하려면 별도의 결정과 추가 정책 계약이
필요하다.
