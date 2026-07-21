> Languages: [English](0015-fixed-bug-bounty-lab-execution.en.md) | [한국어](0015-fixed-bug-bounty-lab-execution.ko.md)

# ADR 0015: 고정된 Bug Bounty local-lab 실행

- 상태: 승인됨
- 날짜: 2026-07-13
- 확인 의미 체계 개정: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)

> 원래 통제 집합의 관찰 결과를 다시 계산하는 것은 증거 검토이지 독립 재현이 아니다. ADR
> 0027에서는 보안 Finding이 제품 수준의 `confirmed` 상태가 되기 전에 별도의 재실행 요청과
> 증거 계보를 요구한다.

## 배경

범위 파서와 보수적 리포터는 권한 부여 및 보고 경계를 설정하지만 완전한 Bug Bounty 다중 에이전트
실행을 입증하지는 않는다. 모델이 선택한 범용 익스플로잇을 실행하면 현재의 안전성 논증을 넘어선다.
에이전트의 주장을 검증으로 취급하면서 제한 없는 페이로드, 트래픽, 엔드포인트 및 데이터 접근을
도입할 수 있기 때문이다.

PAJIN에는 공용 시스템이나 실제 사용자 데이터를 대상으로 하지 않으면서 Docker Worker, 이그레스
프록시, Planner, Specialist, Validator, 증거 저장소 및 초안 리포터를 실행하는 실제적이고 재현
가능한 수직 단면이 필요하다.

## 결정

PAJIN에 하나의 실행 가능 자산 프로필 `boolean-sqli-lab`을 추가한다. 다음 조건이 모두 충족될
때만 사용할 수 있다.

- `BugBountyProgram` 플랫폼이 `local-lab`이다.
- 사설 네트워크 접근이 명시적으로 활성화되어 있다.
- 실행 가능한 모든 진입점이 `host.docker.internal`을 사용한다.
- 컴파일된 대상 타입이 `bug-bounty-api`다.
- 승인된 Tool 범주에 고정 프로브가 선언한 모든 범주가 포함되어 있다.

로컬 대상에는 합성 레코드 두 개가 있고 호스트 루프백 포트 8770에만 바인딩된다. 취약 프로필은
하나의 정확한 Boolean SQL 인젝션 신호를 모델링하며, 강화 프로필은 숫자가 아닌 식별자를
거부한다. 어느 프로필에도 자격 증명, 영속 상태, 프로덕션 데이터 또는 외부 제출 경로가 없다.

`BugBountyPlannerRuntime`은 컴파일된 각 랩 대상마다 타입이 지정된
`bug-bounty.boolean-sqli-probe` 단계 하나를 방출한다. Tool 입력에는 고정 시나리오 식별자만
포함된다. 그 외의 메서드, 쿼리, 프래그먼트 및 엔드포인트 경로는 거부한다. 신뢰할 수 있는
Worker가 세 개의 고정 요청 값을 소유하며, Gateway가 주입한 이그레스를 통해 정확히 기준선,
거짓 대조군 및 참 Boolean 비교를 수행한다. 캠페인 속도 제한이 실제 HTTP 요청 수를 측정하도록
Tool은 요청 비용을 3으로 선언한다.

`BugBountyValidatorRuntime`은 관찰 결과를 다시 파싱하고 다음 사항을 독립적으로 요구한다.

1. 합성 레코드 하나를 포함한 200 기준선
2. 비어 있는 200 또는 400 음성 대조군
3. 기준선보다 더 많은 레코드를 포함한 200 Boolean 프로브
4. 모든 관찰 결과의 합성 마커
5. 연결된 Specialist 결과가 생성한 증거

Validator는 Worker의 `vulnerable` 값과 파생된 검사 불리언을 의도적으로 무시한다. 다시 계산한
양성 결과는 정확한 `CWE-89` Candidate로 일반 validation gate에 들어간다. Gate는 request,
evidence provenance, target, scope 및 semantic 결합을 강제한 뒤
`independent-reproduction-missing` 사유의 `needs-review`를 기록한다. 이 원래 control-set 실행은
제품 Confirmed Finding projection을 채우지 않는다. Bug Bounty 리포터는 봉인된 이
Candidate/Decision 쌍을 사용하여 `submission_eligible=false`인 명확한
`semantic-review-only` 초안 하나를 만든다. 강화 결과는 Candidate도 초안도 만들지 않는다.

`bug-bounty-run`은 Docker 전용이다. 모의 실행 옵션이 없으며 외부로 제출하지 않는다. 일반적인
공개 Bug Bounty 프로그램도 검토하고 컴파일할 수는 있지만, 별도로 제한된 프로브 프로필이
존재하기 전에는 Planner가 실행을 거부한다.

## 결과

이 단면은 공격 문법과 트래픽을 유한하게 유지하면서 실제 HTTP 대상을 상대로 완전한 아키텍처를
입증한다. 취약/강화 프로필 쌍은 결정론적인 양성 및 음성 통합 테스트도 제공한다.

이는 범용 SQL 인젝션 스캐너가 아니다. 매개변수를 발견하거나, 임의의 페이로드를 허용하거나,
크롤링하거나, 레코드를 열거하거나, CVSS를 계산하거나, 바운티 플랫폼에 인증하거나, 프로덕션
대상이 취약하다는 사실을 입증하지 않는다. 다른 취약점 클래스를 추가하려면 타입이 지정된 새로운
프로필, Worker 명령, 요청 비용, Mode가 소유하는 증거 검토 및 재실행 계약, 안전성 검토가 필요하다.

## 검증

테스트는 프로필 컴파일 및 사설 네트워크 제한, 고정 Tool 입력, Gateway 전용 이그레스, 3단위
요청 한도 예약, 독립적인 관찰 결과 재계산, 강화 프로필의 거부, 5개 역할의 다중 에이전트 실행,
봉인된 Candidate/Decision authority, 취약한 경우의 review-only 초안 생성, 강화된 경우의
무-Candidate/무-초안 동작, Docker 전용 CLI 선택 및 합성 대상의 동작을 다룬다. Docker 통합
시퀀스는 동일한 다이제스트 승인 Campaign을 통해 취약 프로필과 강화 프로필을 모두 실행한다.
