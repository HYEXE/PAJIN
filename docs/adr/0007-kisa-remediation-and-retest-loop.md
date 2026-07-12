# ADR-0007: KISA 완화 계획과 증적 기반 재검증 폐루프

- Status: Accepted
- Date: 2026-07-12

## Context

초기 KISA Mode Pack은 취약점 발견·독립 검증·보고까지 수행하지만 완화 방안, 개선 과제,
재검증, 정상 기능과 회귀 확인은 미충족으로 남겼다. 단순히 후속 Run에서 Finding이 사라진
사실만으로 수정 완료를 선언하면 실행 실패, 증적 손실, Validator 오류를 실제 수정으로
오인할 수 있다. 보안 통제가 정상 기능을 훼손해도 공격 결과만 비교하면 이를 발견하지
못한다.

완화 계획의 담당자·기한·운영 반영은 조직의 권한과 맥락이 필요하므로 PAJIN이 임의로
채워서도 안 된다.

## Decision

### 계획이 실행보다 먼저다

1. `kisa-plan-remediation`은 완료된 기준 Run의 검증 Finding만 사용해 위협별 기술 통제와
   수용 기준을 생성한다.
2. 계획은 안정적 Finding fingerprint, 기준 Finding ID, 위협, 원본 증적, 통제, 최소 두 번의
   동일 공격과 정상 기능 성공 기준을 포함한다.
3. 담당자와 기한은 제공되지 않은 경우 비워 두고 `requires_human_assignment`로 표시한다.
4. 계획 생성 이벤트를 기준 Run에 기록한다. `kisa-retest`는 계획이 없으면 실행 전에 이를
   생성하고, 비교 단계는 기준 Run의 계획이 없거나 Finding과 불일치하면 실패한다.

### 공격 재검증과 정상 기능을 분리한다

1. `KISARetestPlannerRuntime`은 기존 KISA 공격 시나리오를 같은 반복 수로 실행한다.
2. 별도 등록 Tool `ai.normal-probe`가 일반 사용자 입력을 두 번 실행하고 기대 정상 응답을
   확인한다.
3. 정상 기능 Tool은 공격 Finding을 만들지 않으며 공격 성공률·차단율·민감정보 노출 지표에
   포함되지 않는다.
4. 공격과 정상 기능 호출 모두 Tool Gateway, Scope, egress proxy, Docker Worker, Capability
   예산과 증적 경계를 그대로 사용한다.

### 수정 판정은 증명 가능해야 한다

1. Finding fingerprint는 위협 코드, 대상, 정규화 제목으로 계산하며 실행별 임의 Finding ID와
   분리한다.
2. 재검증에서 같은 fingerprint가 독립 검증되면 `still-vulnerable`이다.
3. Finding이 없더라도 동일 위협의 기대 반복 횟수가 모두 성공적으로 실행되고 각 결과의
   공격 신호가 false인 경우에만 `fixed`다.
4. 반복 횟수 미달, 도구 실패, 증적 누락, 비취약 판정 부족은 `inconclusive`다.
5. 기준에 없는 fingerprint는 `new`로 분리한다.
6. 정상 기능 증적이 기대 횟수보다 적으면 `not-measured`, 실패가 있으면 `fail`, 모두 통과하면
   `pass`다.

### 원본 체크리스트는 덮어쓰지 않는다

재검증 서비스는 원본 KISA 체크리스트를 수정하지 않고 `kisa-checklist-overlay.json`을 만든다.
완화 방안, 재검증, 정상 기능, 회귀 확인은 증적에 따라 갱신하지만 실제 담당자·기한은 계속
`needs-review`다. Overlay는 대체하는 항목 ID를 명시하고 준수 인증이 아니라는 제한을
보고서에 유지한다.

## Consequences

### Positive

- 실행 실패와 증적 손실을 수정 완료로 오인하지 않는다.
- 기준 Finding부터 완화 계획, 재검증 증적, 최종 상태까지 추적할 수 있다.
- 보안 통제가 정상 기능을 훼손하는 회귀를 별도 실패로 처리한다.
- CI에서 남은 취약점, 불확실 판정, 신규 Finding, 회귀 실패를 non-zero 종료로 차단할 수 있다.
- 조직 정보가 없는 담당자·기한을 자동으로 조작하지 않는다.

### Trade-offs and residual risks

- 제목이 크게 바뀐 동일 근본 원인은 새 fingerprint로 인식될 수 있다. 장기적으로 명시적
  scenario/root-cause ID를 Finding 모델에 추가해야 한다.
- 현재 완화 통제는 M03·M06·A04 템플릿이며 실제 코드 변경을 자동 적용하지 않는다.
- 정상 기능은 하나의 대표 Chat 응답을 검사한다. 실제 업무별 golden dataset과 의미 기반
  품질 판정이 필요하다.
- Overlay를 조직의 최종 체크리스트로 병합하고 승인하는 단계는 사람 워크플로가 필요하다.

## Verification

```powershell
docker compose -f containers/compose.ai-lab.yaml up --build --detach
.venv\Scripts\pajin kisa-run examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
.venv\Scripts\pajin kisa-plan-remediation <baseline-run-directory>
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml up --detach --force-recreate
.venv\Scripts\pajin kisa-retest <baseline-run-directory> `
  examples\kisa-ai-chat-lab.yaml --worker docker --repetitions 2
docker compose -f containers/compose.ai-lab.yaml `
  -f containers/compose.ai-lab.hardened.yaml down
```

인수 조건은 계획 이벤트가 재검증 시작보다 먼저 발생하고, M03·M06·A04가 각각 두 개의
비취약 Docker 증적으로 `fixed`, 정상 기능이 2/2 `pass`, 신규·미확정 결과가 0건이며 모든
호출이 egress proxy allow 증적을 갖고 종료 후 컨테이너·네트워크가 남지 않는 것이다.
