# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `e11561c219cd07e6088de111845e7610875d8ab0`
- 현재 구현 체크포인트: `SUP-004A` sealed non-invocable checkpoint invocation plan 구현
- 다음 구현: `SUP-004B` atomic Campaign/Supervisor dual-budget Provider receipt

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

`SUP-004A`는 verified SUP-002 input에서 exact Graph checkpoint와 future Provider request를
결정론적으로 계획하고 별도 sealed Run에 기록하지만 모델이나 실행 경로를 호출하지 않는다.

- SUP-001 v1alpha1을 변경하지 않고 additive request·budget·schedule v1alpha1 authority를 추가했다.
- request는 code-owned developer message와 complete canonical `SupervisorSnapshotInput` user JSON 두 개만
  사용하고 Tool·streaming·parallel call을 비활성화한다.
- sealed binding에는 raw message/target text/secret reference가 아니라 ordered digest·byte count와 complete
  request/schema·binding·Snapshot identity만 들어간다.
- shared pure Provider usage helper가 실제 `PolicyBoundProviderPort`와 같은 prompt/token/cost 보수적 상한을
  계산한다.
- dedicated call/token/time/cost policy는 Campaign보다 항상 attenuated되고 SUP-004A에서는 affordability만
  확인하며 `BudgetController`를 reserve하거나 소비하지 않는다.
- 같은 Campaign/Graph checkpoint exact retry는 같은 publication을 반환하고 다른 request/config/budget은
  equivocation으로 거부한다. single-flight 범위는 process-local로 명시했다.
- plan은 predecessor Run이 아닌 별도 create-only Run에 기록·seal하고 external verifier가 caller-expected
  dedicated policy, exact registered path, one-seal/one-artifact/one-event Run 형태, root/artifact SHA/event와
  current SUP-002/Graph authority를 다시 검증한다.
- Provider request/result/usage의 boolean-number coercion을 차단했다.
- model invocation, Task/Plan mutation, Scope, Capability, Permit, execution, activation은 모두 false다.

핵심 위치: `src/pajin/supervision/invocation.py`,
`src/pajin/supervision/checkpoint_scheduler.py`,
`tests/test_supervisor_checkpoint_scheduler.py`,
`docs/orchestration/SUP-004A-checkpoint-invocation-plan.md`,
`docs/adr/0120-plan-supervisor-checkpoints-before-invocation.md`.

## 현재 검증

- SUP-004A 집중 테스트: 24 passed
- SUP-004A 포함 Provider/SUP-001~003 집중 회귀: 122 passed
- 전체 Ruff 통과
- Linux 대상 strict mypy: 239 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- 해당 두 Benchmark 파일 제외 재확인: 기존 Windows symlink `WinError 1314`로 349 passed,
  6 skipped 뒤 중단
- 독립 최종 검토: P0-P2 finding 없음. 검증 기록 갱신 P3만 반영

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_checkpoint_scheduler.py tests\test_provider_session.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_model_binding.py tests\test_supervisor_snapshot_input.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

- current Provider port는 internal random ToolRequest ID를 만들고 `ProviderChatResult`만 반환하므로 caller가
  request/reservation/Gateway receipt를 동시성 안전하게 결박할 수 없다.
- separate Supervisor `BudgetController`만 쓰면 Campaign 전역 비용 상한을 우회할 수 있으므로 actual call은
  두 budget의 atomic reserve/rollback/commit이 필요하다.
- raw Gateway evidence는 full request를 포함하므로 target-tainted model input을 그대로 audit artifact에
  복제하지 않는 secret-free receipt projection이 선행돼야 한다.
- 이 세 공백을 숨기지 않기 위해 SUP-004A는 `scheduled-not-invoked`에서 멈추며 실제 Provider/Gateway/
  Worker 호출 경로를 import하거나 실행하지 않는다.
- strict Pydantic wire가 `true`를 token/chunk 1로 coercion하던 문제를 발견해 request/result/usage에서
  exact JSON scalar type을 요구하도록 보강했다.
- 읽기 전용 병렬 조사가 request/receipt 분리, existing Graph reason 재사용, 별도 sealed Run, shared usage
  estimate와 actual dual-budget 필요성을 확인했고 설계에 반영했다.

## 다음 조치

`SUP-004B`에서 먼저 기존 `PolicyBoundProviderPort`에 stable request ID와 secret-free bound outcome을
반환하는 additive 경계를 설계한다. Campaign 전역 `BudgetController`와 Supervisor dedicated controller의
보수적 reservation을 원자적으로 함께 처리하고, intent 기록 뒤 실패는 자동 재호출하지 않으며
`indeterminate` terminal로 봉인한다. exact plan/request/Gateway/Provider/usage/draft receipt를 current
authority와 함께 재검증한 뒤에만 SUP-003 compiler로 전달한다. raw prompt/rationale/secret reference를
receipt에 넣거나 Scheduler output으로 Task·Plan·Capability·Permit·execution을 적용해서는 안 된다.

## 알려진 경계

- SUP-004A는 process-local scheduling single-flight만 제공하며 cross-process claim과 crash-after-dispatch
  분류를 제공하지 않는다.
- SUP-004A affordability는 reservation/usage가 아니며 actual Provider receipt가 없다.
- SUP-004A는 canonical SUP-002 user JSON이 현재 `ProviderMessage`의 65,536자 한도를 넘으면 publication 전에
  fail closed한다. SUP-002 자체의 더 큰 projection ceiling 전체를 호출 가능하다고 주장하지 않는다.
- SUP-002 v1은 current Collaboration Snapshot만 materialize하고 WALK-006 Snapshot actual projection은 없다.
- 전체 pytest의 기존 Benchmark fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
