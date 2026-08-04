# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `77cc736bb1cfcce9e93077bde4088e6c454fb7ae`
- 현재 구현 체크포인트: `SUP-004B1` atomic Campaign/dedicated model budget 구현
- 다음 구현: `SUP-004B2` stable Provider request·secret-free bound outcome

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

`SUP-004B1`은 existing Provider lifecycle이 Campaign 전역 budget과 dedicated model budget을 하나의
원자적 process-local reservation으로 함께 처리할 수 있게 한다.

- 각 `BudgetController`가 usage check·mutation·reservation·restore·snapshot을 내부 `RLock`으로 보호한다.
- `DualModelUsageBudget`은 두 controller lock을 object identity 순서로 함께 잡고 같은 model/Tool-call,
  prompt/completion token, cost 상한을 양쪽에 예약하며 더 짧은 남은 duration을 적용한다.
- Campaign이 먼저 통과한 뒤 dedicated가 거부해도 Campaign reservation을 lock 해제 전에 rollback하므로
  partial charge가 남지 않는다.
- 두 internal reservation 뒤 composite publication이 실패해도 양쪽을 rollback하며, Campaign budget과
  Tool Loop checkpoint restore의 boolean-number coercion을 ingress에서 차단한다.
- Provider 성공·executed failure·timeout·cancel·불확실성은 기존 보수 정책대로 양쪽 상한을 commit하고,
  Gateway가 `executed=false`를 증명한 경우에만 양쪽을 함께 release한다.
- direct Campaign caller와 dual caller도 같은 Campaign lock에서 경쟁하므로 마지막 capacity를 동시에
  소비할 수 없다.
- composite reservation은 내부 단일 reservation handle을 노출하지 않으며 exact active object만
  commit/release할 수 있다.
- 기존 `PolicyBoundProviderPort` caller는 바뀌지 않고 optional dual boundary를 공급한 경로만 양쪽을 쓴다.
- stable request ID, Provider bound outcome, durable claim, Supervisor receipt와 실제 SUP-003 전달은 아직 없다.

핵심 위치: `src/pajin/runtime/control.py`, `src/pajin/providers/session.py`,
`tests/test_control.py`, `tests/test_provider_session.py`, `tests/test_manifest.py`,
`tests/test_tool_loop.py`,
`docs/orchestration/SUP-004B1-atomic-dual-model-budget.md`,
`docs/adr/0121-atomically-charge-campaign-and-dedicated-model-budgets.md`.

## 현재 검증

- control 집중 회귀(Windows symlink case 제외): 34 passed, 1 deselected
- Provider·Manifest 집중 회귀: 52 passed
- SUP-004B1 인접 Control·Provider·Manifest·Tool Loop·SUP-004A 회귀: 146 passed,
  2 deselected(Windows symlink, POSIX file mode assertion)
- 전체 Ruff 통과
- Linux 대상 strict mypy: 239 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- 두 선행 Benchmark 파일 제외 재확인: 다른 기존 Benchmark registry fixture 만료로 219 passed,
  3 skipped 뒤 중단
- 독립 공격 검토: P1 composite publication rollback, P2 persistent boolean coercion,
  P3 duration 문서 과장을 발견해 모두 수정했다. 수정 후 독립 재검토 87 passed, 1 deselected,
  변경 Ruff·Linux mypy·diff check 통과, 잔존 P0-P3 finding 없음.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_control.py -k "not symlink"
.\.venv\Scripts\python.exe -m pytest -q tests\test_provider_session.py tests\test_manifest.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_control.py tests\test_provider_session.py tests\test_manifest.py tests\test_tool_loop.py tests\test_supervisor_checkpoint_scheduler.py -k "not symlink and not test_high_risk_tool_waits_for_exact_approval_and_resumes_in_new_run"
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

- composite 자체 lock만으로는 direct Campaign caller와 경쟁하지 못한다는 문제를 병렬 조사에서 확인해
  lock을 각 `BudgetController` 내부에 두고 dual boundary가 두 lock을 stable order로 함께 잡도록 했다.
- sequential reserve의 두 번째 거부가 partial state를 만들 수 있으므로 Campaign rollback도 lock 안에서
  완료한다. dedicated denial·thread competition·commit·proven non-execution release를 음성/경쟁 테스트로
  확인했다.
- runtime numeric API와 persistent restore에서 `true`가 token/cost/duration 1로 취급될 수 있어 Campaign
  budget ingress, model usage, checkpoint restore에 exact boolean rejection을 요구했다.
- 독립 리뷰가 composite publication fault 뒤 handle 없는 양쪽 charge가 남는 P1을 재현해 publication 전체를
  rollback 범위에 넣고 UUID fault-injection 회귀를 추가했다. duration reservation 문서 과장 P3도 실제
  minimum-remaining enforcement로 정정했다.
- stable request ID만으로는 Gateway의 Run-local request reservation을 넘어 restart/new Run at-most-once를
  보장할 수 없다. SQLite CAS journal과 secret-free outcome을 다음 두 별도 경계로 유지한다.

## 다음 조치

`SUP-004B2`에서 기존 `PolicyBoundProviderPort.chat()`을 유지하면서 caller-supplied stable request ID와
ephemeral raw `ProviderChatResult`, serializable secret-free bound outcome을 분리하는 additive API를 만든다.
Gateway와 Provider가 하나의 public canonical ToolRequest digest helper를 공유하고 request/chat/decision/
ToolResult/WorkerResult/ProviderResult digest, exact reported usage와 B1 charged bound를 결박한다. outcome에는
raw prompt/content/refusal/tool arguments/stdout/stderr/secret reference를 넣지 않는다. `SUP-004B3`가 이
경계를 SQLite durable claim과 sealed Supervisor receipt에 연결하기 전에는 model-backed draft를 SUP-003에
전달하지 않는다.

## 알려진 경계

- SUP-004A는 process-local scheduling single-flight만 제공하며 cross-process claim과 crash-after-dispatch
  분류를 제공하지 않는다.
- SUP-004A affordability는 reservation/usage가 아니며 actual Provider receipt가 없다.
- SUP-004B1 budget 원자성은 같은 process에서 공유하는 두 controller에 한정된다. 독립 process의 전역
  Campaign budget이나 at-most-once Provider dispatch를 주장하지 않는다.
- SUP-004A는 canonical SUP-002 user JSON이 현재 `ProviderMessage`의 65,536자 한도를 넘으면 publication 전에
  fail closed한다. SUP-002 자체의 더 큰 projection ceiling 전체를 호출 가능하다고 주장하지 않는다.
- SUP-002 v1은 current Collaboration Snapshot만 materialize하고 WALK-006 Snapshot actual projection은 없다.
- 전체 pytest의 기존 Benchmark fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
