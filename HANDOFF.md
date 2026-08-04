# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `733a2c1bdfb779b896638d350747ec06231a2d85`
- 현재 구현 체크포인트: `SUP-004B2` stable Provider request·secret-free bound outcome
- 다음 구현: `SUP-004B3` durable Supervisor invocation journal·sealed draft receipt

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

`SUP-004B2`는 기존 Provider lifecycle에 caller-owned stable Tool request ID와 성공 전용
content-addressed outcome을 additive하게 연결한다.

- `PolicyBoundProviderPort.chat_bound()`는 portable stable ID를 실제 Gateway `ToolRequest`에 그대로
  주입하고 ephemeral raw `ProviderChatResult`와 serializable `ProviderBoundChatOutcome`을 분리해 반환한다.
- invalid·Windows reserved·case-fold collision request/evidence coordinate는 budget reservation,
  Capability consumption, Gateway, Worker 전에 거부된다.
- Gateway reservation, 기존 Capability activation compatibility wrapper와 Provider outcome이
  `canonical_tool_request_digest()` 하나를 공유하므로 exact `requestSha256` 계산이 갈라지지 않는다.
- `pajin.dev/provider-bound-chat-outcome/v1alpha1`은 complete Provider registration을 secret reference 원문 없이
  digest로 결박하고 grant/chat/ToolRequest/Policy/ToolResult/WorkerResult/Gateway/ProviderResult/evidence,
  reported usage와 conservative charged projection을 domain-separated digest로 결박한다.
- verifier는 code-owned expected ToolRequest를 다시 만들고 canonical digest exact equality를 요구한다.
  conservative token/cost bound도 독립 재계산하며 Campaign/dual scope는 별도 expected input과 비교한다.
- outcome에는 raw prompt/content/refusal/tool arguments/endpoint/secret reference/Worker transcript가 없다.
  기존 Gateway evidence는 그대로 민감하며 B2가 제거하거나 정제하지 않는다.
- Policy·ToolResult·Gateway·Worker·Provider·usage·outcome 성공 scalar는 boolean/integer coercion을 거부하고
  usage cost의 `-0.0`을 canonical `+0.0`으로 정규화한다.
- proven non-execution만 B1 reservation을 release하고 dispatch·불확실성·invalid raw output·outcome construction
  failure는 conservative charge를 유지한다. 성공 event만 bound outcome ID/digest를 additive하게 기록한다.
- 기존 `chat()`·`complete()` signature, random request ID, raw return, event payload와
  `pajin.providers.session.ProviderModelUsageBound` import 경로는 유지된다.
- durable claim, evidence bytes/root/seal, actual Supervisor call, sealed draft receipt와 SUP-003 admission은 없다.

핵심 위치: `src/pajin/providers/receipts.py`, `src/pajin/providers/session.py`,
`src/pajin/providers/usage.py`, `src/pajin/tools/gateway.py`, `src/pajin/runtime/store.py`,
`src/pajin/domain/models.py`, `src/pajin/policy/engine.py`, `src/pajin/runtime/worker.py`,
`tests/test_provider_session.py`, `tests/test_gateway.py`, `tests/test_worker.py`,
`docs/orchestration/SUP-004B2-stable-provider-bound-outcome.md`,
`docs/adr/0122-bind-stable-provider-requests-to-secret-free-outcomes.md`.

## 현재 검증

- Provider·Gateway·Worker 핵심 회귀와 독립 재검토: 178 passed
- Capability rollout·SUP-004A·Provider transport/agent 인접 회귀: 92 passed
- Capability authority 단독 회귀: 7 passed
- 전체 Ruff 통과
- Linux 대상 strict mypy: 241 source files 통과
- 전체 `pytest -x -q`: 기존 Benchmark registry fixture 만료로 190 passed, 3 skipped 뒤 중단
- 독립 공격 검토: charge scope 자기서명, JSON 숫자형 치환, signed-zero digest 다중성,
  secret reference substitution, nonportable request/evidence coordinate, legacy import 단절과 문서 과장을
  발견해 모두 수정했다. 최신 diff 재검토에서 잔존 P0-P3 finding 없음.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_gateway.py tests\test_provider_session.py tests\test_worker.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_existing_capability_rollout.py tests\test_supervisor_checkpoint_scheduler.py tests\test_provider.py tests\test_provider_agents.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_capability_authorities.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

- caller가 outcome과 charged usage를 함께 축소하거나 scope를 바꿔 verifier에 전달할 수 있어 token/cost를
  공용 pure bound로 재계산하고 scope를 별도 expected input으로 분리했다.
- Provider runtime digest에서 `secret_ref`를 제외하면 credential reference substitution을 놓치므로 complete
  registration을 원문 노출 없이 digest한다. digest는 encryption이 아니며 low-entropy 값을 숨긴다고 주장하지 않는다.
- Python dict equality가 JSON `10`과 `10.0`을 같게 취급하므로 expected ToolRequest를 재구성하고 canonical
  digest로 비교한다. signed zero도 JSON identity를 나누지 못하게 `+0.0`으로 정규화한다.
- ToolRequest regex가 허용하는 `CON`, `AUX`, `COM1` 같은 ID는 RunStore artifact path가 거부한다. bound API와
  standalone outcome 모두 RunStore portable path를 사전 검증해 Worker 없는 phantom charge를 차단한다.
- outcome은 Run membership, seal, evidence artifact authenticity나 live budget ledger state를 증명하지 않는다.
  문서의 과대표현을 제거하고 B3 책임으로 명시했다.
- `tests/test_capability_authorities.py`가 같은 process에서 SUP-004A보다 먼저 실행되면 schema digest가 달라지는
  별도 import-order 문제가 재현돼 `KNOWN_ISSUES.md`에 기록했다. 두 파일은 별도 process에서 통과한다.

## 다음 조치

`SUP-004B3`의 가장 작은 수직 슬라이스를 설계한다. 먼저 기존 SQLite/CAS journal과 sealed Run receipt 패턴을
재사용할 수 있는지 조사하고, exact SUP-004A schedule/request binding에서 stable request ID를 결정해
intent-before-dispatch로 claim한다. 상태는 최소한 crash-before-dispatch, dispatch-started/outcome-unknown,
terminal-success를 구분하고 자동 redispatch는 false로 유지한다. 실제 Shadow Supervisor 경로는
`budgetScope=campaign-and-dedicated`를 강제하며 exact schedule, request, Gateway evidence artifact SHA/root,
B2 outcome, usage와 raw draft/schema를 하나의 sealed receipt에 결박한다. consumer가 journal·Run·seal·artifact와
모든 source를 다시 검증한 뒤에만 draft를 SUP-003 compiler에 전달한다.

## 알려진 경계

- stable ID와 Gateway duplicate rejection은 한 Run에 한정되며 cross-process·cross-Run at-most-once가 아니다.
- B2 outcome은 성공 전용 projection이며 sealed artifact, 서명, Provider attestation 또는 evidence-byte 증명이 아니다.
- generic `chat_bound()`는 Campaign-only budget도 허용한다. 실제 Supervisor dual scope 강제는 B3 책임이다.
- B1 budget 원자성은 같은 process에서 공유하는 controller에 한정된다.
- SUP-004A는 canonical SUP-002 user JSON이 `ProviderMessage`의 65,536자 한도를 넘으면 fail closed한다.
- 전체 pytest의 Benchmark fixture 만료, Windows symlink 제약과 schema import-order 문제는
  `KNOWN_ISSUES.md`에 기록돼 있다.
