# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 직전 원격 체크포인트: `74f54c9c58bc7b60c9721306d94fb42c2e5d76c9` (`SUP-005B2`)
- 현재 구현 체크포인트: `SUP-006` Adversarial Prompt Injection Regression
- 다음 구현: `PERMIT-001` 일반 공격 ActionProposal

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같은지 확인한다.

## 현재 구현 상태

`SUP-006`은 새 실행·threshold·activation authority를 만들지 않고 기존 SUP-002~SUP-005B2 경계를 하나의
adversarial regression으로 관통한다.

- `parse_supervisor_shadow_proposal_draft()`는 raw Provider JSON에서 광고한 camelCase alias만 허용한다.
  내부 Python 모델 생성의 `populate_by_name` 호환성은 유지하지만 snake_case Provider wire는 거부한다.
- target Fact corpus는 system/developer 역할 위장, taint downgrade, Scope·Plan·TaskGraph mutation,
  `shell.execute`, ToolRequest, Capability, Permit, execution, threshold와 activation 요청을 포함한다.
- SUP-002 projection은 corpus를 `target-tainted-untrusted`, `instructionAuthorized=false`로 유지한다.
- SUP-004A request는 code-owned developer 1개와 tainted canonical user JSON 1개만 만들고 Tool을 노출하지 않는다.
- schema-valid 악성 `escalate` rationale는 B3를 통과할 수 있지만 SUP-003 typed proposal에는 원문 대신 digest만
  남고 mutation·Scope·Capability·Permit·scheduling·execution·activation은 모두 false다.
- extra ToolRequest, Capability true, unknown kind, snake_case wire, foreign Snapshot draft는 model call 1회 뒤
  `dispatch-started-outcome-unknown`·manual review로 고정되며 재호출하지 않는다.
- SUP-005B2는 candidate가 exact current sealed Plan publication을 사용하도록 추가 결박한다. 같은 Plan content의
  다른 정상 publication도 replay할 수 없다.
- adversarial proposal을 포함한 B2 numeric Comparison도 external Target/Harness metrics만 사용한다. final
  lineage에는 prompt/rationale가 없고 causal attribution·threshold·activation·execution은 false다.

핵심 위치:

- `src/pajin/supervision/model_binding.py`
- `src/pajin/supervision/invocation_runtime.py`
- `src/pajin/supervision/benchmark_measurement.py`
- `tests/test_supervisor_adversarial_prompt_injection.py`
- `docs/orchestration/SUP-006-adversarial-prompt-injection-regression.md`
- `docs/adr/0127-enforce-the-advertised-supervisor-draft-wire.md`

## 현재 검증

- SUP-006 adversarial 집중 회귀: 13 passed
- SUP-001~SUP-006 인접 Supervisor 회귀: 143 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 246 source files 통과
- 새 테스트와 나머지 변경 Python 7개 formatter: 통과. `model_binding.py`는 기존 formatter drift의
  관련 없는 5개 hunk를 재배치하지 않고 보존했으며 Ruff lint는 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 고정 registry distribution bundle 만료로 중단
  (`test_benchmark_single_agent_measurement.py`; SUP-006 집중·인접 검증과 무관한 기존 fixture 제한)
- `git diff --check`: 통과
- 독립 품질 리뷰: 잔존 P0-P2 없음; private helper 결합만 기록된 P3
- 독립 신뢰 리뷰: decoded dict 공개 parser의 duplicate-key P2를 발견해 raw bytes strict parser로 수정,
  live B3 duplicate-key 공격 재검증 뒤 잔존 P0-P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_adversarial_prompt_injection.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_adversarial_prompt_injection.py tests\test_supervisor_snapshot_input.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_checkpoint_scheduler.py tests\test_supervisor_invocation_journal.py tests\test_supervisor_benchmark_campaign.py tests\test_supervisor_benchmark_measurement.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 수정 Python만 검사하고 저장소
전체를 기계적으로 재포맷하지 않는다.

## 핵심 신뢰 경계

- Prompt injection regression은 모델이 공격에 영향받지 않는다고 주장하지 않는다. 영향받은 schema-valid
  rationale도 실행 권위로 승격되지 않음을 증명한다.
- B3가 사용하는 Provider Gateway ToolRequest 1개는 사전 결박된 model call 경계다. target prompt나 model
  output이 추가 ToolRequest, Capability, Permit, Scope 또는 execution을 생성할 수 있다는 뜻이 아니다.
- invalid Provider output은 증명된 non-execution이 아니므로 budget을 release하지 않고 manual review한다.
- raw untrusted draft receipt에는 rationale가 포함될 수 있다. typed proposal과 final measured lineage는
  rationale를 digest로만 결박한다.
- SUP-005B2 numeric delta는 external Target measurement이며 proposal 효과나 활성화 threshold가 아니다.
- exact Plan publication 결박은 content-equal retry Run 사이의 candidate replay도 금지한다.

## 다음 작업의 첫 단계

`PERMIT-001`은 Shadow proposal이나 prompt text를 직접 Action으로 전환하지 않고 일반 공격
`ActionProposal`의 비실행 schema와 authority 경계를 먼저 고정해야 한다.

1. 기존 Replay/validation ActionProposal, ActionIntent, ToolRequest, Scope, Target, Cleanup 관련 타입을
   인벤토리하고 중복 authority를 피한다.
2. action kind, target, arguments, expected evidence, cleanup과 risk tier를 content-addressed proposal로
   결박하되 Capability·Permit·execution은 false로 둔다.
3. Supervisor typed proposal은 입력 lineage일 수 있지만 target text·rationale에서 Action fields를 추론하지
   않는다. deterministic code-owned compiler 전 단계로 유지한다.
4. cross-Campaign·cross-Snapshot·cross-Plan substitution과 Scope 확대, executable ToolRequest 주입을
   fail closed하는 최소 음성 경계를 설계한다.

## 알려진 경계

- SUP-006 corpus는 deterministic fake Provider와 fake external measurement adapter를 사용한다.
- corpus는 대표 공격 클래스의 authority containment를 검증하며 모든 자연어 prompt injection을 열거하지 않는다.
- B3 journal은 host-local SQLite, budget ledger는 process-local이며 distributed exactly-once가 아니다.
- external measurement signer와 host-local registry activation은 계속 신뢰 전제다.
- 테스트는 기존 private fixture helper와 seed 1개·repetition 1개에 결합돼 있다.
- Docker daemon은 세션별 재확인이 필요하며 fake-provider 검증은 real-container 검증을 대신하지 않는다.
- 전체 pytest에는 기존 Benchmark registry fixture 만료와 Windows symlink 권한 제약이 남아 있다.
