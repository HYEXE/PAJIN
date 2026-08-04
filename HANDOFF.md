# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `1b01b26170eb016ed52e616a1b8dfc7c75ff5c1a`
- 현재 구현 체크포인트: `SUP-001` SupervisorModelBinding 검증·사전 리뷰 완료
- 다음 구현: `SUP-002` Snapshot-only input·Target Taint

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

`SUP-001`은 모델을 호출하지 않는 content-addressed `SupervisorModelBinding`이다.

- exact legacy Campaign Profile compilation, Common Engine contract, `AgentRole.SUPERVISOR`, WALK-006
  registered Shadow policy를 재사용한다.
- Provider ID·normalized endpoint·model ID·explicit immutable revision과 complete
  `ProviderRegistration` digest를 secret-free identity projection으로 결박한다.
- registration의 set-valued Tool allowlist는 digest 전에 정렬해 프로세스별 순서 차이를 제거한다.
- structured JSON configuration은 max completion tokens, zero temperature, top-p 1, seed, no streaming,
  empty function Tools를 고정하고 prompt content를 포함하지 않는다.
- WALK-006 `WalkingShadowInputSnapshot`, Phase 5 `CollaborationSnapshot`, untrusted
  `SupervisorShadowProposalDraft`의 code-owned JSON Schema digest를 정확히 결박한다.
- output draft는 Snapshot ref, `task|replan|stop|escalate`, bounded rationale만 표현하며 command,
  message, prompt, arguments, ToolRequest, Capability, Permit 필드가 없다.
- model invocation, Capability, Permit, execution, activation eligibility는 literal false다.
- consumer는 expected Campaign·Provider registration·model revision·configuration으로
  `verify_supervisor_model_binding()`을 호출해야 하며, 다른 runtime의 자체 일관된 binding도 거부된다.

핵심 위치: `src/pajin/supervision/model_binding.py`,
`tests/test_supervisor_model_binding.py`,
`docs/orchestration/SUP-001-supervisor-model-binding.md`,
`docs/adr/0117-bind-shadow-supervisor-model-before-invocation.md`.

## 마지막 검증

- SUP-001 집중 테스트: 34 passed
- SUP-001 + WALK-006/Profile/Collaboration predecessor 회귀: 128 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 235 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- 만료 fixture 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_model_binding.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_model_binding.py tests\test_campaign_profile.py tests\test_profile_compatibility.py tests\test_collaboration_snapshots.py tests\test_walking_mcp_authorization.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
.\.venv\Scripts\python.exe -m pytest -x -q --ignore=tests\test_benchmark_single_agent_measurement.py --ignore=tests\test_benchmark_zap_scanner.py
git diff --check
```

## 사전 허상·버그 검토 결과

- 모델명 하나나 prompt text를 authority로 사용하지 않는다. registration digest, explicit revision,
  configuration, Campaign/Profile/Common Engine, role, policy, schema가 전체 binding에 함께 들어간다.
- `ProviderRegistration.allowed_function_tools` set의 비결정적 직렬화 가능성을 발견해 정렬 후 digest하도록
  수정하고 동등 registration 회귀를 추가했다.
- Pydantic이 `seed=True`, `streaming=0`, authority marker `0|1`을 coercion할 수 있음을 재현해 모든
  SUP-001 보안 불리언과 정수·고정 sampling 값을 exact type으로 검증한다.
- schema body, secret reference, prompt content는 binding wire에 넣지 않았다.
- standalone content addressing을 current runtime authority로 오인하지 않도록 exact consumer verifier와
  cross-Campaign·cross-Provider·cross-revision·cross-config 음성 테스트를 추가했다.
- 기존 Provider session, execution Supervisor, WALK-006, Campaign Profile, Collaboration wire와 reader는
  변경하지 않았다.

## 다음 조치

`SUP-002`에서 실제 모델 호출 없이 `SupervisorModelBinding.allowedInputSchemas` 중 하나의 exact Snapshot
instance만 받는 minimal input envelope를 설계한다. Campaign/profile/binding identity와 Snapshot
ID·digest·schema digest를 결박하고, Graph Fact·Observation·Artifact에서 유래한 모든 model-visible text와
reference에 Target Taint를 보존한다. raw prompt relay, content omission으로 taint 제거, cross-Campaign·stale
Snapshot, schema substitution을 fail closed한다. SUP-001 output draft나 SUP-003 proposal authority를 아직
생성하지 않고, 기존 MEM-003/WALK-006 readers와 authority를 재사용한다.

## 알려진 경계

- SUP-001은 Provider 또는 model-weight attestation, deterministic inference, output quality를 증명하지 않는다.
- binding은 model invocation을 수행하지 않으며 standalone foreign binding도 자기 내용에 대해서는 유효하다.
  실제 사용 전 expected runtime input과 exact verifier가 필수다.
- 실제 Snapshot projection과 Target Taint는 SUP-002, typed proposal compilation은 SUP-003 범위다.
- 전체 pytest의 기존 fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
