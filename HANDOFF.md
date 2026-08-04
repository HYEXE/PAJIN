# PAJIN 개발 인수인계

- 기록일: 2026-08-04
- 브랜치: `main`
- 작업 시작 기준: `a19869e4c35ded90c9c1bca517372cf54ffc3ba3`
- 현재 구현 체크포인트: `SUP-003` typed non-executable proposal compiler 구현·독립 리뷰 완료
- 다음 구현: `SUP-004` Checkpoint Scheduler·전용 Budget

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

`SUP-003`은 verified SUP-002 input과 SUP-001 draft를 네 종류의 typed advisory proposal로
결정론적으로 컴파일하지만 모델이나 실행 경로를 호출하지 않는다.

- compiler policy가 actual `SupervisorSnapshotInput`, SUP-001 draft, typed output schema와 exact
  WALK-006 policy를 content-addressed digest로 결박한다.
- current Collaboration state에는 trusted typed lifecycle가 없으므로 Fact/rationale 의미를 해석하지 않고
  `task|replan|stop|escalate` 네 roadmap kind만 exact ordered allowlist로 허용한다.
- compiler가 expected Campaign·Provider registration·model revision·configuration·current Collaboration
  Snapshot·Graph·Artifact source로 SUP-002 input을 다시 검증한다.
- draft의 Snapshot ID/digest는 SUP-002의 source Collaboration Snapshot과 같아야 한다. projection input
  ID/digest, binding, source Snapshot, complete taint, draft와 rationale digest는 별도로 모두 결박한다.
- target/Agent Fact text, Artifact content/path와 model rationale 원문은 typed proposal에 복사하지 않는다.
- 네 payload는 code-owned literal만 포함하고 scheduling, Plan·TaskGraph mutation, Scope 확대, Stop 적용,
  통지, approval, Capability, Permit, execution, activation은 false다.
- Provider가 draft를 실제 생성했다는 attestation이나 invocation receipt는 주장하지 않는다.
- 인접 WALK-006 Stop·authority boolean의 Pydantic `0/1` coercion도 exact JSON boolean 검증으로 차단했다.

핵심 위치: `src/pajin/supervision/proposal_compiler.py`,
`tests/test_supervisor_proposal_compiler.py`,
`docs/orchestration/SUP-003-typed-non-executable-supervisor-proposal.md`,
`docs/adr/0119-compile-untrusted-supervisor-drafts.md`.

## 현재 검증

- SUP-003/SUP-002/SUP-001/WALK-006 집중 회귀: 76 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 237 source files 통과
- 전체 `pytest -x -q`: 190 passed, 3 skipped 후 기존 Benchmark registry fixture 만료
- 만료 fixture 두 개 제외 전체 pytest: 349 passed, 6 skipped 후 기존 Windows symlink 권한 중단

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_proposal_compiler.py tests\test_supervisor_model_binding.py tests\test_supervisor_snapshot_input.py tests\test_walking_mcp_authorization.py::test_walking_shadow_supervisor_records_human_task_and_stop_without_mutation tests\test_walking_mcp_authorization.py::test_walking_shadow_supervisor_rejects_capability_execution_and_source_mutation
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 사전 허상·버그 검토 결과

- SUP-001은 raw Collaboration schema를 결박하지만 actual SUP-002 wrapper는 별도 wire임을 발견했다.
  SUP-003 compiler policy가 actual wrapper schema를 직접 pin해 compile-only 경계를 닫았고, model call 전
  additive invocation binding 필요성을 `KNOWN_ISSUES.md`에 기록했다.
- current Collaboration input에는 WALK-006 `still-vulnerable` 같은 typed semantic state가 없으므로 이를
  Fact text에서 추론하지 않는다. 네 kind는 모두 advisory structural kind이며 state-specific 제한은 별도
  typed projection 전에는 만들지 않는다.
- 실제 Task·Plan·StopDecision·GraphProposal 타입을 재사용하면 실행 허상이 생기므로 supervision
  namespace의 별도 non-executable payload만 사용한다.
- rationale과 target text는 output title·reason·argument·Scope·assignee로 복사하지 않고 digest만 남긴다.
- compiler entry에서 `model_copy()` 검증 우회 draft도 canonical reparse해 거부한다.
- cross-Snapshot·foreign runtime·kind 확대·payload discriminator mismatch·digest 위조·extra command field·
  boolean/integer coercion·비정상 Unicode를 fail closed 회귀로 확인했다.
- 독립 읽기 전용 병렬 리뷰가 actual projection schema 공백과 WALK-006 boolean coercion을 발견했고 두
  문제를 구현과 테스트에 반영했다.

## 다음 조치

`SUP-004`에서 먼저 actual model invocation request의 versioned additive binding을 설계한다. 기존 SUP-001
v1alpha1 schema list를 조용히 바꾸지 말고 exact `SupervisorSnapshotInput`, message/request normalization,
Provider registration/model/configuration, request·response receipt를 결박해야 한다. 그 authority를 전제로
checkpoint trigger, dedicated call/token/time/cost budget, deterministic idempotency와 single-flight scheduling을
비실행 또는 shadow-only 상태로 구현한다. Scheduler output만으로 Task·Plan·Capability·Permit·execution을
적용해서는 안 된다.

## 알려진 경계

- SUP-003는 syntactically valid untrusted draft만 컴파일하며 Provider/model provenance를 증명하지 않는다.
- SUP-003 schema binding은 compiler 경계이며 model invocation authority가 아니다.
- SUP-002 v1은 current Collaboration Snapshot만 materialize하고 WALK-006 Snapshot actual projection은 없다.
- 전체 pytest의 기존 Benchmark fixture 만료와 Windows symlink 제약은 `KNOWN_ISSUES.md`에 기록돼 있다.
