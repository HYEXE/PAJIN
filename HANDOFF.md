# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 직전 원격 체크포인트: `c85cac5ad83140d87e1440ede2656c435d183963` (`PERMIT-001`)
- 현재 구현 체크포인트: `PERMIT-002` Deterministic Action Compiler
- 다음 구현: `PERMIT-003` Exact Single-use ActionPermit

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

`PERMIT-002`는 PERMIT-001의 비실행 의미를 exact CAP-002 code-backed compiler에 통과시켜
`GeneralAttackCompiledIntent`로 결박한다.

- PERMIT-001 external verifier로 current Campaign·Snapshot·Plan·Task·Hypothesis·Target·Scope·Definition을
  완전히 다시 연 뒤에만 compiler를 선택한다.
- caller가 지정한 exact `CodeBackedCapabilityRef`를 complete 7-role `CapabilityAuthorityRegistry`에서 resolve하고
  registered Materializer와 Action Compiler wrapper만 각각 한 번 호출한 뒤 complete set을 다시 resolve한다.
  Registry는 연속 두 complete observation, stable-context 수집 전후의 역할 identity 고정과 마지막
  context-free declared-identity sweep을 요구한다.
- request ID는 source proposal digest, authority-set ref, Materializer/Compiler authority digest에서 fresh하게
  파생한다. 과거 ORCH Specialist request ID를 재사용하지 않는다.
- target·Tool은 current Campaign/Definition에서 다시 열고 method·arguments는 source proposal에서만 온다.
  materialized arguments와 compiled request는 JSON scalar type까지 canonical byte equality를 요구한다.
- 기존 Gateway request digest와 CAP-002 normalized-parameter digest를 재사용하고, complete source proposal·
  authority-set·selected binding·request와 함께 intent digest에 결박한다.
- release·activation·Graph Capability·Grant·MissionEnvelope·Graph Decision·reservation·GRAPH ActionProposal·
  Permit·dispatch·execution은 생성하지 않고 관련 authority flag는 literal false다.
- cross-source/compiler substitution, self-consistent ToolRequest forgery, materializer default/argument expansion,
  bool/int/float argument type substitution, 정·역방향 cross-role 및 self-identity drift, compiler target expansion,
  post-compilation authority 주입은 fail closed한다.

핵심 위치:

- `src/pajin/supervision/action_compiler.py`
- `src/pajin/supervision/action_proposal.py`
- `src/pajin/capabilities/authorities.py`
- `src/pajin/capabilities/activation.py`
- `tests/test_general_attack_action_proposal.py`
- `docs/orchestration/PERMIT-002-deterministic-action-compiler.md`
- `docs/orchestration/PERMIT-001-general-attack-action-proposal.md`
- `docs/adr/0129-bind-cap002-compilation-before-graph-authority.md`

## 현재 검증

- General Attack Compiler·CAP-002 authority 집중 회귀: 58 passed
- ORCH·Replanning·PERMIT 집중 회귀: 75 passed
- General Attack·CAP-001/002·Definition·existing adapter 인접 회귀: 73 passed
- Capability rollout·GRAPH-006·Engine Gate·Replay·Supervisor 통합 회귀: 153 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 248 source files 통과
- 신규 compiler·export·변경 테스트 Python 4개 Ruff formatter check: 통과
- `src/pajin/capabilities/authorities.py` formatter: HEAD에도 존재하는 기존 Ruff baseline 불일치를
  재포맷하지 않고 관련 hunk만 유지, Ruff lint 통과
- `git diff --check`: 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 registry distribution bundle 만료로 중단
  (`test_benchmark_single_agent_measurement.py`; 현재 시각 2026-08-05가 fixture 만료 시각을 지남)
- 독립 품질·trust·계약 리뷰: JSON scalar equality·ordered/late identity drift·typed error 경계를 수정한 뒤
  세 관점 모두 잔존 P0-P2 없음

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_discovery_hypothesis.py tests\test_discovery_replanning.py tests\test_general_attack_action_proposal.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_proposal.py tests\test_capability_authorities.py tests\test_existing_capability_adapters.py tests\test_capability_definition.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_existing_capability_rollout.py tests\test_graph_action_permit.py tests\test_engine_execution_gate.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_replay_models.py tests\test_replay_compiler.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_supervisor_proposal_compiler.py tests\test_supervisor_adversarial_prompt_injection.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 변경 Python만 검사하고 저장소
전체를 기계적으로 재포맷하지 않는다.

## 핵심 신뢰 경계

- `GeneralAttackCompiledIntent`의 `ToolRequest`는 typed request material이지 Grant나 Permit이 아니다.
- `CodeBackedCapabilityRef`는 complete code identity이지만 signed release, activation 또는 GRAPH registration이 아니다.
- exact equality 규칙은 Materializer가 default를 추가하거나 bool/int/float 타입을 치환하는 것도 expansion으로
  거부한다. normalization 정책은 별도 versioned contract 없이는 완화하지 않는다.
- CAP-002 adapter와 side-effect-free `stable_execution_context()`는 code-owned TCB다. observed drift는
  거부하지만 같은 process의 Byzantine Python adapter를 sandbox한다고 주장하지 않는다.
- request identity는 source+compiler authority에 결박되지만 Gateway, Worker 또는 Permit consumer는 이 module에서
  호출되지 않는다.
- expected evidence·risk·side-effect·cleanup은 embedded PERMIT-001 의미로 보존할 뿐 Oracle, Replay, Cleanup,
  Executor role을 호출하지 않는다.

## 다음 작업의 첫 단계

`PERMIT-003`은 compiled intent와 실제 실행 ceiling을 교차 결박해 기존 GRAPH-006 atomic Permit 경로로
넘기는 최소 bridge를 구현해야 한다.

1. CAP-004/005 release·activation, 기존 run-level MissionEnvelope, external Graph Decision/Snapshot, trusted
   request-unit·cost authority와 GRAPH-006 소비 경계를 먼저 재인벤토리한다.
2. current PERMIT-002 intent를 complete source+CAP-002 registry로 다시 compile해 exact equality를 요구한다.
3. action마다 새 Envelope를 만들지 않고 기존 run-level ceiling을 사용하며 external Decision kind/payload/
   actor와 latest Snapshot을 exact 검증한다.
4. current activation에서 exact GRAPH Capability를 resolve하고 definition request-unit cost와 trusted cost로만
   reservation을 만든 뒤 기존 `pajin.graph.ActionProposal`을 파생한다.
5. 새 Permit store/dispatcher 없이 기존 SQLite atomic single-use authority와 first-consumption dispatcher만 쓴다.

## 알려진 경계

- PERMIT-002는 signed release, activation, Graph Capability, MissionEnvelope, Graph Decision, reservation,
  GRAPH ActionProposal, Grant, Permit 또는 execution runtime에 아직 연결되지 않았다.
- exact-equality materialization을 만족하지 않는 existing adapter는 별도 narrowing/normalization 계약 전에는
  일반 공격 compiled intent로 승격되지 않는다.
- Success Oracle과 cleanup handler/plan/Permit은 PERMIT-004 전까지 metadata-only다.
- 전체 pytest에는 기존 Benchmark registry fixture 만료와 이후 Windows symlink 권한 제약이 남아 있다.
- Docker daemon 상태는 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
