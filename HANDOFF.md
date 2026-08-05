# PAJIN 개발 인수인계

- 기록일: 2026-08-05
- 브랜치: `main`
- 직전 원격 체크포인트: `d693ad5f68cef66dac4172f1060c752fcdd0dd6a` (`PERMIT-002`)
- 현재 구현 체크포인트: `PERMIT-003` Exact Single-use ActionPermit
- 다음 구현: `PERMIT-004` Side-effect·Data-flow·Cleanup Gate

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

`PERMIT-003`은 current PERMIT-002 intent와 실제 실행 ceiling을 교차 결박해 기존 GRAPH-006
atomic single-use Permit 경로로 넘기는 direct-call bridge다.

- complete PERMIT-001·ORCH·CAP-001/002 source를 다시 열어 `GeneralAttackCompiledIntent`를 exact-rebuild한다.
- current CAP-005 activation에서 complete `CodeBackedCapabilityRef`가 같은 binding을 정확히 하나 찾고,
  signed release를 dispatch 전후에 resolve하며 CAP-002 `prepare_action()`을 다시 실행한다.
- source Definition Registry와 activated rollout Definition을 독립 resolve해 exact equality를 요구한다.
- prepared activation-set·release·GRAPH Capability·request·request/parameter digest와 canonical request bytes가
  compiled intent와 다르면 fail closed한다.
- 일반 공격용 verified Envelope producer, Decision provenance registry, generic pricing service가 아직 없으므로
  외부 `GeneralAttackActionPermitInputAuthority`가 기존 run-level MissionEnvelope, authenticated Graph
  Decision actor/provenance와 trusted strict-integer fixed-point cost를 공급한다. 이 in-process interface는
  새 persisted authority wire가 아니며 default 구현도 등록하지 않는다.
- provider에는 intent·prepared action·Campaign·Definition의 canonical deep-detached copy만 전달한다. provider가
  그 복사본을 변조해도 gate-owned request·Campaign·callback material은 바뀌지 않으며 forged Envelope는
  current source digest 교차 검증에서 거부된다.
- gate는 외부 결과를 canonicalize하고 current Campaign authorization/testing window와 Envelope
  duration·autonomy·risk·Tool-call·cost·rate ceiling을 감쇠한다. request-unit은 activated Definition에서 직접
  파생하고 Decision kind/payload/Snapshot Campaign, exact Capability·Target과 budget을 다시 검증한다.
- 외부 authority 호출 뒤 exact signed activation을 다시 resolve한다. provider 운영 예외와 synchronous
  callback은 Permit claim 전에 typed fail-closed 오류로 거부한다.
- 기존 `pajin.dev/action-proposal/v1alpha2`, `GraphActionPermitAuthority`, SQLite Permit store와
  `GraphActionPermitDispatcher`만 사용한다. Campaign-aware final claim clock은 SQLite와 같은 시각으로
  authorization/testing window를 다시 검사한다. 새 Envelope·Proposal·Permit·store·ledger·dispatcher가 없다.
- gate 하나는 exact Envelope digest와 activation-set digest에 고정된다. exact retry는 같은 consumed Permit을
  반환하고 consumer를 다시 호출하지 않는다. stale/unreconciled Graph는 기존 final transaction에서 거부된다.
- first-consumption callback은 exact current `PreparedCapabilityAction`, derived `ActionProposal`, consumed Permit을
  함께 받는다. default workflow, Gateway, Worker, Grant·Run audit, Success Oracle·cleanup은 아직 연결하지 않는다.

핵심 위치:

- `src/pajin/supervision/action_permit.py`
- `src/pajin/supervision/action_compiler.py`
- `src/pajin/capabilities/activation.py`
- `src/pajin/graph/authority.py`
- `src/pajin/graph/sqlite_store.py`
- `tests/test_general_attack_action_permit.py`
- `tests/test_general_attack_action_proposal.py`
- `docs/orchestration/PERMIT-003-exact-single-use-action-permit.md`
- `docs/adr/0130-reuse-graph-permit-at-the-general-attack-boundary.md`

## 현재 검증

- PERMIT-003 신규 성공·음성 경계: 23 passed
- PERMIT-001/002/003·CAP-005·GRAPH-006·Common Engine 인접 회귀: 113 passed
- ORCH·PERMIT·CAP-001/002·Replay·Supervisor 확장 회귀: 234 passed
- Ruff 전체: 통과
- Linux 대상 strict mypy: 249 source files 통과
- 전체 pytest: 190 passed, 3 skipped 뒤 기존 registry distribution bundle 만료로 중단
  (`test_benchmark_single_agent_measurement.py`; 현재 시각 2026-08-05가 fixture 만료 시각을 지남)
- 기존 GRAPH-006 concurrency·crash·exact retry 테스트를 변경 없이 재사용했고 신규 stale-Graph bridge 회귀도
  통과했다.
- 독립 계약·품질·trust 검토에서 provider 지연 중 testing-window 종료와 live-reference 변조를 보완한 뒤
  세 관점 모두 잔존 P0-P2 없음으로 재확인했다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_permit.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_general_attack_action_proposal.py tests\test_general_attack_action_permit.py tests\test_existing_capability_rollout.py tests\test_graph_action_permit.py tests\test_engine_execution_gate.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_discovery_hypothesis.py tests\test_discovery_replanning.py tests\test_general_attack_action_proposal.py tests\test_general_attack_action_permit.py tests\test_capability_authorities.py tests\test_capability_definition.py tests\test_existing_capability_adapters.py tests\test_replay_models.py tests\test_replay_compiler.py tests\test_supervisor_proposal_compiler.py tests\test_supervisor_adversarial_prompt_injection.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

전체 formatter check는 기존 다수 파일이 현재 Ruff formatter와 불일치하므로 변경 Python만 검사하고 저장소
전체를 기계적으로 재포맷하지 않는다.

## 핵심 신뢰 경계

- `GeneralAttackActionPermitInputAuthority` implementation은 existing Envelope provenance, Decision actor와
  micro-USD cost의 composition trust root다. gate는 그 결과의 교집합과 exact propagation을 검증하지만 잘못된
  provider 자체를 signature 없이 교정한다고 주장하지 않는다.
- canonical MissionEnvelope·GraphDecision·ActionBudgetReservation의 self-digest는 producer provenance가 아니다.
  raw 모델이나 caller integer를 직접 신뢰 입력으로 승격하지 않는다.
- request-unit은 current activated CAP-001 Definition에서만 gate가 직접 파생한다. cost는 외부
  trusted/conservative policy가 strict integer로 공급하고 Campaign과 Envelope ceiling이 다시 제한한다.
- GraphDecision은 `action-proposal` kind와 exact intent payload를 요구하고 proposer는 authenticated actor에서만
  복사한다. latest Snapshot은 preflight가 아니라 기존 SQLite final transaction에서 검증한다.
- ActionPermit은 issuance 때 consumed다. 미리 발급·보관하지 않으며 callback failure나 uncertain outcome을
  자동 redispatch하지 않는다.
- callback에 prepared request를 직접 전달해 downstream이 stale caller closure에서 request material을 다시
  만들지 않게 한다. 그러나 Gateway Grant·Run audit 검증과 actual Worker dispatch는 SUP-007 책임이다.
- expected evidence·risk·side-effect·cleanup은 embedded PERMIT-001 의미로 유지하지만 Success Oracle, Replay,
  Cleanup Handler, Executor role은 PERMIT-004 전까지 호출하지 않는다.

## 다음 작업의 첫 단계

`PERMIT-004`는 consumed action과 후속 결과 처리 사이의 side-effect·data-flow·cleanup authority를 최소
수직 슬라이스로 결박해야 한다.

1. CAP-002 Success Oracle·Side-effect Class·Cleanup Handler·Executor Adapter, existing `ToolResult`/Gateway
   Outcome, cleanup plan/Permit과 관련된 현재 contract·ADR·테스트를 재인벤토리한다.
2. PERMIT-003 callback failure가 consumed terminal이라는 GRAPH-006 계약을 보존하고, 결과가 없거나 uncertain인
   경우 성공·cleanup 완료를 추론하지 않는다.
3. embedded PERMIT-001 evidence·side-effect·cleanup metadata와 current activated Definition을 exact-rebuild한 뒤
   실제 result/evidence authority의 교집합에서만 Success Oracle을 호출한다.
4. cleanup required action에는 별도 exact cleanup request/authority와 bounded one-shot Permit을 요구하되 기존
   ActionPermit을 cleanup 실행 권위로 재사용하거나 일반 실행 budget을 우회하지 않는다.
5. default Supervisor activation과 T0/T1 Gateway wiring은 계속 SUP-007에 남기고, 가장 작은 direct-call
   outcome/cleanup gate와 fail-closed 음성 경계를 먼저 구현한다.

## 알려진 경계

- verified general-attack Envelope producer, Decision provenance registry와 generic pricing provider는 아직
  deployment-supplied TCB다. 구체적 product composition은 SUP-007 전까지 없다.
- Grant·matching RunStore·Gateway·Worker가 연결되지 않았으므로 PERMIT-003 테스트 callback은 product execution
  증거가 아니라 single-consumption authority 회귀다.
- Success Oracle과 cleanup handler/plan/Permit은 PERMIT-004 전까지 metadata-only다.
- 전체 pytest에는 기존 Benchmark registry fixture 만료와 이후 Windows symlink 권한 제약이 남아 있다.
- Docker daemon 상태는 이번 체크포인트에서 확인하지 않았고 real-container 검증은 수행하지 않았다.
