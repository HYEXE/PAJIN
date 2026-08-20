# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-20
- 작업 체크아웃: `/Users/hyeonexcel/Workspace/HYEXEN/PAJIN`
- 브랜치: `main`
- 기준 commit: `367d348ae126e33c618a8da0d8e91bfff16b4471`
- 시작 시점 upstream: `main == origin/main`
- 로컬 기능 commit:
  - `06bedf4` `feat(pentest): 동적 child deployment 실행 경계 연결`
  - `6e49f01` `feat(redteam): 승인된 LLM·RAG 실행 프로필 추가`
- 완료 단계: `PENTEST-004C2B2`, `REDTEAM-001A`, `REDTEAM-001B` multi-turn LLM/RAG profile
- 다음 단계: `REDTEAM-001C` bounded Web Capability profile
- 원격 push·Pull Request·merge·배포: 수행하지 않음

PENTEST-004C2B2와 REDTEAM-001A/B 변경은 위 두 로컬 commit으로 보존했다. 원격 상태는 변경하지 않았으며
사용자의 별도 승인 없이 push나 다른 원격 작업을 수행하지 않는다.

## 구현된 동작

### server-owned 동적 child registry

- `PentestWorkflowCoordinationDeployment`는 외부 SHA-256으로 고정된 coordination Run ID/root, activation
  trust anchor, child registry, Replay comparison root, Graph database, 004C1 workflow root와 finalization
  trust anchor를 소유한다.
- signed activation의 stage와 child deployment digest만으로
  `<registry>/<stage>/<childDeploymentDigest>.json`을 계산한다. request는 path, approval, Graph Decision,
  Permit 또는 Worker identity를 공급하지 않는다.
- `PentestWorkflowChildDeploymentRegistration`은 self-digest, child ID/digest, server-side absolute path,
  file SHA-256, Worker subject와 Replay 전용 fixed comparison Run ID를 결박하며 authority를 발급하지 않는다.
- startup deployment, registry entry와 child deployment가 다른 digest·stage·Worker·mTLS policy를 보이면
  dispatch 전에 fail closed한다.

### concrete 004B/004C2A adapters

- source와 세 Control은 기존 `load_pentest_recon_operator_deployment` 및 004B one-use runtime을 사용한다.
- Replay는 새 activation loader로 기존 004C2A runtime과 verified source/Discovery inputs를 함께 재구성한다.
- fresh dispatch와 terminal-evidence reuse 모두 현재 direct-mTLS scope와 separated Worker principal을 다시
  인증한다. dedicated Replay Worker는 generic stage에 사용할 수 없고 그 반대도 거부한다.
- fresh Recon child가 실제 기존 Worker backend를 정확히 한 번 호출하는 통합 회귀를 추가했다.
- 모든 terminal stage는 sealed approval·Permit·Run·evidence를 다시 읽어 실제
  `PentestWorkflowExecutionReference`를 반환한다.
- Replay comparison은 registration의 fixed Run ID로 create/reopen하고 새로 계산한 body-free authority와
  정확히 같아야 한다.

### restart와 reconciliation

- root loader restart는 exact coordination Run을 재사용한다.
- active activation만 fresh dispatch할 수 있다. B1의 sealed `stage-started`가 있는 expired activation은
  reconcile-only로 진입한다.
- Replay reconciliation은 child Run이 이미 존재해야 하며 누락된 Run을 만들지 않는다. 모든 adapter는
  terminal child seal만 다시 읽고 Worker를 호출하지 않는다.
- 다섯 receipt와 Replay comparison이 검증되면 기존 B1이 004C1 handoff를 생성하고 즉시 재검증한다.

### Control Plane·client·CLI

- opt-in startup pair:
  - `PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_PATH`
  - `PAJIN_CP_PENTEST_WORKFLOW_COORDINATION_DEPLOYMENT_SHA256`
- `PAJIN_CP_ADDITIONAL_WORKER_CREDENTIALS`는 추가 generic Worker subject를 bearer token 값이 아니라 그
  secret을 가진 환경변수 이름에 매핑한다. token과 subject는 모두 distinct여야 하며 모든 Worker는 현재
  mTLS policy에 정확히 하나씩 있어야 한다.
- `ControlPlaneClient.dispatch_pentest_workflow_stage`는 signed stage에 따라 generic 또는 Replay route를
  선택한다.
- `pajin pentest-workflow-stage-dispatch`는 signed activation bundle에서 coordination selector와 stage를
  파생한다. Replay는 기본 Replay token env를 사용하고 추가 generic Worker는 `--worker-token-env`를 쓴다.

### REDTEAM-001A approved single-turn LLM profile

- `redteam-llm-v1`은 기존 `capability-graph-v1`의 signed release·activation·T2 approval·Permit·Gateway·
  Worker receipt·sealed audit 경로를 재사용하는 제품 전용 ceiling이다.
- exact `pajin.ai.kisa.system-prompt-disclosure@1.0.0` M03와
  `pajin.ai.kisa.jailbreak-policy-bypass@1.0.0` M06만 허용한다.
- Campaign은 `ai-redteam`, exact `ai-chat-api` Target, POST/T2와 해당 threat를 선언해야 한다. prepared
  request는 `ai.chat-probe`, exact catalog scenario/threat, 단일 turn이어야 한다.
- 다른 Tool, RAG Target, multi-turn A04와 승인 누락은 Permit 생성과 Worker 호출 전에 거부한다. M03/M06
  성공 뒤 exact retry는 기존 terminal Permit을 재사용하며 Worker를 두 번 호출하지 않는다.
- PENTEST GET Recon wire는 변경하지 않았고 Replay·Finding·confirmation·report authority를 만들지 않는다.

### REDTEAM-001B multi-turn LLM/RAG request-unit profile

- A04 Capability를 `pajin.ai.kisa.memory-poisoning-persistence@1.1.0`으로 version-up하고 exact catalog
  두 turn에 맞춰 code-owned `requestUnitCost=2`를 등록했다. 다른 등록은 기존 ToolSpec 비용을 사용한다.
- 새 `redteam-llm-rag-v1`은 exact A04·`ai.chat-probe@1.0.0`·A04 threat·두 turn과
  `ai-chat-api` 또는 `rag-chat-api` Target 하나만 허용한다.
- prepared request turn 수, Capability Definition, Graph Proposal의 request units가 모두 2여야 한다.
  T2 approval은 Proposal/reservation을 exact 결박하고 기존 transaction이 같은 예약으로 Permit을 소비한다.
  기존 CAP-005 dispatcher와 Gateway가 Definition 비용과 실제 두 proxy receipt를 다시 검증한다.
- 1-unit under-reservation, 3-unit over-reservation, single-turn Capability, approval 누락과 generic Envelope
  relabel은 Permit·Worker 전에 거부한다. 성공 후 exact retry는 같은 terminal Permit을 반환하고 Worker를
  한 번만 호출한다.
- 기존 `redteam-llm-v1` M03/M06 경계와 PENTEST GET wire는 변경하지 않았다. A04 `1.0.0`은 historical
  identity이며 current `1.1.0` activation에는 별도 reviewed signed release가 필요하다.

## 주요 변경 파일

- `src/pajin/control_plane/pentest_workflow_coordination_deployment.py`
- `src/pajin/control_plane/pentest_workflow_coordination.py`
- `src/pajin/control_plane/pentest_replay_deployment.py`
- `src/pajin/workflow/pentest_recon_replay.py`
- `src/pajin/control_plane/api.py`
- `src/pajin/control_plane/client.py`
- `src/pajin/control_plane/executors.py`
- `src/pajin/control_plane/redteam_profiles.py`
- `src/pajin/capabilities/adapters.py`
- `src/pajin/capabilities/existing.py`
- `src/pajin/cli.py`
- `tests/test_pentest_recon_dispatch.py`
- `tests/test_pentest_compile_cli.py`
- `tests/test_control_plane_error_safety.py`
- `tests/test_control_plane_phase9_deployment.py`
- `tests/test_control_plane_worker_mtls_config.py`
- `tests/test_existing_capability_rollout.py`
- `tests/test_existing_capability_adapters.py`
- `docs/adr/0201-resolve-dynamic-pentest-child-deployments-from-server-registry.md`
- `docs/adr/0202-compose-approved-single-turn-llm-redteam-profile.md`
- `docs/adr/0203-bind-multi-turn-llm-rag-request-units.md`
- `docs/orchestration/PENTEST-004C2B2-concrete-child-deployment-adapters.md`
- `docs/orchestration/REDTEAM-001A-approved-single-turn-llm-profile.md`
- `docs/orchestration/REDTEAM-001B-multi-turn-llm-rag-profile.md`

`PLAN.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`, `README.md`와 B1 계약도 현재 상태로 갱신했다.

## 검증 상태

- lock 기준 환경 복구:
  - `uv sync --frozen --extra dev --extra control-plane --extra object-storage-minio --reinstall`
  - `uv venv --allow-existing .venv`
  - `.venv/bin`의 이전 Google Drive 경로: 0건
  - `boto3==1.43.73`, `pytest==9.1.1`, editable `pajin`이 현재 checkout을 가리킴
- 기존 환경 실패 2건 직접 재검증: `2 passed`
  - packaging clean-install smoke와 MinIO selected-inventory 검증을 `.venv/bin/pytest`로 실행했다.
- REDTEAM-001A/B·request-unit 집중 회귀: `15 passed, 55 deselected`
- CAP-005 adapter·rollout 전체: `70 passed`
- A04 주변 Gateway·Replay·Retest·Validation·MCP·cleanup 회귀: `197 passed`
- PENTEST-004C2B2·REDTEAM-001A·문서 통합 묶음: `127 passed`
- `tests/test_existing_capability_rollout.py`: `61 passed`
- 문서 정책: `2 passed`
- `ruff check src tests containers scripts`: 성공
- `python -m mypy src`: `Success: no issues found in 315 source files`
- `python -m compileall -q src`: 성공
- `uv lock --check`: `Resolved 71 packages`
- 전체 pytest 회귀 checkpoint: `4136 passed, 67 skipped, 2 deselected`
  - deselect 2건은 managed sandbox가 금지하는 `127.0.0.1` bind 회귀다.
  - 동일 두 테스트를 승인된 sandbox 밖에서 최종 재실행해 `2 passed`를 확인했다.
  - REDTEAM-001B 반영 뒤 Ruff 전체, mypy 전체와 문서 정책도 다시 통과했다. 두 결과를 합치면 확인된
    코드 회귀는 없다.
- `git diff --check`: 성공.

## 알려진 제한과 운영 경계

- 구현은 host-local이다. child registry filesystem 권한이 deployment TCB이며 cross-host fence, distributed
  Worker queue, registry publication automation은 없다.
- 실제 외부 Target이나 Docker network는 호출하지 않았다. trusted Docker-receipt fixture로 M03/M06/A04
  Gateway·semantic Oracle·no-redispatch 경계를 검증했으며 운영 Target 증거는 아니다.
- executable 제품 경계는 signed Scope의 GET Recon/Replay, `redteam-llm-v1` 단일-turn M03/M06와
  `redteam-llm-rag-v1` exact A04 LLM/RAG Target까지다. Web, MCP, browser, system은 닫혀 있다.
- 현재 `.venv`에는 `object-storage-minio` extra가 설치돼 있다. clean 환경에서 해당 검증을 실행할 때 같은
  extra를 명시해야 한다.

## Git 재개 확인

다음 세션은 문서를 그대로 신뢰하지 말고 먼저 실행한다.

```bash
git status --short --branch
git rev-parse HEAD
git rev-parse '@{upstream}'
git diff --check
.venv/bin/python -m pytest -q \
  tests/test_pentest_recon_dispatch.py \
  tests/test_pentest_compile_cli.py \
  tests/test_control_plane_error_safety.py \
  tests/test_control_plane_phase9_deployment.py \
  tests/test_control_plane_worker_mtls_config.py \
  tests/test_existing_capability_rollout.py \
  tests/test_documentation.py
```

staged 변경과 진행 중인 merge/rebase/cherry-pick/revert/bisect가 없어야 한다. 실제 Git과 파일시스템이
이 문서와 다르면 실제 상태를 우선한다.

## 다음 한 단계

`REDTEAM-001C`에서 현재 signed Capability inventory와 Tool/Gateway 경계를 대조해 bounded Web Capability
profile의 exact Tool, Target type, risk, request-unit, receipt와 negative boundary를 먼저 고정한다. LLM/RAG
프로필의 Tool category 또는 surface declaration을 Web 실행 권위로 해석하지 않는다.
