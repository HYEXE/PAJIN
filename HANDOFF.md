# PAJIN 인수인계

## 현재 체크포인트 (2026-09-11)

새 후속 5개 goal의 ②·③·④·⑤ 구현·로컬 검증을 완료했다. ②는 품질 개선 미확인 결과다.
①을 포함한 여섯 commit·`origin/main` push·동일 신규 커밋 CI/Web/Network/AI 실행을 승인받았다.
앞의 다섯 커밋을 로컬에 저장했으며 현재 상태 문서 반영 뒤 push·원격 검증을 진행한다.
이전 8개 및 직전 5개 개선 goal은 완료 상태를 유지한다. 이번 전체 로컬 pytest는
8,342 passed·기존 76 skipped / 2,585.85초에 통과했고 실행 중인 검증은 없다.

## Git 상태와 승인 경계

- 시작 기준은 `main`의 `215d4fc03e1385c64ccc1e4e7fe70efd0ea4add2`다. HEAD·upstream·실제
  origin/main이 일치했고 worktree 하나, staged/untracked/삭제 및 진행 중 Git 작업은 없었다.
- 시작 시 `HANDOFF.md`, `KNOWN_ISSUES.md`, `PLAN.md`,
  `docs/orchestration/OPS-002-isolated-postgres-operations.md`만 unstaged였다.
  정확한 원본 bytes·diff·manifest·검토 결과는 `.pajin/followup-five-20260910/step1-docs/`에 보존했다.
  해당 문서 검사 4개와 `git diff --check`를 통과했다. 원본 CI log·24 artifact·세 Docker 결과도 대조했다.
- 검토안의 여섯 commit·일반 `origin/main` push·자동 CI·세 Docker workflow 실행은 사용자에게
  명시적으로 승인받았다. ①의 보존 패치만 `625e53b`에 저장했고 원본 bytes와 staged bytes가 일치했다.
- 이어 EFFECT-003 `0db2f1d`, OPS-003 `f8da370`, Graph `afe22b5`, SYS-002 `78e9a6d`를 저장했다.
  각 커밋의 파일 목록과 staged bytes가 검토·실제 검증한 지문과 일치했다. private 자료는 제외했다.
  이 체크포인트는 여섯 번째 상태 문서 커밋 직전이며 HEAD는 `78e9a6d`, upstream은 시작 SHA다.
  현재 남은 변경은 `DECISIONS.md`, `HANDOFF.md`, `KNOWN_ISSUES.md`, `PLAN.md`, `README.md`,
  `docs/README.md`다. staging/삭제/untracked/진행 중 Git 작업은 없고 새 브랜치/worktree/서브에이전트를 만들지 않았다.
- 운영 호스트·운영 데이터·유료 외부 자원·배포는 이번 로컬 검증 범위 밖이다.

## ② EFFECT-003: 개선 미확인

- `tools/disclosure_context.py`와 `benchmark/effectiveness_revision/`에 별도 후보/평가/reader를 추가했다.
  계약은 [EFFECT-003](docs/benchmark/EFFECT-003-context-disclosure-comparison.md), 결정은 ADR-0278이다.
  기존 EFFECT-001/002·`novel-opaque-output-v1`·APP-002의 구현과 기존 artifact reader는 변경하지 않았다.
- EFFECT-002는 개발 자료로만 사용했다. 새 16개 과제·24개 모델 설정·독립 정답·표본/제외/성공 규칙,
  탐지기와 source 23개를 실행 전에 고정했다. detector는 private Ground Truth를 받지 않는다.
- 실제 smoke 4개 통과 후 held-out 384번 시도 중 382개 응답·2개 ModelCallFailure(exit 70)를 받았다.
  baseline TP/TN/FP/FN **129/201/45/7**, 후보 **135/195/51/1**이다.
  정밀도 **74.14→72.58%**, 재현율 **94.85→99.26%**다. 비교 완전성·정밀도 비감소 기준을 실패했다.
  기존 기본 탐지기를 유지하며 후보는 실험 버전으로만 보존한다. 소비한 평가군을 재실행/재조정하지 않는다.
- 실제 모델 파일과 고정 이미지 지문을 확인했고 fresh-process reader가 동일 집계를 재계산했다.
  실행/reader exit 2는 불완전 비교의 거부다. 두 실패의 세부 원인은 확인하지 못했다.
  시간·토큰·로컬 한계비용·24개 좌표와 반복 편차·stratum은 계약에 기록했다.
- 모델 실행 동안 별도 로컬 검증과 일부 시간이 겹쳤다. 시간은 공유 호스트 관측이며 전용 처리량이나
  모델 간 성능 순위를 의미하지 않는다. 의심 신호는 Finding 권위가 아니다.
- private plan: `.pajin/effectiveness-v3-plan.json`; frozen source:
  `.pajin/effectiveness-v3-frozen-source/`; 결과: `.pajin/effectiveness-v3-result.json`;
  fresh reader: `.pajin/effectiveness-v3-public.json`.
  `.pajin/followup-five-20260910/effect003-external-cleanup.json`에서 독립 관찰자가 408개
  exact selector의 container/network 부재를 확인했다. 원문·canary·키·모델은 공개하지 않는다.

## ③ OPS-003: 운영자용 hybrid 복원·승인 재개

- `python -m pajin.operations`가 code-digest/preflight/stop/checkpoint/restore/verify/resume을 제공한다.
  선정 구성은 Linux 단일 호스트·PG17 CP·local SQLite Graph/journal·host-local sealed RunStore다.
  계약은 [OPS-003](docs/orchestration/OPS-003-managed-hybrid-recovery.md), 결정은 ADR-0279다.
- 등록형 OPS-001 API는 그대로 유지한다. 독립 대상/이미지/code/key pin, 모든 참여 writer의 정지,
  암호화 checkpoint·독립 pin, 원래 예산/Graph/Run 증거, 새 빈 대상의 정확한 복원을 검증한다.
  별도 서명 승인과 현재 CP Operator 권한을 재확인하고 기존 CP 승인/예산/one-use 재개 경로를 호출한다.
  복원 데이터는 Scope/Capability/Permit/재개 승인이 아니며 불확실한 호출 차감과 결과를 보존한다.
- 첫 성공은 `.pajin/followup-five-20260910/ops003-attempt5/`에 보존했다. 최종 전체 제품 지문
  `0dd72d3b14fd1b6f61edc55051c171164eafc52d6dc9de3e6c9526f55ce420b6`의 새 이미지로 통합 재검증했다.
  `.pajin/followup-five-20260910/ops003-final/`의 실제 Linux 리허설은 **11개 확인 / 71.07초**에 통과했다.
  source 정지·중간 pg_restore 실패·정확한 재시도·fresh-process 검증·만료/권한/승인 거부·
  별도 승인 재개·중복 거부·unknown charge 1회 보존·2개 Run seal을 확인했다.
- 별도 관찰자의 `external-cleanup.json`에서 8개 exact container/volume selector와 controller 부재를 확인했다.
  CP/Worker mTLS·PG17은 실제 실행이고 payload는 deterministic simulated model/mock Tool이다.
  물리 host/storage 장애·정전·live backup·분산 failover·외부 rollback·운영 배포는 검증하지 않았다.

## ④ GRAPH-PERF-002: 최초·이력 변경 비용 검증

- `graph/sqlite_store.py`는 검증된 Event Log를 한 번 누적 재생하면서 모든 역사 Projection의 정확한
  nodes/edges/head를 비교한다. persisted model/digest/index·schema/integrity·current head·권한은 그대로 검증한다.
  DB eligibility만 256 MiB로 늘렸고 Snapshot 16 MiB·한 entry·두 번 전체 hash는 유지한다.
  관련 **90개 회귀**와 전체 pytest를 통과했다. API/wire/schema 변경은 없다.
- 고정 medium/large/history base와 successor DB를 같은 macOS arm64/Python 3.12.13에서 비교했다.
  전체 회귀가 끝난 뒤 다른 검증/모델/Docker 부하 없이 버전별 9개 process·72개 query를 실행했다.
  동일 fixture·실험 코드·실제 loaded module 지문을 대조했으며 변경 파일은 verifier/cache 두 개뿐이다.
- 5,002 node / 10,000 edge 최초 **13.481→8.134초**, 변경 직후 **15.646→9.202초**다.
  148,643,840-byte 큰 이력의 최초 **20.810→14.551초**, 변경 후 **22.720→15.405초**,
  반복 **20.801→0.304초**다. 상세 SD/CPU/메모리/I/O·검증 횟수는 계약에 있다.
- 작은 DB의 반복은 8–12 ms 느려졌고 큰 이력 uninstrumented process RSS 평균은 **1,313→1,618 MiB**로
  증가했다. cold retained Python allocation도 약 39.3 MiB로 늘었다. 메모리 감소나 운영 SLO를 주장하지 않는다.
  filesystem pages는 미리 데웠고 0인 OS block counter가 논리 I/O 없음이나 물리 디스크 성능을 증명하지 않는다.
- [GRAPH-PERF-002](docs/benchmark/GRAPH-PERF-002-first-and-history-page-cost.md)·ADR-0280에 이 결과와
  비용을 기록하고 채택했다. 과거 Projection의 중복 replay는 줄였지만 Snapshot 전체 검증은 남는다.
- private `.pajin/followup-five-20260910/`의 `graph-baseline-source/`, `graph-history-fixtures/`,
  `graph-history-before.json`, `graph-history-after.json`, `graph-history-summary.json`이 재현 근거다.
  `scripts/profile_graph_history.py`의 공통 실험 SHA는
  `2a6fd95fb838ded20e8b51fb7ec1656a659ca585c7ff6d4a83f17acf90a4ca69`다.

## ⑤ SYS-002: 실제 인증 System 읽기 한 기능

- `system_read/`, `containers/system-agent/`에 고정 `/usr/lib/os-release` 읽기를 추가했다.
  허가된 Scope→현재 Capability/Policy→별도 서명 Approval/one-use Permit→mTLS agent/Worker→
  Run 봉인→독립 확인/새 승인 재실행→`python -m pajin.system_read` 제품 보고로 연결한다.
  계약은 [SYS-002](docs/orchestration/SYS-002-authenticated-os-release-read.md), 결정은 ADR-0281이다.
- 새 격리 Linux container userspace만 읽는다. 임의 경로/명령·Cloud credential·운영 호스트가 필요 없다.
  TLS CA/인증서/agent/client/image/대상 pin과 짧은 one-use SecretBroker lease를 검증한다.
  client 인증 실패와 중복 nonce는 파일 읽기 전에 거부한다. nonce ledger는 process-local이다.
- `.pajin/followup-five-20260910/sys002-final/`에서 **실제 1 passed / 32.19초**다.
  2개 승인 Run, 독립 `platform.freedesktop_os_release()` 결과, fresh-process 보고와 Scope/서명/인증/
  duplicate/비정상 파일 거부를 확인했다. 별도 관찰자가 4개 Worker/proxy/network와 두 agent 부재를 확인했다.
- 고정 agent 이미지: `sha256:6919e15137bae8a6dadf8a183dbd5f63113178d6f32da3c0f96b29c4447b2536`.
  private `report.json`, `fresh-process-report.json`, `independent-standard-library.json`이 근거다.
  일반 System·물리 host·SYS-001 전체 conformance나 기본 CP/Console 활성화로 확대하지 않는다.

## 공통 검증과 패키징

- 전체 `.venv/bin/python -m pytest -q --tb=short`는 **8,342 passed·기존 76 skipped / 2,585.85초**, exit 0이다.
  `.pajin/followup-five-20260910/full-pytest.log`와 `full-pytest-result.json`을 보존했다.
  시작 inventory 1,519개 중 제품·테스트 800개를 포함한 1,518개가 일치했다. 유일한 변경은
  측정 전에 별도 타입/정적 검사를 마친 profiler script다. 전체 소스가 완전히 동일했다고 주장하지 않는다.
  이후 최종 README/계약/운영 문서 검사도 **4 passed**다. `git diff --check`를 통과했다.
- Ruff `src tests containers scripts` 전체 통과. Linux strict mypy 기본 **466 files** 통과.
  새 script와 agent/client 7개도 별도 strict 검사했다. OPS/System 최신 관련 **33 passed / 2.05초**다.
- private copy에서 wheel/sdist를 빌드하고 별도 설치 경로의 `python -I`로 실제 package import를 확인했다.
  설치된 reader의 EFFECT-003/System 보고가 source 결과와 같고 OPS code digest도 최종 이미지와 일치했다.
  `.pajin/followup-five-packaging/installed-verification.log`와 `dist/`가 근거다. release나 게시가 아니다.
- 변경 경로 정책은 일반 CI와 Web/Network/AI workflow를 요구한다.
  `.pajin/followup-five-20260910/required-conformance.json`은 선택만 기록하며 실행 권한을 부여하지 않는다.
  새 원격 검증은 미실행이다. 실제 로컬 모델/DB/Docker와 원격 exact-commit 검증을 구분한다.

## 이전 완료 근거와 다음 작업

기존 `215d4fc`의 CI 34466459329는 Quality·24 shard 모두 성공, **8,260 passed / 76 skipped**다.
Web 34466552572 **136.13초**, Network 34466556691 **270.42초**, AI 34466560216 **91.39초**의
실제 검사와 별도 cleanup도 통과했다. 기존 Dependabot 6건은 당시 모두 fixed였다.
원본·검토 결과는 `.pajin/five-improvements-remote/215d4fc03e1385c64ccc1e4e7fe70efd0ea4add2/`와
이번 `step1-docs/`에서 확인한다. 완료한 코드를 반복하거나 새 소스 검증으로 재사용하지 않는다.

다음 단계는 승인된 마지막 상태/탐색 문서 커밋을 저장하고 여섯 commit을 `origin/main`에 push하는 것이다.
첫 commit에는 보존한 기존 문서 4개 patch만 포함했으며 사용자 변경을 보존했다.
동일 신규 커밋의 일반 CI와 Web/Network/AI workflow에서 실제 검사·모든 시도·필수 job·cleanup을 확인한다.
검토안은 `.pajin/followup-five-20260910/commit-review.md`다. 해당 승인 범위를 다시 묻지 않는다.
원격 검증 중 추가 코드/문서 커밋이 필요하면 실제 diff와 기존 승인 범위를 대조한다. 배포 승인은 포함하지 않는다.
모델 원문·canary·키·DB·deployment inventory 등 `.pajin/`의 private 자료는 Git에 포함하지 않는다.
