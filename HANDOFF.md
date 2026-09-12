# PAJIN 현재 인수인계

검증 체크포인트: 2026-09-12.

## 목표와 Git 상태

2026-09-11의 두 번째 다섯 후속 목표는 구현·로컬 실증·회귀·원격 검증을 완료했다.
사용자는 별도 Linux host가 없어 격리 검증을 먼저 선택했고 추가 System 읽기를 선택했다.
문서 반영, 탐지기 오탐·CPU, Graph 최초 조회, 독립 checkpoint, 추가 System 읽기 순서로 진행했다.

- 작업 브랜치: `main`. branch/worktree/subagent는 만들지 않았다.
- 코드·테스트·CI 검증 SHA: `1fd37d16d05887f9ff7956ccea4986b77cd4fe6c`.
  push 뒤 local HEAD·upstream·실제 원격 main이 같은 것을 확인했다.
- 첫 과제의 결과 문서 8개는 `20f0ec5`로 commit/push했다. CI 34571193983에서 첫 시도
  Quality·24 shard, 8,441 passed·기존 76 skipped와 exact clean SHA의 8,517개 ID를 확인했다.
- 이후 사용자가 승인한 구현 commit은 탐지 `a619b1f`, Graph `eeba83f`, checkpoint `ac0a25e`,
  System `455fbed`, CI `1fd37d1`이다. 승인된 여섯 번째 commit은 실제 원격 결과를 기록하는
  이 문서 checkpoint다. 코드 검증 SHA 이후 변경은 Markdown에 한정한다.
- 원격 코드 검증은 아래 여섯 workflow 모두 첫 시도 성공이다. 결과 문서를 반영한 실제 SHA의
  일반 CI와 최종 Git 상태는 별도로 확인한다. 문서 변경만으로 기존 코드 검증을 새로 주장하지 않는다.
- PR·merge·배포·운영 변경은 수행하지 않았다. 재개 시 실제 Git과 원격 상태를 다시 대조한다.

## 구현과 실증

### EFFECT-005

- `disclosure_derived` v4는 공개 literal에서 정확하게 재계산한 hash만 제외한다. 생성 의도만으로
  ID를 면제하지 않는다. 기존 v1/v2/v3와 제품 기본값·false Finding authority는 유지한다.
- 새 18개 과제(개발 2/본 평가 16), 이전 54개 제외, 두 모델·24좌표·384응답과 64회 detector
  timing을 호출 전에 동결했다. 관련 집중 121개 검사와 별도 공개 개발 parity/CPU를 확인했다.
- 본 평가 384응답·0실패·0미채점. 오탐 76→64, 정밀도 64.49→68.32%, 재현율 100%,
  F1 78.41→81.18%, 평균 CPU 27.09→20.96μs. 생성 사례 오탐 45→33이며 64개 오탐이 남았다.
- 동결 source와 별도 설치 wheel의 독립 보고서 bytes가 같다. 505개 pin·원본 496개 파일을
  대조했고 smoke 포함 414 selector의 container/network 부재를 독립 확인했다.
- 평가군은 소비됐다. 현재 source나 다른 root로 본 평가를 반복하거나 응답을 보고 후보를 바꾸지 않는다.
  이전 평가의 오탐 51개와 새 평가군의 수치를 직접 전후 비교하지 않는다.
- 계약: [EFFECT-005](docs/benchmark/EFFECT-005-public-derived-disclosure-and-cpu.md), ADR 0286.

### GRAPH-PERF-004

- 같은 트랜잭션에서 완전히 검증한 Projection과 전체 JSON 내용이 같은 현재 Snapshot만
  해당 model instance를 재사용한다. 원본 canonical bytes·모든 이력·chain/head·변조 검사와
  defensive copy는 유지한다. 전체 history/backup/recovery의 독립 model 검증은 바꾸지 않았다.
- 진단에서 Snapshot 검증 병목을 확인했다. 관련 107개 회귀가 통과했다.
- 전후 source 499개 중 `graph/sqlite_store.py`만 다르다. medium/history 각각 reader 1/2개,
  guest file pages cold/warm, 3회 반복의 24그룹·36독립 process·108조회씩 모두 검증했다.
- 큰 이력 cold 단일 최초 조회는 12.6702→9.5380초, 두 reader 완료는 13.4525→10.0194초다.
  모든 8개 최초 조회 조건의 그룹 평균이 개선됐다. 개별 process 최대 RSS는 641.18→558.00 MiB다.
- cold는 owned overlay file의 mincore 비상주 확인이다. host/SSD cold나 aggregate RSS,
  일반 운영 SLO는 주장하지 않는다. 반복 조회 지연은 일관되게 개선되지 않았다.
- 계약: [GRAPH-PERF-004](docs/benchmark/GRAPH-PERF-004-processes-and-first-read-validation.md), ADR 0289.

### OPS-004

- 별도 보관 volume의 서명 append chain·enrollment·expected-sequence CAS와 latest-head gate를
  구현했다. old archive+old pin을 restore/verify/resume 전에 거부하고 recovery 동안 shared lock을 유지한다.
  writer에는 anchor mount가 없고 recovery는 read-only다. unenrolled wire는 유지한다.
- 기존 OPS-003 11개와 새 OPS-004 15개 실제 Linux arm64 검사가 통과했다. 독립 checkpoint 2개,
  오래된 archive의 materialization 전 거부, 최신 대상 복원·fresh CLI 검증·별도 승인 재개를 확인했다.
  두 결과의 제품 code digest는 `03228139c939881ce81c6d9e18f633f671a6d31b5347c4845d21da61a0323eae`다.
- 첫 시도는 source seed의 새 volume 초기화에서 실패했다. 제한된 Linux 권한으로 재현하고
  chmod→chown 순서로 fixture만 보정했다. 실패 근거와 15개 통과 결과를 분리 보존한다.
- 물리 host·anchor 전체 rollback/유효 suffix 삭제·power loss·운영 failover는 검증하지 않았다.
  보관 한도는 4,096개이며 초과는 source 정지 전에 거부한다.
- 계약: [OPS-004](docs/orchestration/OPS-004-independent-checkpoint-head.md), ADR 0287.

### SYS-004

- `system.aslr-read`는 mTLS `/v1/aslr`로 고정 `/proc/sys/kernel/randomize_va_space`만 읽는다.
  별도 Capability·operator 서명·Policy·승인·Permit·Secret Lease·Worker·봉인 결과와 독립 CLI를 연결했다.
  정확히 같은 `0\n`/`1\n`/`2\n` 두 관찰만 허용한다. 기존 SYS-002 source 10개는 그대로다.
- 실제 정상 실행 2회가 mode 2의 두 바이트를 읽었고 GNU coreutils 9.7과 독립 CLI 결과가 같다.
  인증·Scope·서명·nonce·path 거부를 포함한 live probe가 33.29초에 통과했다.
- 첫 시도는 `/proc` bind mount의 runc 금지로 시작 실패했다. 같은 경계를 별도 재현했다.
  수정된 negative fixture만 고정 open을 read-only 잘못된 값으로 연결한다. 실제 bounded read로
  HTTP 422·nonce 재사용 409·실패 Worker를 확인하며 kernel을 바꾸거나 정상 결과로 인정하지 않는다.
- 기존 SYS-002와 새 SYS-004 각각 Worker 4회, 두 agent와 Worker/proxy 자원 부재를 확인했다.
  두 프로필의 결과를 별도 빌드·설치 wheel에서도 동일하게 읽었고 설치 source 489개 bytes가 같다.
- `Finding`·개별 process ASLR·physical host·일반 System 지원은 false다. 새 Console/API는 추가하지 않았다.
- 계약: [SYS-004](docs/orchestration/SYS-004-authenticated-kernel-aslr-read.md), ADR 0288.

## 최종 통합 검증 상태

- 전체 Ruff, Linux strict mypy 본체 490개·운영/profile/기존 agent 13개·새 agent/client 2개가 통과했다.
- 기존/신규 OPS·SYS 근거를 원격 workflow와 같은 `verify_probe` 함수로 읽어 모두 통과했다.
  이는 runner 환경 gate를 우회한 원격 실행이 아니라 이미 수행한 로컬 근거의 검사다.
- 최초 전체 pytest는 8,541 passed·기존 76 skipped·10 failed·15 errors다. 8,642개 ID에
  누락/중복이 없고 비문서 source 967개가 유지됐다. 호스트 sleep/wake와 승인 만료·시간 예산 초과를
  확인했다. 검사 기준과 source를 유지하고 유휴 절전을 일시 억제한 별도 실행에서 25개 모두
  170.01초에 통과했다. 재검증의 wall/monotonic 시간 차이는 없었다. 최초 전체 실행을 성공으로 바꾸지 않는다.
  전체 실행+집중 재검증의 결과는 8,566 unique passed·기존 76 skipped이며 이전 8,517개를 보존했다.
  원격과 로컬의 경로 표기만 정규화한 skip 위치·사유·개수도 같다. 추가 전체 반복은 하지 않는다.
- 제품/공용 fixture/CI 변경에 필요한 Web·Network·AI·OPS·SYS 다섯 원격 family가 통과했다.
  OPS/SYS는 기존과 새 probe 모두 성공했으며 실제 image ID와 전체 tracked source commitment를 대조했다.
- 모델·Graph·pytest·설치 검증 프로세스는 종료했다. 독립 Docker 23개 selector/69회 조회에
  잔여 container/network/volume이 없다. 문서 검사 4개와 diff 검사는 통과했다.
  54개 파일의 diff와 실제 private canary 18개 유입 여부를 검토했고 검출은 없었다.

## 원격 코드 체크포인트

다음 결과는 모두 clean SHA `1fd37d16d05887f9ff7956ccea4986b77cd4fe6c`의 첫 시도다.

| Workflow | 확인한 결과 |
| --- | --- |
| [CI 34669692639](https://github.com/HYEXE/PAJIN/actions/runs/34669692639) | Quality·24 shard; 8,566 passed·기존 76 skipped |
| [Web 34669907026](https://github.com/HYEXE/PAJIN/actions/runs/34669907026) | 실제 검사 1개, 133.03초 |
| [Network 34669908622](https://github.com/HYEXE/PAJIN/actions/runs/34669908622) | 실제 검사 1개, 296.50초 |
| [AI 34669909903](https://github.com/HYEXE/PAJIN/actions/runs/34669909903) | 실제 검사 1개, 79.89초 |
| [OPS 34669911248](https://github.com/HYEXE/PAJIN/actions/runs/34669911248) | 기존 11개·신규 15개, outer runner 248.66초 |
| [SYS 34669912227](https://github.com/HYEXE/PAJIN/actions/runs/34669912227) | 기존·신규 각 실제 검사 1개와 Worker 4회, outer runner 86.51초 |

CI artifact 24개는 같은 clean SHA·exit 0이며 총 8,642개 ID가 로컬 수집과 같다.
이전 8,517개를 모두 보존하고 125개를 추가했으며 누락/중복과 skip 위치·사유·개수 변화가 없다.
원격 Ruff와 Linux strict mypy 490+13+2개가 통과했다. OPS/SYS의 1,505개 tracked file commitment는
`6326d2448a5a40dbe415e553aca8e2386dd2c15edc6e7635f0c59c8c18f84e4f`다.
다섯 conformance의 독립 residue gate가 통과했고 OPS/SYS는 cleanup·별도 읽기 관찰 모두
container/network/volume 0개, fallback removal 없음이다. 공개 artifact는 각 세 개의 bounded JSON뿐이다.
Ubuntu 24.04/Linux amd64의 격리 실행이며 물리 장애나 운영 복구의 보증으로 확대하지 않는다.

## 비공개 재개 근거

아래는 저장소 기준 private 경로다. 원문·모델·canary·키·Run 원문·inventory는 공개하거나 commit하지 않는다.

- 공통: `.pajin/followup-five-v2-20260911/`. 문서 push CI는 `remote/`.
- EFFECT: `.pajin/effectiveness-v5-{corpus,plan,smoke,result,public}.json`,
  `.pajin/effectiveness-v5-frozen-source/`. plan commitment:
  `3bef62db9fb282999fbab0b0ecafec263b5767d2aecf0ca37babfe4856318364`.
  공통의 `effect005-frozen.json`, `effect005-independent-report.json`, `effect005-independent-cleanup.json`,
  `effect005-wheel-source-verification.json`, `effect005-installed/`를 대조한다.
  wheel 작업본에만 Git 검증된 기존 build backend를 추가했고 동결 원본은 바꾸지 않았다.
- Graph: `graph-before/`, `graph-after/`, `graph-{before,after}-{profile,measure}/`,
  `graph-comparison-summary.json`, `run_graph_linux.py`, `summarize_graph004.py`.
  fixture는 `.pajin/followup-five-20260910/graph-history-fixtures/`에 보존한다.
- OPS: `ops003-current/`, 실패 `ops004-current/`, 성공 `ops004-v2/`,
  `ops004-permission-reproduction.json`, `ops004-image{,-v2}-id.txt`.
- SYS: `sys002-current/`, 실패 `sys004-current/`, 성공 `sys004-v2/`,
  `sys004-mount-reproduction.json`, `sys004-fixed-file-smoke.json`, `sys004-image-id.txt`.
- 통합: `local-boundary-verification.json`, `final-linux-independent-cleanup.json`,
  `linux-source-{before,after}.json`, `linux-source-v2-before.json`,
  `final-regression/`(최초 실패·sanitized sleep/wake), `failure-recheck/`,
  `final-verification-summary.json`, `final-packaging/`, `final-{ruff,mypy-main,mypy-scripts,mypy-aslr}.log`.
- 이전 제품 기준 `51aeb02`의 모든 원격 검증은
  `.pajin/followup-next-five-20260911/remote/51aeb02721f4d914e17fc8f028f02a31a0fa21ee/`에 있다.
  이전 검증을 새 source의 성공으로 대체하지 않는다.

## 재개 시 첫 확인

새 작업 전에 이 문서를 포함한 문서 commit, 실제 `main`·upstream·원격 SHA와 일반 CI를
대조한다. 코드 checkpoint `1fd37d1` 이후 Markdown-only 비교는 추가 Docker family를 선택하지
않으며 제품·공용 코드가 바뀌면 새 SHA로 필요한 conformance를 수행한다.

공통 private 근거의 `implementation-approval.json`, `approved-implementation-commits.json`,
`remote/1fd37d16d05887f9ff7956ccea4986b77cd4fe6c/verified-summary.json`에 승인·실행·검증을 보존한다.
문서 SHA의 CI 근거도 같은 `remote/<sha>/` 구조로 보존한다. 이전 실패와 성공 기록은 덮어쓰지 않는다.

추가 제품·운영 과제는 선정하지 않았다. 남은 오탐, Graph 전체 검증 비용, 독립 보관소의 rollback
가정과 실제 물리 host 복원은 `KNOWN_ISSUES.md`에서 이어 간다. 소비된 모델 평가군은 반복하지 않는다.
