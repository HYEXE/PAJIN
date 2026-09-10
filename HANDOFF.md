# PAJIN 인수인계

## 현재 체크포인트

2026-09-09 새 goal의 5개 과제를 `PLAN.md` 순서로 진행한다. 이전 8개 개선은 완료됐고 반복하지 않는다.
SEC-001은 로컬 수정·회귀·설치/packaging과 원격 6건 fixed·동일 커밋 conformance를 완료했다.
EFFECT-002는 새 384개 응답의 비교·fresh-process 검증을 완료했다. 고정된 비교 기준을 통과했으며
남은 FP 31/FN 2·조건별 편차·시간·토큰·비용을 문서화했다. ③의 독립 PostgreSQL·Worker·crash·DB 복원 검증을 완료했다. 선정 Linux hybrid 구성의 전체 상태 cold backup/독립 복원 검증도 완료했다.
④의 Graph 반복 조회 개선과 ⑤의 승인된 offline ELF64 헤더 실행·재실행·보고를 로컬에서 검증했다.
마지막 변경을 포함한 최종 소스의 전체 회귀와 실제 DB/Docker 로컬 검증을 완료했다.
`72bdbd9`의 일반 CI·Web/Network/AI 원격 검증도 완료했다. 추가 Linux 검증 변경의 새 커밋·원격 CI/conformance가 남아 전체 goal은 미완료다.
2026-09-10 사용자가 준비된 여섯 commit·push·동일 커밋의 원격 workflow 실행을 승인했다.
승인된 여섯 커밋의 원격 반영·검증을 마쳤다. 사용자는 Linux 단일 호스트·PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal을
선택하고 ③의 격리 검증 진행을 승인했다. 해당 로컬 검증은 완료했다. 검토한 추가 14개 파일의
한 commit·`origin/main` push·동일 커밋 CI 및 Web/Network/AI 실행도 새로 승인받았다.
다음 단계는 승인된 커밋을 원격에 반영하고 해당 커밋의 실제 검증 결과를 확인하는 것이다.
구성 선택은 더 이상 대기하지 않는다. 운영 배포·운영 데이터 변경 승인은 아니다.

## Git과 승인 범위

- 시작 시 `main`의 HEAD·upstream·실제 원격 main은 모두
  `b359c3c782f9afa39f31a6d0aba9a9a8ace1dbd7`이었다. 깨끗한 worktree 하나만 존재했고
  staged/unstaged/untracked 변경과 merge/rebase/cherry-pick/revert/bisect는 없었다.
- 하위 `AGENTS.md`는 없다. `main`에서 작업하며 새 브랜치·서브에이전트는 만들지 않았다.
- 이번 58개 변경의 여섯 commit·`origin/main` push·일반 CI와 Web/Network/AI Docker workflow 실행을
  새로 승인받았다. 이후 Linux hybrid 구성의 격리 검증도 별도로 승인받았다. 배포 승인은 아니다. 제품·회귀·계약 53개 파일은 아래 다섯
  커밋에 보존했고 운영 상태·색인 5개 파일을 여섯 번째 커밋으로 묶어 push했다.
  local HEAD·upstream·실제 원격 main은 `72bdbd9ea281741d1120f64b0016047d95955bdd`로 일치했고
  push 직후 worktree는 깨끗했다. 이후 검증 결과를 이 문서·`PLAN.md`·`KNOWN_ISSUES.md`·SEC-001에
  반영한 Markdown 4개를 보존하면서 Linux 검증 실행기·테스트 전용 이미지/lock·ADR·계약을 추가했다.
  현재 총 14개 파일이 미커밋이며 staging·삭제·진행 중인 Git 작업은 없다. 제품 `src`·기존 lock은
  바뀌지 않았다. 추가 14개 파일의 한 commit·push·CI/세 Docker workflow 실행은 별도로 승인받았다.

## SEC-001 구현과 실제 결과

- `pyproject.toml`에 `httpx2>=2.12,<3` runtime 하한을 추가했다. HTTPX2의 exact 의존으로
  HTTPcore2도 2.12.0이다. `uv.lock`과 Control Plane의 `requirements.lock`을 함께 갱신했다.
  genai-prices/PydanticAI/OpenAI/httpx/httpcore는 기존 버전을 유지한다.
- 실제 의존 경로는 PAJIN → pydantic-ai-slim → genai-prices → httpx2 → httpcore2다.
  명시적 가격 갱신기의 HTTPX2 GET과 기본 bundled snapshot 사용을 소스·설치 환경에서 확인했다.
  직접 PAJIN HTTP 전송과 다른 경로다. 자세한 도달 조건·5개 공식 advisory·6개 경고는
  [SEC-001](docs/orchestration/SEC-001-http-client-dependency-security.md)에 기록한다.
- 새 테스트 `test_dependency_security.py`와 `test_dependency_socks_tls.py`는 압축 해제·오류 시
  stream close·요청 framing·multipart CR/LF·SSE 반복 스캔·실제 SOCKS TLS를 검증한다.
  SOCKS extra는 개발 환경에만 추가했다. 실제 소켓에서 sync/async·정상 인증서·불신 인증서를 대조한다.
- 동일 19개 보안/정상 대조 사례: 이전 2.7.0은 **17 failed, 2 passed**, 현재 2.12.0은 **19 passed**.
  기존 SOCKS wss 전송의 평문 GET도 관찰했다. 수정 후 실제 TLS handshake와 CA 거부를 확인했다.
  이전 패키지는 `.pajin/sec001-old-http`에만 격리했고 프로젝트 가상환경을 되돌리지 않았다.
- 주요 기존 회귀 포함 실행은 **199 passed / 15.32초**다. 테스트 이식성·소켓 읽기 보완 후 영향 범위의
  보안/packaging/deployment 재검증은 **55 passed / 10.23초**, 문서 검사는 **4 passed**다.
  중복 결과를 합산하지 않는다.
- `.venv/bin/uv lock --check --offline --cache-dir .pajin/uv-cache` 통과.
  `.venv/bin/uv sync --cache-dir .pajin/uv-cache --locked --all-extras`와 설치 의존성 check 통과.
- wheel/sdist를 `.pajin/sec001-dist`에 생성했다. 별도 `.pajin/sec001-install`에 Control Plane의
  hash-locked binary 의존성 38개와 wheel을 설치하고 39개 package 정합성을 확인했다.
  `python -I`로 wheel 경로 import·두 수정 버전·기본 bundled 가격 계산·실제 API import를 확인했다.
  기존 packaging smoke도 wheel/sdist·의존성 없는 설치·metadata 하한을 검사한다.
- Ruff 전체 통과. Linux strict mypy는 **428 source files 통과**. `git diff --check` 통과.
- sandbox의 DNS·캐시 접근·loopback bind 제한은 원인을 확인한 뒤 허용된 패키지/로컬 소켓 실행으로
  재검증했다. skip·TLS 해제·assertion 약화는 하지 않았다. 테스트의 소켓·thread는 종료됐다.

재현 명령(프로젝트 루트):

```sh
.venv/bin/python -m pytest -q tests/test_dependency_security.py tests/test_dependency_socks_tls.py tests/test_provider.py tests/test_provider_agents.py tests/test_provider_session.py tests/test_pydantic_ai_adapter.py tests/test_http_tool.py tests/test_worker_http.py tests/test_packaging_entrypoints.py tests/test_deployment.py
.venv/bin/ruff check --output-format concise src tests containers scripts
.venv/bin/mypy --platform linux src scripts/measured_conformance.py scripts/ci_sharding.py
.venv/bin/python scripts/measured_conformance.py --base HEAD --include-working-tree
git diff --check
```

로그: `.pajin/sec001-before.log`, `sec001-old-boundary.log`, `sec001-verified.log`,
`sec001-final.log`, `sec001-socks-tls.log`, `sec001-mypy.log`, `sec001-build.log`,
`sec001-conformance-required.json`. 마지막 보완을 포함한 전체 pytest 결과는 아래 통합 검증에 있다.

## 동일 커밋 원격 검증

- `72bdbd9ea281741d1120f64b0016047d95955bdd`를 push하고 GitHub의 의존 그래프 갱신을 확인했다.
  2026-09-10 08:24:01~02 UTC에 기존 Dependabot 경고 2~7번이 모두 fixed로 바뀌었고 열린 경고는 0건이다.
  로컬 패키지 제거·취약 동작 회귀와 실제 원격 경고 해소를 각각 검증했다.
- [CI 34454851268](https://github.com/HYEXE/PAJIN/actions/runs/34454851268): 첫 시도에 Quality와
  24 shard 모두 성공. **8,238 passed·기존 76 skipped**, 전체 job 실행 구간 515초다.
  로그 집계와 duration artifact 24개를 대조해 동일 SHA·clean tree·exit 0, 테스트 8,314개의
  중복 없는 처리를 확인했다. 집계는 `.pajin/five-improvements-remote/72bdbd9ea281741d1120f64b0016047d95955bdd/ci-verified.json`에 있다.
- 동일 커밋의 실제 Ubuntu 24.04 / Linux amd64 Docker 검증은 모두 첫 시도에 통과했다.

  | Workflow | 실제 검사 | 결과 |
  | --- | --- | --- |
  | [Web 34454971625](https://github.com/HYEXE/PAJIN/actions/runs/34454971625) | source·controlled validation·거부·product/fresh process | 1 passed / 132.94초 |
  | [Network 34454974833](https://github.com/HYEXE/PAJIN/actions/runs/34454974833) | 6 source·6 Replay·floor·product/fresh process | 1 passed / 334.19초 |
  | [AI 34454978127](https://github.com/HYEXE/PAJIN/actions/runs/34454978127) | source·Replay 2개·Controls 3개·floor·product/fresh process | 1 passed / 77.17초 |

  각 workflow의 명시적 확인·clean commit·이미지 ID 기록·실제 검사·무조건 실행되는 zero-residue
  단계가 모두 성공했다. 이미지 ID·runtime·로그 SHA-256은 같은 private 디렉터리의
  `web-verified.json`, `network-verified.json`, `ai-verified.json`에 보존했다. 원문·private inventory는 공개하지 않았다.
- 변경 경로 정책과 비교는 `five-improvements-conformance-committed.json`에 보존했다. 도구의
  `dispatchAuthorized: false`는 도구가 자동 실행 권한을 부여하지 않는다는 뜻이며 실제 사용자 승인·실행 결과와 구분한다.
- 이전 제품 검증 커밋 `e7c824362b8c69116db24c8b8f5e3917431eab1e`의 CI 34299070623과
  Web 34299157203·Network 34299158701·AI 34299160492는 성공 기록이다. 이전 최종 문서 커밋은
  b359c3c이며 사용자 제공 CI 34300565021은 8,095 passed·76 opt-in skipped 기록이다.
  새 코드·의존성 검증의 결과로 사용하지 않는다. 이전 원격 증거는 `.pajin/remote-verification/`에 있다.

## EFFECT-002 완료 체크포인트

- EFFECT-001의 기존 384개 응답은 개발 자료로만 사용한다. TP/TN/FP/FN은 28/166/100/90이다.
  `.pajin/effectiveness-v1-plan.json`, `.pajin/effectiveness-v1-result.json`,
  `.pajin/effectiveness-v1-public.json`, `.pajin/effectiveness-v1-frozen-source/`와 private Run tree가 있다.
- 기존 오탐 100개 중 92개는 공개 marker echo 사례였고, 미탐 90개 중 76개는 literal nonce,
  14개는 공백으로 분리된 nonce 노출이었다. 기존 자료를 개발에 사용했으며 새 평가 점수와 혼합하지 않는다.
- `tools/disclosure.py`의 opt-in 의심 탐지기는 응답·공개 사용자 입력만 받는다. 비공개 정답을 받지 않으며
  Finding 권위는 false다. 기존 marker와 oracle은 변경하지 않았다. 비교 계획·별도 reader·paired 결과는
  `benchmark/effectiveness_comparison/`, 계약은 [EFFECT-002](docs/benchmark/EFFECT-002-disclosure-detector-comparison.md),
  결정은 ADR-0274에 있다. 새 corpus는 중복·기존 사례 중첩·입력 내 canary를 거부한다.
- 새/기존 benchmark 집중 검증 **67 passed / 5.74초**, packaging/문서 **21 passed / 10.51초**,
  Ruff 전체와 Linux strict mypy **435 files**가 통과했다. EFFECT-001 fresh-process 보고서는 기존 공개
  결과와 byte-identical이었다. 이는 새 품질 결과를 대신하지 않는다.
- 허용된 로컬 Docker 실행을 시작했다. Linux arm64의 전용 Worker/proxy 이미지를 빌드했고,
  두 모델 파일의 크기·SHA-256을 실제로 다시 확인했다. 원문·canary·모델은 private `.pajin/`에만 있다.
- 새 plan 참조는 `.pajin/effectiveness-v2-plan.json`, root는 `.pajin/effectiveness-v2`이며
  plan Run은 `run_20260909T053459Z_695ed040`, root digest는
  `668e323427b23d5262c94baea60d513a93c25a3393baf49004637b8b5fc088dd`다.
  고정된 16개 Python source는 `.pajin/effectiveness-v2-frozen-source/`에 보존했다.
- 개발용 smoke는 두 모델의 총 4개 요청·봉인 검증을 통과했다. 미사용 평가를 시작했으므로 탐지기·정답·
  설정·제외 규칙을 변경하거나 같은 corpus를 새 canary로 재사용하지 않는다.
- 실제 실행과 fresh-process `report`가 exit 0으로 끝났다. 결과 참조는
  `.pajin/effectiveness-v2-result.json`, 검증 보고서는 `.pajin/effectiveness-v2-public.json`이다.
  result Run `run_20260909T064558Z_d48e9e41`, root
  `a16cd1ebca64aba5ad8bf73fb7eecac0968c8ae98ba5efa5e1ba72b598e3d461`이다.
- 384개 응답·0 failed/unscored. 기존 TP/TN/FP/FN 60/199/56/69, 개선 127/224/31/2다.
  정밀도 51.72%→80.38%, 재현율 46.51%→98.45%, F1 48.98%→88.50%로 사전 기준을 통과했다.
  기존 EFFECT-001 점수를 새 baseline과 혼합하지 않는다. 개발/평가 원문과 canary는 공개하지 않는다.
- 실제 시간 3,940.32초, provider 토큰 56,935개, local marginal token USD 0이며 기타 비용은 미측정이다.
  반복 편차·CPU·wall·조건별 악화·남은 오류는 EFFECT-002에 기록했다. 평가 후 Python 고정 소스를 바꾸지 않았다.
- 2026-09-10 실제 소유 label 기반 Docker inventory에서 target/Worker container·network 잔여가 없었다.
  실행 프로세스는 종료됐으며 `.pajin/effect002-run.log`, `.pajin/effect002-report.log`에 결과가 있다.

## OPS-002 선정 Linux 구성의 로컬 검증

- 선정 구성은 Linux 단일 호스트·PostgreSQL 17 Control Plane·local SQLite Graph/실행 journal·
  host-local RunStore다. `scripts/operational_linux.py`, `operations_cold_checkpoint.py`,
  `tests/operational_linux_probe.py`와 전용 테스트 이미지/lock을 추가했다. 기존 SQLite 전용
  OPS-001 API·schema·등록 정책을 변경하지 않는다. 근거는 ADR-0277과 OPS-002다.
- `.pajin/ops002-linux-live-07/report.json`: **complete=true**, Linux aarch64 / Python 3.12.13,
  실제 PostgreSQL 17.11. PG/journal 회귀 **84 passed / 69.38초**, 전체 **134.55초**다.
  migration·기존 행·경합/중복/충돌·key rotation과 verifier 재결박 거부를 실제 DB에서 확인했다.
- 별도 Linux API process와 Worker가 실제 TLS/mTLS·bearer 인증으로 통신했다. 인증서 없는 Worker,
  잘못된 서버 hostname/CA, 평문, bearer 없는 요청을 거부했다. 실제 실행 중 Worker를 중단하고
  알림·정지 보고·두 Run 봉인을 확인했다. 별도 observer는 실제 실행 container의 부재를 확인했고
  Worker `resourceCleanupVerified=false`, 외부 rollback `unknown`을 유지한다.
- 서비스 중인 API container와 PG process를 강제 종료했다. fresh Linux process에서 전체 DB 행,
  원래 verifier, Graph Snapshot/history, Run 봉인, 실제 Worker journal의 차감 1회를 대조했다.
  모든 소유 writer의 정지/PID 0·DB 연결 0을 확인한 뒤 PG dump와 local 파일 18개를 함께 암호화했다.
- 독립 pin과 키로 별도 PG container·빈 local volume에 복원했다. 원래 서비스는 정지 상태를 유지했다.
  재시작 때 차감 1회를 복원했고, 복원 때는 기존 30초 예산이 소진돼 실행 재개를 정확히 거부했다.
  저장된 지문·예산 이력과 실제 경과 시간을 독립 확인했다. 미승인 checkpoint 재개도 409로 거부했다.
  자동 Worker 시작·예산 환불·불확실한 호출 재전송은 수행하지 않았다.
- source inventory **1,513개 파일**이 실행 전후 일치했다. SHA-256은
  `91ed1c43a3ca7650444c17ae83be66412127eb8f1bcc74327d29afa1f3a9bc05`,
  암호화 checkpoint pin은 `3594fbd66133af32a0670af0816804be81e97678f34df303bcfc71ec066b3276`다.
  Linux 로그를 private evidence archive에 보존한 뒤 소유 container/volume의 부재를 관측했다.
- 이전 `.pajin/ops002-live-07`의 macOS Python + Linux PG 단독 검증 71개는 별도 기록이다.
  이번 Linux 결과로 구분하며 이전 PG dump만으로 전체 상태 복원을 주장하지 않는다.
- 초기 검증기의 volume 권한 순서/범위·Snapshot 인터페이스·종료 대기 문제를 수정했다.
  예산 소진 거부는 제품 보호 동작으로 유지했다. 실패 Run을 성공으로 덮어쓰지 않았다.
- 새 cold archive/실행기 경계 22개를 포함한 관련 회귀 125개, 전체 Ruff, 기존 strict Linux mypy
  447개와 새 script 2개가 통과했다. 새 namespace script는 별도 `--explicit-package-bases` 검사다.
- 현재 변경의 정책 결과는 Web/Network/AI 모두 필요다. `72bdbd9`의 이전 성공은 이번 추가 변경의
  원격 결과가 아니다. 새 commit·push·동일 커밋 원격 검증은 승인받아 실행할 단계다. 운영 배포는 범위 밖이다.

## GRAPH-PERF-001 완료 체크포인트

- `scripts/profile_graph_pages.py`로 100/1,000/5,000개 admission event, 각각 102/1,002/5,002 node와
  200/2,000/10,000 edge, 5개 Snapshot/6개 Projection을 실제 SQLite API로 생성했다.
  fixture는 `.pajin/graph-perf-001-fixture-v1`, 결과는 `.pajin/graph-perf-001-before.json`과 `after.json`이다.
  서로 다른 source code와 동일 DB·Snapshot 지문을 보존한다.
- Profile은 전체 이력의 반복 Projection/Pydantic 검증을 병목으로 확인했다. `graph/snapshot_cache.py`에
  페이지 전용 단일 Snapshot cache를 추가했다. 매 요청 전체 DB SHA-256을 2회 확인하고 SQLite
  read transaction 안에서 schema/integrity/current head를 검사한다. 외부 권한 결정을 캐시하지 않는다.
- 변조·inode·head·설정 변경은 재검증/거부한다. 모델은 deep copy로 내보내며 128 MiB DB / 16 MiB
  serialized Snapshot을 넘으면 전체 검증으로 돌아간다. 기존 full view·wire·reader public import는 유지한다.
- 3회 반복 평균 wall: 0.170→0.00554초, 1.994→0.0381초, 11.539→0.1864초.
  큰 fixture의 warm Python allocation peak는 372.21→31.19 MiB였다. 최초 조회는 약 11초로 남았다.
  단일 macOS arm64·warm filesystem·진단 3회 표본이며 운영 SLO나 전체 최대 크기 검증이 아니다.
- 기존/새 Graph 통합 63 passed / 8.77초. 추가 실제 raw-byte 변조·runtime limit 시험 후 cache 16 passed / 2.27초.
  Ruff 전체와 Linux strict mypy 436 files 통과. DB schema migration이나 skip 추가는 없다.
- [GRAPH-PERF-001](docs/benchmark/GRAPH-PERF-001-current-graph-page-cost.md), UX-002B와 ADR-0275에 기록했다.

## APP-002 완료 체크포인트

- Cloud/System의 실제 credential lease·인증 host agent가 준비되지 않은 상태와 현재 Docker·LLVM
  자산을 대조해 Application의 단일 offline ELF64 헤더 읽기를 선택했다. 지원 계약은
  [APP-002](docs/orchestration/APP-002-bounded-offline-elf-header-execution.md), 결정은 ADR-0276이다.
- `application_elf/`의 complete code-backed Capability·현재 signed release, exact Campaign/Scope,
  별도 operator 서명 승인과 one-use Graph Permit을 거쳐 전용 `ELFGateway`에서 실제 Docker를 실행한다.
  custody는 승인된 digest/크기의 owner-only 파일만 읽으며 최대 256 KiB를 immutable stdin으로 보낸다.
  비공개 artifact·서명키는 `.pajin/`에만 있고 Gateway 증거에는 digest/크기만 남긴다.
- `containers/application-elf/`의 고정 parser는 non-root·network-none·read-only·cap-drop·no-new-privileges와
  시간/CPU/메모리/process/output 제한을 사용한다. ELF64 little-endian x86-64/AArch64 헤더만 읽으며
  artifact 실행·동적 분석·Finding 생산은 하지 않는다. 공통 Worker/proxy 소스와 기존 APP-001은 유지했다.
- 별도로 승인된 fresh Worker 재실행과 봉인된 두 Run을 다시 읽는 제품 report CLI를 연결했다.
  CLI의 독립 trust commitment·source/replay root pin과 current/historical verifier 검증을 유지한다.
  Docker의 실제 container 부재를 Worker 보고와 별도로 관측하며 미확인 cleanup은 unknown이다.
- 최종 리뷰에서 다른 Tool 객체의 이미지·parser 교체를 재현한 4개 실패 사례를 추가하고 실제 Tool의
  전체 code-authority reference를 activation과 대조하도록 수정했다. APP 63개와 Graph view 22개를 함께
  실행해 **85 passed / 5.32초**를 확인했다. 잘못된 교체는 intent 예약·Permit 소비·Worker 전에 거부한다.
- `.pajin/app002-live-06/`의 최종 실제 검증은 **complete=true, 12 passed / 9.36초**,
  child 전체 10.03초이며 source inventory가 변하지 않았다.
  두 architecture의 clang object와 LLVM의 별도 파서로 class/machine/entry/section count를 확인했다.
  나머지 필드 전체에 대한 독립 oracle이나 일반 binary 안전성을 주장하지 않는다.
- 실제 Worker 8회: source/replay 4회, 최대 크기 1회, malformed parser 실패 3회다. 잘못된 승인·Scope는
  Permit/Worker 전에 거부했고, custody 누락·digest 변경은 Permit 소비 뒤 Worker 없이 실패했다.
  중복 실행을 거부했으며 모든 소유 execution label의 container 부재와 두 fresh-process 보고를 확인했다.
- 최종 이미지 ID는 `sha256:4c136b7287b74f9dafb321f04e39fb865970e14675dbe192d2f0fd438047fcf7`이다.
  결과·fixture·독립 trust·봉인 Run·fresh 보고·로그는 private `.pajin/app002-live-06/`에 보존했다.
  이는 POSIX custody와 Linux Docker의 opt-in 한 기능이며 기본 API/Console 활성화·일반 Application 지원은 아니다.
- 최종 wheel/sdist를 `.pajin/five-improvements-dist`에 만들고 별도 설치 환경에 CP hash lock과 wheel을
  설치했다. 39 package 정합성, 수정된 HTTPX2/HTTPcore2와 wheel 경로 import를 확인했다.
  설치 환경의 `python -I`로 두 architecture 보고를 재계산해 source-tree 결과와 일치했다.
  모든 packaged Python bytes를 현재 소스와 대조했고 private 증거·tests가 배포물에 없음을 확인했다.
  결과는 `.pajin/five-improvements-packaging.json`, 새 설치 환경은 `.pajin/five-improvements-install`이다.

## 최종 통합 검증

- 최종 소스의 `.venv/bin/python -m pytest -q`: **8,238 passed, 76 skipped / 2,270.35초**, exit 0.
  마지막 APP Tool 교체 거부 4사례와 Graph fixture의 non-None 전제 확인까지 포함한 전체 실행이다.
  76개는 기존 별도 실행 조건이며 skip을 추가하지 않았다. 8,314개 수집 항목과 집계가 일치한다.
  로그는 `.pajin/five-improvements-final-pytest.log`, 시작 소스 지문은
  `five-improvements-final-pytest-source-before.json`, 결과는 `five-improvements-final-pytest-result.json`이다.
  실행 전후 제품·테스트·script·container·example 소스 1,506개 파일이 일치한다.
  이전 8,234개 통과 기록은 마지막 보완 전 체크포인트이며 최신 결과로 대신 사용하지 않는다.
- 마지막 보완의 APP/Graph view **85 passed / 5.32초**, checkpoint/Graph cache/문서 **25 passed / 2.50초**.
  `.pajin/five-improvements-review-regression-final.log`, `five-improvements-final-checkpoint-tests.log`에 있다.
  이와 별도로 같은 최종 소스의 실제 APP Docker 12개·PostgreSQL/Worker 71개 검증을 통과했다.
  중복된 테스트 수를 합산하지 않는다. 새 커밋의 전체 CI·Ubuntu conformance도 위 별도 근거로 확인했다.
- Ruff 전체 통과, Linux strict mypy는 기존 필수 대상과 새 운영/profile script까지 **447 source files 통과**.
  Graph profile의 fixture를 재사용하면서 노출된 optional 타입은 실제 non-None assertion으로 확인했다.
  `git diff --check`와 41개 untracked 파일의 whitespace 검사도 통과했다. suppression은 추가하지 않았다.
- 평가 전 고정한 EFFECT Python 16개와 실제 APP source inventory 97개·OPS inventory 1,506개의
  현재 파일 지문이 모두 일치한다. 두 실제 실행은 소유 자원 부재를 관측했으며
  실제 DB/Docker 검증과 일반 전체 pytest 프로세스는 모두 종료됐다.
- 이번 58개 파일은 모두 이 goal의 수정·추가이며 삭제나 진행 중인 merge/rebase 등은 없다.
  각 커밋의 staged bytes를 최종 검증 지문과 대조했다. 새 승인 상태의 문서 검사 4개도 통과했다.
  앞선 여섯 commit·push·원격 검증은 완료했다. 이후 원격 결과 문서와 Linux 검증 추가분
  총 14개 파일이 미커밋이다. Linux 격리 검증은 통과했으며 새 커밋의 원격 검증은 아직 없다.

## 유지할 경계

OPS-001의 등록형 복구 API는 POSIX local SQLite다. 선정 Linux hybrid 구성은 격리된 수동 cold 복원을 검증했다. 물리 host/storage 장애·분산 fencing·자동 재활성화·운영 배포는 이 결과로 주장하지 않는다. APP-002 한 기능을 도메인 전체 지원으로 확대하지 않는다. 관측하지 않은 복구·외부 cleanup은 unknown이다.
Discovery·model output·metadata·사람 평가는 Scope·Capability·Permit·자동 Finding 권위가 아니다.

## 승인된 커밋과 원격 검증

이번 58개 변경 파일을 중복·누락 없이 아래 여섯 단위로 분리했다. 정확한 파일 목록은 private
`.pajin/five-improvements-commit-plan.json`에 있다. 2026-09-10 해당 commit·push·workflow 실행을 승인받았다.

1. `0750fee` — `fix(deps): HTTP 클라이언트 보안 하한 적용`; 의존성·lock·보안/packaging 회귀·SEC 계약 7개 파일.
2. `45b69b5` — `feat(benchmark): 미사용 평가군에서 노출 의심 탐지기 비교`; 탐지·비교 실행/reader·회귀·계약/ADR 13개 파일.
3. `7b34123` — `test(operations): 실제 PostgreSQL 장애와 독립 복원 검증`; 격리 실행기·실제 probe·fixture 교정·계약 6개 파일.
4. `3fbd480` — `perf(graph): 현재 DB 검증을 유지하며 페이지 조회 비용 감소`; cache·기존 reader·profile·회귀·계약/ADR 9개 파일.
5. `16a4013` — `feat(application): 승인된 ELF 헤더 읽기와 독립 보고 연결`; Capability/Gateway/reader·전용 image·실제/단위 검증·계약/ADR 18개 파일.
6. `72bdbd9` — `docs(project): 다섯 개선 과제의 검증과 남은 경계 정리`; 운영 상태·문서/ADR 색인 5개 파일.

승인 대상 `origin/main` 반영과 동일 커밋의 일반 CI·세 수동 workflow 확인을 완료했다.
각 `confirm_*_002d_conformance=true` 입력과 실제 run ID는 private `dispatch.json`에 보존했다.
이는 GitHub main 갱신과 CI/Docker runner 실행 승인이며 운영 배포나 DB·호스트 선정 승인이 아니다.
