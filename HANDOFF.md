# PAJIN 인수인계

## 현재 체크포인트 (2026-09-11)

승인된 8개 추가 커밋·2회 일반 push와 동일 SHA의 여섯 원격 검증을 실행했다.
`27127bd`의 일반 CI/Web/Network/AI/SYS는 첫 시도에 통과했고 OPS는 실제 probe 단계에서 실패했다.
기존 goal은 완료 상태를 유지한다. 이번 goal의 남은 단계는 로컬 검증을 마친 OPS fixture 보정의
승인된 추가 1 commit·1 push와 새 SHA 원격 재검증이다. 실패를 성공으로 처리하지 않는다.

1. **문서 상태 수정:** SYS-002/OPS-003/GRAPH-PERF-002의 로컬·기존 원격 검증 범위를 바로잡았다.
   최초 검토한 6개 문서의 bytes·patch·manifest는 `.pajin/followup-next-five-20260911/step1-docs/`에
   보존했다. 원래 검토 bytes로 문서 `bbcb72f`를 만들고 기존 `a599818`과 함께 일반 push했다.
   CI 34563781824의 Quality·24 shard, 8,342 passed·76 skipped와 정확한 clean SHA를 확인했다.
2. **EFFECT-004:** Worker의 제한된 실패 분류와 보수적 차감 회귀 164개, 새 평가 관련 회귀 108개를
   통과했다. 기존 EFFECT-003 실패 2건의 세부 원인은 여전히 미확인이다. 새 과제 18개 중 smoke 2개,
   평가 16개를 분리하고 24좌표·384회·495개 소스 pin을 실행 전에 동결했다. 실제 smoke 4회 및
   본 평가 384응답/0실패/0미채점이 완료됐다. baseline TP/TN/FP/FN은 130/197/51/6, 후보는
   136/197/51/0이다. 정밀도 71.82→72.73%, 재현율 95.59→100%, F1 82.02→84.21%로 고정 기준을
   충족했다. 오탐 51개와 generation 오탐 47개는 줄지 않았다. 기본 v1을 유지하고 후보는 별도로 보존한다.
   동결 소스로 만든 별도 설치 wheel의 495개 pin과 fresh-process 재계산이 일치했고, 별도 Docker
   관찰에서 smoke 포함 정확한 414개 selector의 container/network 부재를 확인했다.
3. **GRAPH-PERF-003:** 할당 진단으로 동시 과거 Snapshot 보관 비용을 확인했다. 모든 이력·체인·
   Projection 검증을 유지하면서 행을 순차 처리하고 현재 조회 대상만 보관하도록 수정했다.
   관련 Graph 회귀 57개와 독립 객체 검사를 통과했다. 같은 프로토콜의 전후 각 24개 프로세스 측정을
   완료했다. 큰 이력의 단일 reader 평균 peak RSS는 1,424.56→769.73 MiB, 독립 reader 두 개는
   1,928.19→1,278.38 MiB다. 단일 reader 변경 직후 최초 조회는 10.9536→11.1738초로 악화됐다.
   GC 후 보관량은 약 35.48 MiB로 같고 모든 측정은 실험 기준인 4 GiB 이내였다. 운영 SLO는 아니다.
4. **OPS/SYS CI:** 별도 수동 workflow, 정확한 commit·이미지·clean tree 확인, CI 전용 실행/정리/독립
   자원 검사 및 선택 규칙을 구현했다. 기존 Web/Network/AI 요구는 유지한다. CI 관련 회귀 55개를 통과했다.
   최종 제품 소스의 Linux arm64 OPS 11개 확인, SYS 실제 1 passed/39.17초·Worker 4회와 독립 cleanup이
   통과했다. OPS 최종 소요 시간은 114.33초다. 최종 source-before/after 1,552개 파일은 실행 중
   일치했다. 별도 최종 Docker 관찰은 8개 소유 selector의 container/network/volume 부재를 확인했다.
   원격 SYS는 실제 1개·Worker 4회와 cleanup이 통과했다. OPS 실패와 보정은 아래에 구분한다.
5. **SYS-003 조회:** 배포자 pin·Operator subject·Campaign 제한을 유지하는 API/Console을 구현했다.
   실제 봉인 결과와 독립 reader 비교, 새 API 8개, 배포 호환성 포함 회귀 24개, JS 회귀를 통과했다.
   실제 HTTP Chromium으로 정상·빈 결과·미구성·역할/Campaign 거부·변조·잠금, 키보드 및
   1440x1000/390x844 화면을 확인했고 서버는 종료했다. 패키징의 새 JS 누락을 고쳤으며 18개 검사와
   별도 설치한 최종 wheel의 Python/화면 파일 483개 일치, 자산/API HTTP 200, 독립 결과 일치를 확인했다.
   System 미구성 배포 JSON에는 새 필드를 쓰지 않아 기존 reader용 형식을 보존한다.

## Git 및 원격 검증

- branch `main`, HEAD·upstream·실제 origin/main은 `27127bd1872c56c98a0ffc93cabaa834cfcc0259`다.
  기존 `a599818`을 보존했고 승인된 추가 8개 커밋과 두 번의 일반 push를 완료했다.
- [문서 CI 34563781824](https://github.com/HYEXE/PAJIN/actions/runs/34563781824)는 `bbcb72f`에서
  Quality·24 shard, 8,342 passed·76 skipped가 통과했다. 24개 artifact의 clean SHA와
  중복·누락 없는 8,418개 테스트를 확인했다.
- 제품 `27127bd`의 모든 run은 첫 시도다. [CI 34565353026](https://github.com/HYEXE/PAJIN/actions/runs/34565353026)는
  Quality·24 shard, 8,426 passed·76 skipped다. 24개 artifact가 같은 clean SHA·exit 0이며
  8,502개 테스트가 로컬 collection과 같고 기존 8,418개를 모두 보존했다. Ruff·Linux mypy 475/10개도 통과했다.
- [Web 34565392600](https://github.com/HYEXE/PAJIN/actions/runs/34565392600): 1 passed/133.81초.
  [Network 34565395467](https://github.com/HYEXE/PAJIN/actions/runs/34565395467): 1 passed/202.33초.
  [AI 34565397658](https://github.com/HYEXE/PAJIN/actions/runs/34565397658): 1 passed/87.50초.
  모두 정확한 commit·이미지·실제 검사·무조건 잔여 자원 검사를 통과했다.
- [SYS 34565402103](https://github.com/HYEXE/PAJIN/actions/runs/34565402103): 실제 1 passed·Worker 4회,
  외부 실행기 47.01초. clean source·Linux amd64 이미지와 cleanup·독립 잔여 부재를 확인했다.
- [OPS 34565400116](https://github.com/HYEXE/PAJIN/actions/runs/34565400116): 실제 probe 7.18초 뒤 exit 1.
  cleanup과 독립 관찰은 zero residue로 성공했다. 공개 진단에 세부 단계가 없어 정확한 내부 실패 원인은
  확정할 수 없다. 네 다른 conformance 성공은 이 OPS 실패를 대신하지 않는다.
- 새 branch/worktree/subagent·이력 수정·배포는 없다. 보정은 미커밋이며 추가 1 commit·1 push와 새 SHA의
  일반 CI 및 다섯 전용 검증을 승인받았다.

## OPS fixture 보정 체크포인트

- 별도 격리 Linux 재현에서 root+CHOWN의 타 UID 0600 파일 읽기 실패와 잘못된 socket group 거부를 확인했다.
  fixture의 TLS/HBA 세 파일은 stdin archive로 전달하고 trusted controller는 daemon 쪽 소켓 GID를 관찰한다.
  파일·호스트 소켓 권한이나 target Worker 권한을 넓히지 않는다. 실패 공개 요약에는 allowlist phase/count만 추가한다.
- 변경은 `scripts/operational_postgres.py`, `operational_linux.py`, `hybrid_operations_rehearsal.py`,
  `linux_boundary_conformance.py`와 관련 테스트 3개, 상태·계약 문서다. 제품 `src/`는 바뀌지 않았다.
- 집중 66 passed, Ruff 전체, 관련 script Linux strict mypy 4개가 통과했다. 신규 15개로 전체 collection은
  8,517개다. 보정 후 전체 pytest와 새 원격 CI는 아직 실행하지 않았다.
- 보정한 새 Linux arm64 이미지의 실제 OPS 11개 검사가 72.97초에 통과했다. source inventory는 유지됐고
  별도 read-only observer가 네 ownership selector의 container/network/volume 부재를 확인했다.
- 보정 후 SYS probe 자체는 변경되지 않아 로컬 재실행하지 않았다. 새 commit에서는 정책대로 여섯 원격 검증을
  다시 수행한다. 기존 소비된 모델 평가·완료된 Graph 비교·HTTP UI 검증은 제품 소스가 같으므로 반복하지 않는다.

## 최종 로컬 검증

- 기존 원격 collection 8,418개가 모두 유지됐고 신규 84개를 포함해 현재 8,502개를 수집했다.
- Graph 변경 전에 시작한 중간 전체 pytest는 최종 소스 검증을 대신하지 못해 6,218 passed/69 skipped에서
  SIGINT로 종료했다. 종료 시 CI 타입 검사 문자열 기대값 불일치 1개가 확인됐다. 기존 명령과 새 10개
  스크립트 명령을 모두 검사하도록 수정했고 관련 CI 회귀 55개가 통과했다. 실패/중단 로그는 보존한다.
- 최종 전체 4 shard는 8,426 passed·기존 76 skipped, 모두 exit 0이다. duration artifact의
  중복·누락 없는 합집합은 8,502개이며 검사 중 비문서 소스 939개가 바뀌지 않았다. 최대 shard
  소요 시간은 937.46초다. 이는 dirty working source의 로컬 결과이며 clean commit 원격 CI가 아니다.
- 최종 Ruff 전체, Linux strict mypy 475개 및 `--explicit-package-bases`의 운영/CI/profile/agent
  스크립트 10개, 문서 검사 4개와 `git diff --check`가 통과했다. 새 skip/xfail 표시는 없고
  기존 assertion을 약화하지 않았다. 실행한 모델/Graph/회귀 프로세스는 종료했고 HTTP QA의
  네 포트에 listener가 없음을 별도로 확인했다.

## 비공개 재개 근거

모든 아래 경로는 저장소 기준이며 다른 환경에서 실제 가용성을 확인한다. 원문·canary·키·모델·
Run 원문·private inventory를 commit하거나 공개 artifact로 내보내지 않는다.

- 공통: `.pajin/followup-next-five-20260911/`
- 평가: `.pajin/effectiveness-v4-{plan,result,public}.json`, `.pajin/effectiveness-v4/`,
  `.pajin/effectiveness-v4-frozen-source/`, 공통 경로의 `effect004-packaging/`, `effect004-independent-cleanup.json`.
  평가군은 소비됐다. 결과 조회는 frozen source/설치 wheel로만 하고 모델 실행을 중복하지 않는다.
- Graph: `graph-protocol.json`, 원래 `graph-baseline-source/`와 inventory, `graph-comparison/`의
  before/after source 및 inventory. 독립 배포 호환성 수정은 양쪽에 동일하게 넣었고 실제 다른 파일은
  `pajin/graph/sqlite_store.py` 하나다. baseline Graph bytes는 최초 동결본에서 가져왔다.
  `graph-before.json`, `graph-after.json` 및 `graph-summary.json`에 모든 샘플과 전후 결과를 보존했다.
- Linux: `ops003-final/`, `sys002-final/`, `final-linux-images.json`, `final-linux-source-{before,after}.json`,
  `final-linux-independent-cleanup.json`.
- 최종 회귀: `final-regression/summary.json`과 네 개 duration/로그, `final-ruff.log`,
  `final-mypy-main.log`, `final-mypy-scripts.log`, `final-sensitive-content-review.json`.
- 커밋 분리 검증: `commit-checks/`의 01~07 집중 결과. 루프백 소켓 제한은 허용된 환경에서
  재검증했고 독립 설치에 상속된 PYTHONPATH는 제거한 뒤 패키징 17개가 통과했다. 제품 수정은 없었다.
- OPS 보정: `linux-permission-reproduction.json`, `ops003-portability/`, `ops003-portability-summary.json`,
  `portability-independent-cleanup.json`, `portability-source-{before,after}.json`.
- 원격 제품 검증: `remote/27127bd1872c56c98a0ffc93cabaa834cfcc0259/`의 전체 run/jobs/logs,
  CI duration, SYS/OPS bounded summaries와 `verified-conformance-initial.json`.
- 원격 문서 검증: `remote/bbcb72f/`의 run/jobs/artifact와 전체 로그, 24개 duration 및 검증 요약.
- 패키지: `final-packaging-v2/`의 inventory와 `installed-smoke.json`; 수정 전 패키징 결과는 별도로 보존했다.
- 브라우저: `sys003-ui/`의 private 설정과 독립 결과, `sys003-browser-final.log`. 브라우저 도구의
  화면/실행 파일은 저장소 밖 임시 자료이므로 다른 환경에서는 다시 관찰해야 한다.

## 다음 한 단계

로컬 검증을 마친 fixture 보정과 실제 원격 결과의 문서 diff를 추가 논리 커밋 1개로 보존하고
origin/main 일반 push 1회, 새 SHA의 일반 CI 및 Web/Network/AI/OPS/SYS를 실행한다. 이 범위는 승인받았다.
이전 승인된 8개 커밋·두 push는 모두 사용했고 추가 수정은 아직 staging하지 않았다.
같은 새 SHA에서 모든 시도의 필수 job·실제 검사·cleanup을 확인하고 결과 문서를 갱신한다.
소비된 모델 평가나 완료된 Graph 비교는 다시 실행하지 않는다.
