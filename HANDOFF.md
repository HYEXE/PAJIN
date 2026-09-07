# PAJIN 인수인계

## 현재 목표와 체크포인트

2026-09-07 검토 후 사용자가 8개 개선 항목을 순서대로 구현하도록 요청했다.
전체 순서와 완료 기준은 `PLAN.md`의 순차 개선 목표가 권위다. 1단계 `UX-010A~C`의
기본 서버 reader 구성, 시작 진단, Network/AI Console 연결과 로컬 검증을 완료했다.
2단계의 재검증 기준과 세 도메인의 로컬 Docker 검증도 완료했다. 최신 exact-commit
Ubuntu Docker conformance는 승인된 commit/push 후 진행할 다음 작업이다.
2~8단계와 저장소 전체 CI 완료를 주장하지 않는다.

## Git 상태

- 브랜치: `main`; 기준 HEAD: `47d279b90b2c7cdedd2ea7eac9a39b872ec3132d`.
- 작업 시작 시 HEAD, upstream과 실제 원격 main은 같았고 작업 트리는 깨끗했다.
- UX-010 구현과 재검증 정책은 이 체크포인트의 두 논리적 커밋으로 보존한다.
  정확한 현재 HEAD와 staged/unstaged/untracked 상태는 아래 Git 명령으로 확인한다.
- 사용자는 검증된 변경의 commit·origin/main push·전체 CI·세 Ubuntu Docker workflow 실행을
  승인했다. 원격 결과는 아직 없으며 merge·배포는 수행하지 않았다.
- 재개 시 `git status --short --branch`, `git diff --stat`, `git diff --cached --stat`,
  `git rev-parse HEAD`로 실제 상태를 대조한다. 현재 변경을 보존한다.

## 구현된 변경

- `control_plane/measured_product_settings.py`: 경로·SHA-256 설정 쌍 검증.
- `measured_product_sources.py`, `web_measured_product_deployment.py`,
  `measured_product_deployment.py`: 엄격한 JSON recipe와 기존 증거 경로 검증,
  fixed Web/Network/AI reader 재구성과 startup source preflight.
- `control_plane/api.py`, `control_plane/__main__.py`, `entrypoints.py`: 기본 서버 연결과
  `--check-config`. 잘못된 설정은 CP DB 생성 전 거부하며 기존 positional 설정 순서는 유지한다.
- Graph·registry activation·route claim·Worker evidence의 비초기화 reopen을 추가했다.
  누락된 저장소를 생성하거나 무결성 장치를 복구해 검증을 통과시키지 않는다.
- Capability lifecycle은 공개 검증 입력만 복제한다. ZAP provider는 서명키 없는 읽기를 지원하며
  이 구성에서 stage 실행·서명을 거부한다.
- Network/AI Console은 정확한 공개 모델·합성 실험 범위와 오류·재시도·잠금 상태를 표시한다.
  공개 검증 상수는 `measured_product_web_contract.py`에서 생성한다.
- 상세 계약: `docs/orchestration/UX-010-measured-product-deployment-and-console.md`.
  채택한 근거: `docs/adr/0260-compose-measured-readers-from-pinned-deployment-inventory.md`.
- `scripts/measured_conformance.py`와 CI quality summary는 변경 경로별 필수 Docker workflow를
  제시한다. 공통 코드·의존성·미분류 경로·확인할 수 없는 baseline은 세 도메인을 모두 요구한다.
  결과는 검증 증거나 실행 승인이 아니다. `MEASURED-CONFORMANCE.md`가 재검증 기준이다.
- Web workflow에도 `GITHUB_SHA == HEAD`와 clean worktree gate를 추가했다.
  AI/Network 실제 Docker 테스트는 배포 JSON 내보내기와 새 프로세스 API 검증도 수행한다.

## 확인된 검증

- 배포 구성·서명키 없는 provider·packaging·mTLS 설정·Console·Web API·문서의 집중 회귀:
  67 passed (335.20초). AI와 Network의 JSON 복원, 새 프로세스 API 200,
  실제 backend JSON에 대한 Node validator 검사를 포함한다. Docker 조회는 test runner다.
- Graph SQLite·Capability lifecycle·기존 Docker/Hybrid provider: 51 passed, 3 opt-in skipped.
- `test_measured_product_readonly_provider.py`, `test_web_controlled_validation_route.py`,
  `test_web_controlled_validation_runtime.py`, `test_benchmark_measurement_registry_distribution.py`:
  88 passed (56.19초). 무생성 reopen·스키마 변조 거부와 기존 실행 경계를 검증했다.
- 실제 환경을 읽는 module/console `--check-config` 성공·실패·CP DB 무생성: 2 passed.
- Node Console runtime과 Chrome 1440×1000·390×844: 인증, 안내 문구, Network/AI 조회,
  503 후 재시도, 지표 펼치기, 잠금 후 결과 제거 통과. page error와 가로 넘침 없음.
  UI 측정 응답은 공개 모델 검증된 합성 fixture이며 실 Docker 증거와 구분한다.
- `PAJIN_TEST_DOCKER_WEB_002D=1 .venv/bin/python -m pytest -q tests/test_web_controlled_validation_docker.py::test_real_docker_web_002d_controlled_validation_conformance`:
  1 passed (398.33초). 현재 소스로 빌드한 로컬 이미지와 고정 ZAP image를 사용했다.
- 최종 비초기화 코드로 위 실제 Web 증거를 재검증하고 별도 프로세스 API 200을 확인했다.
  원본 파일 159개의 해시와 파일 집합이 동일했다. workflow와 같은 6개 Docker residue 조회는 모두 0건.
- `.venv/bin/ruff check src tests containers`, `.venv/bin/mypy --platform linux src`: 통과.
  전체 pytest와 현재 변경의 원격 CI는 아직 실행하지 않았다.
- 최종 CLI·mTLS 설정·문서 점검: 26 passed, 기검증한 무거운 왕복 사례 2건은 선택하지 않았다.
  `git diff --check` 통과.
- `PAJIN_AI_002D_REAL_DOCKER=1 .venv/bin/python -m pytest -q tests/test_ai_measured_product_docker.py::test_real_docker_ai_002d_exact_commit_product_conformance`:
  1 passed (80.41초). source·독립 Replay 2개·대조군 3개·새 프로세스 reader/API를 검증했다.
- `PAJIN_NETWORK_002D_REAL_DOCKER=1 .venv/bin/python -m pytest -q tests/test_network_measured_product_docker.py::test_real_docker_net_002d_exact_commit_product_conformance`:
  1 passed (393.01초). source 6개·Replay 6개·새 프로세스 reader/API를 검증했다.
- 두 실행은 현재 소스로 빌드한 로컬 고정 이미지로 수행했다. AI/Network workflow와 같은
  12개 라벨·이름 residue 조회는 모두 0건이었다.
- 재검증 selector·기존 CI 구조·Web/Network/AI workflow·문서 검사: 36 passed.
  Ruff와 Linux strict mypy는 새 selector를 포함해 통과했다 (390 source files).
- 브라우저와 임시 UI 서버는 종료했다. 검증용 로컬 이미지는 보존했다.

## 다음 첫 작업

1. 승인된 두 커밋을 origin/main에 반영하고 local HEAD·upstream·실제 원격·clean worktree를 대조한다.
2. 새 exact clean commit의 전체 CI와 세 Ubuntu Docker workflow를 실행해 결과·residue를 확인한다.
   `python scripts/measured_conformance.py --base 47d279b --head HEAD`로 변경 범위를 확인한다.
   이 체크포인트는 Web/Network/AI 모두를 요구한다. 각 원격 run의 실제 SHA와 종료 결과를 기록한다.
3. AI 실제 source·독립 Replay·세 Controls·cleanup·residue가 통과한 뒤 3단계 효과 벤치마크로 이동한다.

## 유지할 경계

- 로컬 Docker는 Linux arm64이며 Ubuntu 24.04·linux/amd64 exact clean-commit gate와 구분한다.
  과거 Web/Network 성공이나 이번 로컬 Web 성공을 최신 AI conformance로 확대하지 않는다.
- inventory는 host 신뢰 설정이며 독립 서명이 아니다. 비공개 Ground Truth·완료된 승인 문맥을
  Git·로그·HTTP·브라우저에 노출하지 않는다. 현재 키·정책 변경은 재시작이 필요하다.
- 기존 Scope → 승인 → Permit → Gateway → Worker → Evidence/Replay 경계를 유지한다.
  읽기 recipe나 공개 metadata를 실행·Finding 권위로 전환하지 않는다.
- 단일 호스트 복구·rollback 방지·긴급 중단은 5단계에 남아 있다.
