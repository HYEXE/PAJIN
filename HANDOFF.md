# PAJIN 인수인계

## 현재 체크포인트

2026-09-09 기준, 사용자 요청의 8개 순차 개선을 구현하고 해당 범위를 검증했다.
`e7c824362b8c69116db24c8b8f5e3917431eab1e`의 일반 CI와 Web/Network/AI Docker conformance가
모두 첫 시도에 통과했다. 이 문서는 그 검증 결과와 남아 있는 제품 제약을 기록한다.
완료된 구현을 반복하지 말고 재개 시 실제 Git과 아래 검증 커밋을 대조한다.

## Git과 승인 범위

- 브랜치는 `main`이다. 제품·테스트·CI 변경의 마지막 커밋은
  `9b93929e6ed8d7c1d39f248fcb160dfced44aa59`다. 현재 체크포인트는 이 코드와 운영 문서로 구성된다.
  제품 검증 체크포인트는 `e7c8243`이며, 원격 검증 당시 local HEAD·upstream·실제 원격 SHA가
  일치하고 작업 트리는 깨끗했다. 후속 문서 커밋을 포함한 실제 HEAD·upstream·원격 main은
  `git rev-parse HEAD '@{upstream}'`와
  `git ls-remote --heads origin main`으로 재확인한다.
- 최초 검토 기준은 `47d279b90b2c7cdedd2ea7eac9a39b872ec3132d`다. 승인된 1·2단계만
  `a60395b`(reader·Console), `3b9aaa0`(재검증 정책)로 commit·push했다.
- 3~7단계 코드·테스트·계약·ADR-0261~0273·CI duration profile을 아래 일곱 커밋으로 보존했다.
  운영 문서 체크포인트 `e7c8243`까지 여덟 커밋을 승인받아 push했고 동일 커밋을 원격 검증했다.
  merge·배포·이력 수정은 수행하지 않았다.
- 사용자가 3~8단계 변경의 commit·push와 동일 커밋의 일반 CI·Web/Network/AI Docker 검증을
  명시적으로 승인했다. merge·배포·이력 수정은 이 승인 범위에 포함하지 않는다.

## 구현 범위와 주요 위치

| 단계 | 현재 동작 | 코드·계약 |
| --- | --- | --- |
| 1~2 | 기본 서버의 pinned reader·시작 진단·Network/AI Console, 변경별 conformance 요구 | `control_plane/measured_product_settings.py`, `scripts/measured_conformance.py`, UX-010·MEASURED-CONFORMANCE |
| 3 | 실제 로컬 LLM의 분리된 평가군·독립 canary 정답·지표·정책 경유 실행·봉인 reader | `benchmark/effectiveness/`, EFFECT-001·ADR-0261 |
| 4 | 공개 근거 → 사람 평가 → 별도 승인 → 재검증 연결·재승인 → Markdown 보고 | `control_plane/measured_reviews/`, `control_plane/web/measured-reviews.js`, CP v15·UX-011·ADR-0262 |
| 5 | 키 연속성·보수적 예산·첫 사용 inventory·활동 배제·암호화 복구·긴급 취소/관측/알림 | `runtime/host_*.py`, `runtime/inventory*.py`, `control_plane/run_budgets.py`, `control_plane/urgent_stop*.py`, CP v16·OPS-001·ADR-0263~0270 |
| 6 | Snapshot cursor Graph 페이지·Console와 4 MiB Supervisor 입력 분할/검증·큰 Provider 전송 | `control_plane/graph_pages.py`, `supervision/input_transport.py`, Worker/proxy·UX-002B·SUP-004A·ADR-0271/0272 |
| 7 | private code-owned taxonomy/Graph template 캐시·분리된 반환값, 실측 시간 배치·기록 | `domain/security_domain.py`, `graph/domain_semantics.py`, `scripts/ci_sharding.py`, `.github/test-durations.json`, ADR-0273 |
| 8 | 현재 로드맵·제약·인수인계를 계약 링크로 정리, 설치 조건·인증 목록·CI 명령 정합성 보완 | 루트 상태 문서·README·CI·Pydantic 최소 2.12 조건, 잠금 버전 자체는 유지 |

현재 코드의 커밋은 EFFECT-001 `b68d6bb`, UX-011 `644825b`, OPS-001 `bdfe3f6`,
Graph 페이지 `5041e7c`, Supervisor 입력 `2114d7b`, metadata 캐시 `9622b38`, CI 배치 `9b93929`다.

위 코드 경로는 별도 표시가 없으면 `src/pajin/` 기준이다. 상세 경계는
[문서 색인](docs/README.md)과 [결정 색인](DECISIONS.md)에서 찾는다.

## 현재 변경의 로컬 검증

- 커밋 직전 각 인덱스 트리를 별도 디렉터리로 꺼내 필요한 범위만 포함한 상태를 검증했다.
  EFFECT-001 27개, UX-011 266개와 packaging 재검증 17개, OPS-001 301개와 영향 모듈 재검증 64개,
  Graph 29개, 입력 전송 269개, metadata 164개, CI 31개가 통과했다. 중복 사례를 합산하지 않는다.
  packaging의 초기 실패는 검증 도구가 주입한 PYTHONPATH 상속 때문이었으며 환경만 수정했다.
  복구 후보에 섞였던 입력 전송 변경은 해당 입력 전송 커밋으로 분리하고 관련 실패를 재검증했다.
  각 인덱스의 Ruff·Linux strict mypy도 통과했다. 최종 src와 두 CI script는 428 source files 통과다.
  기록은 `.pajin/commit-review/`의 `*-candidate-*.log`에 보존한다.
- 전체 수집 8,170개를 네 hash shard로 실행했다. 초기 결과는 8,083 passed, 76 opt-in skipped,
  9 failed, 2 setup errors다. 최장 shard는 1,061.76초였다. 로그는 `.pajin/step7-full-0.log`부터
  `step7-full-3.log`, 원래 duration profile도 같은 basename의 `.json`으로 보존했다.
- 실패 11건 중 하나는 새 POST 경로 7개의 기존 인증 목록 누락이었다. exact 목록을 추가했으며
  모든 경로의 HTTPBearer 요구 검사는 유지했다. 하나는 sandbox의 임시 TLS bind 제한이었다.
  나머지는 실제 UTC 기준의 짧은 권한·예산 창이 만료되어 거부된 사례였다.
- 포트 바인딩을 허용하고 관련 여덟 모듈을 한 pytest 프로세스로 실행해 **71 passed, 2 opt-in skipped**
  (185.27초)를 확인했다. 원래 실패·오류 11개 node ID가 이 성공한 재검증에 모두 포함된다.
  TTL·예산 검사나 assertion을 약화하지 않았다. 재검증 로그는 `.pajin/step8-regression.log`다.
- duration reader가 긴 adversarial parameter ID를 거부하던 오류를 수정하고 왕복 회귀를 추가했다.
  두 기존 입력 거부 테스트에는 짧은 사례 ID를 부여했으며 입력·검사는 유지했다.
  **43 passed** (2.91초), `.pajin/step8-duration-fix.log`. 현재 전체 수집은 **8,171개**다.
- 성공한 재검증과 추가 테스트를 합치면 현재 사례의 검증 범위는 8,095 passed와 76 opt-in skipped에
  대응한다. 이것을 하나의 새 전체 pytest 명령이 처음부터 모두 통과했다고 표현하지 않는다.
- 변경 전후 metadata canonical bytes 동일성과 강제 nested mutation 격리·외부 변조 거부를 검증했다.
  같은 Forensics Replay 사례의 기록된 이전 cProfile 592.67초에 대해 현재는 **43.17초**다.
  digest 호출은 41,234,564회에서 28회로 줄었다. 새 로그와 profile은
  `.pajin/forensics-final-profile.log`, `.pajin/forensics-final.prof`다. CI 속도 개선 수치는 아니다.
- 초기 full profile과 명시적 후속 측정에서 현재 node ID만 선택해 `.github/test-durations.json`을 만들었다.
  원래 실패 상태를 포함한 source provenance를 보존한다. 8,171개가 24 shard에 중복·누락 없이 배정된다.
  실제 pytest의 shard 0 수집도 예상 335개와 일치했다. `.pajin/step8-shard-verification.json` 참조.
  같은 로컬 측정으로 계산한 최대 shard는 hash 289.638초, 실측 배치 161.655초다.
  공유 fixture 재생성·runner 차이를 포함한 실제 CI 완료 시간 예측으로 사용하지 않는다.
- `.venv/bin/ruff check --output-format concise src tests containers scripts` 통과.
  `.venv/bin/mypy --platform linux src scripts/measured_conformance.py scripts/ci_sharding.py`도
  428 source files 통과했다(`.pajin/step8-mypy.log`). 문서·CI·인증 목록 최종 점검은
  **32 passed** (10.13초, `.pajin/step8-final-focused.log`), `git diff --check`도 통과했다.
- packaging의 wheel·sdist·깨끗한 설치, API/권한, Node Console 회귀는 전체 실행에 포함됐다.
  5단계 관련 회귀 418개, 6단계 관련 회귀 517개와 실제 HTTPS 전송·불신 인증서 거부 2개도 통과했다.
  `.pajin/recovery-enrollment-regression.log`, `.pajin/step6-regression.log`,
  `.pajin/supervisor-input-live.log`에서 해당 범위를 확인한다.
- 실제 API-backed 사람 검토·재승인·보고서, 긴급 알림과 Graph Console을 브라우저로 확인했다.
  Graph는 실제 SQLite 504 node·6페이지, 데스크톱/모바일·키보드·잠금·오류 흐름을 검증했다.
  임시 브라우저·서버·Worker 프로세스는 검증 종료 때 정리했다.

## 실제 모델 평가의 보존 상태

EFFECT-001의 24개 실행·384개 응답은 두 실제 모델·두 정책·두 temperature·세 seed의
고정 진단 평가군이다. TP/TN/FP/FN은 28/166/100/90이며 일반 모델 안전성으로 일반화하지 않는다.
수치·반복 편차·시간·비용 범위는 [EFFECT-001](docs/benchmark/EFFECT-001-local-llm-effectiveness.md)이 권위다.

- 계획 참조 `.pajin/effectiveness-v1-plan.json`, 결과 참조 `.pajin/effectiveness-v1-result.json`.
- private Run root `.pajin/effectiveness`, 원래 공개 집계 `.pajin/effectiveness-v1-public.json`.
- terminal Run `run_20260907T082018Z_872bdd7c`, root
  `6eb7aff77b50dc3a28aa68d8ba95f0684cd65b4e91b6e356964befe8b0d2cd21`.
- 평가 당시 소스 9개는 `.pajin/effectiveness-v1-frozen-source/`에 보존했다.
- 현재 코드의 새 프로세스 report 재검증도 통과했다. `.pajin/effectiveness-step8-public.json`은
  원래 공개 집계와 byte-identical이다. 원문·canary·모델 파일은 commit 대상이 아니다.

## 동일 커밋의 원격 검증

다음은 모두 `e7c824362b8c69116db24c8b8f5e3917431eab1e`, attempt 1의 성공 결과다.

| 검증 | 확인한 결과 |
| --- | --- |
| [CI 34299070623](https://github.com/HYEXE/PAJIN/actions/runs/34299070623) | Quality·24 shard 모두 성공. 8,095 passed·76 opt-in skipped |
| [Web 34299157203](https://github.com/HYEXE/PAJIN/actions/runs/34299157203) | source·Replay·Controls·fresh reader·exact clean commit·zero residue, 1 passed / 132.16초 |
| [Network 34299158701](https://github.com/HYEXE/PAJIN/actions/runs/34299158701) | 6 source·6 Replay·fresh reader·exact clean commit·zero residue, 1 passed / 335.00초 |
| [AI 34299160492](https://github.com/HYEXE/PAJIN/actions/runs/34299160492) | source·2 Replay·3 Controls·fresh reader·exact clean commit·zero residue, 1 passed / 86.56초 |

- CI의 첫 job 시작부터 마지막 job 종료까지 477초(7분 57초)였다. shard job은 249~477초,
  pytest 자체는 233.80~460.73초였다. 단일 실행의 관측이며 다른 커밋과의 통제된 A/B 결과나 SLA가 아니다.
- 시간 artifact 24개를 실제로 내려받아 source SHA·clean tree·exit 0·selected/reported 수를 확인했다.
  8,171개가 checked-in profile의 현재 node ID와 정확히 일치하며 중복·누락은 없다.
- 세 Docker job은 Ubuntu 24.04의 `linux/amd64` 이미지로 실행했다. 각 workflow의
  `Record exact image identities`에서 Web 5개·Network 3개·AI 3개의 실제 ID를 확인했다.
  Web의 ZAP RepoDigest도 등록된 `71db37cd5b75663b35758d10aaec05bf6fbac23f5020e3046c70e628a5f84efa`와 일치한다.
  각 clean-commit·실제 conformance·unconditional residue step이 모두 성공했다.
- 로그와 집계는 `.pajin/remote-verification/`에 보존했다. `ci-tests.json`, `docker-evidence.json`,
  `artifact-verification.json`과 원격 run URL로 확인한다. 임시 인덱스 검증용 소스 복사본은 정리했다.

## 재개 시 첫 확인과 후속 작업

1. 현재 HEAD·upstream·원격 main·작업 트리를 확인하고 현재 HEAD의 일반 CI를 조회한다.
   `e7c8243` 이후 변경이 운영 Markdown뿐이면 [MEASURED-CONFORMANCE](docs/orchestration/MEASURED-CONFORMANCE.md)에
   따라 추가 Docker 실행은 선택되지 않는다. 제품·테스트·설정이 바뀌면 해당 새 커밋을 재검증한다.
2. `KNOWN_ISSUES.md`의 현재 의존성 경고를 먼저 검토한다. 기존 lockfile의 httpx2/httpcore2 2.7.0에
   해당하는 Dependabot 경고 6건을 확인했으며 이번 순차 개선에는 의존성 교체를 추가하지 않았다.
3. 실제 detector 개선에는 새 미사용 평가군이 필요하다. live PostgreSQL·자동 배포 이전·분산 fence와
   미구현 domain provider는 별도 범위이며 이번 검증으로 완료되었다고 계산하지 않는다.

## 유지할 경계

사람 검토·benchmark·Domain metadata·model output은 Scope·Capability·Permit을 만들지 않는다.
OPS-001 복원은 독립 expected checkpoint를 요구하며 자동 실행 재개가 아니다. Worker 중단 보고는
외부 자원 cleanup·side effect rollback의 증거가 아니다. 큰 입력은 matching host/Worker/proxy가
필요하며 외부 모델의 context 수용을 보장하지 않는다. 알려진 한계는 `KNOWN_ISSUES.md`에 남긴다.
