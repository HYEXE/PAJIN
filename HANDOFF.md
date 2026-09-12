# PAJIN 현재 인수인계

체크포인트: 2026-09-12. 직전 다섯 slice의 로컬 구현·통합 검증을 바탕으로 새 네 후속 항목을 시작했다.
기존 완료분과 OPS 실행 순서 보완을 push했다. 다섯 원격 실증이 통과했고 Replay 시작 경계의 CI 회귀를 보완했다.

## 목표와 승인 범위

`PLAN.md`의 완료분 원격 검증, EFFECT-007, GRAPH-PERF-006, UX-014를 순서대로 수행한다.
기존 완료분의 commit/push·일반 CI와 다섯 실증 workflow 실행은 사용자가 승인했다.
별도 물리 Linux host는 아직 없다는 선택을 유지한다. 운영 배포·merge·tag는 승인되지 않았다.
main에서 작업하며 branch/worktree/subagent는 없다.

## Git과 기준

- 시작 main·upstream·실제 원격은 `b2fe5cb2413cf3c4aa25e50e58ecd4e641aebee7`이고 worktree는 clean이었다.
- 기준 SHA의 CI 34670400044 첫 시도 성공은 확인했다. 이전 코드의 8,566 passed·76 skipped와
  Web/Network/AI/OPS/SYS 검증은 이번 미커밋 변경의 결과로 사용하지 않는다.
- 구현·테스트·계약은 다섯 로컬 커밋 `22b0e6f`, `7555b31`, `0769472`, `045eb46`, `9d4a325`로 보존했다.
  문서 커밋을 포함한 `dd039ef3c261224f529d07f431dab2cbf7f8cbc9`를 push했다. 배포는 없다.
  기준·원본 실패·최종 결과는 아래 private 디렉터리에 보존한다.

## 구현과 확인된 결과

| Slice | 현재 결과 | 남는 한계 |
| --- | --- | --- |
| EFFECT-006 | v5 후보·동결 평가·독립 재계산 구현. 새 실제 모델 384응답/0실패. v4/v5 모두 FP 62/FN 0, 정밀도 68.37%·재현율 100%. 평균 CPU 29.73→27.52μs, 중앙값 20.72→22.52μs | 품질 개선 기준 실패, 기본 v1 유지. 개별 판정도 차이 0이며 오탐 감소는 미완료 |
| GRAPH-PERF-005 | 전체 검증을 유지하며 중복 직렬화/재검증 제거. Linux 전후 24그룹씩. 큰 이력 cold 최초 단일 9.8673→7.9494초, 두 reader 10.9121→8.7437초 | RSS 약 556 MiB로 거의 같고 반복 조회는 혼재. 물리 cold disk·동시 aggregate RSS·운영 SLO 미측정 |
| OPS-005 | 독립 서명 witness·v2 enrollment·witness-first fsync·한쪽 rollback 거부·원본 보존 재구성. 최신 이미지에서 21개 검사·실제 SIGKILL·32회 새 process 검증, 기존 OPS-003 11개 모두 통과 | 중간 timeout 기록을 보존. 두 store 동시 rollback·물리 host·power loss·운영 failover는 미검증 |
| UX-012 | 최대 100개 등록 Campaign과 검증된 과거 Snapshot의 별도 API·Console. 집중 12개와 실제 브라우저 사용 경로 확인 | local DB 등록·redacted 역사 조회에 한정. 과거 결과의 실행/현재 승인 권위 없음 |
| UX-013 | v2 배정 이력·개인별 내부 알림·확인, 기존 판단/증거/승인 보존. 집중 14개와 실제 배정→수신→확인 브라우저 흐름 통과 | v2 쓰기 전에 모든 reader/복구 도구 갱신. 200회 이력이 차거나 Auditor인 수신자는 읽기만 가능 |

### 실제 모델·성능 근거

- EFFECT-006 plan commitment:
  `5870ee523e5c980710919aed3f932511609fc2172ba044ed22b19888ec389393`.
  이전 72개 prompt를 제외한 18개 과제(개발 2·미사용 16), 24좌표의 단 한 번 평가다.
- `.pajin/effectiveness-v6-frozen-source/`의 510개 입력 파일을 보존했다. 별도 wheel 설치에서
  521개 source pin·봉인 report 전체 일치·개별 판정 차이 0을 확인했다. 26개 모델 생명주기와
  414개 owner/execution selector의 독립 cleanup 관찰도 통과했다.
- `.pajin/effectiveness-v6-public.json`과
  [EFFECT-006](docs/benchmark/EFFECT-006-public-text-transforms-and-disclosure.md)에 실제 결과를 기록했다.
  이 평가군은 소비됐고 재호출·retune·새 검증군으로의 재사용은 금지한다.
- Graph는 같은 Linux arm64 image·2 CPU/4 GiB·두 DB·1/2개 process·guest cold/warm 조건이다.
  510개 source 중 Graph 세 파일만 전후 차이가 있고 현재 Graph bytes도 after와 일치한다.
  전체 16개 요약 행과 한계는 [GRAPH-PERF-005](docs/benchmark/GRAPH-PERF-005-canonical-serialization-cost.md)에 있다.
  모델 평가와 시간 측정을 겹치지 않았다. 두 소유 container의 부재를 별도로 확인했다.

### 사용성과 호환성

- 실제 로컬 API와 두 SQLite Campaign fixture에서 등록 조회·Campaign 전환·과거 Snapshot 선택·
  키보드 실행·오프라인 실패 뒤 명시적 재조회 성공을 확인했다. 390 × 844에서 가로 넘침이 없었다.
- Operator 배정 후 새 revision, Approver 로그인 후 개인 알림과 확인 기록을 실제 브라우저에서 확인했다.
  확인 뒤 inbox status로 포커스가 이동했다. Auditor/용량 경계는 API·JS 회귀로 검증했다.
- Auditor 수신자의 잘못된 DB 쓰기와 마지막 200번째 배정 조회 실패를 먼저 재현했다.
  현재 역할을 쓰기 전에 검사하고 마지막 배정은 읽되 추가 확인을 거부하도록 수정했다.
  SQL schema를 바꾸거나 오래된 v1 bytes를 수정하지 않았다.
- 임시 browser와 API server는 종료했다. 원문 fixture·화면·console 기록은 private으로 보존한다.
  실제 screen reader·외부 알림·운영 배포는 검증하지 않았다.

## 검증 상태와 다음 작업

- 전체 8,747개 ID를 기존 CI shard 옵션으로 네 process에서 중복/누락 없이 실행했다.
  첫 결과는 **8,669 passed·76 skipped·2 failed**다. 실행 중 987개 source inventory는 같았다.
  새 배정/확인 API와 복구 script를 기존 명시적 인증/CI 목록에 등록하지 않은 두 실패였다.
- 두 목록을 정확히 보완하고 보고서의 배정/평가 제목 순서, 복구 probe의 총 예산을 수정했다.
  전체 회귀 이후 비문서 변경은 이 네 파일뿐이며 983개 source는 그대로다.
  `test_control_plane_phase9_exit`, `test_main_ci_sharding`, `test_measured_reviews`,
  `test_measured_review_api`, `test_review_assignments`, `test_linux_boundary_conformance`,
  `test_checkpoint_witness`의 **121개가 모두 통과**했다. 처음 실패한 두 ID도 포함한다.
- 전체+집중 재검증의 최종 고유 결과는 **8,671 passed·기존 76 skipped·미해결 실패 0**이다.
  skip 사유/수를 이전 기준과 정규화 비교해 일치를 확인했다. 전체를 두 번째 실행하거나
  최초 전체 실행이 성공한 것으로 바꾸어 기록하지 않는다.
- 마지막 네 파일 수정 뒤 Ruff 전체와 Linux strict mypy의 500개 source·14개 script·2개 ASLR
  source 검사를 다시 통과했다. 새 product wheel의 모듈/Console asset과 설치된 510개 source도 일치한다.
- OPS-005에서 관측한 180초 timeout 보고서와 소유 자원 부재를 보존한다. 실제 첫 성공 probe도
  약 117초였다. 하위 35개 process 각각의 30초 제한은 유지하고 전체 한도만 1,200초로 맞췄다.
  전체 회귀와 겹치지 않은 최종 OPS-005는 184.27초에 21개 검사·32회 새 process 검증을 통과했고
  기존 OPS-003은 73.15초에 11개 검사를 통과했다. 두 실행 모두 원래 기준·예산/승인 거부를 유지했다.
- 최종 runtime image는 `sha256:bfc1dea247ab1e32f305d198d3b43bb3b758205f8c22db85e76cc89bda0aad97`,
  현재 Python 구현 digest는 `999acc112588cc140c7507025cd9cb4504712add82df27f2bd6d63af40057103`이다.
  이미지 안의 구현·probe·rehearsal bytes, 두 보고서의 code pin과 전체 source inventory를 대조했다.
- 최종 read-only 관찰에서 OPS 소유 container/network/volume, source 확인 container와 Graph 측정
  container가 모두 없었다. 임시 API listener도 없다. 증거·fixture·검증 이미지는 재현용으로 보존했다.
- 문서 검사 4개와 `git diff --check`를 통과했다. 기존 소스를 commit/push했고 아래 원격 결과를 확인했다. 배포는 없다.

### 검증 명령

- `.venv/bin/python -m pytest tests --ci-shard-index N --ci-shard-total 4 --ci-shard-durations .github/test-durations.json`
  (`N`은 0~3): 전체 ID 8,747개와 최초 결과를 위에 기록했다.
- `.venv/bin/python -m pytest -q tests/test_control_plane_phase9_exit.py tests/test_main_ci_sharding.py tests/test_measured_reviews.py tests/test_measured_review_api.py tests/test_review_assignments.py tests/test_linux_boundary_conformance.py tests/test_checkpoint_witness.py`: 121 passed.
- `.venv/bin/ruff check src tests containers scripts`: 통과.
- `.venv/bin/python -m mypy --platform linux src scripts/measured_conformance.py scripts/ci_sharding.py`: 500 source 통과.
  `.github/workflows/ci.yml`의 나머지 두 Linux mypy 명령도 14개·2개 source를 통과했다.
- `.venv/bin/python -m pytest -q tests/test_documentation.py`: 4 passed.
- 실제 Linux 실행은 `scripts.witness_checkpoint_rehearsal`, `scripts.hybrid_operations_rehearsal`에
  위 고정 이미지·Worker 이미지·새 소유 output 경로를 전달했다. 정확한 실행 입력과 결과는
  `run_verified_ops.py`, `ops-source-verified.json`, `ops-verified-summary.json`에 있다.

Private 작업 근거는 `.pajin/continuation-three-20260912/`에 있다. `baseline.json`,
`effect006-wheel-verification.json`, `graph-comparison.json`, `graph-source-pins.json`,
`final-cleanup-observation-a.json`, `final-regression/`, `regression-combined-verification.json`,
`post-regression-delta.json`, `final-source-inventory.json`, `skip-comparison.json`,
`ops005-linux-a/`, `ops005-linux-final/`, `ops005-linux-verified/`, `ops003-linux-verified/`,
`ops-verified-summary.json`, `final-cleanup-observation-b.json`, `browser-qa-evidence.json`,
`current-final-wheel-verification.json`, `output/playwright/`를 먼저 확인한다.
실제 자격증명·private 원문은 출력하지 않는다.

## 현재 원격 검증과 다음 한 단계

- `dd039ef`의 CI 34695320503은 첫 시도 quality·24 shard 모두 통과했다. 24개 artifact의
  clean SHA·exit 0과 고유 8,747개 ID를 확인했고 실제 로그는 8,671 passed·기존 76 skipped다.
- Web 34695348325, Network 34695349598, AI 34695350838, SYS 34695353359도 첫 시도 성공했다.
  실제 test와 clean commit·image·독립 residue gate를 확인했다. SYS source digest는 로컬
  tracked bytes와 같은 `a854bfa0adc87b40d3e88e20c0e7acafdc00805911baccfb705a236cb82f2d8b`다.
- OPS 34695351995는 기존 11개·추가 15개를 통과했지만 witness의 15/21 검사 뒤
  `target-resume`에서 실패했다. 원격 private 명령 상세는 공개 artifact에 없어 원인은 미확정이다.
  별도 cleanup·독립 관찰은 자원 0·fallback 없음이다. 실패 원문/요약을 private으로 보존했다.
- 독립 스트레스가 5분 승인 유효기간을 소모하는 순서를 별도 회귀에서 재현했다. 32회 검사를
  실제 승인된 재개 뒤로 옮겼고 개별 제한·만료 거부·모든 검사·cleanup은 유지한다.
  재개 단계는 고정된 public-safe 하위 phase로 구분한다. 관련 101개·Ruff·Linux mypy를 통과했다.
  새 소유 Linux 실증도 187.20초에 21개 검사·32회 새 process를 통과했고 독립 9회 조회에서 자원은 0개다.
- 복구 순서 보완 커밋 `0d7343a5d013187ee5cffbe93fc4d730b17a76d0`를 push했다.
  Web 34696427693·Network 34696428887·AI 34696430066·OPS 34696431387·SYS 34696432624가
  같은 SHA에서 첫 시도 성공했다. OPS는 748.62초에 기존 11·추가 15·witness 21 검사와
  32회 새 process 검증을 모두 통과했고 독립 cleanup도 통과했다.
- 일반 CI 34696391646의 shard 19는 기존 Replay 0.15초 lease 테스트의 진단 문구 불일치로
  실패했다. quality와 나머지 23 shard는 성공했다. 원격에서 만료를 관측한 정확한 내부 위치는
  해당 traceback만으로 확정하지 않는다.
- 별도 결정론적 재현에서 초기 검사 뒤 scheduling 전에 만료되면 executor가 한 번 호출되는
  경계를 확인했다. claim 복사 뒤 실제 executor 호출 직전에 local lease를 재검사한다.
  재현은 수정 전 1 failed·2 passed, 수정 뒤 Replay/Worker 전체 **199 passed**다.
  stalled-heartbeat 통합 검사는 시작 여유를 확보하고 기존 중단/겹침/최종화 검사를 유지하며
  실제 heartbeat 시작과 더 구체적인 local-deadline 예외를 추가 검사한다.
- Ruff 전체·Linux strict mypy 507 source가 통과했다. 이 필요한 수정만 승인된 commit/push한 뒤
  새 SHA의 일반 CI와 다섯 실증을 확인한다. 새 후보 파일은 이 커밋에 섞지 않는다.
- 새 작업 근거는 `.pajin/four-followups-20260912/`다. 초기 실패, 0d7343a 검증은 `remote/`,
  `remote-fixed/`, scheduling 재현은 `replay-start-red.log`, 검증은 `replay-start-green.log`에 있다.

## 유지되는 운영 경계

- anchor와 witness를 함께 되돌린 상태는 두 local store만으로 탐지할 수 없다.
- 별도 물리 host·실제 power loss·운영 failover·production 배포·장기 가용성은 미검증이다.
- 현재 승인과 일회용 복구 권한, uncertain 사용량의 보수적 차감, 명시적 실행 재개를 유지한다.
- 알림은 앱 내부 기록이며 실행 권한·Finding·외부 전송을 만들지 않는다.
