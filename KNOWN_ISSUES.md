# PAJIN 알려진 문제

재현된 미해결 제약만 기록한다. 비밀정보의 실제 값과 추측성 백로그는 기록하지 않는다.
로드맵 작업은 `PLAN.md`에서 관리한다.

## Windows 심볼릭 링크 테스트 권한

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-01
- 명령: `.\.venv\Scripts\python.exe -m pytest -x -q`
- 결과: 197 passed, 4 skipped 이후
  `test_provider_checks_fail_closed_on_unsealed_symlink_artifact`가 테스트용 심볼릭 링크를
  생성하는 과정에서 `WinError 1314`로 중단됐다.
- 영향: 심볼릭 링크 생성 권한이 없는 Windows 세션에서는 전체 테스트를 완료할 수 없다.
  이는 PAJIN 코드 회귀의 증거가 아니다.
- 해소 조건: Linux CI 또는 심볼릭 링크 권한이 있는 Windows 환경에서 전체 테스트를
  실행한다.

## P0-C2B2B provider fence의 host-local 범위

- 상태: 활성 분산 운영 공백
- 현재 보장: local Docker adapter는 별도 SQLite provider state에 fence를 side effect 전에
  영속하고 stale 호출을 Docker 전에 차단한다. 별도 SQLite operation lock이 같은 host의 live
  mutation과 higher-fence cleanup을 직렬화하며, receipt-bound evidence와 실제 Docker
  conformance가 이를 검증한다.
- 영향: 이 강제 경계는 하나의 host와 provider state 경로에 한정된다. 서로 다른 host나 원격
  Docker/cloud control plane이 같은 Target을 공유하면 local SQLite만으로 stale writer를 차단할
  수 없다.
- 해소 조건: 원격 provider의 원자적 compare-and-set fence 또는 lease authority와 독립 provider
  evidence를 구현하고 cross-host stale-call 음성 검증을 수행한다.

## P0-C2A recovery seal과 journal terminal 전이 사이 중복 감사

- 상태: 활성 보수적 중복 가능성
- 조건: Recovery Authority Run을 seal한 직후 journal attempt를 `reconciled`로 바꾸기 전에
  프로세스가 종료된다.
- 영향: 다음 시작은 이미 journaled된 성공 cleanup receipt를 재사용해 provider를 다시
  호출하지 않지만 동일 attempt에 대한 새 Recovery Authority Run을 하나 더 봉인할 수 있다.
  측정 Admission은 두 Run 모두 false라 안전성이나 metric에는 영향을 주지 않는다.
- 해소 조건: sealed Run ID를 journal terminal transition과 연결하는 재개 가능한 publication
  marker를 추가하고 동일 authority의 재봉인을 제거한다.

## P0-C2B2A1 activation store의 외부 복구 권위

- 상태: 활성 운영 복구 공백
- 현재 보장: registry distribution origin은 별도 Ed25519 key로 검증되고, intact host-local SQLite
  store는 마지막 accepted bundle을 append-only로 유지해 restart rollback·gap·equivocation을
  차단한다.
- 영향: activation database 전체가 삭제되거나 신뢰 경계 밖에서 교체되면 remembered head도 함께
  사라진다. local store만으로는 오래된 revision 1을 새 bootstrap처럼 복원한 상황을 구분할 수 없다.
  distribution Trust Anchor rotation과 remote HTTPS fetch도 아직 없다.
- 해소 조건: 운영 백업 또는 독립 transparency/checkpoint anchor와 명시적 distribution Trust
  Anchor rotation authority를 추가한다.

## Windows 애플리케이션 제어에 의한 mypy 네이티브 모듈 차단

- 상태: 현재 재현되지 않음, 재발 가능 환경 제약
- 마지막 확인: 2026-08-01
- 명령: `.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src`
- 현재 결과: 199 source files 통과
- 과거 증상: import 단계에서 Windows 애플리케이션 제어가 네이티브 `librt.base64` 모듈을
  차단했다.
- 재발 시 조치: Linux CI를 사용하거나 조직의 애플리케이션 제어 정책에서 서명된 네이티브
  모듈을 허용한다. mypy 실행을 위해 정책을 비활성화하지 않는다.

## Git OpenSSL CA 경로

- 상태: 활성 로컬 전송 제약
- 마지막 재현: 2026-08-01
- 증상: 기본 Git OpenSSL backend가 GitHub 원격에 대해
  `unable to get local issuer certificate`를 보고할 수 있다.
- 검증된 대안: TLS 검증을 끄지 않고 Windows 인증서 검증을 사용한다.
  - `git -c http.sslBackend=schannel push origin main`
  - `git -c http.sslBackend=schannel ls-remote origin refs/heads/main`
- 해소 조건: 로컬 Git CA bundle을 복구하거나 schannel override를 계속 사용한다.

## Docker daemon 가용성

- 상태: 현재 가용, 세션 의존 환경 제약
- 마지막 관찰: 2026-08-01
- 현재 결과: Docker Desktop 4.78.0 / Engine 29.5.3에서 P0-C2B2B real Target conformance가
  통과했고 종료 뒤 `pajin-bench-*` container와 network가 남지 않았다.
- 영향: Docker Desktop이 다음 세션에 자동으로 가용하다는 보장은 없다. daemon이 꺼져 있으면
  opt-in live test는 실행할 수 있지만 일반 fake-provider 검증은 계속 가능하다.
- 필요한 조치: 실제 컨테이너 증거가 필요한 작업 전에 daemon 상태와 exact image ID를 다시
  확인한다. 실행하지 않은 live 검증을 성공으로 보고하지 않는다.
