# PAJIN 알려진 문제

재현된 미해결 제약만 기록한다. 비밀정보의 실제 값과 추측성 백로그는 기록하지 않는다.
로드맵 작업은 `PLAN.md`에서 관리한다.

## Windows 심볼릭 링크 테스트 권한

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-01
- 명령: `.\.venv\Scripts\python.exe -m pytest -x -q`
- 결과: 150 passed, 3 skipped 이후
  `test_provider_checks_fail_closed_on_unsealed_symlink_artifact`가 테스트용 심볼릭 링크를
  생성하는 과정에서 `WinError 1314`로 중단됐다.
- 영향: 심볼릭 링크 생성 권한이 없는 Windows 세션에서는 전체 테스트를 완료할 수 없다.
  이는 PAJIN 코드 회귀의 증거가 아니다.
- 해소 조건: Linux CI 또는 심볼릭 링크 권한이 있는 Windows 환경에서 전체 테스트를
  실행한다.

## Windows 애플리케이션 제어에 의한 mypy 네이티브 모듈 차단

- 상태: 활성 환경 제약
- 마지막 재현: 2026-08-01
- 명령: `.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src`
- 결과: import 단계에서 Windows 애플리케이션 제어가 네이티브 `librt.base64` 모듈을
  차단했다.
- 영향: 일반 mypy 진입점은 소스 분석 전에 실패할 수 있다.
- 검증된 대안: 같은 mypy 버전의 순수 Python 소스와 메모리 내 `librt` 호환 계층을
  사용한 Linux 대상 strict 분석에서 185개 소스 파일이 통과했다.
- 해소 조건: Linux CI를 사용하거나 조직의 애플리케이션 제어 정책에서 서명된 네이티브
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

- 상태: 컨테이너 의존 작업 전에 재확인 필요
- 마지막 관찰: WALK-001/WALK-002 검증 전 비활성
- 영향: 실제 컨테이너 MCP·egress 검증을 실행하지 못했으며 결정론적 구조 fixture로 계약을
  검증했다.
- 필요한 조치: 실제 컨테이너 증거가 필요한 작업 전에 Docker daemon 상태를 확인한다.
  실제로 실행하지 않은 컨테이너 검증을 성공으로 보고하지 않는다.
