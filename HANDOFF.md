# PAJIN 인수인계

## 현재 체크포인트

- 기록일: 2026-08-12
- 브랜치: `main`
- HEAD: `38f2ce565400d27879dba56167d91bf1cce1dc13`
- upstream: `origin/main@38f2ce565400d27879dba56167d91bf1cce1dc13` (ahead/behind `0/0` 확인)
- 단계: Phase 9 `UX-006B`와 `UX-007A` OIDC MFA Human Identity 구현·문서화·회귀 검증 완료, 미커밋
- 다음 로드맵: ABAC·Worker Identity·mTLS
- commit/push/PR/merge/deploy: 수행하지 않음

## 재개 전 확인

```powershell
git status --short --branch
git rev-parse HEAD
git rev-parse origin/main
git -c http.sslBackend=schannel ls-remote origin refs/heads/main
```

실제 Git과 파일시스템을 우선한다. 현재 변경은 사용자 승인 전 commit 또는 push하지 않는다.

## 이번 체크포인트에서 완료한 범위

`UX-006B`는 `UX-006A`가 만든 exact verified SARIF bytes를 외부 endpoint로 전달하기 전에 다음 권위를
분리해 결박한다.

- content-addressed deployment-owned HTTPS sink와 same-origin reconciliation endpoint
- source Run/root/Finding-set, payload digest/bytes, sink를 묶는 deterministic intent와 stable idempotency key
- exact intent·sink·payload·key와 두 번의 최대 시도를 승인하는 별도 authorization verifier
- sink audience, source Run scope, operation, attempt ordinal에 결박된 one-use `SecretBroker` lease
- mutating network call 전에 attempt를 기록하는 host-local append-only SQLite journal
- exact intent/key/payload/attempt를 묶은 HMAC-SHA256 authenticated sink response
- authenticated acceptance에서만 생성되는 durable local delivery receipt
- unknown outcome 무자동 재전송, authenticated `not-received` 뒤 동일 key 단 한 번의 explicit retry

state는 다음 범위만 허용한다.

```text
ready-initial
  -> dispatch-started-outcome-unknown
     -> delivered
     -> ready-retry
        -> dispatch-started-outcome-unknown
           -> delivered
           -> terminal-not-delivered
```

receipt의 `externalDeliveryPerformed`와 `deliveryReceiptAuthority`는 true지만
`downstreamActionAttested`는 false다. 따라서 endpoint acceptance는 Issue 생성, SIEM indexing, SOAR action을
증명하지 않는다.

### UX-007A

`UX-007A`는 external OIDC login이 발급한 RFC 9068-shaped JWT access token을 기존 Control Plane Bearer
경계에서 검증한다.

- `pajin.control-plane.oidc-human-trust-policy/v1` strict JSON deployment policy
- exact HTTPS issuer, single resource audience, client ID, required scope, bounded token/authentication age
- provider-specific exact ACR와 required AMR 기반 MFA 결박
- deployment-pinned RS256 SPKI key, active/retired/revoked lifecycle, no dynamic discovery/JWKS
- explicit `at+jwt` only; ID Token·untyped JWT·token-selected key URL 거부
- exact provider subject를 local Principal에 매핑하고 token role/group/entitlement claim은 무시
- Human OIDC mapping의 Worker role과 Operator+Approver 결합 거부
- OIDC와 opaque authority의 local subject 공유, 한 bearer를 두 authenticator가 수용하는 ambiguity 거부
- 기존 route role dependency와 durable Run audit actor, static Worker bearer 경로 재사용

OIDC policy가 있으면 static Operator/Approver token은 생략할 수 있지만 effective Operator와 Approver
authority는 각각 존재해야 한다. Worker token과 checkpoint key는 계속 필수다.

## 변경 파일

- `src/pajin/reporting/delivery.py`
  - sink/intent/authorization/response/receipt/record v1alpha1 모델
  - deployment sink·authorization registry와 coordinator
  - direct HTTPS/no-proxy/no-redirect transport
  - append-only hash-chained SQLite journal
- `tests/test_external_delivery.py`
  - acceptance, unknown reconciliation, one retry, terminal second failure
  - forged response, wrong lease, stale source, cross-sink substitution, unsafe endpoint
  - journal tamper/idempotent registration, unregistered authorization
- `docs/orchestration/UX-006B-authenticated-external-delivery.md`
- `docs/adr/0165-authenticate-and-journal-external-delivery.md`
- `src/pajin/control_plane/identity.py`
- `src/pajin/control_plane/security.py`, `src/pajin/control_plane/api.py`
- `tests/test_control_plane_identity.py`
- `docs/orchestration/UX-007A-oidc-mfa-human-identity.md`
- `docs/adr/0166-bind-mfa-oidc-identity-without-token-role-authority.md`
- `README.md`, `PLAN.md`, `DECISIONS.md`, `KNOWN_ISSUES.md`, `HANDOFF.md`

## 검증 결과

성공:

- UX-006B 집중: `13 passed`
- 인접 SARIF·secret·safe-file·문서 묶음: `50 passed, 3 skipped`
- 문서 크기 수정 후 `tests/test_documentation.py`: `2 passed`
- exact `uv.lock` Windows 환경의 `ruff check src tests containers`: 통과
- `ruff format --check src/pajin/reporting/delivery.py tests/test_external_delivery.py`: 통과
- strict mypy 대상 2개: `Success: no issues found in 2 source files`
- `git diff --check`: 통과
- UTF-8 문서 읽기: 통과
- UX-007A 집중: `26 passed`
- 기존 `tests/test_control_plane.py`: `114 passed`
- 최종 UX-007A·기존 Control Plane API·문서 묶음: `142 passed`
- UX-007A 대상 `ruff format --check`: 통과
- UX-007A 코드·테스트 strict mypy: `Success: no issues found in 4 source files`

환경 제한:

- 인접 테스트의 3개 skip은 Windows symbolic-link 권한 제한이다.
- 전체 `mypy src`는 로컬 캐시를 사용했지만 424초 제한에 도달했고 진단은 출력되지 않았다. 새 모듈과 테스트의
  strict mypy는 별도로 통과했다.
- `test_control_plane*.py` 전체 23개 파일은 로컬 NTFS 임시 경로에서도 실행했으나 Windows의 POSIX directory
  `fsync` 미지원과 이에 종속된 sealed-artifact fixture/setup 실패로 `553 passed, 78 skipped, 222 failed,
  4 errors`였다. 기본 Temp에서는 `.pajin-run-locks` ACL 오류, 저장소 내 basetemp에서는 Google Drive의
  hard-link 메타데이터 차이도 재현됐다. UX-007A 집중 및 기존 `tests/test_control_plane.py` 통과 결과와 분리한다.
- 실제 외부 HTTPS sink 호출은 실행하지 않았다. 외부 side effect 테스트는 fake transport만 쓴다.
- 동기화된 `.venv`는 macOS arm64 환경이라 Windows에서 실행할 수 없었다. 저장소 밖 ASCII 경로에
  `uv --system-certs sync --frozen --extra control-plane --extra dev`로 exact `uv.lock` Windows 환경을 만들고
  저장소 밖 로컬 NTFS pytest basetemp를 사용했다. `pyproject.toml`·`uv.lock`은 변경하지 않았다.

## Git 복구 확인

작업 시작 시 local/remote-tracking `main` ref 본문이 없고 동일 SHA를 가진 stale `.lock`만 남아 있었다.
진행 중 Git process와 merge/rebase/cherry-pick은 없었고 HEAD reflog, origin reflog, index/worktree, live
`ls-remote`가 모두 `38f2ce565400d27879dba56167d91bf1cce1dc13`으로 일치했다. 해당 ref를 복구한 뒤:

- branch/upstream/origin live SHA 일치
- ahead/behind `0/0`
- clean baseline 확인
- `git fsck --connectivity-only` 통과; 연결성 오류 없이 dangling object만 보고

현재 ref 복구는 완료됐으며 추가 Git 작업은 필요하지 않다.

## 알려진 경계

- sink·authorization registry는 process-local deployment input이다.
- journal은 single-host authority이며 distributed exactly-once, replication, backup, failover를 제공하지 않는다.
- bearer request와 response HMAC은 같은 brokered secret을 사용한다.
- HTTPS trust-chain 검증 외 DNS/IP allowlist와 private-network egress는 deployment 책임이다.
- authorization expiry 뒤 unknown outcome은 deployment intervention이 필요할 수 있다.
- journal hash chain은 외부 transparency anchor가 아니며 privileged host replacement를 막지 못한다.
- generic CLI, Control Plane write API, scheduled retry worker, vendor semantic adapter는 없다.
- OIDC는 external login 뒤 resource-server admission만 제공하며 authorization-code/PKCE·browser session·logout·
  refresh·token issuance를 제공하지 않는다.
- trust policy는 startup 1회 load다. remote discovery/JWKS refresh·multi-issuer·introspection·`jti` replay ledger는 없다.
- ABAC, Worker workload identity, mTLS와 proxy certificate forwarding은 아직 구현되지 않았다.

## 다음 한 단계

Phase 9의 남은 `ABAC·Worker Identity·mTLS`에서 다음 vertical slice를 정한다. 먼저 기존 route
`PrincipalRole`, Replay executor profile allowlist, Worker bearer client, TLS 1.2 Target session binding을 대조해
Human OIDC mapping을 workload identity나 실행 attribute authority로 확장하지 않는다. 가장 작은 후보는 existing
Worker subject를 deployment-pinned certificate identity에 결박하되 trusted proxy header를 새 권위로 만들지 않는
Worker mTLS admission 계약이다.
