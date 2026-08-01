# PAJIN 개발 인수인계

- 기록일: 2026-08-01
- 브랜치: `main`
- 작업 시작 기준: `d6563b18da9c9bdd13f35216d2acff97e3c47d44` (`P0-D2`)
- 현재 구현 체크포인트: `P0-D2B` local AI/RAG/MCP provider·별도 runnable catalog
- 다음 구현: `P0-D3` Hybrid Target composition authority

## 재개 전 확인

문서보다 실제 저장소 상태를 우선한다.

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

정상 delivery 뒤에는 `main`, clean worktree, local HEAD, `origin/main`, 실제 원격
`refs/heads/main`이 모두 같아야 한다. merge, rebase, cherry-pick 또는 background helper가 없어야
한다.

## 현재 구현 상태

`WALK-001`~`WALK-006`, `BENCH-003A/B1/B2`, `P0-C1`, `P0-C2A`, `P0-C2B1`,
`P0-C2B2A1/A2/B`, `P0-D1`, `P0-D2`, `P0-D2B`가 구현됐다. P0-D2B는 다음 경계를 추가한다.

- `DockerAIRAGMCPTargetProfile`이 exact Target·Worker image ID, internal bridge, vulnerable target
  state와 Factory digest를 결박한다.
- 기존 SQLi provider의 durable SQLite journal, operation lock, monotonic fence, hardened container,
  internal network, receipt-bound evidence와 cleanup을 공통 lifecycle로 재사용한다.
- 별도 Target·Worker image가 실제 HTTP document upload, deterministic RAG retrieval, Target 내부
  MCP `inspect_text` 호출, synthetic internal marker 관찰을 수행한다.
- host parser가 Worker 성공 flag만 신뢰하지 않고 exact field/check set, observation 순서,
  Base64 response body, body SHA-256와 decoded JSON 전체를 검증한다.
- runnable profile은 `target-catalog:pajin-ai-rag-mcp-local-docker`에 별도 등록된다. P0-D2
  fixture catalog와 `BenchmarkTargetFixtureSelectionAuthority`는 변경되지 않고 계속 non-runnable이다.
- runnable Ground Truth는 Walking fixture matcher를 재사용하지 않고 Docker profile/evidence와 실제
  Target 응답을 묶는 `matcher:docker-ai-rag-mcp-chain-probe` digest를 사용한다.
- catalog wrapper가 provider mutation 전 Manifest·adapter·profile·catalog·private Ground Truth를
  exact 검증하고 실행 뒤 evidence와 등록된 3 Surface·1 Finding·1 chain 측정치를 대조한다.
- 이 lab은 model call과 외부 서비스를 사용하지 않는다. MCP endpoint는 별도 server deployment가
  아니라 Target container 내부의 명시적 HTTP protocol boundary다.

핵심 구현 위치:

- `src/pajin/benchmark/docker_provider.py`
- `src/pajin/benchmark/ai_target_catalog.py`
- `src/pajin/benchmark/target_catalog.py`
- `src/pajin/benchmark/__init__.py`
- `containers/ai-rag-mcp-target/`
- `containers/ai-rag-mcp-benchmark-worker/`
- `tests/test_benchmark_docker_provider.py`
- `docs/benchmark/P0-D2B-local-ai-rag-mcp-docker-provider.md`
- `docs/adr/0089-local-ai-rag-mcp-docker-provider.md`

## 마지막 검증

- WALK·Benchmark·Target·문서 집중 테스트: 132 passed, 2 skipped
  - skip: P0-D1, P0-D2B opt-in real Docker conformance
- P0-D2B 실제 Docker image build 및 live conformance: 1 passed
- Ruff 전체 통과
- Linux 대상 strict mypy: 201 source files 통과
- 전체 `pytest -x -q`: 221 passed, 5 skipped 뒤 기존 Windows symlink 생성 권한
  `WinError 1314`에서 중단
- 커밋 전 검토에서 Walking fixture matcher 재사용 오류를 발견해 별도 Docker matcher로 수정했다.
- 성공 flag는 참이지만 decoded body가 치환된 Worker 출력, malformed output, adapter digest와 Ground
  Truth matcher 치환이 모두 provider·catalog 호출에서 fail closed하는지 확인했다.

재현 명령:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_walking_file_upload.py tests\test_walking_rag_injection.py tests\test_walking_mcp_authorization.py tests\test_walking_benchmark_measurement.py tests\test_benchmark_target_recovery.py tests\test_benchmark_target_factory.py tests\test_benchmark_ai_target_catalog.py tests\test_benchmark_target_catalog.py tests\test_benchmark_measurement_registry_distribution.py tests\test_benchmark_measurement_registry.py tests\test_benchmark_docker_provider.py tests\test_benchmark_contract.py tests\test_documentation.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

실제 Docker conformance는 두 image를 build한 뒤 `PAJIN_TEST_DOCKER_AI_BENCHMARK=1`로
`test_real_docker_ai_rag_mcp_provider_conformance`를 실행한다. 권한 격리 환경에서는 `TEMP`와
`TMP`를 쓰기 가능한 별도 경로로 지정해야 PAJIN run lock을 생성할 수 있다.

## 커밋 전 검토 결과

- P0-D2 fixture profile·catalog·selection wire와 false authority flag는 변경하지 않았다.
- 기존 P0-D1 SQLi provider 수명주기 테스트가 공통 hook 분리 뒤에도 통과했다.
- AI Worker action, input, output, decoded Target body와 Docker worker command가 exact 일치해야 한다.
- 실제 Target은 업로드 뒤 corpus를 조회하고 loopback MCP HTTP request를 수행한다. 단순 성공 fixture를
  Benchmark Observation으로 변환하지 않는다.
- Target·Worker image substitution, hardening drift, stale fence, foreign receipt, lifecycle reorder,
  catalog/Manifest/adapter/Ground Truth substitution은 기존 또는 새 음성 테스트에서 차단된다.
- 민감정보, SSL 우회, 외부 서비스 호출, 임의 command/image runner 일반화는 포함하지 않았다.

## 다음 조치

`P0-D3`를 진행한다.

1. P0-D1 Traditional Web/API와 P0-D2B AI/RAG/MCP의 profile, catalog, private Ground Truth,
   provider lifecycle을 대조한다.
2. 서로 다른 두 Factory를 단순히 한 catalog에 나열하는 것을 Hybrid execution으로 오인하지 않도록
   composition identity와 chain Ground Truth를 별도 content-addressed authority로 정의한다.
3. 하나의 coordinate에서 reset·isolation·execution·cleanup 순서와 두 provider의 fence·receipt를
   어떻게 결박할지 가장 작은 비실행 contract slice부터 결정한다.
4. cross-profile substitution, partial lifecycle, repeated component, component order change,
   Surface·Finding·chain scope expansion을 fail closed하는 음성 경계를 우선 설계한다.
5. 실제 multi-provider 실행이 없으면 non-runnable로 명시하고 Benchmark metric을 생성하지 않는다.

## 알려진 경계

- P0-D2 fixture는 계속 contract-only이며 P0-D2B 실행 증거로 대체되지 않는다.
- P0-D2B는 host-local, single Target container, deterministic no-model profile이다.
- MCP endpoint는 Target 내부에 있으며 별도 MCP server/process 격리를 증명하지 않는다.
- catalog distribution signature, durable anti-rollback activation, sealed Harness source binding이 없다.
- exact Docker image ID는 trusted local provisioning input이다.
- provider fence는 같은 host·SQLite·Docker 경계이며 cross-host를 보장하지 않는다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않는다.

자세한 재현 조건과 해소 기준은 `KNOWN_ISSUES.md`에 있다.

## 문서 권위와 사용자 승인

현재 로드맵과 인수인계 권위는 각각 `PLAN.md`와 이 문서다. 기존 Notion 로드맵은 역사 자료이며
병렬 갱신하지 않는다.

사용자는 기능별 사전 검토 뒤 자동 커밋·push하고 다음 개발로 계속 진행하는 것을 승인했다.
