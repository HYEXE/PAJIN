# PAJIN 개발 인수인계

- 기록일: 2026-08-02
- 브랜치: `main`
- 작업 시작 기준: `f7fe51fd9631351dd33296231a92427bc39cc836`
- 현재 구현 체크포인트: `P0-E3B2` registry-governed local single-agent baseline 측정
- 다음 구현: `ENG-001` 공통 Campaign Execution Engine 계약

## 재개 전 확인

```powershell
git branch --show-current
git status --short
git rev-parse HEAD
git rev-parse origin/main
git status --porcelain=v2 --branch
```

문서보다 실제 저장소를 우선한다. 정상 delivery 뒤에는 `main`, clean worktree, local HEAD,
`origin/main`, 실제 원격 `refs/heads/main`이 모두 같아야 한다.

## 현재 구현 상태

P0-E3B2는 P0-E3A plan과 P0-E3B1 local llama.cpp/Qwen registration을 실제 P0-D1 Target
measurement lifecycle에 결박한다.

- `DockerSingleAgentTargetFactoryAdapter`는 fresh reset·internal isolation·execution·cleanup과 기존
  recoverable fence를 재사용한다.
- Provider action은 host-local llama.cpp가 있는 기본 bridge로, fixed SQLi Tool action은 현재 Target의
  internal network로 route한다. route map은 Docker Worker execution context v2에 정렬해 결박되며 각
  Worker는 여전히 전용 internal network와 host-observed egress proxy를 사용한다.
- provider evidence는 P0-E3A plan, P0-E3B1 registration, normalized/raw trace, Tool Loop Run/root,
  exact Worker/proxy image ID와 Target 상태를 execution receipt에 결박한다.
- `SingleAgentBaselineMeasurementRunner`는 registry-governed Harness·Target Run·attestation·receipt·
  provider evidence·raw trace·normalization을 다시 열고 전체 좌표의 completed `BenchmarkResult`와
  하나의 content-addressed measurement authority를 봉인한다.
- trace seed는 exact benchmark coordinate와 같아야 하며 Campaign, plan, trace, image, source 또는
  cleanup substitution은 실행 authority나 Result admission이 생성되기 전에 fail closed한다.
- candidate comparison과 Supervisor activation은 계속 false다.

핵심 구현 위치:

- `src/pajin/benchmark/single_agent_docker_provider.py`
- `src/pajin/benchmark/single_agent_measurement.py`
- `src/pajin/benchmark/single_agent_runtime.py`
- `src/pajin/benchmark/docker_provider.py`
- `src/pajin/runtime/worker.py`
- `src/pajin/workflow/tool_loop.py`
- `tests/test_benchmark_single_agent_measurement.py`
- `tests/test_benchmark_single_agent_runtime.py`
- `tests/test_worker.py`
- `docs/benchmark/P0-E3B-local-single-agent-runtime.md`
- `docs/adr/0100-bind-single-agent-run-to-governed-target-measurement.md`

## 실제 적합성 근거

- Docker Desktop 4.78.0 / Engine 29.5.3, NVIDIA RTX 3090에서 실행
- Target image ID: `sha256:1237af881d2cdbe96cc87dada42a9fd8952abd10ab357463c2efaf8aafd1e5a1`
- benchmark Worker image ID: `sha256:84c1dad2e13f260c6daee0850c0c76b1be8b7944dccd2c33689ae83b949f04af`
- agent Worker image ID: `sha256:973fe191b390e28328acc6d4c32bca59417bc0b74f934170258411f6604481f6`
- egress proxy image ID: `sha256:1a2615628fc7d48dc4d5a67f76ec8cf5511c875085c7fe0822cfa6f19c46b9e4`
- llama.cpp image ID: `sha256:f92150249e1913ef96e744b5d78f6291f0e4399a7925ffc7b1d0680d82506551`
- GGUF SHA-256: `ae916ede1c010a26955ee8ae2e908bf8815a3f135ec860439ab924701c69d5f1`
- Tool Loop Run: `run_20260802T095356Z_2bd38e7f`
- Target Run: `run_20260802T095419Z_940042da`
- measurement Run: `run_20260802T095419Z_70ef492f`
- normalized trace digest: `317b362d506f7e46502245e199d53398027fd3bbc7dc1855ec12d7b4eb50591a`
- raw trace SHA-256: `7cb390effaccf293b4b1f44a1611458a8bcf285bc052ff85c9473c74dad67de1`
- Provider usage: prompt 1,371 + completion 62 = total 1,433 tokens
- Result: `benchmark-result:298db8b9e8176e1ed91cb9758e3e457087d33c61f5b65e2c1f6f2ac8a2bc878d`
- measurement authority:
  `single-agent-baseline-measurement:981fac2cf002ace8b4e14d63e26869d90510ebb9510949edbe416370b5c44e17`
- 결과: status completed, fixed SQLi Tool 1회, model call 2회, cleanup succeeded, recall·precision 1.0

## 마지막 검증

- 실제 local Docker·llama.cpp·Qwen B2 적합성: 1 passed
- runtime·measurement 집중 테스트: 11 passed, opt-in live 1 skipped
- benchmark·measurement·registry·문서 집중 회귀: 82 passed, 3 skipped
- action-specific Worker route: 3 passed
- Campaign·executor substitution, trace seed substitution, raw trace mutation과 unsafe route 음성 경계 포함
- Ruff 전체 통과
- Linux 대상 strict mypy: 216 source files 통과
- 전체 `pytest -x -q`: 331 passed, 8 skipped 뒤 기존 Windows symlink 권한
  `WinError 1314`에서 중단
- `git diff --check`: 통과, Windows CRLF 변환 경고만 존재

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_single_agent_runtime.py tests\test_benchmark_single_agent_measurement.py
.\.venv\Scripts\python.exe -m pytest -q tests\test_benchmark_docker_provider.py tests\test_walking_benchmark_measurement.py tests\test_worker.py
.\.venv\Scripts\python.exe -m ruff check .
.\.venv\Scripts\python.exe -m mypy --no-incremental --platform linux src
.\.venv\Scripts\python.exe -m pytest -x -q
git diff --check
```

## 다음 조치

`ENG-001`의 가장 작은 수직 슬라이스를 설계한다.

1. `docs/adr/0046-common-engine-and-campaign-profiles.md`, Architecture v2 RFC와 현재
   `workflow/` 진입점을 대조해 이미 공통인 Policy·Capability·Worker·Evidence 경계를 구분한다.
2. 기존 `bug-bounty`, `ctf`, `ai-redteam` 입력과 public wire shape을 깨지 않는 공통 Campaign 실행
   request/outcome 계약을 먼저 정의한다.
3. Mode별 planner·scheduler·validation을 중복 구현하거나 한 번에 이관하지 않고, 실행 권한 확대가 없는
   한 경로의 compatibility adapter를 최소 수직 슬라이스로 연결한다.
4. Scope·risk·budget·Capability 불변식과 legacy/new path parity를 음성 테스트로 고정한다.

## 알려진 경계

- B2 결과는 host-local Docker·GPU와 한 synthetic SQLi 좌표에 한정되며 일반 single-agent 성능이 아니다.
- local Provider의 USD 0 가격은 marginal token 가격만 의미하며 GPU 전력·감가상각 비용은 제외한다.
- 비교와 Supervisor activation은 별도 sealed Result·eligibility 계약 없이는 계속 false다.
- 전체 pytest는 Windows symlink 권한 제약으로 끝까지 실행되지 않을 수 있다.
- Docker daemon과 ignore된 local model·Run은 다른 host에서 자동 복원되지 않는다.

자세한 조건은 `KNOWN_ISSUES.md`에 있다. 현재 roadmap과 handoff 권위는 각각 `PLAN.md`와 이 문서다.
기존 Notion은 역사 자료이며 병렬 갱신하지 않는다. 사용자는 기능별 사전 검토 뒤 자동 commit·push하고
다음 개발로 계속 진행하는 것을 승인했지만, 비용·credential·외부 데이터 전송 결정은 별도 권한이다.
