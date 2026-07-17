> Languages: [English](0028-durable-local-replay-ticket-ledger.en.md) | [한국어](0028-durable-local-replay-ticket-ledger.ko.md)

# ADR 0028: 내구성 있는 로컬 Replay Ticket 원장과 재시작 검증

- 상태: 승인됨
- 날짜: 2026-07-16
- 구현: M6-06 로컬 수직 조각
- 개정 대상: [ADR 0027](0027-independent-reproduction-confirmation-boundary.ko.md)
- 관련 문서: [ADR 0011](0011-durable-control-plane.ko.md), [ADR 0024](0024-cooperative-execution-cancellation.ko.md)

## 맥락

ADR 0027의 Restricted Reproducer는 컴파일된 실행 권한을 opaque single-use ticket으로
결박한다. 현재 process-local `ReplayExecutionAuthority`는 한 프로세스 안에서 issued,
claimed, finalized 상태 전이와 final receipt 검증을 강제하지만, 프로세스가 종료되면 원장도
사라진다. 따라서 재시작한 Gate가 issued compilation, Candidate source root, replay Run,
artifact set과 final seal root를 처음 발급된 권한에 대해 다시 검증할 수 없다.

Replay Run 안의 두 integrity seal만으로는 이 공백을 메울 수 없다. seal은 저장된 artifact가
바뀌지 않았음을 검증하지만, 그 Run이 실제로 선발급된 single-use ticket을 claim했는지 또는
같은 ticket이 다른 replay Run에 재사용되지 않았는지는 증명하지 않는다. 반대로 mutable
runtime 객체를 Gate에 넘기면 Gate가 재시작 후 독립적으로 검증한다는 의미가 사라진다.

이 단계에서 PostgreSQL Control Plane 전체에 replay orchestration을 합치면 Job lease,
fencing, migration, 역할 분리까지 함께 설계해야 한다. 휴대 가능한 제3자 검증 증명에는
공개키 서명과 key lifecycle도 필요하다. M6-06은 그 범위를 넓히지 않고, 한 호스트의 KISA
positive confirmation과 baseline-bound negative retest가 프로세스 재시작을 견디는 최소
내구성 경계를 먼저 만든다.

## 결정

### 로컬 표준 원장

PAJIN은 Python 표준 라이브러리 `sqlite3`로 구현한 SQLite Replay Ticket 원장을 로컬 실행의
표준 내구성 backend로 추가한다. DB는 개별 sealed replay Run 디렉터리 안이 아니라 output
root에서 파생되고 명시적으로 주입되는 안정적인 state 경로의 `replay-tickets.sqlite3` 파일에
둔다. 한 positive 또는 negative KISA 실행이 만든 모든 replay Run은 같은 원장 경로를
사용한다. Run 정리나 새 replay Run 생성이 기존 ticket authority를 암묵적으로 바꾸지 않는다.

DB는 다음 논리 구조를 가진다.

| 구조 | 역할 | 핵심 불변식 |
| --- | --- | --- |
| schema metadata | 원장 schema 식별과 버전 | 구현이 기대하는 정확한 버전만 연다 |
| tickets | 발급된 compilation과 현재 상태 | ticket ID와 replay Run ID는 유일하다 |
| ticket events | 상태 전이 감사 기록 | 상태 전이 transaction 안에서 append되며 update/delete되지 않는다 |

새 schema 또는 기존 row를 호환 가능한 것으로 추측하지 않는다. writer는 기대한 schema가 없는
새 파일에만 현재 schema를 만들고, verifier는 schema version과 필요한 table, index, 제약,
append-only 보호가 정확한지 검사한다. 버전 불일치나 부분 migration은 자동 복구하지 않고 fail
closed한다. 향후 schema 변경은 명시적인 forward migration과 별도 호환성 결정을 요구한다.

### 발급 데이터와 결박

ticket row는 최소한 다음 authority-bearing 값을 보존한다.

- opaque ticket ID, state, issued/claimed/finalized 시각과 expiry;
- canonical compiled replay specification bytes와 그 SHA-256 digest;
- Candidate source integrity root;
- Campaign, Tool specification, Scenario를 결박한 context와 각각의 digest;
- ticket에 배정된 정확한 replay Run ID;
- finalized artifact set digest와 final receipt seal root.

원장은 canonical compilation bytes를 단순 blob으로 신뢰하지 않는다. 읽을 때마다 digest를 다시
계산하고 typed contract로 parse한 뒤 다시 canonicalize한 bytes가 저장값과 정확히 같은지
검증한다. compilation 내부 identity, 별도 index column, context digest, source root와 replay
Run이 서로 일치하지 않으면 해당 ticket을 사용할 수 없다. compilation 또는 context가
평문 secret을 저장하도록 권한을 넓히지 않으며 ADR 0027의 secret-bearing field 거부가
그대로 적용된다.

### 원자적 single-use 상태 기계

허용되는 상태 전이는 다음뿐이다.

```text
issued -> claimed -> finalized
```

발급, claim, finalize는 각각 짧은 `BEGIN IMMEDIATE` transaction과 compare-and-set 조건으로
수행한다. ticket row 변경과 대응하는 append-only event는 같은 transaction에서 commit된다.
foreign key 검사는 켜고, durability 설정은 `synchronous=FULL` 이상으로 유지한다. 동일 ticket을
여러 process나 thread가 동시에 claim해도 정확히 하나만 성공해야 한다.

상태 전이 시각은 authority가 소유한 UTC-aware trusted clock으로 결정한다. 운영에서는 system
clock을 사용하고 테스트에서는 clock을 주입할 수 있다. facade caller가 제출한 timestamp나
evidence의 시간을 expiry 또는 상태 전이 권한 판단에 신뢰하지 않으며, 원장은 canonical UTC ISO
표현을 저장한다. `expires_at`을 지난 issued ticket은 claim할 수 없다.

claimed process가 crash해도 ticket을 issued로 되돌리거나 다른 replay Run에 재배정하지 않는다.
그 ticket은 소비된 것으로 남고 finalization verifier는 계속 거부한다. 재시도에는 현재 정책,
budget, cancellation과 source binding을 다시 검사해 새로운 compilation, ticket, replay Run을
발급해야 한다. 이 로컬 원장은 lease timeout이나 crash recovery queue를 가장하지 않는다.

finalize는 claimed ticket에 대해 처음 한 번만 상태를 바꾼다. 이미 finalized된 ticket에 같은
compilation digest, source root, replay Run ID, artifact set digest와 final seal root로 다시
요청하는 경우에만 전송 재시도로 보고 idempotent하게 성공할 수 있다. 값이 하나라도 다른
finalize 재시도, finalized ticket의 재-claim, 상태 건너뛰기 또는 역방향 전이는 hard failure다.

### 재시작 후 read-only 검증

실행 Gate와 retest Gate는 mutable authority 객체 전체를 받지 않고
`ReplayTicketFinalizationVerifier` capability만 받는다. SQLite 구현은 writer와 별개로 새
connection을 열 수 있는 read-only verifier를 제공한다. verifier는 SQLite URI의 `mode=ro`와
query-only 동작을 사용하며, 파일이 없을 때 만들거나 schema를 초기화·migration하거나 row를
수정하지 않는다.

verifier는 process restart 뒤에도 다음 조건을 모두 다시 검사한다.

1. DB와 schema가 기대한 version과 구조로 열리고 ticket row가 정확히 하나 존재한다;
2. ticket 상태가 `finalized`이며 issued, claimed, finalized 순서가 유효하다;
3. 저장된 compilation bytes, compilation digest와 context binding이 self-consistent하다;
4. 요청된 Candidate source root, replay Run ID와 canonical compilation digest가 발급 row와
   정확히 일치한다;
5. replay Run loader가 검증한 artifact set digest와 final receipt seal root가 finalize row와
   정확히 일치한다.
6. replay receipt와 compilation에 포함된 Candidate, original Run/request, replay request,
   Mode, scenario, threat, Tool과 target identity가 ADR 0027 Gate의 기존 검사를 통과한다.

`issued` 또는 crash로 남은 `claimed` ticket은 sealed artifact가 있더라도 검증되지 않는다.
DB open 오류, unknown ticket, duplicate row, schema 손상, canonicalization 실패, digest 불일치,
context/source/replay/final seal/artifact substitution과 검증 중 관찰되는 DB 오류는 모두 fail
closed한다. `offline verification`은 이 문서에서 실행 authority와 분리된 새 read-only process가
같은 호스트의 DB를 다시 읽는다는 뜻이며, DB 없이 receipt 파일만으로 검증한다는 뜻이 아니다.

### 파일과 신뢰 경계

writer는 새 전용 state directory를 owner-only `0700`, DB 파일과 DELETE journal sidecar를
owner-only `0600`으로 만든다. 기존 상위 output directory와 backup, 복제본에 대한 OS ACL과
운영 접근 제어는 배포자의 책임이다. read-only verifier 역시 권한 없는 경로를 우회하거나
다른 파일로 fallback하지 않는다.

SQLite 원장은 이 로컬 경계의 신뢰 anchor다. digest, canonical bytes, schema와 event 검사는
부분 write, 우발적 손상과 일관되지 않은 row 변조를 탐지하지만, DB 파일을 쓸 수 있는 특권
공격자가 row, digest, schema와 보호 장치를 모두 일관되게 다시 쓰는 경우를 암호학적으로
증명하지 못한다. 그런 OS 계정 또는 storage compromise는 이 ADR의 trust boundary 밖이다.
그러므로 SQLite DB 사본은 원격 감사자에게 제시할 휴대형 cryptographic proof가 아니며,
파일 권한을 integrity seal 또는 signature로 오해하지 않는다.

### KISA 수직 조각과 호환성

M6-06은 KISA의 두 경로에 같은 backend interface를 dependency injection한다.

- positive `kisa-run`은 issued ticket을 claim/finalize한 뒤 새 read-only verifier로 canonical
  receipt를 다시 열어 reproduction-backed confirmation Gate에 전달한다.
- negative `kisa-retest`은 sealed Confirmed baseline과 remediation binding을 유지하면서 각
  공격 replay ticket을 같은 방식으로 검증한다. 정상 기능 parent regression은 여전히 negative
  proof가 아니며 ticket 원장이 이 의미를 바꾸지 않는다.

coordinator 결과와 common Gate에는 issuer나 claimer가 아니라 최소 read-only verifier
capability만 노출한다. positive/negative Oracle, 모든 기대 반복, raw transcript 재계산과
baseline 결박 규칙은 ADR 0027을 그대로 따른다. durable ticket은 그 규칙을 대체하지 않고,
Gate가 소비한 receipt가 선발급된 한 번의 compilation에서 나왔다는 사실만 추가로 결박한다.

기존 process-local `ReplayExecutionAuthority`와 facade는 단위 테스트, embedded 실행과 이전
호출자 호환성을 위해 유지한다. 공통 Protocol을 구현하되, process-local backend는 재시작
내구성을 주장하지 않으며 production-style KISA confirmation/retest의 표준 backend가 아니다.

## 명시적 제외 사항

- PostgreSQL Replay Ticket repository, Control Plane API, distributed replay queue, Worker lease,
  retry ownership과 fencing은 이 ADR에 포함하지 않는다. ADR 0011의 repository/migration
  경계와 M6-07/M10에서 별도로 설계한다.
- SQLite를 PostgreSQL `SKIP LOCKED` queue 또는 다중 host consensus 대체재로 사용하지 않는다.
- crash 난 claimed ticket을 timeout 뒤 자동 재발급하거나 finalized로 추정하지 않는다.
- Ed25519 등 공개키 서명, key rotation/revocation, 외부 transparency log, 제3자 또는 off-host
  portable proof는 M12와 새 ADR의 범위다.
- durable ticket은 Campaign Scope, Capability Grant, Tool Gateway, Worker isolation, budget,
  rate limit, cancellation, evidence seal 또는 Mode Oracle을 대체하지 않는다.

## 결과

- KISA confirmation과 retest Gate가 실행 process의 mutable memory 없이 ticket finalization을
  다시 검증할 수 있다.
- atomic claim과 burn-on-crash 규칙으로 같은 실행 권한의 동시 또는 crash 후 재사용을 막는다.
- stable DB와 append-only event가 replay Run 밖의 권한 이력을 보존하지만, output state의 보관,
  backup과 접근 제어가 새로운 운영 책임이 된다.
- SQLite 손상이나 schema 불일치는 가용성보다 fail-closed integrity를 우선하므로 수동 복구 또는
  새 ticket 발급이 필요하다.
- 로컬 OS ACL 신뢰를 명시해 process restart 내구성과 portable cryptographic attestation을
  구분한다.

## 승인 및 검증

구현은 자동화된 테스트가 다음을 증명할 때 완료된다.

- 새 원장이 정확한 schema/version과 owner-only 권한으로 생성되고, 기존 process-local backend가
  호환성을 유지한다;
- 발급, 새 프로세스에서 원장을 다시 연 뒤의 claim, 또 다른 프로세스에서 다시 연 뒤의 finalize,
  `mode=ro` verifier 검증이 성공하며 verifier가 DB를 생성하거나 변경하지 않는다;
- 별도 process와 동시 connection이 같은 issued ticket을 claim할 때 정확히 하나만 성공한다;
- claim 뒤 process가 종료된 ticket은 issued로 돌아가지 않고, verifier가 finalized로 인정하지
  않으며 새로운 replay에는 새 ticket과 replay Run이 필요하다;
- exact finalize retry만 idempotent하고 다른 root, artifact, source, compilation 또는 replay Run을
  넣은 재시도와 모든 역방향 상태 전이가 거부된다;
- expired, unknown, issued-only, claimed-only ticket과 Candidate source root, replay Run,
  compilation, Campaign/Tool/Scenario context, final seal root, artifact set substitution이 fail
  closed한다;
- schema version/table/index/append-only protection 손상, row와 canonical compilation bytes 변조,
  digest·typed parse·recanonicalization 불일치가 fail closed한다;
- KISA positive와 negative coordinator가 injected SQLite authority를 사용하고, 실행 authority를
  폐기한 뒤 만든 새 read-only verifier가 각 canonical receipt를 재검증한다;
- positive receipt만 reproduction-backed confirmation으로, baseline-bound negative receipt만
  `fixed` 판정으로 들어가며 normal regression, semantic-only 결과 또는 Worker verdict가 ticket
  존재만으로 승격되지 않는다.
- CLI 수준에서 정상 재시작 검증은 성공하고 missing/wrong ledger, unfinished ticket, 바뀐 replay
  Run 또는 tampered receipt는 성공 Exit Gate를 통과하지 못한다.

## 참고 자료

- [ADR 0011: PostgreSQL 내구성 Control Plane](0011-durable-control-plane.ko.md)
- [ADR 0016: 변조 방지 Run 무결성 체인](0016-tamper-evident-run-integrity.ko.md)
- [ADR 0024: 협력적 실행 취소](0024-cooperative-execution-cancellation.ko.md)
- [ADR 0025: Candidate 검증 원장과 재실행 경계](0025-candidate-validation-ledger-and-replay-boundary.ko.md)
- [ADR 0027: 확인 경계로서의 독립적인 제한적 재현](0027-independent-reproduction-confirmation-boundary.ko.md)
