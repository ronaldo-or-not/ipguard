# ipguard

**PostgreSQL 쿼리 트리 수준에서 동적 데이터 마스킹을 *집행*하고, 집행할 수 없는 쿼리는 열화(degrade)가 아니라 *거부*하는 연구용 확장.**
(마이데이터 / OpenAPI 고TPS DB 티어 대상, PostgreSQL 16)

> **English TL;DR** — `ipguard` is a research-grade PostgreSQL C extension that enforces
> dynamic PII masking by rewriting the **planned query tree** (resolving every `Var` to its
> base column through expressions, subqueries, CTEs and views) *before* planning — so
> wrapping a column in `substr()`, `||`, or `coalesce()` can no longer leak it, which
> output-byte redaction cannot prevent. It formalizes dynamic masking as a
> **Fidelity / Opacity / Totality trilemma** and occupies the *refuse* vertex that
> Blockaid (OSDI'22, refuses on other grounds) and Mascara (SIGMOD'25, degrades) leave open.
> Through disciplined adversarial self-testing it found **real enforcement-bypass defects in
> its own control path** — most notably that every control GUC was `PGC_USERSET`, so an app
> role (or a SQL injection) could disable all masking with a single `SET` statement
> (fixed → `PGC_SUSET`). **This is a research prototype, not a production product**
> (see Limitations & Roadmap), and the implementation was built with an AI coding agent
> under the author's direction (see Attribution).

---

## 왜 이게 문제인가 (Problem)

마이데이터·오픈API 서버는 커넥션 풀 뒤에서 수많은 최종 사용자의 요청을 소수의 DB 롤로
처리한다. 이때 PII 마스킹은 보통 **출력 바이트를 고쳐 쓰는 방식**(값이 나온 뒤 `***`로
치환)으로 붙는다. 문제는 **표현식 한 번이면 우회된다**는 것이다.

```sql
SELECT ssn             FROM customer;   -- 마스킹됨
SELECT substr(ssn,1,6) FROM customer;   -- 출력 바이트 마스킹은 여기서 뚫린다
SELECT length(ssn)     FROM customer;   -- 길이로 측면 정보가 샌다
```

와이어 레벨 탐지기(RowDescription의 `resorigtbl/resorigcol`만 보는 방식)로 재현하면
**PII 노출 55건 중 21건(38%)만 탐지**된다 — 표현식으로 감싸는 순간 provenance가 0이 되기
때문이다. (`results/wire-baseline.md`)

더 근본적으로, "동적 마스킹"이라는 설계 공간 자체가 **삼자택이(trilemma)**다:

- **Fidelity** — 마스킹된 결과가 쿼리의 원래 의미를 얼마나 보존하는가
- **Mask opacity** — 마스킹이 공격자에게 얼마나 불투명한가(측면 정보 차단)
- **Totality** — 얼마나 넓은 쿼리 집합을 커버하는가

셋을 동시에 최대화할 수 없다. 선행 시스템은 두 꼭짓점을 택한다 — **Blockaid**(OSDI 2022)는
다른 조건으로 *거부*하고, **Mascara**(SIGMOD 2025)는 거부 대신 *열화*한다. **"판정 불가한
쿼리를 거부한다"는 세 번째 꼭짓점이 비어 있었다.** (`results/trilemma.md`)

## 접근 (Approach)

ipguard는 출력이 아니라 **계획된 Query 트리**를 건다.

1. **탐지(Detection)** — 파스·재작성(뷰 전개 포함)이 끝난 Query 트리를 직접 순회해 모든
   `Var`를 base relation 컬럼까지 해석한다. 표현식 안이든, 서브쿼리 너머든, CTE 안이든
   따라간다. 출력 컬럼(클라이언트에 값이 도달)과 술어 참조(부채널)를 **분리 보고**한다.
   → PII 노출 탐지 **회수율 95%**.
2. **집행(Enforcement)** — `planner_hook`에서 **계획 전에** PII `Var`를
   `ipguard_mask(var, kind)` 호출로 치환한다. 마스킹된 값 위에서 계산이 일어나므로
   `length(ssn)`·`substr(ssn,1,6)` 같은 표현식 우회가 **구조적으로** 무력해진다.
   → 집행 **92%**, 과마스킹 **0**. (`results/enforcement.md`)
3. **거부(Release-factorization gate)** — 원본 비교가 공개된 정보(release)로부터 재구성
   가능한지(factor through) 판정한다. 선언된 SQL fragment 위의 제한된 인증서 언어에 대해
   **decidable·sound한 checker**이며, 그 밖은 `unknown → reject`(fail-closed)다.
   (`docs/spec-lineage-and-masks.md`, v0.2.1 동결)

## 핵심 결과 (Key Results)

| 측정 | 결과 | 근거 |
|---|---|---|
| 와이어 기준선 탐지 | 38% (55건 중 21건) | `results/wire-baseline.md` |
| **AST 탐지 회수율** | **95%** | `results/ast-recovery.md`, `ext/ipguard.c` |
| **마스킹 집행** | **92%, 과마스킹 0** | `results/enforcement.md` |
| 커버리지(DETACH·사본) | 정탐 3/3, 오탐 0 | `results/coverage.md` |
| 마스크 능력 레지스트리 | 46/46 (지문 기반 철회 전파) | `results/registry.md` |
| release-factorization gate | 118/118 경계 폐쇄성 | `results/gate.md` |
| 거부율(독립 워크로드 TPC-H) | 0/22 (판정식 on: 5/22) | `results/tpch-refusal.md` |
| 마스킹 뷰 대비 델타 | 필터 3/4 vs 0/4, 우회 3/3 vs 0/3 | `results/view-baseline.md` |

## 적대적 자기검증에서 찾은 결함 (Findings)

> ⚠️ **범위 명시:** 아래는 대부분 **내 확장의 집행 경로를 스스로 적대적으로 red-team해서
> 찾은 결함**이다(제3자 제품의 0-day가 아니다). 마지막 항목만 외부(PostgreSQL Anonymizer)를
> 향한 발견이다.

- **★ 보안 컨트롤이 `SET` 한 줄 거리에 있었다** — 컨트롤 GUC 6개가 전부 `PGC_USERSET`이라,
  `SELECT` 권한만 가진 앱 롤이(또는 **SQL 인젝션이 공짜로**) `SET ipguard.enforce = off`
  한 줄로 마스킹 전체를 끌 수 있었다. 4라운드에 걸쳐 쌓은 집행·판정식·라벨 키잉이 전부 그
  한 줄 아래에 있었다. → **전부 `PGC_SUSET`으로 전환**, 필요 시 `GRANT SET ON PARAMETER`로
  명시 위임(기본 거부). (`results/adversarial5.md`)
- **중첩 집합연산 평문 누출** — 판정식/센티널을 우회해 PII가 평문으로 샜다. (`results/adversarial3.md`)
- **카탈로그·DDL 경로 노출** — 시나리오 10건 중 6건이 평문 노출(1건 수정). (`results/adversarial4.md`)
- **★ 외부 교차검증** — 동일 의미 발산을 **PostgreSQL Anonymizer**에 대해 재현. 하드닝 후에도
  재현되어, 이것이 *내 버그가 아니라 동적 마스킹 접근 전반의 성질*임을 보였다.
  (`results/crosscheck-anon.md`)

## 한계 & 로드맵 (Limitations & Roadmap)

**이것은 연구 프로토타입이다. 다음은 아직 하지 않았거나 측정하지 못했다:**

- **성능 미측정** — 공유 서버 환경이라 이 호스트에서 처리량/지연 측정을 하지 못했다.
- legacy 게이트(R1~R3)는 v0.2.1 기준 불건전으로 표시됨 — 새 게이트와 나란히 재측정이 다음 작업.
- 정리 1·2(구조적 귀납 증명)는 `F_core` 위에서 미완.
- 유저스페이스 KMS 검증 데몬, WAS측 eBPF 에이전트, pgJDBC 바이트코드 에이전트는 미구현.
- 평가는 주로 합성 코퍼스 + TPC-H에서 수행했다(실서비스 트래픽 아님).

## 개발 이력 / 자기정정 (Development Log)

이 repo는 59회 이상 반복된 연구 프로젝트에서 **공개 가능한 부분만 추출한 clean-room 버전**이다
(내부 호스트명 등 환경 정보 제거). 원 프로젝트는 주장을 **스스로 철회·정정하며** 진행했고,
그 정직성 기록을 `docs/dev-notes.md`에 보존한다. 예:

- *"기여는 커넥션 풀을 관통하는 신원 배관이다"* → **철회.** 그 배관은 만들지 않았고,
  선행연구(Oracle Real Application Security, 2013; US 10,049,205)가 이미 해결했음을 확인.
- *"결정 가능한 판정"* → **정정.** 임의 UDF를 포함하면 semantic factorization은 일반적으로
  결정 불가능하다. 정확한 문장: *"a decidable and sound certificate checker for sufficient
  release-factorization conditions over a declared SQL fragment."*

## 빌드 & 설치 (Build)

```bash
# PostgreSQL 16 소스 빌드(sudo 없이) — tools/build-pg.sh 참고
# 확장 빌드/설치 (PGXS)
cd ext && make && make install
```

```sql
CREATE EXTENSION ipguard;

-- ★ 집행은 롤/전역 기본값으로 켠다. 앱이 세션에서 켜는 게 아니다.
--   (GUC는 전부 PGC_SUSET이라 앱 사용자는 SET할 수 없다 — 5R Z01)
ALTER ROLE app_role SET ipguard.enforce = on;
GRANT SELECT ON h5.pii_label TO app_role;

-- 라벨 변경을 계획 캐시에 전파(없으면 커넥션 풀에서 평문이 지속될 수 있다)
SELECT ipguard_watch_labels('h5.pii_label');
```

SQL 단위로 판정을 조회하려면 `ipguard_verdict(query)` / `ipguard_explain(query)`를 쓴다.

## 선행연구 위치 (Related Work)

| 시스템 | 전략 | ipguard와의 차이 |
|---|---|---|
| PostgreSQL Anonymizer / Oracle Data Redaction | 출력/뷰 마스킹 | 표현식 우회에 취약(교차검증으로 재현) |
| Oracle Real App Security (2013) | 세션 신원 전파 | ipguard의 기여는 신원 전파가 아니라 **집행 정확성·거부** |
| Blockaid (OSDI 2022) | 거부(다른 조건) | 삼자택이의 다른 꼭짓점 |
| Mascara (SIGMOD 2025) | 열화(degrade) | ipguard는 열화 대신 **거부(fail-closed)** |

## 저장소 구조 (Layout)

```
ext/      ipguard C 확장 (planner_hook AST 재작성) + SQL/control
corpus/   합성 평가 코퍼스 (스키마 + 우회 표현식 + TPC-H)
tools/    탐지·집행·거부 채점 하네스 (Python/셸/C)
results/  각 측정의 .md 요약 + .txt/.json 원시 산출물(재현 증거)
docs/     명세(동결), 인증서 프로파일, 프로토콜, 개발 노트
```

## 기여도 (Attribution)

연구 방향 설정, 위협 모델링, 평가 설계(측정 순서·대조군·fail-closed 기준), 그리고
적대적 자기검증과 정직한 음성 결과 보고는 **저자(오병훈)의 작업**입니다.
C 확장 구현과 채점 하네스 코드는 **저자의 설계·검증 아래 AI 코딩 에이전트로 구축**했습니다.
즉 *"I designed and directed this work and verified it adversarially; the implementation was
built with an AI coding agent under my direction."*

## License

MIT (코드). 자세한 내용은 [`LICENSE`](LICENSE). 평가 코퍼스는 합성 데이터이며,
외부 데이터셋/제품은 포함하지 않고 참조만 합니다.
