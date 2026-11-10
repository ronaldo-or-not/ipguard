# 실제 워크로드 거부율 — 독립 표준 워크로드 (2026-08-08)

**문제:** 지금까지의 코퍼스는 전부 내가 썼다. 거부율이 낮게 나와도
"내가 안 걸리게 썼기 때문"일 수 있다. 그리고 이 공유 서버의 다른 사용자
데이터는 볼 수 없다(봐서도 안 된다).

**선택:** **TPC-H 22개 쿼리.** 표준화 기구가 만든 것이고, 서브쿼리·CTE·상관
서브쿼리가 밀집해 있어 artifact 패턴(마스킹된 서브쿼리 출력을 술어가 참조)에
가장 가혹하다. 거부는 계획 시점에 일어나므로 `EXPLAIN` 만으로 측정된다 —
데이터 생성이 필요 없다.

원시 출력: [`tpch-refusal.txt`](tpch-refusal.txt)

---

## 결과

| 라벨 조건 | 마스킹 발동 | **거부** | 거부율 |
|---|---:|---:|---:|
| **현실적 PII 라벨** (8컬럼: 성명·주소·전화·잔액) | 7/22 | **0** | **0%** |
| **전 컬럼 PII** (61컬럼, 구조적 상한) | 22/22 | **1** (Q15) | **5%** |

22개 전부 파싱·계획에 성공했다(측정 제외 0건).

## 왜 0인가 — 구조가 드문 게 아니라 PII가 그 자리에 안 온다

두 조건을 분리해 재기 위해 **모든 컬럼을 PII로 라벨하고** 다시 돌렸다.
그래도 거부는 **Q15 하나뿐**이다. 즉:

1. **패턴의 구조적 빈도 자체가 낮다** — 22개 중 1개(5%)만이 "서브쿼리/뷰의
   출력 컬럼을 술어가 참조"하는 형태다. TPC-H 는 서브쿼리를 많이 쓰지만,
   대부분 `EXISTS`/`IN`/스칼라 집계로 쓰이고 **그 출력 컬럼을 다시 필터하지는
   않는다.**
2. **현실적 라벨에서는 그마저도 0이 된다** — Q15 가 술어에서 참조하는 것은
   `total_revenue`(매출 집계)이지 성명·주소·전화가 아니다.

**PII 컬럼은 출력하고 그룹핑하지, 필터하지 않는다.** 필터는 키·날짜·코드에
걸고 성명·주소는 화면에 뿌린다. 이건 TPC-H 의 우연이 아니라 데이터 모델링의
일반적 성질이며, 그래서 이 패턴이 드물다.

실측 뒷받침: PII 를 출력하는 7개 쿼리(Q2·Q10·Q15·Q18·Q20·Q21·Q22) 중
Q10 은 `c_name, c_acctbal, c_address, c_phone` 를 **GROUP BY** 하고,
Q22 는 `substring(c_phone…)` 를 그룹 키로 쓴다 — 둘 다 마스킹으로 결과가
바뀌지만(intrinsic) **술어가 아니므로 거부되지 않는다.** 설계 의도대로다.

## 양성 대조군 — 0%가 감지기 고장이 아님을 확인

0% 는 감지기가 죽어 있어도 나온다. 반드시 확인했다:

```sql
SET ipguard.label_schema='tpch'; SET ipguard.enforce=on;
EXPLAIN SELECT t.c_name, t.c_acctbal
          FROM (SELECT c_custkey, c_name, c_acctbal FROM customer) t
         WHERE t.c_name = 'Customer#001';
-- ERROR: ipguard: masking would change query results
--        Masked subquery/CTE output column "c_name" is referenced from a predicate…

EXPLAIN SELECT a.c_name FROM (SELECT c_custkey, c_name FROM customer) a
          JOIN (SELECT c_custkey, c_name FROM customer) b ON a.c_name = b.c_name;
-- ERROR: (동일)
```

TPC-H 스키마에서도 감지기는 정확히 발화한다. **0% 는 유효한 측정이다.**

## 종합 — 지금까지의 모든 워크로드

| 워크로드 | 쿼리 | 거부 | 출처 |
|---|---:|---:|---|
| 기본 코퍼스(탐지) | 72 | 0 | 내가 씀 |
| 적대적 1R | 31 | 0 | 내가 씀 |
| 적대적 2R | 23 | 0 | 내가 씀 |
| 집행 스위트 | 102 | 0 | 내가 씀 |
| **TPC-H** | **22** | **0** | **표준화 기구** |
| 정합성 코퍼스(위험 재현용) | 27 | 5 | 내가 씀, **거부시키려고 만듦** |

**의도적으로 만든 것 외에는 거부가 한 건도 없다.** fail-closed 의 운영 비용이
낮다는 최초의 독립적 근거다.

---

## 이 측정의 한계 — 그대로 남긴다

1. **도메인이 다르다.** TPC-H 는 분석계, 타겟은 마이데이터/OpenAPI 거래계다.
   분석계가 서브쿼리를 훨씬 많이 쓰므로 **거부율의 상한**으로 읽어야 한다.
   거래계는 더 낮을 것으로 예상되지만 **측정하지 않았다.**
2. **표본이 22개다.** 통계적 신뢰구간을 말할 크기가 아니다.
3. **쿼리를 내가 전사했다.** 22개 전부 파싱·계획에 성공했으므로 구조적으로는
   타당하지만, 공식 명세와 문자 단위로 동일하다고 보증할 수 없다. 측정에
   중요한 것은 *구조*(서브쿼리 배치, 술어 위치)이고 그것은 충실하다.
4. **PII 라벨 배치는 내 판단이다.** `c_name`/`c_address`/`c_phone`/`c_acctbal`
   를 PII 로 본 것은 합리적이나, 다른 배치(예: `o_comment`, `c_comment` 포함)
   에서는 결과가 달라질 수 있다.
5. **여전히 진짜 프로덕션 워크로드가 아니다.** `pg_stat_statements` 기반
   실측이 최종 근거이며, 그것은 도입 대상 기관의 협조 없이는 불가능하다.
   `ipguard.on_conflict=warn` 이 그 용도로 준비되어 있다.

## 재현

```bash
psql -d ipdev -f corpus/tpch-schema.sql
python3 tools/score_tpch.py corpus/tpch-queries.sql
```
