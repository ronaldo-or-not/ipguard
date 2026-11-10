# 정합성 — 조용한 오답 규명과 fail-closed 거부 (2026-08-08)

**왜 따로 재나.** 누출은 데이터가 나가는 것이고, 정합성 변경은 **조용한
오답**이다. 에러가 없으므로 운영에서 발견이 훨씬 어렵다. 집행률 92%만
봤다면 이 위험은 보이지 않는다.

원시 출력: [`semantics.txt`](semantics.txt)

---

## 1단계 — 위험 규명 (거부 구현 전)

27개 쿼리를 `enforce=off` / `on` 으로 돌려 행 수와 결과 해시를 비교했다.

**조건: PII 를 출력하면서 그 서브쿼리/CTE 출력을 바깥 술어·조인에 쓰는 쿼리.**
해당 패턴 8건 중 8건에서 결과가 바뀌었다.

```sql
SELECT t.id, t.ssn FROM (SELECT id, ssn FROM cust) t
 WHERE t.ssn = '800102-1000001';
--  off: 1행  →  on: 0행        ← 에러 없음

SELECT a.ssn FROM (SELECT id,ssn FROM cust LIMIT 50) a
  JOIN (SELECT id,ssn FROM cust LIMIT 50) b ON a.ssn = b.ssn;
--  off: 50행 →  on: 2500행     ← 50배 폭증
```

**폭증 방향이 더 위험하다.** 마스킹된 값이 전부 같아져 조인이 교차곱이 된다.
필터가 *완화*되므로 "행이 줄어 이상하다"는 신호조차 없고, 집계·리포트 숫자가
조용히 틀어진다.

원인: 서브쿼리 targetList 항목 하나가 **출력과 술어 양쪽에 동시에** 쓰이는데
우리는 그것을 마스킹한다. 출력 경로만 마스킹하려는 의도가 구조적으로 깨진다.

## 2단계 — 감지 후 거부 (구현)

**보안 컨트롤은 결과를 조용히 바꾸면 안 된다.** 변이 후 모든 술어(jointree
전체 = `WHERE` + `JOIN ... ON`, `HAVING`)를 훑어, 마스킹된 서브쿼리/CTE 출력을
가리키는 `Var` 가 있으면 계획을 거부한다.

```
ERROR:  ipguard: masking would change query results
DETAIL: Masked subquery/CTE output column "ssn" is referenced from a predicate
        or join condition. Executing as-is compares the filter against the mask
        value, silently dropping rows or turning the join into a cross product.
HINT:   Move the predicate onto the base table, or drop the column from the
        output list.
```

`GROUP BY`/`DISTINCT`/`ORDER BY` 는 **일부러 막지 않는다** — 서브쿼리가 없어도
`SELECT ssn FROM cust GROUP BY ssn` 이 똑같이 붕괴하므로 우리 설계 탓이 아니라
마스킹의 정의다(intrinsic).

GUC `ipguard.on_conflict = error | warn | allow` (기본 `error`).
`warn`/`allow` 는 **실제 워크로드에서 이 패턴의 빈도를 재기 위한 것**이지
운영용이 아니다.

## 결과

| 분류 | 항목 | 기대대로 | 위반 |
|---|---:|---:|---:|
| **none** (대조군) | 7 | 7 | **0** |
| **scoped** (PII 미출력) | 6 | 6 | **0** |
| **refuse** (반드시 거부) | 5 | **5** | **0** |
| **refuse_over** (과잉 거부) | 2 | 2 | 0 |
| **intrinsic** (불가피) | 7 | 7 | **0** |

**조용한 오답이 되던 5건이 전부 명시적 에러가 됐다.**

**대조군은 지켜졌다.** `SELECT id FROM cust WHERE ssn = '...'` 는 off/on 모두
1행 — 술어의 base-relation `Var` 를 마스킹하지 않는 설계가 유지되고 있다.
`scoped` 6건도 전부 동일: PII 를 출력하지 않으면 마스킹이 발동조차 하지 않는다.

## 과잉 거부 비용 — 2건

`A05 = SELECT t.ssn FROM (SELECT ssn FROM cust) t WHERE t.ssn IS NOT NULL`
`A06 = ... WHERE length(t.ssn) = 14`

둘 다 **실제로는 결과가 보존됐다** — `ipguard_mask` 가 NULL 을 NULL 로 두고
문자 수를 보존하기 때문. 그러나 감지기는 술어가 마스킹된 컬럼을 참조한다는
사실만 알 뿐 **그 술어가 마스킹에 불변인지는 알 수 없다.** 보수적으로 함께
거부한다.

정밀화하려면 술어 연산자별 불변성 분석이 필요하다(`IS NULL`, `length()` 는
불변, `=`, `LIKE`, `<` 는 아님). v1 에서는 하지 않았고, **비용을 2건으로
측정해 기록한다.**

## 빈도 — 좁은 패턴이다

거부 구현 후 다른 스위트를 전부 재실행했다:

| 스위트 | 쿼리 | 새 거부 |
|---|---:|---:|
| 탐지(기본 코퍼스) | 72 | 0 |
| 적대적 1R | 31 | 0 |
| 적대적 2R | 23 | 0 |
| 집행 | 102 | **0** |

**집행 스위트 102개 쿼리에서 거부가 한 건도 발생하지 않았다.** 충돌 패턴은
좁다 — PII 출력 + 같은 서브쿼리 출력에 대한 술어라는 두 조건이 겹쳐야 한다.
다만 이 코퍼스들은 내가 쓴 것이므로 **실제 워크로드 빈도는 여전히 미측정**이다
(`on_conflict=warn` + `pg_stat_statements` 로 재야 한다).

퇴행도 없다: 탐지 95%/퇴행 0/FP 0, 집행 92%/과마스킹 0 모두 유지.

## intrinsic — 고칠 수 없다

| 쿼리 | off | on |
|---|---:|---:|
| `SELECT DISTINCT ssn FROM cust` | 10000행 | **1행** |
| `SELECT ssn, count(*) FROM cust GROUP BY ssn` | 10000행 | **1행** |
| `SELECT ssn FROM cust UNION SELECT ssn FROM cust` | 10000행 | **1행** |
| `SELECT count(DISTINCT ssn) FROM cust` | 10000 | **1** |

**버그가 아니라 마스킹이라는 것의 의미다.** DB 네이티브든 프록시든 뷰 기반이든
동일하게 발생한다. 다만 **카디널리티가 소실되어 통계·리포트가 조용히
틀어진다**는 것은 도입 전에 반드시 고지해야 하고, 그 경로는 마스킹 대상에서
제외하거나 별도 집계 테이블을 쓰도록 안내해야 한다.

---

## 이번에도 측정 도구가 편향돼 있었다 (세 번째)

최초 artifact 6건이 전부 "동일"로 나왔다. **설계가 옳아서가 아니라 그
쿼리들이 PII 를 출력하지 않아 마스킹이 아예 발동하지 않았기 때문이다.**
위험을 재려던 코퍼스가 위험을 재지 못했다 → `scoped` 로 재분류하고 PII 를
출력하는 항목 8건을 새로 만들자 8/8 이 터졌다.

그리고 수동 확인 때 `SELECT count(*) FROM (원본) z` 로 감쌌더니 1행이 나와
"문제 없다"고 잘못 판단할 뻔했다. **래퍼 자체가 PII 출력 여부를 바꿔 마스킹
발동 조건을 바꿨다.** 원본 쿼리를 그대로 돌려서야 0행이 확인됐다.

2R 의 `write` 축 미검증, 집행 채점기의 플레이스홀더 미전개에 이어 세 번째다.
**측정 도구는 대상과 같은 편향을 갖는다.**

## 아직 안 잰 것

- **실제 워크로드에서의 거부율.** 위 8건은 내가 위험을 재려고 만든 것이다.
  `on_conflict=warn` 으로 `pg_stat_statements` 코퍼스를 돌려야 도입 판단이 된다.
- 술어 연산자별 불변성 분석(과잉 거부 2건을 없앨 수 있는 정밀화).
- `UPDATE ... WHERE (마스킹된 서브쿼리 출력)` 같은 DML 정합성.
- 마스킹된 컬럼에 인덱스가 걸린 경우의 계획 변화(성능 축, 이 서버에서 측정 불가).
