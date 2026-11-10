# Totality 분모의 동결 — `F_core` (2026-08-09)

삼자택이의 **Totality** 를 측정하려면 분모가 있어야 한다. 분모를 나중에
바꿀 수 있으면 *"어려운 질의를 미지원으로 옮겨 성공률을 올렸다"* 는 반론을
그대로 받는다 — 그리고 그 반론은 맞다.

그래서 명세 v0.2.1 §12 에서 `F_core` 를 닫고, 여기서 **재작성 이후 Query
트리로** 세어 동결한다.

원시 출력: [`fragment.txt`](fragment.txt) ·
도구: [`../tools/score_fragment.py`](../tools/score_fragment.py) ·
명세: [`../docs/spec-lineage-and-masks.md`](../docs/spec-lineage-and-masks.md) §12

---

## 세 이름을 구별한다

| 이름 | 어떻게 얻는가 |
|---|---|
| `candidate-F_core` | SQL **텍스트** 휴리스틱 (`tools/classify_fcore.py`) — **상한** |
| **`F_core`** | **`ipguard_fragment()`, 재작성 후 Query 트리** — 이것이 분모 |
| `F_impl` | 확장이 실제로 처리하는 범위 — 보장을 주장하지 않는다 |

## 동결된 분모

| 코퍼스 | `F_core` | `F_impl` | 밖의 사유 (**non-exclusive**) |
|---|---:|---:|---|
| 삼자택이 | **10/10** | 10/10 | — |
| 발산 코퍼스 | **37/45** | 45/45 | window function 8 |
| TPC-H | **13/22** | 22/22 | 상관 스칼라 서브쿼리 6, `NOT EXISTS` 2, `NOT IN` 1, outer join 1 |

**TPC-H 의 사유 합계 10 ≠ 밖 질의 9 다.** `Q22` 가 `NOT EXISTS` 와 상관 스칼라
서브쿼리를 둘 다 쓴다. **사유 수로 질의 수를 세면 안 된다.**

밖으로 나간 TPC-H 질의:

```
Q2  scalar subquery     Q13 outer join          Q20 scalar subquery
Q11 scalar subquery     Q15 scalar subquery     Q21 NOT EXISTS
Q16 NOT IN / <> ALL     Q17 scalar subquery     Q22 scalar subquery + NOT EXISTS
```

outer join 은 **`Q13`** (`customer LEFT OUTER JOIN orders`) 하나다. `Q15` 는
outer join 이 아니라 `total_revenue = (SELECT max(total_revenue) FROM revenue0)`
때문에 나간다 — `revenue0` 은 `GROUP BY` 집계 뷰다
([`../corpus/tpch-schema.sql:65`](../corpus/tpch-schema.sql)).

## 텍스트와 트리가 일치했다 — 그러나 그게 요점이 아니다

세 코퍼스 **전부에서 불일치 0** 이었다. 이걸 "텍스트 휴리스틱으로 충분하다"
로 읽으면 안 된다. 일치한 이유는 **이 코퍼스들이 뷰를 쓰지 않기 때문**이다.

대조군을 박아 뒀다:

| | 텍스트 | 트리 |
|---|---|---|
| `SELECT id FROM fc_outer` (뷰 안에 `LEFT JOIN`) | 안 | **outer join** |
| `SELECT id, rn FROM fc_win` (뷰 안에 `row_number()`) | 안 | **window function** |
| `SELECT id FROM fc_plain` (평범한 뷰) | 안 | 안 |

텍스트는 셋 다 "안" 이라고 답한다 — **뷰 이름밖에 안 보이기 때문이다.**
분모를 텍스트로 잡으면 정리의 보호 범위를 **과대하게 선언**하게 된다.

## 구현에서 걸린 것 — `NOT IN` 은 `ALL_SUBLINK` 가 아니다

처음에 `NOT IN` 을 `ALL_SUBLINK` 로만 잡았더니 **통째로 미탐**됐다.
PostgreSQL 문법은 `x NOT IN (subquery)` 를 이렇게 만든다:

```
NOT ( x = ANY (subquery) )      -- BoolExpr(NOT) 위의 ANY_SUBLINK
```

`ALL_SUBLINK` 로 오는 것은 명시적 `<> ALL (subquery)` 뿐이다. `NOT EXISTS` 도
같은 모양(`BoolExpr(NOT)` 위의 `EXISTS_SUBLINK`)이라 함께 잡는다.

`(a,b) IN (subquery)` 도 `RowExpr` 로 남지 않는다 — 파서가 `testexpr` 를
`RowCompareExpr` 또는 `OpExpr` 의 `AND` 체인으로 이미 바꾼다.

**둘 다 텍스트 정규식으로는 알 수 없고 트리에서만 보인다.**

## `F_core` 밖은 어떻게 쓰는가

정리 1·2 의 보호를 받지 않는다. 그러나 **측정을 멈추지는 않는다** —
`F_impl` 에서 계속 재고, 논문에서 두 분모를 **나란히** 보고한다.

```
TPC-H 거부율:  5/22 (F_impl)  ·  ?/13 (F_core)
```

`F_impl` 만 쓰면 보장 범위를 넘어선 주장이 되고, `F_core` 만 쓰면 어려운
질의를 숨겼다는 반론을 받는다.

### window 8건은 약점이 아니라 **명시된 후속 범위**다

발산 코퍼스에서 나간 8건은 전부 window function 이고, 그중 `DV33~DV36`·`DV40`
은 5R 에서 추가한 `lag`/`lead`/`row_number` 계열이다. 이것들이 조용한 오답의
주요 원천이었다.

논문에서는 이렇게 **분리**해서 쓴다:

| | 범위 | 주장 |
|---|---|---|
| 정리 1·2 | `F_core` | fidelity / scoped opacity 를 증명한다 |
| 후속 | **`F_impl \ F_core`** | 가장 위험하지만 **아직 인증하지 않는다** |

window function 은 `ORD` 를 출력 셀로 **직접 나르는** 별도 축이라(§2 의
effect→sink 표에서 `ORD → window/ordered-aggregate cell`), 관계 연산의 귀납
구조와 다른 규칙이 필요하다. 그것을 `F_core` 에 억지로 넣으면 정리가 약해지고,
빼고 침묵하면 측정이 부정직해진다. **범위로 선언하고 계속 측정한다** —
`F_impl` 에서 이 8건이 어떻게 다뤄지는지는 [`divergence.md`](divergence.md) 에
그대로 남아 있다.

## 한계

- `ipguard_fragment()` 도 완전하지 않다. 등록되지 않은 UDF 의 `total` 여부는
  카탈로그로 알 수 없다 — `volatile` 은 보지만 *"정의역 전체에서 오류가
  없는가"* 는 레지스트리(명세 §5)가 답할 문제다.
- 재작성은 보되 **계획**은 보지 않는다. 계획기가 SubLink 를 semi/anti join 으로
  바꾸는 것은 이 판정 뒤의 일이라 무관하다.
- 분모는 이 세 코퍼스에 대해서만 동결됐다. 새 코퍼스를 추가하면 같은 도구로
  다시 세야 한다.

## 재현

```bash
python3 tools/score_fragment.py      # 트리 판정 (서버에서)
python3 tools/classify_fcore.py      # 텍스트 상한 (로컬에서도 된다)
```
