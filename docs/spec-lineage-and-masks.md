# 명세: release-factorization gate (v0.2.1, 동결 2026-08-09)

이 문서는 **코드보다 먼저** 고정해야 하는 정의를 담는다. 지금까지 "마스킹이
결과를 바꾼다"를 측정해 왔지만, **무엇을 기준으로 바뀌었다고 하는지**와
**어떤 마스크에 대해 그런지**를 명세하지 않았다. 그 둘이 없으면 이후의 규칙과
증명이 서로 다른 대상을 말하게 된다.

> 상태: **동결.** 동결 심사에서 다섯 항목이 지적됐고 전부 반영했다.
> 이제 §12 의 fragment 와 Totality 분모가 고정됐으므로 레지스트리로 넘어간다.

### 동결 심사에서 닫은 것 (2026-08-09)

| | 지적 | 반영 |
|---|---|---|
| 1 | `Q10` 은 증명이 아니라 witness | §2 — 주장을 witness 수준으로 낮추고 **양성 대조군** 역할을 명시 |
| 2 | `M(D1)=M(D2)` 의 동등성이 미정의 | §6.5 — 보존 대상 5가지를 명시 |
| 3 | `δ_Q` 를 사후 선택하면 정리가 공허 | §3.5 — `Declass(source,effect,sink,observation)` 인증서, **질의 실행 전 고정** |
| 4 | factor-through 를 "결정" 이라 쓰면 안 됨 | §5.5 — **decidable sound certificate checker** 로 하향 |
| 5 | 오류·부수효과 관찰 모델 미고정 | §1.5 — 코어 정리를 pure/total/deterministic 으로 제한, timing 은 범위 밖 |

---

## 1. 관찰 모델 — 결과 도메인

결과를 **컨테이너 + 셀**로 둔다. 순서는 **조건부로만** 관찰에 포함한다.

```
Res(Q, D) =
    Bag<Row>                       최상위 ORDER BY 가 없으면
    OrderedBag<Row, ⪯_K>           최상위 ORDER BY K 가 있으면
```

**`Seq<Row>` 로 두면 안 된다.** 최상위 `ORDER BY` 가 있어도 **정렬 키가 같은
행(peer group) 사이의 순서는 SQL 의미상 보장되지 않는다.** 단일 sequence 로
정의하면 실행계획이 바뀐 것만으로 fidelity 위반이 된다.

`OrderedBag<Row, ⪯_K>` 는 **peer group 내부의 순열을 동일하게 본다.**
`ORDER BY secret, id` 처럼 키가 전순서를 만들 때만 일반 sequence 와 같아진다.

최상위 `ORDER BY` 가 없으면 물리적 반환 순서는 관찰 동치에서 **제외**한다
(permutation quotient = bag 으로 비교). 그러지 않으면 heap scan 순서나 계획
변경만으로 fidelity 가 깨져 정리가 무의미해진다.

```
Mout(Bag[r1,…,rn])            = Bag[redact(r1),…,redact(rn)]
Mout(OrderedBag[r1,…,rn], ⪯_K) = (OrderedBag[redact(r1),…,redact(rn)], ⪯_K)
```

**둘째 줄에서 `⪯_K` 는 그대로 둔다.** 순서는 *원본* 키로 매겨진 것이고 마스킹은
셀만 바꾼다 — 마스킹된 값으로 다시 정렬하지 **않는다.** 이것이 `Ideal` 이
"원본으로 계산하고 출력만 가린다" 는 뜻이다.

**`Mout` 은 컨테이너를 보존하는 cell map 이다.** 마스킹은 셀에만 작용할 수
있고, 컨테이너(행 수·다중도·보장된 순서)는 **redaction 할 수 있는 대상이
아니다** — 모든 셀을 가려도 반환 행 수와 순서는 그대로 나간다.

설명용으로는 `Shape` / `Cells` 라 부르되, 형식적으로는 위 컨테이너 정의를 쓴다.

  - `Shape` = 컨테이너 종류, 행 수, 다중도, **보장된** 순서
  - `Cells` = 각 행의 출력 셀

### 서브쿼리의 `ORDER BY`

- `LIMIT`/`OFFSET`·window·ordered aggregate 에 영향을 주면 그 효과를 추적한다
- 바깥 연산에 아무 영향이 없으면 **최종 순서 보장으로 취급하지 않는다**
- outer query 에 `ORDER BY` 가 없으면 subquery 순서가 최종 관찰 순서를 보장한다고
  **가정하지 않는다**

### v0.2.1 증명 범위에서 제외

- `ORDER BY` 없이 `LIMIT`/`OFFSET` 만 있는 질의
- **동률이 있는 `ORDER BY … LIMIT`** — peer group 안에서 어느 행이 뽑힐지가
  비결정적이다. **정렬 키가 전순서임이 증명된 경우만** 지원한다.

둘 다 엄밀히 다루려면 가능한 결과들의 **집합**을 돌려주는 비결정적 의미론이
필요하고, 그건 v0.2.1 범위 밖이다.

> **이 정의의 대가**: 현재 outer-query V3 는 **최상위 정렬 질의에서 fidelity 를
> 증명할 수 없다.**
> ```sql
> SELECT redact(q.c) FROM ( SELECT c FROM t ORDER BY secret ) q;
> ```
> 바깥에 `ORDER BY` 가 없으므로 SQL 의미상 안쪽 순서 보존이 보장되지 않는다.
> 정렬까지 다루려면 executor 최종 투영이거나, 정렬 계약을 바깥까지 전달하는
> 구조여야 한다. **v0.2.1 에서도 이것을 미해결로 명시한다.**

## 1.5 오류와 부수효과 — 무엇을 관찰로 세는가

마스킹 **위치**가 바뀌면 값만 달라지는 것이 아니라 **오류의 발생 여부까지**
달라진다. 세 예가 전부 실재한다.

```sql
1 / secret                    -- V1: 마스크가 0 이면 division_by_zero, V3: 원본으로 계산
cast(secret AS integer)       -- V1: '****' 캐스팅 실패, V3: 성공 후 redact
volatile_udf(secret)          -- 호출 횟수·인자가 위치마다 다르다
```

이걸 고정하지 않으면 정리 1(fidelity)이 **오류를 내는 질의에서 자동으로 거짓**이
된다. 두 선택지 중 후자를 택한다.

| 선택 | 내용 | 채택 |
|---|---|---|
| (a) | `Res` 에 `Error(e)` 를 추가하고 오류 호환성까지 증명 | ✗ 마스크마다 오류 대응표가 필요해 현실적이지 않다 |
| **(b)** | **코어 정리의 함수·마스크를 `pure ∧ total ∧ deterministic` 으로 제한** | **✓** |

```
F_core 의 모든 스칼라 함수 f, 집계 A, 마스크 m 에 대해
    pure           부수효과 없음 (§12 의 volatile 배제와 같은 조건)
    total          정의역 전체에서 오류 없이 값을 낸다
    deterministic  같은 입력 → 같은 출력 (§5 determinism)
```

`total` 은 **레지스트리가 지는 의무**다. `1/x`, `cast(text AS integer)`,
`substr` 의 음수 인자처럼 부분함수인 것은 `mask_function_compatibility` 에
등록될 수 없고, 따라서 그것이 마스킹 lineage 위에 오면 `unknown → reject` 로
떨어진다. **정리는 오류를 다루지 않는 대신, 오류를 낼 수 있는 질의를 수락하지
않는다.** 건전성은 유지되고 대가는 acceptance 다.

### 명시적으로 범위 밖 — 위협 모델의 경계

정리가 다루는 것은 **extensional SQL 결과**다 — 셀 값, 다중도, 그리고 §1 이
보장한다고 정의한 순서까지.

> *The theorem concerns extensional SQL results, including multiplicity and
> guaranteed ordering. Timing, plans, resource consumption, and
> transport-level behavior are outside the threat model and require separate
> side-channel defenses.*

- **timing** — 실행 시간, 행별 전송 시간, 계획 선택 시간
- **plan 관찰** — `EXPLAIN`, `pg_stat_statements`, 버퍼 히트 수
- **자원 관찰** — 임시 파일 크기, 메모리 사용, 정렬 spill
- **전송 계층** — 행 전달 순서·타이밍, 커서 fetch 경계

이것들은 `Obs` 에 포함하지 않는다. **별도의 부채널 방어가 필요한 영역**이고,
이 명세는 그것을 제공하지 않는다.

> 앞 판에는 *"timing 을 관찰에 넣으면 세 지점 모두 opacity 가 0 이 되어
> 삼자택이가 무의미해진다"* 고 썼다. **증명하지 않은 강한 주장이라 내렸다.**
> 계획이 다르면 구별 가능성이 생긴다는 것과, 실제로 세 지점 전부가 모든
> witness 에서 구별된다는 것은 다른 명제다. 제외의 근거는 위협 모델 경계이지
> 측정 결과가 아니다.

## 2. lineage 를 **effect 집합**으로

"structural = Shape 에 영향" 으로 등치하면 **너무 좁다.** 다음은 최종 행 수를
바꾸지 않는데도 출력 셀을 바꾼다:

```sql
row_number() OVER (ORDER BY secret)
count(DISTINCT secret)
array_agg(id ORDER BY secret)
```

민감값이 **관계 구조(동치류·순서·다중도)를 거쳐 셀에 도달**한 것이다.
그래서 lineage 를 다섯 effect 로 표현한다.

```
VAL    민감값 또는 그 변환이 셀 값에 전달됨
EQ     동치류·partition·중복 제거에 영향
ORD    순서·순위·ordered evaluation 에 영향
CARD   행 선택·다중도·카디널리티에 영향
```

**`DEC` 는 effect 종류가 아니다.** `VAL/EQ/ORD/CARD` 와 나란히 두면 "민감
술어니까 허가됨" 이라는 이유로 너무 많은 누출을 면제하게 된다. §3.5 참조 —
declassification 은 **effect 를 지우는 표지가 아니라 특정 effect edge 를 특정
관찰 수준에서만 discharge 하는 정책 증명서**다.

`structural := EQ ∪ ORD ∪ CARD` 로 정의하되, **structural 이 출력 셀로 전파될
수 있음**을 명시한다(`count(DISTINCT s)` 가 그 예다).

| SQL 문맥 | effect |
|---|---|
| `SELECT substr(secret,…)` | `VAL` |
| `GROUP BY secret` | `EQ`, `CARD` (키를 출력하면 `VAL` 추가) |
| `SELECT DISTINCT secret` | `EQ`, `CARD`, `VAL` |
| `count(DISTINCT secret)` | `EQ`, `CARD` 가 출력 셀로 요약됨 |
| 최상위 `ORDER BY secret` | `ORD` |
| `ORDER BY secret LIMIT n` | `ORD`, `CARD` |
| `row_number() OVER (ORDER BY secret)` | `ORD` 가 출력 셀에 영향 |
| `PARTITION BY secret` | `EQ` |
| `WHERE secret = ?` | `CARD` — δ_Q 가 행 포함 여부를 discharge 한다 |
| `JOIN ON secret = ?` | `CARD` — δ_Q 가 매칭 결과를 discharge 한다 |

### effect → **관찰 sink** (effect 만으로는 부족하다)

`ORD` 가 있다고 항상 누출되는 것이 아니다. **어디로 흘러 나가는지**를 봐야 한다.

### sink 의 정확한 정의

셋이 겹쳐 보이지만 **다른 관찰**이고, 정책이 각각 따로 허가한다:

| sink | 무엇을 관찰하는가 |
|---|---|
| `MEMBERSHIP` | 어떤 **구별 가능한 row value/identity** 가 존재하는가 |
| `MULTIPLICITY` | 각 observable row 가 **몇 번** 존재하는가 |
| `ROW_COUNT` | multiplicity 의 **총합** |
| `FINAL_ORDER` | 보장된 최종 순서 |
| `CELL` | 출력 셀 값 |

### ★ sink 는 구문별로 열거하면 안 된다 — **transfer function** 으로 닫는다

구문마다 손으로 sink 를 적으면 **계속 빠진다.** 실측으로 다섯 번 연속
빠졌다(`EQ→CELL`, `ORD→MULTIPLICITY`, `ORD→바깥 CELL`, `HAVING→바깥 CELL`,
집합연산`→바깥 CELL`). 대신 각 질의 수준이 세 요약을 돌려주게 한다:

```
bag_in    집계에 **들어가는** 행 집합을 바꾸는 effect
bag_out   이 질의의 **출력** bag 을 바꾸는 effect
ord       이 질의의 **출력 순서**를 바꾸는 effect
```

| 연산자 | 전파 |
|---|---|
| `WHERE` / semi-join / `JOIN ON` | predicate `CARD` → `bag_in` |
| projection | 입력 `bag` 유지, 표현식 의존 → `cell` |
| `GROUP BY K` | `EQ(K)` → `bag_out`, **그리고 집계 `CELL`** |
| 스칼라 집계 | `bag_in` → 집계 `CELL`. 최종 shape 는 **1행 고정** |
| `GROUP BY` + 집계 | `bag_in` → 집계 `CELL` **그리고** `bag_out` (그룹이 사라질 수 있다) |
| aggregate `FILTER` | filter `CARD` → 그 집계 `CELL` |
| aggregate 내부 `ORDER BY` | `ORD` → 그 집계 `CELL` |
| `HAVING` | `CARD` → `bag_out` (집계 **뒤**라 같은 수준 `CELL` 은 아니다) |
| `DISTINCT` | `EQ` → `bag_out` |
| 최종 `ORDER BY` | `ORD` → `ord` |
| `LIMIT`/`OFFSET` | `ord` → `bag_out` |
| 비-`ALL` 집합연산 | row `EQ` + 양쪽 `bag_out` → 출력 `bag_out` |
| 서브쿼리 | 자식 `bag_out` → 부모 `bag_in` |

**서브쿼리 경계를 넘는 합성이 자동으로 잡힌다** — 이것이 손 열거로는 안 되던
부분이다.

### value path 도 같은 구조여야 한다

structural path 만 합성적이고 value path 가 즉석 walker면, 중첩 질의에서 같은
누락이 재발한다. 표현식은 **의무를 만들지 않고 요약을 돌려준다**:

```
ExprProof =
    Public
  | Source(mask_instance)
  | Apply(function_context, ExprProof[], output_mask)
  | Aggregate(aggregate_context, ExprProof[], output_mask)
  | Unknown

QuerySummary { cells[], bag_in, bag_out, ord }
```

**사슬이 아니라 트리여야 한다.** 다중 입력 표현식은 DAG 다:

```
concat(lower(ssn), upper(birth))
  Apply concat
  ├─ Apply lower  └─ Source ssn(mask_ssn)
  └─ Apply upper  └─ Source birth(mask_birth)
```

평탄한 `[lower, upper, concat]` 로는 (a) `upper` 가 어느 입력 mask 를
소비하는지 (b) `concat` 의 인자별 mask 가 무엇인지 (c) 두 branch 의 결과
mask 가 무엇인지를 **증명할 수 없다.**

`f(m(x)) = r_out(f(x))` 이므로 합성은 **출력 마스크를 타고** 올라간다:

```
lower(m(x))         = r1(lower(x))
upper(r1(lower(x))) = r2(upper(lower(x)))      <- r1 에 대한 인증서가 필요
```

그래서 각 `Apply` 는 인증 통과 시 **출력 마스크의 `mask_id`** 를 돌려주고
부모가 그걸로 다시 조회한다. 인자 위치(`pos=i`)가 인증서 키에 들어가야
`f(a,b)` 와 `f(b,a)` 가 구별된다. **마스킹된 입력이 둘 이상이면 공통 출력
마스크를 증명할 수 없어 `UNKNOWN`** 이다(집합연산에서 서로 다른 mask state 가
합쳐질 때도 같다).

### bare 출력의 baseline — `MASK_APPLY`

`SELECT secret FROM t` 에는 commutation 의무가 **없다** — `Mout` 이 같은
마스크를 직접 적용하기 때문이다. 그러나 **MaskInstance 자체의 코어 전제까지
생략하면 안 된다:**

```
MASK_APPLY(mask_instance) := deterministic ∧ total ∧ 지문 일치
```

생략하면 **미등록 UDF 나 변경된 마스크가 bare output 으로 인증 없이
흘러나간다.**

| 표현식 | transfer |
|---|---|
| 공개 `Var`/`Const`/`Param` | `PUBLIC` |
| 라벨된 `Var` | `MASKED(MaskInstance)` |
| `f(e1,…,en)` | 입력 요약 + chain 에 `f` 추가 |
| cast / operator | 같음. 해당 compatibility 가 있어야 결과 mask |
| `CASE` / `COALESCE` | 조건과 **모든 branch** 의 source 를 합쳐 `VAL` lineage. **`UNKNOWN`** |
| `Aggref` | aggregate compatibility + `bag_in` structural deps |
| 서브쿼리 출력 `Var` | 자식 `cells[attno]` 를 **그대로 전달** |
| 집합연산 | 같은 위치 cell 요약을 합성 |
| **미지원 노드에 라벨 source** | **`UNMODELED_EXPR` → 거부** |

**최종 observable target 에서만 `VAL → CELL` 을 발행**하고 중간 레벨은
`cells[]` 를 부모로 넘긴다. 그래야

```sql
SELECT upper(x) FROM (SELECT lower(secret) AS x FROM t) s
```

가 `[lower, upper]` **합성 경로 하나로** 인증된다 — 안팎을 따로 인증하거나
경계에서 lineage 를 잃지 않는다. 인증은 **사슬 전체**를 검사한다: 마지막
변환만 보면 `lower` 가 무인증 통과한다.

`CASE WHEN secret … THEN grade ELSE dept END` 은 행 수를 바꾸지 않지만 출력
셀을 직접 바꾼다 — **`CARD` 가 아니라 control lineage → `VAL`** 이고, 값
변환이 아니므로 commutation 인증서로 해소되지 않는다(`UNKNOWN` → 거부).

### 경계 폐쇄성 — summary 마다 네 조건

transfer table 을 **만든 것**과 코드가 **그 표대로 도는 것**은 다르다.
`cells[]` 가 실제로 서브쿼리 경계에서 끊겨 있었다. 그래서 각 summary
(`cells[]`·`bag_out`·`ord`)마다 넷을 확인한다:

| 조건 | 의미 |
|---|---|
| propagation | 자식 effect 가 부모 sink 까지 도달 |
| missing proof | 자식 인증서 삭제 시 거부 |
| context preservation | 다른 연산자·상수·collation 인증서로 통과하지 않음 |
| erasure | 부모가 관찰을 지우면 의무도 사라짐 |

★ **라벨 접촉 판정도 게이트 자신의 순회로** 해야 한다. 별도의 사전검사를
두면 그 탐색 범위가 게이트보다 좁을 수 있고, 실제로 그랬다 — 민감 컬럼이
서브쿼리 술어에만 있으면 게이트가 **아예 돌지 않았다.**

### 종료 조건 — 실험 개수가 아니라 **exhaustive fail-closed transfer table**

1. `F_core` 의 모든 expression node 가 명시적 transfer rule 을 가진다
2. 라벨 source 를 가진 미처리 node 는 **무조건 `UNMODELED_EXPR`**
3. 모든 query boundary 에서 `cells[]`·`bag_out`·`ord` 가 부모로 전파된다

셋이 만족되면 완전성을 witness 개수로 주장하지 않아도 된다 — **지원 AST 에
대한 전수 fail-closed 표**로 방어한다.

### 행 **수**를 바꾸는가, **어느 행인지**만 바꾸는가

```
CARD(WHERE) / EQ(DISTINCT·GROUP BY)   행 수가 달라진다
ORD + LIMIT n                          항상 min(n,|입력|) 행. 어느 행인지만 달라진다
```

구별하지 않으면 `SELECT 'x' … ORDER BY secret LIMIT 3` 이 `ROW_COUNT` 로
거부된다 — 행 수는 **공개 입력**이 정하는데도. 그래서:

```
count_affecting      -> ROW_COUNT, MULTIPLICITY  (행이 구별 안 돼도 관찰됨)
!count_affecting     -> MULTIPLICITY, MEMBERSHIP (행이 **구별될 때만**)
```

| effect | 도달 가능한 관찰 |
|---|---|
| `VAL` | 출력 cell |
| `EQ` | cell, multiplicity, membership, row count |
| `ORD` | 최종 order, membership, multiplicity, **집계 cell** |
| `CARD` | row count, multiplicity, **membership**, cell |

> **`CARD` 의 sink 는 넷이다.** 술어는 행 **수**뿐 아니라 **어느 공개 행이
> 남는지**(`MEMBERSHIP`)도 누출하고, 그 선택이 집계로 흐르면 **셀 값**
> (`CELL`)까지 바꾼다. `ROW_COUNT` 만 보면 둘 다 놓친다:
>
> ```
> D1:(1,a),(2,b)  D2:(1,b),(2,a)   SELECT id FROM t WHERE secret='a'
>   -> {1} vs {2}, 행 수는 둘 다 1          MEMBERSHIP
> D1:(1,10,a),(2,20,b) D2:(1,10,b),(2,20,a) SELECT sum(amt) … WHERE secret='a'
>   -> 10 vs 20, 최종 shape 는 둘 다 1행    CELL
> ```
>
> 반대로 **스칼라 집계면 shape sink 가 소거된다** — 내부 선택 카디널리티는
> `CARD` **effect** 이지 최종 결과 shape 의 `ROW_COUNT` **sink** 가 아니다.

**실측 witness:**

```
Q10  SELECT 'x' FROM t ORDER BY secret        → V1·V2·V3 전부 불투명
Q9   SELECT id  FROM t ORDER BY secret, id    → V2·V3 누출
```

`Q10` 은 `ORD` 가 있지만 모든 행이 관찰상 동일해 **sink 가 없다.** `Q9` 는
공개 컬럼 `id` 가 sink 라서 즉시 구별된다. 그래서 `Q9` 는 `ORD → final order`,
`Q6` 은 `ORD → top-k membership → CARD` 로 정확히 잡힌다.

**`resjunk` 여부는 완전히 무관하다** — 이것이 현재 R3b 가 틀린 이유다(§8).

> **`Q10` 은 증명이 아니다.** 실험 하나가 *"sink 가 없으면 항상 안전하다"* 를
> 보이지는 못한다. 논문 표현은 이 수준으로 쓴다:
>
> *Q10 empirically demonstrates that sensitive `ORD` influence need not be
> observable when projection erases row distinguishability.*
>
> "sink 가 없으면 안전" 은 §6 의 정리에서 **구조적 귀납으로** 증명해야 할
> 명제이고, `Q10` 은 그 명제가 비자명하다는 것을 보이는 witness 다.

### `Q10` 은 새 게이트의 **양성 대조군**이다

`Q10` 의 진짜 역할은 두 게이트를 가르는 것이다.

| 게이트 | `Q10` | `Q9`/`Q6` | 성격 |
|---|---|---|---|
| `ORD` 를 보면 일괄 거부 | **거부** | 거부 | 건전하지만 **지나치게 불완전** |
| 현재 R3b (masked-ness) | 수락 | **수락 = 누출** | **불건전** |
| `ORD → observable sink` | **수락** | 거부 | 건전하고 더 정밀 |

즉 `Q10` 은 새 기법이 "무조건 더 거부해서" 안전해진 것이 아님을 보이는
대조군이다. **`Q10` 을 수락하면서 `Q9`/`Q6` 을 거부해야** effect→sink 분석이
값을 한다. 이 셋이 §11-5 재측정의 핵심 행이다.

### effect → 증명 의무

```
EQ    → 키 전체에 대한 factor-through (§5.5). equality_embedding 은 충분조건
ORD   → 키 전체에 대한 factor-through. order_embedding 은 충분조건
VAL   → expression / aggregate compatibility
CARD  → 원인이 된 EQ/ORD 가 안전하거나 δ_Q 가 discharge
```

내부 `EQ`/`ORD` 가 후속 연산에서 완전히 소거되는 경우까지 거부해도 **건전성은
유지된다.** 논문에서는 이 분석을 **sound but incomplete conservative gate** 라고
써야 한다. "모든 안전한 질의를 판정한다" 는 완전성 주장은 할 수 없다.

### 왜 나눠야 하는가

"민감값에 의존하는 모든 것을 가린다"는 정의는 두 가지 이유로 쓸 수 없다.

1. **전부 NULL 이 된다.** `WHERE s = ?` 로 걸러진 결과의 모든 컬럼은 `s` 에
   의존하므로, 완전한 정보흐름 lineage 를 다 가리면 출력이 남지 않는다.
2. **실제 구현이 그렇게 하지 않는다.** Oracle 공식 예제에서
   `COUNT(CASE WHEN credit_limit < avg_credit_limit THEN 1 END)` 는 **실제 건수**
   (`359`, `336`)를 반환하고, 같은 질의의 `MAX`/`MIN`/`AVG(credit_limit)` 만
   `0` 으로 redaction 된다. 즉 Oracle 은 완전한 transitive lineage 가 아니라
   **value-bearing expression 과 structural/control influence 를 구별한다.**
   > 리뷰어가 원문에서 확인한 값이다. 저자는 `blogs.oracle.com` 이 403 이라
   > 직접 열람하지 못했다 — 출판 전 실기 또는 원문 재확인이 필요하다.

## 3. `Mout` 의 정의

```
Mout(R) :
    VAL effect 를 가진 셀    → redact_by_result_type(cell)
    EQ / ORD / CARD          → 컨테이너에 이미 반영됨. 손댈 수 없다
```

`Ideal(Q, D, M) = Mout(Q(D))` — **원본으로 계산하고 출력 셀만 가린다.**

`Mout` 에는 declassification 항목이 **없다.** `Mout` 은 순수한 cell map 이고,
정책이 무엇을 허가했는지는 `Mout` 이 아니라 §3.5 의 `Release_Q` 가 표현한다.
둘을 한 함수에 섞으면 정리 1(fidelity)과 정리 2(opacity)가 같은 정의에 의존하게
되어 §6 의 분리가 무의미해진다.

## 3.5 Declassification — `Release`

정책이 허용한 관찰을 **함수로 명시**한다.

```
Release_Q(D) = ( M(D),  δ_Q(D) )
```

`M(D)` 는 DB 의 마스킹된 모습, `δ_Q(D)` 는 이 질의에 대해 정책이 **명시적으로
공개를 허가한 것**이다. Scoped opacity 는 이렇게 된다:

```
Release_Q(D1) = Release_Q(D2)  ⇒  Obs(Impl(Q,D1)) ≡_Q Obs(Impl(Q,D2))
```

`δ_Q` 가 무엇을 허용하는지 **정확히** 정해야 한다:

- `WHERE secret = 'a'` → **행 포함 여부**를 허용할 수 있다
- 그렇다고 `ORDER BY secret` 의 **상대 순서**까지 허용되는 것은 **아니다**
- `CASE WHEN secret … ` 의 **출력 셀**이 자동으로 discharge 되지도 **않는다**

즉 declassification 은 술어 하나를 통째로 면제하는 것이 아니라, **(effect edge,
관찰 수준)** 쌍 단위로 발급되는 증명서다.

### 인증서 키에 **context fingerprint** 가 들어간다

```
Declass( sources, effect, context_fingerprint, sink, observation )
```

```
context_canonical                                     -- 정책이 읽고 검토한다
context_key = sha256(version || domain || canonical)  -- 게이트가 맞춰본다
```

canonical 에는 순서 보존된 key expression, `relid.attnum` source identity
(공개 컬럼 포함), 함수·연산자 OID, 상수의 타입과 값, collation,
`ASC/DESC`·`NULLS FIRST/LAST`, effect, sink 가 들어간다. `location`·alias·
내부 `varno` 는 **뺀다** — 의미와 무관하고 rewrite 마다 달라진다. 인코딩은
**길이 구분**이어야 한다(단순 결합은 구분자 충돌로 우회가 생긴다).

**parameterized predicate** 는 `param_scope` 로 명시한다: 기본 `none` 은
파라미터가 있으면 거부, `domain` 은 정책이 그 정의역 전체를 허가한다는 선언이다.
조용히 모든 값에 재사용되는 형태를 금지한다.

`context_fingerprint` = 키 표현식 + 비교자 + collation. `ORDER BY secret` 을
허가한 것이 `ORDER BY lower(secret)` 이나 `ORDER BY secret USING ~<~` 까지
허가하면 안 된다 — 드러나는 정보가 다르다. 이것을 구현의 특별 규칙이 아니라
**인증서 키**로 두어야 명세와 구현이 어긋나지 않는다
([`results/gate.md`](../results/gate.md)).

### ★ `δ_Q` 는 **질의 실행 전에** 정책이 고정한다

이게 없으면 정리 2 가 **공허하다.** 결과를 본 뒤 "그건 허가된 채널이었다" 고
`δ_Q` 를 넓힐 수 있으면 어떤 누출도 사후에 정당화된다. 삼자택이 표에서
`declass=True` 를 우리가 손으로 표시한 것도 지금은 **사후 선택**이고, 이건
현재 측정의 알려진 약점이다(§11-5 에서 정책 선언으로 옮긴다).

인증서의 형태를 고정한다.

```
Declass( source, effect, sink, observation )
```

| 필드 | 뜻 |
|---|---|
| `source` | 어느 라벨된 컬럼/마스크 인스턴스인가 |
| `effect` | `VAL` / `EQ` / `ORD` / `CARD` 중 어느 edge 인가 |
| `sink` | §2 의 관찰 sink 중 어디로 도달하는가 |
| `observation` | 그 sink 에서 **무엇까지** 보이는 것을 허용하는가 |

예:

```
(secret, CARD, row-membership, predicate-result)   허용
(secret, ORD,  final-order,    relative-order)     불허
(secret, EQ,   row-count,      group-count)        불허
```

첫 줄이 있어도 둘째·셋째는 **자동으로 따라오지 않는다.** 같은 컬럼이라도
`WHERE secret='a'` 의 행 포함 여부 허가가 `ORDER BY secret` 의 상대 순서나
`row_number() OVER (ORDER BY secret)` 의 rank 를 허가하지 않는다.

`δ_Q(D)` 는 이 인증서 집합을 `D` 에 적용한 값이다. 게이트는 질의를 보기 전에
발급된 인증서만 사용할 수 있고, **인증서가 없는 effect edge 는 discharge 되지
않는다.**

### V3 는 두 갈래다

지금 구현한 `mask_position = projection` 은 **value lineage 전부**를 가린다.
이것을 Oracle 과 같다고 부르면 안 된다.

| | 무엇을 가리는가 | 상태 |
|---|---|---|
| **V3-strict** (현재 구현) | 결과 셀의 value lineage 전부 (`avg(s)`, `count(DISTINCT s)` 포함) | 우리의 Ideal |
| **V3-oracle** | Oracle 의 정책 전파 규칙. 비교 기반 파생(`COUNT(CASE …)`)은 가리지 않는 것으로 보임 | **`[미확인]`** |

논문에서는 **V3-strict 를 우리의 Ideal 로 명시**하고, Oracle 은 "문서상 유사한
지점이나 전파 규칙은 미확인" 으로 인용한다.

## 4. 마스크 인스턴스의 동일성

**속성은 PII 종류(`kind`)가 아니라 마스크 인스턴스에 속한다.** 같은 `ssn`
kind 에도 상수 마스크, 뒤 4자리 보존, injective token, 무작위 대체,
order-preserving token 이 전부 가능하다.

```
MaskInstance = ( function_oid,
                 normalized_args,      -- 정규화된 상수 인자
                 input_type,
                 output_type,
                 collation,            -- 비교·정렬 의미가 여기 달려 있다
                 impl_fingerprint )    -- 구현이 바뀌면 속성도 다시 봐야 한다
```

`mask_prop(kind, …)` 로 만들면 같은 kind 에 다른 마스크를 붙이는 순간 증명이
깨진다. **레지스트리의 키는 위 튜플이어야 한다.**

### `impl_fingerprint` 는 관리자가 적는 문자열이면 안 된다

앞 판의 `impl_version` 을 바꿨다. **`CREATE OR REPLACE FUNCTION` 은 OID 를
유지한다.** 본문만 갈아끼우면 `(function_oid, args, types, collation)` 이 전부
그대로이므로, 관리자가 버전 문자열을 손으로 올리지 않는 한 **옛 인증서가 새
구현 위에서 살아남는다.** 그건 `RegistrySound` 를 조용히 깨는 경로다 — 5R 에서
GUC 가 `USERSET` 이라 한 줄로 꺼졌던 것과 같은 종류의 구멍이다.

fingerprint 는 최소한 다음에 결합돼야 한다.

| 대상 | 무엇에 결합 |
|---|---|
| SQL/PLpgSQL 함수 | `prosrc` 해시 + `provolatile` + `proisstrict` + `proconfig` |
| C 함수 | `probin` 이 가리키는 extension 의 버전 + 모듈 파일 해시 |
| collation | `pg_collation.collversion` (OS 라이브러리 변경 감지) |
| 의존 extension | `pg_extension.extversion` |

그리고 **무효화가 자동이어야 한다** — 함수·extension·collation 이 바뀌면
해당 `MaskInstance` 의 인증서가 `unknown` 으로 떨어져야 한다. Y07 에서
계획 캐시에 relcache 콜백을 단 것과 같은 문제이고, 같은 해법(카탈로그 무효화
콜백)이 필요하다.

### `total` 은 장기적으로 boolean 이 아니다

§1.5 의 `total` 을 전역 boolean 으로 두면 너무 많이 거부한다. `substr(x,1,2)`
는 임의 `text` 에 대해 total 이지만 `x/y` 는 `y ≠ 0` 이라는 **전제** 아래에서만
total 이다. 스키마 제약(`CHECK (y <> 0)`)이나 마스크의 치역이 그 전제를
보장할 수 있다.

```
total_under(f, precondition)
```

첫 구현은 `precondition = ⊤` 만 지원한다(= 무조건 total). 스키마 제약을 읽어
전제를 discharge 하는 것은 뒤로 미루되, **컬럼을 boolean 으로 만들지 않고
전제를 담을 수 있게 설계**한다. 나중에 타입을 바꾸면 기존 인증서가 전부
무효가 된다.

## 5. 마스크 능력 (수학적 정의)

`m` 은 마스크 인스턴스, `C` 는 입력 컬레이션, `C'` 는 출력 컬레이션,
`≡_{SQL,C}` 는 **SQL grouping equivalence** (일반 `=` 가 아니다 — `DISTINCT`
와 `GROUP BY` 는 NULL 을 같은 그룹으로 취급한다).

```
determinism(m)
    같은 입력에 대해 요구된 범위 안에서 동등한 출력을 낸다

null_equivalence(m)
    x IS NULL  ⇔  m(x) IS NULL          -- 양방향이다

equality_embedding(m)
    x ≡_{SQL,C} y  ⇔  m(x) ≡_{SQL,C'} m(y)

order_embedding(m)
    cmp_C(x, y) = cmp_{C'}(m(x), m(y))   -- tie 보존 포함

commutes(m, f, r_out)
    f(m(x)) = r_out(f(x))                -- 함수 f 에 대한 호환성

aggregate_compatible(m, A, r_out)
    A(m(X)) = r_out(A(X))                -- 집계 A 에 대한 호환성
```

### 5.5 실제 의무는 **키 전체의 factor-through** 다

```
EQ  → 각 마스크가 equality_embedding
ORD → 각 마스크가 order_embedding
```
로 쓰면 **너무 강하다.** 실제 의무는 *"원본 비교가 공개된 정보로부터 재구성
가능한가"* 다:

```
eq_raw (K1, K2) = eq^  ( release(K1), release(K2) )
cmp_raw(K1, K2) = cmp^ ( release(K1), release(K2) )
```

이 **factor-through 조건**이 핵심이고, `equality_embedding`/`order_embedding`
은 그것을 증명하는 **충분조건일 뿐**이다.

### ★ 게이트는 factorization 을 **결정하지 않는다** — 인증서를 **검사**한다

논문 표현을 여기서 반드시 낮춰야 한다. 임의 UDF 를 포함하면 semantic
factorization 자체는 **일반적으로 결정 불가능**하다(함수 동등성으로 환원된다).
따라서 다음 문장은 그대로 공격받는다.

> ~~factorization 이 성립하는지를 **결정**하는 게이트~~

정확한 기여 문장은 이것이다.

> **A decidable and sound certificate checker for sufficient
> release-factorization conditions over a declared SQL fragment.**
>
> 선언된 SQL fragment(§12) 위에서, 충분조건들로 이루어진 제한된 인증서 언어에
> 대해 **결정적으로** 검사하는 건전한 검사기.

세 층위를 구분해 쓴다.

| 층위 | 결정 가능? | 누가 담당 |
|---|---|---|
| semantic factorization 자체 | **아니오** (일반적으로) | — |
| 인증서 언어(원자적 capability 의 유한 조합) | **예** | 게이트 |
| 개별 capability 가 참인가 | 명세 밖 | 레지스트리(§6 의 `proved_builtin` / `trusted_assumption`) |

레지스트리의 **`unknown → reject` 가 정확히 이 차이를 만든다.** 게이트는 의미론
전체를 판정하는 것이 아니라, 인증서가 붙어 있는 조각만 통과시키고 나머지는
거부한다. 그래서 **불완전하지만 건전**하고, 불완전성의 크기가 곧 acceptance
비용으로 측정된다.

이 정의는 다음을 자연스럽게 처리한다:

- 복합 `GROUP BY`/`ORDER BY` 키 (공개 PK 가 섞이면 마스킹 컬럼이 embedding 이
  아니어도 안전할 수 있다)
- `NULLS FIRST/LAST`, `ASC/DESC`, collation
- 튜플 수준 함수 종속

**따라서 레지스트리는 원자적 capability 만 제공하고, 게이트가 질의 문맥에서
capability 를 합성한다.**

**뒤 두 개는 마스크 단독 속성이 아니라 `(mask, 연산, 결과 redactor)` 의
관계**다. 따라서 레지스트리가 셋으로 나뉜다.

```
mask_capability                 -- m 단독 속성 (determinism, null, equality, order)
mask_function_compatibility     -- (m, f, r_out)
mask_aggregate_compatibility    -- (m, A, r_out)
```

## 6. 속성의 상태와 `RegistrySound`

속성을 boolean 으로 두면 안 된다. **출처**가 정리의 전제이기 때문이다.

```
proved_builtin        시스템이 제공하고 검증한 내장 마스크
trusted_assumption    관리자가 선언했다 (신뢰 가정으로 명시적으로 기록)
unknown               기본값. 어떤 규칙도 이 속성에 의존할 수 없다 → 거부
```

사용자 UDF 는 **기본이 전부 `unknown`** 이다. 속성 기반 검증(property-based
testing)은 보조 수단이며 **증명으로 취급하지 않는다.**

정리는 **두 개**다. 섞으면 논리가 흐려진다.

**정리 1 — accepted-query fidelity**
```
Accept_Π(Q) ∧ RegistrySound(Π)
⇒  Obs(Impl_Π(Q, D))  ≡_Q  Obs(Mout(Q(D)))
```

**정리 2 — accepted-query scoped opacity**
```
Accept_Π(Q) ∧ RegistrySound(Π) ∧ Release_Q(D1) = Release_Q(D2)
⇒  Obs(Impl_Π(Q, D1))  ≡_Q  Obs(Impl_Π(Q, D2))
```

두 의무의 성격이 다르다는 것이 중요하다:

- **원본 값으로 정렬·그룹핑하는 것은 fidelity 에 도움이 된다** (V2 가 술어를
  건드리지 않는 이유)
- **`equality`/`order` factor-through 는 그 구조가 마스킹된 공개 정보로
  결정된다는 것을 보여 opacity 를 지키기 위해 필요하다**

한 규칙으로 섞으면 안 된다.

관리자가 잘못된 속성을 선언하면 정리가 깨지는 것이 아니라 **`RegistrySound`
전제가 깨진다.** 책임 소재가 형식에 드러나야 한다.

`Release_Q` 로 declassification 을 명시했으므로(§3.5), `WHERE s = ?` 를 원본으로
처리하면서도 "그 채널 밖에서는 opacity 를 보장한다"가 형식적으로 성립한다.

## 6.5 `M(D1) = M(D2)` 는 무엇이 같다는 뜻인가

정리 2 의 전제를 **셀 집합 동일성**으로 두면 안 된다. 그러면 `Q10` 의 행 수나
`Q9` 의 `id` 대응을 정리 안에서 말할 수 없다 — 전제가 너무 약해 반례가 아닌
것까지 반례가 된다.

`M(D)` 는 DB 를 **마스킹된 관계 인스턴스로** 보내는 함수이고,
`M(D1) = M(D2)` 는 다음 다섯 가지가 전부 보존되는 동형을 뜻한다.

| | 보존 대상 | 없으면 깨지는 것 |
|---|---|---|
| 1 | **relation 구분** — 어느 테이블의 행인지 | 서로 다른 표를 섞어 놓고 "같다" 고 할 수 있다 |
| 2 | **공개(비라벨) 컬럼의 값** | `Q9` 의 `id` 가 sink 라는 논증이 성립하지 않는다 |
| 3 | **행 다중도** (bag 의미) | `Q10` 의 "행 수가 같다" 를 전제로 쓸 수 없다 |
| 4 | **공개 row identity 가 있으면 그 대응** (PK 등) | 행 대응 없이 "같은 행" 을 말할 수 없다 |
| 5 | **SQL 동등성** — `NULL` 취급과 **collation** | `≡_{SQL,C}` 와 전제가 서로 다른 동등성이 된다 |

측정 witness 가 이 조건을 실제로 만족하는지 확인해 둔다.

```
tri_a: (1,'f','A') … (6,'a','C')      tri_b: (1,'a','A') … (6,'b','C')
  1 relation      같은 스키마·같은 이름공간(h5)          ✓
  2 공개 컬럼     id 1..6, grade A,A,B,B,C,C  동일        ✓
  3 다중도        각 6행                                  ✓
  4 row identity  id 가 PK 역할, 1:1 대응                  ✓
  5 SQL 동등성    NULL 없음, 같은 collation                ✓
  마스킹 후       secret 은 양쪽 다 상수 '*'               ✓
```

따라서 `M(tri_a) = M(tri_b)` 이고, **결과가 다르면 곧 opacity 위반**이라는
측정 도구의 판정이 정리의 전제와 정확히 일치한다.

> `null_equivalence` 가 깨지는 마스크(§7 의 `numeric_mask=nullify`)는 조건 5 를
> 통해 이미 문제로 잡힌다 — 그 마스크에서는 `M(D)` 가 원본의 NULL 여부를 바꾸어
> `≡_{SQL,C}` 를 보존하지 않는다.

## 7. 현재 구현의 마스크는 무엇을 만족하는가

`ipguard_mask(anyelement, text)` 는 타입별 상수를 돌려준다
(text → 글자수 보존 `*`, date → `1900-01-01`, 숫자 → `NULL`(기본) 또는 `0`).

| 속성 | 상태 | 근거 |
|---|---|---|
| `determinism` | **proved** | 입력에 무관한 상수. `IMMUTABLE` 선언 |
| `null_equivalence` | **proved** | `PG_ARGISNULL` 이면 NULL 반환, 아니면 non-NULL. 단 `numeric_mask=nullify` 에서는 **깨진다**(non-NULL 입력이 NULL 이 됨) |
| `equality_embedding` | **false** | 모든 값이 같은 마스크로 간다 |
| `order_embedding` | **false** | 상수는 순서를 뭉갠다 |

**`numeric_mask = nullify` 가 `null_equivalence` 를 깬다**는 것이 이 표에서
처음 드러났다. 숫자 PII 를 `NULL` 로 가리면 `x IS NOT NULL` 이 거짓이 되어
`count(col)` 이 바뀐다 — 5R 에서 실측했던 `count(*) FILTER (WHERE salary IS
NOT NULL)` 1000 → 0 이 정확히 이 위반이다. **명세를 쓰자 이미 측정된 현상이
속성 위반으로 설명됐다.**

## 8. R3 는 둘로 나뉜다 — 그리고 현재 구현은 v0.2.1 기준으로 불건전하다

최상위 순서를 관찰에 포함하면 `LIMIT` 없는 `ORDER BY secret` 도 opacity 채널이다.
따라서 기존 R3b 는 나뉘어야 한다.

```
R3-order      최상위 관찰 순서가 민감값에 의존한다
R3-selection  그 순서가 LIMIT/OFFSET/FETCH 를 통해 선택 멤버십까지 바꾼다
```

**★ 실측으로 현재 구현의 불건전성이 드러났다.** witness 데이터를 정렬 순서가
id 순서와 **다르도록** 바꾸자(전에는 같아서 채널이 가려져 있었다):

```
Q9  SELECT id FROM t ORDER BY secret, id           (LIMIT 없음)
      V2 → D1/D2 결과가 다르다  = ORD 채널 누출
Q6  SELECT id FROM t ORDER BY secret, id LIMIT 3
      V2 → D1/D2 결과가 다르다  = R3b 가 있는데도 누출
```

`Q6` 에서 R3b 가 발화하지 않는 이유: `secret` 이 출력에 없어 `resjunk` 이므로
**마스킹되지 않고**, R3b 는 "마스킹된 정렬 키" 를 조건으로 하므로 아예 걸리지
않는다. **규칙이 masked-ness 를 보는 것이 틀렸다 — lineage 를 봐야 한다.**

이 발견으로 이전 삼자택이 수치가 정정됐다. 약한 witness 가 ORD 채널을 가려
V2 의 opacity 를 실제보다 높게 보이게 하고 있었다.

## 9. R1~R2 를 재유도할 때 주의할 것

**동치류 조건은 키 전체에 대해 써야 한다.**

```
K(x) ≡ K(y)  ⇔  M_K(K(x)) ≡ M_K(K(y))
```

키가 여러 컬럼이면 마스킹된 각 컬럼이 `equality_embedding` 일 필요는 없다 —
함께 출력되는 비마스킹 PK 가 이미 튜플을 구별하면 `DISTINCT` 는 안전하다.
**첫 구현은 보수적으로** 각 마스킹 키에 embedding 을 요구하고, PK/FD 최적화는
나중에 붙인다(그래야 과거부가 줄어든다는 것을 별도로 측정할 수 있다).

`substr` 의 상수 마스크 commutation 도 **자동으로 참이라고 두면 안 된다**:

```
substr('****', 1, 2)      = '**'
r_out(substr(x, 1, 2))    = ?     ← r_out 이 결과 길이에 맞춰 '**' 를
                                     돌려준다는 명세가 있어야만 같다
```

## 10. 미확인 목록

- Oracle 의 `COUNT(CASE …)` 동작 — **공식 문서 예제로 확인됨; 독립 실행
  재현은 아직 안 됨.** 실험 결과로 주장하려면 Oracle 인스턴스 재현이 별도로
  필요하다. 또한 이 예제는 **value/structural 구분의 필요성**을 뒷받침할 뿐,
  우리 분류 체계의 정확성을 검증한 것은 아니다 — 제품의 전파 정책을 확인한
  것이다. (원래 문구: **확인됨**
  (리뷰어 확인: 실제 건수 `359`/`336` 반환, 같은 질의의 `MAX`/`MIN`/`AVG` 만
  `0` 으로 redaction). 즉 Oracle 은 완전한 transitive lineage 가 아니라
  value-bearing expression 과 structural/control influence 를 구별한다.
  원문은 403 이라 저자가 직접 열람하지는 못했다.
- Oracle 의 `COUNT(DISTINCT <redacted>)` 동작 — 문서에 명시 없음
- Oracle 의 정책 전파 규칙 일반 (어디까지 파생을 가리는가)

**이 셋이 확인되기 전에는 "우리 V3 = Oracle" 이라고 쓸 수 없다.**

## 10.5 기법의 이름

`Q6`/`Q9` 발견 — **syntactic maskedness 가 아니라 semantic lineage 와 observable
effect 를 검사해야 한다** — 이 기법의 필요성을 가장 잘 보여준다. 그래서 이름을
단순 마스킹 변이가 아니라 다음으로 세운다:

> **release-factorization gate**
> (또는 effect-and-capability masking analysis)

원본 비교가 **공개된 정보(release)로부터 재구성 가능한가(factor through)** 를
묻는 것이 이 게이트의 판정 내용이기 때문이다.

## 11. 이 명세가 확정된 뒤의 순서

1. ~~v0.2.1 확정~~ **완료** (peer-order, `Release`/`δ_Q`, effect→sink,
   factor-through, + 동결 심사 5항목)
2. ~~지원 SQL fragment 와 비결정적 top-k 범위 확정~~ **완료 → §12**
2.5 ~~**분모 동결** — rewrite 이후 Query 트리로 재분류~~ **완료**
   (`ipguard_fragment()`, `results/fragment.md`: 10/10 · 37/45 · 13/22)
3. ~~`MaskInstance` 키로 레지스트리 3종 구현~~ **완료**
   ([`results/registry.md`](../results/registry.md), 46/46)
   - `claim`(holds/fails/unknown)과 `assurance`(proved_builtin/
     trusted_assumption/unknown)를 **분리**했다
   - 지문을 조회 시점에 재계산해 불일치면 `unknown`. `CREATE OR REPLACE` 가
     OID 를 유지하는 경로가 여기서 막힌다
   - assurance 4등급. `proved_builtin` 은 `internal` 만, 우리 모듈의
     C 함수는 `trusted_provider` — 소스 해시로는 **바이너리 동일성**을
     못 얻는다. `BuildSound(provider_manifest)` 전제 아래에서만 쓴다
   - 조회 API 가 **강제 전제를 등록 조회보다 먼저** AND 한다. 잘못
     등록된 `count -> holds` 가 `null_equivalence` 의무를 우회 못 함
   - `registry_epoch` + relcache 무효화로 generic plan 까지 전파.
     **cross-backend** 로 확인했다 — 살아 있는 백엔드 3개 + 철회 세션,
     `ROLLBACK` 대조군 포함. 계획 **사건**을 직접 측정(`ipguard_pii_plan_count()`)
   - `total` 을 boolean 이 아니라 `total_under(f, precondition)` 으로 설계.
     첫 구현은 `precondition = ''` 만 지원
4. ~~lineage 기반 effect propagation + effect→sink 게이트 구현~~ **완료**
   ([`results/gate.md`](../results/gate.md), 118/118)
   - effect 노드는 **hyperedge** 다 — key vector 전체를 문맥으로 들고 다닌다.
     source 별 boolean 전파는 per-column embedding 으로 퇴행한다
   - fidelity(`VAL→CELL`, commutation)와 opacity(`EQ/ORD/CARD→sink`,
     factor-through 또는 declassification)를 **끝까지 분리**했다
   - `ipguard.gate = legacy | release`, 기본 legacy — 나란히 재측정하기 위해
   - **fail-closed 3단**: 라벨 미접촉 → 수락 / `F_core` 밖 →
     `OUTSIDE_CERTIFIED_FRAGMENT` / 미모델링 노드 → `UNMODELED_NODE`.
     노드를 안 만들면 "sink 없음" 으로 오인되어 수락된다 — 미탐이다
   - `KeyTerm`(bare_var, collation, sortop, eqop, nulls_first)을 순서대로
     보존한다. 컬럼 집합으로 축약하면 `ORDER BY lower(secret)` 과
     `COLLATE "C"` 가 인증서를 우회한다(실측)
5. **기존 게이트와 새 게이트를 나란히** 재측정 (acceptance 병기)
   - `Q10` 수락 / `Q9`·`Q6` 거부가 되는지가 판정 행이다(§2)
   - `declass` 표시를 손으로 하지 말고 §3.5 인증서에서 읽어온다
6. 코어 관계대수에 대한 구조적 귀납 증명 (정리 1·2 분리)

## 12. 지원 SQL fragment 와 Totality 의 분모

**이 절이 레지스트리보다 먼저인 이유는 `Totality` 의 분모를 고정하기
위해서다.** 나중에 어려운 질의를 "미지원" 으로 옮기면 삼자택이 측정이
임의적이라는 비판을 그대로 받는다. 그래서 분모를 **여기서 닫고**, 이후
측정에서 바꾸지 않는다. 바꿔야 하면 버전을 올리고 이전 수치를 다시 낸다.

### `F_core` — 정리 1·2 가 적용되는 범위

| | 구성 |
|---|---|
| 관계 | `SELECT`, 중첩 derived table |
| 의미 | **bag semantics** (§1 컨테이너) |
| 투영 | 등록된 **pure/total/deterministic** scalar function (§1.5) |
| 선택 | selection, **inner join**, **primitive semi-join** (아래) |
| 중복 | `GROUP BY`, `DISTINCT` |
| 집계 | 등록된 일반 aggregate (`mask_aggregate_compatibility`) |
| 집합연산 | `UNION ALL`. 비-`ALL` 집합연산은 **`EQ` 의무 적용** |
| 정렬 | **최상위** `ORDER BY` |
| 절단 | `LIMIT`/`OFFSET` — **정렬 키가 전순서로 인증된 경우에만** |

### semi-join 은 **primitive 로** 넣는다 — 유도하면 안 된다

앞 판에 *"`SELECT DISTINCT` + inner join 으로 유도된다"* 고 썼는데 **bag
의미론에서 틀렸다.** 왼쪽에 같은 행 2개, 오른쪽에 매칭 2개일 때:

```
semi-join    →  왼쪽 행 2개  (왼쪽 다중도 보존)
inner join   →  4개          (곱해진다)
+ DISTINCT   →  1개          (뭉개진다)
```

셋이 전부 다르다. `Res` 를 bag 으로 정의한 이상(§1) 다중도가 관찰에 들어가므로
이 차이는 정리에 그대로 나타난다. 따라서 **`EXISTS` 는 코어 대수의 primitive
semi-join** 으로 둔다. `⋉` 에 대한 귀납 단계를 따로 쓴다.

`IN` 은 범위를 좁힌다.

| 형태 | `F_core` | 이유 |
|---|---|---|
| `WHERE x IN (subquery)` | **안** | TRUE 여부만 쓰므로 semi-join 으로 모델링된다 |
| `SELECT x IN (subquery)` | **밖** | UNKNOWN 자체가 출력 셀이 된다. 3VL scalar expression 이고 `Row` 정의가 늘어난다 |
| `(a,b) IN (subquery)` | **밖** | row-comparison 의미론이 별도로 필요하다 |

즉 `F_core` 에 들어가는 것은 **predicate-position scalar `IN`** 뿐이다.

민감값이 semi-join 술어에 들어가면 `CARD` effect 이고 §3.5 인증서가 필요하다 —
별도 규칙이 아니다.

### `F_core` 에서 **제외** (초기 정리 밖)

```
tied / unordered top-k                 -- §1 의 비결정성
DISTINCT ON, FETCH … WITH TIES         -- 같은 이유
recursive CTE, LATERAL, SRF            -- 귀납 구조가 다르다
volatile function                      -- §1.5 pure 위반
GROUPING SETS, ordered-set aggregate   -- 집계 인터페이스가 다르다
window function (frame 포함)            -- ORD 를 셀로 직접 나르는 별도 축
outer join                             -- 확장 NULL 이 null_equivalence 와 얽힌다
NOT EXISTS (anti-semijoin)             -- ⋉ 규칙이 선 뒤에 여집합으로 유도한다
NOT IN / <> ALL (3VL quantified cmp)   -- null_equivalence 를 전제로 요구하는 별도 규칙
SELECT 위치의 IN, row-valued IN         -- UNKNOWN 이 출력 셀이 된다 / row 비교 의미론
상관 스칼라 서브쿼리 ( = (SELECT …) )     -- 1행 초과면 런타임 오류 = total 위반
DML / RETURNING, COPY, cursor          -- 계획기 경로가 다르다
버전이 고정되지 않은 collation           -- §6.5 조건 5 를 만족시킬 수 없다
```

리뷰어 목록에 없었으나 이번에 **추가로 뺀 셋**은 전부 앞 절에서 유도된다.

| 제외 | 유도한 절 | 이유 |
|---|---|---|
| `outer join` | §6.5 조건 5, §7 `null_equivalence` | 확장 NULL 과 마스크 NULL 이 결과 도메인에서 구별되지 않는다. 분리하려면 `Row` 를 다시 정의해야 한다 |
| `NOT EXISTS` (anti-semijoin) | 같음 | 매칭 부재를 검사한다. `⋉` 의 여집합이므로 `⋉` 규칙이 선 뒤에 따로 쓴다 |
| `NOT IN` (null-aware quantified comparison) | 같음 + 아래 실측 | `<> ALL` 이라 RHS 의 NULL **유무**에 비단조로 의존한다. `EQ` factor-through 위에 "마스크가 NULL 을 새로 만들지 않는다" 는 **추가 의무**가 붙는다 |
| 상관 스칼라 서브쿼리 | §1.5 `total` | `= (SELECT …)` 가 2행을 받으면 `ERROR: more than one row returned`. 부분함수이므로 코어 정리가 다룰 수 없다 |

### anti-join 제외의 실측 근거

`aj_t = {100,200,300}`, `aj_s = {100}` (`aj_s.sal` 만 라벨),
`mask_position = source`(V1).

| 형태 | 마스크 | 결과 | 마스킹 없을 때 |
|---|---|---:|---:|
| `sal NOT IN (SELECT sal FROM aj_s)` | `nullify` | **0** | 2 |
| `sal NOT IN (SELECT sal FROM aj_s)` | `zero` | **3** | 2 |
| `NOT EXISTS (… y.sal = x.sal)` | `nullify` | **3** | 2 |
| `sal IN (SELECT sal FROM aj_s)` (semi, 대조) | `nullify` | 0 | 1 |

> **[정정]** 앞 판에는 *"원본에서 동치인 두 표기가 갈리므로 구조적 귀납이
> 성립하지 않는다"* 고 썼다. **틀렸다.** `NOT EXISTS` 와 `NOT IN` 은 애초에
> 동치가 아니다 — 이 데이터에서 둘 다 2가 나온 것은 RHS 에 NULL 이 없어
> **우연히 같았던 것**이다.
>
> ```
> NOT EXISTS   anti-semijoin.       TRUE 인 매칭 행이 없는지 본다.
>                                   NULL 비교는 TRUE 매치를 만들지 않으므로 통과한다.
> NOT IN       <> ALL.  NULL-aware quantified comparison.
>                                   RHS 에 NULL 이 있고 같은 값이 없으면 TRUE 가 아니라 UNKNOWN.
> ```
>
> (PostgreSQL 문서 *Subquery Expressions* 의 `NOT IN`/`ALL` 절)
>
> 정확한 문장은 이것이다:
>
> *`NOT EXISTS` and `NOT IN` are distinct operators under SQL three-valued
> logic. We exclude both pending separate rules for anti-semijoin and
> null-aware quantified comparison. The experiment demonstrates the
> consequence of violating null equivalence, not a failure of structural
> induction.*

즉 실험이 보이는 것은 **`null_equivalence` 위반의 결과**다. `nullify` 가 NULL
을 도입하자 두 3VL 연산자의 원래 차이가 **활성화**됐다. 1행과 3행이 갈린 것은
구조적 귀납의 반례가 아니라, 두 연산자에 **각각 다른 규칙이 필요하다**는 증거다.

둘 다 빼는 이유도 그래서 다르다.

- `NOT EXISTS` — `⋉` 의 귀납 규칙이 선 뒤에 그 여집합으로 유도한다. 순서 문제다
- `NOT IN` — 3VL quantified comparison 이라 `Row` 와 술어 의미론이 늘어난다.
  `null_equivalence` 를 **전제로 요구**하는 별도 규칙이 필요하다

> 마지막 행은 semi-join 도 V1 에서 어긋남을 보인다(0 vs 1). 그건 예상된
> 것이다 — V1 은 fidelity 꼭짓점이 아니고(표 A 4/9), `nullify` 는 §7 에서
> `null_equivalence` 를 깨는 것으로 이미 기록됐다. semi-join 을 `F_core` 에
> 두는 것은 "항상 안전하다" 가 아니라 **정리가 다룰 수 있다**는 뜻이다.
>
> 참고: 현재 V2(출력경로)는 술어를 건드리지 않으므로 위 네 경우 모두 원본과
> 같다. 이 witness 는 V1 에서만 관찰된다.

### `F_core` ≠ `F_impl`

구현은 더 넓게 지원한다. 논문에서 둘을 **분리해서** 쓴다.

| | 뜻 | 어디에 쓰나 |
|---|---|---|
| `F_core` | 정리 1·2 가 증명되는 범위 | 증명 절, Totality 분모 |
| `F_impl` | 확장이 실제로 계획기에서 처리하는 범위 | 적대적 시험, TPC-H, 운영 측정 |

`F_impl \ F_core` 에 대해서는 **보장을 주장하지 않는다.** 게이트는 그 영역에서
`unknown → reject` 로 동작하거나, 동작하더라도 정리의 보호를 받지 못한다는
것을 명시한다. 3R~5R 에서 찾은 구멍 대부분이 이 영역에 있었다는 사실이 이
분리의 근거다.

### 세 이름을 구별한다 — 지금 있는 값은 `F_core` 가 아니다

| 이름 | 어떻게 얻는가 | 상태 |
|---|---|---|
| `candidate-F_core` | SQL **텍스트** 휴리스틱 (`tools/classify_fcore.py`) | 상한 |
| **`F_core`** | **`ipguard_fragment()`, 재작성 후 Query 트리** | **동결됨** |
| `F_impl` | 구현이 실제로 처리하는 범위 | 전체 |

텍스트만 보면 **뷰 본문에 숨은 구조**, rewrite 가 만들어내는 구성(규칙·RLS
술어), `SELECT` 위치 판정, 카탈로그 사실(`volatile`)을 놓친다. 그래서 분모는
텍스트가 아니라 **Query 트리**로 잡는다.

### 동결된 분모 ([`results/fragment.md`](../results/fragment.md))

| 코퍼스 | `F_core` | `F_impl` | 밖의 사유 (**non-exclusive**) |
|---|---:|---:|---|
| 삼자택이 | **10/10** | 10/10 | — |
| 발산 코퍼스 | **37/45** | 45/45 | window function 8 |
| TPC-H | **13/22** | 22/22 | 상관 스칼라 서브쿼리 6, `NOT EXISTS` 2, `NOT IN` 1, outer join 1 |

**TPC-H 의 사유 합계 10 ≠ 밖 질의 9 다.** `Q22` 가 `NOT EXISTS` 와 상관 스칼라
서브쿼리를 **둘 다** 쓴다. 사유는 중첩되므로 합계로 질의 수를 세면 안 된다.

- 삼자택이 `Q6`(`ORDER BY secret, id LIMIT 3`)은 정렬 키 `(secret,id)` 에서
  `id` 가 유일하므로 **전순서**다. 동률 top-k 제외 조항에 걸리지 않는다.
- TPC-H `Q4`·`Q18` 은 술어 위치의 `EXISTS`/`IN` 이라 **안에 있다.**
- outer join 은 **`Q13`** (`customer LEFT OUTER JOIN orders`) 하나다.
  `Q15` 는 outer join 이 아니라 상관 스칼라 서브쿼리
  (`total_revenue = (SELECT max(total_revenue) FROM revenue0)`)로 나간다 —
  `revenue0` 은 `GROUP BY` 집계 뷰다(`corpus/tpch-schema.sql:65`).
- 발산 코퍼스에서 나간 8건은 **전부 window function** 이고, 그중
  `DV33~DV36`·`DV40` 은 5R 에서 추가한 `lag`/`lead`/`row_number` 계열이다.
  **조용한 오답의 주요 원천이 `F_core` 밖**이라는 뜻이므로 숨기지 않고 쓴다.

세 코퍼스에서 텍스트와 트리의 결론은 **전부 일치**했다. 그러나 그것은 이
코퍼스들이 **뷰를 쓰지 않기 때문**이고, 텍스트가 충분하다는 뜻이 아니다.
대조군에서 `SELECT id FROM v` (뷰 안에 `LEFT JOIN`)를 텍스트는 "안" 으로,
트리는 `outer join` 으로 판정한다.

재측정(§11-5)에서는 두 분모를 **나란히** 보고한다 — 예: TPC-H 거부율
`5/22`(`F_impl`) 와 `?/13`(`F_core`) 병기.

```bash
python3 tools/score_fragment.py      # 트리 판정 = 동결된 분모
python3 tools/classify_fcore.py      # 텍스트 상한 (DB 없이 돈다)
```
