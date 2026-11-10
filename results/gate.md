# release-factorization gate — effect hyperedge → observable sink (2026-08-09)

legacy `R1~R3` 는 **masked-ness** 를 본다. 그래서 `ORDER BY secret` 에서
`secret` 이 출력에 없어 `resjunk` 이면 마스킹되지 않고, 규칙이 아예 발화하지
않는다(명세 §8, `Q6`/`Q9` 누출 실측). 새 게이트는 그 대신 **경로**를 본다:

```
source → effect → observable sink
```

경로가 없으면 수락한다. 있으면 그 effect 가 release 를 factor through 한다는
인증서나, **정확한 `(effect, sink)` declassification** 이 있어야 한다.

원시 출력: [`gate.txt`](gate.txt) ·
도구: [`../tools/score_gate.py`](../tools/score_gate.py) ·
명세: [`../docs/spec-lineage-and-masks.md`](../docs/spec-lineage-and-masks.md) §2·§3.5·§5.5

---

## ★ 단순 path 가 아니라 hyperedge 다

`EQ` 와 `ORD` 는 **여러 입력이 함께** 의미를 결정한다. source 별 boolean 전파로
만들면 다시 per-column `order_embedding` 으로 퇴행하고, 그러면 명세 §5.5 가
*"충분조건일 뿐"* 이라고 못박은 것을 구현이 의무로 되돌린다.

`Q9` 의 의무는 `secret → ORD` 가 아니라 이것이다:

```
ORD( key_vector = [secret, id],
     sources    = [secret],
     sink       = FINAL_ORDER(공개 id) )
```

노드가 **key vector 전체**를 들고 다녀야 복합키·collation·`NULLS FIRST/LAST`·
공개키와의 조합을 문맥 단위로 판정할 수 있다.

```c
EffNode { kind: VAL|EQ|ORD|CARD, sources[], nkey, nkey_labeled, fn, ... }
Sink    { CELL | MULTIPLICITY | ROW_COUNT | FINAL_ORDER | MEMBERSHIP }
Oblig   { node, sink, class: fidelity|opacity, discharge }
```

복합 질의 하나가 어떻게 분해되는지 (`ipguard_obligations()`):

```
SELECT id, substr(ssn,1,2), count(*) OVER (PARTITION BY ssn ORDER BY id)
  FROM cust WHERE ssn LIKE '8%' GROUP BY id, ssn ORDER BY ssn LIMIT 5

EQ    GROUP BY key vector    [key 2, labeled 1]  -> ROW_COUNT     opacity
ORD   ORDER BY key vector    [key 1, labeled 1]  -> FINAL_ORDER   opacity
ORD   ORDER BY key vector    [key 1, labeled 1]  -> MEMBERSHIP    opacity
EQ    window PARTITION BY    [key 1, labeled 1]  -> CELL          opacity
CARD  WHERE/JOIN predicate   [key 1, labeled 1]  -> ROW_COUNT     opacity
VAL   scalar function        [key 3, labeled 1]  -> CELL          fidelity
```

`[key 2, labeled 1]` 이 hyperedge 의 내용이다 — 키가 2개고 그중 1개가 라벨됐다.

## 의무는 두 종류다 — 끝까지 분리한다

| 종류 | 조건 | 해소 |
|---|---|---|
| **Fidelity** | `VAL → CELL` | scalar/aggregate **commutation** 인증서 |
| **Opacity** | `EQ`/`ORD`/`CARD` → 관찰 sink | **factor-through** 또는 정확한 declassification |

원본으로 정렬·그룹핑했다는 사실은 fidelity 에는 유리하지만 **opacity 인증서가
아니다.** 한 규칙으로 섞으면 안 된다(명세 §6).

## ★ [0] fail-closed — 미구현 경로가 수락으로 빠지지 않는가

**노드를 안 만들면 "sink 없음" 으로 오인되어 수락된다. 그건 과거부가 아니라
미탐이다.** 판정 행만 맞추면 "의도한 것만 되는 게이트" 이고, 이 군이 있어야
gate regression suite 가 된다.

release 모드 진입점이 세 단계로 막는다:

```
0) 라벨된 데이터를 안 건드리면        -> 인증 대상 아님, 수락
1) F_core 밖이면                     -> OUTSIDE_CERTIFIED_FRAGMENT reject
2) visitor 가 못 다룬 노드가 있으면    -> UNMODELED_NODE reject
```

| | 판정 |
|---|---|
| `F_core` 밖: window function · outer join · `NOT IN` · 상관 스칼라 서브쿼리 | **거부** |
| `UNION`(비-`ALL`) / `EXCEPT` / `INTERSECT`, `equality_factor=fails` | **거부** |
| 같은 셋, `equality_factor=holds` | 수락 |
| `UNION ALL` (값 비교 없음) | 수락 |
| 중첩 집합연산(서브쿼리 안) | **거부** |

> **window function 은 effect 코드가 있지만 release 모드에서 수락하지 않는다.**
> 명세 §12 가 `F_impl \ F_core` 에 **보장을 주장하지 않는다**고 못박았으므로,
> 게이트가 그 영역을 수락하면 명세와 구현이 정면으로 충돌한다.

### ★ 실측으로 잡은 미탐 — `resjunk` 사각지대

처음에는 게이트를 `out_kinds != NIL || pred_kinds != NIL` 일 때만 돌렸다.
그런데 분석기는 **`resjunk` TLE 를 건너뛴다** — 클라이언트로 나가지 않으니
마스킹 대상이 아니기 때문이다. 그래서

```sql
SELECT id, row_number() OVER (ORDER BY ssn) FROM cust
```

가 `out= pred=` 즉 "PII 없음" 으로 나오고, **게이트가 아예 돌지 않았다.**
`R3b` 가 틀렸던 것과 같은 뿌리다 — masked-ness 를 기준 삼으면 `resjunk` 가
통째로 사각지대가 된다. 게이트는 `scan_all` 로 `resjunk` 까지 훑어 **스스로**
판정한다.

### ★ key term 문맥 — 컬럼 집합으로 축약하면 뚫린다

hyperedge 가 보존해야 하는 것은 컬럼 수가 아니라 **순서 있는 표현식 문맥**이다.

```c
KeyTerm { bare_var, collation, sortop, eqop, nulls_first, sources[] }
KeyVector = ordered KeyTerm[]
```

`bare_var` 와 `collation` 은 **건전성에 직접 걸린다.** 둘 다 실측으로 뚫렸다가
닫았다:

| | 이유 |
|---|---|
| `ORDER BY lower(secret)` | `order_factor(m)` 은 `cmp(x,y)=cmp(m(x),m(y))` 이지 `cmp(lower(x),lower(y))=cmp(lower(m(x)),lower(m(y)))` **가 아니다** |
| `ORDER BY secret COLLATE "C"` | `order_factor` 는 **등록된 collation 에서만** 증명된 주장이다 |
| `GROUP BY upper(secret)` | 같은 이유(`equality_factor`) |
| 컬럼이 `COLLATE "C"` 로 선언됨 | bare Var 지만 인스턴스가 기본 collation 으로만 등록돼 있다 |

`cap_of()` 가 `collation_name` 까지 맞춰 인스턴스를 찾는다. 없으면 `unknown`.

`ORDER BY secret, id` 와 `ORDER BY id, secret` 은 같은 컬럼 집합이지만 의미가
다르다. 지금은 둘 다 보수적으로 거부하지만, **실제 key vector 를 버리면 나중에
공개 유일 prefix 를 증명할 방법이 없다** — 그래서 순서를 보존한다.

### ★ `CARD` 는 `ROW_COUNT` 하나가 아니다 — **미탐이었다**

술어는 행 **수**뿐 아니라 **어느 공개 행이 남는지**도 누출한다. 행 수가
같아도 다른 행일 수 있다:

```
D1: (1,a),(2,b)     D2: (1,b),(2,a)     m(a)=m(b)
SELECT id FROM t WHERE secret='a'
D1 -> {1}           D2 -> {2}           ★ 행 수는 둘 다 1
```

`CARD → ROW_COUNT` 만 만들면 이걸 통째로 놓친다. 활성 sink 를 전부 만든다:

| 문맥 | sink |
|---|---|
| `WHERE` / `HAVING` / semi-join / `JOIN ON` | `ROW_COUNT`, `MULTIPLICITY`, `MEMBERSHIP` |
| aggregate `FILTER` | 그 집계의 **`CELL`** |
| **selection 이 downstream aggregate 로 흐르면** | **`CELL`** ★ |
| 투영이 행 구별을 지우면 | `MEMBERSHIP` **소거** (`ORD` 와 같은 규칙) |
| **스칼라 집계라 최종 shape 가 1행 고정이면** | shape sink **소거** ★ |

### ★ `CARD → CELL` — selection 이 집계로 흐른다

`aggregate FILTER → CELL` 만으로는 부족하다. **일반 `WHERE` 도** downstream
aggregate 의 셀 값을 바꾼다:

```
D1: (1,10,a),(2,20,b)     D2: (1,10,b),(2,20,a)     m(a)=m(b)
SELECT sum(amt) FROM t WHERE secret='a'
D1 -> 10                  D2 -> 20
```

그리고 이 질의에서 **`ROW_COUNT` 를 만드는 것은 sink 이름이 틀린 것**이다 —
최종 shape 는 둘 다 **1행**이다. 내부 선택 카디널리티는 **`CARD` effect** 이지
최종 결과 shape 의 `ROW_COUNT` sink 가 아니다. 그 영향은 `CELL` 로 나간다.

| 질의 | sink |
|---|---|
| `SELECT sum(id) … WHERE secret='a'` | **`CELL` 만** |
| `SELECT grade, sum(id) … WHERE secret='a' GROUP BY grade` | `CELL` + shape 3종 |
| `SELECT id … WHERE secret='a'` | shape 3종 (집계 없음) |
| `SELECT sum(z.id) FROM (SELECT id … WHERE secret='a') z` | `CELL` + shape 3종 |

`HAVING` 은 **집계 뒤에** 그룹을 거르므로 `CELL` 을 만들지 않는다 — 살아남은
그룹의 셀 값 자체는 바뀌지 않고, 어느 그룹이 남는지는 shape sink 가 잡는다.

P0/P1 회귀:

```
P0  CARD -> CELL 미인증                       reject
    shape sink 만 허가 -> CELL 의무가 남음      reject   ★
P1  CARD -> CELL 까지 정확한 context 로 허가    accept
```

즉 P1 은 *"술어 채널"* 이 아니라 **decision-path declassification** 이고,
그 trace 가 **downstream aggregate cell 까지** discharge 한다고 명세해야 한다.

실측:

```
SELECT id  FROM t WHERE secret='a'   -> ROW_COUNT, MULTIPLICITY, MEMBERSHIP
SELECT 'x' FROM t WHERE secret='a'   -> ROW_COUNT, MULTIPLICITY   (소거됨)
```

그리고 sink 가 **판정에 실제로 쓰인다**:

```
ROW_COUNT 만 declassify  ->  MEMBERSHIP 이 남아 **거부**
셋 다 declassify         ->  수락
```

`aggregate FILTER` 는 처음에 미탐이었다 — `count(*)` 는 인자가 없어
`src == NIL` 조기 반환에 걸렸다. **5R 에서 실측한
`count(*) FILTER (WHERE salary IS NOT NULL)` `1000 → 0` 이 정확히 그 경로다.**
`FILTER` 를 인자 검사보다 **먼저** 보게 고쳤다.

`JoinExpr` 의 `ON` 절도 놓치고 있었다 — `FromExpr->quals` 만 봐서
inner join·semi-join 의 술어가 통째로 빠졌다. `gate_collect_quals()` 로
jointree 전체를 훑는다.

### ★ `EQ`/`ORD` 는 `null_equivalence` 를 **함께** 요구한다

`sortop`/`eqop`/`nulls_first` 를 수집만 하고 판정에 안 쓴 것이 구멍이었다.
실측으로 뚫렸다:

```
order_factor = holds,  null_equivalence = fails
  ORDER BY secret NULLS LAST   -> 수락됐다   ✗
  GROUP BY secret              -> 수락됐다   ✗
```

`ORDER BY` 는 NULL 을 `cmp` 로 놓지 **않는다** — `NULLS FIRST/LAST` 로 놓는다.
마스크가 non-NULL 을 NULL 로 바꾸면 그 행이 통째로 끝(또는 앞)으로 점프하는데,
`order_factor` 는 `cmp` 에 대한 주장이라 이걸 덮지 못한다. `GROUP BY` 도 SQL
grouping 이 NULL 들을 한 그룹으로 묶으므로 같은 문제다.

> **[정정]** 앞 판에는 이 조합을 *"그 자체로 모순"* 이라고 썼다. **틀렸다.**
> `order_factor` 를 **non-NULL 정의역의 comparator 주장**으로 정의하면 둘은
> 양립한다. 정확한 진술은 *"그것만으로는 SQL 전체 정렬 인증서로 불충분하다"*
> 이다. 즉 의무를 이렇게 분해해야 한다:
>
> ```
> ORD = NullPartitionPreserved ∧ ComparatorFactors
> EQ  = NullPartitionPreserved ∧ EqualityFactors
> ```

`null_equivalence` 가 앞의 연언지다. 뒤의 연언지가 다음 절이다.

### ★ comparator 인증서 — **어느 연산자에 대한** 주장인가

`order_factor`/`equality_factor` 를 마스크 단독 속성으로만 두면 구멍이다.
같은 마스크가 표준 `<` 에는 factor-through 해도 사용자 정의 역순·부분순서
연산자에는 그렇지 않을 수 있다. 그래서 네 번째 레지스트리를 뒀다:

```
EQ  인증서 키:  mask_instance, eqop_oid,   collation, comparator_fingerprint
ORD 인증서 키:  mask_instance, sortop_oid, collation, comparator_fingerprint
```

**미등록 comparator 는 `unknown → reject`.** 일반 사용자 정의 연산자를 지원할
필요는 없고 **표준 연산자만 등록해도 충분**하다
(`ipguard_register_default_comparators()` 가 기본 btree `<`·`>`·`=` 를 등록).

| | 판정 |
|---|---|
| 기본 sortop 인증됨 | 수락 |
| ORD comparator 인증서 삭제 | **거부** — `order_factor` 만으로는 부족 |
| EQ comparator 인증서 삭제 → `DISTINCT` | **거부** |
| `ORDER BY … DESC` (다른 sortop `>`) | 수락 — 기본 등록에 포함 |
| **`ORDER BY … USING ~<~`** (`text_pattern_ops`) | **거부** ★ |

마지막 행이 요점이다 — 기본 `<` 인증서가 **다른 opfamily 의 연산자를 덮지
않는다.**

> **[정확히 말하면]** 측정 환경의 DB 는 `lc_collate = C` 다(평가 동결
> 아티팩트 참조). 그래서 이 인스턴스에서는 기본 `<` 도 이미 바이트 순서라
> `~<~` 와 **결과가 같다.** 즉 이 대조군이 보이는 것은 *"두 비교자의 의미가
> 달라서 결과가 갈린다"* 가 아니라 **"인증서가 연산자로 키잉된다"** 는
> 사실이다. 후자가 검증 대상이므로 시험은 유효하지만, 전자를 주장하면
> 이 환경에서는 거짓이다. 의미 차이가 실제로 드러나려면 `lc_collate` 가
> `C` 가 아닌 인스턴스가 필요하고, 여기서는 만들 수 없다.

집합연산도 `SetOperationStmt.groupClauses` 의 `eqop` 를 써서 같은 검사를 받는다
— 안 그러면 집합연산만 comparator 인증을 우회한다.

### ★ 기본 comparator 등록은 **증명을 생성하지 않는다**

`ipguard_register_default_comparators()` 는 `claim`·`assurance` 에 **기본값이
없다.** "btree 기본 연산자니까 `holds`" 를 자동으로 만들면 안 되기 때문이다 —
기본 comparator 라는 사실은 **연산자를 식별**해 줄 뿐, 특정 마스크가 그
비교자를 factor through 한다는 증거가 아니다.

인증서는 넷의 결합이다:

```
MaskInstance
ComparatorInstance(op_oid, collation, fingerprint)
claim_value
assurance
```

회귀로 못박았다 — `order_factor = holds` 인 상태에서 기본 comparator 를
`claim = unknown` 으로 등록하면 **거부된다.**

### ★ declassification 키에 context fingerprint 가 들어간다

```
Declass( sources, effect, context_fingerprint, sink, observation )
```

`context_fingerprint` 에는 **키 표현식·비교자·collation** 이 들어간다.
앞 판은 *"`bare_var=false` 면 무조건 거부"* 라는 **구현의 특별 규칙**이었는데,
그러면 형식 명세와 구현이 어긋난다. 인증서 **키**로 처리하면 데이터로
표현되고, 정책이 좁은 문맥을 명시적으로 허가할 수도 있다.

| `(secret, ORD, FINAL_ORDER)` 를 bare 문맥으로 허가한 상태 | 판정 |
|---|---|
| `ORDER BY secret, id` | 수락 |
| `ORDER BY lower(secret), id` | **거부** — context_key 가 다르다 |
| `ORDER BY secret USING ~<~, id` | **거부** — 비교자가 다르다 |

값은 손으로 만들 수 없다. `ipguard_obligations(sql)` 에서 읽어 그대로
인증서에 넣는다 — 정책이 허가한 문맥과 게이트가 판정하는 문맥이 어긋나면
인증서가 있는데 거부되거나(운영 사고) 없는데 수락된다(누출).

#### canonical 을 **같이 저장**한다 — opaque hash 만으로는 부족하다

```
context_canonical                                    -- 정책 담당자가 읽는다
context_key = sha256(version || domain || canonical) -- 게이트가 맞춰본다
```

canonical 은 **길이 구분 인코딩**이다. 단순 문자열 결합은 구분자 충돌로 서로
다른 문맥이 같은 문자열이 될 수 있고, 인증서 키에서는 그게 곧 우회다.

들어가는 것 / 빠지는 것:

| 넣는다 | 뺀다 |
|---|---|
| 순서 보존된 key expression | `location` |
| `relid.attnum` 기반 source identity (**공개 컬럼 포함**) | alias |
| 함수·연산자 OID | 내부 `varno` |
| 상수의 타입과 값 | |
| collation, `NULLS FIRST/LAST`, sortop/eqop | |
| effect, sink | |

뺀 것들은 의미와 무관하거나 rewrite 마다 달라진다 — 넣으면 같은 질의가
재작성 경로에 따라 다른 키를 내서 인증서가 있는데 거부된다.

실제 출력:

```
v:1:1;effect:3:ORD;sink:11:FINAL_ORDER;kind:19:ORDER BY key vector;nkey:1:2;
term:0:;shape:4:bare;sortop:3:664;eqop:2:98;coll:7:default;nullsfirst:1:0;
  var:0:;vtype:2:25;col:7:16386.4;
term:0:;shape:4:bare;sortop:3:412;eqop:3:410;coll:7:default;nullsfirst:1:0;
  var:0:;vtype:2:20;col:7:16386.1;
```

두 key term 이 **순서대로** 있고, 라벨된 `16386.4`(ssn)와 공개 `16386.1`(id)이
둘 다 identity 로 들어간다 — `ORDER BY grade, secret` 과
`ORDER BY dept, secret` 은 다른 문맥이다.

#### ★ parameterized predicate

`WHERE secret = $1` 의 인증서가 **모든 `$1` 값에 조용히 재사용되면 안 된다.**
`param_scope` 를 명시적으로 둔다:

| `param_scope` | 뜻 |
|---|---|
| `none` (기본) | 파라미터가 있으면 **거부** |
| `domain` | 정책이 **그 파라미터 정의역 전체를 허가**한다고 명시 |

실측:

| | 판정 |
|---|---|
| `WHERE secret = $1`, `param_scope='none'` | **거부** |
| 같은 인증서를 `param_scope='domain'` 으로 | 수락 |
| `WHERE secret = 'a'` (상수는 다른 문맥) | **거부** |
| `'a'` 에 발급 → `WHERE secret = 'b'` | **거부** — `cval` 이 canonical 에 있다 |
| `'a'` 에 발급 → `WHERE secret <> 'a'` | **거부** — `opno` 가 다르다 |

`CARD`/`VAL` 노드도 **표현식 자체를 담는다.** 안 담으면 같은 컬럼의 모든
술어가 하나의 context 를 공유해서 `WHERE secret='a'` 인증서가 `= $1` 과
`<> 'b'` 까지 덮는다 — 실제로 처음 구현이 그랬고 실측으로 잡았다.

파생 표현식에 대한 **합성 증명 경로는 여전히 없다.** scalar compatibility 로
공개 표현을 도출한 뒤 그 결과 comparator 를 인증하는 것이 올바른 해법이고,
지금은 명시적 declassification 이 없으면 거부한다.

### 레지스트리 조회가 터져도 fail-open 되면 안 된다

`ipguard_busy` 를 boolean 에서 **깊이 카운터**로 바꿨다. SPI 가 오류를 내며
`longjmp` 하면 플래그가 복원되지 않아 **그 백엔드의 이후 모든 질의가 게이트를
우회**한다 — fail-open 이다. `PG_CATCH` 에서 감소시키고 `PG_RE_THROW` 한다.

```
조회 오류 전            -> accept
ipguard_capability 가 RAISE  -> 수락이 아니라 오류    ★
복구 후                 -> accept
```

## ★ sink 는 구문별로 열거하면 안 된다 — transfer function 감사

구문마다 손으로 sink 를 적어 왔고, 그래서 **다섯 번 연속 빠졌다.**

| | 빠졌던 경로 |
|---|---|
| W1 | `SELECT sum(amt) FROM t GROUP BY secret` — `EQ → 집계 CELL` |
| W2 | `SELECT grade … ORDER BY secret,id LIMIT 2` — `ORD → MULTIPLICITY` |
| W3 | `SELECT sum(amt) FROM (… ORDER BY secret,id LIMIT 2) s` — **의무 0개** |
| W4 | `SELECT sum(v) FROM (… GROUP BY grade HAVING max(secret)='a') s` — `→ 바깥 CELL` |
| W5 | `SELECT count(*) FROM (… UNION …) z` — `→ 바깥 CELL` |

각 질의 수준이 **세 요약**을 돌려주도록 바꿨다:

```
bag_in    집계에 들어가는 행 집합을 바꾸는 effect
bag_out   이 질의의 출력 bag 을 바꾸는 effect
ord       이 질의의 출력 순서를 바꾸는 effect
```

**서브쿼리의 `bag_out` 이 부모의 `bag_in` 으로 흐른다** — 질의 경계를 넘는
합성이 자동으로 잡힌다. 연산자별 전파는 명세 §2 에 표로 고정했다.

### 행 **수**를 바꾸는가, **어느 행인지**만 바꾸는가

```
CARD(WHERE) / EQ(DISTINCT·GROUP BY)   행 수가 달라진다
ORD + LIMIT n                          항상 min(n,|입력|) 행
```

`W2` 에서 **`ROW_COUNT` 는 sink 가 아니다** — 항상 2행이다. 바뀌는 것은
선택된 공개 `grade` 의 bag 과 multiplicity 다. 이걸 구별하지 않으면 `Q6'`
(`SELECT 'x' … LIMIT 3`)이 `ROW_COUNT` 로 거부된다.

```
count_affecting   -> ROW_COUNT, MULTIPLICITY  (행이 구별 안 돼도 관찰)
!count_affecting  -> MULTIPLICITY, MEMBERSHIP (행이 **구별될 때만**)
```

`HAVING` 은 같은 수준 `CELL` 을 만들지 않지만 `bag_out` 을 통해 **바깥 집계
`CELL`** 로는 흐른다(W4). 두 대조군을 다 박았다.

### value path 도 합성적으로 — `ExprSummary`

structural 만 합성적이고 value 가 즉석 walker면 중첩에서 같은 누락이 재발한다.
표현식은 **의무를 만들지 않고 요약을 돌려준다.**

| | 질의 | 의무 |
|---|---|---|
| V1 | `SELECT secret` | **없음** — `Mout` 이 가린다 |
| V2 | `lower(secret)` | `VAL/CELL` |
| **V3** | `upper(x) FROM (SELECT lower(secret) AS x …)` | `VAL/CELL` ★ 경계를 넘는 합성 |
| V4 | `concat(secret, grade)` | `VAL/CELL` |
| **V5** | `CASE WHEN secret='a' THEN …` | `VAL/CELL` ★ control lineage |
| V6 | `min(secret)` | `VAL/CELL` |
| V7 | `secret, count(*) … GROUP BY secret` | `EQ/CELL` + shape 3종 |
| **V8** | `lower(x) FROM (… UNION ALL …)` | `VAL/CELL` ★ |
| N1 | `id … ORDER BY lower(secret)` | `ORD/FINAL_ORDER` **만** (VAL 없음) |
| N2 | `id … WHERE lower(secret)='a'` | `CARD` 3종 **만** (VAL 없음) |

### ★ 사슬이 아니라 **proof tree** 여야 한다

```
ExprProof = Public | Source(mask) | Apply(fn_ctx, args[], out_mask)
          | Aggregate(agg_ctx, args[], out_mask) | Unknown
```

평탄한 `[lower, upper, concat]` 로는 어느 함수가 어느 mask 를 소비하는지,
인자 위치가 무엇인지, branch 결과 mask 가 무엇인지를 증명할 수 없다.
`f(m(x)) = r_out(f(x))` 이므로 각 `Apply` 는 **출력 마스크 id** 를 돌려주고
부모가 그걸로 다시 조회한다.

| 음성 대조군 | 판정 |
|---|---|
| `lower` 인증서 삭제 → `upper(lower(secret))` | **거부** |
| `upper` 인증서 삭제 | **거부** |
| 2인자 함수 인증서 삭제 | **거부** |
| **인자 위치가 다른 인증서만 존재** (`pos=1` 만) | **거부** ★ |
| **마스킹된 입력 둘** (`f(lower(s), upper(s))`) | **거부** — 공통 출력 마스크 증명 불가 |

### ★ bare 출력의 `MASK_APPLY` baseline

`SELECT secret` 에는 commutation 의무가 없지만 — `Mout` 이 같은 마스크를
직접 적용하므로 — **MaskInstance 의 코어 전제는 봐야 한다:**

```
MASK_APPLY(mask_instance) := deterministic ∧ total ∧ 지문 일치
```

생략하면 미등록 UDF 나 변경된 마스크가 bare output 으로 인증 없이 나간다.
앞 판은 V1 에 의무를 **하나도** 만들지 않았다.

### 실측으로 잡은 것 — 서브쿼리 경계에서 proof 손실

`sum_merge` 가 `sources` 만 합치고 **`proof` 를 넘기지 않았다.** 그래서
`upper(x) FROM (SELECT lower(secret) AS x …)` 의 `lower` branch 가 `PUBLIC`
으로 취급돼, **인증서를 지워도 통과했다.** 리뷰가 예측한
*"subquery 경계에서 lineage 를 잃을 위험"* 이 그대로 실재했다.

`V5` 는 값 변환이 아니라 **control lineage** 라 commutation 인증서로
해소되지 않는다(`UNKNOWN` → 거부).

**미지원 표현식 노드에 라벨 source 가 있으면 `UNMODELED_EXPR` 로 거부**한다.
그래서 완전성을 witness 개수가 아니라 **지원 AST 에 대한 전수 fail-closed
transfer table** 로 방어한다(명세 §2 종료 조건 3항).

## ★ 경계 폐쇄성 행렬 — 표를 만든 것과 코드가 표대로 도는 것은 다르다

`cells[]` 가 실제로 경계에서 끊겨 있었으므로, `bag_out` 과 `ord` 도 네 조건을
전부 확인한다.

| 조건 | 의미 |
|---|---|
| propagation | 자식 effect 가 부모 sink 까지 도달 |
| missing proof | 자식 인증서 삭제 시 거부 |
| context preservation | 다른 연산자·상수·collation 인증서로 통과하지 않음 |
| erasure | 부모가 관찰을 지우면 의무도 사라짐 |

| | 질의 | 결과 |
|---|---|---|
| B1 | `sum(id) FROM (… WHERE secret='a')` | `CARD → 부모 CELL` |
| B2 | `sum(v) FROM (… GROUP BY secret)` | `EQ → 부모 CELL` |
| B3 | `count(*) FROM (… UNION …)` | `EQ → 부모 CELL` |
| O1 | `sum(id) FROM (… ORDER BY secret,id LIMIT 2)` | `ORD → 부모 CELL` |
| O2 | `… FROM (… ORDER BY secret,id) s LIMIT 2` | `LIMIT without ORDER BY` → `F_core` 밖 |
| **O3** | `… FROM (… ORDER BY secret,id) s` | **의무 없음** — 자식 order 소거 |
| **O4** | `… FROM (… ORDER BY secret) s ORDER BY id` | **의무 없음** — 공개 order 가 대체 |

`O3`/`O4` 는 명세 §1 을 따른다 — PostgreSQL 이 물리적으로 안쪽 순서를
보존하더라도 **최상위 `ORDER BY` 가 없으면 관찰 의미는 Bag** 이다.

missing proof · context preservation:

```
B1 'a' 인증서 발급 -> 수락 ;  같은 상태에서 'b' -> 거부    (상수가 canonical 에)
B1 인증서 삭제                                  -> 거부
B2 EQ comparator 삭제                          -> 거부
B3 set-op 도 같은 이유로                         -> 거부
O1 ORD comparator 삭제                         -> 거부
ORDER BY secret USING ~<~ 가 경계를 넘어도
  기본 `<` 인증서로 통과하지 않는다               -> 거부
```

### ★★ 이 행렬이 찾은 것 — 게이트가 통째로 안 돌던 경로

의무 목록에는 `UNDISCHARGED` 가 넷 떠 있는데 **질의는 수락**됐다.

라벨 접촉 여부를 `walk_query` 기반 **사전검사**로 판정하고 있었고, 그건
출력 `Var` 가 가리키는 컬럼만 따라간다. 그래서

```sql
SELECT sum(s.id) FROM (SELECT id FROM t WHERE secret='a') s
```

처럼 **민감 컬럼이 서브쿼리 술어·`GROUP BY`·`ORDER BY` 에만** 있으면
"PII 없음" 으로 판정돼 **release 게이트가 아예 돌지 않았다.**

`resjunk` 사각지대와 같은 뿌리다 — 이번에는 사전검사의 탐색 범위가 게이트의
탐색 범위보다 좁았다. 게이트 자신이 순회하며 세우는 플래그(`gate_touched`)
로 바꿨다.

## 판정 행 — 118/118

### [1] 기본: 상수 마스크(`order_factor = fails`), 인증서 없음

| 질의 | 판정 | 왜 |
|---|---|---|
| `Q10 SELECT 'x' … ORDER BY secret` | **수락** | 출력 행이 전부 같아 순서가 결과 bag 을 못 바꾼다 |
| `Q9  SELECT id … ORDER BY secret, id` | **거부** | `ORD → FINAL_ORDER(공개 id)` |
| `Q6  … LIMIT 3` | **거부** | `ORD → MEMBERSHIP` + `FINAL_ORDER` |
| **`Q6' SELECT 'x' … ORDER BY secret, id LIMIT 3`** | **수락** | ★ 아래 |
| 비민감 대조군 | 수락 | 라벨된 source 가 없다 |

**`Q6'` 가 이 구현의 강한 증거다.** 정렬 키 `(secret, id)` 는 **전순서**이고
`LIMIT` 도 있다 — 즉 `ORD` 도 `CARD` 도 있다. 그런데 수락한다:

- 선택된 row identity 가 **투영에서 사라진다**(모든 행이 `'x'`)
- 반환 건수는 `min(3, |t|)` 로 **공개 입력 multiplicity** 가 정한다

`ORD` 를 보고 일괄 거부하는 게이트는 여기서도 거부한다 — 건전하지만 지나치게
불완전하다. `Q10` 과 `Q6'` 를 **수락하면서** `Q9`·`Q6` 을 거부해야 effect→sink
소거를 실제로 구현한 것이다.

### [2] 전순서 보존 마스크 (`order_factor = holds`)

| | |
|---|---|
| `Q9` | **수락** — factor-through 로 해소 |
| `Q6` | **수락** — 같은 `ORD` 노드라 함께 해소 |
| `SELECT DISTINCT secret` | **거부** — `order_factor` 가 `equality_factor` 를 대신하지 않는다 |

### [3] declassification — `(effect, context, sink)` 단위

| | |
|---|---|
| `(secret, ORD, FINAL_ORDER)` 만 허가 → `Q9` | **수락** |
| 같은 상태에서 `Q6` | **거부** ★ |
| `(secret, ORD, MEMBERSHIP)` 도 허가 → `Q6` | 수락 |
| 그래도 `DISTINCT secret` | **거부** — `EQ` 는 별개 |

**같은 컬럼·같은 effect 라도 sink 가 다르면 별도 허가가 필요하다.** 명세 §3.5
가 요구한 4-튜플 `Declass(source, effect, sink, observation)` 이 실제로 그렇게
동작한다.

### [4] 인증서 `unknown` → 거부

`order_factor = unknown`, `equality_factor = unknown`, **MaskInstance 자체가
미등록** — 셋 다 거부. 등록 안 된 것이 조용히 "안전" 으로 읽히면 레지스트리가
있으나 마나다.

### [5] ★ 연결 회귀 — 같은 generic plan: 철회 → 재계획 → 거부

무효화 범위가 **세 군데**여야 한다. 하나라도 빠지면 사용자가 정책을 바꿨는데
캐시된 옛 계획이 계속 돌면서 **에러도 경고도 없다.**

레지스트리 회귀(F 그룹)는 *"철회가 캐시된 계획까지 닿는다"* 는 **기전**만
확인했다. 게이트가 레지스트리를 읽게 된 지금은 **같은 generic plan** 을 대상으로
셋을 한 번에 봐야 한다.

```
holds 인증서로 generic plan 생성                    -> accept      ✓
다른 backend 에서 order_factor 철회 COMMIT
같은 generic plan EXECUTE
  -> ipguard_pii_plan_count()  +1                  (재계획됐다)   ✓
  -> ORD(ORDER BY key vector) -> FINAL_ORDER :
     order_factor=unknown                                          ✓
  -> reject                                                        ✓
```

같은 방식으로 **declassification 철회**도 확인했다:

```
declassification 으로 generic plan 생성            -> accept
다른 backend 에서 DELETE ... COMMIT
같은 plan EXECUTE  -> 계획 +1 -> reject
```

그리고 **gate 모드 전환**도 계획을 무효화해야 한다:

```
ipguard.gate = legacy 로 generic plan 생성         -> accept
SET ipguard.gate = release
같은 plan EXECUTE  -> 계획 +1 -> release 판정 -> reject   ★
```

이게 없으면 사용자가 release 로 바꿨는데 캐시된 legacy plan 이 계속 실행된다.
`ipguard.enforce` 와 `ipguard.gate` 에 GUC assign hook 을 달아
`ResetPlanCache()` 를 부르고, `ipguard_declassification` 을
`ipguard_watch_registry()` 대상에 넣었다.

`plan_cache_mode = force_generic_plan` 아래에서 쟀다.

## legacy 와 나란히 둔다

`ipguard.gate = legacy | release`, **기본은 legacy**. 하나로 합치면 어느
게이트가 무엇을 잡았는지 구별할 수 없고 §11-5 비교가 불가능해진다.

기본값으로 돌린 회귀는 **전부 불변**이다: 조용한 오답 0/45(판정식 ON, 거부 28),
과마스킹 0, 삼자택이 표 A(V1 9/9·4/9·9/9 · V2 6/9·6/6·4/6 · V3 9/9·9/9·5/9),
레지스트리 46/46.

## 구현 노트 — SPI 재귀

`release_gate` 는 레지스트리 조회 API 를 SPI 로 부른다. 그 질의들이 다시
`planner_hook` 을 타고 들어와 또 게이트를 돌리면 **무한 재귀**한다.
`load_labels` 가 같은 이유로 이미 `ipguard_busy` 가드 안에 있고, 게이트도 같은
가드 안에서 돌려야 한다. 처음 구현에서 가드 밖에 뒀다가 잡았다.

## 한계

- **`rows_distinguishable()` 는 보수적이다.** non-resjunk 타깃이 전부 `Var` 를
  포함하지 않을 때만 "구별 불가" 로 판정한다. `SELECT 1+1`, `SELECT 'a'||'b'`
  는 잡지만, 상수 함수 결과나 함수 종속으로 상수가 되는 경우는 못 잡는다 —
  건전한 방향의 불완전성이다.
- **공개 prefix 가 유일키인 경우를 아직 안 본다.** `ORDER BY id, secret` 은
  `id` 가 PK 라 `secret` 이 절대 참조되지 않으므로 안전한데, 현재는 키 벡터에
  라벨 컬럼이 있으면 의무를 만든다. 과거부이고 §11-5 에서 비용으로 잡힌다.
- **`CARD` 는 factor-through 로 해소되지 않는다** — declassification 만이
  경로다. V2 가 설계상 술어를 원본으로 두므로, 술어 채널을 쓰는 모든 질의는
  명시적 인증서가 필요하다. 이것이 legacy 대비 acceptance 를 크게 낮춘다.
- 지문을 계획마다 SPI 로 재계산한다. **성능은 이 호스트에서 잴 수 없다.**
- **`ORDER BY id, secret` 처럼 공개 유일 prefix 가 있는 경우를 아직 증명하지
  않는다.** key term 순서는 보존하지만 유일성 판정을 안 한다 — 과거부다.
- **서브쿼리 selection 에 shape sink 를 보수적으로 남긴다.** 바깥이 집계해
  최종 shape 가 1행이어도 서브쿼리의 행 수가 다른 경로로 새어나갈 수 있다고
  가정한다 — 과거부다.
- `KeyTerm` 의 `nulls_first` 는 `null_equivalence` 강제 전제로 **간접적으로만**
  덮인다. `NULLS FIRST` 와 `NULLS LAST` 를 구별한 직접 판정은 후속이다.
- 파생 키(`lower(secret)`)에 대한 **합성 증명 경로가 없다.** scalar
  compatibility 로 공개 표현을 도출한 뒤 그 comparator 를 인증하는 것이
  올바른 해법이고, 지금은 거부만 한다 — 과거부다.

## 재현

```bash
python3 tools/score_gate.py
```
