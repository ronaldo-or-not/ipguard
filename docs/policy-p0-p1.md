# 평가 정책 P0 / P1 — 형식 정의와 결정적 발급 규칙

**seed 를 파생하기 전에 동결한다.** 정책이 seed 재료에 없으면 "결과를 보고
정책을 골랐다" 는 반론을 막을 수 없다(`docs/heldout-protocol.md`).

---

## P0 — declassification 없음

```
Declass_P0 = ∅
δ_P0(Q, θ, D) = ()          -- 빈 튜플
```

모든 trial 이 **자동으로 δ-equivalent** 다(`δ_P0(D1) = () = δ_P0(D2)`).
따라서 P0 의 acceptance 는 **순수 certification acceptance** 이고,
applicability 판정이 필요 없다.

## P1 — decision-path declassification

> *"술어 채널"* 이라는 표현은 부정확하다. `CARD` 는 `ROW_COUNT` 하나가 아니라
> `MULTIPLICITY`·`MEMBERSHIP`·(집계로 흐르면) `CELL` 까지 간다
> (`results/gate.md`). 정확한 이름은 **decision-path declassification** 이다.

```
지정된 decision-predicate origin 에서 발생한
  effect = CARD
  sink   ∈ 그 obligation 의 active observable sink
만 declassify 한다. exact context_key 를 쓴다.
VAL / EQ / ORD 는 허가하지 않는다.
```

**origin 은 다섯 가지뿐이다:**

```
WHERE · JOIN_ON · HAVING · AGG_FILTER · SEMIJOIN
```

### P1 은 sink 별 최소 허가가 아니라 **decision trace 전체**를 허가한다

> *P1 declassifies the complete decision trace of designated predicates;
> sink-specific certificates restrict where that trace may affect
> observations.*

정직하게 이렇게 써야 한다. `δ_{Q,θ}` 를 predicate outcome trace 로 정의하면
downstream aggregate `CELL` 까지 **일관되게** 설명되지만, 그 trace 는 실제
sink 보다 **강한** declassification 일 수 있다.

---

## 결정적 발급 알고리즘 — 입력은 **raw obligation stream**

★ **`ipguard_obligations()` 가 현재 인증서로 이미 discharge 된 것을 빼고
반환하면 정책 생성이 registry 상태에 종속된다.** 정책 script 는 discharge
**이전의** 전체 structural obligation stream 을 받아 고정 규칙만 적용한다.

```
입력으로 쓰면 안 되는 것:
  - 현재 인증서 유무
  - legacy/release 수락 결과
  - 게이트 판정
```

```
for each obligation o in raw_stream(Q):
    if policy == P0:                     continue          # 아무것도 발급 안 함
    if o.effect != 'CARD':               continue          # VAL/EQ/ORD 불허
    if o.origin ∉ {WHERE, JOIN_ON, HAVING, AGG_FILTER, SEMIJOIN}: continue
    if o.context_key is unstable:        continue          # non-built-in type 등
    issue Declass(
        source      = o.sources,
        effect      = 'CARD',
        sink        = o.sink,            # active sink 그대로
        context_key = o.context_key,     # 게이트에서 읽은 값. 손으로 안 만든다
        context_canonical = o.context_canonical,
        param_scope = 'all_values' if o.has_param else 'none',
        observation = 'predicate-decision-trace')
```

**수동 가감은 없다.** 생성 후 인증서를 고르거나 빼면 그 시점부터 결과가
정책이 아니라 선택이 된다.

### 인증서 목록 digest — **record hash 를 정렬**한다

> `(relid, attnum, effect, sink, context_key)` 는 `ipguard_declassification`
> 의 **full primary key** 이므로 그 자체로는 결정적이다. 그래도 아래 방식을
>쓴다 — **PK 정의가 바뀌면 digest 규칙도 조용히 깨지기** 때문이고,
> `observation`·`param_scope` 는 인증서의 **의미**인데 정렬 키에 없었다.

```
certificate_record = canonical_encode(
    policy_version,
    ordered_sources[],      -- (relid, attnum) 를 정렬해 나열
    effect,
    sink,
    context_key,
    observation,
    param_scope)

certificate_digest = SHA256( concat( sort( SHA256(record) for record ) ) )
```

encoding 은 context canonical 과 같은 **길이 구분**을 쓴다:

```
f"{name}:{len(value)}:{value};"
```

이러면 digest 가 **SQL 반환 순서에도, 빠진 tie-breaker 에도 의존하지 않는다.**
개별 record hash 를 정렬하므로 인증서 사이의 순서 개념 자체가 사라진다.

---

## δ oracle — predicate outcome trace

`δ_{Q,θ}(D)` 를 **decision trace** 로 정의한다. 그래야 downstream aggregate
`CELL` 까지 일관되게 설명된다.

| origin | trace 원소 |
|---|---|
| `WHERE` · `AGG_FILTER` | `(public row occurrence id, T/F/NULL)` |
| `JOIN_ON` | `((left id, right id), T/F/NULL)` |
| `SEMIJOIN` | `(left id, matching-right-id bag 또는 existence result)` |
| `HAVING` | `(group occurrence identity, T/F/NULL)` |

★ **`HAVING` 의 group identity 는 민감 group key 가 아니라 그 그룹을 구성하는
public row-id bag** 이다. 민감 키를 쓰면 그 자체가 누출이고, public bag 을
쓰면 D1/D2 에서 그룹 구성이 다를 때 자연스럽게 `δ-equivalent = false` 가 된다.

★ **3VL 결과를 `T/F` 로 축약하면 안 된다.** `NULL` 까지 보존해야 NULL 관련
정책 차이를 놓치지 않는다.

★ parameterized 질의는 **정확한 `θ` binding 과 함께** trace 를 계산한다.
`all_values` 인증서는 모든 가능한 `θ` 에 대한 공개이므로, 값을 적응적으로
바꾸면 secret 을 열거할 수 있다 — 강한 declassification 이고 논문에 명시한다.

### canonical encoding

```
trace_canonical =
  origin '\x1f' sorted( element_encoding for element in trace )
element_encoding = key_repr '\x1f' outcome     # outcome ∈ {T, F, NULL}
key_repr = public row/group identity, 길이 구분 인코딩
```

정렬해야 평가 순서가 결과를 바꾸지 않는다.

---

## applicability 판정 — **게이트 결과를 보기 전에**

각 `(Q[θ], pair)` trial 에 대해:

| 조건 | 필수 | 실패하면 |
|---|---|---|
| `M(D1) = M(D2)` | 항상 | **pair 생성 결함** |
| `δ_{Q,θ}(D1) = δ_{Q,θ}(D2)` | P1 에서만 | 그 trial 은 **scoped-opacity 비교 불가** |

- 비교 불가능하다고 **질의를 폐기하지 않는다.** `opacity_applicable = false`
  로 남기고 별도 집계한다.
- P0 는 `δ_P0 = ()` 이므로 **모든 trial 이 applicable** 이다.
- P1 에서 membership 이 허가된 두 DB 의 membership 이 다르면 그건
  **opacity 실패가 아니라 `δ-equivalent = false`** 다. applicability 비율을
  반드시 함께 보고한다.

---

## label-free outside-fragment 대조군

전체 traversal 을 **먼저** 돌리므로, 라벨 미접촉 질의까지 fragment 제한을
받으면 안 된다. 순서:

```
traverse and summarize
if no labeled source touched:  accept
if outside F_core:             reject   OUTSIDE_CERTIFIED_FRAGMENT
if unmodeled:                  reject   UNMODELED_NODE / UNMODELED_EXPR
discharge obligations
```

실측(`results/gate.md`):

```
public-only window / outer join   -> accept
sensitive-touching window          -> OUTSIDE_CERTIFIED_FRAGMENT
```

---

## 보고 단위

```
400     generated queries
1,600   pair trials              (= 400 × 4 pair 유형)
?       masked-equivalent trials
?       δ-equivalent trials      (P0 는 전부)
?       release-accepted applicable trials
?/?     opacity successes / failures
```

질의 수와 trial 수는 **다른 단위**다. 섞으면 표본이 부풀려진다.
