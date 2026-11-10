# 환원 감사 — Blockaid / Mascara 대비 잔여 기여

목적: 구현을 더 하기 전에, 우리 기법이 선행연구로 환원되는지 **정면으로** 따진다.
환원되지 않는 잔여분이 작거나 인위적이면 방향을 바꾼다.

## 0. 검증 상태 — 먼저 밝힌다

| 대상 | 상태 |
|---|---|
| Blockaid | **본문 확인.** 정의 4.4·4.5, 가정, 한계 문장을 원문에서 인용 |
| Mascara | **본문 확인.** DNB 공개 사본 28쪽에서 정의·알고리즘·정리·평가를 확인 |
| Tattle-Tale | 미확인 — 이 감사의 결론에 쓰지 않는다 |

Mascara 공개 전문:
<https://npregional.dnb.de/objekte?idn=1362066206&iln=63>

직전 판단에서 저지른 오류를 기록해 둔다: 요약 모델이 생성한 문장
("row count remains outside its threat model")을 논문의 진술처럼 인용했다.
그 문장은 원문에 없다. set 결과의 행 수는 set equality 에 포함되므로
빠지는 것은 **duplicate multiplicity 와 order** 다.

---

## 문장 1 — opacity 는 release determinacy 의 한 형태다

**인정한다.** 우리 정의로

    R(D)   = (M(D), δ_Q(D))
    O_Q(D) = M_out(Res(Q, D))
    opacity:  R(D1) = R(D2)  ⟹  O_Q(D1) = O_Q(D2)

이고, 이는 `O_Q` 가 `R` 에 의해 **결정된다**는 진술이다. 동치류 위에서는
`O_Q = h ∘ R` 인 `h` 의 존재와 같다. 공역이 `Set` 에서 `Bag`/`OrderedBag`
으로 바뀌어도 이 추상 관계는 깨지지 않는다.

Blockaid 의 정의 4.5(trace determinacy)는 구조적으로 같은 모양이다:

> `V^ctx(D₁) = V^ctx(D₂) (∀V∈𝒱)` 이고 `Qᵢ(D₁) = Oᵢ`, `Qᵢ(D₂) = Oᵢ`
> `(∀1≤i≤n)` 이면 `Q(D₁) = Q(D₂)`

> "We call Definition 4.5 trace determinacy because it extends the classic
> notion of query determinacy with the trace."

정책 뷰 `𝒱` 자리에 `M(D)` 와 `δ_Q(D)` 를 놓으면 우리 opacity 가 된다.
**따라서 "우리 원리는 determinacy 가 아니다" 는 주장은 포기한다.**
원리의 최초성은 주장할 수 없다.

마찬가지로 "마스크 함수가 없으니 인코딩 불가" 도 과했다. 추상 모델에서는
`M(D)` 를 정책 뷰로 두면 된다 — 마스크가 해당 논리로 표현 가능하다는
전제가 필요할 뿐, 개념적 인코딩이 불가능한 것은 아니다.

---

## 문장 2 — Blockaid **checker** 가 지원하지 않는 것

원리는 가깝지만 지원 의미론과 집행이 다르다. 원문 인용:

### 2.1 set semantics

> "Relational algebra has five operators … and tables are interpreted as
> *sets* of rows (i.e., no duplicates)."

논문 스스로 간극을 인정한다:

> "While the encoding assumes that relational algebra is evaluated under
> *set semantics*, in practice databases use a mix of set, bag, and other
> semantics when evaluating queries."

### 2.2 중복 없음 가정

> "Blockaid must first assume that database tables contain no duplicate
> rows. This is generally the case for web applications as
> object-relational mapping libraries like Active Record and Django add a
> primary key for every table."

### 2.3 ordering

형식 모델:

> "Blockaid adds any ORDER BY column as an output column and then discards
> the ORDER BY clause. It also discards any LIMIT clause but, when adding
> the query to the trace, uses a modified condition `Oᵢ ⊆ D(Qᵢ)` (instead
> of `=`) to indicate that it may have observed a partial result."

프로토타입:

> "Our prototype does not verify that queries return no duplicate rows and
> does not look at any ORDER BY columns. **We manually ensured that queries
> in our evaluation return no duplicates and do not reveal inaccessible
> information through ORDER BY.**"

즉 duplicate multiplicity 와 ordering 누출은 **평가에서 수동으로 배제**됐다.
시스템이 다룬 것이 아니다.

### 2.4 미지원 SQL

> "The SQL features not supported include GROUP BY, ANY, EXISTS, etc.,
> although they can also be formulated / approximated using basic queries."

> "We only support IN and NOT IN with a list of values, not with a
> subquery."

### 2.5 정확히 무엇이 빠지는가 — 과장하지 않고

| 관찰 채널 | Blockaid |
|---|---|
| `CELL` (셀 값) | 다룬다 |
| `MEMBERSHIP` (어느 행이 나오는가) | 다룬다 |
| `ROW_COUNT` | **다룬다.** 중복 없는 set 결과의 행 수는 set equality 에 포함된다 |
| `MULTIPLICITY` (중복 개수) | 가정으로 배제 |
| `FINAL_ORDER` | 모델 밖. 프로토타입은 보지 않음 |
| 마스킹된 값의 fidelity | 개념 자체가 없음 — 통과한 질의는 원본 DB 에 그대로 실행된다 |

`ROW_COUNT` 를 "빠졌다" 고 쓰면 안 된다.

---

## 문장 2b — PK-projection 우회가 이 논거를 무너뜨리는가

Blockaid 는 집계를 이렇게 처리한다:

> "SELECT SUM(A) FROM R into SELECT PK, A FROM R, where PK is table R's
> primary key. By projecting the primary key in addition to A, the
> rewritten query reveals the multiplicity of the values in A—necessary for
> computing SUM(A)—without returning duplicate rows."

**즉 set semantics 안에서 multiplicity 를 우회하는 수단이 이미 있다.**
"bag semantics 가 빠졌다" 는 논거는 이것을 넘어야 한다. 확인한 것:

1. **일반화 여부가 논문에 없다.** 확인 결과 이 우회의 적용 범위는 이 한
   예시 밖으로 명시돼 있지 않다. 일반 절차가 아니라 집계 처리용 재작성이다.

2. **정밀도를 대가로 지불한다.** `(PK, A)` 의 determinacy 는 `SUM(A)` 의
   determinacy 보다 **강하다.** 정책이 합계는 공개하되 어느 행이 기여했는지는
   공개하지 않는 경우, PK-projection 은 행 identity 의 determinacy 를 요구해
   거부한다. 우리 모델은 그 구분을 `CARD → ROW_COUNT` 와
   `CARD → MEMBERSHIP` 으로 나눠 각각 판정한다.

3. **ordering 에는 같은 우회가 성립하지 않는다.** 정렬 컬럼을 출력으로
   올리는 처리는 **정렬 키 값 자체가 정책 뷰로 결정될 것**을 요구한다.
   순서를 관찰 채널로 모델링하는 것이 아니라, 키를 공개로 만들어 회피한다.

3번이 결정적이다. 우리 회귀의 두 판정 행이 정확히 그 차이에 걸린다.

```
Q10   SELECT 'x' FROM t ORDER BY secret
Q6'   SELECT 'x' FROM t ORDER BY secret, id LIMIT 3
```

우리 게이트는 **수락**한다. 출력 행이 전부 동일하므로 정렬이 결과 bag 을
바꿀 수 없고, `LIMIT` 이 뽑는 건수도 공개 multiplicity 가 정한다.
Blockaid 의 처리를 그대로 적용하면 `secret` 이 출력 컬럼이 되어 정책 뷰로
결정되어야 하고, 마스킹된 컬럼이므로 **거부**된다.

이것이 잔여 기여의 구체적 사례다. 다만 다음 두 가지를 정직하게 붙여야 한다.

- Blockaid 의 대상은 ORM 이 만드는 웹앱 질의다. `SELECT 'x' FROM t ORDER BY
  secret` 은 그 workload 에 나타나지 않는다. **정밀도 이득은 현실 workload
  에서 재야 한다.** 개발 witness 에서만 나오면 약하다.
- 우리 게이트의 정밀도는 `CARD` 계열에서 나오고, `EQ`/`ORD` 계열에서는
  실제 마스크가 전부 `fails` 라 정밀도가 발휘될 여지가 좁다(§5).

---

## 문장 3 — Mascara **(전문 확인 완료)**

### 3.1 compliance 정의

Mascara 는 정책 `P` 마다 원본 관계를 필터·투영·마스킹한 anonymized relation 을
만들고, 그 집합을 `D^P` 로 둔다. SPJG 질의 답 `Q(D)` 가 disclosure-compliant
하다는 정의는 다음이다(§3.2, pp. 6–7).

    Q(D) is compliant  iff  exists Q' such that Q(D) = Q'(D^P)

즉 정책 뷰로부터 답할 수 있는가를 묻는 **view-answerability** 계열이다. 논문도
identity mask 특수 경우를 answering queries using views 로 환원하고, query
determinacy 의 undecidability 를 직접 언급한다. 따라서 Mascara 역시 determinacy
계열과 무관하지 않다.

그러나 실제 최적화 문제의 출력은 원래 `Q` 와 같은 답을 요구하지 않는다. 후보
`Q_c` 들 중 `dist_D(Q,Q_c)`가 최소인 disclosure-compliant query 를 선택한다.
논문은 이 거리를 원래 답과 수정된 답 사이의 **information loss**로 정의한다.

### 3.2 마스크 성질

predicate computability 의 `theta-preserving` 조건은 원 술어에서 마스킹된
술어로의 **단방향 함의**다(§5, Property 1). 양방향 동치가 아니므로 더 약한
술어가 추가 행을 통과시킬 수 있다. 실제 알고리즘과 평가도 사용할 수 없는
predicate 를 제거하며, 그 결과의 cardinality 차이를 information loss 로 센다.

aggregate computability 의 `gamma-preserving` 조건도 원본 aggregate 답과의
동일성이나 `M_out` commutation 을 요구하지 않는다. 마스킹된 값에 변환 `tau`를
적용해 해당 aggregate 를 계산할 수 있으면 후보를 만든다(§5, Property 2).

따라서 두 성질은 우리 `equality_factor` / `order_factor` / exact aggregate
compatibility 와 동일하지 않다. Mascara 는 **정책 준수 후보를 구성하기 위한
computability**를, 우리는 **원본 계산 뒤 정해진 redaction과 정확히 일치하는가**를
검사한다.

### 3.3 지원 의미론

| 항목 | Mascara 전문에서 확인된 범위 |
|---|---|
| `GROUP BY`·aggregate | 지원. SPJG와 수정 알고리즘에 명시 |
| `ORDER BY` | SPJG 문법·알고리즘·평가에 없음 |
| `DISTINCT` | 질의 연산자로 다루지 않음(통계의 distinct value 언급만 있음) |
| bag multiplicity | 답을 `set of tuples`로 정의하며 별도 bag 의미론 없음 |
| subquery | 사전 de-correlation을 가정 |

### 3.4 거부와 열화

모든 입력 relation 을 덮는 정책 조합이 없으면 거부하고, 개요는 modifier 가
재작성에 실패해도 거부한다고 명시한다. 그러나 적용 가능한 정책이 있으면
predicate·projection 을 제거하거나 masked-domain 연산으로 바꾼 여러 후보를
만들고, 원본과 달라도 최소 정보 손실 후보를 실행한다. 평가에서는 predicate
제거 때문에 정보 손실이 커지는 경우를 명시적으로 보고한다.

따라서 Mascara 에 **minimum loss가 0이 아니면 거부하는 exact-fidelity 모드**는
없다. 거리 0인 후보가 있으면 최적 후보가 될 수는 있지만, 0을 요구하거나
그렇지 않을 때 거부하지 않는다.

### 3.5 확정된 차이

> Mascara 는 anonymized relation 위에서 계산 가능한 정책 준수 질의로
> **열화하고 그 손실을 최소화**한다. 우리는 지정한 `M_out(Res(Q,D))`와의
> **정확한 fidelity**를 인증하지 못하면 거부한다.

이 차이는 확정됐다. 다만 `query-aware masking`, 마스크 성질, view 기반 정책,
재작성 실패 시 거부 각각은 Mascara 에 이미 있으므로 개별 최초성은 주장하지 않는다.

---

## 문장 4 — 잔여 기여 후보 (TPC-H go/no-go 이후 수정)

처음 세운 최대 후보는 다음이었다.

> 마스킹된 SQL 에서 셀 값뿐 아니라 **bag multiplicity 와 ordering 을 포함한
> 관찰 shape** 를 추적하고, **exact fidelity** 와 **scoped opacity** 를 함께
> 보장하며, 입증하지 못하면 결과를 열화하지 않고 **거부**하는, 솔버 없는
> 결정 가능한 compositional certificate checker.

그러나 외부 작성 TPC-H와 생성 workload에서 sink-erasure 회수가 모두 0이므로,
**bag/order shape 추적의 workload 정밀도 이득은 주 기여에서 내린다.** 이는 해당
현상이 존재하지 않는다는 보편 명제가 아니라, 현재 논문이 그 중요성을 실증하지
못했다는 go/no-go 판정이다. Q10/Q6'은 형식적 witness와 회귀로만 남긴다.

현재 남은 주 기여 후보는 더 좁다.

> 동적 마스킹에서 원본 질의 결과에 지정된 output redaction을 적용한 의미와의
> **exact fidelity**를 compositional certificate로 검사하고, 입증하지 못하면
> 조용히 열화하지 않고 거부하는 PostgreSQL checker와 differential audit 방법.

factorization 자체나 shape-aware opacity precision의 최초성을 주장하지 않는다.
다음 요소는 이 좁은 기여를 구성하는 구현·형식 자산이다.

1. bag multiplicity·result shape 를 포함한 마스킹 관찰 모델 — 형식적 기반
2. `VAL/EQ/ORD/CARD → sink` 의 SQL 구문별 합성 분석 (subquery·setop 경계 통과)
3. 마스크·함수·집계·비교자 인증서의 조합과 그 **의미론적 검증**
4. exact fidelity 를 지킬 수 없으면 열화 대신 거부
5. PostgreSQL 의 실제 rewritten Query tree 와 plan cache 무효화까지 연결

### 이 문장이 견뎌야 할 공격

| 공격 | 현재 답 |
|---|---|
| "determinacy 의 corollary 아닌가" | 원리는 맞다. 잔여는 richer semantics 를 결정 가능하게 검사하는 checker다 |
| "PK-projection 으로 multiplicity 되지 않나" | 집계 예시에만 명시. 정밀도를 잃고, ordering 에는 적용 안 됨 |
| "SMT 로 하면 되지 않나" | 우리 checker 는 솔버 없이 구문 지향. **더 보수적이다.** 속도·SQL coverage 로 이겨야 하는데 **성능을 한 번도 측정한 적이 없다** |
| "설정으로 안전성을 만든 것 아닌가" | **현재로선 반박 불가.** §5 |
| "shape 분석이 실제로 더 수락하나" | 두 workload에서 회수 0. **주 기여에서 내렸다** |
| "삼자택이가 기여 아닌가" | 단독으로는 약하다. 동기·경계 정리로만 쓴다 |

3번째 줄이 아프다. 솔버 없는 보수적 checker 는 그 자체로 기여가 아니다.
"더 빠르다" 또는 "Blockaid 가 못 다루는 SQL 을 다룬다" 를 보여야 하는데,
**공용 서버라 성능 측정이 불가능하다.** 남는 축은 SQL coverage 뿐이다
(`GROUP BY`, 집계, setop, 중첩 — Blockaid 가 미지원이라고 명시한 것들).

---

## 5. 가장 큰 미해결 — 설정 기반 allowlist 위험

held-out v1 의 P1 인증서 653건은 **held-out 코퍼스 자신의 obligation stream
에서** 생성됐다. 결정적 알고리즘이고 seed 를 오염시키지 않았지만,
실용성 비판을 해결하지 못한다. 사실상 workload-derived allowlist 다.

최종 평가에서 셋을 분리해야 한다.

```
capability certificate   마스크·함수의 일반적·재사용 가능한 성질
declassification         관리자가 승인하는 보안 정책
query context cache      정책 판단을 특정 AST 에 적용한 파생물
```

관리자는 질의를 보기 전에 고수준 정책만 쓰고, 새 질의는 시스템이 자동
판단해야 한다.

### 5.1 "컬럼 전체 CARD 선언" 은 해결책이 아니다

이전에 실용성 측정 방법으로 "`birth` 의 CARD 를 모든 술어 문맥에서 선언"
을 제안했다. **철회한다.**

```sql
WHERE birth = $1
WHERE birth < $1
```

을 모든 파라미터에 허용하면 이진 탐색으로 `birth` 를 복구할 수 있다.
`param_scope = all_values` 가 강한 declassification 이라는 기존 분석과 같은
문제다. 실용성 숫자를 얻으려고 opacity 를 없애는 것이다.

### 5.2 대신 — declassification 을 factorization 으로

공개 함수 `r` 을 정의하고, **허용 술어가 `r` 을 factor through 하는지**
검사한다.

```
r(birth) = year(birth)          -> WHERE year(birth) = 1990  허용
                                   WHERE birth < $1          거부
r(birth) = (birth <= today-18y) -> 그 고정 판정만 허용
```

이것은 기존 기계장치와 **같은 판정 형태**다. capability 는 "등가가 `M` 을
factor through 하는가" 를 묻고, 이 정책은 "술어가 `r` 을 factor through
하는가" 를 묻는다. 관리자는 질의를 보지 않고 `r` 만 고른다.

### 5.3 Blockaid 정책 뷰로의 환원 결과 — **환원된다**

공개 row identity `id`와 공개 함수 `r`을 다음 정책 뷰로 두면 된다.

    V_r := SELECT id, r(birth), <public columns> FROM t

`p(birth)`가 `r`을 factor through 한다는 것은 어떤 `p_hat`에 대해
`p = p_hat o r`이라는 뜻이다. 그러면 `WHERE p(birth)`의 membership 결과는
`V_r`만으로 계산되므로 그 질의 관찰은 `V_r`에 의해 결정된다.

    r(birth) = year(birth)
        WHERE year(birth) = 1990   -> V_r 로 결정됨
        WHERE birth < $1           -> 일반적으로 결정되지 않음

따라서 `r` 기반 release/declassification은 **정책 언어의 새로운 원리로 주장할
수 없다.** Blockaid의 view policy와 고전적 query determinacy로 표현된다.

남는 차이는 checker 다. Blockaid의 일반 determinacy 검사는 schema constraint와
join 상관관계까지 이용할 수 있는 반면, 우리의 pointwise factor certificate는
그보다 보수적인 충분조건이다. 대신 우리 checker 는 bag/order/NULL/collation과
마스킹 fidelity를 명시적으로 다루는 선언된 SQL fragment에서 결정 가능하다.
이 정밀도·coverage 차이를 실제 workload로 입증해야 한다.

`context_key` 는 **건드리지 않는다.** authorization amplification 방어이므로,
안전한 고수준 release policy 가 정의되기 전에는 느슨하게 열 수 없다.

---

## 6. 결론과 다음 단계

| 질문 | 답 |
|---|---|
| 원리가 새로운가 | **아니다.** opacity 는 release determinacy 다 |
| Blockaid checker 로 우리 문제가 풀리는가 | **아니다.** bag multiplicity·ordering·masking fidelity 미지원, `GROUP BY` 미지원 |
| PK-projection 이 그 간극을 메우는가 | 집계 multiplicity 는 부분적으로. **ordering 은 아니다** |
| Mascara 와 다른가 | **예.** compliant degradation/min-loss 대 exact-or-reject |
| `r` 정책이 새로운가 | **아니다.** Blockaid policy view/query determinacy로 환원됨 |
| 잔여 기여가 인위적인가 | Q10/Q6′ 는 실재하나 **현실 workload 빈도 미측정** |
| 실용성이 입증됐는가 | **아니다.** P1 이 workload-derived |

### 감사 통과 조건

1. **완료:** Mascara 전문 확보 후 §3 확정
2. **완료:** `r` 기반 declassification 은 Blockaid 정책 뷰로 환원됨
3. **go/no-go 실패:** Q10/Q6′ 류 sink-erasure 수락의 workload 가치
4. **현재 실패:** query-specific certificate 0인 유용한 CARD 정책. 종이 위 감사는
   `docs/card-policy-audit.md` 참조

3·4 가 실패하면 방향을 바꾼다. 그 경우에도 버릴 것은 없다 — 지금까지
**게이트 결함 3건**(`Aggref` 미구현, `aggdistinct` EQ 누락,
`CREATE EXTENSION` 이 무효화 트리거 미설치), **정책 구현 결함 1건**(PD1),
**레지스트리 거짓 주장 1건**(`hxnum null_equivalence`)을 실제로 찾았다.
마스킹 시스템의 fidelity/leakage differential tester 로는 이미 작동한다.

### 조건 3의 예비 진단 — 강한 부정 신호, 아직 실패 확정은 아님

기존 held-out v1 400문을 사후 진단했다. 실제 profile의 마스크만 두고
query-specific certificate가 없는 P0 결과를, 절 단위 naive rule
(`WHERE`/`ORDER BY`/`GROUP BY`/`DISTINCT`의 라벨 접촉이면 거부)과 비교했다.

| 항목 | 예비 결과 |
|---|---:|
| naive 거부 | 301/400 |
| held-out v1 P0 수락 | 72/400 |
| naive 거부 ∧ P0 수락(회수) | **0** |
| naive 수락 ∧ P0 거부(역행) | 27 |
| 절 단위 sink-erasure 후보 | **0** |

개발 witness Q10/Q6′에서 보인 sink-erasure는 이 생성 corpus에는 한 건도 없었다.
따라서 이 corpus에서는 compositional opacity 분석이 naive rule의 거부를 회수하지
못했다. `역행` 27건은 주로 opacity가 아니라 미인증 cast/function/aggregate 등
fidelity 의무에서 생겼다.

그러나 이 숫자로 조건 3을 **실패 확정하지 않는다.** 이유는 세 가지다.

1. held-out v1은 우리 generator가 만든 뒤 버그를 발견한 **bug-discovery set**이지
   외부 작성 현실 workload가 아니다.
2. P0 72라는 gate 결과는 `Aggref` transfer와 사유 분류를 고친 `5c3534a` 이전
   raw run에서 나온 값이다. 현재 checker의 acceptance 수치가 아니다.
3. 첫 정규식 분류가 절 경계를 넘는 오류를 냈다. 절 단위로 정정했지만 재현용
   Query-tree baseline과 query별 원시 판정 아티팩트는 아직 동결하지 않았다.

정확한 지위는 **"개발 생성 workload에서 회수 0이라는 강한 부정 신호"**다.
다음 판정은 외부 작성 TPC-H에 현재 gate/profile을 사용해 수행한다. 비교는
정규식이 아니라 Query tree 기반 naive baseline으로 하고, `F_core` 안/밖,
현실적 PII 라벨/전 컬럼 stress 라벨, opacity 회수/fidelity 추가 거부를 분리한다.
거기서도 비퇴화 회수가 0이면 shape-aware opacity 정밀도를 주 기여로 두지 않는다.

### 외부 TPC-H go/no-go 결과

커밋 `81829ea`의 Query-tree baseline으로 외부 작성 TPC-H 22문을 측정했다.
회수와 역행은 `F_core` 안에서만 계산한다.

| 라벨 | F_core | F_core 내 라벨 접촉 | F_core 내 naive 거부 | F_core 내 gate 거부 | 회수 | 역행 | sink-erasure |
|---|---:|---:|---:|---:|---:|---:|---:|
| realistic | 13/22 | 2 | 2 | 2 | **0** | 0 | **0** |
| stress | 13/22 | 13 | 13 | 13 | **0** | 0 | **0** |

전체 22문을 분모로 쓰면 realistic naive/gate 거부는 6/7, stress는 22/22지만,
밖의 질의는 회수 정밀도 비교 대상이 아니다. 표에서는 그 수를 섞지 않는다.

생성 workload 400문에서도 회수 0이었고, 외부 workload에서도 회수 0이다.
따라서 조건 3은 이 프로젝트의 방향 결정 기준으로 실패했다. 다만 400문은
bug-discovery set이고 외부 workload는 TPC-H 하나뿐이므로, 이를
"현실 SQL에는 sink-erasure가 없다"는 일반화된 빈도 주장으로 쓰지 않는다.

출판 전 재현성 보강이 하나 남는다. `tools/measure_recovery.py`는 주석으로
P0/profile v1을 선언하지만, 실행 전 `ipguard_declassification = 0`과 profile
digest를 강제·결과에 기록하지 않는다. 이 preflight를 추가해 재실행하기 전까지
커밋 `81829ea`는 방향 전환 증거이지 최종 수치 아티팩트는 아니다. 또한 stress
Q12가 `ipguard_fragment=''`인데 gate에서 `UNMODELED_EXPR`로 거부돼, fragment
분류와 실제 transfer coverage의 불일치도 coverage 표에서 별도로 보고해야 한다.

### 다음 산출물

새 CARD 정책 구현이 아니다. `docs/card-policy-audit.md`의 부정 결과를 근거로
연구 질문을 **exact-fidelity certification과 differential audit**으로 좁히고,
그 방향이 선행연구 대비 남는지를 별도로 감사한다.

---

## 참고문헌

- Wen Zhang, Eric Sheng, Michael Chang, Aurojit Panda, Mooly Sagiv, Scott
  Shenker. **Blockaid: Data Access Policy Enforcement for Web
  Applications.** USENIX OSDI 2022.
  <https://www.usenix.org/conference/osdi22/presentation/zhang>
  확장판: <https://arxiv.org/abs/2205.06911>
- Rudi Poepsel Lemaitre, Kaustubh Beedkar, Volker Markl.
  **Disclosure-Compliant Query Answering.** Proc. ACM Manag. Data 2(6),
  Article 233, 2024. <https://dl.acm.org/doi/10.1145/3698808>
  공개 전문: <https://npregional.dnb.de/objekte?idn=1362066206&iln=63>
- Primal Pappachan et al. **Don't Be a Tattle-Tale: Preventing Leakages
  through Data Dependencies on Access Control Protected Data.** PVLDB 2022.
  **(미확인 — 결론에 사용하지 않음)**
- Google Cloud. **BigQuery Data Masking** — 결정적 해시 마스크의 joinability.
  <https://docs.cloud.google.com/bigquery/docs/column-data-masking-intro>
- Microsoft. **SQL Server Dynamic Data Masking** — 보안 경계가 아님을 명시.
- Oracle. **Data Redaction FAQ** — 정렬·그룹핑이 원본값으로 처리됨을 명시.

---

## 부록 A — 조건 1 측정 중 발견된 checker coverage 결함

`81829ea` 측정에서 stress Q12 가 `F_core` 안으로 분류됐는데 `UNMODELED_EXPR`
로 거부됐다. 원인을 단일 컬럼 단위로 이분해 확정했다.

**`BoolExpr`(AND/OR/NOT)가 표현식 transfer table 에 없다.**

```
SELECT CASE WHEN p = 'x' THEN 1 ELSE 0 END          -> MISSING_CERTIFICATE  (모델링됨)
SELECT CASE WHEN p = 'x' OR p = 'y' THEN 1 ELSE 0 END -> UNMODELED_EXPR     ★
SELECT CASE WHEN p <> 'x' AND p <> 'y' ...            -> UNMODELED_EXPR     ★
SELECT CASE WHEN NOT (p = 'x') ...                    -> UNMODELED_EXPR     ★
SELECT (p = 'x' OR p = 'y')                           -> UNMODELED_EXPR     ★
대조: WHERE p = 'x' OR p = 'y'                        -> MISSING_CERTIFICATE (정상)
```

술어 위치는 `gate_collect_quals` 가 AND 를 쪼개고 OpExpr 를 처리하므로
정상이다. **값 위치**의 `BoolExpr` 만 `summarize_expr` 의 default 분기로
떨어진다.

`TargetEntry` 누락(G3 의 근본 원인)과 **정확히 같은 부류**다 —
`summarize_expr` 에 노드 타입이 빠졌고, fail-closed 라 건전성 문제는 아니지만
**fragment 분류기는 `F_core` 안이라고 하는데 checker 는 모델링하지 못한다.**

exact-fidelity certifier 가 주 기법이 되면 이 불일치는 넘길 수 없다.
compositional transfer table 의 coverage 가 곧 기여의 크기이기 때문이다.
최종 실험 전에 다음을 해야 한다.

1. `BoolExpr` 를 transfer table 에 추가 (인자 전부 공개 -> 공개,
   하나라도 마스킹 -> 그 마스크로부터 boolean 이 복원되는지 인증 필요)
2. **`ipguard_fragment` 가 `F_core` 안이라고 한 모든 질의에 대해 checker 가
   `UNMODELED_EXPR` 를 내지 않는다**는 것을 회귀로 고정. 이 불일치가 0 이어야
   coverage 를 주장할 수 있다.

## 부록 B — `81829ea` 측정 아티팩트의 한계

최종 논문 수치로 쓰기 전에 보강해야 한다.

| | 내용 |
|---|---|
| provenance 미기록 | 측정 스크립트가 P0(declassification 0건)와 profile v1 적용 상태를 주석으로만 선언하고, 실행 전에 **강제하지도 기록하지도 않는다.** 실행 시점의 registry 상태를 digest 로 남겨야 한다 |
| stress 라벨 kind 오배정 | `date` 컬럼에 `pv_text` kind 를 붙였다(규칙이 `pv_num if type in (integer, numeric) else pv_text`). 실제 마스크는 타입으로 분기하므로 판정은 바뀌지 않지만, 레지스트리 kind 와 컬럼 타입이 어긋난 상태로 쟀다 |
| Q12 불일치 | 부록 A |

셋 다 **회수 0 이라는 결론은 바꾸지 않는다.** 회수는 naive 와 gate 의 판정
차이인데, 위 셋은 gate 를 더 거부하게 만드는 방향이라 회수를 늘릴 수 없다.
