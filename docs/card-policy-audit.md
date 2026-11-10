# CARD sink 분해 정책 감사

목적: `CARD -> {CELL, MEMBERSHIP, MULTIPLICITY, ROW_COUNT}` 분해가
query-specific declassification 인증서 없이도 현실적인 고수준 정책으로 이어지는지
종이 위에서 먼저 판정한다. 이 감사에서는 코드나 정책 언어를 추가하지 않는다.

## 1. 통과 기준

후보 정책은 다음 네 조건을 모두 만족해야 주 기여 후보로 남긴다.

1. workload와 개별 질의를 보기 전에 고정할 수 있다.
2. 새 질의마다 exact `context_key` 인증서를 발급하지 않아도 자동 적용된다.
3. Blockaid식 정책 뷰와 고전적 determinacy로 그대로 환원되지 않는 잔여가 있다.
4. 파라미터를 바꾸거나 질의를 반복해도 정책이 의도한 것보다 더 공개되지 않는다.

TPC-H 측정은 이 감사의 동기일 뿐 정책의 유효성 증거가 아니다. realistic
라벨에서 `F_core` 안의 라벨 접촉은 Q10과 Q18 두 건뿐이고 둘 다 `GROUP BY`
경로다. 즉 현실적 CARD workload 표본은 현재 없다.

## 2. 후보 A — coarse attribute release

예:

```sql
V_year := SELECT id, extract(year FROM birth) AS birth_year FROM person;
```

허용 술어를 `birth_year`에서 계산 가능한 술어로 제한하면, 관리자는 개별 질의를
보기 전에 `r(birth) = year(birth)`만 선언할 수 있다. `WHERE year(birth)=1990`은
허용되고 `WHERE birth < $1`은 허용되지 않는다.

그러나 이 정책은 `V_year`라는 정책 뷰로 직접 표현된다. 허용된 membership,
count, aggregate cell은 모두 그 뷰의 결과로부터 결정되는 관찰이다. 따라서
정책 원리의 잔여 기여는 없다.

현재 구현도 `r`에서 임의 질의 문맥의 factorization 인증서를 자동 합성하지
않는다. exact `context_key`를 질의별로 발급하면 조건 2를 실패하고, 문맥을
느슨하게 재사용하면 authorization amplification 위험이 다시 생긴다.

**판정: 탈락.** 안전한 정책이지만 정책 뷰로 환원되며, 현재 checker에는
query-independent compiler가 없다.

## 3. 후보 B — fixed decision release

예:

```sql
V_adult :=
  SELECT id, birth <= DATE '2008-01-01' AS is_adult
  FROM person;
```

cutoff가 정책에 고정돼 있으면 `is_adult` 판정이 membership이나 downstream
aggregate에 영향을 주는 것을 허용할 수 있다. 그러나 이것도 공개 decision bit를
담은 정책 뷰로 그대로 표현된다.

cutoff를 `$1`의 모든 값에 열면 성질이 달라진다. 반복 질의로 birth를 이진 탐색할
수 있으므로 `all_values`는 좁은 decision release가 아니라 원값 복구에 가까운
강한 declassification이다. 안전한 것은 고정 cutoff 또는 신뢰된 request context의
유한한 값뿐인데, 그 경우 다시 고정 정책 뷰가 된다.

**판정: 탈락.** 고정하면 환원되고, 일반화하면 과도하게 공개한다. 현재 시스템은
이 둘 사이의 제한된 파라미터 영역을 인증하는 정책 언어도 제공하지 않는다.

## 4. 후보 C — aggregate-only release

예:

```sql
V_count :=
  SELECT public_bucket, count(*)
  FROM person
  WHERE fixed_predicate(secret)
  GROUP BY public_bucket;
```

이 후보가 `CARD` sink 분해의 실제 목적에 가장 가깝다. 정책은 count 또는 aggregate
cell만 공개하고, 어느 row가 predicate를 통과했는지는 공개하지 않을 수 있다.
PK-projection처럼 row identity 전체를 요구하는 판정보다 원칙적으로 정밀하다.

하지만 현재 P1은 이 정책을 구현하지 않는다. P1의 release는
`predicate outcome trace`이며 각 public row occurrence의 `T/F/NULL`을 포함한다.
sink-specific 인증서는 그 trace가 어느 출력 sink에 영향을 줄 수 있는지만
제한한다. 따라서 `CARD -> ROW_COUNT`만 허가해도 형식상 release되는 정보는
**count만이 아니라 행별 decision trace 전체**다. count-only 정책보다 엄격한
검사를 하는 것이 아니라 더 많은 비밀을 정책으로 공개해 opacity를 공허하게 만든다.

count-only로 고치려면 `delta_Q`를 행별 trace가 아니라 승인된 aggregate answer로
정의해야 한다. 그러면 고정된 grouping, predicate, parameter 범위가 필요하고,
서로 겹치는 cohort와 반복 질의의 differencing 공격을 다룰 composition 규칙,
minimum cohort 또는 privacy budget까지 필요하다. 이것은 현재 게이트의 작은
확장이 아니라 별도 aggregate-release 정책 시스템이다. 추상적으로는 aggregate
정책 뷰에 대한 determinacy로 다시 표현할 수 있다. Blockaid 프로토타입의 SQL
지원 범위와는 차이가 있지만 정책 원리의 최초성은 아니다.

**판정: 현 시스템 기준 탈락.** 세 후보 중 유일하게 sink 분해의 정밀도 이득을
설명하지만, 현재 P1 의미론은 그 정책보다 강하게 공개하며 현실 workload도 없다.

## 5. 결론

| 후보 | 사전 고정 | query-specific 인증서 0 | 정책 뷰 비환원 | 반복 질의 안전 | 판정 |
|---|---:|---:|---:|---:|---|
| coarse attribute | 예 | 현재는 아니오 | **아니오** | 고정 함수면 예 | 탈락 |
| fixed decision | 예 | 현재는 아니오 | **아니오** | 고정 cutoff만 예 | 탈락 |
| aggregate-only | 가능 | **아니오** | 원리는 환원 | 현재 P1은 아니오 | 탈락 |

따라서 CARD sink 분해는 관찰 모델과 안전성 설명에는 남기되, 현재 논문의 주 기여나
실용성 근거로 쓰지 않는다. 이 방향을 살리려면 별도 정책 언어와 실제 거래계
workload가 모두 필요하며, 지금 그것을 구현하면 연구 질문을 다시 바꾸는 것이다.

다음 주 방향은 **dynamic masking의 exact-fidelity certification**이다. 즉 원본
질의 결과에 지정된 output redaction을 적용한 의미와 정확히 일치함을 인증하고,
증명할 수 없으면 조용한 오답 대신 거부하는 checker 및 differential audit 도구로
범위를 좁힌다. shape/effect 분석과 삼자택이는 이 주장을 설명하는 형식적 기반과
방어 범위로 남고, workload precision의 실증 기여로 내세우지 않는다.
