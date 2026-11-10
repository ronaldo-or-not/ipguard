# 동적 마스킹의 삼자택이 — 형식화와 실측 (2026-08-08)

동적 마스킹에는 서로 배타적인 세 속성이 있고, **어떤 구현도 셋을 동시에
만족할 수 없다.** 이 문서는 그 불가능성과, 세 꼭짓점을 **같은 확장·같은 마스크
함수**로 돌려 얻은 실측을 담는다.

원시 출력: [`trilemma.txt`](trilemma.txt) ·
도구: [`../tools/score_trilemma.py`](../tools/score_trilemma.py)

---

> **명세 선행**: `Mout` 의 lineage 분해(value / structural / decision), 마스크
> 인스턴스의 동일성, 능력 술어의 수학적 정의는
> [`../docs/spec-lineage-and-masks.md`](../docs/spec-lineage-and-masks.md)
> 에 따로 고정했다. 이 문서의 수치는 그 명세의 **v0.1 기준**이다.

> ## ⚠ 이 표는 **legacy R1–R3 게이트**를 진단한 표다
>
> 아래 수치는 명세 v0.2.1 기준으로 **불건전한** 현재 게이트(R3b 가 lineage 가
> 아니라 masked-ness 를 본다, 명세 §8)에서 나온 것이다. **새 게이트의 성능이
> 아니다.** 최종 논문에는 둘을 나란히 둔다:
>
> | 게이트 | acceptance | 결과 |
> |---|---|---|
> | legacy R1–R3 | 높음 | **`Q6`/`Q9` 누출** |
> | release-factorization | 낮아짐 | 수락한 부분집합에서 opacity |
>
> 즉 이 표의 역할은 "우리 시스템이 이만큼 한다" 가 아니라 **"무엇이 왜 새
> 게이트를 필요하게 만들었나"** 의 증거다.

## 세 속성

| | 정의 |
|---|---|
| **Fidelity** | 원본 질의를 계산한 뒤 출력을 마스킹한 결과(`Mout(Q(D))`)와 같다 |
| **Mask opacity** | 마스크로 구별되지 않는 두 DB 를 결과로도 구별할 수 없다 |
| **Totality** | 지원 언어의 모든 질의에 답한다(거부하지 않는다) |

`Mout` 은 **결과 lineage 기반 redaction** 이다 — 안쪽 계산은 원본으로 하고,
출력이 민감 컬럼에서 왔으면 **결과 타입에 맞춰** 가린다. Oracle 23ai 문서와
예제가 `AVG`/`MIN`/`MAX` 같은 파생·집계 결과도 최종 출력에서 가린다고
명시하므로 이쪽이 실제 구현에 맞다.

> 처음에는 `Mout` 을 **컬럼 전용** 마스크로 정의했는데, 그러면 V2 가 `substr`
> 을 가리는 것이 "과마스킹 = fidelity 위반" 으로 잡혀 V2 가 exact-fidelity
> 꼭짓점을 점유하지 못했다. 정의를 바로잡자 **V2 의 fidelity 가 8/8 이 됐다.**
> Ideal 의 정의가 결론을 바꾼다.

## 불가능성

비주입 마스크(`m(a) = m(b)`, `a ≠ b`)가 존재하면 셋을 동시에 만족할 수 없다.

```
D1 = { a, a }          D2 = { a, b },   a ≠ b,  m(a) = m(b)
→ 두 DB 의 마스킹된 모습은 동일하다.

SELECT DISTINCT secret FROM t;
→ 원본 결과의 **행 수**는 각각 1 과 2.

· 둘 다 정확한 행 수를 낸다 → 결과가 D1/D2 를 구별한다      → opacity 위반
· 행 수를 맞추지 않는다      → 원본 질의 결과와 다르다        → fidelity 위반
· 거부한다                  → 답하지 않는다                  → totality 위반
```

**witness 를 `count(DISTINCT)` 가 아니라 `SELECT DISTINCT` 의 행 수로 잡는 것이
중요하다.** 행 수는 **redaction 할 수 있는 대상이 아니다** — 모든 셀을 가려도
반환 행 수는 그대로 새어나간다. 그래서 이 witness 는 구현이 집계 결과를
가리든 말든 성립한다.

즉 **Ideal 자신이 opacity 를 어긴다.** fidelity 와 totality 를 다 가지면
opacity 는 원리적으로 불가능하다.

마스크가 주입적이면(값이 1:1) 전제가 깨지지만, 주입적 마스크는 원본을 복원할 수
있으므로 마스킹이라 부를 수 없다.

## 실측 — 세 꼭짓점을 한 시스템에서

`ipguard.mask_position` 으로 마스크를 넣는 위치만 바꾼다. 마스크 함수도,
라벨도, 코드 경로도 같다.

| 지점 | 마스크 위치 | 대표 구현 |
|---|---|---|
| **V1** `source` | 테이블 진입점 | 마스킹 뷰, PostgreSQL Anonymizer 동적 마스킹 |
| **V2** `output_path` | 트리의 공개 경로 | **이 확장의 기본** |
| **V3** `projection` | 모든 관계 연산 뒤 | Oracle Data Redaction 계열 |

D1 = 민감값 6개 전부 다름, D2 = 고유값 2개. 행 수와 비민감 컬럼은 동일하고,
마스크가 상수이므로 **두 표의 마스킹된 모습은 같다.** 따라서 결과가 다르면
곧 opacity 위반이다.

### 표 A — 정리 검증 (수락된 질의만, 허가된 결정 술어는 declassify)

| | Acceptance | Fidelity(수락분) | Scoped opacity(수락분) |
|---|---:|---:|---:|
| V1 소스 | 9/9 | 4/9 | 9/9 |
| **V2 출력경로** | **6/9** | **6/6** | **4/6** |
| V3 투영 | 9/9 | 9/9 | **5/9** |

**Acceptance 열이 반드시 같이 있어야 한다.** 없으면 "어려운 질의를 거부해서
성공률을 올렸다"는 반론을 받는다 — 그리고 그 반론은 **맞다.** V2 의 `4/4` 는
`4/7` 만 수락한 대가로 산 것이고, 그게 삼자택이의 비용이다.

### 표 B — 운영 행태 (전체 질의, 숨기지 않는다)

| | Fidelity | Mask opacity | Totality |
|---|---:|---:|---:|
| **V1** 소스 | **4/10** | 10/10 | 10/10 |
| **V2** 출력경로 | 10/10 | **7/10** | **7/10** |
| **V3** 투영 | 10/10 | **5/10** | 10/10 |

**세 지점이 서로 다른 속성을 포기한다.** 이것이 삼자택이의 실측이다.

## 질의별로 무엇이 일어나는가

| 질의 | V1 | V2 | V3 |
|---|---|---|---|
| 컬럼 투영 | ✓ | ✓ | ✓ |
| `substr(secret,1,2)` | ✓ | ✓ | ✓ (파생 결과도 가린다) |
| `DISTINCT secret` | fidelity✗ | **거부** | **opacity✗** — ★ 행 수가 고유값 개수를 드러낸다 |
| `count(DISTINCT secret)` | fidelity✗ | **거부** | ✓ (lineage 로 가려진다) |
| `GROUP BY secret` | fidelity✗ | **거부** | **opacity✗** |
| `ORDER BY secret LIMIT` | ✓ | ✓ | ✓ |
| `WHERE secret = 'a1'` | fidelity✗ | **opacity✗** | **opacity✗** |
| 비민감 대조군 | ✓ | ✓ | ✓ |

> **[v0.2 정정]** 위 숫자는 witness 를 강화한 뒤의 값이다. 이전 witness 는
> 민감값의 **정렬 순서가 id 순서와 같아** `ORD` 채널을 가리고 있었고, 그래서
> V2 의 opacity 가 실제보다 높게(7/8) 나왔다. 정렬 순서가 다르도록 데이터를
> 바꾸자 **V2 가 `ORD` 채널에서 샌다**는 것이 드러났다:
>
> ```
> Q9  SELECT id FROM t ORDER BY secret, id          (LIMIT 없음)  → D1/D2 구별됨
> Q6  SELECT id FROM t ORDER BY secret, id LIMIT 3               → D1/D2 구별됨
> ```
>
> `Q6` 은 R3b 가 있는데도 샌다. `secret` 이 출력에 없어 `resjunk` 라 마스킹되지
> 않고, R3b 는 "마스킹된 정렬 키" 를 조건으로 하므로 걸리지 않는다.
>
> 그리고 **`ORD` 가 있어도 항상 새는 것은 아니다** — 관찰 sink 가 있어야 한다:
> ```
> Q10  SELECT 'x' FROM t ORDER BY secret   → V1·V2·V3 전부 불투명
> ```
> 모든 행이 관찰상 같으면 순서 차이가 보이지 않는다. 그래서 게이트는
> effect 만이 아니라 **effect → observable sink** 를 봐야 한다(명세 v0.2.1 §2).
> **규칙이 masked-ness 를 보는 것이 틀렸고 lineage 를 봐야 한다** — 명세 v0.2
> §8 에 R3-order / R3-selection 분리로 기록했다. **아직 구현하지 않았다.**
>
> `Q10` 은 **증명이 아니라 witness**다. 실험 하나로 *"sink 가 없으면 항상
> 안전"* 을 보일 수는 없다. 대신 `Q10` 은 새 게이트의 **양성 대조군**이다 —
> `ORD` 를 보고 일괄 거부하는 게이트는 `Q10` 까지 거부해서 건전하지만 지나치게
> 불완전하고, effect→sink 를 보는 게이트만 **`Q10` 을 수락하면서 `Q9`/`Q6` 을
> 거부**한다. 그 세 행이 재측정의 판정 기준이다.

**V2 의 나머지 opacity 위반은 술어 채널이다.** `WHERE secret = 'a1'` 은 D1 에서
1, D2 에서 4 를 돌려준다. 이건 설계상 **의도적으로 허용한** 것이다 — 필터가
동작해야 하므로. 따라서 V2 의 성질은 일반적 기밀성이 아니라

> **명시적으로 허가된 결정 술어 밖에서의 masked-domain opacity**

라고 써야 정확하다. Oracle 도 같은 선택을 하고 같은 추론 위험을 문서화한다.

## Oracle 의 집계 동작은 아직 [미확인]

`count(DISTINCT secret)` 을 Oracle 이 어떻게 처리하는지는 **문서로 확인하지
못했다.** 공식 자료는 민감 컬럼에서 파생된 `AVG`/`MIN`/`MAX`/`SUM` 을 가린다고
설명하지만 `COUNT(DISTINCT)` 는 명시가 없다. 실기 확인 전까지 `[미확인]` 이다.

**다행히 삼자택이 witness 는 그 동작에 의존하지 않는다** — 위에서 witness 를
`SELECT DISTINCT` 의 행 수로 고정한 이유가 이것이다.

## V3 는 "정합적"이 아니라 "원본 질의 fidelity 를 보존"한다

`SELECT DISTINCT secret` 이 **똑같아 보이는 행 여러 개**를 돌려준다. 원본 질의의
multiplicity 는 보존되지만, 클라이언트가 보는 결과는 `DISTINCT` 의 관계적
불변식을 깬다. Oracle 문서의 예제도 정확히 이 모습이다(값이 전부 `0` 인 4행).

즉 V3 는 **fidelity 를 지키는 대신 redacted presentation 의 관계적 불변식과
opacity 를 포기**한다.

## 구현 노트 — V3 는 target-list 변이로 만들 수 없다

PostgreSQL 에서 `DISTINCT`/`GROUP BY` 는 `ressortgroupref` 로 **같은
`TargetEntry`** 를 가리킨다. TLE 를 마스킹하면 그룹핑도 마스크 위에서 돌아
**V2 로 되돌아간다.** 진짜 V3 는 모든 관계 연산 뒤여야 한다:

```sql
SELECT mask(q.secret) FROM ( <원래 질의 전체> ) q
```

`ORDER BY`·`LIMIT`·`DISTINCT`·집계는 서브쿼리 안에 남아 원본으로 계산된다.

구현을 두 번 뒤집었다. 처음에는 파생 표현식까지 가렸고(lineage), 그다음
컬럼만 가리도록(`IsA(expr, Var)`) 좁혔다가, Oracle 문서·예제가 파생·집계
결과도 가린다고 명시하는 것을 확인하고 **다시 lineage 로 돌렸다.**
이 되돌림이 V2 의 fidelity 를 7/8 에서 8/8 로 바꿨다 — **Ideal 을 어떻게
정의하느냐가 세 꼭짓점의 좌표를 전부 움직인다.**

## 한계

- 서브쿼리의 `ORDER BY` 는 바깥 질의에서 보존이 **보장되지 않는다.** 완전한
  V3 는 executor 최종 투영이어야 한다. `COPY`·커서·`RETURNING`·집합연산은
  별도 구현 축이다(현재 V3 는 `CMD_SELECT` 만, 나머지는 V2 로 떨어진다).
- 질의 8개는 속성별 witness 로 고른 것이지 워크로드 분포가 아니다. 비율
  (3/8, 7/8 …)은 **각 지점이 무엇을 포기하는지의 증거**이지 빈도 추정치가 아니다.
- Oracle 은 실행하지 못했다. V3 는 Oracle 문서(*"GROUP BY 절은 갱신하지
  않는다"*)에 따라 재구성한 것이며, Oracle 의 집계 동작은 문서로 확인하지
  못했다. **출판 전 실기 재현이 필요하다.**
- 마스크가 타입별 상수라 opacity 판정이 단순해졌다. 부분 마스크
  (`right(ssn,4)`)에서는 판정이 달라진다.
- **`declass=True` 표시가 사후 선택이다.** 표 A 에서 `Q7` 을 제외한 것은 저자가
  손으로 정한 것이고, 명세 v0.2.1 §3.5 는 `δ_Q` 가 **질의 실행 전에** 정책으로
  고정돼야 한다고 요구한다. 재측정에서는 `Declass(source,effect,sink,
  observation)` 인증서 테이블에서 읽어와야 한다. 지금 이대로면 "누출을 사후에
  허가로 분류했다" 는 반박이 성립한다.
- **관찰 모델에서 timing·plan·자원을 뺐다**(명세 §1.5). 세 지점은 계획이 다르므로
  그 채널에서는 반드시 구별된다. 이 제외를 넣지 않으면 삼자택이 자체가 성립하지
  않지만, 제외했다는 사실은 논문에 명시해야 한다.
- 질의 10문 중 `F_core`(명세 §12) 밖은 없다. `Q6` 의 정렬 키 `(secret,id)` 는
  `id` 가 유일해 **전순서**라 동률 top-k 문제를 피한다. 발산 코퍼스 45건과
  TPC-H 22 는 일부가 `F_core` 밖이며 재분류가 필요하다.

## 재현

```bash
python3 tools/score_trilemma.py
```
