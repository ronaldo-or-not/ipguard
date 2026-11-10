| ID | 소스 | 예측 | 마스킹 | 출력 PII | ipguard 실측 | 일치 | 정답 | 보안 | 마스킹 뷰 | 비고 |
|---|---|---|---|---|---|---|---|---|---|---|
| D01 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D02 | h5-corpus.json | `mask` | 7 | ci,name,ssn,phone,addr,birth,acct | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D03 | h5-corpus.json | `mask` | 2 | name,ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D04 | h5-corpus.json | `mask` | 2 | ssn,name | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D05 | h5-corpus.json | `mask` | 3 | acct,name,ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D06 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 50000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| D07 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| D08 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| D09 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| E01 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E02 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E03 | h5-corpus.json | `mask` | 2 | name,ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E04 | h5-corpus.json | `mask` | 1 | name | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E05 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E06 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E07 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E08 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E09 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E10 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E11 | h5-corpus.json | `mask` | 2 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E12 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E13 | h5-corpus.json | `mask` | 1 | ssn | ERR(off) | · | - | - | - | enforce=off 에서도 실패: more than one row returned by a subquery used as an expression |
| E14 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E15 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E16 | h5-corpus.json | `mask` | 1 | birth | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E17 | h5-corpus.json | `mask` | 1 | ssn | unchanged | ✓ | - | OK | broken | 파생값만 출력(length/IS NULL) -- 마스크가 글자수를 보존하고 NULL 이 아니므로 설계상 동일 |
| E18 | h5-corpus.json | `mask` | 1 | ssn | unchanged | ✓ | - | OK | broken | 파생값만 출력(length/IS NULL) -- 마스크가 글자수를 보존하고 NULL 이 아니므로 설계상 동일 |
| E19 | h5-corpus.json | `mask` | 1 | name | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| E20 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | masked |  |
| E21 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | masked |  |
| V01 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V02 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V03 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V04 | h5-corpus.json | `mask` | 2 | ssn | changed | ✓ | - | OK | broken | 행 수 20000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V05 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V06 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| V07 | h5-corpus.json | `mask` | 2 | ssn | distorted | ! | - | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| V08 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 30000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| F01 | h5-corpus.json | `pass` | 0 | - | changed | ! | - | OK | - | 정적 판정은 pass, 실측은 변경 -- 함수 본문 등 별도 계획 경로에서 집행됨(집행이 정적 판정보다 넓다) |
| F02 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | LEAK | - | 마스킹되어야 하는데 값이 그대로 나갔다 |
| F03 | h5-corpus.json | `pass` | 0 | - | changed | ! | - | OK | - | 정적 판정은 pass, 실측은 변경 -- 함수 본문 등 별도 계획 경로에서 집행됨(집행이 정적 판정보다 넓다) |
| F04 | h5-corpus.json | `mask` | 7 | ci,name,ssn,phone,addr,birth,acct | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| F05 | h5-corpus.json | `mask` | 7 | ci,name,ssn,phone,addr,birth,acct | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| F06 | h5-corpus.json | `mask` | 7 | ci,name,ssn,phone,addr,birth,acct | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| F07 | h5-corpus.json | `mask` | 1 | ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| F08 | h5-corpus.json | `mask` | 7 | ci,name,ssn,phone,addr,birth,acct | changed | ✓ | - | OK | masked |  |
| S01 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| S02 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| S03 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| S04 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| S05 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| C01 | h5-corpus.json | `utility` | 0 | ci,name,ssn,phone,addr,birth,acct | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| C02 | h5-corpus.json | `utility` | 0 | ssn | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| C03 | h5-corpus.json | `utility` | 0 | ssn,name | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| C04 | h5-corpus.json | `utility` | 0 | ssn | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| B01 | h5-corpus.json | `mask` | 1 | birth | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| B02 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| B03 | h5-corpus.json | `mask` | 1 | name | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| B04 | h5-corpus.json | `mask` | 1 | addr | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| B05 | h5-corpus.json | `mask` | 3 | ssn,birth,acct | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| X01 | h5-corpus.json | `pass` | 0 | - | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| X02 | h5-corpus.json | `pass` | 0 | - | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| X03 | h5-corpus.json | `pass` | 0 | - | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| X04 | h5-corpus.json | `pass` | 0 | - | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| X05 | h5-corpus.json | `pass` | 0 | - | - | · | - | - | - | 실행 불가(부작용/결과셋 없음) |
| X06 | h5-corpus.json | `pass` | 0 | - | unchanged | ✓ | - | OK | - |  |
| X07 | h5-corpus.json | `mask` | 1 | ssn | ERR(off) | · | - | - | - | enforce=off 에서도 실패: syntax error at or near ";" |
| P01 | h5-corpus.json | `mask` | 2 | name,ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| P02 | h5-corpus.json | `mask` | 2 | name,ssn | changed | ✓ | - | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| P03 | h5-corpus.json | `mask` | 2 | name,ssn | ERR(off) | · | - | - | - | enforce=off 에서도 실패: operator does not exist: bigint = text |
| P04 | h5-corpus.json | `mask` | 2 | name,ssn | changed | ✓ | - | OK | masked |  |
| P05 | h5-corpus.json | `mask` | 2 | name,ssn | ERR(off) | · | - | - | - | enforce=off 에서도 실패: op ANY/ALL (array) requires array on right side |
| R01 | adversarial.json | `mask` | 1 | ssn | - | · | must | - | - | 실행 불가(부작용/결과셋 없음) |
| R02 | adversarial.json | `mask` | 1 | ssn | - | · | must | - | - | 실행 불가(부작용/결과셋 없음) |
| R03 | adversarial.json | `mask` | 2 | name,ssn | - | · | must | - | - | 실행 불가(부작용/결과셋 없음) |
| R04 | adversarial.json | `mask` | 1 | ssn | - | · | must | - | - | 실행 불가(부작용/결과셋 없음) |
| R05 | adversarial.json | `pass` | 0 | - | - | · | policy | - | - | 실행 불가(부작용/결과셋 없음) |
| R06 | adversarial.json | `mask` | 1 | ssn | - | · | must | - | - | 실행 불가(부작용/결과셋 없음) |
| N01 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| N02 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| N03 | adversarial.json | `refuse` | 0 | - | refused | ✓ | must | REFUSED | - | ipguard: 쿼리 구조가 분석 한계를 초과했습니다 |
| N04 | adversarial.json | `refuse` | 0 | - | refused | ✓ | must | REFUSED | - | ipguard: 쿼리 구조가 분석 한계를 초과했습니다 |
| N05 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 400000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| H01 | adversarial.json | `mask` | 1 | acct | changed | ✓ | must | OK | broken | 행 수 9999→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| H02 | adversarial.json | `mask` | 1 | acct | changed | ✓ | must | OK | broken | 행 수 4999→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| H03 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| H04 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| H05 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 1→2 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| W01 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| W02 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| W03 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| T01 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| T02 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| T03 | adversarial.json | `pass` | 0 | - | unchanged | ✓ | must | OK | - |  |
| T04 | adversarial.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| T05 | adversarial.json | `pass` | 0 | - | unchanged | ✓ | must | OK | - |  |
| L01 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| L02 | adversarial.json | `pass` | 0 | - | unchanged | ✓ | must | OK | - |  |
| L03 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| G01 | adversarial.json | `mask` | 1 | ssn | distorted | ! | must | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| G02 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| G03 | adversarial.json | `pass` | 0 | - | unchanged | ✓ | must | OK | - |  |
| G04 | adversarial.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| M01 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| M02 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| M03 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| M04 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| M05 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | policy | GAP | - | 알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다 |
| M06 | adversarial2.json | `pass` | 0 | - | - | · | write | - | - | 실행 불가(부작용/결과셋 없음) |
| M07 | adversarial2.json | `pass` | 0 | - | - | · | write | - | - | 실행 불가(부작용/결과셋 없음) |
| M08 | adversarial2.json | `pass` | 0 | - | unchanged | ✓ | must | OK | - |  |
| Z01 | adversarial2.json | `mask` | 10 | ssn | changed | ✓ | must | OK | masked |  |
| Z02 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| Z03 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| Z04 | adversarial2.json | `mask` | 100 | ssn | changed | ✓ | must | OK | masked |  |
| J01 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| J02 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| J03 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | broken | 행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| J04 | adversarial2.json | `error` | 0 | - | ERR(off) | · | must | - | - | enforce=off 에서도 실패: unsupported XML feature |
| J05 | adversarial2.json | `mask` | 1 | ssn | changed | ✓ | must | OK | masked |  |
| A01 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse | OK | broken | ipguard: masking would change query results |
| A02 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse | OK | broken | ipguard: masking would change query results |
| A03 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse | OK | broken | ipguard: masking would change query results |
| A04 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse | OK | masked | ipguard: masking would change query results |
| A05 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse_over | OK | masked | ipguard: masking would change query results |
| A06 | semantics.json | `refuse` | 1 | ssn | refused | ✓ | refuse_over | OK | masked | ipguard: masking would change query results |
| A07 | semantics.json | `mask` | 1 | ssn | distorted | ! | intrinsic | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| A08 | semantics.json | `mask` | 1 | ssn | changed | ✓ | masked_ok | OK | broken | 행 수 1→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다 |
| S06 | semantics.json | `pass` | 0 | - | unchanged | ✓ | scoped | OK | - |  |
| I01 | semantics.json | `mask` | 1 | ssn | distorted | ! | intrinsic | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| I02 | semantics.json | `mask` | 1 | ssn | distorted | ! | intrinsic | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| I03 | semantics.json | `mask` | 1 | ssn | changed | ✓ | intrinsic | OK | masked | 마스킹 정의상 불가피한 결과 변화 |
| I04 | semantics.json | `pass` | 0 | - | unchanged | ✓ | intrinsic | OK | - | 마스킹 정의상 불가피한 결과 변화 |
| I05 | semantics.json | `mask` | 2 | ssn | distorted | ! | intrinsic | DISTORT | broken | 마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡 |
| I06 | semantics.json | `mask` | 2 | ssn | changed | ✓ | intrinsic | OK | masked | 마스킹 정의상 불가피한 결과 변화 |
| N06 | semantics.json | `pass` | 0 | - | unchanged | ✓ | none | OK | - |  |
| N07 | semantics.json | `pass` | 0 | - | unchanged | ✓ | none | OK | - |  |
| Q1 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q2 | tpch-queries.sql | `mask` | 4 | acct,name,addr,phone | changed | ✓ | no-refuse | OK | - |  |
| Q3 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q4 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q5 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q6 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q7 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q8 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q9 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q10 | tpch-queries.sql | `mask` | 4 | name,acct,addr,phone | changed | ✓ | no-refuse | OK | - |  |
| Q11 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q12 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q13 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q14 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q15 | tpch-queries.sql | `mask` | 3 | name,addr,phone | changed | ✓ | no-refuse | OK | - |  |
| Q16 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q17 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q18 | tpch-queries.sql | `mask` | 1 | name | changed | ✓ | no-refuse | OK | - |  |
| Q19 | tpch-queries.sql | `pass` | 0 | - | unchanged | ✓ | no-refuse | OK | - |  |
| Q20 | tpch-queries.sql | `mask` | 2 | name,addr | changed | ✓ | no-refuse | OK | - |  |
| Q21 | tpch-queries.sql | `mask` | 1 | name | changed | ✓ | no-refuse | OK | - |  |
| Q22 | tpch-queries.sql | `mask` | 2 | phone,acct | changed | ✓ | no-refuse | OK | - |  |

================================================================================================================
항목 159    예측 분포: error=1  mask=95  pass=51  refuse=8  utility=4
----------------------------------------------------------------------------------------------------------------
① 자기일관성 — 예측이 실제 집행과 같은가
   일치 ✓ 129   불일치 ✗ 0 (0 이어야 함)   확인필요 ! 8   보류 · 22
② 보안 — 실측이 코퍼스 정답과 같은가
   OK 122   ★LEAK 1 (0 이어야 함)   GAP 6 (알려진 범위 밖)   OVER 0   REFUSED 2   ★DISTORT 6
③ 마스킹 뷰 대조군 — 같은 SQL, 같은 마스크 함수, 메커니즘만 다름
   PII 출력 쿼리 85건 중: broken=64  masked=21
   ipguard 는 **필터** 파손 0 — 술어를 건드리지 않기 때문. 다만
   카디널리티 왜곡은 6건 있다(②의 DISTORT) -- DISTINCT/GROUP BY/
   UNION 이 마스크값 위에서 일어나 행이 무너지는 경우다. 뷰의 파손과
   원인은 다르지만 **조용히 틀린다는 점은 같다.** 숨기지 않는다.
   ※ bypassed 0 은 이 코퍼스에 스키마 수식(h5.cust) 쿼리가 없어서다.
      뷰는 search_path 로만 유도되므로 h5.cust 를 직접 쓰면 뚫린다 --
      score_view_baseline.py 의 별도 우회 시험에서 3/3 우회됨.

뷰 broken — 마스킹 뷰가 쿼리를 깨뜨린 것 (행 수가 달라짐):
  D01    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT ssn FROM cust WHERE ci = $1
  D02    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT * FROM cust WHERE ci = $1
  D03    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT c.name, c.ssn FROM cust c WHERE c.ci = $1
  D04    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT ssn AS x, name AS y FROM cust WHERE ci = $1
  D05    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT acct_no, grade, name, balance, ssn FROM cust WHERE ci = $1
  D06    예측=mask      실측=changed    행 수 50000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT c.ssn, t.amount FROM cust c JOIN tx t ON t.cust_id = c.id WHERE c.ci = $1
  E01    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT substr(ssn, 1, 6) FROM cust WHERE ci = $1
  E02    예측=mask      실측=changed    행 수 10000→0 — 술어가 마스크값과 비교되어 결과가 조용히 틀어졌다
         SELECT ssn || '' FROM cust WHERE ci = $1
  ... 외 56건 (전체는 표 본문 참조)

★ DISTORT — 마스킹이 행 수를 바꾼 것 (우리도 조용히 틀리는 경우):
  V07    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn FROM v_cust UNION SELECT ssn FROM cust WHERE ci = $1
  G01    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT grade, ssn, count(*) FROM cust GROUP BY GROUPING SETS ((grade),(ssn))
  A07    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT t.ssn FROM (SELECT ssn FROM cust) t GROUP BY t.ssn
  I01    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT DISTINCT ssn FROM cust
  I02    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn, count(*) FROM cust GROUP BY ssn
  I05    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn FROM cust UNION SELECT ssn FROM cust

★ LEAK — 마스킹되어야 하는데 안 된 것:
  F02    예측=pass      실측=unchanged  마스킹되어야 하는데 값이 그대로 나갔다
         SELECT * FROM f_srf()

GAP — 메커니즘 범위 밖(라벨 없는 사본 등):
  T04    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT * FROM f_inline()
  M01    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT ssn FROM mv_cust
  M02    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT substr(ssn,1,6) FROM mv_cust
  M03    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT ssn FROM ctas_cust
  M04    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT ssn6 FROM gen_t
  M05    예측=pass      실측=unchanged  알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 평문 그대로 나간다
         SELECT ssn_rev FROM gen_t

확인필요 ! — 집행 경로가 정적 판정보다 넓은 것:
  V07    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn FROM v_cust UNION SELECT ssn FROM cust WHERE ci = $1
  F01    예측=pass      실측=changed    정적 판정은 pass, 실측은 변경 -- 함수 본문 등 별도 계획 경로에서 집행됨(집행이 정적 판정보다 넓다)
         SELECT f_ssn(id) FROM cust WHERE ci = $1
  F03    예측=pass      실측=changed    정적 판정은 pass, 실측은 변경 -- 함수 본문 등 별도 계획 경로에서 집행됨(집행이 정적 판정보다 넓다)
         SELECT f_dyn('ssn')
  G01    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT grade, ssn, count(*) FROM cust GROUP BY GROUPING SETS ((grade),(ssn))
  A07    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT t.ssn FROM (SELECT ssn FROM cust) t GROUP BY t.ssn
  I01    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT DISTINCT ssn FROM cust
  I02    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn, count(*) FROM cust GROUP BY ssn
  I05    예측=mask      실측=distorted  마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡
         SELECT ssn FROM cust UNION SELECT ssn FROM cust
