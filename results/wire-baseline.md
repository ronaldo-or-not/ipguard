# 와이어 레벨 탐지기 기준선 — 실측 (2026-08-08)

**측정 대상:** RowDescription의 `resorigtbl`/`resorigcol` 만으로 출력 컬럼을
PII로 분류할 때의 탐지 능력. 이것이 C 확장 AST 순회가 넘어서야 할 기준선이다.

**방법:** `PQprepare` + `PQdescribePrepared` 로 쿼리를 **실행하지 않고** 결과
메타데이터만 받고, `PQftable()` / `PQftablecol()` 을 판독한다. 와이어 훅이
보는 것과 정확히 동일한 정보다.

**환경:** db.example.internal, PostgreSQL 16.10 (소스 빌드, `--without-icu
--without-readline`), UTF8 / C locale, 유닉스 소켓 전용.
원시 출력: [`wire-baseline.txt`](wire-baseline.txt)

---

## 헤드라인

| | |
|---|---:|
| 코퍼스 항목 | 72 |
| PII를 실제로 노출하는 항목 | 55 |
| **와이어 훅이 완전히 잡은 항목** | **21 (38%)** |
| **AST 순회가 회수해야 할 항목** | **34** |
| 오탐(FP) | **0** |

설계 시점 추정치는 29%였다. 실측은 38%다. 추정이 아니라 측정으로 바뀌었다.

## 카테고리별

| 카테고리 | 항목 | 통과 | 미탐 | 오탐 | prepare 실패 |
|---|---:|---:|---:|---:|---:|
| 직접참조 | 9 | 9 | 0 | 0 | 0 |
| **표현식래핑** | 21 | 3 | **18** | 0 | 0 |
| 뷰/CTE/집합연산 | 8 | 4 | 4 | 0 | 0 |
| **함수/동적SQL** | 8 | 1 | **7** | 0 | 0 |
| 부채널 | 5 | 5 | 0 | 0 | 0 |
| **COPY** | 4 | 0 | **4** | 0 | 0 |
| 바이너리/인코딩 | 5 | 5 | 0 | 0 | 0 |
| 제어문 | 7 | 6 | 0 | 0 | 1 |
| 파라미터결속 | 5 | 5 | 0 | 0 | 0 |
| **합계** | **72** | **38** | **33** | **0** | **1** |

미탐이 세 카테고리(표현식 18 / 함수 7 / COPY 4)에 집중된다. 이 29건이 전체
미탐의 88%다. **AST 순회의 가치는 이 세 곳에서 결정된다.**

## 설계 시점 가정과 달랐던 6건

소스만 읽고 추정했던 라벨이 실측에서 뒤집힌 항목. 코퍼스에 반영 완료.

| ID | SQL | 가정 | 실측 | 왜 |
|---|---|---|---|---|
| E05 | `ssn::text` | ast | **wire** | 동일 타입 캐스트를 플래너가 제거 |
| V02 | `WITH x AS (SELECT ssn ...) SELECT * FROM x` | ast | **wire** | **CTE가 provenance를 유지한다.** "RTE_CTE는 resorigtbl을 안 준다"는 내 서술이 틀렸다 |
| V03 | `WITH x AS MATERIALIZED (...)` | ast | **wire** | MATERIALIZED로 인라인을 막아도 유지 |
| F07 | `(c).ssn` | ast | **wire** | FieldSelect가 provenance를 유지 |
| P04 | `WHERE ci = $1 OR 1=1` | ast | **wire** | 술어 변조는 출력 provenance에 영향 없음 |
| X07 | `SELECT ssn FROM cust; SELECT 1` | ast | **no_parse** | 다중 문장은 prepared statement로 만들 수 없음 |

**V02/V03이 특히 중요하다.** CTE가 provenance를 유지한다면, 와이어 훅의
약점은 내가 서술했던 것보다 좁다. 반대로 **`UNION ALL`(V04), 뷰(V01/V07),
재귀 CTE(V08)는 실제로 잃는다** — 뷰는 base table이 아니라 뷰 OID를 준다.

## COPY: 와이어에서 완전히 무형

C01–C04는 **`PQprepare`가 성공하는데 결과 컬럼이 0개**로 나온다. COPY는 유틸리티
문장이라 Parse 시점에 릴레이션 해석조차 하지 않는다. 즉 와이어 레벨 관측자는
Parse 단계에서 COPY에 대해 **아무 정보도 얻지 못한다** — 컬럼도, 테이블도, 심지어
대상이 존재하는지조차. `pg_dump`가 쓰는 경로가 이것이다.

## 부채널 5건은 "통과"지만 안심할 근거가 아니다

S01–S05는 출력에 PII가 없으므로 FP 없이 통과한다. 그러나 이들은
`WHERE ssn LIKE '8001%'` 같은 이진탐색 오라클이다. **마스킹은 이 클래스에
구조적으로 무력하다.** 술어 참조(`predicate_pii`) 탐지 + 쿼리 형태 allowlist
만이 막을 수 있고, 그건 마스킹 지표로는 측정되지 않는다. 별도 지표가 필요하다.

## 오탐 0의 의미

`D08`(non-PII 자유텍스트에 주민번호 형태 문자열을 심어둔 함정)을 포함해
FP가 하나도 없다. **카탈로그 provenance 기반 접근은 원리적으로 과마스킹하지
않는다** — 바이트 패턴 매칭 방식과의 결정적 차이다. AST 순회로 넘어갈 때도
이 성질을 유지해야 하며, FP가 생기면 그것은 순회기의 버그다.

---

## 다음 측정

1. **AST 순회 회수율** — C 확장을 만들고 같은 코퍼스로 재실행. 34건 중 몇 건을
   회수하는가. 특히 F04/F05/F06/F08(whole-row Var)과 C01–C04(COPY)를 잡는지.
2. **바이너리 포맷** — 이번 측정은 `describePrepared` 응답이라 format이 항상 0이다.
   B01/B05의 바이너리 전송 경로는 실제 실행으로 따로 재야 한다.
3. **컬럼명 난독화 재실행** — 탐지기가 `pii_label`이 아니라 컬럼명 문자열을
   보고 맞히는 부정행위를 하지 않는지 검증.

## 재현

```bash
gcc -O2 -Wall -I$HOME/pg/include -o probe_provenance probe_provenance.c \
    -L$HOME/pg/lib -lpq -Wl,-rpath,$HOME/pg/lib
export PATH="$HOME/pg/bin:$PATH" PGHOST="$HOME/.pgsock" PGPORT=55432 PGDATABASE=ipdev
python3 score_wire.py h5-corpus.json --probe ./probe_provenance
```
