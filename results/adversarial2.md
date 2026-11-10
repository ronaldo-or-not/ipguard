# 적대적 시험 2라운드 — 라벨 자체를 겨냥 (2026-08-08)

1라운드는 **순회기 로직**을 쳤다. 이번엔 **라벨 자체**를 친다 — PII 를 라벨
없는 릴레이션으로 물질화해버리면 순회기가 아무리 정교해도 무의미하다.
그리고 탐지기에 대한 자원 공격을 포함한다.

23개 공격, 5개 표면. 원시 출력: [`adversarial2.txt`](adversarial2.txt)

---

## 결과

| | 최초 | **수정 후** |
|---|---:|---:|
| 우회 | **3** | **0** |
| 정책으로 분류(탐지 불가가 정당) | 6 | 6 |
| 픽스처 오류 | 1 | 1 |

| 표면 | 항목 | 통과 | 우회 | 비고 |
|---|---:|---:|---:|---|
| 물질화(라벨전파) | 8 | 3 | 0 | 5건은 정책 — 아래 §1 |
| 정책/재작성(RLS·RULE) | 3 | 3 | 0 | |
| 실행컨텍스트(트리거·MERGE·SECDEF) | 3 | 2 | 0 | 1건 정책 |
| **탐지기 자원공격** | 4 | 4 | 0 | 전부 방어 |
| JSON/배열/SRF | 5 | 4 | 0 | 1건 픽스처(libxml 미빌드) |

## 찾은 진짜 버그 3건

### 1. 서브쿼리 전체 행 참조 (J05)

`SELECT json_agg(t) FROM (SELECT ssn FROM cust WHERE ci=$1) t` 가 미탐.

원인: `varattno == 0`(전체 행 Var)을 **`RTE_RELATION` 에서만** 처리했다.
서브쿼리/CTE 의 전체 행 참조는 `get_tle_by_resno(list, 0)` 이 NULL 을 반환해
`unresolved` 로 빠졌다. `row_to_json(c)` 는 잡으면서 `json_agg(t)` 는 놓쳤다 —
**같은 개념인데 RTE 종류가 달라서.**

수정: `RTE_SUBQUERY` / `RTE_CTE` 에서도 `varattno == 0` 이면 대상 목록 전체를 순회.

### 2. MERGE (X02)

`MERGE INTO merge_t USING cust ON ... WHEN MATCHED THEN UPDATE SET note = c.ssn`
이 통째로 미탐.

원인: MERGE 의 SET/INSERT 값은 `targetList` 가 아니라 **`mergeActionList`**
안에 있다. 1라운드에서 고친 `returningList` 와 같은 계열의 구조 누락.

### 3. CREATE TABLE AS (M07)

`CREATE TABLE t_new AS SELECT ssn FROM cust` 가 완전히 안 보였다.

원인: utility 문장 분기에서 `CopyStmt` 만 처리했다. `CreateTableAsStmt`
(CTAS / `SELECT INTO` / `CREATE MATERIALIZED VIEW`)가 빠져 있었다.

---

## §1 물질화 — 순회기로는 원리적으로 회수 불가한 클래스

> **[2026-08-08 정정]** "원리적으로 회수 불가"는 절반만 맞았다. 카탈로그
> 연결이 없어 **자동 전파는 불가능**하지만, **사본 자체에 라벨을 붙이면
> 마스킹된다**(구체화 뷰·CTAS·FDW 외부 테이블 전부 확인). 즉 없던 것은
> 집행 수단이 아니라 **"사본이 생겼다는 사실을 아는 수단"**이었고,
> 그건 커버리지 감사로 메웠다 — [`coverage.md`](coverage.md).
> 파생 컬럼(`substr(ssn,1,6)` 등)은 여전히 열려 있다.

| ID | 쿼리 | 왜 못 잡나 |
|---|---|---|
| M01·M02 | `SELECT ssn FROM mv_cust` | **구체화 뷰는 뷰가 아니라 릴레이션이다.** 재작성 전개가 없고 `mv_cust.ssn` 은 라벨 없는 별개 컬럼 |
| M03 | `SELECT ssn FROM ctas_cust` | CTAS 사본. 같은 이유 |
| M04·M05 | `SELECT ssn6 FROM gen_t` | 생성 컬럼 `GENERATED ALWAYS AS (substr(ssn,1,6)) STORED`. 쓰기 시점에 파생값이 라벨 없는 컬럼으로 물질화됨 |

**이건 walker 버그가 아니라 라벨 전파 문제다.** 순회기를 아무리 고쳐도
안 잡힌다 — 조회 시점에는 PII 와의 연결이 카탈로그에 존재하지 않는다.

**그러나 복사되는 순간은 잡을 수 있고, 지금 잡는다:**

| 복사 행위 | 탐지 |
|---|---|
| `INSERT INTO sink_t SELECT id, ssn FROM cust` | `write=ssn` ✅ |
| `CREATE TABLE t_new AS SELECT ssn FROM cust` | `write=ssn` ✅ (수정 후) |
| `MERGE ... SET note = c.ssn` | `write=ssn` ✅ (수정 후) |

→ **대응은 두 갈래다.** (i) `write` 축으로 PII 가 라벨 없는 릴레이션으로
흘러드는 행위를 차단하거나, (ii) 그 시점에 **라벨을 자동 전파**한다.

**생성 컬럼은 (ii)가 기계적으로 가능한 유일한 물질화 케이스다** — 생성식이
`pg_attrdef` 에 남아 있으므로 카탈로그만 읽어 `ssn6 → ssn` 을 유도할 수 있다.
구체화 뷰도 `pg_rewrite` 에 정의 쿼리가 있으므로 원리적으로는 가능하다.
CTAS 사본은 정의가 남지 않으므로 (i) 밖에 없다.

## §2 재작성이 드러내는 것 — 설계 선택의 실증

`P03 = INSERT INTO rule_src VALUES (1, 'x')` 는 **원문에 `cust` 가 한 번도
나오지 않는다.** 그런데 `DO INSTEAD` 룰이 이를 `INSERT INTO sink_t SELECT
NEW.id, ssn FROM cust ...` 로 재작성한다. 탐지 결과: `write=ssn`.

RLS(P01·P02)도 마찬가지로 통과했다 — 재작성이 정책 qual 을 서브쿼리로
감싸도 provenance 가 유지된다.

**파스 트리만 봤다면 둘 다 못 잡는다.** 재작성 후를 보기로 한 설계 선택의
실증이다.

## §3 탐지기 자원 공격 — 전부 방어

| 공격 | 결과 |
|---|---|
| 표현식 200단 중첩 (`coalesce(coalesce(...)))`) | 정상 탐지. 서브쿼리 깊이가 아니라 **표현식** 깊이라 `MAX_DEPTH` 가 아니라 `check_stack_depth()` 관할 |
| targetList 500 컬럼 | 정상 탐지 |
| `UNION ALL` arm 100개 | 정상 탐지 |
| 라벨 10 × 컬럼 10 (`label_of` 선형 탐색) | 정상 탐지. 이 규모에서는 문제 없음 |

`label_of` 의 선형 탐색은 **라벨 수 × 참조 수**로 늘어난다. 수백 컬럼에
라벨이 붙은 실제 스키마에서는 해시로 바꿔야 하지만, 지금 규모에서 병목이
아님을 확인했다.

## §4 정직하게 남기는 것

- **X01 은 맞는 이유로 통과한 게 아니다.** `INSERT INTO gen_t SELECT id, ssn
  FROM cust` 는 AFTER STATEMENT 트리거가 전이 테이블을 통해 `sink_t` 로 PII 를
  흘리는데, **트리거 본문은 호출부 트리에 없다.** 같은 문장이 우연히 `ssn` 을
  직접 읽기 때문에 `write=ssn` 이 나왔을 뿐이다. 트리거 경유 유출 자체는
  여전히 미탐이며 함수 미탐과 같은 클래스다.
- **X03(SECURITY DEFINER 함수)** 은 F01/F02/F03 과 같은 클래스이나 권한 상승이
  얹혀 위험도가 다르다. 정책(함수 생성 권한)으로만 막을 수 있다.
- **J04(`xmlelement`)** 는 `--without-libxml` 빌드라 실행 자체가 실패했다.
  탐지기 문제가 아니라 시험 환경 제약. 미시험으로 남는다.

## §5 측정 도구 자체의 버그

채점기가 `expect="write"` 항목의 **write 축을 검증하지 않아** M07(CTAS)과
X02(MERGE) 미탐이 "OK" 로 표시됐다. 수동으로 `write=` 를 직접 들여다보고서야
발견했다.

**측정 도구도 코퍼스와 같은 편향을 가진다.** 내가 out 축만 생각하고 짰기
때문에 write 축 실패를 볼 수 없었다. 지표를 추가하면 채점기도 같이 고쳐야
한다는 것이 이번의 교훈.

---

## 누적 — 적대적 시험이 찾아낸 결함

| | 1라운드 | 2라운드 | 계 |
|---|---:|---:|---:|
| 진짜 결함 | 8 | 3 | **11** |
| 수정 | 6 | 3 | 9 |
| 신호로 검출(`bounded`) | 2 | 0 | 2 |

**기본 코퍼스 72항목(95% 통과)은 이 11건 중 0건을 찾지 못했다.**
자기가 쓴 코퍼스로 자기 방어를 재는 것이 왜 숫자가 아니라 주장인지의 실증.

## 여전히 시험하지 않은 것

- FDW 외부 테이블(`postgres_fdw` 설치돼 있음 — 다음 라운드 후보)
- `xmlelement` 계열 (libxml 빌드 필요)
- 라벨 변경과의 동시성 경합 (SPI 로 매 호출 적재)
- `pg_stat_statements` / 서버 로그를 통한 간접 노출 (탐지기 범위 밖 — 별도 통제)
- 파티션 **detach 후** 조회, 파티션별 상이한 컬럼 순서
- `information_schema` 경유 메타데이터 추론
