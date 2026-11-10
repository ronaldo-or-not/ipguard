# 적대적 시험 — ipguard 탐지기 (2026-08-08)

**왜 했나.** 기본 코퍼스(`h5-corpus.json`)의 95%는 **내가 공격 집합과 방어를
둘 다 설계해서 나온 숫자**다. 심사위원이 가장 먼저 하는 일은 그 코퍼스 밖의
쿼리를 만드는 것이므로, 그 일을 먼저 스스로 한다.

31개 공격, 기본 코퍼스가 한 번도 건드리지 않은 7개 표면.
원시 출력: [`adversarial.txt`](adversarial.txt)

---

## 결과

| | 최초 실행 | **수정 후** |
|---|---:|---:|
| 우회 성공 | **8** | **2** |
| 오탐 | 2 | **0** |
| 기본 코퍼스 퇴행 | — | **0** (95%, FP 0 유지) |

남은 2건은 우회가 **가능한 채로 남겨둔 것이 아니라, 신호로 검출되어
fail-closed 로 막을 수 있게 된 것**이다(아래 §fail-closed 참조).

| 표면 | 항목 | 통과 | 우회 |
|---|---:|---:|---:|
| DML RETURNING | 6 | 6 | 0 |
| **중첩/재귀 bound** | 5 | 3 | **2** |
| 상속/파티션 | 5 | 5 | 0 |
| 재작성(뷰/별칭) | 3 | 3 | 0 |
| 타입/RTE 종류 | 5 | 4 | 0 |
| 상관 서브쿼리 | 3 | 3 | 0 |
| 집계/그룹화 | 4 | 4 | 0 |

## 찾은 우회 — 원인 4가지

### 1. DML `RETURNING` 전체 미탐 (R01·R02·R03·R06) — 카테고리 전멸

`UPDATE cust SET ... WHERE ci=$1 RETURNING ssn` 이 통째로 미탐이었다.

원인: `walk_query` 가 `q->targetList` 만 봤다. **DML 에서 `targetList` 는
"테이블에 써넣는 값"이고, 클라이언트로 나가는 것은 `q->returningList` 다.**
둘을 혼동했다.

기본 코퍼스에 **DML 이 한 건도 없었다.** SELECT 만 생각한 설계 편향이
그대로 드러난 사례다 — 적대적 시험이 아니었으면 발견되지 않았다.

수정: `commandType == CMD_SELECT` 일 때만 `targetList` 를 출력으로 보고,
DML 은 `returningList` 를 출력으로, `targetList` 는 **쓰기(`write=`)** 라는
별도 축으로 보고한다. RTE_SUBQUERY / RTE_CTE 해석에도 같은 분기가 필요했다
(R06: `WITH d AS (DELETE ... RETURNING ssn) SELECT * FROM d`).

### 2. 파티션·상속 자식을 직접 겨냥 (H02·H04)

라벨은 부모(`acct`, `base_cust`)에만 붙는데 `SELECT acct_no FROM acct_p1`
처럼 자식을 직접 조회하면 미탐. **핀테크 스키마는 거래·이력 테이블이 거의
항상 파티셔닝돼 있으므로 실전에서 바로 뚫린다.**

수정: 라벨 적재 쿼리를 `pg_inherits` 재귀로 자손까지 전개. 컬럼은 `attnum`
이 아니라 **`attname` 으로 잇는다** — `ADD COLUMN` 이력에 따라 자식의
`attnum` 이 부모와 다를 수 있다.

### 3. 쓰기 경로 서브쿼리의 오귀속 (R05)

`UPDATE cust_w SET grade = (SELECT ssn FROM cust WHERE ci=$1)` 이
"클라이언트로 ssn 이 나간다"로 보고됐다. `walk_query` 가 서브쿼리를 만나면
호출자의 수집 대상을 무시하고 항상 `out_kinds` 에 넣었기 때문.

수정: 수집 대상을 호출자에게서 물려받게 함. 지금은
`out=;pred=ci;write=ssn` — **PII 가 클라이언트로 나가는 게 아니라 non-PII
컬럼으로 이동한다**는 것을 정확히 구분해 보고한다. 이건 마스킹 범위 밖이며
별도 통제가 필요한 별개 위험이다.

### 4. 순회 bound 소진 (N03·N04) — **남아 있음, 그러나 검출된다**

중첩 서브쿼리 30단/60단이면 `MAX_DEPTH(24)` / `MAX_STACK(32)` 를 넘어
탐지기가 조용히 포기한다. 30단 중첩은 한 줄로 생성 가능하다.

이것은 내가 1차 심사에서 eBPF 를 두고 했던 지적 — *"bound 에서 포기하는
파서는 fail-open 이면 장식이다"* — 을 내 C 확장에서 그대로 재현한 것이다.

---

## fail-closed 신호 설계 — 이 시험의 핵심 산출물

bound 소진을 막으려면 "해석 못 한 참조"를 거부 신호로 써야 한다.
그런데 **정상 쿼리도 해석 못 하는 참조를 만든다**(`generate_series()`,
`VALUES`). 그래서 신호를 하나로 뭉치면 우회를 열어두거나 정상 업무를
막거나의 양자택일이 된다.

두 신호를 분리했다:

- **`unresolved`** — RTE 종류 때문에 출처를 못 밝힘. `RTE_FUNCTION`,
  `RTE_VALUES` 등. **정상 쿼리에서 흔하다.**
- **`bounded`** — 순회 깊이/스택 소진으로 포기. **정상 쿼리에서 나올 이유가
  없다.**

전체 103개 쿼리(기본 코퍼스 72 + 적대적 31) 실측:

| 거부 신호 | 거부되는 쿼리 | 실제 우회 차단 | **정상 쿼리 오탐** |
|---|---:|---:|---:|
| `unresolved > 0` | 4 | 2 | **2** |
| **`bounded > 0`** | 2 | 2 | **0** |

`unresolved>0` 로 막으면 `SELECT g FROM generate_series(1,3) g` 같은 정상
쿼리가 같이 막힌다. `bounded>0` 로 막으면 **확인된 우회 2건을 전부 차단하고
오탐이 0**이다.

**이 분리가 fail-closed 를 값싸게 만든다.** 마스킹 집행 설계는 이 신호를
쓰면 된다: `bounded > 0` → 거부. 오탐 비용 0으로 bound 우회가 닫힌다.

> 주의: 오탐 0은 103개 쿼리 기준이다. 실제 워크로드에서 `bounded` 를 올리는
> 정상 쿼리가 있는지는 프로덕션 쿼리 코퍼스로 다시 재야 한다. 지금 숫자는
> "이 신호가 원리적으로 분리 가능하다"는 근거이지 운영 오탐률이 아니다.

## 정책으로 남기는 미탐

`T04 = SELECT * FROM f_inline()`. FROM 절 SRF 는
`inline_set_returning_function` 대상이라 **계획하면** 전개된다. 우리는
재작성까지만 하므로 미탐. **`planner_hook` 로 옮기면 잡히는지가 다음 단계
(c) 의 정량적 논거**가 된다 — 옮길 이유가 성능이 아니라 탐지율일 수 있다.

기본 코퍼스의 F01/F02/F03(UDF 본문, 동적 SQL)과 같은 계열이며, 대응은
탐지가 아니라 정책(함수 생성 권한, 지문 allow-list)이다.

---

## 여전히 시험하지 않은 것

정직하게 남긴다. 이 목록이 비어 보이면 공격이 약한 것이다.

- **RLS 정책**이 붙은 테이블의 재작성
- **트리거 전이 테이블**(`REFERENCING OLD/NEW TABLE`), `RTE_NAMEDTUPLESTORE`
- **`MERGE`** (PG 16 은 `RETURNING` 미지원이라 제외했으나 PG 17+ 에서는 필요)
- `DO INSTEAD` **DML 룰**
- **외부 테이블**(FDW) / `postgres_fdw` 를 통한 원격 노출
- **`SECURITY DEFINER` 함수**를 통한 권한 상승 경로
- 대량 `IN (...)` / 매우 긴 targetList 로 인한 시간 복잡도 공격
  (`label_of` 가 선형 탐색이다 — 라벨 수 × 컬럼 수)
- 동시성: 라벨을 SPI 로 매 호출 적재하므로 라벨 변경과의 경합

## 재현

```bash
psql -d ipdev -f corpus/schema.sql -f corpus/adversarial-schema.sql
python3 tools/score_adversarial.py corpus/adversarial.json corpus/h5-corpus.json
```
