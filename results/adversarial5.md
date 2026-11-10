# 적대적 시험 5라운드 — 권한 / 롤 / 우회 경로 (2026-08-08)

1~3R 은 SQL 문장을, 4R 은 카탈로그 DDL 을 쳤다. 이번 표적은 **누가 이 컨트롤을
끌 수 있는가**다.

**집행기가 아무리 정교해도 스위치를 아무나 끌 수 있으면 의미가 없다.**

시나리오 10건 중 **처음에 4건이 평문**이었고, 전부 원인이 하나였다.
고친 뒤 남은 것은 1건이며 그건 구조상 불가피하다 — 대신 **감지**로 덮었다.

원시 출력: [`adversarial5.txt`](adversarial5.txt) ·
도구: [`../tools/score_adversarial5.py`](../tools/score_adversarial5.py)

---

## ★★ 최대 발견 — 보안 컨트롤이 `SET` 한 줄 거리에 있었다

일반 앱 롤(`z5_app`, `SELECT` 권한만)로 실측:

```sql
SET ipguard.enforce = off;                  -- 800102-1000001   평문
SET ipguard.label_schema = 'z5_empty';      -- 800102-1000001   평문 (빈 라벨표로 우회)
SET ipguard.on_divergence = allow;          -- 조용한 오답 허용
```

**GUC 6개가 전부 `PGC_USERSET` 이었다.** 앱 사용자가, 또는 **SQL 인젝션이
공짜로**, 한 줄로 마스킹 전체를 끈다. 이 프로젝트가 4라운드에 걸쳐 쌓은
집행·판정식·라벨 키잉이 전부 그 한 줄 아래에 있었다.

**전부 `PGC_SUSET` 으로 바꿨다.** PostgreSQL 15+ 에서는 필요하면 개별 위임이
가능하다 — `GRANT SET ON PARAMETER ipguard.enforce TO <role>`. 기본은 거부,
위임은 명시적.

```
   Z01 enforce 끄기        exposed  ->  masked + "permission denied to set parameter"
   Z02 label_schema 돌리기  exposed  ->  masked + 차단
   Z03 판정식 끄기          허용됨    ->  차단
```

## 배포 모델이 바뀐다 (그리고 하네스가 그걸 드러냈다)

`PGC_SUSET` 으로 바꾸자 **모든 시나리오가 "SET 권한 없음" 에러**가 됐다 —
내 하네스가 세션에서 `SET ipguard.enforce = on` 을 하고 있었기 때문이다.

그게 정답을 알려줬다. **집행은 앱이 세션에서 켜는 게 아니라 롤/전역 기본값으로
켜는 것이다:**

```sql
ALTER ROLE app_role SET ipguard.enforce = on;
ALTER ROLE app_role SET ipguard.on_divergence = error;
-- 또는 postgresql.conf 에 전역으로
```

앱은 켤 수도 끌 수도 없고, 켜져 있는 채로 돌 뿐이다. 하네스를 이 모델로
고치자 시나리오가 제대로 측정됐다.

> 하마터면 "SET 권한 없음 에러"를 방어 성공으로 셀 뻔했다. **막힌 것과 쿼리가
> 안 돌아간 것은 다르다** — 공격용 `SET` 이 거부돼도 그 뒤의 질의 출력을 봐야
> 데이터가 새는지 알 수 있다. 판정기를 그렇게 고쳤다.

## 남은 1건 — `SECURITY DEFINER` 백도어 (구조상 불가피)

```sql
CREATE FUNCTION f() RETURNS text SECURITY DEFINER AS $$
  BEGIN SET LOCAL ipguard.enforce = off;        -- 소유자 = superuser
        RETURN (SELECT ssn FROM cust WHERE id=1); END $$;
```

함수가 **소유자 권한으로** 돌기 때문에 `PGC_SUSET` 이 막지 못한다.
이건 코드로 못 막는다 — superuser 는 정의상 뭐든 할 수 있고, 그런 함수가
만들어진 시점에 이미 신뢰 경계가 깨졌다.

**그래서 감지한다** (커버리지 감사와 같은 원칙):

```sql
SELECT * FROM ipguard_audit_definers();   -- 빈 결과가 정상
```

`SECURITY DEFINER` 함수 중 본문이나 `SET` 절에서 `ipguard.*` 를 건드리거나
라벨된 릴레이션을 참조하는 것을 나열한다. Z10 시나리오에서 백도어 함수를
실제로 잡는 것을 확인했다.

## 방어한 축

| | 시나리오 | 결과 |
|---|---|---|
| Z05 | 앱 롤이 라벨 테이블 `DELETE` | 차단(`SELECT` 만 부여) |
| Z06·Z07 | `COPY (SELECT …) TO STDOUT` | **마스킹됨** — 내부 질의는 계획되므로 훅이 발화한다 |
| Z08 | 일반 사용자 정상 조회 | 마스킹 |
| Z09 | 슈퍼유저 정상 조회 | 마스킹 — **컨트롤은 롤과 무관하다** |
| Z10 | 백도어 감사 | 잡음 |

## 운영 수칙 (이 라운드가 만든 것)

```sql
-- 1) 집행은 롤/전역 기본값으로. 앱이 켜고 끄는 것이 아니다
ALTER ROLE app_role SET ipguard.enforce = on;

-- 2) 앱 롤은 라벨 테이블에 SELECT 만. load_labels 가 읽어야 하므로 필요하다
--    (없으면 쿼리가 통째로 에러난다 -- fail-closed 이긴 하나 앱이 멈춘다)
GRANT SELECT ON h5.pii_label TO app_role;

-- 3) SECURITY DEFINER 백도어 정기 감사
SELECT * FROM ipguard_audit_definers();
```

## 한계

- `SECURITY DEFINER` 감사는 **함수 본문 텍스트**를 본다. 동적 SQL 로 조립하면
  피할 수 있다. 확실한 방어는 그런 함수를 만들 권한 자체를 통제하는 것이다.
- 논리 복제·`pg_dump`·물리 백업은 계획기를 아예 거치지 않는다. 이 경계는
  **이 확장이 다루는 범위 밖**이며(힙을 직접 읽는다), 저장 암호화나 별도
  통제가 필요하다. 이번 라운드에서 측정하지 않았다(`wal_level=replica` 라
  논리 복제 슬롯을 만들 수 없었다).

## 회귀

기본값에서 변동 0: 탐지 **95%**, FP **0**, 퇴행 **0**, 집행 **92%**,
과마스킹 **0**, 3R 방어 **30/30**, 4R 방어 5, 커버리지 정탐 **3/3**·오탐 **0**,
정합성 위반 **0**, 발산 조용한 오답 **0**, TPC-H **0/22**(판정식 ON 5/22),
뷰 필터 **3/4 vs 0/4**, 우회 **3/3 vs 0/3**.

## 누적

> **적대적 시험 5라운드가 결함 25건을 찾았고, 95% 통과하는 기본 코퍼스는
> 그중 0건을 찾지 못했다.** 라운드마다 표적이 달랐다 — SQL 문장(1~3R),
> 카탈로그 DDL(4R), **권한과 롤(5R)**. 한 축만 파면 나머지는 안 보인다.

## 재현

```bash
python3 tools/score_adversarial5.py
```
