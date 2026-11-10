# 라벨 키잉 방식 결정 — 이름 vs OID vs 이벤트 트리거 (2026-08-08)

4라운드가 남긴 숙제. **DDL 한 줄로 마스킹이 꺼지는 문제**를 어떻게 고칠 것인가.

**결론: OID 키잉(`regclass` + `attnum`)을 쓴다.** 이벤트 트리거는 채택하지
않는다 — 이름 변경에는 중복이고 파티션 `DETACH` 는 애초에 못 본다.

원시 출력: [`adversarial4.txt`](adversarial4.txt) ·
도구: [`../tools/score_adversarial4.py`](../tools/score_adversarial4.py) (`--key name|oid`)

---

## 결정적 대비

```
ALTER TABLE h5.cust RENAME TO cust_tmp;
SELECT ssn FROM cust_tmp WHERE id=1;

   label_key = name   ->  800102-1000001     ← 평문
   label_key = oid    ->  **************     ← 유지
```

## 커버리지 (4R 시나리오 10건)

| | 시나리오 | name | **oid** |
|---|---|---|---|
| Y01 | `ALTER TABLE RENAME` | ✗ 평문 | **✅** |
| Y02 | `ALTER TABLE RENAME COLUMN` | ✗ 평문 | **✅** |
| Y03 | `ALTER TABLE SET SCHEMA` | ✗ 평문 | **✅** |
| Y04 | 파티션 `DETACH` | ✗ 평문 | ✗ 평문 |
| Y08 | FDW 외부 테이블 | ✗ 평문 | ✗ 평문 |
| Y05·Y06·Y07·Y09·Y10 | 대조군 | ✅ | ✅ |

Y04·Y08 은 **이름 문제가 아니라 구조 문제**다. `DETACH` 는 상속 연결이 끊기는
것이고, FDW 는 원격 카탈로그의 라벨이 전파될 경로가 없는 것이다. 어떤 키잉을
써도 안 고쳐진다.

## 측정 가능한 대가: 0

OID 모드로 전 축을 다시 쟀다. **한 자리도 안 움직였다.**

| 축 | name | oid |
|---|---|---|
| 탐지 회수율 | 95% (52/55) | 95% (52/55) |
| 오탐 | 0 | 0 |
| 마스킹 집행 | 92% (79/86) | 92% (79/86) |
| 과마스킹 | 0 | 0 |
| 3R 적대적 방어 | 30/30 | 30/30 |
| 정합성 위반 | 0 | 0 |
| 발산 조용한 오답 | 0 | 0 |

## OID 키잉의 약점을 실제로 확인했다

**"덤프/복원에서 OID 가 바뀐다"는 걱정은 절반만 맞다.** 실측:

```
$ pg_dump --data-only -t h5oid.pii_label
COPY h5oid.pii_label (relid, attnum, kind) FROM stdin;
h5.cust  2  ci
h5.cust  3  name
h5.cust  4  ssn
```

`relid` 는 **`regclass` 타입**이라 pg_dump 가 생 OID 가 아니라 **이름으로**
덤프하고 복원 시 재해석한다. 릴레이션 쪽 위험은 없다.

**남는 위험은 `attnum` 이다.** 이름이 없는 생 숫자라, 삭제된 컬럼이 있는
테이블을 덤프/복원하면 attnum 이 밀린다. 그러면 라벨이 **엉뚱한 컬럼을
가리킨다** — 라벨을 잃는 것보다 나쁘다. 엉뚱한 걸 가리면서 진짜 PII 는 그대로
나가기 때문이다.

`attname` 을 저장해 검증하면 되지 않느냐는 반문이 가능한데, **안 된다** —
`attname` 이 바뀌는 것(RENAME COLUMN)이 정확히 attnum 으로 막으려던 상황이다.
하나의 저장값이 "이름 변경에 면역"과 "이름으로 검증"을 동시에 할 수 없다.

그래서 **검증 함수**로 옮겼다. 복원 직후와 정기 점검에서 돌린다:

```sql
SELECT * FROM ipguard_verify_labels('h5oid');   -- 빈 결과가 정상
```

인위로 드리프트를 만들어 잡히는 것을 확인했다:
`dangling attnum | h5.cust attnum=99`.

## 이벤트 트리거를 채택하지 않은 이유

이벤트 트리거가 DDL 후에 라벨을 자동 갱신하면 이름 키잉을 유지할 수 있다는
발상이었다. 실제로 무엇이 보이는지 쟀다:

```
ALTER TABLE h5.et_p DETACH PARTITION h5.et_p1;
   ET: tag=ALTER TABLE  type=table  identity=h5.et_p   objid=17652   ← 부모만
ALTER TABLE h5.et_p1 RENAME TO et_p2;
   ET: tag=ALTER TABLE  type=table  identity=h5.et_p2  objid=17655   ← OID+새이름
```

- **`DETACH` 는 부모만 보고한다.** 어느 파티션이 떨어졌는지 알 수 없다.
  `pg_inherits` 를 DDL 전후로 스냅샷해 비교하면 되지만 취약하다.
- **RENAME 은 OID 와 새 이름을 준다.** 그런데 이걸 라벨에 반영하려면 라벨이
  **OID 앵커를 갖고 있어야 한다.** OID 앵커가 있으면 애초에 OID 키잉으로
  끝나므로 **이벤트 트리거는 중복이다.**
- 이벤트 트리거 생성은 superuser 권한이 필요하다.

즉 이벤트 트리거는 이름 키잉을 구제하지 못하고, OID 키잉을 보조할 필요도 없다.

## 기본값을 바꾸지 않은 이유

라벨 테이블의 **모양이 다르다**(`relname, attname` vs `relid, attnum`).
기본값을 `oid` 로 바꾸면 기존 이름 키잉 설치가 즉시 깨진다 — 조용히가 아니라
SQL 에러로 깨지므로 위험하지는 않지만, 파괴적 기본값 변경은 근거가 더 필요하다.

대신 이렇게 했다:

```sql
SELECT ipguard_migrate_labels_to_oid('h5', 'h5oid');   -- 28건, 멱등
SET ipguard.label_schema = 'h5oid';
SET ipguard.label_key = oid;
```

마이그레이션은 멱등이고(두 번째 실행은 0건), 트리거도 자동으로 걸어 준다.
**권장값은 `oid` 다.** README 설치 절에 적었다.

## 남은 것

- **Y04 파티션 `DETACH`** — 어떤 키잉으로도 안 고쳐진다. 라벨을 잃는 순간을
  **감지**하는 쪽(정기 커버리지 점검)으로 가야 한다. 월별 파티션 순환은
  금융권 표준 운영이므로 실전에서 반드시 밟는다.
- **Y08 FDW** — 외부 테이블에 라벨을 따로 붙이는 운영 수칙.
- `attnum` 드리프트 — 검증 함수로 감지는 되지만 **자동 복구는 없다.**

## 재현

```bash
python3 tools/score_adversarial4.py --key name
python3 tools/score_adversarial4.py --key oid
```
