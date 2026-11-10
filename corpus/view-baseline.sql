-- 마스킹 뷰 베이스라인.
--
-- "그냥 마스킹 뷰 만들면 되잖아요?" 에 숫자로 답하기 위한 대조군.
-- 현장에서 가장 흔한 마스킹 방식이고, 확장 코드가 0줄이다.
--
-- 공정성: 마스크 함수는 ipguard 와 **동일한 것**을 쓴다. 비교 대상은
-- 마스크 값이 아니라 메커니즘(뷰 vs 계획 재작성)이어야 하기 때문이다.
--
-- 배치: vmask 스키마에 base 테이블과 **같은 이름**의 뷰를 만든다.
-- search_path = vmask, h5, public 으로 두면 애플리케이션 SQL 을 한 글자도
-- 고치지 않고 뷰로 유도된다 -- 실제 배포에서 쓰는 방법 그대로.

DROP SCHEMA IF EXISTS vmask CASCADE;
CREATE SCHEMA vmask;

CREATE VIEW vmask.cust AS
SELECT id,
       ipguard_mask(ci,      'ci')    AS ci,
       ipguard_mask(name,    'name')  AS name,
       ipguard_mask(ssn,     'ssn')   AS ssn,
       ipguard_mask(phone,   'phone') AS phone,
       ipguard_mask(addr,    'addr')  AS addr,
       ipguard_mask(birth,   'birth') AS birth,
       ipguard_mask(acct_no, 'acct')  AS acct_no,
       grade, balance, memo, created_at
  FROM h5.cust;

-- 코퍼스가 참조하는 뷰들도 같은 이름으로 덮어쓴다
CREATE VIEW vmask.v_cust      AS SELECT * FROM vmask.cust;
CREATE VIEW vmask.v_cust_safe AS SELECT id, grade, balance FROM vmask.cust;

-- 실제 배포라면 여기에 더해 base 테이블 권한을 회수해야 한다:
--   REVOKE SELECT ON h5.cust FROM app_role;
-- 회수하지 않으면 `SELECT ssn FROM h5.cust` 한 줄로 우회된다.
-- (이 측정에서는 회수하지 않고, 우회 가능성 자체를 항목으로 잰다.)

-- ─────────────────────────────────────────────────────────────────────────
-- 라벨된 **모든 테이블**에 대해 마스킹 뷰를 자동 생성한다.
--
-- 손으로 cust 하나만 만들어 두면 acct/base_cust/decoy/dom_t/wide_t 를 쓰는
-- 쿼리가 전부 "뷰 우회"로 집계된다. 그건 뷰 메커니즘이 뚫린 게 아니라
-- **아무도 그 테이블 뷰를 안 만든 것**이므로, 그렇게 세면 대조군을 부당하게
-- 나쁘게 만든다. ipguard 도 같은 라벨 테이블을 자동으로 읽으므로, 뷰도 같은
-- 출처에서 자동 생성해야 두 메커니즘을 같은 조건에서 비교하는 것이 된다.
--
-- 상속/파티션 자식까지 pg_inherits 로 전개한다(load_labels 와 동일 규칙).
DROP TABLE IF EXISTS _lbl;
CREATE TEMP TABLE _lbl AS
WITH RECURSIVE d(relid, attname, kind) AS (
        SELECT c.oid, l.attname, l.kind
          FROM h5.pii_label l
          JOIN pg_class c ON c.relname = l.relname
                         AND c.relnamespace = 'h5'::regnamespace
      UNION ALL
        SELECT i.inhrelid, d.attname, d.kind
          FROM d JOIN pg_inherits i ON i.inhparent = d.relid
)
SELECT d.relid, a.attnum, d.kind
  FROM d JOIN pg_attribute a ON a.attrelid = d.relid
                            AND a.attname = d.attname
 WHERE NOT a.attisdropped AND a.attnum > 0;

DO $gen$
DECLARE
    r    record;
    cols text;
BEGIN
    FOR r IN
        SELECT DISTINCT c.oid AS relid, c.relname
          FROM _lbl l
          JOIN pg_class c ON c.oid = l.relid
         WHERE c.relkind IN ('r', 'p')          -- 테이블/파티션 테이블만
           AND c.relnamespace = 'h5'::regnamespace
    LOOP
        SELECT string_agg(
                 CASE WHEN l.kind IS NULL THEN quote_ident(a.attname)
                      ELSE format('ipguard_mask(%I, %L) AS %I',
                                  a.attname, l.kind, a.attname)
                 END, ', ' ORDER BY a.attnum)
          INTO cols
          FROM pg_attribute a
          LEFT JOIN _lbl l ON l.relid = a.attrelid AND l.attnum = a.attnum
         WHERE a.attrelid = r.relid AND a.attnum > 0 AND NOT a.attisdropped;

        EXECUTE format('CREATE OR REPLACE VIEW vmask.%I AS SELECT %s FROM h5.%I',
                       r.relname, cols, r.relname);
    END LOOP;
END
$gen$;

-- 생성 결과 확인용
SELECT 'vmask 뷰 ' || count(*)::text || '개' AS generated
  FROM pg_class c
 WHERE c.relnamespace = 'vmask'::regnamespace AND c.relkind = 'v';

-- ─────────────────────────────────────────────────────────────────────────
-- h5 의 **뷰**에 대해서도 마스킹 그림자를 만든다.
--
-- ★ 이건 뷰 방식에 실제보다 유리한 조건이다. 뷰의 출력 컬럼 중 어느 것이 PII
--   인지는 뷰 정의만 봐서는 알 수 없다(`SELECT substr(ssn,1,6) AS x` 같은
--   표현식 컬럼에서 provenance 가 사라지는 게 정확히 와이어 38% 의 이유다).
--   여기서는 그 판별을 ipguard 의 분석으로 대신 해준다 -- 즉 대조군에게
--   **혼자서는 얻을 수 없는 정보**를 쥐여 준다.
--
--   그래도 이렇게 하는 이유: 이러고도 남는 우회는 설정 부실이 아니라
--   메커니즘 자체의 한계이기 때문이다. 유리하게 깔아주고도 지는 쪽이
--   진짜 결과다.
DO $genv$
DECLARE
    r    record;
    cols text;
BEGIN
    FOR r IN
        SELECT c.relname
          FROM pg_class c
         WHERE c.relnamespace = 'h5'::regnamespace
           AND c.relkind = 'v'
           AND c.relname NOT IN ('v_cust', 'v_cust_safe')   -- 손으로 만든 것 유지
    LOOP
        SELECT string_agg(
                 CASE WHEN e.label IS NULL THEN quote_ident(a.attname)
                      ELSE format('ipguard_mask(%I, %L) AS %I',
                                  a.attname, e.label, a.attname)
                 END, ', ' ORDER BY a.attnum)
          INTO cols
          FROM pg_attribute a
          LEFT JOIN LATERAL (
                SELECT x.label
                  FROM ipguard_explain(
                         format('SELECT %I FROM h5.%I', a.attname, r.relname)) x
                 WHERE x.path = 'output'
                 LIMIT 1) e ON true
         WHERE a.attrelid = format('h5.%I', r.relname)::regclass
           AND a.attnum > 0 AND NOT a.attisdropped;

        IF cols IS NOT NULL THEN
            EXECUTE format('CREATE OR REPLACE VIEW vmask.%I AS SELECT %s FROM h5.%I',
                           r.relname, cols, r.relname);
        END IF;
    END LOOP;
END
$genv$;

SELECT 'vmask 뷰 최종 ' || count(*)::text || '개' AS generated
  FROM pg_class c
 WHERE c.relnamespace = 'vmask'::regnamespace AND c.relkind = 'v';
