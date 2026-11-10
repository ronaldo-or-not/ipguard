-- 적대적 시험용 스키마 확장.
-- 기본 코퍼스(schema.sql)가 다루지 않은 표면을 만든다:
--   파티션/상속(라벨 상속 문제), RULE 재작성, security_barrier 뷰,
--   도메인 타입, 전이 테이블, 인라인 가능한 SRF.
SET search_path = h5, public;

-- ── 파티션: 라벨은 부모에만. 자식을 직접 겨냥하면?
DROP TABLE IF EXISTS acct CASCADE;
CREATE TABLE acct (id bigint, ci text, acct_no text, amount numeric)
    PARTITION BY RANGE (id);
CREATE TABLE acct_p1 PARTITION OF acct FOR VALUES FROM (1) TO (5000);
CREATE TABLE acct_p2 PARTITION OF acct FOR VALUES FROM (5000) TO (1000000);
INSERT INTO acct SELECT g, repeat('A',88),
       '110-' || lpad((g%1000)::text,3,'0'), (g%9999)::numeric
FROM generate_series(1,9999) g;

-- ── 상속(레거시 패턴): 라벨은 부모에만
DROP TABLE IF EXISTS base_cust CASCADE;
CREATE TABLE base_cust (id bigint, ssn text);
CREATE TABLE child_cust () INHERITS (base_cust);
INSERT INTO base_cust VALUES (1,'800101-1111111');
INSERT INTO child_cust VALUES (2,'800102-2222222');

-- ── 재작성으로만 출처가 드러나는 릴레이션.
-- (테이블에 ON SELECT 룰을 다는 것은 현대 PG 에서 금지되므로 -- 
--  "relation cannot have ON SELECT rules" -- 뷰 + 컬럼 별칭으로 구성한다.
--  컬럼명이 x 로 완전히 가려져 이름 기반 추론이 원천 불가능하다.)
DROP VIEW IF EXISTS decoy CASCADE;
CREATE VIEW decoy AS SELECT id, ssn AS x FROM cust;

-- ── security_barrier 뷰
DROP VIEW IF EXISTS v_barrier;
CREATE VIEW v_barrier WITH (security_barrier) AS SELECT * FROM cust;

-- ── 도메인 타입 위의 PII
DROP TABLE IF EXISTS dom_t CASCADE;
DROP DOMAIN IF EXISTS ssn_t;
CREATE DOMAIN ssn_t AS text;
CREATE TABLE dom_t (id bigint, s ssn_t);
INSERT INTO dom_t VALUES (1,'800101-3333333');

-- ── DML 대상 (RETURNING 시험용). cust 를 직접 건드리지 않도록 사본.
DROP TABLE IF EXISTS cust_w CASCADE;
CREATE TABLE cust_w AS SELECT * FROM cust LIMIT 100;

-- ── 인라인 가능한 SRF (FROM 절 SRF 는 inline_set_returning_function 대상)
CREATE OR REPLACE FUNCTION f_inline() RETURNS SETOF cust
    LANGUAGE sql STABLE AS $$ SELECT * FROM h5.cust $$;

-- ── 라벨: 부모/원본에만 붙인다. 자식·사본은 일부러 라벨하지 않는다.
DELETE FROM pii_label WHERE relname IN
    ('acct','acct_p1','base_cust','child_cust','decoy','dom_t','cust_w');
INSERT INTO pii_label VALUES
    ('acct','ci','ci'), ('acct','acct_no','acct'),   -- 부모만
    ('base_cust','ssn','ssn'),                       -- 부모만
    ('dom_t','s','ssn'),
    ('cust_w','ssn','ssn'), ('cust_w','name','name'), ('cust_w','ci','ci');

ANALYZE;
