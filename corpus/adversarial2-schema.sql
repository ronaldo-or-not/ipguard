-- 적대적 시험 2라운드 스키마.
-- 1라운드는 순회기 로직을 쳤다. 이번엔 **라벨 자체**를 겨냥한다:
-- PII 를 라벨 없는 릴레이션으로 물질화해버리면 순회기가 아무리 정교해도
-- 무의미해진다. 이건 walker 버그가 아니라 라벨 전파(label propagation) 문제다.
SET search_path = h5, public;

-- ── ① 구체화 뷰: 뷰가 아니라 *릴레이션*이다. 재작성 전개가 없다.
DROP MATERIALIZED VIEW IF EXISTS mv_cust CASCADE;
CREATE MATERIALIZED VIEW mv_cust AS
    SELECT id, name, ssn, grade FROM cust;

-- ── ② CTAS: PII 를 라벨 없는 새 테이블로 복사
DROP TABLE IF EXISTS ctas_cust CASCADE;
CREATE TABLE ctas_cust AS SELECT id, ssn FROM cust;

-- ── ③ 생성 컬럼: 쓰기 시점에 PII 파생값이 라벨 없는 컬럼으로 물질화된다
DROP TABLE IF EXISTS gen_t CASCADE;
CREATE TABLE gen_t (
    id      bigint,
    ssn     text,
    ssn6    text GENERATED ALWAYS AS (substr(ssn, 1, 6)) STORED,
    ssn_rev text GENERATED ALWAYS AS (reverse(ssn)) STORED
);
INSERT INTO gen_t (id, ssn) SELECT id, ssn FROM cust LIMIT 100;

-- ── ④ 라벨 없는 수취 테이블 (INSERT ... SELECT 로 PII 유출)
DROP TABLE IF EXISTS sink_t CASCADE;
CREATE TABLE sink_t (id bigint, blob text);

-- ── ⑤ RLS: 재작성 시 qual 이 붙는다. 구조가 달라진다.
DROP TABLE IF EXISTS rls_t CASCADE;
CREATE TABLE rls_t (id bigint, owner text, ssn text);
INSERT INTO rls_t VALUES (1,'me','800101-1111111'), (2,'you','800102-2222222');
ALTER TABLE rls_t ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS p_rls ON rls_t;
CREATE POLICY p_rls ON rls_t USING (owner = current_user);

-- ── ⑥ DO INSTEAD DML 룰: INSERT 가 다른 테이블로 redirect 된다
DROP TABLE IF EXISTS rule_src CASCADE;
CREATE TABLE rule_src (id bigint, x text);
CREATE RULE r_redirect AS ON INSERT TO rule_src DO INSTEAD
    INSERT INTO sink_t (id, blob) SELECT NEW.id, ssn FROM cust WHERE id = NEW.id;

-- ── ⑦ 트리거 전이 테이블 (RTE_NAMEDTUPLESTORE)
CREATE OR REPLACE FUNCTION trg_leak() RETURNS trigger
    LANGUAGE plpgsql AS $$
    BEGIN
        INSERT INTO h5.sink_t SELECT id, ssn FROM new_rows;
        RETURN NULL;
    END $$;
DROP TRIGGER IF EXISTS t_leak ON gen_t;
CREATE TRIGGER t_leak AFTER INSERT ON gen_t
    REFERENCING NEW TABLE AS new_rows
    FOR EACH STATEMENT EXECUTE FUNCTION trg_leak();

-- ── ⑧ MERGE 대상
DROP TABLE IF EXISTS merge_t CASCADE;
CREATE TABLE merge_t (id bigint PRIMARY KEY, note text);
INSERT INTO merge_t VALUES (1,'x');

-- ── ⑨ SECURITY DEFINER 함수
CREATE OR REPLACE FUNCTION f_sd(p_id bigint) RETURNS text
    LANGUAGE sql SECURITY DEFINER STABLE
    AS $$ SELECT ssn FROM h5.cust WHERE id = p_id $$;

-- ── ⑩ 탐지기 복잡도 공격용: 라벨을 많이 만든다 (label_of 가 선형 탐색)
DROP TABLE IF EXISTS wide_t CASCADE;
CREATE TABLE wide_t (id bigint, c1 text, c2 text, c3 text, c4 text, c5 text,
                     c6 text, c7 text, c8 text, c9 text, c10 text);
-- 행이 없으면 enforce off/on 비교가 EMPTY==EMPTY 가 되어 허위 누출로 잡힌다.
INSERT INTO wide_t SELECT g, 'v1','v2','v3','v4','v5','v6','v7','v8','v9','v10'
FROM generate_series(1,10) g;

-- ── 라벨: 원본에만. 물질화된 사본(mv_cust, ctas_cust, gen_t.ssn6 ...)은
--    일부러 라벨하지 않는다. 그게 이번 라운드의 요점이다.
DELETE FROM pii_label WHERE relname IN
    ('mv_cust','ctas_cust','gen_t','sink_t','rls_t','rule_src','wide_t');
INSERT INTO pii_label VALUES
    ('gen_t','ssn','ssn'),          -- 원본 컬럼만. 생성 컬럼 ssn6/ssn_rev 는 라벨 없음
    ('rls_t','ssn','ssn');
INSERT INTO pii_label SELECT 'wide_t', 'c' || g, 'ssn' FROM generate_series(1,10) g;

ANALYZE;
