-- H5 측정용 테스트 스키마.
-- PII 컬럼은 이름으로 자명하게 구분되도록 지었다 (분류기가 이름을 보고
-- 맞히는 부정행위를 막기 위해, 분류기는 반드시 카탈로그 라벨을 쓰고
-- 컬럼명 휴리스틱을 쓰지 말 것 — 채점 스크립트가 이를 검사한다).

DROP SCHEMA IF EXISTS h5 CASCADE;
CREATE SCHEMA h5;
SET search_path = h5, public;

CREATE TABLE cust (
    id          bigint PRIMARY KEY,
    ci          text NOT NULL,      -- PII 연계정보 (파라미터 결속 키)
    name        text NOT NULL,      -- PII 성명 (한글, UTF-8 3바이트/음절)
    ssn         text NOT NULL,      -- PII 주민등록번호 '######-#######'
    phone       text NOT NULL,      -- PII 전화번호
    addr        text,               -- PII 주소 (한글, 가변 길이)
    birth       date NOT NULL,      -- PII 생년월일 (바이너리 전송 대상)
    acct_no     text NOT NULL,      -- PII 계좌번호
    grade       text,               -- non-PII 등급
    balance     numeric(18,2),      -- non-PII 잔액
    memo        text,               -- non-PII 이지만 자유텍스트 (오탐 유도용)
    created_at  timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE tx (
    id          bigint PRIMARY KEY,
    cust_id     bigint NOT NULL REFERENCES cust(id),
    amount      numeric(18,2) NOT NULL,
    memo        text,
    occurred_at timestamptz NOT NULL
);

-- 뷰: 와이어의 resorigtbl은 base table이 아니라 뷰의 OID를 준다
CREATE VIEW v_cust AS SELECT * FROM cust;
CREATE VIEW v_cust_safe AS SELECT id, grade, balance FROM cust;

-- UDF: 내부에서 PII를 읽지만 호출부 AST에는 인자만 보인다 (예상 FN)
CREATE FUNCTION f_ssn(p_id bigint) RETURNS text
    LANGUAGE sql STABLE AS $$ SELECT ssn FROM h5.cust WHERE id = p_id $$;

CREATE FUNCTION f_srf() RETURNS SETOF cust
    LANGUAGE sql STABLE AS $$ SELECT * FROM h5.cust $$;

-- 동적 SQL: 계획 시점에 아무것도 알 수 없다 (예상 FN)
CREATE FUNCTION f_dyn(p_col text) RETURNS SETOF text
    LANGUAGE plpgsql STABLE AS $$
    BEGIN
        RETURN QUERY EXECUTE format('SELECT %I::text FROM h5.cust', p_col);
    END $$;

-- 시드 데이터: 한글 마스킹과 인코딩 경로를 실제로 태우기 위한 값
INSERT INTO cust (id, ci, name, ssn, phone, addr, birth, acct_no, grade, balance, memo)
SELECT g,
       repeat('A', 88),
       (ARRAY['홍길동','김철수','이영희','박민준','최서연'])[1 + g % 5],
       lpad((800101 + g % 100)::text, 6, '0') || '-' || lpad((1000000 + g)::text, 7, '0'),
       '010-' || lpad((1000 + g % 9000)::text, 4, '0') || '-' || lpad((g % 10000)::text, 4, '0'),
       '서울특별시 동작구 흑석로 ' || (g % 200 + 1) || '길 ' || (g % 50 + 1),
       DATE '1980-01-01' + (g % 10000),
       '110-' || lpad((g % 1000)::text, 3, '0') || '-' || lpad((g % 1000000)::text, 6, '0'),
       (ARRAY['A','B','C'])[1 + g % 3],
       (g * 1237 % 100000)::numeric / 100,
       CASE WHEN g % 97 = 0
            -- 오탐 유도: non-PII 자유텍스트 안에 주민번호 형태의 문자열
            THEN '고객 문의 접수. 본인확인 800101-1234567 대조 완료.'
            ELSE '일반 문의' END
FROM generate_series(1, 10000) g;

INSERT INTO tx (id, cust_id, amount, memo, occurred_at)
SELECT g, 1 + g % 10000, (g % 50000)::numeric / 100, 'tx ' || g,
       now() - (g || ' minutes')::interval
FROM generate_series(1, 50000) g;

CREATE INDEX ON cust (ci);
CREATE INDEX ON tx (cust_id);
ANALYZE;

-- 분류 라벨. 분류기는 반드시 이 테이블만 근거로 삼아야 하며
-- 컬럼명 패턴 매칭을 쓰면 안 된다.
CREATE TABLE pii_label (
    relname  name NOT NULL,
    attname  name NOT NULL,
    kind     text NOT NULL,   -- ci | name | ssn | phone | addr | birth | acct
    PRIMARY KEY (relname, attname)
);
INSERT INTO pii_label VALUES
    ('cust','ci','ci'), ('cust','name','name'), ('cust','ssn','ssn'),
    ('cust','phone','phone'), ('cust','addr','addr'),
    ('cust','birth','birth'), ('cust','acct_no','acct');
