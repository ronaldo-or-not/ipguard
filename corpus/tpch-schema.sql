-- TPC-H 스키마 (표준 DDL). 실제 워크로드 거부율 측정용.
--
-- 왜 TPC-H 인가: 지금까지의 코퍼스는 전부 내가 쓴 것이라 편향돼 있다.
-- TPC-H 22개 쿼리는 표준화 기구가 만든 것이고, 서브쿼리/CTE/상관 서브쿼리가
-- 밀집해 있어 artifact 패턴(서브쿼리 출력을 술어가 참조)에 가장 가혹하다.
--
-- 한계(반드시 같이 보고할 것): TPC-H 는 분석계 워크로드이고 이 프로젝트의
-- 타겟은 마이데이터/OpenAPI 거래계다. 분석계가 서브쿼리를 훨씬 많이 쓰므로
-- **거부율의 상한**으로 읽어야지 타겟 도메인의 값으로 읽으면 안 된다.
--
-- 거부는 계획 시점에 일어나므로 EXPLAIN 만으로 측정된다 -> 데이터 불필요.

DROP SCHEMA IF EXISTS tpch CASCADE;
CREATE SCHEMA tpch;
SET search_path = tpch, public;

CREATE TABLE region  (r_regionkey int PRIMARY KEY, r_name char(25),
                      r_comment varchar(152));
CREATE TABLE nation  (n_nationkey int PRIMARY KEY, n_name char(25),
                      n_regionkey int, n_comment varchar(152));
CREATE TABLE part    (p_partkey int PRIMARY KEY, p_name varchar(55),
                      p_mfgr char(25), p_brand char(10), p_type varchar(25),
                      p_size int, p_container char(10), p_retailprice numeric,
                      p_comment varchar(23));
CREATE TABLE supplier(s_suppkey int PRIMARY KEY, s_name char(25),
                      s_address varchar(40), s_nationkey int, s_phone char(15),
                      s_acctbal numeric, s_comment varchar(101));
CREATE TABLE partsupp(ps_partkey int, ps_suppkey int, ps_availqty int,
                      ps_supplycost numeric, ps_comment varchar(199),
                      PRIMARY KEY (ps_partkey, ps_suppkey));
CREATE TABLE customer(c_custkey int PRIMARY KEY, c_name varchar(25),
                      c_address varchar(40), c_nationkey int, c_phone char(15),
                      c_acctbal numeric, c_mktsegment char(10),
                      c_comment varchar(117));
CREATE TABLE orders  (o_orderkey int PRIMARY KEY, o_custkey int,
                      o_orderstatus char(1), o_totalprice numeric,
                      o_orderdate date, o_orderpriority char(15),
                      o_clerk char(15), o_shippriority int,
                      o_comment varchar(79));
CREATE TABLE lineitem(l_orderkey int, l_partkey int, l_suppkey int,
                      l_linenumber int, l_quantity numeric,
                      l_extendedprice numeric, l_discount numeric,
                      l_tax numeric, l_returnflag char(1), l_linestatus char(1),
                      l_shipdate date, l_commitdate date, l_receiptdate date,
                      l_shipinstruct char(25), l_shipmode char(10),
                      l_comment varchar(44),
                      PRIMARY KEY (l_orderkey, l_linenumber));

-- PII 라벨: 자연인/사업자 식별정보에 해당하는 컬럼.
-- 마이데이터 스키마의 성명·주소·전화번호·계좌잔액에 대응시킨다.
CREATE TABLE pii_label (relname name, attname name, kind text,
                        PRIMARY KEY (relname, attname));
INSERT INTO pii_label VALUES
    ('customer','c_name','name'),
    ('customer','c_address','addr'),
    ('customer','c_phone','phone'),
    ('customer','c_acctbal','acct'),
    ('supplier','s_name','name'),
    ('supplier','s_address','addr'),
    ('supplier','s_phone','phone'),
    ('supplier','s_acctbal','acct');

ANALYZE;

-- Q15 가 참조하는 뷰
CREATE VIEW revenue0 (supplier_no, total_revenue) AS
  SELECT l_suppkey, sum(l_extendedprice * (1 - l_discount))
    FROM lineitem
   WHERE l_shipdate >= date '1996-01-01'
     AND l_shipdate < date '1996-01-01' + interval '3 month'
   GROUP BY l_suppkey;
