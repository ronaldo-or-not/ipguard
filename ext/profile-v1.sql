-- ==================================================================
-- 인증서 profile v1 — **동결 대상**
--
-- 여기 있는 `holds` 는 전부 dossier(docs/certificate-profile-v1.md)에
-- 의미론 식·증명·반례가 적혀 있고, tools/verify_profile.py 가 probe 정의역
-- 위에서 전수 검사로 확인한다. acceptance 를 높이려고 고르지 않았다 --
-- 의미론적으로 증명 가능한 것만 넣었다.
--
-- 실 마스킹 계열은 EQ/ORD 가 **전부 fails** 다. 서로 다른 값을 합치기
-- 때문이며, 이것이 마스크의 목적이다. 따라서 게이트의 factor-through 경로를
-- 한 번이라도 실행하려면 구조를 의도적으로 공개하는 control transform 이
-- 필요하다. `ctl:` namespace 가 그것이고, **운영에 쓰면 안 된다.**
--
-- 적용: psql -d <db> -f ext/profile-v1.sql
-- 검증: python3 tools/verify_profile.py     (거짓 holds 0건이어야 한다)
-- ==================================================================
SET client_min_messages = warning;

-- ------------------------------------------------------------------
-- MaskInstance
-- ------------------------------------------------------------------
-- 실 마스킹 계열
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'text'::regtype, 'text'::regtype, 'kind=pv_text', '',
       'star mask: m(x) = repeat(''*'', char_length(x))');
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'date'::regtype, 'date'::regtype, 'kind=pv_date', '',
       'constant date mask: m(d) = 1900-01-01');
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'integer'::regtype, 'integer'::regtype, 'kind=pv_num', '',
       'nullify mask: m(n) = NULL  (ipguard.numeric_mask = 1)');

-- ★ control transform -- 보호 마스크가 아니다.
--   Structural-revealing control transform used only to exercise
--   certified factorization paths.
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'text'::regtype, 'text'::regtype, 'kind=ctl:rot13', '',
       'CONTROL ONLY -- ROT13 involution. 원문 복원 가능. 운영 금지.');
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'text'::regtype, 'text'::regtype, 'kind=ctl:prefix', '',
       'CONTROL ONLY -- m(x) = ''P:''||x. 원문을 그대로 포함한다. 운영 금지.');

-- ------------------------------------------------------------------
-- capability
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_temp.pv_caps(
        p_kind text, p_det text, p_tot text, p_nul text,
        p_eq text, p_ord text, p_assur text)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
    SELECT i.mask_id, c.cap, c.cl::ipguard_claim, p_assur::ipguard_assurance
      FROM ipguard_mask_instance i,
           (VALUES ('determinism', p_det), ('total', p_tot),
                   ('null_equivalence', p_nul),
                   ('equality_factor', p_eq), ('order_factor', p_ord))
             AS c(cap, cl)
     WHERE i.normalized_args = 'kind=' || p_kind
    ON CONFLICT (mask_id, capability)
    DO UPDATE SET claim = excluded.claim, assurance = excluded.assurance;
$$;

-- ★ assurance 는 `trusted_provider` 다. `proved_builtin` 이 아니다.
--   레지스트리 가드가 거부한다:
--     ERROR: mask_id=N 의 지문이 불완전해(c-provider) proved_builtin 을
--            주장할 수 없습니다
--   이 마스크들은 C 로 구현돼 있어 레지스트리가 구현을 완전히 지문화할 수
--   없다. 아래 dossier 의 증명은 **소스를 읽고 사람이 한 것**이고, 도구가
--   확인한 것은 probe 정의역 전수 검사뿐이다. 그 구분을 assurance 로
--   표시한다 -- 올바른 거부이므로 우회하지 않는다.
--                       kind        det    tot    null   eq     ord
SELECT pg_temp.pv_caps('pv_text',   'holds','holds','holds','fails','fails',
                       'trusted_provider');
SELECT pg_temp.pv_caps('pv_date',   'holds','holds','holds','fails','fails',
                       'trusted_provider');
-- ★ nullify 는 non-NULL 을 NULL 로 보낸다 -> null_equivalence = fails.
--   held-out v1 의 h5 registry 는 이것을 holds 로 등록했다. 거짓이다.
SELECT pg_temp.pv_caps('pv_num',    'holds','holds','fails','fails','fails',
                       'trusted_provider');
-- ★ ROT13: 전역 bijection -> EQ holds. 순서는 보존하지 않는다('a'<'b' 인데
--   rot13('a')='n' > rot13('b')='o' 는 아니지만 'z'/'m' 에서 깨진다).
SELECT pg_temp.pv_caps('ctl:rot13', 'holds','holds','holds','holds','fails',
                       'trusted_provider');
-- ★ prefix: C collation 에서 순서·동치를 **정확히** 보존한다.
--   collation 이 C 가 아니면 이 주장은 성립하지 않는다.
SELECT pg_temp.pv_caps('ctl:prefix','holds','holds','holds','holds','holds',
                       'trusted_provider');

-- ------------------------------------------------------------------
-- comparator compatibility -- ORD/EQ = NullPartitionPreserved ∧ Factors
--   앞 연언지는 null_equivalence, 뒤 연언지가 여기다. 연산자별로 건다.
-- ------------------------------------------------------------------
SELECT ipguard_register_default_comparators(mask_id,
         'fails'::ipguard_claim, 'fails'::ipguard_claim,
         'trusted_provider'::ipguard_assurance)
  FROM ipguard_mask_instance
 WHERE normalized_args IN ('kind=pv_text', 'kind=pv_date', 'kind=pv_num');
SELECT ipguard_register_default_comparators(mask_id,
         'fails'::ipguard_claim, 'holds'::ipguard_claim,
         'trusted_provider'::ipguard_assurance)
  FROM ipguard_mask_instance WHERE normalized_args = 'kind=ctl:rot13';
SELECT ipguard_register_default_comparators(mask_id,
         'holds'::ipguard_claim, 'holds'::ipguard_claim,
         'trusted_provider'::ipguard_assurance)
  FROM ipguard_mask_instance WHERE normalized_args = 'kind=ctl:prefix';

-- ------------------------------------------------------------------
-- 출력 redactor 로 쓸 MaskInstance
--   집계·함수 compatibility 의 out_redactor 는 **등록된 MaskInstance 여야**
--   한다. 등록하지 않으면 out_mask 조회가 NULL 이라 VAL 의무가 남는다.
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION h5.pv_ident_bigint(bigint) RETURNS bigint
  LANGUAGE sql IMMUTABLE STRICT AS 'SELECT $1';
CREATE OR REPLACE FUNCTION h5.pv_ident_int(integer) RETURNS integer
  LANGUAGE sql IMMUTABLE STRICT AS 'SELECT $1';
SELECT ipguard_register_mask('h5.pv_ident_bigint(bigint)'::regprocedure,
       'bigint'::regtype, 'bigint'::regtype, 'kind=pv_ident_bigint', '',
       'identity redactor -- 집계 결과를 그대로 공개한다는 명시적 선언');
SELECT ipguard_register_mask('h5.pv_ident_int(integer)'::regprocedure,
       'integer'::regtype, 'integer'::regtype, 'kind=pv_ident_int', '',
       'identity redactor');

-- ------------------------------------------------------------------
-- aggregate compatibility
--   count(x) 는 인자 **값**을 보지 않는다. 따라서 임의의 전단사 아닌
--   마스크에서도 count(m(x)) = count(x) 다 -- 단, m 이 NULL 을 새로
--   만들지 않을 때만이다(count 는 NULL 을 세지 않는다).
--   즉 **null_equivalence 가 전제**다. nullify 마스크에서는 성립하지 않는다.
--
--   count(DISTINCT x) 는 별개다. 값을 합치면 개수가 줄기 때문에
--   aggregate compatibility 와 **별도로** EQ 인증이 필요하다.
--   게이트가 aggregate DISTINCT key vector 의 EQ->CELL 의무를 따로 만든다.
-- ------------------------------------------------------------------
CREATE OR REPLACE FUNCTION pg_temp.pv_agg(p_kind text, p_dist boolean)
RETURNS void LANGUAGE sql AS $$
    INSERT INTO ipguard_mask_aggregate_compatibility
      (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name,
       agg_fingerprint, red_fingerprint, claim, assurance, evidence)
    SELECT i.mask_id, 'count("any")'::regprocedure, p_dist, false,
           'h5.pv_ident_bigint(bigint)'::regprocedure, '',
           (SELECT fingerprint FROM
              ipguard_fingerprint('count("any")'::regprocedure)),
           (SELECT fingerprint FROM
              ipguard_fingerprint('h5.pv_ident_bigint(bigint)'::regprocedure)),
           'holds'::ipguard_claim, 'trusted_provider'::ipguard_assurance,
           'count 는 인자 값을 보지 않는다. null_equivalence 가 전제.'
      FROM ipguard_mask_instance i
     WHERE i.normalized_args = 'kind=' || p_kind
    ON CONFLICT DO NOTHING;
$$;

-- null_equivalence 가 holds 인 마스크에만 건다. pv_num 은 제외한다.
SELECT pg_temp.pv_agg('pv_text', false);
SELECT pg_temp.pv_agg('pv_date', false);
SELECT pg_temp.pv_agg('ctl:rot13', false);
SELECT pg_temp.pv_agg('ctl:prefix', false);
-- DISTINCT 변형은 EQ 인증이 있는 control 에만 건다.
SELECT pg_temp.pv_agg('ctl:rot13', true);
SELECT pg_temp.pv_agg('ctl:prefix', true);

-- ------------------------------------------------------------------
-- scalar function compatibility
--   lower/upper 는 C collation·ASCII 정의역에서만 등록한다.
--   star mask 는 '*' 만 내므로 lower('*')='*' 로 자기 자신이 출력 마스크다.
--   ROT13/prefix 는 대소문자를 바꾸므로 lower 와 가환이 아니다 -- 등록하지
--   않는다(미등록 = 거부).
-- ------------------------------------------------------------------
INSERT INTO ipguard_mask_function_compatibility
  (mask_id, func, arg_signature, out_redactor, collation_name,
   func_fingerprint, red_fingerprint, claim, assurance, evidence)
SELECT i.mask_id, 'lower(text)'::regprocedure, 'pos=0',
       'ipguard_mask(anyelement,text)'::regprocedure, '',
       (SELECT fingerprint FROM ipguard_fingerprint('lower(text)'::regprocedure)),
       i.impl_fingerprint, 'holds'::ipguard_claim,
       'trusted_provider'::ipguard_assurance,
       'lower(m(x)) = m(x) = m(lower(x)) -- 출력이 ''*'' 뿐이다'
  FROM ipguard_mask_instance i
 WHERE i.normalized_args = 'kind=pv_text'
ON CONFLICT DO NOTHING;
INSERT INTO ipguard_mask_function_compatibility
  (mask_id, func, arg_signature, out_redactor, collation_name,
   func_fingerprint, red_fingerprint, claim, assurance, evidence)
SELECT i.mask_id, 'upper(text)'::regprocedure, 'pos=0',
       'ipguard_mask(anyelement,text)'::regprocedure, '',
       (SELECT fingerprint FROM ipguard_fingerprint('upper(text)'::regprocedure)),
       i.impl_fingerprint, 'holds'::ipguard_claim,
       'trusted_provider'::ipguard_assurance,
       'upper(m(x)) = m(x) = m(upper(x)) -- 출력이 ''*'' 뿐이다'
  FROM ipguard_mask_instance i
 WHERE i.normalized_args = 'kind=pv_text'
ON CONFLICT DO NOTHING;

-- ★ length(text) 는 **등록하지 않는다.**
--   star mask 가 길이를 이미 공개하므로 opacity 에는 안전하지만, fidelity 는
--   Ideal 의 출력 정책이 그 파생값을 identity-release 로 허용할 때만 맞다.
--   조용히 '라벨 아님' 으로 두면 안 된다. v1 은 그 정책을 정의하지 않았으므로
--   미등록 = 거부로 둔다.
-- ★ substr(text,int,int) 도 등록하지 않는다.
--   count < 0 에서 오류를 내므로 임의 인자 전체에서 total 이 아니다.
--   v1 은 precondition = ⊤ 만 지원한다.
