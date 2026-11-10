#!/usr/bin/env python3
"""release-factorization gate 판정 행 (명세 v0.2.1 §11-4).

게이트의 핵심은 boolean lineage 가 아니라 **경로**다:

    source -> effect -> observable sink

경로가 없으면 수락한다(Q10). 있으면 그 effect 가 release 를 factor through
한다는 인증서나, 정확한 (effect, sink) declassification 이 있어야 한다.

★ effect 노드는 **hyperedge** 다. EQ 와 ORD 는 여러 입력이 함께 의미를
  결정하므로 key vector 전체를 문맥으로 들고 다닌다. source 별 boolean
  전파로 만들면 다시 per-column order_embedding 으로 퇴행한다.

판정 행:

  Q10  ORD 있으나 관찰 가능한 행 구별 없음                  수락
  Q9   ORD -> FINAL_ORDER(공개 id)                        거부
  Q6   ORD -> MEMBERSHIP(공개 id) + FINAL_ORDER            거부
  Q6'  ORD -> 전순서지만 row identity 가 투영에서 사라짐     수락  ★ 새 대조군
  Q9   전순서 보존 마스크(order_factor=holds)               수락
  Q9   최종 순서만 declassify                              수락
  Q6   순서만 declassify, membership 미허가                 거부
  any  인증서 unknown                                      거부

사용: python3 tools/score_gate.py
"""
import subprocess
import sys

SETUP = r"""
SET client_min_messages = warning;
DROP TABLE IF EXISTS h5.g_t;
CREATE TABLE h5.g_t (id int PRIMARY KEY, secret text, grade text);
INSERT INTO h5.g_t VALUES
  (1,'f','A'),(2,'e','A'),(3,'d','B'),(4,'c','B'),(5,'b','C'),(6,'a','C');
DELETE FROM h5.pii_label WHERE relname = 'g_t';
INSERT INTO h5.pii_label VALUES ('g_t','secret','gsec');

DELETE FROM ipguard_declassification
 WHERE relid = 'h5.g_t'::regclass;
DELETE FROM ipguard_mask_instance WHERE normalized_args = 'kind=gsec';
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'text'::regtype, 'text'::regtype, 'kind=gsec', '', '상수 마스크');
-- ★ 이 시험은 자기 전제를 스스로 세운다. 예전에는 score_registry.py 가
--   먼저 돌아 트리거를 깔아 준 덕에 초록이었고, 그래서 실제 제품 결함
--   (CREATE EXTENSION 이 ipguard_watch_registry() 를 부르지 않음)을
--   'flaky 테스트' 로 오해했다.
SELECT ipguard_watch_registry();
SELECT ipguard_watch_labels('h5.pii_label'::regclass);
"""

TEARDOWN = r"""
SET client_min_messages = warning;
DROP TABLE IF EXISTS h5.g_t;
DROP FUNCTION IF EXISTS h5.g_ident(bigint);
DELETE FROM h5.pii_label WHERE relname = 'g_t';
DELETE FROM ipguard_mask_instance WHERE normalized_args = 'kind=gsec';
"""

# capability 를 통째로 다시 세운다. 앞 케이스의 부작용에 기대면 순서를 바꾸는
# 순간 조용히 틀린다 -- 레지스트리 회귀에서 이미 한 번 당했다.
def set_caps(order_factor, equality_factor="fails"):
    return f"""
    DELETE FROM ipguard_mask_capability
     WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                        WHERE normalized_args = 'kind=gsec');
    INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
    SELECT m.mask_id, c.cap, c.cl::ipguard_claim,
           CASE WHEN c.cl = 'unknown' THEN 'unknown'
                ELSE 'trusted_provider' END::ipguard_assurance
      FROM ipguard_mask_instance m, (VALUES
        ('determinism','holds'), ('null_equivalence','holds'),
        ('total','holds'),
        ('order_factor','{order_factor}'),
        ('equality_factor','{equality_factor}')
      ) c(cap, cl)
     WHERE m.normalized_args = 'kind=gsec';
    -- ★ comparator 인증서도 같이 세운다. ORD/EQ 는
    --   NullPartitionPreserved ∧ ComparatorFactors 이므로 둘 다 있어야 한다.
    DELETE FROM ipguard_mask_comparator_compatibility
     WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                        WHERE normalized_args = 'kind=gsec');
    -- ★ claim 과 assurance 를 **명시**한다. 기본값이 없다 -- "btree 기본
    --   연산자니까 holds" 를 자동으로 만들면 안 되기 때문이다.
    SELECT ipguard_register_default_comparators(mask_id,
             '{order_factor}'::ipguard_claim, '{equality_factor}'::ipguard_claim,
             CASE WHEN '{order_factor}'='unknown' AND '{equality_factor}'='unknown'
                  THEN 'unknown' ELSE 'trusted_assumption' END::ipguard_assurance)
      FROM ipguard_mask_instance WHERE normalized_args = 'kind=gsec';
    """


def context_key_of(sql, effect, sink):
    """게이트가 **실제로 보는** context_key 를 읽어온다.

    ★ 손으로 만들면 안 된다. 정책이 허가한 문맥과 게이트가 판정하는 문맥이
      어긋나면, 인증서가 있는데 거부되거나(운영 사고) 없는데 수락된다(누출).
    """
    r = psql(f"""SELECT context_key || E'\t' || context_canonical
                   FROM ipguard_obligations($ipg${sql}$ipg$)
                  WHERE effect='{effect}' AND sink='{sink}' LIMIT 1;""", PRELUDE)
    out = [l for l in r.stdout.splitlines() if l.strip() and "\t" in l]
    if not out:
        return "", ""
    k, _, c = out[-1].partition("\t")
    return k.strip(), c


def declass(effect, sink, observation, sql=None, param_scope='none'):
    """(source, effect, context, sink, observation) 5-튜플 인증서.

    context_key 를 게이트에서 읽어 그대로 넣는다.
    """
    key, canon = context_key_of(sql, effect, sink) if sql else ("", "")
    canon = canon.replace("'", "''")
    return f"""
    INSERT INTO ipguard_declassification
      (relid, attnum, effect, sink, context_key, context_canonical,
       param_scope, observation, rationale)
    SELECT 'h5.g_t'::regclass, a.attnum, '{effect}', '{sink}',
           '{key}', '{canon}', '{param_scope}', '{observation}', '판정 행 시험'
      FROM pg_attribute a
     WHERE a.attrelid = 'h5.g_t'::regclass AND a.attname = 'secret'
    ON CONFLICT DO NOTHING;
    """


CLEAR_DECLASS = "DELETE FROM ipguard_declassification WHERE relid='h5.g_t'::regclass;"


def declass_all(effect, observation, sql, param_scope='none'):
    """그 effect 의 **활성 sink 전부**에 인증서를 발급한다.

    ★ CARD 는 ROW_COUNT 하나가 아니다 -- MULTIPLICITY 와 (행 구별이 살아
      있으면) MEMBERSHIP 까지 만든다. 하나만 발급하면 나머지가 남아 거부된다.
      그게 올바른 동작이고, 정책은 활성 sink 를 **명시적으로** 다 허가해야 한다.
    """
    r = psql(f"SELECT 'SINK:'||sink FROM ipguard_obligations($ipg${sql}$ipg$) "
             f"WHERE effect='{effect}';", PRELUDE)
    out = ""
    for l in r.stdout.splitlines():
        if l.startswith("SINK:"):
            out += declass(effect, l.strip()[5:], observation, sql, param_scope)
    return out

PRELUDE = ("SET search_path = h5, public;\n"
           "SET ipguard.enforce = on;\n"
           "SET ipguard.gate = release;\n"
           "SET ipguard.on_divergence = allow;\n")


def psql(script, prelude=""):
    return subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                          input=prelude + script, capture_output=True, text=True)


def verdict(sql):
    """게이트가 이 질의를 수락하는가.

    $1 이 있으면 PREPARE/EXECUTE 로 돌린다 -- 계획기가 Param 을 보는 경로가
    그쪽이고, 그게 실제 운영(prepared statement) 형태다.
    """
    if "$1" in sql:
        body = (f"PREPARE vq AS {sql};\nEXECUTE vq('x');\nDEALLOCATE vq;")
        r = psql(body, PRELUDE)
    else:
        r = psql(sql + ";", PRELUDE)
    if "ipguard: 해소되지 않은 의무" in r.stderr:
        return "reject"
    if "ERROR" in r.stderr:
        line = [l for l in r.stderr.splitlines() if "ERROR" in l][0]
        return "ERR:" + line[-45:]
    return "accept"


def one(sql):
    r = psql(f"SELECT 'V:'||({sql});", PRELUDE)
    v = [l[2:] for l in r.stdout.splitlines() if l.startswith("V:")]
    return v[-1] if v else ""


def obligations(sql):
    r = psql(f"SELECT effect||'->'||sink||'['||discharge||']' "
             f"FROM ipguard_obligations($ipg${sql}$ipg$);", PRELUDE)
    return [l for l in r.stdout.splitlines() if l.strip() and "->" in l]


RESULTS = []

Q9 = "SELECT id FROM h5.g_t ORDER BY secret, id"
Q6 = "SELECT id FROM h5.g_t ORDER BY secret, id LIMIT 3"
Q10 = "SELECT 'x' FROM h5.g_t ORDER BY secret"
Q6P = "SELECT 'x' FROM h5.g_t ORDER BY secret, id LIMIT 3"


def check(name, sql, want, note=""):
    got = verdict(sql)
    ok = got == want
    RESULTS.append((name, got, want, ok))
    print(f"  {'✓' if ok else '✗'} {name:52} {got:<8} (기대 {want})")
    if note:
        print(f"      {note}")
    if not ok:
        for o in obligations(sql):
            print(f"      의무: {o}")
    return ok


class Session:
    """살아 있는 psql 백엔드 하나."""

    def __init__(self):
        self.p = subprocess.Popen(["psql", "-d", "ipdev", "-At", "-q"],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True, bufsize=1)

    def run(self, sql):
        self.p.stdin.write(sql.rstrip().rstrip(";") + ";\n")
        self.p.stdin.write("SELECT '###END###';\n")
        self.p.stdin.flush()
        out = []
        while True:
            line = self.p.stdout.readline()
            if not line or "###END###" in line:
                break
            if line.strip():
                out.append(line.strip())
        return out

    def val(self, sql):
        v = self.run(sql)
        return v[-1] if v else ""

    def close(self):
        try:
            self.p.stdin.write("\\q\n")
            self.p.stdin.flush()
            self.p.wait(timeout=5)
        except Exception:
            self.p.kill()


def obl_set(sql):
    """(effect, sink, context 종류) 집합. 순서·중복에 의존하지 않는다."""
    r = psql(f"SELECT 'O:'||effect||'|'||sink||'|'||split_part(context,' [',1) "
             f"FROM ipguard_obligations($ipg${sql}$ipg$);", PRELUDE)
    return sorted({l[2:] for l in r.stdout.splitlines() if l.startswith("O:")})


def check_obl(name, sql, want, note=""):
    got = obl_set(sql)
    ok = got == sorted(want)
    RESULTS.append((name, "obl", "obl", ok))
    print(f"  {'✓' if ok else '✗'} {name:52} {len(got)}건")
    if note:
        print(f"      {note}")
    if not ok:
        print(f"      기대: {sorted(want)}")
        print(f"      실제: {got}")
    return ok


def check_reason(name, sql, want_code, note=""):
    """거부 **사유 코드**를 본다. 세 코드가 섞이면 보고 분모가 무너진다."""
    r = psql(sql + ";", PRELUDE)
    txt = r.stderr
    got = ("accept" if "ERROR" not in txt else
           next((c for c in ("OUTSIDE_CERTIFIED_FRAGMENT", "UNMODELED_EXPR",
                             "CAPABILITY_FAILS", "MISSING_CERTIFICATE")
                 if c in txt), "?"))
    ok = got == want_code
    RESULTS.append((name, got, want_code, ok))
    print(f"  {'✓' if ok else '✗'} {name:52} {got:<26} (기대 {want_code})")
    if note:
        print(f"      {note}")
    return ok


AGG_SETUP = r"""
SET client_min_messages = warning;
DELETE FROM ipguard_mask_aggregate_compatibility
 WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                    WHERE normalized_args = 'kind=gsec');
-- count 는 값을 보지 않으므로 출력 redactor 는 항등이다. 그래도 **명시**한다.
CREATE OR REPLACE FUNCTION h5.g_ident(bigint) RETURNS bigint
  LANGUAGE sql IMMUTABLE STRICT AS 'SELECT $1';
-- ★ out_redactor 는 **등록된 MaskInstance 여야** 한다. 등록하지 않으면
--   ipguard_aggregate_out_mask 가 NULL 을 돌려주고 VAL 의무가 남는다.
DELETE FROM ipguard_mask_instance WHERE normalized_args = 'kind=gident';
SELECT ipguard_register_mask('h5.g_ident(bigint)'::regprocedure,
       'bigint'::regtype, 'bigint'::regtype, 'kind=gident', '',
       'count 출력 항등 redactor');
"""


def agg_compat(dist, ordered):
    """count(any) 에 대한 aggregate compatibility 인증서."""
    return f"""
    INSERT INTO ipguard_mask_aggregate_compatibility
      (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name,
       agg_fingerprint, red_fingerprint, claim, assurance, evidence)
    SELECT m.mask_id, 'count("any")'::regprocedure, {dist}, {ordered},
           'h5.g_ident(bigint)'::regprocedure, '',
           (SELECT fingerprint FROM ipguard_fingerprint('count("any")'::regprocedure)),
           (SELECT fingerprint FROM ipguard_fingerprint('h5.g_ident(bigint)'::regprocedure)),
           'holds'::ipguard_claim, 'trusted_provider'::ipguard_assurance,
           'Aggref transfer 회귀'
      FROM ipguard_mask_instance m
     WHERE m.normalized_args = 'kind=gsec'
    ON CONFLICT DO NOTHING;
    """


def group_aggref():
    """★ Aggref transfer table 을 통째로 닫는다.

    held-out v1 에서 `Aggref.args` 가 TargetEntry 로 감싸여 있다는 사실을
    놓쳐 집계 경로 전체가 default 분기(UNMODELED_EXPR)로 떨어졌다. 라벨
    집계 50건이 전부 거기 걸렸고, 그 결과 `aggdistinct` 의 EQ 의무가
    **한 번도 생성되지 않은 채** '건전성 영향 없음' 으로 보고됐다.
    registry 가 비어 우연히 fail-closed 였을 뿐이다.

      Aggref 구성            의무
      ------------------    -----------------------------------
      일반 argument          VAL -> CELL + aggregate compatibility
      aggdistinct           key vector 의 EQ -> CELL
      aggorder              key vector 의 ORD -> CELL
      aggfilter             CARD -> CELL
      count(*)              argument VAL 없음
      ordered/hypothetical  F_core 밖 -> fail-closed
    """
    print("\n[6] ★ Aggref transfer table")
    psql(AGG_SETUP + set_caps("fails", "fails") + CLEAR_DECLASS)

    check_obl("     count(*) -> 의무 없음",
              "SELECT count(*) FROM h5.g_t", [],
              "argument 가 없으므로 VAL source 도 없다")
    check_obl("     count(secret) -> VAL/CELL 만",
              "SELECT count(secret) FROM h5.g_t",
              ["VAL|CELL|aggregate"])
    check_obl("★    count(DISTINCT secret) -> EQ/CELL 추가",
              "SELECT count(DISTINCT secret) FROM h5.g_t",
              ["EQ|CELL|aggregate DISTINCT key vector",
               "VAL|CELL|aggregate"],
              "마스킹된 컬럼 위의 등가 기반 중복제거 -- 질의 수준 DISTINCT 와 같은 의무")
    check_obl("★    string_agg(... ORDER BY secret) -> ORD/CELL 추가",
              "SELECT string_agg(grade, ',' ORDER BY secret) FROM h5.g_t",
              ["ORD|CELL|aggregate ORDER BY key vector",
               "VAL|CELL|aggregate"],
              "집계 입력 순서가 셀 값으로 나간다")
    check_obl("     count(*) FILTER (WHERE secret=..) -> CARD/CELL",
              "SELECT count(*) FILTER (WHERE secret = 'a') FROM h5.g_t",
              ["CARD|CELL|aggregate FILTER"])
    check_obl("     비민감 집계는 의무 없음",
              "SELECT count(DISTINCT grade) FROM h5.g_t", [])

    print("\n[6b] ★ 사유 코드가 셋으로 갈리는가")
    check_reason("     ordered-set aggregate -> F_core 밖",
                 "SELECT mode() WITHIN GROUP (ORDER BY secret)"
                 " FROM h5.g_t", "OUTSIDE_CERTIFIED_FRAGMENT",
                 "percentile_cont 은 text 를 못 받는다 -- mode() 로 본다")
    check_reason("     equality_factor=fails -> 명시적 실패",
                 "SELECT count(DISTINCT secret) FROM h5.g_t",
                 "CAPABILITY_FAILS",
                 "인증서가 있고 그것이 fails 라고 말한다")
    psql(set_caps("holds", "holds") + CLEAR_DECLASS)
    check_reason("     capability 는 holds 인데 집계 인증서 없음",
                 "SELECT count(DISTINCT secret) FROM h5.g_t",
                 "MISSING_CERTIFICATE",
                 "★ 같은 질의가 registry 상태에 따라 다른 코드를 낸다")

    print("\n[6c] ★ EQ 와 aggregate compatibility 는 **둘 다** 필요하다")
    psql(agg_compat("true", "false"))
    check("     EQ holds + 집계 인증서 -> 수락",
          "SELECT count(DISTINCT secret) FROM h5.g_t", "accept")
    psql(set_caps("holds", "fails"))
    check("★    집계 인증서가 있어도 EQ 가 fails 면 거부",
          "SELECT count(DISTINCT secret) FROM h5.g_t", "reject",
          "aggregate compatibility 가 EQ factor-through 를 대신하지 않는다")
    psql(set_caps("holds", "holds") + AGG_SETUP)
    check("★    EQ 가 holds 여도 집계 인증서가 없으면 거부",
          "SELECT count(DISTINCT secret) FROM h5.g_t", "reject",
          "역방향 대조군 -- 두 인증서는 서로를 대신하지 않는다")

    print("\n[6d] ★ 문맥 격리 -- 질의 수준 EQ 인증서가 집계 DISTINCT 를 덮지 않는다")
    psql(set_caps("fails", "fails") + CLEAR_DECLASS + agg_compat("true", "false"))
    psql(declass_all("EQ", "group-membership",
                     "SELECT DISTINCT secret FROM h5.g_t"))
    check("     질의 수준 DISTINCT 는 수락",
          "SELECT DISTINCT secret FROM h5.g_t", "accept")
    check("★    같은 컬럼·같은 effect 라도 집계 DISTINCT 는 거부",
          "SELECT count(DISTINCT secret) FROM h5.g_t", "reject",
          "context_key 가 다르다 -- 별도 허가가 필요하다")
    psql(AGG_SETUP + set_caps("fails", "fails") + CLEAR_DECLASS)


def group_failclosed():
    """★ 미구현 경로가 **수락으로 빠지지 않는가.**

    노드를 안 만들면 "sink 없음" 으로 오인되어 수락된다. 그건 과거부가 아니라
    **미탐**이다. 판정 행만 맞추면 "의도한 것만 되는 게이트" 이고, 이 군이
    있어야 gate regression suite 가 된다.
    """
    print("\n[0] ★ fail-closed — 미구현·미인증 경로가 수락으로 빠지는가")
    psql(set_caps("holds", "holds") + CLEAR_DECLASS)   # 가장 관대한 상태

    # F_core 밖: window function 은 명세 §12 가 인증 대상에서 뺐다.
    # effect 코드는 있지만 release-certified 모드에서 수락하면 명세와 충돌한다.
    check("F_core 밖: window function",
          "SELECT id, row_number() OVER (ORDER BY secret) FROM h5.g_t",
          "reject", "OUTSIDE_CERTIFIED_FRAGMENT — 인증 대상이 아니다")
    check("F_core 밖: outer join",
          "SELECT a.id FROM h5.g_t a LEFT JOIN h5.g_t b ON b.id = a.id "
          "ORDER BY a.secret", "reject")
    check("F_core 밖: NOT IN",
          "SELECT id FROM h5.g_t WHERE secret NOT IN (SELECT secret FROM h5.g_t)",
          "reject")
    check("F_core 밖: 상관 스칼라 서브쿼리",
          "SELECT id FROM h5.g_t WHERE secret = (SELECT max(secret) FROM h5.g_t)",
          "reject")

    # ★ 전체 traversal 을 먼저 돌리므로, **라벨 미접촉 질의까지 fragment
    #   제한을 받으면 안 된다.** 순서가 이래야 한다:
    #     traverse -> 라벨 미접촉이면 수락 -> F_core 밖이면 거부
    #     -> 미모델링이면 거부 -> 의무 해소
    check("라벨 미접촉 + F_core 밖 (window) -> 수락",
          "SELECT id, row_number() OVER (ORDER BY id) FROM h5.g_t", "accept",
          "PII 와 무관한 질의까지 거부하면 DB 가 멈춘다")
    check("라벨 미접촉 + outer join -> 수락",
          "SELECT a.id FROM h5.g_t a LEFT JOIN h5.g_t b ON b.id = a.id",
          "accept")
    check("★ 민감 접촉 + window -> OUTSIDE_CERTIFIED_FRAGMENT",
          "SELECT id, row_number() OVER (ORDER BY secret) FROM h5.g_t",
          "reject")

    # ★ 집합연산 -- 노드가 없으면 조용히 수락된다(legacy R1 이 잡던 경로).
    #   equality_factor=holds 인 상태에서도 EXCEPT/INTERSECT 는 EQ 의무를
    #   만들어야 하고, holds 면 해소돼야 한다. fails 로 바꾸면 거부여야 한다.
    U = "SELECT secret FROM h5.g_t UNION SELECT secret FROM h5.g_t"
    X = "SELECT secret FROM h5.g_t EXCEPT SELECT secret FROM h5.g_t"
    I = "SELECT secret FROM h5.g_t INTERSECT SELECT secret FROM h5.g_t"
    UA = "SELECT secret FROM h5.g_t UNION ALL SELECT secret FROM h5.g_t"
    check("집합연산 UNION(비-ALL), equality_factor=holds", U, "accept")
    check("집합연산 UNION ALL (값 비교 없음)", UA, "accept")
    psql(set_caps("holds", "fails"))
    check("★ UNION(비-ALL), equality_factor=fails", U, "reject",
          "노드를 안 만들면 여기서 조용히 수락된다 = 미탐")
    check("★ EXCEPT, equality_factor=fails", X, "reject")
    check("★ INTERSECT, equality_factor=fails", I, "reject")
    check("UNION ALL 은 여전히 수락 (값 비교를 하지 않는다)", UA, "accept")
    # 중첩 집합연산 -- 3R 누출과 같은 구조
    check("★ 중첩 집합연산 (서브쿼리 안)",
          "SELECT * FROM (SELECT secret FROM h5.g_t "
          "EXCEPT SELECT secret FROM h5.g_t) z", "reject")

    # ★ key term 이 hyperedge 문맥을 실제로 보존하는가.
    #
    #   order_factor(m) 은  cmp(x,y) = cmp(m(x),m(y))  이지
    #   cmp(lower(x),lower(y)) = cmp(lower(m(x)),lower(m(y)))  가 아니다.
    #   컬럼 집합으로 축약하면 둘을 구별 못 해 function compatibility 를
    #   우회한다. collation 도 같다 -- 등록된 collation 에서만 증명된 주장이다.
    print("      ── key term 문맥 (파생 표현식 · collation) ──")
    psql(set_caps("holds", "holds"))
    check("bare Var + 기본 collation (기준선)", Q9, "accept")
    check("★ 파생 표현식 ORDER BY lower(secret)",
          "SELECT id FROM h5.g_t ORDER BY lower(secret), id", "reject",
          "order_factor 는 컬럼에 대한 주장이지 그 위의 함수에 대한 주장이 아니다")
    check("★ ORDER BY secret COLLATE \"C\"",
          'SELECT id FROM h5.g_t ORDER BY secret COLLATE "C", id', "reject")
    check("★ 파생 표현식 GROUP BY upper(secret)",
          "SELECT upper(secret), count(*) FROM h5.g_t GROUP BY upper(secret)",
          "reject")
    # 컬럼 자체가 비기본 collation 인 경우 -- bare Var 지만 인증서가 다르다
    psql("""ALTER TABLE h5.g_t ADD COLUMN IF NOT EXISTS csec text COLLATE "C";
            UPDATE h5.g_t SET csec = secret;
            DELETE FROM h5.pii_label WHERE relname='g_t' AND attname='csec';
            INSERT INTO h5.pii_label VALUES ('g_t','csec','gsec');""")
    check("★ bare Var 지만 컬럼이 COLLATE \"C\" 로 선언됨",
          "SELECT id FROM h5.g_t ORDER BY csec, id", "reject",
          "인스턴스가 기본 collation 으로만 등록돼 있다")
    psql("""DELETE FROM h5.pii_label WHERE relname='g_t' AND attname='csec';
            ALTER TABLE h5.g_t DROP COLUMN IF EXISTS csec;""")

    # ★ EQ/ORD 는 null_equivalence 를 **함께** 요구한다.
    #
    #   ORDER BY 는 NULL 을 cmp 로 놓지 않고 NULLS FIRST/LAST 로 놓는다.
    #   마스크가 non-NULL 을 NULL 로 바꾸면 그 행이 통째로 점프한다 --
    #   order_factor(cmp 에 대한 주장)가 이걸 덮지 못한다.
    #   GROUP BY 도 NULL 들을 한 그룹으로 묶으므로 같은 문제다.
    #   관리자가 order_factor=holds 와 null_equivalence=fails 를 동시에
    #   선언할 수 있으므로(그 자체로 모순) 조회 시점에 막아야 한다.
    print("      ── EQ/ORD 의 null_equivalence 전제 ──")
    psql("""DELETE FROM ipguard_mask_capability
             WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                WHERE normalized_args='kind=gsec');
            INSERT INTO ipguard_mask_capability(mask_id,capability,claim,assurance)
            SELECT m.mask_id, c.cap, c.cl::ipguard_claim, 'trusted_provider'
              FROM ipguard_mask_instance m, (VALUES
                ('order_factor','holds'), ('equality_factor','holds'),
                ('null_equivalence','fails'), ('determinism','holds'),
                ('total','holds')) c(cap,cl)
             WHERE m.normalized_args='kind=gsec';""")
    check("★ order_factor=holds 인데 null_equivalence=fails: ORDER BY",
          "SELECT id FROM h5.g_t ORDER BY secret NULLS LAST, id", "reject",
          "NULL 은 cmp 가 아니라 NULLS FIRST/LAST 로 놓인다")
    check("★ 같은 상태에서 GROUP BY",
          "SELECT secret, count(*) FROM h5.g_t GROUP BY secret", "reject",
          "SQL grouping 은 NULL 들을 한 그룹으로 묶는다")
    psql(set_caps("holds", "holds"))
    check("   null_equivalence=holds 로 되돌리면 수락", Q9, "accept")

    # ★ comparator 인증서 — order_factor 는 **어느 연산자에 대한** 주장인가.
    #
    #   ORD = NullPartitionPreserved ∧ ComparatorFactors
    #   EQ  = NullPartitionPreserved ∧ EqualityFactors
    #
    # 같은 마스크가 표준 `<` 에는 factor-through 해도 사용자 정의 역순
    # 연산자에는 아닐 수 있다. 미등록 comparator 는 unknown -> reject.
    print("      ── comparator 인증서 (sortop / eqop) ──")
    psql(set_caps("holds", "holds"))
    check("기본 sortop 인증됨", Q9, "accept")
    psql("""DELETE FROM ipguard_mask_comparator_compatibility
             WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                WHERE normalized_args='kind=gsec')
               AND kind='ORD';""")
    check("★ ORD comparator 인증서를 지우면", Q9, "reject",
          "order_factor 만으로는 부족하다")
    psql("""DELETE FROM ipguard_mask_comparator_compatibility
             WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                WHERE normalized_args='kind=gsec')
               AND kind='EQ';""")
    check("★ EQ comparator 인증서를 지우면 DISTINCT",
          "SELECT DISTINCT secret FROM h5.g_t", "reject")
    psql(set_caps("holds", "holds"))
    check("DESC 는 다른 sortop(>) 이지만 같이 등록된다",
          "SELECT id FROM h5.g_t ORDER BY secret DESC, id", "accept")
    # ★ text_pattern_ops 의 ~<~ 는 **진짜 다른 comparator** 다.
    #   기본 collation-aware `<` 와 바이트 순서 비교는 의미가 다르다.
    check("★ 다른 opfamily 의 정렬 연산자 (~<~)",
          "SELECT id FROM h5.g_t ORDER BY secret USING ~<~, id", "reject",
          "기본 `<` 인증서가 text_pattern_ops 를 덮지 않는다")
    check("   기본 정렬은 여전히 수락", Q9, "accept")
    # ★ "btree 기본 연산자니까 holds" 를 자동으로 만들면 안 된다.
    #   기본 comparator 라는 사실은 **연산자 식별**일 뿐 증거가 아니다.
    psql(set_caps("holds", "holds") + """
        SELECT ipguard_register_default_comparators(mask_id,
                 'unknown'::ipguard_claim, 'unknown'::ipguard_claim,
                 'unknown'::ipguard_assurance)
          FROM ipguard_mask_instance WHERE normalized_args='kind=gsec';""")
    check("★ 기본 comparator 를 claim=unknown 으로 등록",
          Q9, "reject",
          "기본 연산자라는 사실이 factor-through 증거를 만들지 않는다")
    psql(set_caps("holds", "holds"))

    # ★ CARD 는 ROW_COUNT 만으로 부족하다 -- 술어는 **어느 공개 행이 남는지**도
    #   누출한다. 행 수가 같아도 다른 행일 수 있다:
    #
    #     D1: (1,a),(2,b)   D2: (1,b),(2,a)   m(a)=m(b)
    #     SELECT id FROM t WHERE secret='a'   ->  D1={1}  D2={2}
    #
    #   ROW_COUNT 만 보면 둘 다 1이라 놓친다.
    print("      ── CARD 의 활성 sink ──")
    psql(set_caps("holds", "holds") + CLEAR_DECLASS)

    def sinks(sql, effect="CARD"):
        r = psql(f"SELECT 'SINK:'||sink FROM ipguard_obligations($ipg${sql}$ipg$) "
                 f"WHERE effect='{effect}';", PRELUDE)
        return sorted(l.strip()[5:] for l in r.stdout.splitlines()
                      if l.startswith("SINK:"))

    for name, sql, want in [
        ("WHERE 술어", "SELECT id FROM h5.g_t WHERE secret = 'a'",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("★ 투영이 행 구별을 지우면 MEMBERSHIP 소거",
         "SELECT 'x' FROM h5.g_t WHERE secret = 'a'",
         ["MULTIPLICITY", "ROW_COUNT"]),
        ("inner join ON 절",
         "SELECT a.id FROM h5.g_t a JOIN h5.g_t b ON b.id=a.id AND a.secret='a'",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("semi-join (EXISTS)",
         "SELECT id FROM h5.g_t c WHERE EXISTS "
         "(SELECT 1 FROM h5.g_t p WHERE p.id=c.id AND c.secret='a')",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("HAVING",
         "SELECT grade, count(*) FROM h5.g_t GROUP BY grade "
         "HAVING max(secret) = 'a'",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("★ aggregate FILTER -> 그 집계의 CELL",
         "SELECT count(*) FILTER (WHERE secret IS NOT NULL) FROM h5.g_t",
         ["CELL"]),
    ]:
        got = sinks(sql)
        ok = got == want
        RESULTS.append((name, ",".join(got), ",".join(want), ok))
        print(f"  {'✓' if ok else '✗'} {name:52} {','.join(got)[:22]:<22}"
              f" (기대 {','.join(want)[:22]})")

    # ★ selection 의 CARD 가 **downstream aggregate 의 CELL 로 흐른다.**
    #
    #   D1: (1,10,a),(2,20,b)   D2: (1,10,b),(2,20,a)   m(a)=m(b)
    #   SELECT sum(amt) FROM t WHERE secret='a'
    #   D1 -> 10   D2 -> 20      ★ 최종 shape 는 둘 다 1행
    #
    # aggregate FILTER -> CELL 만으로는 못 잡는다. 그리고 이 경우
    # ROW_COUNT 를 만드는 것은 **sink 이름이 틀린 것**이다 -- 내부 선택
    # 카디널리티는 CARD effect 이지 최종 결과 shape 의 ROW_COUNT sink 가 아니다.
    print("      ── CARD -> downstream aggregate CELL ──")
    for name, sql, want in [
        ("★ 스칼라 집계: CELL 만 (최종 shape 는 1행)",
         "SELECT sum(id) FROM h5.g_t WHERE secret = 'a'", ["CELL"]),
        ("GROUP BY 있으면 shape 도 변한다 (그룹이 통째로 사라질 수 있다)",
         "SELECT grade, sum(id) FROM h5.g_t WHERE secret='a' GROUP BY grade",
         ["CELL", "MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("집계 없으면 CELL 없음",
         "SELECT id FROM h5.g_t WHERE secret = 'a'",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("★ 서브쿼리 selection 을 바깥 집계가 소비",
         "SELECT sum(z.id) FROM (SELECT id FROM h5.g_t WHERE secret='a') z",
         ["CELL", "MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
    ]:
        got = sinks(sql)
        ok = got == want
        RESULTS.append((name, ",".join(got), ",".join(want), ok))
        print(f"  {'✓' if ok else '✗'} {name:52} {','.join(got)[:22]:<22}"
              f" (기대 {','.join(want)[:22]})")

    # ★ 연산자별 transfer function 감사 -- 구문마다 sink 를 손으로 열거하면
    #   계속 빠진다. 다섯 번 연속 빠졌던 경로를 회귀로 박는다.
    #
    #   cell_deps   각 출력 cell 을 바꾸는 effect
    #   bag_deps    출력 row bag·membership·multiplicity 를 바꾸는 effect
    #   order_deps  출력 순서를 바꾸는 effect
    print("      ── transfer function 감사 (서브쿼리 경계를 넘는 합성) ──")
    for name, sql, effect, want in [
        ("★ W1 EQ -> 집계 CELL (그룹 수가 같아도 셀이 다르다)",
         "SELECT sum(id) FROM h5.g_t GROUP BY secret", "EQ",
         ["CELL", "MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("★ W2 ORD+LIMIT -> MULTIPLICITY (ROW_COUNT 는 **아니다**)",
         "SELECT grade FROM h5.g_t ORDER BY secret, id LIMIT 2", "ORD",
         ["FINAL_ORDER", "MEMBERSHIP", "MULTIPLICITY"]),
        ("★ W3 ORD -> 바깥 집계 CELL",
         "SELECT sum(s.id) FROM (SELECT id FROM h5.g_t "
         "ORDER BY secret, id LIMIT 2) s", "ORD",
         ["CELL", "MEMBERSHIP", "MULTIPLICITY"]),
        ("★ W4 HAVING -> 바깥 집계 CELL",
         "SELECT sum(s.v) FROM (SELECT grade, sum(id) AS v FROM h5.g_t "
         "GROUP BY grade HAVING max(secret)='a') s", "CARD",
         ["CELL", "MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
        ("★ W5 집합연산 -> 바깥 집계 CELL",
         "SELECT count(*) FROM (SELECT secret FROM h5.g_t "
         "UNION SELECT secret FROM h5.g_t) z", "EQ",
         ["CELL", "MULTIPLICITY", "ROW_COUNT"]),
        ("   대조: 같은 수준 HAVING 은 CELL 을 만들지 않는다",
         "SELECT grade, count(*) FROM h5.g_t GROUP BY grade "
         "HAVING max(secret)='a'", "CARD",
         ["MEMBERSHIP", "MULTIPLICITY", "ROW_COUNT"]),
    ]:
        got = sinks(sql, effect)
        ok = got == want
        RESULTS.append((name, ",".join(got), ",".join(want), ok))
        print(f"  {'✓' if ok else '✗'} {name:52} {','.join(got)[:20]:<20}"
              f" (기대 {','.join(want)[:20]})")

    # ★ VAL 도 합성적이어야 한다. 즉석 walker 면 중첩 질의에서 lineage 를
    #   잃는다:  SELECT upper(x) FROM (SELECT lower(secret) AS x FROM t) s
    #   표현식은 의무를 만들지 않고 **요약**을 돌려주고, 최종 observable
    #   target 에서만 VAL -> CELL 을 발행한다.
    print("      ── VAL transfer function (proof tree) ──")
    psql(set_caps("holds", "holds") + CLEAR_DECLASS)
    # ★ 합성 경로를 실제로 세운다. f(m(x)) = r_out(f(x)) 이므로 부모는
    #   **자식의 출력 마스크**로 다시 조회한다.
    #     (gsec, lower, pos=0) -> R1 ;  (R1, upper, pos=0) -> R1
    psql("""
    CREATE OR REPLACE FUNCTION h5.g_r1(x text) RETURNS text
      LANGUAGE sql IMMUTABLE AS $f$ SELECT repeat('*', length($1)) $f$;
    -- concat 은 VARIADIC "any" 라 regprocedure 로 특정할 수 없다.
    -- 인자 위치를 시험하려면 2인자 함수가 필요하다.
    CREATE OR REPLACE FUNCTION h5.g_two(a text, b text) RETURNS text
      LANGUAGE sql IMMUTABLE AS $f$ SELECT $1 || $2 $f$;
    DELETE FROM ipguard_mask_instance WHERE normalized_args='chain=r1';
    SELECT ipguard_register_mask('h5.g_r1(text)'::regprocedure,
             'text'::regtype,'text'::regtype,'chain=r1');
    INSERT INTO ipguard_mask_capability(mask_id,capability,claim,assurance)
    SELECT mask_id, c.cap, 'holds', 'trusted_assumption'
      FROM ipguard_mask_instance, (VALUES ('determinism'),('total'),
           ('null_equivalence')) c(cap)
     WHERE normalized_args='chain=r1';
    """)

    def reg_fn(mask_args, fn, pos, out_fn):
        return f"""
        INSERT INTO ipguard_mask_function_compatibility
          (mask_id, func, arg_signature, out_redactor, collation_name,
           func_fingerprint, red_fingerprint, claim, assurance)
        SELECT m.mask_id, '{fn}'::regprocedure, 'pos={pos}',
               '{out_fn}'::regprocedure, '',
               (SELECT fingerprint FROM ipguard_fingerprint('{fn}'::regprocedure)),
               (SELECT fingerprint FROM ipguard_fingerprint('{out_fn}'::regprocedure)),
               'holds', 'trusted_assumption'
          FROM ipguard_mask_instance m
         WHERE m.normalized_args = '{mask_args}'
        ON CONFLICT DO NOTHING;"""

    psql(reg_fn("kind=gsec", "lower(text)", 0, "h5.g_r1(text)")
         + reg_fn("chain=r1", "upper(text)", 0, "h5.g_r1(text)")
         + reg_fn("kind=gsec", "h5.g_two(text,text)", 0, "h5.g_r1(text)")
         + reg_fn("kind=gsec", "min(text)", 0, "h5.g_r1(text)"))

    def vsinks(sql):
        r = psql(f"SELECT 'S:'||effect||'/'||sink FROM "
                 f"ipguard_obligations($ipg${sql}$ipg$);", PRELUDE)
        return sorted(l.strip()[2:] for l in r.stdout.splitlines()
                      if l.startswith("S:"))

    for name, sql, want in [
        ("★ V1 맨 컬럼 — commutation 은 없지만 MASK_APPLY baseline 은 본다",
         "SELECT secret FROM h5.g_t", ["VAL/CELL"]),
        ("V2 스칼라 변환", "SELECT lower(secret) FROM h5.g_t", ["VAL/CELL"]),
        ("★ V3 중첩 변환 (질의 경계를 넘는 합성)",
         "SELECT upper(x) FROM (SELECT lower(secret) AS x FROM h5.g_t) s",
         ["VAL/CELL"]),
        ("V4 민감 입력 하나 + 공개 하나",
         "SELECT h5.g_two(secret, grade) FROM h5.g_t", ["VAL/CELL"]),
        ("★ V5 control dependency -> CELL (CARD 가 아니다)",
         "SELECT CASE WHEN secret='a' THEN grade ELSE grade END FROM h5.g_t",
         ["VAL/CELL"]),
        ("V6 집계 값", "SELECT min(secret) FROM h5.g_t", ["VAL/CELL"]),
        ("★ V4b 마스킹된 입력 둘 -- 공통 출력 마스크 증명 불가",
         "SELECT h5.g_two(lower(secret), upper(secret)) FROM h5.g_t",
         ["VAL/CELL"]),
        ("V7 그룹 키가 동시에 공개 값",
         "SELECT secret, count(*) FROM h5.g_t GROUP BY secret",
         ["EQ/CELL", "EQ/MEMBERSHIP", "EQ/MULTIPLICITY", "EQ/ROW_COUNT",
          "VAL/CELL"]),
        ("★ V8 집합연산 출력이 바깥 표현식으로",
         "SELECT lower(x) FROM (SELECT secret AS x FROM h5.g_t "
         "UNION ALL SELECT secret AS x FROM h5.g_t) s", ["VAL/CELL"]),
        ("N1 resjunk 키 — VAL 없이 ORD 만",
         "SELECT id FROM h5.g_t ORDER BY lower(secret)", ["ORD/FINAL_ORDER"]),
        ("N2 술어만 — VAL 이 아니라 CARD",
         "SELECT id FROM h5.g_t WHERE lower(secret)='a'",
         ["CARD/MEMBERSHIP", "CARD/MULTIPLICITY", "CARD/ROW_COUNT"]),
    ]:
        got = vsinks(sql)
        ok = got == want
        RESULTS.append((name, ",".join(got) or "(없음)", ",".join(want) or "(없음)", ok))
        print(f"  {'✓' if ok else '✗'} {name:52} "
              f"{(','.join(got) or '(없음)')[:24]:<24}"
              f" (기대 {(','.join(want) or '(없음)')[:24]})")

    # ★ proof tree 음성 대조군 -- branch 별로 인증서를 하나씩 지운다
    print("      ── proof tree 음성 대조군 ──")
    V3 = "SELECT upper(x) FROM (SELECT lower(secret) AS x FROM h5.g_t) s"
    CC = "SELECT h5.g_two(secret, 'x') FROM h5.g_t"
    DEL = ("DELETE FROM ipguard_mask_function_compatibility f "
           "USING ipguard_mask_instance m "
           "WHERE f.mask_id=m.mask_id AND m.normalized_args='{a}' "
           "AND f.func='{fn}'::regprocedure;")
    check("V1 baseline 통과 (마스크 등록·인증됨)",
          "SELECT secret FROM h5.g_t", "accept")
    check("★ V3 합성 경로 인증됨", V3, "accept")
    psql(DEL.format(a="kind=gsec", fn="lower(text)"))
    check("★ lower 인증서 삭제 -> V3 거부", V3, "reject")
    psql(reg_fn("kind=gsec", "lower(text)", 0, "h5.g_r1(text)"))
    psql(DEL.format(a="chain=r1", fn="upper(text)"))
    check("★ upper 인증서 삭제 -> V3 거부", V3, "reject",
          "마지막 변환만 보면 이게 통과한다")
    psql(reg_fn("chain=r1", "upper(text)", 0, "h5.g_r1(text)"))
    check("   되돌리면 수락", V3, "accept")
    check("concat 인증됨", CC, "accept")
    psql(DEL.format(a="kind=gsec", fn="h5.g_two(text,text)"))
    check("★ concat 인증서 삭제 -> 거부", CC, "reject")
    # ★ 인자 위치가 다른 인증서만 있으면 통과하면 안 된다
    psql(reg_fn("kind=gsec", "h5.g_two(text,text)", 1, "h5.g_r1(text)"))
    check("★ 인자 위치가 다른 인증서만 존재 -> 거부", CC, "reject",
          "concat(a,b) 와 concat(b,a) 는 다른 주장이다")
    psql(reg_fn("kind=gsec", "h5.g_two(text,text)", 0, "h5.g_r1(text)"))
    check("   pos=0 인증서를 넣으면 수락", CC, "accept")
    check("★ 마스킹된 입력 둘 -> 거부",
          "SELECT h5.g_two(lower(secret), upper(secret)) FROM h5.g_t", "reject",
          "공통 출력 마스크를 증명할 수 없다")

    # ★ 경계 폐쇄성 행렬 -- summary 마다 네 조건을 본다.
    #
    #   propagation           자식 effect 가 부모 sink 까지 도달
    #   missing proof         자식 인증서 삭제 시 거부
    #   context preservation  다른 연산자·상수·collation 인증서로 통과하지 않음
    #   erasure               부모가 관찰을 지우면 의무도 사라짐
    #
    # cells[] 는 이미 확인했다(V3). bag_out 과 ord 를 같은 방식으로 닫는다 --
    # "표를 만든 것" 과 "코드가 표대로 도는 것" 은 별개이고, cells[] 에서
    # 실제로 끊겨 있었다.
    print("      ── 경계 폐쇄성 행렬 (bag_out / ord) ──")
    psql(set_caps("holds", "holds") + CLEAR_DECLASS)

    B1 = "SELECT sum(s.id) FROM (SELECT id FROM h5.g_t WHERE secret='a') s"
    B1b = "SELECT sum(s.id) FROM (SELECT id FROM h5.g_t WHERE secret='b') s"
    B2 = ("SELECT sum(s.v) FROM (SELECT sum(id) AS v FROM h5.g_t "
          "GROUP BY secret) s")
    B3 = ("SELECT count(*) FROM (SELECT secret FROM h5.g_t "
          "UNION SELECT secret FROM h5.g_t) s")
    O1 = ("SELECT sum(s.id) FROM (SELECT id FROM h5.g_t "
          "ORDER BY secret, id LIMIT 2) s")
    O3 = "SELECT s.id FROM (SELECT id FROM h5.g_t ORDER BY secret, id) s"
    O4 = ("SELECT s.id FROM (SELECT id FROM h5.g_t ORDER BY secret) s "
          "ORDER BY s.id")

    for nm, sql, eff in (("B1 selection", B1, "CARD"),
                         ("B2 EQ partition", B2, "EQ"),
                         ("B3 set-op bag", B3, "EQ"),
                         ("O1 child ORD+LIMIT", O1, "ORD")):
        got = "CELL" in sinks(sql, eff)
        RESULTS.append((f"{nm} -> 부모 CELL 전파", str(got), "True", got))
        print(f"  {'✓' if got else '✗'} {nm + ' -> 부모 CELL 전파':52} "
              f"{str(got):<8} (기대 True)")

    for nm, sql in (("O3 최상위 ORDER BY 없음 -> 자식 order 소거", O3),
                    ("O4 공개 outer order 가 대체", O4)):
        got = sinks(sql, "ORD")
        ok = got == []
        RESULTS.append((nm, ",".join(got) or "(없음)", "(없음)", ok))
        print(f"  {'✓' if ok else '✗'} {nm:52} "
              f"{(','.join(got) or '(없음)'):<8} (기대 (없음))")

    psql(declass_all("CARD", "decision-trace", B1))
    check("B1 인증서 발급 -> 수락", B1, "accept")
    check("★ B1 context preservation: 'b' 는 다른 문맥", B1b, "reject",
          "상수가 canonical 에 들어간다 -- 경계를 넘어도 유지된다")
    psql(CLEAR_DECLASS)
    check("★ B1 인증서 삭제 -> 거부", B1, "reject")

    check("★ B2 EQ comparator 있으면 수락", B2, "accept")
    psql("""DELETE FROM ipguard_mask_comparator_compatibility
             WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                WHERE normalized_args='kind=gsec') AND kind='EQ';""")
    check("★ B2 EQ comparator 삭제 -> 거부", B2, "reject",
          "GROUP BY 의 eqop 인증서가 경계를 넘어 필요하다")
    check("★ B3 set-op 도 같은 이유로 거부", B3, "reject")
    psql(set_caps("holds", "holds"))

    check("★ O1 ORD comparator 있으면 수락", O1, "accept")
    psql("""DELETE FROM ipguard_mask_comparator_compatibility
             WHERE mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                WHERE normalized_args='kind=gsec') AND kind='ORD';""")
    check("★ O1 ORD comparator 삭제 -> 거부", O1, "reject",
          "comparator context 가 소비 지점까지 유지된다")
    psql(set_caps("holds", "holds"))
    check("★ ~<~ 가 경계를 넘어도 기본 `<` 인증서로 통과하지 않는다",
          "SELECT sum(s.id) FROM (SELECT id FROM h5.g_t "
          "ORDER BY secret USING ~<~, id LIMIT 2) s", "reject")

    # P0/P1 회귀: CELL 의무가 남으면 거부되는가
    psql(CLEAR_DECLASS)
    AGG = "SELECT sum(id) FROM h5.g_t WHERE secret = 'a'"
    check("P0  CARD -> CELL 미인증", AGG, "reject")
    psql(declass("CARD", "ROW_COUNT", "predicate-result", AGG))
    psql(declass("CARD", "MULTIPLICITY", "predicate-result", AGG))
    psql(declass("CARD", "MEMBERSHIP", "predicate-result", AGG))
    check("★ shape sink 만 허가하면 CELL 의무가 남아 거부", AGG, "reject",
          "decision-path declassification 이 downstream cell 까지 덮어야 한다")
    psql(declass_all("CARD", "predicate-decision-trace", AGG))
    check("P1  CARD -> CELL 까지 정확한 context 로 허가", AGG, "accept")
    psql(CLEAR_DECLASS)

    # ★ 그리고 그 sink 가 **실제로 판정에 쓰이는가** -- 리뷰가 준 witness
    psql(CLEAR_DECLASS)
    psql(declass("CARD", "ROW_COUNT", "predicate-result",
                 "SELECT id FROM h5.g_t WHERE secret = 'a'"))
    check("★ ROW_COUNT 만 허가하면 MEMBERSHIP 이 남아 거부",
          "SELECT id FROM h5.g_t WHERE secret = 'a'", "reject",
          "행 수가 같아도 어느 행이 남는지가 다를 수 있다")
    psql(declass("CARD", "MULTIPLICITY", "predicate-result",
                 "SELECT id FROM h5.g_t WHERE secret = 'a'"))
    psql(declass("CARD", "MEMBERSHIP", "predicate-result",
                 "SELECT id FROM h5.g_t WHERE secret = 'a'"))
    check("   셋 다 허가하면 수락",
          "SELECT id FROM h5.g_t WHERE secret = 'a'", "accept")
    psql(CLEAR_DECLASS)

    # ★ 레지스트리 조회가 터져도 fail-open 되면 안 된다.
    print("      ── 레지스트리 조회 오류 뒤 fail-open 되는가 ──")
    psql(set_caps("holds", "holds"))
    before = verdict(Q9)
    psql("""CREATE OR REPLACE FUNCTION ipguard_capability(mid int, cap text)
            RETURNS ipguard_claim LANGUAGE plpgsql STABLE AS $f$
            BEGIN RAISE EXCEPTION 'ipguard-test: registry lookup exploded'; END $f$;""")
    boom = verdict(Q9)
    # 같은 세션이 아니어도 상관없다 -- busy 가 정적 변수라 백엔드 단위다.
    # 여기서 확인할 것은 "오류가 났는데 수락으로 빠지지 않는가" 다.
    psql("""CREATE OR REPLACE FUNCTION ipguard_capability(mid int, cap text)
            RETURNS ipguard_claim
            LANGUAGE plpgsql STABLE AS $f$
            DECLARE inst record; now_fp record; c ipguard_claim;
            BEGIN
                SELECT * INTO inst FROM ipguard_mask_instance WHERE mask_id = mid;
                IF NOT FOUND THEN RETURN 'unknown'; END IF;
                SELECT * INTO now_fp
                  FROM ipguard_fingerprint(inst.func, inst.collation_name);
                IF now_fp.fingerprint IS DISTINCT FROM inst.impl_fingerprint THEN
                    RETURN 'unknown';
                END IF;
                SELECT claim INTO c FROM ipguard_mask_capability
                 WHERE mask_id = mid AND capability = cap;
                RETURN coalesce(c, 'unknown');
            END $f$;""")
    after = verdict(Q9)
    for nm, got, want in (("조회 오류 전 (holds)", before, "accept"),
                          ("★ 조회가 터지면 수락이 아니라 오류",
                           "not-accept" if boom != "accept" else "accept", "not-accept"),
                          ("복구 후 정상 동작", after, "accept")):
        ok = got == want
        RESULTS.append((nm, got, want, ok))
        print(f"  {'✓' if ok else '✗'} {nm:52} {got:<8} (기대 {want})")


def premise(name, got, want):
    """전제 확인. 실패하면 뒤 주장이 **공허**하므로 따로 센다."""
    ok = got == want
    RESULTS.append((f"전제 {name}", str(got), str(want), ok))
    print(f"  {'✓' if ok else '✗'} {'전제 ' + name:52} {str(got):<8} (기대 {want})")
    return ok


def group_invalidation_premise():
    """★ 무효화 시험의 **전제**를 먼저 결정적으로 확인한다.

    이 전제를 확인하지 않아서 실제 제품 결함을 'flaky 테스트' 로 오해했다.
    `ipguard_watch_registry()` 는 정의만 되어 있고 `CREATE EXTENSION` 이
    부르지 않아, 확장을 새로 만들면 레지스트리 트리거가 **0개**였다. 그래서

        인증서 철회  ->  캐시된 generic plan 이 철회 전 판정으로 계속 돈다

    가 된다. 회귀가 초록이었던 것은 score_registry.py 가 먼저 돌아 트리거를
    깔아 놓았기 때문이다 -- 시험이 다른 시험의 부작용에 기대고 있었다.
    지금은 확장 스크립트가 설치 시점에 건다.

    cold-start 와 invalidation 을 **분리**한다:
        cold-start   generic plan 없음 -> 무효화할 대상 없음 -> +0
        invalidation generic plan 존재를 확인한 뒤 철회 -> +1
    """
    print("\n[5a] ★ 무효화 전제 — 트리거·cold start")
    n = one("SELECT count(*) FROM pg_trigger WHERE tgname LIKE 'ipguard_reg_%'")
    premise("레지스트리 무효화 트리거가 설치돼 있다", int(n) > 0, True)
    n = one("SELECT count(*) FROM pg_trigger WHERE tgname = 'ipguard_label_inval'")
    premise("라벨 무효화 트리거가 설치돼 있다", int(n) > 0, True)

    # cold start: 준비된 계획이 하나도 없는 세션에서 철회해도 계획기는 돌지 않는다.
    C = Session()
    try:
        C.run("SET search_path = h5, public")
        c0 = int(C.val("SELECT ipguard_pii_plan_count()"))
        psql("""UPDATE ipguard_mask_capability SET claim='holds'
                 WHERE capability='order_factor'
                   AND mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                    WHERE normalized_args='kind=gsec');""")
        c1 = int(C.val("SELECT ipguard_pii_plan_count()"))
        nm = "cold start: generic plan 없으면 철회해도 재계획 없음"
        ok = (c1 - c0) == 0
        RESULTS.append((nm, f"+{c1 - c0}", "+0", ok))
        print(f"  {'✓' if ok else '✗'} {nm:52} +{c1 - c0:<7} (기대 +0)")
    finally:
        C.close()


def group_connected():
    """★ 게이트 연결 후의 최종 회귀.

    레지스트리 회귀(F 그룹)는 '철회가 캐시된 계획까지 닿는다' 는 **기전**만
    확인했다. 게이트가 레지스트리를 읽게 된 지금은 **같은 generic plan** 을
    대상으로 셋을 한 번에 봐야 한다:

        holds 인증서로 generic plan 생성  -> accept
        다른 backend 에서 인증서 철회 COMMIT
        같은 generic plan EXECUTE
          -> plan +1        (재계획됐다)
          -> unknown/fails
          -> reject
    """
    print("\n[5] ★ 연결 회귀 — 같은 generic plan: 철회 -> 재계획 -> 거부")
    psql(set_caps("holds") + CLEAR_DECLASS)
    A, B = Session(), Session()
    try:
        A.run("SET plan_cache_mode = force_generic_plan")
        A.run("SET search_path = h5, public")
        A.run("SET ipguard.enforce = on")
        A.run("SET ipguard.gate = release")
        A.run("PREPARE g AS SELECT id FROM h5.g_t ORDER BY secret, id")
        r = A.run("EXECUTE g")
        RESULTS.append(("연결1 holds 인증서로 generic plan 생성",
                        "accept" if not any("ERROR" in x for x in r) else "reject",
                        "accept", not any("ERROR" in x for x in r)))
        print(f"  {'✓' if RESULTS[-1][3] else '✗'} "
              f"{'연결1 holds 인증서로 generic plan 생성':52} "
              f"{RESULTS[-1][1]:<8} (기대 accept)")
        premise("generic plan 이 실제로 만들어졌다",
                int(A.val("SELECT coalesce((SELECT generic_plans FROM "
                          "pg_prepared_statements WHERE name='g'),0)")) > 0,
                True)
        c0 = int(A.val("SELECT ipguard_pii_plan_count()"))

        # 다른 backend 에서 철회
        B.run("BEGIN")
        B.run("""UPDATE ipguard_mask_capability SET claim='unknown',
                 assurance='unknown'
                 WHERE capability='order_factor'
                   AND mask_id IN (SELECT mask_id FROM ipguard_mask_instance
                                    WHERE normalized_args='kind=gsec')""")
        B.run("COMMIT")

        out = A.run("EXECUTE g")
        c1 = int(A.val("SELECT ipguard_pii_plan_count()"))
        rejected = any("해소되지 않은 의무" in x for x in out)

        for nm, got, want in (("연결2 철회 후 같은 plan 이 재계획된다", f"+{c1 - c0}", "+1"),
                              ("연결3 ★ 그리고 거부된다",
                               "reject" if rejected else "accept", "reject")):
            ok = got == want
            RESULTS.append((nm, got, want, ok))
            print(f"  {'✓' if ok else '✗'} {nm:52} {got:<8} (기대 {want})")
        if rejected:
            why = [x for x in out if "DETAIL" in x or "ORD" in x]
            if why:
                print(f"      사유: {why[0][:70]}")
        A.run("DEALLOCATE g")

        # ── (2) declassification 철회도 같은 경로여야 한다 ──
        psql(set_caps("fails") + CLEAR_DECLASS)
        psql(declass("ORD", "FINAL_ORDER", "relative-order", Q9))
        A.run("PREPARE d AS SELECT id FROM h5.g_t ORDER BY secret, id")
        r = A.run("EXECUTE d")
        premise("generic plan 이 실제로 만들어졌다 (declass)",
                int(A.val("SELECT coalesce((SELECT generic_plans FROM "
                          "pg_prepared_statements WHERE name='d'),0)")) > 0,
                True)
        c0 = int(A.val("SELECT ipguard_pii_plan_count()"))
        ok = not any("ERROR" in x for x in r)
        RESULTS.append(("연결4 declassification 으로 generic plan 생성",
                        "accept" if ok else "reject", "accept", ok))
        print(f"  {'✓' if ok else '✗'} "
              f"{'연결4 declassification 으로 generic plan 생성':52} "
              f"{'accept' if ok else 'reject':<8} (기대 accept)")
        B.run("BEGIN")
        B.run("DELETE FROM ipguard_declassification "
              "WHERE relid='h5.g_t'::regclass AND sink='FINAL_ORDER'")
        B.run("COMMIT")
        out = A.run("EXECUTE d")
        c1 = int(A.val("SELECT ipguard_pii_plan_count()"))
        rej = any("해소되지 않은 의무" in x for x in out)
        for nm, got, want in (
                ("연결5 declassification 철회 -> 재계획", f"+{c1 - c0}", "+1"),
                ("연결6 ★ 그리고 거부된다", "reject" if rej else "accept", "reject")):
            o = got == want
            RESULTS.append((nm, got, want, o))
            print(f"  {'✓' if o else '✗'} {nm:52} {got:<8} (기대 {want})")
        A.run("DEALLOCATE d")

        # ── (3) ★ gate 모드 전환이 캐시된 계획을 무효화하는가 ──
        #
        # 사용자가 release 로 바꿨는데 캐시된 legacy plan 이 계속 돌면,
        # 모드를 바꾼 것이 아무 효력이 없으면서 에러도 경고도 없다.
        psql(set_caps("fails") + CLEAR_DECLASS)
        C = Session()
        try:
            C.run("SET plan_cache_mode = force_generic_plan")
            C.run("SET search_path = h5, public")
            C.run("SET ipguard.enforce = on")
            C.run("SET ipguard.gate = legacy")
            C.run("PREPARE m AS SELECT id FROM h5.g_t ORDER BY secret, id")
            r = C.run("EXECUTE m")
            legacy_ok = not any("ERROR" in x for x in r)
            RESULTS.append(("연결7 legacy 로 generic plan 생성",
                            "accept" if legacy_ok else "reject", "accept", legacy_ok))
            print(f"  {'✓' if legacy_ok else '✗'} "
                  f"{'연결7 legacy 로 generic plan 생성':52} "
                  f"{'accept' if legacy_ok else 'reject':<8} (기대 accept)")
            c0 = int(C.val("SELECT ipguard_pii_plan_count()"))
            C.run("SET ipguard.gate = release")
            out = C.run("EXECUTE m")
            c1 = int(C.val("SELECT ipguard_pii_plan_count()"))
            rej = any("해소되지 않은 의무" in x for x in out)
            for nm, got, want in (
                    ("연결8 gate 모드 전환 -> 재계획", f"+{c1 - c0}", "+1"),
                    ("연결9 ★ 같은 plan 이 release 판정을 받는다",
                     "reject" if rej else "accept", "reject")):
                o = got == want
                RESULTS.append((nm, got, want, o))
                print(f"  {'✓' if o else '✗'} {nm:52} {got:<8} (기대 {want})")
            C.run("DEALLOCATE m")
        finally:
            C.close()
    finally:
        A.close()
        B.close()


def main():
    print("=" * 78)
    print("release-factorization gate — 판정 행")
    print("=" * 78)
    psql(SETUP)
    try:
        # ── 기본: 상수 마스크(order_factor=fails), declassification 없음 ──
        group_failclosed()
        psql(set_caps("fails") + CLEAR_DECLASS)
        print("\n[1] 기본 — 상수 마스크(order_factor=fails), 인증서 없음")
        check("Q10  ORD 있으나 관찰 가능한 행 구별 없음", Q10, "accept",
              "모든 출력 행이 'x' 라 순서가 결과 bag 을 바꾸지 못한다")
        check("Q9   ORD -> FINAL_ORDER(공개 id)", Q9, "reject")
        check("Q6   ORD -> MEMBERSHIP + FINAL_ORDER", Q6, "reject")
        # ★ 새 대조군: 정렬키는 전순서지만 선택된 row identity 가 사라진다.
        #   반환 건수도 min(3,|t|) 로 공개 multiplicity 가 정한다.
        #   이걸 수락해야 effect->sink 소거를 실제로 구현한 것이다.
        check("Q6'  전순서 정렬 + LIMIT, 그러나 row identity 소멸", Q6P, "accept",
              "★ 정렬키는 전순서지만 투영이 행 구별을 지운다")
        check("     비민감 대조군", "SELECT grade FROM h5.g_t ORDER BY grade",
              "accept")

        # ── 전순서 보존 마스크 ──
        print("\n[2] 전순서 보존 마스크 (order_factor=holds)")
        psql(set_caps("holds") + CLEAR_DECLASS)
        check("Q9   factor-through 로 해소", Q9, "accept",
              "키 벡터 전체가 release 로부터 재구성 가능하다")
        check("Q6   membership 도 같은 ORD 노드라 함께 해소", Q6, "accept")
        check("     그래도 EQ 는 별개다: DISTINCT secret",
              "SELECT DISTINCT secret FROM h5.g_t", "reject",
              "order_factor 가 equality_factor 를 대신하지 않는다")

        # ── declassification ──
        print("\n[3] declassification — (effect, sink) 쌍 단위")
        psql(set_caps("fails") + CLEAR_DECLASS)
        psql(declass("ORD", "FINAL_ORDER", "relative-order", Q9))
        check("Q9   최종 순서만 declassify", Q9, "accept")
        check("Q6   순서만 허가, membership 미허가", Q6, "reject",
              "★ 같은 컬럼·같은 effect 라도 sink 가 다르면 별도 허가가 필요하다")
        psql(declass_all("ORD", "top-k-membership", Q6))
        check("Q6   membership 까지 허가하면", Q6, "accept")
        # ★ 인증서 키에 context 가 들어간다:
        #     Declass(sources, effect, context_fingerprint, sink, observation)
        #   bare 키에 준 허가가 파생 표현식이나 다른 비교자까지 덮으면 안 된다.
        check("★ 같은 (effect,sink) 지만 파생 표현식 문맥",
              "SELECT id FROM h5.g_t ORDER BY lower(secret), id", "reject",
              "context_key 가 달라 bare 인증서가 덮지 않는다")
        check("★ 같은 (effect,sink) 지만 다른 비교자 (~<~)",
              "SELECT id FROM h5.g_t ORDER BY secret USING ~<~, id", "reject")

        # ★ parameterized predicate — 인증서가 조용히 모든 값에 재사용되면 안 된다
        print("      ── parameterized predicate ──")
        PC = "SELECT count(*) FROM h5.g_t WHERE secret = $1"
        PK = "SELECT count(*) FROM h5.g_t WHERE secret = 'a'"
        psql(CLEAR_DECLASS)
        psql(declass_all("CARD", "predicate-result", PC, "none"))
        check("★ param_scope=none 이면 $1 술어 거부", PC, "reject",
              "인증서가 어느 $1 값을 허가하는지 불명확하다")
        psql("""UPDATE ipguard_declassification SET param_scope='all_values'
                 WHERE relid='h5.g_t'::regclass;""")
        check("   param_scope=all_values 로 명시하면 수락", PC, "accept",
              "★ 강한 declassification -- 적응적으로 값을 바꾸면 열거 가능하다")
        check("★ 상수 술어는 **다른 문맥**이라 여전히 거부", PK, "reject",
              "cval 이 canonical 에 들어간다")
        psql(CLEAR_DECLASS)
        psql(declass_all("CARD", "predicate-result", PK))
        check("   상수 술어에 발급하면 그것만 수락", PK, "accept")
        check("★ 다른 상수는 거부", "SELECT count(*) FROM h5.g_t WHERE secret = 'b'",
              "reject")
        check("★ 다른 연산자는 거부", "SELECT count(*) FROM h5.g_t WHERE secret <> 'a'",
              "reject")
        psql(CLEAR_DECLASS)
        psql(declass("ORD", "FINAL_ORDER", "relative-order", Q9))
        psql(declass_all("ORD", "top-k-membership", Q6))
        check("     EQ 는 여전히 미허가: DISTINCT secret",
              "SELECT DISTINCT secret FROM h5.g_t", "reject")

        # ── 인증서 unknown ──
        print("\n[4] 인증서 unknown -> 거부")
        psql(set_caps("unknown", "unknown") + CLEAR_DECLASS)
        check("Q9   order_factor=unknown", Q9, "reject")
        check("     DISTINCT, equality_factor=unknown",
              "SELECT DISTINCT secret FROM h5.g_t", "reject")
        psql("DELETE FROM ipguard_mask_instance WHERE normalized_args='kind=gsec';")
        check("Q9   MaskInstance 자체가 미등록", Q9, "reject",
              "등록 안 된 것이 조용히 '안전' 으로 읽히면 안 된다")

        # 위에서 인스턴스를 지웠으니 다시 등록하고 연결 회귀로 간다
        psql("SELECT ipguard_register_mask("
             "'ipguard_mask(anyelement,text)'::regprocedure, "
             "'text'::regtype, 'text'::regtype, 'kind=gsec', '', '상수 마스크');")
        group_invalidation_premise()
        group_connected()
        group_aggref()
    finally:
        psql(TEARDOWN)

    print("\n" + "=" * 78)
    ok = sum(1 for *_, o in RESULTS if o)
    print(f"  합계 {ok}/{len(RESULTS)}")
    bad = [(n, g, w) for n, g, w, o in RESULTS if not o]
    if bad:
        print("\n  실패:")
        for n, g, w in bad:
            print(f"    {n}: {g}  (기대 {w})")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(main())
