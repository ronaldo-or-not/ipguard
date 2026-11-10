#!/usr/bin/env python3
"""레지스트리 단독 회귀 (명세 v0.2.1 §11-3, 리뷰 요구 8단계 중 8).

**effect 분석과 연결하기 전에** 레지스트리만 따로 검증한다. 순서를 바꾸면
어느 쪽이 틀렸는지 구별할 수 없다 -- 이 프로젝트에서 이미 네 번 당했다.

다섯 그룹:

  A 상수 마스크    deterministic=holds, equality_factor=fails, order_factor=fails
  B 미등록 UDF     모든 요구 capability 가 unknown
  C CREATE OR REPLACE  같은 OID 인데도 지문 불일치 -> unknown
  D 인증서 철회    epoch 증가 + 이미 만든 generic plan 재계획
  E 호환성         등록된 substr 조합만 holds. 다른 인자·collation·redactor 는 unknown

★ `fails` 와 `unknown` 을 구별하는 것이 이 표의 요점이다.
  unknown = "인증 안 됨" (나중에 인증되면 수락 가능)
  fails   = "성립하지 않음이 확인됨" (영원히 수락 불가)
  하나로 뭉치면 진단이 무너진다.

사용: python3 tools/score_registry.py
"""
import subprocess
import sys

SETUP = r"""
SET client_min_messages = warning;
SELECT ipguard_watch_registry();
DELETE FROM ipguard_mask_instance;

-- 테스트용 UDF 두 개. 하나는 등록하고 하나는 안 한다.
CREATE OR REPLACE FUNCTION h5.reg_udf(x text) RETURNS text
  LANGUAGE sql IMMUTABLE AS $f$ SELECT repeat('*', length($1)) $f$;
CREATE OR REPLACE FUNCTION h5.reg_unreg(x text) RETURNS text
  LANGUAGE sql IMMUTABLE AS $f$ SELECT '#' $f$;
CREATE OR REPLACE FUNCTION h5.reg_redact(x text) RETURNS text
  LANGUAGE sql IMMUTABLE AS $f$ SELECT repeat('*', length($1)) $f$;
CREATE OR REPLACE FUNCTION h5.reg_redact2(x text) RETURNS text
  LANGUAGE sql IMMUTABLE AS $f$ SELECT '?' $f$;
-- F 그룹(cross-backend)용. 다른 세션에서 CREATE OR REPLACE 한다.
CREATE OR REPLACE FUNCTION h5.reg_xsess(x text) RETURNS text
  LANGUAGE sql IMMUTABLE AS $f$ SELECT '@' $f$;
"""

TEARDOWN = r"""
SET client_min_messages = warning;
DELETE FROM ipguard_mask_instance;
DROP FUNCTION IF EXISTS h5.reg_udf(text), h5.reg_unreg(text),
                        h5.reg_redact(text), h5.reg_redact2(text),
                        h5.reg_xsess(text);
"""


def psql(script, db="ipdev"):
    return subprocess.run(["psql", "-d", db, "-At", "-f", "-"], input=script,
                          capture_output=True, text=True)


def one(script):
    r = psql(script)
    if r.returncode != 0 or "ERROR" in r.stderr:
        err = [l for l in r.stderr.splitlines() if "ERROR" in l]
        return "ERR: " + (err[0][-70:] if err else r.stderr[-70:])
    body = [l for l in r.stdout.splitlines() if l.strip()]
    return body[-1] if body else ""


RESULTS = []


def check(group, name, got, want):
    ok = (got == want)
    RESULTS.append((group, name, got, want, ok))
    mark = "✓" if ok else "✗"
    print(f"  {mark} {name:46} {got:<14} (기대 {want})")
    return ok


# ---------------------------------------------------------------- A
def group_a():
    print("\nA. 상수 마스크 — 무엇을 만족하고 무엇을 **못** 하는가")
    print("   ipguard_mask() 는 타입별 상수를 돌려준다. 모든 값이 같은 마스크로")
    print("   가므로 동치·순서가 뭉개진다. 그것을 fails 로 **적극 기록**한다.")
    mid0 = one("""SELECT ipguard_register_mask(
                    'ipguard_mask(anyelement,text)'::regprocedure,
                    'text'::regtype, 'text'::regtype, 'kind=ssn', '', '상수 마스크')""")
    check("A", "우리 모듈 C 함수는 c-provider (complete 아님)",
          one(f"SELECT fp_basis_kind || '/' || fp_complete "
              f"FROM ipguard_mask_instance WHERE mask_id = {mid0}"),
          "c-provider/false")
    # ★ 등록 **전에** 시험한다. capability 이름은 CHECK 제약을 통과하는 유효한
    #   것이어야 한다 -- 없는 이름을 쓰면 guard 가 아니라 CHECK 가 막아서
    #   "잘못된 이유로 통과" 한다.
    check("A", "★ c-provider 에 proved_builtin 은 거부",
          "rejected" if one(f"""INSERT INTO ipguard_mask_capability
                (mask_id, capability, claim, assurance)
                VALUES ({mid0}, 'determinism', 'holds', 'proved_builtin')"""
                            ).startswith("ERR") else "accepted", "rejected")
    check("A", "src 기반 UDF 에 trusted_provider 도 거부",
          "rejected" if one("""INSERT INTO ipguard_mask_capability
                (mask_id, capability, claim, assurance)
                SELECT ipguard_register_mask('h5.reg_redact2(text)'::regprocedure,
                       'text'::regtype, 'text'::regtype),
                       'determinism', 'holds', 'trusted_provider'"""
                            ).startswith("ERR") else "accepted", "rejected")
    psql("""
    -- ★ assurance 가 trusted_provider 다. proved_builtin 이 아니다.
    --   우리 모듈의 C 함수라도 소스 해시로는 바이너리 동일성을 못 얻는다
    --   (컴파일러·플래그·헤더·링크 라이브러리·ABI가 manifest 밖에 있다).
    INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance, evidence)
    SELECT mask_id, c.cap, c.cl::ipguard_claim, c.asr::ipguard_assurance, c.ev
      FROM ipguard_mask_instance, (VALUES
        ('determinism',      'holds',  'trusted_provider', '입력 무관 상수. IMMUTABLE 선언'),
        ('null_equivalence', 'holds',  'trusted_provider', 'PG_ARGISNULL 이면 NULL, 아니면 non-NULL'),
        ('equality_factor',  'fails',  'trusted_provider', '모든 값이 같은 마스크로 간다'),
        ('order_factor',     'fails',  'trusted_provider', '상수는 순서를 뭉갠다'),
        ('total',            'holds',  'trusted_provider', '정의역 전체에서 오류 없음')
      ) c(cap, cl, asr, ev)
     WHERE func = 'ipguard_mask(anyelement,text)'::regprocedure;
    """)
    mid = mid0
    for cap, want in [("determinism", "holds"), ("null_equivalence", "holds"),
                      ("equality_factor", "fails"), ("order_factor", "fails")]:
        check("A", f"ipguard_mask.{cap}",
              one(f"SELECT ipguard_capability({mid}, '{cap}')"), want)
    check("A", "ipguard_mask.total", one(f"SELECT ipguard_capability({mid}, 'total')"),
          "holds")
    # ★ 같은 마스크 안에서 holds / fails / unknown 셋이 **동시에** 나와야 한다.
    #   fails 를 unknown 으로 뭉개면 "아직 인증 안 됨" 과 "성립하지 않음이
    #   확인됨" 이 구별되지 않는다 -- 전자는 나중에 수락 가능하고 후자는 아니다.
    check("A", "★ 한 마스크에 holds/fails/unknown 이 공존한다",
          one(f"""SELECT string_agg(v, ',' ORDER BY v) FROM (
                    SELECT DISTINCT ipguard_capability({mid}, c)::text AS v
                      FROM unnest(ARRAY['determinism','equality_factor',
                                        'no_such_capability']) c) z"""),
          "fails,holds,unknown")
    return mid


# ---------------------------------------------------------------- B
def group_b():
    print("\nB. 미등록 UDF — 기본값이 unknown 이어야 한다")
    print("   어떤 규칙도 unknown 에 의존할 수 없다. 등록 안 한 것이 조용히")
    print("   '안전' 으로 읽히면 레지스트리가 있으나 마나다.")
    mid = one("SELECT ipguard_register_mask('h5.reg_unreg(text)'::regprocedure,"
              " 'text'::regtype, 'text'::regtype)")
    for cap in ("determinism", "null_equivalence", "equality_factor",
                "order_factor", "total"):
        check("B", f"미등록 UDF.{cap}",
              one(f"SELECT ipguard_capability({mid}, '{cap}')"), "unknown")
    check("B", "아예 없는 mask_id",
          one("SELECT ipguard_capability(999999, 'determinism')"), "unknown")
    return mid


# ---------------------------------------------------------------- C
def group_c():
    print("\nC. CREATE OR REPLACE — 같은 OID 인데 구현이 바뀐다")
    print("   ★ 이게 impl_version 을 관리자 문자열로 두면 안 되는 이유다.")
    print("   OID·인자·타입·collation 이 전부 그대로라 키로는 구별되지 않는다.")
    psql("""
    SELECT ipguard_register_mask('h5.reg_udf(text)'::regprocedure,
                                 'text'::regtype, 'text'::regtype);
    INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
    SELECT mask_id, 'determinism', 'holds', 'trusted_assumption'
      FROM ipguard_mask_instance WHERE func = 'h5.reg_udf(text)'::regprocedure;
    """)
    mid = one("SELECT mask_id FROM ipguard_mask_instance "
              "WHERE func = 'h5.reg_udf(text)'::regprocedure")
    oid_before = one("SELECT 'h5.reg_udf(text)'::regprocedure::oid::text")
    check("C", "교체 전 claim", one(f"SELECT ipguard_capability({mid}, 'determinism')"),
          "holds")

    psql("""CREATE OR REPLACE FUNCTION h5.reg_udf(x text) RETURNS text
            LANGUAGE sql IMMUTABLE AS $f$ SELECT 'CHANGED' $f$;""")
    oid_after = one("SELECT 'h5.reg_udf(text)'::regprocedure::oid::text")
    check("C", "OID 는 그대로다 (그래서 키로 못 잡는다)",
          "same" if oid_before == oid_after else "changed", "same")
    check("C", "교체 후 claim (지문 불일치 -> 무효)",
          one(f"SELECT ipguard_capability({mid}, 'determinism')"), "unknown")
    check("C", "감사에 잡히는가",
          one(f"SELECT count(*)::text FROM ipguard_audit_registry() "
              f"WHERE mid = {mid} AND problem LIKE '지문 불일치%'"), "1")

    # 휘발성만 바꿔도 잡혀야 한다 -- prosrc 만 보면 놓친다
    psql("""CREATE OR REPLACE FUNCTION h5.reg_udf(x text) RETURNS text
            LANGUAGE sql IMMUTABLE AS $f$ SELECT 'CHANGED' $f$;""")
    psql(f"""UPDATE ipguard_mask_instance SET impl_fingerprint =
             (SELECT fingerprint FROM ipguard_fingerprint(func, collation_name))
             WHERE mask_id = {mid};""")
    check("C", "지문 재등록 후 claim 복구",
          one(f"SELECT ipguard_capability({mid}, 'determinism')"), "holds")
    psql("""CREATE OR REPLACE FUNCTION h5.reg_udf(x text) RETURNS text
            LANGUAGE sql VOLATILE AS $f$ SELECT 'CHANGED' $f$;""")
    check("C", "본문 그대로, IMMUTABLE->VOLATILE 만 바꿔도 무효",
          one(f"SELECT ipguard_capability({mid}, 'determinism')"), "unknown")

    # proved_builtin 은 지문이 완전할 때만
    err = one(f"""INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
                  VALUES ({mid}, 'total', 'holds', 'proved_builtin')""")
    check("C", "지문 불완전(src)에 proved_builtin 은 거부",
          "rejected" if err.startswith("ERR") else "accepted", "rejected")
    return mid


# ---------------------------------------------------------------- D
def group_d():
    print("\nD. 인증서 철회 — 이미 만든 generic plan 까지 닿는가")
    print("   ★ Y07 과 같은 구멍이다. 철회해도 캐시된 계획이 살아 있으면")
    print("   커넥션 풀에서 몇 시간씩 옛 판정으로 돈다.")
    # 한 세션 안에서 해야 generic plan 이 유지된다.
    script = r"""
SET client_min_messages = warning;
SET ipguard.enforce = on;
SET search_path = h5, public;
PREPARE p AS SELECT ssn FROM h5.cust WHERE id = $1;
EXECUTE p(1); EXECUTE p(2); EXECUTE p(3);
EXECUTE p(4); EXECUTE p(5); EXECUTE p(6);
-- 여기서 PostgreSQL 은 generic plan 으로 전환돼 있다
SELECT 'e0=' || ipguard_registry_epoch();
SELECT 'c0=' || ipguard_pii_plan_count();
EXECUTE p(7);
SELECT 'c1=' || ipguard_pii_plan_count();     -- 재계획 없음 -> c1 = c0
UPDATE ipguard_mask_capability SET claim='unknown', assurance='unknown'
 WHERE capability='determinism';
SELECT 'e1=' || ipguard_registry_epoch();
EXECUTE p(8);
SELECT 'c2=' || ipguard_pii_plan_count();     -- 캐시 비워짐 -> c2 = c1 + 1
DEALLOCATE p;
"""
    r = psql(script)
    kv = dict(l.split("=") for l in r.stdout.splitlines() if "=" in l and l[0] in "ec")
    if len(kv) < 5:
        print("     !! 측정 실패:", r.stderr.strip().splitlines()[:1])
        RESULTS.append(("D", "epoch/replan 측정", "FAIL", "5 values", False))
        return
    e0, e1 = int(kv["e0"]), int(kv["e1"])
    c0, c1, c2 = int(kv["c0"]), int(kv["c1"]), int(kv["c2"])
    check("D", "레지스트리 쓰기가 epoch 를 올린다",
          "bumped" if e1 > e0 else f"{e0}->{e1}", "bumped")
    check("D", "철회 전 EXECUTE 는 재계획하지 않는다 (generic plan)",
          f"+{c1 - c0}", "+0")
    check("D", "★ 철회 후 EXECUTE 는 재계획한다",
          f"+{c2 - c1}", "+1")
    print("     ↑ 게이트가 레지스트리를 **읽도록** 연결하는 것은 §11-4 다.")
    print("       여기서 확인한 것은 '철회가 캐시된 계획까지 닿는다' 는 기전이고,")
    print("       '그래서 거부된다' 는 아직 주장하지 않는다.")


# ---------------------------------------------------------------- E
def group_e():
    print("\nE. 호환성 — 등록된 **조합**만 holds")
    print("   arg_signature 를 키에 넣지 않으면 substr(x,1,2) 의 인증서가")
    print("   substr(x,1,3) 으로 번진다. 검증 안 된 인자로 번지는 것이 위험하다.")
    psql("""
    INSERT INTO ipguard_mask_function_compatibility
      (mask_id, func, arg_signature, out_redactor, collation_name,
       func_fingerprint, red_fingerprint, claim, assurance, evidence)
    SELECT i.mask_id, 'substr(text,int,int)'::regprocedure, '1,2',
           'h5.reg_redact(text)'::regprocedure, '',
           (SELECT fingerprint FROM ipguard_fingerprint('substr(text,int,int)'::regprocedure)),
           (SELECT fingerprint FROM ipguard_fingerprint('h5.reg_redact(text)'::regprocedure)),
           'holds', 'trusted_assumption',
           'substr(mask(x),1,2) = r_out(substr(x,1,2)) -- 상수 마스크 + 길이보존 redactor'
      FROM ipguard_mask_instance i
     WHERE i.func = 'ipguard_mask(anyelement,text)'::regprocedure;
    """)
    mid = one("SELECT mask_id FROM ipguard_mask_instance "
              "WHERE func = 'ipguard_mask(anyelement,text)'::regprocedure")
    Q = ("SELECT ipguard_function_compatible({m}, 'substr(text,int,int)'::regprocedure,"
         " '{a}', {r}, '{c}')")
    R = "'h5.reg_redact(text)'::regprocedure"
    R2 = "'h5.reg_redact2(text)'::regprocedure"
    check("E", "등록된 조합 (args=1,2 / redact / 기본 collation)",
          one(Q.format(m=mid, a="1,2", r=R, c="")), "holds")
    check("E", "다른 인자 (1,3)", one(Q.format(m=mid, a="1,3", r=R, c="")), "unknown")
    check("E", "다른 redactor", one(Q.format(m=mid, a="1,2", r=R2, c="")), "unknown")
    check("E", "다른 collation (C)", one(Q.format(m=mid, a="1,2", r=R, c="C")), "unknown")
    check("E", "미등록 함수 (upper)",
          one(f"SELECT ipguard_function_compatible({mid},"
              f" 'upper(text)'::regprocedure, '', {R}, '')"), "unknown")
    # 대상 함수가 바뀌면 조합 인증서도 무효
    psql("""CREATE OR REPLACE FUNCTION h5.reg_redact(x text) RETURNS text
            LANGUAGE sql IMMUTABLE AS $f$ SELECT 'DIFFERENT' $f$;""")
    check("E", "★ redactor 를 바꾸면 조합 인증서도 무효",
          one(Q.format(m=mid, a="1,2", r=R, c="")), "unknown")

    # 집계: count(x) 와 count(DISTINCT x) 는 다른 주장이다
    psql("""
    INSERT INTO ipguard_mask_aggregate_compatibility
      (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name,
       agg_fingerprint, red_fingerprint, claim, assurance, evidence)
    SELECT i.mask_id, 'count("any")'::regprocedure, false, false,
           'h5.reg_redact2(text)'::regprocedure, '',
           (SELECT fingerprint FROM ipguard_fingerprint('count("any")'::regprocedure)),
           (SELECT fingerprint FROM ipguard_fingerprint('h5.reg_redact2(text)'::regprocedure)),
           'holds', 'trusted_assumption', 'count(x) 는 값을 안 본다'
      FROM ipguard_mask_instance i
     WHERE i.func = 'ipguard_mask(anyelement,text)'::regprocedure;
    """)
    # ★ count 의 시그니처는 count("any") 다 -- count(anyelement) 는 없다.
    A = ("""SELECT ipguard_aggregate_compatible({m}, 'count("any")'::regprocedure,"""
         " {d}, false, {r}, '')")
    check("E", "count(x) — null_equivalence=holds 인 상수 마스크",
          one(A.format(m=mid, d="false", r=R2)), "holds")
    # ★ 상수 마스크는 equality_factor 가 **fails** 다. 그러면 count(DISTINCT x)
    #   는 등록 여부와 무관하게 성립할 수 없다 -- unknown("아직 인증 안 됨")이
    #   아니라 fails("영원히 불가")여야 한다. 전제를 등록 조회보다 **먼저**
    #   보게 고친 뒤 이 값이 unknown 에서 fails 로 바뀌었다.
    check("E", "★ count(DISTINCT x): EQ 가 fails 라 fails (unknown 아님)",
          one(A.format(m=mid, d="true", r=R2)), "fails")

    # ------------------------------------------------------------------
    # ★ 음성 대조군: 잘못 등록된 인증서가 null_equivalence 의무를 우회하는가
    #
    # count(x) 는 **non-NULL 값을 센다.** 마스크가 non-NULL 을 NULL 로 바꾸면
    # (numeric_mask=nullify) 결과가 바뀐다 -- 5R 에서 실측한
    # count(*) FILTER (WHERE salary IS NOT NULL) 1000 -> 0 이 정확히 이것이다.
    #
    # 그래서 같은 함수의 **다른 MaskInstance** 를 null_equivalence=fails 로
    # 등록하고, count 인증서는 holds 로 (잘못) 등록한다. 조회 API 가 강제
    # 전제를 AND 하지 않으면 여기서 holds 가 나오고 의무가 뚫린다.
    print("\n   ── 음성 대조군: 잘못 등록된 인증서가 의무를 우회하는가 ──")
    nid = one("""SELECT ipguard_register_mask(
                   'ipguard_mask(anyelement,text)'::regprocedure,
                   'numeric'::regtype, 'numeric'::regtype,
                   'numeric_mask=nullify', '', 'NULL 로 가리는 변형')""")
    psql(f"""
    INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance, evidence)
    VALUES ({nid}, 'null_equivalence', 'fails', 'trusted_provider',
            'non-NULL 입력이 NULL 이 된다 -- 명세 §7'),
           ({nid}, 'equality_factor', 'fails', 'trusted_provider', '상수'),
           ({nid}, 'determinism', 'holds', 'trusted_provider', '상수');
    -- ★ 여기서 count -> holds 를 **일부러 잘못** 등록한다.
    INSERT INTO ipguard_mask_aggregate_compatibility
      (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name,
       agg_fingerprint, red_fingerprint, claim, assurance, evidence)
    VALUES ({nid}, 'count("any")'::regprocedure, false, false,
            'h5.reg_redact2(text)'::regprocedure, '',
            (SELECT fingerprint FROM ipguard_fingerprint('count("any")'::regprocedure)),
            (SELECT fingerprint FROM ipguard_fingerprint('h5.reg_redact2(text)'::regprocedure)),
            'holds', 'trusted_assumption', '잘못된 등록 -- 의무를 우회하려 한다');
    """)
    check("E", "★ nullify 마스크: count(x) 는 fails (등록은 holds 인데도)",
          one(A.format(m=nid, d="false", r=R2)), "fails")
    check("E", "   전제 자체는 fails 로 조회된다",
          one(f"SELECT ipguard_capability({nid}, 'null_equivalence')"), "fails")
    check("E", "★ nullify + DISTINCT: EQ 도 fails 라 fails",
          one(A.format(m=nid, d="true", r=R2)), "fails")
    # count(*) 는 민감 인자가 없다 -- 애초에 조회 대상이 아니다
    check("E", "count(*) 는 시그니처가 다르다 (인자 없음) -> 조회 불가",
          one(f"SELECT ipguard_aggregate_compatible({nid}, 'count()'::regprocedure,"
              f" false, false, {R2}, '')"), "unknown")
    # EQ 인증이 unknown 인 마스크로 DISTINCT
    uid = one("""SELECT ipguard_register_mask('h5.reg_udf(text)'::regprocedure,
                   'text'::regtype, 'text'::regtype, 'eq-unknown')""")
    psql(f"""
    INSERT INTO ipguard_mask_aggregate_compatibility
      (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name,
       agg_fingerprint, red_fingerprint, claim, assurance)
    VALUES ({uid}, 'count("any")'::regprocedure, true, false,
            'h5.reg_redact2(text)'::regprocedure, '',
            (SELECT fingerprint FROM ipguard_fingerprint('count("any")'::regprocedure)),
            (SELECT fingerprint FROM ipguard_fingerprint('h5.reg_redact2(text)'::regprocedure)),
            'holds', 'trusted_assumption');
    """)
    check("E", "★ EQ 인증이 없는 마스크로 count(DISTINCT x) -> unknown",
          one(A.format(m=uid, d="true", r=R2)), "unknown")


# ---------------------------------------------------------------- F
class Session:
    """살아 있는 psql 백엔드 하나. **다른 프로세스**여야 의미가 있다.

    D 그룹은 한 세션 안에서 쟀으므로 local invalidation 만 확인한 것이다.
    커넥션 풀에서 실제로 일어나는 일은 **A 가 계획을 들고 있는 동안 B 가
    철회**하는 것이고, 그건 프로세스 간 무효화 방송이 닿아야 잡힌다.
    """

    def __init__(self, name):
        self.name = name
        self.p = subprocess.Popen(
            ["psql", "-d", "ipdev", "-At", "-q"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT, text=True, bufsize=1)

    def run(self, sql):
        """SQL 을 보내고 sentinel 까지 읽는다."""
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


PREP = """
SET plan_cache_mode = force_generic_plan;
SET ipguard.enforce = on;
SET search_path = h5, public;
PREPARE p AS SELECT ssn FROM h5.cust WHERE id = $1;
EXECUTE p(1)
"""


def group_f():
    print("\nF. ★ cross-backend — 다른 세션의 철회가 내 generic plan 까지 닿는가")
    print("   D 는 같은 세션이라 local invalidation 만 확인한 것이다. 커넥션")
    print("   풀에서 실제로 일어나는 일은 A 가 계획을 들고 있는 동안 B 가")
    print("   철회하는 것이고, 그건 프로세스 간 방송이 닿아야 잡힌다.")

    A1, A2, A3 = Session("A1"), Session("A2"), Session("A3")
    B = Session("B")
    try:
        # ★ 철회 대상을 **한 인스턴스로 한정**한다. capability 이름만으로
        #   UPDATE 하면 reg_xsess 를 포함한 모든 마스크의 claim 이 같이
        #   지워져, 뒤의 (3) 대조군이 무의미해진다(실제로 처음에 그랬다).
        target = B.val("SELECT mask_id FROM ipguard_mask_instance "
                       "WHERE func = 'ipguard_mask(anyelement,text)'::regprocedure "
                       "ORDER BY mask_id LIMIT 1")
        REVOKE = ("UPDATE ipguard_mask_capability SET claim='unknown', "
                  f"assurance='unknown' WHERE capability='determinism' "
                  f"AND mask_id = {target}")
        # D 가 이미 전역으로 철회해 뒀다. F 는 자기 상태를 스스로 세운다 --
        # 앞 그룹의 부작용에 기대면 순서를 바꾸는 순간 조용히 틀린다.
        B.run(f"""INSERT INTO ipguard_mask_capability
                    (mask_id, capability, claim, assurance)
                  VALUES ({target}, 'determinism', 'holds', 'trusted_provider')
                  ON CONFLICT (mask_id, capability) DO UPDATE
                    SET claim='holds', assurance='trusted_provider'""")

        # 상태를 세운 **뒤에** 계획을 잡는다. 순서를 바꾸면 이 쓰기가
        # 곧바로 계획을 무효화해 기준선이 오염된다.
        for s in (A1, A2, A3):
            s.run(PREP)
        c0 = {s.name: int(s.val("SELECT ipguard_pii_plan_count()"))
              for s in (A1, A2, A3)}

        # (1) B 가 ROLLBACK 하면 무효화가 방송되지 않아야 한다
        B.run("BEGIN")
        B.run(REVOKE)
        B.run("ROLLBACK")
        A1.run("EXECUTE p(2)")
        c_rb = int(A1.val("SELECT ipguard_pii_plan_count()"))
        check("F", "B 가 ROLLBACK 하면 A 는 재계획하지 않는다",
              f"+{c_rb - c0['A1']}", "+0")
        check("F", "   ROLLBACK 후 인증서는 계속 유효",
              A1.val(f"SELECT ipguard_capability({target}, 'determinism')"), "holds")

        # (2) B 가 COMMIT 하면 A 세션 **전부** 재계획해야 한다
        B.run("BEGIN")
        B.run(REVOKE)
        B.run("COMMIT")
        for s, base in ((A1, c_rb), (A2, c0["A2"]), (A3, c0["A3"])):
            s.run("EXECUTE p(3)")
            c = int(s.val("SELECT ipguard_pii_plan_count()"))
            check("F", f"★ B 의 COMMIT 이 {s.name} 의 generic plan 을 무효화한다",
                  f"+{c - base}", "+1")

        # (3) 다른 세션의 CREATE OR REPLACE 가 A 에게 보이는가
        mid = B.val("SELECT mask_id FROM ipguard_mask_instance "
                    "WHERE func = 'h5.reg_xsess(text)'::regprocedure")
        check("F", "교체 전 A 가 보는 claim",
              A1.val(f"SELECT ipguard_capability({mid}, 'determinism')"), "holds")
        B.run("""CREATE OR REPLACE FUNCTION h5.reg_xsess(x text) RETURNS text
                 LANGUAGE sql IMMUTABLE AS $f$ SELECT 'XSESS' $f$""")
        check("F", "★ 다른 세션의 CREATE OR REPLACE 를 A 가 본다",
              A1.val(f"SELECT ipguard_capability({mid}, 'determinism')"), "unknown")

        # (4) provider 지문(빌드 식별자) 변경 -- 재빌드 없이 시뮬레이션한다
        B.run("UPDATE ipguard_mask_instance SET impl_fingerprint = 'STALE' "
              "WHERE func = 'ipguard_mask(anyelement,text)'::regprocedure")
        cmid = A1.val("SELECT mask_id FROM ipguard_mask_instance "
                      "WHERE func = 'ipguard_mask(anyelement,text)'::regprocedure")
        check("F", "provider 지문이 어긋나면 A 도 unknown",
              A1.val(f"SELECT ipguard_capability({cmid}, 'determinism')"), "unknown")
    finally:
        for s in (A1, A2, A3, B):
            s.close()


def main():
    print("=" * 78)
    print("레지스트리 단독 회귀 — effect 분석과 연결하기 **전**")
    print("=" * 78)
    psql(SETUP)
    try:
        group_a()
        group_b()
        group_c()
        group_d()
        group_e()
        # F 는 살아 있는 백엔드 여러 개가 필요하다. 등록을 먼저 해 둔다.
        psql('''
        INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
        SELECT ipguard_register_mask('h5.reg_xsess(text)'::regprocedure,
               'text'::regtype, 'text'::regtype),
               'determinism', 'holds', 'trusted_assumption';
        ''')
        group_f()
    finally:
        psql(TEARDOWN)

    print("\n" + "=" * 78)
    ok = sum(1 for *_, o in RESULTS if o)
    for g in ("A", "B", "C", "D", "E", "F"):
        rows = [r for r in RESULTS if r[0] == g]
        if rows:
            print(f"  {g}: {sum(1 for r in rows if r[4])}/{len(rows)}")
    print("-" * 78)
    print(f"  합계 {ok}/{len(RESULTS)}")
    fails = [(g, n, got, want) for g, n, got, want, o in RESULTS if not o]
    if fails:
        print("\n  실패:")
        for g, n, got, want in fails:
            print(f"    [{g}] {n}: {got}  (기대 {want})")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
