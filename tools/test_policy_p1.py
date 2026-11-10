#!/usr/bin/env python3
"""PD1 회귀 — 발급이 **정확한 source 에만** 나가는가.

PD1 은 개수로는 안 잡힌다. 같은 개수로 **다른 컬럼**에 설치됐기 때문이다.
그래서 다음 넷을 본다.

  1. birth 술어에서 나온 인증서가 ssn 에 설치되지 않는다
  2. manifest 의 대상 컬럼 집합 == obligation 의 ordered_sources 합집합
  3. 설치 후 DB 행 집합 == manifest (집합 동치, 개수 동치가 아니다)
  4. 옛 발급기(테이블의 라벨 컬럼 전부 순회)는 이 검사를 통과하지 못한다

사용: python3 tools/test_policy_p1.py
"""
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from policy_p1 import (issue, install_sql, manifest_digest,  # noqa: E402
                       installed_rows, key_of, psql, verify)

SETUP = r"""
SET client_min_messages = warning;
SET search_path = h5, public;
DROP TABLE IF EXISTS h5.pd_t;
CREATE TABLE h5.pd_t (id int PRIMARY KEY, a text, b date, c int);
INSERT INTO h5.pd_t VALUES (1,'x',DATE '1980-01-01',5),(2,'y',DATE '2000-01-01',7);
DELETE FROM h5.pii_label WHERE relname = 'pd_t';
INSERT INTO h5.pii_label VALUES ('pd_t','a','pdsec'),('pd_t','b','pddate');
DELETE FROM ipguard_declassification WHERE relid = 'h5.pd_t'::regclass;
DELETE FROM ipguard_mask_instance WHERE normalized_args IN ('kind=pdsec','kind=pddate');
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       'text'::regtype, 'text'::regtype, 'kind=pdsec', '', 'PD1 회귀');
"""

TEARDOWN = r"""
SET client_min_messages = warning;
DROP TABLE IF EXISTS h5.pd_t;
DELETE FROM h5.pii_label WHERE relname = 'pd_t';
DELETE FROM ipguard_mask_instance WHERE normalized_args IN ('kind=pdsec','kind=pddate');
"""

RESULTS = []


def check(name, got, want):
    ok = got == want
    RESULTS.append(ok)
    print(f"  {'✓' if ok else '✗'} {name:58} {str(got):<22} (기대 {want})")
    return ok


def obligations(sql):
    r = psql("SET search_path=h5,public;\n"
             "SELECT 'O:'||effect||E'\\t'||sink||E'\\t'||context||E'\\t'"
             "||context_key||E'\\t'||context_canonical||E'\\t'"
             "||ordered_sources::text||E'\\t'||fail_kind "
             f"FROM ipguard_obligations($ipg${sql}$ipg$);")
    out = []
    for l in r.stdout.splitlines():
        if not l.startswith("O:"):
            continue
        f = l[2:].split("\t")
        out.append({"effect": f[0], "sink": f[1], "context": f[2],
                    "context_key": f[3], "canonical": f[4],
                    "ordered_sources": [x for x in
                                        f[5].strip("{}").split(",") if x],
                    "fail_kind": f[6]})
    return out


def relid(name="h5.pd_t"):
    r = psql(f"SELECT 'X:'||'{name}'::regclass::oid;")
    return int([l for l in r.stdout.splitlines() if l.startswith("X:")][0][2:])


def attnum(col):
    r = psql("SELECT 'X:'||attnum FROM pg_attribute "
             f"WHERE attrelid='h5.pd_t'::regclass AND attname='{col}';")
    return int([l for l in r.stdout.splitlines() if l.startswith("X:")][0][2:])


def main():
    print("=" * 78)
    print("PD1 회귀 — exact-source declassification 발급")
    print("=" * 78)
    psql(SETUP)
    try:
        rid, a_at, b_at = relid(), attnum("a"), attnum("b")

        # ---- birth(b) 술어 하나만 있는 질의 -------------------------------
        Q = "SELECT id FROM h5.pd_t WHERE b < DATE '1990-01-01'"
        obl = obligations(Q)
        card = [o for o in obl if o["effect"] == "CARD"]
        print(f"\n[1] `WHERE b < ...` 의 CARD obligation {len(card)}건")
        srcs = sorted({s for o in card for s in o["ordered_sources"]})
        check("ordered_sources 가 b 하나뿐", srcs, [f"{rid}.{b_at}"])
        check("a(다른 라벨 컬럼)는 들어 있지 않다",
              f"{rid}.{a_at}" in srcs, False)

        rows, skipped = issue({"Q": obl}, {})
        print(f"\n[2] 발급 {len(rows)}행  digest {manifest_digest(rows)[:16]}")
        cols = sorted({f"{r['relid']}.{r['attnum']}" for r in rows})
        check("★ manifest 대상 컬럼 == ordered_sources", cols, [f"{rid}.{b_at}"])
        check("   행 수 == CARD obligation 수", len(rows), len(card))
        check("   전부 effect=CARD", sorted({r["effect"] for r in rows}),
              ["CARD"])
        check("   param 없는 질의는 param_scope=none",
              sorted({r["param_scope"] for r in rows}), ["none"])

        # ---- 설치하고 집합 동치를 확인 -----------------------------------
        psql("DELETE FROM ipguard_declassification "
             "WHERE relid='h5.pd_t'::regclass;")
        psql(install_sql(rows))
        v = verify(rows, [rid])
        print(f"\n[3] 설치 검증")
        check("★ 설치 행 집합 == manifest", v["ok"], True)
        check("   누락 0", v["n_missing"], 0)
        check("   초과 0", v["n_extra"], 0)
        got_cols = sorted({f"{r['relid']}.{r['attnum']}"
                           for r in installed_rows([rid])})
        check("★ DB 에도 b 만 설치됐다", got_cols, [f"{rid}.{b_at}"])

        # ---- 옛 발급기를 재현해 검사가 실제로 잡는지 본다 ------------------
        print(f"\n[4] ★ 옛 발급기(라벨 컬럼 전부 순회) 재현 — 검사가 잡는가")
        old = []
        for r in rows:
            for at in (a_at, b_at):          # PD1 이 하던 그대로
                o = dict(r)
                o["attnum"] = at
                old.append(o)
        psql("DELETE FROM ipguard_declassification "
             "WHERE relid='h5.pd_t'::regclass;")
        psql(install_sql(old))
        v2 = verify(rows, [rid])
        check("★ manifest 대조가 초과 설치를 잡는다", v2["ok"], False)
        check("   초과분이 정확히 a 컬럼 수만큼", v2["n_extra"], len(rows))
        check("   digest 도 달라진다",
              manifest_digest(old) == manifest_digest(rows), False)

        # ---- 두 라벨 컬럼이 **함께** 술어에 나오면 둘 다 발급되어야 한다 ----
        print(f"\n[5] 두 컬럼이 함께 술어에 나오면 둘 다 발급")
        Q2 = ("SELECT id FROM h5.pd_t "
              "WHERE b < DATE '1990-01-01' AND a = 'x'")
        rows2, _ = issue({"Q2": obligations(Q2)}, {})
        cols2 = sorted({f"{r['relid']}.{r['attnum']}" for r in rows2})
        check("대상 컬럼 == {a, b}", cols2,
              sorted([f"{rid}.{a_at}", f"{rid}.{b_at}"]))

        # ---- VAL/EQ/ORD 는 어떤 경우에도 발급하지 않는다 -------------------
        print(f"\n[6] CARD 외 effect 는 발급하지 않는다")
        rows3, sk3 = issue({"Q3": obligations(
            "SELECT DISTINCT a FROM h5.pd_t ORDER BY a")}, {})
        check("발급 0행", len(rows3), 0)
        check("effect 로 제외된 obligation 이 있다", sk3["effect"] > 0, True)
    finally:
        psql("DELETE FROM ipguard_declassification "
             "WHERE relid='h5.pd_t'::regclass;")
        psql(TEARDOWN)

    n, tot = sum(RESULTS), len(RESULTS)
    print("\n" + "=" * 78)
    print(f"  합계 {n}/{tot}")
    return 0 if n == tot else 1


if __name__ == "__main__":
    sys.exit(main())
