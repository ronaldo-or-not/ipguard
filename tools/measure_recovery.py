#!/usr/bin/env python3
"""조건 1 — sink-erasure 회수를 **외부 작성 workload**(TPC-H)에서 측정한다.

감사 문서 §6 의 통과 조건 1:

    Q10/Q6' 류 sink-erasure 수락이 현실 workload 에서 유의미한 빈도인가.

우리 생성 코퍼스(held-out 400)에서는 **0/301** 이었다. 그러나 그 코퍼스는
우리 generator 산물이라 외부 확인이 필요하다. TPC-H 22문은 표준화 기구가
작성했고 우리가 이 목적을 위해 고르지 않았다.

설계 원칙:

  * release gate + profile v1. **control mask(ctl:*) 제외**, 실 마스크만.
  * P0 — query-specific certificate **0개**.
  * naive baseline 을 정규식이 아니라 **Query tree** 로 판정한다
    (`ipguard_label_positions`). 텍스트 정규식은 절 경계를 넘어 오분류했다:
    `WHERE grade=$1 GROUP BY ssn` 을 "WHERE 에 라벨" 로 셌다.
  * `F_core` 안/밖을 분리한다. 밖은 회수 논의 대상이 아니다.
  * 라벨링을 **두 가지**로 나눠 따로 보고한다. 하나만 쓰면 라벨 선택으로
    결과를 만들 수 있다.
  * 질의별 원시 판정을 전부 보존한다.

naive 규칙 (리뷰어 정의): 민감 컬럼이 EQ/ORD/CARD 위치에 있으면 거부.
`target`/`agg_arg` 만이면 수락한다 — 마스킹으로 처리하면 되는 자리다.

사용: python3 tools/measure_recovery.py corpus/tpch-queries.sql out-tpch/
"""
import collections
import json
import os
import re
import subprocess
import sys

# 위치 -> 순진한 규칙이 보는 effect 부류
POS_EFFECT = {
    "where": "CARD", "having": "CARD", "agg_filter": "CARD",
    "group_by": "EQ", "distinct": "EQ", "setop_dedup": "EQ",
    "agg_distinct": "EQ",
    "order_by": "ORD", "agg_order": "ORD",
    # 아래는 naive 가 거부 사유로 삼지 않는다
    "target": None, "agg_arg": None, "setop_all": None,
}

# 현실적 PII 라벨 — 고객·공급자 식별 정보. 조인 키는 공개로 둔다.
REALISTIC = [
    ("customer", "c_name", "pv_text"), ("customer", "c_address", "pv_text"),
    ("customer", "c_phone", "pv_text"), ("customer", "c_acctbal", "pv_num"),
    ("supplier", "s_name", "pv_text"), ("supplier", "s_address", "pv_text"),
    ("supplier", "s_phone", "pv_text"), ("supplier", "s_acctbal", "pv_num"),
]

# stress — 키가 아닌 **모든** 컬럼. 조인은 공개로 남겨 두어야 양쪽이
# 전부 거부로 붕괴하지 않는다.
KEYCOLS = re.compile(r"(key)$")


def psql(script, quiet=True):
    return subprocess.run(["psql", "-q", "-A", "-t", "-F", "|", "-d", "ipdev",
                           "-f", "-"], input=script, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


PRELUDE = "SET search_path = tpch, public;\nSET ipguard.label_schema='tpch';\n"


def split_queries(path):
    txt = open(path, encoding="utf-8").read()
    parts = re.split(r"^--\s*(Q\d+)\s*$", txt, flags=re.M)
    out = []
    for i in range(1, len(parts), 2):
        sql = parts[i + 1].strip()
        if sql.endswith(";"):
            sql = sql[:-1]
        out.append((parts[i], " ".join(sql.split())))
    return out


def all_columns():
    r = psql("SELECT 'C:'||c.relname||'|'||a.attname||'|'||"
             "format_type(a.atttypid,-1) "
             "FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
             "JOIN pg_attribute a ON a.attrelid=c.oid "
             "WHERE n.nspname='tpch' AND c.relkind='r' AND a.attnum>0 "
             "AND NOT a.attisdropped ORDER BY 1;")
    out = []
    for l in r.stdout.splitlines():
        if l.startswith("C:"):
            out.append(tuple(l[2:].split("|")))
    return out


def set_labels(rows):
    """(table, column, kind) 목록으로 라벨을 통째로 다시 세운다."""
    parts = [PRELUDE, "SET client_min_messages=warning;",
             "DELETE FROM tpch.pii_label;"]
    for t, c, k in rows:
        parts.append(f"INSERT INTO tpch.pii_label VALUES "
                     f"('{t}','{c}','{k}') ON CONFLICT DO NOTHING;")
    psql("\n".join(parts))


def positions(sql):
    r = psql(PRELUDE + "SET ipguard.enforce=off;\n"
             "SELECT 'P:'||pos_kind||'|'||depth||'|'||sources::text "
             f"FROM ipguard_label_positions($ipg${sql}$ipg$);")
    out = []
    for l in r.stdout.splitlines():
        if l.startswith("P:"):
            f = l[2:].split("|")
            out.append({"pos": f[0], "depth": int(f[1]),
                        "sources": [x for x in f[2].strip("{}").split(",")
                                    if x]})
    return out


def obligations(sql):
    r = psql(PRELUDE + "SET ipguard.enforce=off;\n"
             "SELECT 'O:'||effect||'|'||sink||'|'||split_part(context,' [',1) "
             f"FROM ipguard_obligations($ipg${sql}$ipg$);")
    return sorted({l[2:] for l in r.stdout.splitlines() if l.startswith("O:")})


def fragment(sql):
    """★ ipguard_fragment 는 boolean 이 아니라 **text** 를 돌려준다.
    빈 문자열이면 F_core 안, 아니면 밖인 사유 목록이다.
    처음에 't' 와 비교해 22/22 를 전부 '밖' 으로 셌다 -- 측정 도구 버그였다."""
    r = psql(PRELUDE + "SET ipguard.enforce=off;\n"
             f"SELECT 'F:'||ipguard_fragment($ipg${sql}$ipg$);")
    v = [l[2:] for l in r.stdout.splitlines() if l.startswith("F:")]
    return v[-1] if v else "?ERR"


def gate_verdict(sql):
    r = psql(PRELUDE + "SET ipguard.enforce=on;\nSET ipguard.gate=release;\n"
             "SET ipguard.on_divergence=allow;\n"
             f"EXPLAIN (COSTS OFF) {sql};")
    txt = r.stdout
    if "해소되지 않은 의무" in txt or "ERROR" in txt:
        det = [l for l in txt.splitlines() if "DETAIL" in l]
        code = next((c for c in ("OUTSIDE_CERTIFIED_FRAGMENT", "UNMODELED_EXPR",
                                 "CAPABILITY_FAILS", "MISSING_CERTIFICATE")
                     if c in txt), "OTHER")
        return "reject", code, (det[0][8:150] if det else
                                txt.strip().splitlines()[0][:150])
    return "accept", "", ""


def naive_verdict(pos):
    eff = {POS_EFFECT.get(p["pos"]) for p in pos if p["sources"]}
    eff.discard(None)
    return ("reject" if eff else "accept"), sorted(eff)


def run(tag, labels, queries, outdir):
    set_labels(labels)
    rows = []
    for qid, sql in queries:
        pos = positions(sql)
        frag = fragment(sql)
        nv, neff = naive_verdict(pos)
        gv, code, detail = gate_verdict(sql)
        rows.append({"tag": tag, "qid": qid, "fragment": frag,
                     "positions": sorted({p["pos"] for p in pos
                                          if p["sources"]}),
                     "naive_effects": neff, "naive": nv,
                     "gate": gv, "gate_code": code, "gate_detail": detail,
                     "obligations": obligations(sql),
                     "touches_label": bool(pos)})
    json.dump(rows, open(f"{outdir}/{tag}.json", "w"), ensure_ascii=False,
              indent=1, sort_keys=True)
    return rows


def report(tag, rows):
    inf = [r for r in rows if r["fragment"] == ""]
    outf = [r for r in rows if r["fragment"] != ""]
    print(f"\n{'=' * 74}\n[{tag}]  질의 {len(rows)}  "
          f"F_core 안 {len(inf)} / 밖 {len(outf)}\n{'=' * 74}")
    print(f"  라벨 접촉        : {sum(1 for r in rows if r['touches_label'])}")
    print(f"  naive 거부       : {sum(1 for r in rows if r['naive'] == 'reject')}")
    print(f"  게이트 거부      : {sum(1 for r in rows if r['gate'] == 'reject')}")
    rec = [r for r in inf if r["naive"] == "reject" and r["gate"] == "accept"]
    back = [r for r in inf if r["naive"] == "accept" and r["gate"] == "reject"]
    print(f"\n  ★ 회수 (F_core 안, naive 거부 ∧ 게이트 수락) : {len(rec)}"
          f"   {[r['qid'] for r in rec]}")
    print(f"  ★ 역행 (F_core 안, naive 수락 ∧ 게이트 거부) : {len(back)}"
          f"   {[r['qid'] for r in back]}")
    if back:
        c = collections.Counter(r["gate_code"] for r in back)
        print(f"      역행 사유: {dict(c)}")
    # sink-erasure: 라벨이 effect 위치에 있는데 그 effect obligation 이 없음
    er = []
    for r in inf:
        got = {o.split("|")[0] for o in r["obligations"]}
        for p in r["positions"]:
            e = POS_EFFECT.get(p)
            if e and e not in got:
                er.append((r["qid"], p, e))
    print(f"  ★ sink-erasure (effect 위치인데 obligation 미생성) : {len(er)}")
    for q, p, e in er[:8]:
        print(f"      {q}  {p} -> {e} 없음")
    oc = collections.Counter(r["fragment"][:40] for r in outf)
    print(f"\n  F_core 밖 {len(outf)}건: {[r['qid'] for r in outf]}")
    for k, v in oc.most_common(6):
        print(f"      {v:3}  {k}")
    return {"n": len(rows), "in_fcore": len(inf), "recovery": len(rec),
            "backward": len(back), "sink_erasure": len(er),
            "recovered": [r["qid"] for r in rec]}


def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    queries = split_queries(src)
    cols = all_columns()
    stress = [(t, c, "pv_num" if ty in ("integer", "numeric") else "pv_text")
              for t, c, ty in cols if not KEYCOLS.search(c)]
    print(f"질의 {len(queries)}  TPC-H 컬럼 {len(cols)}  "
          f"stress 라벨 {len(stress)}  현실 라벨 {len(REALISTIC)}")
    summ = {}
    for tag, labels in (("realistic", REALISTIC), ("stress", stress)):
        summ[tag] = report(tag, run(tag, labels, queries, outdir))
    json.dump(summ, open(f"{outdir}/summary.json", "w"), ensure_ascii=False,
              indent=1, sort_keys=True)
    print(f"\n{'=' * 74}")
    for tag, s in summ.items():
        print(f"  {tag:10} F_core {s['in_fcore']}/{s['n']}  "
              f"회수 {s['recovery']}  역행 {s['backward']}  "
              f"sink-erasure {s['sink_erasure']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
