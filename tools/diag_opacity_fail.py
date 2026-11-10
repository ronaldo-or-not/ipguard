#!/usr/bin/env python3
"""opacity fail 11건 진단 — bug-discovery set 분석용.

측정만 한다. 게이트·정책·코퍼스를 건드리지 않는다.
핵심 질문 하나: 게이트가 수락한 이 질의들에서 D1/D2 출력 차이가
  (a) δ_Q(D1) ≠ δ_Q(D2)  -> declassification 범위 안 (opacity 위반 아님)
  (b) δ_Q(D1) = δ_Q(D2)  -> 진짜 scoped-opacity 위반
중 어느 쪽인가.
"""
import json
import subprocess
import sys

sys.path.insert(0, "tools")
from run_heldout import (PK, load, psql, where_of)  # noqa: E402

CASES = [("HO0037", ["eq_split", "null_structure"]),
         ("HO0088", ["eq_split", "null_structure", "ord_permutation"]),
         ("HO0183", ["eq_split", "null_structure", "ord_permutation"]),
         ("HO0362", ["eq_split", "null_structure", "ord_permutation"])]

# run_batch 가 실제로 쓴 θ binding (tools/run_heldout.py 와 동일)
BIND = {"text": "'x'", "date": "DATE '1990-01-01'", "int": "1"}


def bind(sql, params):
    for pm in params:
        sql = sql.replace("$%d" % pm["n"], BIND[pm["type"]])
    return sql


def trace(table, pred):
    """δ: (public row id, 3VL outcome) 정렬 목록. 술어를 θ로 치환한 뒤 잰다."""
    r = psql(f"SET search_path=h5,public; SET ipguard.enforce=off;\n"
             f"SELECT 'D:'||{PK[table]}||'='||"
             f"coalesce(({pred})::text,'NULL') FROM h5.{table} "
             f"ORDER BY {PK[table]};")
    return "|".join(sorted(l[2:] for l in r.stdout.splitlines()
                           if l.startswith("D:")))


def rows(sql):
    r = psql(f"SET search_path=h5,public; SET ipguard.enforce=off;\n"
             f"SELECT 'R:'||z::text FROM ({sql}) z;")
    return sorted(l[2:] for l in r.stdout.splitlines() if l.startswith("R:"))


def main():
    body = json.load(open("corpus/heldout.json"))
    byq = {q["id"]: q for q in body["queries"]}
    pairs = body["db_pairs"]
    out = []
    for qid, pts in CASES:
        q = byq[qid]
        tb = q["table"]
        bound = bind(" ".join(q["sql"].split()), q.get("params", []))
        pred_raw = where_of(q["sql"])
        pred = bind(pred_raw, q.get("params", [])) if pred_raw else None
        for pt in pts:
            psql(load(tb, pairs[pt][tb]["d1"]))
            t1, r1 = trace(tb, pred), rows(bound)
            psql(load(tb, pairs[pt][tb]["d2"]))
            t2, r2 = trace(tb, pred), rows(bound)
            rec = {"query_id": qid, "pair_type": pt, "table": tb,
                   "bound_sql": bound, "bound_pred": pred,
                   "delta_equivalent_measured": t1 == t2,
                   "rows_equal": r1 == r2,
                   "n_rows_d1": len(r1), "n_rows_d2": len(r2),
                   "delta_d1": t1, "delta_d2": t2,
                   "rows_only_d1": [x for x in r1 if x not in r2][:6],
                   "rows_only_d2": [x for x in r2 if x not in r1][:6]}
            out.append(rec)
            print(f"{qid:8} {pt:16} δ-equiv(측정)={t1 == t2!s:5} "
                  f"rows-equal={r1 == r2!s:5} n={len(r1)}/{len(r2)}")
    json.dump(out, open("out/diag-opacity.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    print()
    real = [r for r in out if r["delta_equivalent_measured"]
            and not r["rows_equal"]]
    print(f"δ 동치인데도 출력이 다른 trial = {len(real)}건  "
          f"<- 이것만 진짜 scoped-opacity 위반 후보")
    for r in real:
        print("   ", r["query_id"], r["pair_type"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
