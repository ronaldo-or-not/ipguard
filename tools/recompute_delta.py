#!/usr/bin/env python3
"""δ matrix 재계산 — attempt 1 의 oracle 결함 교정.

attempt 1 의 δ 오라클은 술어에 `$1` 이 있으면 측정을 건너뛰고
`delta_equivalent = True` 로 **가정**했다. θ binding 은 하네스가 고정으로
알고 있었으므로 측정 가능했다. 여기서는 θ 를 치환한 뒤 실제로 잰다.

게이트는 다시 돌리지 않는다. attempt 1 이 보존한 result_d1 / result_d2 를
그대로 쓰고 **oracle label 만** 교정한다. 따라서 이것은 재실행이 아니라
보존된 raw 위에서의 사후 판정이다.
"""
import json
import sys

sys.path.insert(0, "tools")
from run_heldout import PK, load, psql, where_of  # noqa: E402

BIND = {"text": "'x'", "date": "DATE '1990-01-01'", "int": "1"}


def bind(s, params):
    for pm in params:
        s = s.replace("$%d" % pm["n"], BIND[pm["type"]])
    return s


def traces(table, preds):
    """한 번 적재된 상태에서 여러 술어의 δ 를 한 세션으로 잰다."""
    parts = ["SET search_path=h5,public; SET ipguard.enforce=off;"]
    for qid, pred in preds:
        parts.append(f"\\echo T:{qid}")
        parts.append(f"SELECT 'D:'||{PK[table]}||'='||"
                     f"coalesce(({pred})::text,'NULL') FROM h5.{table} "
                     f"ORDER BY {PK[table]};")
    r = psql("\n".join(parts))
    out, cur, buf = {}, None, []
    for line in r.stdout.splitlines():
        if line.startswith("T:"):
            if cur:
                out[cur] = "|".join(sorted(buf))
            cur, buf = line[2:], []
        elif line.startswith("D:") and cur:
            buf.append(line[2:])
    if cur:
        out[cur] = "|".join(sorted(buf))
    return out


def main():
    body = json.load(open("corpus/heldout.json"))
    queries, pairs = body["queries"], body["db_pairs"]
    delta = {}
    for pt in body["pair_types"]:
        for tb in sorted({q["table"] for q in queries}):
            preds, nopred = [], []
            for q in [x for x in queries if x["table"] == tb]:
                p = where_of(q["sql"])
                if p is None:
                    nopred.append(q["id"])
                else:
                    preds.append((q["id"], bind(p, q.get("params", []))))
            side = {}
            for s in ("d1", "d2"):
                psql(load(tb, pairs[pt][tb][s]))
                side[s] = traces(tb, preds)
            for qid, _ in preds:
                t1, t2 = side["d1"].get(qid), side["d2"].get(qid)
                delta[f"{qid}/{pt}"] = {
                    "delta_equivalent": t1 == t2 and t1 is not None,
                    "measured": t1 is not None and t2 is not None}
            for qid in nopred:
                delta[f"{qid}/{pt}"] = {"delta_equivalent": True,
                                        "measured": True,
                                        "reason": "술어 없음"}
            print(f"  {pt}/{tb}: 술어 {len(preds)}건 + 무술어 {len(nopred)}건")
    json.dump(delta, open("out/delta-v2.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    de = sum(1 for v in delta.values() if v["delta_equivalent"])
    nm = sum(1 for v in delta.values() if not v["measured"])
    print(f"δ-equivalent {de}/{len(delta)}   미측정 {nm}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
