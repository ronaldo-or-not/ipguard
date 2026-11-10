#!/usr/bin/env python3
"""§11-5 held-out 평가 — attempt 2 (runner-only 수정).

attempt 1 은 정상 종료했지만 **관측 함수 자체가 결함**이었다. 아래 셋만
고치고 게이트·정책·코퍼스·seed 는 손대지 않는다.

  H1  δ 오라클이 술어에 `$1` 이 있으면 측정을 건너뛰고 δ-equivalent 를
      True 로 가정했다. θ binding 은 하네스가 고정으로 알고 있었으므로
      측정 가능했다.  -> θ 를 치환한 뒤 실제로 잰다.

  H2  파라미터 질의와 비파라미터 질의에 **서로 다른 관측 함수**를 썼다.
      전자는 psql 원시 줄을 정렬해 해시, 후자는 md5(string_agg(z::text)).
      한 실험 안에 관측이 두 개면 두 집합의 수치를 비교할 수 없다.
      -> 두 경로 모두 동일한 관측 함수를 쓴다.

  H3  그 wrapper 의 `z::text` 는 whole-row composite cast 이고 F_core
      **밖**이다. 게이트는 검사 대상 질의가 아니라 wrapper 때문에
      fail-close 했다 (비파라미터 라벨접촉 264건 중 175건).
      -> wrapper 를 없애고 psql -q 의 튜플 줄을 직접 관측한다.

관측 함수 (attempt 2, 전 질의 공통):
    psql -q -A -t -F '|' 의 QSTART/QEND 사이 튜플 줄 목록.
    shape ∈ {order_by, order_limit} 이면 **순서 보존** 해시  (OrderedBag)
    그 외에는 정렬 후 해시                                    (Bag)
  순서 민감/둔감 선택은 코퍼스 metadata 의 shape 만 본다 — 게이트를
  쓰지 않으므로 oracle 독립성은 유지된다.

적재 스케줄은 δ 루프만 (pair_type, table, side) 당 1회로 바꾼다.
transaction/session 경계, registry 초기화 순서, plan_cache_mode 는
attempt 1 과 동일하게 둔다.
"""
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_heldout import (LABELED, PK, REGISTRY, SCHEMA,  # noqa: E402
                         check_masked_equiv, classify, install_certs, load,
                         oracle_class, p1_certificates, psql, raw_obligations,
                         where_of)

BIND = {"text": "'x'", "date": "DATE '1990-01-01'", "int": "1"}
ORDERED_SHAPES = {"order_by", "order_limit"}


def bind(s, params):
    for pm in params:
        s = s.replace("$%d" % pm["n"], BIND[pm["type"]])
    return s


def digest(obj):
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


# ---------------------------------------------------------------- 관측 함수
NOISE = ("psql:", "ERROR:", "DETAIL:", "HINT:", "CONTEXT:", "STATEMENT:",
         "LINE ", "  ", "^")


def observe(buf, ordered):
    """튜플 줄만 남겨 canonical 관측값을 만든다."""
    rows = [l for l in buf if l and not l.startswith(NOISE)]
    if not rows:
        return "(empty)"
    seq = rows if ordered else sorted(rows)
    return hashlib.md5("\n".join(seq).encode()).hexdigest()


def run_batch(queries, prelude):
    """한 세션. wrapper 없이 질의를 그대로 돌린다."""
    parts = ["\\set ON_ERROR_STOP 0", prelude]
    for q in queries:
        one = " ".join(q["sql"].split())
        parts.append(f"\\echo QSTART:{q['id']}")
        if "$1" in one:
            th = [BIND[pm["type"]] for pm in q.get("params", [])]
            parts.append(f"PREPARE hq AS {one};")
            parts.append(f"EXECUTE hq({','.join(th)});")
            parts.append("DEALLOCATE hq;")
        else:
            parts.append(f"{one};")
        parts.append(f"\\echo QEND:{q['id']}")
    r = subprocess.run(["psql", "-q", "-A", "-t", "-F", "|", "-d", "ipdev",
                        "-f", "-"],
                       input="\n".join(parts), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    byid = {q["id"]: q for q in queries}
    res, cur, buf = {}, None, []
    for line in r.stdout.splitlines():
        if line.startswith("QSTART:"):
            cur, buf = line[7:], []
        elif line.startswith("QEND:"):
            if cur:
                v = classify(buf)
                if v[0] == "accept":
                    v = ("accept",
                         observe(buf, byid[cur]["shape"] in ORDERED_SHAPES))
                res[cur] = v
            cur = None
        elif cur is not None:
            buf.append(line)
    return res


# ------------------------------------------------------- 규율 점검용 digest
def input_digest(queries, pair_types):
    """query id · SQL hash · pair · θ 의 전체 ordered list."""
    rows = []
    for pt in sorted(pair_types):
        for q in sorted(queries, key=lambda x: x["id"]):
            rows.append([q["id"],
                         hashlib.sha256(
                             " ".join(q["sql"].split()).encode()).hexdigest(),
                         pt,
                         json.dumps(q.get("params", []), sort_keys=True)])
    return rows, digest(rows)


def table_digest(table):
    r = psql(f"SET search_path=h5,public;\n"
             f"SELECT 'H:'||md5(string_agg(t::text,'|' ORDER BY {PK[table]}))"
             f" FROM h5.{table} t;")
    for l in r.stdout.splitlines():
        if l.startswith("H:"):
            return l[2:]
    return "?"


def traces(table, preds):
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
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    body = json.load(open(src))
    queries, pairs = body["queries"], body["db_pairs"]
    byq = {q["id"]: q for q in queries}

    print("=" * 78)
    print("§11-5 held-out 평가 — attempt 2 (runner-only 수정)")
    print("=" * 78)

    rows, idg = input_digest(queries, body["pair_types"])
    json.dump({"digest": idg, "n": len(rows), "rows": rows},
              open(f"{outdir}/input-list.json", "w"),
              ensure_ascii=False, indent=1)
    print(f"[0] 입력 ordered list {len(rows)}행  digest {idg[:16]}")

    psql(SCHEMA); psql(REGISTRY)
    print("[1] 스키마·registry 복원")

    appl, tdg = {}, {}
    for pt in body["pair_types"]:
        for tb in sorted(LABELED):
            d1, d2 = pairs[pt][tb]["d1"], pairs[pt][tb]["d2"]
            fails = check_masked_equiv(d1, d2, tb)
            appl[f"{pt}/{tb}"] = {"masked_equivalent": not fails,
                                  "failures": fails}
            for s in ("d1", "d2"):
                psql(load(tb, pairs[pt][tb][s]))
                tdg[f"{pt}/{tb}/{s}"] = table_digest(tb)
    json.dump(appl, open(f"{outdir}/applicability.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    json.dump(tdg, open(f"{outdir}/table-digests.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    ok_me = sum(1 for v in appl.values() if v["masked_equivalent"])
    print(f"[2] applicability digest {digest(appl)[:16]}  "
          f"masked-equivalent {ok_me}/{len(appl)}")
    print(f"    적재 table digest {digest(tdg)[:16]}  ({len(tdg)}개 상태)")

    def run_policy():
        trials = {}
        for pt in body["pair_types"]:
            for tb in sorted(LABELED):
                qs = [q for q in queries if q["table"] == tb]
                for side in ("d1", "d2"):
                    psql(load(tb, pairs[pt][tb][side]))
                    res = run_batch(qs, "SET search_path=h5,public;\n"
                                        "SET ipguard.enforce=on;\n"
                                        "SET ipguard.gate=release;\n"
                                        "SET ipguard.on_divergence=allow;")
                    for qid, v in res.items():
                        trials.setdefault((qid, pt), {})[side] = v
                psql(load(tb, pairs[pt][tb]["d1"]))
                pv = run_batch(qs, "SET search_path=h5,public;\n"
                                   "SET ipguard.enforce=off;")
                for qid, v in pv.items():
                    trials.setdefault((qid, pt), {})["priv"] = v
        return trials

    print("[3] P0 실행 중 …")
    p0 = run_policy()
    print(f"    trial {len(p0)}")

    psql(REGISTRY)
    print("[4] registry 재복원")

    obl = raw_obligations(queries)
    certs, cdg = p1_certificates(obl, queries)
    print(f"[5] raw obligation {sum(len(v) for v in obl.values())}건 -> "
          f"P1 인증서 {len(certs)}건")
    json.dump({"certificates": certs, "digest": cdg},
              open(f"{outdir}/p1-certificates.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    print(f"[6] 인증서 digest {cdg[:16]}")

    # ---- 7) δ matrix : θ 치환 후 **실측** ------------------------------
    delta = {}
    for pt in body["pair_types"]:
        for tb in sorted(LABELED):
            preds, nopred = [], []
            for q in [x for x in queries if x["table"] == tb]:
                p = where_of(q["sql"])
                (nopred if p is None else preds).append(
                    q["id"] if p is None else (q["id"],
                                               bind(p, q.get("params", []))))
            side = {}
            for s in ("d1", "d2"):
                psql(load(tb, pairs[pt][tb][s]))
                side[s] = traces(tb, preds)
            for qid, _ in preds:
                t1, t2 = side["d1"].get(qid), side["d2"].get(qid)
                delta[f"{qid}/{pt}"] = {"delta_equivalent": t1 == t2,
                                        "measured": t1 is not None}
            for qid in nopred:
                delta[f"{qid}/{pt}"] = {"delta_equivalent": True,
                                        "measured": True,
                                        "reason": "술어 없음"}
    json.dump(delta, open(f"{outdir}/delta.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    de = sum(1 for v in delta.values() if v["delta_equivalent"])
    nm = sum(1 for v in delta.values() if not v["measured"])
    print(f"[7] δ matrix digest {digest(delta)[:16]}  "
          f"δ-equivalent {de}/{len(delta)}  미측정 {nm}")

    install_certs(certs)
    print("[8] P1 실행 중 …")
    p1 = run_policy()

    raw = []
    for pol, tr in (("P0", p0), ("P1", p1)):
        for (qid, pt), v in sorted(tr.items()):
            q = byq[qid]
            d1v = v.get("d1", ("error", "missing"))
            d2v = v.get("d2", ("error", "missing"))
            priv = v.get("priv", ("error", "missing"))
            oc = oracle_class(q)
            acc = d1v[0] == "accept"
            dq = delta[f"{qid}/{pt}"]["delta_equivalent"]
            raw.append({
                "query_id": qid, "pair_type": pt, "policy": pol,
                "theta": q.get("params", []),
                "touches_labeled": q["touches_labeled"],
                "lineage": q["lineage"], "shape": q["shape"],
                "table": q["table"],
                "ordered_observation": q["shape"] in ORDERED_SHAPES,
                "masked_equivalent": appl[f"{pt}/{q['table']}"][
                    "masked_equivalent"],
                "delta_equivalent": dq,
                "gate_accept": acc,
                "rejection_reason": (None if acc else d1v[1]),
                "verdict": d1v[0],
                "n_raw_obligations": len(obl.get(qid, [])),
                "result_d1": d1v[1], "result_d2": d2v[1],
                "privileged": priv[1],
                "oracle_class": oc,
                "fidelity_result": (None if not acc else
                                    ("pass" if (oc == "A" and d1v[1] == priv[1])
                                     else "fail" if oc == "A" else None)),
                # scoped opacity: δ 가 다르면 declassification 범위 안이므로
                # 이 trial 은 opacity 주장의 **적용 대상이 아니다**.
                "opacity_applicable": bool(acc and dq),
                "opacity_result": (None if not (acc and dq) else
                                   ("pass" if d1v[1] == d2v[1] else "fail")),
                "opacity_unscoped": (None if not acc else
                                     ("pass" if d1v[1] == d2v[1] else "fail")),
                "oracle_error": (None if oc == "A" else "oracle 미구현(C)"),
            })
    with open(f"{outdir}/raw-trials.jsonl", "w") as f:
        for r in raw:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    rdg = hashlib.sha256(open(f"{outdir}/raw-trials.jsonl", "rb").read()
                         ).hexdigest()
    print(f"[9~10] raw trial {len(raw)}건  digest {rdg[:16]}")

    audit = sorted(q["id"] for q in queries
                   if int(hashlib.sha256(q["id"].encode()).hexdigest()[:4],
                          16) % 40 == 0)
    json.dump({"audit_sample": audit, "rule": "sha256(query_id)[:4] % 40 == 0"},
              open(f"{outdir}/audit-sample.json", "w"),
              ensure_ascii=False, indent=1)
    print(f"       수동 감사 표본 {len(audit)}건 (id 해시로 선택)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
