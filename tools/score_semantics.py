#!/usr/bin/env python3
"""
마스킹 집행이 쿼리 *결과*를 바꾸는지, 그리고 감지기가 그걸 거부하는지 잰다.

누출과 다른 위험이다. 누출은 데이터가 나가는 것이고, 이건 **조용한 오답**이다.
에러가 없으므로 운영에서 발견이 훨씬 어렵다. 보안 컨트롤은 결과를 조용히
바꾸면 안 되므로, 바꾸게 되는 쿼리는 거부(fail-closed)해야 한다.

분류:
  refuse      : 반드시 거부되어야 함
  refuse_over : 실제로는 안전했는데 감지기가 구분 못 해 함께 거부됨(과잉 거부 비용)
  intrinsic   : 마스킹 본질상 불가피. 거부 대상 아님
  scoped      : PII 미출력 -> 마스킹 미발동
  none        : 대조군. 변경도 거부도 없어야 함

각 쿼리를 enforce off/on 으로 따로 실행해 행수/해시/에러를 비교한다.
"""
import json
import subprocess
import sys
from collections import defaultdict

CONFLICT = "would change query results"


def run_one(sql, enforce, on_conflict="error"):
    script = (f"SET search_path = h5, public;\n"
              f"SET ipguard.enforce = {'on' if enforce else 'off'};\n"
              f"SET ipguard.on_conflict = {on_conflict};\n"
              f"SELECT count(*)::text || E'\\t' || "
              f"coalesce(md5(string_agg(x, '|' ORDER BY x)), '-') "
              f"FROM (SELECT t::text AS x FROM ({sql}) t) s;")
    r = subprocess.run(["psql", "-Atq", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                       input=script, capture_output=True, text=True)
    if r.returncode != 0:
        msg = " ".join(l for l in r.stderr.splitlines() if "ERROR" in l)
        return ("REFUSED" if CONFLICT in r.stderr else "ERR", msg[:70])
    for line in r.stdout.splitlines():
        if "\t" in line:
            a, b = line.split("\t", 1)
            return (int(a), b)
    return ("ERR", "no output")


def main():
    corpus = json.load(open(sys.argv[1]))
    entries = corpus["entries"]

    per = defaultdict(lambda: dict(n=0, ok=0, bad=0))
    rows, violations = [], []

    for e in entries:
        qid, exp = e["id"], e["expect"]
        c = per[exp]
        c["n"] += 1
        off = run_one(e["sql"], False)
        on = run_one(e["sql"], True)

        refused = on[0] == "REFUSED"
        errored = on[0] == "ERR"
        changed = (not refused and not errored and off[0] != on[0])

        if exp in ("refuse", "refuse_over"):
            good = refused
            verdict = "거부됨" if refused else ("행수변경!" if changed else "통과(변경없음)")
        elif exp == "intrinsic":
            good = not refused and not errored
            verdict = "거부됨!" if refused else ("행수변경(불가피)" if changed else "동일")
        elif exp == "masked_ok":
            # 값은 마스킹되어야 하고(달라야 하고), 행 수는 보존되어야 한다.
            good = (not refused and not errored and not changed
                    and off[1] != on[1])
            verdict = ("거부됨!" if refused else
                       "행수변경!" if changed else
                       "마스킹안됨!" if off[1] == on[1] else "행수보존+마스킹")
        else:                                   # scoped / none
            good = (not refused and not errored and not changed
                    and off[1] == on[1])
            verdict = ("거부됨!" if refused else
                       "변경!" if (changed or off[1] != on[1]) else "동일")
        if good:
            c["ok"] += 1
        else:
            c["bad"] += 1
            violations.append((qid, exp, verdict, off, on, e["sql"][:52]))
        rows.append((qid, exp, off[0], on[0], verdict))

    print("=" * 88)
    print("정합성 감지·거부 검증 — enforce off vs on (on_conflict=error)")
    print("=" * 88)
    print(f"{'ID':5} {'분류':13} {'off':>8} {'on':>9} 판정")
    print("-" * 88)
    for qid, exp, a, b, v in rows:
        mark = "! " if v.endswith("!") else "  "
        print(f"{mark}{qid:4} {exp:13} {str(a):>8} {str(b):>9} {v}")

    print()
    print("=" * 88)
    print(f"{'분류':14} {'항목':>4} {'기대대로':>8} {'위반':>6}")
    print("-" * 88)
    for k in ("none", "scoped", "masked_ok", "refuse", "refuse_over", "intrinsic"):
        c = per.get(k)
        if c:
            print(f"{k:14} {c['n']:>4} {c['ok']:>8} {c['bad']:>6}")

    print()
    print("=" * 88)
    print("판정")
    print("-" * 88)
    r_ok = per.get("refuse", {}).get("ok", 0)
    r_n = per.get("refuse", {}).get("n", 0)
    o_ok = per.get("refuse_over", {}).get("ok", 0)
    o_n = per.get("refuse_over", {}).get("n", 0)
    print(f"조용한 오답이 되던 쿼리 {r_n}건 중 {r_ok}건이 거부됨"
          f" -- 이제 명시적 에러다.")
    print(f"과잉 거부: {o_ok}/{o_n}건 -- 실제로는 안전했는데 감지기가 구분하지 못한 것.")
    print(f"  (NULL 여부/문자 수는 마스킹이 보존하지만 감지기는 그걸 알 수 없다.)")
    if violations:
        print()
        print("위반:")
        for qid, exp, v, off, on, sql in violations:
            print(f"  {qid} [{exp}] {v}  off={off[0]} on={on[0]}  {sql}")
    else:
        print()
        print("위반 0건.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
