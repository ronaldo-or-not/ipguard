#!/usr/bin/env python3
"""
집행(마스킹)이 실제로 값을 가리는지 측정한다.

탐지율과 집행률은 반드시 따로 재야 한다. 탐지기가 "ssn 이 나간다"를 알아도
집행기가 안 가리면 **가렸다고 믿는데 안 가려진** 최악의 상태가 된다.
실제로 전체 행 Var(row_to_json)에서 그 격차가 있었고, 이 측정으로 잡았다.

방법: 각 코퍼스 쿼리를 enforce=off / enforce=on 두 번 실행해 결과를 비교한다.
  - exposes 가 있는 항목  -> 결과가 **달라져야** 한다 (마스킹됨)
  - exposes 가 빈 항목    -> 결과가 **같아야** 한다 (과마스킹 없음)

DML/제어문/COPY 는 부작용이나 캡처 방식이 달라 제외하고 별도로 다룬다.

사용: python3 score_enforce.py <corpus.json> [...]
"""
import json
import subprocess
import sys
from collections import defaultdict

CI = "repeat('A',88)"
SKIP_CAT = {"X"}                       # 제어문: 반환값 없음
SKIP_PREFIX = ("COPY", "CREATE", "INSERT", "UPDATE", "DELETE", "MERGE", "WITH d AS (DELETE")


def expand(sql):
    """__NEST_n__ 등 생성 플레이스홀더를 펼친다.
    (score_adversarial.py 와 동일 규칙 -- 안 펼치면 해당 항목이 통째로
     '실행 실패'로 빠져 집행 측정에서 조용히 사라진다.)"""
    if not (sql.startswith("__") and sql.endswith("__")):
        return sql
    kind, n = sql.split("_")[2], int(sql.split("_")[3])
    if kind == "NEST":
        q = "SELECT ssn AS a FROM cust"
        for i in range(n):
            q = f"SELECT a FROM ({q}) t{i}"
        return q
    if kind == "DEEPEXPR":
        e = "ssn"
        for _ in range(n):
            e = f"coalesce({e}, '')"
        return f"SELECT {e} FROM cust WHERE ci = $1"
    if kind == "WIDETL":
        cols = ", ".join(["ssn"] + [f"{i} AS n{i}" for i in range(n)])
        return f"SELECT {cols} FROM cust WHERE ci = $1"
    if kind == "UNION":
        return " UNION ALL ".join(
            [f"SELECT ssn FROM cust WHERE id = {i}" for i in range(n)])
    return sql


def runnable(e):
    sql = expand(e["sql"]).strip().upper()
    if e["cat"] in SKIP_CAT:
        return False
    return not sql.startswith(SKIP_PREFIX)


def probe(entries, enforce):
    """각 쿼리 결과를 md5 로 요약해 받아온다."""
    stmts = []
    for e in entries:
        sql = expand(e["sql"]).replace("$1", CI)
        # 결과 5행을 텍스트로 요약. 실패하면 err 로 표시.
        stmts.append(
            f"SELECT $t${e['id']}$t$ || E'\\t' || "
            f"coalesce(md5(string_agg(x, '|')), 'EMPTY') "
            f"FROM (SELECT t::text AS x FROM ({sql}) t LIMIT 5) s;")
    script = ("SET search_path = h5, public;\n"
              f"SET ipguard.enforce = {'on' if enforce else 'off'};\n"
              + "\n".join(stmts))
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    out = {}
    for line in r.stdout.splitlines():
        if "\t" in line:
            k, v = line.split("\t", 1)
            out[k] = v
    for line in r.stderr.splitlines():
        if line.startswith("ERROR") or line.startswith("psql:"):
            pass
    return out


def main():
    entries = []
    for path in sys.argv[1:]:
        entries += [e for e in json.load(open(path))["entries"] if runnable(e)]
    # 중복 id 제거 (P01/P02 처럼 SQL 이 같아도 id 는 다름)
    seen, uniq = set(), []
    for e in entries:
        if e["id"] not in seen:
            seen.add(e["id"])
            uniq.append(e)
    entries = uniq

    off = probe(entries, False)
    on = probe(entries, True)

    per_cat = defaultdict(lambda: dict(n=0, ok=0, leak=0, over=0, err=0))
    rows, leaks, overs = [], [], []

    for e in entries:
        qid, cat = e["id"], e["cat"]
        exp = bool(e["exposes"])
        c = per_cat[cat]
        c["n"] += 1
        a, b = off.get(qid), on.get(qid)
        if a is None or b is None:
            c["err"] += 1
            rows.append((qid, cat, exp, "ERR", "실행 실패(off/on 중 하나)"))
            continue
        changed = (a != b)
        if exp and not changed:
            c["leak"] += 1
            leaks.append((qid, cat, e["sql"][:58]))
            v = "누출"
        elif (not exp) and changed:
            c["over"] += 1
            overs.append((qid, cat, e["sql"][:58]))
            v = "과마스킹"
        else:
            c["ok"] += 1
            v = "OK"
        rows.append((qid, cat, exp, v, ""))

    print("=" * 78)
    print("집행(마스킹) 검증 — enforce off vs on 결과 비교")
    print("=" * 78)
    print(f"{'ID':6} {'cat':4} {'PII노출기대':12} 판정")
    print("-" * 78)
    for qid, cat, exp, v, note in rows:
        mark = "  " if v == "OK" else "! "
        print(f"{mark}{qid:5} {cat:4} {'있음' if exp else '없음':12} {v}"
              + (f"  {note}" if note else ""))

    print()
    print("=" * 78)
    print(f"{'카테고리':8} {'항목':>4} {'통과':>5} {'누출':>5} {'과마스킹':>8} {'에러':>5}")
    print("-" * 78)
    tot = dict(n=0, ok=0, leak=0, over=0, err=0)
    for cat in sorted(per_cat):
        c = per_cat[cat]
        print(f"{cat:8} {c['n']:>4} {c['ok']:>5} {c['leak']:>5} "
              f"{c['over']:>8} {c['err']:>5}")
        for k in tot:
            tot[k] += c[k]
    print("-" * 78)
    print(f"{'합계':8} {tot['n']:>4} {tot['ok']:>5} {tot['leak']:>5} "
          f"{tot['over']:>8} {tot['err']:>5}")

    print()
    print("=" * 78)
    print("헤드라인")
    print("-" * 78)
    pii = [e for e in entries if e["exposes"]]
    print(f"PII 노출 쿼리          : {len(pii)}")
    print(f"  실제로 마스킹됨      : {len(pii) - len(leaks)}"
          f"  ({(len(pii)-len(leaks))/max(len(pii),1)*100:.0f}%)")
    print(f"  ★ 누출(집행 실패)    : {len(leaks)}")
    print(f"과마스킹(정상 쿼리 변형): {len(overs)}   ← 0이어야 한다")
    if leaks:
        print()
        print("누출 목록 — 탐지는 됐는데 집행이 안 된 것:")
        for qid, cat, sql in leaks:
            print(f"  {qid} [{cat}] {sql}")
    if overs:
        print()
        print("과마스킹 목록:")
        for qid, cat, sql in overs:
            print(f"  {qid} [{cat}] {sql}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
