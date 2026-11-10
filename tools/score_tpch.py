#!/usr/bin/env python3
"""
독립 표준 워크로드(TPC-H)에 대한 거부율 측정.

지금까지의 코퍼스는 전부 내가 쓴 것이라 편향돼 있다. TPC-H 22개 쿼리는
표준화 기구가 만든 것이고 서브쿼리/CTE/상관 서브쿼리가 밀집해 있어
artifact 패턴(마스킹된 서브쿼리 출력을 술어가 참조)에 가장 가혹하다.

거부는 계획 시점에 일어나므로 EXPLAIN 만으로 측정된다 -- 데이터 불필요.

한계(반드시 같이 보고): TPC-H 는 분석계이고 타겟은 마이데이터/OpenAPI
거래계다. 분석계가 서브쿼리를 훨씬 많이 쓰므로 이 숫자는 **거부율의 상한**
이지 타겟 도메인의 값이 아니다.

사용: python3 score_tpch.py corpus/tpch-queries.sql
"""
import re
import subprocess
import sys

PRELUDE = ("SET search_path = tpch, public;\n"
           "SET ipguard.label_schema = 'tpch';\n")
CONFLICT = "would change query results"      # 술어가 마스킹된 출력을 참조
DIVERGE = "would change query semantics"     # 의미 발산 판정식(R1/R2)
DIVERGENCE = "allow"                         # --strict 로 error 로 바꾼다
NUMMASK = "nullify"                          # --zero 로 예전 센티널


def split_queries(path):
    txt = open(path, encoding="utf-8").read()
    parts = re.split(r"^--\s*(Q\d+)\s*$", txt, flags=re.M)
    out = []
    for i in range(1, len(parts), 2):
        sql = parts[i + 1].strip()
        if sql.endswith(";"):
            sql = sql[:-1]
        out.append((parts[i], sql))
    return out


def psql(script):
    return subprocess.run(["psql", "-Atq", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                          input=script, capture_output=True, text=True)


def analyze(sql):
    r = psql(PRELUDE + "SET ipguard.enforce = off;\n"
             f"SELECT ipguard_analyze($ipg${sql}$ipg$);")
    return r.stdout.strip() if r.returncode == 0 else "err=" + r.stderr[:60]


def explain(sql, enforce, on_conflict="error"):
    r = psql(PRELUDE + f"SET ipguard.enforce = {enforce};\n"
             f"SET ipguard.on_conflict = {on_conflict};\n"
             f"SET ipguard.on_divergence = {DIVERGENCE};\n"
             f"SET ipguard.numeric_mask = {NUMMASK};\n"
             f"EXPLAIN (COSTS OFF) {sql};")
    if r.returncode == 0:
        return ("OK", "")
    msg = " ".join(l for l in r.stderr.splitlines() if "ERROR" in l)
    if DIVERGE in r.stderr:
        return ("REFUSED-DIV", msg[:90])
    return ("REFUSED" if CONFLICT in r.stderr else "ERR", msg[:90])


def main():
    global DIVERGENCE, NUMMASK
    if "--strict" in sys.argv:
        DIVERGENCE = "error"
    if "--zero" in sys.argv:
        NUMMASK = "zero"
    qs = split_queries([a for a in sys.argv[1:] if not a.startswith("--")][0])
    rows = []
    for qid, sql in qs:
        base = explain(sql, "off")
        if base[0] != "OK":
            rows.append((qid, "PARSE_FAIL", set(), base[1]))
            continue
        a = analyze(sql)
        kinds = set()
        for part in a.split(";"):
            k, _, v = part.partition("=")
            if k == "out" and v:
                kinds = set(v.split(","))
        res = explain(sql, "on")
        rows.append((qid, res[0], kinds, res[1]))

    print("=" * 84)
    print("TPC-H 22개 쿼리 — 거부율 (독립 표준 워크로드)")
    print("=" * 84)
    print(f"{'Q':5} {'PII 출력':26} {'계획':10} 비고")
    print("-" * 84)
    for qid, st, kinds, msg in rows:
        k = ",".join(sorted(kinds)) if kinds else "-"
        mark = "! " if st in ("REFUSED", "PARSE_FAIL", "ERR") else "  "
        print(f"{mark}{qid:4} {k[:25]:26} {st:10} {msg[:34]}")

    ok = [r for r in rows if r[1] != "PARSE_FAIL"]
    masked = [r for r in ok if r[2]]
    refused = [r for r in ok if r[1].startswith("REFUSED")]
    refused_div = [r for r in ok if r[1] == "REFUSED-DIV"]
    errs = [r for r in ok if r[1] == "ERR"]
    bad = [r for r in rows if r[1] == "PARSE_FAIL"]

    print()
    print("=" * 84)
    print("결과")
    print("-" * 84)
    print(f"쿼리 총계                        : {len(rows)}")
    if bad:
        print(f"  파싱 실패(측정 제외)           : {len(bad)}"
              f"  ({', '.join(b[0] for b in bad)})")
    print(f"측정 대상                        : {len(ok)}")
    print(f"  PII 를 출력 -> 마스킹 발동      : {len(masked)}"
          f"  ({', '.join(m[0] for m in masked) if masked else '-'})")
    print(f"  ★ 거부됨                       : {len(refused)}"
          f"  ({', '.join(r[0] for r in refused) if refused else '-'})")
    if errs:
        print(f"  기타 에러                      : {len(errs)}"
              f"  ({', '.join(e[0] for e in errs)})")
    print()
    if ok:
        print(f"거부율(전체 대비)                : "
              f"{len(refused)}/{len(ok)} = {len(refused)/len(ok)*100:.0f}%")
    if masked:
        print(f"거부율(마스킹 발동 쿼리 대비)     : "
              f"{len(refused)}/{len(masked)} = {len(refused)/len(masked)*100:.0f}%")
    print(f"  그중 의미 발산 판정식(R1/R2) 탓 : {len(refused_div)}"
          f"  ({', '.join(r[0] for r in refused_div) if refused_div else '-'})")
    print(f"  설정                            : on_divergence={DIVERGENCE} "
          f"numeric_mask={NUMMASK}")
    print()
    print("주의: TPC-H 는 분석계다. 서브쿼리 밀도가 거래계보다 훨씬 높으므로")
    print("      이 값은 **거부율의 상한**으로 읽어야 한다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
