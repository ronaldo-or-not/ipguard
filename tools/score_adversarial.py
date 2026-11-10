#!/usr/bin/env python3
"""
ipguard 탐지기에 대한 적대적 시험 채점.

기본 코퍼스(h5-corpus.json)는 방어를 설계하면서 같이 쓴 것이라 편향돼 있다.
이 스크립트는 그 코퍼스 밖의 표면을 공격하고, 두 가지를 보고한다:

 1. 우회 성공 목록 (exposes 가 있는데 탐지가 비어 있는 항목)
 2. `unresolved > 0 -> 거부` 정책의 오탐 비용
    -- 마스킹 집행 설계의 입력이 되는 숫자. bound 소진 시 fail-open 을
       막으려면 unresolved 를 거부 신호로 써야 하는데, 정상 쿼리도
       unresolved 를 올리면 그만큼 정상 업무가 막힌다.

사용: python3 score_adversarial.py <adversarial.json> [<base-corpus.json>]
"""
import json
import subprocess
import sys
from collections import defaultdict

CAT = {"R": "DML RETURNING", "N": "중첩/재귀 bound", "H": "상속/파티션",
       "W": "재작성(RULE/뷰)", "T": "타입/RTE 종류", "L": "상관 서브쿼리",
       "G": "집계/그룹화", "M": "물질화(라벨전파)", "P": "정책/재작성",
       "X": "실행컨텍스트", "Z": "탐지기 자원공격", "J": "JSON/배열/SRF"}
CAT_ORDER = "RNHWTLGMPXZJ"


def expand(sql):
    """__NEST_n__ 플레이스홀더를 실제 중첩 쿼리로 펼친다."""
    if not (sql.startswith("__") and sql.endswith("__")):
        return sql
    kind = sql.split("_")[2]
    n = int(sql.split("_")[3])
    if kind == "NEST":
        q = "SELECT ssn AS a FROM cust"
        for i in range(n):
            q = f"SELECT a FROM ({q}) t{i}"
        return q
    if kind == "DEEPEXPR":           # 표현식 깊이 (서브쿼리 깊이가 아님)
        e = "ssn"
        for _ in range(n):
            e = f"coalesce({e}, '')"
        return f"SELECT {e} FROM cust WHERE ci = $1"
    if kind == "WIDETL":             # 넓은 targetList
        cols = ", ".join(["ssn"] + [f"{i} AS n{i}" for i in range(n)])
        return f"SELECT {cols} FROM cust WHERE ci = $1"
    if kind == "UNION":              # UNION ALL arm 다수
        return " UNION ALL ".join(
            [f"SELECT ssn FROM cust WHERE id = {i}" for i in range(n)])
    return sql


def analyze(entries):
    vals = ",\n".join(
        f"($t${e['id']}$t$, $s${expand(e['sql'])}$s$)" for e in entries)
    script = (f"SET search_path = h5, public;\n"
              f"CREATE TEMP TABLE _a(id text, sql text);\n"
              f"INSERT INTO _a VALUES\n{vals};\n"
              f"SELECT id || E'\\t' || ipguard_analyze(sql) FROM _a ORDER BY id;\n")
    r = subprocess.run(["psql", "-Atq", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                       input=script, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stderr, file=sys.stderr)
        sys.exit(1)
    out = {}
    for line in r.stdout.splitlines():
        if "\t" not in line:
            continue
        qid, payload = line.split("\t", 1)
        rec = {"err": None, "out": set(), "pred": set(), "write": set(),
               "unresolved": 0, "bounded": 0}
        if payload.startswith("err="):
            rec["err"] = payload[4:]
        else:
            for part in payload.split(";"):
                k, _, v = part.partition("=")
                if k == "out" and v:
                    rec["out"] = set(v.split(","))
                elif k == "pred" and v:
                    rec["pred"] = set(v.split(","))
                elif k == "write" and v:
                    rec["write"] = set(v.split(","))
                elif k == "unresolved":
                    rec["unresolved"] = int(v or 0)
                elif k == "bounded":
                    rec["bounded"] = int(v or 0)
        out[qid] = rec
    return out


def main():
    adv = json.load(open(sys.argv[1]))
    entries = adv["entries"]
    res = analyze(entries)

    per_cat = defaultdict(lambda: dict(n=0, ok=0, evade=0, fp=0, err=0))
    evasions, fps, policy_misses, rows = [], [], [], []

    for e in entries:
        qid, cat = e["id"], e["cat"]
        exp = set(e["exposes"])
        r = res.get(qid)
        c = per_cat[cat]
        c["n"] += 1
        if r is None or r["err"]:
            c["err"] += 1
            rows.append((qid, cat, exp, None, "ERR", 0,
                         (r["err"] if r else "no result")[:55]))
            continue
        det, unres = r["out"], r["unresolved"]
        missed, extra = exp - det, det - exp
        # expect="write": 클라이언트로 나가지는 않지만 PII 가 라벨 없는
        # 릴레이션/컬럼으로 이동한다. write 축이 잡아야 한다.
        # 이 검증이 없으면 CTAS/MERGE 미탐이 "OK" 로 가려진다(2라운드에서 겪음).
        if e.get("expect") == "write":
            if not r["write"]:
                missed = {"(write축 미탐)"}
            else:
                missed = set()
            extra = set()
        ok = not missed and not extra
        if ok:
            c["ok"] += 1
        elif missed:
            if e.get("expect") == "policy":
                policy_misses.append(qid)
            else:
                c["evade"] += 1
                evasions.append((qid, cat, sorted(missed), unres,
                                 e.get("note", "")))
        if extra:
            c["fp"] += 1
            fps.append((qid, sorted(extra)))
        verdict = "OK" if ok else ("우회" if missed else "오탐")
        if missed and e.get("expect") == "policy":
            verdict = "정책"
        rows.append((qid, cat, exp, det, verdict, unres, ""))

    print("=" * 84)
    print("ipguard 적대적 시험 — 기본 코퍼스 밖 표면")
    print("=" * 84)
    print(f"{'ID':5} {'cat':4} {'기대':26} {'탐지':26} {'판정':6} unres")
    print("-" * 84)
    for qid, cat, exp, det, verdict, unres, note in rows:
        e_s = ",".join(sorted(exp)) if exp else "-"
        d_s = "n/a" if det is None else (",".join(sorted(det)) if det else "-")
        mark = "  " if verdict == "OK" else "! "
        print(f"{mark}{qid:4} {cat:4} {e_s[:25]:26} {d_s[:25]:26} "
              f"{verdict:6} {unres}" + (f"  {note}" if note else ""))

    print()
    print("=" * 84)
    print(f"{'카테고리':20} {'항목':>4} {'통과':>5} {'우회':>5} {'오탐':>5}")
    print("-" * 84)
    tot = dict(n=0, ok=0, evade=0, fp=0, err=0)
    for k in CAT_ORDER:
        c = per_cat.get(k)
        if not c:
            continue
        print(f"{CAT[k]:20} {c['n']:>4} {c['ok']:>5} {c['evade']:>5} {c['fp']:>5}")
        for t in tot:
            tot[t] += c[t]
    print("-" * 84)
    print(f"{'합계':20} {tot['n']:>4} {tot['ok']:>5} {tot['evade']:>5} {tot['fp']:>5}")

    print()
    print("=" * 84)
    print("1. 우회 성공")
    print("-" * 84)
    if not evasions:
        print("  없음 — 공격이 약했을 가능성을 먼저 의심할 것.")
    for qid, cat, missed, unres, note in evasions:
        print(f"  {qid} [{CAT[cat]}] 미탐={','.join(missed)}  unresolved={unres}")
        if note:
            print(f"       {note[:100]}")
    if policy_misses:
        print(f"\n  (정책으로 분류된 미탐: {', '.join(policy_misses)} — 탐지 불가가 정당한 항목)")

    # --- fail-closed 신호 비교
    print()
    print("=" * 84)
    print("2. fail-closed 신호 설계: `unresolved` vs `bounded`")
    print("-" * 84)
    pool = list(entries)
    if len(sys.argv) > 2:
        base = json.load(open(sys.argv[2]))["entries"]
        base_res = analyze(base)
        res.update(base_res)
        pool += base

    def stat(flag):
        blocked = [e for e in pool
                   if res.get(e["id"]) and not res[e["id"]]["err"]
                   and res[e["id"]][flag] > 0]
        catch = [e for e in blocked
                 if e.get("exposes") and not (set(e["exposes"]) & res[e["id"]]["out"])]
        noise = [e for e in blocked if e not in catch]
        return blocked, catch, noise

    print(f"{'거부 신호':14} {'거부 쿼리':>9} {'실제 우회 차단':>13} "
          f"{'정상 차단(오탐)':>15}")
    print("-" * 84)
    for flag, label in (("unresolved", "unresolved>0"), ("bounded", "bounded>0")):
        b, c, n = stat(flag)
        print(f"{label:14} {len(b):>9} {len(c):>13} {len(n):>15}")

    b_u, c_u, n_u = stat("unresolved")
    b_b, c_b, n_b = stat("bounded")
    print()
    print(f"전체 쿼리 {len(pool)}건 기준.")
    print()
    print("해석:")
    print(f"  - `unresolved>0` 로 거부하면 정상 쿼리 {len(n_u)}건이 같이 막힌다.")
    print(f"    RTE_FUNCTION/RTE_VALUES 는 정상 쿼리에서 흔하므로 이 신호는 쓸 수 없다.")
    print(f"  - `bounded>0` 로 거부하면 확인된 우회 {len(c_b)}건을 막고")
    print(f"    정상 쿼리 오탐은 {len(n_b)}건이다.")
    if n_b:
        print("    오탐 목록: " + ", ".join(e["id"] for e in n_b))
    print()
    print("  => 순회 bound 소진(bounded)과 RTE 종류로 인한 미해석(unresolved)을")
    print("     분리한 것이 fail-closed 를 값싸게 만든다. 하나로 뭉쳤다면")
    print(f"     정상 쿼리 {len(n_u)}건을 막거나 우회를 열어두는 양자택일이었다.")
    if n_u:
        print()
        print("  unresolved>0 인 정상 쿼리(참고):")
        for e in n_u[:10]:
            print(f"    {e['id']:5} unresolved={res[e['id']]['unresolved']:<3} "
                  f"{e['sql'][:50]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
