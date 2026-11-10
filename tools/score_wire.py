#!/usr/bin/env python3
"""
와이어 레벨 탐지기의 실측 능력을 채점한다.

측정하는 것: RowDescription의 resorigtbl/resorigcol 만 가지고 출력 컬럼을
PII로 분류할 때, H5 코퍼스에서 미탐(FN)과 오탐(FP)이 얼마나 나오는가.

이 숫자가 C 확장 AST 순회가 회수해야 할 기준선이다. 확장이 없어도 지금
잴 수 있다 -- libpq가 두 필드를 그대로 노출하기 때문이다.

전제: probe_provenance 가 빌드되어 있고, PGHOST/PGPORT/PGDATABASE 가
      h5 스키마가 적재된 인스턴스를 가리킬 것.

사용: python3 score_wire.py <corpus.json> [--probe ./probe_provenance]
"""
import json
import os
import subprocess
import sys
from collections import defaultdict

CAT_NAMES = {
    "D": "직접참조", "E": "표현식래핑", "V": "뷰/CTE/집합연산",
    "F": "함수/동적SQL", "S": "부채널", "C": "COPY",
    "B": "바이너리/인코딩", "X": "제어문", "P": "파라미터결속",
}


def psql_tsv(sql):
    out = subprocess.run(
        ["psql", "-Atq", "-F", "\t", "-c", sql],
        capture_output=True, text=True, check=True,
    ).stdout
    return [l.split("\t") for l in out.splitlines() if l]


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    corpus_path = sys.argv[1]
    probe = "./probe_provenance"
    if "--probe" in sys.argv:
        probe = sys.argv[sys.argv.index("--probe") + 1]

    corpus = json.load(open(corpus_path))
    entries = corpus["entries"]

    # --- 카탈로그 맵: (reloid, attnum) -> (relname, attname)
    attmap = {}
    for oid, relname, attnum, attname in psql_tsv(
        "SELECT c.oid, c.relname, a.attnum, a.attname "
        "FROM pg_class c JOIN pg_attribute a ON a.attrelid = c.oid "
        "WHERE c.relnamespace = 'h5'::regnamespace AND a.attnum > 0 "
        "AND NOT a.attisdropped"
    ):
        attmap[(int(oid), int(attnum))] = (relname, attname)

    # --- PII 라벨: (relname, attname) -> kind
    labels = {(r, a): k for r, a, k in psql_tsv(
        "SELECT relname, attname, kind FROM h5.pii_label")}

    # --- 프로브 실행
    probe_in = "".join(f"{e['id']}\t{e['sql']}\n" for e in entries)
    # 코퍼스 SQL은 비수식 이름(cust, v_cust ...)을 쓴다 -- 실제 애플리케이션이
    # 그렇게 쓰기 때문이다. 프로브 연결의 search_path를 h5로 맞춘다.
    env = dict(os.environ)
    env["PGOPTIONS"] = "-c search_path=h5,public " + env.get("PGOPTIONS", "")
    res = subprocess.run([probe], input=probe_in, capture_output=True,
                         text=True, env=env)
    if res.returncode != 0:
        print(res.stderr, file=sys.stderr)
        return 1

    cols = defaultdict(list)     # id -> [(idx, name, tableoid, tablecol, typeoid)]
    status = {}                  # id -> ("OK", ncols) | ("ERR", sqlstate, msg)
    for line in res.stdout.splitlines():
        f = line.split("\t")
        if len(f) < 2:
            continue
        qid, kind = f[0], f[1]
        if kind == "OK":
            status[qid] = ("OK", int(f[2]))
        elif kind == "ERR":
            status[qid] = ("ERR", f[2] if len(f) > 2 else "", f[3] if len(f) > 3 else "")
        elif kind == "COL":
            cols[qid].append((int(f[2]), f[3], int(f[4]), int(f[5]), int(f[6])))

    # --- 채점
    rows, per_cat = [], defaultdict(lambda: dict(n=0, fn=0, fp=0, err=0, ok=0))
    for e in entries:
        qid, cat = e["id"], e["cat"]
        expected = set(e["exposes"])
        st = status.get(qid, ("MISSING",))
        c = per_cat[cat]
        c["n"] += 1

        if st[0] != "OK":
            c["err"] += 1
            rows.append((qid, cat, expected, None, "PREPARE_FAIL",
                         (st[2] if len(st) > 2 else st[0]).strip()[:70]))
            continue

        detected = set()
        unresolved = 0
        for _, _, toid, tcol, _ in cols[qid]:
            if toid == 0 or tcol == 0:
                unresolved += 1
                continue
            key = attmap.get((toid, tcol))
            if key and key in labels:
                detected.add(labels[key])

        fn = expected - detected
        fp = detected - expected
        if fn:
            c["fn"] += 1
        if fp:
            c["fp"] += 1
        if not fn and not fp:
            c["ok"] += 1
        verdict = "PASS" if not fn and not fp else ("FN" if fn else "") + ("/FP" if fp else "")
        rows.append((qid, cat, expected, detected, verdict,
                     f"provenance 소실 컬럼 {unresolved}개" if unresolved else ""))

    # --- 리포트
    print("=" * 78)
    print("와이어 레벨 탐지기 (RowDescription resorigtbl/resorigcol) 실측 채점")
    print("=" * 78)
    print(f"{'ID':5} {'cat':4} {'기대':28} {'탐지':22} 판정")
    print("-" * 78)
    for qid, cat, exp, det, verdict, note in rows:
        e_s = ",".join(sorted(exp)) if exp else "-"
        d_s = ("-" if det is not None and not det else
               ",".join(sorted(det)) if det else "n/a")
        mark = "  " if verdict == "PASS" else "! "
        print(f"{mark}{qid:4} {cat:4} {e_s[:27]:28} {d_s[:21]:22} {verdict}"
              + (f"  {note}" if note else ""))

    print()
    print("=" * 78)
    print(f"{'카테고리':22} {'항목':>4} {'통과':>5} {'미탐':>5} {'오탐':>5} {'prepare실패':>10}")
    print("-" * 78)
    tot = dict(n=0, ok=0, fn=0, fp=0, err=0)
    for cat in "DEVFSCBXP":
        c = per_cat.get(cat)
        if not c:
            continue
        print(f"{CAT_NAMES[cat]:22} {c['n']:>4} {c['ok']:>5} {c['fn']:>5} "
              f"{c['fp']:>5} {c['err']:>10}")
        for k in tot:
            tot[k] += c[k]
    print("-" * 78)
    print(f"{'합계':22} {tot['n']:>4} {tot['ok']:>5} {tot['fn']:>5} "
          f"{tot['fp']:>5} {tot['err']:>10}")

    # --- 헤드라인 숫자
    pii = [e for e in entries if e["exposes"]]
    missed = [r for r in rows if r[2] and (r[4] != "PASS")]
    print()
    print("=" * 78)
    print("헤드라인")
    print("-" * 78)
    print(f"PII를 노출하는 항목            : {len(pii)}")
    print(f"와이어 훅이 완전히 잡은 항목   : {len(pii) - len(missed)}"
          f"  ({(len(pii)-len(missed))/len(pii)*100:.0f}%)")
    print(f"AST 순회가 회수해야 할 항목    : {len(missed)}")
    print()
    print("회수 대상 목록:")
    for qid, cat, exp, det, verdict, note in missed:
        print(f"  {qid} [{cat}] {verdict:6} 기대={','.join(sorted(exp))}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
