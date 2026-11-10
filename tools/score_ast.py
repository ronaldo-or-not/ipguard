#!/usr/bin/env python3
"""
C 확장(ipguard)의 AST 순회 탐지 능력을 채점하고 와이어 기준선과 비교한다.

와이어 기준선은 corpus JSON의 wire_verdict 필드에 이미 실측되어 있다
(results/wire-baseline.md). 이 스크립트는 같은 코퍼스에 대해 AST 탐지기를
돌려 회수율을 낸다.

두 축을 따로 잰다:
  - 출력 노출(out): 클라이언트에 값이 도달하는 PII. 마스킹 대상.
  - 술어 참조(pred): 출력엔 없지만 WHERE/ORDER BY에서 참조. 부채널 정책 대상.
    마스킹으로는 막을 수 없는 별개 클래스이므로 같은 지표에 섞지 않는다.

사용: python3 score_ast.py <corpus.json>
      (PGHOST/PGPORT/PGDATABASE 가 ipguard 설치된 인스턴스를 가리킬 것)
"""
import json
import subprocess
import sys
from collections import defaultdict

CAT_NAMES = {
    "D": "직접참조", "E": "표현식래핑", "V": "뷰/CTE/집합연산",
    "F": "함수/동적SQL", "S": "부채널", "C": "COPY",
    "B": "바이너리/인코딩", "X": "제어문", "P": "파라미터결속",
}


def run_analyzer(entries):
    """모든 코퍼스 SQL을 한 번의 psql 호출로 분석한다."""
    vals = ",\n".join(
        f"($tag${e['id']}$tag$, $sql${e['sql']}$sql$)" for e in entries)
    script = f"""
SET search_path = h5, public;
CREATE TEMP TABLE _c(id text, sql text);
INSERT INTO _c VALUES
{vals};
SELECT id || E'\\t' || ipguard_analyze(sql) FROM _c ORDER BY id;
"""
    out = subprocess.run(
        ["psql", "-Atq", "-v", "ON_ERROR_STOP=1", "-f", "-"],
        input=script, capture_output=True, text=True,
    )
    if out.returncode != 0:
        print(out.stderr, file=sys.stderr)
        sys.exit(1)

    res = {}
    for line in out.stdout.splitlines():
        if "\t" not in line:
            continue
        qid, payload = line.split("\t", 1)
        rec = {"raw": payload, "err": None, "out": set(), "pred": set(),
               "unresolved": 0}
        if payload.startswith("err="):
            rec["err"] = payload[4:]
        else:
            for part in payload.split(";"):
                k, _, v = part.partition("=")
                if k == "out" and v:
                    rec["out"] = set(v.split(","))
                elif k == "pred" and v:
                    rec["pred"] = set(v.split(","))
                elif k == "unresolved":
                    rec["unresolved"] = int(v or 0)
        res[qid] = rec
    return res


def main():
    if len(sys.argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    corpus = json.load(open(sys.argv[1]))
    entries = corpus["entries"]
    ast = run_analyzer(entries)

    per_cat = defaultdict(lambda: dict(n=0, ok=0, fn=0, fp=0, err=0))
    rows, recovered, still_missed, regressions, derived = [], [], [], [], []

    for e in entries:
        qid, cat = e["id"], e["cat"]
        expected = set(e["exposes"])
        wire_ok = e.get("wire_verdict") == "PASS"
        r = ast.get(qid)
        c = per_cat[cat]
        c["n"] += 1

        if r is None or r["err"]:
            c["err"] += 1
            rows.append((qid, cat, expected, None, "ERR", wire_ok,
                         (r["err"] if r else "no result")[:60]))
            continue

        det = r["out"]
        fn, fp = expected - det, det - expected
        # derived_only: 값이 아니라 파생 메타데이터만 나가는 항목.
        # 노출로 셀지가 미결이므로 오탐으로 단정하지 않고 따로 집계한다.
        if fp and e.get("derived_only"):
            derived.append((qid, sorted(fp)))
            fp = set()
        if fn:
            c["fn"] += 1
        if fp:
            c["fp"] += 1
        ast_ok = not fn and not fp
        if ast_ok:
            c["ok"] += 1
        verdict = "PASS" if ast_ok else (("FN" if fn else "") + ("/FP" if fp else ""))

        if expected:
            if ast_ok and not wire_ok:
                recovered.append(qid)
            elif not ast_ok:
                still_missed.append((qid, verdict, sorted(fn), sorted(fp)))
            if wire_ok and not ast_ok:
                regressions.append(qid)

        note = f"unresolved={r['unresolved']}" if r["unresolved"] else ""
        rows.append((qid, cat, expected, det, verdict, wire_ok, note))

    print("=" * 86)
    print("AST 순회 탐지기 (ipguard) 채점 — 와이어 기준선 대비")
    print("=" * 86)
    print(f"{'ID':5} {'cat':3} {'기대':26} {'AST 탐지':26} {'AST':7} 와이어")
    print("-" * 86)
    for qid, cat, exp, det, verdict, wire_ok, note in rows:
        e_s = ",".join(sorted(exp)) if exp else "-"
        d_s = "n/a" if det is None else (",".join(sorted(det)) if det else "-")
        w_s = "PASS" if wire_ok else "miss"
        mark = "  " if verdict == "PASS" else "! "
        star = " ←회수" if (verdict == "PASS" and not wire_ok and exp) else ""
        print(f"{mark}{qid:4} {cat:3} {e_s[:25]:26} {d_s[:25]:26} "
              f"{verdict:7} {w_s}{star}"
              + (f"  {note}" if note else ""))

    print()
    print("=" * 86)
    print(f"{'카테고리':20} {'항목':>4} {'통과':>5} {'미탐':>5} {'오탐':>5} {'에러':>5}")
    print("-" * 86)
    tot = dict(n=0, ok=0, fn=0, fp=0, err=0)
    for cat in "DEVFSCBXP":
        c = per_cat.get(cat)
        if not c:
            continue
        print(f"{CAT_NAMES[cat]:20} {c['n']:>4} {c['ok']:>5} {c['fn']:>5} "
              f"{c['fp']:>5} {c['err']:>5}")
        for k in tot:
            tot[k] += c[k]
    print("-" * 86)
    print(f"{'합계':20} {tot['n']:>4} {tot['ok']:>5} {tot['fn']:>5} "
          f"{tot['fp']:>5} {tot['err']:>5}")

    # --- 술어 참조 (부채널) 축
    pred_exp = [e for e in entries if e.get("predicate_pii")]
    pred_hit = [e for e in pred_exp
                if ast.get(e["id"]) and ast[e["id"]]["pred"]]
    # --- 헤드라인
    pii = [e for e in entries if e["exposes"]]
    ast_ok_n = len(pii) - len(still_missed)
    wire_ok_n = sum(1 for e in pii if e.get("wire_verdict") == "PASS")

    print()
    print("=" * 86)
    print("헤드라인")
    print("-" * 86)
    print(f"PII 노출 항목                : {len(pii)}")
    print(f"  와이어 훅 탐지             : {wire_ok_n:>3}  ({wire_ok_n/len(pii)*100:.0f}%)")
    print(f"  AST 순회 탐지              : {ast_ok_n:>3}  ({ast_ok_n/len(pii)*100:.0f}%)")
    print(f"  회수                       : {len(recovered):>3}")
    print(f"  여전히 미탐                : {len(still_missed):>3}")
    print(f"  퇴행(와이어는 잡았는데 AST가 놓침): {len(regressions)}")
    print(f"오탐(FP) 총계                : {tot['fp']}   ← 0이어야 한다")
    if derived:
        print(f"파생 메타데이터 항목(미결)   : {len(derived)}  "
              f"({', '.join(q for q, _ in derived)}) — 정책 결정 전까지 FP로 세지 않음")
    print()
    print(f"술어 참조 항목               : {len(pred_exp)}")
    print(f"  AST가 술어 참조를 탐지      : {len(pred_hit)}"
          f"  ({len(pred_hit)/len(pred_exp)*100:.0f}%)"
          "   (마스킹이 아니라 쿼리형태 정책의 입력)")

    if still_missed:
        print()
        print("여전히 미탐 / 오탐:")
        for qid, verdict, fn, fp in still_missed:
            print(f"  {qid} {verdict:6} 미탐={','.join(fn) or '-'}"
                  f" 오탐={','.join(fp) or '-'}")
    if regressions:
        print()
        print("!! 퇴행 (와이어가 잡던 것을 AST가 놓침) — 반드시 조사할 것:")
        for qid in regressions:
            print(f"  {qid}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
