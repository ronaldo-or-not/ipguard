#!/usr/bin/env python3
"""Totality 의 분모를 **Query 트리로** 동결한다 (명세 v0.2.1 §11-2.5, §12).

`tools/classify_fcore.py` 는 SQL **텍스트**를 본다. 그래서 다음을 놓친다:

    - 뷰 본문에 숨은 구조   SELECT id FROM v_hidden   (v_hidden 안에 LEFT JOIN)
    - rewrite 가 만든 구성  규칙, RLS 술어
    - SELECT 위치 판정      WHERE x IN (…) 와 SELECT x IN (…) 의 구별
    - 카탈로그 사실         UDF 의 volatile 여부

그 결과는 `candidate-F_core` 이고 **상한**이다. 이 스크립트는 확장의
`ipguard_fragment()` 를 써서 **pg_analyze_and_rewrite 이후 Query 트리**로
다시 세고, 두 값의 차이를 보고한다. 차이가 곧 텍스트 휴리스틱의 오차다.

사용: python3 tools/score_fragment.py
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import classify_fcore as TXT      # noqa: E402  텍스트 휴리스틱과 나란히 본다

# 코퍼스마다 스키마가 다르다. search_path 를 안 맞추면 전부 "parse error" 가
# 되어 분모가 0 이 된다 -- 그러면 "전부 밖" 으로 보여 결론이 뒤집힌다.
def load_trilemma_real():
    """{T} 를 SETUP 이 실제로 만드는 표(tri_a)로 채운다.

    classify_fcore.load_trilemma() 은 텍스트 분류용이라 T='t' 로 채우는데,
    그 표는 존재하지 않으므로 여기서 쓰면 전부 parse error 가 되어 분모가
    0 이 된다 -- 그러면 "전부 밖" 으로 보여 결론이 뒤집힌다.
    """
    import score_trilemma
    return [(q[0].split()[0], q[1].format(T="tri_a"))
            for q in score_trilemma.QUERIES]


CORPORA = [
    ("삼자택이",   "h5, public",   load_trilemma_real),
    ("발산 코퍼스", "h5, public",   lambda: TXT.load_divergence()),
    ("TPC-H",     "tpch, public", lambda: TXT.load_tpch()),
]

# 삼자택이 질의는 {T} 가 실제 표여야 파스된다. **질의문을 손대지 않고**
# score_trilemma.py 의 SETUP 으로 진짜 표를 만든 뒤 원문 그대로 넣는다.
# -- 컬럼명을 치환하면 측정 도구가 측정 대상을 바꾸는 것이고, 이 프로젝트에서
#    이미 네 번 당한 실패 양식이다.


def psql(script):
    return subprocess.run(["psql", "-Atq", "-f", "-"], input=script,
                          capture_output=True, text=True)


def q_literal(s):
    return "$ipg$" + s + "$ipg$"


def run_corpus(name, search_path, items):
    """각 질의를 ipguard_fragment() 에 넣고 (사유 문자열) 을 받는다."""
    lines = [f"SET search_path = {search_path};"]
    for _, sql in items:
        one = " ".join(sql.split())
        lines.append(f"SELECT ipguard_fragment({q_literal(one)});")
    r = psql("\n".join(lines))
    out = [l for l in r.stdout.splitlines()]
    if len(out) != len(items):
        print(f"  !! {name}: 응답 {len(out)} != 질의 {len(items)}")
        print("     " + (r.stderr.strip().splitlines() or ["(stderr 없음)"])[0])
        return None
    return out


def main():
    print("=" * 78)
    print("F_core 분모 동결 — Query 트리 판정 (명세 v0.2.1 §12)")
    print("=" * 78)

    import score_trilemma
    psql(score_trilemma.SETUP)          # tri_a / tri_b 를 만든다
    grand = []
    try:
        grand = run_all()
    finally:
        psql(score_trilemma.TEARDOWN)
    return summarize(grand)


def run_all():
    grand = []
    for name, sp, loader in CORPORA:
        items = loader()
        got = run_corpus(name, sp, items)
        if got is None:
            continue

        inside, outside, reasons, disagree = [], [], {}, []
        for (qn, sql), verdict in zip(items, got):
            v = verdict.strip()
            txt_out = TXT.classify(sql)
            if v.startswith("parse error"):
                outside.append((qn, ["parse error"]))
                reasons["parse error"] = reasons.get("parse error", 0) + 1
                continue
            tree_out = [x.strip() for x in v.split(",") if x.strip()]
            if tree_out:
                outside.append((qn, tree_out))
                for x in tree_out:
                    reasons[x] = reasons.get(x, 0) + 1
            else:
                inside.append(qn)
            # 텍스트 휴리스틱과 결론이 다른 질의
            if bool(tree_out) != bool(txt_out):
                disagree.append((qn, "텍스트=안/트리=밖" if tree_out
                                 else "텍스트=밖/트리=안",
                                 ",".join(tree_out or txt_out)))

        n, k = len(items), len(inside)
        nout, mentions = n - k, sum(reasons.values())
        print(f"\n=== {name} — F_core {k}/{n} ===")
        for r, c in sorted(reasons.items(), key=lambda x: -x[1]):
            print(f"    밖: {r:24} {c}")
        if reasons and mentions != nout:
            print(f"    {'합계':24} {mentions}"
                  f"   ← non-exclusive: 사유 {mentions}건, 질의 {nout}개")
        if outside:
            print("  밖 : " + ", ".join(f"{a}({'/'.join(b)})" for a, b in outside))
        if disagree:
            print("  ★ 텍스트 휴리스틱과 결론이 다른 질의:")
            for qn, how, why in disagree:
                print(f"       {qn:8} {how:18} {why}")
        else:
            print("  (텍스트 휴리스틱과 결론 일치)")
        grand.append((name, k, n, len(disagree)))
    return grand


VIEW_CONTROL = """
CREATE OR REPLACE VIEW h5.fc_outer AS
  SELECT c.id, p.salary FROM h5.cust c LEFT JOIN h5.payroll p ON p.id = c.id;
CREATE OR REPLACE VIEW h5.fc_win AS
  SELECT id, row_number() OVER (ORDER BY ssn) AS rn FROM h5.cust;
CREATE OR REPLACE VIEW h5.fc_plain AS SELECT id, ssn FROM h5.cust;
"""

VIEW_QUERIES = [
    ("뷰가 outer join 을 숨김", "SELECT id FROM h5.fc_outer",  "outer join"),
    ("뷰가 window 를 숨김",     "SELECT id, rn FROM h5.fc_win", "window function"),
    ("대조: 평범한 뷰",          "SELECT id FROM h5.fc_plain",   ""),
]


def view_control():
    """★ 세 코퍼스에서 텍스트와 트리가 일치한 것은 **그 코퍼스가 뷰를 쓰지
    않기 때문**이다. "텍스트로 충분하다" 로 읽히면 안 되므로, 텍스트가
    원리적으로 못 보는 경우를 대조군으로 박아 둔다.
    """
    print("\n" + "=" * 78)
    print("대조군 — 텍스트가 원리적으로 볼 수 없는 것 (뷰 본문)")
    print("-" * 78)
    psql("SET search_path = h5, public;\n" + VIEW_CONTROL)
    script = ["SET search_path = h5, public;"]
    for _, sql, _ in VIEW_QUERIES:
        script.append(f"SELECT ipguard_fragment({q_literal(sql)});")
    got = psql("\n".join(script)).stdout.splitlines()
    psql("DROP VIEW IF EXISTS h5.fc_outer, h5.fc_win, h5.fc_plain;")

    ok = True
    for (label, sql, want), tree in zip(VIEW_QUERIES, got):
        txt = TXT.classify(sql)
        tree = tree.strip()
        hit = (tree == want)
        ok &= hit
        print(f"  {label:26} 텍스트=[{','.join(txt) or '안'}]"
              f"  트리=[{tree or '안'}]  {'✓' if hit else '✗'}")
    print()
    print("  텍스트는 세 경우 모두 '안' 이라고 답한다 -- 뷰 이름만 보이기 때문이다.")
    print("  분모를 텍스트로 잡으면 정리의 보호 범위를 **과대**하게 선언하게 된다.")
    return ok


def summarize(grand):
    view_control()
    print("\n" + "=" * 78)
    print(f"{'코퍼스':14}{'F_core(트리)':>14}{'F_impl':>10}{'텍스트와 불일치':>16}")
    print("-" * 78)
    for name, k, n, d in grand:
        print(f"{name:14}{str(k) + '/' + str(n):>14}{str(n) + '/' + str(n):>10}{d:>16}")
    print()
    print("이 표가 **동결된 분모**다. 이후 측정에서 바꾸지 않는다 -- 바꿔야 하면")
    print("명세 버전을 올리고 이전 수치를 다시 낸다.")
    print()
    print("불일치 열이 0 이 아니면 텍스트 휴리스틱을 분모로 쓸 수 없다는 뜻이다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
