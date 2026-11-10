#!/usr/bin/env python3
"""측정 코퍼스가 `candidate-F_core` 안인지 밖인지 분류한다 (명세 v0.2.1 §12).

**왜 이게 필요한가.** Totality 의 **분모**를 고정하지 않으면 삼자택이 측정이
임의적이라는 비판을 그대로 받는다 -- 나중에 어려운 질의를 "미지원" 으로 옮겨
성공률을 올릴 수 있기 때문이다. 그래서 분모를 명세에서 닫고, 이 스크립트가
그 분류를 **재현 가능하게** 만든다.

★★ 이 스크립트가 내는 것은 `F_core` 가 **아니다.**

    candidate-F_core   SQL **텍스트** 휴리스틱의 결과 = 여기서 내는 값
    F_core             view expansion 과 rewrite 후 **Query 트리**로 확정
    F_impl             구현이 실제로 처리하는 범위

  텍스트만 보면 다음을 놓친다:
    - 뷰 뒤에 숨은 구조 (뷰 본문에 outer join 이 있어도 호출부에는 안 보인다)
    - rewrite 가 만들어내는 구성 (규칙, RLS 술어)
    - 등록되지 않은 UDF 의 pure/total 여부
  따라서 여기 나오는 "안" 은 **상한(upper bound)** 이다.
  "밖" 은 확실하지만 "안" 은 Query 트리 재판정 전까지 확정이 아니다.
  **최종 분모는 rewrite 이후 Query 트리로 다시 세어 동결해야 한다.**

사용: python3 tools/classify_fcore.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 정규식으로 잡히는 것들. (이름, 패턴, 명세 §12 의 사유)
RULES = [
    ("recursive CTE",   r"\bWITH\s+RECURSIVE\b",                       "귀납 구조가 다르다"),
    ("LATERAL",         r"\bLATERAL\b",                                "귀납 구조가 다르다"),
    ("SRF",             r"\b(generate_series|unnest|regexp_split_to_table)\s*\(",
                                                                       "귀납 구조가 다르다"),
    ("outer join",      r"\b(LEFT|RIGHT|FULL)\s+(OUTER\s+)?JOIN\b",    "확장 NULL vs 마스크 NULL"),
    ("NOT EXISTS",      r"\bNOT\s+EXISTS\s*\(",                        "anti-semijoin: ⋉ 규칙 이후"),
    ("NOT IN",          r"\bNOT\s+IN\s*\(\s*select",                   "3VL quantified comparison"),
    ("<> ALL",          r"(<>|!=)\s*ALL\s*\(\s*select",                "3VL quantified comparison"),
    ("row-valued IN",   r"\)\s*(NOT\s+)?IN\s*\(\s*select",             "row-comparison 의미론"),
    ("scalar subq",     r"[=<>]\s*\(\s*select\b",                      "1행 초과면 오류 = total 위반"),
    ("window func",     r"\bOVER\s*\(",                                "ORD 를 셀로 직접 나른다"),
    ("DISTINCT ON",     r"\bDISTINCT\s+ON\b",                          "비결정적 top-k"),
    ("WITH TIES",       r"\bWITH\s+TIES\b",                            "비결정적 top-k"),
    ("GROUPING SETS",   r"\b(GROUPING\s+SETS|CUBE\s*\(|ROLLUP\s*\()",  "집계 인터페이스가 다르다"),
    ("ordered-set agg", r"\bWITHIN\s+GROUP\b",                         "집계 인터페이스가 다르다"),
    ("DML",             r"\b(INSERT\s+INTO|UPDATE\s+\w+\s+SET|DELETE\s+FROM|RETURNING\b|COPY\s)",
                                                                       "계획기 경로가 다르다"),
]

CLAUSE = re.compile(r"\b(select|from|where|group|having|order|on|when)\b", re.I)
TOKEN = re.compile(r"\(|\)|\bin\b|\bexists\b|" + CLAUSE.pattern, re.I)


def in_positions(sql):
    """`IN (subquery)` 가 술어 위치인지 SELECT 목록 위치인지 가른다.

    §12: predicate-position scalar IN 만 F_core 안이다.
    `SELECT x IN (...)` 은 UNKNOWN 이 출력 셀이 되므로 밖.

    괄호 깊이별로 "현재 절" 을 들고 다니는 가벼운 스캐너. 파서가 아니므로
    문자열 리터럴 안의 키워드는 구별하지 못한다.
    """
    stack = [None]          # 깊이별 현재 절
    bad = False
    for m in TOKEN.finditer(sql):
        t = m.group(0).lower()
        if t == "(":
            stack.append(None)
        elif t == ")":
            if len(stack) > 1:
                stack.pop()
        elif t == "in":
            # 뒤에 (select 가 오는가?
            if re.match(r"\s*\(\s*select\b", sql[m.end():], re.I):
                if stack[-1] == "select":       # SELECT 목록 안 = 스칼라 위치
                    bad = True
        elif t in ("select", "from", "where", "group", "having", "order", "on", "when"):
            stack[-1] = t
    return bad


def classify(sql):
    """candidate-F_core 밖인 사유 목록. 비어 있으면 (후보로) 안이다."""
    out = [name for name, pat, _ in RULES if re.search(pat, sql, re.I)]
    if in_positions(sql):
        out.append("SELECT-position IN")
    # ORDER BY 없는 LIMIT 은 §1 에서 명시적으로 제외됐다.
    if re.search(r"\blimit\b", sql, re.I) and not re.search(r"\border\s+by\b", sql, re.I):
        out.append("LIMIT w/o ORDER")
    return out


SEMI = re.compile(r"(?<!not )\b(exists|in)\s*\(\s*select", re.I)


def report(title, items):
    inside, outside, reasons = [], [], {}
    for name, sql in items:
        why = classify(sql)
        if why:
            outside.append((name, why))
            for r in why:
                reasons[r] = reasons.get(r, 0) + 1
        else:
            inside.append(name + ("*" if SEMI.search(sql) else ""))
    n, k = len(items), len(inside)
    nout = n - k
    mentions = sum(reasons.values())
    print(f"\n=== {title} — candidate-in-core {k}/{n} (상한) ===")
    for r, c in sorted(reasons.items(), key=lambda x: -x[1]):
        print(f"    밖: {r:20} {c}")
    if reasons:
        tag = "" if mentions == nout else \
              f"   ← non-exclusive: 사유 {mentions}건, 질의 {nout}개"
        print(f"    {'합계':20} {mentions}{tag}")
    print(f"  안 : {', '.join(inside) or '없음'}")
    if outside:
        print(f"  밖 : {', '.join(f'{a}({chr(47).join(b)})' for a, b in outside)}")
    return k, n


def load_divergence():
    p = os.path.join(ROOT, "corpus", "divergence.json")
    return [(e["id"], e["sql"]) for e in json.load(open(p))["entries"]]


def load_tpch():
    p = os.path.join(ROOT, "corpus", "tpch-queries.sql")
    b = re.split(r"^--\s*Q(\d+)\s*$", open(p).read(), flags=re.M)
    return [(f"Q{b[i]}", b[i + 1]) for i in range(1, len(b) - 1, 2)]


def load_trilemma():
    """score_trilemma.py 의 QUERIES 를 재선언 없이 읽는다."""
    sys.path.insert(0, os.path.join(ROOT, "tools"))
    import score_trilemma
    return [(q[0].split()[0], q[1].format(T="t")) for q in score_trilemma.QUERIES]


def main():
    print("=" * 78)
    print("candidate-F_core 분류 — 명세 v0.2.1 §12.  Totality 분모의 **상한**.")
    print("=" * 78)
    print("* 표시 = predicate-position semi-join(EXISTS / IN) 을 쓴다. §12 상 안이다.")

    tot = [("삼자택이",) + report("삼자택이", load_trilemma()),
           ("발산 코퍼스",) + report("발산 코퍼스", load_divergence()),
           ("TPC-H",) + report("TPC-H", load_tpch())]

    print("\n" + "=" * 78)
    print(f"{'코퍼스':14}{'candidate-F_core':>20}{'F_impl':>10}")
    print("-" * 78)
    for name, k, n in tot:
        print(f"{name:14}{str(k) + '/' + str(n):>20}{str(n) + '/' + str(n):>10}")
    print()
    print("재측정에서는 두 분모를 **나란히** 보고한다. F_impl 만 쓰면 보장 범위를")
    print("넘어선 주장이 되고, candidate-F_core 만 쓰면 어려운 질의를 숨겼다는")
    print("반론을 받는다.")
    print()
    print("★ 이 값은 텍스트 휴리스틱의 **상한**이다. 뷰 본문·rewrite 결과·UDF 의")
    print("  total 여부를 보지 못한다. 최종 분모는 PostgreSQL rewrite 이후 Query")
    print("  트리로 다시 세어 동결해야 한다 -- 그때까지 F_core 라고 부르지 않는다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
