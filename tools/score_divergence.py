#!/usr/bin/env python3
"""마스킹이 결과를 조용히 바꾸는 경로를 분류하고 크기를 잰다.

ipguard 는 "마스킹이 결과를 바꾸면 거부한다"고 주장한다. 실제로 거부하는 것은
**한 가지 조건**뿐이다 -- 마스킹된 서브쿼리 출력을 술어가 참조하는 경우.
나머지는 `intrinsic`("마스킹 정의상 불가피")으로 분류해 통과시킨다.

그 분류는 정책 선택이지 건전성 논증이 아니다. 심사위원이 정확히 여기를 찌른다:
"DISTINCT 가 10000행을 1행으로 무너뜨리는데 그걸 조용히 돌려준다면 무엇이
건전한가?" 이 스크립트는 그 질문에 숫자로 답한다.

**행 수만 보면 안 된다.** 가장 위험한 경우가 행 수를 안 바꾼다:

    SELECT count(DISTINCT ssn) FROM cust     1행 -> 1행,  값 10000 -> 1
    SELECT sum(acct_no) FROM cust            1행 -> 1행,  값 (합계) -> 0

출력이 PII 가 아닌 **평범한 숫자**인데 조용히 틀린다. 클라이언트는 마스킹이
일어났다는 것조차 알 수 없다.

사용: python3 score_divergence.py corpus/divergence.json
"""
import json
import subprocess
import sys
from collections import defaultdict

HEAD = "SET search_path = h5, public;\n"
# 판정식 on/off 를 명령행으로 바꿔 같은 코퍼스에서 전후를 비교한다
DIVERGENCE = "allow"
NUMMASK = "nullify"    # --zero 로 예전 센티널(0)과 비교한다
MASK_CHARS = set("*")


def psql(script):
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    return r.stdout, r.stderr


def stmt(qid, sql):
    """행 수 + 대표값. **출력에서 x(전체행 투영)를 참조하는 형태여야 한다.**
    `SELECT count(*) FROM (q) z` 처럼 감싸면 출력에 PII 참조가 없어 마스킹이
    발동하지 않는다 -- 측정이 조용히 무력화된다. probe 와 재실행이 반드시
    같은 모양을 쓰도록 여기 한 곳에 둔다."""
    return (f"SELECT $t${qid}$t$ || E'\\t' || count(*)::text || E'\\t' || "
            f"coalesce(array_to_string((array_agg(x ORDER BY x))[1:20], "
            f"'\u241f'), '(빈결과)') "
            f"FROM (SELECT t::text AS x FROM ({sql}) t) s;")


def probe(entries, enforce):
    """행 수 + 첫 행 값을 뽑는다.

    대표행 하나만 보면 안 된다 -- 윈도우 순위처럼 **다른 행에서만** 값이
    바뀌는 경우를 놓친다(실측: dense_rank 가 1..5 -> 전부 1 인데 첫 행은
    양쪽 다 1 이라 '변화 없음'으로 찍혔다). 정렬해 앞 20행을 짝지어 본다.

    ★ 반드시 전체행 투영(t::text)을 **출력에서 참조**하는 형태여야 한다.
      `SELECT count(*) FROM (q) z` 처럼 감싸면 출력에 PII 참조가 없어서
      ipguard 의 출력경로 추종 변이기가 아무것도 마스킹하지 않는다 --
      마스킹이 꺼진 상태를 재게 되고, 그 오류는 우리에게 유리한 쪽으로 틀린다.
    """
    stmts = [stmt(e["id"], e["sql"]) for e in entries]
    out, err = psql(HEAD + f"SET ipguard.enforce = {'on' if enforce else 'off'};\n"
                    + f"SET ipguard.on_divergence = {DIVERGENCE};\n"
                    + f"SET ipguard.numeric_mask = {NUMMASK};\n"
                    + "\n".join(stmts))
    res = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) == 3:
            res[f[0]] = (int(f[1]), f[2])
    return res, err


def verdicts(entries):
    stmts = [f"SELECT $t${e['id']}$t$ || E'\\t' || verdict "
             f"FROM ipguard_verdict($ipg${e['sql']}$ipg$);" for e in entries]
    out, _ = psql(HEAD + "SET ipguard.enforce = off;\n" + "\n".join(stmts))
    return dict(l.split("\t", 1) for l in out.splitlines() if "\t" in l)


def fields(row):
    """행 텍스트 `(a,b,c)` 를 필드로 쪼갠다.

    값에 콤마가 들어가면 부정확하지만 이 코퍼스에는 없다. 정확한 파싱보다
    **마스크된 필드와 평범한 필드를 구분한다**는 목적이 중요하다.
    """
    return [f.strip('"') for f in row.strip("()").split(",")]


def looks_masked(val):
    """값이 마스크 센티널인가, 그리고 **마스크인 줄 알아볼 수 있는가.**

    이 구분이 이 측정의 핵심이다. 마스킹됐다는 사실이 결과에 드러나면
    클라이언트가 "이 답은 실제 모집단이 아니다"를 알 수 있다. 드러나지
    않으면 조용한 오답과 실질적으로 같다.

        text     '**************'   -> 명백히 마스크        recognizable
        date     '1900-01-01'       -> 의심스럽다           recognizable
        numeric  '0' / '0.00'       -> ★ 정상 값과 구별 불가  ambiguous

    숫자형에서 0 은 유효한 급여·잔액일 수 있다. 마스크 센티널이 도메인
    안의 평범한 값인 타입에서는 "값 보존 집계는 안전하다"는 논거가 깨진다.
    """
    body = val.strip('"').strip()
    if not body:
        return None
    if (set(body) <= MASK_CHARS or body.startswith("1900-01-01")
            or body == "00000000-0000-0000-0000-000000000000"):
        return "recognizable"
    if body.replace("-", "").replace(".", "").strip("0") == "":
        return "ambiguous"      # 0, 0.00, -0.0 …
    return None


def classify(rows_off, rows_on, val_off, val_on):
    """무엇이 일어났는가.

    핵심 구분: **출력이 마스크값인가, 아니면 평범한 값인데 틀렸는가.**
    전자는 마스킹의 의도된 동작이고, 후자는 조용한 오답이다.

    ★ 행 전체를 한 덩어리로 보면 안 된다. 윈도우/정렬 항목은 마스킹된 컬럼과
      평범한 컬럼이 **같이** 나간다:

          (1, 800102-1000001, 1)  ->  (1, **************, 1)   해롭지 않음
          (100, 800101-1000100)   ->  (1, **************)      ★ id 가 바뀌었다

      첫 필드만 보던 판정은 음성 대조군(DV38)까지 '조용한 오답'으로 찍었다.
      필드별로 짝지어 **마스크로 바뀐 필드는 빼고** 평범한 필드가 바뀌었는지
      본다.
    """
    if (rows_off, val_off) == (rows_on, val_on):
        return "none", "아무것도 안 바뀜"
    if rows_off != rows_on:
        r = rows_off / rows_on if rows_on else float("inf")
        return "collapse", f"행 {rows_off}→{rows_on} ({r:.0f}배 붕괴)"

    ro, rn = val_off.split("\u241f"), val_on.split("\u241f")
    if len(ro) != len(rn):
        return "silent-wrong", f"행 구성이 다르다 ({len(ro)}↔{len(rn)} 표본)"

    worst, plain = None, []
    for row_o, row_n in zip(ro, rn):
        fo, fn = fields(row_o), fields(row_n)
        if len(fo) != len(fn):
            return "silent-wrong", f"값 {row_o[:22]} → {row_n[:22]}"
        for a, b in zip(fo, fn):
            if a == b:
                continue
            if b == "" and a != "":
                worst = worst or "masked"   # NULL 로 바뀜 = 값 없음이 명시됨
                continue
            m = looks_masked(b)
            if m == "recognizable":
                worst = worst or "masked"
            elif m == "ambiguous":
                worst = "ambiguous"
            else:
                plain.append(f"{a[:12]}→{b[:12]}")
    if plain:
        return "silent-wrong", ("마스크가 아닌 필드가 바뀌었다: "
                               + ", ".join(dict.fromkeys(plain))[:60])
    if worst == "ambiguous":
        return "ambiguous", (f"값 {val_off[:20]} → {val_on[:14]} "
                             f"(마스크지만 정상 값과 구별 불가)")
    if worst == "masked":
        return "masked", "마스킹된 필드만 바뀜 = 의도한 동작"
    return "none", "아무것도 안 바뀜"


def main():
    global DIVERGENCE, NUMMASK
    argv = [a for a in sys.argv[1:] if not a.startswith("--")]
    if "--strict" in sys.argv:
        DIVERGENCE = "error"
    if "--zero" in sys.argv:
        NUMMASK = "zero"
    entries = json.load(open(argv[0]))["entries"]
    v = verdicts(entries)
    off, _ = probe(entries, False)
    on, err_on = probe(entries, True)

    rows = []
    for e in entries:
        qid = e["id"]
        if qid not in off:
            rows.append((e, v.get(qid, "?"), "ERR", "off 실행 실패", 0, 0))
            continue
        if qid not in on:
            _, e1 = psql(HEAD + "SET ipguard.enforce = on;\n"
                         + f"SET ipguard.on_divergence = {DIVERGENCE};\n"
                         + f"SET ipguard.numeric_mask = {NUMMASK};\n"
                         + stmt(e["id"], e["sql"]))
            msg = next((l.split("ERROR:", 1)[-1].strip()
                        for l in e1.splitlines() if "ERROR" in l), "?")
            rows.append((e, v.get(qid, "?"),
                         "refused" if "ipguard" in msg else "ERR",
                         msg[:52], 0, 0))
            continue
        kind, detail = classify(off[qid][0], on[qid][0], off[qid][1], on[qid][1])
        rows.append((e, v.get(qid, "?"), kind, detail,
                     off[qid][0], on[qid][0]))

    print("=" * 100)
    print("마스킹 정합성 발산 — 무엇이 조용히 틀리는가")
    print("=" * 100)
    print(f"{'ID':6}{'class':12}{'판정':9}{'실제 일어난 일':16}상세")
    print("-" * 100)
    per_class = defaultdict(lambda: defaultdict(int))
    for e, verdict, kind, detail, _, _ in rows:
        mark = "  " if kind in ("none", "masked", "refused") else "! "
        print(f"{mark}{e['id']:4}{e['class']:12}{verdict:9}{kind:16}{detail}")
        per_class[e["class"]][kind] += 1

    print()
    print("=" * 100)
    print("분류별 집계")
    print("-" * 100)
    print(f"{'class':12}{'none':>6}{'masked':>8}{'ambiguous':>11}{'collapse':>10}"
          f"{'silent-wrong':>14}{'refused':>9}")
    for c in sorted(per_class):
        d = per_class[c]
        print(f"{c:12}{d['none']:>6}{d['masked']:>8}{d['ambiguous']:>11}"
              f"{d['collapse']:>10}{d['silent-wrong']:>14}{d['refused']:>9}")

    bad = [r for r in rows if r[2] in ("collapse", "silent-wrong")]
    amb = [r for r in rows if r[2] == "ambiguous"]
    refused = [r for r in rows if r[2] == "refused"]
    ctrl = [r for r in rows if r[0]["class"] == "control"]
    ctrl_bad = [r for r in ctrl if r[2] not in ("none",)]

    print()
    print("=" * 100)
    print("판정")
    print("-" * 100)
    print(f"설정: on_divergence={DIVERGENCE}  numeric_mask={NUMMASK}")
    print(f"전체 {len(rows)}건 중 조용히 틀리는 것: {len(bad)}건")
    print(f"  그중 ipguard 가 거부한 것            : {len(refused)}건")
    print(f"  그냥 통과시킨 것                     : {len(bad)}건  ← 주장과의 격차")
    print(f"음성 대조군 {len(ctrl)}건 중 오염: {len(ctrl_bad)}건   ← 0 이어야 한다")
    if ctrl_bad:
        for e, _, kind, detail, _, _ in ctrl_bad:
            print(f"    {e['id']} {kind} {detail}")

    if amb:
        print()
        print("★ 마스킹은 됐지만 마스크인 줄 알아볼 수 없는 것: "
              f"{len(amb)}건")
        print("  숫자형 PII 의 마스크 센티널은 0 이고, 0 은 유효한 급여·잔액이다.")
        print("  텍스트의 '****' 와 달리 결과만 봐서는 마스킹 사실을 알 수 없다.")
        for e, _, _, detail, _, _ in amb:
            print(f"    {e['id']:5} {' '.join(e['sql'].split())[:56]}")
            print(f"          {detail}")

    hidden = [r for r in rows if r[2] == "silent-wrong" and r[4] == r[5]]
    print()
    print(f"★ 행 수가 안 바뀌면서 값만 틀린 것: {len(hidden)}건")
    print("  행 수 기반 탐지기로는 잡히지 않는다. 출력이 PII 가 아닌 평범한")
    print("  숫자라 클라이언트는 마스킹이 일어난 사실조차 알 수 없다.")
    for e, _, _, detail, _, _ in hidden:
        print(f"    {e['id']:5} {' '.join(e['sql'].split())[:56]}")
        print(f"          {detail}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
