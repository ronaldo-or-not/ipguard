#!/usr/bin/env python3
"""적대적 시험 3라운드 — 의미 발산 판정식과 nullify 센티널을 친다.

이전 두 라운드에서 적대적 시험이 결함 11건을 찾았고 **기본 코퍼스 72항목은
그중 0건을 찾지 못했다.** 새 기능(R1/R2/R3 판정식, 숫자 센티널 변경)을 붙였으면
새로 쳐야 한다는 뜻이다.

각 공격의 expect 는 **판정식을 켠 상태에서** 무엇이 일어나야 하는가다:

  refuse : 거부되어야 한다 (조용한 오답을 만드는 형태)
  mask   : 마스킹만 되고 통과해야 한다
  pass   : 아무 일도 없어야 한다 (음성 대조군 -- 막히면 과거부)

판정은 실행 결과로 한다. 판정식이 "잡았다"고 주장하는 것과 실제로 결과가
어떻게 나오는지는 다르다.

사용: python3 score_adversarial3.py corpus/adversarial3.json
"""
import json
import subprocess
import sys
from collections import defaultdict

HEAD = ("SET search_path = h5, public;\n"
        "SET ipguard.enforce = on;\n"
        "SET ipguard.on_divergence = error;\n")


def psql(script):
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    return r.stdout, r.stderr


def stmt(sql):
    """행 수 + 앞 20행. 출력에서 전체행 투영을 참조해야 마스킹이 발동한다."""
    return (f"SELECT count(*)::text || E'\\t' || "
            f"coalesce(array_to_string((array_agg(x ORDER BY x))[1:20], '|'), '-') "
            f"FROM (SELECT t::text AS x FROM ({sql}) t) s;")


def run(sql, enforce, diverge):
    out, err = psql(f"SET search_path = h5, public;\n"
                    f"SET ipguard.enforce = {enforce};\n"
                    f"SET ipguard.on_divergence = {diverge};\n" + stmt(sql))
    for line in err.splitlines():
        if "ERROR" in line:
            msg = line.split("ERROR:", 1)[-1].strip()
            return ("REFUSED" if "ipguard" in msg else "ERR"), msg[:70]
    for line in out.splitlines():
        if "\t" in line:
            n, rows = line.split("\t", 1)
            return "OK", (int(n), rows)
    return "ERR", "출력 없음"


def main():
    entries = json.load(open(sys.argv[1]))["entries"]
    rows = []
    for e in entries:
        base = run(e["sql"], "off", "allow")
        if base[0] != "OK":
            rows.append((e, "SETUP", f"enforce=off 에서 실패: {base[1]}"))
            continue
        got = run(e["sql"], "on", "error")

        if got[0] == "REFUSED":
            actual = "refuse"
        elif got[0] == "ERR":
            rows.append((e, "ERR", f"ipguard 와 무관한 에러: {got[1]}"))
            continue
        elif got[1] == base[1]:
            actual = "pass"
        else:
            actual = "mask"

        want = e["expect"]
        if actual == want:
            verdict = "OK"
            detail = ""
        elif want == "refuse" and actual == "mask":
            # 가장 중요한 실패다. 거부해야 할 것이 조용히 결과를 내놓았다.
            verdict = "우회"
            detail = (f"거부되어야 하는데 통과했다  "
                      f"행 {base[1][0]}→{got[1][0]}")
        elif want == "pass" and actual == "refuse":
            verdict = "과거부"
            detail = "정상 쿼리가 막혔다"
        elif want == "pass" and actual == "mask":
            verdict = "과마스킹"
            detail = f"손대지 않아야 하는데 결과가 바뀌었다"
        elif want == "mask" and actual == "refuse":
            verdict = "과거부"
            detail = "마스킹으로 충분한데 거부됐다"
        else:
            verdict = "불일치"
            detail = f"기대 {want}, 실제 {actual}"
        rows.append((e, verdict, detail))

    print("=" * 96)
    print("적대적 시험 3R — 의미 발산 판정식 / nullify 센티널")
    print("=" * 96)
    print(f"{'ID':6}{'class':12}{'기대':9}{'판정':9}비고")
    print("-" * 96)
    per = defaultdict(lambda: defaultdict(int))
    for e, verdict, detail in rows:
        mark = "  " if verdict == "OK" else "! "
        print(f"{mark}{e['id']:4}{e['class']:12}{e['expect']:9}{verdict:9}{detail}")
        per[e["class"]][verdict] += 1

    print()
    print("=" * 96)
    ev = [r for r in rows if r[1] == "우회"]
    over = [r for r in rows if r[1] in ("과거부", "과마스킹")]
    err = [r for r in rows if r[1] in ("ERR", "SETUP")]
    ok = [r for r in rows if r[1] == "OK"]
    print(f"공격 {len(rows)}건")
    print(f"  방어    : {len(ok)}")
    print(f"  ★ 우회  : {len(ev)}   ← 거부해야 할 것이 통과했다")
    print(f"  과거부/과마스킹: {len(over)}   ← 정상 쿼리를 막았다")
    print(f"  측정 불가: {len(err)}")
    for tag, lst in (("★ 우회", ev), ("과거부/과마스킹", over),
                     ("측정 불가", err)):
        if lst:
            print()
            print(f"{tag}:")
            for e, _, detail in lst:
                print(f"  {e['id']:5} [{e['class']}] {detail}")
                print(f"        {' '.join(e['sql'].split())[:86]}")
                print(f"        {e['note'][:86]}")
    return 1 if ev else 0


if __name__ == "__main__":
    sys.exit(main())
