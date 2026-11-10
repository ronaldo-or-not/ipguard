#!/usr/bin/env python3
"""peer-group golden 의미론 회귀 (§11-5 준비).

`corpus/peer-golden.json` 의 **사람이 계산한 허용 결과 집합**에 실제 출력이
들어 있는지 본다.

★ 이건 게이트의 fidelity oracle 이 **아니다.** 두 가지를 확인한다:

  1. 내 손계산이 SQL 의미론과 맞는가        (마스킹 OFF 로 확인)
  2. 마스킹이 켜져도 허용 집합 안에 있는가   (의미론 회귀)

1번이 게이트를 안 쓰므로 순환이 아니다 -- 마스킹 OFF 의 PostgreSQL 은 그냥
PostgreSQL 이고, 거기 출력이 내 허용 집합에 있으면 손계산이 맞은 것이다.

★ 허용 집합은 release 결과를 **보기 전에** 동결됐다
  (docs/heldout-protocol.md 1단계). 결과를 보고 고치면 oracle 이 아니다.

사용: python3 tools/score_peer_golden.py
"""
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GOLDEN = os.path.join(ROOT, "corpus", "peer-golden.json")

MODES = [
    ("마스킹 OFF (손계산 검증)", "SET ipguard.enforce = off;"),
    ("legacy 게이트",
     "SET ipguard.enforce = on; SET ipguard.gate = legacy;"
     "SET ipguard.on_divergence = allow;"),
    ("release 게이트",
     "SET ipguard.enforce = on; SET ipguard.gate = release;"
     "SET ipguard.on_divergence = allow;"),
]


def psql(script):
    return subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                          input=script, capture_output=True, text=True)


def run(sql, prelude):
    r = psql("SET search_path = h5, public;\n" + prelude + "\n" + sql + ";")
    if "ERROR" in r.stderr:
        line = [l for l in r.stderr.splitlines() if "ERROR" in l][0]
        if "해소되지 않은 의무" in line:
            return "REFUSED"
        return "ERR: " + line[-50:]
    rows = [l for l in r.stdout.splitlines() if not l.startswith("SET")]
    return "|".join(rows)


def main():
    g = json.load(open(GOLDEN))
    psql("SET client_min_messages=warning;\n" + "\n".join(g["schema"]))
    total = ok = 0
    refused = {}
    try:
        print("=" * 78)
        print("peer-group golden — 사람이 계산한 허용 결과 집합")
        print("=" * 78)
        print("허용 집합은 release 결과를 **보기 전에** 동결됐다.")
        print("실행기가 낸 한 sequence 가 아니라 **의미론적 허용 결과**다.")
        for e in g["entries"]:
            print(f"\n{e['id']}  {e['class']}")
            print(f"     {e['sql']}")
            print(f"     허용 {len(e['allowed'])}가지"
                  f"{'  (전순서)' if len(e['allowed']) == 1 else ''}")
            for label, prelude in MODES:
                got = run(e["sql"], prelude)
                if got == "REFUSED":
                    refused.setdefault(label, []).append(e["id"])
                    print(f"  ·  {label:24} 거부")
                    continue
                total += 1
                hit = got in e["allowed"]
                ok += hit
                mark = "✓" if hit else "✗"
                print(f"  {mark}  {label:24} {got[:44]}")
                if not hit:
                    print(f"       허용: {', '.join(a[:44] for a in e['allowed'])}")
            # 금지 예가 실제로 허용 집합 밖인지 -- golden 자체의 자기점검
            if e["forbidden_example"] in e["allowed"]:
                print(f"  ✗  golden 오류: forbidden 예가 허용 집합 안에 있다")
                total += 1
    finally:
        psql("SET client_min_messages=warning;\n" + "\n".join(g["teardown"]))

    print("\n" + "=" * 78)
    print(f"  허용 집합 안 {ok}/{total}")
    for label, ids in refused.items():
        print(f"  {label} 거부: {', '.join(ids)}")
    print()
    print("  ★ 거부는 실패가 아니다. release 게이트가 인증서 없이 ORD 를 거부하는")
    print("    것은 설계대로다. 여기서 보는 것은 **수락한 것이 허용 집합 안에")
    print("    있는가** 이고, acceptance 비용은 §11-5 에서 따로 센다.")
    return 0 if ok == total else 1


if __name__ == "__main__":
    sys.exit(main())
