#!/usr/bin/env python3
"""peer-group golden 의 `allowed` 가 **빠짐없이 정확한가** (completeness check).

두 검사는 다르다:

  soundness sanity   실제 출력 하나가 allowed 안에 있다
                     -> tools/score_peer_golden.py 가 한다
  completeness       모든 peer 내부 순열을 projection 한 집합이 allowed 와
                     **정확히 같다**
                     -> 이 스크립트가 한다

앞의 것만으로는 allowed 가 너무 넓거나(금지된 순서를 허용) 너무 좁은지
(정당한 순서를 누락) 알 수 없다. DB 를 쓰지 않고 raw_peer_blocks 에서
독립적으로 재구성해 비교한다.

★ 블록 **구성**(1단계)은 여전히 손계산이다 -- 어느 행들이 peer 인가는 SQL
  의미론 판단이고, 그걸 기계로 만들면 검증하려는 대상과 같은 코드가 된다.
  이 스크립트가 검증하는 것은 2~4단계다:
    2) 블록별 허용 순열 생성
    3) projection/redaction 적용
    4) 중복되는 observable sequence 합치기

사용: python3 tools/enumerate_peer_golden.py
"""
import itertools
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def observable_set(entry):
    """2~4단계를 독립 수행해 관찰 가능한 sequence 집합을 만든다."""
    proj = entry["projection"]
    per_block = []
    for b in entry["raw_peer_blocks"]:
        # 2) 블록 내부 순열 전부
        per_block.append(list(itertools.permutations(b["rows"])))
    out = set()
    for combo in itertools.product(*per_block):
        rows = [r for block in combo for r in block]
        # 3) projection 적용   4) set 이므로 중복 자동 합침
        out.add("|".join(proj[str(r)] for r in rows))
    return out


def main():
    g = json.load(open(os.path.join(ROOT, "corpus", "peer-golden.json")))
    print("=" * 78)
    print("peer-group golden — allowed 의 **완전성** 검사")
    print("=" * 78)
    print("raw_peer_blocks 에서 2~4단계를 독립 수행해 allowed 와 집합 비교한다.")
    print("(블록 구성 1단계는 손계산 -- SQL 의미론 판단이라 기계화하면 순환이다)")
    bad = 0
    for e in g["entries"]:
        want = set(e["allowed"])
        got = observable_set(e)
        nrows = sum(len(b["rows"]) for b in e["raw_peer_blocks"])
        nperm = 1
        for b in e["raw_peer_blocks"]:
            for i in range(1, len(b["rows"]) + 1):
                nperm *= i
        ok = (got == want)
        bad += not ok
        print(f"\n{'✓' if ok else '✗'} {e['id']}  {e['class']}")
        print(f"    행 {nrows}, 블록 {len(e['raw_peer_blocks'])}, "
              f"블록내 순열 {nperm} -> observable {len(got)}")
        if not ok:
            miss, extra = want - got, got - want
            if miss:
                print(f"    ★ allowed 에 있는데 열거되지 않음: {sorted(miss)}")
            if extra:
                print(f"    ★ 열거됐는데 allowed 에 없음:     {sorted(extra)}")
        # forbidden 예가 실제로 밖인지도 독립 확인
        if e["forbidden_example"] in got:
            print(f"    ✗ forbidden 예가 열거 집합 안에 있다 -- golden 오류")
            bad += 1
    print("\n" + "=" * 78)
    print(f"  {len(g['entries']) - bad}/{len(g['entries'])} 완전성 일치")
    if nperm := sum(1 for e in g["entries"] if len(e["allowed"]) == 1):
        print(f"  그중 {nperm}건은 허용 sequence 가 하나뿐이다 "
              f"(전순서 또는 projection 소거)")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
