#!/usr/bin/env python3
"""held-out 생성 결과를 **동결된 fragment classifier 로만** 검증한다.

생성기는 DB 없이 돌므로 syntax/alignment 폐기를 채울 수 없다. 이 스크립트가
rejection sampling 의 나머지를 마무리한다.

★ **게이트 판정은 절대 쓰지 않는다.** 그건 평가 대상을 평가로 고르는 것이다.
  `ipguard_fragment()` (동결된 fragment classifier) 만 유효성 검사에 쓴다.

  syntax     파스/재작성 실패
  alignment  ipguard_fragment() 가 F_core 밖이라고 한다
             -- generator/fragment alignment failure. 넷 중 하나다:
                (a) grammar/명세 불일치  (b) rewrite 가 예상 못 한 구조
                (c) fragment 의 false negative  (d) 문서/구현 불일치

사용: python3 tools/validate_heldout.py corpus/heldout.json
"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [q for q in sys.path if os.path.abspath(q or ".") != _here]

import hashlib     # noqa: E402
import json        # noqa: E402
import subprocess  # noqa: E402

SCHEMA_SQL = """
SET client_min_messages = warning;
DROP TABLE IF EXISTS h5.hx_cust, h5.hx_pay;
CREATE TABLE h5.hx_cust (id int PRIMARY KEY, grade text, dept text,
                         amt int, ssn text, birth date);
CREATE TABLE h5.hx_pay  (pid int PRIMARY KEY, id int, band text, salary int);
DELETE FROM h5.pii_label WHERE relname IN ('hx_cust','hx_pay');
INSERT INTO h5.pii_label VALUES
  ('hx_cust','ssn','hxsec'), ('hx_cust','birth','hxdate'),
  ('hx_pay','salary','hxnum');
"""


def psql(script):
    return subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                          input=script, capture_output=True, text=True)


def main():
    path = sys.argv[1]
    body = json.load(open(path))
    psql(SCHEMA_SQL)

    lines = ["SET search_path = h5, public;"]
    for q in body["queries"]:
        one = " ".join(q["sql"].split())
        lines.append(f"SELECT 'F:'||ipguard_fragment($ipg${one}$ipg$);")
    r = psql("\n".join(lines))
    verdicts = [l[2:] for l in r.stdout.splitlines() if l.startswith("F:")]
    if len(verdicts) != len(body["queries"]):
        print(f"!! 응답 {len(verdicts)} != 질의 {len(body['queries'])}")
        print((r.stderr.strip().splitlines() or ["(no stderr)"])[0])
        return 1

    kept, disc = [], dict(body.get("discarded_by_reason_shape", {}))
    for q, v in zip(body["queries"], verdicts):
        v = v.strip()
        if v.startswith("parse error"):
            reason = "syntax"
        elif v:
            reason = "alignment"
        else:
            kept.append(q)
            continue
        disc.setdefault(reason, {}).setdefault(q["shape"], 0)
        disc[reason][q["shape"]] += 1
        q["discard_reason"] = reason
        q["fragment_verdict"] = v

    body["queries"] = [dict(q, id=f"HO{i+1:04d}") for i, q in enumerate(kept)]
    body["discarded_by_reason_shape"] = disc
    body["n_generated"] = len(kept)
    body["shortfall"] = body["n_target"] - len(kept)
    body["n_touching_labeled"] = sum(1 for q in kept if q["touches_labeled"])
    rz = {}
    for q in kept:
        rz[q["shape"]] = rz.get(q["shape"], 0) + 1
    body["realized_shape_counts"] = rz
    body["validated_with"] = "ipguard_fragment() -- 동결된 fragment classifier"
    body["gate_used_for_selection"] = False

    with open(path, "w") as f:
        json.dump(body, f, ensure_ascii=False, indent=1, sort_keys=True)
    dg = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    print(f"검증 후 {len(kept)}/{body['n_target']}  "
          f"shortfall {body['shortfall']}")
    print(f"폐기 사유별: { {k: sum(v.values()) for k, v in disc.items()} }")
    for k in sorted(disc):
        if k != "duplicate":
            print(f"  {k}: {disc[k]}")
    print(f"라벨 접촉 {body['n_touching_labeled']}/{len(kept)}  "
          f"비접촉 {len(kept) - body['n_touching_labeled']}")
    print(f"digest {dg}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
