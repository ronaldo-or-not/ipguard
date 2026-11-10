#!/usr/bin/env python3
"""held-out 평가 입력 생성기 — **seed 는 이 파일에 없다.**

★ seed 를 여기 박으면 "generator 를 seed 에 맞췄다" 는 방법론적 반론을
  막을 수 없다. 순서를 고정한다(docs/heldout-protocol.md):

    1. 이 파일을 **seed 없이** 커밋                  <- 지금
    2. 그 커밋 OID 에서 최종 seed 를 파생
    3. 이후 generator 수정 금지
    4. 생성 결과와 digest 만 다음 커밋에 저장

★ **질의만 동결하면 부족하다.** 평가 입력 전체가 동결돼야 한다:
    - masked-equivalent (D1, D2) -- **여러 유형**으로
    - mask instance 와 label 배치
    - parameterized query 의 타입과 θ binding
    - declassification policy seed
    - 독립 output-lineage metadata

  하나의 약한 DB pair 만 쓰면 예전 ORD witness 처럼 채널이 **우연히 가려진다**
  (삼자택이 opacity 7/8 -> 4/6 정정이 정확히 그 사고였다).

사용:
    python3 tools/gen_heldout.py --seed <hex16> --out heldout.json
"""
import os
import sys

# ★ tools/token.py 가 표준 라이브러리 `token` 을 가린다. 스크립트를
#   `python3 tools/gen_heldout.py` 로 돌리면 sys.path[0] 이 tools/ 라
#   argparse 의 지연 import 사슬(inspect -> tokenize -> token)이 터진다.
#   생성기는 남의 환경에서도 그대로 돌아야 하므로 여기서 막는다.
_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [q for q in sys.path if os.path.abspath(q or ".") != _here]

import argparse            # noqa: E402
import hashlib             # noqa: E402
import json                # noqa: E402
import random              # noqa: E402

# ==================================================================
# 스키마 — F_core (명세 v0.2.1 §12) 안에서만 생성한다
# ==================================================================
SCHEMA = {
    "hx_cust": {
        "pk": "id",
        "public": ["id", "grade", "dept", "amt"],
        "labeled": {"ssn": "hxsec", "birth": "hxdate"},
        "types": {"id": "int", "grade": "text", "dept": "text",
                  "amt": "int", "ssn": "text", "birth": "date"},
    },
    "hx_pay": {
        "pk": "pid",
        "public": ["pid", "id", "band"],
        "labeled": {"salary": "hxnum"},
        "types": {"pid": "int", "id": "int", "band": "text", "salary": "int"},
    },
}

# ------------------------------------------------------------------
# 생성 비율 — **생성 전에 고정.** 생성 후 바꾸면 seed 를 유지해도 표본이 달라진다.
# ------------------------------------------------------------------
SHAPE_WEIGHTS = {
    "projection": 20, "derived": 12, "aggregate": 16, "distinct": 10,
    "group_by": 14, "order_by": 14, "order_limit": 8, "setop": 6,
}
PRED_WEIGHTS = {"=": 40, "<>": 15, "<": 15, ">": 15, "IS NULL": 5, "none": 10}
PRED_OPERAND = {"const": 70, "param": 30}
AGG_WEIGHTS = {"count": 25, "count_distinct": 20, "sum": 20, "avg": 15,
               "min": 10, "max": 10}
FUNC_WEIGHTS = {"substr": 35, "lower": 25, "upper": 20, "length": 20}
SETOP_WEIGHTS = {"UNION ALL": 40, "UNION": 25, "EXCEPT": 20, "INTERSECT": 15}

# ★ **draw 당** 확률이지 질의당이 아니다. 한 질의가 술어·키·출력에서 각각
#   독립으로 뽑으므로, "적어도 하나가 라벨을 건드릴" 질의당 확률은 이보다
#   높다(실측 ~0.87). 실현 비율은 결과의 n_touching_labeled 에 기록된다.
#
#   비접촉 표본은 **false-positive 측정용**이고 전체 acceptance 에 섞어
#   수치를 부풀리면 안 된다. 그래서 질의마다 touches_labeled 를 기록해
#   결과를 반드시 분리할 수 있게 한다.
P_TOUCH_LABELED_PER_DRAW = 0.75

N_QUERIES = 400
MAX_ATTEMPTS = 20000
MAX_DEPTH = 2

# ==================================================================
# rejection sampling — **생성 전에 고정**
#
# ★ 게이트 결과를 보고 질의를 폐기하면 안 된다. 그건 평가 대상을 평가로
#   고르는 것이다. **동결된 fragment classifier 만** 유효성 검사에 쓴다.
#
#   syntax     문법 오류
#   alignment  ipguard_fragment() 가 F_core 밖이라고 한다
#              ★ 이름이 'outside_fcore' 가 아니라 **alignment** 인 이유:
#                generator 결함만이 아니다. 네 가지가 가능하다 --
#                  (a) generator grammar 와 명세 불일치
#                  (b) rewrite 가 예상 못 한 구조를 생성
#                  (c) ipguard_fragment() 의 false negative
#                  (d) fragment 문서와 구현 불일치
#                즉 **generator/fragment alignment failure** 다.
#   duplicate  중복 질의
#
# 폐기된 시도를 **shape·사유별로 보존**한다 -- 그래야 rejection sampling 후
# 실현 분포가 어떻게 바뀌었는지 알 수 있다.
# ==================================================================
DISCARD_REASONS = ("syntax", "alignment", "duplicate")


def w(rng, weights):
    ks = sorted(weights)
    return rng.choices(ks, weights=[weights[k] for k in ks])[0]


def pick_col(rng, t, labeled):
    s = SCHEMA[t]
    return rng.choice(sorted(s["labeled"] if labeled else s["public"]))


def gen_pred(rng, t, st):
    """술어 하나. st 에 라벨 접촉·파라미터 정보를 누적한다."""
    op = w(rng, PRED_WEIGHTS)
    if op == "none":
        return ""
    want = rng.random() < P_TOUCH_LABELED_PER_DRAW
    col = pick_col(rng, t, want)
    if col in SCHEMA[t]["labeled"]:
        st["labeled"].setdefault(col, set()).add("CARD")
    if op == "IS NULL":
        return f" WHERE {col} IS NULL"
    if w(rng, PRED_OPERAND) == "param":
        st["params"].append({"n": len(st["params"]) + 1,
                             "type": SCHEMA[t]["types"][col], "col": col})
        return f" WHERE {col} {op} ${len(st['params'])}"
    ty = SCHEMA[t]["types"][col]
    lit = ("'x'" if ty == "text" else
           "DATE '1990-01-01'" if ty == "date" else str(rng.randint(1, 99)))
    return f" WHERE {col} {op} {lit}"


def gen_query(rng):
    """F_core 안의 질의 하나. (sql, meta) 반환.

    ★ meta 의 `lineage` 는 **generator 가 스스로 아는 사실**이다 -- 무엇을
      만들었는지 알기 때문에 게이트를 보지 않고 적을 수 있다. 이것이 oracle
      독립성의 근거다(docs/heldout-protocol.md).
    """
    t = rng.choice(sorted(SCHEMA))
    shape = w(rng, SHAPE_WEIGHTS)
    pk = SCHEMA[t]["pk"]
    st = {"labeled": {}, "params": []}

    def L(col, *effects):
        if col in SCHEMA[t]["labeled"]:
            st["labeled"].setdefault(col, set()).update(effects)

    if shape == "projection":
        c1 = pick_col(rng, t, False)
        c2 = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
        L(c2, "VAL")
        sql = f"SELECT {c1}, {c2} FROM h5.{t}{gen_pred(rng, t, st)}"
        out_cols = [c1, c2]

    elif shape == "derived":
        col = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
        L(col, "VAL")
        fn = w(rng, FUNC_WEIGHTS)
        if SCHEMA[t]["types"][col] != "text":
            fn, expr = "length", f"length({col}::text)"
        elif fn == "substr":
            expr = f"substr({col}, 1, {rng.randint(1, 4)})"
        else:
            expr = f"{fn}({col})"
        sql = f"SELECT {pk}, {expr} FROM h5.{t}{gen_pred(rng, t, st)}"
        out_cols = [pk, expr]

    elif shape == "aggregate":
        col = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
        agg = w(rng, AGG_WEIGHTS)
        if agg in ("sum", "avg") and SCHEMA[t]["types"][col] != "int":
            agg = "count"
        L(col, "VAL", *(["EQ"] if agg == "count_distinct" else []))
        expr = (f"count(DISTINCT {col})" if agg == "count_distinct"
                else f"{agg}({col})")
        sql = f"SELECT {expr} FROM h5.{t}{gen_pred(rng, t, st)}"
        out_cols = [expr]

    elif shape == "distinct":
        # ★ 키를 1~2개로 둔다. 한 컬럼만 쓰면 변형이 8가지뿐이라 중복 폐기가
        #   폭증하고 실현 분포가 요청과 크게 어긋난다(스모크에서 확인).
        #   복합 키는 명세가 신경 쓰는 "공개 컬럼이 섞인 key vector" 이기도 하다.
        keys = [pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)]
        if rng.random() < 0.5:
            k2 = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
            if k2 != keys[0]:
                keys.append(k2)
        for k in keys:
            L(k, "VAL", "EQ", "CARD")
        sql = (f"SELECT DISTINCT {', '.join(keys)} FROM h5.{t}"
               f"{gen_pred(rng, t, st)}")
        out_cols = list(keys)

    elif shape == "group_by":
        keys = [pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)]
        if rng.random() < 0.5:
            k2 = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
            if k2 != keys[0]:
                keys.append(k2)
        for k in keys:
            L(k, "VAL", "EQ", "CARD")
        pred = gen_pred(rng, t, st)
        having = (f" HAVING count(*) > {rng.randint(0, 2)}"
                  if rng.random() < 0.4 else "")
        sql = (f"SELECT {', '.join(keys)}, count(*) FROM h5.{t}{pred}"
               f" GROUP BY {', '.join(keys)}{having}")
        out_cols = list(keys) + ["count(*)"]

    elif shape in ("order_by", "order_limit"):
        key = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
        out = pick_col(rng, t, False)
        L(key, "ORD", *(["CARD"] if shape == "order_limit" else []))
        direction = rng.choice(["", " DESC"])
        nulls = rng.choice(["", " NULLS FIRST", " NULLS LAST"])
        # ★ LIMIT 은 **전순서 키에서만** (명세 §1). PK 를 정렬 키 뒤에 둔다.
        sql = (f"SELECT {out} FROM h5.{t} "
               f"ORDER BY {key}{direction}{nulls}, {pk}")
        if shape == "order_limit":
            sql += f" LIMIT {rng.randint(1, 5)}"
        out_cols = [out]

    else:  # setop
        op = w(rng, SETOP_WEIGHTS)
        col = pick_col(rng, t, rng.random() < P_TOUCH_LABELED_PER_DRAW)
        L(col, "VAL", *([] if op == "UNION ALL" else ["EQ", "CARD"]))
        # 두 팔의 술어를 다르게 둬야 변형이 생긴다
        sql = (f"SELECT {col} FROM h5.{t}{gen_pred(rng, t, st)} {op} "
               f"SELECT {col} FROM h5.{t}{gen_pred(rng, t, st)}")
        out_cols = [col]

    return sql, {
        "shape": shape, "table": t,
        "touches_labeled": bool(st["labeled"]),
        # ★ 독립 output-lineage metadata. 게이트를 보지 않고 적는다.
        "lineage": {k: sorted(v) for k, v in st["labeled"].items()},
        "out_cols": out_cols,
        "params": st["params"],
    }


# ==================================================================
# masked-equivalent (D1, D2) — **여러 유형**
#
# 하나의 약한 pair 만 쓰면 채널이 우연히 가려진다. 유형별로 결과를 보고한다.
#
# ★ 모든 유형이 M(D1) = M(D2) 를 만족해야 한다(명세 §6.5). 특히 마스크가
#   null_equivalence 를 지키므로 **NULL 위치가 두 DB 에서 같아야** 한다 --
#   다르면 마스킹된 모습이 달라져 전제가 깨진다. 하네스가 3단계에서 검증한다.
# ==================================================================
PAIR_TYPES = ["eq_split", "ord_permutation", "null_structure", "multiplicity"]
N_ROWS = 12


def _vals(kind, ty, n, rng):
    """pair 유형·타입별 **라벨 컬럼 값 두 벌**. (a, b) 를 돌려준다.

    공개 컬럼은 두 DB 에서 **동일**하고, 라벨 컬럼만 다르다. 그래야
    M(D1) = M(D2) 가 성립한다(상수 마스크가 라벨 컬럼을 뭉갠다).
    """
    def enc(i):
        if ty == "text":
            return f"v{i:03d}"
        if ty == "date":
            return f"19{80 + (i % 20):02d}-{1 + (i % 12):02d}-15"
        return 1000 + i                      # int

    if kind == "eq_split":
        # 고유값 n개  vs  2개  -> EQ 채널
        return [enc(i) for i in range(n)], [enc(i % 2) for i in range(n)]
    if kind == "ord_permutation":
        # 정렬 순서가 PK 순서의 역순  vs  정순  -> ORD 채널
        return [enc(n - i) for i in range(n)], [enc(i) for i in range(n)]
    if kind == "null_structure":
        # NULL 위치는 같고(호출부가 넣는다) non-NULL 분포만 다르다
        return [enc(i) for i in range(n)], [enc((i * 7) % 3) for i in range(n)]
    # multiplicity: 고유값 **개수는 같고** 다중도만 다르다
    a = [enc(i % 3) for i in range(n)]
    b = [enc(0 if i < n - 2 else (i % 3)) for i in range(n)]
    return a, b


def gen_pair(rng, kind, table, n=N_ROWS):
    """(rows_D1, rows_D2) -- **스키마에 맞는** 행.

    ★ 앞 판은 스키마와 무관한 {id,secret,grade,dept,amt} 를 냈다. 어느
      테이블에도 적재할 수 없었다. seed 파생 전에 발견해 고쳤다.
    """
    sc = SCHEMA[table]
    pk = sc["pk"]
    # NULL 위치는 **두 DB 에서 같아야** 한다 -- 마스크가 null_equivalence 를
    # 지키므로 위치가 다르면 마스킹된 모습이 달라져 M(D1)=M(D2) 가 깨진다.
    nulls = {c: sorted(rng.sample(range(n), rng.randint(0, 2)))
             for c in sc["labeled"]}
    # 공개 컬럼은 두 DB 에서 **동일**하게 만든다
    pub = {}
    for c in sc["public"]:
        if c == pk:
            pub[c] = list(range(1, n + 1))
        elif sc["types"][c] == "int":
            pub[c] = [rng.randint(1, 9) for _ in range(n)]
        else:
            pub[c] = [rng.choice(["A", "B", "C"]) for _ in range(n)]
    lab = {c: _vals(kind, sc["types"][c], n, rng) for c in sc["labeled"]}

    def mk(side):
        rows = []
        for i in range(n):
            r = {c: pub[c][i] for c in sc["public"]}
            for c in sc["labeled"]:
                r[c] = None if i in nulls[c] else lab[c][side][i]
            rows.append(r)
        return rows

    return mk(0), mk(1)


def masked_view(rows, table):
    """M(D) -- 라벨 컬럼을 타입별 상수로 가린 모습. NULL 은 NULL 로 남는다
    (ipguard_mask 의 null_equivalence). 명세 §6.5 비교의 대상이다."""
    sc = SCHEMA[table]
    out = []
    for r in rows:
        m = dict(r)
        for c in sc["labeled"]:
            m[c] = None if r[c] is None else "<masked>"
        out.append(m)
    return out


def check_masked_equivalent(d1, d2, table):
    """명세 §6.5 의 다섯 조건을 **실제로** 확인한다.

    ★ 가정하면 안 된다. witness 전제가 깨진 채로 opacity 를 재면 그 수치는
      아무 의미가 없다 -- 삼자택이 7/8 -> 4/6 정정이 그 사고였다.
    """
    sc = SCHEMA[table]
    pk = sc["pk"]
    fails = []
    if len(d1) != len(d2):
        fails.append("행 다중도 불일치")
        return fails
    for c in sc["public"]:                       # 조건 2: 공개 컬럼
        if [r[c] for r in d1] != [r[c] for r in d2]:
            fails.append(f"공개 컬럼 {c} 불일치")
    if [r[pk] for r in d1] != [r[pk] for r in d2]:
        fails.append("공개 row identity 대응 불일치")   # 조건 4
    for c in sc["labeled"]:                      # 조건 5: NULL 취급
        if [r[c] is None for r in d1] != [r[c] is None for r in d2]:
            fails.append(f"NULL 위치 불일치: {c}")
    m1, m2 = masked_view(d1, table), masked_view(d2, table)
    if sorted(map(str, m1)) != sorted(map(str, m2)):   # 조건 1+3: bag 동일
        fails.append("마스킹된 bag 불일치")
    return fails


def main():
    ap = argparse.ArgumentParser()
    # ★ 기본값 없음 -- 실수로 임의 seed 를 쓰는 것을 막는다
    ap.add_argument("--seed", required=True,
                    help="16자리 hex. docs/heldout-protocol.md 의 유도 규칙으로 "
                         "**generator 커밋 OID** 에서 파생한 값")
    ap.add_argument("--out", required=True)
    a = ap.parse_args()

    rng = random.Random(int(a.seed, 16))
    seen, out, discarded = set(), [], []
    attempts = 0
    while len(out) < N_QUERIES and attempts < MAX_ATTEMPTS:
        attempts += 1
        sql, meta = gen_query(rng)
        if sql in seen:
            # ★ 폐기된 시도를 shape·사유별로 **보존**한다
            discarded.append({"reason": "duplicate", "shape": meta["shape"],
                              "touches_labeled": meta["touches_labeled"]})
            continue
        seen.add(sql)
        out.append({"id": f"HO{len(out)+1:04d}", "sql": sql, **meta})

    # 테이블마다 pair 를 만든다 -- 질의가 두 테이블을 다 쓴다
    pairs, pair_checks = {}, {}
    for k in PAIR_TYPES:
        pairs[k] = {}
        for tb in sorted(SCHEMA):
            d1, d2 = gen_pair(rng, k, tb)
            pairs[k][tb] = {"d1": d1, "d2": d2}
            # ★ M(D1)=M(D2) 를 **생성 시점에** 확인한다. 게이트를 보기 전이다.
            pair_checks[f"{k}/{tb}"] = check_masked_equivalent(d1, d2, tb)

    # 요청 분포 vs 실현 분포 -- rejection 후 무엇이 바뀌었는지 보이게
    realized = {}
    for q in out:
        realized[q["shape"]] = realized.get(q["shape"], 0) + 1
    disc_by = {}
    for d in discarded:
        disc_by.setdefault(d["reason"], {}).setdefault(d["shape"], 0)
        disc_by[d["reason"]][d["shape"]] += 1

    body = {
        "generator": "tools/gen_heldout.py",
        "seed": a.seed,
        "n_target": N_QUERIES, "n_generated": len(out),
        "attempts": attempts, "max_attempts": MAX_ATTEMPTS,
        "max_depth": MAX_DEPTH, "shortfall": N_QUERIES - len(out),
        "discard_reasons": list(DISCARD_REASONS),
        "discarded_total": len(discarded),
        "discarded_by_reason_shape": disc_by,
        "requested_shape_weights": SHAPE_WEIGHTS,
        "realized_shape_counts": realized,
        "n_touching_labeled": sum(1 for q in out if q["touches_labeled"]),
        "weights": {
            "pred": PRED_WEIGHTS, "pred_operand": PRED_OPERAND,
            "agg": AGG_WEIGHTS, "func": FUNC_WEIGHTS, "setop": SETOP_WEIGHTS,
            "p_touch_labeled_per_draw": P_TOUCH_LABELED_PER_DRAW,
        },
        # 평가 입력 전체 -- 질의만으로는 부족하다
        "mask_instances": [
            {"kind": "hxsec", "in": "text", "out": "text"},
            {"kind": "hxdate", "in": "date", "out": "date"},
            {"kind": "hxnum", "in": "int", "out": "int"},
        ],
        "label_placement": {t: SCHEMA[t]["labeled"] for t in sorted(SCHEMA)},
        "db_pairs": pairs,
        "pair_types": PAIR_TYPES,
        "n_rows_per_pair": N_ROWS,
        # ★ applicability 행렬의 첫 조건. 빈 리스트가 정상이다.
        "masked_equivalence_check": pair_checks,
        "masked_equivalence_ok": all(not v for v in pair_checks.values()),
        # opacity 의 단위를 미리 고정한다 -- 질의 수와 trial 수를 섞으면
        # 표본이 부풀려진다.
        "trial_unit": {
            "generated_queries": N_QUERIES,
            "pair_types": len(PAIR_TYPES),
            "query_pair_trials": N_QUERIES * len(PAIR_TYPES),
            "note": "trial = (Q[θ], pair). 질의 수와 trial 수는 다른 단위다.",
        },
        "note": [
            "★ alignment 폐기는 generator 결함만이 아니다. 네 가지가 가능하다:",
            "  (a) generator grammar 와 명세 불일치",
            "  (b) rewrite 가 예상 못 한 구조를 생성",
            "  (c) ipguard_fragment() 의 false negative",
            "  (d) fragment 문서와 구현 불일치",
            "  이름이 generator/fragment alignment failure 인 이유다.",
            "",
            "★ acceptance 를 전체로만 보고하면 안 된다. 비접촉 25% 가 쉬운",
            "  표본이라 수치를 올린다. touches_labeled 로 분리하고,",
            "  label-touching subset 에서 effect·sink 별 분포까지 낸다.",
            "",
            "★ lineage 는 generator 가 스스로 아는 사실이다 -- 게이트를 보지",
            "  않고 적었으므로 oracle 로 독립적이다.",
        ],
        "queries": out,
    }
    with open(a.out, "w") as f:
        json.dump(body, f, ensure_ascii=False, indent=1, sort_keys=True)
    digest = hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True).encode()).hexdigest()
    print(f"질의 {len(out)}/{N_QUERIES}  시도 {attempts}  "
          f"폐기 {len(discarded)}  shortfall {body['shortfall']}")
    print(f"라벨 접촉 {body['n_touching_labeled']}/{len(out)}  "
          f"비접촉 {len(out) - body['n_touching_labeled']}")
    print(f"DB pair 유형 {len(PAIR_TYPES)}: {', '.join(PAIR_TYPES)}")
    print(f"digest {digest}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
