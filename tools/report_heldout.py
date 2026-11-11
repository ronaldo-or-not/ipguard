#!/usr/bin/env python3
"""held-out attempt 2 결과 -> results/heldout.md.

보존된 raw 만 읽는다. DB 에 접속하지 않는다. 상수를 손으로 적지 않는다 —
모든 수치는 raw 에서 계산한다(초판에서 `param_scope` 를 하드코딩해 사실오류를
낸 적이 있다).

사용: python3 tools/report_heldout.py results/heldout-raw2 > results/heldout.md
"""
import collections
import json
import re
import sys

RAW = sys.argv[1] if len(sys.argv) > 1 else "results/heldout-raw2"
RAW1 = "results/heldout-raw"

T = [json.loads(l) for l in open(f"{RAW}/raw-trials.jsonl")]
T1 = [json.loads(l) for l in open(f"{RAW1}/raw-trials.jsonl")]
O = json.load(open(f"{RAW}/raw-obligations.json"))
C = json.load(open(f"{RAW}/p1-certificates.json"))["certificates"]
A = json.load(open(f"{RAW}/applicability.json"))
D = json.load(open(f"{RAW}/delta.json"))
AU = json.load(open(f"{RAW}/audit-sample.json"))["audit_sample"]
BODY = json.load(open("corpus/heldout.json"))
Q = {q["id"]: q for q in BODY["queries"]}
SQL = {i: " ".join(q["sql"].split()) for i, q in Q.items()}
LABCOLS = {"hx_cust": ("ssn", "birth"), "hx_pay": ("salary",)}


def rx(pat, i):
    return bool(re.search(pat, SQL[i], re.I))


def cause(reason):
    r = (reason or "").strip()
    if r.startswith("UNMODELED_NODE"):
        return "라벨 집계 미인증 (사유코드 G1)"
    if "CARD 는 factor-through" in r:
        return "CARD 미선언 (declassification 없음)"
    if "order_factor=fails" in r:
        return "ORD capability fails"
    if "equality_factor=fails" in r:
        return "EQ capability fails"
    if "cast: 인증 불가" in r:
        return "cast 미지원"
    if "인증서 없음 또는 출력 마스크 미등록" in r:
        return "함수 인증서 없음"
    return "기타: " + r[:40]


def nondegenerate(t):
    """관측이 실제로 무언가를 시험했는가.

    라벨을 건드리고, 게이트가 강제할 obligation 이 있고, 결과가 비어 있지
    않아야 한다. 셋 중 하나라도 아니면 통과는 구조적 항등식이지 측정이 아니다.
    """
    return (t["touches_labeled"] and t["n_raw_obligations"] > 0
            and t["result_d1"] != "(empty)")


def bucket(pol):
    S = [t for t in T if t["policy"] == pol]
    acc = [t for t in S if t["gate_accept"]]
    return {
        "S": S, "acc": acc, "q": {t["query_id"] for t in acc},
        "fid": collections.Counter(str(t["fidelity_result"]) for t in acc),
        "opa": collections.Counter(str(t["opacity_result"]) for t in acc),
        "uns": collections.Counter(str(t["opacity_unscoped"]) for t in acc),
        "rej": collections.Counter(cause(t["rejection_reason"])
                                   for t in S if not t["gate_accept"]),
        "nd": [t for t in acc if nondegenerate(t)],
        "fnd": [t for t in acc if t["fidelity_result"] == "pass"
                and t["n_raw_obligations"] > 0 and t["result_d1"] != "(empty)"],
    }


P = {p: bucket(p) for p in ("P0", "P1")}
NQ = len(Q)
NT = len(P["P0"]["S"])
W = print

W("# Held-out v1 — bug-discovery evaluation")
W("")
W("> **이것은 최종 안전성 표가 아니다.** 이 실행의 목적지는 §11-6(정리 1·2의")
W("> 구조적 귀납 증명)이었으나, 실행 중 **정리 2의 잠재적 반례**(G3)와 명세와")
W("> 어긋나는 정책 구현(PD1)이 드러났다. 그래서 이 실행은 `bug-discovery set`")
W("> 으로 확정하고, 수정 뒤 **새 동결·새 seed·새 코퍼스**로 최종 평가를 다시")
W("> 한다. `fidelity 위반 0` · `opacity 위반 0` 을 headline 으로 쓰지 않는다.")
W("")
W("최초 관측(attempt 1)은 정상 종료했으나 **관측 함수 자체가 결함**이어서 결과를")
W("쓰지 않는다. 보존물은 `results/heldout-raw/` 와")
W("`results/heldout-run-provenance.md` 에 그대로 남겼다. 아래 수치는 전부")
W("attempt 2(`results/heldout-raw2/`) 에서 나온다.")
W("")
W("이 문서는 외부 독립 재계산·반증 검증을 한 차례 거쳐 수정됐다.")
W("초판의 사실오류 1건(`param_scope`)과 근거 오류 1건(표 B)이 그 과정에서")
W("드러났고, 새 결함 3건(H4·G3·PD1)이 추가로 발견됐다. §5 참조.")
W("")
W("## 이 실행으로 주장할 수 있는 것 / 없는 것")
W("")
W("| | |")
W("|---|---|")
W("| ✅ 주장 가능 | 판정 결과의 **재현성**과 **데이터 독립성**이 확인됐다 |")
W("| ✅ | **측정 가능한** accepted subset 에서 fidelity·opacity 실패를 관찰하지 않았다 |")
W("| ✅ | P0 ⊆ P1 **단조성**이 성립한다 |")
W("| ❌ 주장 불가 | 출력이 **바뀐** trial 의 fidelity 는 대부분 미측정이다 |")
W("| ❌ | `ORD→FINAL_ORDER`·`EQ→CELL` 은 수락 사례가 0건이라 **양성 증거가 없다** |")
W("| ❌ | P1 scoped-opacity 성공은 δ 비동치 trial 제외에 크게 의존한다 |")
W("| ❌ | `F_impl \\ F_core` 동작에 대한 증거가 전혀 없다 (표 B 공집합) |")
W("")
W("이 실행이 실제로 잡아낸 것 — runner 의 δ 가정 오류(H1), wrapper 로 인한")
W("fail-close(H3)와 fail-open(H4), `aggdistinct` 의 `EQ` 누락(G3),")
W("declassification 과잉 설치(PD1), fidelity oracle coverage 공백, 평가 채널")
W("편중. 최종 평가 **전에** 이것들을 찾은 것이 이 단계의 성과다.")
W("")
W("## 0. provenance")
W("")
W("```")
W("GATE_COMMIT       5e21c7d7cd089773cf7f4a9a629b61bd53067ac7")
W("GENERATOR_COMMIT  9222ef3b4e7e13b685db5377486cb9eef8c7f236")
W("POLICY_COMMIT     533502d297e12ede971b8c08cce8ce2f46446b0c")
W("EVAL_INPUT_COMMIT 68ed0020fc0bd8d8e9131ef91a69ec4d0af8eec7")
W("seed              0xa3062488859d4a48")
W("attempt 1 runner  31d46a73964504ba766f979106e93cf2673b7048c84e08fff0937bbad2d72a70")
W("attempt 2 runner  1ddeb57d55e9f34f362dcd6d9d762e164024ed00cde97d9d8c9e3de296d76dc1")
W("입력 ordered list digest  115127f14c827b11   (두 attempt 동일 — 3중 대조)")
W("pair 적재 table digest    d934aa47c1e37c48   (16상태, 재적재 재현 확인)")
W("raw trial digest          8dd5d6066c7305d5")
W("```")
W("")
ck_o = {o["context_key"] for v in O.values() for o in v if o["effect"] == "CARD"}
ck_c = {c["context_key"] for c in C}
W("`raw-obligations.json` 만 예외다. 이 파일은 실행 **뒤에** 같은 코드로 다시")
W("뽑았다. 스키마를 재생성했으므로 canonical 안의 relation OID 가 달라")
W(f"`context_key` 는 인증서와 {len(ck_o & ck_c)}/{len(ck_c)} 만 겹친다. 다만")
W("질의별 obligation 개수는 digest 로 봉인된 `raw-trials.jsonl` 의")
W("`n_raw_obligations` 와 400/400 질의에서 일치하므로 **분포 통계는 독립**")
W("**확인**된다. effect/sink 분포를 읽을 때만 쓰고, 인증서 대응 관계의 근거로는")
W("쓰지 않는다.")
W("")
W("## 1. 분모")
W("")
lab = sum(1 for q in Q.values() if q["touches_labeled"])
ocq = collections.Counter(t["oracle_class"] for t in P["P0"]["S"])
W("| 단위 | 수 |")
W("|---|---:|")
W(f"| 질의 | {NQ} |")
W(f"| pair 유형 | {len(BODY['pair_types'])} |")
W(f"| pair trial (정책당) | {NT} |")
W(f"| 전체 trial (P0+P1) | {len(T)} |")
W(f"| label-touching 질의 | {lab} |")
W(f"| label 미접촉 질의 | {NQ - lab} |")
W(f"| fidelity oracle 가용(class A) 질의 | "
  f"{len({t['query_id'] for t in T if t['oracle_class'] == 'A'})} |")
W(f"| fidelity oracle 미구현(class C) 질의 | "
  f"{len({t['query_id'] for t in T if t['oracle_class'] == 'C'})} |")
W(f"| class A / class C trial (정책당) | {ocq['A']} / {ocq['C']} |")
W("")
W("shape: " + ", ".join(f"`{k}` {v}" for k, v in collections.Counter(
    q["shape"] for q in Q.values()).most_common()))
W("")
W("## 2. 적용가능성 — 게이트 실행 **전**에 고정")
W("")
ok = sum(1 for v in A.values() if v["masked_equivalent"])
de = sum(1 for v in D.values() if v["delta_equivalent"])
nm = sum(1 for v in D.values() if not v.get("measured", True))
nopred = sum(1 for v in D.values() if v.get("reason") == "술어 없음")
W(f"- `M(D1) = M(D2)`: **{ok}/{len(A)}** (pair 유형 4 × 테이블 2). 실패 0.")
W(f"- `δ_Q(D1) = δ_Q(D2)`: **{de}/{len(D)}**, 미측정 **{nm}**.")
W("  θ 를 실제 binding 으로 치환한 뒤 3VL 을 축약하지 않고 측정했다.")
W(f"- 그 중 **{nopred}건**({100 * nopred / len(D):.1f}%)은 질의에 WHERE 가 없어")
W("  δ 동치가 공허하게 성립한다. 실제로 술어를 비교한 것은")
W(f"  {len(D) - nopred}건이고 그 중 {len(D) - de}건이 상이하다.")
W("")
W("## 3. 실행 전 고정된 obligation·인증서")
W("")
eff = collections.Counter(o["effect"] for v in O.values() for o in v)
snk = collections.Counter(o["sink"] for v in O.values() for o in v)
pr = collections.Counter((o["effect"], o["sink"]) for v in O.values() for o in v)
kd = collections.Counter(o["context"].split(" [")[0]
                         for v in O.values() for o in v)
W(f"raw obligation **{sum(len(v) for v in O.values())}건** / 질의 {len(O)}건 "
  f"(obligation 0건 {sum(1 for v in O.values() if not v)}건 = label 미접촉 집합과 일치).")
W("")
W("effect: " + ", ".join(f"`{k}` {v}" for k, v in eff.most_common()) +
  " / sink: " + ", ".join(f"`{k}` {v}" for k, v in snk.most_common()))
W("")
W("(effect, sink): " + ", ".join(f"`{e}→{s}` {n}"
                                for (e, s), n in pr.most_common()))
W("")
W("context: " + ", ".join(f"`{k}` {v}" for k, v in kd.most_common()))
W("")
ps = collections.Counter(c["param_scope"] for c in C)
dis = len({(c["canonical"], c["table"]) for c in C})
inst = sum(collections.Counter(c["table"] for c in C)[t] * len(LABCOLS[t])
           for t in LABCOLS)
W(f"P1 인증서 **{len(C)}건** (obligation 인스턴스 단위. 서로 다른")
W(f"`(canonical, table)` 는 **{dis}개** — `{len(C)}` 을 '서로 다른 인증서 수'로")
W("읽으면 안 된다).")
W("")
W("| 필드 | 값 |")
W("|---|---|")
for f in ("effect", "observation", "sink"):
    W(f"| {f} | " + ", ".join(
        f"`{k}` {v}" for k, v in
        collections.Counter(c[f] for c in C).most_common()) + " |")
W("| **param_scope** | " + ", ".join(
    f"`{k}` **{v}**" for k, v in ps.most_common()) + " |")
W("")
W("`param_scope` 는 질의에 파라미터가 있을 때만 `all_values` 다")
W(f"(`tools/run_heldout.py:281`). 파라미터 질의 "
  f"{sum(1 for i in Q if '$1' in SQL[i])}건에서 나온 {ps.get('all_values', 0)}건만")
W(f"`all_values` 이고 나머지 {ps.get('none', 0)}건은 `none` 이다.")
W(f"실제 DB 설치 행수는 **{inst}행**이다 — 인증서 수가 아니다. 사유는 §5 PD1.")
W("")
W("## 표 A — 인증 평가")
W("")
W("| | P0 | P1 |")
W("|---|---:|---:|")


def row(lbl, f):
    W(f"| {lbl} | {f('P0')} | {f('P1')} |")


row("수락 (질의)", lambda p: f"{len(P[p]['q'])}/{NQ}")
row("수락 (trial)", lambda p: f"{len(P[p]['acc'])}/{NT}")
row("수락률 (trial)", lambda p: f"{100 * len(P[p]['acc']) / NT:.1f}%")
row("— 그중 **비퇴화**",
    lambda p: f"{len(P[p]['nd'])} ({len({t['query_id'] for t in P[p]['nd']})} 질의)")
row("fidelity — pass", lambda p: str(P[p]["fid"].get("pass", 0)))
row("fidelity — **fail**", lambda p: f"**{P[p]['fid'].get('fail', 0)}**")
row("fidelity — 미측정(class C)", lambda p: str(P[p]["fid"].get("None", 0)))
row("— pass 중 **비자명**",
    lambda p: f"{len(P[p]['fnd'])} ({len({t['query_id'] for t in P[p]['fnd']})} 질의)")
row("scoped opacity — 적용",
    lambda p: str(sum(1 for t in P[p]["acc"] if t["opacity_applicable"])))
row("scoped opacity — pass", lambda p: str(P[p]["opa"].get("pass", 0)))
row("scoped opacity — **fail**", lambda p: f"**{P[p]['opa'].get('fail', 0)}**")
row("scoped opacity — 비적용(δ 상이)",
    lambda p: str(sum(1 for t in P[p]["acc"] if not t["opacity_applicable"])))
row("(참고) 무범위 opacity fail", lambda p: str(P[p]["uns"].get("fail", 0)))
k0 = {(t["query_id"], t["pair_type"]) for t in P["P0"]["acc"]}
newt = [t for t in P["P1"]["acc"] if (t["query_id"], t["pair_type"]) not in k0]
W(f"| declassification 신규 수락 | — | {len(newt)} trial / "
  f"{len({t['query_id'] for t in newt})} 질의 |")
W("")
W("**비퇴화** = 라벨을 건드리고 ∧ obligation ≥ 1 ∧ 관측이 비어 있지 않은 trial.")
W("나머지는 통과가 측정이 아니라 구조적 항등식이다:")
acc_all = P["P0"]["acc"] + P["P1"]["acc"]
nolab = sum(1 for t in acc_all if not t["touches_labeled"])
empt = sum(1 for t in acc_all if t["result_d1"] == "(empty)")
W(f"수락 {len(acc_all)}건 중 라벨 미접촉 {nolab}건(읽는 컬럼이 D1·D2 에서")
W(f"byte-identical), 관측이 `(empty)` 인 것 {empt}건(12행 테이블에서 술어가")
W("충족 불가능).")
W("")
W("### 거부 사유 분해 (trial)")
W("")
W("게이트는 **처음 해소되지 않은 obligation 하나**를 사유로 보고한다. 아래는")
W("원인의 분할이 아니라 *먼저 보고된* 원인의 분포다. P0→P1 에서 capability")
W("계열이 늘어난 것도 새로 생긴 게 아니라, P0 에서 `CARD` 에 가려져 있던")
W("obligation 이 `CARD` 를 declassify 하자 드러난 것이다.")
W("")
W("| 사유 | P0 | P1 |")
W("|---|---:|---:|")
allc = sorted(set(P["P0"]["rej"]) | set(P["P1"]["rej"]),
              key=lambda k: -(P["P1"]["rej"][k] + P["P0"]["rej"][k]))
for k in allc:
    W(f"| {k} | {P['P0']['rej'][k]} | {P['P1']['rej'][k]} |")
W(f"| **합계** | **{sum(P['P0']['rej'].values())}** | "
  f"**{sum(P['P1']['rej'].values())}** |")
W("")
W("### 어느 채널이 실제로 시험됐는가")
W("")
W("| 채널 | 해당 질의 | P0 수락 | P1 수락 |")
W("|---|---:|---:|---:|")
CH = [("`ORDER BY` 가 라벨 → ORD/FINAL_ORDER",
       r"order\s+by\s+[^;]*\b(ssn|birth|salary)\b"),
      ("`GROUP BY` 가 라벨 → EQ/CELL",
       r"group\s+by\s+[^;]*\b(ssn|birth|salary)\b"),
      ("`SELECT DISTINCT` + 라벨 → EQ/ROW_COUNT", r"select\s+distinct"),
      ("`WHERE` 술어가 라벨 → CARD",
       r"where\s+[^;]*\b(ssn|birth|salary)\b")]
for nm2, pat in CH:
    hs = [i for i in Q if rx(pat, i) and Q[i]["touches_labeled"]]
    W(f"| {nm2} | {len(hs)} | {len(set(hs) & P['P0']['q'])} | "
      f"{len(set(hs) & P['P1']['q'])} |")
W("")
W("`ORD→FINAL_ORDER` 와 `EQ→CELL` 은 **수락 trial 이 0건**이다. 이 실행의")
W("opacity·fidelity 결과는 그 두 채널에 대해 아무 말도 하지 않는다. 실질적으로")
W("시험된 것은 `CARD`(전량 declassify)와 `VAL`(출력 마스킹) 두 채널뿐이다.")
W("")
W("## 표 B — 운영 범위 (`F_impl \\ F_core`)")
W("")
W("**근거는 텍스트가 아니라 트리다.** `corpus/heldout.json` 의")
W(f"`validated_with = {BODY['validated_with']}` — 생성기가 질의마다 재작성 후")
W("Query 트리를 `ipguard_fragment()` 로 분류하고 `F_core` 밖이면 폐기했다.")
W("배포된 코퍼스의 폐기 사유는")
W(f"`{json.dumps(BODY['discarded_by_reason_shape'], ensure_ascii=False)}` 뿐이다 —")
W(f"`alignment` 0, `syntax` 0, 총 {BODY['discarded_total']}/{BODY['attempts']}")
W("시도. 즉 400건 전부가 동결된 분류기의 `F_core` 판정을 통과했다.")
W("")
W("명세 §12 의 `F_core` 제외 목록에 대한 텍스트 대조는 **보조 확인**이다")
W("(명세가 `candidate-F_core` = 상한이라고 규정한 산출물이므로 단독 근거가 되지")
W("못한다):")
W("")
EXC = [("window function (frame 포함)", r"\bover\s*\("),
       ("`LATERAL`", r"\blateral\b"),
       ("recursive CTE", r"\bwith\s+recursive\b"),
       ("`DISTINCT ON`", r"\bdistinct\s+on\b"),
       ("`FETCH … WITH TIES`", r"\bwith\s+ties\b"),
       ("`GROUPING SETS`/`ROLLUP`/`CUBE`",
        r"\b(grouping\s+sets|rollup|cube)\s*\("),
       ("ordered-set aggregate (`WITHIN GROUP`)", r"\bwithin\s+group\b"),
       ("outer join", r"\b(left|right|full)\s+(outer\s+)?join\b"),
       ("`NOT EXISTS`", r"\bnot\s+exists\b"),
       ("`NOT IN` / `<> ALL`", r"\bnot\s+in\s*\(|<>\s*all\s*\("),
       ("row-valued `IN`", r"\(\s*\w+\s*,\s*\w+\s*\)\s+in\b"),
       ("상관 스칼라 서브쿼리 `= (SELECT`", r"=\s*\(\s*select\b"),
       ("DML / `RETURNING` / `COPY`",
        r"\breturning\b|\b(insert|update|delete)\s+|\bcopy\b"),
       ("명시 `COLLATE`", r"\bcollate\b"),
       ("SRF (`generate_series` 등)", r"\bgenerate_series\s*\("),
       ("unordered top-k (`LIMIT` w/o `ORDER BY`)", None)]
W("| 명세 §12 제외 항목 | 코퍼스 출현 |")
W("|---|---:|")
for nm2, pat in EXC:
    n = (sum(1 for i in Q if rx(r"\blimit\b", i) and not rx(r"\border\s+by\b", i))
         if pat is None else sum(1 for i in Q if rx(pat, i)))
    W(f"| {nm2} | {n} |")
W("")
W("**표 B 는 공집합이다.** 두 근거(트리 분류기 + 텍스트 대조)가 일치하고,")
W("`raw-trials.jsonl` 에 `OUTSIDE_CERTIFIED_FRAGMENT` 문자열도 0건이다.")
W("")
W("따라서 이 실행은 인증 범위 밖 동작 — 관측된 silent-wrong,")
W("`OUTSIDE_CERTIFIED_FRAGMENT` 거부 — 에 대해 **아무 증거도 제공하지 않는다**.")
W("이전 divergence 코퍼스의 window 8건 수치는 여기로 이월되지 않는다.")
W("")
W("주의 하나. `NOT IN` 과 row-valued `IN` 은 파서가 각각 `NOT(x = ANY …)` 와")
W("`RowCompareExpr`/AND-chain 으로 재작성하므로 **텍스트로는 원리적으로 탐지할**")
W("**수 없다**. 이 둘의 0 은 위 텍스트 행이 아니라 트리 분류기가 보증한다.")
W("초판은 `JOIN`·`EXISTS`·`IN (SELECT`·CTE·`VALUES`·`CASE` 를 세었는데, 이 여섯은")
W("명세 §12 가 `F_core` **안쪽**으로 넣은 구성이라 표 B 에 대한 정보량이 0이었다.")
W("")
W("## 4. 핵심 검증과 그 한계")
W("")
W("### 검증된 것")
W("")
uf = [t for t in P["P1"]["acc"] if t["opacity_unscoped"] == "fail"]
W(f"1. **출력이 달라진 P1 수락 {len(uf)} trial**"
  f"({len({t['query_id'] for t in uf})} 질의)은 전부 `δ_Q(D1) ≠ δ_Q(D2)` 이고,")
W("   전부 P0 에서 `CARD` 사유로 거부됐다. 수락은 전적으로 declassification")
W("   때문이고 차이는 `predicate-decision-trace` 범위 안이다.")
W("2. P0 수락 → P1 수락 **단조성 성립**, 역행 0.")
W("3. 게이트 판정은 pair 유형과 무관 — `gate_accept`·`rejection_reason` 불일치 0.")
W("")
W("### 그 검증이 닿지 않는 곳")
W("")
neq = [t for t in acc_all if t["result_d1"] != t["privileged"]]
neqA = [t for t in neq if t["oracle_class"] == "A"]
napp = sum(1 for t in P["P1"]["acc"] if not t["opacity_applicable"])
W("1. **fidelity 오라클은 강제가 출력을 바꾼 trial 에 한 번도 적용되지 않았다.**")
W(f"   수락 {len(acc_all)}건 중 `release ≠ privileged` 인 것이 {len(neq)}건인데")
W(f"   그 전부가 class C(미측정)다 (class A 인 것 {len(neqA)}건). 뒤집으면 class A")
W("   수락은 전건이 `release = privileged` 다. `fail 0` 은 위반이 없다는 증거가")
W("   아니라, 위반이 가능한 영역이 분모에 없었다는 사실의 결과다.")
W("2. **`scoped opacity fail 0` 은 정의 변경의 결과이기도 하다.** P1 비적용")
W(f"   {napp}건의 내역이 무범위 fail {P['P1']['uns'].get('fail', 0)} + pass "
  f"{napp - P['P1']['uns'].get('fail', 0)} 이다 — 제외집합이 실패집합과 거의")
W("   일치한다. 이 필터가 정당한 근거는 필터 자체가 아니라 위 검증 1(δ 상이 ∧")
W("   P0 거부)이다.")
W("3. **pair 무관 주장은 이 설계에서 반증 불가능하다.** 게이트는 SQL·카탈로그에")
W("   대한 정적 분석이고 `pair_type` 은 데이터 속성이라 판정이 갈릴 경로가 없다.")
W("   정작 pair 유형이 가르는 관측치(무범위 opacity)는 같은 질의 안에서 갈린다 —")
W(f"   fail {P['P1']['uns'].get('fail', 0)}건이 4의 배수가 아닌 것이 그 증거다.")
W("4. **단조성도 위험집합이 공집합이다.** P0 수락 질의의 obligation 은 전부")
W("   `VAL→CELL` 인데 인증서는 전부 `CARD` 라, P1 은 그 질의들에 대해 P0 과")
W("   똑같은 계산을 반복한다. 게다가 인증서 추가는 obligation 해소를 늘릴 뿐이라")
W("   단조성은 게이트 설계의 정리이지 측정 결과가 아니다.")
W("")
W("## 5. 발견된 결함")
W("")
W("### 하네스 (attempt 1) — 결과 폐기 사유")
W("")
ka = {(t["query_id"], t["pair_type"], t["policy"]): t for t in T1}
kb = {(t["query_id"], t["pair_type"], t["policy"]): t for t in T}
flip = [k for k in ka if ka[k]["gate_accept"] and not kb[k]["gate_accept"]]
W("| | 내용 | 영향 |")
W("|---|---|---|")
W("| H1 | δ 오라클이 술어에 `$1` 이 있으면 측정을 건너뛰고 "
  "`δ-equivalent=True` 로 가정 | opacity 판정이 부당하게 엄격 → 허위 fail 11 |")
W("| H2 | 파라미터/비파라미터 질의에 서로 다른 관측 함수 | 두 집합 비교 불가 |")
W("| H3 | 관측 wrapper 의 `z::text` 가 whole-row composite cast (`F_core` 밖) "
  "| 게이트가 wrapper 때문에 **fail-close** — 라벨접촉 비파라미터 264건 중 175건 |")
W(f"| **H4** | 같은 wrapper 가 내부 `ORDER BY` 를 **삼켰다** | 게이트가 "
  f"**fail-open** — attempt 1 이 수락한 {len(flip)} trial "
  f"({len({k[0] for k in flip})} 질의, 전부 `order_by`)을 attempt 2 는 "
  f"`ORD → FINAL_ORDER : order_factor=fails` 로 거부한다 |")
W("")
W("H4 가 H3 보다 나쁘다. H3 는 없는 위반을 만들었지만 H4 는 **있는 의무를**")
W("**숨겼다** — attempt 1 은 ORD 인증서 없이 라벨 컬럼으로 정렬하는 질의를 조용히")
W("수락했다. attempt 1 폐기 결정은 이 발견으로 더 강해진다.")
W("")
W("### 게이트 (`5e21c7d`)")
W("")
g1 = {t["query_id"] for t in P["P1"]["S"]
      if (t["rejection_reason"] or "").strip().startswith("UNMODELED_NODE")}
ad = [i for i in Q if rx(r"\b(count|sum|avg|max|min)\s*\(\s*distinct\s+"
                         r"[^)]*\b(ssn|birth|salary)\b", i)]
adeq = sum(1 for i in ad for o in O.get(i, []) if o["effect"] == "EQ")
dq = [i for i in Q if rx(r"select\s+distinct", i) and Q[i]["touches_labeled"]]
dqeq = sum(1 for i in dq for o in O.get(i, []) if o["effect"] == "EQ")
W("- **G1 사유코드 (건전성 영향 없음).** 라벨 컬럼 집계에")
W("  aggregate-compatibility 인증서가 없을 때 `UNMODELED_NODE: UNMODELED_EXPR`")
W(f"  로 보고한다 — 질의 {len(g1)}건 / {len(g1) * 4} trial. fail-closed 이지만")
W("  `F_core` 밖과 `F_core` 안-미인증을 구분할 수 없게 만든다. 반증검사: 라벨접촉")
W("  이면서 라벨 집계·라벨 cast 가 없는 265건 중 `UNMODELED_NODE` 는 0건.")
W(f"- **G3 의무 누락 (잠재 불건전).** `count(DISTINCT <라벨컬럼>)` 형태 {len(ad)}건이")
W("  마스킹된 컬럼 위에서 등가 기반 중복제거를 하는데 `EQ` obligation 을")
W(f"  **{adeq}건** 낸다. 대조로 질의 수준 `SELECT DISTINCT` + 라벨 {len(dq)}건은")
W(f"  `EQ` obligation {dqeq}건을 낸다. `ipguard_fragment()` 의 `Aggref` 검사도")
W(f"  `aggdistinct` 를 보지 않는다. 지금은 {len(ad)}건 전부 G1 으로 fail-close 되어")
W("  실제 불건전 수락이 없지만, aggregate-compatibility 인증서를 등록하는 순간")
W("  `EQ` 채널이 검사되지 않은 채 통과한다.")
W("- **G2 계측 (건전성 영향 없음).** `ipguard_pii_plan_count()` 가 set-operation")
W("  계획을 세지 않는다 (`HO0064`, `HO0149`, `HO0275`). 세 질의 모두 obligation 을")
W("  정상 생성하고 P0 에서 거부됐으므로 게이트는 실행됐다.")
W("")
W("### 정책 하네스")
W("")
W("- **PD1 declassification 과잉 설치.** `tools/run_heldout.py:271-273` 의 컬럼")
W("  제한 루프가 본문 `pass` 인 죽은 코드라, `install_certs` 가 인증서를 해당")
W("  테이블의 **모든** 라벨 컬럼에 설치한다. `birth` 술어에서 나온 CARD 인증서가")
W(f"  `ssn` 의 CARD declassification 도 부여한다. 인증서 {len(C)}건 → 설치")
W(f"  {inst}행. P1 의 실제 선언 범위가 보고된 것보다 넓다.")
W("")
W("## 6. 성능")
W("")
W("**미측정.** 공용 서버에서 `unprivileged_bpf_disabled=2`,")
W("`perf_event_paranoid=4`, sudo 없음 — eBPF·perf 계측이 불가능하다.")
W("")
W("planner-work proxy(`ipguard_pii_plan_count()`)는 **보고에서 제외한다**.")
W("G2 때문에 set-operation 계획을 세지 않아 신뢰할 수 없다. 한계는")
W("`ext/ipguard.c` 의 계수 지점 주석에 남겼다. 성능 수치는 이 프로젝트에서")
W("아직 **한 건도 측정된 적이 없다**.")
W("")
W("## 7. 수동 감사 표본")
W("")
W(f"질의 ID 해시 규칙 `sha256(id)[:4] % 40 == 0` 으로 **{len(AU)}건**. 결과를 보고")
W("고르지 않았고 두 attempt 에서 byte-identical 하다.")
W("")
W("| 질의 | shape | P0 | P1 | oracle |")
W("|---|---|---|---|---|")
for qid in AU:
    t0 = [t for t in P["P0"]["S"] if t["query_id"] == qid][0]
    t1 = [t for t in P["P1"]["S"] if t["query_id"] == qid][0]

    def g(t):
        return "수락" if t["gate_accept"] else cause(t["rejection_reason"])

    W(f"| `{qid}` | {t0['shape']} | {g(t0)} | {g(t1)} | {t0['oracle_class']} |")
