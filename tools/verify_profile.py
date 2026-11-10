#!/usr/bin/env python3
"""인증서 profile 검증 — 등록된 주장을 **실제 구현**에 대해 확인한다.

레지스트리는 `holds` 라고 쓰기만 하면 되는 표다. 그 문자열이 실제로 적용되는
변환의 성질과 일치한다는 보장은 어디에도 없었다. 실제로 회귀 시험은
별표 마스크(`'*'×char_length`)에 `order_factor=holds` 를 넣어 factor-through
경로를 시험해 왔다 -- 게이트 로직의 단위 시험으로는 타당하지만, 그 조합은
**의미론적으로 거짓**이다. profile 을 동결하려면 그 구분이 기계로 잡혀야 한다.

이 도구는 각 capability 를 probe 정의역 위에서 **전수 검사**한다.

    determinism        m(x) 를 두 번 불러 같은가
    total              m(x) 가 오류 없이 값을 내는가
    null_equivalence   m(NULL) IS NULL  ∧  x IS NOT NULL -> m(x) IS NOT NULL
    equality_factor    ∀x,y.  m(x) = m(y)  ⟺  x = y          (단사)
    order_factor       ∀x,y.  cmp(m(x),m(y)) = cmp(x,y)      (순서 매장)

전수 검사는 무한 정의역에 대한 증명이 아니다. 그래서 dossier
(`docs/certificate-profile-v1.md`)에 증명이나 그 부재를 함께 적고, 여기서는
**반례가 있으면 반드시 잡는다**는 방향만 보장한다. 반례를 하나라도 찾으면
그 주장은 `holds` 일 수 없다.

사용: python3 tools/verify_profile.py [--kind ctl:rot13]
"""
import subprocess
import sys

DB = "ipdev"

# probe 정의역. 별표 마스크의 길이 붕괴('aa','ab' -> '**')와 상수 마스크의
# 전면 붕괴를 **반드시** 노출하도록 고른다. 경계값·빈 문자열·multibyte 포함.
PROBE = {
    "text": ["NULL", "''", "'a'", "'b'", "'A'", "'aa'", "'ab'", "'n'", "'z'",
             "'*'", "'**'", "'P:a'", "'abc'", "'ABC'", "E'\\u00e9'", "'한'",
             "'한글'"],
    "date": ["NULL", "DATE '1900-01-01'", "DATE '1980-01-01'",
             "DATE '1990-01-01'", "DATE '2000-12-31'"],
    "int": ["NULL", "0", "1", "-1", "2", "2147483647"],
}
TYPE_SQL = {"text": "text", "date": "date", "int": "int"}

CAPS = ("determinism", "total", "null_equivalence", "equality_factor",
        "order_factor")


def psql(sql):
    return subprocess.run(["psql", "-q", "-A", "-t", "-F", "|", "-d", DB,
                           "-f", "-"], input=sql, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


def one(sql):
    """스칼라 **식** 하나를 평가한다."""
    return q(f"SELECT ({sql})")


def q(sql):
    """완전한 SELECT 문을 돌려 첫 값을 돌려준다."""
    r = psql(f"SET search_path=h5,public;\nSELECT 'V:'||coalesce(("
             f"{sql} LIMIT 1)::text,'(null)');")
    v = [l[2:] for l in r.stdout.splitlines() if l.startswith("V:")]
    return v[-1] if v else f"ERR:{r.stdout.strip()[:90]}"


def m(val, kind, ty, func=None):
    """★ MaskInstance 에 **등록된 함수**를 부른다.

    ipguard_mask 를 하드코딩하면 다른 함수로 등록된 인스턴스(예: identity
    redactor)의 '실제' 값이 엉뚱하게 나온다 -- 검증기가 검증 대상을 잘못
    부르는 셈이다. func 이름으로 분기한다."""
    v = f"{val}::{TYPE_SQL[ty]}"
    if func is None or func.startswith("ipguard_mask"):
        return f"ipguard_mask({v}, '{kind}')"
    base = func.split("(")[0]
    return f"{base}({v})"


def cnt_true(exprs):
    """참인 항의 개수. 하나도 없으면 '0'."""
    if not exprs:
        return "0"
    vals = ",".join(f"(({e}))" for e in exprs)
    return q(f"SELECT count(*)::text FROM (VALUES {vals}) t(x) WHERE x")


def measure(kind, ty, func=None):
    """probe 정역 위에서 다섯 capability 의 **실제** 값을 잰다."""
    def m_(v):
        return m(v, kind, ty, func)
    dom = PROBE[ty]
    nn = [v for v in dom if v != "NULL"]
    out = {"_eq_witness": None, "_ord_witness": None}

    # total: 모든 값에서 오류 없이 돈다 (NULL 포함)
    ok = all(not q(f"SELECT ({m_(v)}) IS NOT DISTINCT FROM "
                   f"({m_(v)})").startswith("ERR") for v in dom)
    out["total"] = "holds" if ok else "fails"

    # determinism: 같은 입력에 같은 출력
    bad = cnt_true([f"({m_(v)}) IS DISTINCT FROM ({m_(v)})"
                    for v in dom])
    out["determinism"] = "holds" if bad == "0" else "fails"

    # null_equivalence: NULL 파티션이 보존되는가
    nul = q(f"SELECT ({m('NULL', kind, ty)}) IS NULL")
    bad = cnt_true([f"({m_(v)}) IS NULL" for v in nn])
    out["null_equivalence"] = ("holds" if nul == "true" and bad == "0"
                               else "fails")

    pairs = [(a, b) for i, a in enumerate(nn) for b in nn[i + 1:]]

    # equality_factor: 단사인가. m(x)=m(y) 인데 x<>y 인 쌍이 있으면 fails.
    #
    # ★ `=` 가 아니라 `IS NOT DISTINCT FROM` 이어야 한다. nullify 마스크는
    #   모든 값을 NULL 로 보내는데 `NULL = NULL` 은 NULL 이라 참이 되지 않아
    #   검사가 **공허하게 통과**한다. 실제로 그렇게 통과했다.
    #   명세도 같은 이유로 SQL grouping equivalence(= NULL 들을 한 그룹으로)를
    #   쓴다 -- 여기서 쓰는 동치가 그것과 같아야 한다.
    bad = cnt_true([f"({m_(a)}) IS NOT DISTINCT FROM "
                    f"({m_(b)})" for a, b in pairs])
    out["equality_factor"] = "holds" if bad == "0" else "fails"
    if bad != "0":
        for a, b in pairs:
            if q(f"SELECT ({m_(a)}) IS NOT DISTINCT FROM "
                 f"({m_(b)})") == "true":
                out["_eq_witness"] = f"m({a}) = m({b}) 인데 {a} <> {b}"
                break

    # order_factor: sign(cmp(m(x),m(y))) == sign(cmp(x,y)) 인가
    def sgn(x, y):
        return (f"(CASE WHEN {x} < {y} THEN -1 WHEN {x} > {y} THEN 1 "
                f"ELSE 0 END)")

    def raw(v):
        return f"{v}::{TYPE_SQL[ty]}"

    bad = cnt_true([f"{sgn(m_(a), m_(b))} <> "
                    f"{sgn(raw(a), raw(b))}" for a, b in pairs])
    out["order_factor"] = "holds" if bad == "0" else "fails"
    if bad != "0":
        for a, b in pairs:
            if q(f"SELECT {sgn(m_(a), m_(b))} <> "
                 f"{sgn(raw(a), raw(b))}") == "true":
                out["_ord_witness"] = f"cmp(m({a}),m({b})) != cmp({a},{b})"
                break
    return out


def registered(kind):
    r = psql("SET search_path=h5,public;\n"
             "SELECT 'C:'||c.capability||'|'||c.claim||'|'||c.assurance "
             "FROM ipguard_mask_capability c JOIN ipguard_mask_instance i "
             "  ON i.mask_id = c.mask_id "
             f"WHERE i.normalized_args = 'kind={kind}';")
    out = {}
    for l in r.stdout.splitlines():
        if l.startswith("C:"):
            f = l[2:].split("|")
            out[f[0]] = (f[1], f[2])
    return out


def main():
    kinds = []
    if "--kind" in sys.argv:
        kinds = [(sys.argv[sys.argv.index("--kind") + 1], "text", None)]
    else:
        r = psql("SET search_path=h5,public;\n"
                 "SELECT 'K:'||i.normalized_args||'|'||i.input_type::text"
                 "||'|'||i.func::text "
                 "FROM ipguard_mask_instance i ORDER BY 1;")
        for l in r.stdout.splitlines():
            if not l.startswith("K:"):
                continue
            na, ity, fn = (l[2:].split("|") + ["", ""])[:3]
            k = na.split("=", 1)[1] if "=" in na else na
            ty = ("text" if ity in ("text", "character varying", "name")
                  else "date" if ity == "date"
                  else "int" if ity in ("integer", "bigint", "smallint")
                  else None)
            if ty:
                kinds.append((k, ty, fn))
    if not kinds:
        print("등록된 MaskInstance 가 없습니다.")
        return 0

    print("=" * 78)
    print("인증서 profile 검증 — 등록된 주장 vs 실제 구현 (probe 전수 검사)")
    print("=" * 78)
    nbad = 0
    for kind, ty, fn in kinds:
        reg = registered(kind)
        act = measure(kind, ty, fn)
        print(f"\n  kind='{kind}'  ({ty}, {fn or 'ipguard_mask'}, "
              f"probe {len(PROBE[ty])}값 / "
              f"쌍 {len(PROBE[ty]) * (len(PROBE[ty]) - 2) // 2})")
        for c in CAPS:
            claim, assur = reg.get(c, ("(미등록)", "-"))
            real = act[c]
            if claim == "(미등록)":
                mark, note = "·", "등록 없음"
            elif claim == "holds" and real != "holds":
                mark, note = "✗", "★ 등록은 holds 인데 반례가 있다"
                nbad += 1
            elif claim == "fails" and real == "holds":
                mark, note = "!", "등록이 실제보다 보수적(안전 방향)"
            elif claim == real:
                mark, note = "✓", ""
            else:
                mark, note = "·", ""
            w = act.get("_eq_witness") if c == "equality_factor" else \
                act.get("_ord_witness") if c == "order_factor" else None
            print(f"    {mark} {c:18} 등록={claim:8} 실제={real:8} "
                  f"{assur:20} {note}")
            if mark == "✗" and w:
                print(f"        반례: {w}")
    print("\n" + "=" * 78)
    print(f"  거짓 holds {nbad}건")
    return 0 if nbad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
