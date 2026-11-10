#!/usr/bin/env python3
"""커버리지 감사 채점 — "라벨이 붙어야 하는데 안 붙은 컬럼"을 찾는다.

4라운드가 남긴 가장 큰 미해결 구멍: **파티션 DETACH 는 어떤 라벨 키잉으로도
못 막는다.** 상속 연결이 끊기면 자식은 라벨 없는 독립 테이블이 되고, 데이터는
같은 파일에 그대로 있다. 월별 파티션을 떼어 아카이브하는 것은 금융권 표준
운영이므로 실전에서 반드시 밟는다.

막을 수 없으면 **감지**해야 한다. 두 가지 감사기를 채점한다:

  구조 감사 ipguard_coverage()      -- 라벨된 컬럼과 이름+타입이 같은데 라벨 없음
  값 감사   ipguard_coverage_deep() -- 표본 값이 라벨된 컬럼과 겹침

★ 이 감사기들은 **집행의 입력이 아니다.** load_labels 는 라벨 테이블만 근거로
  삼는다. 여기 결과는 사람이 검토할 후보이고, 사람이 라벨 테이블에 넣어야
  효력이 생긴다. 이 분리를 깨면 코퍼스 측정이 무의미해진다.

사용: python3 score_coverage.py
"""
import subprocess
import sys

HEAD = "SET search_path = h5, public;\n"

# 현재 스키마에서 **라벨이 없는 채로 PII 를 들고 있는** 컬럼들.
# 코퍼스가 의도적으로 남겨 둔 것들이다(2R 이 규명한 물질화 클래스) --
# 감사기가 이걸 전부 찾아야 하고, 이것 말고 다른 걸 찾으면 오탐이다.
GROUND_TRUTH = {
    ("h5", "mv_cust", "ssn"),
    ("h5", "mv_cust", "name"),
    ("h5", "ctas_cust", "ssn"),
}


def psql(script):
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()


def rows(sql):
    out, err = psql(HEAD + sql + ";")
    if "ERROR" in err:
        print("  ERROR:", [l for l in err.splitlines() if "ERROR" in l][0][:90])
        return []
    return [tuple(l.split("|")) for l in out.splitlines() if l]


def audit(kind):
    if kind == "구조":
        return {(r[0], r[1], r[2]) for r in
                rows("SELECT nspname, relname, attname FROM ipguard_coverage()")}
    return {(r[0], r[1], r[2]) for r in
            rows("SELECT nspname, relname, attname FROM ipguard_coverage_deep()")}


def scenario(name, setup, teardown, expect_struct, expect_deep, probe=None):
    """DDL 시나리오를 만들고 두 감사기가 잡는지 본다."""
    psql(HEAD + "\n".join(s + ";" for s in setup))
    try:
        st = {(r[1], r[2]) for r in
              rows("SELECT nspname, relname, attname FROM ipguard_coverage()")}
        dp = {(r[1], r[2]) for r in
              rows("SELECT nspname, relname, attname FROM ipguard_coverage_deep()")}
        leaked = None
        if probe:
            out, _ = psql(HEAD + "SET ipguard.enforce = on;\n" + probe + ";")
            leaked = ("*" not in out) if out else None
        return (name,
                expect_struct in st, expect_deep in dp, leaked)
    finally:
        psql(HEAD + "\n".join(t + ";" for t in teardown))


def main():
    print("=" * 92)
    print("커버리지 감사 — 라벨이 붙어야 하는데 안 붙은 컬럼 찾기")
    print("=" * 92)

    results = {}
    for kind in ("구조", "값"):
        found = audit(kind)
        tp = found & GROUND_TRUTH
        fp = found - GROUND_TRUTH
        fn = GROUND_TRUTH - found
        results[kind] = (tp, fp, fn)
        print()
        print(f"[{kind} 감사] 정탐 {len(tp)}/{len(GROUND_TRUTH)}   "
              f"오탐 {len(fp)}   미탐 {len(fn)}")
        for t in sorted(tp):
            print(f"   ✅ {t[1]}.{t[2]}")
        for t in sorted(fp):
            print(f"   ! 오탐 {t[1]}.{t[2]}")
        for t in sorted(fn):
            print(f"   ! 미탐 {t[1]}.{t[2]}")

    print()
    print("=" * 92)
    print("DDL 시나리오 — 4R 이 못 막은 것을 감지할 수 있는가")
    print("-" * 92)
    scs = [
        scenario("파티션 DETACH",
                 ["CREATE TABLE h5.cov_p (id int, ssn text) PARTITION BY RANGE (id)",
                  "CREATE TABLE h5.cov_p1 PARTITION OF h5.cov_p "
                  "FOR VALUES FROM (1) TO (100)",
                  "INSERT INTO h5.cov_p SELECT id, ssn FROM h5.cust LIMIT 50",
                  "INSERT INTO h5.pii_label VALUES ('cov_p','ssn','ssn')",
                  "ALTER TABLE h5.cov_p DETACH PARTITION h5.cov_p1"],
                 ["DROP TABLE IF EXISTS h5.cov_p1",
                  "DROP TABLE IF EXISTS h5.cov_p CASCADE",
                  "DELETE FROM h5.pii_label WHERE relname LIKE 'cov%'"],
                 ("cov_p1", "ssn"), ("cov_p1", "ssn"),
                 probe="SELECT ssn FROM h5.cov_p1 LIMIT 1"),

        scenario("CTAS 사본",
                 ["CREATE TABLE h5.cov_c AS SELECT id, ssn FROM h5.cust LIMIT 50"],
                 ["DROP TABLE IF EXISTS h5.cov_c"],
                 ("cov_c", "ssn"), ("cov_c", "ssn"),
                 probe="SELECT ssn FROM h5.cov_c LIMIT 1"),

        scenario("이름 바꾼 사본 (구조 감사로는 못 잡는다)",
                 ["CREATE TABLE h5.cov_r AS "
                  "SELECT id, ssn AS id_no FROM h5.cust LIMIT 50"],
                 ["DROP TABLE IF EXISTS h5.cov_r"],
                 ("cov_r", "id_no"), ("cov_r", "id_no"),
                 probe="SELECT id_no FROM h5.cov_r LIMIT 1"),

        scenario("음성 대조군 — PII 아닌 사본",
                 ["CREATE TABLE h5.cov_n AS "
                  "SELECT id, grade, balance FROM h5.cust LIMIT 50"],
                 ["DROP TABLE IF EXISTS h5.cov_n"],
                 ("cov_n", "grade"), ("cov_n", "grade")),
    ]
    print(f"{'시나리오':38}{'구조':7}{'값':7}{'평문 누출':10}")
    print("-" * 92)
    bad = 0
    for name, st, dp, leaked in scs:
        control = name.startswith("음성")
        ok = (not st and not dp) if control else (st or dp)
        bad += 0 if ok else 1
        print(f"{'  ' if ok else '! '}{name:36}"
              f"{'잡음' if st else '못잡음':7}{'잡음' if dp else '못잡음':7}"
              f"{'예' if leaked else ('아니오' if leaked is False else '-'):10}")

    print()
    print("=" * 92)
    print("판정")
    print("-" * 92)
    s_tp, s_fp, s_fn = results["구조"]
    d_tp, d_fp, d_fn = results["값"]
    print(f"구조 감사: 정탐 {len(s_tp)}  오탐 {len(s_fp)}  미탐 {len(s_fn)}")
    print(f"값   감사: 정탐 {len(d_tp)}  오탐 {len(d_fp)}  미탐 {len(d_fn)}")
    print(f"시나리오 {len(scs)}건 중 실패 {bad}건")
    print()
    print("두 감사는 상호보완이다 -- 이름을 바꾼 사본은 구조 감사가 못 잡고,")
    print("값이 안 겹치는 파생 컬럼은 값 감사가 못 잡는다. 둘 다 돌려야 한다.")
    return 1 if (s_fp or d_fp or s_fn or d_fn or bad) else 0


if __name__ == "__main__":
    sys.exit(main())
