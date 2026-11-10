#!/usr/bin/env python3
"""
마스킹 뷰 vs ipguard(계획 재작성) 비교.

"그냥 마스킹 뷰 만들면 되잖아요?" 에 숫자로 답한다. 뷰 방식은 확장 코드가
0줄이고 현장에서 가장 흔하므로, 델타를 못 대면 이 프로젝트의 존재 이유가 없다.

세 가지 설정으로 같은 쿼리를 돌려 비교한다:
  base    : search_path=h5,   enforce=off   (원본, 정답)
  view    : search_path=vmask,h5, enforce=off  (마스킹 뷰)
  ipguard : search_path=h5,   enforce=on    (계획 재작성)

세 축을 잰다:
  1. 마스킹 커버리지 -- PII 가 실제로 가려지는가
  2. 정합성 피해     -- 정상 쿼리의 결과가 바뀌는가 (뷰는 술어까지 마스킹된
                        값을 보므로 필터가 깨진다)
  3. 우회            -- 스키마 수식, 함수 본문, COPY

사용: python3 score_view_baseline.py <corpus.json> [...]
"""
import json
import subprocess
import sys

CI = "repeat('A',88)"
CONFIG = {
    "base":    ("h5, public", "off"),
    "view":    ("vmask, h5, public", "off"),
    "ipguard": ("h5, public", "on"),
}


def expand(sql):
    if not (sql.startswith("__") and sql.endswith("__")):
        return sql
    kind, n = sql.split("_")[2], int(sql.split("_")[3])
    if kind == "NEST":
        q = "SELECT ssn AS a FROM cust"
        for i in range(n):
            q = f"SELECT a FROM ({q}) t{i}"
        return q
    return sql


def run(sql, cfg):
    sp, enf = CONFIG[cfg]
    script = (f"SET search_path = {sp};\n"
              f"SET ipguard.enforce = {enf};\n"
              f"SELECT count(*)::text || E'\\t' || "
              f"coalesce(md5(string_agg(x, '|' ORDER BY x)), '-') "
              f"FROM (SELECT t::text AS x FROM ({sql}) t) s;")
    r = subprocess.run(["psql", "-Atq", "-v", "ON_ERROR_STOP=1", "-f", "-"],
                       input=script, capture_output=True, text=True)
    if r.returncode != 0:
        msg = " ".join(l for l in r.stderr.splitlines() if "ERROR" in l)
        return ("ERR", msg[:80])
    for line in r.stdout.splitlines():
        if "\t" in line:
            a, b = line.split("\t", 1)
            return (int(a), b)
    return ("ERR", "no output")


def load(paths):
    out, seen = [], set()
    for p in paths:
        for e in json.load(open(p))["entries"]:
            sql = expand(e["sql"])
            up = sql.strip().upper()
            if e["id"] in seen:
                continue
            if up.startswith(("COPY", "CREATE", "INSERT", "UPDATE",
                              "DELETE", "MERGE", "BEGIN", "COMMIT",
                              "ROLLBACK", "SAVEPOINT", "SET ", "WITH D AS (DELETE")):
                continue
            seen.add(e["id"])
            out.append({"id": e["id"], "sql": sql.replace("$1", CI),
                        "exposes": e.get("exposes", []),
                        "expect": e.get("expect")})
    return out


BYPASS = [
    ("BP1", "SELECT ssn FROM h5.cust WHERE id = 1",
     "스키마 수식으로 base 테이블 직접 조회"),
    ("BP2", "SELECT f_ssn(1)",
     "함수 본문이 h5.cust 를 스키마 수식으로 읽음"),
    ("BP3", "SELECT ssn FROM h5.cust WHERE id = 2 UNION ALL SELECT ssn FROM h5.cust WHERE id = 3",
     "동일 우회, 집합연산"),
]
FILTER = [
    ("FL1", "SELECT id FROM cust WHERE ssn = '800102-1000001'",
     "PII 컬럼으로 필터링"),
    ("FL2", "SELECT count(*) FROM cust WHERE ci = repeat('A',88)",
     "CI 로 필터링 -- 파라미터 결속의 전제"),
    ("FL3", "SELECT id FROM cust WHERE substr(ssn,1,6) = '800102'",
     "술어 안 표현식"),
    ("FL4", "SELECT count(*) FROM cust c JOIN tx t ON t.cust_id = c.id WHERE c.id = 1",
     "PII 아닌 조인 키"),
]


def main():
    entries = load(sys.argv[1:])

    # ── 1. 마스킹 커버리지
    pii = [e for e in entries if e["exposes"]]
    v_masked = i_masked = v_err = i_err = 0
    v_fail, i_fail, i_errs, v_errs = [], [], [], []
    for e in pii:
        b = run(e["sql"], "base")
        if b[0] == "ERR":
            continue
        v, i = run(e["sql"], "view"), run(e["sql"], "ipguard")
        if v[0] == "ERR":
            v_err += 1
            v_errs.append((e["id"], v[1][:60]))
        elif v == b:
            v_fail.append(e["id"])
        else:
            v_masked += 1
        if i[0] == "ERR":
            i_err += 1
            i_errs.append((e["id"], i[1][:60]))
        elif i == b:
            i_fail.append(e["id"])
        else:
            i_masked += 1

    print("=" * 80)
    print("마스킹 뷰 vs ipguard — 같은 코퍼스, 같은 마스크 함수")
    print("=" * 80)
    print()
    print("① 마스킹 커버리지 (PII 노출 쿼리가 실제로 가려지는가)")
    print("-" * 80)
    n = len(pii)
    print(f"{'':22} {'마스킹됨':>10} {'누출':>6} {'에러':>6}")
    print(f"{'마스킹 뷰':22} {v_masked:>10} {len(v_fail):>6} {v_err:>6}   /{n}")
    print(f"{'ipguard':22} {i_masked:>10} {len(i_fail):>6} {i_err:>6}   /{n}")
    if v_fail:
        print(f"  뷰 누출: {', '.join(v_fail[:12])}")
    if i_fail:
        print(f"  ipguard 누출: {', '.join(i_fail[:12])}")
    for tag, lst in (("뷰", v_errs), ("ipguard", i_errs)):
        for qid, msg in lst:
            print(f"  {tag} 에러 {qid}: {msg}")

    # ── 2. 정합성 피해 (필터가 계속 동작하는가)
    print()
    print("② 정합성 — 필터링이 계속 동작하는가")
    print("-" * 80)
    print(f"{'ID':5} {'base':>7} {'view':>9} {'ipguard':>9}  설명")
    v_broken = i_broken = 0
    for qid, sql, desc in FILTER:
        b, v, i = run(sql, "base"), run(sql, "view"), run(sql, "ipguard")
        if v[0] == "ERR":
            v = ("ERR", v[1])
        if i[0] == "ERR":
            i = ("ERR", i[1])
        # count(*) 는 항상 1행이므로 행 수만 보면 파손이 안 잡힌다. 값까지 본다.
        vb = (v != b)
        ib = (i != b)
        v_broken += vb
        i_broken += ib
        print(f"{qid:5} {str(b[0]):>7} {str(v[0]):>9}{'!' if vb else ' '} "
              f"{str(i[0]):>8}{'!' if ib else ' '} {desc}")
    print(f"\n  필터 파손:  마스킹 뷰 {v_broken}/{len(FILTER)}"
          f"   ipguard {i_broken}/{len(FILTER)}")

    # ── 3. 우회
    print()
    print("③ 우회 — base 테이블·함수 본문 경유")
    print("-" * 80)
    print(f"{'ID':5} {'view':>10} {'ipguard':>10}  설명")
    v_byp = i_byp = 0
    for qid, sql, desc in BYPASS:
        b, v, i = run(sql, "base"), run(sql, "view"), run(sql, "ipguard")
        vb = (v == b)          # 원본과 같으면 = 안 가려짐 = 우회 성공
        ib = (i == b)
        v_byp += vb
        i_byp += ib
        print(f"{qid:5} {'우회됨' if vb else '차단':>10} "
              f"{'우회됨' if ib else '차단':>10}  {desc}")
    print(f"\n  우회 성공:  마스킹 뷰 {v_byp}/{len(BYPASS)}"
          f"   ipguard {i_byp}/{len(BYPASS)}")
    print("  (뷰 방식은 base 테이블 권한을 회수해야 막힌다. 회수하면 쓰기 경로와")
    print("   예외 계정이 전부 영향을 받으므로 그 자체가 도입 비용이다.)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
