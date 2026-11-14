#!/usr/bin/env python3
"""적대적 시험 4라운드 — 카탈로그/DDL 표면.

1~3라운드는 전부 SQL 문장을 쳤다. 이번 표적은 **라벨이 카탈로그에 매달리는
방식**이다. `load_labels` 는 라벨 테이블을 이렇게 읽는다:

    JOIN pg_class c ON c.relname = l.relname
                   AND c.relnamespace = 'h5'::regnamespace
    ... UNION ALL pg_inherits 로 자손 전개 ...
    JOIN pg_attribute a ON a.attname = d.attname

즉 라벨은 **이름으로** 붙어 있고 상속으로 전파된다. 그러면 이름이 바뀌거나
상속이 끊기는 순간 라벨이 사라진다. DDL 한 줄로 마스킹이 꺼지는지가 질문이다.

각 시나리오는 setup → probe → teardown 이고, teardown 은 실패해도 반드시
돈다. 코퍼스 테이블은 건드리지 않는다 -- 전용 r4_* 테이블만 쓴다.

사용: python3 score_adversarial4.py
"""
import subprocess
import sys

# 라벨 키잉 방식을 바꿔 가며 같은 시나리오를 돌린다 -- results/label-keying.md
KEY = "name"          # --key oid 로 바꾼다


def pgset(enforce="on"):
    sch = "h5oid" if KEY == "oid" else "h5"
    return (f"SET search_path = h5, public;\n"
            f"SET ipguard.label_schema = '{sch}';\n"
            f"SET ipguard.label_key = {KEY};\n"
            f"SET ipguard.enforce = {enforce};\n"
            f"SET ipguard.on_divergence = allow;\n")

PROBE = "SELECT {col} FROM {rel} ORDER BY 1 LIMIT 1"


def psql(script, quiet=True):
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()


def observe(probe_sql):
    """마스킹됐는가. 값이 별표를 포함하면 마스킹, 아니면 평문."""
    out, err = psql(pgset() + probe_sql + ";")
    if err and "ERROR" in err:
        msg = [l for l in err.splitlines() if "ERROR" in l][0]
        return "ERR", msg.split("ERROR:", 1)[-1].strip()[:60]
    if not out:
        return "EMPTY", ""
    return ("masked" if "*" in out else "exposed"), out[:40]


# ── 시나리오 ────────────────────────────────────────────────────────────
# want 는 **보안이 요구하는 것**이다. 예측이 아니라 요구사항을 적는다 --
# 예측을 적으면 통과시키고 싶은 쪽으로 기대값이 휘어진다.
SCENARIOS = [
    dict(id="Y01", name="ALTER TABLE RENAME",
         note="라벨을 relname 으로 조인한다. 테이블 이름을 바꾸면?",
         setup=["CREATE TABLE h5.r4_a (id int, ssn text)",
                "INSERT INTO h5.r4_a VALUES (1, '800102-1000001')",
                "SELECT h5.r4_label('r4_a','ssn','ssn')",
                "ALTER TABLE h5.r4_a RENAME TO r4_a2"],
         probe="SELECT ssn FROM h5.r4_a2 LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_a2",
                   "DROP TABLE IF EXISTS h5.r4_a",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y02", name="ALTER TABLE RENAME COLUMN",
         note="라벨을 attname 으로 조인한다. 컬럼 이름을 바꾸면?",
         setup=["CREATE TABLE h5.r4_b (id int, ssn text)",
                "INSERT INTO h5.r4_b VALUES (1, '800102-1000001')",
                "SELECT h5.r4_label('r4_b','ssn','ssn')",
                "ALTER TABLE h5.r4_b RENAME COLUMN ssn TO ssn2"],
         probe="SELECT ssn2 FROM h5.r4_b LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_b",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y03", name="ALTER TABLE SET SCHEMA",
         note="라벨 조회가 relnamespace='h5' 로 제한된다. 스키마를 옮기면?",
         setup=["CREATE SCHEMA IF NOT EXISTS r4_other",
                "CREATE TABLE h5.r4_c (id int, ssn text)",
                "INSERT INTO h5.r4_c VALUES (1, '800102-1000001')",
                "SELECT h5.r4_label('r4_c','ssn','ssn')",
                "ALTER TABLE h5.r4_c SET SCHEMA r4_other"],
         probe="SELECT ssn FROM r4_other.r4_c LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS r4_other.r4_c",
                   "DROP SCHEMA IF EXISTS r4_other CASCADE",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y04", name="파티션 DETACH",
         note="라벨은 pg_inherits 로 자손에 전파된다. 파티션을 떼면?",
         setup=["CREATE TABLE h5.r4_p (id int, ssn text) PARTITION BY RANGE (id)",
                "CREATE TABLE h5.r4_p1 PARTITION OF h5.r4_p FOR VALUES FROM (1) TO (100)",
                "INSERT INTO h5.r4_p VALUES (1, '800102-1000001')",
                "SELECT h5.r4_label('r4_p','ssn','ssn')",
                "ALTER TABLE h5.r4_p DETACH PARTITION h5.r4_p1"],
         probe="SELECT ssn FROM h5.r4_p1 LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_p1",
                   "DROP TABLE IF EXISTS h5.r4_p CASCADE",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y05", name="파티션 ATTACH (양성 대조군)",
         note="나중에 붙인 파티션이 라벨을 물려받는가. 전파가 살아 있다는 확인",
         setup=["CREATE TABLE h5.r4_q (id int, ssn text) PARTITION BY RANGE (id)",
                "SELECT h5.r4_label('r4_q','ssn','ssn')",
                "CREATE TABLE h5.r4_q1 (id int, ssn text)",
                "INSERT INTO h5.r4_q1 VALUES (1, '800102-1000001')",
                "ALTER TABLE h5.r4_q ATTACH PARTITION h5.r4_q1 FOR VALUES FROM (1) TO (100)"],
         probe="SELECT ssn FROM h5.r4_q1 LIMIT 1",
         want="masked",
         teardown=["ALTER TABLE h5.r4_q DETACH PARTITION h5.r4_q1",
                   "DROP TABLE IF EXISTS h5.r4_q1",
                   "DROP TABLE IF EXISTS h5.r4_q CASCADE",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y06", name="상속 자식 나중 생성 (양성 대조군)",
         note="INHERITS 로 자식을 만들면 라벨이 전파되는가",
         setup=["CREATE TABLE h5.r4_par (id int, ssn text)",
                "SELECT h5.r4_label('r4_par','ssn','ssn')",
                "CREATE TABLE h5.r4_chi () INHERITS (h5.r4_par)",
                "INSERT INTO h5.r4_chi VALUES (1, '800102-1000001')"],
         probe="SELECT ssn FROM h5.r4_chi LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_chi",
                   "DROP TABLE IF EXISTS h5.r4_par CASCADE",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y07", name="라벨 추가 vs 준비된 문장",
         note="★ PREPARE 후에 라벨을 붙이면 그 세션은 계속 평문을 볼까. "
              "운영에서 '컬럼을 라벨링했다'가 즉시 효력을 갖는지의 문제다",
         setup=["CREATE TABLE h5.r4_d (id int, ssn text)",
                "INSERT INTO h5.r4_d VALUES (1, '800102-1000001')"],
         session=["PREPARE p1 AS SELECT ssn FROM h5.r4_d LIMIT 1",
                  "EXECUTE p1", "EXECUTE p1", "EXECUTE p1",
                  "EXECUTE p1", "EXECUTE p1", "EXECUTE p1",
                  "SELECT h5.r4_label('r4_d','ssn','ssn')",
                  "EXECUTE p1"],
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_d",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y08", name="FDW 외부 테이블",
         note="외부 테이블은 다른 relid 를 갖는다. 라벨이 붙을 자리가 없다",
         setup=["CREATE EXTENSION IF NOT EXISTS postgres_fdw",
                "CREATE SERVER IF NOT EXISTS r4_srv FOREIGN DATA WRAPPER postgres_fdw "
                "OPTIONS (host '/home/user/.pgsock', port '55432', dbname 'ipdev')",
                "CREATE USER MAPPING IF NOT EXISTS FOR CURRENT_USER SERVER r4_srv "
                "OPTIONS (user 'user')",
                "CREATE FOREIGN TABLE h5.r4_f (id bigint, ssn text) "
                "SERVER r4_srv OPTIONS (schema_name 'h5', table_name 'cust')"],
         probe="SELECT ssn FROM h5.r4_f LIMIT 1",
         want="masked",
         teardown=["DROP FOREIGN TABLE IF EXISTS h5.r4_f",
                   "DROP USER MAPPING IF EXISTS FOR CURRENT_USER SERVER r4_srv",
                   "DROP SERVER IF EXISTS r4_srv CASCADE"]),

    dict(id="Y10", name="FDW + 외부 테이블에 라벨 (양성 대조군)",
         note="외부 테이블 자체에 라벨을 붙이면 마스킹된다. 즉 메커니즘 실패가 "
              "아니라 커버리지 문제다 -- 원격 원본의 라벨은 전파되지 않는다",
         setup=["CREATE EXTENSION IF NOT EXISTS postgres_fdw",
                "CREATE SERVER IF NOT EXISTS r4_srv2 FOREIGN DATA WRAPPER postgres_fdw "
                "OPTIONS (host '/home/user/.pgsock', port '55432', dbname 'ipdev')",
                "CREATE USER MAPPING IF NOT EXISTS FOR CURRENT_USER SERVER r4_srv2 "
                "OPTIONS (user 'user')",
                "CREATE FOREIGN TABLE h5.r4_g (id bigint, ssn text) "
                "SERVER r4_srv2 OPTIONS (schema_name 'h5', table_name 'cust')",
                "SELECT h5.r4_label('r4_g','ssn','ssn')"],
         probe="SELECT ssn FROM h5.r4_g ORDER BY id LIMIT 1",
         want="masked",
         teardown=["DROP FOREIGN TABLE IF EXISTS h5.r4_g",
                   "DROP USER MAPPING IF EXISTS FOR CURRENT_USER SERVER r4_srv2",
                   "DROP SERVER IF EXISTS r4_srv2 CASCADE",
                   "SELECT h5.r4_unlabel()"]),

    dict(id="Y09", name="대조군 — 손대지 않은 테이블",
         note="음성 대조군. DDL 없이 그대로면 마스킹되어야 한다",
         setup=["CREATE TABLE h5.r4_e (id int, ssn text)",
                "INSERT INTO h5.r4_e VALUES (1, '800102-1000001')",
                "SELECT h5.r4_label('r4_e','ssn','ssn')"],
         probe="SELECT ssn FROM h5.r4_e LIMIT 1",
         want="masked",
         teardown=["DROP TABLE IF EXISTS h5.r4_e",
                   "SELECT h5.r4_unlabel()"]),
]


def run_scenario(sc):
    setup = "\n".join(s + ";" for s in sc["setup"])
    out, err = psql(pgset("off") + setup)
    if "ERROR" in err:
        return "SETUP", [l for l in err.splitlines() if "ERROR" in l][0][:80]

    if "session" in sc:
        # 같은 세션에서 PREPARE -> 여러 번 EXECUTE -> 라벨 추가 -> EXECUTE.
        # 계획 캐시(generic plan)는 5회 실행 후 만들어지므로 넉넉히 돌린다.
        script = (pgset() + "\n".join(s + ";" for s in sc["session"]))
        out, err = psql(script)
        if "ERROR" in err:
            return "ERR", [l for l in err.splitlines() if "ERROR" in l][0][:80]
        last = out.splitlines()[-1] if out.splitlines() else ""
        return ("masked" if "*" in last else "exposed"), last[:40]
    return observe(sc["probe"])


def main():
    global KEY
    if "--key" in sys.argv:
        KEY = sys.argv[sys.argv.index("--key") + 1]
    rows = []
    for sc in SCENARIOS:
        try:
            got, detail = run_scenario(sc)
        finally:
            # teardown 은 무슨 일이 있어도 돈다. 안 그러면 다음 라운드의
            # 다른 측정이 이 라운드의 잔해 위에서 돈다.
            psql(pgset("off") + "\n".join(t + ";" for t in sc["teardown"]))
        rows.append((sc, got, detail))

    print("=" * 96)
    print(f"적대적 시험 4R — 카탈로그 / DDL 표면   (label_key = {KEY})")
    print("=" * 96)
    print(f"{'ID':6}{'시나리오':28}{'요구':9}{'실제':10}값")
    print("-" * 96)
    for sc, got, detail in rows:
        bad = got != sc["want"]
        print(f"{'! ' if bad else '  '}{sc['id']:4}{sc['name']:28}"
              f"{sc['want']:9}{got:10}{detail}")

    holes = [r for r in rows if r[1] == "exposed"]
    errs = [r for r in rows if r[1] in ("ERR", "SETUP", "EMPTY")]
    ok = [r for r in rows if r[1] == r[0]["want"]]

    print()
    print("=" * 96)
    print(f"시나리오 {len(rows)}건")
    print(f"  방어      : {len(ok)}")
    print(f"  ★ 평문 노출: {len(holes)}   ← DDL 한 줄로 마스킹이 꺼졌다")
    print(f"  측정 불가  : {len(errs)}")
    for tag, lst in (("★ 평문 노출", holes), ("측정 불가", errs)):
        if lst:
            print()
            print(f"{tag}:")
            for sc, got, detail in lst:
                print(f"  {sc['id']} {sc['name']}  ({got}) {detail}")
                print(f"      {sc['note']}")
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())
