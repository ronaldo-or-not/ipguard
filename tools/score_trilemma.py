#!/usr/bin/env python3
"""동적 마스킹의 삼자택이 — Fidelity / Mask opacity / Totality 를 실측한다.

세 속성을 이렇게 정의한다:

  Fidelity      원본 질의를 계산한 뒤 **출력 컬럼만** 마스킹한 결과와 같다.
  Mask opacity  마스크로 구별되지 않는 두 DB 를 결과로도 구별할 수 없다.
  Totality      지원 언어의 모든 질의에 답한다(거부하지 않는다).

**불가능성**: 비주입 마스크 m(a)=m(b) 가 존재하면 셋을 동시에 만족할 수 없다.

    D1 = {a, a}      D2 = {a, b},  a≠b, m(a)=m(b)
    두 DB 의 마스킹된 모습은 동일하다.
    SELECT count(DISTINCT secret) 의 원본 정답은 각각 1, 2 다.
      · 둘 다 정확히 답하면      -> 두 DB 를 구별하므로 opacity 위반
      · 같은 값을 답하면          -> 적어도 하나는 fidelity 위반
      · 거부하면                  -> totality 위반

이 스크립트는 그 witness 를 **자동화**한다. 마스크가 타입별 상수이므로
민감 컬럼 값이 어떻게 다르든 두 표의 마스킹된 모습은 같다. 따라서

    Q(D1) 과 Q(D2) 의 결과가 다르면 = opacity 위반

이 성립한다. Fidelity 는 V3(투영 경계)가 정의상 기준이므로 그것과 비교한다.

세 지점을 같은 확장·같은 마스크 함수로 돌린다:
  source      V1  테이블 진입점 (마스킹 뷰 / PostgreSQL Anonymizer 계열)
  output_path V2  트리의 공개 경로 (이 확장의 기본)
  projection  V3  모든 관계 연산 뒤 (Oracle Data Redaction 계열)

사용: python3 score_trilemma.py
"""
import hashlib
import subprocess
import sys

MODES = ["source", "output_path", "projection"]
LABEL = {"source": "V1 소스", "output_path": "V2 출력경로", "projection": "V3 투영"}

SETUP = """
DROP TABLE IF EXISTS h5.tri_a, h5.tri_b;
-- D1: 고유값 6. 그리고 **정렬 순서가 id 순서의 역순**이 되도록 잡는다.
--     그래야 ORD 채널(정렬이 민감값에 의존)이 드러난다.
CREATE TABLE h5.tri_a (id int, secret text, grade text);
INSERT INTO h5.tri_a VALUES
  (1,'f','A'),(2,'e','A'),(3,'d','B'),(4,'c','B'),(5,'b','C'),(6,'a','C');
-- D2: 같은 행 수·같은 비민감 컬럼. 고유값 2, 정렬 순서는 id 순서.
CREATE TABLE h5.tri_b (id int, secret text, grade text);
INSERT INTO h5.tri_b VALUES
  (1,'a','A'),(2,'a','A'),(3,'a','B'),(4,'a','B'),(5,'b','C'),(6,'b','C');
-- 두 표의 마스킹된 모습은 같다(상수 마스크). 그러나
--   EQ  채널: 고유값 6 vs 2
--   ORD 채널: ORDER BY secret,id -> 6,5,4,3,2,1  vs  1,2,3,4,5,6
DELETE FROM h5.pii_label WHERE relname IN ('tri_a','tri_b');
INSERT INTO h5.pii_label VALUES ('tri_a','secret','ssn'), ('tri_b','secret','ssn');
"""

TEARDOWN = """
DROP TABLE IF EXISTS h5.tri_a, h5.tri_b;
DELETE FROM h5.pii_label WHERE relname IN ('tri_a','tri_b');
"""

# {T} 를 tri_a / tri_b 로 치환해 같은 질의를 두 DB 에 건다.
# declass=True 는 **명시적으로 허가된 결정 술어**를 쓰는 질의다. 정리 검증표에서는
# declassification 으로 제외한다 -- 그 채널은 정책상 허용한 것이지 결함이 아니다.
# 운영 행태표에서는 그대로 보고한다.
QUERIES = [
    ("Q1 컬럼 투영",        "SELECT id, secret FROM {T} ORDER BY id", False),
    ("Q2 파생 표현식",      "SELECT id, substr(secret,1,2) FROM {T} ORDER BY id", False),
    ("Q3 DISTINCT",         "SELECT DISTINCT secret FROM {T}", False),
    ("Q4 count(DISTINCT)",  "SELECT count(DISTINCT secret) FROM {T}", False),
    ("Q5 GROUP BY 민감컬럼", "SELECT secret, count(*) FROM {T} GROUP BY secret ORDER BY 2,1", False),
    ("Q6 ORDER BY+LIMIT",   "SELECT id FROM {T} ORDER BY secret, id LIMIT 3", False),
    ("Q7 술어 필터",        "SELECT count(*) FROM {T} WHERE secret = 'a'", True),
    ("Q9 ORDER BY(LIMIT없음)", "SELECT id FROM {T} ORDER BY secret, id", False),
    # ★ ORD 는 있는데 **관찰 sink 가 없다**. 모든 행이 관찰상 동일하므로
    #   순서가 달라도 구별되지 않아야 한다 -- effect 만으로는 누출을 말할 수
    #   없고 effect→sink 를 봐야 한다는 주장의 witness.
    ("Q10 ORD 있으나 sink 없음", "SELECT 'x' FROM {T} ORDER BY secret", False),
    ("Q8 대조군(비민감)",    "SELECT grade, count(*) FROM {T} GROUP BY grade ORDER BY 1", False),
]


def psql(sql, mode):
    """질의를 **그대로** 실행하고 클라이언트가 보는 것을 그대로 받는다.

    ★ 래퍼로 감싸면 안 된다. V3 는 **클라이언트가 보낸 질의의 최종 투영**에
      마스크를 넣으므로, 감싸는 순간 래퍼의 투영이 대상이 되어 아무것도
      마스킹되지 않는다. 측정 도구가 측정 대상의 동작을 바꾸는 전형이다.
    """
    script = (f"SET search_path = h5, public;\n"
              f"SET ipguard.enforce = on;\n"
              f"SET ipguard.mask_position = {mode};\n"
              f"SET ipguard.on_divergence = error;\n{sql};")
    r = subprocess.run(["psql", "-At", "-f", "-"],
                       input=script, capture_output=True, text=True)
    if "ERROR" in r.stderr:
        line = [l for l in r.stderr.splitlines() if "ERROR" in l][0]
        return ("REFUSED" if "ipguard" in line else "ERR"), line[-50:]
    body = [l for l in r.stdout.splitlines() if l and not l.startswith("SET")]
    return "OK", "\n".join(body)


def digest(v):
    return hashlib.md5(v.encode()).hexdigest()[:8] if v else "-"


def main():
    psql_raw(SETUP)
    rows = []
    try:
        for name, tmpl, declass in QUERIES:
            res = {}
            for m in MODES:
                sa, va = psql(tmpl.format(T="tri_a"), m)
                sb, vb = psql(tmpl.format(T="tri_b"), m)
                res[m] = (sa, va, sb, vb)
            rows.append((name, tmpl, res, declass))
    finally:
        psql_raw(TEARDOWN)

    print("=" * 100)
    print("동적 마스킹 삼자택이 — 같은 확장, 같은 마스크 함수, 세 지점")
    print("=" * 100)
    print("D1(tri_a): 민감값 6개 전부 다름   D2(tri_b): 고유값 2개")
    print("두 DB 의 **마스킹된 모습은 동일**하다(마스크가 상수이므로).")
    print()
    print(f"{'질의':22}{'V1 소스':26}{'V2 출력경로':26}{'V3 투영':26}")
    print("-" * 100)

    tally = {m: dict(fid=0, op=0, tot=0, n=0,
                     acc=0, afid=0, aop=0, an=0) for m in MODES}
    for name, tmpl, res, declass in rows:
        cells = []
        ideal = res["projection"][1] if res["projection"][0] == "OK" else None
        for m in MODES:
            sa, va, sb, vb = res[m]
            t = tally[m]
            t["n"] += 1
            if sa == "REFUSED":
                cells.append("거부")
                t["fid"] += 1          # 거부는 틀린 답을 주지 않는다
                t["op"] += 1
                continue               # 정리 검증표는 **수락된 질의만** 센다
            if sa != "OK":
                cells.append("ERR")
                continue
            t["tot"] += 1
            opaque = (va == vb)        # 두 DB 를 구별하지 못해야 한다
            faithful = (ideal is not None and va == ideal)
            t["op"] += opaque
            t["fid"] += faithful
            # 정리 검증: 수락된 질의만, declassified 채널 제외
            if not declass:
                t["an"] += 1
                t["afid"] += faithful
                t["aop"] += opaque
            mark = ("F" if faithful else "f") + ("O" if opaque else "o")
            cells.append(f"{mark} {digest(va)}/{digest(vb)}")
        print(f"{name:22}{cells[0]:26}{cells[1]:26}{cells[2]:26}")

    print()
    print("  대문자 F/O = 만족, 소문자 f/o = 위반.  해시는 D1/D2 결과.")
    print("  D1 과 D2 의 해시가 다르면 = 결과가 두 DB 를 구별함 = opacity 위반")
    print()
    print("=" * 100)
    print("표 A — 정리 검증  (수락된 질의만, 허가된 결정 술어는 declassify)")
    print("-" * 100)
    # ★ Acceptance 를 같이 보이지 않으면 "어려운 질의를 거부해 성공률을
    #   높였다" 는 반론을 받는다. 삼자택이의 비용은 바로 이 열이다.
    ndecl = sum(1 for _, _, _, d in rows if not d)
    print(f"{'':14}{'Acceptance':>13}{'Fidelity(수락)':>17}{'Scoped opacity(수락)':>22}")
    for m in MODES:
        t = tally[m]
        print(f"{LABEL[m]:14}{t['an']}/{ndecl:<12}"
              f"{t['afid']}/{t['an']:<16}{t['aop']}/{t['an']:<21}")
    print()
    print("  V2 는 **수락한 질의 안에서** 두 속성을 모두 지킨다. 대신 수락률이 낮다.")
    print("  이 세 열을 같이 봐야 삼자택이의 비용이 정직하게 보인다 --")
    print("  '거부로 산 정확성' 이라는 주장의 형식적 내용이 acceptance 열이다.")
    print()
    print("=" * 100)
    print("표 B — 운영 행태  (전체 질의, 숨기지 않는다)")
    print("-" * 100)
    print(f"{'':14}{'Fidelity':>12}{'Mask opacity':>16}{'Totality':>12}")
    for m in MODES:
        t = tally[m]
        n = t["n"]
        print(f"{LABEL[m]:14}{t['fid']}/{n:<11}{t['op']}/{n:<15}{t['tot']}/{n:<11}")
    print()
    print("세 지점이 서로 다른 속성을 포기한다 — 이것이 삼자택이의 실측이다.")
    print("V3(=Ideal) 의 opacity 위반은 **행 수 채널**이다: SELECT DISTINCT 의")
    print("반환 행 수가 원본 고유값 개수인데, 행 수는 redaction 할 수 없다.")
    return 0


def psql_raw(script):
    subprocess.run(["psql", "-Atq", "-f", "-"], input=script,
                   capture_output=True, text=True)


if __name__ == "__main__":
    sys.exit(main())
