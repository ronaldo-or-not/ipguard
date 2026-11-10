#!/usr/bin/env python3
"""적대적 시험 5라운드 — 권한 / 롤 / 우회 경로.

1~3R 은 SQL 문장을, 4R 은 카탈로그 DDL 을 쳤다. 이번 표적은 **누가 이 컨트롤을
끌 수 있는가**다.

집행기가 아무리 정교해도 스위치를 아무나 끌 수 있으면 의미가 없다. GUC 의
권한 컨텍스트, 라벨 테이블의 접근 권한, 그리고 계획기를 아예 거치지 않는
경로(COPY, 복제, 덤프)를 본다.

시나리오는 전용 롤 `z5_app` 과 전용 테이블만 쓰고, teardown 은 실패해도
반드시 돈다.

사용: python3 score_adversarial5.py
"""
import subprocess
import sys

DB = ["-Atq", "-f", "-"]


def psql(script, user=None):
    cmd = ["psql"] + (["-U", user] if user else []) + DB
    r = subprocess.run(cmd, input=script, capture_output=True, text=True)
    return r.stdout.strip(), r.stderr.strip()


def probe(script, user=None):
    """평문이 나왔는가.

    ★ 공격용 SET 이 거부되는 것은 **성공**이지 실패가 아니다. 그래서 에러가
      있어도 마지막 질의의 출력을 봐야 한다 -- 에러만 보고 판정하면 "막혔다"와
      "쿼리가 안 돌았다"를 구별하지 못한다.
    """
    out, err = psql(script, user)
    blocked = "permission denied to set parameter" in err
    if out:
        last = out.splitlines()[-1]
        v = "masked" if "*" in last else "exposed"
        return (v + ("+차단" if blocked else "")), last[:36]
    if "ERROR" in err:
        msg = [l for l in err.splitlines() if "ERROR" in l][0]
        return "ERR", msg.split("ERROR:", 1)[-1].strip()[:56]
    return "EMPTY", ""


SETUP = """
DROP ROLE IF EXISTS z5_app;
CREATE ROLE z5_app LOGIN;
GRANT USAGE ON SCHEMA h5 TO z5_app;
GRANT SELECT ON h5.cust TO z5_app;
-- load_labels 가 라벨 테이블을 읽으므로 앱 롤에 SELECT 가 필요하다.
-- 없으면 쿼리가 통째로 에러난다(fail-closed 이긴 하나 앱이 멈춘다).
GRANT SELECT ON h5.pii_label TO z5_app;
DROP SCHEMA IF EXISTS z5_empty CASCADE;
CREATE SCHEMA z5_empty;
CREATE TABLE z5_empty.pii_label(relname text, attname text, kind text);
GRANT USAGE ON SCHEMA z5_empty TO z5_app;
GRANT SELECT ON z5_empty.pii_label TO z5_app;
-- ★ 실제 배포 모델: 집행은 **롤/전역 기본값**으로 켠다. 앱 사용자가 세션에서
--   켜는 게 아니다. GUC 를 PGC_SUSET 으로 바꾼 뒤에는 앱 사용자가 SET 할 수
--   없으므로, 이렇게 하지 않으면 시나리오가 전부 "SET 권한 없음" 에러가 되어
--   **정작 재려던 것(데이터가 새는가)을 못 잰다.**
ALTER ROLE z5_app SET search_path = h5, public;
ALTER ROLE z5_app SET ipguard.enforce = on;
ALTER ROLE z5_app SET ipguard.on_divergence = error;
"""

TEARDOWN = """
DROP SCHEMA IF EXISTS z5_empty CASCADE;
ALTER ROLE z5_app RESET ALL;
REVOKE ALL ON h5.cust FROM z5_app;
REVOKE ALL ON h5.pii_label FROM z5_app;
REVOKE ALL ON SCHEMA h5 FROM z5_app;
DROP FUNCTION IF EXISTS h5.z5_sd();
DROP ROLE IF EXISTS z5_app;
"""

# 앱 사용자는 enforce 를 SET 하지 않는다 -- 롤 기본값으로 켜져 있다
BASE = ""

SCENARIOS = [
    dict(id="Z01", name="일반 사용자가 enforce 를 끈다",
         note="★ GUC 가 PGC_USERSET 이면 앱 사용자(또는 SQL 인젝션)가 한 줄로 "
              "보안 컨트롤 전체를 끈다",
         user="z5_app", want="masked",
         sql=BASE + "SET ipguard.enforce = off;\n"
                    "SELECT ssn FROM h5.cust WHERE id=1;"),

    dict(id="Z02", name="라벨 스키마를 빈 곳으로 돌린다",
         note="★ enforce 를 켠 채로도 라벨 출처를 자기가 통제하는 빈 테이블로 "
              "바꾸면 마스킹할 대상이 없어진다",
         user="z5_app", want="masked",
         sql=BASE + "SET ipguard.label_schema = 'z5_empty';\n"
                    "SELECT ssn FROM h5.cust WHERE id=1;"),

    dict(id="Z03", name="판정식을 끈다",
         note="의미 발산 거부도 사용자가 끌 수 있는가",
         user="z5_app", want="ERR_or_masked",
         sql=BASE + "SET ipguard.on_divergence = allow;\n"
                    "SELECT count(DISTINCT ssn)::text FROM h5.cust;",
         hardened="on_divergence=error 를 롤 기본값으로 걸어 둔 상태에서 "
                  "사용자가 되돌릴 수 있는지 본다"),

    dict(id="Z04", name="SECURITY DEFINER 함수 안에서 끈다",
         note="함수 본문에서 SET 하면 호출자 권한과 무관하게 꺼지는가",
         user="z5_app", want="masked",
         setup=["CREATE FUNCTION h5.z5_sd() RETURNS text LANGUAGE plpgsql "
                "SECURITY DEFINER AS $$ BEGIN SET LOCAL ipguard.enforce = off; "
                "RETURN (SELECT ssn FROM h5.cust WHERE id=1); END $$",
                "GRANT EXECUTE ON FUNCTION h5.z5_sd() TO z5_app"],
         sql=BASE + "SELECT h5.z5_sd();"),

    dict(id="Z05", name="라벨 테이블을 지운다",
         note="앱 롤이 라벨을 지울 수 있으면 컨트롤이 무의미하다. "
              "SELECT 만 줬으므로 막혀야 한다",
         user="z5_app", want="ERR_or_masked",
         sql="DELETE FROM h5.pii_label WHERE attname='ssn';\n" + BASE +
             "SELECT ssn FROM h5.cust WHERE id=1;"),

    dict(id="Z06", name="COPY TO — 계획기를 거치지 않는다",
         note="COPY tbl TO 는 utility 문장이라 planner_hook 이 발화하지 않는다. "
              "4R 에서 이미 utility 로 분류했던 경로를 권한 관점에서 재확인",
         user="z5_app", want="masked",
         sql=BASE + "COPY (SELECT ssn FROM h5.cust WHERE id=1) TO STDOUT;"),

    dict(id="Z07", name="COPY tbl TO STDOUT (서브쿼리 없이)",
         note="★ 계획 경로가 아예 없다. 마스킹이 걸릴 자리가 없다",
         user="z5_app", want="masked",
         sql=BASE + "COPY (SELECT ssn FROM h5.cust WHERE id=1) TO STDOUT;"),

    dict(id="Z08", name="대조군 — 일반 사용자의 정상 조회",
         note="음성 대조군. 아무것도 안 건드리면 마스킹되어야 한다",
         user="z5_app", want="masked",
         sql=BASE + "SELECT ssn FROM h5.cust WHERE id=1;"),

    dict(id="Z10", name="SECURITY DEFINER 백도어를 감사가 잡는가",
         note="막을 수 없으면 감지한다. Z04 의 백도어 함수가 감사에 나와야 한다",
         user=None, want="detected",
         setup=["CREATE OR REPLACE FUNCTION h5.z5_sd() RETURNS text "
                "LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN "
                "SET LOCAL ipguard.enforce = off; "
                "RETURN (SELECT ssn FROM h5.cust WHERE id=1); END $$"],
         sql="SELECT count(*)::text FROM ipguard_audit_definers() "
             "WHERE funcname = 'z5_sd';"),

    dict(id="Z09", name="대조군 — 슈퍼유저의 정상 조회",
         note="음성 대조군. 운영자도 마스킹된다(컨트롤은 롤 무관)",
         user=None, want="masked",
         sql="SET search_path = h5, public;\nSET ipguard.enforce = on;\n"
             "SELECT ssn FROM h5.cust WHERE id=1;"),
]


def main():
    psql(SETUP)
    rows = []
    try:
        for sc in SCENARIOS:
            if "setup" in sc:
                psql("\n".join(s + ";" for s in sc["setup"]))
            got, detail = probe(sc["sql"], sc.get("user"))
            want = sc["want"]
            if want == "detected":
                got = "detected" if detail.strip() not in ("0", "") else "미탐"
                ok = got == "detected"
            else:
                ok = got.startswith(want) or got.startswith("masked") or (
                     want == "ERR_or_masked" and got in ("ERR", "EMPTY"))
            rows.append((sc, got, detail, ok))
    finally:
        psql(TEARDOWN)

    print("=" * 96)
    print("적대적 시험 5R — 권한 / 롤 / 우회 경로")
    print("=" * 96)
    print(f"{'ID':6}{'시나리오':34}{'롤':10}{'요구':9}{'실제':9}값")
    print("-" * 96)
    for sc, got, detail, ok in rows:
        print(f"{'  ' if ok else '! '}{sc['id']:4}{sc['name']:32}"
              f"{(sc.get('user') or 'superuser'):10}"
              f"{sc['want'][:8]:9}{got:9}{detail}")

    holes = [r for r in rows if r[1].startswith("exposed")]
    print()
    print("=" * 96)
    print(f"시나리오 {len(rows)}건   방어 {len(rows)-len(holes)}   "
          f"★ 평문 노출 {len(holes)}")
    if holes:
        print()
        print("★ 평문 노출:")
        for sc, got, detail, _ in holes:
            print(f"  {sc['id']} {sc['name']}  ({sc.get('user') or 'superuser'})")
            print(f"      {sc['note']}")
    return 1 if holes else 0


if __name__ == "__main__":
    sys.exit(main())
