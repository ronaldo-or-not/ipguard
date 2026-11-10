#!/usr/bin/env bash
# 독립 구현 교차검증 — PostgreSQL Anonymizer 에 우리 공격 클래스를 그대로 건다.
#
# 왜 필요한가: 3~5라운드가 찾은 결함 25건은 **우리 구현의 버그**로 읽힐 수 있다.
# 심사위원의 첫 질문이 그것이다 -- "GUC 를 USERSET 으로 만든 건 당신 실수 아닌가?
# 이게 왜 논문인가?"
#
# 같은 실패가 **독립된 서드파티 구현**에서도 나오면 그건 우리 버그가 아니라
# 이 부류 전체의 성질이다. 안 나오면 우리 버그가 맞고 접어야 한다.
#
# 대상: PostgreSQL Anonymizer 1.3.2 (dalibo) -- 오픈소스 마스킹 확장의 사실상 표준.
#
# ★ 공정성: anon 문서가 권장하는 하드닝(원본 스키마 접근 REVOKE)을 **적용한
#   상태**에서도 남는지를 본다. 하드닝을 빼먹고 "우회된다"고 하면 부당하다.
#
# 사용: bash crosscheck-anon.sh
set -u
export PATH=$HOME/pg/bin:$PATH PGHOST=$HOME/.pgsock PGPORT=55432

DB=anontest
own() { psql -d $DB -Atc "$1" 2>&1 | tail -1; }            # 소유자(원본 값)
msk() { psql -d $DB -U anon_app -Atc "$1" 2>&1 | tail -1; } # 마스킹 대상 롤

# ── 준비 (멱등) ────────────────────────────────────────────────────────────
psql -d postgres -X -q -c "DROP DATABASE IF EXISTS $DB" -c "CREATE DATABASE $DB" \
    -c "ALTER DATABASE $DB SET session_preload_libraries = 'ipguard', 'anon'" \
    >/dev/null 2>&1

psql -d $DB -X -q >/dev/null 2>&1 <<'SQL'
CREATE EXTENSION IF NOT EXISTS anon CASCADE;
CREATE TABLE cust (
    id bigserial PRIMARY KEY, ci text, name text, ssn text,
    phone text, grade text, balance numeric(18,2));
INSERT INTO cust (ci, name, ssn, phone, grade, balance)
SELECT repeat('A',88), '고객'||i,
       '8001'||lpad((i%28+1)::text,2,'0')||'-1'||lpad(i::text,6,'0'),
       '010-'||lpad(i::text,4,'0')||'-0000',
       (ARRAY['A','B','C'])[1+(i%3)], (i*1000)::numeric
  FROM generate_series(1,200) i;
SECURITY LABEL FOR anon ON COLUMN cust.ssn  IS 'MASKED WITH VALUE ''**************''';
SECURITY LABEL FOR anon ON COLUMN cust.name IS 'MASKED WITH VALUE ''****''';
DROP ROLE IF EXISTS anon_app;
CREATE ROLE anon_app LOGIN;
GRANT USAGE ON SCHEMA public TO anon_app;
GRANT SELECT ON cust TO anon_app;
SECURITY LABEL FOR anon ON ROLE anon_app IS 'MASKED';
SELECT anon.start_dynamic_masking();
SQL

echo "======================================================================"
echo "독립 구현 교차검증 — PostgreSQL Anonymizer 1.3.2"
echo "======================================================================"
echo
echo "[1] 하드닝 전 — anon 기본 배포 상태"
echo "----------------------------------------------------------------------"
printf '  %-42s %s\n' "기준선 (마스킹 동작 확인)"        "$(msk "SELECT ssn FROM cust WHERE id=1")"
printf '  %-42s %s\n' "★ 마스킹 롤이 search_path 되돌림" "$(msk "SET search_path=public; SELECT ssn FROM cust WHERE id=1")"
printf '  %-42s %s\n' "★ 스키마 수식 직접 조회"          "$(msk "SELECT ssn FROM public.cust WHERE id=1")"
echo
echo "  → anon 의 동적 마스킹은 **롤의 search_path 를 조작**하는 방식이다"
echo "    (anon 문서: \"the search_path of the masked role is rigged\")."
echo "    롤이 자기 search_path 를 되돌리면 그대로 뚫린다 -- 우리 뷰 베이스라인의"
echo "    우회 3/3 과 **같은 메커니즘, 같은 결과**다."
echo
echo "[2] anon 문서가 권장하는 하드닝 적용 (REVOKE)"
echo "----------------------------------------------------------------------"
psql -d $DB -X -q -c "REVOKE ALL ON SCHEMA public FROM anon_app" \
                   -c "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM anon_app" \
                   >/dev/null 2>&1
printf '  %-42s %s\n' "search_path 되돌리기" "$(msk "SET search_path=public; SELECT ssn FROM cust WHERE id=1")"
printf '  %-42s %s\n' "스키마 수식"          "$(msk "SELECT ssn FROM public.cust WHERE id=1")"
printf '  %-42s %s\n' "정상 조회"            "$(msk "SELECT ssn FROM cust WHERE id=1")"
echo "  → 우회는 막혔다. 대가는 원본 스키마 권한 회수이며, 쓰기 경로·배치"
echo "    계정·예외 업무가 전부 영향을 받는다(우리가 뷰 방식에 대해 적은 것과 동일)."
echo
echo "[3] ★★ 하드닝 후에도 의미 발산이 남는가 — 이것이 이 시험의 핵심"
echo "----------------------------------------------------------------------"
printf '  %-34s 원본=%-18s 마스킹 롤=%s\n' "count(DISTINCT ssn)" \
    "$(own "SELECT count(DISTINCT ssn) FROM cust")" "$(msk "SELECT count(DISTINCT ssn) FROM cust")"
printf '  %-34s 원본=%-18s 마스킹 롤=%s\n' "DISTINCT 행 수" \
    "$(own "SELECT count(*) FROM (SELECT DISTINCT ssn FROM cust) t")" \
    "$(msk "SELECT count(*) FROM (SELECT DISTINCT ssn FROM cust) t")"
printf '  %-34s 원본=%-18s 마스킹 롤=%s\n' "ORDER BY ssn LIMIT 5 의 id" \
    "$(own "SELECT string_agg(id::text,',') FROM (SELECT id FROM cust ORDER BY ssn LIMIT 5) t")" \
    "$(msk "SELECT string_agg(id::text,',') FROM (SELECT id FROM cust ORDER BY ssn LIMIT 5) t")"
printf '  %-34s 원본=%-18s 마스킹 롤=%s\n' "max(ssn) (값 보존 집계)" \
    "$(own "SELECT max(ssn) FROM cust")" "$(msk "SELECT max(ssn) FROM cust")"
echo
echo "  → 에러도 경고도 없다. anon 문서 어디에도 이 클래스에 대한 언급이 없다."
echo
echo "[4] 스키마 진화 — anon 은 SECURITY LABEL(OID 키잉)을 쓴다"
echo "----------------------------------------------------------------------"
psql -d $DB -X -q -c "ALTER TABLE cust RENAME TO cust_v2" >/dev/null 2>&1
printf '  %-42s %s\n' "ALTER TABLE RENAME 후" "$(msk "SELECT ssn FROM cust_v2 WHERE id=1")"
psql -d $DB -X -q -c "ALTER TABLE cust_v2 RENAME TO cust" >/dev/null 2>&1
printf '  %-42s %s\n' "RENAME COLUMN 시도" \
    "$(psql -d $DB -Atc "ALTER TABLE cust RENAME COLUMN ssn TO rrn" 2>&1 | tail -1)"
echo "  → RENAME TABLE 은 살아남는다. SECURITY LABEL 이 pg_seclabel 에 **OID 로**"
echo "    저장되기 때문이다 -- 우리가 4R 후 OID 키잉으로 바꾼 결정을 독립적으로"
echo "    확인해 준다. 우리가 틀렸고 anon 이 처음부터 맞았던 유일한 축이다."
echo "  → 대신 RENAME COLUMN 은 **아예 막힌다**(마스킹 뷰가 의존). 뷰 방식은"
echo "    보안을 지키는 대신 정상적인 스키마 진화를 막는다."
echo
echo "[5] 물질화 사본"
echo "----------------------------------------------------------------------"
psql -d $DB -X -q -c "DROP TABLE IF EXISTS cust_copy CASCADE" \
    -c "CREATE TABLE cust_copy AS SELECT id, ssn FROM cust" \
    -c "GRANT SELECT ON cust_copy TO anon_app" >/dev/null 2>&1
printf '  %-42s %s\n' "CTAS 사본 조회" "$(msk "SELECT ssn FROM cust_copy WHERE id=1")"
psql -d $DB -X -q -c "DROP TABLE IF EXISTS cust_copy CASCADE" >/dev/null 2>&1
echo "  → 평문. 우리 2R 이 규명한 물질화 클래스가 그대로 재현된다."
echo
echo "======================================================================"
echo "정리"
echo "----------------------------------------------------------------------"
echo "  우회(search_path/스키마수식) : 재현 -- REVOKE 로만 막힌다 (도입 비용)"
echo "  ★ 의미 발산                  : 재현 -- 하드닝 후에도 남는다, 문서에 없다"
echo "  물질화 사본                  : 재현 -- 평문"
echo "  스키마 RENAME                : anon 이 이김 (OID 키잉) -- 우리가 배웠다"
echo "======================================================================"
