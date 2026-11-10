-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION ipguard" to load this file. \quit

-- 주어진 SQL을 파스 + 재작성(뷰 전개 포함)한 뒤 Query 트리를 걸어
-- base relation 컬럼까지 Var를 해석한다. 실행하지 않는다.
-- 반환 형식: "out=<kinds>;pred=<kinds>;unresolved=<n>"  또는 "err=<message>"
CREATE FUNCTION ipguard_analyze(sql text) RETURNS text
AS 'MODULE_PATHNAME', 'ipguard_analyze'
LANGUAGE C STRICT;

-- 임의의 SQL 하나에 대해 "적용되는가?" 를 1행으로 답한다. 실행하지 않는다.
-- planner_hook 과 같은 순서(분석 -> bound -> 마스킹 -> 충돌)를 재현하므로
-- 여기서 나온 판정이 실제 집행 결과와 같아야 한다.
--
--   verdict : mask     출력 경로 PII 를 마스킹한다
--             refuse   거부한다 (bound 소진 또는 정합성 충돌)
--             pass     손대지 않는다 (출력 경로에 라벨된 PII 없음)
--             utility  COPY/CTAS 등 -- 최상위가 planner_hook 경로가 아님
--             mismatch 분석기와 변이기 불일치 = 결함 신호
--             error    파스/재작성 실패
CREATE FUNCTION ipguard_verdict(sql text,
    OUT verdict    text,
    OUT reason     text,
    OUT out_pii    text,
    OUT pred_pii   text,
    OUT write_pii  text,
    OUT masked     int,
    OUT bounded    int,
    OUT unresolved int)
RETURNS record
AS 'MODULE_PATHNAME', 'ipguard_verdict'
LANGUAGE C STRICT;

-- 같은 판정의 컬럼 단위 내역. 어느 테이블의 어느 컬럼이 어느 경로(출력/술어/
-- 쓰기)로 도달하고 어떻게 처리되는지 행으로 펼친다.
CREATE FUNCTION ipguard_explain(sql text,
    OUT relname text,
    OUT attname text,
    OUT label   text,
    OUT path    text,
    OUT action  text)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'ipguard_explain'
LANGUAGE C STRICT;

-- F_core 판정 (명세 v0.2.1 §12). 정리 1·2 가 적용되는 SQL fragment 안인가.
--   ''                     안
--   'reason, reason, …'    밖. **사유는 중첩될 수 있다** -- 사유 수로 질의 수를
--                          세면 안 된다
--   'parse error: …'       분석 실패
--
-- tools/classify_fcore.py 와 달리 **재작성 이후 Query 트리**를 본다. 뷰 본문에
-- 숨은 outer join, rewrite 가 만든 구성, SELECT 위치의 IN/EXISTS 를 텍스트로는
-- 판정할 수 없기 때문이다. Totality 의 분모는 이쪽으로 동결한다.
CREATE FUNCTION ipguard_fragment(sql text) RETURNS text
AS 'MODULE_PATHNAME', 'ipguard_fragment'
LANGUAGE C STRICT;

-- 소스 컬럼 마스킹 함수. planner_hook 이 PII Var 를 이 호출로 치환한다.
-- 타입별 동일 의미 센티널을 돌려준다(별표를 아무 데나 넣으면 클라이언트
-- 파서가 터진다).
CREATE FUNCTION ipguard_mask(anyelement, text) RETURNS anyelement
AS 'MODULE_PATHNAME', 'ipguard_mask'
LANGUAGE C IMMUTABLE;

-- 라벨 테이블 변경을 모든 백엔드의 계획 캐시에 전파한다.
--
-- load_labels 는 계획 시점에 돌기 때문에, 계획이 캐시된 뒤 라벨을 붙이면
-- 그 세션에는 효력이 없다(4R Y07 -- 커넥션 풀에서 몇 시간씩 샌다).
-- 이 트리거가 relcache 무효화를 방송하고 각 백엔드가 계획 캐시를 비운다.
--
-- 라벨 테이블은 확장 소유가 아니므로(사용자 스키마에 있다) 트리거는
-- ipguard_watch_labels() 로 직접 걸어야 한다:
--
--     SELECT ipguard_watch_labels('h5.pii_label');
CREATE FUNCTION ipguard_label_changed() RETURNS trigger
AS 'MODULE_PATHNAME', 'ipguard_label_changed'
LANGUAGE C;

CREATE FUNCTION ipguard_watch_labels(tbl regclass) RETURNS void
LANGUAGE plpgsql AS $$
BEGIN
    EXECUTE format('DROP TRIGGER IF EXISTS ipguard_label_inval ON %s', tbl);
    EXECUTE format(
        'CREATE TRIGGER ipguard_label_inval AFTER INSERT OR UPDATE OR DELETE '
        'OR TRUNCATE ON %s FOR EACH STATEMENT '
        'EXECUTE FUNCTION ipguard_label_changed()', tbl);
END $$;

-- 라벨 무결성 점검.
--
-- OID 키잉(ipguard.label_key = oid)은 이름 변경에 면역이지만 attnum 은
-- 이름이 없다. 덤프/복원 과정에서 삭제된 컬럼이 사라지면 attnum 이 밀려
-- **라벨이 엉뚱한 컬럼을 가리킬 수 있다** -- 라벨을 잃는 것보다 나쁘다
-- (엉뚱한 걸 가리면서 진짜 PII 는 그대로 나간다).
--
-- 복원 직후와 정기 점검에서 이 함수를 돌린다. 빈 결과가 정상이다.
--
--   SELECT * FROM ipguard_verify_labels('h5oid');
CREATE FUNCTION ipguard_verify_labels(label_schema text DEFAULT NULL)
RETURNS TABLE (problem text, detail text)
LANGUAGE plpgsql AS $$
DECLARE
    sch text := coalesce(label_schema,
                         nullif(current_setting('ipguard.label_schema', true), ''),
                         'h5');
    has_oid bool;
BEGIN
    SELECT count(*) = 2 INTO has_oid
      FROM information_schema.columns
     WHERE table_schema = sch AND table_name = 'pii_label'
       AND column_name IN ('relid', 'attnum');

    IF has_oid THEN
        RETURN QUERY EXECUTE format($q$
            SELECT 'dangling relid'::text,
                   l.relid::text || ' attnum=' || l.attnum::text
              FROM %I.pii_label l
             WHERE NOT EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = l.relid)
            UNION ALL
            SELECT 'dangling attnum'::text,
                   l.relid::text || ' attnum=' || l.attnum::text
              FROM %I.pii_label l
             WHERE EXISTS (SELECT 1 FROM pg_class c WHERE c.oid = l.relid)
               AND NOT EXISTS (SELECT 1 FROM pg_attribute a
                                WHERE a.attrelid = l.relid
                                  AND a.attnum = l.attnum
                                  AND NOT a.attisdropped)
        $q$, sch, sch);
    ELSE
        RETURN QUERY EXECUTE format($q$
            SELECT 'unresolved relname'::text, l.relname || '.' || l.attname
              FROM %I.pii_label l
             WHERE NOT EXISTS (
                 SELECT 1 FROM pg_class c
                  WHERE c.relname = l.relname
                    AND c.relnamespace = %L::regnamespace)
            UNION ALL
            SELECT 'unresolved attname'::text, l.relname || '.' || l.attname
              FROM %I.pii_label l
              JOIN pg_class c ON c.relname = l.relname
                             AND c.relnamespace = %L::regnamespace
             WHERE NOT EXISTS (SELECT 1 FROM pg_attribute a
                                WHERE a.attrelid = c.oid
                                  AND a.attname = l.attname
                                  AND NOT a.attisdropped)
        $q$, sch, sch, sch, sch);
    END IF;
END $$;

-- 이름 키잉 라벨을 OID 키잉으로 옮긴다.
--
--   SELECT ipguard_migrate_labels_to_oid('h5', 'h5oid');
--   SET ipguard.label_schema = 'h5oid';
--   SET ipguard.label_key = oid;          -- 또는 postgresql.conf 에
--
-- relid 는 regclass 라 pg_dump 가 **이름으로** 덤프한다(복원 안전). attnum 은
-- 생 숫자이므로 복원 뒤 ipguard_verify_labels() 를 반드시 돌릴 것.
CREATE FUNCTION ipguard_migrate_labels_to_oid(src text, dst text)
RETURNS bigint LANGUAGE plpgsql AS $$
DECLARE n bigint;
BEGIN
    EXECUTE format('CREATE SCHEMA IF NOT EXISTS %I', dst);
    EXECUTE format('CREATE TABLE IF NOT EXISTS %I.pii_label '
                   '(relid regclass, attnum int2, kind text)', dst);
    EXECUTE format($q$
        INSERT INTO %I.pii_label (relid, attnum, kind)
        SELECT c.oid, a.attnum, l.kind
          FROM %I.pii_label l
          JOIN pg_class c ON c.relname = l.relname
                         AND c.relnamespace = %L::regnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = l.attname
         WHERE NOT a.attisdropped
           AND NOT EXISTS (SELECT 1 FROM %I.pii_label x
                            WHERE x.relid = c.oid AND x.attnum = a.attnum)
    $q$, dst, src, src, dst);
    GET DIAGNOSTICS n = ROW_COUNT;
    PERFORM ipguard_watch_labels(format('%I.pii_label', dst)::regclass);
    RETURN n;
END $$;

-- ==========================================================================
-- 커버리지 감사 — "라벨이 붙어야 하는데 안 붙은 컬럼"을 찾는다
--
-- ★ 이 함수들은 **집행의 입력이 아니다.** load_labels 는 라벨 테이블만
--   근거로 삼는다(컬럼명 휴리스틱을 집행에 쓰면 코퍼스 측정이 무의미해진다).
--   여기서 나오는 것은 **사람이 검토할 후보**이고, 사람이 라벨 테이블에
--   넣어야 비로소 효력이 생긴다. 이 분리를 깨면 안 된다.
--
-- 왜 필요한가: 파티션 DETACH 는 어떤 라벨 키잉으로도 못 막는다(4R Y04).
-- 상속 연결이 끊기면 자식은 라벨 없는 독립 테이블이 되고, **데이터는 같은
-- 파일에 그대로 있다.** 월별 파티션을 떼어 아카이브하는 것은 금융권 표준
-- 운영이므로 실전에서 반드시 밟는다. 막을 수 없으면 **감지**해야 한다.
-- 구체화 뷰·CTAS 사본도 같은 클래스다.
-- ==========================================================================

-- 구조적 감사: 라벨된 컬럼과 **이름+타입이 같은데** 라벨이 없는 컬럼.
-- 떨어져 나간 파티션은 부모의 컬럼 구조를 그대로 갖고 있으므로 여기 걸린다.
CREATE FUNCTION ipguard_coverage(label_schema text DEFAULT NULL)
RETURNS TABLE (nspname text, relname text, attname text,
               atttype text, kind text, reason text)
LANGUAGE plpgsql AS $$
DECLARE
    sch text := coalesce(label_schema,
                         nullif(current_setting('ipguard.label_schema', true), ''),
                         'h5');
    has_oid bool;
BEGIN
    SELECT count(*) = 2 INTO has_oid
      FROM information_schema.columns
     WHERE table_schema = sch AND table_name = 'pii_label'
       AND column_name IN ('relid', 'attnum');

    RETURN QUERY EXECUTE format($q$
        WITH RECURSIVE lbl(relid, attnum, kind) AS (
            %s
          UNION ALL
            SELECT i.inhrelid, ac.attnum, l.kind
              FROM lbl l
              JOIN pg_inherits i ON i.inhparent = l.relid
              JOIN pg_attribute ap ON ap.attrelid = l.relid AND ap.attnum = l.attnum
              JOIN pg_attribute ac ON ac.attrelid = i.inhrelid
                                  AND ac.attname = ap.attname
        ),
        -- 라벨된 (컬럼명, 타입) 지문
        sig AS (
            SELECT DISTINCT a.attname, a.atttypid, l.kind
              FROM lbl l JOIN pg_attribute a ON a.attrelid = l.relid
                                            AND a.attnum = l.attnum
        )
        SELECT n.nspname::text, c.relname::text, a.attname::text,
               format_type(a.atttypid, a.atttypmod)::text, s.kind::text,
               CASE c.relkind
                   WHEN 'm' THEN '구체화 뷰 — 라벨 전파 경로 없음'
                   WHEN 'f' THEN '외부 테이블 — 원격 라벨은 전파되지 않음'
                   ELSE '라벨된 컬럼과 이름+타입 일치'
               END::text
          FROM pg_class c
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = c.oid
          JOIN sig s ON s.attname = a.attname AND s.atttypid = a.atttypid
         WHERE c.relkind IN ('r','p','m','f')
           AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
           AND a.attnum > 0 AND NOT a.attisdropped
           AND NOT EXISTS (SELECT 1 FROM lbl l
                            WHERE l.relid = c.oid AND l.attnum = a.attnum)
         ORDER BY 1, 2, 3
    $q$,
    CASE WHEN has_oid THEN
        format('SELECT l.relid::oid, l.attnum, l.kind FROM %I.pii_label l', sch)
    ELSE
        format('SELECT c.oid, a.attnum, l.kind FROM %I.pii_label l '
               'JOIN pg_class c ON c.relname = l.relname '
               '  AND c.relnamespace = %L::regnamespace '
               'JOIN pg_attribute a ON a.attrelid = c.oid AND a.attname = l.attname '
               'WHERE NOT a.attisdropped', sch, sch)
    END);
END $$;

-- 라벨 소스를 키잉 방식에 맞게 골라 주는 내부 헬퍼.
-- (relid, attnum, kind) 세 컬럼을 내놓는 SQL 조각을 돌려준다.
CREATE FUNCTION ipguard__label_src(sch text) RETURNS text
LANGUAGE sql STABLE AS $$
    SELECT CASE WHEN count(*) = 2
             THEN format('(SELECT relid::oid AS relid, attnum, kind FROM %I.pii_label) l0', sch)
             ELSE format('(SELECT c.oid AS relid, a.attnum, l.kind '
                         '   FROM %I.pii_label l '
                         '   JOIN pg_class c ON c.relname = l.relname '
                         '                  AND c.relnamespace = %L::regnamespace '
                         '   JOIN pg_attribute a ON a.attrelid = c.oid '
                         '                      AND a.attname = l.attname '
                         '  WHERE NOT a.attisdropped) l0', sch, sch)
           END
      FROM information_schema.columns
     WHERE table_schema = sch AND table_name = 'pii_label'
       AND column_name IN ('relid', 'attnum')
$$;

-- 값 기반 감사. 이름이 바뀐 사본은 구조 감사가 못 잡는다:
--
--   ALTER TABLE h5.cov_p1 RENAME COLUMN ssn TO id_no;   -- 이름+타입 일치 깨짐
--
-- 라벨된 컬럼에서 표본을 뽑아 값 집합을 만들고, 라벨 없는 컬럼의 표본이 거기에
-- 얼마나 겹치는지 본다. 겹침이 높으면 같은 데이터의 사본이다.
--
-- 비싸다 -- 정기 배치용이지 쿼리 경로가 아니다. 그리고 여기 결과도 **집행의
-- 입력이 아니다.** 사람이 보고 라벨 테이블에 넣어야 효력이 생긴다.
CREATE FUNCTION ipguard_coverage_deep(label_schema text DEFAULT NULL,
                                      sample_rows int DEFAULT 200,
                                      min_overlap float8 DEFAULT 0.5)
RETURNS TABLE (nspname text, relname text, attname text,
               kind text, overlap float8, sampled int)
LANGUAGE plpgsql AS $$
DECLARE
    -- 같은 kind 의 기준 컬럼이 여럿이면(cust.ssn, gen_t.ssn, rls_t.ssn …)
    -- 같은 후보가 여러 번 나온다. 최대 겹침만 남긴다.
    seen jsonb := '{}'::jsonb;
    sch  text := coalesce(label_schema,
                          nullif(current_setting('ipguard.label_schema', true), ''),
                          'h5');
    src  text := ipguard__label_src(sch);
    k    record;
    c    record;
    vals text[];
    hit  bigint;
    tot  bigint;
BEGIN
    -- 라벨된 컬럼마다 기준 값 표본을 만든다
    FOR k IN EXECUTE format($q$
        SELECT l0.kind,
               format('%%I.%%I', n.nspname, c.relname) AS rel,
               a.attname AS col,
               c.oid AS relid, a.attnum
          FROM %s
          JOIN pg_class c ON c.oid = l0.relid
          JOIN pg_namespace n ON n.oid = c.relnamespace
          JOIN pg_attribute a ON a.attrelid = l0.relid AND a.attnum = l0.attnum
         WHERE c.relkind IN ('r','p') AND NOT a.attisdropped
    $q$, src)
    LOOP
        BEGIN
            EXECUTE format('SELECT array_agg(DISTINCT x) FROM '
                           '(SELECT %I::text AS x FROM %s '
                           '  WHERE %I IS NOT NULL LIMIT %s) s',
                           k.col, k.rel, k.col, sample_rows)
               INTO vals;
        EXCEPTION WHEN others THEN
            CONTINUE;
        END;
        -- 저카디널리티 컬럼은 우연 일치가 많아 기준으로 못 쓴다
        CONTINUE WHEN vals IS NULL OR array_length(vals, 1) < 5;

        FOR c IN
            SELECT n.nspname AS ns, cl.relname AS rel, a.attname AS col,
                   cl.oid AS relid, a.attnum
              FROM pg_class cl
              JOIN pg_namespace n ON n.oid = cl.relnamespace
              JOIN pg_attribute a ON a.attrelid = cl.oid
             WHERE cl.relkind IN ('r','p','m')
               AND n.nspname NOT IN ('pg_catalog','information_schema','pg_toast')
               AND a.attnum > 0 AND NOT a.attisdropped
               AND cl.oid <> k.relid
        LOOP
            -- 이미 라벨된 컬럼은 건너뛴다. **상속 전파까지 펴야 한다** --
            -- 안 그러면 파티션 자식이 전부 오탐으로 나온다(실측으로 발견).
            EXECUTE format($c$
                WITH RECURSIVE d(relid, attnum) AS (
                    SELECT relid, attnum FROM %s
                  UNION ALL
                    SELECT i.inhrelid, ac.attnum
                      FROM d
                      JOIN pg_inherits i ON i.inhparent = d.relid
                      JOIN pg_attribute ap ON ap.attrelid = d.relid
                                          AND ap.attnum = d.attnum
                      JOIN pg_attribute ac ON ac.attrelid = i.inhrelid
                                          AND ac.attname = ap.attname
                )
                SELECT count(*) FROM d WHERE relid = $1 AND attnum = $2
            $c$, src) INTO hit USING c.relid, c.attnum;
            CONTINUE WHEN hit > 0;

            BEGIN
                EXECUTE format(
                    'SELECT count(*) FILTER (WHERE x = ANY($1)), count(*) FROM '
                    '(SELECT %I::text AS x FROM %I.%I '
                    '  WHERE %I IS NOT NULL LIMIT %s) s',
                    c.col, c.ns, c.rel, c.col, sample_rows)
                  INTO hit, tot USING vals;
            EXCEPTION WHEN others THEN
                CONTINUE;       -- 캐스팅 불가 타입 등
            END;

            IF tot >= 5 AND hit::float8 / tot >= min_overlap THEN
                DECLARE
                    key text := format('%s.%s.%s', c.ns, c.rel, c.col);
                    prev float8 := coalesce((seen ->> key)::float8, -1);
                    ov   float8 := round((hit::float8 / tot)::numeric, 3);
                BEGIN
                    IF ov > prev THEN
                        seen := seen || jsonb_build_object(key, ov);
                        nspname := c.ns; relname := c.rel; attname := c.col;
                        kind := k.kind; overlap := ov; sampled := tot;
                        RETURN NEXT;
                    END IF;
                END;
            END IF;
        END LOOP;
    END LOOP;
END $$;

-- SECURITY DEFINER 백도어 감사.
--
-- ★ 5R 이 남긴 것: GUC 를 PGC_SUSET 으로 바꾸면 앱 사용자의 직접 SET 은
--   막히지만, **권한 있는 롤이 소유한 SECURITY DEFINER 함수**는 그대로
--   뚫는다. 함수가 소유자 권한으로 돌기 때문이다:
--
--     CREATE FUNCTION f() RETURNS text SECURITY DEFINER AS $$
--       BEGIN SET LOCAL ipguard.enforce = off;        -- 소유자 = superuser
--             RETURN (SELECT ssn FROM cust WHERE id=1); END $$;
--
--   이건 코드로 못 막는다 -- superuser 는 정의상 뭐든 할 수 있고, 그런 함수를
--   만든 시점에 이미 신뢰 경계가 깨졌다. 그래서 **감지**한다.
--
-- 빈 결과가 정상이다. 나온 것은 사람이 검토한다.
CREATE FUNCTION ipguard_audit_definers()
RETURNS TABLE (nspname text, funcname text, owner text, reason text)
LANGUAGE sql STABLE AS $$
    SELECT n.nspname::text, p.proname::text, a.rolname::text,
           CASE WHEN p.prosrc ~* 'ipguard\.(enforce|on_divergence|on_conflict|label_)'
                THEN 'ipguard 설정을 본문에서 바꾼다 ★'
                WHEN p.proconfig IS NOT NULL
                     AND array_to_string(p.proconfig, ',') ~* 'ipguard\.'
                THEN 'ipguard 설정이 함수 SET 절에 있다 ★'
                ELSE '라벨된 릴레이션을 참조한다'
           END::text
      FROM pg_proc p
      JOIN pg_namespace n ON n.oid = p.pronamespace
      JOIN pg_authid a ON a.oid = p.proowner
     WHERE p.prosecdef                      -- SECURITY DEFINER 만
       AND n.nspname NOT IN ('pg_catalog', 'information_schema')
       AND (p.prosrc ~* 'ipguard\.(enforce|on_divergence|on_conflict|label_)'
            OR (p.proconfig IS NOT NULL
                AND array_to_string(p.proconfig, ',') ~* 'ipguard\.')
            OR EXISTS (
                SELECT 1
                  FROM pg_class c
                  JOIN pg_namespace cn ON cn.oid = c.relnamespace
                 WHERE c.relkind IN ('r','p','m','v','f')
                   AND p.prosrc ~* ('\m' || c.relname || '\M')
                   AND EXISTS (SELECT 1 FROM h5.pii_label l
                                WHERE l.relname = c.relname)))
     ORDER BY 1, 2
$$;

-- ==================================================================
-- 마스크 능력 레지스트리 (명세 v0.2.1 §4·§5·§6)
--
-- 왜 이게 필요한가: 게이트가 "이 마스크는 동치를 보존한다" 같은 사실에
-- 의존해 질의를 수락하려면, 그 사실의 **출처와 유효성**이 형식에 남아야
-- 한다. 관리자가 틀린 속성을 선언하면 정리가 깨지는 것이 아니라
-- RegistrySound 전제가 깨진다 -- 책임 소재가 드러나야 한다.
--
-- ★ 설계 원칙 넷
--   1. 속성은 PII 종류(kind)가 아니라 **마스크 인스턴스**에 속한다
--   2. **claim(무엇인가)과 assurance(어떻게 아는가)를 분리**한다
--   3. 지문이 어긋나면 저장된 claim 과 무관하게 **unknown**
--   4. 기본값은 unknown 이고, 어떤 규칙도 unknown 에 의존할 수 없다
-- ==================================================================

-- 1) claim 과 assurance 는 다른 축이다.
--
-- 섞으면 'fails' 를 표현할 수 없다. `fails` 는 unknown 과 전혀 다르다 --
-- unknown 은 "인증 안 됨"(나중에 인증되면 수락 가능)이고, fails 는
-- "성립하지 않음이 확인됨"(영원히 수락 불가)이다. 진단 품질이 달라진다.
CREATE TYPE ipguard_claim AS ENUM ('holds', 'fails', 'unknown');

-- 출처. 정리의 **전제**이지 결론이 아니다.
--
-- ★ trusted_provider 가 proved_builtin 과 별개인 이유:
--   우리 모듈의 C 함수에 소스 해시를 박아도 **바이너리 동일성**은 못 얻는다.
--   컴파일러·플래그·PG 헤더·링크 라이브러리·ABI·같은 소스의 다른 바이너리가
--   전부 밖에 있다. 그래서 주장은 이 수준이다:
--
--       provider-attested build identity
--       complete only under BuildSound(provider_manifest)
--
--   manifest 가 덮은 축은 ipguard_manifest_axes() 로 노출한다. 거기 없는
--   축의 변경은 잡히지 않는다 -- 그 사실이 assurance 등급에 드러나야 한다.
CREATE TYPE ipguard_assurance AS ENUM
    ('proved_builtin',       -- 서버 빌드에 묶인 내장 함수. 지문이 완전하다
     'trusted_provider',     -- 제공자가 빌드를 증언한다. BuildSound 전제 필요
     'trusted_assumption',   -- 관리자가 선언했다 (신뢰 가정으로 기록)
     'unknown');             -- 기본값

-- 2) MaskInstance. **키가 이 튜플이어야 한다** -- mask_prop(kind, ...) 로
--    만들면 같은 kind 에 다른 마스크를 붙이는 순간 증명이 깨진다.
CREATE TABLE ipguard_mask_instance (
    mask_id          serial PRIMARY KEY,
    func             regprocedure NOT NULL,   -- regprocedure 는 이름으로 덤프된다
    normalized_args  text        NOT NULL DEFAULT '',
    input_type       regtype     NOT NULL,
    output_type      regtype     NOT NULL,
    collation_name   text        NOT NULL DEFAULT '',
    -- 등록 시점의 지문. 지금 계산한 값과 다르면 인증서 전체가 무효다.
    impl_fingerprint text        NOT NULL,
    fp_complete      boolean     NOT NULL,
    fp_basis_kind    text        NOT NULL,    -- internal | c-self | c-foreign | src
    registered_at    timestamptz NOT NULL DEFAULT now(),
    note             text,
    UNIQUE (func, normalized_args, input_type, output_type, collation_name)
);

-- 3) 지문 계산. C 쪽 pg_proc 부분에 확장 버전과 collation 버전을 붙인다.
--
--   internal    서버 빌드에 묶인다                                complete
--   c-provider  우리 모듈. provider-attested build identity.
--               ★ complete 가 **아니다** -- manifest 가 덮은 축만 잡는다
--               (ipguard_manifest_axes()). 바이너리 동일성이 아니다  INCOMPLETE
--   c-foreign   extversion 밖에 못 본다. make install 로 .so 를
--               덮어써도 카탈로그는 그대로다                       INCOMPLETE
--   src         prosrc 는 보지만 **본문이 호출하는 함수**의 변경은
--               못 본다                                           INCOMPLETE
CREATE FUNCTION ipguard_proc_basis(func regprocedure,
    OUT basis text, OUT lang text, OUT self boolean, OUT build text)
RETURNS record AS 'MODULE_PATHNAME', 'ipguard_proc_basis'
LANGUAGE C STRICT;

CREATE FUNCTION ipguard_build_id() RETURNS text
AS 'MODULE_PATHNAME', 'ipguard_build_id' LANGUAGE C;

-- 이 백엔드에서 **PII 가 걸린 질의를 계획한 횟수.**
-- 라벨/레지스트리 변경이 generic plan 까지 전파됐는지를 결과가 아니라
-- **계획 사건**으로 직접 잰다. 라벨 없는 질의(이 함수 호출 자체 포함)는
-- 세지 않으므로 측정이 측정값을 흔들지 않는다.
CREATE FUNCTION ipguard_pii_plan_count() RETURNS bigint
AS 'MODULE_PATHNAME', 'ipguard_pii_plan_count' LANGUAGE C;

CREATE FUNCTION ipguard_fingerprint(func regprocedure, coll text DEFAULT '',
    OUT fingerprint text, OUT complete boolean, OUT basis_kind text)
RETURNS record
LANGUAGE sql STABLE AS $$
    SELECT md5(b.basis
               -- 확장 버전: 타 확장의 C 함수에는 이것밖에 없다
               || coalesce((SELECT ';ext=' || e.extname || '@' || e.extversion
                              FROM pg_depend d
                              JOIN pg_extension e ON e.oid = d.refobjid
                             WHERE d.classid = 'pg_proc'::regclass
                               AND d.objid = func
                               AND d.refclassid = 'pg_extension'::regclass
                             LIMIT 1), '')
               -- collation 버전: OS 라이브러리가 바뀌면 정렬 의미가 바뀐다
               || coalesce((SELECT ';coll=' || c.collname || '@'
                                   || coalesce(c.collversion, '?')
                              FROM pg_collation c
                             WHERE coll <> '' AND c.collname = coll
                             LIMIT 1), CASE WHEN coll = '' THEN '' ELSE ';coll=' || coll || '@missing' END)
              ),
           -- ★ complete 는 internal 에만 준다. 우리 모듈이라도 소스 해시로는
           --   바이너리 동일성을 얻지 못한다.
           b.lang = 'internal',
           CASE WHEN b.lang = 'internal' THEN 'internal'
                WHEN b.lang = 'c' AND b.self THEN 'c-provider'
                WHEN b.lang = 'c' THEN 'c-foreign'
                ELSE 'src' END
      FROM ipguard_proc_basis(func) b
$$;

CREATE FUNCTION ipguard_manifest_axes() RETURNS text
AS 'MODULE_PATHNAME', 'ipguard_manifest_axes' LANGUAGE C;

-- 마스크 인스턴스 등록. 지문은 **여기서 계산한다** -- 관리자가 못 적는다.
-- ★ 파라미터 이름을 컬럼 이름과 겹치지 않게 p_ 로 접두한다. PL/pgSQL 은
--   ON CONFLICT 절에서 둘을 구별하지 못하고 "column reference is ambiguous"
--   로 죽는다 -- 실제로 처음 구현에서 여기서 걸렸다.
CREATE FUNCTION ipguard_register_mask(
    p_func regprocedure, p_input_type regtype, p_output_type regtype,
    p_normalized_args text DEFAULT '', p_coll text DEFAULT '',
    p_note text DEFAULT NULL)
RETURNS int
LANGUAGE plpgsql AS $$
DECLARE fp record; mid int;
BEGIN
    SELECT * INTO fp FROM ipguard_fingerprint(p_func, p_coll);
    INSERT INTO ipguard_mask_instance
        (func, normalized_args, input_type, output_type, collation_name,
         impl_fingerprint, fp_complete, fp_basis_kind, note)
    VALUES (p_func, p_normalized_args, p_input_type, p_output_type, p_coll,
            fp.fingerprint, fp.complete, fp.basis_kind, p_note)
    ON CONFLICT (func, normalized_args, input_type, output_type, collation_name)
    DO UPDATE SET impl_fingerprint = excluded.impl_fingerprint,
                  fp_complete      = excluded.fp_complete,
                  fp_basis_kind    = excluded.fp_basis_kind,
                  registered_at    = now()
    RETURNING mask_id INTO mid;
    RETURN mid;
END $$;

-- 4) mask_capability -- m 단독 속성
--
-- capability 이름은 명세 §5 의 술어와 1:1 이다:
--   determinism, null_equivalence, equality_factor, order_factor, total
--
-- ★ equality_embedding 이 아니라 equality_factor 로 적는다. 실제 의무는
--   키 전체의 factor-through 이고 embedding 은 그것의 **충분조건**일 뿐이다
--   (§5.5). 레지스트리는 원자적 capability 만 제공하고, 합성은 게이트가
--   질의 문맥에서 한다.
--
-- precondition: total 은 전역 boolean 이 아니다. x/y 는 y<>0 아래에서만
--   total 이다. 첫 구현은 '' (= 무조건) 만 지원하되 컬럼은 지금 만든다 --
--   나중에 타입을 바꾸면 기존 인증서가 전부 무효가 된다.
CREATE TABLE ipguard_mask_capability (
    mask_id      int  NOT NULL REFERENCES ipguard_mask_instance ON DELETE CASCADE,
    capability   text NOT NULL,
    claim        ipguard_claim     NOT NULL DEFAULT 'unknown',
    assurance    ipguard_assurance NOT NULL DEFAULT 'unknown',
    precondition text NOT NULL DEFAULT '',
    evidence     text,
    PRIMARY KEY (mask_id, capability),
    CONSTRAINT cap_known CHECK (capability IN
        ('determinism','null_equivalence','equality_factor','order_factor','total')),
    -- unknown 인 주장에 출처가 있을 수 없다. 있으면 표가 스스로 모순이다.
    CONSTRAINT unknown_has_no_source
        CHECK ((claim = 'unknown') = (assurance = 'unknown'))
);

-- 5) mask_function_compatibility -- (m, f, r_out) 의 관계
--
-- 마스크 단독 속성이 아니다. arg_signature 를 키에 넣는 것이 핵심이다:
-- substr(x,1,2) 와 substr(x,1,3) 은 **다른 주장**이다. 하나로 뭉치면
-- 인증서가 검증 안 된 인자로 번진다.
CREATE TABLE ipguard_mask_function_compatibility (
    mask_id        int  NOT NULL REFERENCES ipguard_mask_instance ON DELETE CASCADE,
    func           regprocedure NOT NULL,
    arg_signature  text NOT NULL DEFAULT '',
    out_redactor   regprocedure NOT NULL,
    collation_name text NOT NULL DEFAULT '',
    func_fingerprint text NOT NULL,
    red_fingerprint  text NOT NULL,
    claim      ipguard_claim     NOT NULL DEFAULT 'unknown',
    assurance  ipguard_assurance NOT NULL DEFAULT 'unknown',
    evidence   text,
    PRIMARY KEY (mask_id, func, arg_signature, out_redactor, collation_name),
    CONSTRAINT unknown_has_no_source
        CHECK ((claim = 'unknown') = (assurance = 'unknown'))
);

-- 6) mask_aggregate_compatibility -- (m, A, r_out)
--
-- distinct_arg 를 키에 넣는다: count(x) 와 count(DISTINCT x) 는 마스크에
-- 대해 완전히 다르게 행동한다(후자는 EQ 채널을 탄다).
CREATE TABLE ipguard_mask_aggregate_compatibility (
    mask_id       int  NOT NULL REFERENCES ipguard_mask_instance ON DELETE CASCADE,
    agg           regprocedure NOT NULL,
    distinct_arg  boolean NOT NULL DEFAULT false,
    ordered_arg   boolean NOT NULL DEFAULT false,
    out_redactor  regprocedure NOT NULL,
    collation_name text NOT NULL DEFAULT '',
    agg_fingerprint text NOT NULL,
    red_fingerprint text NOT NULL,
    claim      ipguard_claim     NOT NULL DEFAULT 'unknown',
    assurance  ipguard_assurance NOT NULL DEFAULT 'unknown',
    evidence   text,
    PRIMARY KEY (mask_id, agg, distinct_arg, ordered_arg, out_redactor, collation_name),
    CONSTRAINT unknown_has_no_source
        CHECK ((claim = 'unknown') = (assurance = 'unknown'))
);

-- proved_builtin 은 지문이 완전할 때만 주장할 수 있다.
--
-- 지문이 불완전하면 **변경을 놓칠 수 있다**. 그 위에 "시스템이 검증했다"를
-- 얹으면, 검증한 그 구현이 아직 그대로라는 것을 보장할 수 없는데도 정리가
-- 그 전제를 쓰게 된다. 최대 trusted_assumption 으로 내린다.
CREATE FUNCTION ipguard_registry_guard() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE inst record;
BEGIN
    SELECT fp_complete, fp_basis_kind INTO inst
      FROM ipguard_mask_instance WHERE mask_id = NEW.mask_id;

    IF NEW.assurance = 'proved_builtin' AND NOT inst.fp_complete THEN
        RAISE EXCEPTION 'ipguard: mask_id=% 의 지문이 불완전해(%) '
                        'proved_builtin 을 주장할 수 없습니다',
                        NEW.mask_id, inst.fp_basis_kind
          USING HINT = 'internal 함수만 proved_builtin 이 가능합니다. '
                       '우리 모듈의 C 함수는 trusted_provider 입니다.';
    END IF;

    -- trusted_provider 는 **제공자가 빌드를 증언할 수 있을 때만** 쓴다.
    -- 남의 확장이나 SQL UDF 에 붙이면 근거 없는 등급이 된다.
    IF NEW.assurance = 'trusted_provider'
       AND inst.fp_basis_kind NOT IN ('internal', 'c-provider') THEN
        RAISE EXCEPTION 'ipguard: mask_id=% (%) 에는 trusted_provider 를 '
                        '쓸 수 없습니다', NEW.mask_id, inst.fp_basis_kind
          USING HINT = '제공자 빌드 증언이 없는 것은 trusted_assumption 입니다.';
    END IF;
    RETURN NEW;
END $$;

-- 7) registry_epoch -- 인증서 철회를 prepared/generic plan 까지 전파한다
--
-- ★ 이게 없으면 Y07 과 같은 구멍이 난다. 인증서를 철회해도 이미 만들어진
--   generic plan 은 철회 전 판정으로 계속 돈다 -- 커넥션 풀에서는 몇 시간씩
--   간다. 라벨에서 이미 당한 실패 양식이므로 같은 해법을 쓴다:
--   레지스트리 테이블 쓰기 -> relcache 무효화 방송 -> 각 백엔드가 ResetPlanCache.
CREATE TABLE ipguard_registry_epoch (
    only_row boolean PRIMARY KEY DEFAULT true CHECK (only_row),
    epoch    bigint  NOT NULL DEFAULT 0,
    bumped_at timestamptz NOT NULL DEFAULT now()
);
INSERT INTO ipguard_registry_epoch DEFAULT VALUES;

CREATE FUNCTION ipguard_registry_epoch() RETURNS bigint
LANGUAGE sql STABLE AS $$ SELECT epoch FROM ipguard_registry_epoch $$;

CREATE FUNCTION ipguard_registry_bump() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    UPDATE ipguard_registry_epoch SET epoch = epoch + 1, bumped_at = now();
    RETURN NULL;
END $$;

-- 레지스트리 세 표 전부에 (a) epoch 증가 (b) 계획 캐시 무효화를 단다.
CREATE FUNCTION ipguard_watch_registry() RETURNS void
LANGUAGE plpgsql AS $$
DECLARE t text;
BEGIN
    -- ★ declassification 도 반드시 포함한다. 인증서를 철회했는데 캐시된
    --   generic plan 이 철회 전 판정으로 계속 돌면 라벨(Y07)과 같은 구멍이다.
    FOREACH t IN ARRAY ARRAY['ipguard_mask_instance',
                             'ipguard_mask_capability',
                             'ipguard_mask_function_compatibility',
                             'ipguard_mask_aggregate_compatibility',
                             'ipguard_mask_comparator_compatibility',
                             'ipguard_declassification'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS ipguard_reg_epoch ON %I', t);
        EXECUTE format('DROP TRIGGER IF EXISTS ipguard_reg_inval ON %I', t);
        EXECUTE format(
            'CREATE TRIGGER ipguard_reg_epoch AFTER INSERT OR UPDATE OR DELETE '
            'OR TRUNCATE ON %I FOR EACH STATEMENT '
            'EXECUTE FUNCTION ipguard_registry_bump()', t);
        EXECUTE format(
            'CREATE TRIGGER ipguard_reg_inval AFTER INSERT OR UPDATE OR DELETE '
            'OR TRUNCATE ON %I FOR EACH STATEMENT '
            'EXECUTE FUNCTION ipguard_label_changed()', t);
    END LOOP;
    -- proved_builtin 가드는 행 단위여야 한다
    FOREACH t IN ARRAY ARRAY['ipguard_mask_capability',
                             'ipguard_mask_function_compatibility',
                             'ipguard_mask_aggregate_compatibility',
                             'ipguard_mask_comparator_compatibility'] LOOP
        EXECUTE format('DROP TRIGGER IF EXISTS ipguard_reg_guard ON %I', t);
        EXECUTE format(
            'CREATE TRIGGER ipguard_reg_guard BEFORE INSERT OR UPDATE ON %I '
            'FOR EACH ROW EXECUTE FUNCTION ipguard_registry_guard()', t);
    END LOOP;
END $$;

-- ==================================================================
-- 조회 API -- 게이트는 **반드시 이것만** 본다. 표를 직접 읽으면 안 된다.
--
-- 지문을 지금 다시 계산해서 저장된 값과 비교한다. 어긋나면 저장된 claim 이
-- 무엇이든 **unknown**. CREATE OR REPLACE 로 본문이 바뀐 경우가 여기서 잡힌다.
-- ==================================================================
CREATE FUNCTION ipguard_capability(mid int, cap text)
RETURNS ipguard_claim
LANGUAGE plpgsql STABLE AS $$
DECLARE inst record; now_fp record; c ipguard_claim;
BEGIN
    SELECT * INTO inst FROM ipguard_mask_instance WHERE mask_id = mid;
    IF NOT FOUND THEN RETURN 'unknown'; END IF;

    SELECT * INTO now_fp
      FROM ipguard_fingerprint(inst.func, inst.collation_name);
    IF now_fp.fingerprint IS DISTINCT FROM inst.impl_fingerprint THEN
        RETURN 'unknown';           -- ★ 구현이 바뀌었다. 인증서 전부 무효.
    END IF;

    SELECT claim INTO c FROM ipguard_mask_capability
     WHERE mask_id = mid AND capability = cap;
    RETURN coalesce(c, 'unknown');  -- 등록 안 된 capability 는 unknown
END $$;

CREATE FUNCTION ipguard_function_compatible(
    mid int, f regprocedure, args text DEFAULT '',
    redactor regprocedure DEFAULT NULL, coll text DEFAULT '')
RETURNS ipguard_claim
LANGUAGE plpgsql STABLE AS $$
DECLARE inst record; now_fp record; row_ record; fnow record; rnow record;
BEGIN
    SELECT * INTO inst FROM ipguard_mask_instance WHERE mask_id = mid;
    IF NOT FOUND THEN RETURN 'unknown'; END IF;
    SELECT * INTO now_fp FROM ipguard_fingerprint(inst.func, inst.collation_name);
    IF now_fp.fingerprint IS DISTINCT FROM inst.impl_fingerprint THEN
        RETURN 'unknown';
    END IF;

    SELECT * INTO row_ FROM ipguard_mask_function_compatibility
     WHERE mask_id = mid AND func = f AND arg_signature = args
       AND collation_name = coll
       AND (redactor IS NULL OR out_redactor = redactor);
    IF NOT FOUND THEN RETURN 'unknown'; END IF;   -- 다른 인자·collation = 미지

    -- 대상 함수와 redactor 도 바뀌었을 수 있다. 셋 다 봐야 한다.
    SELECT * INTO fnow FROM ipguard_fingerprint(row_.func, coll);
    SELECT * INTO rnow FROM ipguard_fingerprint(row_.out_redactor, coll);
    IF fnow.fingerprint IS DISTINCT FROM row_.func_fingerprint
       OR rnow.fingerprint IS DISTINCT FROM row_.red_fingerprint THEN
        RETURN 'unknown';
    END IF;
    RETURN row_.claim;
END $$;

-- ★ 집계 인증서는 **전제 capability 를 우회할 수 없다.**
--
-- `count(x) holds` 는 그 MaskInstance 가 `null_equivalence` 를 만족할 때만
-- 맞다. count 는 **non-NULL 값을 센다** -- 마스크가 non-NULL 을 NULL 로
-- 바꾸면(numeric_mask=nullify) 결과가 바뀐다. 5R 에서 실측한
-- `count(*) FILTER (WHERE salary IS NOT NULL)` 1000 -> 0 이 정확히 이것이다.
--
-- 관리자가 실수로 (또는 고의로) `count -> holds` 를 등록해도 이 의무는
-- 우회되면 안 된다. 그래서 조회 API 가 **강제 전제**를 항상 AND 한다.
CREATE TABLE ipguard_aggregate_obligation (
    agg        regprocedure NOT NULL,
    capability text NOT NULL,
    rationale  text,
    PRIMARY KEY (agg, capability)
);
-- NULL 을 무시하는 집계는 전부 null_equivalence 를 요구한다.
INSERT INTO ipguard_aggregate_obligation VALUES
  ('count("any")'::regprocedure, 'null_equivalence', 'count 는 non-NULL 을 센다'),
  ('sum(numeric)'::regprocedure, 'null_equivalence', 'NULL 은 합에서 빠진다'),
  ('avg(numeric)'::regprocedure, 'null_equivalence', 'NULL 은 분모에서도 빠진다'),
  ('min(numeric)'::regprocedure, 'null_equivalence', 'NULL 은 무시된다'),
  ('max(numeric)'::regprocedure, 'null_equivalence', 'NULL 은 무시된다');

-- claim 셋의 **가장 약한 것**. fails 가 unknown 보다 강한 신호다
-- (unknown 은 나중에 인증되면 수락 가능, fails 는 영원히 불가).
CREATE FUNCTION ipguard_weakest(a ipguard_claim, b ipguard_claim)
RETURNS ipguard_claim
LANGUAGE sql IMMUTABLE AS $$
    SELECT CASE WHEN a = 'fails' OR b = 'fails' THEN 'fails'
                WHEN a = 'unknown' OR b = 'unknown' THEN 'unknown'
                ELSE 'holds' END::ipguard_claim
$$;

CREATE FUNCTION ipguard_aggregate_compatible(
    mid int, a regprocedure, is_distinct boolean DEFAULT false,
    is_ordered boolean DEFAULT false,
    redactor regprocedure DEFAULT NULL, coll text DEFAULT '')
RETURNS ipguard_claim
LANGUAGE plpgsql STABLE AS $$
DECLARE inst record; now_fp record; row_ record; anow record; rnow record;
        res ipguard_claim; ob record;
BEGIN
    SELECT * INTO inst FROM ipguard_mask_instance WHERE mask_id = mid;
    IF NOT FOUND THEN RETURN 'unknown'; END IF;
    SELECT * INTO now_fp FROM ipguard_fingerprint(inst.func, inst.collation_name);
    IF now_fp.fingerprint IS DISTINCT FROM inst.impl_fingerprint THEN
        RETURN 'unknown';
    END IF;

    -- ★ 강제 전제를 **등록 조회보다 먼저** 본다.
    --
    -- 순서가 중요하다. 나중에 보면 "등록 안 된 조합" 이 전부 unknown 이 되어,
    -- **확정적으로 불가능한 조합**까지 unknown 으로 뭉개진다. EQ 가 fails 인
    -- 마스크에 count(DISTINCT x) 는 등록 여부와 무관하게 성립할 수 없다 --
    -- 그건 unknown("아직 인증 안 됨")이 아니라 fails("영원히 불가")다.
    res := 'holds';
    --   1: DISTINCT 는 EQ 채널을 탄다 (명세 §2 effect->의무)
    IF is_distinct THEN
        res := ipguard_weakest(res, ipguard_capability(mid, 'equality_factor'));
    END IF;
    --   2: ordered aggregate 는 ORD 채널을 탄다
    IF is_ordered THEN
        res := ipguard_weakest(res, ipguard_capability(mid, 'order_factor'));
    END IF;
    --   3: 집계별 의무 (count/sum/avg/min/max -> null_equivalence)
    FOR ob IN SELECT capability FROM ipguard_aggregate_obligation WHERE agg = a
    LOOP
        res := ipguard_weakest(res, ipguard_capability(mid, ob.capability));
    END LOOP;
    IF res = 'fails' THEN RETURN 'fails'; END IF;

    SELECT * INTO row_ FROM ipguard_mask_aggregate_compatibility
     WHERE mask_id = mid AND agg = a AND distinct_arg = is_distinct
       AND ordered_arg = is_ordered AND collation_name = coll
       AND (redactor IS NULL OR out_redactor = redactor);
    IF NOT FOUND THEN RETURN 'unknown'; END IF;

    SELECT * INTO anow FROM ipguard_fingerprint(row_.agg, coll);
    SELECT * INTO rnow FROM ipguard_fingerprint(row_.out_redactor, coll);
    IF anow.fingerprint IS DISTINCT FROM row_.agg_fingerprint
       OR rnow.fingerprint IS DISTINCT FROM row_.red_fingerprint THEN
        RETURN 'unknown';
    END IF;

    RETURN ipguard_weakest(row_.claim, res);
END $$;

-- 감사: 지금 무엇이 어긋나 있는가. 빈 결과가 정상이다.
CREATE FUNCTION ipguard_audit_registry()
RETURNS TABLE (mid int, mask_func text, problem text, detail text)
LANGUAGE sql STABLE AS $$
    SELECT i.mask_id, i.func::text,
           '지문 불일치 -- 인증서 전부 무효'::text,
           (i.fp_basis_kind || ': ' || i.impl_fingerprint || ' -> ' || f.fingerprint)::text
      FROM ipguard_mask_instance i, ipguard_fingerprint(i.func, i.collation_name) f
     WHERE f.fingerprint IS DISTINCT FROM i.impl_fingerprint
    UNION ALL
    SELECT i.mask_id, i.func::text,
           '지문이 불완전하다 -- 변경을 놓칠 수 있다'::text,
           (i.fp_basis_kind ||
            CASE i.fp_basis_kind
              WHEN 'c-foreign' THEN ': .so 를 덮어써도 카탈로그가 안 바뀐다'
              WHEN 'src' THEN ': 본문이 호출하는 함수의 변경을 못 본다'
              ELSE '' END)::text
      FROM ipguard_mask_instance i
     WHERE NOT i.fp_complete
    ORDER BY 1, 3
$$;

-- ==================================================================
-- comparator 인증서 -- EQ/ORD 는 **어느 연산자에 대한** 주장인가
--
-- ★ order_factor / equality_factor 를 마스크 단독 속성으로만 두면 구멍이다.
--   같은 마스크가 표준 `<` 에는 factor-through 하더라도 사용자 정의 역순·
--   부분순서 연산자에는 그렇지 않을 수 있다.
--
--   ORD = NullPartitionPreserved  ∧  ComparatorFactors
--   EQ  = NullPartitionPreserved  ∧  EqualityFactors
--
--   null_equivalence 가 앞의 연언지이고, 이 표가 뒤의 연언지다.
--   (그래서 order_factor=holds 와 null_equivalence=fails 는 **모순이 아니다** --
--    order_factor 를 non-NULL 정의역의 comparator 주장으로 읽으면 양립한다.
--    다만 SQL 전체 정렬 인증서로는 불충분하다.)
--
-- 일반 사용자 정의 연산자를 지원할 필요는 없다. **표준 연산자만 등록해도
-- 충분**하고, 미등록 comparator 는 unknown -> reject 다.
-- ==================================================================
CREATE TABLE ipguard_mask_comparator_compatibility (
    mask_id        int  NOT NULL REFERENCES ipguard_mask_instance ON DELETE CASCADE,
    kind           text NOT NULL,          -- 'EQ' | 'ORD'
    op             regoperator NOT NULL,   -- eqop 또는 sortop
    collation_name text NOT NULL DEFAULT '',
    op_fingerprint text NOT NULL,          -- 연산자 구현 함수(oprcode)의 지문
    claim      ipguard_claim     NOT NULL DEFAULT 'unknown',
    assurance  ipguard_assurance NOT NULL DEFAULT 'unknown',
    evidence   text,
    PRIMARY KEY (mask_id, kind, op, collation_name),
    CONSTRAINT cmp_kind_known CHECK (kind IN ('EQ','ORD')),
    CONSTRAINT unknown_has_no_source
        CHECK ((claim = 'unknown') = (assurance = 'unknown'))
);

CREATE FUNCTION ipguard_register_comparator(
    p_mask_id int, p_kind text, p_op regoperator,
    p_claim ipguard_claim DEFAULT 'holds',
    p_assurance ipguard_assurance DEFAULT 'trusted_assumption',
    p_coll text DEFAULT '', p_evidence text DEFAULT NULL)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE fp text;
BEGIN
    SELECT f.fingerprint INTO fp
      FROM pg_operator o,
           LATERAL ipguard_fingerprint(o.oprcode::regprocedure, p_coll) f
     WHERE o.oid = p_op;
    INSERT INTO ipguard_mask_comparator_compatibility
        (mask_id, kind, op, collation_name, op_fingerprint,
         claim, assurance, evidence)
    VALUES (p_mask_id, p_kind, p_op, p_coll, fp, p_claim, p_assurance, p_evidence)
    ON CONFLICT (mask_id, kind, op, collation_name) DO UPDATE
        SET op_fingerprint = excluded.op_fingerprint,
            claim = excluded.claim, assurance = excluded.assurance,
            evidence = excluded.evidence;
END $$;

-- 인스턴스 입력 타입의 **기본 btree** 연산자를 식별해서 넣는다.
--
-- ★ "btree 기본 연산자니까 holds" 를 **자동으로 만들지 않는다.** 기본
--   comparator 라는 사실은 **연산자를 식별**해 줄 뿐, 특정 마스크가 그
--   비교자를 factor through 한다는 증거가 아니다. 그래서 claim 과 assurance
--   에 기본값을 두지 않는다 -- 호출자가 반드시 명시해야 한다.
--
--   인증서는 이 넷의 결합이다:
--     MaskInstance
--     ComparatorInstance(op_oid, collation, fingerprint)
--     claim_value
--     assurance
CREATE FUNCTION ipguard_register_default_comparators(
    p_mask_id int,
    p_ord ipguard_claim,
    p_eq  ipguard_claim,
    p_assurance ipguard_assurance)
RETURNS void
LANGUAGE plpgsql AS $$
DECLARE t regtype; c text; lt regoperator; gt regoperator; eq regoperator;
BEGIN
    SELECT input_type, collation_name INTO t, c
      FROM ipguard_mask_instance WHERE mask_id = p_mask_id;
    SELECT amop.amopopr INTO lt
      FROM pg_opclass oc
      JOIN pg_amop amop ON amop.amopfamily = oc.opcfamily
     WHERE oc.opcintype = t AND oc.opcdefault
       AND oc.opcmethod = (SELECT oid FROM pg_am WHERE amname='btree')
       AND amop.amopstrategy = 1 AND amop.amoplefttype = t
       AND amop.amoprighttype = t;
    SELECT amop.amopopr INTO eq
      FROM pg_opclass oc
      JOIN pg_amop amop ON amop.amopfamily = oc.opcfamily
     WHERE oc.opcintype = t AND oc.opcdefault
       AND oc.opcmethod = (SELECT oid FROM pg_am WHERE amname='btree')
       AND amop.amopstrategy = 3 AND amop.amoplefttype = t
       AND amop.amoprighttype = t;
    IF lt IS NOT NULL THEN
        PERFORM ipguard_register_comparator(p_mask_id, 'ORD', lt, p_ord,
                    CASE WHEN p_ord='unknown' THEN 'unknown'
                         ELSE p_assurance END, c, '기본 btree < 연산자');
    END IF;
    -- DESC 는 **다른 sortop**(strategy 5, `>`)이다. 순서 역전은 factor-through
    -- 를 보존하므로 같이 등록한다 -- 안 하면 ORDER BY ... DESC 가 전부 거부된다.
    SELECT amop.amopopr INTO gt
      FROM pg_opclass oc
      JOIN pg_amop amop ON amop.amopfamily = oc.opcfamily
     WHERE oc.opcintype = t AND oc.opcdefault
       AND oc.opcmethod = (SELECT oid FROM pg_am WHERE amname='btree')
       AND amop.amopstrategy = 5 AND amop.amoplefttype = t
       AND amop.amoprighttype = t;
    IF gt IS NOT NULL THEN
        PERFORM ipguard_register_comparator(p_mask_id, 'ORD', gt, p_ord,
                    CASE WHEN p_ord='unknown' THEN 'unknown'
                         ELSE p_assurance END, c, '기본 btree > 연산자 (DESC)');
    END IF;
    IF eq IS NOT NULL THEN
        PERFORM ipguard_register_comparator(p_mask_id, 'EQ', eq, p_eq,
                    CASE WHEN p_eq='unknown' THEN 'unknown'
                         ELSE p_assurance END, c, '기본 btree = 연산자');
    END IF;
END $$;

-- 조회 API. 지문 재계산 -> 불일치면 unknown. 미등록 연산자도 unknown.
CREATE FUNCTION ipguard_comparator_compatible(
    mid int, p_kind text, p_op regoperator, p_coll text DEFAULT '')
RETURNS ipguard_claim
LANGUAGE plpgsql STABLE AS $$
DECLARE inst record; now_fp record; row_ record; opnow text;
BEGIN
    SELECT * INTO inst FROM ipguard_mask_instance WHERE mask_id = mid;
    IF NOT FOUND THEN RETURN 'unknown'; END IF;
    SELECT * INTO now_fp FROM ipguard_fingerprint(inst.func, inst.collation_name);
    IF now_fp.fingerprint IS DISTINCT FROM inst.impl_fingerprint THEN
        RETURN 'unknown';
    END IF;

    SELECT * INTO row_ FROM ipguard_mask_comparator_compatibility
     WHERE mask_id = mid AND kind = p_kind AND op = p_op
       AND collation_name = p_coll;
    IF NOT FOUND THEN RETURN 'unknown'; END IF;   -- ★ 미등록 comparator

    SELECT f.fingerprint INTO opnow
      FROM pg_operator o,
           LATERAL ipguard_fingerprint(o.oprcode::regprocedure, p_coll) f
     WHERE o.oid = p_op;
    IF opnow IS DISTINCT FROM row_.op_fingerprint THEN
        RETURN 'unknown';                          -- 연산자 구현이 바뀌었다
    END IF;
    RETURN row_.claim;
END $$;

-- ==================================================================
-- proof tree 를 위한 조회 API
--
-- ★ 다중 입력 표현식은 **사슬이 아니라 proof tree** 다:
--
--     concat(lower(ssn), upper(birth))
--       Apply concat
--       ├─ Apply lower  └─ Source ssn(mask_ssn)
--       └─ Apply upper  └─ Source birth(mask_birth)
--
--   평탄한 [lower, upper, concat] 로는 (a) upper 가 어느 입력 mask 를
--   소비하는지 (b) concat 의 첫째·둘째 인자 mask 가 무엇인지 (c) 두 branch 의
--   결과 mask 가 무엇인지를 **증명할 수 없다.**
--
--   f(m(x)) = r_out(f(x)) 이므로 합성은 **출력 마스크를 타고** 올라간다:
--     lower(m(x))       = r1(lower(x))
--     upper(r1(lower(x))) = r2(upper(lower(x)))   <- r1 에 대한 인증서가 필요
--   그래서 인증 통과 시 **출력 마스크의 mask_id** 를 돌려준다.
-- ==================================================================
CREATE FUNCTION ipguard_mask_id_of_kind(p_kind text, p_coll text DEFAULT '')
RETURNS int LANGUAGE sql STABLE AS $$
    SELECT mask_id FROM ipguard_mask_instance
     WHERE normalized_args = 'kind=' || p_kind AND collation_name = p_coll
     LIMIT 1
$$;

-- ★ bare 출력(SELECT secret)에는 commutation 의무가 없다 -- Mout 이 같은
--   마스크를 직접 적용하기 때문이다. 그러나 **MaskInstance 자체의 코어
--   전제까지 생략하면 안 된다.** 미등록 UDF 나 변경된 마스크가 bare output
--   으로 인증 없이 흘러나간다.
--
--     MASK_APPLY(mask_instance) := deterministic ∧ total ∧ 지문 일치
--
--   지문 일치는 ipguard_capability() 가 이미 본다(불일치면 unknown).
CREATE FUNCTION ipguard_mask_baseline(mid int) RETURNS ipguard_claim
LANGUAGE sql STABLE AS $$
    SELECT ipguard_weakest(ipguard_capability(mid, 'determinism'),
                           ipguard_capability(mid, 'total'))
$$;

-- 인증 통과 시 **출력 마스크의 mask_id**, 실패면 NULL.
-- arg_signature 에 **인자 위치**가 들어가야 concat(a,b) 와 concat(b,a) 를
-- 구별한다 -- 안 그러면 인자 순서가 다른 인증서로 통과한다.
CREATE FUNCTION ipguard_function_out_mask(
    mid int, f regprocedure, args text DEFAULT '', coll text DEFAULT '')
RETURNS int LANGUAGE plpgsql STABLE AS $$
DECLARE c ipguard_claim; r regprocedure;
BEGIN
    c := ipguard_function_compatible(mid, f, args, NULL, coll);
    IF c <> 'holds' THEN RETURN NULL; END IF;
    SELECT out_redactor INTO r FROM ipguard_mask_function_compatibility
     WHERE mask_id = mid AND func = f AND arg_signature = args
       AND collation_name = coll LIMIT 1;
    RETURN (SELECT mask_id FROM ipguard_mask_instance
             WHERE func = r AND collation_name = coll LIMIT 1);
END $$;

CREATE FUNCTION ipguard_aggregate_out_mask(
    mid int, a regprocedure, is_distinct boolean DEFAULT false,
    is_ordered boolean DEFAULT false, coll text DEFAULT '')
RETURNS int LANGUAGE plpgsql STABLE AS $$
DECLARE c ipguard_claim; r regprocedure;
BEGIN
    c := ipguard_aggregate_compatible(mid, a, is_distinct, is_ordered, NULL, coll);
    IF c <> 'holds' THEN RETURN NULL; END IF;
    SELECT out_redactor INTO r FROM ipguard_mask_aggregate_compatibility
     WHERE mask_id = mid AND agg = a AND distinct_arg = is_distinct
       AND ordered_arg = is_ordered AND collation_name = coll LIMIT 1;
    RETURN (SELECT mask_id FROM ipguard_mask_instance
             WHERE func = r AND collation_name = coll LIMIT 1);
END $$;

-- ==================================================================
-- Declassification 인증서 (명세 v0.2.1 §3.5)
--
-- ★ δ_Q 를 **질의 실행 전에** 정책이 고정해야 한다. 결과를 본 뒤 넓힐 수
--   있으면 opacity 정리가 공허해진다 -- 어떤 누출도 사후에 정당화된다.
--
-- 인증서는 **(source, effect, sink, observation) 4-튜플**이다. 술어 하나를
-- 통째로 면제하는 것이 아니다:
--
--   (secret, CARD, ROW_COUNT,   predicate-result)  허용
--   (secret, ORD,  FINAL_ORDER, relative-order)    불허
--
-- 첫 줄이 있어도 둘째는 자동으로 따라오지 않는다. `WHERE secret='a'` 의 행
-- 포함 여부 허가가 `ORDER BY secret` 의 상대 순서를 허가하지 않는다.
-- ==================================================================
-- ★ 키에 **context_key** 가 들어간다.
--
--   Declass( sources, effect, context_fingerprint, sink, observation )
--
-- `ORDER BY secret` 을 허가한 것이 `ORDER BY lower(secret)` 이나
-- `ORDER BY secret USING ~<~` 까지 허가하면 안 된다. 드러나는 것이 다른
-- 정보이기 때문이다. context_key 에는 **키 표현식·비교자·collation** 이
-- 들어간다. 구현의 특별 규칙이 아니라 **인증서 키**로 처리해야 명세와
-- 구현이 어긋나지 않는다.
--
-- 값은 ipguard_obligations(sql).context_key 에서 그대로 읽어 쓴다.
CREATE TABLE ipguard_declassification (
    relid       regclass NOT NULL,     -- regclass 는 이름으로 덤프된다
    attnum      int2     NOT NULL,
    effect      text     NOT NULL,
    sink        text     NOT NULL,
    context_key text     NOT NULL DEFAULT '',
    -- 정책 담당자가 **읽고 검토할 수 있는** 형태. opaque hash 만 두면
    -- 무엇을 허가하는지 아무도 못 읽는다.
    context_canonical text NOT NULL DEFAULT '',
    -- ★ parameterized predicate. `WHERE secret = $1` 의 인증서가 조용히
    --   모든 $1 값에 재사용되면 안 된다. 기본은 'none' (파라미터 있으면 거부),
    --   'domain' 은 **정책이 그 파라미터 정의역 전체를 명시적으로 허가**한다.
    param_scope text     NOT NULL DEFAULT 'none',
    observation text     NOT NULL,
    granted_by  text     NOT NULL DEFAULT current_user,
    granted_at  timestamptz NOT NULL DEFAULT now(),
    rationale   text,
    PRIMARY KEY (relid, attnum, effect, sink, context_key),
    CONSTRAINT effect_known CHECK (effect IN ('VAL','EQ','ORD','CARD')),
    CONSTRAINT sink_known CHECK (sink IN
        ('CELL','MULTIPLICITY','ROW_COUNT','FINAL_ORDER','MEMBERSHIP')),
    CONSTRAINT param_scope_known CHECK (param_scope IN ('none','all_values'))
);

-- context_key = sha256(version || domain || context_canonical)
--
-- 버전과 도메인을 넣는 이유: canonical 인코딩이 바뀌면 **옛 인증서가 새
-- 문맥에 붙으면 안 된다.** 버전을 올리면 전부 무효가 된다.
CREATE FUNCTION ipguard_context_key(p_canonical text) RETURNS text
LANGUAGE sql IMMUTABLE AS $$
    SELECT encode(sha256(convert_to('ipgctx' || '\x1f' || 'declass' || '\x1f'
                                    || p_canonical, 'UTF8')), 'hex')
$$;

-- 게이트가 무엇을 보고 왜 그렇게 판정했는지 행으로 펼친다.
--
-- 판정만 돌려주면 **규칙이 우연히 맞은 것과 제대로 맞은 것을 구별할 수 없다.**
-- 이 프로젝트에서 R3b 가 정확히 그렇게 오래 숨어 있었다.
-- ★ 측정 도구. 라벨이 어느 **구문 위치**에 나타나는지만 낸다.
--   sink 도달 분석을 하지 않으므로 "민감 컬럼이 EQ/ORD/CARD 위치에 있으면
--   거부" 라는 순진한 baseline 을 Query tree 위에서 만들 수 있다.
--   게이트는 이 함수를 부르지 않는다 -- 부르면 비교가 순환한다.
-- ★ `position` 은 PostgreSQL 예약어다(POSITION(x IN y)). pos_kind 로 쓴다.
CREATE FUNCTION ipguard_label_positions(sql text,
    OUT pos_kind text, OUT depth int, OUT sources text[])
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'ipguard_label_positions'
LANGUAGE C STRICT;
REVOKE ALL ON FUNCTION ipguard_label_positions(text) FROM PUBLIC;

CREATE FUNCTION ipguard_obligations(sql text,
    OUT effect      text,
    OUT context     text,
    OUT sink        text,
    OUT class       text,
    OUT discharge   text,
    OUT detail      text,
    OUT context_key text,
    OUT context_canonical text,
    -- ★ 정책 발급이 사람용 context 문자열을 파싱하면 안 된다.
    --   '<relid>.<attnum>' 을 obligation 의 source 순서 그대로 낸다.
    OUT ordered_sources text[],
    -- 미해소 사유 코드: CAPABILITY_FAILS | MISSING_CERTIFICATE | ''(해소됨)
    OUT fail_kind   text)
RETURNS SETOF record
AS 'MODULE_PATHNAME', 'ipguard_obligations'
LANGUAGE C STRICT;

-- ==================================================================
-- 권한 — 진단 함수가 부수 채널이 되면 안 된다
--
-- 이 프로젝트가 5R 에서 이미 당한 클래스다: 보안 컨트롤의 **관찰·조작 표면**을
-- 열어 두면 집행기를 아무리 정교하게 만들어도 소용이 없다.
--
--   ipguard_pii_plan_count()  이 백엔드에서 PII 계획이 몇 번 일어났는가
--                             -> 어떤 테이블에 라벨이 붙어 있는지, 방금 어떤
--                                질의가 PII 를 건드렸는지가 새어나간다
--   ipguard_audit_*()         라벨·레지스트리 내부 상태
--   ipguard_register_mask()   인증서를 **쓴다** -- 공격자가 원하는 capability 를
--                             holds 로 등록하면 게이트가 통째로 무력화된다
--
-- 반대로 조회 API 셋은 **계획기가 앱 사용자 권한으로 호출**하므로 PUBLIC 이
-- 실행할 수 있어야 한다. 그래서 SECURITY DEFINER 로 두고 밑 테이블은 닫는다.
-- ==================================================================

-- 1) 레지스트리 표는 PUBLIC 이 읽지도 쓰지도 못한다.
REVOKE ALL ON ipguard_mask_instance                    FROM PUBLIC;
REVOKE ALL ON ipguard_mask_capability                  FROM PUBLIC;
REVOKE ALL ON ipguard_mask_function_compatibility      FROM PUBLIC;
REVOKE ALL ON ipguard_mask_aggregate_compatibility     FROM PUBLIC;
REVOKE ALL ON ipguard_aggregate_obligation             FROM PUBLIC;
REVOKE ALL ON ipguard_mask_comparator_compatibility    FROM PUBLIC;
REVOKE ALL ON ipguard_registry_epoch                   FROM PUBLIC;
-- declassification 은 **정책**이다. 앱이 자기 허가를 발급하면 의미가 없다.
REVOKE ALL ON ipguard_declassification                 FROM PUBLIC;

-- 2) 쓰기·관리·진단 함수는 PUBLIC 실행 금지.
REVOKE ALL ON FUNCTION ipguard_register_mask(regprocedure, regtype, regtype,
                                             text, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_watch_registry()        FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_register_comparator(int, text, regoperator,
              ipguard_claim, ipguard_assurance, text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_register_default_comparators(int,
              ipguard_claim, ipguard_claim, ipguard_assurance) FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_watch_labels(regclass)  FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_registry_bump()         FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_registry_guard()        FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_label_changed()         FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_audit_registry()        FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_audit_definers()        FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_verify_labels(text)     FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_migrate_labels_to_oid(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_coverage(text)          FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_coverage_deep(text, int, float8) FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_build_id()              FROM PUBLIC;
REVOKE ALL ON FUNCTION ipguard_manifest_axes()         FROM PUBLIC;
-- ★ PII 계획 카운터. 진단용이지 앱이 볼 것이 아니다.
REVOKE ALL ON FUNCTION ipguard_pii_plan_count()        FROM PUBLIC;
-- 의무 목록은 어떤 컬럼에 라벨이 붙었는지를 그대로 드러낸다.
REVOKE ALL ON FUNCTION ipguard_obligations(text)       FROM PUBLIC;

-- 3) 조회 API 는 SECURITY DEFINER + 고정 search_path.
--
-- 계획기가 앱 사용자 권한으로 부르므로 PUBLIC 실행이 필요하지만, 밑 테이블은
-- 닫혀 있어야 한다. search_path 를 고정하지 않으면 호출자가 자기 스키마에
-- 가짜 ipguard_mask_capability 를 만들어 **원하는 claim 을 주입**할 수 있다 --
-- SECURITY DEFINER 의 고전적 함정이고, 여기서는 게이트 무력화로 직결된다.
ALTER FUNCTION ipguard_capability(int, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_function_compatible(int, regprocedure, text,
                                           regprocedure, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_aggregate_compatible(int, regprocedure, boolean,
                                            boolean, regprocedure, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_fingerprint(regprocedure, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_comparator_compatible(int, text, regoperator, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_mask_id_of_kind(text, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_mask_baseline(int)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_function_out_mask(int, regprocedure, text, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;
ALTER FUNCTION ipguard_aggregate_out_mask(int, regprocedure, boolean, boolean, text)
    SECURITY DEFINER SET search_path = @extschema@, pg_catalog, pg_temp;

-- 지문 계산 자체는 카탈로그만 읽으므로 열어 둬도 되지만, 조회 API 가
-- SECURITY DEFINER 로 부르므로 PUBLIC 이 직접 부를 이유가 없다.
REVOKE ALL ON FUNCTION ipguard_proc_basis(regprocedure) FROM PUBLIC;

-- ==================================================================
-- ★ 설치 시점에 레지스트리 감시를 **켠다**.
--
-- 이전에는 `ipguard_watch_registry()` 를 정의만 하고 부르지 않았다. 부르는
-- 곳은 회귀 스크립트 하나뿐이었다(tools/score_registry.py). 그래서
--
--     CREATE EXTENSION ipguard;   -- 트리거 0개
--     ... 마스크·인증서 등록 ...
--     ... 인증서 철회 ...          -- 캐시된 generic plan 이 그대로 돈다
--
-- 가 된다. 운영자는 철회했다고 믿는데 살아 있는 세션의 계획 캐시는 철회 전
-- 판정으로 계속 돈다. 에러도 경고도 없다 -- 라벨 staleness(Y07)와 정확히
-- 같은 구멍이고, 커넥션 풀에서 가장 위험하다.
--
-- 실측으로 잡혔다: 확장을 재생성한 직후 gate 회귀의 연결2·3·5·6 이
-- "철회 후 재계획 +0, 그리고 수락" 으로 뒤집혔다. 회귀가 초록이었던 것은
-- score_registry.py 가 **먼저 돌아** 트리거를 깔아 놓았기 때문이다.
-- 시험이 다른 시험의 부작용에 기대고 있었다.
--
-- 라벨 표는 스키마마다 다르므로 여기서 걸 수 없다 --
-- ipguard_provision_schema() 가 만들 때 ipguard_watch_labels() 를 부른다.
-- 레지스트리 표는 확장 소유이므로 지금 건다.
-- ==================================================================
SELECT ipguard_watch_registry();
