/*
 * ipguard -- PII provenance 분석 (탐지 전용 v1)
 *
 * 와이어 레벨 탐지기는 RowDescription의 resorigtbl/resorigcol 만 본다.
 * 그래서 표현식으로 한 번만 감싸면(substr, ||, coalesce ...) provenance가
 * 0이 되어 미탐이 난다. 실측: 55개 PII 노출 항목 중 21개(38%)만 탐지.
 *
 * 이 확장은 파스 + 재작성(뷰 전개 포함)이 끝난 Query 트리를 직접 걸어
 * 모든 Var를 base relation 컬럼까지 해석한다. 표현식 안이든, 서브쿼리
 * 너머든, CTE 안이든 따라간다.
 *
 * v1은 탐지만 한다. 마스킹은 회수율을 측정한 뒤에 붙인다 -- 순서를 바꾸면
 * 무엇을 얼마나 개선했는지 말할 근거가 없어진다.
 *
 * 출력 컬럼(클라이언트에 값이 도달)과 술어 참조(부채널)를 분리해서 보고한다.
 * 부채널(WHERE ssn LIKE '8001%')은 마스킹으로 막을 수 없는 별개 클래스이므로
 * 같은 지표에 섞으면 안 된다.
 */
#include "postgres.h"

#include "access/htup_details.h"     /* heap_form_tuple */
#include "catalog/namespace.h"       /* RangeVarGetRelid */
#include "catalog/pg_aggregate.h"    /* AGGKIND_ORDERED_SET */
#include "catalog/pg_class.h"
#include "access/transam.h"          /* FirstNormalObjectId */
#include "catalog/pg_collation.h"   /* DEFAULT_COLLATION_OID */
#include "catalog/pg_proc.h"         /* PROVOLATILE_VOLATILE, Form_pg_proc */
#include "catalog/pg_type.h"
#include "utils/array.h"             /* proconfig 순회 */
#include "utils/syscache.h"          /* SearchSysCache1(PROCOID) */
#include "mb/pg_wchar.h"
#include "nodes/makefuncs.h"
#include "optimizer/planner.h"
#include "utils/guc.h"
#include "executor/spi.h"
#include "funcapi.h"
#include "lib/stringinfo.h"
#include "miscadmin.h"
#include "nodes/nodeFuncs.h"
#include "optimizer/optimizer.h"     /* get_sortgroupclause_tle */
#include "parser/analyze.h"
#include "parser/parse_func.h"
#include "parser/parse_node.h"       /* make_parsestate */
#include "parser/parse_relation.h"   /* expandRTE, addRangeTableEntryForSubquery */
#include "parser/parsetree.h"
#include "storage/lmgr.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/lsyscache.h"
#include "utils/varlena.h"
#include "utils/lsyscache.h"         /* get_attnum */
#include "utils/memutils.h"
#include "utils/tuplestore.h"        /* ipguard_explain 의 집합 반환 */
#include "utils/inval.h"             /* 라벨 변경 -> 계획 캐시 무효화 */
#include "utils/plancache.h"         /* ResetPlanCache */
#include "commands/trigger.h"

PG_MODULE_MAGIC;

#define MAX_DEPTH   24      /* 재귀 CTE 등에서 무한 재귀 방지 */
#define MAX_STACK   32

typedef struct Label
{
    Oid     relid;
    int     attno;
    char   *kind;
} Label;

/* 컬럼 단위 근거. kinds 리스트는 "ssn 이 나간다"까지만 말해주므로
 * "어느 테이블의 어느 컬럼이 어느 경로로 나가는가"를 사람에게 보여줄 수 없다.
 * ipguard_explain() 이 이걸 행으로 펼친다. */
typedef struct ColHit
{
    Oid         relid;
    int         attno;
    const char *kind;
    int         path;               /* 0=출력 1=술어 2=쓰기 */
} ColHit;

typedef struct Ctx
{
    Label      *labels;
    int         nlabels;

    Query      *stack[MAX_STACK];   /* 쿼리 레벨 스택 (varlevelsup / ctelevelsup 해석용) */
    int         sp;

    List       *out_kinds;          /* 출력으로 도달하는 PII 종류 */
    List       *pred_kinds;         /* 술어에서만 참조되는 PII 종류 */
    List       *write_kinds;        /* DML 로 테이블에 써넣어지는 PII 종류 */
    List      **sink;               /* 현재 수집 대상 */
    int         unresolved;         /* RTE 종류 때문에 출처를 못 밝힌 참조 (정상일 수 있음) */
    int         bounded;            /* ★ 순회 bound 소진으로 포기한 횟수.
                                     * unresolved 와 반드시 구분해야 한다:
                                     * RTE_FUNCTION 은 정상 쿼리에서도 흔하지만,
                                     * bound 소진은 언제나 의심스럽다. 이 구분이
                                     * fail-closed 를 값싸게 만든다. */
    int         depth;

    int         utility_n;          /* utility 문장 수. planner_hook 은 utility 를
                                     * 보지 않으므로 판정을 "실측 확인 필요"로
                                     * 낮춰야 한다 -- 여기서 거짓 안심이 생긴다. */
    List       *cols;               /* of ColHit *, 컬럼 단위 근거 */
    /* ★ resjunk 까지 훑는다.
     *
     * 기본(false)에서는 resjunk TLE 를 건너뛴다 -- 클라이언트로 나가지
     * 않으므로 **마스킹 대상이 아니기 때문**이다. 그런데 그러면
     *
     *     SELECT id, row_number() OVER (ORDER BY ssn) FROM cust
     *
     * 처럼 민감 컬럼이 **정렬/윈도우 키에만** 있는 질의에서 분석기가 아무것도
     * 보고하지 않는다. R3b 가 틀렸던 것과 같은 뿌리다 -- masked-ness 를 기준
     * 삼으면 resjunk 가 통째로 사각지대가 된다.
     *
     * release 게이트는 "이 질의가 라벨된 데이터를 건드리는가" 를 물어야 하고,
     * 그 판정은 resjunk 를 포함해야 한다. */
    bool        scan_all;
    /* ★ 공개(비라벨) 컬럼도 기록한다. declassification 의 context canonical 은
     * key vector 의 **모든** 항을 식별해야 한다 -- `ORDER BY grade, secret` 과
     * `ORDER BY dept, secret` 은 다른 문맥이다. */
    bool        collect_all;
    /* ★ 게이트가 순회 중 라벨된 컬럼을 **한 번이라도** 만났는가.
     *
     * 앞 판은 walk_query 기반 사전검사로 판정했는데, 그건 출력 Var 가
     * 가리키는 컬럼만 따라가므로 **서브쿼리 술어/GROUP BY/ORDER BY 에만
     * 라벨이 있으면 못 본다.** 그러면 게이트가 아예 안 돌아
     *   SELECT sum(s.id) FROM (SELECT id FROM t WHERE secret='a') s
     * 가 무조건 수락됐다 -- 실측으로 잡았다.
     *
     * 게이트 자신이 순회하며 세우는 플래그여야 한다. */
    bool        gate_touched;
    bool        collect;            /* cols 수집 여부.
                                     * planner_hook 은 매 계획마다 도는 hot path
                                     * 이므로 기본은 끈다 -- 설명 함수에서만 켠다. */
} Ctx;

/* 라벨 테이블이 있는 스키마. 하드코딩하면 다른 스키마의 워크로드(TPC-H 등)로
 * 측정할 수 없다. */
static char *ipguard_label_schema = NULL;

/* 라벨을 무엇으로 붙잡는가.
 *
 *   name : pii_label(relname, attname, kind)   -- 사람이 읽고 덤프에 안전하지만
 *          ALTER TABLE RENAME / RENAME COLUMN / SET SCHEMA 로 조용히 끊긴다
 *          (4R Y01~Y03).
 *   oid  : pii_label(relid regclass, attnum, kind) -- 이름 변경에 면역.
 *          regclass 는 pg_dump 가 **이름으로** 덤프하므로 복원에도 안전하다.
 *          다만 attnum 은 이름이 없어 컬럼 삭제 이력에 따라 흔들릴 수 있다.
 *
 * 어느 쪽이 나은지 재려고 만든 스위치다 -- results/label-keying.md */
static int ipguard_label_key = 0;        /* 0=name 1=oid */

/* 마스크를 **어디에** 넣는가. 동적 마스킹 설계 공간의 세 꼭짓점이다.
 *
 *   source      V1 -- 테이블 진입점. 술어·그룹핑·집계가 전부 마스크를 본다.
 *                     (마스킹 뷰, PostgreSQL Anonymizer 의 동적 마스킹)
 *   output_path V2 -- 트리의 공개 경로만. 술어는 원본을 본다. (이 확장의 기본)
 *   projection  V3 -- **모든 관계 연산 뒤**. 그룹핑·정렬·집계는 원본으로 계산되고
 *                     최종 투영에서만 가린다. (Oracle Data Redaction 26ai 가
 *                     문서상 이 지점이다 -- GROUP BY 절은 갱신하지 않는다고 명시)
 *
 * 세 지점은 Fidelity / Mask opacity / Totality 중 서로 다른 하나를 포기한다.
 * 한 시스템에서 같은 마스크 함수로 셋을 다 돌릴 수 있어야 비교가 성립한다. */
static int ipguard_mask_position = 1;    /* 0=source 1=output_path 2=projection */
static const struct config_enum_entry mask_position_options[] = {
    {"source", 0, false}, {"output_path", 1, false},
    {"projection", 2, false}, {NULL, 0, false}
};
static const struct config_enum_entry label_key_options[] = {
    {"name", 0, false}, {"oid", 1, false}, {NULL, 0, false}
};

static void walk_query(Ctx *ctx, Query *q, List **out_sink);
static bool has_mask_call(Node *node, void *unused);
static bool walk_expr(Node *node, Ctx *ctx);
static void collect_setop_arms(Query *q, Node *n, List **arms);
static void walk_setop_col(Ctx *ctx, Query *sub, AttrNumber attno);

/* ---------------------------------------------------------------- 라벨 */

/* h5.pii_label 을 (relid, attno, kind) 로 펼쳐 읽는다.
 * 라벨 테이블만 근거로 삼는다 -- 컬럼명 문자열 패턴은 쓰지 않는다.
 * (컬럼명 휴리스틱을 쓰면 코퍼스 측정이 무의미해진다) */
static void
load_labels(Ctx *ctx)
{
    /* 라벨은 부모 릴레이션에만 붙는다. 파티션 자식/상속 자식을 직접 겨냥하는
     * 쿼리(SELECT acct_no FROM acct_p1)를 놓치지 않도록 pg_inherits 를 따라
     * 자손까지 전개한다. 컬럼은 attnum 이 아니라 attname 으로 잇는다 --
     * ADD COLUMN 이력에 따라 자식의 attnum 이 부모와 다를 수 있다. */
    StringInfoData  q;
    const char     *sch = (ipguard_label_schema && *ipguard_label_schema)
                          ? ipguard_label_schema : "h5";
    const char     *sql;

    initStringInfo(&q);
    if (ipguard_label_key == 1)
    {
        /* OID 키잉. 상속 자식으로의 전개는 여전히 **이름으로** 잇는다 --
         * 자식의 attnum 은 ADD/DROP COLUMN 이력에 따라 부모와 다를 수 있다. */
        appendStringInfo(&q,
            "WITH RECURSIVE d(relid, attnum, kind) AS ( "
            "    SELECT l.relid::oid, l.attnum, l.kind "
            "      FROM %s.pii_label l "
            "  UNION ALL "
            "    SELECT i.inhrelid, ac.attnum, d.kind "
            "      FROM d "
            "      JOIN pg_inherits i ON i.inhparent = d.relid "
            "      JOIN pg_attribute ap ON ap.attrelid = d.relid "
            "                          AND ap.attnum = d.attnum "
            "      JOIN pg_attribute ac ON ac.attrelid = i.inhrelid "
            "                          AND ac.attname = ap.attname "
            ") "
            "SELECT d.relid::int8, a.attnum::int4, d.kind "
            "  FROM d JOIN pg_attribute a ON a.attrelid = d.relid "
            "                            AND a.attnum = d.attnum "
            " WHERE NOT a.attisdropped AND a.attnum > 0",
            quote_identifier(sch));
        sql = q.data;
        goto have_sql;
    }
    appendStringInfo(&q,
        "WITH RECURSIVE d(relid, attname, kind) AS ( "
        "    SELECT c.oid, l.attname, l.kind "
        "      FROM %s.pii_label l "
        "      JOIN pg_class c ON c.relname = l.relname "
        "                     AND c.relnamespace = %s::regnamespace "
        "  UNION ALL "
        "    SELECT i.inhrelid, d.attname, d.kind "
        "      FROM d JOIN pg_inherits i ON i.inhparent = d.relid "
        ") "
        "SELECT d.relid::int8, a.attnum::int4, d.kind "
        "  FROM d JOIN pg_attribute a ON a.attrelid = d.relid "
        "                            AND a.attname = d.attname "
        " WHERE NOT a.attisdropped AND a.attnum > 0",
        quote_identifier(sch), quote_literal_cstr(sch));
    sql = q.data;

have_sql:
    if (SPI_connect() != SPI_OK_CONNECT)
        elog(ERROR, "ipguard: SPI_connect failed");
    if (SPI_execute(sql, true, 0) != SPI_OK_SELECT)
        elog(ERROR, "ipguard: label query failed");

    ctx->nlabels = SPI_processed;
    ctx->labels = MemoryContextAlloc(CurrentMemoryContext,
                                     sizeof(Label) * Max(ctx->nlabels, 1));

    for (uint64 i = 0; i < SPI_processed; i++)
    {
        bool isnull;
        HeapTuple  t = SPI_tuptable->vals[i];
        TupleDesc  d = SPI_tuptable->tupdesc;

        ctx->labels[i].relid =
            (Oid) DatumGetInt64(SPI_getbinval(t, d, 1, &isnull));
        ctx->labels[i].attno =
            DatumGetInt32(SPI_getbinval(t, d, 2, &isnull));
        /* SPI 메모리는 SPI_finish 에서 사라지므로 복사 */
        ctx->labels[i].kind =
            MemoryContextStrdup(TopTransactionContext, SPI_getvalue(t, d, 3));
    }
    SPI_finish();
}

static const char *
label_of(Ctx *ctx, Oid relid, int attno)
{
    for (int i = 0; i < ctx->nlabels; i++)
        if (ctx->labels[i].relid == relid && ctx->labels[i].attno == attno)
            return ctx->labels[i].kind;
    return NULL;
}

static void
add_kind(Ctx *ctx, const char *kind)
{
    ListCell *lc;

    if (kind == NULL)
        return;
    foreach(lc, *ctx->sink)
        if (strcmp((char *) lfirst(lc), kind) == 0)
            return;                        /* 중복 제거 */
    *ctx->sink = lappend(*ctx->sink, (void *) kind);
}

/* 컬럼 단위 근거를 기록한다. 경로는 현재 수집 대상 sink 로 판정한다 --
 * add_kind 와 같은 지점에서 불러야 둘이 어긋나지 않는다. */
static void
add_col(Ctx *ctx, Oid relid, int attno, const char *kind)
{
    ColHit     *h;
    ListCell   *lc;
    int         path;

    if (!ctx->collect || attno <= 0)
        return;
    if (kind == NULL && !ctx->collect_all)
        return;

    path = (ctx->sink == &ctx->pred_kinds) ? 1
         : (ctx->sink == &ctx->write_kinds) ? 2 : 0;

    foreach(lc, ctx->cols)
    {
        h = (ColHit *) lfirst(lc);
        if (h->relid == relid && h->attno == attno && h->path == path)
            return;                        /* 중복 제거 */
    }
    h = (ColHit *) palloc0(sizeof(ColHit));
    h->relid = relid;
    h->attno = attno;
    h->kind = kind;
    h->path = path;
    ctx->cols = lappend(ctx->cols, h);
}

/* ------------------------------------------------------------ Var 해석 */

/* 스택에서 levelsup 만큼 위의 Query */
static Query *
query_at(Ctx *ctx, int levelsup)
{
    int idx = ctx->sp - 1 - levelsup;

    return (idx >= 0 && idx < MAX_STACK) ? ctx->stack[idx] : NULL;
}


/* setOperations 트리의 팔(arm) 서브쿼리들을 모은다 */
static void
collect_setop_arms(Query *q, Node *n, List **arms)
{
    if (n == NULL)
        return;
    if (IsA(n, RangeTblRef))
    {
        RangeTblRef    *r = (RangeTblRef *) n;
        RangeTblEntry  *rte;

        if (r->rtindex < 1 || r->rtindex > list_length(q->rtable))
            return;
        rte = rt_fetch(r->rtindex, q->rtable);
        if (rte->rtekind == RTE_SUBQUERY && rte->subquery != NULL)
            *arms = lappend(*arms, rte->subquery);
    }
    else if (IsA(n, SetOperationStmt))
    {
        SetOperationStmt *so = (SetOperationStmt *) n;

        collect_setop_arms(q, so->larg, arms);
        collect_setop_arms(q, so->rarg, arms);
    }
}

/* ── 중첩 집합연산의 팔(arm) 처리 ────────────────────────────────────────
 *
 * ★ 3라운드 적대적 시험이 찾은 누출. 최상위 집합연산은 walk_setop/mask_setop
 *   이 따로 처리하지만, **서브쿼리/CTE 안에 있으면** 바깥 Var 가 맨 왼쪽 팔의
 *   TLE 만 가리키므로 나머지 팔을 아무도 보지 않는다:
 *
 *     SELECT * FROM (SELECT 'zzz' AS v UNION ALL SELECT ssn FROM cust) t
 *        -> zzz
 *           800102-1000001      ← 평문 주민번호. 탐지도 집행도 못 했다.
 *
 *   왼쪽 팔에 PII 가 있으면 우연히 맞게 동작해서 기존 코퍼스(V04/V07)는
 *   이걸 못 잡았다. PII 를 왼쪽이 아닌 팔에만 두면 그대로 샌다.
 *
 * 아래 두 함수는 setOperations 트리의 모든 팔에 대해 같은 컬럼 위치를
 * 방문한다. 팔 자체가 또 집합연산일 수 있으므로 재귀한다. */

/* 분석기용: 팔들의 attno 번째 출력 표현식을 순회한다. attno==0 이면 전부. */
static void
walk_setop_col(Ctx *ctx, Query *sub, AttrNumber attno)
{
    ListCell *lc;

    if (sub == NULL)
        return;
    if (ctx->sp >= MAX_STACK || ctx->depth > MAX_DEPTH)
    {
        ctx->bounded++;
        return;
    }

    if (sub->setOperations)
    {
        List *arms = NIL;

        collect_setop_arms(sub, sub->setOperations, &arms);
        ctx->depth++;
        foreach(lc, arms)
            walk_setop_col(ctx, (Query *) lfirst(lc), attno);
        ctx->depth--;
        return;
    }

    ctx->stack[ctx->sp++] = sub;
    ctx->depth++;
    if (attno == 0)
    {
        foreach(lc, sub->targetList)
        {
            TargetEntry *ste = (TargetEntry *) lfirst(lc);

            if (!ste->resjunk)
                walk_expr((Node *) ste->expr, ctx);
        }
    }
    else
    {
        TargetEntry *tle = get_tle_by_resno(sub->targetList, attno);

        if (tle == NULL)
            ctx->unresolved++;
        else
            walk_expr((Node *) tle->expr, ctx);
    }
    ctx->depth--;
    ctx->sp--;
}

static void
resolve_var(Ctx *ctx, Var *var)
{
    Query          *q = query_at(ctx, var->varlevelsup);
    RangeTblEntry  *rte;

    if (ctx->depth > MAX_DEPTH)
    {
        ctx->bounded++;             /* 우회 신호: 깊이 소진 */
        return;
    }
    if (q == NULL)
    {
        ctx->unresolved++;
        return;
    }
    if (var->varno == INNER_VAR || var->varno == OUTER_VAR ||
        var->varno == INDEX_VAR || var->varno < 1 ||
        var->varno > list_length(q->rtable))
    {
        ctx->unresolved++;
        return;
    }

    rte = rt_fetch(var->varno, q->rtable);

    switch (rte->rtekind)
    {
        case RTE_RELATION:
            if (var->varattno == 0)
            {
                /* 전체 행 참조(row_to_json(c), SELECT c ...) -> 전 컬럼 노출 */
                for (int i = 0; i < ctx->nlabels; i++)
                    if (ctx->labels[i].relid == rte->relid)
                    {
                        add_kind(ctx, ctx->labels[i].kind);
                        add_col(ctx, rte->relid, ctx->labels[i].attno,
                                ctx->labels[i].kind);
                    }
            }
            else if (var->varattno > 0)
            {
                const char *k = label_of(ctx, rte->relid, var->varattno);

                add_kind(ctx, k);
                add_col(ctx, rte->relid, var->varattno, k);
            }
            break;

        case RTE_SUBQUERY:
        {
            /* 서브쿼리의 varattno 번째 출력 표현식으로 내려간다.
             * 서브쿼리가 DML 이면 출력은 returningList 다. */
            List *sublist = (rte->subquery->commandType == CMD_SELECT)
                ? rte->subquery->targetList : rte->subquery->returningList;

            if (rte->subquery->setOperations)
            {
                /* 집합연산 서브쿼리: 맨 왼쪽 팔만 보면 나머지가 샌다 */
                walk_setop_col(ctx, rte->subquery, var->varattno);
                break;
            }
            if (ctx->sp >= MAX_STACK) { ctx->bounded++; break; }
            ctx->stack[ctx->sp++] = rte->subquery;
            ctx->depth++;
            if (var->varattno == 0)
            {
                /* 서브쿼리의 *전체 행* 참조: json_agg(t), row_to_json(t) ...
                 * varattno==0 을 RTE_RELATION 에서만 처리하면 여기서 샌다. */
                ListCell *sc;

                foreach(sc, sublist)
                {
                    TargetEntry *ste = (TargetEntry *) lfirst(sc);

                    if (!ste->resjunk)
                        walk_expr((Node *) ste->expr, ctx);
                }
            }
            else
            {
                TargetEntry *tle = get_tle_by_resno(sublist, var->varattno);

                if (tle == NULL)
                    ctx->unresolved++;
                else
                    walk_expr((Node *) tle->expr, ctx);
            }
            ctx->depth--;
            ctx->sp--;
            break;
        }

        case RTE_CTE:
        {
            /* CTE 는 ctelevelsup 만큼 위 Query 의 cteList 에 있다 */
            Query *owner = query_at(ctx, var->varlevelsup + rte->ctelevelsup);
            CommonTableExpr *cte = NULL;
            ListCell *lc;

            if (owner == NULL) { ctx->unresolved++; break; }
            foreach(lc, owner->cteList)
            {
                CommonTableExpr *c = (CommonTableExpr *) lfirst(lc);

                if (strcmp(c->ctename, rte->ctename) == 0) { cte = c; break; }
            }
            if (cte == NULL || !IsA(cte->ctequery, Query))
            { ctx->unresolved++; break; }

            {
                Query *cq = (Query *) cte->ctequery;
                /* data-modifying CTE: WITH d AS (DELETE ... RETURNING ssn)
                 * 여기서도 출력은 targetList 가 아니라 returningList 다. */
                List *outlist = (cq->commandType == CMD_SELECT)
                    ? cq->targetList : cq->returningList;

                /* CTE 본문이 집합연산이면 최상위 targetList 는 맨 왼쪽 팔만
                 * 가리킨다 -- RTE_SUBQUERY 와 같은 구멍이다. 3R X28 실측:
                 *   WITH u AS (SELECT 'a' UNION ALL SELECT ssn FROM cust)
                 *   SELECT * FROM u     -> 평문 주민번호 */
                if (cq->setOperations)
                {
                    walk_setop_col(ctx, cq, var->varattno);
                    break;
                }
                if (ctx->sp >= MAX_STACK) { ctx->bounded++; break; }
                ctx->stack[ctx->sp++] = cq;
                ctx->depth++;
                if (var->varattno == 0)
                {
                    ListCell *sc;

                    foreach(sc, outlist)
                    {
                        TargetEntry *ste = (TargetEntry *) lfirst(sc);

                        if (!ste->resjunk)
                            walk_expr((Node *) ste->expr, ctx);
                    }
                }
                else
                {
                    TargetEntry *tle = get_tle_by_resno(outlist, var->varattno);

                    if (tle == NULL)
                        ctx->unresolved++;
                    else
                        walk_expr((Node *) tle->expr, ctx);
                }
                ctx->depth--;
                ctx->sp--;
            }
            break;
        }

        case RTE_JOIN:
        {
            Node *alias = (var->varattno > 0 &&
                           var->varattno <= list_length(rte->joinaliasvars))
                ? (Node *) list_nth(rte->joinaliasvars, var->varattno - 1)
                : NULL;

            if (alias == NULL) { ctx->unresolved++; break; }
            ctx->depth++;
            walk_expr(alias, ctx);
            ctx->depth--;
            break;
        }

        default:
            /* RTE_FUNCTION(SETOF 반환 함수), RTE_VALUES, RTE_TABLEFUNC ...
             * 함수 본문은 호출부 계획에 없다. 계획만으로는 알 수 없음. */
            ctx->unresolved++;
            break;
    }
}

/* -------------------------------------------------------- 표현식/쿼리 */

static bool
walk_expr(Node *node, Ctx *ctx)
{
    if (node == NULL)
        return false;

    check_stack_depth();

    if (IsA(node, Var))
    {
        resolve_var(ctx, (Var *) node);
        return false;
    }
    if (IsA(node, Query))
    {
        Query *sub = (Query *) node;

        if (ctx->sp >= MAX_STACK || ctx->depth > MAX_DEPTH)
        { ctx->bounded++; return false; }
        ctx->stack[ctx->sp++] = sub;
        ctx->depth++;
        /* ★ 서브쿼리의 출력은 호출자의 수집 대상으로 간다.
         * 여기서 out_kinds 로 하드코딩하면 UPDATE ... SET x = (SELECT ssn ...)
         * 처럼 쓰기 경로 안의 SELECT 가 "클라이언트로 나간다"로 잘못 보고된다. */
        walk_query(ctx, sub, ctx->sink);
        ctx->depth--;
        ctx->sp--;
        return false;
    }
    return expression_tree_walker(node, walk_expr, (void *) ctx);
}

/* setOperations 트리의 모든 arm 을 훑는다 (UNION/EXCEPT/INTERSECT).
 * 상위 targetList 는 좌측 arm 만 가리키므로 이걸 따로 해야 우측을 놓치지 않는다. */
static void
walk_setop(Ctx *ctx, Query *q, Node *n)
{
    if (n == NULL)
        return;
    if (IsA(n, RangeTblRef))
    {
        RangeTblRef    *ref = (RangeTblRef *) n;
        RangeTblEntry  *rte;
        ListCell       *lc;

        if (ref->rtindex < 1 || ref->rtindex > list_length(q->rtable))
            return;
        rte = rt_fetch(ref->rtindex, q->rtable);
        if (rte->rtekind != RTE_SUBQUERY || ctx->sp >= MAX_STACK)
            return;

        ctx->stack[ctx->sp++] = rte->subquery;
        ctx->depth++;
        foreach(lc, rte->subquery->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk)
                walk_expr((Node *) tle->expr, ctx);
        }
        ctx->depth--;
        ctx->sp--;
    }
    else if (IsA(n, SetOperationStmt))
    {
        SetOperationStmt *s = (SetOperationStmt *) n;

        walk_setop(ctx, q, s->larg);
        walk_setop(ctx, q, s->rarg);
    }
}

static void
walk_query(Ctx *ctx, Query *q, List **out_sink)
{
    ListCell   *lc;
    List      **saved = ctx->sink;

    if (out_sink == NULL)
        out_sink = &ctx->out_kinds;

    /* --- 출력: 클라이언트에 값이 도달하는 것 ---
     *
     * ★ DML 에서 targetList 는 "테이블에 써넣는 값"이고, 클라이언트로
     *   나가는 것은 returningList 다. 이 둘을 혼동하면 UPDATE ...
     *   RETURNING ssn 이 통째로 미탐된다(적대적 시험 R01~R06 에서 확인). */
    if (q->commandType == CMD_SELECT)
    {
        ctx->sink = out_sink;
        foreach(lc, q->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk || ctx->scan_all)
                walk_expr((Node *) tle->expr, ctx);
        }
    }
    else
    {
        /* 쓰기: PII 가 non-PII 컬럼으로 이동하는 것도 통제 대상이므로 따로 센다 */
        ctx->sink = &ctx->write_kinds;
        foreach(lc, q->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk || ctx->scan_all)
                walk_expr((Node *) tle->expr, ctx);
        }
    }
    /* MERGE 의 SET/INSERT 값은 targetList 가 아니라 mergeActionList 안에 있다.
     * 빠뜨리면 MERGE ... WHEN MATCHED THEN UPDATE SET note = c.ssn 이
     * 통째로 미탐된다(적대적 2라운드 X02 에서 확인). */
    if (q->mergeActionList)
    {
        ListCell *ma;

        ctx->sink = &ctx->write_kinds;
        foreach(ma, q->mergeActionList)
        {
            MergeAction *act = (MergeAction *) lfirst(ma);
            ListCell    *tc;

            foreach(tc, act->targetList)
            {
                TargetEntry *tle = (TargetEntry *) lfirst(tc);

                if (!tle->resjunk)
                    walk_expr((Node *) tle->expr, ctx);
            }
        }
        ctx->sink = &ctx->pred_kinds;
        foreach(ma, q->mergeActionList)
            walk_expr((Node *) ((MergeAction *) lfirst(ma))->qual, ctx);
    }

    ctx->sink = out_sink;
    foreach(lc, q->returningList)
        walk_expr((Node *) ((TargetEntry *) lfirst(lc))->expr, ctx);
    if (q->setOperations)
        walk_setop(ctx, q, q->setOperations);

    /* CTE 본문도 출력 경로로 간주 (WITH x AS (...) SELECT * FROM x) 는
     * 이미 Var 해석으로 잡히지만, 참조되지 않는 CTE 는 결과에 안 나오므로
     * 여기서 따로 훑지 않는다. */

    /* --- 술어: 값은 안 나가지만 참조되는 것 (부채널 정책 대상) --- */
    ctx->sink = &ctx->pred_kinds;
    if (q->jointree)
        walk_expr((Node *) q->jointree->quals, ctx);
    walk_expr((Node *) q->havingQual, ctx);
    foreach(lc, q->sortClause)
    {
        SortGroupClause *sg = (SortGroupClause *) lfirst(lc);
        TargetEntry     *tle = get_sortgroupclause_tle(sg, q->targetList);

        if (tle && tle->resjunk)
            walk_expr((Node *) tle->expr, ctx);
    }

    ctx->sink = saved;
}

/* -------------------------------------------------------------- SQL API */

static char *
join_kinds(List *l)
{
    StringInfoData  buf;
    ListCell       *lc;
    bool            first = true;

    initStringInfo(&buf);
    foreach(lc, l)
    {
        if (!first)
            appendStringInfoChar(&buf, ',');
        appendStringInfoString(&buf, (char *) lfirst(lc));
        first = false;
    }
    return buf.data;
}

/* SQL 문자열 하나를 파스 + 재작성한 뒤 분석기를 돌린다.
 *
 * ipguard_analyze() / ipguard_explain() / ipguard_verdict() 가 **같은** 코드를
 * 쓰도록 분리했다. 설명 함수가 별도 경로로 재구현되면 사람에게 보여주는 판정과
 * 실제 집행이 조용히 어긋난다 -- 이 프로젝트에서 측정 도구 편향으로 네 번
 * 당한 실패 양식이므로 구조적으로 막는다.
 *
 * walked  : utility 가 아닌 Query 들(집행 재현용). NULL 이면 수집하지 않는다.
 * err_out : 파스/재작성 실패 메시지. 성공 시 NULL.
 */
static void
analyze_sql(const char *sql, Ctx *ctx, List **walked, char **err_out)
{
    List           *raw;
    ListCell       *lc;
    volatile bool   failed = false;
    char           *errmsg_copy = NULL;

    *err_out = NULL;
    if (walked)
        *walked = NIL;

    PG_TRY();
    {
        raw = pg_parse_query(sql);
        foreach(lc, raw)
        {
            RawStmt *rs = lfirst_node(RawStmt, lc);
            Oid     *ptypes = NULL;
            int      nptypes = 0;
            List    *queries;
            ListCell *lc2;

            /* varparams: $1 의 타입을 서버가 추론하게 한다 */
            queries = pg_analyze_and_rewrite_varparams(rs, sql, &ptypes,
                                                       &nptypes, NULL);
            foreach(lc2, queries)
            {
                Query *q = lfirst_node(Query, lc2);

                if (q->commandType == CMD_UTILITY)
                {
                    ctx->utility_n++;
                    /* COPY 등: 재작성 후에도 utility 문장은 Query 트리가 없다.
                     * COPY (SELECT ...) TO STDOUT 은 utilityStmt 안에 Query 가 있다. */
                    if (q->utilityStmt && IsA(q->utilityStmt, CreateTableAsStmt))
                    {
                        /* CTAS / SELECT INTO / CREATE MATERIALIZED VIEW.
                         * PII 를 라벨 없는 새 릴레이션으로 복사하는 행위 자체를
                         * write 축으로 잡아야 한다 -- 일단 복사되고 나면 사본에
                         * 라벨이 없어 이후 조회는 원리적으로 탐지 불가다. */
                        CreateTableAsStmt *cts = (CreateTableAsStmt *) q->utilityStmt;

                        if (cts->query && IsA(cts->query, Query))
                        {
                            Query *cq = (Query *) cts->query;

                            ctx->sp = 0;
                            ctx->depth = 0;
                            ctx->stack[ctx->sp++] = cq;
                            walk_query(ctx, cq, &ctx->write_kinds);
                        }
                        continue;
                    }
                    if (q->utilityStmt && IsA(q->utilityStmt, CopyStmt))
                    {
                        CopyStmt *cs = (CopyStmt *) q->utilityStmt;

                        if (cs->query)
                        {
                            /* CopyStmt->query 는 *원시 파스 트리*다. COPY 의 내부
                             * 쿼리는 실행 시점(DoCopy)에야 분석되므로 여기서는
                             * 아직 Query 가 아니다. 직접 분석해서 걸어야 한다.
                             * -- 이걸 빼먹으면 COPY (SELECT ssn ...) 이 조용히
                             *    미탐된다(C02/C04). */
                            RawStmt  *rw = makeNode(RawStmt);
                            Oid      *qt = NULL;
                            int       nqt = 0;
                            List     *ql;
                            ListCell *lc3;

                            rw->stmt = cs->query;
                            rw->stmt_location = 0;
                            rw->stmt_len = 0;
                            ql = pg_analyze_and_rewrite_varparams(rw, sql, &qt,
                                                                  &nqt, NULL);
                            foreach(lc3, ql)
                            {
                                Query *cq = lfirst_node(Query, lc3);

                                ctx->sp = 0;
                                ctx->depth = 0;
                                ctx->stack[ctx->sp++] = cq;
                                walk_query(ctx, cq, NULL);
                            }
                        }
                        else if (cs->relation)
                        {
                            /* COPY tbl [(cols)] TO STDOUT -- 계획 트리가 없으므로
                             * 릴레이션과 컬럼 목록에서 직접 판정한다. */
                            Oid relid = RangeVarGetRelid(cs->relation,
                                                         AccessShareLock, true);

                            ctx->sink = &ctx->out_kinds;
                            if (OidIsValid(relid))
                            {
                                if (cs->attlist == NIL)
                                {
                                    for (int i = 0; i < ctx->nlabels; i++)
                                        if (ctx->labels[i].relid == relid)
                                        {
                                            add_kind(ctx, ctx->labels[i].kind);
                                            add_col(ctx, relid,
                                                    ctx->labels[i].attno,
                                                    ctx->labels[i].kind);
                                        }
                                }
                                else
                                {
                                    ListCell *a;

                                    foreach(a, cs->attlist)
                                    {
                                        const char *nm = strVal(lfirst(a));
                                        AttrNumber  an =
                                            get_attnum(relid, nm);

                                        if (an > 0)
                                        {
                                            const char *k =
                                                label_of(ctx, relid, an);

                                            add_kind(ctx, k);
                                            add_col(ctx, relid, an, k);
                                        }
                                    }
                                }
                            }
                            else
                                ctx->unresolved++;
                        }
                    }
                    continue;
                }

                ctx->sp = 0;
                ctx->depth = 0;
                ctx->stack[ctx->sp++] = q;
                walk_query(ctx, q, NULL);
                if (walked)
                    *walked = lappend(*walked, q);
            }
        }
    }
    PG_CATCH();
    {
        ErrorData *ed;

        MemoryContextSwitchTo(TopTransactionContext);
        ed = CopyErrorData();
        errmsg_copy = pstrdup(ed->message);
        FlushErrorState();
        FreeErrorData(ed);
        failed = true;
    }
    PG_END_TRY();

    if (failed)
        *err_out = errmsg_copy ? errmsg_copy : "unknown";
}

PG_FUNCTION_INFO_V1(ipguard_analyze);

Datum
ipguard_analyze(PG_FUNCTION_ARGS)
{
    char           *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    Ctx             ctx;
    StringInfoData  res;
    char           *err = NULL;

    memset(&ctx, 0, sizeof(ctx));
    load_labels(&ctx);
    analyze_sql(sql, &ctx, NULL, &err);

    initStringInfo(&res);
    if (err)
        appendStringInfo(&res, "err=%s", err);
    else
        appendStringInfo(&res, "out=%s;pred=%s;write=%s;unresolved=%d;bounded=%d",
                         join_kinds(ctx.out_kinds),
                         join_kinds(ctx.pred_kinds),
                         join_kinds(ctx.write_kinds),
                         ctx.unresolved,
                         ctx.bounded);

    PG_RETURN_TEXT_P(cstring_to_text(res.data));
}

/* ==========================================================================
 * 집행 (v1) -- 소스 컬럼 마스킹
 *
 * 출력 바이트를 고쳐 쓰지 않는다. 계획 *전에* Query 트리의 PII Var 를
 * ipguard_mask(var, kind) 호출로 치환한다. 그러면 그 Var 를 쓰는 모든
 * 표현식이 자동으로 마스킹된 값 위에서 계산된다:
 *
 *     substr(ssn,1,6)      ->  substr(mask(ssn),1,6)
 *     concat(name,'/',ssn) ->  concat(mask(name),'/',mask(ssn))
 *     length(ssn)          ->  length(mask(ssn))     <- E17 이 자연히 해결된다
 *
 * 즉 표현식 우회가 구조적으로 무력해진다. 출력 바이트 마스킹으로는
 * 불가능한 성질이며, 이것이 AST 탐지가 열어준 집행 지점이다.
 *
 * 술어(qual)는 건드리지 않는다. WHERE ci=$1 이 계속 필터링해야 하기 때문.
 * 그 대가로 부채널(WHERE ssn LIKE '8001%')은 여전히 열려 있다 -- 마스킹으로
 * 막을 수 없는 별개 클래스이며 쿼리 형태 정책의 몫이다.
 * ========================================================================== */

static planner_hook_type prev_planner_hook = NULL;
static bool ipguard_enforce = false;
static Oid  mask_fn_oid = InvalidOid;

/* ★ 재진입 가드.
 * planner_hook 안에서 load_labels() 가 SPI 로 라벨 쿼리를 돌리는데, 그 쿼리도
 * planner_hook 을 탄다 -> load_labels -> SPI -> planner_hook -> ... 무한 재귀로
 * "stack depth limit exceeded" 가 난다. 훅을 다는 확장의 고전적 실수이고
 * 실행해봐야만 드러난다(정적 분석이나 컴파일로는 안 잡힌다). */
/* ★ boolean 이 아니라 **깊이 카운터**여야 한다.
 *
 * 두 가지 이유:
 *  (1) 중첩. 안쪽에서 false 로 되돌리면 바깥 가드가 풀려 재귀가 열린다.
 *  (2) 예외. SPI 가 오류를 내며 longjmp 하면 플래그가 복원되지 않고,
 *      그 백엔드의 **이후 모든 질의가 게이트를 우회**한다 -- fail-open 이다.
 *      PG_FINALLY 로 감싸도 boolean 은 (1) 때문에 여전히 위험하다.
 *
 * 진입/이탈을 매크로로 고정해 손으로 짝을 맞추지 않게 한다. */
static int ipguard_busy_depth = 0;

#define IPGUARD_BUSY_ENTER()  (ipguard_busy_depth++)
#define IPGUARD_BUSY_LEAVE()  \
    do { \
        Assert(ipguard_busy_depth > 0); \
        if (ipguard_busy_depth > 0) \
            ipguard_busy_depth--; \
    } while (0)
#define IPGUARD_BUSY  (ipguard_busy_depth > 0)

/* ★ 계획 캐시 무효화를 **관측 가능**하게 만드는 카운터.
 *
 * 라벨/레지스트리 변경이 generic plan 까지 전파되는지는 결과만 봐서는 알 수
 * 없다 -- 그래서 Y07 이 오래 숨어 있었다. PII 가 걸린 질의를 실제로 계획한
 * 횟수를 세면 "EXECUTE 가 재계획을 유발했는가" 를 직접 잰다.
 *
 * 라벨된 컬럼이 걸린 계획만 센다. 그래야 측정 질의(SELECT ipguard_...())가
 * 카운터를 흔들지 않는다 -- 측정 도구가 측정값을 바꾸는 것을 구조적으로 막는다. */
static int64 ipguard_pii_plans = 0;

/* 정합성 충돌 시 동작. error 가 기본 -- 보안 컨트롤이 결과를 조용히 바꾸면
 * 안 된다. warn/allow 는 실제 워크로드에서 이 패턴의 빈도를 재기 위한 것이며
 * 운영에서 쓰라고 만든 것이 아니다. */
static int ipguard_on_conflict = 0;      /* 0=error 1=warn 2=allow */
static const struct config_enum_entry conflict_options[] = {
    {"error", 0, false}, {"warn", 1, false}, {"allow", 2, false}, {NULL, 0, false}
};

/* 의미 발산(divergence) 시 동작. **기본은 allow** -- on_conflict 와 달리 이건
 * 켜면 정상 분석 쿼리를 막는다(GROUP BY 된 PII 컬럼은 흔하다). 과거부 비용을
 * 먼저 재고 켤지 정하라고 만든 스위치다. results/divergence.md 참조. */
static int ipguard_on_divergence = 2;    /* 0=error 1=warn 2=allow */

/* 숫자형 PII 의 마스크 센티널. **기본은 nullify** -- 실측으로 정했다.
 *
 * 숫자에는 "명백히 마스크인 값"이 없다. 0 은 유효한 급여·잔액이라 결과만
 * 봐서는 마스킹 사실을 알 수 없고, 그 상태는 판정식으로도 못 메운다:
 *
 *   SELECT id, salary FROM payroll     <- 집계도 그룹핑도 없다. R1~R3 어느
 *                                         규칙에도 안 걸리는데 0 이 나간다.
 *
 * NULL 은 "값 없음"을 명시해 이 가장 흔한 쿼리 모양을 덮는다. 실측(45건):
 *
 *              구별 불가(판정식 ON)   거부   TPC-H 과거부
 *      zero            3              30      5/22
 *      nullify         1              28      5/22
 *
 * 대가 둘: count(col) 이 1000 -> 0 이 되고(판정식이 잡는다), NOT NULL 을
 * 기대하는 클라이언트가 깨진다(여기서 측정할 수 없는 축이다).
 * zero 로 되돌리려면 ipguard.numeric_mask = zero. */
static int ipguard_numeric_mask = 1;     /* 0=zero 1=nullify */
/* 값을 'null' 이라 부르지 않는다 -- SET x = null 은 SQL 예약어라 문자열이
 * 아니라 NULL 로 해석돼 조용히 기본값이 된다. 운영자가 그대로 밟는다. */
static const struct config_enum_entry numeric_mask_options[] = {
    {"zero", 0, false}, {"nullify", 1, false}, {NULL, 0, false}
};

PG_FUNCTION_INFO_V1(ipguard_mask);

/* 타입별 동일 의미 센티널. 별표를 아무 데나 넣으면 클라이언트 파서가 터진다
 * (binary int4 를 '****' 로 덮으면 707406378 이라는 그럴듯한 틀린 숫자가 된다).
 * 여기서는 엔진 안이므로 타입 유효값을 돌려주면 된다. */
/* ★ 예약 namespace `ctl:` -- **보호 마스크가 아닌** 대조 변환.
 *
 * 인증서 profile 에는 EQ/ORD factor-through 가 `holds` 인 항목이 있어야
 * 게이트의 factor-through 경로가 한 번이라도 실행된다. 그런데 실제 보호
 * 마스크(별표·상수·nullify)는 전부 서로 다른 값을 합치므로 EQ/ORD 가
 * 구조적으로 `fails` 다. 그래서 구조를 **의도적으로 공개하는** 변환을
 * 따로 둔다.
 *
 *   ctl:rot13    전역 bijection      EQ holds / ORD fails
 *   ctl:prefix   C collation 순서보존 EQ holds / ORD holds
 *
 * 둘 다 원문을 복원 가능하거나 순서를 그대로 드러내므로 **운영에 쓰면 안**
 * **된다.** 인증된 factorization 경로를 시험하기 위한 control transform 이다.
 * 실용적인 order-revealing encryption 은 별개 연구 범위다. */
static bool
ctl_kind_is(FunctionCallInfo fcinfo, const char *want)
{
    text *k;
    bool  hit;

    if (PG_NARGS() < 2 || PG_ARGISNULL(1))
        return false;
    k = PG_GETARG_TEXT_PP(1);
    hit = (VARSIZE_ANY_EXHDR(k) == (int) strlen(want) &&
           memcmp(VARDATA_ANY(k), want, strlen(want)) == 0);
    return hit;
}

Datum
ipguard_mask(PG_FUNCTION_ARGS)
{
    Oid typ;

    if (PG_ARGISNULL(0))
        PG_RETURN_NULL();

    typ = get_fn_expr_argtype(fcinfo->flinfo, 0);

    /* ---- control transform 은 **kind 로** 고른다 ---------------------
     *
     * 이전에는 kind 인자를 아예 읽지 않고 타입으로만 분기했다. 그러면
     * 레지스트리가 `kind` 로 MaskInstance 를 구별하는데 집행은 그 구별을
     * 무시한다 -- 레지스트리에 등록한 속성이 실제로 적용되는 변환의
     * 속성이라는 보장이 없어진다. profile 동결의 전제가 무너지는 지점이다. */
    if ((typ == TEXTOID || typ == VARCHAROID || typ == BPCHAROID) &&
        ctl_kind_is(fcinfo, "ctl:rot13"))
    {
        text  *in = PG_GETARG_TEXT_PP(0);
        int    n = VARSIZE_ANY_EXHDR(in);
        text  *out = (text *) palloc(VARHDRSZ + n);
        char  *src = VARDATA_ANY(in), *dst = VARDATA(out);
        int    i;

        SET_VARSIZE(out, VARHDRSZ + n);
        /* ASCII 문자만 회전한다. UTF-8 에서 연속 바이트는 항상 0x80 이상이라
         * ASCII 바이트와 겹치지 않으므로 바이트 단위로 안전하고, 결과도
         * 유효한 UTF-8 이다. 회전은 involution 이므로 전역 bijection 이다. */
        for (i = 0; i < n; i++)
        {
            unsigned char c = (unsigned char) src[i];

            if (c >= 'a' && c <= 'z')
                dst[i] = (char) ('a' + (c - 'a' + 13) % 26);
            else if (c >= 'A' && c <= 'Z')
                dst[i] = (char) ('A' + (c - 'A' + 13) % 26);
            else
                dst[i] = (char) c;
        }
        PG_RETURN_TEXT_P(out);
    }
    if ((typ == TEXTOID || typ == VARCHAROID || typ == BPCHAROID) &&
        ctl_kind_is(fcinfo, "ctl:prefix"))
    {
        text  *in = PG_GETARG_TEXT_PP(0);
        int    n = VARSIZE_ANY_EXHDR(in);
        text  *out = (text *) palloc(VARHDRSZ + 2 + n);

        SET_VARSIZE(out, VARHDRSZ + 2 + n);
        memcpy(VARDATA(out), "P:", 2);
        memcpy(VARDATA(out) + 2, VARDATA_ANY(in), n);
        PG_RETURN_TEXT_P(out);
    }

    switch (typ)
    {
        case TEXTOID:
        case VARCHAROID:
        case BPCHAROID:
        case NAMEOID:
        {
            /* 문자 수를 보존한다(바이트 수가 아니라). 한글이든 ASCII 든
             * 컬럼 길이 제약을 깨지 않는다. */
            text   *in = PG_GETARG_TEXT_PP(0);
            int     nbytes = VARSIZE_ANY_EXHDR(in);
            int     nchars = pg_mbstrlen_with_len(VARDATA_ANY(in), nbytes);
            text   *out = (text *) palloc(VARHDRSZ + nchars);

            SET_VARSIZE(out, VARHDRSZ + nchars);
            memset(VARDATA(out), '*', nchars);
            PG_RETURN_TEXT_P(out);
        }
        case INT2OID: case INT4OID: case INT8OID:
        case FLOAT4OID: case FLOAT8OID: case NUMERICOID:
            /* 숫자에는 "명백히 마스크인 값"이 없다. 어떤 수를 골라도 도메인
             * 안의 그럴듯한 값이다. 그래서 선택은 0 이냐 NULL 이냐뿐이고,
             * 둘 다 대가가 있다 -- 실측해서 정한다. */
            if (ipguard_numeric_mask == 1)
                PG_RETURN_NULL();
            switch (typ)
            {
                case INT2OID:   PG_RETURN_INT16(0);
                case INT4OID:   PG_RETURN_INT32(0);
                case INT8OID:   PG_RETURN_INT64(0);
                case FLOAT4OID: PG_RETURN_FLOAT4(0);
                case FLOAT8OID: PG_RETURN_FLOAT8(0);
                default:
                    PG_RETURN_DATUM(DirectFunctionCall3(numeric_in,
                        CStringGetDatum("0"), ObjectIdGetDatum(InvalidOid),
                        Int32GetDatum(-1)));
            }
        case DATEOID:
            PG_RETURN_DATUM(DirectFunctionCall1(date_in,
                CStringGetDatum("1900-01-01")));
        case TIMESTAMPOID:
            PG_RETURN_DATUM(DirectFunctionCall3(timestamp_in,
                CStringGetDatum("1900-01-01 00:00:00"),
                ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1)));
        case TIMESTAMPTZOID:
            PG_RETURN_DATUM(DirectFunctionCall3(timestamptz_in,
                CStringGetDatum("1900-01-01 00:00:00+00"),
                ObjectIdGetDatum(InvalidOid), Int32GetDatum(-1)));
        case UUIDOID:
            PG_RETURN_DATUM(DirectFunctionCall1(uuid_in,
                CStringGetDatum("00000000-0000-0000-0000-000000000000")));
        default:
            /* 모르는 타입은 NULL. 추측해서 값을 만들면 누출 위험이 있다. */
            PG_RETURN_NULL();
    }
}

/* ---------------------------------------------------- Var -> mask() 치환 */

typedef struct MutCtx
{
    Ctx    *ctx;        /* 라벨 조회용 */
    Query  *q;          /* 현재 Query 레벨 */
    int     masked;
} MutCtx;

/* Var 하나를 ipguard_mask(var, kind) 호출로 감싼다. */
static FuncExpr *
mask_call(Var *var, const char *kind)
{
    FuncExpr *fe = makeNode(FuncExpr);

    fe->funcid = mask_fn_oid;
    fe->funcresulttype = var->vartype;      /* anyelement 해소 */
    fe->funcretset = false;
    fe->funcvariadic = false;
    fe->funcformat = COERCE_EXPLICIT_CALL;
    fe->funccollid = var->varcollid;
    fe->inputcollid = var->varcollid;
    fe->args = list_make2(var,
        makeConst(TEXTOID, -1, InvalidOid, -1,
                  CStringGetTextDatum(kind), false, false));
    fe->location = -1;
    return fe;
}

static Node *mask_mutator(Node *node, MutCtx *m);
static void mask_setop(Ctx *ctx, Query *q, Node *n, MutCtx *m);

/* 서브쿼리/CTE 의 출력 표현식 하나를 마스킹한다. 이미 마스킹돼 있으면 건너뛴다
 * (같은 TLE 가 출력에서 두 번 참조될 수 있다). */
static void
mask_tle(MutCtx *m, TargetEntry *tle)
{
    if (tle == NULL || has_mask_call((Node *) tle->expr, NULL))
        return;
    tle->expr = (Expr *) mask_mutator((Node *) tle->expr, m);
}

/* ★ 출력 경로를 따라서만 마스킹한다.
 *
 * 이전 버전은 "모든 Query 레벨의 targetList 에 있는 모든 PII Var" 를 마스킹했다.
 * 그러면 뷰/서브쿼리의 컬럼 중 **출력되지 않고 술어에만 쓰이는 것**까지 마스킹돼
 * 충돌 감지기가 정상 쿼리를 거부한다. 실측 사례:
 *
 *     SELECT ssn FROM v_cust WHERE ci = $1
 *       -> 분석기는 out=ssn, pred=ci 로 정확히 구분하는데
 *          변이기가 뷰의 ci 까지 마스킹 -> 술어 참조 -> 거부
 *
 * 이제 Var 해석과 같은 방식으로 **출력에서 참조된 TLE 만** 따라 내려간다.
 * 술어에만 쓰이는 컬럼은 애초에 도달하지 않으므로 마스킹되지 않는다.
 * 같은 TLE 가 출력과 술어 양쪽에 쓰이면 여전히 마스킹되고 -- 그건 진짜
 * 충돌이므로 거부되는 것이 맞다. */
static Node *
mask_mutator(Node *node, MutCtx *m)
{
    if (node == NULL)
        return NULL;

    if (IsA(node, Var))
    {
        Var            *var = (Var *) node;
        Query          *vq = query_at(m->ctx, var->varlevelsup);
        RangeTblEntry  *rte;

        if (vq == NULL || var->varno < 1 || var->varno > list_length(vq->rtable))
            return node;
        rte = rt_fetch(var->varno, vq->rtable);

        switch (rte->rtekind)
        {
            case RTE_RELATION:
            {
                const char *kind;

                if (var->varattno == 0)
                {
                    /* 전체 행 Var: RowExpr 로 펼쳐 컬럼별 마스킹 */
                    List       *names = NIL, *vars = NIL, *args = NIL;
                    ListCell   *vc;
                    RowExpr    *re;

                    expandRTE(rte, var->varno, var->varlevelsup, var->location,
                              false, &names, &vars);
                    foreach(vc, vars)
                    {
                        Var        *cv = (Var *) lfirst(vc);
                        const char *k;

                        if (cv == NULL || !IsA(cv, Var))
                        { args = lappend(args, cv); continue; }
                        k = label_of(m->ctx, rte->relid, cv->varattno);
                        if (k == NULL)
                        { args = lappend(args, cv); continue; }
                        args = lappend(args, mask_call(cv, k));
                        m->masked++;
                    }
                    re = makeNode(RowExpr);
                    re->args = args;
                    re->row_typeid = var->vartype;
                    re->row_format = COERCE_IMPLICIT_CAST;
                    re->colnames = names;
                    re->location = var->location;
                    return (Node *) re;
                }
                if (var->varattno < 0)
                    return node;                    /* 시스템 컬럼 */
                kind = label_of(m->ctx, rte->relid, var->varattno);
                if (kind == NULL)
                    return node;
                m->masked++;
                return (Node *) mask_call(var, kind);
            }

            case RTE_SUBQUERY:
            {
                /* 서브쿼리(뷰 전개 포함)의 해당 출력 표현식으로 내려간다. */
                Query  *sub = rte->subquery;
                List   *tl = (sub->commandType == CMD_SELECT)
                             ? sub->targetList : sub->returningList;
                Query  *saved_q = m->q;

                if (m->ctx->sp >= MAX_STACK)
                { m->ctx->bounded++; return node; }
                m->ctx->stack[m->ctx->sp++] = sub;
                m->q = sub;
                if (var->varattno == 0)
                {
                    ListCell *lc;

                    foreach(lc, tl)
                    {
                        TargetEntry *tle = (TargetEntry *) lfirst(lc);

                        if (!tle->resjunk)
                            mask_tle(m, tle);
                    }
                }
                else
                    mask_tle(m, get_tle_by_resno(tl, var->varattno));
                if (sub->setOperations)
                    mask_setop(m->ctx, sub, sub->setOperations, m);
                m->q = saved_q;
                m->ctx->sp--;
                return node;                        /* Var 자체는 그대로 */
            }

            case RTE_CTE:
            {
                Query           *owner = query_at(m->ctx,
                                    var->varlevelsup + rte->ctelevelsup);
                CommonTableExpr *cte = NULL;
                ListCell        *lc;

                if (owner == NULL)
                    return node;
                foreach(lc, owner->cteList)
                {
                    CommonTableExpr *c = (CommonTableExpr *) lfirst(lc);

                    if (strcmp(c->ctename, rte->ctename) == 0 &&
                        IsA(c->ctequery, Query))
                    { cte = c; break; }
                }
                if (cte == NULL)
                    return node;
                {
                    Query  *cq = (Query *) cte->ctequery;
                    List   *tl = (cq->commandType == CMD_SELECT)
                                 ? cq->targetList : cq->returningList;
                    Query  *saved_q = m->q;

                    if (m->ctx->sp >= MAX_STACK)
                    { m->ctx->bounded++; return node; }
                    m->ctx->stack[m->ctx->sp++] = cq;
                    m->q = cq;
                    if (var->varattno == 0)
                    {
                        ListCell *l2;

                        foreach(l2, tl)
                        {
                            TargetEntry *tle = (TargetEntry *) lfirst(l2);

                            if (!tle->resjunk)
                                mask_tle(m, tle);
                        }
                    }
                    else
                        mask_tle(m, get_tle_by_resno(tl, var->varattno));
                    if (cq->setOperations)
                        mask_setop(m->ctx, cq, cq->setOperations, m);
                    m->q = saved_q;
                    m->ctx->sp--;
                }
                return node;
            }

            case RTE_JOIN:
            {
                Node *alias = (var->varattno > 0 &&
                               var->varattno <= list_length(rte->joinaliasvars))
                    ? (Node *) list_nth(rte->joinaliasvars, var->varattno - 1)
                    : NULL;

                if (alias == NULL || !IsA(alias, Var))
                    return node;
                return mask_mutator(alias, m);
            }

            default:
                return node;
        }
    }
    if (IsA(node, Query))
    {
        /* 출력 표현식 안의 스칼라 서브쿼리(SubLink->subselect).
         * expression_tree_mutator 가 여기로 데려온다. 그냥 반환하면
         *   SELECT (SELECT c2.ssn FROM cust c2 WHERE c2.id = c1.id) FROM cust c1
         * 이 통째로 미탐된다(L01 에서 실측). 우리는 출력 경로만 훑으므로
         * 여기 도달했다는 것 자체가 출력 경로라는 뜻이다. */
        Query      *sub = (Query *) node;
        Query      *saved_q = m->q;
        ListCell   *lc;

        if (m->ctx->sp >= MAX_STACK)
        { m->ctx->bounded++; return node; }
        m->ctx->stack[m->ctx->sp++] = sub;
        m->q = sub;
        foreach(lc, sub->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk)
                mask_tle(m, tle);
        }
        if (sub->setOperations)
            mask_setop(m->ctx, sub, sub->setOperations, m);
        m->q = saved_q;
        m->ctx->sp--;
        return node;
    }
    /* FILTER (WHERE …) 는 **술어**다. 설계 원칙상 술어는 건드리지 않는다 --
     * 건드리면 필터가 마스크값과 비교되어 조용히 틀린다. 우리가 마스킹 뷰를
     * 비판한 바로 그 실패를 우리가 하게 된다. 3R X21 실측:
     *   count(*) FILTER (WHERE salary IS NOT NULL)   1000 -> 0 */
    if (IsA(node, Aggref))
    {
        Aggref *a = (Aggref *) node;
        Expr   *filt = a->aggfilter;
        Node   *out;

        a->aggfilter = NULL;
        out = expression_tree_mutator(node, mask_mutator, (void *) m);
        a->aggfilter = filt;
        ((Aggref *) out)->aggfilter = filt;
        return out;
    }
    if (IsA(node, WindowFunc))
    {
        WindowFunc *w = (WindowFunc *) node;
        Expr       *filt = w->aggfilter;
        Node       *out;

        w->aggfilter = NULL;
        out = expression_tree_mutator(node, mask_mutator, (void *) m);
        w->aggfilter = filt;
        ((WindowFunc *) out)->aggfilter = filt;
        return out;
    }
    return expression_tree_mutator(node, mask_mutator, (void *) m);
}

/* setOperations 의 각 arm 도 출력이다. 상위 targetList 는 좌측 arm 만 가리킨다. */
static void
mask_setop(Ctx *ctx, Query *q, Node *n, MutCtx *m)
{
    if (n == NULL)
        return;
    if (IsA(n, RangeTblRef))
    {
        RangeTblRef    *ref = (RangeTblRef *) n;
        RangeTblEntry  *rte;
        ListCell       *lc;
        Query          *saved_q = m->q;

        if (ref->rtindex < 1 || ref->rtindex > list_length(q->rtable))
            return;
        rte = rt_fetch(ref->rtindex, q->rtable);
        if (rte->rtekind != RTE_SUBQUERY || ctx->sp >= MAX_STACK)
            return;
        ctx->stack[ctx->sp++] = rte->subquery;
        m->q = rte->subquery;
        foreach(lc, rte->subquery->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk)
                mask_tle(m, tle);
        }
        if (rte->subquery->setOperations)
            mask_setop(ctx, rte->subquery, rte->subquery->setOperations, m);
        m->q = saved_q;
        ctx->sp--;
    }
    else if (IsA(n, SetOperationStmt))
    {
        SetOperationStmt *so = (SetOperationStmt *) n;

        mask_setop(ctx, q, so->larg, m);
        mask_setop(ctx, q, so->rarg, m);
    }
}

/* 최상위 Query 의 출력만 진입점으로 삼는다. 하위 쿼리는 Var 해석을 통해
 * 출력 경로를 따라서만 도달한다. */
static int
mask_output(Ctx *ctx, Query *q)
{
    MutCtx      m;
    ListCell   *lc;

    ctx->sp = 0;
    ctx->stack[ctx->sp++] = q;
    m.ctx = ctx;
    m.q = q;
    m.masked = 0;

    if (q->commandType == CMD_SELECT)
        foreach(lc, q->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk)
                mask_tle(&m, tle);
        }
    foreach(lc, q->returningList)
        mask_tle(&m, (TargetEntry *) lfirst(lc));
    if (q->setOperations)
        mask_setop(ctx, q, q->setOperations, &m);
    ctx->sp--;
    return m.masked;
}

/* ── V1: 소스 마스킹 ────────────────────────────────────────────────────
 *
 * 테이블 진입점에서 값을 바꾼다. 경로를 구분하지 않으므로 **술어도 마스크를
 * 본다** -- 마스킹 뷰와 PostgreSQL Anonymizer 의 동적 마스킹이 이 지점이다.
 * 필터가 마스크값과 비교되어 깨지지만(Fidelity 포기), 거부는 하지 않고
 * (Totality 유지) 마스크된 값 밖으로는 아무것도 안 나간다(Opacity 유지).
 *
 * 뷰 베이스라인은 별도 메커니즘(스키마 그림자)이라 마스크 함수만 같았다.
 * 여기서는 **같은 코드 경로·같은 함수**로 세 꼭짓점을 돌릴 수 있다. */
static Node *
mask_source_mutator(Node *node, MutCtx *m)
{
    if (node == NULL)
        return NULL;

    if (IsA(node, Var))
    {
        Var            *var = (Var *) node;
        Query          *vq = query_at(m->ctx, var->varlevelsup);
        RangeTblEntry  *rte;
        const char     *kind;

        if (vq == NULL || var->varno < 1 || var->varno > list_length(vq->rtable))
            return node;
        rte = rt_fetch(var->varno, vq->rtable);
        if (rte->rtekind != RTE_RELATION || var->varattno <= 0)
            return node;
        kind = label_of(m->ctx, rte->relid, var->varattno);
        if (kind == NULL)
            return node;
        m->masked++;
        return (Node *) mask_call(var, kind);
    }
    if (IsA(node, Query))
    {
        Query *sub = (Query *) node;

        if (m->ctx->sp >= MAX_STACK)
        {
            m->ctx->bounded++;
            return node;
        }
        m->ctx->stack[m->ctx->sp++] = sub;
        query_tree_mutator(sub, mask_source_mutator, (void *) m,
                           QTW_DONT_COPY_QUERY);
        m->ctx->sp--;
        return node;
    }
    return expression_tree_mutator(node, mask_source_mutator, (void *) m);
}

static int
mask_source(Ctx *ctx, Query *q)
{
    MutCtx m;

    ctx->sp = 0;
    ctx->depth = 0;
    ctx->stack[ctx->sp++] = q;
    m.ctx = ctx;
    m.q = q;
    m.masked = 0;
    query_tree_mutator(q, mask_source_mutator, (void *) &m,
                       QTW_DONT_COPY_QUERY);
    ctx->sp--;
    return m.masked;
}

/* 이 출력 표현식이 어떤 PII 에서 왔는가. 없으면 NULL.
 * 분석기(walk_expr)를 그대로 재사용한다 -- 별도 구현하면 판정이 갈라진다. */
static const char *
output_kind(Ctx *ctx, Query *q, Node *expr)
{
    List       *tmp = NIL;
    List      **saved_sink = ctx->sink;
    int         saved_sp = ctx->sp;
    const char *k = NULL;

    ctx->sp = 0;
    ctx->depth = 0;
    ctx->stack[ctx->sp++] = q;
    ctx->sink = &tmp;
    walk_expr(expr, ctx);
    ctx->sink = saved_sink;
    ctx->sp = saved_sp;
    if (tmp != NIL)
        k = (const char *) linitial(tmp);
    return k;
}

/* ── V3: 투영 경계 redaction ────────────────────────────────────────────
 *
 * ★ 최상위 targetList 를 변이하는 것으로는 V3 가 되지 않는다. PostgreSQL 에서
 *   DISTINCT/GROUP BY 는 `ressortgroupref` 로 **같은 TargetEntry** 를 가리키므로,
 *   TLE 를 마스킹하면 그룹핑도 마스크 위에서 돈다 -- 그러면 V2 로 되돌아간다.
 *
 *   진짜 V3 는 모든 관계 연산 **뒤**에 redaction 이 와야 한다:
 *
 *       SELECT mask(q.ssn) FROM ( <원래 질의 전체> ) q
 *
 *   ORDER BY / LIMIT / DISTINCT / 집계는 서브쿼리 안에 남아 원본으로 계산되고,
 *   바깥에서만 가린다. Oracle 이 `GROUP BY` 절을 갱신하지 않는다고 문서에
 *   적은 것과 같은 효과다.
 *
 * 한계(문서에 남긴다): 서브쿼리의 ORDER BY 는 바깥에서 보존이 **보장되지 않는다.**
 * 완전한 V3 는 executor 최종 투영이어야 한다. */
static Query *
wrap_projection(Ctx *ctx, Query *orig, int *nmasked)
{
    Query              *outer = makeNode(Query);
    ParseState         *pstate = make_parsestate(NULL);
    RangeTblRef        *rtr = makeNode(RangeTblRef);
    ListCell           *lc;
    List               *tl = NIL;
    int                 resno = 1;

    (void) addRangeTableEntryForSubquery(pstate, orig,
                                         makeAlias("ipguard_proj", NIL),
                                         false, true);
    outer->commandType = CMD_SELECT;
    outer->querySource = QSRC_ORIGINAL;
    outer->canSetTag = true;
    outer->rtable = pstate->p_rtable;
    rtr->rtindex = 1;
    outer->jointree = makeFromExpr(list_make1(rtr), NULL);

    foreach(lc, orig->targetList)
    {
        TargetEntry *ste = (TargetEntry *) lfirst(lc);
        Node        *e = (Node *) ste->expr;
        const char  *kind;
        Var         *v;

        if (ste->resjunk)
            continue;
        v = makeVar(1, ste->resno, exprType(e), exprTypmod(e),
                    exprCollation(e), 0);
/* ★ V3 는 **결과 lineage** 로 redaction 한다.
         *
         * 안쪽 질의는 손대지 않는다 -- 그룹핑·정렬·집계가 전부 원본으로 계산된다.
         * 바깥에서, 그 출력이 민감 컬럼에서 왔으면 **결과 타입에 맞춰** 가린다:
         *
         *     round(secret)    -> 계산은 원본, 최종 숫자를 가린다
         *     substr(secret,…) -> 계산은 원본, 최종 문자열을 가린다
         *     avg(secret)      -> 계산은 원본, 최종 숫자를 가린다
         *     count(*)         -> lineage 없음 -> 진짜 건수
         *
         * 처음에는 `IsA(e, Var)` 로 **컬럼만** 가렸는데, Oracle 23ai 문서와
         * 예제는 파생·집계 결과도 최종 출력에서 가린다고 명시하므로 그쪽이
         * 맞다. 이 정의에서 V3 는 곧 Ideal(= Mout(Q(D)))이 된다.
         *
         * 그리고 그래서 정리가 더 강해진다 -- **Ideal 조차 opacity 를 어긴다.**
         * `SELECT DISTINCT secret` 의 **반환 행 수**는 원본 고유값 개수인데,
         * 행 수는 redaction 할 수 있는 대상이 아니다. 모든 셀을 가려도 샌다. */
        kind = output_kind(ctx, orig, e);
        if (kind != NULL)
            (*nmasked)++;
        tl = lappend(tl,
                     makeTargetEntry((Expr *) (kind ? (Node *) mask_call(v, kind)
                                                    : (Node *) v),
                                     resno++,
                                     ste->resname ? pstrdup(ste->resname) : NULL,
                                     false));
    }
    outer->targetList = tl;
    free_parsestate(pstate);
    return outer;
}

/* 표현식 안에 mask() 호출이 있는가 */
static bool
has_mask_call(Node *node, void *unused)
{
    if (node == NULL)
        return false;
    if (IsA(node, FuncExpr) && ((FuncExpr *) node)->funcid == mask_fn_oid)
        return true;
    if (IsA(node, Query))
        return false;               /* 하위 쿼리는 따로 검사한다 */
    return expression_tree_walker(node, has_mask_call, unused);
}

typedef struct ConflictCtx
{
    Ctx        *ctx;
    bool        found;
    const char *col;
} ConflictCtx;

/* 술어 안의 Var 가 *마스킹된* 서브쿼리/CTE 출력을 가리키는가.
 *
 * 이것이 정합성 파손의 정확한 조건이다: 서브쿼리 targetList 항목 하나가
 * 출력과 술어 양쪽에 동시에 쓰이는데 우리는 그것을 마스킹한다. 그러면
 * 필터가 마스크값과 비교되어 행이 사라지거나(0행), 값이 전부 같아져 조인이
 * 교차곱이 된다(폭증). 둘 다 에러 없이 조용히 틀린다. */
static bool
qual_var_walker(Node *node, ConflictCtx *cc)
{
    if (node == NULL || cc->found)
        return false;

    if (IsA(node, Var))
    {
        Var            *var = (Var *) node;
        Query          *q = query_at(cc->ctx, var->varlevelsup);
        RangeTblEntry  *rte;
        List           *tl = NIL;

        if (q == NULL || var->varno < 1 || var->varno > list_length(q->rtable))
            return false;
        rte = rt_fetch(var->varno, q->rtable);

        if (rte->rtekind == RTE_SUBQUERY)
        {
            /* 집합연산 서브쿼리면 최상위 targetList 는 맨 왼쪽 팔을 가리키는
             * Var 라 mask 호출이 안 보인다. 팔을 직접 봐야 한다 -- 3R X07. */
            if (rte->subquery->setOperations)
            {
                List     *arms = NIL;
                ListCell *ac;

                collect_setop_arms(rte->subquery,
                                   rte->subquery->setOperations, &arms);
                foreach(ac, arms)
                {
                    Query    *arm = (Query *) lfirst(ac);
                    ListCell *tc;

                    foreach(tc, arm->targetList)
                    {
                        TargetEntry *at = (TargetEntry *) lfirst(tc);

                        if (at->resjunk)
                            continue;
                        if (var->varattno != 0 && at->resno != var->varattno)
                            continue;
                        if (has_mask_call((Node *) at->expr, NULL))
                        {
                            cc->found = true;
                            cc->col = at->resname ? at->resname : "?";
                            return true;
                        }
                    }
                }
                return false;
            }
            tl = rte->subquery->targetList;
        }
        else if (rte->rtekind == RTE_CTE)
        {
            Query    *owner = query_at(cc->ctx,
                                       var->varlevelsup + rte->ctelevelsup);
            ListCell *lc;

            if (owner == NULL)
                return false;
            foreach(lc, owner->cteList)
            {
                CommonTableExpr *c = (CommonTableExpr *) lfirst(lc);

                if (strcmp(c->ctename, rte->ctename) == 0 &&
                    IsA(c->ctequery, Query))
                {
                    tl = ((Query *) c->ctequery)->targetList;
                    break;
                }
            }
        }
        else
            return false;

        if (var->varattno == 0)
        {
            ListCell *lc;

            foreach(lc, tl)
            {
                TargetEntry *tle = (TargetEntry *) lfirst(lc);

                if (has_mask_call((Node *) tle->expr, NULL))
                {
                    cc->found = true;
                    cc->col = tle->resname ? tle->resname : "?";
                    return true;
                }
            }
            return false;
        }
        else
        {
            TargetEntry *tle = get_tle_by_resno(tl, var->varattno);

            if (tle && has_mask_call((Node *) tle->expr, NULL))
            {
                cc->found = true;
                cc->col = tle->resname ? tle->resname : "?";
                return true;
            }
            return false;
        }
    }
    if (IsA(node, Query))
        return false;
    return expression_tree_walker(node, qual_var_walker, (void *) cc);
}

/* Query 트리를 돌며 각 레벨의 술어를 검사한다.
 * 술어만 본다 -- GROUP BY/DISTINCT/ORDER BY 로 결과가 바뀌는 것은 마스킹의
 * 정의상 불가피한 것(intrinsic)이지 우리 설계 탓이 아니므로 막지 않는다. */
static bool
conflict_walker(Node *node, ConflictCtx *cc)
{
    if (node == NULL || cc->found)
        return false;
    if (IsA(node, Query))
    {
        Query *q = (Query *) node;
        bool   ret;

        if (cc->ctx->sp >= MAX_STACK)
            return false;
        cc->ctx->stack[cc->ctx->sp++] = q;

        /* jointree 전체를 훑는다 -- JoinExpr->quals(ON 절)도 여기 있다 */
        qual_var_walker((Node *) q->jointree, cc);
        if (!cc->found)
            qual_var_walker((Node *) q->havingQual, cc);

        ret = cc->found ? false
            : query_tree_walker(q, conflict_walker, (void *) cc, 0);
        cc->ctx->sp--;
        return ret;
    }
    return expression_tree_walker(node, conflict_walker, (void *) cc);
}

/* ==========================================================================
 * 의미 발산 감지 -- 마스킹이 "조용한 오답"을 만드는 경우
 *
 * 위의 conflict_walker 는 한 가지 조건만 본다(마스킹된 서브쿼리 출력을 술어가
 * 참조). 실측해 보니 그것만으로는 부족했다 -- corpus/divergence.json 24건 중
 * 12건이 조용히 틀리는데 한 건도 거부되지 않았다(results/divergence.md).
 *
 * 측정에서 나온 구분선은 **행 단위 파생이냐 행 간 연산이냐** 이다:
 *
 *   substr(ssn,1,6) -> "******"     행 단위. 클라이언트가 f(마스크)를 받는다.
 *                                   그게 마스킹의 정의다. 허용.
 *   count(DISTINCT ssn) -> 1        행 간. 답은 값이 아니라 **모집단에 대한
 *                                   통계**인데, 마스킹이 모집단을 파괴했다.
 *                                   출력은 평범한 숫자라 마스킹된 티도 안 난다.
 *
 * 두 규칙으로 좁혔다:
 *
 *   R1 카디널리티 -- 마스킹된 값이 DISTINCT/GROUP BY 키이거나 비-ALL 집합연산의
 *                    출력이다. 결과 행 수가 마스크값에 좌우된다.
 *   R2 통계       -- 마스킹된 값이 **값 보존이 아닌** 집계의 인자다.
 *
 * 값 보존 집계(max/min/string_agg/array_agg/…)는 결과가 입력 값들 중 하나이거나
 * 그 연결이다. 전부 마스크값이면 결과도 마스크값이라 클라이언트가 알아본다.
 * 반면 count/avg/sum 은 마스크값에서 **평범한 숫자**를 만들어낸다 -- 실측:
 *
 *      round(avg(extract(year FROM birth)))    1993 -> 1900
 *
 * 1900 은 별표가 아니다. 눈치챌 방법이 없다.
 *
 * 아직 덮지 못하는 것(측정에서 '의도한 동작'으로 분류된 것들): 윈도우 함수의
 * ORDER BY/PARTITION BY, 정렬 후 LIMIT 의 행 선택. 출력이 전부 마스킹돼
 * 클라이언트가 어차피 구분 못 하므로 일단 뒀다.
 * ========================================================================== */

/* 마스크 센티널이 결과만 봐서 마스크인 줄 알아볼 수 있는가.
 *
 * text  -> '**********'   명백하다
 * date  -> 1900-01-01     의심스럽다
 * uuid  -> 000…0          명백하다
 * 숫자  -> 0              ★ 유효한 급여·잔액이다. 구별 불가.
 *
 * 이 구분이 값 보존 집계 면제의 전제다. max(ssn) 은 '****' 를 돌려주므로
 * 클라이언트가 마스킹됐음을 안다. max(salary) 는 0 을 돌려주는데, 그건
 * "최고 급여가 0원"이라는 **그럴듯한 답**이다 -- 실측 DV27.
 * 그래서 숫자형이면 값 보존이어도 면제하지 않는다. */
static bool
mask_sentinel_is_ambiguous(Node *node, void *unused)
{
    if (node == NULL)
        return false;
    if (IsA(node, FuncExpr))
    {
        FuncExpr *f = (FuncExpr *) node;

        if (f->funcid == mask_fn_oid)
            switch (f->funcresulttype)
            {
                case INT2OID: case INT4OID: case INT8OID:
                case FLOAT4OID: case FLOAT8OID: case NUMERICOID:
                    return true;
                default:
                    break;
            }
    }
    if (IsA(node, Query))
        return false;
    return expression_tree_walker(node, mask_sentinel_is_ambiguous, unused);
}

static bool
agg_preserves_value(Oid aggfnoid)
{
    char   *n = get_func_name(aggfnoid);
    bool    ok;

    if (n == NULL)
        return false;
    ok = (strcmp(n, "max") == 0 || strcmp(n, "min") == 0 ||
          strcmp(n, "string_agg") == 0 || strcmp(n, "array_agg") == 0 ||
          strcmp(n, "json_agg") == 0 || strcmp(n, "jsonb_agg") == 0 ||
          strcmp(n, "json_agg_strict") == 0 || strcmp(n, "xmlagg") == 0);
    pfree(n);
    return ok;
}

typedef struct DivCtx
{
    Ctx        *ctx;
    bool        found;
    const char *rule;               /* 어떤 규칙에 걸렸는가 */
    const char *what;               /* 무엇이 */
} DivCtx;

/* 표현식이 마스킹된 값에 닿는가 -- 직접 mask() 호출이거나, 마스킹된
 * 서브쿼리/CTE 출력을 가리키는 Var 이거나.
 *
 * 두 번째 경우를 빼먹으면 한 겹만 감싸도 뚫린다. 실측 누락 사례:
 *
 *     SELECT t.ssn FROM (SELECT ssn FROM cust) t GROUP BY t.ssn
 *
 * 바깥 GROUP BY 키는 그냥 Var 이고 mask() 는 서브쿼리 안에 있다.
 * 술어 충돌 감지기가 이미 같은 해석을 하므로 그대로 재사용한다. */
static bool
touches_mask(Node *expr, DivCtx *dc)
{
    ConflictCtx cc;

    if (has_mask_call(expr, NULL))
        return true;
    cc.ctx = dc->ctx;
    cc.found = false;
    cc.col = NULL;
    qual_var_walker(expr, &cc);
    return cc.found;
}

/* R2: 값 보존이 아닌 집계 안에 마스크 호출이 있는가 */
static bool
div_agg_walker(Node *node, DivCtx *dc)
{
    if (node == NULL || dc->found)
        return false;

    if (IsA(node, Aggref))
    {
        Aggref *a = (Aggref *) node;

        if (touches_mask((Node *) a->args, dc) ||
            touches_mask((Node *) a->aggdirectargs, dc))
        {
            /* DISTINCT 집계는 값 보존 여부와 무관하게 고유값 수에 의존한다.
             * 그리고 마스크 센티널이 정상 값과 구별되지 않는 타입(숫자)이면
             * 값 보존 집계여도 면제하지 않는다 -- max(salary)=0 은 그럴듯한
             * 오답이다. */
            if (a->aggdistinct != NIL || !agg_preserves_value(a->aggfnoid) ||
                (ipguard_numeric_mask == 0 &&
                 mask_sentinel_is_ambiguous((Node *) a->args, NULL)))
            {
                char *n = get_func_name(a->aggfnoid);

                dc->found = true;
                dc->rule = (a->aggdistinct != NIL) ? "DISTINCT 집계"
                    : agg_preserves_value(a->aggfnoid)
                      ? "집계(마스크 0 이 정상 값과 구별 불가)" : "집계";
                dc->what = n ? n : "?";
                return true;
            }
        }
        return false;           /* 값 보존 집계면 더 볼 것 없다 */
    }
    if (IsA(node, Query))
        return false;           /* 하위 쿼리는 div_walker 가 따로 본다 */
    return expression_tree_walker(node, div_agg_walker, (void *) dc);
}

/* R1(집합연산 부분): 비-ALL 집합연산의 arm 출력이 마스킹됐는가.
 * UNION/EXCEPT/INTERSECT 는 중복 제거를 하므로 마스크값 위에서 계산되면
 * 결과 집합 자체가 무너진다 (실측: EXCEPT 50행 -> 0행). */
static bool
setop_dedup_masked(Ctx *ctx, Query *q, Node *n, bool under_dedup, DivCtx *dc)
{
    if (n == NULL || dc->found)
        return false;

    if (IsA(n, SetOperationStmt))
    {
        SetOperationStmt *so = (SetOperationStmt *) n;
        /* ALL 이 값 비교를 없애는 것은 UNION 뿐이다. UNION ALL 은 단순 연결이라
         * 마스크값이어도 결과가 안 바뀐다. 반면 EXCEPT ALL / INTERSECT ALL 은
         * **다중집합 연산**이라 여전히 값을 비교한다 -- 3R X05/X06:
         *   A EXCEPT ALL B (서로소)  원본 49행 -> 마스킹 후 0행 */
        bool              cmp = under_dedup || !so->all
                                || so->op != SETOP_UNION;

        return setop_dedup_masked(ctx, q, so->larg, cmp, dc)
            || setop_dedup_masked(ctx, q, so->rarg, cmp, dc);
    }
    if (IsA(n, RangeTblRef) && under_dedup)
    {
        RangeTblRef    *ref = (RangeTblRef *) n;
        RangeTblEntry  *rte;
        ListCell       *lc;

        if (ref->rtindex < 1 || ref->rtindex > list_length(q->rtable))
            return false;
        rte = rt_fetch(ref->rtindex, q->rtable);
        if (rte->rtekind != RTE_SUBQUERY)
            return false;
        foreach(lc, rte->subquery->targetList)
        {
            TargetEntry *tle = (TargetEntry *) lfirst(lc);

            if (!tle->resjunk && has_mask_call((Node *) tle->expr, NULL))
            {
                dc->found = true;
                dc->rule = "집합연산(중복 제거)";
                dc->what = tle->resname ? tle->resname : "?";
                return true;
            }
        }
    }
    return false;
}

static bool
div_walker(Node *node, DivCtx *dc)
{
    if (node == NULL || dc->found)
        return false;

    if (IsA(node, Query))
    {
        Query      *q = (Query *) node;
        ListCell   *lc;
        bool        ret;

        /* Var 해석(varlevelsup)을 위해 conflict_walker 와 같은 방식으로
         * 쿼리 레벨 스택을 유지한다. */
        if (dc->ctx->sp >= MAX_STACK)
            return false;
        dc->ctx->stack[dc->ctx->sp++] = q;

        /* R1: 중복 제거 / 그룹핑 키 */
        foreach(lc, q->distinctClause)
        {
            SortGroupClause *sg = (SortGroupClause *) lfirst(lc);
            TargetEntry     *tle = get_sortgroupclause_tle(sg, q->targetList);

            if (tle && touches_mask((Node *) tle->expr, dc))
            {
                dc->found = true;
                dc->rule = "DISTINCT";
                dc->what = tle->resname ? tle->resname : "?";
                break;
            }
        }
        if (!dc->found)
            foreach(lc, q->groupClause)
            {
                SortGroupClause *sg = (SortGroupClause *) lfirst(lc);
                TargetEntry     *tle = get_sortgroupclause_tle(sg, q->targetList);

                if (tle && touches_mask((Node *) tle->expr, dc))
                {
                    dc->found = true;
                    dc->rule = "GROUP BY";
                    dc->what = tle->resname ? tle->resname : "?";
                    break;
                }
            }
        if (!dc->found && q->setOperations)
            setop_dedup_masked(dc->ctx, q, q->setOperations, false, dc);

        /* R3a: 윈도우 프레임의 PARTITION BY / ORDER BY 키가 마스킹됐는가.
         *
         * 윈도우 함수의 출력(rank/row_number/lag …)은 평범한 정수인데 그 값이
         * 마스크 순서·마스크 파티션에서 나온다. 실측:
         *
         *     dense_rank() OVER (ORDER BY ssn)   1,2,3,4,5 -> 전부 1
         *     rank() OVER (PARTITION BY ssn …)   전부 1    -> 1,2,3,4,5
         *
         * 같은 행에 마스킹된 컬럼이 함께 나가더라도, 순위 컬럼 자체에는
         * 마스킹됐다는 표시가 없다. */
        if (!dc->found)
        {
            ListCell *wc;

            foreach(wc, q->windowClause)
            {
                WindowClause   *w = (WindowClause *) lfirst(wc);
                ListCell       *k;
                List           *keys[2];
                int             i;

                keys[0] = w->partitionClause;
                keys[1] = w->orderClause;
                for (i = 0; i < 2 && !dc->found; i++)
                    foreach(k, keys[i])
                    {
                        SortGroupClause *sg = (SortGroupClause *) lfirst(k);
                        TargetEntry     *tle =
                            get_sortgroupclause_tle(sg, q->targetList);

                        if (tle && touches_mask((Node *) tle->expr, dc))
                        {
                            dc->found = true;
                            dc->rule = (i == 0) ? "윈도우 PARTITION BY"
                                                : "윈도우 ORDER BY";
                            dc->what = tle->resname ? tle->resname : "?";
                            break;
                        }
                    }
                if (dc->found)
                    break;
            }
        }

        /* R3b: 정렬 키가 마스킹됐고 LIMIT/OFFSET 이 있는가.
         *
         * LIMIT 이 없으면 행 **순서**만 바뀌고 집합은 그대로다. LIMIT 이 붙는
         * 순간 **어느 행이 나올지**가 마스크값에 좌우된다. 실측:
         *
         *     SELECT id, ssn FROM cust ORDER BY ssn LIMIT 5
         *        id 100,200,300,400,500  ->  1,2,3,4,5
         *
         * id 는 마스킹되지 않은 평범한 값인데 완전히 다른 행이 나온다. */
        if (!dc->found && (q->limitCount != NULL || q->limitOffset != NULL))
        {
            ListCell *k;

            foreach(k, q->sortClause)
            {
                SortGroupClause *sg = (SortGroupClause *) lfirst(k);
                TargetEntry     *tle =
                    get_sortgroupclause_tle(sg, q->targetList);

                if (tle && touches_mask((Node *) tle->expr, dc))
                {
                    dc->found = true;
                    dc->rule = "ORDER BY + LIMIT (행 선택)";
                    dc->what = tle->resname ? tle->resname : "?";
                    break;
                }
            }
        }

        /* R2: 집계 -- 출력과 HAVING 만 본다(술어는 마스킹하지 않으므로) */
        if (!dc->found)
            foreach(lc, q->targetList)
            {
                TargetEntry *tle = (TargetEntry *) lfirst(lc);

                if (div_agg_walker((Node *) tle->expr, dc))
                    break;
            }
        if (!dc->found)
            div_agg_walker((Node *) q->havingQual, dc);

        ret = dc->found ? true
            : query_tree_walker(q, div_walker, (void *) dc, 0);
        dc->ctx->sp--;
        return ret;
    }
    return expression_tree_walker(node, div_walker, (void *) dc);
}

/* 마스킹된 트리에서 발산을 찾는다. 찾으면 true 와 사유를 채운다. */
static bool
find_divergence(Ctx *ctx, Query *q, const char **rule, const char **what)
{
    DivCtx dc;

    dc.ctx = ctx;
    dc.found = false;
    dc.rule = NULL;
    dc.what = NULL;
    ctx->sp = 0;
    div_walker((Node *) q, &dc);
    if (dc.found)
    {
        *rule = dc.rule;
        *what = dc.what;
    }
    return dc.found;
}

/* ==========================================================================
 * 설명 / 판정 -- "이 SQL 에 적용되는가?" 를 SQL 한 줄로 답한다
 *
 * 채점기는 코퍼스 전체 집계(95%, 92% ...)만 낸다. 그래서 "우리 서비스의 이
 * 쿼리는 어떻게 되느냐"에 답할 수가 없었다. 아래 두 함수는 **임의의 SQL** 에
 * 대해, 실행하지 않고 판정을 돌려준다:
 *
 *   ipguard_verdict(sql) -> 1행.     적용 / 거부 / 미적용 + 이유
 *   ipguard_explain(sql) -> 컬럼별.  어느 테이블의 어느 컬럼이 어느 경로로
 *                                    나가고 어떻게 처리되는가
 *
 * planner_hook 과 **같은 순서**(분석 -> bound 검사 -> 마스킹 -> 충돌 검사)를
 * 그대로 재현한다. 순서나 코드가 갈라지면 사람에게 보여주는 판정이 실제 집행과
 * 조용히 달라진다 -- 그 순간 이 도구는 신뢰할 수 없다.
 * ========================================================================== */

typedef struct Verdict
{
    Ctx     ctx;
    char   *err;                    /* 파스/재작성 실패 메시지 */
    int     refuse;                 /* 0=없음 1=bound 소진 2=정합성 충돌 */
    char   *detail;
    int     masked;                 /* 실제로 mask() 로 치환된 컬럼 수 */
} Verdict;

static void
run_verdict(const char *sql, Verdict *v)
{
    List     *walked = NIL;
    ListCell *lc;

    memset(v, 0, sizeof(*v));
    v->ctx.collect = true;

    /* 내부 SPI(load_labels)가 다시 planner_hook 을 타고 들어오는 것을 막는다 */
    IPGUARD_BUSY_ENTER();
    PG_TRY();
    {
        load_labels(&v->ctx);
        analyze_sql(sql, &v->ctx, &walked, &v->err);
    }
    PG_CATCH();
    {
        IPGUARD_BUSY_LEAVE();
        PG_RE_THROW();
    }
    PG_END_TRY();
    IPGUARD_BUSY_LEAVE();

    if (v->err != NULL)
        return;

    /* planner_hook 2단계: 순회 bound 소진은 우회 신호다 -> 거부 */
    if (v->ctx.bounded > 0)
    {
        v->refuse = 1;
        v->detail = psprintf("순회 bound 를 %d회 소진 -- 노출 여부를 판정할 수 없음",
                             v->ctx.bounded);
        return;
    }
    if (v->ctx.out_kinds == NIL)
        return;                     /* 출력 경로에 라벨된 PII 없음 = 손대지 않음 */

    /* 충돌 감지기가 mask() 호출을 funcid 로 식별하므로 OID 가 필요하다 */
    if (!OidIsValid(mask_fn_oid))
    {
        Oid argt[2] = {ANYELEMENTOID, TEXTOID};

        mask_fn_oid = LookupFuncName(list_make1(makeString("ipguard_mask")),
                                     2, argt, true);
    }

    foreach(lc, walked)
    {
        Query       *q = (Query *) lfirst(lc);
        ConflictCtx  cc;

        /* 3단계: 출력 경로 치환 */
        v->ctx.sp = 0;
        v->ctx.depth = 0;
        v->masked += mask_output(&v->ctx, q);

        /* 4단계: 정합성 충돌 -> 거부 */
        cc.ctx = &v->ctx;
        cc.found = false;
        cc.col = NULL;
        v->ctx.sp = 0;
        conflict_walker((Node *) q, &cc);
        if (cc.found)
        {
            v->refuse = 2;
            v->detail = psprintf("마스킹된 출력 컬럼 \"%s\" 를 술어/조인 조건이 "
                                 "참조 -- 실행하면 에러 없이 틀린 결과",
                                 cc.col ? cc.col : "?");
            return;
        }

        /* 5단계: 의미 발산 (기본 allow) */
        if (ipguard_on_divergence != 2)
        {
            const char *rule = NULL, *what = NULL;

            if (find_divergence(&v->ctx, q, &rule, &what))
            {
                v->refuse = 3;
                v->detail = psprintf("%s 가 마스킹된 값 \"%s\" 위에서 계산됨 "
                                     "-- 결과가 모집단이 아니라 마스크를 반영한다",
                                     rule, what);
                return;
            }
        }
    }
}

PG_FUNCTION_INFO_V1(ipguard_verdict);

Datum
ipguard_verdict(PG_FUNCTION_ARGS)
{
    char       *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    Verdict     v;
    TupleDesc   tupdesc;
    Datum       vals[8];
    bool        nulls[8];
    const char *verdict;
    const char *reason;

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "ipguard_verdict: 복합 반환 타입이 필요합니다");
    tupdesc = BlessTupleDesc(tupdesc);

    run_verdict(sql, &v);

    if (v.err != NULL)
    {
        verdict = "error";
        reason = v.err;
    }
    else if (v.refuse != 0)
    {
        verdict = "refuse";
        reason = v.detail;
    }
    else if (v.ctx.out_kinds == NIL)
    {
        verdict = "pass";
        reason = (v.ctx.pred_kinds != NIL || v.ctx.write_kinds != NIL)
            ? "출력 경로에 PII 없음 (술어/쓰기에서만 참조)"
            : "라벨된 PII 참조 없음";
    }
    else if (v.masked > 0)
    {
        verdict = "mask";
        reason = psprintf("출력 경로 PII 컬럼 %d개를 ipguard_mask() 로 치환",
                          v.masked);
    }
    else if (v.ctx.utility_n > 0)
    {
        /* COPY / CTAS 등. 최상위는 planner_hook 을 타지 않으므로 여기서
         * "적용됨"이라고 말하면 거짓 안심이 된다. 실측으로 확인해야 한다. */
        verdict = "utility";
        reason = "utility 문장 -- 최상위는 planner_hook 경로가 아님. 실측 필요";
    }
    else
    {
        /* 분석기는 찾았는데 변이기가 0개를 바꿨다. 둘 중 하나가 틀렸다. */
        verdict = "mismatch";
        reason = "분석기는 출력 PII 를 찾았으나 치환은 0건 -- 결함 신호";
    }

    memset(nulls, 0, sizeof(nulls));
    vals[0] = CStringGetTextDatum(verdict);
    vals[1] = CStringGetTextDatum(reason != NULL ? reason : "");
    vals[2] = CStringGetTextDatum(join_kinds(v.ctx.out_kinds));
    vals[3] = CStringGetTextDatum(join_kinds(v.ctx.pred_kinds));
    vals[4] = CStringGetTextDatum(join_kinds(v.ctx.write_kinds));
    vals[5] = Int32GetDatum(v.masked);
    vals[6] = Int32GetDatum(v.ctx.bounded);
    vals[7] = Int32GetDatum(v.ctx.unresolved);

    PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, vals, nulls)));
}

PG_FUNCTION_INFO_V1(ipguard_explain);

Datum
ipguard_explain(PG_FUNCTION_ARGS)
{
    char               *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    ReturnSetInfo      *rsi = (ReturnSetInfo *) fcinfo->resultinfo;
    Verdict             v;
    TupleDesc           tupdesc;
    Tuplestorestate    *store;
    MemoryContext       oldcx;
    ListCell           *lc;

    if (rsi == NULL || !IsA(rsi, ReturnSetInfo) ||
        (rsi->allowedModes & SFRM_Materialize) == 0)
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("ipguard_explain: 집합 반환 문맥에서만 호출할 수 있습니다")));
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "ipguard_explain: 복합 반환 타입이 필요합니다");

    oldcx = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);
    tupdesc = CreateTupleDescCopy(tupdesc);
    store = tuplestore_begin_heap(true, false, work_mem);
    rsi->returnMode = SFRM_Materialize;
    rsi->setResult = store;
    rsi->setDesc = tupdesc;
    MemoryContextSwitchTo(oldcx);

    run_verdict(sql, &v);

    if (v.err != NULL)
    {
        Datum   vals[5];
        bool    nulls[5] = {false, true, true, false, false};

        vals[0] = CStringGetTextDatum("(parse failed)");
        vals[3] = CStringGetTextDatum("-");
        vals[4] = CStringGetTextDatum(v.err);
        tuplestore_putvalues(store, tupdesc, vals, nulls);
        return (Datum) 0;
    }

    foreach(lc, v.ctx.cols)
    {
        ColHit     *h = (ColHit *) lfirst(lc);
        Datum       vals[5];
        bool        nulls[5];
        char       *rel = get_rel_name(h->relid);
        char       *att = get_attname(h->relid, h->attno, true);
        const char *path = (h->path == 1) ? "predicate"
                         : (h->path == 2) ? "write" : "output";
        const char *action;

        if (h->path == 1)
            action = "kept — 술어는 건드리지 않음 (필터가 계속 동작해야 함)";
        else if (h->path == 2)
            action = "kept — 쓰기 값 (출력이 아님)";
        else if (v.refuse != 0)
            action = "refused — 마스킹하면 결과가 바뀜";
        else if (v.masked > 0)
            action = "masked — ipguard_mask() 로 치환";
        else
            action = "NOT masked — 확인 필요";

        memset(nulls, 0, sizeof(nulls));
        vals[0] = CStringGetTextDatum(rel != NULL ? rel : "?");
        vals[1] = CStringGetTextDatum(att != NULL ? att : "?");
        vals[2] = CStringGetTextDatum(h->kind != NULL ? h->kind : "?");
        vals[3] = CStringGetTextDatum(path);
        vals[4] = CStringGetTextDatum(action);
        tuplestore_putvalues(store, tupdesc, vals, nulls);
    }
    return (Datum) 0;
}

/* ------------------------------------------------------------------
 * F_core 판정 -- 명세 v0.2.1 §12
 *
 * 왜 별도 함수인가: tools/classify_fcore.py 는 SQL **텍스트**를 본다. 그래서
 * 뷰 본문에 숨은 outer join, rewrite 가 만들어내는 구성(규칙·RLS 술어),
 * SELECT 위치 판정을 놓친다. Totality 의 **분모**를 그 상한으로 두면
 * "어려운 질의를 숨겼다"는 반론을 못 막는다.
 *
 * 여기서는 pg_analyze_and_rewrite 가 끝난 Query 트리를 본다. 뷰는 이미
 * 전개돼 있고 SubLink 종류가 명시적이므로 텍스트로는 불가능한 판정을 한다.
 *
 * ★ 이것도 완전하지 않다: 등록되지 않은 UDF 의 total 여부는 여전히 모른다.
 *   volatile 은 카탈로그에서 보지만 "정의역 전체에서 오류가 없는가"는
 *   레지스트리(§5)가 답할 문제다.
 * ------------------------------------------------------------------ */
typedef struct FragCtx
{
    List   *reasons;        /* char * -- 중복 없이 */
    bool    in_tlist;       /* SELECT 목록 안을 걷는 중인가 */
    int     depth;
} FragCtx;

static bool frag_expr(Node *node, FragCtx *f);
static void frag_query(Query *q, FragCtx *f);

static void
frag_add(FragCtx *f, const char *r)
{
    ListCell *lc;

    foreach(lc, f->reasons)
        if (strcmp((char *) lfirst(lc), r) == 0)
            return;
    f->reasons = lappend(f->reasons, pstrdup(r));
}

/* jointree 는 expression_tree_walker 로 걸으면 JoinExpr->jointype 을
 * 못 보므로 직접 내려간다. outer join 은 확장 NULL 때문에 F_core 밖이다. */
static void
frag_jointree(Node *n, FragCtx *f)
{
    if (n == NULL)
        return;
    if (IsA(n, FromExpr))
    {
        FromExpr *fe = (FromExpr *) n;
        ListCell *lc;

        foreach(lc, fe->fromlist)
            frag_jointree((Node *) lfirst(lc), f);
        frag_expr(fe->quals, f);
    }
    else if (IsA(n, JoinExpr))
    {
        JoinExpr *je = (JoinExpr *) n;

        if (je->jointype != JOIN_INNER)
            frag_add(f, "outer join");
        frag_jointree(je->larg, f);
        frag_jointree(je->rarg, f);
        frag_expr(je->quals, f);
    }
    /* RangeTblRef 는 rtable 순회에서 다룬다 */
}

static bool
frag_expr(Node *node, FragCtx *f)
{
    if (node == NULL)
        return false;

    check_stack_depth();

    if (IsA(node, SubLink))
    {
        SubLink *sl = (SubLink *) node;
        bool     saved = f->in_tlist;

        switch (sl->subLinkType)
        {
            case EXPR_SUBLINK:
            case ARRAY_SUBLINK:
                /* = (SELECT ...) 는 1행 초과면 런타임 오류다. §1.5 total 위반. */
                frag_add(f, "scalar subquery");
                break;
            case ALL_SUBLINK:
                /* NOT IN 은 재작성 후 <> ALL 로 온다. 3VL quantified comparison. */
                frag_add(f, "NOT IN / <> ALL");
                break;
            case ANY_SUBLINK:
                if (f->in_tlist)
                    frag_add(f, "SELECT-position IN");
                /* 술어 위치의 **scalar** IN 만 F_core 안이다.
                 * (a,b) IN (...) 은 파서가 testexpr 를 이미 변환하므로
                 * RowExpr 로 남지 않는다 -- RowCompareExpr 이거나 OpExpr 의
                 * AND 체인이다. RowExpr 만 보면 미탐된다. */
                if (sl->testexpr &&
                    (IsA(sl->testexpr, RowCompareExpr) ||
                     IsA(sl->testexpr, RowExpr) ||
                     (IsA(sl->testexpr, BoolExpr) &&
                      ((BoolExpr *) sl->testexpr)->boolop == AND_EXPR)))
                    frag_add(f, "row-valued IN");
                break;
            case EXISTS_SUBLINK:
                if (f->in_tlist)
                    frag_add(f, "SELECT-position EXISTS");
                break;
            case ROWCOMPARE_SUBLINK:
                frag_add(f, "row-valued IN");
                break;
            default:
                frag_add(f, "unsupported sublink");
                break;
        }
        /* 서브쿼리 본문은 자기 문맥에서 다시 본다 */
        f->in_tlist = false;
        if (sl->subselect && IsA(sl->subselect, Query))
            frag_query((Query *) sl->subselect, f);
        frag_expr(sl->testexpr, f);
        f->in_tlist = saved;
        return false;
    }
    if (IsA(node, BoolExpr))
    {
        BoolExpr *be = (BoolExpr *) node;

        /* NOT EXISTS 는 anti-semijoin 이고 NOT IN 과 다른 연산자다(§12).
         *
         * ★ gram.y 는 `x NOT IN (subquery)` 를 ALL_SUBLINK 로 만들지 않는다.
         *   `NOT (x = ANY (subquery))` -- 즉 ANY_SUBLINK 위에 NOT 을 얹는다.
         *   ALL_SUBLINK 로만 보면 NOT IN 이 통째로 미탐된다(실측으로 걸렸다).
         *   명시적 `<> ALL (subquery)` 만 ALL_SUBLINK 로 온다. */
        if (be->boolop == NOT_EXPR && list_length(be->args) == 1)
        {
            Node *a = (Node *) linitial(be->args);

            if (IsA(a, SubLink))
            {
                SubLink *s = (SubLink *) a;

                if (s->subLinkType == EXISTS_SUBLINK)
                    frag_add(f, "NOT EXISTS");
                else if (s->subLinkType == ANY_SUBLINK)
                    frag_add(f, "NOT IN / <> ALL");
            }
        }
    }
    if (IsA(node, WindowFunc))
        frag_add(f, "window function");
    if (IsA(node, Aggref))
    {
        Aggref *a = (Aggref *) node;

        if (a->aggkind == AGGKIND_ORDERED_SET ||
            a->aggkind == AGGKIND_HYPOTHETICAL || a->aggdirectargs != NIL)
            frag_add(f, "ordered-set aggregate");
    }
    if (IsA(node, FuncExpr))
    {
        FuncExpr *fe = (FuncExpr *) node;

        if (func_volatile(fe->funcid) == PROVOLATILE_VOLATILE)
            frag_add(f, "volatile function");
    }
    if (IsA(node, Query))
    {
        frag_query((Query *) node, f);
        return false;
    }
    return expression_tree_walker(node, frag_expr, (void *) f);
}

static void
frag_query(Query *q, FragCtx *f)
{
    ListCell *lc;
    bool      saved;

    if (q == NULL || f->depth > MAX_DEPTH)
    {
        if (q != NULL)
            frag_add(f, "depth bound");
        return;
    }
    f->depth++;

    if (q->commandType != CMD_SELECT)
        frag_add(f, "DML");
    if (q->hasRecursive)
        frag_add(f, "recursive CTE");
    if (q->hasWindowFuncs || q->windowClause != NIL)
        frag_add(f, "window function");
    if (q->hasDistinctOn)
        frag_add(f, "DISTINCT ON");
    if (q->groupingSets != NIL)
        frag_add(f, "GROUPING SETS");
    if (q->hasTargetSRFs)
        frag_add(f, "set-returning function");
    if (q->limitOption == LIMIT_OPTION_WITH_TIES)
        frag_add(f, "FETCH WITH TIES");
    /* §1: ORDER BY 없는 LIMIT/OFFSET 은 어느 행이 나올지 비결정적이다 */
    if ((q->limitCount || q->limitOffset) && q->sortClause == NIL)
        frag_add(f, "LIMIT without ORDER BY");
    if (q->rowMarks != NIL)
        frag_add(f, "row locking");

    foreach(lc, q->rtable)
    {
        RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);

        if (rte->lateral)
            frag_add(f, "LATERAL");
        switch (rte->rtekind)
        {
            case RTE_RELATION:
            case RTE_JOIN:
            case RTE_VALUES:
                break;
            case RTE_SUBQUERY:
                frag_query(rte->subquery, f);
                break;
            case RTE_CTE:
                if (rte->self_reference)
                    frag_add(f, "recursive CTE");
                break;
            case RTE_FUNCTION:
                frag_add(f, "set-returning function");
                break;
            default:
                frag_add(f, "unsupported range table entry");
                break;
        }
    }
    foreach(lc, q->cteList)
    {
        CommonTableExpr *cte = lfirst_node(CommonTableExpr, lc);

        if (cte->ctequery && IsA(cte->ctequery, Query))
            frag_query((Query *) cte->ctequery, f);
    }

    /* ★ targetList 는 in_tlist 로 표시하고 걷는다. SELECT 위치의 IN/EXISTS 는
     * UNKNOWN 이 출력 셀이 되므로 F_core 밖이다(§12). 술어 위치는 안이다. */
    saved = f->in_tlist;
    f->in_tlist = true;
    foreach(lc, q->targetList)
        frag_expr((Node *) lfirst_node(TargetEntry, lc)->expr, f);
    f->in_tlist = false;

    frag_jointree((Node *) q->jointree, f);
    frag_expr(q->havingQual, f);
    frag_expr(q->limitCount, f);
    frag_expr(q->limitOffset, f);
    if (q->setOperations)
        frag_expr(q->setOperations, f);
    f->in_tlist = saved;

    f->depth--;
}

PG_FUNCTION_INFO_V1(ipguard_fragment);

/*
 * ipguard_fragment(sql text) -> text
 *   ''                       -- F_core 안
 *   'reason, reason, ...'    -- 밖. 사유는 **중첩될 수 있다**
 *   'parse error: ...'       -- 분석 실패
 */
Datum
ipguard_fragment(PG_FUNCTION_ARGS)
{
    char           *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    Ctx             ctx;
    FragCtx         f;
    List           *walked = NIL;
    char           *err = NULL;
    ListCell       *lc;
    StringInfoData  out;

    memset(&ctx, 0, sizeof(ctx));
    memset(&f, 0, sizeof(f));
    load_labels(&ctx);
    analyze_sql(sql, &ctx, &walked, &err);

    initStringInfo(&out);
    if (err)
    {
        appendStringInfo(&out, "parse error: %s", err);
        PG_RETURN_TEXT_P(cstring_to_text(out.data));
    }
    if (ctx.utility_n > 0)
        frag_add(&f, "utility statement");

    foreach(lc, walked)
        frag_query(lfirst_node(Query, lc), &f);

    foreach(lc, f.reasons)
        appendStringInfo(&out, "%s%s", out.len ? ", " : "",
                         (char *) lfirst(lc));
    PG_RETURN_TEXT_P(cstring_to_text(out.data));
}

/* ==================================================================
 * release-factorization gate — effect hyperedge -> observable sink
 *                              (명세 v0.2.1 §2, §3.5, §5.5)
 *
 * ★ 왜 그래프 path 가 아니라 **hyperedge** 인가.
 *
 * `EQ` 와 `ORD` 는 **여러 입력이 함께** 의미를 결정한다. source 별 boolean
 * 전파로 만들면 다시 per-column `order_embedding` 으로 퇴행하고, 그러면
 * 명세 §5.5 가 "충분조건일 뿐" 이라고 못박은 것을 구현이 의무로 되돌린다.
 *
 * Q9 의 의무는 `secret -> ORD` 가 아니라 이것이다:
 *
 *     ORD( key_vector = [secret, id],
 *          sources    = [secret],
 *          sink       = FINAL_ORDER(공개 id) )
 *
 * 복합키·collation·NULL ordering·공개키와의 조합을 **문맥 단위**로 판정해야
 * 한다. 그래서 노드가 key_vector 전체를 들고 다닌다.
 *
 * ★ 의무를 두 종류로 끝까지 분리한다.
 *
 *   Fidelity 의무   VAL -> CELL          scalar/aggregate commutation 필요
 *   Opacity  의무   EQ/ORD/CARD -> sink  factor-through 또는 정확한 declassification
 *
 * 원본으로 정렬·그룹핑했다는 사실은 **fidelity 에는 유리하지만 opacity
 * 인증서가 아니다.** 한 규칙으로 섞으면 안 된다(명세 §6).
 * ================================================================== */
typedef enum { EK_VAL, EK_EQ, EK_ORD, EK_CARD } EffectKind;
typedef enum { SK_CELL, SK_MULTIPLICITY, SK_ROW_COUNT,
               SK_FINAL_ORDER, SK_MEMBERSHIP } SinkKind;

static const char *effect_name[] = {"VAL", "EQ", "ORD", "CARD"};
static const char *sink_name[] = {"CELL", "MULTIPLICITY", "ROW_COUNT",
                                  "FINAL_ORDER", "MEMBERSHIP"};

/* ★ hyperedge 가 보존해야 하는 것은 **컬럼 집합이 아니라 순서 있는 표현식
 * 문맥**이다.
 *
 *   ORDER BY secret, id  와  ORDER BY id, secret 은 같은 컬럼 집합이지만
 *   의미가 다르다. 공개 유일 prefix 를 나중에 증명하려면 실제 key vector 가
 *   있어야 한다.
 *
 * 그리고 두 가지가 **건전성에 직접 걸린다**:
 *
 *   bare_var   `ORDER BY lower(secret)` 을 underlying column 으로 축약하면
 *              order_factor(m) 만 보고 통과한다. 그런데 order_factor 는
 *              cmp(x,y) = cmp(m(x),m(y)) 이지 cmp(lower(x),lower(y)) =
 *              cmp(lower(m(x)),lower(m(y))) 가 아니다. 실측으로 뚫렸다.
 *   collation  order_factor 는 **등록된 collation 에서만** 증명된 것이다.
 *              `ORDER BY secret COLLATE "C"` 는 다른 주장이다. 역시 뚫렸다.
 */
typedef struct KeyTerm
{
    bool    bare_var;           /* 표현식이 그대로 컬럼인가 */
    Oid     collation;          /* 비교·정렬 의미가 여기 달려 있다 */
    Oid     sortop;             /* ASC/DESC 가 여기 담긴다 */
    Oid     eqop;
    bool    nulls_first;
    Node   *expr;               /* canonical 문맥용 -- 의미적 모양을 적는다 */
    List   *sources;            /* ColHit * -- 이 항의 라벨된 출처 */
} KeyTerm;

/* ★ value path 도 **합성적**이어야 한다.
 *
 * 즉석 walker 로 의무를 바로 달면 중첩 질의에서 lineage 를 잃는다:
 *
 *     SELECT upper(x) FROM (SELECT lower(secret) AS x FROM t) s
 *
 * 안쪽과 바깥쪽을 따로 인증하거나 경계에서 끊긴다. 필요한 것은 **전체 합성
 * 경로**다. 그래서 표현식은 의무를 만들지 않고 **요약을 돌려준다.** */
typedef enum { RS_PUBLIC, RS_MASKED, RS_UNKNOWN } ReleaseState;

/* ★ 다중 입력 표현식은 **사슬이 아니라 proof tree** 다.
 *
 *     concat(lower(ssn), upper(birth))
 *       Apply concat
 *       +- Apply lower  +- Source ssn(mask_ssn)
 *       +- Apply upper  +- Source birth(mask_birth)
 *
 * 평탄한 [lower, upper, concat] 로는 (a) upper 가 어느 입력 mask 를 소비하는지
 * (b) concat 의 인자별 mask 가 무엇인지 (c) 두 branch 의 결과 mask 가 무엇인지를
 * **증명할 수 없다.** 각 노드가 인자 위치와 입출력 마스크를 보존해야 한다. */
typedef enum { PF_PUBLIC, PF_SOURCE, PF_APPLY, PF_AGG, PF_UNKNOWN } ProofKind;

typedef struct ExprProof
{
    ProofKind    kind;
    ColHit      *src;           /* SOURCE */
    Oid          fn;            /* APPLY / AGG */
    bool         distinct_arg;
    bool         ordered_arg;
    List        *args;          /* ExprProof * -- **인자 위치 보존** */
    const char  *ctx;
} ExprProof;

typedef struct ExprSummary
{
    List         *sources;      /* ColHit * -- 라벨된 출처 (문맥·감사용) */
    ReleaseState  state;
    ExprProof    *proof;        /* ★ 사슬이 아니라 트리 */
    const char   *ctx;
    Node         *expr;
} ExprSummary;

typedef struct EffNode
{
    EffectKind  kind;
    List       *sources;        /* ColHit * -- 라벨된 컬럼들 */
    List       *keyterms;       /* KeyTerm * -- **순서 있는** key vector */
    int         nkey;           /* key vector 전체 길이 (공개 컬럼 포함) */
    int         nkey_labeled;   /* 그중 라벨된 것 */
    Oid         fn;             /* VAL: 함수/집계 OID (0 이면 직접 투영) */
    bool        is_agg;
    bool        distinct_arg;
    bool        ordered_arg;
    /* ★ 이 effect 가 출력 행 **수**를 바꾸는가, 아니면 **어느 행인지**만
     * 바꾸는가.
     *
     *   CARD(WHERE) / EQ(DISTINCT·GROUP BY)   행 수가 달라진다
     *   ORD + LIMIT n                          항상 min(n,|입력|) 행이다.
     *                                          **어느 행인지**만 달라진다
     *
     * 이걸 구별하지 않으면 `SELECT 'x' … ORDER BY secret LIMIT 3` 이
     * ROW_COUNT 로 거부된다 -- 행 수는 공개 입력이 정하는데도. */
    bool        count_affecting;
    /* ★ keyterms 가 없는 노드(CARD 술어, VAL 함수)도 **표현식을 담아야**
     * 한다. 안 담으면 같은 컬럼의 모든 술어가 하나의 context 를 공유해서
     * `WHERE secret='a'` 인증서가 `WHERE secret=$1` 과 `WHERE secret<>'b'`
     * 까지 조용히 덮는다. */
    Node       *expr;
    ExprProof  *proof;          /* VAL 노드의 합성 **증명 트리** */
    const char *ctxdesc;        /* 사람이 읽을 문맥 */
} EffNode;

typedef struct Oblig
{
    EffNode    *node;
    SinkKind    sink;
    bool        fidelity;       /* false 면 opacity 의무 */
    bool        discharged;
    const char *how;            /* compatibility | factorization | declassification */
    char       *detail;
    /* ★ 왜 해소되지 않았는가 -- **세 사유를 섞으면 안 된다.**
     *
     * held-out v1 에서 이 셋이 한 코드(`UNMODELED_NODE`)로 뭉쳐 있어
     * "F_core 밖" 과 "F_core 안-미인증" 을 보고서에서 구분할 수 없었다.
     * 그 둘은 서로 다른 표에 들어가야 하는 값이다. */
    enum {
        FK_NONE = 0,
        FK_MISSING_CERT,        /* F_core 안인데 인증서가 없다 */
        FK_CAPABILITY_FAILS     /* 인증된 속성이 **명시적으로** 실패한다 */
    }           failkind;
} Oblig;

/* ★ 커버리지 상태 -- **미모델링 노드는 수락으로 빠지면 안 된다.**
 *
 * 노드를 안 만들면 "sink 없음" 으로 오인되어 수락된다. 그건 과거부가 아니라
 * **미탐**이다. 그래서 visitor 가 모든 노드를 처리했는지 명시적으로 들고
 * 다니고, 하나라도 못 다루면 거부한다. */
typedef enum {
    COV_FULL = 0,               /* 전부 모델링했다 */
    COV_UNMODELED,              /* 게이트가 모르는 노드를 만났다 */
    COV_OUTSIDE_FCORE           /* F_core 밖이다 -- 인증 대상이 아니다 */
} Coverage;

typedef struct GateCtx
{
    Ctx        *ctx;
    List       *obligs;         /* Oblig * */
    bool        rows_distinct;  /* 출력 행이 서로 구별되는가 */
    /* ★ 이 질의(또는 감싸는 질의)가 집계를 하는가.
     *
     * selection 의 CARD 가 **downstream aggregate 의 CELL 로 흐른다**:
     *
     *   D1: (1,10,a),(2,20,b)   D2: (1,10,b),(2,20,a)   m(a)=m(b)
     *   SELECT sum(amt) FROM t WHERE secret='a'
     *   D1 -> 10   D2 -> 20     ★ 최종 shape 는 둘 다 1행이다
     *
     * aggregate FILTER -> CELL 만으로는 이 경로를 못 잡는다. */
    bool        in_agg;
    List       *last_bag_out;   /* gate_subquery 반환 통로 */
    List       *last_cells;     /* QuerySummary.cells -- 부모로 전달 */
    List      **rte_cells;      /* [rtindex-1] -> 자식 cells (서브쿼리 경계) */
    int         nrte;
    Coverage    coverage;
    const char *uncovered;      /* 무엇을 못 다뤘는가 */
} GateCtx;

static void gate_query(GateCtx *g, Query *q, bool toplevel);
static List *gate_subquery(GateCtx *g, Query *sub);
static void gate_setop(GateCtx *g, Query *q, Node *n, List **bag_out);

/* jointree 의 **모든** qual 을 모은다. FromExpr->quals 만 보면 JoinExpr 의
 * ON 절(inner join·semi-join)을 통째로 놓친다. */
static void
gate_collect_quals(Node *n, List **quals)
{
    if (n == NULL)
        return;
    if (IsA(n, FromExpr))
    {
        FromExpr *f = (FromExpr *) n;
        ListCell *lc;

        if (f->quals)
            *quals = lappend(*quals, f->quals);
        foreach(lc, f->fromlist)
            gate_collect_quals((Node *) lfirst(lc), quals);
    }
    else if (IsA(n, JoinExpr))
    {
        JoinExpr *j = (JoinExpr *) n;

        if (j->quals)
            *quals = lappend(*quals, j->quals);
        gate_collect_quals(j->larg, quals);
        gate_collect_quals(j->rarg, quals);
    }
}

static void
mark_uncovered(GateCtx *g, const char *what)
{
    if (g->coverage == COV_FULL)
    {
        g->coverage = COV_UNMODELED;
        g->uncovered = what;
    }
}

static int ipguard_gate = 0;    /* 0=legacy 1=release */
static const struct config_enum_entry gate_options[] = {
    {"legacy", 0, false}, {"release", 1, false}, {NULL, 0, false}
};

/* 표현식이 건드리는 **라벨된** 컬럼들을 모은다.
 * 기존 cols 수집 경로를 그대로 쓴다 -- 별도 해석기를 만들면 두 경로가
 * 어긋나고, 이 프로젝트에서 그게 반복된 실패 양식이다. */
static List *
collect_sources(Ctx *ctx, Node *expr)
{
    List   *saved_cols = ctx->cols;
    List  **saved_sink = ctx->sink;
    List   *scratch = NIL;
    bool    saved_collect = ctx->collect;
    List   *got;

    ctx->cols = NIL;
    ctx->sink = &scratch;
    ctx->collect = true;
    walk_expr(expr, ctx);
    got = ctx->cols;
    ctx->cols = saved_cols;
    ctx->sink = saved_sink;
    ctx->collect = saved_collect;
    if (got != NIL)
        ctx->gate_touched = true;
    return got;
}

static EffNode *
mk_node(EffectKind k, List *sources, int nkey, const char *desc)
{
    EffNode *n = palloc0(sizeof(EffNode));

    n->kind = k;
    n->sources = sources;
    n->nkey = nkey;
    n->nkey_labeled = list_length(sources);
    n->ctxdesc = desc;
    /* CARD·EQ 는 행 수를 바꾼다. ORD 는 어느 행인지만 바꾼다. */
    n->count_affecting = (k != EK_ORD);
    return n;
}

/* 라벨된 출처를 가진 key term 중 **건전성 전제를 깨는 것**을 찾는다.
 * 없으면 NULL. 있으면 사람이 읽을 사유를 돌려준다. */
static const char *
keyterm_blocker(EffNode *n)
{
    ListCell *lc;

    foreach(lc, n->keyterms)
    {
        KeyTerm *kt = (KeyTerm *) lfirst(lc);

        if (kt->sources == NIL)
            continue;           /* 공개 항은 factor-through 를 막지 않는다 */
        if (!kt->bare_var)
            return "키 항이 파생 표현식이다 -- order/equality_factor 는 "
                   "컬럼에 대한 주장이지 그 위의 함수에 대한 주장이 아니다";
    }
    return NULL;
}

static void
add_oblig(GateCtx *g, EffNode *n, SinkKind s, bool fidelity, const char *detail)
{
    Oblig    *o;
    ListCell *lc;

    if (n->sources == NIL)
        return;                 /* 라벨된 source 가 없으면 의무가 없다 */
    /* ★ 같은 (노드, sink) 를 두 번 만들지 않는다. GROUP BY 노드는 집계
     * CELL 을 위해 bag_in 에, 출력 shape 를 위해 bag_out 에 둘 다 들어가고
     * 그 둘이 합쳐지므로 중복이 생긴다. 중복 의무는 판정을 바꾸지는 않지만
     * 사유 목록과 집계 수치를 부풀린다. */
    foreach(lc, g->obligs)
    {
        Oblig *x = (Oblig *) lfirst(lc);

        if (x->node == n && x->sink == s && x->fidelity == fidelity)
            return;
    }
    o = palloc0(sizeof(Oblig));
    o->node = n;
    o->sink = s;
    o->fidelity = fidelity;
    o->detail = pstrdup(detail ? detail : "");
    g->obligs = lappend(g->obligs, o);
}

/*
 * 출력 행이 서로 **구별되는가**.
 *
 * ★ 이것이 effect->sink 소거의 핵심이다. 모든 출력 행이 관찰상 같으면
 *   순서를 바꾸든 어느 행을 고르든 결과 bag 이 같다. 그러면 `ORD` 가 있어도
 *   FINAL_ORDER / MEMBERSHIP sink 가 **관찰되지 않는다**(Q10).
 *
 *   SELECT 'x' FROM t ORDER BY secret            -> 구별 불가
 *   SELECT 'x' FROM t ORDER BY secret, id LIMIT 3 -> 구별 불가.
 *        정렬키가 전순서라도 **선택된 row identity 가 투영에서 사라진다.**
 *        반환 건수도 min(3, |t|) 로 공개 입력 multiplicity 가 정한다.
 *   SELECT id  FROM t ORDER BY secret, id         -> 구별 가능 (id 가 sink)
 *
 * 보수적으로 판정한다: 증명할 수 있을 때만 "구별 불가". 즉 non-resjunk
 * 타깃이 **전부 Var 를 포함하지 않을 때만** false 를 돌려준다.
 */
static bool
tle_has_var(Node *n, void *ignored)
{
    if (n == NULL)
        return false;
    if (IsA(n, Var))
        return true;
    if (IsA(n, Query))
        return true;            /* 서브쿼리 결과는 행마다 다를 수 있다 */
    return expression_tree_walker(n, tle_has_var, ignored);
}

static bool
rows_distinguishable(Query *q)
{
    ListCell *lc;

    foreach(lc, q->targetList)
    {
        TargetEntry *te = lfirst_node(TargetEntry, lc);

        if (te->resjunk)
            continue;           /* ★ resjunk 는 클라이언트가 못 본다 */
        if (tle_has_var((Node *) te->expr, NULL))
            return true;
    }
    return false;
}

/* ==================================================================
 * value path 의 transfer function
 *
 * 표현식은 **의무를 만들지 않고 요약을 돌려준다.** 최종 observable target
 * 에서만 VAL -> CELL fidelity 의무를 발행하고, 중간 query level 은 cells[]
 * 를 부모에게 전달한다. 그래야 질의 경계를 넘는 합성이 잡힌다.
 *
 * ★ 라벨된 source 를 가진 **미처리 노드는 무조건 UNMODELED_EXPR** 이다.
 *   "모르는 것은 안전" 이 아니라 "모르는 것은 거부" 여야 한다.
 * ================================================================== */
static ExprSummary *summarize_expr(GateCtx *g, Node *n);

static ExprSummary *
mk_sum(void)
{
    ExprSummary *e = palloc0(sizeof(ExprSummary));

    e->state = RS_PUBLIC;
    return e;
}

static void
sum_merge(ExprSummary *dst, ExprSummary *src)
{
    ListCell *lc;

    if (src == NULL)
        return;
    foreach(lc, src->sources)
    {
        ColHit   *h = (ColHit *) lfirst(lc);
        ListCell *l2;
        bool      dup = false;

        foreach(l2, dst->sources)
        {
            ColHit *x = (ColHit *) lfirst(l2);

            if (x->relid == h->relid && x->attno == h->attno)
            { dup = true; break; }
        }
        if (!dup)
            dst->sources = lappend(dst->sources, h);
    }

    /* 상태는 **가장 약한 것**으로 -- UNKNOWN 이 하나라도 있으면 UNKNOWN */
    if (src->state == RS_UNKNOWN)
        dst->state = RS_UNKNOWN;
    else if (src->state == RS_MASKED && dst->state == RS_PUBLIC)
        dst->state = RS_MASKED;
}

static ExprProof *
mk_proof(ProofKind k, const char *ctx)
{
    ExprProof *p = palloc0(sizeof(ExprProof));

    p->kind = k;
    p->ctx = ctx;
    return p;
}

/* Aggref 의 aggdistinct/aggorder 를 키 벡터로 읽으려면 아래가 먼저 필요하다. */
static List *keyvec_sources(GateCtx *g, List *clause, List *tlist,
                            int *nkey, List **terms);

/* 인자들을 **순서를 보존해** 요약하고, proof 트리의 자식으로 단다. */
static ExprSummary *
sum_args(GateCtx *g, List *args, const char *ctx, ProofKind pk, Oid fn,
         bool dist, bool ord)
{
    ExprSummary *e = mk_sum();
    ExprProof   *pf = mk_proof(pk, ctx);
    ListCell    *lc;

    e->ctx = ctx;
    pf->fn = fn;
    pf->distinct_arg = dist;
    pf->ordered_arg = ord;
    foreach(lc, args)
    {
        ExprSummary *a = summarize_expr(g, (Node *) lfirst(lc));

        sum_merge(e, a);
        pf->args = lappend(pf->args,
                           a->proof ? a->proof : mk_proof(PF_PUBLIC, "public"));
    }
    e->proof = pf;
    return e;
}

/* 서브쿼리 출력 Var -> 자식 cells[attno] 를 **그대로 전달** */
static ExprSummary *
sum_subquery_var(GateCtx *g, Var *v)
{
    List *cells;

    if (v->varlevelsup != 0 || v->varno < 1 || v->varno > g->nrte)
        return NULL;
    cells = g->rte_cells ? g->rte_cells[v->varno - 1] : NIL;
    if (cells == NIL || v->varattno < 1 || v->varattno > list_length(cells))
        return NULL;
    return (ExprSummary *) list_nth(cells, v->varattno - 1);
}

static ExprSummary *
summarize_expr(GateCtx *g, Node *n)
{
    ExprSummary *e;

    if (n == NULL)
        return mk_sum();
    check_stack_depth();

    switch (nodeTag(n))
    {
        case T_Const:
        case T_Param:
        case T_CaseTestExpr:
        case T_CoerceToDomainValue:
        case T_SetToDefault:
            e = mk_sum();
            e->proof = mk_proof(PF_PUBLIC, "public");
            return e;

        case T_Var:
            {
                /* 서브쿼리 출력이면 자식 요약을 그대로 물려받는다 */
                ExprSummary *child = sum_subquery_var(g, (Var *) n);

                if (child != NULL)
                {
                    e = mk_sum();
                    e->ctx = "subquery output";
                    sum_merge(e, child);
                    /* ★ **증명 트리를 그대로 물려받는다.** 이걸 빼면 자식의
                     * Apply 노드가 사라져 PUBLIC 으로 취급되고, 인증서를
                     * 지워도 통과한다 -- 실측으로 잡았다. */
                    e->proof = child->proof;
                    return e;
                }
                e = mk_sum();
                e->sources = collect_sources(g->ctx, n);
                e->state = (e->sources != NIL) ? RS_MASKED : RS_PUBLIC;
                e->ctx = "column";
                e->expr = n;
                if (e->sources != NIL)
                {
                    e->proof = mk_proof(PF_SOURCE, "column");
                    e->proof->src = (ColHit *) linitial(e->sources);
                }
                else
                    e->proof = mk_proof(PF_PUBLIC, "public column");
                return e;
            }

        case T_FuncExpr:
            return sum_args(g, ((FuncExpr *) n)->args, "scalar function",
                            PF_APPLY, ((FuncExpr *) n)->funcid, false, false);
        case T_OpExpr:
        case T_DistinctExpr:
        case T_NullIfExpr:
            return sum_args(g, ((OpExpr *) n)->args, "operator",
                            PF_APPLY, ((OpExpr *) n)->opfuncid, false, false);
        case T_RelabelType:
            return summarize_expr(g, (Node *) ((RelabelType *) n)->arg);
        case T_CollateExpr:
            return summarize_expr(g, (Node *) ((CollateExpr *) n)->arg);
        case T_CoerceViaIO:
            e = sum_args(g, list_make1(((CoerceViaIO *) n)->arg),
                         "cast", PF_APPLY, InvalidOid, false, false);
            if (e->sources != NIL)
            {
                /* 캐스트 함수를 특정할 수 없다 -- 인증 불가 */
                e->state = RS_UNKNOWN;
                e->proof->kind = PF_UNKNOWN;
                e->ctx = "cast (compatibility 미등록)";
            }
            return e;

        case T_CaseExpr:
            {
                /* ★ 조건과 **모든 branch** 의 source 를 합친다.
                 * `CASE WHEN secret='a' THEN grade ELSE dept END` 는 행 수를
                 * 바꾸지 않지만 **출력 셀을 직접 바꾼다** -- CARD 가 아니라
                 * control lineage -> VAL 이다. 값 변환이 아니므로 commutation
                 * 인증서로 해소되지 않는다. UNKNOWN 으로 둔다. */
                CaseExpr *c = (CaseExpr *) n;
                ListCell *lc;

                e = mk_sum();
                e->ctx = "CASE (control lineage)";
                sum_merge(e, summarize_expr(g, (Node *) c->arg));
                foreach(lc, c->args)
                {
                    CaseWhen *w = lfirst_node(CaseWhen, lc);

                    sum_merge(e, summarize_expr(g, (Node *) w->expr));
                    sum_merge(e, summarize_expr(g, (Node *) w->result));
                }
                sum_merge(e, summarize_expr(g, (Node *) c->defresult));
                if (e->sources != NIL)
                {
                    e->state = RS_UNKNOWN;
                    e->proof = mk_proof(PF_UNKNOWN, "CASE (control lineage)");
                }
                else
                    e->proof = mk_proof(PF_PUBLIC, "CASE");
                return e;
            }
        case T_CoalesceExpr:
            e = sum_args(g, ((CoalesceExpr *) n)->args, "COALESCE",
                         PF_APPLY, InvalidOid, false, false);
            if (e->sources != NIL)
            {
                e->state = RS_UNKNOWN;
                e->proof->kind = PF_UNKNOWN;
            }
            return e;

        /* ★ Aggref·SortGroupClause 의 인자는 TargetEntry 로 **감싸여** 있다.
         *
         * 이 case 가 없으면 `count(ssn)` 의 인자가 default 분기로 떨어져
         * `UNMODELED_EXPR` 이 된다 -- 집계 경로 전체가 사실상 미구현이었다.
         * held-out v1 에서 라벨 집계 50건이 전부 여기서 걸렸다. */
        case T_TargetEntry:
            return summarize_expr(g, (Node *) ((TargetEntry *) n)->expr);

        case T_Aggref:
            {
                Aggref      *a = (Aggref *) n;
                ExprSummary *f;
                List        *ksrc, *kts;
                int          knk;

                /* ---- ordered-set / hypothetical 은 F_core **밖** -------- */
                if (a->aggkind != AGGKIND_NORMAL || a->aggdirectargs != NIL)
                {
                    List *src = collect_sources(g->ctx, n);

                    e = mk_sum();
                    e->sources = src;
                    e->expr = n;
                    e->ctx = "ordered-set/hypothetical aggregate";
                    e->proof = mk_proof(src != NIL ? PF_UNKNOWN : PF_PUBLIC,
                                        "ordered-set/hypothetical aggregate");
                    if (src != NIL)
                    {
                        e->state = RS_UNKNOWN;
                        g->coverage = COV_OUTSIDE_FCORE;
                        if (g->uncovered == NULL)
                            g->uncovered =
                                "ordered-set/hypothetical aggregate";
                    }
                    return e;
                }

                /* ---- 일반 argument: VAL -> CELL + aggregate compatibility */
                e = sum_args(g, a->args, "aggregate", PF_AGG, a->aggfnoid,
                             a->aggdistinct != NIL, a->aggorder != NIL);

                /* ---- aggdistinct: 키 벡터의 EQ -> 이 집계의 CELL -------
                 *
                 * `count(DISTINCT secret)` 은 마스킹된 컬럼 위에서 **등가 기반
                 * 중복제거**를 한다. 어느 값이 같은 것으로 접히는지가 셀을
                 * 바꾼다. 질의 수준 DISTINCT 와 정확히 같은 의무이고,
                 * SortGroupClause 의 eqop·collation·NULL 파티션 전제도 같다.
                 * 출력 bag 의 모양은 바뀌지 않으므로 sink 는 CELL 뿐이다. */
                ksrc = keyvec_sources(g, a->aggdistinct, a->args, &knk, &kts);
                if (ksrc != NIL)
                {
                    EffNode *dn = mk_node(EK_EQ, ksrc, knk,
                                          "aggregate DISTINCT key vector");

                    dn->keyterms = kts;
                    dn->expr = n;
                    add_oblig(g, dn, SK_CELL, false,
                              "어느 값이 같은 것으로 접히는지가 집계 셀을 바꾼다");
                }

                /* ---- aggorder: 키 벡터의 ORD -> 이 집계의 CELL ---------
                 *
                 * `string_agg(x, ',' ORDER BY secret)` 처럼 집계 **입력 순서**가
                 * 셀 값으로 나간다. 순서는 행 수를 바꾸지 않으므로 CELL 뿐이다. */
                ksrc = keyvec_sources(g, a->aggorder, a->args, &knk, &kts);
                if (ksrc != NIL)
                {
                    EffNode *on = mk_node(EK_ORD, ksrc, knk,
                                          "aggregate ORDER BY key vector");

                    on->keyterms = kts;
                    on->expr = n;
                    add_oblig(g, on, SK_CELL, false,
                              "집계 입력 순서가 셀 값으로 나간다");
                }

                /* ---- aggfilter: CARD -> 이 집계의 CELL ----------------- */
                f = summarize_expr(g, (Node *) a->aggfilter);
                if (f->sources != NIL)
                {
                    EffNode *fn2 = mk_node(EK_CARD, f->sources, 1,
                                           "aggregate FILTER");

                    fn2->expr = (Node *) a->aggfilter;
                    add_oblig(g, fn2, SK_CELL, false,
                              "FILTER 가 어느 행을 집계에 넣을지 정한다");
                }
                /* `count(*)` 은 args 가 NIL 이라 VAL source 가 없다 -- 위
                 * sum_args 가 자동으로 공개 요약을 돌려준다. 별도 규칙 없음. */
                return e;
            }
        case T_WindowFunc:
            return sum_args(g, ((WindowFunc *) n)->args, "window function",
                            PF_AGG, ((WindowFunc *) n)->winfnoid,
                            false, false);

        case T_SubLink:
            {
                SubLink *sl = (SubLink *) n;

                e = mk_sum();
                e->ctx = "sublink";
                if (sl->subselect && IsA(sl->subselect, Query) &&
                    g->ctx->sp < MAX_STACK)
                {
                    g->ctx->stack[g->ctx->sp++] = (Query *) sl->subselect;
                    (void) gate_subquery(g, (Query *) sl->subselect);
                    g->ctx->sp--;
                }
                sum_merge(e, summarize_expr(g, sl->testexpr));
                if (e->proof == NULL)
                    e->proof = mk_proof(e->sources != NIL ? PF_UNKNOWN
                                                         : PF_PUBLIC, "sublink");
                return e;
            }

        default:
            {
                /* ★ 모르는 노드. 라벨된 source 가 있으면 **무조건 거부**한다. */
                List *src = collect_sources(g->ctx, n);

                e = mk_sum();
                e->sources = src;
                e->ctx = "unmodeled expression";
                e->expr = n;
                e->proof = mk_proof(src != NIL ? PF_UNKNOWN : PF_PUBLIC,
                                    "unmodeled expression");
                if (src != NIL)
                {
                    e->state = RS_UNKNOWN;
                    mark_uncovered(g, "UNMODELED_EXPR");
                }
                return e;
            }
    }
}

/* ------------------------------------------------------------------
 * 집합연산 -- 노드를 안 만들면 **미탐**이다
 *
 *   UNION ALL                   피연산자만 재귀. 값 비교를 하지 않는다
 *   UNION / INTERSECT / EXCEPT   중복 제거 = 값 비교 -> 출력 bag 을 바꾼다
 *
 * 결과는 bag_out 으로 흐르므로 바깥이 집계하면 CELL 까지 간다.
 * ------------------------------------------------------------------ */
static void
gate_setop(GateCtx *g, Query *q, Node *n, List **bag_out)
{
    if (n == NULL)
        return;
    if (IsA(n, RangeTblRef))
        return;                 /* 팔 자체는 rtable 순회에서 본다 */
    if (!IsA(n, SetOperationStmt))
    {
        mark_uncovered(g, "set-operation node");
        return;
    }
    {
        SetOperationStmt *so = (SetOperationStmt *) n;
        bool  compares = (!so->all || so->op != SETOP_UNION);

        if (compares)
        {
            List     *arms = NIL;
            List     *src = NIL;
            List     *kts = NIL;
            ListCell *lc;
            ListCell *gc = list_head(so->groupClauses);
            ListCell *cc = list_head(so->colCollations);
            int       nkey = 0;
            EffNode  *e;

            collect_setop_arms(q, (Node *) so, &arms);
            foreach(lc, arms)
            {
                Query    *arm = (Query *) lfirst(lc);
                ListCell *l2;

                if (g->ctx->sp >= MAX_STACK)
                {
                    mark_uncovered(g, "set-operation depth");
                    return;
                }
                g->ctx->stack[g->ctx->sp++] = arm;
                foreach(l2, arm->targetList)
                {
                    TargetEntry *te = lfirst_node(TargetEntry, l2);
                    KeyTerm     *kt;

                    if (te->resjunk)
                        continue;
                    kt = palloc0(sizeof(KeyTerm));
                    nkey++;
                    kt->sources = collect_sources(g->ctx, (Node *) te->expr);
                    kt->bare_var = IsA(te->expr, Var);
                    kt->expr = (Node *) te->expr;
                    kt->collation = cc ? lfirst_oid(cc) : InvalidOid;
                    if (gc)
                    {
                        SortGroupClause *sg = lfirst_node(SortGroupClause, gc);

                        kt->eqop = sg->eqop;
                        kt->sortop = sg->sortop;
                        gc = lnext(so->groupClauses, gc);
                    }
                    if (cc)
                        cc = lnext(so->colCollations, cc);
                    kts = lappend(kts, kt);
                    src = list_concat(src, list_copy(kt->sources));
                }
                g->ctx->sp--;
                if (lc != list_head(arms))
                    kts = list_truncate(kts, list_length(so->groupClauses));
            }
            if (src != NIL)
            {
                e = mk_node(EK_EQ, src, nkey,
                            so->op == SETOP_UNION ? "UNION (non-ALL)"
                            : so->op == SETOP_INTERSECT ? "INTERSECT"
                            : "EXCEPT");
                e->keyterms = list_truncate(kts,
                                            list_length(so->groupClauses));
                *bag_out = lappend(*bag_out, e);
            }
        }
        gate_setop(g, q, so->larg, bag_out);
        gate_setop(g, q, so->rarg, bag_out);
    }
}

/* sortClause / groupClause / distinctClause 의 **키 벡터 전체**를 본다. */
static List *
keyvec_sources(GateCtx *g, List *clause, List *tlist, int *nkey, List **terms)
{
    ListCell *lc;
    List     *src = NIL;

    *nkey = 0;
    if (terms)
        *terms = NIL;
    foreach(lc, clause)
    {
        SortGroupClause *sgc = lfirst_node(SortGroupClause, lc);
        TargetEntry     *te = get_sortgroupclause_tle(sgc, tlist);
        KeyTerm         *kt;

        (*nkey)++;
        if (te == NULL)
        {
            mark_uncovered(g, "sort/group clause without target entry");
            continue;
        }
        kt = palloc0(sizeof(KeyTerm));
        kt->sources = collect_sources(g->ctx, (Node *) te->expr);
        kt->bare_var = IsA(te->expr, Var);
        kt->expr = (Node *) te->expr;
        kt->collation = exprCollation((Node *) te->expr);
        kt->sortop = sgc->sortop;
        kt->eqop = sgc->eqop;
        kt->nulls_first = sgc->nulls_first;
        if (terms)
            *terms = lappend(*terms, kt);
        src = list_concat(src, list_copy(kt->sources));
    }
    return src;
}

static void
gate_query(GateCtx *g, Query *q, bool toplevel)
{
    ListCell *lc;
    List     *src;
    int       nkey;
    EffNode  *n;
    List     *kt_d = NIL, *kt_g = NIL, *kt_s = NIL, *kt_p = NIL, *kt_o = NIL;
    bool      saved_agg;
    /* ★ 연산자별 transfer function.
     *
     * 구문마다 sink 를 손으로 열거하면 **계속 빠진다** -- 실측으로 다섯 번
     * 연속 빠졌다(EQ->CELL, ORD->MULTIPLICITY, ORD->outer CELL,
     * HAVING->outer CELL, setop->outer CELL). 대신 세 요약을 들고 다닌다:
     *
     *   bag_in    집계에 **들어가는** 행 집합을 바꾸는 effect
     *   bag_out   이 질의의 **출력** bag(membership/multiplicity/row count)
     *   ord       이 질의의 **출력 순서**
     *
     * 소비 문맥이 sink 를 정한다. 서브쿼리의 bag_out 이 바깥 bag_in 으로
     * 흐르므로 질의 경계를 넘는 합성이 자동으로 잡힌다. */
    List     *bag_in = NIL;     /* WHERE/JOIN CARD + 자식 bag_out */
    List     *bag_out = NIL;    /* 이 질의의 출력 bag 을 바꾸는 것 */
    List     *ord = NIL;        /* 이 질의의 출력 순서를 바꾸는 것 */
    List     *cells = NIL;      /* 출력 컬럼별 ExprSummary -- 부모로 전달 */
    bool      has_agg, scalar_agg;
    List    **saved_rte_cells = g->rte_cells;
    int       saved_nrte = g->nrte;

    if (q == NULL)
        return;
    saved_agg = g->in_agg;
    g->in_agg = g->in_agg || q->hasAggs;
    has_agg = q->hasAggs;
    g->nrte = list_length(q->rtable);
    g->rte_cells = g->nrte > 0
                   ? (List **) palloc0(sizeof(List *) * g->nrte) : NULL;
    scalar_agg = (has_agg && q->groupClause == NIL &&
                  q->groupingSets == NIL && q->setOperations == NULL);

    /* ---- 자식 먼저: 서브쿼리의 bag_out 이 내 bag_in 이다 ------------- */
    foreach(lc, q->rtable)
    {
        RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);

        switch (rte->rtekind)
        {
            case RTE_SUBQUERY:
                if (rte->subquery && g->ctx->sp < MAX_STACK)
                {
                    List *child;
                    int   idx = foreach_current_index(lc);

                    g->ctx->stack[g->ctx->sp++] = rte->subquery;
                    child = gate_subquery(g, rte->subquery);
                    g->ctx->sp--;
                    bag_in = list_concat(bag_in, child);
                    /* ★ 자식 cells 를 이 레벨의 Var 해석에 쓴다 --
                     * 질의 경계를 넘는 value 합성이 여기서 이어진다. */
                    if (g->rte_cells)
                        g->rte_cells[idx] = g->last_cells;
                }
                else if (rte->subquery)
                    mark_uncovered(g, "subquery depth");
                break;
            case RTE_RELATION:
            case RTE_JOIN:
            case RTE_VALUES:
            case RTE_CTE:
                break;
            default:
                mark_uncovered(g, "unsupported range table entry");
                break;
        }
    }
    foreach(lc, q->cteList)
    {
        CommonTableExpr *cte = lfirst_node(CommonTableExpr, lc);

        if (cte->ctequery && IsA(cte->ctequery, Query) &&
            g->ctx->sp < MAX_STACK)
        {
            g->ctx->stack[g->ctx->sp++] = (Query *) cte->ctequery;
            bag_in = list_concat(bag_in,
                                 gate_subquery(g, (Query *) cte->ctequery));
            g->ctx->sp--;
        }
    }

    /* ---- CARD: WHERE / JOIN ON / semi-join  ->  bag_in --------------- */
    {
        List *quals = NIL;

        gate_collect_quals((Node *) q->jointree, &quals);
        foreach(lc, quals)
        {
            Node *qual = (Node *) lfirst(lc);

            src = collect_sources(g->ctx, qual);
            if (src == NIL)
                continue;
            n = mk_node(EK_CARD, src, 1, "WHERE/JOIN predicate");
            n->expr = qual;
            bag_in = lappend(bag_in, n);
        }
    }
    /* ---- EQ: GROUP BY  ->  집계 CELL 과 출력 bag 둘 다 --------------- */
    src = keyvec_sources(g, q->groupClause, q->targetList, &nkey, &kt_g);
    if (src != NIL)
    {
        n = mk_node(EK_EQ, src, nkey, "GROUP BY key vector");
        n->keyterms = kt_g;
        bag_out = lappend(bag_out, n);
        /* ★ 어느 공개 행이 같은 그룹에 들어가는지가 **집계 셀**을 바꾼다.
         * 그룹 **수**가 같아도 셀 값이 다를 수 있다 -- ROW_COUNT 만 보면
         * 놓친다(실측 witness W1). */
        if (has_agg)
            bag_in = lappend(bag_in, n);
    }
    /* ---- CARD: HAVING  ->  출력 bag (집계 **뒤에** 거른다) ----------- */
    if (q->havingQual)
    {
        src = collect_sources(g->ctx, q->havingQual);
        if (src != NIL)
        {
            n = mk_node(EK_CARD, src, 1, "HAVING predicate");
            n->expr = q->havingQual;
            bag_out = lappend(bag_out, n);
        }
    }
    /* ---- EQ: DISTINCT  ->  출력 bag --------------------------------- */
    src = keyvec_sources(g, q->distinctClause, q->targetList, &nkey, &kt_d);
    if (src != NIL)
    {
        n = mk_node(EK_EQ, src, nkey, "DISTINCT key vector");
        n->keyterms = kt_d;
        bag_out = lappend(bag_out, n);
    }
    /* ---- 집합연산  ->  출력 bag -------------------------------------- */
    if (q->setOperations)
        gate_setop(g, q, q->setOperations, &bag_out);

    /* ---- ORD: 최상위 ORDER BY --------------------------------------- */
    src = keyvec_sources(g, q->sortClause, q->targetList, &nkey, &kt_s);
    if (src != NIL)
    {
        n = mk_node(EK_ORD, src, nkey, "ORDER BY key vector");
        n->keyterms = kt_s;
        ord = lappend(ord, n);
        /* ★ LIMIT/OFFSET 은 **순서를 bag 으로 바꾼다.** 어느 행이 뽑히는지가
         * 순서로 정해지므로 membership·multiplicity·(집계면) cell 이 전부
         * 그 순서에 의존한다. */
        if (q->limitCount || q->limitOffset)
            bag_out = lappend(bag_out, n);
    }
    /* ---- 윈도우 절 (F_core 밖이지만 effect 는 만든다) ---------------- */
    foreach(lc, q->windowClause)
    {
        WindowClause *w = lfirst_node(WindowClause, lc);

        src = keyvec_sources(g, w->partitionClause, q->targetList, &nkey, &kt_p);
        if (src != NIL)
        {
            n = mk_node(EK_EQ, src, nkey, "window PARTITION BY");
            n->keyterms = kt_p;
            add_oblig(g, n, SK_CELL, false, "파티션 경계가 셀에 반영된다");
        }
        src = keyvec_sources(g, w->orderClause, q->targetList, &nkey, &kt_o);
        if (src != NIL)
        {
            n = mk_node(EK_ORD, src, nkey, "window ORDER BY");
            n->keyterms = kt_o;
            add_oblig(g, n, SK_CELL, false, "순위가 셀로 나간다");
        }
    }
    /* ---- VAL: 타깃 목록 -> cells[] ----------------------------------
     *
     * ★ 여기서 의무를 만들지 않는다. 요약만 만들어 부모로 넘긴다.
     *   최종 observable target 에서만 VAL -> CELL 을 발행한다. */
    foreach(lc, q->targetList)
    {
        TargetEntry *te = lfirst_node(TargetEntry, lc);
        ExprSummary *es;

        if (te->resjunk)
        {
            /* resjunk 는 클라이언트가 못 본다. 다만 그 안의 서브쿼리·집계
             * FILTER 같은 구조 효과는 봐야 하므로 요약은 돌린다. */
            (void) summarize_expr(g, (Node *) te->expr);
            continue;
        }
        es = summarize_expr(g, (Node *) te->expr);
        es->expr = (Node *) te->expr;
        cells = lappend(cells, es);
    }

    /* ================================================================
     * sink 방출 -- **소비 문맥**이 정한다
     * ================================================================ */
    /* (1) bag_in -> 집계 CELL. 최종 shape 가 1행이어도 그 한 행의 값이 바뀐다. */
    if (has_agg)
        foreach(lc, bag_in)
            add_oblig(g, (EffNode *) lfirst(lc), SK_CELL, false,
                      "★ 집계에 들어가는 행 집합이 결과 셀로 요약된다");
    /* ★ 집계가 있어도 **GROUP BY 가 있으면** 선택이 그룹을 통째로 없앨 수
     * 있어 출력 행 수가 달라진다. 스칼라 집계일 때만 출력이 1행 고정이다. */
    if (!scalar_agg)
        bag_out = list_concat(bag_out, bag_in);

    /* (2) bag_out -> shape sink.
     *
     * ★ 스칼라 집계면 최종 shape 가 **항상 1행**이라 shape sink 가 없다.
     *   내부 선택 카디널리티는 CARD **effect** 이지 결과 shape 의 ROW_COUNT
     *   **sink** 가 아니다. */
    if (!scalar_agg)
        foreach(lc, bag_out)
        {
            EffNode *e = (EffNode *) lfirst(lc);

            if (e->count_affecting)
            {
                /* 행 **수**가 달라진다 -- 행이 구별되지 않아도 관찰된다 */
                add_oblig(g, e, SK_ROW_COUNT, false, "출력 행 수가 달라진다");
                add_oblig(g, e, SK_MULTIPLICITY, false,
                          "각 관찰 가능한 행의 반복 횟수가 달라진다");
            }
            /* ★ **어느 행인지**만 바뀌는 경우(ORD+LIMIT)는 행이 구별될 때만
             * 관찰된다. 모든 출력이 같으면 어느 행을 뽑든 결과 bag 이 같다. */
            if (g->rows_distinct)
            {
                if (!e->count_affecting)
                    add_oblig(g, e, SK_MULTIPLICITY, false,
                              "선택된 행이 달라져 관찰 bag 의 다중도가 바뀐다");
                add_oblig(g, e, SK_MEMBERSHIP, false,
                          "어떤 구별 가능한 행이 존재하는지가 달라진다");
            }
        }
    /* (2.5) ★ **최종 observable target 에서만** VAL -> CELL 을 발행한다.
     *
     * 중간 레벨은 cells[] 를 부모로 넘길 뿐이다. 그래야
     *   SELECT upper(x) FROM (SELECT lower(secret) AS x FROM t) s
     * 가 [lower, upper] 합성 경로 하나로 인증된다. */
    if (toplevel)
        foreach(lc, cells)
        {
            ExprSummary *es = (ExprSummary *) lfirst(lc);
            EffNode     *v;

            if (es->sources == NIL)
                continue;                   /* 공개 값 -- 의무 없다 */
            v = mk_node(EK_VAL, es->sources, 1,
                        es->ctx ? es->ctx : "output cell");
            v->expr = es->expr;
            v->proof = es->proof;
            /* ★ bare 컬럼(PF_SOURCE)도 의무를 만든다. commutation 은 없지만
             * MASK_APPLY baseline(determinism ∧ total ∧ 지문)은 봐야 한다 --
             * 안 그러면 미등록 UDF 나 변경된 마스크가 bare output 으로
             * 인증 없이 흘러나간다. */
            add_oblig(g, v, SK_CELL, true,
                      es->state == RS_UNKNOWN
                      ? "값 경로가 인증되지 않았다"
                      : "값이 출력 셀로 나간다");
        }

    /* (3) ord -> 최종 순서. 최상위에서만, 그리고 행이 구별될 때만. */
    if (toplevel && g->rows_distinct)
        foreach(lc, ord)
            add_oblig(g, (EffNode *) lfirst(lc), SK_FINAL_ORDER, false,
                      "최종 순서가 공개 컬럼으로 관찰된다");

    g->in_agg = saved_agg;
    g->rte_cells = saved_rte_cells;
    g->nrte = saved_nrte;
    /* 이 질의의 출력 bag·cells 를 호출자에게 넘긴다 */
    g->last_bag_out = scalar_agg ? NIL : bag_out;
    g->last_cells = cells;
}

/* 서브쿼리를 걷고 그 **출력 bag** 을 돌려준다. 바깥 질의의 bag_in 이 된다. */
static List *
gate_subquery(GateCtx *g, Query *sub)
{
    g->last_bag_out = NIL;
    g->last_cells = NIL;
    gate_query(g, sub, false);
    return g->last_bag_out;
}

/* ------------------------------------------------------------------
 * 의무 해소 -- 레지스트리와 declassification 인증서를 본다.
 *
 * ★ 게이트는 레지스트리 **표를 직접 읽지 않는다.** 조회 API 만 본다.
 *   표를 읽으면 지문 재계산 검사를 건너뛰게 된다.
 * ------------------------------------------------------------------ */
static char *
spi_one(const char *sql)
{
    char *r = NULL;

    if (SPI_execute(sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
    {
        bool isnull;
        Datum d = SPI_getbinval(SPI_tuptable->vals[0],
                                SPI_tuptable->tupdesc, 1, &isnull);

        if (!isnull)
            r = MemoryContextStrdup(TopTransactionContext,
                                    TextDatumGetCString(d));
    }
    return r;
}

/* 이 컬럼에 적용되는 MaskInstance 의 claim 을 묻는다.
 *
 * ★ collation 까지 맞춰서 찾는다. order_factor 는 **등록된 collation 에서만**
 *   증명된 주장이다. `ORDER BY secret COLLATE "C"` 에 기본 collation 인증서를
 *   쓰면 안 된다 -- 실측으로 뚫렸던 경로다. 맞는 인스턴스가 없으면 unknown. */
static const char *
cap_of(const ColHit *h, const char *cap, Oid coll)
{
    StringInfoData s;
    char       *v;
    const char *cname = "";

    if (OidIsValid(coll) && coll != DEFAULT_COLLATION_OID)
    {
        char *n = get_collation_name(coll);

        cname = n ? n : "?unknown-collation";
    }
    initStringInfo(&s);
    appendStringInfo(&s,
        "SELECT ipguard_capability(m.mask_id, %s)::text "
        "  FROM ipguard_mask_instance m "
        " WHERE m.normalized_args = 'kind=' || %s "
        "   AND m.collation_name = %s LIMIT 1",
        quote_literal_cstr(cap),
        quote_literal_cstr(h->kind ? h->kind : ""),
        quote_literal_cstr(cname));
    v = spi_one(s.data);
    pfree(s.data);
    return v ? v : "unknown";
}

/* 이 (마스크, 연산자, collation) 조합에 comparator 인증서가 있는가.
 *
 * ★ order_factor/equality_factor 는 **어느 연산자에 대한** 주장인지를 담지
 *   않는다. 같은 마스크가 표준 `<` 에는 factor-through 해도 사용자 정의
 *   역순 연산자에는 아닐 수 있다. 미등록이면 unknown -> 거부. */
static const char *
comparator_of(const ColHit *h, const char *kind, Oid op, Oid coll)
{
    StringInfoData s;
    char       *v;
    const char *cname = "";

    if (!OidIsValid(op))
        return "unknown";       /* 연산자를 모르면 판정할 수 없다 */
    if (OidIsValid(coll) && coll != DEFAULT_COLLATION_OID)
    {
        char *n = get_collation_name(coll);

        cname = n ? n : "?unknown-collation";
    }
    initStringInfo(&s);
    appendStringInfo(&s,
        "SELECT ipguard_comparator_compatible(m.mask_id, %s, %u::regoperator, %s)::text"
        "  FROM ipguard_mask_instance m "
        " WHERE m.normalized_args = 'kind=' || %s "
        "   AND m.collation_name = %s LIMIT 1",
        quote_literal_cstr(kind), op, quote_literal_cstr(cname),
        quote_literal_cstr(h->kind ? h->kind : ""),
        quote_literal_cstr(cname));
    v = spi_one(s.data);
    pfree(s.data);
    return v ? v : "unknown";
}

/*
 * declassification 인증서의 **context fingerprint**.
 *
 *   Declass( sources, effect, context_fingerprint, sink, observation )
 *
 * `ORDER BY secret` 을 허가한 것이 `ORDER BY lower(secret)` 이나
 * `ORDER BY secret USING ~<~` 까지 허가하면 안 된다 -- 드러나는 정보가 다르다.
 * 그래서 **키 표현식·비교자·collation** 을 인증서 키에 넣는다.
 *
 * 구현의 특별 규칙("bare_var=false 면 무조건 거부")으로 처리하면 형식 명세와
 * 어긋난다. 데이터로 처리해야 정책이 명시적으로 좁게 허가할 수 있다.
 *
 * 흔한 경우(bare Var + 기본 collation)는 비교자만 붙여 짧게 유지한다.
 * 파생 표현식일 때만 nodeToString 을 넣는다 -- 그쪽은 어차피 드물다.
 */
/* 바이너리를 hex 로. 상수를 세션 의존 텍스트가 아니라 send 표현으로 적기 위해. */
static char *
encode_to_hex(const char *p, int len)
{
    static const char *h = "0123456789abcdef";
    char *out = palloc(len * 2 + 1);

    for (int i = 0; i < len; i++)
    {
        out[i * 2] = h[(unsigned char) p[i] >> 4];
        out[i * 2 + 1] = h[(unsigned char) p[i] & 0x0f];
    }
    out[len * 2] = '\0';
    return out;
}

/* 길이 구분 인코딩. 단순 결합은 구분자 충돌로 서로 다른 문맥이 같은 문자열이
 * 될 수 있다 -- 인증서 키에서는 그게 곧 우회다. */
static void
cf(StringInfo b, const char *name, const char *val)
{
    appendStringInfo(b, "%s:%d:%s;", name, (int) strlen(val), val);
}

static void
cfi(StringInfo b, const char *name, long v)
{
    char buf[32];

    snprintf(buf, sizeof(buf), "%ld", v);
    cf(b, name, buf);
}

/* 표현식의 **의미적 모양**을 적는다.
 *
 * 넣는 것   노드 종류, 함수·연산자 OID, 상수의 타입과 값, 컬럼 identity
 * 빼는 것   location, alias, 내부 varno -- 의미와 무관하고 rewrite 마다 바뀐다
 *
 * 이걸 안 지키면 같은 질의가 재작성 경로에 따라 다른 context_key 를 내서
 * 인증서가 있는데 거부되는 운영 사고가 난다. */
typedef struct CanonCtx
{
    StringInfo  b;
    Ctx        *ctx;
    bool        has_param;
    /* ★ canonical 표현이 안정적이라고 **주장할 수 없는** 요소가 있는가.
     * binary send 는 내장 타입에는 좋은 선택이지만 임의 사용자 정의 타입까지
     * canonical 이라고 주장할 수 없다 -- send 구현이 값마다 유일하다는 보장이
     * 없다. v1 은 인증된 내장 타입만 허용하고 나머지는 unknown 으로 둔다. */
    bool        unstable;
} CanonCtx;

static bool
canon_node(Node *n, CanonCtx *c)
{
    if (n == NULL)
    {
        cf(c->b, "nil", "");
        return false;
    }
    switch (nodeTag(n))
    {
        case T_Var:
            {
                /* varno 는 넣지 않는다. 라벨/공개 컬럼 identity 로 대체한다. */
                List     *src = collect_sources(c->ctx, n);
                ListCell *l;

                cf(c->b, "var", "");
                cfi(c->b, "vtype", ((Var *) n)->vartype);
                foreach(l, src)
                {
                    ColHit *h = (ColHit *) lfirst(l);
                    char    buf[64];

                    snprintf(buf, sizeof(buf), "%u.%d", h->relid, h->attno);
                    cf(c->b, "col", buf);
                }
                if (src == NIL)
                    cf(c->b, "col", "?unresolved");
                return false;
            }
        case T_Const:
            {
                Const *k = (Const *) n;

                cf(c->b, "const", "");
                cfi(c->b, "ctype", k->consttype);
                cfi(c->b, "ctypmod", k->consttypmod);
                cfi(c->b, "ccoll", k->constcollid);
                if (k->constisnull)
                    cf(c->b, "cval", "NULL");
                else
                {
                    /* ★ 일반 텍스트 출력(typoutput)은 TimeZone·DateStyle·
                     * locale 같은 **세션 설정에 따라 달라진다.** 그걸 쓰면
                     * 같은 인증서가 세션마다 불일치해서 보안 우회가 아니라
                     * 운영 사고가 난다. 안정적인 binary send 표현을 쓴다. */
                    Oid   sendfn;
                    bool  varlena;

                    getTypeBinaryOutputInfo(k->consttype, &sendfn, &varlena);
                    /* send 함수 OID 도 넣는다 -- 구현이 바뀌면 다른 문맥이다. */
                    cfi(c->b, "csend", sendfn);
                    if (k->consttype >= FirstNormalObjectId)
                    {
                        /* ★ **non-built-in type** 이다 -- "UDT" 보다 이 이름이
                         * 정확하다. domain 과 extension 이 제공하는 타입도
                         * 포함하는 보수적 분류다.
                         *
                         * send 표현이 canonical 이라는 근거가 없다: 서로 다른
                         * 값이 같은 바이트를 낼 수도 있고 그러면 인증서가
                         * 넓어진다. v1 은 인증된 내장 타입만 허용한다. */
                        c->unstable = true;
                        cf(c->b, "cnonbuiltin", "1");
                    }
                    if (OidIsValid(sendfn))
                    {
                        bytea *raw = OidSendFunctionCall(sendfn, k->constvalue);

                        cf(c->b, "cbin",
                           encode_to_hex(VARDATA(raw),
                                         VARSIZE(raw) - VARHDRSZ));
                    }
                    else
                    {
                        /* send 함수가 없는 타입. 텍스트로 떨어지되 **그 사실을
                         * 표시**한다 -- 세션 의존이라 재현성이 낮다. */
                        Oid   out;
                        bool  vl;

                        c->unstable = true;
                        getTypeOutputInfo(k->consttype, &out, &vl);
                        cf(c->b, "ctxt(unstable)",
                           OidOutputFunctionCall(out, k->constvalue));
                    }
                }
                return false;
            }
        case T_Param:
            /* ★ 파라미터는 값이 정해지지 않았다. 인증서가 조용히 모든 값에
             * 재사용되면 안 되므로 표시하고 정책이 명시적으로 허가하게 한다.
             * 번호까지 넣는다 -- $1 과 $2 는 다른 문맥이다. */
            {
                Param *pm = (Param *) n;

                c->has_param = true;
                cf(c->b, "param", "");
                cfi(c->b, "pid", pm->paramid);
                cfi(c->b, "pkind", pm->paramkind);
                cfi(c->b, "ptype", pm->paramtype);
                cfi(c->b, "ptypmod", pm->paramtypmod);
                cfi(c->b, "pcoll", pm->paramcollid);
            }
            return false;
        case T_FuncExpr:
            cf(c->b, "func", "");
            cfi(c->b, "fnoid", ((FuncExpr *) n)->funcid);
            break;
        case T_OpExpr:
        case T_DistinctExpr:
        case T_NullIfExpr:
            cf(c->b, "op", "");
            cfi(c->b, "opno", ((OpExpr *) n)->opno);
            break;
        case T_CoerceViaIO:
        case T_RelabelType:
        case T_CollateExpr:
            cf(c->b, "coerce", "");
            cfi(c->b, "ctag", nodeTag(n));
            break;
        default:
            cf(c->b, "node", "");
            cfi(c->b, "tag", nodeTag(n));
            break;
    }
    cf(c->b, "(", "");
    expression_tree_walker(n, canon_node, (void *) c);
    cf(c->b, ")", "");
    return false;
}

/*
 * declassification 인증서의 **canonical 문맥**.
 *
 *   Declass( sources, effect, context_fingerprint, sink, observation )
 *   context_key = sha256(version || domain || context_canonical)
 *
 * canonical 을 같이 저장해야 정책 담당자가 **의미를 검토**할 수 있다.
 * opaque hash 만 두면 무엇을 허가하는지 아무도 못 읽는다.
 */
static char *
context_canonical(Ctx *ctx, EffNode *n, SinkKind s, bool *has_param,
                  bool *unstable)
{
    StringInfoData b;
    CanonCtx       c;
    ListCell      *lc;
    bool           saved_all = ctx->collect_all;

    initStringInfo(&b);
    c.b = &b;
    c.ctx = ctx;
    c.has_param = false;
    c.unstable = false;
    ctx->collect_all = true;    /* 공개 컬럼도 identity 로 넣는다 */

    cf(&b, "v", "1");
    cf(&b, "effect", effect_name[n->kind]);
    cf(&b, "sink", sink_name[s]);
    cf(&b, "kind", n->ctxdesc);
    if (n->keyterms == NIL)
    {
        cfi(&b, "fn", n->fn);
        cfi(&b, "nkey", n->nkey);
        cfi(&b, "distinct", n->distinct_arg ? 1 : 0);
        cfi(&b, "ordered", n->ordered_arg ? 1 : 0);
        if (n->expr)
            canon_node(n->expr, &c);    /* 술어·함수 표현식 자체 */
    }
    else
    {
        cfi(&b, "nkey", list_length(n->keyterms));
        foreach(lc, n->keyterms)
        {
            KeyTerm *kt = (KeyTerm *) lfirst(lc);
            char    *cn = (OidIsValid(kt->collation) &&
                           kt->collation != DEFAULT_COLLATION_OID)
                          ? get_collation_name(kt->collation) : NULL;

            cf(&b, "term", "");
            cf(&b, "shape", kt->bare_var ? "bare" : "derived");
            cfi(&b, "sortop", kt->sortop);
            cfi(&b, "eqop", kt->eqop);
            cf(&b, "coll", cn ? cn : "default");
            cfi(&b, "nullsfirst", kt->nulls_first ? 1 : 0);
            if (kt->expr)
                canon_node(kt->expr, &c);
        }
    }
    ctx->collect_all = saved_all;
    if (has_param)
        *has_param = c.has_param;
    if (unstable)
        *unstable = c.unstable;
    return b.data;
}

static bool
declassified(const ColHit *h, const char *effect, const char *sink,
             const char *canonical, bool has_param)
{
    StringInfoData s;
    char *v;

    initStringInfo(&s);
    appendStringInfo(&s,
        "SELECT '1' FROM ipguard_declassification d "
        " WHERE d.relid = %u AND d.attnum = %d "
        "   AND d.effect = %s AND d.sink = %s "
        "   AND d.context_key = ipguard_context_key(%s) "
        /* ★ 파라미터가 있으면 인증서가 **명시적으로** 그 domain 전체를
         * 허가한다고 적혀 있어야 한다. 기본값 'none' 이면 거부다 --
         * `WHERE secret = $1` 이 조용히 모든 값에 재사용되면 안 된다. */
        "   AND (%s OR d.param_scope = 'all_values') LIMIT 1",
        h->relid, h->attno,
        quote_literal_cstr(effect), quote_literal_cstr(sink),
        quote_literal_cstr(canonical),
        has_param ? "false" : "true");
    v = spi_one(s.data);
    pfree(s.data);
    return v != NULL;
}

#define PROOF_PUBLIC   0
#define PROOF_FAIL     (-1)

static int
spi_int(const char *sql)
{
    int r = PROOF_FAIL;

    if (SPI_execute(sql, true, 1) == SPI_OK_SELECT && SPI_processed > 0)
    {
        bool  isnull;
        Datum d = SPI_getbinval(SPI_tuptable->vals[0],
                                SPI_tuptable->tupdesc, 1, &isnull);

        if (!isnull)
            r = DatumGetInt32(d);
    }
    return r;
}

/*
 * proof tree 를 재귀로 검증한다.
 *
 * 반환  PROOF_PUBLIC  공개 값 -- 의무 없음
 *       >0            인증 통과. **출력 마스크의 mask_id**
 *       PROOF_FAIL    인증 실패
 */
static int
check_proof(ExprProof *pf, StringInfo why)
{
    ListCell      *lc;
    StringInfoData s;
    int            masked_mid = PROOF_PUBLIC;
    int            masked_pos = -1;
    int            pos = 0;
    char          *v;

    if (pf == NULL)
    {
        appendStringInfoString(why, "값 경로가 모델링되지 않았다");
        return PROOF_FAIL;
    }
    switch (pf->kind)
    {
        case PF_PUBLIC:
            return PROOF_PUBLIC;

        case PF_UNKNOWN:
            appendStringInfo(why, "%s: 인증 불가",
                             pf->ctx ? pf->ctx : "표현식");
            return PROOF_FAIL;

        case PF_SOURCE:
            {
                /* ★ MASK_APPLY baseline. commutation 은 없어도 마스크 자체의
                 * 코어 전제(determinism ∧ total ∧ 지문 일치)는 봐야 한다. */
                int   mid;
                char *q;

                initStringInfo(&s);
                appendStringInfo(&s, "SELECT ipguard_mask_id_of_kind(%s)",
                                 quote_literal_cstr(pf->src && pf->src->kind
                                                    ? pf->src->kind : ""));
                mid = spi_int(s.data);
                pfree(s.data);
                if (mid <= 0)
                {
                    appendStringInfoString(why,
                        "MaskInstance 가 등록되지 않았다");
                    return PROOF_FAIL;
                }
                q = psprintf("SELECT ipguard_mask_baseline(%d)::text", mid);
                v = spi_one(q);
                if (v == NULL || strcmp(v, "holds") != 0)
                {
                    appendStringInfo(why,
                        "MASK_APPLY baseline=%s (determinism ∧ total ∧ 지문)",
                        v ? v : "unknown");
                    return PROOF_FAIL;
                }
                return mid;
            }

        case PF_APPLY:
        case PF_AGG:
            /* 자식을 먼저 -- **인자 위치를 세면서** */
            foreach(lc, pf->args)
            {
                int m = check_proof((ExprProof *) lfirst(lc), why);

                if (m == PROOF_FAIL)
                    return PROOF_FAIL;
                if (m > 0)
                {
                    if (masked_mid > 0)
                    {
                        /* ★ 마스킹된 입력이 둘 이상이면 공통 출력 마스크를
                         * 증명할 수 없다 -- 현재 레지스트리 스키마는 단일
                         * 입력 마스크에 대한 r_out 만 담는다. */
                        appendStringInfoString(why,
                            "마스킹된 입력이 둘 이상 -- 공통 출력 마스크 증명 불가");
                        return PROOF_FAIL;
                    }
                    masked_mid = m;
                    masked_pos = pos;
                }
                pos++;
            }
            if (masked_mid == PROOF_PUBLIC)
                return PROOF_PUBLIC;        /* 전부 공개 -> 결과도 공개 */
            if (!OidIsValid(pf->fn))
            {
                appendStringInfoString(why, "변환 함수를 특정할 수 없다");
                return PROOF_FAIL;
            }
            initStringInfo(&s);
            if (pf->kind == PF_AGG)
                appendStringInfo(&s,
                    "SELECT ipguard_aggregate_out_mask(%d, %u::regprocedure,"
                    " %s, %s, '')",
                    masked_mid, pf->fn,
                    pf->distinct_arg ? "true" : "false",
                    pf->ordered_arg ? "true" : "false");
            else
                /* ★ arg_signature 에 **인자 위치**가 들어간다.
                 * concat(a,b) 와 concat(b,a) 를 구별해야 한다. */
                appendStringInfo(&s,
                    "SELECT ipguard_function_out_mask(%d, %u::regprocedure,"
                    " 'pos=%d', '')",
                    masked_mid, pf->fn, masked_pos);
            {
                int out = spi_int(s.data);

                pfree(s.data);
                if (out == PROOF_FAIL)
                {
                    appendStringInfo(why,
                        "%s(oid=%u, pos=%d): 인증서 없음 또는 출력 마스크 미등록",
                        pf->kind == PF_AGG ? "aggregate" : "function",
                        pf->fn, masked_pos);
                    return PROOF_FAIL;
                }
                return out;
            }
    }
    appendStringInfoString(why, "알 수 없는 proof 노드");
    return PROOF_FAIL;
}

/* discharge 는 Ctx 가 필요하다(canonical 문맥이 canonical 컬럼 identity 를 쓴다).
 * 백엔드는 단일 스레드이고 게이트는 재진입하지 않으므로 파일 스코프로 둔다. */
static Ctx *g_canon_ctx = NULL;

static void
discharge(Oblig *o)
{
    ListCell   *lc;
    const char *cap;
    StringInfoData why;

    initStringInfo(&why);
    o->discharged = false;
    o->how = "UNDISCHARGED";

    if (o->fidelity)
    {
        /* Fidelity 의무: VAL -> CELL.
         *
         * ★ **proof tree 를 재귀로** 검증한다. 평탄한 사슬로는
         *   concat(lower(ssn), upper(birth)) 에서 어느 함수가 어느 mask 를
         *   소비하는지, 인자 위치가 무엇인지, branch 결과 mask 가 무엇인지를
         *   증명할 수 없다.
         *
         *   f(m(x)) = r_out(f(x)) 이므로 합성은 **출력 마스크를 타고** 올라간다:
         *     lower(m(x))         = r1(lower(x))
         *     upper(r1(lower(x))) = r2(upper(lower(x)))
         *   그래서 각 Apply 는 인증 통과 시 **출력 마스크 id** 를 돌려주고,
         *   부모가 그걸로 다시 조회한다. */
        int mid = check_proof(o->node->proof, &why);

        if (mid == PROOF_FAIL)
        {
            o->detail = why.data;
            o->failkind = FK_MISSING_CERT;
            return;
        }
        o->discharged = true;
        o->how = "compatibility";
        return;
    }

    /* Opacity 의무: EQ/ORD/CARD -> 관찰 sink.
     *
     * ★ 두 경로 중 하나여야 한다:
     *   (1) factor-through -- 키 벡터의 **모든** 라벨 컬럼이 해당 capability
     *   (2) 정확한 (effect, sink) declassification 인증서
     *
     * `WHERE secret='a'` 가 행 포함 여부를 허가한다고 `ORDER BY secret` 의
     * 상대 순서까지 허가되지 않는다(명세 §3.5). 그래서 sink 까지 맞춰 본다. */
    cap = (o->node->kind == EK_EQ) ? "equality_factor"
        : (o->node->kind == EK_ORD) ? "order_factor" : NULL;

    if (cap != NULL)
    {
        const char *blk = keyterm_blocker(o->node);
        bool        all_hold = (blk == NULL);
        /* ★ "인증된 속성이 명시적으로 실패" 와 "인증서가 아예 없음" 은
         * 다른 사유다. 보고서에서 다른 표에 들어간다. */
        bool        saw_fails = false;

        if (blk != NULL)
            appendStringInfoString(&why, blk);
        else
        {
            ListCell *k;

            /* ★ key term 단위로 본다. 컬럼 집합으로 뭉개면 collation 과
             * 파생 표현식이 사라진다. */
            foreach(k, o->node->keyterms)
            {
                KeyTerm  *kt = (KeyTerm *) lfirst(k);
                ListCell *l2;

                foreach(l2, kt->sources)
                {
                    ColHit     *h = (ColHit *) lfirst(l2);
                    const char *c = cap_of(h, cap, kt->collation);
                    const char *ne;

                    if (strcmp(c, "holds") != 0)
                    {
                        all_hold = false;
                        saw_fails |= (strcmp(c, "fails") == 0);
                        appendStringInfo(&why, "%s=%s", cap, c);
                        break;
                    }
                    /* ★ 강제 전제: EQ/ORD 는 null_equivalence 를 **함께**
                     * 요구한다. 집계에서 쓴 것과 같은 패턴이다.
                     *
                     *   ORD  ORDER BY 는 NULL 을 cmp 로 놓지 않는다 --
                     *        NULLS FIRST/LAST 로 놓는다. 마스크가 non-NULL 을
                     *        NULL 로 바꾸면 그 행이 통째로 끝(또는 앞)으로
                     *        점프한다. order_factor 는 cmp 에 대한 주장이라
                     *        이걸 덮지 못한다.
                     *   EQ   SQL grouping equivalence 는 NULL 들을 한 그룹으로
                     *        묶는다. NULL 여부가 바뀌면 그룹 소속이 바뀐다.
                     *
                     * ★ order_factor=holds 와 null_equivalence=fails 는
                     * **모순이 아니다.** order_factor 를 non-NULL 정의역의
                     * comparator 주장으로 읽으면 둘은 양립한다. 다만 그것만으로는
                     * **SQL 전체 정렬 인증서로 불충분**하다:
                     *
                     *   ORD = NullPartitionPreserved ∧ ComparatorFactors
                     *   EQ  = NullPartitionPreserved ∧ EqualityFactors
                     *
                     * 여기가 앞의 연언지다. 실측으로 뚫렸던 경로다. */
                    ne = cap_of(h, "null_equivalence", kt->collation);
                    if (strcmp(ne, "holds") != 0)
                    {
                        all_hold = false;
                        saw_fails |= (strcmp(ne, "fails") == 0);
                        appendStringInfo(&why,
                                         "null_equivalence=%s (%s 의 전제)",
                                         ne, cap);
                        break;
                    }
                    /* ★ ComparatorFactors -- 어느 연산자에 대한 주장인가.
                     *
                     *   ORD = NullPartitionPreserved ∧ ComparatorFactors
                     *   EQ  = NullPartitionPreserved ∧ EqualityFactors
                     *
                     * 앞 연언지는 null_equivalence, 뒤 연언지가 여기다.
                     * 표준 연산자만 등록해도 충분하고, 미등록은 거부다. */
                    {
                        const char *ck = (o->node->kind == EK_ORD) ? "ORD" : "EQ";
                        Oid   op = (o->node->kind == EK_ORD) ? kt->sortop : kt->eqop;
                        const char *cc = comparator_of(h, ck, op, kt->collation);

                        if (strcmp(cc, "holds") != 0)
                        {
                            all_hold = false;
                            saw_fails |= (strcmp(cc, "fails") == 0);
                            appendStringInfo(&why,
                                "comparator(%s, op=%u)=%s", ck, op, cc);
                            break;
                        }
                    }
                }
                if (!all_hold)
                    break;
            }
            /* keyterms 가 없는 노드(집합연산 등)는 source 단위로 본다 */
            if (all_hold && o->node->keyterms == NIL)
                foreach(lc, o->node->sources)
                {
                    ColHit     *h = (ColHit *) lfirst(lc);
                    const char *c = cap_of(h, cap, InvalidOid);
                    const char *ne;

                    if (strcmp(c, "holds") != 0)
                    {
                        all_hold = false;
                        saw_fails |= (strcmp(c, "fails") == 0);
                        appendStringInfo(&why, "%s=%s", cap, c);
                        break;
                    }
                    ne = cap_of(h, "null_equivalence", InvalidOid);
                    if (strcmp(ne, "holds") != 0)
                    {
                        all_hold = false;
                        saw_fails |= (strcmp(ne, "fails") == 0);
                        appendStringInfo(&why,
                                         "null_equivalence=%s (%s 의 전제)",
                                         ne, cap);
                        break;
                    }
                }
        }
        if (all_hold)
        {
            o->discharged = true;
            o->how = "factorization";
            return;
        }
        o->failkind = saw_fails ? FK_CAPABILITY_FAILS : FK_MISSING_CERT;
    }
    else
        appendStringInfoString(&why, "CARD 는 factor-through 로 해소되지 않는다");

    /* declassification: **모든** source 가 정확히 이
     * (effect, context, sink) 로 허가돼야 한다.
     *
     * 파생 표현식은 factor-through 로는 해소되지 않지만(합성 증명 경로가
     * 없다), context_key 가 다르므로 정책이 **그 문맥을 명시적으로** 허가한
     * 경우에만 통과한다. 구현의 특별 규칙이 아니라 인증서 키로 처리한다. */
    {
        bool  all_dec = true;
        bool  hp = false, un = false;
        char *canon = context_canonical(g_canon_ctx, o->node, o->sink, &hp, &un);

        if (un)
        {
            /* canonical 이 안정적이라고 주장할 수 없다 -- 인증 대상이 아니다. */
            appendStringInfo(&why, "%scanonical 이 불안정하다 "
                             "(non-built-in type 또는 send 함수 없음)",
                             why.len ? ", " : "");
            o->detail = why.data;
            if (o->failkind == FK_NONE)
                o->failkind = FK_MISSING_CERT;
            return;
        }
        foreach(lc, o->node->sources)
            if (!declassified((ColHit *) lfirst(lc),
                              effect_name[o->node->kind], sink_name[o->sink],
                              canon, hp))
            {
                all_dec = false;
                break;
            }
        if (all_dec && o->node->sources != NIL)
        {
            o->discharged = true;
            o->how = "declassification";
            return;
        }
    }
    appendStringInfo(&why, "%s인증서 없음", why.len ? ", " : "");
    o->detail = why.data;
    if (o->failkind == FK_NONE)
        o->failkind = FK_MISSING_CERT;
}

/*
 * 새 게이트 판정. true = 수락.
 * 해소 안 된 의무가 하나라도 있으면 거부한다.
 */
static bool
release_gate(Ctx *ctx, Query *parse, StringInfo reason)
{
    GateCtx  g;
    FragCtx  f;
    ListCell *lc;
    bool      ok = true;

    /* ★ 0) 게이트를 **먼저** 돌린다.
     *
     * 앞 판은 walk_query 기반 사전검사로 "라벨 접촉" 을 판정했는데, 그건
     * 출력 Var 가 가리키는 컬럼만 따라가므로 서브쿼리 술어에만 라벨이 있는
     * 질의를 통째로 놓쳤다. 게이트 자신의 순회로 판정해야 한다. */
    memset(&g, 0, sizeof(g));
    g.ctx = ctx;
    g.rows_distinct = rows_distinguishable(parse);
    ctx->gate_touched = false;
    ctx->sp = 0;
    ctx->stack[ctx->sp++] = parse;
    gate_query(&g, parse, true);

    /* 라벨된 데이터를 안 건드리면 인증 대상이 아니다. 이 검사가 없으면
     * PII 와 무관한 질의까지 F_core 밖이라는 이유로 거부되어 DB 가 멈춘다. */
    if (!ctx->gate_touched)
        return true;

    /* ★ 1) F_core membership.
     *
     * 명세 §12 는 `F_impl \ F_core` 에 대해 **보장을 주장하지 않는다**고
     * 못박았다. 그런데 게이트가 그 영역의 질의를 수락하면 명세와 구현이
     * 정면으로 충돌한다. window function 이 대표적이다 -- effect 코드는
     * 실험적으로 남겨 두되, release-certified 모드에서는 수락하지 않는다. */
    memset(&f, 0, sizeof(f));
    frag_query(parse, &f);
    if (f.reasons != NIL)
    {
        if (reason)
        {
            ListCell *l;

            appendStringInfoString(reason, "OUTSIDE_CERTIFIED_FRAGMENT: ");
            foreach(l, f.reasons)
                appendStringInfo(reason, "%s%s",
                                 l == list_head(f.reasons) ? "" : ", ",
                                 (char *) lfirst(l));
        }
        return false;
    }

    /* ★ 2) visitor 가 전부 다뤘는가.
     *
     * 노드를 안 만들면 "sink 없음" 으로 오인되어 수락된다 -- 과거부가 아니라
     * **미탐**이다. 모델링 못 한 것이 하나라도 있으면 거부한다. */
    if (g.coverage != COV_FULL)
    {
        if (reason)
            appendStringInfo(reason, "%s: %s",
                             g.coverage == COV_OUTSIDE_FCORE
                                 ? "OUTSIDE_CERTIFIED_FRAGMENT"
                                 : "UNMODELED_EXPR",
                             g.uncovered ? g.uncovered : "?");
        return false;
    }

    if (g.obligs == NIL)
        return true;
    if (SPI_connect() != SPI_OK_CONNECT)
        return false;           /* fail-closed */
    g_canon_ctx = ctx;
    foreach(lc, g.obligs)
    {
        Oblig *o = (Oblig *) lfirst(lc);

        discharge(o);
        if (!o->discharged)
        {
            ok = false;
            if (reason && reason->len == 0)
                appendStringInfo(reason, "%s: %s(%s) -> %s : %s",
                                 o->failkind == FK_CAPABILITY_FAILS
                                     ? "CAPABILITY_FAILS"
                                     : "MISSING_CERTIFICATE",
                                 effect_name[o->node->kind], o->node->ctxdesc,
                                 sink_name[o->sink],
                                 o->detail ? o->detail : "인증서 없음");
        }
    }
    SPI_finish();
    return ok;
}

/* ==========================================================================
 * ipguard_label_positions(sql) -- **측정 도구**. 판정에 쓰지 않는다.
 *
 * 라벨된 컬럼이 어느 **구문 위치**에 나타나는지만 보고한다. sink 도달 분석을
 * 전혀 하지 않는다. 그래서 "민감 컬럼이 EQ/ORD/CARD 위치에 있으면 거부" 라는
 * 순진한 baseline 을 **Query tree 위에서** 만들 수 있다.
 *
 * ★ 왜 필요한가. baseline 을 SQL 텍스트 정규식으로 만들었더니 절 경계를 넘어
 *   오분류했다(`WHERE grade=$1 GROUP BY ssn` 을 "WHERE 에 ssn" 으로 셌다).
 *   비교 대상이 틀리면 회수율 전체가 무의미하다.
 *
 * ★ 게이트는 이 함수를 부르지 않는다. 부르면 baseline 이 게이트에 의존하게
 *   되어 비교가 순환한다.
 * ========================================================================== */
PG_FUNCTION_INFO_V1(ipguard_label_positions);

typedef struct LPCtx
{
    Ctx             *ctx;
    Tuplestorestate *store;
    TupleDesc        td;
    int              depth;
} LPCtx;

static void lp_query(LPCtx *lp, Query *q);
static List *lp_keys(Ctx *ctx, List *clause, List *tlist);

static void
lp_emit(LPCtx *lp, const char *pos, List *src)
{
    Datum  vals[3];
    bool   nulls[3] = {false, false, false};
    Datum *sd;
    int    n = 0;
    ListCell *lc;

    if (src == NIL)
        return;
    sd = (Datum *) palloc(sizeof(Datum) * list_length(src));
    foreach(lc, src)
    {
        ColHit *h = (ColHit *) lfirst(lc);

        sd[n++] = CStringGetTextDatum(psprintf("%u.%d", h->relid, h->attno));
    }
    vals[0] = CStringGetTextDatum(pos);
    vals[1] = Int32GetDatum(lp->depth);
    vals[2] = PointerGetDatum(construct_array(sd, n, TEXTOID, -1, false,
                                              TYPALIGN_INT));
    tuplestore_putvalues(lp->store, lp->td, vals, nulls);
}

/* 표현식 안의 Aggref 를 찾아 인자·DISTINCT·ORDER·FILTER 위치를 보고한다. */
static bool
lp_agg_walker(Node *n, LPCtx *lp)
{
    if (n == NULL)
        return false;
    if (IsA(n, Aggref))
    {
        Aggref *a = (Aggref *) n;

        lp_emit(lp, "agg_arg", collect_sources(lp->ctx, (Node *) a->args));
        /* ★ SortGroupClause 는 표현식이 아니라 tleSortGroupRef 를 담는다.
         *   args 를 tlist 로 주고 해소해야 실제 키 표현식이 나온다.
         *   그냥 collect_sources 를 걸면 **항상 빈 결과**가 나온다. */
        lp_emit(lp, "agg_distinct",
                lp_keys(lp->ctx, a->aggdistinct, a->args));
        lp_emit(lp, "agg_order", lp_keys(lp->ctx, a->aggorder, a->args));
        lp_emit(lp, "agg_filter",
                collect_sources(lp->ctx, (Node *) a->aggfilter));
    }
    if (IsA(n, SubLink))
    {
        SubLink *sl = (SubLink *) n;

        if (sl->subselect && IsA(sl->subselect, Query) &&
            lp->ctx->sp < MAX_STACK)
        {
            lp->ctx->stack[lp->ctx->sp++] = (Query *) sl->subselect;
            lp->depth++;
            lp_query(lp, (Query *) sl->subselect);
            lp->depth--;
            lp->ctx->sp--;
        }
        return lp_agg_walker(sl->testexpr, lp);
    }
    if (IsA(n, Query))
        return false;
    return expression_tree_walker(n, lp_agg_walker, (void *) lp);
}

/* SortGroupClause 목록의 키 표현식만 모은다. */
static List *
lp_keys(Ctx *ctx, List *clause, List *tlist)
{
    List     *src = NIL;
    ListCell *lc;

    foreach(lc, clause)
    {
        SortGroupClause *sgc = lfirst_node(SortGroupClause, lc);
        TargetEntry     *te = get_sortgroupclause_tle(sgc, tlist);

        if (te)
            src = list_concat(src,
                              collect_sources(ctx, (Node *) te->expr));
    }
    return src;
}

static bool
lp_setop_nonall(Node *n)
{
    SetOperationStmt *op;

    if (n == NULL || !IsA(n, SetOperationStmt))
        return false;
    op = (SetOperationStmt *) n;
    if (!op->all)
        return true;
    return lp_setop_nonall(op->larg) || lp_setop_nonall(op->rarg);
}

static void
lp_query(LPCtx *lp, Query *q)
{
    ListCell *lc;
    List     *tgt = NIL;

    if (lp->depth > 8)
        return;

    foreach(lc, q->targetList)
    {
        TargetEntry *te = (TargetEntry *) lfirst(lc);

        if (!te->resjunk)
            tgt = list_concat(tgt, collect_sources(lp->ctx,
                                                   (Node *) te->expr));
    }
    lp_emit(lp, "target", tgt);
    lp_emit(lp, "where", collect_sources(lp->ctx, (Node *) q->jointree));
    lp_emit(lp, "group_by", lp_keys(lp->ctx, q->groupClause, q->targetList));
    lp_emit(lp, "distinct",
            lp_keys(lp->ctx, q->distinctClause, q->targetList));
    lp_emit(lp, "order_by", lp_keys(lp->ctx, q->sortClause, q->targetList));
    lp_emit(lp, "having", collect_sources(lp->ctx, q->havingQual));
    if (q->setOperations)
    {
        /* 비-ALL 집합연산은 중복 제거를 하므로 EQ 위치다. leaf 서브쿼리의
         * 출력에서 라벨을 모은다 -- 최상위 targetList 는 비어 있다. */
        List     *ss = NIL;
        ListCell *l2;
        bool      nonall = lp_setop_nonall(q->setOperations);

        foreach(l2, q->rtable)
        {
            RangeTblEntry *r = (RangeTblEntry *) lfirst(l2);

            /* ★ collect_sources 는 ctx->stack 꼭대기의 rtable 로 Var 를
             *   해소한다. 서브쿼리를 밀지 않으면 **항상 빈 결과**가 나온다.
             *   서브쿼리가 대부분인 workload(TPC-H)에서 치명적이다. */
            if (r->rtekind == RTE_SUBQUERY && r->subquery &&
                lp->ctx->sp < MAX_STACK)
            {
                lp->ctx->stack[lp->ctx->sp++] = r->subquery;
                ss = list_concat(ss, collect_sources(lp->ctx,
                                        (Node *) r->subquery->targetList));
                lp->ctx->sp--;
            }
        }
        lp_emit(lp, nonall ? "setop_dedup" : "setop_all", ss);
    }
    (void) lp_agg_walker((Node *) q->targetList, lp);
    (void) lp_agg_walker(q->havingQual, lp);
    (void) lp_agg_walker((Node *) q->jointree, lp);   /* 술어 안의 SubLink */

    lp->depth++;
    foreach(lc, q->rtable)
    {
        RangeTblEntry *rte = (RangeTblEntry *) lfirst(lc);

        if (rte->rtekind == RTE_SUBQUERY && rte->subquery &&
            lp->ctx->sp < MAX_STACK)
        {
            lp->ctx->stack[lp->ctx->sp++] = rte->subquery;
            lp_query(lp, rte->subquery);
            lp->ctx->sp--;
        }
    }
    lp->depth--;
}

Datum
ipguard_label_positions(PG_FUNCTION_ARGS)
{
    char           *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    ReturnSetInfo  *rsi = (ReturnSetInfo *) fcinfo->resultinfo;
    Ctx             ctx;
    LPCtx           lp;
    List           *walked = NIL;
    char           *err = NULL;
    ListCell       *lc;
    TupleDesc       tupdesc;
    MemoryContext   old;

    if (rsi == NULL || !IsA(rsi, ReturnSetInfo))
        elog(ERROR, "ipguard_label_positions: 집합 반환 문맥이 아닙니다");
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "ipguard_label_positions: 결과 타입을 결정할 수 없습니다");
    old = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);
    tupdesc = CreateTupleDescCopy(tupdesc);
    memset(&lp, 0, sizeof(lp));
    lp.store = tuplestore_begin_heap(true, false, work_mem);
    lp.td = tupdesc;
    rsi->returnMode = SFRM_Materialize;
    rsi->setResult = lp.store;
    rsi->setDesc = tupdesc;
    MemoryContextSwitchTo(old);

    memset(&ctx, 0, sizeof(ctx));
    load_labels(&ctx);
    analyze_sql(sql, &ctx, &walked, &err);
    if (err || walked == NIL)
        return (Datum) 0;
    lp.ctx = &ctx;
    foreach(lc, walked)
    {
        ctx.sp = 0;
        ctx.stack[ctx.sp++] = lfirst_node(Query, lc);
        lp_query(&lp, lfirst_node(Query, lc));
    }
    return (Datum) 0;
}

PG_FUNCTION_INFO_V1(ipguard_obligations);

/*
 * ipguard_obligations(sql text) -> setof
 *   effect, context, sink, class, discharge, detail
 *
 * 게이트가 **무엇을 보고 왜 그렇게 판정했는지**를 행으로 펼친다.
 * 판정만 돌려주면 규칙이 우연히 맞은 것과 제대로 맞은 것을 구별할 수 없다.
 */
Datum
ipguard_obligations(PG_FUNCTION_ARGS)
{
    char           *sql = text_to_cstring(PG_GETARG_TEXT_PP(0));
    ReturnSetInfo  *rsi = (ReturnSetInfo *) fcinfo->resultinfo;
    Ctx             ctx;
    GateCtx         g;
    List           *walked = NIL;
    char           *err = NULL;
    ListCell       *lc;
    TupleDesc       tupdesc;
    Tuplestorestate *store;
    MemoryContext   old;

    if (rsi == NULL || !IsA(rsi, ReturnSetInfo))
        elog(ERROR, "ipguard_obligations: 집합 반환 문맥이 아닙니다");
    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "ipguard_obligations: 결과 타입을 결정할 수 없습니다");
    old = MemoryContextSwitchTo(rsi->econtext->ecxt_per_query_memory);
    tupdesc = CreateTupleDescCopy(tupdesc);
    store = tuplestore_begin_heap(true, false, work_mem);
    rsi->returnMode = SFRM_Materialize;
    rsi->setResult = store;
    rsi->setDesc = tupdesc;
    MemoryContextSwitchTo(old);

    memset(&ctx, 0, sizeof(ctx));
    memset(&g, 0, sizeof(g));
    load_labels(&ctx);
    analyze_sql(sql, &ctx, &walked, &err);
    if (err || walked == NIL)
        return (Datum) 0;

    g.ctx = &ctx;
    g.rows_distinct = rows_distinguishable(linitial_node(Query, walked));
    foreach(lc, walked)
    {
        Query *q = lfirst_node(Query, lc);

        ctx.sp = 0;
        ctx.stack[ctx.sp++] = q;
        gate_query(&g, q, true);
    }

    if (SPI_connect() != SPI_OK_CONNECT)
        return (Datum) 0;
    g_canon_ctx = &ctx;
    foreach(lc, g.obligs)
    {
        Oblig  *o = (Oblig *) lfirst(lc);
        Datum   vals[10];
        bool    nulls[10];
        StringInfoData srcs;
        ListCell *l2;
        Datum  *sd;
        int     nsrc = 0;

        discharge(o);
        initStringInfo(&srcs);
        /* ★ 사람이 읽는 문자열과 **기계가 읽는 정확한 source 목록**을 따로 낸다.
         *
         * 정책이 사람용 문자열을 파싱하거나 "이 테이블의 라벨 컬럼 전부" 로
         * 근사하면 명세의 exact-source declassification 이 아니게 된다.
         * held-out v1 에서 정확히 그 일이 있었다(PD1: birth 술어에서 나온
         * 인증서가 ssn 에도 설치됐다). 그래서 (relid, attnum) 을 순서 그대로
         * 낸다. */
        sd = (Datum *) palloc(sizeof(Datum) *
                              Max(1, list_length(o->node->sources)));
        foreach(l2, o->node->sources)
        {
            ColHit *h = (ColHit *) lfirst(l2);

            appendStringInfo(&srcs, "%s%s.%d(%s)", srcs.len ? "," : "",
                             get_rel_name(h->relid) ? get_rel_name(h->relid) : "?",
                             h->attno, h->kind ? h->kind : "?");
            sd[nsrc++] = CStringGetTextDatum(psprintf("%u.%d", h->relid,
                                                      h->attno));
        }
        memset(nulls, 0, sizeof(nulls));
        vals[0] = CStringGetTextDatum(effect_name[o->node->kind]);
        vals[1] = CStringGetTextDatum(psprintf("%s [key %d, labeled %d] {%s}",
                                               o->node->ctxdesc, o->node->nkey,
                                               o->node->nkey_labeled, srcs.data));
        vals[2] = CStringGetTextDatum(sink_name[o->sink]);
        vals[3] = CStringGetTextDatum(o->fidelity ? "fidelity" : "opacity");
        vals[4] = CStringGetTextDatum(o->how);
        vals[5] = CStringGetTextDatum(o->detail ? o->detail : "");
        /* ★ canonical 과 key 를 **둘 다** 낸다.
         * opaque hash 만 두면 정책 담당자가 무엇을 허가하는지 못 읽는다. */
        {
            bool  hp = false, un = false;
            char *canon = context_canonical(&ctx, o->node, o->sink, &hp, &un);
            char *q = psprintf("SELECT ipguard_context_key(%s)",
                               quote_literal_cstr(canon));
            char *k = spi_one(q);

            vals[6] = CStringGetTextDatum(k ? k : "");
            vals[7] = CStringGetTextDatum(canon);
        }
        vals[8] = PointerGetDatum(construct_array(sd, nsrc, TEXTOID, -1,
                                                  false, TYPALIGN_INT));
        vals[9] = CStringGetTextDatum(
            o->discharged ? "" :
            o->failkind == FK_CAPABILITY_FAILS ? "CAPABILITY_FAILS" :
            o->failkind == FK_MISSING_CERT ? "MISSING_CERTIFICATE" : "");
        tuplestore_putvalues(store, tupdesc, vals, nulls);
    }
    SPI_finish();
    return (Datum) 0;
}

static PlannedStmt *
ipguard_planner(Query *parse, const char *query_string, int cursorOptions,
                ParamListInfo boundParams)
{
    if (ipguard_enforce && !IPGUARD_BUSY && parse->commandType != CMD_UTILITY)
    {
        Ctx ctx;

        if (!OidIsValid(mask_fn_oid))
        {
            Oid argt[2] = {ANYELEMENTOID, TEXTOID};

            mask_fn_oid = LookupFuncName(
                list_make1(makeString("ipguard_mask")), 2, argt, true);
            if (!OidIsValid(mask_fn_oid))
                ereport(ERROR,
                        (errcode(ERRCODE_UNDEFINED_FUNCTION),
                         errmsg("ipguard: ipguard_mask() 를 찾을 수 없습니다"),
                         errhint("CREATE EXTENSION ipguard 를 실행했고 "
                                 "해당 스키마가 search_path 에 있는지 확인하십시오.")));
        }

        memset(&ctx, 0, sizeof(ctx));

        IPGUARD_BUSY_ENTER();
        PG_TRY();
        {
            load_labels(&ctx);

            /* 1) 분석: 무엇이 나가는지 + bound 를 소진했는지 */
            ctx.sp = 0;
            ctx.depth = 0;
            ctx.stack[ctx.sp++] = parse;
            walk_query(&ctx, parse, NULL);
        }
        PG_CATCH();
        {
            IPGUARD_BUSY_LEAVE();
            PG_RE_THROW();
        }
        PG_END_TRY();
        IPGUARD_BUSY_LEAVE();

        /* PII 가 걸린 계획만 센다(§ipguard_pii_plans 주석 참조). 이 지점이
         * 곧 "계획 캐시가 비워져서 계획기가 다시 돌았다" 의 관측점이다.
         *
         * ★ 알려진 한계(G2): **set-operation 계획을 세지 않는다.**
         *   setOperations 질의는 최상위 Query 의 targetList 가 비어 있고
         *   출력·술어가 leaf 서브쿼리에 있어서 out_kinds/pred_kinds 가 NIL 로
         *   남는다. held-out v1 에서 HO0064·HO0149·HO0275 가 그랬다 --
         *   셋 다 obligation 을 정상 생성하고 거부됐으므로 **게이트는 실행**
         *   **됐고 판정도 옳다.** 계수기만 누락한다.
         *
         *   그래서 이 값을 "게이트가 PII 를 봤는가" 의 지표로 쓰면 안 된다.
         *   판정의 근거는 언제나 obligation stream 이다. 계획기 작업량
         *   proxy 로도 신뢰할 수 없어 §11-5 보고에서 제외했다. 고치려면
         *   분석기 순회가 setop leaf 를 최상위 관점으로 접어 올려야 하는데,
         *   그건 건전성과 무관한 계측을 위해 판정 경로를 건드리는 일이다. */
        if (ctx.out_kinds != NIL || ctx.pred_kinds != NIL)
            ipguard_pii_plans++;

        /* 2) fail-closed: 순회 bound 소진은 우회 신호다.
         *    (unresolved 로는 막지 않는다 -- generate_series() 같은 정상
         *     쿼리에서도 흔하며, 103개 쿼리 실측에서 오탐 2건이 나왔다.
         *     bounded 는 같은 실측에서 오탐 0건.) */
        if (ctx.bounded > 0)
            ereport(ERROR,
                    (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                     errmsg("ipguard: 쿼리 구조가 분석 한계를 초과했습니다"),
                     errdetail("순회 bound 를 %d회 소진했습니다. "
                               "PII 노출 여부를 판정할 수 없어 거부합니다.",
                               ctx.bounded),
                     errhint("중첩 깊이를 줄이십시오.")));

        /* 2.5) release-factorization gate.
         *
         * legacy R1~R3 와 **나란히** 둔다. 하나로 합치면 어느 게이트가 무엇을
         * 잡았는지 구별할 수 없고, §11-5 비교 측정이 불가능해진다.
         * legacy 는 masked-ness 를, 이쪽은 effect->observable sink 를 본다. */
        /* ★ out_kinds/pred_kinds 를 조건으로 걸면 안 된다. 그건 resjunk 를
         * 건너뛰므로 정렬/윈도우 키에만 민감 컬럼이 있는 질의에서 게이트가
         * 아예 안 돈다(실측). 게이트가 스스로 판정한다. */
        if (ipguard_gate == 1)
        {
            StringInfoData why;
            bool           accept;

            initStringInfo(&why);
            /* ★ 반드시 busy 가드 안에서 돌려야 한다. release_gate 는 레지스트리
             * 조회 API 를 SPI 로 부르는데, 그 질의들이 다시 이 훅을 타고 들어와
             * 또 게이트를 돌리면 **무한 재귀**한다. load_labels 가 같은 이유로
             * 이미 가드 안에 있다. */
            IPGUARD_BUSY_ENTER();
            PG_TRY();
            {
                accept = release_gate(&ctx, parse, &why);
            }
            PG_CATCH();
            {
                /* ★ 레지스트리 조회가 터져도 가드는 반드시 복원돼야 한다.
                 * 안 그러면 그 뒤 모든 질의가 게이트를 우회한다. */
                IPGUARD_BUSY_LEAVE();
                PG_RE_THROW();
            }
            PG_END_TRY();
            IPGUARD_BUSY_LEAVE();

            if (!accept)
                ereport(ERROR,
                        (errcode(ERRCODE_INSUFFICIENT_PRIVILEGE),
                         errmsg("ipguard: 해소되지 않은 의무가 있어 거부합니다"),
                         errdetail("%s", why.data),
                         errhint("factor-through 인증서를 등록하거나 "
                                 "정확한 (effect, sink) declassification 을 "
                                 "발급하십시오.")));
        }

        /* 3) 치환. 어디에 넣을지는 설계 공간의 선택이다 -- mask_position 참조 */
        if (ipguard_mask_position == 0)
        {
            /* V1 소스 마스킹: 술어까지 마스크를 본다. 거부하지 않는다. */
            mask_source(&ctx, parse);
            goto plan_it;
        }
        if (ctx.out_kinds != NIL && ipguard_mask_position == 2)
        {
            /* V3 투영 경계: 모든 관계 연산 뒤에서만 가린다.
             * 정의상 원본 질의의 계산을 바꾸지 않으므로(Fidelity 보존)
             * 발산 판정도 충돌 판정도 하지 않는다 -- 할 것이 없다.
             * 대신 카디널리티·통계가 그대로 나간다(Mask opacity 포기).
             *
             * SELECT 만 다룬다. DML RETURNING/utility 는 바깥 질의로 감쌀 수
             * 없으므로 output_path 로 떨어진다(문서에 한계로 기록). */
            if (parse->commandType == CMD_SELECT)
            {
                int n = 0;
                Query *wrapped = wrap_projection(&ctx, parse, &n);

                if (n > 0)
                    parse = wrapped;
                goto plan_it;
            }
        }
        if (ctx.out_kinds != NIL)
        {
            ConflictCtx cc;

            ctx.sp = 0;
            ctx.depth = 0;
            mask_output(&ctx, parse);

            /* 4) 정합성 충돌 감지 -> fail-closed.
             *    조용한 오답보다 명시적 에러가 낫다. */
            if (ipguard_on_conflict != 2)
            {
                cc.ctx = &ctx;
                cc.found = false;
                cc.col = NULL;
                ctx.sp = 0;
                conflict_walker((Node *) parse, &cc);
                if (cc.found)
                    ereport(ipguard_on_conflict == 0 ? ERROR : WARNING,
                            (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                             errmsg("ipguard: masking would change query results"),
                             errdetail("Masked subquery/CTE output column \"%s\" is "
                                       "referenced from a predicate or join condition. "
                                       "Executing as-is compares the filter against the "
                                       "mask value, silently dropping rows or turning the "
                                       "join into a cross product.", cc.col),
                             errhint("Move the predicate onto the base table, or drop the "
                                     "column from the output list.")));
            }

            /* 5) 의미 발산 감지. **기본은 allow** -- 켜면 GROUP BY 된 PII 등
             *    정상 분석 쿼리를 막는다. 과거부 비용을 재고 켤 것. */
            if (ipguard_on_divergence != 2)
            {
                const char *rule = NULL, *what = NULL;

                if (find_divergence(&ctx, parse, &rule, &what))
                    ereport(ipguard_on_divergence == 0 ? ERROR : WARNING,
                            (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                             errmsg("ipguard: masking would change query semantics"),
                             errdetail("%s is computed over the masked value \"%s\". "
                                       "The answer would describe the mask, not the "
                                       "population -- and the output is an ordinary "
                                       "value with no sign that masking occurred.",
                                       rule, what),
                             errhint("Aggregate on a non-PII key, or drop the PII "
                                     "column from the grouping/output.")));
            }
        }
    }

plan_it:
    if (prev_planner_hook)
        return prev_planner_hook(parse, query_string, cursorOptions, boundParams);
    return standard_planner(parse, query_string, cursorOptions, boundParams);
}

/* ==========================================================================
 * 라벨 변경 -> 계획 캐시 무효화
 *
 * ★ 4라운드 적대적 시험이 찾은 결함. load_labels 는 **계획 시점에** 돈다.
 *   그래서 계획이 캐시되고 나면 라벨을 새로 붙여도 그 세션에는 효력이 없다:
 *
 *     PREPARE p AS SELECT ssn FROM t;  EXECUTE p x6   (generic plan 캐시됨)
 *     INSERT INTO pii_label ...                        (컬럼을 라벨링)
 *     EXECUTE p                        -> 평문 그대로
 *
 *   새 세션에서는 정상 마스킹된다. 즉 순수한 계획 캐시 staleness 인데,
 *   **커넥션 풀 환경에서 가장 위험한 형태다** -- 풀의 세션은 몇 시간씩
 *   살아 있으므로 "컬럼을 라벨링했다"가 언제 효력을 갖는지 알 수 없고,
 *   에러도 경고도 없이 계속 샌다.
 *
 * 고치는 방법: 라벨 테이블에 문장 트리거를 달아 relcache 무효화를 방송하고,
 * 각 백엔드가 그 신호를 받아 ResetPlanCache() 를 부른다. 이게 PostgreSQL 이
 * 카탈로그 변경을 전파하는 표준 경로다.
 * ========================================================================== */

static void
ipguard_label_inval(Datum arg, Oid relid)
{
    /* relid == InvalidOid 는 "전부 무효" 신호다. 우리 라벨 테이블의 OID 를
     * 따로 들고 있지 않으므로 보수적으로 계획 캐시를 비운다 -- 라벨 변경은
     * 드물고, 놓치면 평문이 나가므로 값싼 쪽으로 틀리면 안 된다. */
    (void) arg;
    (void) relid;
    ResetPlanCache();
}

PG_FUNCTION_INFO_V1(ipguard_label_changed);

/* 라벨 테이블에 다는 문장 트리거. 커밋 시 relcache 무효화가 모든 백엔드로
 * 방송되고, 위 콜백이 각자의 계획 캐시를 비운다.
 *
 * 레지스트리 테이블에도 같은 함수를 단다(ipguard_watch_registry). 인증서가
 * 철회됐는데 generic plan 이 살아 있으면, 이미 계획된 질의는 철회 전 판정으로
 * 계속 돈다 -- 라벨 지연(Y07)과 정확히 같은 구멍이다. */
Datum
ipguard_label_changed(PG_FUNCTION_ARGS)
{
    TriggerData *td = (TriggerData *) fcinfo->context;

    if (!CALLED_AS_TRIGGER(fcinfo))
        ereport(ERROR,
                (errcode(ERRCODE_FEATURE_NOT_SUPPORTED),
                 errmsg("ipguard_label_changed() 는 트리거로만 호출할 수 있습니다")));

    CacheInvalidateRelcache(td->tg_relation);
    return PointerGetDatum(NULL);
}

/* ------------------------------------------------------------------
 * 레지스트리 -- 마스크 인스턴스의 구현 지문 (명세 v0.2.1 §4)
 *
 * `impl_version` 을 관리자가 손으로 적는 문자열로 두면 안 된다:
 * **CREATE OR REPLACE FUNCTION 은 OID 를 유지한다.** 본문만 갈아끼우면
 * (function_oid, args, types, collation) 이 전부 그대로이므로, 버전 문자열을
 * 올리지 않는 한 **옛 인증서가 새 구현 위에서 살아남는다.** RegistrySound 를
 * 조용히 깨는 경로다.
 *
 * 그래서 지문을 카탈로그 사실에서 **계산**한다. 여기서는 pg_proc 부분만
 * 만들고, 확장 버전과 collation 버전은 SQL 쪽에서 붙인다(카탈로그 조인이
 * SQL 로 훨씬 짧다).
 *
 * ★ 완전성이 언어마다 다르다. 그것을 숨기지 않고 `complete` 로 돌려준다:
 *
 *   internal    서버 빌드에 묶인다                                complete
 *   c (우리)    provider-attested build identity.
 *               **complete 가 아니다** -- 아래 참조                 INCOMPLETE
 *   c (타 확장) extversion 밖에 못 본다.
 *               `make install` 로 .so 를 덮어써도 카탈로그는 그대로다 INCOMPLETE
 *   sql/plpgsql prosrc 는 보지만 **본문이 호출하는 함수**가 바뀌는 것은
 *               못 본다                                            INCOMPLETE
 *
 * ★★ 우리 모듈이라고 complete 가 아니다.
 *   소스 해시를 바이너리에 박아도 **바이너리 동일성**은 얻지 못한다:
 *   컴파일러·플래그·PG 헤더·링크 라이브러리·ABI·같은 소스의 다른 바이너리가
 *   전부 밖에 있다. Makefile 의 manifest 가 덮은 축만 잡힌다
 *   (IPGUARD_MANIFEST_AXES 로 노출한다).
 *
 *   따라서 주장은 이 수준이다:
 *       provider-attested build identity
 *       complete only under BuildSound(provider_manifest)
 *
 *   assurance 로는 `trusted_provider` 다. `proved_builtin` 은 `internal`
 *   에만 준다. 그 사실이 감사에 남아야 한다.
 * ------------------------------------------------------------------ */
#ifndef IPGUARD_BUILD_ID
#define IPGUARD_BUILD_ID "unknown-build"
#endif
#ifndef IPGUARD_MANIFEST_AXES
#define IPGUARD_MANIFEST_AXES "none"
#endif

PG_FUNCTION_INFO_V1(ipguard_build_id);

Datum
ipguard_build_id(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(IPGUARD_BUILD_ID));
}

PG_FUNCTION_INFO_V1(ipguard_manifest_axes);

/* build manifest 가 **덮은 축**. 여기 없는 것은 변경돼도 잡히지 않는다.
 * 이걸 노출해야 `BuildSound(provider_manifest)` 전제가 검증 가능해진다. */
Datum
ipguard_manifest_axes(PG_FUNCTION_ARGS)
{
    PG_RETURN_TEXT_P(cstring_to_text(IPGUARD_MANIFEST_AXES));
}

PG_FUNCTION_INFO_V1(ipguard_pii_plan_count);

/* 이 백엔드에서 **PII 가 걸린 질의를 계획한 횟수.**
 * 라벨/레지스트리 변경이 generic plan 까지 전파됐는지를 직접 잰다. */
Datum
ipguard_pii_plan_count(PG_FUNCTION_ARGS)
{
    PG_RETURN_INT64(ipguard_pii_plans);
}

PG_FUNCTION_INFO_V1(ipguard_proc_basis);

/*
 * ipguard_proc_basis(func regprocedure)
 *   OUT basis text   pg_proc 에서 뽑은 정규화 문자열 (해시는 SQL 에서 md5())
 *   OUT lang  text   언어 이름
 *   OUT self  bool   probin 이 **우리 모듈**인가 (그렇다면 빌드 해시로 잡힌다)
 *   OUT build text   self 일 때 IPGUARD_BUILD_ID
 */
Datum
ipguard_proc_basis(PG_FUNCTION_ARGS)
{
    Oid             fnoid = PG_GETARG_OID(0);
    HeapTuple       tup;
    Form_pg_proc    pf;
    Datum           d;
    bool            isnull;
    char           *lang;
    char           *probin = NULL;
    bool            self = false;
    StringInfoData  b;
    TupleDesc       tupdesc;
    Datum           vals[4];
    bool            nulls[4] = {false, false, false, false};

    if (get_call_result_type(fcinfo, NULL, &tupdesc) != TYPEFUNC_COMPOSITE)
        elog(ERROR, "ipguard_proc_basis: 결과 타입을 결정할 수 없습니다");
    tupdesc = BlessTupleDesc(tupdesc);

    tup = SearchSysCache1(PROCOID, ObjectIdGetDatum(fnoid));
    if (!HeapTupleIsValid(tup))
        ereport(ERROR,
                (errcode(ERRCODE_UNDEFINED_FUNCTION),
                 errmsg("ipguard: 함수 %u 를 찾을 수 없습니다", fnoid)));
    pf = (Form_pg_proc) GETSTRUCT(tup);
    lang = get_language_name(pf->prolang, false);

    initStringInfo(&b);
    /* ★ 이름·인자·반환형·엄격성·휘발성·보안·병렬성을 전부 넣는다.
     * 하나라도 빠지면 그 축의 변경이 지문에 안 잡힌다 -- 예를 들어
     * provolatile 을 빼면 IMMUTABLE -> VOLATILE 변경이 통과한다. */
    appendStringInfo(&b, "name=%s;lang=%s;nargs=%d;ret=%u;",
                     NameStr(pf->proname), lang, pf->pronargs,
                     pf->prorettype);
    for (int i = 0; i < pf->pronargs; i++)
        appendStringInfo(&b, "a%d=%u;", i, pf->proargtypes.values[i]);
    appendStringInfo(&b, "vol=%c;strict=%c;retset=%c;secdef=%c;par=%c;",
                     pf->provolatile, pf->proisstrict ? 't' : 'f',
                     pf->proretset ? 't' : 'f',
                     pf->prosecdef ? 't' : 'f', pf->proparallel);

    d = SysCacheGetAttr(PROCOID, tup, Anum_pg_proc_probin, &isnull);
    if (!isnull)
    {
        probin = TextDatumGetCString(d);
        appendStringInfo(&b, "bin=%s;", probin);
        /* $libdir/ipguard 든 절대경로든 마지막 요소로 판정한다. */
        {
            const char *base = strrchr(probin, '/');

            base = base ? base + 1 : probin;
            if (strcmp(base, "ipguard") == 0 ||
                strcmp(base, "ipguard.so") == 0)
                self = true;
        }
    }

    d = SysCacheGetAttr(PROCOID, tup, Anum_pg_proc_prosrc, &isnull);
    if (!isnull)
        appendStringInfo(&b, "src=%s;", TextDatumGetCString(d));

    d = SysCacheGetAttr(PROCOID, tup, Anum_pg_proc_proconfig, &isnull);
    if (!isnull)
    {
        /* proconfig 는 search_path 등을 담는다. 바뀌면 의미가 달라진다. */
        ArrayType  *arr = DatumGetArrayTypeP(d);
        Datum      *el;
        int         n;

        deconstruct_array(arr, TEXTOID, -1, false, TYPALIGN_INT, &el, NULL, &n);
        for (int i = 0; i < n; i++)
            appendStringInfo(&b, "cfg=%s;", TextDatumGetCString(el[i]));
    }

    if (self)
        appendStringInfo(&b, "build=%s;", IPGUARD_BUILD_ID);

    ReleaseSysCache(tup);

    vals[0] = CStringGetTextDatum(b.data);
    vals[1] = CStringGetTextDatum(lang);
    vals[2] = BoolGetDatum(self);
    vals[3] = CStringGetTextDatum(self ? IPGUARD_BUILD_ID : "");
    PG_RETURN_DATUM(HeapTupleGetDatum(heap_form_tuple(tupdesc, vals, nulls)));
}

/* ★ 5R 이 찾은 결함: GUC 가 PGC_USERSET 이면 **앱 사용자가 한 줄로 보안
 *   컨트롤을 끈다.** 실측(일반 롤 z5_app):
 *
 *     SET ipguard.enforce = off;          -> 800102-1000001   평문
 *     SET ipguard.label_schema = '<빈 스키마>';  -> 평문
 *     SET ipguard.on_divergence = allow;  -> 조용한 오답 허용
 *
 *   SQL 인젝션이면 공짜로 얻는다. 집행기를 아무리 정교하게 만들어도 스위치를
 *   아무나 끌 수 있으면 의미가 없다.
 *
 *   전부 PGC_SUSET 으로 바꿨다. PostgreSQL 15+ 에서는 필요하면 개별 위임이
 *   가능하다 -- GRANT SET ON PARAMETER ipguard.enforce TO <role>.
 *   기본은 거부, 위임은 명시적. */
/* ★ 보안 관련 GUC 가 바뀌면 계획 캐시를 **반드시** 비워야 한다.
 *
 * 라벨(Y07)·레지스트리와 정확히 같은 구멍이다. 사용자가
 * `SET ipguard.gate = release` 로 바꿨는데 캐시된 legacy plan 이 계속 돌면,
 * 모드를 바꾼 것이 아무 효력이 없으면서 **에러도 경고도 없다.** */
static void
ipguard_reset_plans_int(int newval, void *extra)
{
    (void) newval; (void) extra;
    ResetPlanCache();
}

static void
ipguard_reset_plans_bool(bool newval, void *extra)
{
    (void) newval; (void) extra;
    ResetPlanCache();
}

void _PG_init(void);

void
_PG_init(void)
{
    DefineCustomBoolVariable("ipguard.enforce",
                             "PII 마스킹 집행을 켠다.",
                             NULL, &ipguard_enforce, false,
                             PGC_SUSET, 0, NULL,
                             ipguard_reset_plans_bool, NULL);

    DefineCustomStringVariable("ipguard.label_schema",
                               "Schema holding the pii_label table.",
                               NULL, &ipguard_label_schema, "h5",
                               PGC_SUSET, 0, NULL, NULL, NULL);

    /* legacy 와 release 를 **나란히** 둔다. 기본은 legacy -- 기존 측정이
     * 조용히 바뀌면 두 게이트를 비교할 수 없다(명세 §11-5). */
    DefineCustomEnumVariable("ipguard.gate",
                             "판정 게이트(legacy|release).",
                             "legacy 는 R1~R3(masked-ness), release 는 "
                             "effect hyperedge -> observable sink 를 본다.",
                             &ipguard_gate, 0, gate_options,
                             PGC_SUSET, 0, NULL,
                             ipguard_reset_plans_int, NULL);

    DefineCustomEnumVariable("ipguard.mask_position",
                             "마스크를 어디에 넣는가(source|output_path|projection).",
                             "동적 마스킹 설계 공간의 세 꼭짓점. 각각 Fidelity / "
                             "Mask opacity / Totality 중 하나를 포기한다.",
                             &ipguard_mask_position, 1, mask_position_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomEnumVariable("ipguard.label_key",
                             "라벨을 이름으로 붙잡을지 OID 로 붙잡을지(name|oid).",
                             "name 은 읽기 쉽지만 RENAME/SET SCHEMA 로 끊긴다. "
                             "oid 는 이름 변경에 면역이다.",
                             &ipguard_label_key, 0, label_key_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomEnumVariable("ipguard.numeric_mask",
                             "숫자형 PII 의 마스크 센티널(zero|nullify).",
                             "zero 는 정상 값과 구별되지 않고, nullify 는 count() "
                             "를 바꾸고 NOT NULL 클라이언트를 깨뜨린다.",
                             &ipguard_numeric_mask, 1, numeric_mask_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomEnumVariable("ipguard.on_divergence",
                             "마스킹이 의미를 바꿀 때의 동작 "
                             "(DISTINCT/GROUP BY/집합연산/비-값보존 집계).",
                             "기본 allow. 켜면 정상 분석 쿼리도 막히므로 "
                             "과거부율을 먼저 재고 정할 것.",
                             &ipguard_on_divergence, 2, conflict_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    DefineCustomEnumVariable("ipguard.on_conflict",
                             "What to do when masking would change query results.",
                             "error is the default. warn/allow exist only to measure how "
                             "often this pattern occurs in a real workload.",
                             &ipguard_on_conflict, 0, conflict_options,
                             PGC_SUSET, 0, NULL, NULL, NULL);

    prev_planner_hook = planner_hook;
    planner_hook = ipguard_planner;

    /* 라벨이 바뀌면 캐시된 계획이 낡는다 -- 4R Y07 */
    CacheRegisterRelcacheCallback(ipguard_label_inval, (Datum) 0);
}
