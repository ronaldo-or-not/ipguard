/*
 * probe_provenance -- 와이어 훅이 실제로 볼 수 있는 것을 측정한다.
 *
 * 와이어 레벨 탐지기는 RowDescription 메시지의 resorigtbl / resorigcol 로만
 * 출력 컬럼의 출처를 안다. libpq는 그 두 필드를 PQftable() / PQftablecol()로
 * 그대로 노출한다. 따라서 확장을 만들기 전에도 "와이어 훅이 원리상 무엇을
 * 잡을 수 있는가"를 정확히 잴 수 있다.
 *
 * 쿼리를 실행하지 않는다: PQprepare + PQdescribePrepared 로 결과 메타데이터만
 * 받는다. 1만 행을 끌어오지 않고, 부작용도 없다.
 *
 * 주의: describePrepared 응답의 format 코드는 항상 0(text)이다. 포맷은 Bind
 * 시점에 정해지므로, 바이너리 전송 관련 항목(B*)은 실제 실행으로 따로 재야 한다.
 *
 * 입력: stdin, 한 줄에 "<id>\t<sql>"  (sql에 개행 없음)
 * 출력: stdout TSV
 *     <id>\tOK\t<ncols>
 *     <id>\tCOL\t<idx>\t<name>\t<tableoid>\t<tablecol>\t<typeoid>
 *     <id>\tERR\t<sqlstate>\t<message>
 *
 * 빌드:
 *   gcc -O2 -Wall -I$HOME/pg/include -o probe_provenance probe_provenance.c \
 *       -L$HOME/pg/lib -lpq -Wl,-rpath,$HOME/pg/lib
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>

#define MAXLINE (1 << 20)

/* TSV 안전을 위해 탭/개행을 공백으로 접는다 */
static void put_clean(const char *s)
{
    if (!s) { fputs("", stdout); return; }
    for (; *s; s++)
        putchar((*s == '\t' || *s == '\n' || *s == '\r') ? ' ' : *s);
}

int main(void)
{
    PGconn *conn = PQconnectdb("");   /* PGHOST/PGPORT/PGDATABASE 환경변수 사용 */
    if (PQstatus(conn) != CONNECTION_OK) {
        fprintf(stderr, "connect failed: %s", PQerrorMessage(conn));
        PQfinish(conn);
        return 1;
    }

    char *line = malloc(MAXLINE);
    if (!line) { fprintf(stderr, "oom\n"); PQfinish(conn); return 1; }

    long seq = 0;
    while (fgets(line, MAXLINE, stdin)) {
        size_t n = strlen(line);
        while (n && (line[n-1] == '\n' || line[n-1] == '\r')) line[--n] = '\0';
        if (n == 0 || line[0] == '#') continue;

        char *tab = strchr(line, '\t');
        if (!tab) continue;
        *tab = '\0';
        const char *id  = line;
        const char *sql = tab + 1;

        char stmt[64];
        snprintf(stmt, sizeof stmt, "p%ld", seq++);

        /* nParams=0 -> 서버가 파라미터 타입을 추론한다 */
        PGresult *r = PQprepare(conn, stmt, sql, 0, NULL);
        if (PQresultStatus(r) != PGRES_COMMAND_OK) {
            printf("%s\tERR\t", id);
            put_clean(PQresultErrorField(r, PG_DIAG_SQLSTATE));
            putchar('\t');
            put_clean(PQresultErrorMessage(r));
            putchar('\n');
            PQclear(r);
            /* 실패한 트랜잭션 상태를 정리 */
            PQclear(PQexec(conn, "ROLLBACK"));
            continue;
        }
        PQclear(r);

        PGresult *d = PQdescribePrepared(conn, stmt);
        if (PQresultStatus(d) != PGRES_COMMAND_OK) {
            printf("%s\tERR\tDESCRIBE\t", id);
            put_clean(PQresultErrorMessage(d));
            putchar('\n');
            PQclear(d);
            continue;
        }

        int ncols = PQnfields(d);
        printf("%s\tOK\t%d\n", id, ncols);
        for (int i = 0; i < ncols; i++) {
            printf("%s\tCOL\t%d\t", id, i);
            put_clean(PQfname(d, i));
            printf("\t%u\t%d\t%u\n",
                   (unsigned) PQftable(d, i),   /* resorigtbl, 0 = 출처 불명 */
                   PQftablecol(d, i),           /* resorigcol, 0 = 출처 불명 */
                   (unsigned) PQftype(d, i));
        }
        PQclear(d);

        char dealloc[96];
        snprintf(dealloc, sizeof dealloc, "DEALLOCATE %s", stmt);
        PQclear(PQexec(conn, dealloc));
    }

    free(line);
    PQfinish(conn);
    return 0;
}
