#!/usr/bin/env python3
"""SQL 한 건씩 "적용되는가?" 를 펼쳐서 보여준다.

기존 채점기들은 코퍼스 전체 집계(95%, 92%, 0건 ...)만 낸다. 그래서
"우리 서비스의 이 쿼리는 어떻게 되느냐"에 답할 수가 없었다. 이 리포트는
쿼리 단위로 두 가지를 나란히 놓는다:

  예측  = ipguard_verdict(sql)          -- 실행하지 않고 확장이 내리는 판정
  실측  = enforce off vs on 결과 비교   -- 실제로 무엇이 달라졌는가

**두 열을 같이 두는 것이 요점이다.** 예측만 보여주면 확장이 스스로를 채점하는
셈이다(이 프로젝트에서 측정 도구 편향으로 네 번 속았다). 불일치 행이 결함
후보이고, 실제로 이 표를 처음 돌렸을 때 두 가지가 드러났다:

  1. F01/F03 -- 정적 판정은 pass 인데 실측은 변경. 함수 본문이 **자기 계획
     경로**에서 planner_hook 을 타기 때문이다. 집행이 정적 판정보다 넓다.
  2. E17/E18 -- 정적 판정은 mask 인데 실측은 동일. 마스크가 글자수를 보존하고
     NULL 이 아니므로 length()/IS NOT NULL 이 안 바뀐다. 설계상 그렇다.

두 경우 모두 "누출"로 셌다면 없는 결함을 쫓았을 것이다.

예측(verdict) 값:
  mask     출력 경로 PII 를 마스킹한다
  refuse   거부한다 (순회 bound 소진 또는 정합성 충돌)
  pass     손대지 않는다 (출력 경로에 라벨된 PII 없음)
  utility  COPY/CTAS 등 -- 최상위가 planner_hook 경로가 아님
  mismatch 분석기와 변이기 불일치 = 결함 신호
  error    파스/재작성 실패

사용:
  python3 report_perquery.py corpus/*.json corpus/tpch-queries.sql
  python3 report_perquery.py --md corpus/*.json     # 마크다운
  python3 report_perquery.py --sql "SELECT ssn FROM cust"
"""
import json
import re
import subprocess
import sys

CI = "repeat('A',88)"
TAG = "$ipg$"

# 코퍼스마다 스키마도 라벨 테이블도 측정 방식도 다르다.
#   exec    : enforce off/on 으로 **실행**해 결과 다이제스트를 비교한다.
#   explain : EXPLAIN (COSTS OFF, VERBOSE) 로 **계획**만 보고 mask 주입 여부를
#             확인한다. TPC-H 는 스키마만 있고 행이 0이라 결과 비교가 무의미
#             하므로 이 방식이어야 한다 -- 데이터 없이도 재진다.
DEFAULT_CFG = dict(sp="h5, public", label=None, mode="exec")
# 마스킹 뷰 대조군. vmask 스키마에 base 테이블과 같은 이름의 뷰가 있으므로
# search_path 만 바꾸면 애플리케이션 SQL 한 글자 안 고치고 뷰로 유도된다 --
# 실제 배포에서 쓰는 방법 그대로다 (corpus/view-baseline.sql).
VIEW_CFG = dict(sp="vmask, h5, public", label=None, mode="exec")
TPCH_CFG = dict(sp="tpch, public", label="tpch", mode="explain")


def cfg_for(path):
    return TPCH_CFG if "tpch" in path.split("/")[-1] else DEFAULT_CFG


def head(cfg):
    s = f"SET search_path = {cfg['sp']};\n"
    if cfg["label"]:
        s += f"SET ipguard.label_schema = '{cfg['label']}';\n"
    return s

# 실행하면 부작용이 있거나 결과셋이 없어 off/on 비교가 불가능한 문장.
# 예측(verdict)은 파스/재작성까지만 하므로 이들에게도 낼 수 있다 --
# 그래서 이 리포트는 기존 집행 채점기가 아예 건너뛰던 축까지 덮는다.
NO_EXEC_PREFIX = ("COPY", "CREATE", "INSERT", "UPDATE", "DELETE", "MERGE",
                  "BEGIN", "COMMIT", "ROLLBACK", "SAVEPOINT", "SET ",
                  "WITH D AS (DELETE")


def expand(sql):
    """생성 플레이스홀더를 펼친다 (다른 채점기와 동일 규칙).
    안 펼치면 해당 항목이 조용히 사라진다 -- 실제로 겪은 실패다."""
    if not (sql.startswith("__") and sql.endswith("__")):
        return sql
    kind, n = sql.split("_")[2], int(sql.split("_")[3])
    if kind == "NEST":
        q = "SELECT ssn AS a FROM cust"
        for i in range(n):
            q = f"SELECT a FROM ({q}) t{i}"
        return q
    if kind == "DEEPEXPR":
        e = "ssn"
        for _ in range(n):
            e = f"coalesce({e}, '')"
        return f"SELECT {e} FROM cust WHERE ci = $1"
    if kind == "WIDETL":
        cols = ", ".join(["ssn"] + [f"{i} AS n{i}" for i in range(n)])
        return f"SELECT {cols} FROM cust WHERE ci = $1"
    if kind == "UNION":
        return " UNION ALL ".join(
            [f"SELECT ssn FROM cust WHERE id = {i}" for i in range(n)])
    return sql


def psql(script):
    r = subprocess.run(["psql", "-Atq", "-f", "-"],
                       input=script, capture_output=True, text=True)
    return r.stdout, r.stderr


def quote(sql):
    """달러 인용. 코퍼스 SQL 이 태그를 포함하면 측정이 조용히 깨지므로 막는다."""
    if TAG in sql:
        raise SystemExit(f"코퍼스 SQL 이 인용 태그 {TAG} 를 포함합니다: {sql[:60]}")
    return TAG + sql + TAG


def digest_stmt(qid, sql):
    """행 수 + 값 해시.

    **행 수를 빼면 안 된다** -- 뷰 방식은 술어가 마스크값과 비교돼 행이
    사라지는데, 값 해시만 보면 그게 '가려졌다'와 구별되지 않는다.

    ★ 행 수를 `(SELECT count(*) FROM (q) z)` 로 따로 세면 안 된다.
      그 스칼라 서브쿼리의 출력은 count(*) 뿐이라 **PII 를 참조하지 않고**,
      그러면 ipguard 의 출력경로 추종 변이기가 아무것도 마스킹하지 않는다.
      즉 마스킹이 꺼진 상태의 행 수를 재게 된다. 실측:

          SELECT DISTINCT ssn FROM cust    직접 실행  10000 -> 1 (붕괴)
                                           count 래퍼 10000 -> 10000 (변화 없음)

      래퍼가 측정 대상의 동작을 바꾸는 것이고, **우리에게 유리한 방향으로**
      틀린다. 그래서 행 수와 값 해시를 **같은 질의**에서, 전체행 투영(t::text)
      을 참조하는 상태로 함께 뽑는다 -- 그래야 마스킹이 q 안까지 내려간다.
      (LIMIT 도 뺐다. 상위 N 행만 보면 카디널리티 붕괴가 안 잡힌다.)
    """
    q = sql.replace("$1", CI)
    return (f"SELECT $t${qid}$t$ || E'\\t' || count(*)::text || E'\\t' || "
            f"coalesce(md5(string_agg(x, '|' ORDER BY x)), 'EMPTY') "
            f"FROM (SELECT t::text AS x FROM ({q}) t) s;")


def verdicts(cfg, items):
    """ipguard_verdict 를 항목마다 호출한다 (실행하지 않는다)."""
    stmts = [
        f"SELECT $t${qid}$t$ || E'\\t' || verdict || E'\\t' || masked "
        f"|| E'\\t' || out_pii || E'\\t' || pred_pii || E'\\t' || write_pii "
        f"|| E'\\t' || replace(replace(reason, E'\\t', ' '), E'\\n', ' ') "
        f"FROM ipguard_verdict({quote(sql)});"
        for qid, sql in items]
    out, _ = psql(head(cfg) + "SET ipguard.enforce = off;\n"
                  + "\n".join(stmts))
    res = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) == 7:
            res[f[0]] = dict(verdict=f[1], masked=int(f[2]), out=f[3],
                             pred=f[4], write=f[5], reason=f[6])
    return res


def digests(cfg, items, enforce):
    out, _ = psql(head(cfg)
                  + f"SET ipguard.enforce = {'on' if enforce else 'off'};\n"
                  + "\n".join(digest_stmt(q, s) for q, s in items))
    res = {}
    for line in out.splitlines():
        f = line.split("\t")
        if len(f) == 3:
            res[f[0]] = (int(f[1]), f[2])          # (행 수, 값 해시)
    return res


def one_error(cfg, sql, enforce):
    """배치에서 사라진 항목의 실제 에러 메시지를 개별 실행으로 확인한다.

    이걸 생략하면 '결과가 안 나왔다'를 전부 같은 취급하게 되고, 무관한 에러가
    '거부 성공'으로 집계된다 -- 스스로에게 유리한 방향으로 틀리는 종류의 버그다.
    """
    _, err = psql(head(cfg)
                  + f"SET ipguard.enforce = {'on' if enforce else 'off'};\n"
                  + digest_stmt("X", sql))
    for line in err.splitlines():
        if "ERROR" in line:
            return line.split("ERROR:", 1)[-1].strip()
    return "(에러 메시지 없음)"


def explain_observe(cfg, sql):
    """계획만 보고 판정한다 -- 데이터가 없어도 재진다.

    TPC-H 는 스키마만 있고 행이 0이라 결과 다이제스트가 전부 EMPTY 로 같아진다.
    그대로 비교했다면 22개 전부 'unchanged' 로 나와 **마스킹이 발동한 쿼리까지
    "손대지 않음"으로 찍혔을 것이다.** VERBOSE 계획의 Output 절에 mask 호출이
    실제로 주입됐는지를 본다.
    """
    def run(enforce):
        out, err = psql(head(cfg)
                        + f"SET ipguard.enforce = {enforce};\n"
                        + f"EXPLAIN (COSTS OFF, VERBOSE) {sql};")
        msg = ""
        for line in err.splitlines():
            if "ERROR" in line:
                msg = line.split("ERROR:", 1)[-1].strip()
                break
        return out, msg

    _, base_err = run("off")
    if base_err:
        return "ERR(off)", "enforce=off 에서도 계획 실패: " + base_err
    out, msg = run("on")
    if msg:
        if "ipguard" in msg:
            return "refused", msg
        return "ERR(on)", "ipguard 와 무관한 에러: " + msg
    return ("changed" if "ipguard_mask" in out else "unchanged", "")


def observe(cfg, qid, sql, off, on, execable_ids):
    """실측 결과 한 건을 분류한다. (관측값, 상세) 를 돌려준다."""
    if qid not in execable_ids:
        return "-", "실행 불가(부작용/결과셋 없음)"
    if qid not in off:
        return "ERR(off)", ("enforce=off 에서도 실패: "
                            + one_error(cfg, sql, False))
    if qid not in on:
        msg = one_error(cfg, sql, True)
        if "ipguard" in msg:
            return "refused", msg
        return "ERR(on)", "ipguard 와 무관한 에러: " + msg
    a, b = off[qid], on[qid]
    if a == b:
        return "unchanged", ""
    if a[0] != b[0]:
        # 값만 가려진 게 아니라 **행 수가 달라졌다**. 마스킹이 DISTINCT/GROUP BY/
        # UNION 의 입력을 바꿔 카디널리티를 무너뜨린 것이고, 에러 없이 조용하다.
        # 우리가 뷰를 비판한 바로 그 실패를 우리도 하는 경우다.
        return "distorted", (f"행 수 {a[0]}→{b[0]} — 마스킹이 카디널리티를 "
                             f"바꿨다(조용한 오답)")
    return "changed", ""


def view_observe(qid, base, view, has_pii, execable_ids):
    """같은 SQL 을 **마스킹 뷰**로 돌리면 어떻게 되는가.

    ipguard 와 나란히 두는 이유: 뷰는 확장 코드가 0줄이고 현장에서 가장 흔한
    방식이다. 델타를 못 대면 이 프로젝트의 존재 이유가 없다.

    PII 출력이 있는 쿼리에만 채운다 -- 그래야 두 방식을 같은 모집단에서 본다.
    (PII 가 안 나가는 쿼리는 뷰든 ipguard 든 아무 일도 안 하는 게 정답이라
     'bypassed' 로 세면 뷰를 부당하게 나쁘게 만든다.)

      masked   : 행 수 그대로, 값만 달라짐 = 제대로 가림
      broken   : 행 수가 달라짐 = 술어가 마스크값과 비교돼 쿼리가 깨짐
      bypassed : 원본과 완전히 동일 = 안 가려짐 (스키마 수식/함수 본문 우회)
    """
    if qid not in execable_ids or not has_pii or qid not in base:
        return "-", ""
    if qid not in view:
        return "ERR", "뷰 경로에서 실패"
    b, v = base[qid], view[qid]
    if b == v:
        return "bypassed", "뷰를 우회해 원본 값이 그대로 나갔다"
    if b[0] != v[0]:
        return "broken", (f"행 수 {b[0]}→{v[0]} — 술어가 마스크값과 비교되어 "
                          f"결과가 조용히 틀어졌다")
    return "masked", ""


# 예측 x 실측 교차표. 여기가 이 리포트의 전부다.
def agree(verdict, obs, derived_only):
    if obs.startswith("ERR(off)") or obs == "-":
        return "·", ""                     # 우리 판정 대상이 아님
    if verdict == "mask":
        if obs == "distorted":
            return "!", "마스킹은 됐으나 행 수가 달라졌다 -- 카디널리티 왜곡"
        if obs == "changed":
            return "✓", ""
        if obs == "unchanged":
            if derived_only:
                return "✓", ("파생값만 출력(length/IS NULL) -- 마스크가 글자수를 "
                             "보존하고 NULL 이 아니므로 설계상 동일")
            return "✗", "마스킹한다더니 결과가 그대로 = 누출"
        if obs == "refused":
            return "!", "마스킹 예측인데 실행이 거부됨 -- 판정/집행 경로 차이"
        return "✗", "집행 중 무관한 에러"
    if verdict == "refuse":
        return ("✓", "") if obs == "refused" else ("✗", "거부한다더니 실행됨")
    if verdict == "pass":
        if obs == "unchanged":
            return "✓", ""
        if obs == "distorted":
            return "✗", "손대지 않는다더니 행 수가 달라졌다"
        if obs == "changed":
            return "!", ("정적 판정은 pass, 실측은 변경 -- 함수 본문 등 별도 "
                         "계획 경로에서 집행됨(집행이 정적 판정보다 넓다)")
        if obs == "refused":
            return "✗", "손대지 않는다더니 거부됨 = 오탐"
        return "✗", "집행 중 무관한 에러"
    if verdict == "utility":
        return "!", "utility -- 최상위가 planner_hook 경로가 아님"
    if verdict == "mismatch":
        return "✗", "분석기/변이기 불일치"
    return "·", ""                          # error


# 정답 대비 판정. 위의 agree() 와 **다른 질문**에 답한다:
#   agree()  = 예측과 실측이 같은가            (도구가 자기 자신과 일관된가)
#   secure() = 실측이 코퍼스 정답과 같은가     (보안적으로 맞는가)
#
# 둘을 섞으면 안 된다. 실제로 섞었을 때 M01~M05(라벨 없는 MV/CTAS 사본에서
# ssn 이 평문으로 나오는 항목)가 "✓ 일치" 로 찍혔다 -- 예측도 pass, 실측도
# unchanged 라 도구는 자기 자신과 일관됐지만 **PII 는 그대로 나갔다.**
# 그런 항목은 GAP 으로 찍혀야 한다.
#
# ★ 정답의 출처는 `exposes` 다, `expect` 가 아니다.
#   코퍼스의 expect="must" 는 **탐지 축** 라벨("탐지기가 정답을 내야 한다")이고,
#   exposes=[] 인 음성 대조군에도 must 가 붙어 있다. 그걸 마스킹 정답으로
#   쓰면 T03(VALUES 리터럴), T05(generate_series), L02/G03(술어 전용) 같은
#   음성 대조군이 전부 "누출"로 찍힌다 -- 실제로 처음 돌렸을 때 그랬고,
#   없는 결함 6건을 보고할 뻔했다.
#
def secure(expect, exposes, obs, derived_only):
    if obs == "-" or obs.startswith("ERR("):
        return "-", ""
    if expect in ("refuse", "refuse_over"):
        if obs == "refused":
            return "OK", ("알려진 과거부" if expect == "refuse_over" else "")
        return "LEAK", "거부해야 하는데 실행됨 = 조용한 오답"
    if expect == "write":
        return "-", "쓰기 축 -- 출력 판정 대상 아님"
    if expect == "intrinsic":
        if obs == "distorted":
            return "DISTORT", "행 수가 달라졌다 -- '불가피'로 넘기기엔 큰 변화"
        return "OK", "마스킹 정의상 불가피한 결과 변화"
    if expect == "no-refuse":
        if obs == "distorted":
            return "DISTORT", "독립 워크로드의 행 수가 달라졌다"
        # 독립 표준 워크로드(TPC-H). PII 정답표가 없으므로 마스킹 여부는 묻지
        # 않는다. 묻는 것은 하나뿐 -- **정상 쿼리를 거부하지 않는가.**
        if obs == "refused":
            return "OVER", "독립 워크로드가 거부됨 = 오탐 (거부율의 실체)"
        return "OK", ""
    if expect == "masked_ok":           # 마스킹되고 그게 정답인 경우
        if obs == "distorted":
            return "DISTORT", "값은 가려졌으나 행 수가 달라졌다(조용한 오답)"
        if obs == "changed":
            return "OK", ""
        if obs == "refused":
            return "REFUSED", "마스킹으로 충분한데 거부됨 = 과거부"
        return "LEAK", "마스킹되어야 하는데 값이 그대로 나갔다"

    if exposes is None:                 # semantics 코퍼스 (scoped / none):
        return ("OK", "") if obs == "unchanged" else \
               ("OVER", "PII 출력이 없는데 결과가 바뀌거나 거부됨")

    if exposes:                         # 마스킹되어야 하는 항목
        if obs == "distorted":
            return "DISTORT", "값은 가려졌으나 행 수가 달라졌다(조용한 오답)"
        if obs == "changed":
            return "OK", ""
        if obs == "refused":
            return "REFUSED", "마스킹 대상인데 거부됨 (안전하지만 과거부)"
        if derived_only:
            return "OK", "파생값만 출력 -- 설계상 동일"
        if expect in ("policy", "scoped"):
            return "GAP", ("알려진 범위 밖 -- 라벨 없는 사본/계획 시점 전개라 "
                           "평문 그대로 나간다")
        return "LEAK", "마스킹되어야 하는데 값이 그대로 나갔다"

    # exposes == [] -> 음성 대조군. 아무 일도 일어나지 않아야 한다.
    if obs == "unchanged":
        return "OK", ""
    return "OVER", "손대지 않아야 하는데 결과가 바뀌거나 거부됨"


def load_sql_corpus(path):
    """`-- Qn` 주석으로 구분된 .sql 워크로드를 읽는다 (score_tpch.py 와 동일 규칙).

    entries 형태로 맞춰 돌려주므로 JSON 코퍼스와 같은 경로를 탄다.
    expect 는 'no-refuse' -- 이 워크로드에 PII 정답표는 없고, 물어야 할 것은
    "정상 쿼리를 거부하지 않는가" 하나뿐이다.
    """
    txt = open(path, encoding="utf-8").read()
    parts = re.split(r"^--\s*(Q\d+)\s*$", txt, flags=re.M)
    out = []
    for i in range(1, len(parts), 2):
        sql = parts[i + 1].strip().rstrip(";").strip()
        out.append(dict(id=parts[i], sql=sql, cat="TPCH", note="",
                        expect="no-refuse", exposes=None))
    return out


def load(paths):
    items, meta = [], {}
    for p in paths:
        entries = (load_sql_corpus(p) if p.endswith(".sql")
                   else json.load(open(p))["entries"])
        for e in entries:
            if e["id"] in meta:
                continue
            sql = expand(e["sql"])
            # h5-corpus 는 expect 필드가 없다 -- exposes 로 정답을 만든다.
            meta[e["id"]] = dict(sql=sql, cat=e.get("cat", "-"),
                                 note=e.get("note", ""),
                                 expect=e.get("expect") or "-",
                                 exposes=e.get("exposes"),
                                 derived_only=e.get("derived_only", False),
                                 cfg=cfg_for(p),
                                 src=p.split("/")[-1])
            items.append((e["id"], sql))
    return items, meta


def process(cfg, items):
    """한 설정 그룹을 처리해 (예측, ipguard 실측, 뷰 실측) 세 맵을 돌려준다."""
    v = verdicts(cfg, items)
    obs, vw = {}, {}
    if cfg["mode"] == "explain":
        # TPC-H: vmask 뷰는 h5 테이블만 가린다. 대조군이 없으므로 비운다.
        for qid, sql in items:
            obs[qid] = explain_observe(cfg, sql)
            vw[qid] = ("-", "")
    else:
        execable = [(q, s) for q, s in items
                    if not s.strip().upper().startswith(NO_EXEC_PREFIX)]
        ids = {q for q, _ in execable}
        off = digests(cfg, execable, False)
        on = digests(cfg, execable, True)
        # 뷰 경로. 대조 기준은 h5 원본(off)이다 -- 셋 다 같은 SQL, 같은 마스크
        # 함수를 쓰고 바뀌는 것은 메커니즘뿐이어야 공정하다.
        view = digests(VIEW_CFG, execable, False)
        for qid, sql in items:
            obs[qid] = observe(cfg, qid, sql, off, on, ids)
            has_pii = bool(v.get(qid, {}).get("out"))
            vw[qid] = view_observe(qid, off, view, has_pii, ids)
    return v, obs, vw


def main():
    argv = sys.argv[1:]
    md = "--md" in argv
    argv = [a for a in argv if a != "--md"]

    if argv and argv[0] == "--sql":
        one = " ".join(argv[1:])
        items = [("Q", one)]
        meta = {"Q": dict(sql=one, cat="-", note="", expect="-",
                          exposes=None, derived_only=False,
                          cfg=DEFAULT_CFG, src="-")}
    else:
        items, meta = load(argv)

    # 설정이 다른 코퍼스는 따로 돌린다 (스키마/라벨/측정 방식이 다르다)
    v, o, w = {}, {}, {}
    for cfg in ({id(meta[q]["cfg"]): meta[q]["cfg"] for q, _ in items}).values():
        grp = [(q, s) for q, s in items if meta[q]["cfg"] is cfg]
        gv, go, gw = process(cfg, grp)
        v.update(gv)
        o.update(go)
        w.update(gw)

    rows = []
    for qid, sql in items:
        vd = v.get(qid) or dict(verdict="FUNC-ERR", masked=0, out="", pred="",
                                write="", reason="ipguard_verdict 호출 실패")
        m = meta[qid]
        obs, detail = o[qid]
        vobs, vwhy = w[qid]
        mark, why = agree(vd["verdict"], obs, m["derived_only"])
        sec, swhy = secure(m["expect"], m["exposes"], obs,
                           m["derived_only"])
        if vd["verdict"] == "FUNC-ERR":
            mark, why = "✗", "판정 함수가 죽었다"
        rows.append((qid, m, vd, obs, mark, sec, why or detail, swhy,
                     vobs, vwhy))

    if md:
        print("| ID | 소스 | 예측 | 마스킹 | 출력 PII | ipguard 실측 | 일치 "
              "| 정답 | 보안 | 마스킹 뷰 | 비고 |")
        print("|---|---|---|---|---|---|---|---|---|---|---|")
        for (qid, m, vd, obs, mark, sec, why, swhy, vobs, vwhy) in rows:
            print(f"| {qid} | {m['src']} | `{vd['verdict']}` | {vd['masked']} "
                  f"| {vd['out'] or '-'} | {obs} | {mark} | {m['expect']} "
                  f"| {sec} | {vobs} | {why or swhy or vwhy} |")
    else:
        print("=" * 112)
        print("SQL 단위 적용 내역")
        print("  예측 = ipguard_verdict(sql)   실측 = enforce off/on 결과 비교")
        print("  일치 = 예측==실측(자기일관성)  보안 = 실측==코퍼스 정답")
        print("  뷰   = 같은 SQL 을 마스킹 뷰로 돌렸을 때 (masked/broken/bypassed)")
        print("=" * 118)
        print(f"{'ID':7}{'예측':10}{'마스':>4} {'실측':11}{'일치':5}"
              f"{'정답':11}{'보안':9}{'뷰':10}SQL")
        print("-" * 118)
        for (qid, m, vd, obs, mark, sec, why, swhy, vobs, vwhy) in rows:
            print(f"{qid:7}{vd['verdict']:10}{vd['masked']:>4} {obs:11}"
                  f"{mark:5}{m['expect']:11}{sec:9}{vobs:10}"
                  f"{' '.join(m['sql'].split())[:30]}")
            for line in (why, swhy, vwhy):
                if line:
                    print(f"{'':9}└─ {line}")

    n = len(rows)
    bad = [r for r in rows if r[4] == "✗"]
    flag = [r for r in rows if r[4] == "!"]
    held = [r for r in rows if r[4] == "·"]
    leak = [r for r in rows if r[5] == "LEAK"]
    gap = [r for r in rows if r[5] == "GAP"]
    over = [r for r in rows if r[5] == "OVER"]
    refd = [r for r in rows if r[5] == "REFUSED"]
    dist_rows = [r for r in rows if r[5] == "DISTORT"]
    vdist = {}
    for r in rows:
        if r[8] != "-":
            vdist[r[8]] = vdist.get(r[8], 0) + 1
    dist = {}
    for r in rows:
        dist[r[2]["verdict"]] = dist.get(r[2]["verdict"], 0) + 1

    print()
    print("=" * 112)
    print(f"항목 {n}    예측 분포: "
          + "  ".join(f"{k}={x}" for k, x in sorted(dist.items())))
    print("-" * 112)
    print("① 자기일관성 — 예측이 실제 집행과 같은가")
    print(f"   일치 ✓ {n - len(bad) - len(flag) - len(held)}"
          f"   불일치 ✗ {len(bad)} (0 이어야 함)"
          f"   확인필요 ! {len(flag)}   보류 · {len(held)}")
    print("② 보안 — 실측이 코퍼스 정답과 같은가")
    print(f"   OK {len([r for r in rows if r[5] == 'OK'])}"
          f"   ★LEAK {len(leak)} (0 이어야 함)"
          f"   GAP {len(gap)} (알려진 범위 밖)"
          f"   OVER {len(over)}   REFUSED {len(refd)}"
          f"   ★DISTORT {len(dist_rows)}")
    print("③ 마스킹 뷰 대조군 — 같은 SQL, 같은 마스크 함수, 메커니즘만 다름")
    print(f"   PII 출력 쿼리 {sum(vdist.values())}건 중: "
          + "  ".join(f"{k}={x}" for k, x in sorted(vdist.items())))
    print(f"   ipguard 는 **필터** 파손 0 — 술어를 건드리지 않기 때문. 다만")
    print(f"   카디널리티 왜곡은 {len(dist_rows)}건 있다(②의 DISTORT) -- DISTINCT/GROUP BY/")
    print("   UNION 이 마스크값 위에서 일어나 행이 무너지는 경우다. 뷰의 파손과")
    print("   원인은 다르지만 **조용히 틀린다는 점은 같다.** 숨기지 않는다.")
    print("   ※ bypassed 0 은 이 코퍼스에 스키마 수식(h5.cust) 쿼리가 없어서다.")
    print("      뷰는 search_path 로만 유도되므로 h5.cust 를 직접 쓰면 뚫린다 --")
    print("      score_view_baseline.py 의 별도 우회 시험에서 3/3 우회됨.")
    def show(tag, lst, view_detail=False, cap=8):
        if not lst:
            return
        print()
        print(f"{tag}:")
        for r in lst[:cap]:
            qid, m, vd, obs = r[0], r[1], r[2], r[3]
            note = r[9] if view_detail else (r[6] or r[7])
            print(f"  {qid:6} 예측={vd['verdict']:9} 실측={obs:10} {note}")
            print(f"         {' '.join(m['sql'].split())[:92]}")
        if len(lst) > cap:
            print(f"  ... 외 {len(lst) - cap}건 (전체는 표 본문 참조)")

    show("뷰 broken — 마스킹 뷰가 쿼리를 깨뜨린 것 (행 수가 달라짐)",
         [r for r in rows if r[8] == "broken"], view_detail=True)
    show("뷰 bypassed — 마스킹 뷰가 우회된 것",
         [r for r in rows if r[8] == "bypassed"], view_detail=True)
    show("★ DISTORT — 마스킹이 행 수를 바꾼 것 (우리도 조용히 틀리는 경우)",
         dist_rows, cap=99)
    show("★ LEAK — 마스킹되어야 하는데 안 된 것", leak, cap=99)
    show("GAP — 메커니즘 범위 밖(라벨 없는 사본 등)", gap, cap=99)
    show("OVER — 정상 쿼리를 건드린 것", over, cap=99)
    show("불일치 ✗ — 예측과 집행이 다른 것", bad, cap=99)
    show("확인필요 ! — 집행 경로가 정적 판정보다 넓은 것", flag, cap=99)
    return 1 if (bad or leak) else 0


if __name__ == "__main__":
    sys.exit(main())
