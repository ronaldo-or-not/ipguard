#!/usr/bin/env python3
"""§11-5 held-out 평가 — **최초 관측**. 한 번의 결정적 실행.

실행 순서를 프로토콜대로 고정한다(docs/heldout-protocol.md):

   1. P0 용 깨끗한 DB·registry 복원
   2. M(D1)=M(D2) 와 applicability matrix 를 **먼저** 저장·digest
   3. P0 실행
   4. 깨끗한 상태로 재복원
   5. **raw obligation stream** 에서 P1 인증서를 기계적으로 생성
   6. 인증서 목록·digest 를 **게이트 실행 전에** 저장
   7. P1 의 δ-equivalence matrix 를 **먼저** 저장·digest
   8. P1 실행
   9. 독립 oracle 과 비교
  10. raw per-trial 을 **수정 없이** 보존한 뒤 요약

★ oracle 독립성: 게이트의 C lineage 분석을 쓰지 않는다. 코퍼스 metadata 의
  lineage 주석과 **하네스 자체의 텍스트 규칙**으로 마스킹 위치를 정한다.
  같은 버그가 양쪽에 있어 fidelity 100% 가 나오는 것을 막는다.

★ 수동 감사 표본은 **결과를 보고 고르지 않는다** -- query id 해시로 뽑는다.

사용: python3 tools/run_heldout.py corpus/heldout.json out/
"""
import os
import sys

_here = os.path.dirname(os.path.abspath(__file__))
sys.path[:] = [q for q in sys.path if os.path.abspath(q or ".") != _here]

import hashlib     # noqa: E402
import json        # noqa: E402
import re          # noqa: E402
import subprocess  # noqa: E402

LABELED = {"hx_cust": {"ssn": "hxsec", "birth": "hxdate"},
           "hx_pay": {"salary": "hxnum"}}
PK = {"hx_cust": "id", "hx_pay": "pid"}
COLS = {"hx_cust": ["id", "grade", "dept", "amt", "ssn", "birth"],
        "hx_pay": ["pid", "id", "band", "salary"]}
TYPES = {"id": "int", "grade": "text", "dept": "text", "amt": "int",
         "ssn": "text", "birth": "date", "pid": "int", "band": "text",
         "salary": "int"}

SCHEMA = """
SET client_min_messages = warning;
DROP TABLE IF EXISTS h5.hx_cust, h5.hx_pay;
CREATE TABLE h5.hx_cust (id int PRIMARY KEY, grade text, dept text,
                         amt int, ssn text, birth date);
CREATE TABLE h5.hx_pay  (pid int PRIMARY KEY, id int, band text, salary int);
DELETE FROM h5.pii_label WHERE relname IN ('hx_cust','hx_pay');
INSERT INTO h5.pii_label VALUES
  ('hx_cust','ssn','hxsec'), ('hx_cust','birth','hxdate'),
  ('hx_pay','salary','hxnum');
"""

# 깨끗한 registry: 세 마스크 인스턴스 + baseline + comparator.
# ★ order_factor / equality_factor 는 **fails** 다 -- 상수 마스크의 실제 성질이다.
REGISTRY = """
SET client_min_messages = warning;
DELETE FROM ipguard_declassification;
DELETE FROM ipguard_mask_instance;
SELECT ipguard_register_mask('ipguard_mask(anyelement,text)'::regprocedure,
       t.i::regtype, t.o::regtype, 'kind=' || t.k, '', 'held-out')
  FROM (VALUES ('hxsec','text','text'), ('hxdate','date','date'),
               ('hxnum','int','int')) t(k,i,o);
INSERT INTO ipguard_mask_capability(mask_id, capability, claim, assurance)
SELECT m.mask_id, c.cap, c.cl::ipguard_claim, 'trusted_provider'
  FROM ipguard_mask_instance m, (VALUES
    ('determinism','holds'), ('total','holds'),
    ('null_equivalence','holds'),
    ('order_factor','fails'), ('equality_factor','fails')) c(cap,cl);
SELECT ipguard_register_default_comparators(mask_id, 'fails', 'fails',
                                            'trusted_provider')
  FROM ipguard_mask_instance;
"""


def psql(script, quiet=True):
    return subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                          input=script, capture_output=True, text=True)


def lit(v, ty):
    if v is None:
        return "NULL"
    if ty in ("text", "date"):
        return "'" + str(v).replace("'", "''") + "'"
    return str(v)


def load(table, rows):
    vals = ",".join("(" + ",".join(lit(r[c], TYPES[c]) for c in COLS[table])
                    + ")" for r in rows)
    return (f"SET client_min_messages=warning; TRUNCATE h5.{table}; "
            f"INSERT INTO h5.{table} VALUES {vals};")


def masked_view(rows, table):
    """M(D) -- 라벨 컬럼을 상수로. NULL 은 NULL 로 남는다."""
    return [tuple(("<m>" if r[c] is not None else None) if c in LABELED[table]
                  else r[c] for c in COLS[table]) for r in rows]


def check_masked_equiv(d1, d2, table):
    f = []
    if len(d1) != len(d2):
        return ["행 다중도 불일치"]
    pub = [c for c in COLS[table] if c not in LABELED[table]]
    for c in pub:
        if [r[c] for r in d1] != [r[c] for r in d2]:
            f.append(f"공개 컬럼 {c}")
    if [r[PK[table]] for r in d1] != [r[PK[table]] for r in d2]:
        f.append("공개 row identity")
    for c in LABELED[table]:
        if [r[c] is None for r in d1] != [r[c] is None for r in d2]:
            f.append(f"NULL 위치 {c}")
    if sorted(map(str, masked_view(d1, table))) != \
       sorted(map(str, masked_view(d2, table))):
        f.append("마스킹된 bag")
    return f


WHERE_RE = re.compile(
    r"\sWHERE\s(.+?)(?=\s(?:GROUP BY|ORDER BY|LIMIT|UNION|EXCEPT|INTERSECT)\s|$)",
    re.I)


def where_of(sql):
    """★ generator 가 만든 **고정 형식**에서 WHERE 절을 뽑는다.
    파서가 아니라 harness 쪽 텍스트 규칙이다 -- 게이트를 쓰지 않는다."""
    m = WHERE_RE.search(sql)
    return m.group(1).strip() if m else None


def delta_trace(table, pred, side_loaded):
    """δ_{Q,θ}(D) = predicate outcome trace.
    (public row occurrence id, T/F/NULL) 를 정렬해 canonical 로 만든다.
    ★ 3VL 을 T/F 로 축약하지 않는다."""
    if pred is None:
        return "()"
    q = (f"SET search_path=h5,public; SET ipguard.enforce=off;\n"
         f"SELECT 'D:'||{PK[table]}||'='||"
         f"coalesce(({pred})::text,'NULL') FROM h5.{table} ORDER BY {PK[table]};")
    r = psql(q)
    return "|".join(sorted(l[2:] for l in r.stdout.splitlines()
                           if l.startswith("D:")))


def run_batch(queries, prelude):
    """한 세션에서 질의들을 돌린다.

    ★ stderr 를 stdout 에 **합쳐서** 받는다. 그래야 오류가 난 질의도 순서대로
      정렬된다 -- 분리된 파이프로는 어느 질의가 실패했는지 맞출 수 없다.
    \echo 마커를 앞에 두어 오류가 나도 경계를 잃지 않는다.
    """
    parts = ["\\set ON_ERROR_STOP 0", prelude]
    for q in queries:
        one = " ".join(q["sql"].split())
        parts.append(f"\\echo QSTART:{q['id']}")
        if "$1" in one:
            # 파라미터 질의는 고정 θ binding 으로 돌린다(코퍼스 metadata 의 타입).
            th = []
            for pm in q.get("params", []):
                th.append("'x'" if pm["type"] == "text"
                          else "DATE '1990-01-01'" if pm["type"] == "date"
                          else "1")
            parts.append(f"PREPARE hq AS {one};")
            parts.append("CREATE TEMP VIEW hqv AS SELECT 1;" if False else "")
            parts.append(f"SELECT 'Q:'||coalesce(md5(string_agg(z::text,'|' "
                         f"ORDER BY z::text)),'(empty)') FROM "
                         f"(SELECT * FROM (SELECT 1) _ WHERE false) z;"
                         if False else
                         f"\\echo QPARAM")
            parts.append(f"EXECUTE hq({','.join(th)});")
            parts.append("DEALLOCATE hq;")
        else:
            parts.append(
                f"SELECT 'Q:'||coalesce(md5(string_agg(z::text,'|' "
                f"ORDER BY z::text)),'(empty)') FROM ({one}) z;")
        parts.append(f"\\echo QEND:{q['id']}")
    r = subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                       input="\n".join(parts), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    res, cur, buf = {}, None, []
    for line in r.stdout.splitlines():
        if line.startswith("QSTART:"):
            cur, buf = line[7:], []
        elif line.startswith("QEND:"):
            if cur:
                res[cur] = classify(buf)
            cur = None
        elif cur is not None:
            buf.append(line)
    return res


def classify(buf):
    """(verdict, detail) -- verdict ∈ accept | reject | error"""
    txt = "\n".join(buf)
    if "해소되지 않은 의무" in txt:
        m = [l for l in buf if "DETAIL" in l]
        return ("reject", (m[0][8:120] if m else "")[:120])
    if "ERROR" in txt:
        m = [l for l in buf if "ERROR" in l]
        return ("error", m[0][-90:] if m else "?")
    q = [l[2:] for l in buf if l.startswith("Q:")]
    if q:
        return ("accept", q[0])
    p = [l for l in buf if l and not l.startswith(("SET", "PREPARE",
                                                   "DEALLOCATE", "QPARAM"))]
    return ("accept", hashlib.md5("|".join(sorted(p)).encode()).hexdigest())


def raw_obligations(queries):
    """discharge **이전의** structural obligation stream.

    ★ 정책 발급의 입력은 이것이어야 한다. 현재 인증서 유무·게이트 판정을
      입력으로 쓰면 정책 생성이 registry 상태에 종속된다.
    """
    parts = ["\\set ON_ERROR_STOP 0",
             "SET search_path=h5,public; SET ipguard.enforce=off;"]
    for q in queries:
        one = " ".join(q["sql"].split())
        parts.append(f"\\echo OSTART:{q['id']}")
        parts.append(
            "SELECT 'O:'||effect||E'\\t'||sink||E'\\t'||context||E'\\t'"
            "||context_key||E'\\t'||context_canonical "
            f"FROM ipguard_obligations($ipg${one}$ipg$);")
        parts.append(f"\\echo OEND:{q['id']}")
    r = subprocess.run(["psql", "-d", "ipdev", "-At", "-f", "-"],
                       input="\n".join(parts), stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True)
    out, cur = {}, None
    for line in r.stdout.splitlines():
        if line.startswith("OSTART:"):
            cur = line[7:]
            out[cur] = []
        elif line.startswith("OEND:"):
            cur = None
        elif cur is not None and line.startswith("O:"):
            f = line[2:].split("\t")
            if len(f) >= 5:
                out[cur].append({"effect": f[0], "sink": f[1], "context": f[2],
                                 "context_key": f[3], "canonical": f[4]})
    return out


ORIGINS = ("WHERE/JOIN predicate", "HAVING predicate", "aggregate FILTER")


def p1_certificates(obl, queries):
    """★ 결정적 발급. raw obligation stream 만 입력이다.

    origin ∈ {WHERE, JOIN_ON, HAVING, AGG_FILTER, SEMIJOIN} · effect = CARD ·
    sink = 그 obligation 의 active sink · exact context_key.
    VAL/EQ/ORD 는 허가하지 않는다. **수동 가감 없음.**
    """
    qmap = {q["id"]: q for q in queries}
    certs = []
    for qid, rows in sorted(obl.items()):
        q = qmap.get(qid)
        if q is None:
            continue
        tb = q["table"]
        for o in rows:
            if o["effect"] != "CARD":
                continue
            if not any(o["context"].startswith(x) for x in ORIGINS):
                continue
            if not o["context_key"]:
                continue
            for col in sorted(LABELED[tb]):
                if f".{col}" in o["context"] or col in o["context"]:
                    pass
            certs.append({
                "policy_version": "P1/v1", "table": tb,
                "effect": "CARD", "sink": o["sink"],
                "context_key": o["context_key"],
                "canonical": o["canonical"],
                "param_scope": "all_values" if q.get("params") else "none",
                "observation": "predicate-decision-trace"})
    # ★ record hash 를 정렬해 digest -- SQL 반환 순서에 의존하지 않는다
    recs = sorted(hashlib.sha256(
        ("".join(f"{k}:{len(str(c[k]))}:{c[k]};" for k in sorted(c))).encode()
    ).hexdigest() for c in certs)
    return certs, hashlib.sha256("".join(recs).encode()).hexdigest()


def install_certs(certs):
    if not certs:
        return
    parts = ["SET client_min_messages=warning;",
             "SET search_path=h5,public;"]
    for c in certs:
        canon = c["canonical"].replace("'", "''")
        for col in sorted(LABELED[c["table"]]):
            parts.append(
                "INSERT INTO ipguard_declassification"
                "(relid,attnum,effect,sink,context_key,context_canonical,"
                " param_scope,observation,rationale) "
                f"SELECT 'h5.{c['table']}'::regclass, a.attnum, 'CARD',"
                f" '{c['sink']}', '{c['context_key']}', '{canon}',"
                f" '{c['param_scope']}', '{c['observation']}', 'P1 auto' "
                f"FROM pg_attribute a WHERE a.attrelid='h5.{c['table']}'::regclass"
                f" AND a.attname='{col}' ON CONFLICT DO NOTHING;")
    psql("\n".join(parts))


def digest(obj):
    return hashlib.sha256(
        json.dumps(obj, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


MASKABLE = re.compile(r"^(ssn|birth|salary)$")


def oracle_class(q):
    """이 질의의 fidelity 를 독립 oracle 로 잴 수 있는가.

    ★ 게이트의 lineage 분석을 쓰지 않는다. 코퍼스 metadata(out_cols)와
      하네스 자체 텍스트 규칙만 쓴다.

      A  출력에 라벨 컬럼이 없다 -> Mout = 항등. privileged 결과와 직접 비교
      C  출력이 라벨 컬럼(또는 그 파생)이다 -> 마스크 재현이 필요하다.
         이 하네스는 구현하지 않았다 -- **oracle 미구현으로 집계**한다
    """
    for c in q.get("out_cols", []):
        for lab in ("ssn", "birth", "salary"):
            if lab in str(c):
                return "C"
    return "A"


def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    body = json.load(open(src))
    queries = body["queries"]
    pairs = body["db_pairs"]
    byq = {q["id"]: q for q in queries}

    print("=" * 78)
    print("§11-5 held-out 평가 — 최초 관측")
    print("=" * 78)

    # ---- 1) 깨끗한 상태 ------------------------------------------------
    psql(SCHEMA); psql(REGISTRY)
    print("[1] 스키마·registry 복원")

    # ---- 2) applicability matrix (게이트 실행 **전**) -------------------
    appl = {}
    for pt in body["pair_types"]:
        for tb in sorted(LABELED):
            d1, d2 = pairs[pt][tb]["d1"], pairs[pt][tb]["d2"]
            fails = check_masked_equiv(d1, d2, tb)
            appl[f"{pt}/{tb}"] = {"masked_equivalent": not fails,
                                  "failures": fails}
    json.dump(appl, open(f"{outdir}/applicability.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    ok_me = sum(1 for v in appl.values() if v["masked_equivalent"])
    print(f"[2] applicability digest {digest(appl)[:16]}  "
          f"masked-equivalent {ok_me}/{len(appl)}")

    def run_policy(tag):
        """(pair_type, table, side) 마다 적재 후 그 테이블 질의를 일괄 실행."""
        trials = {}
        for pt in body["pair_types"]:
            for tb in sorted(LABELED):
                qs = [q for q in queries if q["table"] == tb]
                for side in ("d1", "d2"):
                    psql(load(tb, pairs[pt][tb][side]))
                    res = run_batch(qs, "SET search_path=h5,public;\n"
                                        "SET ipguard.enforce=on;\n"
                                        "SET ipguard.gate=release;\n"
                                        "SET ipguard.on_divergence=allow;")
                    for qid, v in res.items():
                        trials.setdefault((qid, pt), {})[side] = v
                # privileged (oracle 기준선) -- D1 만
                psql(load(tb, pairs[pt][tb]["d1"]))
                pv = run_batch(qs, "SET search_path=h5,public;\n"
                                   "SET ipguard.enforce=off;")
                for qid, v in pv.items():
                    trials.setdefault((qid, pt), {})["priv"] = v
        return trials

    # ---- 3) P0 ---------------------------------------------------------
    print("[3] P0 실행 중 …")
    p0 = run_policy("P0")
    print(f"    trial {len(p0)}")

    # ---- 4) 깨끗한 상태로 재복원 ---------------------------------------
    psql(REGISTRY)
    print("[4] registry 재복원")

    # ---- 5) raw obligation -> P1 인증서 (기계적) -----------------------
    obl = raw_obligations(queries)
    certs, cdg = p1_certificates(obl, queries)
    print(f"[5] raw obligation {sum(len(v) for v in obl.values())}건 -> "
          f"P1 인증서 {len(certs)}건")

    # ---- 6) 인증서·digest 를 게이트 실행 **전에** 저장 ------------------
    json.dump({"certificates": certs, "digest": cdg},
              open(f"{outdir}/p1-certificates.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    print(f"[6] 인증서 digest {cdg[:16]}")

    # ---- 7) δ-equivalence matrix (게이트 실행 **전**) ------------------
    delta = {}
    for pt in body["pair_types"]:
        for tb in sorted(LABELED):
            for q in [x for x in queries if x["table"] == tb]:
                pred = where_of(q["sql"])
                if pred is None or "$1" in pred:
                    delta[f"{q['id']}/{pt}"] = {"delta_equivalent": True,
                                                "reason": "술어 없음/파라미터"}
                    continue
                psql(load(tb, pairs[pt][tb]["d1"]))
                t1 = delta_trace(tb, pred, "d1")
                psql(load(tb, pairs[pt][tb]["d2"]))
                t2 = delta_trace(tb, pred, "d2")
                delta[f"{q['id']}/{pt}"] = {"delta_equivalent": t1 == t2}
    json.dump(delta, open(f"{outdir}/delta.json", "w"),
              ensure_ascii=False, indent=1, sort_keys=True)
    de = sum(1 for v in delta.values() if v["delta_equivalent"])
    print(f"[7] δ matrix digest {digest(delta)[:16]}  "
          f"δ-equivalent {de}/{len(delta)}")

    # ---- 8) P1 ---------------------------------------------------------
    install_certs(certs)
    print("[8] P1 실행 중 …")
    p1 = run_policy("P1")

    # ---- 9~10) raw per-trial 보존 -> 요약 ------------------------------
    raw = []
    for pol, tr in (("P0", p0), ("P1", p1)):
        for (qid, pt), v in sorted(tr.items()):
            q = byq[qid]
            d1v, d2v = v.get("d1", ("error", "missing")), v.get("d2", ("error", "missing"))
            priv = v.get("priv", ("error", "missing"))
            oc = oracle_class(q)
            acc = d1v[0] == "accept"
            raw.append({
                "query_id": qid, "pair_type": pt, "policy": pol,
                "theta": q.get("params", []),
                "touches_labeled": q["touches_labeled"],
                "lineage": q["lineage"], "shape": q["shape"], "table": q["table"],
                "masked_equivalent": appl[f"{pt}/{q['table']}"]["masked_equivalent"],
                "delta_equivalent": (True if pol == "P0"
                                     else delta[f"{qid}/{pt}"]["delta_equivalent"]),
                "gate_accept": acc,
                "rejection_reason": (d1v[1] if d1v[0] == "reject" else
                                     d1v[1] if d1v[0] == "error" else None),
                "verdict": d1v[0],
                "n_raw_obligations": len(obl.get(qid, [])),
                "result_d1": d1v[1], "result_d2": d2v[1],
                "privileged": priv[1],
                "oracle_class": oc,
                "fidelity_result": (None if not acc else
                                    ("pass" if (oc == "A" and d1v[1] == priv[1])
                                     else "fail" if oc == "A" else None)),
                "opacity_result": (None if not acc else
                                   ("pass" if d1v[1] == d2v[1] else "fail")),
                "oracle_error": (None if oc == "A" else "oracle 미구현(C)"),
            })
    with open(f"{outdir}/raw-trials.jsonl", "w") as f:
        for r in raw:
            f.write(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n")
    rdg = hashlib.sha256(open(f"{outdir}/raw-trials.jsonl", "rb").read()).hexdigest()
    print(f"[9~10] raw trial {len(raw)}건  digest {rdg[:16]}")

    # 수동 감사 표본 -- ★ 결과를 보고 고르지 않는다. query id 해시로 뽑는다.
    audit = sorted(q["id"] for q in queries
                   if int(hashlib.sha256(q["id"].encode()).hexdigest()[:4], 16) % 40 == 0)
    json.dump({"audit_sample": audit, "rule": "sha256(query_id)[:4] % 40 == 0"},
              open(f"{outdir}/audit-sample.json", "w"),
              ensure_ascii=False, indent=1)
    print(f"       수동 감사 표본 {len(audit)}건 (id 해시로 선택)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
