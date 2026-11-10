#!/usr/bin/env python3
"""P1 declassification 발급 — **exact source** 만.

held-out v1 의 발급기(PD1)는 인증서를 해당 테이블의 **모든 라벨 컬럼**에
설치했다. 컬럼 제한 루프의 본문이 `pass` 인 죽은 코드였기 때문이다. 그 결과

    birth 술어에서 나온 CARD 인증서가 ssn 의 CARD declassification 도 부여

했고, 실제 설치 범위가 명세의 P1 보다 넓어졌다:

    Declass_implemented  ≠  Declass_specified

더 넓은 δ 를 전제로 하면 opacity 정리가 성립할 수는 있지만 그것은 논문에
적은 P1 정리가 아니다. 그래서 이 모듈은 다음을 **보장**한다.

  1. 발급 대상은 obligation 의 `ordered_sources[]` 와 정확히 일치한다.
     사람이 읽는 `context` 문자열을 파싱하지 않는다.
  2. 수동 루프나 "테이블의 라벨 컬럼 전부" 순회가 없다.
  3. 설치 전에 canonical manifest 와 record digest 를 고정한다.
  4. 설치 후 DB 의 실제 행 집합이 manifest 와 **집합으로 같은지** 확인한다.
     개수만 세지 않는다 -- 개수가 같고 대상이 다른 경우가 정확히 PD1 이었다.

사용:
    python3 tools/policy_p1.py issue   <obligations.json> <manifest.json>
    python3 tools/policy_p1.py install <manifest.json>
    python3 tools/policy_p1.py verify  <manifest.json>
"""
import hashlib
import json
import subprocess
import sys

# CARD 를 허가할 수 있는 origin. 이 목록 밖의 context 는 발급하지 않는다.
# VAL/EQ/ORD 는 어떤 origin 에서도 허가하지 않는다 -- 정책 v1 의 정의다.
ORIGINS = ("WHERE/JOIN predicate", "HAVING predicate", "aggregate FILTER")

POLICY_VERSION = "P1/v2"
OBSERVATION = "predicate-decision-trace"


def psql(script, dbname="ipdev"):
    return subprocess.run(["psql", "-q", "-A", "-t", "-d", dbname, "-f", "-"],
                          input=script, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)


def rec_hash(r):
    """레코드 하나의 정규 해시. 키 순서·직렬화 방식에 의존하지 않는다."""
    return hashlib.sha256(
        "".join(f"{k}:{len(str(r[k]))}:{r[k]};" for k in sorted(r)).encode()
    ).hexdigest()


def manifest_digest(rows):
    """레코드 해시를 **정렬해** 합친다 -- SQL 반환 순서에 의존하지 않는다."""
    return hashlib.sha256("".join(sorted(rec_hash(r) for r in rows)).encode()
                          ).hexdigest()


def issue(obl_by_qid, params_by_qid):
    """obligation stream -> 설치할 행 목록.

    ★ 행 하나는 (obligation, 그 obligation 자신의 source 하나) 쌍이다.
      테이블을 보고 컬럼을 넓히지 않는다.
    """
    rows, skipped = {}, {"effect": 0, "origin": 0, "no_key": 0, "no_source": 0}
    for qid in sorted(obl_by_qid):
        scope = "all_values" if params_by_qid.get(qid) else "none"
        for o in obl_by_qid[qid]:
            if o["effect"] != "CARD":
                skipped["effect"] += 1
                continue
            if not any(o["context"].startswith(x) for x in ORIGINS):
                skipped["origin"] += 1
                continue
            if not o.get("context_key"):
                skipped["no_key"] += 1
                continue
            src = o.get("ordered_sources") or []
            if not src:
                skipped["no_source"] += 1
                continue
            for s in src:
                relid, _, attnum = s.partition(".")
                r = {"relid": int(relid), "attnum": int(attnum),
                     "effect": "CARD", "sink": o["sink"],
                     "context_key": o["context_key"],
                     "context_canonical": o["canonical"],
                     "param_scope": scope,
                     "observation": OBSERVATION,
                     "policy_version": POLICY_VERSION}
                # 같은 (relid, attnum, effect, sink, context_key) 가 여러 질의에서
                # 나올 수 있다. DB 의 유일성 키와 같은 단위로 접는다.
                k = (r["relid"], r["attnum"], r["effect"], r["sink"],
                     r["context_key"])
                if k in rows and rows[k]["param_scope"] != scope:
                    # ★ 같은 문맥이 파라미터 질의와 비파라미터 질의 양쪽에서
                    #   나오면 좁은 쪽(none)으로 고정한다. 설치 순서에 따라
                    #   유효 scope 가 갈리면 안 된다.
                    rows[k]["param_scope"] = "none"
                    continue
                rows.setdefault(k, r)
    return list(rows.values()), skipped


def install_sql(rows):
    parts = ["SET client_min_messages=warning;",
             "SET search_path=h5,public;"]
    for r in rows:
        canon = r["context_canonical"].replace("'", "''")
        parts.append(
            "INSERT INTO ipguard_declassification"
            "(relid,attnum,effect,sink,context_key,context_canonical,"
            " param_scope,observation,rationale) VALUES"
            f"({r['relid']},{r['attnum']},'{r['effect']}','{r['sink']}',"
            f"'{r['context_key']}','{canon}','{r['param_scope']}',"
            f"'{r['observation']}','{r['policy_version']} exact-source')"
            " ON CONFLICT DO NOTHING;")
    return "\n".join(parts)


def installed_rows(relids=None):
    """relid 는 regclass 다 -- **::oid 로 캐스팅**해야 이름이 아니라 수가 온다."""
    where = ("" if not relids else
             " WHERE relid::oid IN (%s)" % ",".join(str(x) for x in relids))
    r = psql("SET search_path=h5,public;\n"
             "SELECT 'R:'||relid::oid||'|'||attnum||'|'||effect||'|'||sink||'|'"
             "||context_key||'|'||param_scope||'|'||observation "
             f"FROM ipguard_declassification{where} ORDER BY 1;")
    out = []
    for l in r.stdout.splitlines():
        if not l.startswith("R:"):
            continue
        f = l[2:].split("|")
        out.append({"relid": int(f[0]), "attnum": int(f[1]), "effect": f[2],
                    "sink": f[3], "context_key": f[4], "param_scope": f[5],
                    "observation": f[6]})
    return out


def key_of(r):
    return (r["relid"], r["attnum"], r["effect"], r["sink"], r["context_key"],
            r["param_scope"], r["observation"])


def verify(rows, relids=None):
    """설치된 행 집합이 manifest 와 **집합으로 같은가**.

    개수만 맞춰 보면 PD1 을 못 잡는다 -- 그때도 개수는 '설명 가능'했다.
    """
    want = {key_of(r) for r in rows}
    if relids is None:
        relids = sorted({r["relid"] for r in rows}) or None
    got = {key_of(r) for r in installed_rows(relids)}
    return {"ok": want == got, "n_manifest": len(want), "n_installed": len(got),
            "missing": sorted(want - got)[:10],
            "extra": sorted(got - want)[:10],
            "n_missing": len(want - got), "n_extra": len(got - want)}


def main():
    cmd = sys.argv[1]
    if cmd == "issue":
        body = json.load(open(sys.argv[2]))
        rows, skipped = issue(body["obligations"], body.get("params", {}))
        man = {"policy_version": POLICY_VERSION, "origins": list(ORIGINS),
               "observation": OBSERVATION, "n": len(rows),
               "digest": manifest_digest(rows),
               "skipped": skipped,
               "distinct_columns": sorted({f"{r['relid']}.{r['attnum']}"
                                           for r in rows}),
               "rows": sorted(rows, key=key_of)}
        json.dump(man, open(sys.argv[3], "w"), ensure_ascii=False, indent=1,
                  sort_keys=True)
        print(f"발급 {len(rows)}행  digest {man['digest'][:16]}  "
              f"대상 컬럼 {len(man['distinct_columns'])}개")
        print(f"  제외: {skipped}")
        return 0
    man = json.load(open(sys.argv[2]))
    if cmd == "install":
        psql(install_sql(man["rows"]))
        print(f"설치 시도 {man['n']}행")
        return 0
    if cmd == "verify":
        v = verify(man["rows"])
        print(f"manifest {v['n_manifest']}행 / 설치 {v['n_installed']}행  "
              f"일치={v['ok']}")
        if not v["ok"]:
            print(f"  누락 {v['n_missing']}: {v['missing']}")
            print(f"  초과 {v['n_extra']}: {v['extra']}")
        return 0 if v["ok"] else 1
    print(f"알 수 없는 명령: {cmd}", file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
