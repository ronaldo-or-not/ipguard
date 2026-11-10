#!/usr/bin/env python3
"""§11-5 평가 동결 아티팩트를 만든다.

Git 커밋만으로는 재현되지 않는다. 게이트 판정은 **카탈로그 OID·collation
버전·빌드 지문·레지스트리 시드**에 의존하고, 그중 어느 것도 소스에 없다.

동결해야 하는 것:

  IPGUARD_BUILD_ID          provider build manifest (Makefile 이 주입)
  manifest axes             그 manifest 가 **덮은 축** -- 밖은 안 잡힌다
  PostgreSQL 버전과 build
  collation OID 와 실제 version   OS 라이브러리가 바뀌면 정렬 의미가 바뀐다
  registry / declassification 시드
  held-out generator seed
  corpus + oracle metadata digest

★ OID 기반 canonical 은 **한 데이터베이스 안에서만** 안정적이다. dump/restore
  후 OID 가 달라지므로 **인증서는 설치 후 ipguard_obligations() 로 재발급**해야
  한다. 이 사실을 아티팩트에 같이 적는다.

사용: python3 tools/eval_freeze.py > results/eval-freeze.md
"""
import hashlib
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 코퍼스·oracle metadata 는 digest 로 잠근다. 파일이 바뀌면 수치도 다시 내야 한다.
DIGEST_FILES = [
    "corpus/divergence.json", "corpus/h5-corpus.json", "corpus/semantics.json",
    "corpus/tpch-queries.sql", "corpus/tpch-schema.sql", "corpus/schema.sql",
    "ext/ipguard.c", "ext/ipguard--1.0.sql", "ext/Makefile",
    "tools/score_gate.py", "tools/score_registry.py", "tools/score_fragment.py",
    "tools/gen_heldout.py", "tools/validate_heldout.py",
    "corpus/heldout.json", "corpus/peer-golden.json",
    "docs/policy-p0-p1.md", "docs/heldout-protocol.md",
]


def sh(cmd):
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return r.stdout.strip() or r.stderr.strip()


def psql(sql):
    return sh("psql -d ipdev -qAt -c " + repr(sql).replace("'", '"', 0)
              if False else
              f"""psql -d ipdev -qAt -c $'{sql.replace("'", chr(39)*2)}'""")


def remote(sql):
    """서버에서 psql 을 돌린다. 측정 환경이 그쪽이므로 거기 값이 정본이다."""
    esc = sql.replace("'", "'\"'\"'")
    return sh("ssh rinomaru@db.example.internal "
              "'export PATH=$HOME/pg/bin:$PATH PGHOST=$HOME/.pgsock "
              f"PGPORT=55432; psql -d ipdev -qAt -c \"{esc}\"'")


def digest(path):
    p = os.path.join(ROOT, path)
    if not os.path.exists(p):
        return "(없음)"
    with open(p, "rb") as f:
        return hashlib.sha256(f.read()).hexdigest()[:16]


def main():
    print("# §11-5 평가 동결 아티팩트")
    print()
    print("Git 커밋만으로는 재현되지 않는다. 게이트 판정은 카탈로그 OID·")
    print("collation 버전·빌드 지문·레지스트리 시드에 의존하고, 그중 어느 것도")
    print("소스에 없다. 아래가 이 평가의 **정본**이다.")
    print()
    print("## 코드")
    print()
    print("```")
    print("commit      " + sh("git -C %s rev-parse HEAD" % ROOT))
    print("branch      " + sh("git -C %s rev-parse --abbrev-ref HEAD" % ROOT))
    print("dirty       " + ("yes ★ 동결 전에 커밋할 것"
                            if sh("git -C %s status --porcelain" % ROOT) else "no"))
    print("```")
    print()
    print("## 빌드 · 런타임")
    print()
    print("```")
    bid = remote("SELECT ipguard_build_id()")
    print("IPGUARD_BUILD_ID   " + bid + "   (SHA-256, 전체)")
    print("  표시용 축약       " + bid[:12] + "   ★ 보안 판정에는 전체를 쓴다")
    print("manifest axes      " + remote("SELECT ipguard_manifest_axes()"))
    print("postgres           " + remote("SELECT version()"))
    print("```")
    print()
    print("> **manifest 가 덮지 않는 축**(링크 라이브러리·ABI·같은 소스의 다른")
    print("> 바이너리)의 변경은 잡히지 않는다. `BuildSound(provider_manifest)`")
    print("> 는 전제이지 검증된 사실이 아니다 — `results/registry.md` 참조.")
    print()
    print("## collation — OID 와 **실제** version")
    print()
    print("OS 라이브러리가 바뀌면 정렬 의미가 바뀐다. `order_factor` 인증서는")
    print("등록된 collation에서만 증명된 주장이므로 여기가 흔들리면 무효다.")
    print()
    print("```")
    print(remote(
        "SELECT 'db_encoding   ' || pg_encoding_to_char(encoding) || E'\\n' || "
        "       'lc_collate    ' || datcollate || E'\\n' || "
        "       'lc_ctype      ' || datctype || E'\\n' || "
        "       'locale_provider ' || datlocprovider::text "
        "  FROM pg_database WHERE datname = current_database()"))
    print(remote(
        "SELECT c.oid::text || '  ' || rpad(c.collname,10) || '  provider=' || "
        "c.collprovider::text || '  collversion=' || coalesce(c.collversion,'(none)') "
        "|| '  actual=' || coalesce(pg_collation_actual_version(c.oid),'(none)') "
        "FROM pg_collation c WHERE c.collname IN ('default','C','POSIX') ORDER BY 1"))
    print("```")
    print()
    print("> `lc_ctype` 도 같이 기록한다 — `lower()`·대소문자 분류·패턴 연산이")
    print("> **`LC_CTYPE` 의 영향을 받는다.** `order_factor` 는 `LC_COLLATE` 에,")
    print("> 파생 표현식 인증서는 `LC_CTYPE` 에 걸린다.")
    print(">")
    print("> `default`/`C`/`POSIX` 는 libc collation 이라 `collversion` 이 없다.")
    print("> **실제 정렬 의미를 정하는 것은 위의 `lc_collate` 와 libc 버전**이고,")
    print("> 그건 PostgreSQL 이 추적하지 않는다. OS 업그레이드로 정렬이 바뀌어도")
    print("> `collversion` 불일치가 나지 않는다 — 이 평가의 알려진 한계다.")
    print("> ICU collation 을 쓰면 `collversion` 이 잡히지만 측정 환경은 libc 다.")
    print()
    print("## 레지스트리 · declassification 시드")
    print()
    print("측정 **직전** 상태다. 회귀 도구들이 teardown 에서 비우므로, §11-5")
    print("하네스가 시드를 심은 뒤 이 아티팩트를 다시 내야 정본이 된다.")
    print()
    print("```")
    print(remote(
        "SELECT 'mask_instance      ' || count(*) FROM ipguard_mask_instance "
        "UNION ALL SELECT 'capability         ' || count(*) FROM ipguard_mask_capability "
        "UNION ALL SELECT 'fn_compatibility   ' || count(*) FROM ipguard_mask_function_compatibility "
        "UNION ALL SELECT 'agg_compatibility  ' || count(*) FROM ipguard_mask_aggregate_compatibility "
        "UNION ALL SELECT 'comparator         ' || count(*) FROM ipguard_mask_comparator_compatibility "
        "UNION ALL SELECT 'declassification   ' || count(*) FROM ipguard_declassification "
        "UNION ALL SELECT 'registry_epoch     ' || epoch FROM ipguard_registry_epoch"))
    print("```")
    print()
    print("## 코퍼스 · 도구 digest (sha256, 앞 16자리)")
    print()
    print("파일이 바뀌면 수치도 다시 내야 한다.")
    print()
    print("| 파일 | digest |")
    print("|---|---|")
    for f in DIGEST_FILES:
        print(f"| `{f}` | `{digest(f)}` |")
    print()
    print("## held-out seed — 역할별 세 커밋에서 파생")
    print()
    print("```")
    print("GATE_COMMIT       5e21c7d7cd089773cf7f4a9a629b61bd53067ac7")
    print("GENERATOR_COMMIT  9222ef3b4e7e13b685db5377486cb9eef8c7f236")
    print("POLICY_COMMIT     533502d297e12ede971b8c08cce8ce2f46446b0c")
    print("EVAL_BASE_COMMIT  " + sh("git -C %s rev-parse HEAD" % ROOT))
    print()
    print('material = b"ipguard-heldout-v1-final\\0"')
    print('           + GATE + b"\\0" + GENERATOR + b"\\0" + POLICY')
    print("sha256   a3062488859d4a48110c22db405de3a7752f37404428c57f1029ec27ed67965a")
    print("seed     0xa3062488859d4a48  (11747116846818347592)")
    print("```")
    print()
    print("> 세 해시는 파일 트리를 중복 표현하는 것이 아니라 **역할별")
    print("> provenance** 다. `EVAL_BASE_COMMIT` 는 실제 생성을 수행한")
    print("> checkout 이고 seed 재료가 아니다 — 게이트 로직이 안 바뀌고 회귀만")
    print("> 늘어난 커밋이 `GATE_COMMIT` 을 움직이면 안 되기 때문이다.")
    print()
    print("## ★ 운영 조건 — dump/restore 후 인증서 재발급")
    print()
    print("`context_canonical` 은 `relid.attnum` 과 함수·연산자 OID 를 담는다.")
    print("**한 데이터베이스 안에서는 안정적이지만 dump/restore 후 OID 가")
    print("달라진다.** 따라서 복원한 인스턴스에서는 인증서가 전부 불일치하고,")
    print("`ipguard_obligations()` 로 **재발급**해야 한다.")
    print()
    print("이건 결함이 아니라 설계상의 대가다 — 이름 기반으로 하면 `RENAME` 에")
    print("끊기고(4R Y01~Y03), OID 기반으로 하면 dump/restore 에 끊긴다.")
    print("라벨은 `regclass` 라 이름으로 덤프되지만 canonical 은 그럴 수 없다:")
    print("연산자·함수·collation 까지 이름으로 적으면 canonical 이 길어지고")
    print("스키마 경로에 의존하게 된다. **재발급을 운영 절차로 둔다.**")
    print()
    print("복원 후 절차:")
    print()
    print("```sql")
    print("-- 1) 라벨 무결성 (attnum 이 밀렸을 수 있다)")
    print("SELECT * FROM ipguard_verify_labels();")
    print("-- 2) 마스크 인스턴스 지문 재계산")
    print("SELECT * FROM ipguard_audit_registry();")
    print("-- 3) declassification 재발급 (context_key 가 전부 바뀐다)")
    print("--    ipguard_obligations(<질의>) 의 context_key/context_canonical 로")
    print("--    다시 INSERT 한다.")
    print("```")
    print()
    print("> *Automatic certificate migration is not provided; remapping")
    print("> OID-based identities requires an externally authenticated object")
    print("> mapping.*")
    print(">")
    print("> 기계적 매핑이 **원리적으로 불가능한 것은 아니다.** 다만 외부 신뢰")
    print("> 정보(어느 OID 가 어느 OID 로 갔는지에 대한 인증된 대응) 없이")
    print("> 자동으로 '같은 문맥' 이라 판단하는 것이 안전하지 않다는 뜻이다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
