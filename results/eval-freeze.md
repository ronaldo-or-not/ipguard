# §11-5 평가 동결 아티팩트

Git 커밋만으로는 재현되지 않는다. 게이트 판정은 카탈로그 OID·
collation 버전·빌드 지문·레지스트리 시드에 의존하고, 그중 어느 것도
소스에 없다. 아래가 이 평가의 **정본**이다.

## 코드

```
commit      533502d297e12ede971b8c08cce8ce2f46446b0c
branch      master
dirty       yes ★ 동결 전에 커밋할 것
```

## 빌드 · 런타임

```
IPGUARD_BUILD_ID   78dbd8a31626f039ebd83e41e0eb8b00b00660d1326349db3d23776e7bf6ce20   (SHA-256, 전체)
  표시용 축약       78dbd8a31626   ★ 보안 판정에는 전체를 쓴다
manifest axes      src,pg_version,cc_version,cflags,cppflags,ldflags
postgres           PostgreSQL 16.10 on x86_64-pc-linux-gnu, compiled by gcc (Ubuntu 13.3.0-6ubuntu2~24.04.1) 13.3.0, 64-bit
```

> **manifest 가 덮지 않는 축**(링크 라이브러리·ABI·같은 소스의 다른
> 바이너리)의 변경은 잡히지 않는다. `BuildSound(provider_manifest)`
> 는 전제이지 검증된 사실이 아니다 — `results/registry.md` 참조.

## collation — OID 와 **실제** version

OS 라이브러리가 바뀌면 정렬 의미가 바뀐다. `order_factor` 인증서는
등록된 collation에서만 증명된 주장이므로 여기가 흔들리면 무효다.

```
db_encoding   UTF8
lc_collate    C
lc_ctype      C
locale_provider c
100  default     provider=d  collversion=(none)  actual=(none)
950  C           provider=c  collversion=(none)  actual=(none)
951  POSIX       provider=c  collversion=(none)  actual=(none)
```

> `lc_ctype` 도 같이 기록한다 — `lower()`·대소문자 분류·패턴 연산이
> **`LC_CTYPE` 의 영향을 받는다.** `order_factor` 는 `LC_COLLATE` 에,
> 파생 표현식 인증서는 `LC_CTYPE` 에 걸린다.
>
> `default`/`C`/`POSIX` 는 libc collation 이라 `collversion` 이 없다.
> **실제 정렬 의미를 정하는 것은 위의 `lc_collate` 와 libc 버전**이고,
> 그건 PostgreSQL 이 추적하지 않는다. OS 업그레이드로 정렬이 바뀌어도
> `collversion` 불일치가 나지 않는다 — 이 평가의 알려진 한계다.
> ICU collation 을 쓰면 `collversion` 이 잡히지만 측정 환경은 libc 다.

## 레지스트리 · declassification 시드

측정 **직전** 상태다. 회귀 도구들이 teardown 에서 비우므로, §11-5
하네스가 시드를 심은 뒤 이 아티팩트를 다시 내야 정본이 된다.

```
mask_instance      1
capability         3
fn_compatibility   1
agg_compatibility  0
comparator         0
declassification   0
registry_epoch     1919
```

## 코퍼스 · 도구 digest (sha256, 앞 16자리)

파일이 바뀌면 수치도 다시 내야 한다.

| 파일 | digest |
|---|---|
| `corpus/divergence.json` | `92058075099658d8` |
| `corpus/h5-corpus.json` | `1d47768a1d9e1999` |
| `corpus/semantics.json` | `85ee4af4f2d504e0` |
| `corpus/tpch-queries.sql` | `30da1a515f633e32` |
| `corpus/tpch-schema.sql` | `842b2ed0bdcf8947` |
| `corpus/schema.sql` | `3a7169847eab28c8` |
| `ext/ipguard.c` | `6014ed4849ef4d2a` |
| `ext/ipguard--1.0.sql` | `916538b6e542248c` |
| `ext/Makefile` | `812f30256fa9cd68` |
| `tools/score_gate.py` | `f30f7c3640e0a52f` |
| `tools/score_registry.py` | `249e89755b29bc67` |
| `tools/score_fragment.py` | `c78e6e1081aa60e7` |
| `tools/gen_heldout.py` | `97ccf1f62f686c3b` |
| `tools/validate_heldout.py` | `a285e40c3c04ce2a` |
| `corpus/heldout.json` | `e8d2e19a4c0f4aa7` |
| `corpus/peer-golden.json` | `82d160a6aa2ff3e2` |
| `docs/policy-p0-p1.md` | `3536d4a66defe877` |
| `docs/heldout-protocol.md` | `001e13f157087cb0` |

## held-out seed — 역할별 세 커밋에서 파생

```
GATE_COMMIT       5e21c7d7cd089773cf7f4a9a629b61bd53067ac7
GENERATOR_COMMIT  9222ef3b4e7e13b685db5377486cb9eef8c7f236
POLICY_COMMIT     533502d297e12ede971b8c08cce8ce2f46446b0c
EVAL_BASE_COMMIT  533502d297e12ede971b8c08cce8ce2f46446b0c

material = b"ipguard-heldout-v1-final\0"
           + GATE + b"\0" + GENERATOR + b"\0" + POLICY
sha256   a3062488859d4a48110c22db405de3a7752f37404428c57f1029ec27ed67965a
seed     0xa3062488859d4a48  (11747116846818347592)
```

> 세 해시는 파일 트리를 중복 표현하는 것이 아니라 **역할별
> provenance** 다. `EVAL_BASE_COMMIT` 는 실제 생성을 수행한
> checkout 이고 seed 재료가 아니다 — 게이트 로직이 안 바뀌고 회귀만
> 늘어난 커밋이 `GATE_COMMIT` 을 움직이면 안 되기 때문이다.

## ★ 운영 조건 — dump/restore 후 인증서 재발급

`context_canonical` 은 `relid.attnum` 과 함수·연산자 OID 를 담는다.
**한 데이터베이스 안에서는 안정적이지만 dump/restore 후 OID 가
달라진다.** 따라서 복원한 인스턴스에서는 인증서가 전부 불일치하고,
`ipguard_obligations()` 로 **재발급**해야 한다.

이건 결함이 아니라 설계상의 대가다 — 이름 기반으로 하면 `RENAME` 에
끊기고(4R Y01~Y03), OID 기반으로 하면 dump/restore 에 끊긴다.
라벨은 `regclass` 라 이름으로 덤프되지만 canonical 은 그럴 수 없다:
연산자·함수·collation 까지 이름으로 적으면 canonical 이 길어지고
스키마 경로에 의존하게 된다. **재발급을 운영 절차로 둔다.**

복원 후 절차:

```sql
-- 1) 라벨 무결성 (attnum 이 밀렸을 수 있다)
SELECT * FROM ipguard_verify_labels();
-- 2) 마스크 인스턴스 지문 재계산
SELECT * FROM ipguard_audit_registry();
-- 3) declassification 재발급 (context_key 가 전부 바뀐다)
--    ipguard_obligations(<질의>) 의 context_key/context_canonical 로
--    다시 INSERT 한다.
```

> *Automatic certificate migration is not provided; remapping
> OID-based identities requires an externally authenticated object
> mapping.*
>
> 기계적 매핑이 **원리적으로 불가능한 것은 아니다.** 다만 외부 신뢰
> 정보(어느 OID 가 어느 OID 로 갔는지에 대한 인증된 대응) 없이
> 자동으로 '같은 문맥' 이라 판단하는 것이 안전하지 않다는 뜻이다.
