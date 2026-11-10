# 인증서 profile v1 — 동결 dossier

적용: `psql -d <db> -f ext/profile-v1.sql`
검증: `python3 tools/verify_profile.py` — **거짓 holds 0건**이어야 한다.

## 0. 이 문서가 존재하는 이유

레지스트리는 `holds` 라고 **쓰기만 하면 되는 표**다. 그 문자열이 실제로
적용되는 변환의 성질과 일치한다는 보장은 어디에도 없었다. 실제로:

- gate 회귀는 별표 마스크에 `order_factor=holds` 를 넣어 factor-through
  경로를 시험해 왔다. 게이트 로직의 단위 시험으로는 타당하지만 그 조합은
  **의미론적으로 거짓**이다.
- held-out v1 의 평가 registry 는 nullify 마스크(`hxnum`)에
  `null_equivalence=holds` 를 등록했다. **거짓이다** — nullify 는 non-NULL 을
  NULL 로 보낸다. `tools/verify_profile.py` 가 이것을 잡았다.
- `ipguard_mask()` 는 `kind` 인자를 **읽지도 않았다.** 레지스트리는 `kind` 로
  MaskInstance 를 구별하는데 집행은 타입으로만 분기했다. 등록한 속성이 실제
  적용되는 변환의 속성이라는 보장이 없었다. 이번에 `kind` 분기를 넣었다.

profile 은 acceptance 를 높이려고 고르지 않았다. **의미론적으로 증명 가능한
것만** 넣었다.

## 1. 정의

| 이름 | 의미론 식 |
|---|---|
| `determinism` | `m(x)` 가 같은 입력에 같은 출력 |
| `total` | 모든 `x` 에서 오류 없이 값을 낸다 (precondition = ⊤) |
| `null_equivalence` | `m(NULL) IS NULL` ∧ `x IS NOT NULL ⟹ m(x) IS NOT NULL` |
| `equality_factor` | `∀x,y. m(x) ≡ m(y) ⟺ x ≡ y` (`≡` 는 SQL grouping equivalence — NULL 끼리 같다) |
| `order_factor` | `∀x,y. sign(cmp(m(x),m(y))) = sign(cmp(x,y))` (순서 매장, tie 포함) |

`ORD = NullPartitionPreserved ∧ ComparatorFactors`,
`EQ = NullPartitionPreserved ∧ EqualityFactors` (명세 §5.5).
앞 연언지가 `null_equivalence`, 뒤 연언지가 comparator compatibility 다.

## 2. assurance 등급

`proved_builtin` 은 **주장할 수 없다.** 레지스트리 가드가 거부한다:

```
ERROR: mask_id=N 의 지문이 불완전해(c-provider) proved_builtin 을 주장할 수 없습니다
```

`ipguard_mask()` 는 C 로 구현돼 있어 레지스트리가 구현을 완전히 지문화할 수
없다. 올바른 거부이므로 우회하지 않는다. 따라서 이 profile 의 모든 항목은
**`trusted_provider`** 다. 아래 증명은 소스를 읽고 사람이 한 것이고, 도구가
확인한 것은 probe 정의역 전수 검사뿐이다.

probe 정의역 (`tools/verify_profile.py`):

```
text  NULL, '', 'a', 'b', 'A', 'aa', 'ab', 'n', 'z', '*', '**', 'P:a',
      'abc', 'ABC', U+00E9, '한', '한글'        17값 / 순서쌍 127
date  NULL, 1900-01-01, 1980-01-01, 1990-01-01, 2000-12-31   5값 / 7쌍
int   NULL, 0, 1, -1, 2, 2147483647                          6값 / 12쌍
```

전수 검사는 무한 정의역에 대한 증명이 아니다. **반례가 있으면 반드시 잡는다**
는 방향만 보장한다.

---

## 3. 실 마스킹 계열

### 3.1 `pv_text` — star mask

| | |
|---|---|
| 의미론 식 | `m(x) = repeat('*', char_length(x))`, `m(NULL) = NULL` |
| 구현 | `ipguard_mask(anyelement, text)`, `ext/ipguard.c` — `pg_mbstrlen_with_len` |
| 입력/출력 마스크 | `text → text` / 출력 마스크는 자기 자신 |
| 길이 단위 | **문자 수**(byte 수 아님). multibyte 안전 — `'한글' → '**'` |
| type/collation | `text`/`varchar`/`bpchar`/`name`, collation 무관 |
| precondition | ⊤ |
| assurance | `trusted_provider` |

| capability | claim | 근거 |
|---|---|---|
| `determinism` | holds | 입력 길이만의 함수. 상태 없음 |
| `total` | holds | 모든 입력에서 정의됨 |
| `null_equivalence` | holds | `PG_ARGISNULL` 분기로 NULL↦NULL, 그 외 non-NULL |
| `equality_factor` | **fails** | 반례 `m('aa') = m('ab') = '**'` 인데 `'aa' ≠ 'ab'` |
| `order_factor` | **fails** | 반례 `cmp(m('a'),m('b')) = 0` 인데 `'a' < 'b'` |

**음성 반례가 곧 마스크의 목적이다.** 길이만 남기고 값을 지우므로 EQ/ORD 가
성립할 수 없다. 길이는 공개된다.

### 3.2 `pv_date` — constant date mask

| | |
|---|---|
| 의미론 식 | `m(d) = DATE '1900-01-01'` for all non-NULL `d`, `m(NULL) = NULL` |
| 구현 | `ipguard_mask`, `date_in("1900-01-01")` |
| precondition | ⊤ |

| capability | claim | 근거 |
|---|---|---|
| `determinism` | holds | 상수 함수 |
| `total` | holds | |
| `null_equivalence` | holds | NULL↦NULL, non-NULL↦1900-01-01 (non-NULL) |
| `equality_factor` | **fails** | 반례 `m(1980-01-01) = m(1990-01-01)` |
| `order_factor` | **fails** | 반례 `cmp = 0` 인데 raw `<` |

**주의.** 상수 함수라서 EQ/ORD 가 `holds` 인 것이 아니라 **정확히 반대**다.
상수 함수는 서로 다른 값을 전부 합치므로 등가·순서가 release 로부터
복원되지 않는다.

### 3.3 `pv_num` — nullify mask

| | |
|---|---|
| 의미론 식 | `m(n) = NULL` for all `n` (GUC `ipguard.numeric_mask = 1`) |
| 구현 | `ipguard_mask`, `PG_RETURN_NULL()` |
| precondition | ⊤ |

| capability | claim | 근거 |
|---|---|---|
| `determinism` | holds | |
| `total` | holds | |
| `null_equivalence` | **fails** | 반례 `m(1) IS NULL` 인데 `1 IS NOT NULL` |
| `equality_factor` | **fails** | `m(1) ≡ m(2)` (NULL ≡ NULL) 인데 `1 ≠ 2` |
| `order_factor` | **fails** | `cmp` 가 NULL 이라 정의되지 않는다 |

`null_equivalence` 가 `fails` 이므로 EQ/ORD 는 전제부터 성립하지 않고,
`count(x)` 집계 compatibility 도 걸 수 없다 (count 는 NULL 을 세지 않는다).

**held-out v1 의 `hxnum` 은 이것을 `holds` 로 등록했다. 거짓이다.**

---

## 4. control transform — **운영 금지**

> Structural-revealing control transform used only to exercise certified
> factorization paths.

실 마스킹 계열은 EQ/ORD 가 전부 `fails` 다. 그래서 게이트의 factor-through
경로는 **한 번도 실행되지 않는다.** 인증 경로에 양성 증거를 만들려면 구조를
의도적으로 공개하는 변환이 필요하다. `ctl:` 은 그 예약 namespace다.

실용적인 order-revealing encryption 은 별개 연구 범위다.

### 4.1 `ctl:rot13` — EQ positive

| | |
|---|---|
| 의미론 식 | ASCII 문자 `[A-Za-z]` 를 13 회전, 그 외 바이트는 항등 |
| 구현 | `ext/ipguard.c`, 바이트 단위 |
| precondition | ⊤ |

| capability | claim | 근거 |
|---|---|---|
| `null_equivalence` | holds | NULL↦NULL, 길이 보존이라 non-NULL↦non-NULL |
| `equality_factor` | **holds** | 아래 증명 |
| `order_factor` | **fails** | 반례 `'a' < 'n'` 인데 `rot13('a')='n' > rot13('n')='a'` |

**증명 (equality_factor).** 회전은 `[a-z]` 위의 involution이고 `[A-Z]` 위에서도
그렇다. 그 밖의 바이트는 항등이다. 따라서 바이트 단위 사상 `f` 는
`f∘f = id` 이므로 전단사다. 문자열은 바이트 열이고 사상이 각 바이트에
독립적으로 작용하므로 전체 사상도 전단사다. 전단사 ⟹ 단사 ⟹ 등가 factor.

**UTF-8 안전성.** UTF-8 에서 연속 바이트는 항상 `0x80` 이상이라 ASCII
바이트(`0x00`–`0x7F`)와 겹치지 않는다. 따라서 ASCII 범위만 회전하는 것은
multibyte 문자를 건드리지 않고, 출력도 유효한 UTF-8 이다. 실측:
`'한글abc' → '한글nop'`.

**보안 성질 없음.** 원문을 그대로 복원할 수 있다.

### 4.2 `ctl:prefix` — ORD positive

| | |
|---|---|
| 의미론 식 | `m(x) = 'P:' || x`, `m(NULL) = NULL` |
| 구현 | `ext/ipguard.c` |
| type/collation | **`C` collation 한정** |
| precondition | ⊤ |

| capability | claim | 근거 |
|---|---|---|
| `null_equivalence` | holds | |
| `equality_factor` | **holds** | 왼쪽 소거 |
| `order_factor` | **holds** | 아래 증명 |

**증명 (order_factor).** `C` collation 의 `text` 비교는 바이트 열의 사전식
비교다(`memcmp` 후 길이). `p = "P:"` 를 양쪽에 붙이면 앞 2바이트가 동일하므로
첫 불일치 위치는 `p` 뒤에서만 발생한다. 따라서
`cmp(p||x, p||y) = cmp(x, y)` 가 **tie 를 포함해** 성립한다.
한쪽이 다른 쪽의 prefix 인 경우도 길이 비교가 같은 방향으로 옮겨간다.

**collation 제약이 본질적이다.** 비-`C` collation 은 정렬 요소를 언어 규칙으로
만들므로 접두사가 뒤 비교에 영향을 줄 수 있다. 이 profile 은 `C` 에서만
등록하며, `ipguard_mask_comparator_compatibility` 의 `collation_name = ''`
(= 기본, DB 가 `C`)로 건다. 평가 DB 는 `datcollate = C` 다.

**왜 버킷팅이 아닌가.** 단조 버킷팅 `bucket(x)` 은 버킷 내부 값을 합친다:
`x=1, y=2` 에서 `bucket(x)=bucket(y)=0` 이므로 masked comparator 는 동률로
보지만 raw 는 `1 < 2` 다. 즉 **tie 를 만들어** 순서 매장이 아니다. 필요한 것은
단순 monotonicity 가 아니라 tie 까지 보존하는 order embedding 이다.

**보안 성질 없음.** 원문을 그대로 포함한다.

---

## 5. comparator compatibility

`ipguard_register_default_comparators(mask_id, ord_claim, eq_claim, assurance)`
로 btree 기본 연산자에 건다. `collation_name = ''`.

| mask | ORD 연산자 | EQ 연산자 |
|---|---|---|
| `pv_text`, `pv_date`, `pv_num` | fails | fails |
| `ctl:rot13` | fails | holds |
| `ctl:prefix` | holds | holds |

`text_pattern_ops` 계열(`~<~` 등)은 등록하지 않는다 — 미등록 = 거부이고,
연산자 키 격리의 음성 대조군으로 쓴다.

## 6. aggregate compatibility

`count("any")`, `out_redactor = h5.pv_ident_bigint(bigint)`.

**의미론 식.** `count(m(x)) = count(x)` — `count` 는 인자 **값**을 보지 않고
NULL 여부만 본다. 따라서 전단사가 아닌 마스크에서도 성립한다. 단
**`null_equivalence` 가 전제**다: 마스크가 non-NULL 을 NULL 로 보내면
개수가 줄어든다.

| mask | `distinct_arg=false` | `distinct_arg=true` |
|---|---|---|
| `pv_text` | holds | 미등록 |
| `pv_date` | holds | 미등록 |
| `pv_num` | **미등록** (`null_equivalence=fails`) | 미등록 |
| `ctl:rot13` | holds | holds |
| `ctl:prefix` | holds | holds |

**`out_redactor` 는 identity 다.** 이것은 "집계 결과를 그대로 공개한다" 는
**명시적 정책 선언**이다. Ideal 의 출력 정책이 count 결과를 identity-release
로 허용할 때만 fidelity 가 맞다. 조용히 넘어가면 안 되므로 별도
MaskInstance(`pv_ident_bigint`)로 등록했다.

**`count(DISTINCT x)` 는 aggregate compatibility 만으로 부족하다.** 값을
합치면 개수가 줄기 때문에 **EQ 인증이 별도로 필요**하다. 게이트가
`aggregate DISTINCT key vector` 의 `EQ → CELL` 의무를 따로 만들고, 그
의무는 `SortGroupClause` 의 `eqop`·collation·NULL 파티션 전제를 comparator
인증서와 연결해 검사한다. 그래서 `pv_text`·`pv_date` 에는 `distinct_arg=true`
를 걸지 않았다 — 걸어도 EQ 가 `fails` 라 거부된다(회귀 [6c] 양방향 대조군).

## 7. scalar function compatibility

| func | mask | claim | 의미론 식 |
|---|---|---|---|
| `lower(text)` | `pv_text` | holds | `lower(m(x)) = m(x) = m(lower(x))` — 출력이 `'*'` 뿐이라 자명 |
| `upper(text)` | `pv_text` | holds | 같음 |

`ctl:rot13`·`ctl:prefix` 에는 **등록하지 않는다.** ROT13 은 대소문자를 바꾸고
prefix 는 `'P:'` 를 소문자화하므로 `lower` 와 가환이 아니다. 미등록 = 거부.

### 등록하지 않은 것과 그 이유

| 항목 | 이유 |
|---|---|
| `length(text)` | star mask 가 이미 길이를 공개하므로 **opacity 에는 안전**하다. 그러나 fidelity 는 Ideal 의 출력 정책이 그 파생값을 identity-release 로 허용할 때만 맞다. v1 은 그 정책을 정의하지 않았다. 조용히 "라벨 아님" 으로 두지 않고 **미등록 = 거부**로 둔다 |
| `substr(text,int,int)` | `count < 0` 에서 오류를 낸다. 임의 인자 전체에서 `total` 이 아니다. v1 은 `precondition = ⊤` 만 지원하므로 제외한다. 인자를 상수로 고정한 MaskInstance 로만 인증할 수 있고 그건 v2 다 |
| 비-`C` collation | `ctl:prefix` 의 순서 증명이 collation 규칙에 의존한다. `C` 밖에서는 다시 증명해야 한다 |
| ASCII 밖 정의역 | `pv_text` 의 길이는 문자 수라 multibyte 안전하다. `ctl:rot13` 도 UTF-8 안전하다. **정의역 제한이 필요 없다** — probe 에 `한`, `한글`, U+00E9 을 넣어 확인했다 |

## 8. 이 profile 로 무엇이 가능해지는가

| stratum | 마스크 | 기대 판정 |
|---|---|---|
| compatible `VAL → CELL` | `pv_text` + `lower`/`upper` | accept, fidelity 측정 |
| missing VAL compatibility | `pv_text` + 미등록 함수 | reject `MISSING_CERTIFICATE` |
| **certified EQ** | `ctl:rot13` + `GROUP BY`/`DISTINCT` | **accept, 인증 경로 실행** |
| failed EQ | `pv_text` + `GROUP BY` | reject `CAPABILITY_FAILS` |
| **certified ORD** | `ctl:prefix` + `ORDER BY` | **accept, 인증 경로 실행** |
| failed ORD | `pv_text` + `ORDER BY` | reject `CAPABILITY_FAILS` |
| `count(DISTINCT)` 양성 | `ctl:rot13` | accept (EQ + agg 둘 다) |
| `count(DISTINCT)` 음성 | `pv_text` | reject (agg 는 있어도 EQ 없음) |
| sensitive CARD, P0 | 아무 마스크 | reject |
| 같은 CARD, P1 | 아무 마스크 | accept 또는 δ 비동치 |
| label-free | — | accept control |

## 9. `certificate-exercising accepted strata` — 왜 비퇴화 opacity witness 가 없는가

EQ/ORD 양성 stratum 에 대해 "masked-equivalent DB 사이에서 그 구조가 달라지는
비퇴화 opacity witness" 를 요구하면 **원리상 만들 수 없다.** 편의가 아니라
정리의 구조에서 따라나온다.

`M(D1) = M(D2)` 이고 `EQ` 가 `M` 을 factor through 한다고 하자. factor-through
의 정의가

    ∀x,y.  m(x) ≡ m(y)  ⟺  x ≡ y

이므로, 라벨 컬럼의 등가 분할은 마스킹된 값의 등가 분할로 **결정된다.**
`M(D1) = M(D2)` 는 마스킹된 값이 같다는 뜻이므로 두 DB 의 등가 분할도 같다.
따라서 `GROUP BY`/`DISTINCT` 의 결과 구조가 달라질 수 없다. `ORD` 도 같은
논증이 순서 관계에 대해 성립한다.

즉 이 stratum 의 "opacity 실패 0" 은 **공허하게 참**이다. 그것이 결함이 아니라
인증서가 주장하는 바로 그 성질이다. 그래서 이 strata 는

> **certificate-exercising accepted strata**

라고 부른다 — "게이트의 factor-through 판정 경로가 실제로 실행됐다" 를 보이는
것이 목적이고, opacity 에 대한 독립 증거를 주장하지 않는다.

**독립 증거는 반대편에 있다.** 상수 마스크(EQ/ORD `fails`)에서 두 DB 의 등가
분할·순서가 달라지는 pair 를 만들고, 게이트가 그것을 **거부**하는지 본다.
그것이 rejection strata 다.

## 10. 동결

```
profile SQL       ext/profile-v1.sql
dossier           docs/certificate-profile-v1.md   (이 문서)
검증기            tools/verify_profile.py
검증 결과         거짓 holds 0건 (MaskInstance 7, capability 25)
control 마스크    ext/ipguard.c 의 `ctl:` 분기
```
