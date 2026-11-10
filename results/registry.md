# 마스크 능력 레지스트리 — 단독 회귀 (2026-08-09)

게이트가 *"이 마스크는 동치를 보존한다"* 같은 사실에 기대어 질의를 수락하려면,
그 사실의 **출처와 유효성**이 형식에 남아야 한다. 관리자가 틀린 속성을
선언하면 정리가 깨지는 것이 아니라 **`RegistrySound` 전제가 깨진다** — 책임
소재가 드러나야 한다.

**effect 분석과 연결하기 전에** 레지스트리만 따로 잰다. 순서를 바꾸면 어느 쪽이
틀렸는지 구별할 수 없다.

원시 출력: [`registry.txt`](registry.txt) ·
도구: [`../tools/score_registry.py`](../tools/score_registry.py) ·
명세: [`../docs/spec-lineage-and-masks.md`](../docs/spec-lineage-and-masks.md) §4~§6

---

## 결과 — 46/46

| 그룹 | | |
|---|---|---:|
| **A** | 상수 마스크: `determinism`·`total` holds, `equality_factor`·`order_factor` **fails** | 9/9 |
| **B** | 미등록 UDF: 모든 capability `unknown` | 6/6 |
| **C** | `CREATE OR REPLACE`: 같은 OID 인데 지문 불일치 → `unknown` | 7/7 |
| **D** | 인증서 철회(같은 세션): epoch 증가 + generic plan 재계획 | 3/3 |
| **E** | 호환성: 등록된 **조합**만 `holds` + **의무 우회 음성 대조군** | 13/13 |
| **F** | **cross-backend**: 다른 세션의 철회가 내 generic plan 까지 | 8/8 |

## `claim` 과 `assurance` 는 다른 축이다

| | 값 |
|---|---|
| `claim` | `holds` / `fails` / `unknown` — **무엇인가** |
| `assurance` | `proved_builtin` / `trusted_assumption` / `unknown` — **어떻게 아는가** |

섞으면 `fails` 를 표현할 수 없다. 그런데 이 둘은 전혀 다르다:

```
unknown   인증 안 됨          -> 나중에 인증되면 수락 가능
fails     성립하지 않음이 확인  -> 영원히 수락 불가
```

한 마스크 안에서 셋이 **동시에** 나오는 것을 회귀로 못박았다:

```
ipguard_mask  determinism=holds  equality_factor=fails  no_such_cap=unknown
```

표 자체가 모순을 못 담게 제약을 걸었다 — `(claim = 'unknown') = (assurance = 'unknown')`.
인증 안 된 주장에 출처가 있을 수 없다.

## ★ C — `CREATE OR REPLACE` 는 OID 를 유지한다

이것이 `impl_version` 을 관리자가 적는 문자열로 두면 안 되는 이유다.
`(function_oid, args, types, collation)` 이 **전부 그대로**이므로 키로는
구별되지 않는다. 실측:

```
교체 전                       claim = holds
CREATE OR REPLACE (본문 변경)   OID 동일 -- 키로는 못 잡는다
교체 후                       claim = unknown        ★ 지문이 잡았다
지문 재등록                    claim = holds          (복구)
IMMUTABLE -> VOLATILE 만 변경   claim = unknown        ★ 본문이 같아도 잡는다
```

마지막 줄이 중요하다. `prosrc` 만 해시하면 **휘발성 변경이 통과한다** —
`IMMUTABLE` 을 믿고 수락한 질의가 `VOLATILE` 함수 위에서 돌게 된다.
지문에 `provolatile`·`proisstrict`·`proretset`·`prosecdef`·`proparallel`·
인자·반환형·`proconfig` 를 전부 넣는 이유다.

## 지문의 완전성은 언어마다 다르다 — 숨기지 않고 기록한다

| `fp_basis_kind` | 근거 | 완전? | 최대 assurance |
|---|---|---|---|
| `internal` | 서버 빌드에 묶인다 | ✅ | `proved_builtin` |
| `c-provider` | **provider-attested build identity.** manifest 가 덮은 축만 잡는다 | ❌ | `trusted_provider` |
| `c-foreign` | `extversion` 밖에 못 본다. **`make install` 로 `.so` 를 덮어써도 카탈로그는 그대로다** | ❌ | `trusted_assumption` |
| `src` | `prosrc` 는 보지만 **본문이 호출하는 함수**의 변경은 못 본다 | ❌ | `trusted_assumption` |

> **[정정]** 앞 판에는 우리 모듈의 C 함수를 `c-self` / `complete = true` 로
> 뒀다. **틀렸다.** 소스 해시를 바이너리에 박아도 **바이너리 동일성**은 얻지
> 못한다 — 컴파일러·플래그·PG 헤더·링크 라이브러리·ABI·함께 컴파일되는 다른
> 소스·같은 소스의 다른 바이너리가 전부 밖에 있다.
>
> 정확한 표현은 이것이다:
>
> ```
> provider-attested build identity
> complete only under BuildSound(provider_manifest)
> ```
>
> manifest 가 실제로 덮은 축을 `ipguard_manifest_axes()` 로 노출한다:
> `src, pg_version, cc_version, cflags, cppflags, ldflags`.
> **여기 없는 축의 변경은 잡히지 않는다.** 링크 라이브러리와 ABI 가 대표적으로
> 밖에 있다. 주장을 강화하려면 최종 `.so` 자체를 식별하거나 재현 가능한 build
> manifest 를 써야 하고, 지금은 하지 않는다.

강제 규칙 둘을 트리거로 걸었고 실측했다:

```
proved_builtin     complete = true 여야 한다        -> c-provider 에서 거부됨 ✓
trusted_provider   fp_basis_kind ∈ {internal, c-provider}  -> src 에서 거부됨 ✓
```

`ipguard_audit_registry()` 가 불완전 지문 인스턴스를 상시 보고한다.

## ★ D — 철회가 generic plan 까지 닿는가

라벨에서 이미 당한 실패 양식이다(4R Y07). 인증서를 철회해도 이미 만들어진
generic plan 은 철회 전 판정으로 계속 돈다 — 커넥션 풀에서는 몇 시간씩 간다.

**결과가 아니라 계획 사건을 직접 쟀다.** `ipguard_pii_plan_count()` 는 이
백엔드에서 PII 가 걸린 질의를 계획한 횟수다(라벨 없는 질의는 세지 않으므로
측정 질의가 측정값을 흔들지 않는다).

```
PREPARE p AS SELECT ssn FROM cust WHERE id = $1
EXECUTE p ×6                          -- generic plan 으로 전환
EXECUTE p(7)                          -> 계획 +0    (캐시 재사용)
UPDATE ipguard_mask_capability ...    -> epoch 증가
EXECUTE p(8)                          -> 계획 +1    ★ 재계획됐다
```

레지스트리 세 표 전부에 (a) epoch 증가 (b) relcache 무효화 방송을 달았다
(`ipguard_watch_registry()`).

### ★★ F — 같은 세션 측정은 **local invalidation 만** 본 것이다

D 는 한 세션 안에서 쟀다. 커넥션 풀에서 실제로 일어나는 일은 **A 가 계획을
들고 있는 동안 B 가 철회**하는 것이고, 그건 프로세스 간 무효화 방송이 닿아야
잡힌다. 살아 있는 백엔드 4개(`A1`·`A2`·`A3` + `B`)로 다시 쟀다.

`plan_cache_mode = force_generic_plan` 으로 generic plan 을 확정한 뒤:

| | 결과 |
|---|---|
| `B` 가 `ROLLBACK` → `A1` 재계획 | **+0** (무효화 방송 없음) |
| `B` 가 `ROLLBACK` → 인증서 | **여전히 `holds`** |
| `B` 가 `COMMIT` → `A1`·`A2`·`A3` 재계획 | **각각 +1** |
| `B` 의 `CREATE OR REPLACE` → `A1` 이 보는 claim | `holds` → **`unknown`** |
| provider 지문 불일치 → `A1` | **`unknown`** |

**장기 연결 세션 셋 전부**에 무효화가 닿는 것을 확인했다. `ROLLBACK` 대조군이
중요하다 — 없으면 "쓰기만 하면 무조건 비워진다"(과잉 무효화)와 구별되지 않는다.

> **아직 주장하지 않는 것**: 여기서 확인한 것은 *"철회가 캐시된 계획까지
> 닿는다"* 는 **기전**이다. *"그래서 거부된다"* 는 게이트가 레지스트리를
> 읽도록 연결한 뒤(§11-4)에 **같은 generic plan 을 대상으로 철회 → 재계획 →
> 거부를 한 번에** 측정한다.

## E — 인증서는 **조합**에 붙는다

`arg_signature` 를 키에서 빼면 `substr(x,1,2)` 의 인증서가 `substr(x,1,3)` 으로
번진다. 검증하지 않은 인자로 번지는 것이 위험하다.

| 조회 | 결과 |
|---|---|
| 등록된 조합 (`1,2` / `reg_redact` / 기본 collation) | `holds` |
| 다른 인자 (`1,3`) | `unknown` |
| 다른 redactor | `unknown` |
| 다른 collation (`C`) | `unknown` |
| 미등록 함수 (`upper`) | `unknown` |
| **redactor 를 `CREATE OR REPLACE`** | `unknown` |
| `count(x)` | `holds` |
| **`count(DISTINCT x)`** | `unknown` |

마지막 둘이 요점이다. `count(x)` 와 `count(DISTINCT x)` 는 마스크에 대해 완전히
다르게 행동한다 — 후자는 `EQ` 채널을 탄다. `distinct_arg` 를 키에 넣지 않으면
`count(DISTINCT ssn)` 이 `count(ssn)` 의 인증서로 통과한다. 그건 발산 코퍼스가
찾은 **가장 흔한 조용한 오답**(`10000 → 1`)이다.

### ★★ 음성 대조군 — 잘못 등록된 인증서가 의무를 우회하는가

`count(x) holds` 는 그 MaskInstance 가 **`null_equivalence` 를 만족할 때만**
맞다. `count` 는 non-NULL 값을 센다 — 마스크가 non-NULL 을 NULL 로 바꾸면
결과가 바뀐다. 5R 에서 실측한 `count(*) FILTER (WHERE salary IS NOT NULL)`
`1000 → 0` 이 정확히 이것이다.

그래서 같은 함수의 **다른 MaskInstance** 를 `null_equivalence = fails` 로
등록하고, `count → holds` 를 **일부러 잘못** 등록했다:

| 마스크 | 조회 | 결과 |
|---|---|---|
| 상수 (`null_equivalence` holds) | `count(x)` | `holds` |
| **nullify (`null_equivalence` fails)** | `count(x)` | **`fails`** ← 등록은 `holds` 인데도 |
| nullify (`equality_factor` fails) | `count(DISTINCT x)` | **`fails`** |
| 상수 (`equality_factor` fails) | `count(DISTINCT x)` | **`fails`** |
| EQ 인증 없음 (`unknown`) | `count(DISTINCT x)` | `unknown` |
| `count(*)` (인자 없음) | — | 시그니처가 달라 조회 불가 |

조회 API 가 **강제 전제를 항상 AND** 한다. 관리자가 실수로든 고의로든
`holds` 를 넣어도 의무는 우회되지 않는다.

```
DISTINCT       -> equality_factor 를 요구  (명세 §2 effect->의무)
ordered agg    -> order_factor 를 요구
count/sum/avg/min/max -> null_equivalence 를 요구  (ipguard_aggregate_obligation)
```

**전제를 등록 조회보다 먼저 본다.** 순서가 중요하다 — 나중에 보면 "등록 안 된
조합" 이 전부 `unknown` 이 되어 **확정적으로 불가능한 조합까지 `unknown` 으로
뭉개진다.** 고치자 상수 마스크의 `count(DISTINCT x)` 가 `unknown` → `fails` 로
바뀌었다. `fails` 는 "영원히 불가" 라는 훨씬 강한 신호다.

## 조회 API — 게이트는 표를 직접 읽으면 안 된다

```sql
ipguard_capability(mask_id, capability)                        -> claim
ipguard_function_compatible(mask_id, f, args, redactor, coll)  -> claim
ipguard_aggregate_compatible(mask_id, agg, distinct, ordered, redactor, coll)
```

셋 다 **조회 시점에 지문을 다시 계산해서** 저장된 값과 비교한다. 어긋나면
저장된 `claim` 이 무엇이든 `unknown` 을 돌려준다. 표를 직접 읽으면 이 검사를
건너뛰게 되므로 게이트는 반드시 이 함수만 봐야 한다.

## 권한 — 진단 함수가 부수 채널이 되면 안 된다

5R 에서 이미 당한 클래스다. 보안 컨트롤의 **관찰·조작 표면**을 열어 두면
집행기를 아무리 정교하게 만들어도 소용없다. 비특권 롤로 실측:

| 시도 | 결과 |
|---|---|
| `ipguard_pii_plan_count()` | **거부** — 어떤 표에 라벨이 붙었는지가 샌다 |
| `ipguard_audit_registry()` | **거부** |
| `ipguard_register_mask(…)` | **거부** — 인증서를 **쓰는** 함수다 |
| 레지스트리 표 읽기/쓰기 | **거부** |
| `ipguard_watch_registry()` · `ipguard_build_id()` | **거부** |
| **`ipguard_capability(…)`** (조회 API) | **허용** ← 계획기가 앱 권한으로 부른다 |

조회 API 는 `SECURITY DEFINER` + **고정 `search_path`** 다. 고정하지 않으면
호출자가 자기 스키마(또는 `pg_temp`)에 가짜 `ipguard_mask_capability` 를 만들어
**원하는 claim 을 주입**할 수 있다 — `SECURITY DEFINER` 의 고전적 함정이고
여기서는 게이트 무력화로 직결된다. 실제로 시도해 봤다:

```
CREATE TEMP TABLE ipguard_mask_capability(...);
INSERT ... ('equality_factor', 'holds', 'proved_builtin');
SET search_path = pg_temp, public;
SELECT ipguard_capability(1, 'equality_factor');   -> unknown   ★ 주입 실패
```

> 배포 권고: 확장을 `public` 이 아닌 전용 스키마에 설치할 것. 지금 측정
> 환경은 `public` 에 있고 `@extschema@` 가 `public` 으로 해석된다. PG15+
> 기본값에서는 `PUBLIC` 이 `public` 에 객체를 만들 수 없어(실측 확인) 위 주입이
> 막히지만, 그 기본값에 의존하지 않는 편이 낫다.

## 한계

- **게이트에 아직 연결되지 않았다.** 레지스트리는 돌지만 `R1~R3` 는 여전히
  레지스트리를 안 본다. 연결은 §11-4 다.
- `total` 이 아직 전역이다. `total_under(f, precondition)` 을 담을 컬럼은
  만들었지만 첫 구현은 `precondition = ''`(무조건) 만 지원한다. 스키마 제약을
  읽어 전제를 discharge 하는 것은 뒤로 미뤘다.
- `c-provider`·`c-foreign`·`src` 의 지문 불완전성은 **해결한 것이 아니라
  기록한 것**이다. `.so` 덮어쓰기, 링크 라이브러리·ABI 변경, 의존 함수 변경은
  여전히 탐지되지 않는다. `BuildSound(provider_manifest)` 는 **전제**이지
  검증된 사실이 아니다.
- `ipguard_aggregate_obligation` 은 `count`/`sum`/`avg`/`min`/`max` 만 씨앗으로
  넣었다. 다른 집계의 의무는 등록돼 있지 않으므로 **그 집계들은 강제 전제
  없이** 등록된 claim 을 그대로 쓴다 — DISTINCT/ordered 의 일반 규칙만 걸린다.
- 지문은 백엔드 캐시가 아니라 매 조회마다 계산한다. 게이트에 연결하면
  계획당 비용이 붙는다 — 성능은 이 호스트에서 잴 수 없다.

## 재현

```bash
python3 tools/score_registry.py
```
