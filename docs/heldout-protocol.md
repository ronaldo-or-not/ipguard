# Held-out 평가 프로토콜 (§11-5)

**측정을 시작하기 전에 고정한다.** 결과를 본 뒤에 규칙을 정하면 그 평가는
개발 코퍼스가 된다.

지금까지의 모든 수치(`gate.md` 61/61, `registry.md` 46/46, 삼자택이 10문)는
**개발에 쓴 witness** 다. `Q6`/`Q6′`/`Q9`/`Q10` 은 규칙을 만들면서 같이
만들어졌으므로 `accept ⇒ fidelity ∧ opacity` 의 증거가 될 수 없다.
**regression 으로만 남기고 held-out 수치에 섞지 않는다.**

---

## 동결 순서 — 커밋을 나눠야 방어된다

각 단계를 **별도 커밋**으로 한다. 한 커밋에 묶으면 "결과 보고 맞췄다" 는
반론을 구조적으로 막을 수 없다.

| | 단계 | 왜 별도 커밋인가 |
|---|---|---|
| 1 | **peer-group golden 동결** | release 결과를 **보기 전에** 사람이 계산한 정답을 박아야 한다. 나중에 넣으면 oracle 을 결과에 맞춘 것이 된다 |
| 2 | **generator 만** 동결 (seed 없이) | seed 를 알고 grammar 를 쓰면 generator 가 seed 에 맞춰질 수 있다 |
| 3 | **seed 파생 + 생성 결과 digest** | seed 는 generator 커밋 해시에서 나온다. 질의·DB 쌍은 **한 번만** 생성 |
| 4 | **그다음 처음으로** legacy/release 실행 | 여기가 최초 관측 시점이다 |

### ★ seed 는 **generator 를 고정한 뒤** 파생한다

> **[정정]** 앞 판은 `340e330` 에서만 유도했다. **그것으로는 부족하다** —
> generator 가 아직 없었으므로 *"seed 를 알고 grammar·비율을 썼다"* 는
> 방법론적 반론이 성립한다. 의도하지 않아도 그렇게 될 수 있다.

순서를 바꾼다:

| | |
|---|---|
| 1 | generator 의 grammar·비율·코드·질의 수·최대 깊이를 **seed 없이** 커밋 |
| 2 | 그 generator 커밋 해시 `G` 에서 **최종 seed** 파생 |
| 3 | 이후 **generator 수정 금지** |
| 4 | 생성 결과와 digest 만 다음 커밋에 저장 |

`first_64_bits` 와 "문자열 결합" 은 구현마다 해석이 갈린다. **정확한 byte
encoding 을 고정**하고, 축약 해시가 아니라 **full commit OID** 를 쓴다:

```python
material = (
    b"ipguard-heldout-v1-final\0"
    + FULL_GATE_FREEZE_COMMIT.encode("ascii") + b"\0"
    + FULL_GENERATOR_COMMIT.encode("ascii") + b"\0"
    + FULL_POLICY_COMMIT.encode("ascii")
)
seed = int.from_bytes(hashlib.sha256(material).digest()[:8], "big")
```

세 해시는 파일 트리의 최신 상태를 중복 표현하는 것이 아니라 **역할별
provenance** 다:

| | |
|---|---|
| `GATE_COMMIT` | 게이트 **의미론**이 마지막으로 변경된 커밋 |
| `GENERATOR_COMMIT` | 생성기가 마지막으로 변경된 커밋 |
| `POLICY_COMMIT` | 정책·δ oracle·평가 규칙이 동결된 커밋 |

전부 **40자리** OID 다. NUL 구분자를 넣는 이유: 구분자 없이 이으면 서로 다른
세 쌍이 같은 material 을 만들 수 있다.

### `EVAL_BASE_COMMIT` 는 따로 기록한다

seed 는 역할별 세 커밋에서 파생하되, **실제 생성은 `EVAL_BASE_COMMIT`
checkout 에서** 수행한다. 게이트 로직이 안 바뀌고 회귀만 늘어난 커밋은
`GATE_COMMIT` 을 움직이지 않는다 — seed 재료는 *"무엇을 평가하는가"* 를
식별해야 하고, 테스트 추가는 평가 대상을 바꾸지 않는다.

`POLICY_COMMIT` 이 seed 에 들어가므로 그 커밋에 포함된 회귀와 최종 checkout
상태도 seed 에 결합된다.

`tools/gen_heldout.py` 에는 **seed 기본값이 없다** — `--seed` 를 필수로 두어
실수로 임의 seed 를 쓰는 것을 막는다.

기존 `0x865783f532a48e0a` 는 **golden/regression 용 predeclared seed** 로
남긴다. 최종 held-out 에는 쓰지 않는다.

### rejection sampling 도 **생성 전에** 고정한다

| 상황 | 처리 |
|---|---|
| 문법적으로 잘못된 SQL | 폐기, 사유 `syntax` |
| `ipguard_fragment()` 가 `F_core` 밖이라고 함 | 폐기, 사유 **`alignment`** |
| 중복 질의 | 폐기, 사유 `duplicate` |
| 최대 시도 초과 | 목표 미달인 채로 **보고하고 중단**. 조용히 늘리지 않는다 |

폐기된 시도를 **shape·사유별로 보존**한다 — 그래야 rejection sampling 후
**실현 분포가 요청 분포와 얼마나 달라졌는지** 알 수 있다.

> **`alignment` 라고 부르는 이유.** `outside_fcore` 는 generator 결함만을
> 가리키는 것처럼 읽히는데, 네 가지가 가능하다:
>
> (a) generator grammar 와 명세 불일치 · (b) rewrite 가 예상 못 한 구조를
> 생성 · (c) `ipguard_fragment()` 의 false negative · (d) fragment 문서와
> 구현 불일치
>
> 즉 **generator/fragment alignment failure** 다. `> 0` 이면 넷 중 어느
> 것인지 조사해서 보고한다.

> ★ **게이트 결과를 보고 질의를 폐기하면 안 된다.** 그건 평가 대상을 평가로
> 고르는 것이다. 생성 유효성 검사에는 **동결된 fragment classifier**
> (`ipguard_fragment()`)만 쓸 수 있다.

## 오염되면 어떻게 하는가

> **5. held-out 에서 버그가 발견되면 그 집합은 즉시 `bug-discovery set` 으로
> 전환한다.**
>
> **6. 수정 버전의 평가는 새로운 미사용 seed 로 다시 생성한다.**

같은 held-out 을 보고 고친 뒤 그 수치를 최종으로 쓰면 **그건 개발 코퍼스다.**
버그를 찾은 집합은 버그를 찾았다는 사실만 보고하고, 성능 수치는 새 seed 에서
낸다. 이 프로젝트는 이미 여러 번 witness 를 강화하며 수치를 정정했고
(삼자택이 7/8 → 4/6), 그때마다 **정정 사실을 남겼다.** 같은 규율을 여기에도
적용한다.

## 평가 절차 (8단계)

```
1. 고정 seed 로 F_core 질의 생성
2. masked-equivalent D1, D2 생성
3. ★ 하네스가 M(D1)=M(D2) 와 δ_Q(D1)=δ_Q(D2) 를 **먼저 검증**
4. gate 수락 여부 기록
5. 수락분만 독립 oracle 과 fidelity 비교
6. 수락분의 두 DB 결과를 opacity 비교
7. fails / unknown / declassification / unsupported 사유별 집계
8. 생성 표본 일부를 사람이 수동 감사
```

**3단계가 빠지면 6단계가 무의미하다.** `M(D1) ≠ M(D2)` 인 쌍에서 결과가
다른 것은 누출이 아니라 당연한 것이다. 명세 §6.5 의 다섯 조건(relation 구분 /
공개 컬럼 / 행 다중도 / 공개 row identity / NULL·collation)을 하네스가
실제로 확인해야 한다.

## Oracle 독립성

게이트와 oracle 이 **같은 lineage 코드**를 쓰면 같은 버그가 양쪽에 있어도
fidelity 100% 가 나온다. 세 층으로 분리한다.

| 층 | 출처 |
|---|---|
| 게이트 | C Query-tree effect 분석 (`ipguard.c`) |
| oracle | 별도 하네스 + **코퍼스 metadata 에 명시된 출력 lineage 주석** |
| golden | 작은 핵심 질의는 **사람이 계산한 정답** |

정렬 비교에서 **원본 질의에 정렬 키를 추가하지 않는다** — `DISTINCT`/
`GROUP BY` 의미가 바뀐다. 대신:

- **전순서 질의**: 원본 결과 sequence 를 그대로 비교
- **동률 질의**: privileged 실행에서 **별도로 확보한 원본 key vector** 로
  peer group 을 구성한다. 그 경로가 없으면 사람이 계산한 golden 을 쓴다

### peer-group golden 형식

**실행기가 낸 한 sequence 를 정답으로 저장하면 안 된다.** 그건 "지금 이
계획이 낸 순서" 일 뿐이고, 계획이 바뀌면 정답이 바뀐다. 의미론적 **허용
결과 집합**을 저장한다.

```
ordered peer blocks:
  B1 = bag{row_a, row_b}
  B2 = bag{row_c}

allowed:    row_a, row_b, row_c
            row_b, row_a, row_c
forbidden:  row_c, row_a, row_b
```

peer = **모든 `ORDER BY` 키와 SQL comparator·NULL 규칙이 같은 행들의 집합**.
블록 **내부만** 순열을 허용한다.

생성 절차 — **projection 이후 블록 경계 자체가 관찰되지 않을 수 있다**:

```
1. raw-key peer block 구성
2. 블록별 허용 순열 생성
3. output projection/redaction 적용
4. 중복되는 observable sequence 합치기
```

4단계가 요점이다. `SELECT 'x' FROM t ORDER BY secret` 은 raw key 에 여러
블록이 있어도 observable 은 `['x', …]` **하나**다.

구현: [`../corpus/peer-golden.json`](../corpus/peer-golden.json),
[`../tools/score_peer_golden.py`](../tools/score_peer_golden.py).
최소 세 부류를 넣었다 — 공개 `id` 로 peer 내부 순열이 관찰되는 경우,
모든 출력이 같아 order sink 가 소거되는 경우, NULL peer +
`NULLS FIRST`/`LAST`.

## 분모 — 동률 질의를 `F_core` 에서 빼지 않는다

oracle 구현이 어렵다는 이유로 이미 동결한 `F_core` 에서 빼면 **분모가 다시
움직인다.** 나눠서 보고한다:

| 항목 | 기호 |
|---|---|
| 전체 `F_core` | `N` |
| total-order 정량평가 가능 | `A` |
| peer-order 별도 의미론 회귀 | `B` |
| oracle 미구현 | `C` |

`C > 0` 이면 **accepted-query fidelity 를 `A` 에 대해서만 측정했다**고
명시한다. 목표는 동률 핵심 질의에 사람이 계산한 peer-group golden 을 넣어
`C = 0` 으로 만드는 것이다.

## ★ 비접촉 표본을 acceptance 에 섞지 않는다

`P_TOUCH_LABELED_PER_DRAW = 0.75` 는 **draw 당** 확률이라 질의당 접촉률은
더 높다(실측 ~0.87). 비접촉 표본은 **false-positive 측정용**이고, 전체
acceptance 에 섞으면 쉬운 표본이 수치를 올린다. 최소 이렇게 분리한다:

| 층 | 무엇을 보는가 |
|---|---|
| label-**non**-touching | 정상 수락률 / 퇴행 (false positive) |
| label-touching | **certification acceptance** ← 핵심 totality 비용 |
| label-touching 중 | `VAL`/`EQ`/`ORD`/`CARD` 별 분포 |
| label-touching 중 | 각 observable sink 별 분포 |

전체 수치를 같이 내도 되지만, **핵심 totality 비용은 label-touching subset
에서** 보여야 한다.

## ★ opacity 의 **단위**를 미리 고정한다

질의 400개를 DB pair 4유형에 돌리면 **두 숫자가 생긴다**:

```
generated queries  =   400
query-pair trials  = 1,600      trial = (Q[θ], pair)
```

**섞으면 표본 수가 부풀려진다.** 표에 반드시 분리해서 쓴다.

### applicability 는 **게이트 결과를 보기 전에** 판정한다

각 `(Q[θ], pair)` 에 대해:

| 조건 | 필수 여부 | 실패하면 |
|---|---|---|
| `M(D1) = M(D2)` | **항상** | **pair 생성 결함** — 고쳐야 한다 |
| `δ_{Q,θ}(D1) = δ_{Q,θ}(D2)` | declassification 이 있으면 | 그 trial 은 **scoped-opacity 비교 불가** |

- **비교 불가능하다고 질의를 폐기하면 안 된다.** `opacity_applicable = false`
  로 남기고 **별도 집계**한다.
- applicability 판정은 legacy/release 결과를 보기 **전에** 끝낸다.

### 최종 표에 분리해서 쓸 것

```
400     generated queries
1,600   pair trials
?       masked-equivalent trials
?       δ-equivalent trials
?       release-accepted applicable trials
?/?     opacity successes / failures
```

### `multiplicity` pair 의 함정

민감 원본값의 **빈도만** 달라지는 것은 괜찮다. 그러나 **공개 row 대응이
달라지면 witness 전제가 깨진다.** 하네스가 실제로 확인해야 한다:

- 공개 row identity(PK)가 1:1 로 대응
- **마스킹된 튜플의 bag multiplicity 가 완전히 동일**

`gen_heldout.py` 의 `check_masked_equivalent()` 가 명세 §6.5 의 다섯 조건을
생성 시점에 확인하고 결과를 `masked_equivalence_check` 에 남긴다.

## 보고할 수치

- `F_core` acceptance 와 **거부 사유별 분해**
  (`fails` / `unknown` / declassification 으로 수락 / `unsupported`)
- accepted subset 의 fidelity 와 scoped opacity
- `F_impl \ F_core` 의 unsupported 비율 (**window 8건은 여기**)
- **planner-work proxy**: 계획 1건당 레지스트리 SPI 조회 횟수

### ★ 성능은 "미측정" 이다

SPI 조회 횟수를 실행시간 overhead 의 대체값으로 쓰면 **안 된다.** Query-tree
순회, SPI 캐시 상태, 카탈로그 접근 비용을 반영하지 못한다. 이름을 이렇게
제한한다:

> planner-work proxy: number of registry SPI lookups per planned query

계획시간 overhead 는 별도 환경에서 **interleaved legacy/release** 로
median/p95 를 재야 한다. 이 호스트는 공유 서버(홈 10개, 상시 세션 6개)라
불가능하다. 그때까지 **성능은 미측정**으로 남긴다.

## 두 표로 분리해서 보고한다

`F_impl \ F_core` 의 거부가 `F_core` totality 손실로 잘못 계산되지 않도록.

**인증 평가 — `F_core` 만**

| | Legacy | Release |
|---|---:|---:|
| Acceptance | | |
| Fidelity among accepted | | |
| Scoped opacity among accepted | | |
| `fails` 로 거부 | | |
| `unknown` 으로 거부 | | |
| declassification 으로 수락 | | |

**운영 범위 — `F_impl \ F_core`**

| | Legacy | Release |
|---|---:|---:|
| window 8건 | 실행 | certified-mode 거부 |
| 관찰된 조용한 오답 | | |
| `OUTSIDE_CERTIFIED_FRAGMENT` | — | |

## 평가 입력 전체가 동결돼야 한다 — 질의만으로는 부족하다

`[3/4]` 에서 다음을 함께 생성하고 digest 한다:

- masked-equivalent `(D1, D2)` — **여러 유형**
- mask instance 와 label 배치
- parameterized query 의 타입과 `θ` binding
- declassification policy seed
- 독립 output-lineage metadata

> **하나의 약한 DB pair 만 쓰면 채널이 우연히 가려진다.** 삼자택이 opacity 가
> 7/8 에서 4/6 으로 정정된 것이 정확히 그 사고였다 — witness 의 정렬 순서가
> id 순서와 같아 `ORD` 채널이 통째로 숨어 있었다.

그래서 pair 유형을 넷 둔다. **유형별로 결과를 보고한다.**

| 유형 | 무슨 채널을 드러내는가 |
|---|---|
| `eq_split` | 고유값 개수 (`EQ` → `ROW_COUNT`) |
| `ord_permutation` | 정렬 순서가 id 순서의 역순 (`ORD`) |
| `null_structure` | NULL 위치는 같고 non-NULL 분포만 다름 |
| `multiplicity` | 같은 고유값 수, 다른 다중도 (`MULTIPLICITY`) |

★ 모든 유형이 `M(D1) = M(D2)` 를 만족해야 한다(명세 §6.5). 마스크가
`null_equivalence` 를 지키므로 **NULL 위치가 두 DB 에서 같아야** 한다 —
다르면 마스킹된 모습이 달라져 전제가 깨진다. 하네스가 8단계 절차의 3단계에서
실제로 검증한다.

## 환경 동결

`results/eval-freeze.md` 를 **측정 직전에** 다시 생성한다. Git 커밋만으로는
재현되지 않는다 — 카탈로그 OID, collation, 빌드 지문, 레지스트리 시드가
전부 소스 밖에 있다.
