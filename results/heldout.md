# Held-out v1 — bug-discovery evaluation

> **이것은 최종 안전성 표가 아니다.** 이 실행의 목적지는 §11-6(정리 1·2의
> 구조적 귀납 증명)이었으나, 실행 중 **정리 2의 잠재적 반례**(G3)와 명세와
> 어긋나는 정책 구현(PD1)이 드러났다. 그래서 이 실행은 `bug-discovery set`
> 으로 확정하고, 수정 뒤 **새 동결·새 seed·새 코퍼스**로 최종 평가를 다시
> 한다. `fidelity 위반 0` · `opacity 위반 0` 을 headline 으로 쓰지 않는다.

최초 관측(attempt 1)은 정상 종료했으나 **관측 함수 자체가 결함**이어서 결과를
쓰지 않는다. 보존물은 `results/heldout-raw/` 와
`results/heldout-run-provenance.md` 에 그대로 남겼다. 아래 수치는 전부
attempt 2(`results/heldout-raw2/`) 에서 나온다.

이 문서는 외부 독립 재계산·반증 검증을 한 차례 거쳐 수정됐다.
초판의 사실오류 1건(`param_scope`)과 근거 오류 1건(표 B)이 그 과정에서
드러났고, 새 결함 3건(H4·G3·PD1)이 추가로 발견됐다. §5 참조.

## 이 실행으로 주장할 수 있는 것 / 없는 것

| | |
|---|---|
| ✅ 주장 가능 | 판정 결과의 **재현성**과 **데이터 독립성**이 확인됐다 |
| ✅ | **측정 가능한** accepted subset 에서 fidelity·opacity 실패를 관찰하지 않았다 |
| ✅ | P0 ⊆ P1 **단조성**이 성립한다 |
| ❌ 주장 불가 | 출력이 **바뀐** trial 의 fidelity 는 대부분 미측정이다 |
| ❌ | `ORD→FINAL_ORDER`·`EQ→CELL` 은 수락 사례가 0건이라 **양성 증거가 없다** |
| ❌ | P1 scoped-opacity 성공은 δ 비동치 trial 제외에 크게 의존한다 |
| ❌ | `F_impl \ F_core` 동작에 대한 증거가 전혀 없다 (표 B 공집합) |

이 실행이 실제로 잡아낸 것 — runner 의 δ 가정 오류(H1), wrapper 로 인한
fail-close(H3)와 fail-open(H4), `aggdistinct` 의 `EQ` 누락(G3),
declassification 과잉 설치(PD1), fidelity oracle coverage 공백, 평가 채널
편중. 최종 평가 **전에** 이것들을 찾은 것이 이 단계의 성과다.

## 0. provenance

```
GATE_COMMIT       5e21c7d7cd089773cf7f4a9a629b61bd53067ac7
GENERATOR_COMMIT  9222ef3b4e7e13b685db5377486cb9eef8c7f236
POLICY_COMMIT     533502d297e12ede971b8c08cce8ce2f46446b0c
EVAL_INPUT_COMMIT 68ed0020fc0bd8d8e9131ef91a69ec4d0af8eec7
seed              0xa3062488859d4a48
attempt 1 runner  31d46a73964504ba766f979106e93cf2673b7048c84e08fff0937bbad2d72a70
attempt 2 runner  1ddeb57d55e9f34f362dcd6d9d762e164024ed00cde97d9d8c9e3de296d76dc1
입력 ordered list digest  115127f14c827b11   (두 attempt 동일 — 3중 대조)
pair 적재 table digest    d934aa47c1e37c48   (16상태, 재적재 재현 확인)
raw trial digest          8dd5d6066c7305d5
```

`raw-obligations.json` 만 예외다. 이 파일은 실행 **뒤에** 같은 코드로 다시
뽑았다. 스키마를 재생성했으므로 canonical 안의 relation OID 가 달라
`context_key` 는 인증서와 87/358 만 겹친다. 다만
질의별 obligation 개수는 digest 로 봉인된 `raw-trials.jsonl` 의
`n_raw_obligations` 와 400/400 질의에서 일치하므로 **분포 통계는 독립**
**확인**된다. effect/sink 분포를 읽을 때만 쓰고, 인증서 대응 관계의 근거로는
쓰지 않는다.

## 1. 분모

| 단위 | 수 |
|---|---:|
| 질의 | 400 |
| pair 유형 | 4 |
| pair trial (정책당) | 1600 |
| 전체 trial (P0+P1) | 3200 |
| label-touching 질의 | 347 |
| label 미접촉 질의 | 53 |
| fidelity oracle 가용(class A) 질의 | 162 |
| fidelity oracle 미구현(class C) 질의 | 238 |
| class A / class C trial (정책당) | 648 / 952 |

shape: `projection` 95, `aggregate` 68, `derived` 54, `order_by` 49, `group_by` 42, `order_limit` 33, `distinct` 33, `setop` 26

## 2. 적용가능성 — 게이트 실행 **전**에 고정

- `M(D1) = M(D2)`: **8/8** (pair 유형 4 × 테이블 2). 실패 0.
- `δ_Q(D1) = δ_Q(D2)`: **1558/1600**, 미측정 **0**.
  θ 를 실제 binding 으로 치환한 뒤 3VL 을 축약하지 않고 측정했다.
- 그 중 **404건**(25.2%)은 질의에 WHERE 가 없어
  δ 동치가 공허하게 성립한다. 실제로 술어를 비교한 것은
  1196건이고 그 중 42건이 상이하다.

## 3. 실행 전 고정된 obligation·인증서

raw obligation **1265건** / 질의 400건 (obligation 0건 53건 = label 미접촉 집합과 일치).

effect: `CARD` 653, `EQ` 263, `VAL` 243, `ORD` 106 / sink: `CELL` 358, `MULTIPLICITY` 291, `MEMBERSHIP` 291, `ROW_COUNT` 267, `FINAL_ORDER` 58

(effect, sink): `VAL→CELL` 243, `CARD→ROW_COUNT` 191, `CARD→MULTIPLICITY` 191, `CARD→MEMBERSHIP` 191, `CARD→CELL` 80, `EQ→ROW_COUNT` 76, `EQ→MULTIPLICITY` 76, `EQ→MEMBERSHIP` 76, `ORD→FINAL_ORDER` 58, `EQ→CELL` 35, `ORD→MULTIPLICITY` 24, `ORD→MEMBERSHIP` 24

context: `WHERE/JOIN predicate` 653, `GROUP BY key vector` 140, `column` 130, `ORDER BY key vector` 106, `DISTINCT key vector` 84, `aggregate` 50, `scalar function` 43, `subquery output` 20, `EXCEPT` 18, `UNION (non-ALL)` 15, `INTERSECT` 6

P1 인증서 **653건** (obligation 인스턴스 단위. 서로 다른
`(canonical, table)` 는 **358개** — `653` 을 '서로 다른 인증서 수'로
읽으면 안 된다).

| 필드 | 값 |
|---|---|
| effect | `CARD` 653 |
| observation | `predicate-decision-trace` 653 |
| sink | `ROW_COUNT` 191, `MULTIPLICITY` 191, `MEMBERSHIP` 191, `CELL` 80 |
| **param_scope** | `none` **431**, `all_values` **222** |

`param_scope` 는 질의에 파라미터가 있을 때만 `all_values` 다
(`tools/run_heldout.py:281`). 파라미터 질의 89건에서 나온 222건만
`all_values` 이고 나머지 431건은 `none` 이다.
실제 DB 설치 행수는 **946행**이다 — 인증서 수가 아니다. 사유는 §5 PD1.

## 표 A — 인증 평가

| | P0 | P1 |
|---|---:|---:|
| 수락 (질의) | 72/400 | 173/400 |
| 수락 (trial) | 288/1600 | 692/1600 |
| 수락률 (trial) | 18.0% | 43.2% |
| — 그중 **비퇴화** | 46 (12 질의) | 233 (60 질의) |
| fidelity — pass | 212 | 416 |
| fidelity — **fail** | **0** | **0** |
| fidelity — 미측정(class C) | 76 | 276 |
| — pass 중 **비자명** | 0 (0 질의) | 105 (27 질의) |
| scoped opacity — 적용 | 288 | 668 |
| scoped opacity — pass | 288 | 668 |
| scoped opacity — **fail** | **0** | **0** |
| scoped opacity — 비적용(δ 상이) | 0 | 24 |
| (참고) 무범위 opacity fail | 0 | 23 |
| declassification 신규 수락 | — | 404 trial / 101 질의 |

**비퇴화** = 라벨을 건드리고 ∧ obligation ≥ 1 ∧ 관측이 비어 있지 않은 trial.
나머지는 통과가 측정이 아니라 구조적 항등식이다:
수락 980건 중 라벨 미접촉 424건(읽는 컬럼이 D1·D2 에서
byte-identical), 관측이 `(empty)` 인 것 381건(12행 테이블에서 술어가
충족 불가능).

### 거부 사유 분해 (trial)

게이트는 **처음 해소되지 않은 obligation 하나**를 사유로 보고한다. 아래는
원인의 분할이 아니라 *먼저 보고된* 원인의 분포다. P0→P1 에서 capability
계열이 늘어난 것도 새로 생긴 게 아니라, P0 에서 `CARD` 에 가려져 있던
obligation 이 `CARD` 를 declassify 하자 드러난 것이다.

| 사유 | P0 | P1 |
|---|---:|---:|
| CARD 미선언 (declassification 없음) | 664 | 0 |
| EQ capability fails | 160 | 304 |
| ORD capability fails | 232 | 232 |
| 라벨 집계 미인증 (사유코드 G1) | 200 | 200 |
| cast 미지원 | 40 | 128 |
| 함수 인증서 없음 | 16 | 44 |
| **합계** | **1312** | **908** |

### 어느 채널이 실제로 시험됐는가

| 채널 | 해당 질의 | P0 수락 | P1 수락 |
|---|---:|---:|---:|
| `ORDER BY` 가 라벨 → ORD/FINAL_ORDER | 58 | 0 | 0 |
| `GROUP BY` 가 라벨 → EQ/CELL | 35 | 0 | 0 |
| `SELECT DISTINCT` + 라벨 → EQ/ROW_COUNT | 32 | 0 | 4 |
| `WHERE` 술어가 라벨 → CARD | 234 | 0 | 101 |

`ORD→FINAL_ORDER` 와 `EQ→CELL` 은 **수락 trial 이 0건**이다. 이 실행의
opacity·fidelity 결과는 그 두 채널에 대해 아무 말도 하지 않는다. 실질적으로
시험된 것은 `CARD`(전량 declassify)와 `VAL`(출력 마스킹) 두 채널뿐이다.

## 표 B — 운영 범위 (`F_impl \ F_core`)

**근거는 텍스트가 아니라 트리다.** `corpus/heldout.json` 의
`validated_with = ipguard_fragment() -- 동결된 fragment classifier` — 생성기가 질의마다 재작성 후
Query 트리를 `ipguard_fragment()` 로 분류하고 `F_core` 밖이면 폐기했다.
배포된 코퍼스의 폐기 사유는
`{"duplicate": {"aggregate": 6, "derived": 5, "distinct": 3, "group_by": 1, "order_by": 9, "order_limit": 1, "projection": 3}}` 뿐이다 —
`alignment` 0, `syntax` 0, 총 28/428
시도. 즉 400건 전부가 동결된 분류기의 `F_core` 판정을 통과했다.

명세 §12 의 `F_core` 제외 목록에 대한 텍스트 대조는 **보조 확인**이다
(명세가 `candidate-F_core` = 상한이라고 규정한 산출물이므로 단독 근거가 되지
못한다):

| 명세 §12 제외 항목 | 코퍼스 출현 |
|---|---:|
| window function (frame 포함) | 0 |
| `LATERAL` | 0 |
| recursive CTE | 0 |
| `DISTINCT ON` | 0 |
| `FETCH … WITH TIES` | 0 |
| `GROUPING SETS`/`ROLLUP`/`CUBE` | 0 |
| ordered-set aggregate (`WITHIN GROUP`) | 0 |
| outer join | 0 |
| `NOT EXISTS` | 0 |
| `NOT IN` / `<> ALL` | 0 |
| row-valued `IN` | 0 |
| 상관 스칼라 서브쿼리 `= (SELECT` | 0 |
| DML / `RETURNING` / `COPY` | 0 |
| 명시 `COLLATE` | 0 |
| SRF (`generate_series` 등) | 0 |
| unordered top-k (`LIMIT` w/o `ORDER BY`) | 0 |

**표 B 는 공집합이다.** 두 근거(트리 분류기 + 텍스트 대조)가 일치하고,
`raw-trials.jsonl` 에 `OUTSIDE_CERTIFIED_FRAGMENT` 문자열도 0건이다.

따라서 이 실행은 인증 범위 밖 동작 — 관측된 silent-wrong,
`OUTSIDE_CERTIFIED_FRAGMENT` 거부 — 에 대해 **아무 증거도 제공하지 않는다**.
이전 divergence 코퍼스의 window 8건 수치는 여기로 이월되지 않는다.

주의 하나. `NOT IN` 과 row-valued `IN` 은 파서가 각각 `NOT(x = ANY …)` 와
`RowCompareExpr`/AND-chain 으로 재작성하므로 **텍스트로는 원리적으로 탐지할**
**수 없다**. 이 둘의 0 은 위 텍스트 행이 아니라 트리 분류기가 보증한다.
초판은 `JOIN`·`EXISTS`·`IN (SELECT`·CTE·`VALUES`·`CASE` 를 세었는데, 이 여섯은
명세 §12 가 `F_core` **안쪽**으로 넣은 구성이라 표 B 에 대한 정보량이 0이었다.

## 4. 핵심 검증과 그 한계

### 검증된 것

1. **출력이 달라진 P1 수락 23 trial**(8 질의)은 전부 `δ_Q(D1) ≠ δ_Q(D2)` 이고,
   전부 P0 에서 `CARD` 사유로 거부됐다. 수락은 전적으로 declassification
   때문이고 차이는 `predicate-decision-trace` 범위 안이다.
2. P0 수락 → P1 수락 **단조성 성립**, 역행 0.
3. 게이트 판정은 pair 유형과 무관 — `gate_accept`·`rejection_reason` 불일치 0.

### 그 검증이 닿지 않는 곳

1. **fidelity 오라클은 강제가 출력을 바꾼 trial 에 한 번도 적용되지 않았다.**
   수락 980건 중 `release ≠ privileged` 인 것이 181건인데
   그 전부가 class C(미측정)다 (class A 인 것 0건). 뒤집으면 class A
   수락은 전건이 `release = privileged` 다. `fail 0` 은 위반이 없다는 증거가
   아니라, 위반이 가능한 영역이 분모에 없었다는 사실의 결과다.
2. **`scoped opacity fail 0` 은 정의 변경의 결과이기도 하다.** P1 비적용
   24건의 내역이 무범위 fail 23 + pass 1 이다 — 제외집합이 실패집합과 거의
   일치한다. 이 필터가 정당한 근거는 필터 자체가 아니라 위 검증 1(δ 상이 ∧
   P0 거부)이다.
3. **pair 무관 주장은 이 설계에서 반증 불가능하다.** 게이트는 SQL·카탈로그에
   대한 정적 분석이고 `pair_type` 은 데이터 속성이라 판정이 갈릴 경로가 없다.
   정작 pair 유형이 가르는 관측치(무범위 opacity)는 같은 질의 안에서 갈린다 —
   fail 23건이 4의 배수가 아닌 것이 그 증거다.
4. **단조성도 위험집합이 공집합이다.** P0 수락 질의의 obligation 은 전부
   `VAL→CELL` 인데 인증서는 전부 `CARD` 라, P1 은 그 질의들에 대해 P0 과
   똑같은 계산을 반복한다. 게다가 인증서 추가는 obligation 해소를 늘릴 뿐이라
   단조성은 게이트 설계의 정리이지 측정 결과가 아니다.

## 5. 발견된 결함

### 하네스 (attempt 1) — 결과 폐기 사유

| | 내용 | 영향 |
|---|---|---|
| H1 | δ 오라클이 술어에 `$1` 이 있으면 측정을 건너뛰고 `δ-equivalent=True` 로 가정 | opacity 판정이 부당하게 엄격 → 허위 fail 11 |
| H2 | 파라미터/비파라미터 질의에 서로 다른 관측 함수 | 두 집합 비교 불가 |
| H3 | 관측 wrapper 의 `z::text` 가 whole-row composite cast (`F_core` 밖) | 게이트가 wrapper 때문에 **fail-close** — 라벨접촉 비파라미터 264건 중 175건 |
| **H4** | 같은 wrapper 가 내부 `ORDER BY` 를 **삼켰다** | 게이트가 **fail-open** — attempt 1 이 수락한 272 trial (34 질의, 전부 `order_by`)을 attempt 2 는 `ORD → FINAL_ORDER : order_factor=fails` 로 거부한다 |

H4 가 H3 보다 나쁘다. H3 는 없는 위반을 만들었지만 H4 는 **있는 의무를**
**숨겼다** — attempt 1 은 ORD 인증서 없이 라벨 컬럼으로 정렬하는 질의를 조용히
수락했다. attempt 1 폐기 결정은 이 발견으로 더 강해진다.

### 게이트 (`5e21c7d`)

- **G1 사유코드 (건전성 영향 없음).** 라벨 컬럼 집계에
  aggregate-compatibility 인증서가 없을 때 `UNMODELED_NODE: UNMODELED_EXPR`
  로 보고한다 — 질의 50건 / 200 trial. fail-closed 이지만
  `F_core` 밖과 `F_core` 안-미인증을 구분할 수 없게 만든다. 반증검사: 라벨접촉
  이면서 라벨 집계·라벨 cast 가 없는 265건 중 `UNMODELED_NODE` 는 0건.
- **G3 의무 누락 (잠재 불건전).** `count(DISTINCT <라벨컬럼>)` 형태 11건이
  마스킹된 컬럼 위에서 등가 기반 중복제거를 하는데 `EQ` obligation 을
  **0건** 낸다. 대조로 질의 수준 `SELECT DISTINCT` + 라벨 32건은
  `EQ` obligation 84건을 낸다. `ipguard_fragment()` 의 `Aggref` 검사도
  `aggdistinct` 를 보지 않는다. 지금은 11건 전부 G1 으로 fail-close 되어
  실제 불건전 수락이 없지만, aggregate-compatibility 인증서를 등록하는 순간
  `EQ` 채널이 검사되지 않은 채 통과한다.
- **G2 계측 (건전성 영향 없음).** `ipguard_pii_plan_count()` 가 set-operation
  계획을 세지 않는다 (`HO0064`, `HO0149`, `HO0275`). 세 질의 모두 obligation 을
  정상 생성하고 P0 에서 거부됐으므로 게이트는 실행됐다.

### 정책 하네스

- **PD1 declassification 과잉 설치.** `tools/run_heldout.py:271-273` 의 컬럼
  제한 루프가 본문 `pass` 인 죽은 코드라, `install_certs` 가 인증서를 해당
  테이블의 **모든** 라벨 컬럼에 설치한다. `birth` 술어에서 나온 CARD 인증서가
  `ssn` 의 CARD declassification 도 부여한다. 인증서 653건 → 설치
  946행. P1 의 실제 선언 범위가 보고된 것보다 넓다.

## 6. 성능

**미측정.** 공용 서버에서 `unprivileged_bpf_disabled=2`,
`perf_event_paranoid=4`, sudo 없음 — eBPF·perf 계측이 불가능하다.

planner-work proxy(`ipguard_pii_plan_count()`)는 **보고에서 제외한다**.
G2 때문에 set-operation 계획을 세지 않아 신뢰할 수 없다. 한계는
`ext/ipguard.c` 의 계수 지점 주석에 남겼다. 성능 수치는 이 프로젝트에서
아직 **한 건도 측정된 적이 없다**.

## 7. 수동 감사 표본

질의 ID 해시 규칙 `sha256(id)[:4] % 40 == 0` 으로 **17건**. 결과를 보고
고르지 않았고 두 attempt 에서 byte-identical 하다.

| 질의 | shape | P0 | P1 | oracle |
|---|---|---|---|---|
| `HO0020` | projection | CARD 미선언 (declassification 없음) | 수락 | C |
| `HO0059` | order_limit | ORD capability fails | ORD capability fails | A |
| `HO0076` | projection | CARD 미선언 (declassification 없음) | 수락 | C |
| `HO0090` | derived | CARD 미선언 (declassification 없음) | cast 미지원 | C |
| `HO0120` | order_by | ORD capability fails | ORD capability fails | A |
| `HO0132` | aggregate | 라벨 집계 미인증 (사유코드 G1) | 라벨 집계 미인증 (사유코드 G1) | C |
| `HO0180` | aggregate | 라벨 집계 미인증 (사유코드 G1) | 라벨 집계 미인증 (사유코드 G1) | C |
| `HO0196` | derived | CARD 미선언 (declassification 없음) | cast 미지원 | C |
| `HO0203` | projection | CARD 미선언 (declassification 없음) | 수락 | C |
| `HO0216` | order_by | ORD capability fails | ORD capability fails | A |
| `HO0255` | setop | CARD 미선언 (declassification 없음) | EQ capability fails | C |
| `HO0343` | aggregate | CARD 미선언 (declassification 없음) | 수락 | A |
| `HO0347` | aggregate | CARD 미선언 (declassification 없음) | 수락 | A |
| `HO0350` | order_limit | 수락 | 수락 | A |
| `HO0363` | derived | CARD 미선언 (declassification 없음) | 함수 인증서 없음 | C |
| `HO0371` | aggregate | 라벨 집계 미인증 (사유코드 G1) | 라벨 집계 미인증 (사유코드 G1) | C |
| `HO0375` | aggregate | 수락 | 수락 | A |
