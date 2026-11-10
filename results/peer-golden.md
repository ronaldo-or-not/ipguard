# peer-group golden — 의미론 회귀 (2026-08-09)

`corpus/peer-golden.json` 은 **사람이 계산한 의미론적 허용 결과 집합**이다.
release 결과를 **보기 전에** 동결했다(`docs/heldout-protocol.md` 1단계,
커밋 `81c00bc`).

원시 출력: [`peer-golden.txt`](peer-golden.txt) ·
도구: [`../tools/score_peer_golden.py`](../tools/score_peer_golden.py),
[`../tools/enumerate_peer_golden.py`](../tools/enumerate_peer_golden.py)

---

## 두 검사는 다르다

| | 무엇을 보는가 | 도구 | 결과 |
|---|---|---|---|
| **golden consistency** | 실제 출력 **하나**가 허용 집합 안에 있다 | `score_peer_golden.py` | **16/16** |
| **completeness** | 모든 peer 내부 순열을 projection 한 집합이 허용 집합과 **정확히 같다** | `enumerate_peer_golden.py` | **6/6** |

> **[정정]** 앞 판은 `16/16` 을 golden 의 정확성 근거로 썼다. **부족하다.**
> 실제 출력 하나가 집합 안에 있는 것은 **soundness sanity check** 일 뿐,
> 허용 집합이 너무 넓은지(금지된 순서를 허용) 너무 좁은지(정당한 순서를
> 누락) 말해주지 않는다. 정확한 이름은 **golden consistency regression** 이다.

완전성은 독립 enumerator 가 뒷받침한다 — `raw_peer_blocks` 에서 2~4단계를
DB 없이 재구성해 `allowed` 와 **집합으로** 비교한다.

```
2) 블록별 허용 순열 생성
3) output projection/redaction 적용
4) 중복되는 observable sequence 합치기
```

**블록 구성(1단계)은 여전히 손계산이다** — 어느 행들이 peer 인가는 SQL
의미론 판단이고, 그걸 기계로 만들면 검증하려는 대상과 같은 코드가 된다.

## 항목

| | 부류 | 블록 | 블록내 순열 | observable |
|---|---|---:|---:|---:|
| PG01 | 공개 `id` 로 peer 내부 순열이 관찰된다 | 3 | 4 | **4** |
| **PG02** | 모든 출력이 같아 order sink 소거 | 4 | 2 | **1** |
| PG03 | NULL peer + `NULLS FIRST` | 4 | 2 | 2 |
| PG04 | NULL peer + `NULLS LAST` | 4 | 2 | 2 |
| PG05 | `DESC` — 블록 사이만 뒤집힌다 | 3 | 4 | 4 |
| PG06 | 전순서 | 5 | 1 | **1** |

**`PG02` 가 4단계의 예다.** raw key 로는 블록이 4개(`a`,`b`,`c`,`NULL×2`)인데
투영이 전부 `'x'` 로 만들어 **observable 은 하나**다 — 블록 경계 자체가
관찰되지 않는다.

**`PG03`/`PG04` 를 나란히 둔 이유**는 따로 있다. 마스크가 non-NULL 을 NULL 로
바꾸면 그 행이 **블록 사이를 이동**한다. `order_factor` 로는 못 잡고
`null_equivalence` 가 필요하다는 것을 의미론 수준에서 고정한다.

## 마스킹 OFF 검증이 순환이 아닌 이유

마스킹을 끄면 그건 그냥 PostgreSQL 이다. 거기 출력이 손계산 집합에 있으면
**손계산이 맞은 것**이고, 게이트를 쓰지 않으므로 순환이 아니다.

release 게이트가 `PG03`/`PG04` 를 거부하는 것은 설계대로다 — `pgsec` 에
인증서를 등록하지 않았다. **거부는 실패가 아니고**, acceptance 비용은
§11-5 에서 따로 센다.

## 한계

- 블록 구성(1단계)이 손계산이다. `ORDER BY` 키가 복잡해지면 사람이 틀릴 수
  있고, 그때는 enumerator 도 같이 틀린다(같은 입력을 쓰므로).
- 6항목·5행이다. 의미론 부류를 덮는 것이 목적이고 워크로드 분포가 아니다.
- `projection` 이 손으로 명시돼 있다. 마스킹된 출력을 넣는 항목은 아직 없다 —
  현재 항목은 전부 공개 컬럼 또는 상수를 투영한다.

## 재현

```bash
python3 tools/enumerate_peer_golden.py   # 완전성 (DB 불필요)
python3 tools/score_peer_golden.py       # 일관성 (DB 필요)
```
