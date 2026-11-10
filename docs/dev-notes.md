# identity-plumbing

커넥션 풀을 관통하는 최종 사용자 신원 전파 및 DB 티어 인가 집행.
(마이데이터 / OpenAPI 고TPS 서버 대상, PostgreSQL)

**기여는 마스킹 기법이 아니다.** 마스킹은 PostgreSQL Anonymizer / Oracle Data
Redaction이 이미 한다.

> **[2026-08-08 정정]** 원래 이 자리에는 *"기여는 커넥션 풀을 관통하는 신원
> 배관이다"* 라고 적혀 있었다. **그 신원 배관은 만들지 않았고**(상태표 참조),
> 선행연구 조사 결과 **Oracle Real Application Security(2013)와 특허
> US 10,049,205 가 이미 해결**했다. 선언한 기여를 안 만들었고, 만든 것은
> 기여가 아니라고 선언해 둔 상태였다.
>
> **실제로 만들고 측정한 것은 마스킹 집행의 정확성**이고, 그중 선행연구가
> 비워 둔 자리는 하나다 — **동적 마스킹의 설계 공간이 Fidelity·Mask opacity·
> Totality 의 삼자택이임을 형식화하고, 세 번째 꼭짓점(거부)을 점유하며 그
> 비용을 워크로드별로 실측한 것**
> ([`results/trilemma.md`](results/trilemma.md),
> [`results/divergence.md`](results/divergence.md),
> [`results/crosscheck-anon.md`](results/crosscheck-anon.md)).
> Blockaid(OSDI 2022)는 다른 조건으로 거부하고, Mascara(SIGMOD 2025)는 거부
> 대신 열화한다. 여기가 비어 있다.
>
> **[2026-08-09 재정정]** *"결정 가능한 판정"* 이라고 쓰던 것을 내렸다. 임의
> UDF 를 포함하면 semantic factorization 은 **일반적으로 결정 불가능**하다.
> 정확한 문장은 이것이다:
>
> > **A decidable and sound certificate checker for sufficient
> > release-factorization conditions over a declared SQL fragment.**
>
> 게이트가 판정하는 것은 의미론 전체가 아니라 **선언된 fragment 위의 제한된
> 인증서 언어**이고, 나머지는 `unknown → reject` 다. 기법 이름은
> **release-factorization gate** — 원본 비교가 공개된 정보(release)로부터
> 재구성 가능한가(factor through)를 묻기 때문이다.
> 정의는 [`docs/spec-lineage-and-masks.md`](docs/spec-lineage-and-masks.md)
> (v0.2.1, **동결**)에 고정했다.

---

## 현재 상태 (2026-08-08)

| 구성요소 | 상태 |
|---|---|
| 토큰 와이어 포맷 명세 + 레퍼런스 구현 | ✅ `docs/token-format.md`, `tools/token.py` |
| H5 표현식 우회 코퍼스 | ✅ `corpus/h5-corpus.json` (72항목), `corpus/schema.sql` |
| PostgreSQL 16.10 (소스 빌드, sudo 없이) | ✅ `tools/build-pg.sh`, db.example.internal |
| 와이어 기준선 채점 하네스 | ✅ `tools/probe_provenance.c`, `tools/score_wire.py` |
| **와이어 기준선 실측** | ✅ **38%** — `results/wire-baseline.md` |
| **PostgreSQL C 확장 `ipguard` (AST 순회, 탐지 전용)** | ✅ `ext/` — **회수율 95%** |
| **탐지기 적대적 시험 1R** (순회기 로직) | ✅ `results/adversarial.md` — 결함 8건, fail-closed 신호 확립 |
| **탐지기 적대적 시험 2R** (라벨·자원) | ✅ `results/adversarial2.md` — 결함 3건, 라벨전파 한계 규명 |
| **적대적 시험 3R** (판정식·센티널) | ✅ `results/adversarial3.md` — 결함 **4건**, ★중첩 집합연산 PII 평문 누출 |
| **적대적 시험 4R** (카탈로그·DDL) | ✅ `results/adversarial4.md` — **10건 중 6건 평문 노출**, 1건 수정 |
| **라벨 키잉 결정** (이름 vs OID) | ✅ `results/label-keying.md` — OID 채택, **RENAME 3종 차단, 대가 0** |
| **커버리지 감사** (DETACH·사본 감지) | ✅ `results/coverage.md` — 정탐 **3/3**, 오탐 **0**, 코퍼스에서 진짜 누락 4건 발견 |
| **적대적 시험 5R** (권한·롤) | ✅ `results/adversarial5.md` — ★**GUC 가 USERSET 이라 `SET` 한 줄로 꺼졌다**, SUSET 전환 |
| **독립 구현 교차검증** (PostgreSQL Anonymizer) | ✅ `results/crosscheck-anon.md` — ★**의미 발산이 하드닝 후에도 재현**, 우리 버그가 아님 |
| **★ 삼자택이 형식화 + 실측** (`mask_position`) | ✅ `results/trilemma.md` — 표A(수락분) V1 9/9·4/9·9/9 · **V2 6/9·6/6·4/6** · V3 9/9·9/9·5/9 |
| **★ 명세 동결** (`release-factorization gate`) | ✅ `docs/spec-lineage-and-masks.md` **v0.2.1 동결** — 관찰모델·effect→sink·`Release`/`δ_Q`·factor-through·`F_core` |
| **★ Totality 분모 동결** (`ipguard_fragment`) | ✅ `results/fragment.md` — Query 트리 판정. 삼자택이 **10/10**, 발산 **37/45**, TPC-H **13/22** |
| **★ 마스크 능력 레지스트리** (3종 + 지문) | ✅ `results/registry.md` — **46/46**. `CREATE OR REPLACE` 가 OID 를 유지해도 지문이 잡는다, 철회가 **cross-backend** 로 generic plan 까지 전파, 잘못 등록된 인증서가 `null_equivalence` 의무를 우회 못 함 |
| **마스킹 집행** (소스 컬럼, `planner_hook`) | ✅ `results/enforcement.md` — **92%**, 과마스킹 0 |
| **정합성 변경 측정** | ✅ `results/semantics.md` — ★ 조용한 오답 위험 규명 |
| **정합성 fail-closed** (감지 후 거부) | ✅ 조용한 오답 5/5 거부, 퇴행 0 |
| **거부율 (독립 워크로드)** | ✅ `results/tpch-refusal.md` — TPC-H **0/22** (판정식 켜면 **5/22**) |
| **마스킹 뷰 대비 델타** | ✅ `results/view-baseline.md` — 필터 **3/4 vs 0/4**, 우회 **3/3 vs 0/3** |
| **SQL 단위 적용 조회** (`ipguard_verdict` / `ipguard_explain`) | ✅ `results/perquery.txt` — **159건**(TPC-H 포함), 예측↔집행 불일치 **0** |
| **정합성 발산 분류 + 판정식** | ✅ `results/divergence.md` — 조용한 오답 **전부 거부**, 대가는 TPC-H **23% 거부** |
| **마스크 센티널 결정** (숫자 `0`→`NULL`) | ✅ `results/divergence.md` — 알아볼 수 없는 출력 **3→1**, 과거부 변화 **없음** |
| **★ release-factorization gate** (effect hyperedge → sink) | ✅ `results/gate.md` — **118/118**. `Q10`·`Q6'` 수락 / `Q9`·`Q6` 거부, `F_core` 밖·미모델링 노드 **fail-closed**, `(effect,sink)` 쌍 단위 declassification, 철회·모드전환→재계획→**거부** |
| **⚠ legacy R1~R3 는 v0.2.1 기준 불건전** | 🟥 R3b 가 lineage 가 아니라 **masked-ness** 를 본다 → `ORDER BY secret` 이 `resjunk` 면 통과. `Q6`/`Q9` 누출 실측 (명세 §8). `ipguard.gate = release` 가 이것을 고친다 |
| 새 게이트 ↔ legacy 게이트 나란히 재측정 | ⬜ **다음 작업** — 명세 §11-5. acceptance 병기, `F_core`/`F_impl` 분모 병기 |
| 정리 1·2 구조적 귀납 증명 | ⬜ `F_core`(명세 §12) 위에서 |
| 성능 측정 | ⬜ 공유 서버라 이 호스트에서 불가 |
| 유저스페이스 KMS 검증 데몬 | ⬜ |
| WAS측 eBPF 에이전트 | ⬜ Linux 호스트 확보 후 |
| pgJDBC 바이트코드 에이전트 | ⬜ |

### ⚠ 설치 시 반드시 할 것

```sql
-- 0) 집행은 **롤/전역 기본값**으로 켠다. 앱이 세션에서 켜는 것이 아니다.
--    (GUC 는 전부 PGC_SUSET 이라 앱 사용자는 SET 할 수 없다 -- 5R Z01)
ALTER ROLE app_role SET ipguard.enforce = on;
GRANT SELECT ON h5.pii_label TO app_role;   -- load_labels 가 읽어야 한다

-- 1) 라벨 변경을 계획 캐시에 전파 (없으면 커넥션 풀에서 몇 시간씩 평문이 나간다)
SELECT ipguard_watch_labels('h5.pii_label');

-- 1b) 레지스트리 변경도 같은 이유로 전파해야 한다. 인증서를 철회해도
--     캐시된 generic plan 은 철회 전 판정으로 계속 돈다.
SELECT ipguard_watch_registry();

-- 2) 라벨을 OID 로 키잉 (권장). ALTER TABLE RENAME 류에 면역이 된다
SELECT ipguard_migrate_labels_to_oid('h5', 'h5oid');
SET ipguard.label_schema = 'h5oid';
SET ipguard.label_key    = oid;

-- 3) 복원 직후·정기 점검 (빈 결과가 정상)
SELECT * FROM ipguard_verify_labels('h5oid');
```

`load_labels` 는 **계획 시점에** 돈다. 이 트리거를 걸지 않으면 계획이 캐시된
뒤 라벨을 붙여도 그 세션에는 효력이 없다 — 커넥션 풀에서 몇 시간씩 평문이
나가고 **에러도 경고도 없다**(4R Y07). 트리거가 relcache 무효화를 방송해
각 백엔드의 계획 캐시를 비운다.

기본값(`label_key = name`)에서는 **라벨이 이름에 매달려 있다.**
`ALTER TABLE ... RENAME` / `RENAME COLUMN` / `SET SCHEMA` 가 전부 라벨을
조용히 날린다(4R Y01~Y03) — 마이그레이션 스크립트가 보안 컨트롤을 끈다.
`label_key = oid` 로 바꾸면 셋 다 막힌다. **측정 가능한 대가는 0이었다**
(전 축 재측정, 변동 없음 — `results/label-keying.md`).

파티션 `DETACH`(Y04)와 FDW 외부 테이블(Y08)은 **어떤 키잉으로도 안 고쳐진다.**
이름 문제가 아니라 구조 문제다. 대신 **커버리지 감사로 감지한다** — 감사가
찾은 것을 사람이 라벨링하면 집행된다(사본도 외부 테이블도 라벨링 가능하다는
것을 확인했다. `results/coverage.md`).

```sql
SELECT * FROM ipguard_coverage();       -- 라벨 없는 PII 후보 (싸다, 자주)
SELECT * FROM ipguard_coverage_deep();  -- 값 겹침 기반 (비싸다, 야간 배치)
SELECT * FROM ipguard_audit_definers(); -- SECURITY DEFINER 백도어 (5R Z04)
```

### 차단 요인 (해소됨 / 남은 것)

**해소:** PostgreSQL은 홈 디렉터리 소스 빌드로 확보했다(sudo 불필요).
`tools/build-pg.sh` 참조. 단 **PG 16 고정** — 17부터 `distprep` 제거로
tarball에 생성된 파서가 없어 bison/flex가 필수인데 이 호스트엔 둘 다 없고
m4조차 없다.

**남은 차단:** eBPF와 성능 측정.
`unprivileged_bpf_disabled=2` + sudo 없음 → BPF 로드 불가.
`perf_event_paranoid=4` → `perf` 실행 불가.
그리고 **공유 서버**(홈 10개, 상시 세션 6개, loadavg 2.2)라 H1/H3 성능 숫자는
여기서 측정할 수 없다. **H5(정확성) 트랙만 이 호스트에서 완결 가능하다.**

<details><summary>(구) 환경 조사 기록</summary>

**빌드/측정 환경이 아직 없다.** 개발 머신은 macOS / arm64라 eBPF를 실행할 수
없고 컨테이너 런타임도 설치되어 있지 않다. 타겟은 **`db.example.internal`
(port 6689, user `rinomaru`)** 이나 OS·커널·PostgreSQL·권한을 아직 조사하지
못했다 — SSH가 키가 아닌 비밀번호 인증이라 자동 접속이 불가능하다.
`tools/survey-host.sh`를 직접 실행해 결과를 아래에 채울 것.

```bash
ssh db.example.internal 'bash -s' < tools/survey-host.sh
```

키 인증 등록 완료 — 서버 작업이 자동화되어 있다.
</details>

### 조사 결과 (2026-08-08, `tools/survey-host.sh`)

Ubuntu 24.04.4 / **커널 6.17.0-35** / AMD Ryzen 9 3950X 16C32T / 62GB /
베어메탈(`가상화: none`) / clocksource=tsc / `/home` 5.3TB 여유.
BTF 있음, bpffs 마운트됨, lockdown `[none]`, **`unprivileged_bpf_disabled=2`**,
**`perf_event_paranoid=4`**, **sudo 없음**, PostgreSQL 미설치,
docker 바이너리는 있으나 `docker` 그룹 아님.

> 커널이 6.17이라는 점은 설계 논의 중 가정했던 5.x와 다르다. nop5 최적화
> uprobe(6.13+)와 `uprobes_treelock`의 RCU 전환(6.12+)이 이미 들어 있어
> uprobe 비용 추정이 낙관적으로 바뀐다. 다만 C 확장 채택 결정은 성능이
> 아니라 메모리 안전성·권한·카탈로그 접근에서 났으므로 뒤집히지 않는다.

---

## 지금 바로 되는 것

```bash
python3 tools/token.py selftest    # 토큰 포맷 레퍼런스 구현 검증
python3 tools/token.py vectors     # 두 구현이 맞춰야 할 정본 벡터

# 서버에서 (PG 16.10 기동 상태)
ssh db.example.internal 'cd ~ && export PATH=$HOME/pg/bin:$PATH \
  PGHOST=$HOME/.pgsock PGPORT=55432 PGDATABASE=ipdev && \
  python3 score_wire.py h5-corpus.json --probe ./probe_provenance'
```

## 코퍼스가 이미 말해주는 것

**측정 완료 (2026-08-08).** 추정이 아니라 실측이다 — 상세는
[`results/wire-baseline.md`](results/wire-baseline.md).

72항목 중 PII를 노출하는 것이 55항목. **와이어 훅이 완전히 잡은 것은 21항목(38%),
오탐은 0.** 나머지 **34항목이 C 확장 AST 순회가 회수해야 할 대상**이다.

미탐 33건이 세 카테고리에 88% 집중된다: **표현식래핑 18 / 함수·whole-row 7 /
COPY 4.** AST 순회의 가치는 이 세 곳에서 결정된다.

설계 시점 추정치는 29%였고 실측은 38%였다. 그리고 **소스만 읽고 단 라벨 6건이
실측에서 뒤집혔다** — 특히 CTE는 provenance를 유지한다.

### C 확장 회수율 (2026-08-08) — [`results/ast-recovery.md`](results/ast-recovery.md)

| | 와이어 | **AST(`ipguard`)** |
|---|---:|---:|
| 55개 PII 노출 항목 중 탐지 | 21 (38%) | **52 (95%)** |
| 퇴행 | — | **0** |
| 오탐 | 0 | **0** |

표현식래핑 3/21 → **21/21**, COPY 0/4 → **4/4**, 뷰·CTE·집합연산 4/8 → **8/8**.

남은 미탐 3건(F01/F02/F03)은 **원인이 하나다: 함수 본문은 호출부 계획에 없다.**
계획 트리를 아무리 정교하게 걸어도 회수 불가능하며, 대응은 탐지가 아니라
정책(함수 생성 권한 제한 / 지문 allow-list)이어야 한다.

### 적대적 시험 (2026-08-08) — [`results/adversarial.md`](results/adversarial.md)

95%는 내가 공격 집합과 방어를 둘 다 설계해 나온 숫자라, 코퍼스 밖 7개 표면을
31개 공격으로 먼저 스스로 쳤다. **우회 8건이 나왔고 6건을 고쳤다.**

가장 큰 것: **DML `RETURNING` 카테고리 전멸.** `UPDATE ... RETURNING ssn`이
통째로 미탐이었다 — DML에서 `targetList`는 *쓰는 값*이고 클라이언트로 나가는
것은 `returningList`인데 둘을 혼동했다. **기본 코퍼스에 DML이 한 건도 없었다.**

그리고 **파티션·상속 자식을 직접 겨냥**하면 뚫렸다(라벨이 부모에만 있음).
핀테크 스키마는 거의 항상 파티셔닝돼 있으므로 실전에서 바로 뚫린다.

남은 2건(중첩 30·60단 bound 소진)은 **`bounded` 신호로 검출된다.**

**2라운드**는 라벨 자체를 쳤다(23공격). 결함 3건 더 발견 — 서브쿼리 전체 행
참조(`json_agg(t)`), `MERGE`의 `mergeActionList`, `CREATE TABLE AS`. 전부 수정.
탐지기 자원 공격(표현식 200단·targetList 500·UNION 100 arm)은 전부 방어.

그리고 **순회기로는 자동 전파가 불가능한 클래스**를 규명했다 — 구체화 뷰,
CTAS 사본, 생성 컬럼. PII가 라벨 없는 릴레이션으로 물질화되면 조회 시점에
카탈로그에 연결이 없다. **대신 복사되는 순간을 `write` 축이 잡는다.**

> **[정정]** 처음에는 이걸 "원리적으로 회수 불가"라고 적었는데 절반만 맞았다.
> 전파가 불가능한 것은 맞지만 **사본 자체에 라벨을 붙이면 마스킹된다**
> (구체화 뷰·CTAS·FDW 외부 테이블 전부 확인). 진짜로 없던 것은 집행 수단이
> 아니라 **"사본이 생겼다는 사실을 아는 수단"**이었고, 커버리지 감사로
> 메웠다 — [`results/coverage.md`](results/coverage.md).
> 파생 컬럼(`substr(ssn,1,6)` 등)은 여전히 열려 있다.

> **누적: 적대적 시험 5라운드가 결함 25건을 찾았고, 기본 코퍼스 72항목(95%
> 통과)은 그중 0건을 찾지 못했다.** 라운드마다 표적이 달랐다 — SQL 문장(1~3R),
> 카탈로그 DDL(4R), **권한과 롤(5R)**. 한 축만 파면 나머지는 안 보인다. 자기가 쓴 코퍼스로 자기 방어를 재는 것이 왜
> 숫자가 아니라 주장인지의 실증.

| 거부 신호 | 우회 차단 | 정상 쿼리 오탐 |
|---|---:|---:|
| `unresolved > 0` | 2 | **2** |
| **`bounded > 0`** | **2** | **0** |

RTE 종류로 인한 미해석(`unresolved`, 정상 쿼리에서 흔함)과 순회 bound
소진(`bounded`, 정상 쿼리에서 나올 이유 없음)을 **분리한 것이 fail-closed를
값싸게 만든다.** 마스킹 집행은 `bounded>0 → 거부`로 설계한다.

### 집행 (2026-08-08) — [`results/enforcement.md`](results/enforcement.md)

출력 바이트를 고쳐 쓰지 않는다. `planner_hook`에서 **계획 전에** PII `Var`를
`ipguard_mask(var, kind)` 호출로 치환한다. 그러면 그 Var를 쓰는 모든 표현식이
자동으로 마스킹된 값 위에서 계산된다 — **표현식 우회가 구조적으로 무력해진다.**

```
substr(ssn,1,6) -> "******"      concat(name,'/',ssn) -> "***/**************"
birth(date)     -> 1900-01-01    grade(비-PII)        -> 그대로
```

| | |
|---|---:|
| PII 노출 쿼리 86건 중 **실제로 마스킹됨** | **79 (92%)** |
| **과마스킹**(정상 쿼리 변형) | **0** |
| 누출 | 7 (물질화 5 + 플래너 인라인 SRF 2) |

**★ 집행이 탐지보다 넓다.** UDF 본문·동적 SQL·SECURITY DEFINER는 탐지로는
못 잡지만 **집행은 전부 막는다** — 함수 본문도 실행 시점에 각각 계획되므로
훅이 발화하기 때문. 두 지표를 따로 재지 않았으면 몰랐을 사실이고,
`ast-recovery.md`의 결론을 정정했다.

**반대 방향의 격차도 이 측정이 잡았다** — `row_to_json(c)`는 탐지 7종 전부인데
집행이 하나도 안 가렸다(전체 행 `Var` 미처리). "가렸다고 믿는데 안 가려진"
최악의 상태였고, 탐지율만 봤다면 보이지 않는다.

### 정합성 (2026-08-08) — [`results/semantics.md`](results/semantics.md)

집행률만 봐서는 안 보이는 위험이 있다. **누출은 데이터가 나가는 것이고,
정합성 변경은 조용한 오답이다** — 에러가 없어 운영에서 발견이 훨씬 어렵다.

| 분류 | 항목 | 변경 | |
|---|---:|---:|---|
| **none** (대조군) | 7 | **0** | 필터링 정상 ✅ |
| **scoped** (PII 미출력) | 6 | **0** | 마스킹 미발동 ✅ |
| **artifact** (설계 지점 탓) | 8 | **8** | ★ 실재 |
| **intrinsic** (마스킹 본질) | 6 | 5 | 불가피 |

```sql
SELECT t.id, t.ssn FROM (SELECT id, ssn FROM cust) t WHERE t.ssn = '800102-1000001';
--  off: 1행  →  on: 0행     (에러 없음)

SELECT count(*), max(a.ssn) FROM (SELECT id,ssn FROM cust LIMIT 50) a
  JOIN (SELECT id,ssn FROM cust LIMIT 50) b ON a.ssn = b.ssn;
--  off: 50행 →  on: 2500행  (50배 폭증)
```

조건은 **PII를 출력하면서 그 서브쿼리 출력을 바깥 술어·조인에 쓰는 것**.
폭증 방향이 더 위험하다 — 필터가 *완화*되어 신호조차 없다.

**대조군은 지켜졌다.** `WHERE ssn = '...'`는 off/on 모두 1행 — 술어의
base-relation `Var`를 마스킹하지 않는 설계가 유지되고 있다.

**구현 완료 — 감지 후 거부.** 변이 후 모든 술어(`WHERE`·`JOIN ON`·`HAVING`)를
훑어 마스킹된 서브쿼리/CTE 출력을 가리키는 `Var`가 있으면 계획을 거부한다.

```
ERROR:  ipguard: masking would change query results
DETAIL: Masked subquery/CTE output column "ssn" is referenced from a predicate
        or join condition. …silently dropping rows or turning the join into a
        cross product.
```

| 분류 | 항목 | 기대대로 | 위반 |
|---|---:|---:|---:|
| refuse (반드시 거부) | 5 | **5** | 0 |
| refuse_over (과잉 거부 비용) | 2 | 2 | 0 |
| intrinsic / scoped / none | 20 | 20 | **0** |

**조용한 오답 5건이 전부 명시적 에러가 됐고, 다른 스위트 102개 쿼리에서
새 거부는 0건이다** — 충돌 패턴이 좁다는 실측. `GROUP BY`/`DISTINCT`는
일부러 막지 않는다(마스킹의 정의상 불가피, 서브쿼리 없이도 동일).

GUC `ipguard.on_conflict = error|warn|allow` (기본 `error`).

### 거부율 — 독립 표준 워크로드 [`results/tpch-refusal.md`](results/tpch-refusal.md)

지금까지의 코퍼스는 전부 내가 썼으므로 거부율이 낮아도 근거가 못 된다.
**TPC-H 22개 쿼리**(표준화 기구 작성, 서브쿼리 밀집 = 최악 조건)로 쟀다.

| 라벨 조건 | 마스킹 발동 | **거부** |
|---|---:|---:|
| 현실적 PII 라벨(8컬럼) | 7/22 | **0 (0%)** |
| 전 컬럼 PII(61컬럼, 구조적 상한) | 22/22 | **1 (5%)** |

**왜 0인가:** 전 컬럼을 PII로 해도 거부는 Q15 하나다 — 패턴의 **구조적
빈도 자체가 낮고**(22개 중 1개), 현실적 라벨에서는 그마저도 0이 된다.
Q15가 술어에서 참조하는 건 매출 집계이지 성명·주소가 아니다.

> **PII 컬럼은 출력하고 그룹핑하지, 필터하지 않는다.** 필터는 키·날짜에
> 걸고 성명·주소는 화면에 뿌린다. 데이터 모델링의 일반적 성질이라
> 이 패턴이 드물다.

**양성 대조군으로 0%가 감지기 고장이 아님을 확인했다** — TPC-H 스키마에서
의도적 충돌 쿼리 2건은 정확히 거부된다.

### 마스킹 뷰 대비 델타 — [`results/view-baseline.md`](results/view-baseline.md)

*"그냥 마스킹 뷰 만들면 되잖아요?"* 에 대한 답. 같은 코퍼스, **같은 마스크 함수**.

**대조군은 라벨 테이블에서 자동 생성한다** — 손으로 `cust` 뷰 하나만 만들어
두면 나머지 테이블을 쓰는 쿼리가 전부 "뷰 우회"로 집계돼 대조군을 부당하게
나쁘게 만든다. ipguard 도 같은 라벨을 자동으로 읽으므로 출처를 맞췄다.
h5 의 **뷰**에 대한 그림자는 어느 출력 컬럼이 PII 인지를 ipguard 분석으로
판별해 만든다 — 즉 대조군에게 **혼자서는 못 얻을 정보**를 쥐여 준다.
유리하게 깔아주고도 남는 차이가 진짜 차이다.

| 축 | 마스킹 뷰 | ipguard |
|---|---|---|
| 마스킹 커버리지 | **71/87** | 70/87 (+거부 2) — **뷰가 근소 우위** |
| **필터링 보존** | **3/4 파손** | **0/4** |
| **우회 저항** | **3/3 우회됨** | **0/3** |

```
WHERE ci = <연계정보>   원본 10000행  →  뷰 0행(!)  →  ipguard 10000행
```

**마스킹만 놓고 보면 뷰로 충분합니다** 가 정직한 답이다. 차이는 **필터가
살아남는가**와 **우회되는가**에 있다. 뷰는 컬럼 자체가 마스킹된 값이라
술어도 마스크를 보고, 우회는 `REVOKE`로만 막히는데 그 회수가 곧 도입 비용이다.

> 다만 **둘 다 커넥션 풀에서 최종 사용자별 정책은 못 한다.** 그게 유일한
> 미해결 차별점이자 다음 단계다.

### SQL 단위 적용 조회 — [`results/perquery.txt`](results/perquery.txt)

위 지표들은 전부 **코퍼스 집계**다. "우리 서비스의 이 쿼리는 어떻게 되느냐"에
답하려면 쿼리 단위로 볼 수 있어야 한다. 확장에 두 함수를 넣었다 —
**임의의 SQL 에 대해, 실행하지 않고** 판정한다.

```sql
SELECT * FROM ipguard_explain(
  'SELECT c.name, c.ssn, t.amount FROM cust c JOIN tx t ON t.cust_id=c.id WHERE c.ci = $1');
```
```
 relname | attname | label |   path    | action
---------+---------+-------+-----------+-----------------------------------------
 cust    | name    | name  | output    | masked — ipguard_mask() 로 치환
 cust    | ssn     | ssn   | output    | masked — ipguard_mask() 로 치환
 cust    | ci      | ci    | predicate | kept — 술어는 건드리지 않음 (필터 보존)
```

`ipguard_verdict(sql)` 은 같은 판정을 한 줄로 준다:
`mask` / `refuse` / `pass` / `utility` / `mismatch` / `error`.
`planner_hook` 과 **같은 코드·같은 순서**(분석 → bound → 마스킹 → 충돌)를
타므로 판정과 실제 집행이 갈라질 수 없다.

리포트는 축을 **두 개** 둔다. 하나만 두면 도구가 자기를 채점한다:

| 축 | 질문 | 결과 (159건) |
|---|---|---|
| ① 자기일관성 | 예측 == 실제 집행? | 불일치 **0**, 확인필요 2, 보류 22 |
| ② 보안 | 실제 집행 == 코퍼스 정답? | OK 122, **누출 1**, 범위밖 6, 과마스킹 **0**, **왜곡 6** |
| ③ 뷰 대조군 | 같은 SQL 을 마스킹 뷰로 돌리면? | PII 출력 85건 중 **broken 64**, masked 21 |

③ 이 이 표의 값어치다. 같은 쿼리에 대해 **뷰는 64건을 깨뜨리고 ipguard 는
0건을 깨뜨린다.** 다이제스트에 **행 수를 넣은 것이 관건**이었다 — 값 해시만
비교하면 "가려졌다"와 "쿼리가 깨졌다"가 둘 다 `changed` 로 뭉개진다.

```
SELECT ssn FROM cust WHERE ci = $1     원본 10000행  →  뷰 0행  →  ipguard 10000행
```

**두 축을 분리한 것이 요점이다.** 처음엔 ①만 봤는데, 라벨 없는 사본
(`SELECT ssn FROM mv_cust`)이 "예측 pass = 실측 unchanged"라 **✓ 로 찍혔다.**
도구는 자기 자신과 일관됐지만 `ssn` 은 평문으로 나갔다. ② 를 붙이자
그 6건이 `GAP` 으로 분리됐다.

이 표가 새로 드러낸 것 두 가지:

- **집행이 정적 판정보다 넓다.** `SELECT f_ssn(id) FROM cust` 는 정적으로는
  `pass` 인데 실측은 마스킹된다 — SQL 함수 **본문이 자기 계획 경로에서**
  `planner_hook` 을 타기 때문이다 (`f_ssn(1)` → `**************`).
- **`utility` 를 따로 세야 한다.** `COPY tbl TO STDOUT` 은 최상위가
  `planner_hook` 경로가 아니다. "적용됨"으로 뭉뚱그리면 거짓 안심이 된다.

**TPC-H 22개는 측정 방식이 다르다.** `tpch` 스키마는 **행이 0**이라 결과
다이제스트를 비교하면 22개 전부 `EMPTY` 로 같아진다 — 마스킹이 발동한 쿼리까지
"손대지 않음"으로 찍혔을 것이다. 그래서 이 코퍼스만
`EXPLAIN (COSTS OFF, VERBOSE)` 의 Output 절에 `ipguard_mask` 가 실제로
주입됐는지로 잰다(데이터 불필요). 결과는 **22/22 일치, 거부 0, 마스킹 발동 7건**
(Q2·Q10·Q15·Q18·Q20·Q21·Q22) — 독립 경로인 `score_tpch.py` 와 같은 집합이다.

```bash
# 전체
python3 tools/report_perquery.py corpus/*.json corpus/tpch-queries.sql
# 임의 쿼리 한 건
python3 tools/report_perquery.py --sql "SELECT ssn FROM cust WHERE id = 1"
```

## 코퍼스 사용 규칙

- 탐지기는 `pii_label` 테이블만 근거로 삼는다. **컬럼명 문자열 패턴
  (`'ssn' in name`)을 쓰면 이 코퍼스는 무의미해진다.** 채점 스크립트는
  컬럼명을 난독화한 변형 스키마로 재실행해 이를 검사한다.
- FN(미탐)과 FP(오탐)를 따로, **카테고리별로 분해해서** 보고한다.
  총계 하나로 뭉뚱그리지 않는다.
- `D07`/`D08`/`B02`는 음성 대조군이다. 여기서 마스킹이 일어나면 FP —
  특히 `D08`은 non-PII 자유텍스트 안에 주민번호 형태 문자열을 심어두었다.
  바이트 패턴 매칭 방식이면 여기서 터진다.

## 아직 답이 없는 정책 질문 (코퍼스에 항목으로 박아둠)

- `P03` — 결속할 CI 파라미터가 없는 쿼리(`WHERE id = $1`)를 어떻게 하는가.
  전면 거부하면 정상 업무가 깨지고, 통과시키면 IDOR가 열린다.
- `X04` — `SAVEPOINT <가변이름>`은 리터럴 완전 일치 화이트리스트가 성립하지
  않는다. 예외 규칙을 어떻게 쓸 것인가.
- `E17`/`E18` — `length(ssn)` 같은 파생 메타데이터. **AST 측정으로 쟁점이
  선명해졌다**: 소스 컬럼을 마스킹하면(표현식 평가 *전*) `length(마스크값)`이
  되어 정상 동작이고, 출력 바이트만 마스킹하면 정수를 가릴 수 없다.
  즉 이건 라벨 문제가 아니라 **집행 지점 결정**이다. `derived_only`로 분리 집계 중.
- `E20`/`E21`/`F08` — `string_agg`/`json_agg`는 다수 행의 PII를 한 셀에
  모은다. **행 수 상한 정책의 우회 경로**다.

## 알려진 설계 제약

- **`prepareThreshold=0` 필수.** 토큰이 SQL 텍스트 안에 있어 매 실행마다
  문자열이 달라지므로, 그대로 두면 서버측 prepared statement가 무한 누적된다.
  대가(서버측 prepare 재사용 상실)는 H1에서 반드시 측정·보고한다.
  자세한 내용은 `docs/token-format.md` §4.
- 정규화 금지. 양쪽이 동일 옥텟을 해시하지 않으면 전량 거부 장애가 난다.
- HMAC 키는 커널에 두지 않는다(BPF 맵은 `CAP_BPF`로 덤프 가능).

## 문서 작성 규칙

미측정 최상급·절대량화 표현 금지: `가장`, `완벽`, `100%`, `무결점`,
`원천 차단`, `절대`. 이 프로젝트는 같은 오류를 네 번 반복했다.
숫자를 쓰려면 먼저 재고, 재기 전에는 반증 가능한 가설로만 쓴다.
