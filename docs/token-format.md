# 토큰 와이어 포맷 v1 (`t1`)

이 문서는 WAS 호스트 에이전트(Java)와 DB 호스트 집행점(PostgreSQL C 확장)이
**바이트 단위로 합의해야 하는 유일한 계약**이다.

두 독립 구현이 공백·인코딩·바이트 순서·패딩 중 하나라도 다르게 처리하면,
그 결과는 보안 사고가 아니라 **장애**다 — 정상 쿼리가 전부 거부된다.
그래서 산문 명세를 신뢰하지 않는다: **`tools/token.py`가 정본(normative)이며**,
두 구현 모두 아래 테스트 벡터를 재현해야 한다.

```bash
python3 tools/token.py selftest   # 구현 검증
python3 tools/token.py vectors    # 정본 벡터 출력
```

---

## 1. 엔벨로프 — 고정 길이, 오프셋 추출

```
/*@t1:<base64url payload, 150 chars>*/<query bytes>
└─ 6 ─┘└──────────── 150 ────────────┘└2┘
└──────────────── 158 bytes ─────────────┘
```

**추출 규칙 (정규식 금지):**

1. `len(query) < 158` → **거부**
2. `query[0:6] != "/*@t1:"` → **거부**
3. `query[156:158] != "*/"` → **거부**
4. payload = `b64url_decode(query[6:156])`, 길이 112가 아니면 **거부**
5. 서명 대상 SQL = `query[158:]` — **정확히 이 바이트열**

정규식을 쓰지 않는 이유: 주석 안에 `*/`가 들어가거나 쿼리 본문에 `/*@t1:`이
나타나는 순간 스캔 기반 파서는 위치를 잘못 잡는다. 고정 오프셋은 그 클래스의
버그가 존재할 수 없다.

## 2. 페이로드 레이아웃 (112바이트, 빅엔디언)

| off | len | 필드 | 설명 |
|----:|----:|---|---|
| 0 | 1 | `ver` | `0x01` 고정 |
| 1 | 1 | `kid` | 키 ID. 회전 시 중첩 윈도우용 |
| 2 | 2 | `flags` | bit0 = `POSTURE_OK`. 나머지 예약(0) |
| 4 | 8 | `iat_ms` | 발급 시각, unix epoch ms |
| 12 | 4 | `ttl_ms` | 유효 기간 |
| 16 | 32 | `ci_sha256` | `SHA-256(CI utf-8)` |
| 48 | 32 | `sql_sha256` | `SHA-256(query[158:])` |
| 80 | 32 | `mac` | `HMAC-SHA256(key[kid], payload[0:80])` |

### CI를 평문으로 싣지 않는 이유

토큰은 **SQL 텍스트 안에** 들어간다. SQL 텍스트는 `pg_stat_statements`와
`log_statement` / `log_min_duration_statement` 출력에 그대로 남는다.
연계정보를 평문으로 실으면 **PII 유출을 막으려는 시스템이 새로운 PII 싱크를
만드는** 꼴이 된다. 해시만 실어도 파라미터-신원 결속에는 충분하다 —
DB측은 관측한 `$1`의 `SHA-256`을 이 필드와 비교한다.

### 정규화(normalization)를 하지 않는 이유

`sql_sha256`은 **정규화하지 않은 원본 바이트**에 대한 해시다. 공백 축약도,
대소문자 접기도, 리터럴→플레이스홀더 치환도 하지 않는다.
정규화를 넣으면 서로 다른 두 언어의 두 구현이 동일하게 정규화해야 하는데,
그 divergence는 탐지되지 않고 조용히 전량 거부로 나타난다.

WAS측이 해시해야 하는 바이트는 애플리케이션이 쓴 SQL 문자열이 **아니다**.
pgJDBC가 `Parser.parseJdbcSql()`에서 `?` → `$1`, JDBC escape(`{fn now()}`,
`{d '...'}`), `reWriteBatchedInserts` 병합을 끝낸 **`NativeQuery.nativeSql`**이다.
계측 지점: `org.postgresql.core.v3.QueryExecutorImpl#sendParse`.

## 3. 검증 순서 (전부 fail-closed)

```
magic/close/길이 → b64 디코드 → ver → kid 조회 → MAC(상수시간 비교)
→ iat 미래 여부(1s 스큐 허용) → 만료 → sql_sha256 대조
```

- MAC 비교는 **상수시간**이어야 한다. 바이트별 조기 종료 비교는 타이밍 오라클이다.
- 어떤 단계든 실패하면 **거부**한다. "검증됨"과 "검증할 수 없었음"을 구분하지
  못하는 반환값은 두지 않는다 — 그 구분이 흐려지면 결국 fail-open된다.

## 4. ⚠️ 미해결 설계 결함: prepared statement와 토큰의 충돌

**이 절을 읽지 않고 구현하지 말 것.**

토큰이 SQL 텍스트 안에 있고 토큰은 실행마다 달라야 한다(신원·시각이 다름).
그런데 pgJDBC는 **SQL 문자열을 키로 prepared statement를 캐시**한다. 결과:

1. 문자열이 매번 달라지므로 **클라이언트 캐시가 절대 히트하지 않는다**.
2. 따라서 매 실행이 새 `Parse`를 보낸다 — 이건 오히려 좋다. DB측이 항상
   전체 텍스트와 토큰을 본다. **prepared statement 지문 상태 기계가 불필요해진다.**
3. 그러나 `prepareThreshold`(기본 5)를 넘기면 pgJDBC가 **명명된 statement
   `S_n`을 서버에 만들고**, 매번 새 문자열이므로 `S_n`이 무한히 누적된다 →
   장수 풀 커넥션에서 **서버측 prepared statement 누수**.

**따라서 v1은 `prepareThreshold=0`을 요구한다** (선택이 아니라 필수).
그러면 명명 statement가 아예 만들어지지 않는다.

**대가 — 정직하게 측정해야 한다:** 서버측 prepare 재사용이 사라지므로
매 실행이 parse + plan을 다시 한다. 이것은 실제 비용이고 **H1의 일부로
반드시 측정·보고해야 한다.** ("토큰을 넣었더니 prepared statement를 못 쓰게
됐고 그 비용이 X µs였다"는 문장이 논문에 있어야 한다.)

**v2 후보:** 토큰을 주석이 아니라 **추가 Bind 파라미터**로 옮기면 SQL 텍스트가
안정되어 prepared statement를 유지할 수 있다. 대신 `Parse`의 파라미터 타입
선언까지 에이전트가 일관되게 재작성해야 한다. v1에서 측정한 prepare 손실
비용이 크면 v2로 간다. **비용을 재기 전에 v2로 가지 말 것.**

## 5. C 확장 피벗이 없애준 것 (와이어 훅 대비)

DB측이 C 확장이면 `ExecutorStart_hook`의 `QueryDesc->sourceText`로 **모든
실행에서** 원본 쿼리 문자열을 볼 수 있다(extended protocol의 6회차 이후에도,
`CachedPlanSource->query_string`이 유지되므로). 따라서:

- 커넥션별 `statement_name → fingerprint` 맵 **불필요**
- unnamed statement 슬롯 파괴, `DEALLOCATE`, PgBouncer의 `PGBOUNCER_{id}`
  이름 재작성, 맵 eviction 같은 실패 모드 **전부 소멸**

와이어 훅 시절 설계했던 상태 기계는 **폐기**한다. 단 §4의 제약은 남는다.

## 6. 키 관리

- 키는 **커널에 두지 않는다.** BPF 맵에는 write-only 모드가 없어 `CAP_BPF`만
  있으면 `bpftool map dump`로 평문 추출된다.
- 유저스페이스 검증 데몬이 보유(mlock, 가능하면 KMS/keyring/HSM).
- 회전은 in-place 갱신 금지(torn read). **`kid` 인덱스 맵 + 중첩 윈도우**로.
- `kid`는 1바이트 = 256개. 회전 주기를 정할 때 wrap-around를 고려할 것.

## 7. nonce가 없는 이유

read 경로에서 토큰은 이미 `sql_sha256`으로 특정 쿼리에 결속되고 짧은 `ttl_ms`를
가진다. 동일 토큰 + 동일 쿼리의 재생은 **이미 인가된 읽기의 재실행**일 뿐이다.
반면 nonce 추적 맵은 크고, 고갈시키기 쉬우며(= 자체 DoS 표면), 만료 관리가
필요하다. **쓰기 경로를 스코프에 넣을 때 재검토한다.**

---

## 8. 정본 테스트 벡터

두 구현 모두 아래를 정확히 재현해야 한다.

```
key      = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
kid      = 7
flags    = 0x0001 (POSTURE_OK)
iat_ms   = 1767225600000        (2026-01-01T00:00:00Z)
ttl_ms   = 5000
CI       = "AAAA...A" (문자 'A' 88개)
SQL      = SELECT name, ssn FROM cust WHERE ci = $1
```

기대 결과:

```
ci_sha256   ca97d312ef8551820844548f300f9528f27d53f6ad3910ed2709f2b35c9591f3
sql_sha256  fc0e7e9b2575d82db934d8048f3a190d4cd3439aff711c9d86178163fee70735
mac         638d61a25540b6744fd781580b59b39b8cec7c6312799242d81ce404fef68f20
prefix_len  158
wire_len    198
```

전체 와이어 이미지:

```
/*@t1:AQcAAQAAAZt22qgAAAATiMqX0xLvhVGCCERUjzAPlSjyfVP2rTkQ7ScJ8rNclZHz_A5-myV12C25NNgEjzoZDUzTQ5r_cRydhheBY_7nBzVjjWGiVUC2dE_XgVgLWbObjOx8YxJ5kkLYHOQE_vaPIA*/SELECT name, ssn FROM cust WHERE ci = $1
```

거부되어야 하는 케이스(각각 테스트 있음):
magic 변조 · payload 변조 · **SQL 뒤 공백 1개 추가** · 토큰 없음 ·
만료(`iat + ttl` 초과) · 미등록 `kid`.

세 번째 케이스가 핵심이다 — 공백 하나만 달라도 거부된다. 이것이 §2의
"정규화하지 않는다"가 실제로 의미하는 바이며, 두 구현이 갈라지면 어떻게
드러나는지를 보여준다.
