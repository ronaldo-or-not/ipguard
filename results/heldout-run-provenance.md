# held-out 평가 실행 provenance — attempt 1

이 문서는 §11-5 held-out 최초 관측을 **누가·어떤 bytes로·어떤 환경에서** 냈는지
고정한다. 결과 해석 문서(`results/heldout.md`)와 분리되어 있으며, 결과를
보기 전에 먼저 커밋되었다.

## 1. runner 동일성

| 항목 | 값 |
|---|---|
| `EVAL_RUNNER_ATTEMPT_1_DIGEST` | `31d46a73964504ba766f979106e93cf2673b7048c84e08fff0937bbad2d72a70` |
| 파일 | `tools/run_heldout.py` |
| 크기 | 20,721 bytes |
| local ↔ server | sha256 **일치** (rsync 후 재확인) |

`EVAL_RUNNER_ATTEMPT_1_COMMIT`은 이 문서와 함께 커밋된 `tools/run_heldout.py`의
커밋이다. 위 digest가 그 커밋 시점 blob의 bytes와 같아야 한다.

## 2. 실행 명령

```
export PATH=$HOME/pg/bin:$PATH PGHOST=$HOME/.pgsock PGPORT=55432
cd ~/ho
timeout 3000 python3 tools/run_heldout.py corpus/heldout.json out/
```

## 3. 실행 시각 (서버 로컬 시각, KST/+0900)

| 이벤트 | 시각 | 근거 |
|---|---|---|
| runner 배치 (실행 직전) | 2026-08-10 13:31:53.218 | `tools/run_heldout.py` mtime |
| `out/` 생성 | 2026-08-10 13:31:39.979 | 디렉터리 mtime |
| [2] applicability 저장 | 2026-08-10 13:32:04.467 | `out/applicability.json` |
| [5-6] P1 인증서 저장 | 2026-08-10 13:32:12.901 | `out/p1-certificates.json` |
| [7] δ matrix 저장 | 2026-08-10 13:37:23.399 | `out/delta.json` |
| [9-10] raw trial·감사 표본 | 2026-08-10 13:37:59.704 / .709 | `out/raw-trials.jsonl`, `out/audit-sample.json` |
| **총 소요** | **약 6분 06초** | 13:31:53 → 13:37:59 |

**종료 사유: 정상 종료 (exit 0).** `timeout 3000`에 도달하지 않았다.
따라서 attempt 1은 `infrastructure-aborted attempt`가 아니며, 적재 스케줄
최적화는 수행되지 않았다. attempt 2는 존재하지 않는다.

## 4. 환경

| 항목 | 값 |
|---|---|
| host | `CAU-CPSS-Server` (`db.example.internal`), 계정 `rinomaru` |
| kernel | Linux 6.17.0-35-generic x86_64 |
| Python | 3.12.3 |
| psql / postgres | PostgreSQL 16.10 (`$HOME/pg`, 소스 빌드) |
| DB | `ipdev` |
| `datcollate` / `datctype` | `C` / `C` |
| `server_encoding` | UTF8 |
| `plan_cache_mode` | `auto` (runner가 변경하지 않음) |
| `shared_preload_libraries` | 비어 있음 (`ipguard`는 `LOAD` 없이 함수 호출 시 적재) |
| 확장 | `ipguard 1.0` |
| `ipguard_build_id()` | `78dbd8a31626f039ebd83e41e0eb8b00b00660d1326349db3d23776e7bf6ce20` |

## 5. session / transaction 경계

runner가 명시적으로 건 것만 기록한다. 나머지는 PostgreSQL 기본값이다.

- 각 batch = `psql -d ipdev -At -f -` **1 세션**, 명시적 `BEGIN`/`COMMIT` 없음
  (문장별 암묵 트랜잭션).
- P0 prelude: `SET search_path=h5,public; SET ipguard.enforce=off;`
- P1 prelude: `SET search_path=h5,public; SET ipguard.enforce=on;`
  `SET ipguard.gate=release; SET ipguard.on_divergence=allow;`
- 기준(unenforced) 실행 prelude: `SET search_path=h5,public; SET ipguard.enforce=off;`
- registry는 [1]에서 초기 복원, [4]에서 P1 인증서 설치 전 **재복원**.
- `plan_cache_mode`는 어느 단계에서도 설정하지 않음 → 전 구간 `auto`.

## 6. 산출물 digest

runner가 stdout에 직접 찍은 논리 digest (JSON canonical, `sort_keys=True`):

| 대상 | digest |
|---|---|
| applicability matrix | `7fc01d112e775d2e` (앞 16자리) |
| P1 인증서 집합 | `386db4e1ac30514b` (앞 16자리) |
| δ matrix | `dde5b650d654e83c` (앞 16자리) |
| raw trial 3,200건 | `d18ca1aaccc2a574` (앞 16자리) |

파일 bytes digest (sha256 전체):

```
9cb7f315259883482c26d72aa82e6309e34c69c4a21e00bf424711f665baec59  out/applicability.json
580dd7e726ddbdae1565920c980e7478e6440f34bc4a3e5ce5c08e097fef7daf  out/audit-sample.json
ce0d8c9bb5f1fb7b8280b2068a7dc651753ac6528f87957c3f9f59e8f19ec51a  out/delta.json
f400198863245a7e1720e6f37cb0daad021c174623d5e925a06c2b6b3f64b3de  out/p1-certificates.json
d18ca1aaccc2a574582e924f6b3008bbbc6b49914a3b99c8bdf1e7d8456a6066  out/raw-trials.jsonl
```

`raw-trials.jsonl`의 파일 digest와 논리 digest가 같은 것은 우연이 아니다 —
논리 digest를 파일 bytes 위에서 계산했기 때문이다.

## 7. 평가 입력 provenance (재확인)

```
GATE_COMMIT       5e21c7d7cd089773cf7f4a9a629b61bd53067ac7
GENERATOR_COMMIT  9222ef3b4e7e13b685db5377486cb9eef8c7f236
POLICY_COMMIT     533502d297e12ede971b8c08cce8ce2f46446b0c
EVAL_BASE_COMMIT  533502d297e12ede971b8c08cce8ce2f46446b0c
EVAL_INPUT_COMMIT 68ed0020fc0bd8d8e9131ef91a69ec4d0af8eec7
seed              0xa3062488859d4a48
```

runner(`EVAL_RUNNER_ATTEMPT_1_*`)는 seed 파생에 **들어가지 않는다**. seed는
GATE·GENERATOR·POLICY 세 역할 커밋만으로 결정되며, runner를 바꿔도 코퍼스는
바뀌지 않는다. 이것이 runner 수정이 held-out을 오염시키지 않는 이유다.

## 8. 결과를 보기 전에 고정된 사실

- `M(D1) = M(D2)`: 4 pair 유형 × 2 테이블 = **8/8 성립**.
- trial 단위: 질의 400건 × pair 4유형 = pair trial 1,600건, 정책 2개 = **3,200건**.
- 감사 표본 17건은 **질의 ID 해시**로 선택했다 (결과값 미참조).
