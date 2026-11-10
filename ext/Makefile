MODULE_big = ipguard
OBJS = ipguard.o
EXTENSION = ipguard
DATA = ipguard--1.0.sql
PGFILEDESC = "ipguard - PII provenance analysis"

PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)

# ------------------------------------------------------------------
# provider build manifest
#
# C 함수는 CREATE OR REPLACE 없이도 바뀐다 -- `make install` 로 .so 를
# 덮어쓰면 pg_proc 은 한 글자도 안 변한다. prosrc/provolatile/extversion 중
# 어느 것도 그 변화를 잡지 못한다.
#
# ★ 그렇다고 소스 해시가 **바이너리 동일성**을 주는 것은 아니다. 같은 소스로
#   다른 바이너리가 나올 수 있다:
#     - 컴파일러 버전·최적화 플래그
#     - PostgreSQL 헤더 (서버 버전)
#     - 링크되는 라이브러리와 ABI
#     - 함께 컴파일되는 다른 소스·생성 코드
#     - 빌드 환경 일반
#
#   그래서 이것은 **provider-attested build identity** 이지 완전한 지문이
#   아니다. manifest 에 넣은 축만 변경이 잡힌다. 명세는 이 주장을
#   `BuildSound(provider_manifest)` 전제 아래에서만 쓴다.
#
#   더 강하게 하려면 최종 .so 자체를 식별하거나 재현 가능한 build manifest 를
#   써야 한다. 현재는 안 한다 -- 그 사실이 레지스트리에 남는다.
# ------------------------------------------------------------------
_ipg_dir := $(dir $(lastword $(MAKEFILE_LIST)))
# ★ 전체 SHA-256 을 쓴다. cksum(CRC-32)은 충돌이 현실적으로 가능해서
#   **보안 판정에 쓰면 안 된다.** 축약은 표시용으로만 둔다.
IPGUARD_MANIFEST := $(shell { \
      echo "src:"; cat $(_ipg_dir)ipguard.c $(_ipg_dir)ipguard--1.0.sql 2>/dev/null; \
      echo "pg:$$($(PG_CONFIG) --version)"; \
      echo "cc:$$($(shell $(PG_CONFIG) --cc) --version 2>/dev/null | head -1)"; \
      echo "cflags:$$($(PG_CONFIG) --cflags)"; \
      echo "cppflags:$$($(PG_CONFIG) --cppflags)"; \
      echo "ldflags:$$($(PG_CONFIG) --ldflags)"; \
    } | { sha256sum 2>/dev/null || shasum -a 256; } | cut -d' ' -f1)

# manifest 가 **덮은 축**을 그대로 적어 둔다. 여기 없는 것은 잡히지 않는다.
IPGUARD_MANIFEST_AXES := src,pg_version,cc_version,cflags,cppflags,ldflags

PG_CPPFLAGS += -DIPGUARD_BUILD_ID='"$(IPGUARD_MANIFEST)"'
PG_CPPFLAGS += -DIPGUARD_MANIFEST_AXES='"$(IPGUARD_MANIFEST_AXES)"'

include $(PGXS)
