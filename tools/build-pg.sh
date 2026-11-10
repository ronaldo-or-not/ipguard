#!/usr/bin/env bash
# 홈 디렉터리에 PostgreSQL을 소스 빌드하고 기동한다. sudo 불필요.
#
# 이 서버(db.example.internal)는 공유 서버이고 rinomaru에게 sudo가 없다.
# 따라서 시스템 패키지 설치도, 시스템 PostgreSQL 사용도 불가능하다.
# 대신 자기 홈에 자기 소유의 인스턴스를 세우면 shared_preload_libraries
# 등록과 재시작이 전부 자유롭다 -- C 확장 개발에 필요한 것은 그게 전부다.
#
# 빠진 빌드 의존성 처리:
#   - icu      : --without-icu (로케일 제공자가 libc로 떨어질 뿐)
#   - readline : --without-readline (psql 줄편집만 없어짐)
#   - bison/flex : ★ PG_VERSION 을 17 이상으로 올리지 말 것 ★
#       PostgreSQL 17에서 distprep 이 제거되어 릴리스 tarball에 생성된
#       gram.c / scan.c 가 더 이상 들어있지 않다. 실측 확인:
#           16.10 tarball -> gram.c, scan.c, gram.h 있음
#           17.10 tarball -> 없음  (configure: error: bison not found)
#       이 호스트에는 bison/flex 가 없고 sudo 도 없으며, 소스 부트스트랩에
#       필요한 m4 조차 없다(m4 -> flex -> bison 3단 체인이 된다).
#       17 이상이 필요해지면 그 체인을 먼저 세우거나 관리자에게 요청할 것.
#
# PG 16 선택의 대가(정직하게 기록): 이식성을 주장하려면 나중에 17/18에서도
# 확장을 빌드·테스트해야 한다. 특히 PG 18은 ExecutorStart 시그니처가 바뀐
# 것으로 보이므로 별도 확인이 필요하다.
#
# 사용: bash build-pg.sh              # 빌드 + initdb + 기동
#       PG_VERSION=16.9 bash build-pg.sh
set -euo pipefail

PG_VERSION="${PG_VERSION:-16.10}"
PREFIX="${PREFIX:-$HOME/pg}"
PGDATA="${PGDATA:-$HOME/pgdata}"
PGPORT="${PGPORT:-55432}"
SOCKDIR="${SOCKDIR:-$HOME/.pgsock}"
SRCDIR="${SRCDIR:-$HOME/src}"
JOBS="${JOBS:-16}"          # 32스레드 공유 서버. 절반만 쓴다.

log() { printf '\n\033[1m== %s\033[0m\n' "$*"; }

log "설정"
cat <<EOF
  PG_VERSION $PG_VERSION
  PREFIX     $PREFIX
  PGDATA     $PGDATA
  PGPORT     $PGPORT
  SOCKDIR    $SOCKDIR
  JOBS       $JOBS
EOF

# ---------------------------------------------------------------- 다운로드
mkdir -p "$SRCDIR"
cd "$SRCDIR"
TARBALL="postgresql-${PG_VERSION}.tar.bz2"
BASE="https://ftp.postgresql.org/pub/source/v${PG_VERSION}"

if [ ! -f "$TARBALL" ]; then
    log "다운로드 $TARBALL"
    curl -fSL --retry 3 -O "$BASE/$TARBALL" || {
        echo "다운로드 실패. PG_VERSION=$PG_VERSION 이 존재하는지 확인하십시오." >&2
        exit 1
    }
fi

log "체크섬 검증"
if curl -fsSL --retry 3 -o "${TARBALL}.sha256" "$BASE/${TARBALL}.sha256" 2>/dev/null; then
    # 공식 .sha256 파일은 "<hash>  <filename>" 형식
    if sha256sum -c "${TARBALL}.sha256"; then
        echo "  체크섬 OK"
    else
        echo "  체크섬 불일치 -- 중단합니다." >&2
        exit 1
    fi
else
    echo "  경고: .sha256 파일을 받지 못했습니다. 아래 해시를 직접 대조하십시오."
    sha256sum "$TARBALL"
fi

# ---------------------------------------------------------------- 빌드
SRC="$SRCDIR/postgresql-${PG_VERSION}"
if [ ! -d "$SRC" ]; then
    log "압축 해제"
    tar xf "$TARBALL"
fi

if [ ! -x "$PREFIX/bin/postgres" ]; then
    log "configure"
    cd "$SRC"
    ./configure \
        --prefix="$PREFIX" \
        --without-icu \
        --without-readline \
        --with-zlib \
        --enable-debug \
        CFLAGS="-O2 -g -fno-omit-frame-pointer"
    # --enable-debug: 확장 개발 중 심볼이 필요하다. 비용은 거의 없다.
    # --enable-cassert 는 일부러 끈다: H5 정확성 측정에 유용하지만
    #   10~30% 느려지므로, 나중에 별도 빌드로 둔다.

    log "make -j$JOBS"
    make -j"$JOBS" world-bin

    log "make install"
    make install-world-bin
else
    log "이미 빌드됨: $PREFIX/bin/postgres -- 건너뜀"
fi

export PATH="$PREFIX/bin:$PATH"
log "설치된 버전"
"$PREFIX/bin/postgres" --version
"$PREFIX/bin/pg_config" --includedir-server

# ---------------------------------------------------------------- initdb
if [ ! -f "$PGDATA/PG_VERSION" ]; then
    log "initdb (UTF8 / C locale)"
    mkdir -p "$SOCKDIR"
    chmod 700 "$SOCKDIR"
    "$PREFIX/bin/initdb" -D "$PGDATA" -E UTF8 --locale=C -U "$(id -un)"

    log "postgresql.conf 조정"
    cat >> "$PGDATA/postgresql.conf" <<EOF

# --- identity-plumbing 개발 인스턴스 ---
# 공유 서버이므로 TCP를 열지 않는다. 유닉스 소켓 전용, 소켓 디렉터리는 0700.
listen_addresses = ''
unix_socket_directories = '$SOCKDIR'
port = $PGPORT

shared_buffers = 2GB
work_mem = 64MB
max_connections = 100

# H5 채점에 필요
log_min_messages = warning
log_statement = 'none'          # 토큰이 로그로 새지 않도록 기본 off
track_activities = on
EOF
else
    log "PGDATA 이미 존재: $PGDATA -- initdb 건너뜀"
fi

# ---------------------------------------------------------------- 기동
if "$PREFIX/bin/pg_ctl" -D "$PGDATA" status >/dev/null 2>&1; then
    log "이미 기동 중"
else
    log "기동"
    "$PREFIX/bin/pg_ctl" -D "$PGDATA" -l "$HOME/pg.log" -w start
fi

log "연결 확인"
"$PREFIX/bin/psql" -h "$SOCKDIR" -p "$PGPORT" -d postgres -c "SELECT version();"

log "완료 -- 접속 방법"
cat <<EOF
  export PATH="$PREFIX/bin:\$PATH"
  export PGHOST="$SOCKDIR"
  export PGPORT=$PGPORT
  psql -d postgres

  중지: $PREFIX/bin/pg_ctl -D $PGDATA stop
  로그: $HOME/pg.log
EOF
