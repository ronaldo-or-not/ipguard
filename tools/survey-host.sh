#!/usr/bin/env bash
# 타겟 호스트 조사. 읽기 전용 — 설치·설정 변경·서비스 재시작을 하지 않는다.
# 사용:  ssh db.example.internal 'bash -s' < tools/survey-host.sh
#        (~/.ssh/config 에 Host db.example.internal / Port 6689 / User rinomaru 등록됨)
#   또는 서버에 복사해서  bash survey-host.sh
set -u

sec() { printf '\n=== %s ===\n' "$1"; }

sec HOST
hostname; uname -a
sec OS
cat /etc/os-release 2>/dev/null | head -4
sec CPU_MEM
lscpu 2>/dev/null | grep -Ei '^(Architecture|Model name|CPU\(s\)|Thread|Core|Socket|NUMA node\(s\)|Hypervisor)'
free -h 2>/dev/null | head -2
echo -n "가상화: "; systemd-detect-virt 2>/dev/null || echo "unknown"
echo -n "clocksource: "; cat /sys/devices/system/clocksource/clocksource0/current_clocksource 2>/dev/null || echo n/a

sec PRIVILEGE
id
echo -n "sudo(비대화형): "; sudo -n true 2>/dev/null && echo YES || echo "NO 또는 비밀번호 필요"

sec SHARED_SERVER
echo -n "현재 로그인 세션 수: "; who 2>/dev/null | wc -l
who 2>/dev/null | head -8
echo -n "홈 디렉터리 수: "; ls /home 2>/dev/null | wc -l
ls /home 2>/dev/null | head -12
echo "부하 평균: $(cat /proc/loadavg 2>/dev/null)"
echo -n "다른 사용자 프로세스 수: "; ps -eo user= 2>/dev/null | sort -u | wc -l

sec EBPF_PREREQ
echo -n "BTF(/sys/kernel/btf/vmlinux): "; [ -f /sys/kernel/btf/vmlinux ] && echo present || echo ABSENT
echo -n "bpffs: "; mount 2>/dev/null | grep -q ' type bpf ' && echo mounted || echo "미마운트"
echo -n "bpftool: "; command -v bpftool >/dev/null 2>&1 && bpftool version 2>/dev/null | head -1 || echo "(없음)"
echo -n "kernel lockdown: "; cat /sys/kernel/security/lockdown 2>/dev/null || echo "n/a (미활성일 가능성)"
echo -n "unprivileged_bpf_disabled: "; cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo n/a
echo -n "perf_event_paranoid: "; cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo n/a
echo -n "perf: "; command -v perf >/dev/null 2>&1 && perf --version 2>/dev/null || echo "(없음)"

sec POSTGRESQL
for c in psql postgres pg_config pg_lsclusters pg_ctl; do
  printf '%-14s ' "$c"
  command -v "$c" >/dev/null 2>&1 && { "$c" --version 2>/dev/null | head -1; } || echo "(없음)"
done
ls -d /usr/lib/postgresql/* /usr/pgsql-* /var/lib/pgsql 2>/dev/null
echo -n "5432 리스닝: "; { ss -lnt 2>/dev/null || netstat -lnt 2>/dev/null; } | grep -c ':5432'
echo -n "서버 헤더(pg_config --includedir-server): "; pg_config --includedir-server 2>/dev/null || echo "n/a"

sec TOOLCHAIN
for c in gcc clang make git docker podman java javac mvn gradle python3 go cargo; do
  printf '%-8s ' "$c"; command -v "$c" >/dev/null 2>&1 && echo ok || echo "-"
done

sec DISK
df -h "$HOME" 2>/dev/null | tail -1
echo -n "홈 사용량: "; du -sh "$HOME" 2>/dev/null | cut -f1

sec NETWORK
ip -br addr 2>/dev/null | head -6 || ifconfig 2>/dev/null | head -12

printf '\n=== 조사 끝 ===\n'
