#!/usr/bin/env bash
set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/../.." && pwd)

if [ "${PMBMPD:-}" ]; then
  pmbmpd=$PMBMPD
elif [ -x "$repo_root/src/pmbmpd" ]; then
  pmbmpd=$repo_root/src/pmbmpd
elif command -v pmbmpd >/dev/null 2>&1; then
  pmbmpd=$(command -v pmbmpd)
else
  echo "SKIP: pmbmpd not found; build it or set PMBMPD=/path/to/pmbmpd" >&2
  exit 77
fi

tmpdir=$(mktemp -d "${TMPDIR:-/tmp}/pmacct-bmp-malformed.XXXXXX")
tcp_pid=

terminate_pid() {
  pid=$1
  label=$2

  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" 2>/dev/null || true
    return 0
  fi

  kill -INT "$pid" 2>/dev/null || true
  idx=0
  while kill -0 "$pid" 2>/dev/null && [ "$idx" -lt 20 ]; do
    sleep 0.1
    idx=$((idx + 1))
  done

  if kill -0 "$pid" 2>/dev/null; then
    echo "WARN: $label did not exit after SIGINT; sending SIGKILL" >&2
    kill -KILL "$pid" 2>/dev/null || true
  fi

  wait "$pid" 2>/dev/null || true
}

cleanup() {
  if [ "${tcp_pid:-}" ] && kill -0 "$tcp_pid" 2>/dev/null; then
    terminate_pid "$tcp_pid" "pmbmpd TCP malformed-length check"
  fi
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT TERM

require_log() {
  log_file=$1
  pattern=$2
  if ! grep -q "$pattern" "$log_file"; then
    echo "FAIL: pattern '$pattern' not found in $log_file" >&2
    sed -n '1,160p' "$log_file" >&2 || true
    exit 1
  fi
}

wait_for_log() {
  log_file=$1
  pattern=$2
  idx=0
  while [ "$idx" -lt 50 ]; do
    if [ -f "$log_file" ] && grep -q "$pattern" "$log_file"; then
      return 0
    fi
    sleep 0.1
    idx=$((idx + 1))
  done
  echo "FAIL: timed out waiting for '$pattern' in $log_file" >&2
  [ -f "$log_file" ] && sed -n '1,160p' "$log_file" >&2
  exit 1
}

assert_alive() {
  pid=$1
  label=$2
  if ! kill -0 "$pid" 2>/dev/null; then
    wait "$pid" || status=$?
    echo "FAIL: $label exited unexpectedly with status ${status:-unknown}" >&2
    exit 1
  fi
}

"$script_dir/generate-malformed-bmp.sh" tcp-short-length "$tmpdir/tcp-short-length.bmp"
"$script_dir/generate-malformed-bmp.sh" packet-short-length "$tmpdir/packet-short-length.bmp"
"$script_dir/generate-bmp-pcap.py" "$tmpdir/packet-short-length.bmp" "$tmpdir/packet-short-length.pcap"

port=$((20000 + RANDOM % 20000))
tcp_log=$tmpdir/pmbmpd-tcp.log
tcp_conf=$tmpdir/pmbmpd-tcp.conf

cat > "$tcp_conf" <<EOF
core_proc_name: pmbmpd_malformed_tcp
daemonize: false
debug: true
logfile: $tcp_log
pidfile: $tmpdir/pmbmpd-tcp.pid
bmp_daemon: true
bmp_daemon_ip: 127.0.0.1
bmp_daemon_port: $port
bmp_daemon_max_peers: 4
EOF

"$pmbmpd" -f "$tcp_conf" &
tcp_pid=$!
wait_for_log "$tcp_log" "waiting for BMP data"
cat "$tmpdir/tcp-short-length.bmp" > "/dev/tcp/127.0.0.1/$port"
sleep 0.5
assert_alive "$tcp_pid" "pmbmpd TCP malformed-length check"
require_log "$tcp_log" "invalid BMP message length: 4"
terminate_pid "$tcp_pid" "pmbmpd TCP malformed-length check"
tcp_pid=

pcap_log=$tmpdir/pmbmpd-pcap.log
pcap_conf=$tmpdir/pmbmpd-pcap.conf

cat > "$pcap_conf" <<EOF
core_proc_name: pmbmpd_malformed_pcap
daemonize: false
debug: true
logfile: $pcap_log
pidfile: $tmpdir/pmbmpd-pcap.pid
pcap_savefile: $tmpdir/packet-short-length.pcap
pcap_savefile_replay: 1
pcap_savefile_delay: 0
bmp_daemon_port: 1790
bmp_daemon_max_peers: 4
EOF

set +e
timeout 10 "$pmbmpd" -f "$pcap_conf"
pcap_status=$?
set -e

if [ "$pcap_status" -ne 0 ]; then
  echo "FAIL: pmbmpd pcap malformed-length check exited with status $pcap_status" >&2
  sed -n '1,160p' "$pcap_log" >&2 || true
  exit 1
fi

require_log "$pcap_log" "invalid BMP message length: 4"

echo "PASS: malformed BMP short-length checks"
