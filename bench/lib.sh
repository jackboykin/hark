# shellcheck shell=bash
# Sourced by the rigs: NSD authority and hark on loopback inside unshare -Urn,
# pinned for the 7950X, plus the samplers that see what process time hides.
# env: CPU_RES (2), CPU_LOAD (4-7), CPU_NSD (8-11, bench.'s nsd), CPU_ROOT (12,
# the root's), CPU_AUX (13, probes), CPU_SAMPLE (14, the udp sampler), V6=0
# to leave bench.'s AAAA servers unreachable as on an IPv4-only host, PERF=1
# for per-window perf counters on CPU_RES (perfd.sh, started outside the
# namespace).
B=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
P=$B/peers
CPU_RES=${CPU_RES:-2} CPU_LOAD=${CPU_LOAD:-4-7} CPU_NSD=${CPU_NSD:-8-11} CPU_ROOT=${CPU_ROOT:-12} CPU_AUX=${CPU_AUX:-13} CPU_SAMPLE=${CPU_SAMPLE:-14}
PORT=5354

# Re-runs the calling script in a fresh user and network namespace.
ns() {
  [[ ${IN_NS:-} ]] && return
  [[ ${PERF:-} ]] || exec env IN_NS=1 unshare -Urn "$0" "$@"
  PERF_DIR=$(mktemp -d)
  "$B/perfd.sh" "$PERF_DIR" "$CPU_RES" &
  local pd=$! rc
  until [[ -p $PERF_DIR/out ]]; do kill -0 "$pd" 2>/dev/null || exit 1; sleep 0.05; done
  env IN_NS=1 PERF_DIR="$PERF_DIR" unshare -Urn "$0" "$@"; rc=$?
  kill "$pd"; wait "$pd"; rm -rf "$PERF_DIR"; exit "$rc"
}

nsd_up() { # name cpus zone addr...
  local n=$1 c=$2 z=$3; shift 3
  { sed "s|__RUN__|$R|g; s|__DIR__|$P|g; s|__NAME__|$n|g" "$P/nsd.conf"
    printf '    ip-address: %s\n' "$@"
    printf 'zone:\n    name: "%s"\n    zonefile: "%s.zone"\n' "$z" "$n"; } >"$R/nsd-$n.conf"
  taskset -c "$c" nsd -c "$R/nsd-$n.conf" -d 2>"$R/nsd-$n.err" &
}

# The root's nsd on 198.41.0.4 delegates bench. to a second nsd on the
# addresses in zones/bench.ns, so a miss starts at a cached 26-server cut, as
# under com. Query files land in $R.
rig_up() {
  R=$(mktemp -d)
  trap 'kill $(jobs -p) 2>/dev/null; wait; rm -rf "$R"' EXIT
  for w in hit miss; do python3 "$P/gen_queries.py" $w >"$R/$w.txt"; done
  ip link set lo up
  ip addr add 198.41.0.4/32 dev lo
  local a addrs
  mapfile -t addrs < <(awk -v v6="${V6:-1}" '$4 == "A" || ($4 == "AAAA" && v6) { print $5 }' "$P/zones/bench.ns")
  for a in "${addrs[@]}"; do ip addr add "$a" dev lo; done
  nsd_up root "$CPU_ROOT" . 198.41.0.4
  nsd_up bench "$CPU_NSD" bench. "${addrs[@]}"
  sleep 0.5
}

ask() { dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT" "$@"; }
warm() { local i; for i in $(seq 8); do ask "host$i.bench" A >/dev/null; done; }

hark_start() { # bin
  (exec taskset -c "$CPU_RES" "$1" serve --config "$P/hark.toml") >"$R/hark.log" 2>&1 &
  PID=$!
  for _ in $(seq 50); do ask smoke.bench A >/dev/null 2>&1 && return; sleep 0.1; done
  echo "$1 did not come up" >&2; tail "$R/hark.log" >&2; return 1
}
hark_stop() { kill "$PID"; wait "$PID" 2>/dev/null; }

# The latest cumulative stats clients line, freshly printed.
hark_stats() {
  local n; n=$(grep -c 'stats clients' "$R/hark.log")
  kill -USR1 "$PID"
  while (( $(grep -c 'stats clients' "$R/hark.log") == n )); do sleep 0.02; done
  grep 'stats clients' "$R/hark.log" | tail -1
}

# Whole-core time for CPU_RES from /proc/stat, softirq included: process
# time hides the kernel work done on the resolver's behalf.
core_snap() { grep "^cpu$CPU_RES " /proc/stat; }
core_busy() { # snap0 snap1 -> busy usr sys si (percent of the core)
  awk -v a="$1" -v b="$2" 'BEGIN { split(a, x); split(b, y); for (i = 2; i <= 9; i++) { d[i] = y[i] - x[i]; t += d[i] }
    printf "%.1f %.1f %.1f %.1f\n", 100 * (t - d[5] - d[6]) / t, 100 * d[2] / t, 100 * d[4] / t, 100 * d[8] / t }'
}

# /proc/net/udp every 50 ms: per socket "kind inode rx_queue drops", kind L
# for hark's listener and G for a generator socket aimed at it.
# shellcheck disable=SC2016 # awk and the inner bash expand these, not us
udp_start() {
  (exec taskset -c "$CPU_SAMPLE" bash -c 'while :; do awk -v p="$1" "$2" /proc/net/udp; sleep 0.05; done' _ \
    "$(printf ':%04X' "$PORT")" '{ split($5, q, ":"); k = $2 ~ p "$" ? "L" : $3 ~ p "$" ? "G" : "" }
      k { print k, $10, strtonum("0x" q[2]), $13 }') >"$R/udp" &
  UDP=$!
}
udp_stop() { # -> rxq_max_bytes listener_drops generator_drops
  kill "$UDP"; wait "$UDP" 2>/dev/null
  awk '$1 == "L" { d[$2] = $4; if ($3 > m) m = $3 } $1 == "G" && $4 > g[$2] { g[$2] = $4 }
    END { for (i in d) l += d[i]; for (i in g) s += g[i]; print m + 0, l + 0, s + 0 }' "$R/udp"
}

# One counting window on perfd.sh; perf_off prints "event=value ...".
perf_on() {
  [[ ${PERF_DIR:-} ]] || return 0
  echo enable >"$PERF_DIR/ctl"; read -r _ <"$PERF_DIR/ack"
}
perf_off() {
  [[ ${PERF_DIR:-} ]] || return 0
  echo disable >"$PERF_DIR/ctl"; read -r _ <"$PERF_DIR/ack"
  : >"$PERF_DIR/stop"; cat "$PERF_DIR/out"
}
