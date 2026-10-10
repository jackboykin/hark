# shellcheck shell=bash
# Sourced by the rigs: NSD authority and a resolver on loopback inside
# unshare -Urn, all on one CCD, since crossing dies costs a hit a fifth. Its
# last two cores hold the session's nsds and samplers; `place` draws the
# resolver's cores from the rest at random, siblings idle, and gives the
# load what remains.
# env: CCD (the last), N (resolver threads, 1), V6=0 (no AAAA servers),
# LATENCY_MS (netem on lo), PERF=1 (counters on the resolver's cores),
# PERF_EVENTS (perf stat -e list, default cycles,instructions).
B=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
P=$B/config
PORT=5354
N=${N:-1}

mapfile -t CORES < <(lscpu -p=CPU,CORE,CACHE | awk -F, -v want="${CCD:-}" '
  !/^#/ { split($3, c, ":"); l3[$1] = c[4]; core[$1] = $2; if (last == "" || c[4] + 0 > last + 0) last = c[4] }
  END { w = want == "" ? last : want; for (i in core) if (l3[i] == w) t[core[i]] = t[core[i]] " " i; for (k in t) print k t[k] }' | sort -n -k1,1 -k2,2)
read -r _ a b <<<"${CORES[-1]}"; read -r _ c d <<<"${CORES[-2]}"
# shellcheck disable=SC2034 # CPU_AUX is overload.sh's
CPU_NSD=$a${b:+,$b},$c CPU_ROOT=${d:-$c} CPU_AUX=${d:-$c} CPU_SAMPLE=${d:-$c}
unset a b c d

place() { # n: the resolver's n cores, drawn at random; the load every other thread
  local pool=("${CORES[@]:0:${#CORES[@]}-2}") pick c t0 t1
  pick=$(printf '%s\n' "${pool[@]}" | shuf -n "$1")
  CPU_RES='' CPU_LOAD=''
  for c in "${pool[@]}"; do
    read -r _ t0 t1 <<<"$c"
    if grep -qxF "$c" <<<"$pick"; then CPU_RES+=${CPU_RES:+,}$t0
    else CPU_LOAD+=${CPU_LOAD:+,}$t0${t1:+,$t1}; fi
  done
}

# Re-runs the calling script in a fresh user and network namespace.
ns() {
  [[ ${IN_NS:-} ]] && return
  [[ ${PERF:-} ]] || exec env IN_NS=1 unshare -Urn "$0" "$@"
  PERF_DIR=$(mktemp -d)
  "$B/perfd.sh" "$PERF_DIR" ${PERF_EVENTS:-} &
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
  for w in hit miss mix; do python3 "$B/gen_queries.py" $w >"$R/$w.txt"; done
  ip link set lo up
  ip addr add 198.41.0.4/32 dev lo
  local a addrs
  mapfile -t addrs < <(awk -v v6="${V6:-1}" '$4 == "A" || ($4 == "AAAA" && v6) { print $5 }' "$P/zones/bench.ns")
  for a in "${addrs[@]}"; do ip addr add "$a" dev lo; done
  nsd_up root "$CPU_ROOT" . 198.41.0.4
  nsd_up bench "$CPU_NSD" bench. "${addrs[@]}"
  [[ ${LATENCY_MS:-} ]] && tc qdisc add dev lo root netem delay "${LATENCY_MS}ms" limit 200000
  place "$N"
  sleep 0.5
}

ask() { dig +short +time=1 +tries=1 @127.0.0.1 -p "$PORT" "$@"; }
warm() { local i; for i in $(seq 8); do ask "host$i.bench" A >/dev/null; done; }

res_start() { # bin|unbound|pdns|kresd|bind
  local cmd i f
  # kresd is one thread a process: N of them share the port and the cache.
  for f in unbound.conf recursor.yml named.conf; do sed "s|__RUN__|$R|g; s|__DIR__|$P|g; s|__N__|$N|g" "$P/$f" >"$R/$f"; done
  case $1 in
    unbound) cmd=(unbound -d -c "$R/unbound.conf") ;;
    pdns) cmd=(pdns_recursor --config-dir="$R") ;;
    kresd) rm -rf "$R/kres"; mkdir -p "$R/kres"; cmd=(kresd -n -q -c "$P/kresd.conf" "$R/kres") ;;
    bind) cmd=(named -g -n "$N" -c "$R/named.conf") ;;
    *) cmd=("$1" serve --config "$P/hark.toml") ;;
  esac
  PIDS=()
  for i in $(seq "$([[ $1 == kresd ]] && echo "$N" || echo 1)"); do
    (exec taskset -c "$CPU_RES" "${cmd[@]}") >>"$R/res.log" 2>&1 &
    PIDS+=($!)
  done
  PID=${PIDS[0]}
  for _ in $(seq 50); do ask smoke.bench A >/dev/null 2>&1 && return; sleep 0.1; done
  echo "$1 did not come up" >&2; tail "$R/res.log" >&2; return 1
}
res_stop() { kill "${PIDS[@]}"; wait "${PIDS[@]}" 2>/dev/null; }
hark_start() { res_start "$1"; }
hark_stop() { res_stop; }

# A fresh stats dump: the counters, then the summary, ending with its window line.
hark_stats() {
  local l; l=$(wc -l <"$R/res.log")
  kill -USR1 "$PID"
  until tail -n +"$((l + 1))" "$R/res.log" | grep -q 'stats clients\.queries\.udp' &&
    tail -n +"$((l + 1))" "$R/res.log" | grep -q 'stats window ('; do sleep 0.02; done
  tail -n +"$((l + 1))" "$R/res.log"
}

# The resolver's cores from /proc/stat, softirq included: process time
# hides the kernel's work on its behalf.
core_snap() {
  awk -v l="$CPU_RES" 'BEGIN { n = split(l, p, ","); for (i = 1; i <= n; i++) { split(p[i], r, "-"); for (c = r[1]; c <= (r[2] == "" ? r[1] : r[2]); c++) w["cpu" c] = 1 } }
    $1 in w { for (i = 2; i <= 9; i++) s[i] += $i } END { printf "cpu"; for (i = 2; i <= 9; i++) printf " %d", s[i]; print "" }' /proc/stat
}
core_busy() { # snap0 snap1 -> busy usr sys si (percent of the cores)
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
  echo "$CPU_RES" >"$PERF_DIR/cpu"
  echo enable >"$PERF_DIR/ctl"; read -r _ <"$PERF_DIR/ack"
}
perf_off() {
  [[ ${PERF_DIR:-} ]] || return 0
  echo disable >"$PERF_DIR/ctl"; read -r _ <"$PERF_DIR/ack"
  : >"$PERF_DIR/stop"; cat "$PERF_DIR/out"
}
