#!/usr/bin/env bash
# usage (in nix develop .#bench): run.sh smoke|bench [rounds] [resolver...]
# resolver: hark unbound pdns kresd bind. Compare hark builds with tp.sh.
# env: HARK, OUT, LATENCY_MS, and lib.sh's cores
set -uo pipefail
D=$(cd "$(dirname "$0")" && pwd)
# shellcheck source-path=SCRIPTDIR source=../lib.sh
. "$D/../lib.sh"
ns "$@"

MODE=${1:-smoke}; shift
[[ $MODE == bench ]] && { ROUNDS=${1:-1}; shift; }
RES=("$@"); (( ${#RES[@]} )) || RES=(hark unbound pdns kresd bind)
HARK=${HARK:-$D/../../zig-out/bin/hark}
OUT=${OUT:-$D/out/$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
rig_up
for f in unbound.conf recursor.yml named.conf; do sed "s|__RUN__|$R|g; s|__DIR__|$D|g" "$D/$f" >"$R/$f"; done
python3 "$D/gen_queries.py" mix >"$R/mix.txt"
[[ ${LATENCY_MS:-} ]] && tc qdisc add dev lo root netem delay "${LATENCY_MS}ms" limit 200000

start() {
  local cmd
  case $1 in
    hark) cmd=("$HARK" serve --config "$D/hark.toml") ;;
    unbound) cmd=(unbound -d -c "$R/unbound.conf") ;;
    pdns) cmd=(pdns_recursor --config-dir="$R") ;;
    kresd) rm -rf "$R/kres"; mkdir -p "$R/kres"; cmd=(kresd -n -q -c "$D/kresd.conf" "$R/kres") ;;
    bind) cmd=(named -g -n 1 -U 1 -c "$R/named.conf") ;;
  esac
  (exec taskset -c "$CPU_RES" "${cmd[@]}") >"$R/$1.log" 2>&1 &
  PID=$!
  for _ in $(seq 50); do ask smoke.bench A >/dev/null 2>&1 && return; sleep 0.1; done
  echo "$1 did not come up"; tail "$R/$1.log"; return 1
}
stop() { kill "$PID"; wait "$PID" 2>/dev/null; while ask smoke.bench A >/dev/null 2>&1; do sleep 0.1; done; }
perf() { # resolver workload round dnsperf-args...
  local f=$OUT/$1.$2.$3.txt s0; shift 3
  s0=$(core_snap)
  taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 "$@" >"$f" 2>&1
  echo "core_busy $(core_busy "$s0" "$(core_snap)")" >>"$f"
}
round() { # resolver round
  start "$1" || return
  warm
  perf "$1" hit "$2" -d "$R/hit.txt" -c 4 -T 4 -q 400 -l 10
  # A histogram, not -v: dnsperf flushes a -v line per reply, and one
  # write stalling on ext4 held its receiver ~19 ms.
  perf "$1" lat "$2" -d "$R/hit.txt" -c 1 -T 1 -Q 20000 -l 5 -O latency-histogram
  # 70% of the resolver's own ceiling: one rate for all would saturate the slower.
  perf "$1" load "$2" -d "$R/hit.txt" -c 4 -T 4 -q 400 -l 5 -O latency-histogram \
    -Q "$(awk '/Queries per second/ { printf "%d", $4 * 0.7 }' "$OUT/$1.hit.$2.txt")"
  stop; start "$1" || return
  perf "$1" miss "$2" -d "$R/miss.txt" -c 4 -T 4 -q 1000 -l 10
  stop; start "$1" || return
  warm
  perf "$1" mix "$2" -d "$R/mix.txt" -c 4 -T 4 -q 1000 -l 10
  stop
}

if [[ $MODE == smoke ]]; then
  for n in "${RES[@]}"; do start "$n" && echo "$n: $(ask smoke.bench A) $(ask zz9.bench A)" && stop; done
  exit
fi
for r in $(seq "$ROUNDS"); do
  mapfile -t order < <(shuf -e "${RES[@]}")
  echo "round $r: ${order[*]}"
  for n in "${order[@]}"; do round "$n" "$r"; done
done
python3 "$D/sum.py" "$OUT"
