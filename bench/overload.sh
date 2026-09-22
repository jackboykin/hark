#!/usr/bin/env bash
# usage (in nix develop .#bench): overload.sh <bin> [runs=3]
# Open-loop miss load at LEVELS (1 2 4 8) times the miss ceiling, from four
# resperf instances with disjoint names, and an open-loop cached-name probe
# (dnsperf -Q PROBE_QPS, 2000) beside it, on a fresh hark per run for LEN (8)
# s. The ceiling is measured closed loop (-c 4 -T 4 -q 1000) unless CEILING is
# given. Runs land in OUT; overload.py prints the verdict.
set -uo pipefail
# shellcheck source-path=SCRIPTDIR source=lib.sh
. "$(dirname "$0")/lib.sh"
ns "$@"
BIN=$1 RUNS=${2:-3} LEN=${LEN:-8} LEVELS=${LEVELS:-1 2 4 8}
OUT=${OUT:-$P/out/overload-$(date +%Y%m%d-%H%M%S)}
mkdir -p "$OUT"
rig_up

ceiling=${CEILING:-}
if [[ ! $ceiling ]]; then
  hark_start "$BIN" || exit 1
  s0=$(core_snap)
  taskset -c "$CPU_LOAD" dnsperf -s 127.0.0.1 -p "$PORT" -t 3 -d "$R/miss.txt" -c 4 -T 4 -q 1000 -l 10 >"$OUT/ceiling" 2>&1
  echo "busy $(core_busy "$s0" "$(core_snap)")" >>"$OUT/ceiling"
  hark_stop
  ceiling=$(grep -oP 'Queries per second:\s+\K[\d.]+' "$OUT/ceiling")
fi
echo "ceiling=$ceiling len=$LEN" >"$OUT/meta"
# Enough names that no instance wraps into ones already cached.
top=$(tr ' ' '\n' <<<"$LEVELS" | sort -n | tail -1)
for k in 1 2 3 4; do python3 "$P/gen_queries.py" miss "$(awk -v c="$ceiling" -v l="$top" -v t="$LEN" 'BEGIN { printf "%d", c * l * t / 4 * 1.1 }')" "$k" >"$R/flood$k.txt"; done

for level in $LEVELS; do
  rate=$(awk -v c="$ceiling" -v l="$level" 'BEGIN { printf "%d", c * l / 4 }')
  for i in $(seq "$RUNS"); do
    f=$OUT/$level.$i
    hark_start "$BIN" || exit 1
    warm
    hark_stats >"$f.stats0"
    udp_start
    fl=()
    for k in 1 2 3 4; do
      taskset -c "$CPU_LOAD" resperf -s 127.0.0.1 -p "$PORT" -d "$R/flood$k.txt" -m "$rate" -r 0 -c "$LEN" -t 1 \
        -C 4 -q 250000 -F 0 -P "$f.plot$k" >"$f.flood$k" 2>&1 &
      fl+=($!)
    done
    sleep 0.5
    taskset -c "$CPU_AUX" dnsperf -s 127.0.0.1 -p "$PORT" -d "$R/hit.txt" -c 1 -T 1 -Q "${PROBE_QPS:-2000}" -q 10000 -t 1 \
      -l $((LEN - 1)) -v >"$f.probe" 2>&1 &
    s0=$(core_snap); sleep $((LEN - 1)); core_busy "$s0" "$(core_snap)" >"$f.busy"
    wait "${fl[@]}" $!
    udp_stop >"$f.udp"
    hark_stats >"$f.stats1"
    hark_stop
    echo "${level}x run $i" >&2
  done
done
python3 "$B/overload.py" "$OUT"
